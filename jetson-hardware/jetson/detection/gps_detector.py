"""
Al-Ahsa Smart Bus — GPS spoofing detection engine.

Listens for incoming GPS telemetry packets on UDP port 5000 and applies
the same four anomaly checks used in the ns-3 GpsDetectorApp::HandleRead()
(smart-bus.cc lines 912-1053):

  1. Speed anomaly    — speed > 22.2 m/s  (80 km/h)
  2. Jump anomaly     — dt <= 1.5 s AND distance > 1000 m
  3. Corridor anomaly — distance_to_route(pos, route) > 1500 m
  4. Source IP change  — different source IP for the same bus_id

Detection mode is "any" (1-of-4 conditions satisfies), matching the
supervisor requirement.  An anomaly streak of >= 3 consecutive
anomalous readings is required before triggering, exactly as in ns-3
(GPS_STREAK_REQUIRED = 3, line 1015).

One-shot per bus_id: once triggered for a bus, that bus is never
re-triggered.

GPS packet wire format (little-endian, 200 bytes):
    [0..3]   uint32  magic  (0x47505331 = "GPS1")
    [4..7]   uint32  bus_id
    [8..15]  double  pos_x
    [16..23] double  pos_y
    [24..199] padding (zeros)
"""

import logging
import math
import socket
import struct
import threading
import time
from typing import Callable, Dict, Any, Optional, Tuple

from jetson.routes import create_routes, get_bus_route_assignment
from jetson.utils import distance_to_route, euclidean_distance

logger = logging.getLogger(__name__)

# Constants — mirror smart-bus.cc
GPS_PAYLOAD_MAGIC = 0x47505331        # "GPS1"
GPS_PAYLOAD_MIN_SIZE = 24              # magic + busId + posX + posY
GPS_SPEED_THRESHOLD = 22.2            # m/s  (80 km/h)
GPS_JUMP_THRESHOLD = 1000.0           # meters
GPS_CORRIDOR_THRESHOLD = 1500.0       # meters
GPS_STREAK_REQUIRED = 3               # consecutive anomalous readings
MAX_BUSES = 41

# Wire format for the first 24 bytes (little-endian)
_HEADER_FMT = "<IIdd"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 24


class _PerBusState:
    """Per-bus tracking state, mirrors GpsDetectorApp::PerBusState."""

    __slots__ = (
        "last_pos",
        "last_time",
        "last_src_ip",
        "anomaly_streak",
        "detected",
        "initialized",
    )

    def __init__(self):
        self.last_pos: Tuple[float, float] = (0.0, 0.0)
        self.last_time: float = 0.0
        self.last_src_ip: str = ""
        self.anomaly_streak: int = 0
        self.detected: bool = False
        self.initialized: bool = False


class GpsDetector:
    """Thread that receives GPS packets and detects spoofing."""

    def __init__(
        self,
        listen_port: int = 5000,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        detection_mode: str = "any",
        speed_threshold: float = GPS_SPEED_THRESHOLD,
        jump_threshold: float = GPS_JUMP_THRESHOLD,
        corridor_threshold: float = GPS_CORRIDOR_THRESHOLD,
        streak_required: int = GPS_STREAK_REQUIRED,
    ):
        self._listen_port = listen_port
        self._callback = callback
        self._detection_mode = detection_mode

        self._speed_threshold = speed_threshold
        self._jump_threshold = jump_threshold
        self._corridor_threshold = corridor_threshold
        self._streak_required = streak_required

        # Pre-compute route data (avoid re-creating on every packet)
        self._routes = create_routes()
        self._assignment = get_bus_route_assignment()

        # Per-bus state map
        self._bus_states: Dict[int, _PerBusState] = {}
        self._state_lock = threading.Lock()

        # Internal
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._stop_event.clear()
        self._bus_states.clear()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind(("", self._listen_port))

        self._thread = threading.Thread(
            target=self._recv_loop, daemon=True, name="gps-detector"
        )
        self._thread.start()
        logger.info(
            "GpsDetector listening on UDP:%d (mode=%s, streak=%d)",
            self._listen_port,
            self._detection_mode,
            self._streak_required,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("GpsDetector stopped")

    def get_bus_state(self, bus_id: int) -> Optional[Dict[str, Any]]:
        """Return a snapshot of per-bus detection state (for debugging)."""
        with self._state_lock:
            st = self._bus_states.get(bus_id)
            if st is None:
                return None
            return {
                "last_pos": st.last_pos,
                "last_time": st.last_time,
                "last_src_ip": st.last_src_ip,
                "anomaly_streak": st.anomaly_streak,
                "detected": st.detected,
            }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _recv_loop(self) -> None:
        """Receive GPS packets and process them."""
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(256)
                self._handle_packet(data, addr)
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                logger.warning("GpsDetector socket error", exc_info=True)
                continue

    def _handle_packet(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Parse one GPS packet and run anomaly checks.

        Mirrors GpsDetectorApp::HandleRead() line-for-line.
        """
        if len(data) < GPS_PAYLOAD_MIN_SIZE:
            return

        magic, bus_id, pos_x, pos_y = struct.unpack(
            _HEADER_FMT, data[:_HEADER_SIZE]
        )

        if magic != GPS_PAYLOAD_MAGIC:
            return
        if bus_id >= MAX_BUSES:
            return
        if not (math.isfinite(pos_x) and math.isfinite(pos_y)):
            return

        current_pos = (pos_x, pos_y)
        now = time.monotonic()
        src_ip = addr[0]

        with self._state_lock:
            state = self._bus_states.get(bus_id)
            if state is None:
                state = _PerBusState()
                self._bus_states[bus_id] = state

            # First packet for this bus — initialize and return
            if not state.initialized:
                state.last_pos = current_pos
                state.last_time = now
                state.last_src_ip = src_ip
                state.anomaly_streak = 0
                state.detected = False
                state.initialized = True
                return

            dt = now - state.last_time
            if dt <= 0:
                state.last_pos = current_pos
                state.last_time = now
                return

            # Noise filter: skip packets arriving < 0.5 s apart
            # (smart-bus.cc lines 963-971)
            if dt < 0.5:
                return

            distance = euclidean_distance(
                state.last_pos[0], state.last_pos[1],
                current_pos[0], current_pos[1],
            )
            speed = distance / dt

            # ----- Four anomaly checks (smart-bus.cc lines 976-1006) -----

            # Check 1: Speed > 80 km/h (22.2 m/s)
            speed_anomaly = speed > self._speed_threshold

            # Check 2: Jump > 1 km in <= 1.5 s
            jump_anomaly = (dt <= 1.5) and (distance > self._jump_threshold)

            # Check 3: Outside assigned route corridor (> 1500 m)
            corridor_dist = 0.0
            corridor_anomaly = False
            if 0 <= bus_id < len(self._assignment):
                route_idx = self._assignment[bus_id]
                if route_idx < len(self._routes):
                    corridor_dist = distance_to_route(
                        current_pos[0], current_pos[1],
                        self._routes[route_idx],
                    )
                    corridor_anomaly = corridor_dist > self._corridor_threshold

            # Check 4: Source IP changed for same bus_id
            src_anomaly = (
                state.last_src_ip != ""
                and state.last_src_ip != src_ip
            )

            # ----- Aggregation (smart-bus.cc lines 1008-1011) -----
            anomaly_count = sum([
                speed_anomaly,
                jump_anomaly,
                corridor_anomaly,
                src_anomaly,
            ])
            required = 1 if self._detection_mode == "any" else 2
            is_anomalous = anomaly_count >= required

            # ----- Streak logic (smart-bus.cc lines 1013-1024) -----
            if is_anomalous:
                state.anomaly_streak += 1
            else:
                state.anomaly_streak = 0

            logger.debug(
                "GPS bus=%d speed=%.1f m/s dist=%.0f m corridor=%.0f m "
                "src_change=%s anomalous=%s streak=%d",
                bus_id,
                speed,
                distance,
                corridor_dist,
                src_anomaly,
                is_anomalous,
                state.anomaly_streak,
            )

            # ----- Trigger (smart-bus.cc lines 1026-1048) -----
            if (
                state.anomaly_streak >= self._streak_required
                and not state.detected
            ):
                state.detected = True
                details = {
                    "type": "gps_spoof",
                    "timestamp": time.time(),
                    "bus_id": bus_id,
                    "speed": speed,
                    "distance": distance,
                    "corridor_dist": corridor_dist,
                    "src_ip": src_ip,
                    "prev_src_ip": state.last_src_ip,
                    "speed_anomaly": speed_anomaly,
                    "jump_anomaly": jump_anomaly,
                    "corridor_anomaly": corridor_anomaly,
                    "src_anomaly": src_anomaly,
                    "streak": state.anomaly_streak,
                }
                logger.warning(
                    "[GPS SPOOF DETECTED] bus=%d speed=%.1f m/s "
                    "dist=%.0f m corridor=%.0f m src=%s streak=%d",
                    bus_id,
                    speed,
                    distance,
                    corridor_dist,
                    src_ip,
                    state.anomaly_streak,
                )
                if self._callback:
                    try:
                        self._callback(details)
                    except Exception:
                        logger.exception("GPS callback error")

            # Update state for next packet
            state.last_pos = current_pos
            state.last_time = now
            state.last_src_ip = src_ip
