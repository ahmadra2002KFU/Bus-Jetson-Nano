"""Server-side GPS spoofing detector.

Ports the 4-check logic from ``jetson.detection.gps_detector`` into an async,
per-bus state machine driven by WebSocket frames arriving at ``/ingest/gps``.

Checks (any-of-4 triggers an anomalous reading; 3 consecutive anomalous
readings trip a one-shot detection per bus_id):

    1. Speed   > 22.2 m/s  (80 km/h)
    2. Jump    > 1000 m within dt <= 1.5 s
    3. Corridor distance > 1500 m from assigned route polyline
    4. Source address changed for same bus_id
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from jetson.routes import create_routes, get_bus_route_assignment
from jetson.utils import distance_to_route, euclidean_distance

logger = logging.getLogger(__name__)

GPS_SPEED_THRESHOLD = 22.2       # m/s (80 km/h)
GPS_JUMP_THRESHOLD = 1000.0      # meters
GPS_CORRIDOR_THRESHOLD = 1500.0  # meters
GPS_STREAK_REQUIRED = 3
GPS_MIN_DT = 0.5                 # seconds — noise filter

EventSink = Callable[[Dict[str, Any]], Awaitable[None]]


@dataclass
class _BusState:
    last_pos: Tuple[float, float] = (0.0, 0.0)
    last_time: float = 0.0
    last_src_addr: str = ""
    anomaly_streak: int = 0
    detected: bool = False
    initialized: bool = False


@dataclass
class GpsDetectionResult:
    triggered: bool
    anomaly_count: int
    speed: float
    distance: float
    corridor_dist: float
    speed_anomaly: bool
    jump_anomaly: bool
    corridor_anomaly: bool
    src_anomaly: bool
    details: Dict[str, Any] = field(default_factory=dict)


class ServerGpsDetector:
    """Async per-bus GPS spoofing detector.

    The caller feeds frames via :meth:`process`. On a one-shot trigger the
    detector invokes ``on_detect(details)`` once per bus_id.
    """

    def __init__(
        self,
        *,
        on_detect: Optional[EventSink] = None,
        speed_threshold: float = GPS_SPEED_THRESHOLD,
        jump_threshold: float = GPS_JUMP_THRESHOLD,
        corridor_threshold: float = GPS_CORRIDOR_THRESHOLD,
        streak_required: int = GPS_STREAK_REQUIRED,
        detection_mode: str = "any",
    ) -> None:
        self._on_detect = on_detect
        self._speed_threshold = speed_threshold
        self._jump_threshold = jump_threshold
        self._corridor_threshold = corridor_threshold
        self._streak_required = streak_required
        self._detection_mode = detection_mode

        self._routes = create_routes()
        self._assignment = get_bus_route_assignment()

        self._states: Dict[int, _BusState] = {}
        self._lock = asyncio.Lock()

    def reset_bus(self, bus_id: int) -> None:
        self._states.pop(bus_id, None)

    def get_state(self, bus_id: int) -> Optional[Dict[str, Any]]:
        st = self._states.get(bus_id)
        if st is None:
            return None
        return {
            "last_pos": st.last_pos,
            "last_time": st.last_time,
            "last_src_addr": st.last_src_addr,
            "anomaly_streak": st.anomaly_streak,
            "detected": st.detected,
        }

    async def process(
        self,
        bus_id: int,
        pos_x: float,
        pos_y: float,
        src_addr: str,
        *,
        now: Optional[float] = None,
    ) -> GpsDetectionResult:
        """Feed one GPS sample through the detector.

        Returns a :class:`GpsDetectionResult` describing the current frame.
        ``triggered`` is ``True`` only on the exact frame that tripped the
        one-shot (subsequent frames for the same bus return ``False``).
        """
        if not math.isfinite(pos_x) or not math.isfinite(pos_y):
            return GpsDetectionResult(
                triggered=False, anomaly_count=0, speed=0.0,
                distance=0.0, corridor_dist=0.0,
                speed_anomaly=False, jump_anomaly=False,
                corridor_anomaly=False, src_anomaly=False,
            )

        t = now if now is not None else time.monotonic()

        async with self._lock:
            state = self._states.setdefault(bus_id, _BusState())

            if not state.initialized:
                state.last_pos = (pos_x, pos_y)
                state.last_time = t
                state.last_src_addr = src_addr
                state.anomaly_streak = 0
                state.detected = False
                state.initialized = True
                return GpsDetectionResult(
                    triggered=False, anomaly_count=0, speed=0.0,
                    distance=0.0, corridor_dist=0.0,
                    speed_anomaly=False, jump_anomaly=False,
                    corridor_anomaly=False, src_anomaly=False,
                )

            dt = t - state.last_time
            if dt <= 0:
                state.last_pos = (pos_x, pos_y)
                state.last_time = t
                return GpsDetectionResult(
                    triggered=False, anomaly_count=0, speed=0.0,
                    distance=0.0, corridor_dist=0.0,
                    speed_anomaly=False, jump_anomaly=False,
                    corridor_anomaly=False, src_anomaly=False,
                )
            if dt < GPS_MIN_DT:
                return GpsDetectionResult(
                    triggered=False, anomaly_count=0, speed=0.0,
                    distance=0.0, corridor_dist=0.0,
                    speed_anomaly=False, jump_anomaly=False,
                    corridor_anomaly=False, src_anomaly=False,
                )

            distance = euclidean_distance(
                state.last_pos[0], state.last_pos[1], pos_x, pos_y
            )
            speed = distance / dt

            speed_anomaly = speed > self._speed_threshold
            jump_anomaly = (dt <= 1.5) and (distance > self._jump_threshold)

            corridor_dist = 0.0
            corridor_anomaly = False
            if 0 <= bus_id < len(self._assignment):
                route_idx = self._assignment[bus_id]
                if 0 <= route_idx < len(self._routes):
                    corridor_dist = distance_to_route(
                        pos_x, pos_y, self._routes[route_idx]
                    )
                    corridor_anomaly = corridor_dist > self._corridor_threshold

            src_anomaly = bool(
                state.last_src_addr and state.last_src_addr != src_addr
            )

            anomaly_count = int(speed_anomaly) + int(jump_anomaly) + \
                int(corridor_anomaly) + int(src_anomaly)
            required = 1 if self._detection_mode == "any" else 2
            is_anomalous = anomaly_count >= required

            if is_anomalous:
                state.anomaly_streak += 1
            else:
                state.anomaly_streak = 0

            triggered = False
            details: Dict[str, Any] = {}
            if (
                state.anomaly_streak >= self._streak_required
                and not state.detected
            ):
                state.detected = True
                triggered = True
                details = {
                    "type": "gps_spoof",
                    "timestamp": time.time(),
                    "bus_id": bus_id,
                    "speed": speed,
                    "distance": distance,
                    "corridor_dist": corridor_dist,
                    "src_addr": src_addr,
                    "prev_src_addr": state.last_src_addr,
                    "speed_anomaly": speed_anomaly,
                    "jump_anomaly": jump_anomaly,
                    "corridor_anomaly": corridor_anomaly,
                    "src_anomaly": src_anomaly,
                    "streak": state.anomaly_streak,
                }
                logger.warning(
                    "[GPS SPOOF DETECTED] bus=%d speed=%.1f m/s dist=%.0f m "
                    "corridor=%.0f m src=%s streak=%d",
                    bus_id, speed, distance, corridor_dist, src_addr,
                    state.anomaly_streak,
                )

            state.last_pos = (pos_x, pos_y)
            state.last_time = t
            state.last_src_addr = src_addr

        if triggered and self._on_detect is not None:
            try:
                await self._on_detect(details)
            except Exception:
                logger.exception("GPS detector on_detect callback failed")

        return GpsDetectionResult(
            triggered=triggered,
            anomaly_count=anomaly_count,
            speed=speed,
            distance=distance,
            corridor_dist=corridor_dist,
            speed_anomaly=speed_anomaly,
            jump_anomaly=jump_anomaly,
            corridor_anomaly=corridor_anomaly,
            src_anomaly=src_anomaly,
            details=details,
        )
