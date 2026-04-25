"""Edge-side GPS spoof detector.

Runs locally on the Jetson against the bus's OWN outgoing GPS positions.
Models the threat where an RF attacker near the vehicle spoofs the bus's
GPS receiver, so the bus's reported position no longer matches its
assigned route.

Differences from the server-side detector:
- No source-address check — there is only one source, the bus itself.
- The 4-check from the simulation collapses to 3 (speed / jump /
  corridor); src_addr is N/A.
- Auto-clears after a clean streak so the same agent can detect a
  second spoof attack later in the same run, mirroring the DDoS
  detector's clear path.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from jetson.utils import distance_to_route, euclidean_distance

logger = logging.getLogger(__name__)

SPEED_THRESHOLD = 22.2          # m/s (80 km/h)
JUMP_THRESHOLD = 1000.0         # meters
CORRIDOR_THRESHOLD = 1500.0     # meters
STREAK_REQUIRED = 3
CLEAR_STREAK_REQUIRED = 5
NOISE_MIN_DT_S = 0.5


class EdgeGpsDetector:
    """Synchronous per-bus GPS spoofing detector for the edge.

    Feed it each outgoing GPS position via :meth:`feed`. On the third
    consecutive anomalous reading the ``callback`` fires once. After
    ``clear_streak_required`` consecutive clean readings the latch
    clears and the optional ``cleared`` callback fires.
    """

    def __init__(
        self,
        *,
        bus_id: int,
        route_polyline: List[Tuple[float, float]],
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        cleared: Optional[Callable[[], None]] = None,
        speed_threshold: float = SPEED_THRESHOLD,
        jump_threshold: float = JUMP_THRESHOLD,
        corridor_threshold: float = CORRIDOR_THRESHOLD,
        streak_required: int = STREAK_REQUIRED,
        clear_streak_required: int = CLEAR_STREAK_REQUIRED,
    ) -> None:
        self._bus_id = bus_id
        self._route = list(route_polyline)
        self._callback = callback
        self._cleared = cleared
        self._speed_t = speed_threshold
        self._jump_t = jump_threshold
        self._corridor_t = corridor_threshold
        self._streak_required = max(1, int(streak_required))
        self._clear_required = max(1, int(clear_streak_required))

        self._lock = threading.Lock()
        self._initialized = False
        self._last_pos: Tuple[float, float] = (0.0, 0.0)
        self._last_ts: float = 0.0
        self._anomaly_streak = 0
        self._clean_streak = 0
        self._detected = threading.Event()
        self._last_details: Dict[str, Any] = {}

    @property
    def detected(self) -> threading.Event:
        return self._detected

    def get_last_details(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._last_details)

    def reset(self) -> None:
        """Drop all state. Useful when a spoof injection ends and the
        next legit position would otherwise cause a huge speed jump."""
        with self._lock:
            self._initialized = False
            self._last_pos = (0.0, 0.0)
            self._last_ts = 0.0
            self._anomaly_streak = 0
            self._clean_streak = 0
            self._detected.clear()
            self._last_details = {}

    def feed(self, pos_x: float, pos_y: float, ts: Optional[float] = None) -> None:
        """Process one GPS position the bus is reporting outward."""
        ts = ts if ts is not None else time.time()

        triggered = False
        cleared_now = False
        details: Dict[str, Any] = {}

        with self._lock:
            if not self._initialized:
                self._last_pos = (pos_x, pos_y)
                self._last_ts = ts
                self._initialized = True
                return

            dt = ts - self._last_ts
            if dt <= 0 or dt < NOISE_MIN_DT_S:
                return

            distance = euclidean_distance(self._last_pos[0], self._last_pos[1], pos_x, pos_y)
            speed = distance / dt
            corridor_dist = (
                distance_to_route(pos_x, pos_y, self._route) if self._route else 0.0
            )

            speed_anom = speed > self._speed_t
            jump_anom = (dt <= 1.5) and (distance > self._jump_t)
            corridor_anom = corridor_dist > self._corridor_t
            is_anom = speed_anom or jump_anom or corridor_anom

            if is_anom:
                self._anomaly_streak += 1
                self._clean_streak = 0
            else:
                self._clean_streak += 1
                self._anomaly_streak = 0

            details = {
                "type": "gps_spoof",
                "bus_id": self._bus_id,
                "speed": speed,
                "distance": distance,
                "corridor_dist": corridor_dist,
                "speed_anomaly": speed_anom,
                "jump_anomaly": jump_anom,
                "corridor_anomaly": corridor_anom,
                "streak": self._anomaly_streak,
                "timestamp": ts,
            }

            if not self._detected.is_set():
                if self._anomaly_streak >= self._streak_required:
                    self._detected.set()
                    self._last_details = details
                    triggered = True
            else:
                if self._clean_streak >= self._clear_required:
                    self._detected.clear()
                    self._anomaly_streak = 0
                    self._clean_streak = 0
                    cleared_now = True

            self._last_pos = (pos_x, pos_y)
            self._last_ts = ts

        if triggered:
            logger.warning(
                "[EDGE GPS SPOOF] bus=%d corridor=%.0fm speed=%.1f m/s streak=%d",
                self._bus_id, details["corridor_dist"], details["speed"], details["streak"],
            )
            if self._callback:
                try:
                    self._callback(details)
                except Exception:
                    logger.exception("edge gps callback error")
        if cleared_now:
            logger.info("[EDGE GPS SPOOF CLEARED] bus=%d", self._bus_id)
            if self._cleared:
                try:
                    self._cleared()
                except Exception:
                    logger.exception("edge gps cleared callback error")
