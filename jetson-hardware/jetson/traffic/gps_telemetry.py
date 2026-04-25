"""GPS telemetry — WebSocket transport.

Sends 200-byte binary GPS frames (ns-3 wire format) to
``{server_url}/ingest/gps`` once per second, with automatic reconnect
on connection loss. Keeps the 41-bus ping-pong mobility from the
simulation: advance through waypoints at 11.1 m/s, 30-s station stops.

Wire format (little-endian, 200 bytes):
    [0..3]   uint32   magic   = 0x47505331  ("GPS1")
    [4..7]   uint32   bus_id
    [8..15]  float64  pos_x
    [16..23] float64  pos_y
    [24..199] zero padding
"""

from __future__ import annotations

import logging
import math
import random
import struct
import threading
import time
from collections import deque
from typing import Deque, List, Optional, Tuple

import websocket  # from websocket-client

from jetson.constants import (
    BUS_SPEED_MS,
    GPS_PACKET_SIZE,
    GPS_PAYLOAD_MAGIC,
    GPS_SEND_INTERVAL,
    STATION_STOP_TIME,
)

logger = logging.getLogger(__name__)


def _to_ws_url(server_url: str, path: str) -> str:
    base = server_url.rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    return base + path


class GpsTelemetry(threading.Thread):
    """WebSocket-based GPS telemetry generator (1 Hz).

    Parameters
    ----------
    server_url : str
        Base URL of the server (e.g. ``https://example.com``). The WS path
        ``/ingest/gps`` is appended.
    bus_id : int
        Unique bus identifier.
    route_waypoints : list[tuple[float, float]]
        Ordered station coordinates the bus visits; ping-pong traversal.
    send_interval : float
        Seconds between packets (default 1.0).
    """

    def __init__(
        self,
        *,
        server_url: str,
        bus_id: int,
        route_waypoints: List[Tuple[float, float]],
        send_interval: float = GPS_SEND_INTERVAL,
    ):
        super().__init__(daemon=True, name=f"GPSTelemetry-bus{bus_id}")
        self._url = _to_ws_url(server_url, "/ingest/gps")
        self._bus_id = bus_id
        self._send_interval = send_interval
        self._stop_event = threading.Event()
        self._ws: Optional[websocket.WebSocket] = None

        # Buffer held during disconnects (max ~100 frames, drop oldest)
        self._outbox: Deque[bytes] = deque(maxlen=100)

        # Mobility state
        self._waypoints = list(route_waypoints)
        self._cycle_indices: List[int] = []
        n = len(self._waypoints)
        if n > 0:
            self._cycle_indices = list(range(n))
            if n > 2:
                self._cycle_indices += list(range(n - 2, 0, -1))
        self._cycle_pos = 0
        self._pos_x = self._waypoints[0][0] if n else 0.0
        self._pos_y = self._waypoints[0][1] if n else 0.0
        self._segment_progress = 0.0
        self._at_station = True
        self._station_arrival_time: Optional[float] = None

        # Expose the last-N positions for forensic PDF consumers
        self._trace_lock = threading.Lock()
        self._trace: Deque[Tuple[float, float]] = deque(maxlen=60)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> None:
        logger.info("GPS telemetry start bus=%d url=%s", self._bus_id, self._url)
        self._station_arrival_time = time.monotonic()
        backoff = 1.0
        while not self._stop_event.is_set():
            try:
                self._ws = websocket.create_connection(self._url, timeout=10)
                logger.info("GPS WS connected bus=%d", self._bus_id)
                backoff = 1.0
                self._run_send_loop()
            except Exception as exc:
                if self._stop_event.is_set():
                    break
                logger.warning("GPS WS error bus=%d: %s (backoff %.1fs)",
                               self._bus_id, exc, backoff)
                self._close_ws()
                sleep_for = min(backoff, 60.0) * random.uniform(0.7, 1.3)
                self._stop_event.wait(timeout=sleep_for)
                backoff = min(backoff * 2.0, 60.0)
        self._close_ws()
        logger.info("GPS telemetry stop bus=%d", self._bus_id)

    def stop(self) -> None:
        self._stop_event.set()
        self._close_ws()
        self.join(timeout=5.0)

    def get_recent_trace(self) -> List[Tuple[float, float]]:
        with self._trace_lock:
            return list(self._trace)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_send_loop(self) -> None:
        # Drain any buffered frames first
        while self._outbox and not self._stop_event.is_set():
            self._ws.send_binary(self._outbox[0])
            self._outbox.popleft()

        while not self._stop_event.is_set():
            t_start = time.monotonic()
            self._advance_position(self._send_interval)
            packet = self._build_packet()
            try:
                self._ws.send_binary(packet)
            except Exception as exc:
                logger.warning("GPS WS send bus=%d failed: %s", self._bus_id, exc)
                self._outbox.append(packet)
                raise

            with self._trace_lock:
                self._trace.append((self._pos_x, self._pos_y))

            elapsed = time.monotonic() - t_start
            sleep_time = self._send_interval - elapsed
            if sleep_time > 0:
                self._stop_event.wait(timeout=sleep_time)

    def _close_ws(self) -> None:
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None

    def _build_packet(self) -> bytes:
        header = struct.pack(
            "<IIdd", GPS_PAYLOAD_MAGIC, self._bus_id, self._pos_x, self._pos_y
        )
        return header + b"\x00" * (GPS_PACKET_SIZE - len(header))

    def _advance_position(self, dt: float) -> None:
        if not self._cycle_indices:
            return
        remaining = dt
        while remaining > 0:
            if self._at_station:
                time_at = time.monotonic() - (self._station_arrival_time or 0)
                wait_left = STATION_STOP_TIME - time_at
                if wait_left <= 0:
                    self._at_station = False
                    self._segment_progress = 0.0
                else:
                    break
            else:
                cur_idx = self._cycle_indices[self._cycle_pos]
                next_pos = (self._cycle_pos + 1) % len(self._cycle_indices)
                next_idx = self._cycle_indices[next_pos]
                cx, cy = self._waypoints[cur_idx]
                nx, ny = self._waypoints[next_idx]
                seg_len = math.hypot(nx - cx, ny - cy)
                if seg_len < 1e-6:
                    self._cycle_pos = next_pos
                    self._at_station = True
                    self._station_arrival_time = time.monotonic()
                    self._pos_x, self._pos_y = nx, ny
                    continue
                travel = BUS_SPEED_MS * remaining
                dist_left = seg_len * (1.0 - self._segment_progress)
                if travel >= dist_left:
                    remaining -= dist_left / BUS_SPEED_MS
                    self._cycle_pos = next_pos
                    self._pos_x, self._pos_y = nx, ny
                    self._at_station = True
                    self._station_arrival_time = time.monotonic()
                    self._segment_progress = 0.0
                else:
                    self._segment_progress += travel / seg_len
                    frac = self._segment_progress
                    self._pos_x = cx + frac * (nx - cx)
                    self._pos_y = cy + frac * (ny - cy)
                    remaining = 0.0
