"""
GPS Telemetry Traffic Generator

Sends 200-byte GPS telemetry packets over UDP at 1 Hz, exactly matching
the ns-3 GpsTelemetryApp packet format:

    Offset  Size  Field
    ------  ----  -----
    0       4     magic   (uint32 LE, 0x47505331 = "GPS1")
    4       4     bus_id  (uint32 LE)
    8       8     pos_x   (float64 LE, double)
    16      8     pos_y   (float64 LE, double)
    24      176   padding (zero bytes)

Bus mobility is simulated by advancing through route waypoints at
11.1 m/s with 30-second station stops, mirroring the ns-3
WaypointMobilityModel configuration in SetupBusMobility.
"""

import logging
import math
import socket
import struct
import threading
import time
from typing import List, Optional, Tuple

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from jetson.constants import (
    GPS_TELEMETRY_PORT,
    GPS_PAYLOAD_MAGIC,
    GPS_PACKET_SIZE,
    GPS_SEND_INTERVAL,
    BUS_SPEED_MS,
    STATION_STOP_TIME,
)

logger = logging.getLogger(__name__)


class GpsTelemetryGenerator(threading.Thread):
    """
    Thread that sends GPS telemetry UDP packets to the server.

    Parameters
    ----------
    server_ip : str
        IPv4 address of the receiving server.
    bus_id : int
        Unique bus identifier (0-based, matching ns-3 bus indices).
    route_waypoints : list of (float, float)
        Ordered list of (x, y) station coordinates the bus visits.
        The bus travels forward through all waypoints, then reverses
        back (ping-pong), matching ns-3 cycle behavior.
    server_port : int
        UDP port on the server (default from constants).
    send_interval : float
        Seconds between packets (default 1.0).
    """

    def __init__(
        self,
        server_ip: str,
        bus_id: int,
        route_waypoints: List[Tuple[float, float]],
        server_port: int = GPS_TELEMETRY_PORT,
        send_interval: float = GPS_SEND_INTERVAL,
    ):
        super().__init__(daemon=True, name=f"GPSTelemetry-bus{bus_id}")
        self._server_ip = server_ip
        self._server_port = server_port
        self._bus_id = bus_id
        self._send_interval = send_interval
        self._stop_event = threading.Event()

        # Build the ping-pong cycle index list matching ns-3 logic:
        #   forward: 0, 1, 2, ..., N-1
        #   reverse: N-2, N-3, ..., 1
        self._waypoints = list(route_waypoints)
        self._cycle_indices: List[int] = []
        n = len(self._waypoints)
        if n > 0:
            self._cycle_indices = list(range(n))
            if n > 2:
                self._cycle_indices += list(range(n - 2, 0, -1))

        # Current simulated position state
        self._cycle_pos = 0          # index into _cycle_indices
        self._pos_x = 0.0
        self._pos_y = 0.0
        self._segment_progress = 0.0  # 0..1 progress along current segment
        self._at_station = True
        self._station_arrival_time: Optional[float] = None

        # Initialize position to first waypoint
        if self._waypoints:
            self._pos_x = self._waypoints[0][0]
            self._pos_y = self._waypoints[0][1]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main thread loop: send one GPS packet per interval."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            logger.info(
                "GPS telemetry started: bus_id=%d target=%s:%d interval=%.1fs",
                self._bus_id, self._server_ip, self._server_port,
                self._send_interval,
            )
            self._station_arrival_time = time.monotonic()

            while not self._stop_event.is_set():
                t_start = time.monotonic()

                # Advance simulated position
                self._advance_position(self._send_interval)

                # Build packet
                packet = self._build_packet()

                # Send
                try:
                    sock.sendto(packet, (self._server_ip, self._server_port))
                    logger.debug(
                        "GPS TX bus=%d pos=(%.1f, %.1f)",
                        self._bus_id, self._pos_x, self._pos_y,
                    )
                except OSError as exc:
                    logger.warning("GPS send error bus=%d: %s", self._bus_id, exc)

                # Pace to maintain interval
                elapsed = time.monotonic() - t_start
                sleep_time = self._send_interval - elapsed
                if sleep_time > 0:
                    self._stop_event.wait(timeout=sleep_time)

        finally:
            sock.close()
            logger.info("GPS telemetry stopped: bus_id=%d", self._bus_id)

    def stop(self) -> None:
        """Signal the thread to stop and wait for it to finish."""
        self._stop_event.set()
        self.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Packet construction  (matches ns-3 GpsTelemetryApp::SendPacket)
    # ------------------------------------------------------------------

    def _build_packet(self) -> bytes:
        """
        Build a 200-byte GPS telemetry packet.

        Layout (little-endian, matching ns-3 memcpy on x86/ARM):
            [0:4]    uint32  magic   = 0x47505331
            [4:8]    uint32  bus_id
            [8:16]   float64 pos_x
            [16:24]  float64 pos_y
            [24:200] zero padding
        """
        header = struct.pack('<IIdd', GPS_PAYLOAD_MAGIC, self._bus_id,
                             self._pos_x, self._pos_y)
        padding = b'\x00' * (GPS_PACKET_SIZE - len(header))
        return header + padding

    # ------------------------------------------------------------------
    # Simulated mobility  (mirrors ns-3 WaypointMobilityModel behavior)
    # ------------------------------------------------------------------

    def _advance_position(self, dt: float) -> None:
        """
        Advance the simulated bus position by *dt* seconds.

        Behaviour replicates ns-3 SetupBusMobility:
        - Travel between waypoints at BUS_SPEED_MS (11.1 m/s).
        - Stop at each station for STATION_STOP_TIME (30 s).
        - Ping-pong along the route (forward then reverse).
        """
        if not self._cycle_indices:
            return

        remaining = dt

        while remaining > 0:
            if self._at_station:
                # Currently stopped at a station
                time_at_station = time.monotonic() - self._station_arrival_time
                wait_left = STATION_STOP_TIME - time_at_station
                if wait_left <= 0:
                    # Done waiting -- start moving to next waypoint
                    self._at_station = False
                    self._segment_progress = 0.0
                    remaining -= 0.0  # no time consumed, just state change
                else:
                    # Still waiting at station; consume remaining dt
                    break
            else:
                # Currently travelling between waypoints
                cur_idx = self._cycle_indices[self._cycle_pos]
                next_cycle_pos = (self._cycle_pos + 1) % len(self._cycle_indices)
                next_idx = self._cycle_indices[next_cycle_pos]

                cx, cy = self._waypoints[cur_idx]
                nx, ny = self._waypoints[next_idx]
                seg_len = math.hypot(nx - cx, ny - cy)

                if seg_len < 1e-6:
                    # Degenerate segment; skip to next station
                    self._cycle_pos = next_cycle_pos
                    self._at_station = True
                    self._station_arrival_time = time.monotonic()
                    self._pos_x = nx
                    self._pos_y = ny
                    continue

                # How far (in metres) can we travel with remaining time?
                travel_dist = BUS_SPEED_MS * remaining
                dist_left_in_seg = seg_len * (1.0 - self._segment_progress)

                if travel_dist >= dist_left_in_seg:
                    # Arrive at next station
                    time_to_arrive = dist_left_in_seg / BUS_SPEED_MS
                    remaining -= time_to_arrive
                    self._cycle_pos = next_cycle_pos
                    self._pos_x = nx
                    self._pos_y = ny
                    self._at_station = True
                    self._station_arrival_time = time.monotonic()
                    self._segment_progress = 0.0
                else:
                    # Partial progress within segment
                    self._segment_progress += travel_dist / seg_len
                    frac = self._segment_progress
                    self._pos_x = cx + frac * (nx - cx)
                    self._pos_y = cy + frac * (ny - cy)
                    remaining = 0.0
