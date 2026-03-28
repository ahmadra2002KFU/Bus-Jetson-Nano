"""
GPS Telemetry Receiver (Server-side)

Listens on UDP port 5000 for GPS telemetry packets from buses.
Parses the 200-byte packet format defined in the ns-3 simulation:

    Offset  Size  Field
    ------  ----  -----
    0       4     magic   (uint32 LE, must be 0x47505331)
    4       4     bus_id  (uint32 LE)
    8       8     pos_x   (float64 LE)
    16      8     pos_y   (float64 LE)
    24      176   padding (ignored)

Validates the magic number before processing.  Logs every received
packet with timestamp, bus_id, position, and source IP.
"""

import logging
import math
import socket
import struct
import threading
import time
from typing import Tuple

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from jetson.constants import (
    GPS_TELEMETRY_PORT,
    GPS_PAYLOAD_MAGIC,
    GPS_PAYLOAD_MIN_SIZE,
    GPS_PACKET_SIZE,
)

logger = logging.getLogger(__name__)

# Struct format for the GPS header: magic(uint32) + bus_id(uint32) + pos_x(double) + pos_y(double)
_GPS_HEADER_FMT = '<IIdd'
_GPS_HEADER_SIZE = struct.calcsize(_GPS_HEADER_FMT)  # 24 bytes


class GpsReceiver(threading.Thread):
    """
    Thread that receives and parses GPS telemetry packets.

    Parameters
    ----------
    bind_ip : str
        IP address to bind to (default "0.0.0.0" for all interfaces).
    bind_port : int
        UDP port to listen on (default from constants).
    """

    def __init__(
        self,
        bind_ip: str = "0.0.0.0",
        bind_port: int = GPS_TELEMETRY_PORT,
    ):
        super().__init__(daemon=True, name="GpsReceiver")
        self._bind_ip = bind_ip
        self._bind_port = bind_port
        self._stop_event = threading.Event()
        self._sock = None
        self._packet_count = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main receive loop."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._bind_ip, self._bind_port))
        self._sock.settimeout(1.0)  # allow periodic stop-event checks

        logger.info(
            "GPS receiver listening on %s:%d",
            self._bind_ip, self._bind_port,
        )

        try:
            while not self._stop_event.is_set():
                try:
                    data, addr = self._sock.recvfrom(GPS_PACKET_SIZE + 64)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._stop_event.is_set():
                        break
                    logger.error("GPS recv error: %s", exc)
                    continue

                self._handle_packet(data, addr)

        finally:
            self._sock.close()
            logger.info(
                "GPS receiver stopped. Total packets: %d", self._packet_count,
            )

    def stop(self) -> None:
        """Signal the thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Packet parsing  (matches ns-3 GpsDetectorApp::HandleRead)
    # ------------------------------------------------------------------

    def _handle_packet(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Parse and log a single GPS telemetry packet."""
        if len(data) < GPS_PAYLOAD_MIN_SIZE:
            logger.debug(
                "GPS packet too small (%d bytes) from %s, discarding",
                len(data), addr[0],
            )
            return

        magic, bus_id, pos_x, pos_y = struct.unpack_from(_GPS_HEADER_FMT, data)

        # Magic number check (matches ns-3: if (magic != GPS_PAYLOAD_MAGIC) continue;)
        if magic != GPS_PAYLOAD_MAGIC:
            logger.debug(
                "GPS packet bad magic 0x%08X from %s, discarding",
                magic, addr[0],
            )
            return

        # Sanity check on position values (matches ns-3 isfinite check)
        if not (math.isfinite(pos_x) and math.isfinite(pos_y)):
            logger.warning(
                "GPS packet non-finite position from bus %d, discarding",
                bus_id,
            )
            return

        self._packet_count += 1
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Log and print every received packet
        msg = (
            f"[{ts}] GPS RX: bus_id={bus_id:3d} "
            f"pos=({pos_x:10.1f}, {pos_y:10.1f}) "
            f"src={addr[0]}:{addr[1]}"
        )
        logger.info(msg)
        print(msg)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    receiver = GpsReceiver()
    try:
        receiver.start()
        receiver.join()
    except KeyboardInterrupt:
        receiver.stop()
