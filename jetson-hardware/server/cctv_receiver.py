"""
CCTV Stream Receiver (Server-side)

Listens on UDP port 6000 for CCTV video data from buses.
Counts bytes received per second and logs aggregate throughput
every 5 seconds.

This corresponds to the ns-3 UdpServer application installed on
the remote server for CCTV traffic.
"""

import logging
import socket
import threading
import time

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from jetson.constants import (
    CCTV_PORT,
    CCTV_PACKET_SIZE,
)

logger = logging.getLogger(__name__)

# How often (seconds) to log throughput statistics
_LOG_INTERVAL = 5.0


class CctvReceiver(threading.Thread):
    """
    Thread that receives CCTV UDP packets and tracks throughput.

    Parameters
    ----------
    bind_ip : str
        IP address to bind to (default "0.0.0.0").
    bind_port : int
        UDP port to listen on (default from constants).
    """

    def __init__(
        self,
        bind_ip: str = "0.0.0.0",
        bind_port: int = CCTV_PORT,
    ):
        super().__init__(daemon=True, name="CctvReceiver")
        self._bind_ip = bind_ip
        self._bind_port = bind_port
        self._stop_event = threading.Event()
        self._sock = None

        # Throughput tracking
        self._lock = threading.Lock()
        self._bytes_in_window = 0
        self._packets_in_window = 0
        self._total_bytes = 0
        self._total_packets = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main receive loop with periodic throughput logging."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Increase receive buffer to handle 1 Mbps * N buses without drops
        try:
            self._sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024,
            )
        except OSError:
            pass  # best-effort; not critical
        self._sock.bind((self._bind_ip, self._bind_port))
        self._sock.settimeout(1.0)

        logger.info(
            "CCTV receiver listening on %s:%d",
            self._bind_ip, self._bind_port,
        )

        # Start the periodic logger in a sub-thread
        log_thread = threading.Thread(
            target=self._throughput_logger, daemon=True,
            name="CctvThroughputLogger",
        )
        log_thread.start()

        try:
            while not self._stop_event.is_set():
                try:
                    data, _addr = self._sock.recvfrom(CCTV_PACKET_SIZE + 64)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._stop_event.is_set():
                        break
                    logger.error("CCTV recv error: %s", exc)
                    continue

                nbytes = len(data)
                with self._lock:
                    self._bytes_in_window += nbytes
                    self._packets_in_window += 1
                    self._total_bytes += nbytes
                    self._total_packets += 1

        finally:
            self._sock.close()
            logger.info(
                "CCTV receiver stopped. Total: %d packets, %d bytes",
                self._total_packets, self._total_bytes,
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
    # Throughput logger
    # ------------------------------------------------------------------

    def _throughput_logger(self) -> None:
        """Periodically log throughput statistics every 5 seconds."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=_LOG_INTERVAL)
            if self._stop_event.is_set():
                break

            with self._lock:
                window_bytes = self._bytes_in_window
                window_pkts = self._packets_in_window
                self._bytes_in_window = 0
                self._packets_in_window = 0
                total_bytes = self._total_bytes
                total_pkts = self._total_packets

            throughput_bps = (window_bytes * 8.0) / _LOG_INTERVAL
            throughput_mbps = throughput_bps / 1e6

            msg = (
                f"CCTV throughput: {throughput_mbps:.2f} Mbps "
                f"({window_pkts} pkts / {_LOG_INTERVAL:.0f}s) | "
                f"Total: {total_pkts} pkts, {total_bytes} bytes"
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
    receiver = CctvReceiver()
    try:
        receiver.start()
        receiver.join()
    except KeyboardInterrupt:
        receiver.stop()
