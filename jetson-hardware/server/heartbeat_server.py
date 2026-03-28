"""
Heartbeat Echo Server (Server-side)

Listens on UDP port 5001 for 12-byte heartbeat probes from buses
and echoes each probe back immediately.  This enables the Jetson
to measure round-trip latency.

Logs the aggregate heartbeat count every 30 seconds.

Note: The ns-3 simulation does not explicitly model heartbeat
traffic.  This service is an addition for the real deployment to
provide bus-level liveness and latency monitoring.
"""

import logging
import socket
import threading
import time

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from jetson.constants import HEARTBEAT_PORT

logger = logging.getLogger(__name__)

_HEARTBEAT_PROBE_SIZE = 12
_LOG_INTERVAL = 30.0  # seconds between count logs


class HeartbeatServer(threading.Thread):
    """
    Thread that echoes heartbeat probes and logs activity.

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
        bind_port: int = HEARTBEAT_PORT,
    ):
        super().__init__(daemon=True, name="HeartbeatServer")
        self._bind_ip = bind_ip
        self._bind_port = bind_port
        self._stop_event = threading.Event()
        self._sock = None

        # Counters
        self._lock = threading.Lock()
        self._window_count = 0
        self._total_count = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main receive-and-echo loop."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._bind_ip, self._bind_port))
        self._sock.settimeout(1.0)

        logger.info(
            "Heartbeat server listening on %s:%d",
            self._bind_ip, self._bind_port,
        )

        # Start the periodic count logger
        log_thread = threading.Thread(
            target=self._count_logger, daemon=True,
            name="HeartbeatCountLogger",
        )
        log_thread.start()

        try:
            while not self._stop_event.is_set():
                try:
                    data, addr = self._sock.recvfrom(_HEARTBEAT_PROBE_SIZE + 64)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._stop_event.is_set():
                        break
                    logger.error("Heartbeat recv error: %s", exc)
                    continue

                # Echo the probe back immediately
                try:
                    self._sock.sendto(data, addr)
                except OSError as exc:
                    logger.warning("Heartbeat echo error to %s: %s", addr, exc)
                    continue

                with self._lock:
                    self._window_count += 1
                    self._total_count += 1

        finally:
            self._sock.close()
            logger.info(
                "Heartbeat server stopped. Total probes: %d",
                self._total_count,
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
    # Periodic logger
    # ------------------------------------------------------------------

    def _count_logger(self) -> None:
        """Log heartbeat count every 30 seconds."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=_LOG_INTERVAL)
            if self._stop_event.is_set():
                break

            with self._lock:
                window = self._window_count
                self._window_count = 0
                total = self._total_count

            msg = (
                f"Heartbeat: {window} probes in last "
                f"{_LOG_INTERVAL:.0f}s | Total: {total}"
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
    server = HeartbeatServer()
    try:
        server.start()
        server.join()
    except KeyboardInterrupt:
        server.stop()
