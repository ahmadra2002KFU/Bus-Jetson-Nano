"""
Ticketing Receiver (Server-side)

TCP server on port 7000 that accepts connections from buses and
reads ticketing burst data.  Corresponds to the ns-3 PacketSink
application on TICKET_PORT.

Each bus maintains a single persistent TCP connection (matching
the ns-3 TicketingApp design).  The server accepts multiple
concurrent connections and handles each in a dedicated thread.
"""

import logging
import socket
import threading
import time
from typing import Tuple

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from jetson.constants import TICKETING_PORT

logger = logging.getLogger(__name__)

_RECV_BUFFER_SIZE = 4096


class TicketingReceiver(threading.Thread):
    """
    Thread that runs a TCP server to receive ticketing data.

    Parameters
    ----------
    bind_ip : str
        IP address to bind to (default "0.0.0.0").
    bind_port : int
        TCP port to listen on (default from constants).
    """

    def __init__(
        self,
        bind_ip: str = "0.0.0.0",
        bind_port: int = TICKETING_PORT,
    ):
        super().__init__(daemon=True, name="TicketingReceiver")
        self._bind_ip = bind_ip
        self._bind_port = bind_port
        self._stop_event = threading.Event()
        self._server_sock = None
        self._client_threads = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Accept TCP connections and spawn handler threads."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self._bind_ip, self._bind_port))
        self._server_sock.listen(64)
        self._server_sock.settimeout(1.0)

        logger.info(
            "Ticketing receiver listening on %s:%d",
            self._bind_ip, self._bind_port,
        )

        try:
            while not self._stop_event.is_set():
                try:
                    client_sock, addr = self._server_sock.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._stop_event.is_set():
                        break
                    logger.error("Ticketing accept error: %s", exc)
                    continue

                logger.info("Ticketing connection from %s:%d", addr[0], addr[1])
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                    name=f"TicketClient-{addr[0]}:{addr[1]}",
                )
                self._client_threads.append(t)
                t.start()

        finally:
            self._server_sock.close()
            logger.info("Ticketing receiver stopped.")

    def stop(self) -> None:
        """Signal the thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
        self.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Per-client handler
    # ------------------------------------------------------------------

    def _handle_client(
        self,
        client_sock: socket.socket,
        addr: Tuple[str, int],
    ) -> None:
        """Read data from a single ticketing client until disconnection."""
        total_bytes = 0
        try:
            client_sock.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    data = client_sock.recv(_RECV_BUFFER_SIZE)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._stop_event.is_set():
                        break
                    logger.warning(
                        "Ticketing recv error from %s:%d: %s",
                        addr[0], addr[1], exc,
                    )
                    break

                if not data:
                    # Client disconnected
                    break

                nbytes = len(data)
                total_bytes += nbytes
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

                msg = (
                    f"[{ts}] Ticketing RX: bytes={nbytes} "
                    f"total={total_bytes} src={addr[0]}:{addr[1]}"
                )
                logger.info(msg)
                print(msg)

        finally:
            client_sock.close()
            logger.info(
                "Ticketing client %s:%d disconnected. Total: %d bytes",
                addr[0], addr[1], total_bytes,
            )


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    receiver = TicketingReceiver()
    try:
        receiver.start()
        receiver.join()
    except KeyboardInterrupt:
        receiver.stop()
