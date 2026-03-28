"""
Forensic Evidence Receiver (Server-side)

TCP server on port 8000 that accepts forensic evidence uploads
from buses after an attack is detected.  Corresponds to the ns-3
PacketSink on FORENSIC_PORT plus the BulkSend upload of 10 MB.

Accepts one connection at a time.  Reads until either:
  - 10,485,760 bytes (10 MB) have been received, or
  - the connection closes.

Writes received data to a timestamped file:
    evidence_busX_<timestamp>.bin

Logs progress every 1 MB received.
"""

import logging
import os
import socket
import threading
import time
from typing import Tuple

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from jetson.constants import (
    FORENSIC_PORT,
    FORENSIC_TOTAL_BYTES,
)

logger = logging.getLogger(__name__)

_RECV_BUFFER_SIZE = 8192
_PROGRESS_INTERVAL = 1_048_576  # 1 MB -- log progress at each MB boundary


class ForensicReceiver(threading.Thread):
    """
    Thread that runs a TCP server to receive forensic evidence uploads.

    Parameters
    ----------
    bind_ip : str
        IP address to bind to (default "0.0.0.0").
    bind_port : int
        TCP port to listen on (default from constants).
    output_dir : str
        Directory to write evidence files (default current directory).
    """

    def __init__(
        self,
        bind_ip: str = "0.0.0.0",
        bind_port: int = FORENSIC_PORT,
        output_dir: str = ".",
    ):
        super().__init__(daemon=True, name="ForensicReceiver")
        self._bind_ip = bind_ip
        self._bind_port = bind_port
        self._output_dir = output_dir
        self._stop_event = threading.Event()
        self._server_sock = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Accept one connection at a time and receive evidence data."""
        os.makedirs(self._output_dir, exist_ok=True)

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self._bind_ip, self._bind_port))
        self._server_sock.listen(1)  # one connection at a time
        self._server_sock.settimeout(1.0)

        logger.info(
            "Forensic receiver listening on %s:%d (output: %s)",
            self._bind_ip, self._bind_port, self._output_dir,
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
                    logger.error("Forensic accept error: %s", exc)
                    continue

                logger.info(
                    "Forensic upload started from %s:%d", addr[0], addr[1],
                )
                self._handle_upload(client_sock, addr)

        finally:
            self._server_sock.close()
            logger.info("Forensic receiver stopped.")

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
    # Upload handler
    # ------------------------------------------------------------------

    def _handle_upload(
        self,
        client_sock: socket.socket,
        addr: Tuple[str, int],
    ) -> None:
        """
        Receive up to FORENSIC_TOTAL_BYTES from a single client.

        Writes data to evidence_busX_<timestamp>.bin and logs
        progress at every 1 MB boundary.
        """
        timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        # Use source port as a proxy bus identifier in the filename;
        # a real deployment would pass bus_id in a header.
        filename = f"evidence_bus{addr[1]}_{timestamp_str}.bin"
        filepath = os.path.join(self._output_dir, filename)

        total_received = 0
        last_progress_mb = 0

        try:
            client_sock.settimeout(2.0)
            with open(filepath, 'wb') as f:
                while (
                    not self._stop_event.is_set()
                    and total_received < FORENSIC_TOTAL_BYTES
                ):
                    remaining = FORENSIC_TOTAL_BYTES - total_received
                    to_read = min(_RECV_BUFFER_SIZE, remaining)

                    try:
                        data = client_sock.recv(to_read)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        if self._stop_event.is_set():
                            break
                        logger.warning(
                            "Forensic recv error from %s:%d: %s",
                            addr[0], addr[1], exc,
                        )
                        break

                    if not data:
                        # Connection closed by client
                        logger.info(
                            "Forensic client %s:%d closed connection "
                            "after %d bytes",
                            addr[0], addr[1], total_received,
                        )
                        break

                    f.write(data)
                    total_received += len(data)

                    # Log progress every 1 MB
                    current_mb = total_received // _PROGRESS_INTERVAL
                    if current_mb > last_progress_mb:
                        last_progress_mb = current_mb
                        msg = (
                            f"Forensic progress: {total_received:,} / "
                            f"{FORENSIC_TOTAL_BYTES:,} bytes "
                            f"({total_received * 100 / FORENSIC_TOTAL_BYTES:.1f}%) "
                            f"from {addr[0]}:{addr[1]}"
                        )
                        logger.info(msg)
                        print(msg)

        finally:
            client_sock.close()

        status = "COMPLETE" if total_received >= FORENSIC_TOTAL_BYTES else "PARTIAL"
        msg = (
            f"Forensic upload {status}: {total_received:,} bytes -> {filepath}"
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
    receiver = ForensicReceiver(output_dir="./evidence")
    try:
        receiver.start()
        receiver.join()
    except KeyboardInterrupt:
        receiver.stop()
