"""
Ticketing Traffic Generator

Maintains a persistent TCP connection to the server and sends
random small bursts, exactly matching the ns-3 TicketingApp:

    Packet size       : 256 bytes
    Burst interval    : uniform(6.0, 20.0) seconds
    Packets per burst : uniform(1, 3)
    Reconnect delay   : 2 seconds on failure

The persistent-connection design avoids the known ns-3 OnOff TCP
reconnection crash documented in the simulation header.
"""

import logging
import os
import random
import socket
import struct
import threading
import time
from typing import Optional

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from jetson.constants import (
    TICKETING_PORT,
    TICKET_PACKET_SIZE,
    TICKET_MIN_INTERVAL,
    TICKET_MAX_INTERVAL,
    TICKET_MIN_BURST,
    TICKET_MAX_BURST,
    TICKET_RETRY_DELAY,
)

logger = logging.getLogger(__name__)


class TicketingGenerator(threading.Thread):
    """
    Thread that sends ticketing TCP bursts to the server.

    Parameters
    ----------
    server_ip : str
        IPv4 address of the receiving server.
    bus_id : int
        Bus identifier (for logging).
    server_port : int
        TCP port on the server (default from constants).
    """

    def __init__(
        self,
        server_ip: str,
        bus_id: int,
        server_port: int = TICKETING_PORT,
    ):
        super().__init__(daemon=True, name=f"Ticketing-bus{bus_id}")
        self._server_ip = server_ip
        self._server_port = server_port
        self._bus_id = bus_id
        self._stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main thread loop: connect, then send bursts at random intervals."""
        logger.info(
            "Ticketing started: bus_id=%d target=%s:%d",
            self._bus_id, self._server_ip, self._server_port,
        )

        while not self._stop_event.is_set():
            # Establish / re-establish connection
            if self._sock is None:
                if not self._connect():
                    # Connection failed; wait before retrying
                    self._stop_event.wait(timeout=TICKET_RETRY_DELAY)
                    continue

            # Wait a random interval before the next burst
            interval = random.uniform(TICKET_MIN_INTERVAL, TICKET_MAX_INTERVAL)
            if self._stop_event.wait(timeout=interval):
                break  # stop requested during wait

            # Send the burst
            self._send_burst()

        # Cleanup
        self._close()
        logger.info("Ticketing stopped: bus_id=%d", self._bus_id)

    def stop(self) -> None:
        """Signal the thread to stop and wait for it to finish."""
        self._stop_event.set()
        self.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _connect(self) -> bool:
        """
        Attempt to open a persistent TCP connection to the server.

        Returns True on success, False on failure.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((self._server_ip, self._server_port))
            sock.settimeout(None)
            self._sock = sock
            logger.info(
                "Ticketing connected: bus_id=%d -> %s:%d",
                self._bus_id, self._server_ip, self._server_port,
            )
            return True
        except OSError as exc:
            logger.warning(
                "Ticketing connect failed bus=%d: %s (retry in %.1fs)",
                self._bus_id, exc, TICKET_RETRY_DELAY,
            )
            return False

    def _close(self) -> None:
        """Close the TCP socket if open."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ------------------------------------------------------------------
    # Burst transmission  (matches ns-3 TicketingApp::SendBurst)
    # ------------------------------------------------------------------

    def _send_burst(self) -> None:
        """
        Send a random burst of 1-3 packets, each 256 bytes.

        On send failure the socket is closed so the main loop will
        reconnect before the next burst.
        """
        if self._sock is None:
            return

        num_packets = random.randint(TICKET_MIN_BURST, TICKET_MAX_BURST)
        logger.debug(
            "Ticketing burst bus=%d packets=%d",
            self._bus_id, num_packets,
        )

        for i in range(num_packets):
            # Build a 256-byte payload.  Content is not meaningful in
            # the ns-3 simulation (Create<Packet>(m_packetSize) fills
            # with zeros), so we use random bytes for realism.
            payload = os.urandom(TICKET_PACKET_SIZE)

            try:
                self._sock.sendall(payload)
            except OSError as exc:
                logger.warning(
                    "Ticketing send failed bus=%d pkt=%d/%d: %s",
                    self._bus_id, i + 1, num_packets, exc,
                )
                self._close()
                return

        logger.debug(
            "Ticketing burst sent bus=%d packets=%d bytes=%d",
            self._bus_id, num_packets, num_packets * TICKET_PACKET_SIZE,
        )
