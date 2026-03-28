"""
Al-Ahsa Smart Bus — Heartbeat probe (UDP echo) thread.

Sends 12-byte UDP probes to the server every 1 second and listens for
echoed replies.  Tracks packet loss and RTT over a sliding 10-second
window so that the DDoS detector can query network health.

Probe wire format (little-endian):
    [0..3]  uint32  sequence number
    [4..11] double  monotonic timestamp (seconds)

The server is expected to echo the exact 12 bytes back on the same
port (5001).
"""

import logging
import socket
import struct
import threading
import time
from typing import List

logger = logging.getLogger(__name__)

# Wire format: little-endian uint32 + double = 12 bytes
_PROBE_FMT = "<Id"
_PROBE_SIZE = struct.calcsize(_PROBE_FMT)  # 12

_SEND_INTERVAL = 1.0       # seconds between probes
_WINDOW_DURATION = 10.0     # seconds per measurement window


class HeartbeatProbe:
    """Thread that sends UDP probes and measures loss / RTT."""

    def __init__(self, server_ip: str, server_port: int = 5001):
        self._server_ip = server_ip
        self._server_port = server_port

        # Stop signal
        self._stop_event = threading.Event()

        # Per-window counters (protected by _lock)
        self._lock = threading.Lock()
        self._sent_count: int = 0
        self._acked_count: int = 0
        self._rtt_samples: List[float] = []

        # Sequence counter (only touched by sender thread)
        self._seq: int = 0

        # Threads
        self._send_thread: threading.Thread | None = None
        self._recv_thread: threading.Thread | None = None

        # Socket (created on start)
        self._sock: socket.socket | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the sender and receiver threads."""
        self._stop_event.clear()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(1.0)  # recv timeout so thread can check stop
        # Bind to any available port for receiving echoes
        self._sock.bind(("", 0))

        self._send_thread = threading.Thread(
            target=self._send_loop, daemon=True, name="heartbeat-tx"
        )
        self._recv_thread = threading.Thread(
            target=self._recv_loop, daemon=True, name="heartbeat-rx"
        )
        self._send_thread.start()
        self._recv_thread.start()
        logger.info(
            "Heartbeat started -> %s:%d", self._server_ip, self._server_port
        )

    def stop(self) -> None:
        """Signal both threads to stop and close the socket."""
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._send_thread:
            self._send_thread.join(timeout=3.0)
        if self._recv_thread:
            self._recv_thread.join(timeout=3.0)
        logger.info("Heartbeat stopped")

    def get_interval_loss(self) -> float:
        """Return packet loss ratio for the last window (0.0 -- 1.0).

        Resets the window counters after the call.
        """
        with self._lock:
            sent = self._sent_count
            acked = self._acked_count
            # Reset for next window
            self._sent_count = 0
            self._acked_count = 0
            self._rtt_samples.clear()

        if sent == 0:
            return 0.0
        lost = sent - acked
        return max(0.0, min(1.0, lost / sent))

    def get_avg_rtt(self) -> float:
        """Return average RTT in seconds for the last window.

        Does NOT reset counters (call get_interval_loss for that).
        """
        with self._lock:
            samples = list(self._rtt_samples)
        if not samples:
            return 0.0
        return sum(samples) / len(samples)

    # ------------------------------------------------------------------
    # Internal threads
    # ------------------------------------------------------------------

    def _send_loop(self) -> None:
        """Send one probe per second until stopped."""
        while not self._stop_event.is_set():
            try:
                seq = self._seq
                self._seq += 1
                ts = time.monotonic()
                payload = struct.pack(_PROBE_FMT, seq, ts)
                self._sock.sendto(
                    payload, (self._server_ip, self._server_port)
                )
                with self._lock:
                    self._sent_count += 1
                logger.debug("Heartbeat TX seq=%d", seq)
            except OSError as exc:
                if self._stop_event.is_set():
                    break
                logger.warning("Heartbeat send error: %s", exc)

            # Sleep in small increments so stop is responsive
            self._stop_event.wait(timeout=_SEND_INTERVAL)

    def _recv_loop(self) -> None:
        """Receive echoed probes and record RTT."""
        while not self._stop_event.is_set():
            try:
                data, _addr = self._sock.recvfrom(64)
                recv_ts = time.monotonic()
                if len(data) < _PROBE_SIZE:
                    continue
                _seq, send_ts = struct.unpack(_PROBE_FMT, data[:_PROBE_SIZE])
                rtt = recv_ts - send_ts
                if rtt < 0:
                    continue  # clock anomaly
                with self._lock:
                    self._acked_count += 1
                    self._rtt_samples.append(rtt)
                logger.debug("Heartbeat RX seq=%d rtt=%.4fs", _seq, rtt)
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                # Socket closed or other error
                continue
