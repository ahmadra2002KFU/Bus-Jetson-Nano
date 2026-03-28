"""
CCTV Video Stream Traffic Generator

Streams UDP packets at 1 Mbps to the server, matching the ns-3
OnOffHelper CCTV configuration:

    DataRate  = 1000 kbps  (1 Mbps)
    PacketSize = 1400 bytes
    OnTime   = constant 1  (always-on)
    OffTime  = constant 0

At 1 Mbps with 1400-byte packets the send rate is approximately
89.3 packets per second.  This module uses time.monotonic() for
precise pacing to stay within 1% of the target bitrate.

If a camera device is available, packets contain JPEG fragments.
Otherwise, random bytes are used as payload (matching simulation
where ns-3 OnOff fills with arbitrary data).
"""

import logging
import os
import socket
import threading
import time
from typing import Optional

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from jetson.constants import (
    CCTV_PORT,
    CCTV_BITRATE_BPS,
    CCTV_PACKET_SIZE,
)

logger = logging.getLogger(__name__)

# Derived constants
_PACKETS_PER_SECOND = CCTV_BITRATE_BPS / (CCTV_PACKET_SIZE * 8)
_PACKET_INTERVAL = 1.0 / _PACKETS_PER_SECOND  # ~0.0112 seconds


class CctvStreamGenerator(threading.Thread):
    """
    Thread that streams CCTV data over UDP at 1 Mbps.

    Parameters
    ----------
    server_ip : str
        IPv4 address of the receiving server.
    bus_id : int
        Bus identifier (for logging).
    server_port : int
        UDP port on the server (default from constants).
    camera_device : str or None
        Path to a camera device (e.g. "/dev/video0") for real JPEG
        frames.  When None, random bytes are transmitted instead.
    """

    def __init__(
        self,
        server_ip: str,
        bus_id: int,
        server_port: int = CCTV_PORT,
        camera_device: Optional[str] = None,
    ):
        super().__init__(daemon=True, name=f"CCTV-bus{bus_id}")
        self._server_ip = server_ip
        self._server_port = server_port
        self._bus_id = bus_id
        self._camera_device = camera_device
        self._stop_event = threading.Event()

        # Pre-generate a reusable random payload buffer for when no
        # camera is available.  Regenerated periodically to avoid
        # sending an identical pattern every packet.
        self._random_payload = os.urandom(CCTV_PACKET_SIZE)

        # Camera state (lazy-initialized in run())
        self._capture = None
        self._jpeg_buffer: bytes = b''
        self._jpeg_offset: int = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main thread loop: send CCTV packets at ~89.3 pps."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        capture = self._try_open_camera()
        try:
            logger.info(
                "CCTV stream started: bus_id=%d target=%s:%d "
                "bitrate=%d bps pkt_size=%d camera=%s",
                self._bus_id, self._server_ip, self._server_port,
                CCTV_BITRATE_BPS, CCTV_PACKET_SIZE,
                self._camera_device if capture else "none(random)",
            )

            pkt_count = 0
            t_start = time.monotonic()

            while not self._stop_event.is_set():
                # Build packet payload
                if capture is not None:
                    payload = self._read_camera_fragment(capture)
                else:
                    payload = self._random_payload

                # Send
                try:
                    sock.sendto(payload, (self._server_ip, self._server_port))
                    pkt_count += 1
                except OSError as exc:
                    logger.warning(
                        "CCTV send error bus=%d: %s", self._bus_id, exc,
                    )

                # Precise pacing: compute the ideal send time for the
                # next packet and sleep until then.
                next_send = t_start + pkt_count * _PACKET_INTERVAL
                now = time.monotonic()
                sleep_time = next_send - now
                if sleep_time > 0:
                    self._stop_event.wait(timeout=sleep_time)
                elif sleep_time < -1.0:
                    # We fell more than 1 second behind; reset the
                    # pacing clock to avoid a burst of catch-up packets.
                    t_start = time.monotonic()
                    pkt_count = 0

                # Refresh random payload every ~1000 packets (~11 s)
                if capture is None and pkt_count % 1000 == 0:
                    self._random_payload = os.urandom(CCTV_PACKET_SIZE)

        finally:
            sock.close()
            if capture is not None:
                capture.release()
            logger.info("CCTV stream stopped: bus_id=%d", self._bus_id)

    def stop(self) -> None:
        """Signal the thread to stop and wait for it to finish."""
        self._stop_event.set()
        self.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Camera helpers
    # ------------------------------------------------------------------

    def _try_open_camera(self):
        """
        Try to open the camera device using OpenCV.
        Returns a cv2.VideoCapture on success, None on failure.
        """
        if not self._camera_device:
            return None
        try:
            import cv2
            cap = cv2.VideoCapture(self._camera_device)
            if cap.isOpened():
                logger.info("Camera opened: %s", self._camera_device)
                return cap
            else:
                logger.warning(
                    "Camera device %s could not be opened; "
                    "falling back to random bytes",
                    self._camera_device,
                )
                cap.release()
                return None
        except ImportError:
            logger.warning(
                "opencv-python not installed; camera unavailable, "
                "using random bytes"
            )
            return None

    def _read_camera_fragment(self, capture) -> bytes:
        """
        Read a JPEG fragment from the camera capture.

        Grabs a frame, JPEG-encodes it, then serves sequential
        1400-byte chunks as packets.  When the frame buffer is
        exhausted, a new frame is captured.
        """
        if self._jpeg_offset >= len(self._jpeg_buffer):
            # Need a new frame
            try:
                import cv2
                ret, frame = capture.read()
                if ret and frame is not None:
                    ok, encoded = cv2.imencode('.jpg', frame,
                                               [cv2.IMWRITE_JPEG_QUALITY, 50])
                    if ok:
                        self._jpeg_buffer = encoded.tobytes()
                        self._jpeg_offset = 0
                    else:
                        return os.urandom(CCTV_PACKET_SIZE)
                else:
                    return os.urandom(CCTV_PACKET_SIZE)
            except Exception as exc:
                logger.warning("Camera read error: %s", exc)
                return os.urandom(CCTV_PACKET_SIZE)

        # Slice out a CCTV_PACKET_SIZE chunk
        end = self._jpeg_offset + CCTV_PACKET_SIZE
        chunk = self._jpeg_buffer[self._jpeg_offset:end]
        self._jpeg_offset = end

        # Pad if the remaining bytes are fewer than CCTV_PACKET_SIZE
        if len(chunk) < CCTV_PACKET_SIZE:
            chunk = chunk + b'\x00' * (CCTV_PACKET_SIZE - len(chunk))

        return chunk
