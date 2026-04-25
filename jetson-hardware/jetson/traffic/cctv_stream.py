"""CCTV stream — WebSocket transport at 1 Mbps.

Streams 1400-byte binary frames at ~89.3 pps to
``{server_url}/ingest/cctv?bus_id=<n>`` with automatic reconnect.
Uses ``time.monotonic()`` pacing to stay within ~1% of the target rate.

Frame payload: a JPEG fragment from the configured camera, or random
bytes when no camera is available.
"""

from __future__ import annotations

import logging
import os
import random
import threading
import time
from typing import Optional

import websocket  # from websocket-client

from jetson.constants import CCTV_BITRATE_BPS, CCTV_PACKET_SIZE

logger = logging.getLogger(__name__)

_PACKETS_PER_SECOND = CCTV_BITRATE_BPS / (CCTV_PACKET_SIZE * 8)
_PACKET_INTERVAL = 1.0 / _PACKETS_PER_SECOND  # ~0.0112 s


def _to_ws_url(server_url: str, path: str) -> str:
    base = server_url.rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    return base + path


class CCTVStream(threading.Thread):
    """WebSocket CCTV streamer.

    Parameters
    ----------
    server_url : str
        Server base URL (e.g. https://example.com).
    bus_id : int
        Bus identifier (appended as ``?bus_id=<n>``).
    camera_device : str | None
        Camera device path for real frames, or None for random bytes.
    """

    def __init__(
        self,
        *,
        server_url: str,
        bus_id: int,
        camera_device: Optional[str] = None,
    ):
        super().__init__(daemon=True, name=f"CCTV-bus{bus_id}")
        self._url = (
            _to_ws_url(server_url, "/ingest/cctv") + f"?bus_id={bus_id}"
        )
        self._bus_id = bus_id
        self._camera_device = camera_device
        self._stop_event = threading.Event()
        self._ws: Optional[websocket.WebSocket] = None
        self._random_payload = os.urandom(CCTV_PACKET_SIZE)
        self._jpeg_buffer: bytes = b""
        self._jpeg_offset: int = 0

    def run(self) -> None:
        logger.info("CCTV stream start bus=%d url=%s", self._bus_id, self._url)
        capture = self._try_open_camera()
        backoff = 1.0
        try:
            while not self._stop_event.is_set():
                try:
                    self._ws = websocket.create_connection(self._url, timeout=10)
                    logger.info("CCTV WS connected bus=%d", self._bus_id)
                    backoff = 1.0
                    self._run_send_loop(capture)
                except Exception as exc:
                    if self._stop_event.is_set():
                        break
                    logger.warning("CCTV WS error bus=%d: %s (backoff %.1fs)",
                                   self._bus_id, exc, backoff)
                    self._close_ws()
                    sleep_for = min(backoff, 60.0) * random.uniform(0.7, 1.3)
                    self._stop_event.wait(timeout=sleep_for)
                    backoff = min(backoff * 2.0, 60.0)
        finally:
            if capture is not None:
                try:
                    capture.release()
                except Exception:
                    pass
            self._close_ws()
            logger.info("CCTV stream stop bus=%d", self._bus_id)

    def stop(self) -> None:
        self._stop_event.set()
        self._close_ws()
        self.join(timeout=5.0)

    # --------------------------------------------------------------
    # Internals
    # --------------------------------------------------------------

    def _run_send_loop(self, capture) -> None:
        pkt_count = 0
        t_start = time.monotonic()
        while not self._stop_event.is_set():
            payload = self._read_camera_fragment(capture) if capture else self._random_payload
            try:
                self._ws.send_binary(payload)
                pkt_count += 1
            except Exception as exc:
                logger.warning("CCTV send bus=%d failed: %s", self._bus_id, exc)
                raise

            next_send = t_start + pkt_count * _PACKET_INTERVAL
            sleep_for = next_send - time.monotonic()
            if sleep_for > 0:
                self._stop_event.wait(timeout=sleep_for)
            elif sleep_for < -1.0:
                t_start = time.monotonic()
                pkt_count = 0

            if capture is None and pkt_count % 1000 == 0:
                self._random_payload = os.urandom(CCTV_PACKET_SIZE)

    def _close_ws(self) -> None:
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None

    def _try_open_camera(self):
        if not self._camera_device:
            return None
        try:
            import cv2
            cap = cv2.VideoCapture(self._camera_device)
            if cap.isOpened():
                logger.info("camera opened: %s", self._camera_device)
                return cap
            cap.release()
        except ImportError:
            logger.warning("opencv-python not installed; using random bytes")
        except Exception as exc:
            logger.warning("camera open failed: %s", exc)
        return None

    def _read_camera_fragment(self, capture) -> bytes:
        if self._jpeg_offset >= len(self._jpeg_buffer):
            try:
                import cv2
                ret, frame = capture.read()
                if not ret or frame is None:
                    return os.urandom(CCTV_PACKET_SIZE)
                ok, encoded = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
                if not ok:
                    return os.urandom(CCTV_PACKET_SIZE)
                self._jpeg_buffer = encoded.tobytes()
                self._jpeg_offset = 0
            except Exception as exc:
                logger.warning("camera read error: %s", exc)
                return os.urandom(CCTV_PACKET_SIZE)
        end = self._jpeg_offset + CCTV_PACKET_SIZE
        chunk = self._jpeg_buffer[self._jpeg_offset:end]
        self._jpeg_offset = end
        if len(chunk) < CCTV_PACKET_SIZE:
            chunk = chunk + b"\x00" * (CCTV_PACKET_SIZE - len(chunk))
        return chunk
