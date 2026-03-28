"""Synthetic camera frame generator for testing without hardware."""

import numpy as np
import time
import logging

logger = logging.getLogger(__name__)


class DummyCapture:
    """Generates synthetic frames when no real camera is connected."""

    def __init__(self, width=1280, height=720):
        self.width = width
        self.height = height
        self._started = False
        logger.info("DummyCapture initialized (%dx%d)", width, height)

    def start(self):
        self._started = True
        logger.info("DummyCapture started")

    def grab_frame(self):
        """Return a synthetic BGR frame with timestamp overlay."""
        frame = np.zeros((self.height, self.width, 3), dtype=np.uint8)
        frame[:, :, 1] = 40  # dark green tint

        # Draw moving bar to simulate motion
        bar_pos = int((time.time() % 5) / 5 * self.width)
        bar_w = 60
        frame[:, max(0, bar_pos - bar_w):bar_pos + bar_w, 2] = 180

        # Try to add text overlay if OpenCV available
        try:
            import cv2
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            cv2.putText(frame, f"BUS CCTV - DUMMY FEED", (30, 50),
                        cv2.FONT_HERSHEY_SIMPLEX, 1.2, (255, 255, 255), 2)
            cv2.putText(frame, ts, (30, 100),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.8, (200, 200, 200), 1)
            cv2.putText(frame, "No camera connected", (30, self.height - 40),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (100, 100, 255), 1)
        except ImportError:
            pass

        return frame

    def grab_jpeg(self, quality=80):
        """Return frame as JPEG bytes."""
        frame = self.grab_frame()
        try:
            import cv2
            _, buf = cv2.imencode('.jpg', frame,
                                  [cv2.IMWRITE_JPEG_QUALITY, quality])
            return buf.tobytes()
        except ImportError:
            # Fallback: return raw bytes
            return frame.tobytes()[:50000]

    def stop(self):
        self._started = False
        logger.info("DummyCapture stopped")

    def is_opened(self):
        return self._started
