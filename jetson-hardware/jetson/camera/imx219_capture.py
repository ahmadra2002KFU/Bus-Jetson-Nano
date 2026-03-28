"""Real IMX219 CSI camera capture for Jetson Orin Nano."""

import logging
import threading
import time

logger = logging.getLogger(__name__)

GSTREAMER_PIPELINE = (
    "nvarguscamerasrc ! "
    "video/x-raw(memory:NVMM),width={width},height={height},"
    "framerate={fps}/1 ! "
    "nvvidconv ! video/x-raw,format=BGRx ! "
    "videoconvert ! video/x-raw,format=BGR ! appsink"
)


class IMX219Capture:
    """Captures frames from the IMX219 camera via GStreamer on Jetson."""

    def __init__(self, width=1280, height=720, fps=30):
        self.width = width
        self.height = height
        self.fps = fps
        self._cap = None
        self._latest_frame = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        try:
            import cv2
        except ImportError:
            raise RuntimeError("OpenCV is required for IMX219 capture")

        pipeline = GSTREAMER_PIPELINE.format(
            width=self.width, height=self.height, fps=self.fps
        )
        self._cap = cv2.VideoCapture(pipeline, cv2.CAP_GSTREAMER)

        if not self._cap.isOpened():
            raise RuntimeError(
                "Failed to open IMX219 camera. Check CSI connection and "
                "ensure nvarguscamerasrc is available."
            )

        logger.info("IMX219 camera opened (%dx%d @ %d fps)",
                     self.width, self.height, self.fps)

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop,
                                         daemon=True)
        self._thread.start()

    def _capture_loop(self):
        import cv2
        while not self._stop_event.is_set():
            ret, frame = self._cap.read()
            if ret:
                with self._lock:
                    self._latest_frame = frame
            else:
                time.sleep(0.01)

    def grab_frame(self):
        """Return the latest captured BGR frame."""
        with self._lock:
            if self._latest_frame is not None:
                return self._latest_frame.copy()
        return None

    def grab_jpeg(self, quality=80):
        """Return the latest frame as JPEG bytes."""
        frame = self.grab_frame()
        if frame is None:
            return None
        import cv2
        _, buf = cv2.imencode('.jpg', frame,
                              [cv2.IMWRITE_JPEG_QUALITY, quality])
        return buf.tobytes()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._cap:
            self._cap.release()
        logger.info("IMX219 camera stopped")

    def is_opened(self):
        return self._cap is not None and self._cap.isOpened()
