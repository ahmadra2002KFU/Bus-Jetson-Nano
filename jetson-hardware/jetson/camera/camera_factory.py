"""Factory that returns real or dummy camera based on config."""

import logging

logger = logging.getLogger(__name__)


def create_camera(use_real_camera=False, width=1280, height=720, fps=30):
    """Create and return a camera instance.

    Args:
        use_real_camera: If True, attempt to open the IMX219 CSI camera.
                         Falls back to dummy if camera fails to open.
    """
    if use_real_camera:
        try:
            from .imx219_capture import IMX219Capture
            cam = IMX219Capture(width=width, height=height, fps=fps)
            cam.start()
            if cam.is_opened():
                logger.info("Using real IMX219 camera")
                return cam
            else:
                cam.stop()
                logger.warning("IMX219 failed to open, falling back to dummy")
        except Exception as e:
            logger.warning("Cannot use real camera (%s), falling back to dummy", e)

    from .dummy_capture import DummyCapture
    cam = DummyCapture(width=width, height=height)
    cam.start()
    logger.info("Using dummy camera")
    return cam
