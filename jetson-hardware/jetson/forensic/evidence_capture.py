"""Forensic evidence capture — camera frame + logs bundled into 10MB package."""

import logging
import struct
import time
import os

logger = logging.getLogger(__name__)

FORENSIC_SIZE = 10_485_760  # 10 MB, matching ns-3 line 1286


def capture_evidence(camera, csv_logger, bus_id=0, attack_type="unknown"):
    """Capture forensic evidence package.

    Bundles:
    1. Camera frame (JPEG)
    2. Event log snapshot
    3. Metadata header
    4. Zero padding to exactly 10,485,760 bytes

    Returns:
        bytes: 10 MB evidence package
    """
    parts = []

    # Header (64 bytes)
    header = struct.pack('<I', 0x45564431)  # "EVD1" magic
    header += struct.pack('<I', bus_id)
    header += struct.pack('<d', time.time())
    header += attack_type.encode('utf-8')[:32].ljust(32, b'\x00')
    header += b'\x00' * (64 - len(header))
    parts.append(header)

    # Camera frame
    jpeg_bytes = b''
    if camera:
        try:
            jpeg_bytes = camera.grab_jpeg(quality=80) or b''
            logger.info("Captured camera frame: %d bytes", len(jpeg_bytes))
        except Exception as e:
            logger.warning("Camera capture failed: %s", e)

    # Frame length prefix + frame data
    parts.append(struct.pack('<I', len(jpeg_bytes)))
    if jpeg_bytes:
        parts.append(jpeg_bytes)

    # Event log snapshot
    log_data = b''
    if csv_logger:
        try:
            events_path = os.path.join(csv_logger.log_dir, "events.csv")
            if os.path.exists(events_path):
                with open(events_path, 'rb') as f:
                    log_data = f.read()[-8192:]  # last 8KB of log
        except Exception as e:
            logger.warning("Log snapshot failed: %s", e)

    parts.append(struct.pack('<I', len(log_data)))
    if log_data:
        parts.append(log_data)

    # Assemble and pad to exactly 10 MB
    evidence = b''.join(parts)
    if len(evidence) < FORENSIC_SIZE:
        evidence += b'\x00' * (FORENSIC_SIZE - len(evidence))
    elif len(evidence) > FORENSIC_SIZE:
        evidence = evidence[:FORENSIC_SIZE]

    logger.info("Evidence package: %d bytes (target: %d)",
                len(evidence), FORENSIC_SIZE)
    return evidence, jpeg_bytes
