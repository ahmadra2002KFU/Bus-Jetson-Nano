"""CSV event and forensic logger matching ns-3 output format."""

import csv
import os
import threading
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class CSVLogger:
    """Thread-safe CSV logger for detection events and forensic uploads.

    Produces two CSV files matching ns-3's WriteEventsCsv and WriteForensicsCsv:
    - events.csv:     time, busId, eventType, value1, value2, detail
    - forensics.csv:  triggerTime, busId, attackType, uploadStartTime,
                      uploadFinishTime, uploadCompleted, bytesReceived
    """

    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self._lock = threading.Lock()

        self._events_path = os.path.join(log_dir, "events.csv")
        self._forensics_path = os.path.join(log_dir, "forensics.csv")

        self._init_events_csv()
        self._init_forensics_csv()
        logger.info("CSVLogger initialized: %s", log_dir)

    def _init_events_csv(self):
        if not os.path.exists(self._events_path):
            with open(self._events_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'time', 'busId', 'eventType', 'value1', 'value2', 'detail'
                ])

    def _init_forensics_csv(self):
        if not os.path.exists(self._forensics_path):
            with open(self._forensics_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'triggerTime', 'busId', 'attackType',
                    'uploadStartTime', 'uploadFinishTime',
                    'uploadCompleted', 'bytesReceived'
                ])

    def log_event(self, bus_id, event_type, value1=0.0, value2=0.0,
                  detail=""):
        """Log a detection event to events.csv."""
        timestamp = datetime.now().timestamp()
        with self._lock:
            with open(self._events_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    f"{timestamp:.3f}", bus_id, event_type,
                    f"{value1:.6f}", f"{value2:.6f}", detail
                ])
        logger.info("Event logged: %s bus=%d v1=%.3f v2=%.3f %s",
                     event_type, bus_id, value1, value2, detail)

    def log_forensic(self, trigger_time, bus_id, attack_type,
                     upload_start, upload_finish, completed, bytes_received):
        """Log a forensic upload event to forensics.csv."""
        with self._lock:
            with open(self._forensics_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    f"{trigger_time:.3f}", bus_id, attack_type,
                    f"{upload_start:.3f}", f"{upload_finish:.3f}",
                    1 if completed else 0, bytes_received
                ])
        logger.info("Forensic logged: %s bus=%d completed=%s bytes=%d",
                     attack_type, bus_id, completed, bytes_received)
