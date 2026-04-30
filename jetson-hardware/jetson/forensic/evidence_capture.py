"""Forensic evidence capture — build a PDF incident report."""

from __future__ import annotations

import csv
import logging
import os
import time
from typing import Any

from jetson.forensic.pdf_builder import build_incident_pdf

logger = logging.getLogger(__name__)

_MAX_EVENT_ROWS = 25


def _read_recent_events(csv_logger, limit: int = _MAX_EVENT_ROWS
                        ) -> list[dict[str, Any]]:
    """Return the last ``limit`` events from the CSV logger's events.csv."""
    if csv_logger is None:
        return []

    try:
        log_dir = getattr(csv_logger, "log_dir", None)
        if not log_dir:
            return []
        events_path = os.path.join(log_dir, "events.csv")
        if not os.path.exists(events_path):
            return []

        rows: list[dict[str, Any]] = []
        with open(events_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    ts = float(row.get("time", 0.0))
                except (TypeError, ValueError):
                    ts = 0.0
                rows.append({
                    "ts":     ts,
                    "type":   row.get("eventType", ""),
                    "value1": row.get("value1", ""),
                    "value2": row.get("value2", ""),
                    "detail": row.get("detail", ""),
                })
        return rows[-limit:]
    except Exception as exc:
        logger.warning("could not read recent events: %s", exc)
        return []


def capture_evidence(
    camera=None,
    csv_logger=None,
    bus_id: int = 0,
    attack_type: str = "unknown",
    detection_details: dict | None = None,
    gps_trace: list[tuple[float, float]] | None = None,
    route_polyline: list[tuple[float, float]] | None = None,
):
    """Capture forensic evidence and render it as a PDF incident report.

    The ``camera`` parameter is accepted for backward-compatibility with the
    existing call sites but is no longer used: this project does not run
    against a real camera, so no frame is captured.

    Returns:
        tuple[bytes, dict]:
            - PDF bytes.
            - Metadata dict with ``bus_id``, ``attack_type``, ``trigger_ts``,
              ``details`` — consumed by the forensic uploader.
    """
    trigger_ts = time.time()

    # Camera capture intentionally removed: no real camera in this project.
    del camera  # silence unused-arg linters; preserved in signature only

    recent_events = _read_recent_events(csv_logger)
    details = dict(detection_details or {})

    try:
        pdf_bytes = build_incident_pdf(
            bus_id=int(bus_id),
            attack_type=attack_type,
            trigger_ts=trigger_ts,
            detection_details=details,
            recent_events=recent_events,
            gps_trace=gps_trace,
            route_polyline=route_polyline,
        )
    except Exception as exc:
        logger.error("PDF render failed: %s", exc)
        raise

    metadata = {
        "bus_id":      int(bus_id),
        "attack_type": attack_type,
        "trigger_ts":  trigger_ts,
        "details":     details,
    }

    logger.info(
        "forensic evidence ready: bus=%d attack=%s pdf=%d bytes",
        bus_id, attack_type, len(pdf_bytes),
    )
    return pdf_bytes, metadata
