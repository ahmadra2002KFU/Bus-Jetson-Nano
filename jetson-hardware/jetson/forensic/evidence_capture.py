"""Forensic evidence capture — build a PDF + INC_*/ folder + sha256 manifest."""

from __future__ import annotations

import csv
import hashlib
import logging
import os
import time
from typing import Any, Optional

from jetson.forensic.incident_package import build_incident_folder
from jetson.forensic.pdf_builder import build_incident_pdf

logger = logging.getLogger(__name__)

_MAX_EVENT_ROWS = 25
_DEFAULT_INCIDENTS_DIR = os.path.join("logs", "incidents")


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
    csv_logger=None,
    bus_id: int = 0,
    attack_type: str = "unknown",
    detection_details: dict | None = None,
    gps_trace: list[tuple[float, float]] | None = None,
    route_polyline: list[tuple[float, float]] | None = None,
    incidents_dir: Optional[str] = None,
):
    """Capture forensic evidence: PDF + INC_*/ folder + sha256 of PDF.

    Camera capture is intentionally out of scope for M4 — no real camera is
    instantiated and no raw_image.jpg is written. (Camera support is future
    work and lives outside this milestone.)

    Returns:
        tuple[bytes, dict]:
            - PDF bytes (kept for upload).
            - Metadata dict containing ``bus_id``, ``attack_type``,
              ``trigger_ts``, ``details``, ``sha256`` (of PDF),
              ``incident_id``, ``incident_dir``.
    """
    trigger_ts = time.time()

    recent_events = _read_recent_events(csv_logger)
    details = dict(detection_details or {})

    render_start = time.monotonic()
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
    report_gen_time_ms = (time.monotonic() - render_start) * 1000.0

    pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

    # Resolve where INC_*/ folders live. Default: <csv_logger.log_dir>/incidents
    base_dir = incidents_dir
    if base_dir is None:
        log_dir = getattr(csv_logger, "log_dir", None) or "logs"
        base_dir = os.path.join(log_dir, "incidents")

    folder, _, folder_meta = build_incident_folder(
        base_dir=base_dir,
        bus_id=int(bus_id),
        attack_type=attack_type,
        trigger_ts=trigger_ts,
        pdf_bytes=pdf_bytes,
        detection_details=details,
        csv_logger=csv_logger,
        gps_trace=gps_trace,
    )

    metadata = {
        "bus_id":      int(bus_id),
        "attack_type": attack_type,
        "trigger_ts":  trigger_ts,
        "details":     details,
        "sha256":      pdf_sha256,
        "incident_id": folder_meta["incident_id"],
        "incident_dir": folder,
        "report_gen_time_ms": report_gen_time_ms,
        "acquisition_time_s": folder_meta.get("acquisition_time_s", 0.0),
        "hash_gen_time_ms": folder_meta.get("hash_gen_time_ms", 0.0),
    }

    logger.info(
        "forensic evidence ready: bus=%d attack=%s pdf=%d bytes sha256=%s folder=%s",
        bus_id, attack_type, len(pdf_bytes), pdf_sha256, folder,
    )
    return pdf_bytes, metadata
