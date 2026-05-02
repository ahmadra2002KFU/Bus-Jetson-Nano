"""Build the supervisor-mandated INC_<ts>_<bus>/ evidence folder.

For each incident, this module assembles a directory containing:
  - edge_forensic_report.pdf   (existing WeasyPrint PDF)
  - edge_forensic_report.txt   (10-30 line plain-text summary)
  - events.csv                 (slice of events.csv covering ±60s)
  - gps_log.csv                (last 120s of GPS readings)
  - ids_alert.json             (raw detector alert dict)
  - metadata.json              (incident id, ts, bus, detector, host, sha)
  - hash_manifest.txt          (sha256 of every other file, sha256sum format)

(Camera frame capture is intentionally out of scope for M4 — no raw_image.jpg
is written. Camera support is future work.)

The manifest is GNU-sha256sum compatible so:
    sha256sum -c hash_manifest.txt
verifies the folder.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import platform
import socket
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

DETECTOR_VERSION = "1.0.0"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_sha() -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
        return out.decode("ascii", "ignore").strip() or None
    except Exception:
        return None


def _incident_id(trigger_ts: float, bus_id: int) -> str:
    stamp = datetime.fromtimestamp(trigger_ts).strftime("%Y%m%d-%H%M%S")
    return f"INC_{stamp}_{bus_id}"


def _slice_events_csv(
    csv_logger,
    trigger_ts: float,
    pre_s: float = 60.0,
    post_s: float = 60.0,
) -> str:
    """Return a CSV string with header + rows in [trigger-pre, trigger+post]."""
    header = ["time", "busId", "eventType", "value1", "value2", "detail"]
    out_buf = io.StringIO()
    writer = csv.writer(out_buf)
    writer.writerow(header)

    if csv_logger is None:
        return out_buf.getvalue()

    log_dir = getattr(csv_logger, "log_dir", None)
    if not log_dir:
        return out_buf.getvalue()

    src = os.path.join(log_dir, "events.csv")
    if not os.path.exists(src):
        return out_buf.getvalue()

    lo, hi = trigger_ts - pre_s, trigger_ts + post_s
    with open(src, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = float(row.get("time", 0.0))
            except (TypeError, ValueError):
                continue
            if lo <= ts <= hi:
                writer.writerow([
                    row.get("time", ""),
                    row.get("busId", ""),
                    row.get("eventType", ""),
                    row.get("value1", ""),
                    row.get("value2", ""),
                    row.get("detail", ""),
                ])
    return out_buf.getvalue()


def _gps_log_csv(
    gps_trace: Optional[Sequence[Tuple[float, float]]],
    trigger_ts: float,
    window_s: float = 120.0,
) -> str:
    """Build a gps_log.csv from the recent trace.

    The trace is a list of (x_m, y_m). We don't have per-point timestamps,
    so we synthesize them by spacing readings backward from trigger_ts at
    1 Hz (matches the default GPS send_interval) up to window_s seconds.
    """
    out_buf = io.StringIO()
    writer = csv.writer(out_buf)
    writer.writerow(["time", "x_m", "y_m"])

    pts = list(gps_trace or [])
    if not pts:
        return out_buf.getvalue()

    # Keep the most recent N points that fit in window_s at 1Hz.
    n = min(len(pts), int(window_s))
    pts = pts[-n:]
    base = trigger_ts - (len(pts) - 1) * 1.0
    for i, (x, y) in enumerate(pts):
        ts = base + i * 1.0
        writer.writerow([f"{ts:.3f}", f"{float(x):.3f}", f"{float(y):.3f}"])
    return out_buf.getvalue()


def _build_text_summary(
    *,
    incident_id: str,
    attack_type: str,
    trigger_ts: float,
    bus_id: int,
    detection_details: Dict[str, Any],
    pdf_sha256: str,
) -> str:
    iso = datetime.utcfromtimestamp(trigger_ts).isoformat() + "Z"
    lines = [
        "Al-Ahsa Smart Bus — Edge Forensic Report (text summary)",
        "=" * 60,
        f"Incident ID    : {incident_id}",
        f"Type           : {attack_type}",
        f"Trigger ts     : {trigger_ts:.3f}  ({iso})",
        f"Bus ID         : {bus_id}",
        f"Hostname       : {socket.gethostname()}",
        f"Detector ver.  : {DETECTOR_VERSION}",
        f"PDF sha256     : {pdf_sha256}",
        "",
        "Detector outputs:",
    ]
    if detection_details:
        for k in sorted(detection_details.keys()):
            lines.append(f"  - {k}: {detection_details[k]}")
    else:
        lines.append("  (none)")

    lines.extend([
        "",
        "Action taken:",
        "  1. Detection latched on edge.",
        "  2. WeasyPrint PDF rendered (edge_forensic_report.pdf).",
        "  3. SHA-256 manifest written (hash_manifest.txt).",
        "  4. Multipart upload to /ingest/forensic with sha256 field.",
        "",
        "Verify locally:  sha256sum -c hash_manifest.txt",
    ])
    return "\n".join(lines) + "\n"


def _build_ids_alert(
    *,
    attack_type: str,
    trigger_ts: float,
    bus_id: int,
    detection_details: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "type": attack_type,
        "ts": trigger_ts,
        "ts_iso": datetime.utcfromtimestamp(trigger_ts).isoformat() + "Z",
        "bus_id": bus_id,
        "detector_module": (
            "ddos_detector" if attack_type == "ddos" else "edge_gps_detector"
        ),
        "detector_version": DETECTOR_VERSION,
        "indicators": detection_details or {},
    }


def _build_metadata(
    *,
    incident_id: str,
    attack_type: str,
    trigger_ts: float,
    bus_id: int,
    pdf_sha256: str,
) -> Dict[str, Any]:
    return {
        "incident_id": incident_id,
        "ts": trigger_ts,
        "ts_iso": datetime.utcfromtimestamp(trigger_ts).isoformat() + "Z",
        "bus_id": bus_id,
        "attack_type": attack_type,
        "detector_module": (
            "ddos_detector" if attack_type == "ddos" else "edge_gps_detector"
        ),
        "detector_version": DETECTOR_VERSION,
        "jetson_hostname": socket.gethostname(),
        "platform": platform.platform(),
        "agent_git_sha": _git_sha(),
        "pdf_sha256": pdf_sha256,
    }


def _write_manifest(folder: str, exclude: str = "hash_manifest.txt") -> str:
    """Write hash_manifest.txt in GNU sha256sum format and return its path.

    Format per line:  ``<sha256>  <filename>\n``  (two spaces, binary mode).
    """
    entries = []
    for name in sorted(os.listdir(folder)):
        if name == exclude:
            continue
        full = os.path.join(folder, name)
        if not os.path.isfile(full):
            continue
        entries.append((name, _sha256_file(full)))

    manifest_path = os.path.join(folder, exclude)
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as f:
        for name, digest in entries:
            f.write(f"{digest}  {name}\n")
    return manifest_path


def build_incident_folder(
    *,
    base_dir: str,
    bus_id: int,
    attack_type: str,
    trigger_ts: float,
    pdf_bytes: bytes,
    detection_details: Optional[Dict[str, Any]],
    csv_logger,
    gps_trace: Optional[Sequence[Tuple[float, float]]],
) -> Tuple[str, str, Dict[str, Any]]:
    """Materialize a full INC_*/ folder on disk.

    Returns
    -------
    (folder_path, pdf_sha256, metadata_dict)
    """
    os.makedirs(base_dir, exist_ok=True)
    incident_id = _incident_id(trigger_ts, bus_id)
    folder = os.path.join(base_dir, incident_id)
    os.makedirs(folder, exist_ok=True)

    acquisition_start = time.monotonic()
    pdf_sha256 = _sha256_bytes(pdf_bytes)

    # 1. PDF
    with open(os.path.join(folder, "edge_forensic_report.pdf"), "wb") as f:
        f.write(pdf_bytes)

    # 2. Text summary
    text = _build_text_summary(
        incident_id=incident_id,
        attack_type=attack_type,
        trigger_ts=trigger_ts,
        bus_id=bus_id,
        detection_details=detection_details or {},
        pdf_sha256=pdf_sha256,
    )
    with open(os.path.join(folder, "edge_forensic_report.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write(text)

    # 3. events.csv slice
    events_csv = _slice_events_csv(csv_logger, trigger_ts)
    with open(os.path.join(folder, "events.csv"), "w",
              encoding="utf-8", newline="") as f:
        f.write(events_csv)

    # 4. gps_log.csv
    gps_csv = _gps_log_csv(gps_trace, trigger_ts)
    with open(os.path.join(folder, "gps_log.csv"), "w",
              encoding="utf-8", newline="") as f:
        f.write(gps_csv)

    # 5. ids_alert.json
    alert = _build_ids_alert(
        attack_type=attack_type,
        trigger_ts=trigger_ts,
        bus_id=bus_id,
        detection_details=detection_details or {},
    )
    with open(os.path.join(folder, "ids_alert.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(alert, f, indent=2, sort_keys=True)
        f.write("\n")

    # 6. metadata.json
    meta = _build_metadata(
        incident_id=incident_id,
        attack_type=attack_type,
        trigger_ts=trigger_ts,
        bus_id=bus_id,
        pdf_sha256=pdf_sha256,
    )
    with open(os.path.join(folder, "metadata.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(meta, f, indent=2, sort_keys=True)
        f.write("\n")

    # 7. hash_manifest.txt (last — covers everything else)
    hash_start = time.monotonic()
    _write_manifest(folder)
    hash_gen_time_ms = (time.monotonic() - hash_start) * 1000.0
    acquisition_time_s = time.monotonic() - acquisition_start

    meta["acquisition_time_s"] = acquisition_time_s
    meta["hash_gen_time_ms"] = hash_gen_time_ms

    logger.info(
        "forensic folder built: %s (pdf_sha256=%s, acq=%.3fs, hash=%.1fms)",
        folder, pdf_sha256, acquisition_time_s, hash_gen_time_ms,
    )
    return folder, pdf_sha256, meta
