"""Forensic-pipeline metrics writer.

Emits one row per incident to ``logs/forensics_metrics.csv`` covering the eight
metrics the M4 supervisor requires:

  detection_time_s           detector window-to-alert latency (set by detector)
  acquisition_time_s         alert -> incident folder fully built
  hash_gen_time_ms           first hash compute -> hash_manifest.txt written
  integrity_verification     PASS / FAIL / PENDING (server /verify result)
  upload_time_s              first TX byte -> server 200 OK
  upload_success             1 = ok, 0 = failed
  chain_of_custody_pct       files present / 6 expected (no PCAP, no image)
  report_gen_time_ms         WeasyPrint render duration

Writing is append-only and best-effort: failures here must not break the
forensic pipeline. The CSV is intentionally simple so it can be read by
analyze.py or a spreadsheet without extra tooling.
"""

from __future__ import annotations

import csv
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

EXPECTED_FILES = (
    "edge_forensic_report.pdf",
    "edge_forensic_report.txt",
    "events.csv",
    "gps_log.csv",
    "ids_alert.json",
    "metadata.json",
)

HEADER = (
    "incident_id",
    "trigger_ts",
    "bus_id",
    "attack_type",
    "detection_time_s",
    "acquisition_time_s",
    "hash_gen_time_ms",
    "integrity_verification",
    "upload_time_s",
    "upload_success",
    "chain_of_custody_pct",
    "report_gen_time_ms",
)


def chain_of_custody_pct(folder: str) -> float:
    """Return percentage of EXPECTED_FILES present in ``folder``."""
    if not folder or not os.path.isdir(folder):
        return 0.0
    present = sum(
        1 for name in EXPECTED_FILES if os.path.isfile(os.path.join(folder, name))
    )
    return 100.0 * present / len(EXPECTED_FILES)


def record_forensic_metrics(
    *,
    log_dir: str,
    incident_id: str,
    trigger_ts: float,
    bus_id: int,
    attack_type: str,
    detection_time_s: Optional[float],
    acquisition_time_s: float,
    hash_gen_time_ms: float,
    integrity_verification: str,
    upload_time_s: float,
    upload_success: bool,
    incident_folder: str,
    report_gen_time_ms: float,
) -> Optional[str]:
    """Append one row to ``<log_dir>/forensics_metrics.csv``.

    Returns the CSV path on success, or None on failure (logged, not raised).
    """
    if not log_dir:
        return None
    try:
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, "forensics_metrics.csv")
        is_new = not os.path.exists(path)
        coc = chain_of_custody_pct(incident_folder)

        with open(path, "a", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            if is_new:
                w.writerow(HEADER)
            w.writerow([
                incident_id,
                f"{trigger_ts:.3f}",
                bus_id,
                attack_type,
                "" if detection_time_s is None else f"{detection_time_s:.3f}",
                f"{acquisition_time_s:.3f}",
                f"{hash_gen_time_ms:.1f}",
                integrity_verification,
                f"{upload_time_s:.3f}",
                1 if upload_success else 0,
                f"{coc:.1f}",
                f"{report_gen_time_ms:.1f}",
            ])
        return path
    except Exception:
        logger.exception("forensics_metrics: failed to append row")
        return None
