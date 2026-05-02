"""Smoke driver: build a fake INC_*/ folder end-to-end without WeasyPrint.

Calls build_incident_folder() directly with synthetic PDF bytes so the
smoke test runs on Windows where WeasyPrint native deps may be missing.
The same code path runs in production — we're only swapping out the PDF
renderer.
"""
from __future__ import annotations

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)


class _StubLogger:
    def __init__(self, log_dir: str) -> None:
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        events_csv = os.path.join(log_dir, "events.csv")
        if not os.path.exists(events_csv):
            with open(events_csv, "w", encoding="utf-8", newline="") as f:
                f.write("time,busId,eventType,value1,value2,detail\n")
                now = time.time()
                # Three rows around "now" so the slice has content.
                for off, et in [(-5.0, "ddos_detect"), (0.0, "ddos_detect"),
                                (5.0, "gps_spoof_detect")]:
                    f.write(f"{now+off:.3f},7,{et},20.0,0.05,test\n")


def main() -> int:
    from jetson.forensic.incident_package import build_incident_folder

    log_dir = os.path.join(ROOT, "logs")
    csv_logger = _StubLogger(log_dir)

    pdf_bytes = b"%PDF-1.4\n%fake-smoke-pdf\n" + b"X" * 4096 + b"\n%%EOF\n"
    base_dir = os.path.join(log_dir, "incidents")
    trigger_ts = time.time()

    folder, sha, meta = build_incident_folder(
        base_dir=base_dir,
        bus_id=7,
        attack_type="ddos",
        trigger_ts=trigger_ts,
        pdf_bytes=pdf_bytes,
        detection_details={
            "rate_bps": 30_000_000,
            "loss_pct": 0.07,
            "rtt_ms": 142.0,
            "triggers_fired": ["rate", "loss"],
        },
        csv_logger=csv_logger,
        gps_trace=[(1000.0 + i, 2000.0 + i * 0.5) for i in range(20)],
    )
    print(folder)
    print("PDF sha256:", sha)
    return 0


if __name__ == "__main__":
    sys.exit(main())
