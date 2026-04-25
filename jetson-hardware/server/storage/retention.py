"""Background retention task: purge rows and forensic PDFs older than N days."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

from . import db

logger = logging.getLogger(__name__)

RETENTION_TABLES = ("events", "metrics", "gps_positions")
DEFAULT_RETENTION_DAYS = 30
LOOP_INTERVAL_S = 3600.0


def get_retention_days() -> int:
    try:
        return int(os.environ.get("RETENTION_DAYS", DEFAULT_RETENTION_DAYS))
    except ValueError:
        return DEFAULT_RETENTION_DAYS


async def purge_once(retention_days: int | None = None) -> dict:
    """Run a single retention sweep. Returns per-table deletion counts."""
    days = retention_days if retention_days is not None else get_retention_days()
    cutoff_ts = time.time() - (days * 86400.0)

    summary: dict[str, int] = {}
    for table in RETENTION_TABLES:
        try:
            summary[table] = await db.purge_older_than(table, cutoff_ts)
        except Exception:
            logger.exception("retention: purge failed for table %s", table)
            summary[table] = -1

    try:
        stale = await db.fetch_old_forensics(cutoff_ts)
    except Exception:
        logger.exception("retention: fetch_old_forensics failed")
        stale = []

    unlinked = 0
    stale_ids: list[int] = []
    for row in stale:
        pdf_path = row.get("pdf_path")
        if pdf_path:
            try:
                Path(pdf_path).unlink(missing_ok=True)
                unlinked += 1
            except OSError:
                logger.exception("retention: failed to unlink %s", pdf_path)
        stale_ids.append(int(row["id"]))

    try:
        summary["forensics"] = await db.delete_forensic_ids(stale_ids)
    except Exception:
        logger.exception("retention: delete_forensic_ids failed")
        summary["forensics"] = -1
    summary["forensic_files_deleted"] = unlinked

    logger.info(
        "retention sweep (days=%d, cutoff_ts=%.0f): %s", days, cutoff_ts, summary
    )
    return summary


async def retention_loop(stop_event: asyncio.Event | None = None) -> None:
    """Run purge_once every LOOP_INTERVAL_S seconds until stop_event is set."""
    stop_event = stop_event or asyncio.Event()
    logger.info("retention loop starting (days=%d)", get_retention_days())
    while not stop_event.is_set():
        try:
            await purge_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("retention loop iteration failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=LOOP_INTERVAL_S)
        except asyncio.TimeoutError:
            continue
    logger.info("retention loop stopped")
