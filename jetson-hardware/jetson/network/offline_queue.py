"""SQLite-backed store-and-forward FIFO for events and forensic PDFs."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any, Literal

logger = logging.getLogger(__name__)


_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS queued_events (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      REAL    NOT NULL,
        payload TEXT    NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS queued_forensics (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        ts       REAL    NOT NULL,
        metadata TEXT    NOT NULL,
        pdf_path TEXT    NOT NULL
    )
    """,
]


class OfflineQueue:
    """Thread-safe SQLite FIFO for network-outage buffering.

    PDFs are written to a sidecar directory next to the SQLite file so that
    large blobs do not bloat the database. The queue is crash-safe via WAL.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(db_path)) or "."
        os.makedirs(db_dir, exist_ok=True)

        self._pdf_dir = os.path.join(db_dir, "queued_pdfs")
        os.makedirs(self._pdf_dir, exist_ok=True)

        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            db_path,
            check_same_thread=False,
            isolation_level=None,
            timeout=30.0,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        for stmt in _SCHEMA:
            self._conn.execute(stmt)
        logger.info("OfflineQueue ready at %s", db_path)

    # ------------------------------------------------------------------ write

    def enqueue_event(self, payload: dict[str, Any]) -> int:
        """Queue a JSON-serializable event payload for later upload."""
        data = json.dumps(payload, separators=(",", ":"))
        ts = time.time()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO queued_events (ts, payload) VALUES (?, ?)",
                (ts, data),
            )
            row_id = int(cur.lastrowid)
        logger.debug("enqueued event id=%d bytes=%d", row_id, len(data))
        return row_id

    def enqueue_forensic(
        self,
        metadata: dict[str, Any],
        pdf_bytes: bytes,
    ) -> int:
        """Persist a forensic PDF and its metadata to the queue."""
        meta = json.dumps(metadata, separators=(",", ":"))
        ts = time.time()

        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO queued_forensics (ts, metadata, pdf_path) "
                "VALUES (?, ?, ?)",
                (ts, meta, ""),
            )
            row_id = int(cur.lastrowid)
            pdf_path = os.path.join(self._pdf_dir, f"{row_id}.pdf")
            tmp_path = pdf_path + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(pdf_bytes)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, pdf_path)
            self._conn.execute(
                "UPDATE queued_forensics SET pdf_path = ? WHERE id = ?",
                (pdf_path, row_id),
            )
        logger.debug(
            "enqueued forensic id=%d pdf_bytes=%d", row_id, len(pdf_bytes),
        )
        return row_id

    # ------------------------------------------------------------------- read

    def peek_batch(
        self,
        kind: Literal["event", "forensic"],
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return up to ``limit`` oldest queued items without removing them."""
        if limit < 1:
            return []

        with self._lock:
            if kind == "event":
                rows = self._conn.execute(
                    "SELECT id, ts, payload FROM queued_events "
                    "ORDER BY id ASC LIMIT ?",
                    (limit,),
                ).fetchall()
                out: list[dict[str, Any]] = []
                for row_id, ts, payload in rows:
                    try:
                        decoded = json.loads(payload)
                    except json.JSONDecodeError:
                        logger.warning(
                            "malformed event payload id=%d; dropping", row_id,
                        )
                        self._conn.execute(
                            "DELETE FROM queued_events WHERE id = ?",
                            (row_id,),
                        )
                        continue
                    out.append({"id": int(row_id), "ts": float(ts),
                                "payload": decoded})
                return out

            if kind == "forensic":
                rows = self._conn.execute(
                    "SELECT id, ts, metadata, pdf_path FROM queued_forensics "
                    "ORDER BY id ASC LIMIT ?",
                    (limit,),
                ).fetchall()
                out = []
                for row_id, ts, meta, pdf_path in rows:
                    try:
                        decoded = json.loads(meta)
                    except json.JSONDecodeError:
                        decoded = {}
                    out.append({
                        "id": int(row_id),
                        "ts": float(ts),
                        "metadata": decoded,
                        "pdf_path": pdf_path,
                    })
                return out

        raise ValueError(f"unknown kind: {kind!r}")

    # ------------------------------------------------------------------ purge

    def ack(self, kind: str, row_id: int) -> None:
        """Remove a queued row (and its PDF sidecar) after successful upload."""
        with self._lock:
            if kind == "event":
                self._conn.execute(
                    "DELETE FROM queued_events WHERE id = ?", (row_id,),
                )
                return

            if kind == "forensic":
                row = self._conn.execute(
                    "SELECT pdf_path FROM queued_forensics WHERE id = ?",
                    (row_id,),
                ).fetchone()
                if row is not None:
                    pdf_path = row[0]
                    if pdf_path and os.path.exists(pdf_path):
                        try:
                            os.remove(pdf_path)
                        except OSError as exc:
                            logger.warning(
                                "could not remove queued pdf %s: %s",
                                pdf_path, exc,
                            )
                self._conn.execute(
                    "DELETE FROM queued_forensics WHERE id = ?", (row_id,),
                )
                return

        raise ValueError(f"unknown kind: {kind!r}")

    # ------------------------------------------------------------------- meta

    def size(self) -> dict[str, int]:
        """Return counts of queued events and forensics."""
        with self._lock:
            e = self._conn.execute(
                "SELECT COUNT(*) FROM queued_events",
            ).fetchone()[0]
            f = self._conn.execute(
                "SELECT COUNT(*) FROM queued_forensics",
            ).fetchone()[0]
        return {"events": int(e), "forensics": int(f)}

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error as exc:
                logger.warning("error closing offline queue: %s", exc)
