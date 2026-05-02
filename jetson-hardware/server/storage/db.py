"""Async SQLite storage layer for the Al-Ahsa Smart Bus server."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import aiosqlite

DEFAULT_DB_PATH = "/data/server.db"
DEFAULT_FORENSICS_DIR = "/data/forensics"

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS events (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      REAL    NOT NULL,
        bus_id  INTEGER NOT NULL,
        type    TEXT    NOT NULL,
        value1  REAL,
        value2  REAL,
        detail  TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS metrics (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        ts              REAL    NOT NULL,
        bus_id          INTEGER NOT NULL,
        rx_bps          REAL,
        cctv_bps        REAL,
        gps_pps         REAL,
        heartbeat_loss  REAL,
        rtt_ms          REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS forensics (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          REAL    NOT NULL,
        bus_id      INTEGER NOT NULL,
        attack_type TEXT    NOT NULL,
        pdf_path    TEXT    NOT NULL,
        bytes       INTEGER NOT NULL,
        sha256      TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        TEXT    NOT NULL,
        action    TEXT    NOT NULL,
        actor_ip  TEXT,
        target    TEXT,
        detail    TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
    """
    CREATE TABLE IF NOT EXISTS gps_positions (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        ts       REAL    NOT NULL,
        bus_id   INTEGER NOT NULL,
        pos_x    REAL,
        pos_y    REAL,
        src_addr TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_ts         ON events(ts)",
    "CREATE INDEX IF NOT EXISTS idx_metrics_ts        ON metrics(ts)",
    "CREATE INDEX IF NOT EXISTS idx_metrics_bus_ts    ON metrics(bus_id, ts)",
    "CREATE INDEX IF NOT EXISTS idx_forensics_ts      ON forensics(ts)",
    "CREATE INDEX IF NOT EXISTS idx_gps_ts            ON gps_positions(ts)",
    "CREATE INDEX IF NOT EXISTS idx_gps_bus_ts        ON gps_positions(bus_id, ts)",
]


def get_db_path() -> str:
    return os.environ.get("DB_PATH", DEFAULT_DB_PATH)


def get_forensics_dir() -> str:
    return os.environ.get("FORENSICS_DIR", DEFAULT_FORENSICS_DIR)


async def init_db(db_path: Optional[str] = None) -> None:
    """Create tables and indices if they do not yet exist."""
    path = db_path or get_db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(get_forensics_dir()).mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(path) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.execute("PRAGMA foreign_keys=ON")
        for stmt in SCHEMA:
            await db.execute(stmt)
        # Idempotent migration: SQLite has no `IF NOT EXISTS` for ADD COLUMN,
        # so we attempt and swallow only the "duplicate column" error.
        try:
            await db.execute("ALTER TABLE forensics ADD COLUMN sha256 TEXT")
        except aiosqlite.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
        await db.commit()


# ---------------------------------------------------------------------------
# Audit log DAO
# ---------------------------------------------------------------------------

async def insert_audit(
    action: str,
    *,
    actor_ip: Optional[str] = None,
    target: Optional[str] = None,
    detail: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        cursor = await db.execute(
            "INSERT INTO audit_log(ts, action, actor_ip, target, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (ts, action, actor_ip, target, detail),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def fetch_audit(
    *, limit: int = 100, db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, ts, action, actor_ip, target, detail "
            "FROM audit_log ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Forensic sha256 helper
# ---------------------------------------------------------------------------

async def update_forensic_sha256(
    forensic_id: int, sha256: str, *, db_path: Optional[str] = None
) -> None:
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        await db.execute(
            "UPDATE forensics SET sha256 = ? WHERE id = ?",
            (sha256, forensic_id),
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Event DAO
# ---------------------------------------------------------------------------

async def insert_event(
    bus_id: int,
    type_: str,
    *,
    ts: Optional[float] = None,
    value1: Optional[float] = None,
    value2: Optional[float] = None,
    detail: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
) -> int:
    ts = ts if ts is not None else time.time()
    detail_json = json.dumps(detail) if detail is not None else None
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        cursor = await db.execute(
            "INSERT INTO events(ts, bus_id, type, value1, value2, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, bus_id, type_, value1, value2, detail_json),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def fetch_events(
    *,
    since: Optional[float] = None,
    limit: int = 100,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    sql = "SELECT id, ts, bus_id, type, value1, value2, detail FROM events"
    params: List[Any] = []
    if since is not None:
        sql += " WHERE ts >= ?"
        params.append(since)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(int(limit))

    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
    return [_row_to_event(r) for r in rows]


def _row_to_event(row: aiosqlite.Row) -> Dict[str, Any]:
    detail_raw = row["detail"]
    detail: Any = None
    if detail_raw:
        try:
            detail = json.loads(detail_raw)
        except (TypeError, ValueError):
            detail = detail_raw
    return {
        "id": row["id"],
        "ts": row["ts"],
        "bus_id": row["bus_id"],
        "type": row["type"],
        "value1": row["value1"],
        "value2": row["value2"],
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Metrics DAO
# ---------------------------------------------------------------------------

async def insert_metric(
    bus_id: int,
    *,
    ts: Optional[float] = None,
    rx_bps: Optional[float] = None,
    cctv_bps: Optional[float] = None,
    gps_pps: Optional[float] = None,
    heartbeat_loss: Optional[float] = None,
    rtt_ms: Optional[float] = None,
    db_path: Optional[str] = None,
) -> int:
    ts = ts if ts is not None else time.time()
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        cursor = await db.execute(
            "INSERT INTO metrics(ts, bus_id, rx_bps, cctv_bps, gps_pps, "
            "heartbeat_loss, rtt_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, bus_id, rx_bps, cctv_bps, gps_pps, heartbeat_loss, rtt_ms),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def fetch_metrics(
    bus_id: Optional[int],
    *,
    since: float,
    limit: int = 5000,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    sql = (
        "SELECT ts, bus_id, rx_bps, cctv_bps, gps_pps, heartbeat_loss, rtt_ms "
        "FROM metrics WHERE ts >= ?"
    )
    params: List[Any] = [since]
    if bus_id is not None:
        sql += " AND bus_id = ?"
        params.append(bus_id)
    sql += " ORDER BY ts ASC LIMIT ?"
    params.append(int(limit))

    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def fetch_latest_metric_per_bus(
    *, db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Return the latest **non-null** value per (bus_id, field) for each metric.

    Each metric row only sets a subset of columns — e.g. heartbeat writes only
    ``heartbeat_loss`` and ``rtt_ms``; the CCTV ingester writes ``cctv_bps`` /
    ``rx_bps``; the GPS ingester writes ``gps_pps``. A naive ``MAX(ts)`` join
    therefore returns the most recent row, which is usually a heartbeat with
    most fields ``NULL`` — so the dashboard saw ``cctv_bps``/``rx_bps`` as null
    even when CCTV was actively streaming.

    Instead, for every bus and every field we report the timestamp + value of
    the most recent row whose column is non-null. ``ts`` in the result is the
    maximum of those per-field timestamps (i.e. the freshest update of any
    field for that bus).

    Output shape (unchanged, contract preserved for callers)::
        [{"bus_id": int, "ts": float,
          "rx_bps": float|None, "cctv_bps": float|None, "gps_pps": float|None,
          "heartbeat_loss": float|None, "rtt_ms": float|None}, ...]
    """
    fields = ("rx_bps", "cctv_bps", "gps_pps", "heartbeat_loss", "rtt_ms")

    # One query per field: latest ts for which that column IS NOT NULL, joined
    # back to the row to recover the value. SQLite handles this efficiently
    # via the (bus_id, ts) index. We then merge results in Python.
    per_bus: Dict[int, Dict[str, Any]] = {}

    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        for field in fields:
            sql = f"""
                SELECT m.bus_id, m.ts, m.{field} AS value
                FROM metrics m
                JOIN (
                    SELECT bus_id, MAX(ts) AS max_ts
                    FROM metrics
                    WHERE {field} IS NOT NULL
                    GROUP BY bus_id
                ) latest
                  ON latest.bus_id = m.bus_id AND latest.max_ts = m.ts
                WHERE m.{field} IS NOT NULL
            """
            async with db.execute(sql) as cursor:
                rows = await cursor.fetchall()
            for r in rows:
                bus_id = int(r["bus_id"])
                entry = per_bus.setdefault(
                    bus_id,
                    {
                        "bus_id": bus_id,
                        "ts": 0.0,
                        "rx_bps": None,
                        "cctv_bps": None,
                        "gps_pps": None,
                        "heartbeat_loss": None,
                        "rtt_ms": None,
                    },
                )
                entry[field] = r["value"]
                ts = float(r["ts"])
                if ts > entry["ts"]:
                    entry["ts"] = ts

    return list(per_bus.values())


# ---------------------------------------------------------------------------
# Forensics DAO
# ---------------------------------------------------------------------------

async def insert_forensic(
    bus_id: int,
    attack_type: str,
    pdf_path: str,
    size_bytes: int,
    *,
    ts: Optional[float] = None,
    db_path: Optional[str] = None,
) -> int:
    ts = ts if ts is not None else time.time()
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        cursor = await db.execute(
            "INSERT INTO forensics(ts, bus_id, attack_type, pdf_path, bytes) "
            "VALUES (?, ?, ?, ?, ?)",
            (ts, bus_id, attack_type, pdf_path, size_bytes),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def fetch_forensics(
    *,
    bus_id: Optional[int] = None,
    attack_type: Optional[str] = None,
    since: Optional[float] = None,
    until: Optional[float] = None,
    limit: int = 50,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    sql = "SELECT id, ts, bus_id, attack_type, pdf_path, bytes, sha256 FROM forensics WHERE 1=1"
    params: List[Any] = []
    if bus_id is not None:
        sql += " AND bus_id = ?"
        params.append(bus_id)
    if attack_type:
        sql += " AND attack_type = ?"
        params.append(attack_type)
    if since is not None:
        sql += " AND ts >= ?"
        params.append(since)
    if until is not None:
        sql += " AND ts <= ?"
        params.append(until)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(int(limit))

    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
    return [
        {**dict(r), "url": f"/forensics/{r['id']}.pdf"} for r in rows
    ]


async def fetch_forensic(
    forensic_id: int, *, db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, ts, bus_id, attack_type, pdf_path, bytes, sha256 "
            "FROM forensics WHERE id = ?",
            (forensic_id,),
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# GPS positions DAO
# ---------------------------------------------------------------------------

async def insert_gps_position(
    bus_id: int,
    pos_x: float,
    pos_y: float,
    src_addr: str,
    *,
    ts: Optional[float] = None,
    db_path: Optional[str] = None,
) -> int:
    ts = ts if ts is not None else time.time()
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        cursor = await db.execute(
            "INSERT INTO gps_positions(ts, bus_id, pos_x, pos_y, src_addr) "
            "VALUES (?, ?, ?, ?, ?)",
            (ts, bus_id, pos_x, pos_y, src_addr),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def fetch_recent_gps(
    bus_id: int,
    *,
    limit: int = 1,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT ts, bus_id, pos_x, pos_y, src_addr FROM gps_positions "
            "WHERE bus_id = ? ORDER BY ts DESC LIMIT ?",
            (bus_id, int(limit)),
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Bus registry
# ---------------------------------------------------------------------------

async def fetch_known_buses(*, db_path: Optional[str] = None) -> List[int]:
    """Return all bus_ids that have ever produced a metric, gps, or event row."""
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT DISTINCT bus_id FROM metrics "
            "UNION SELECT DISTINCT bus_id FROM gps_positions "
            "UNION SELECT DISTINCT bus_id FROM events"
        ) as cursor:
            rows = await cursor.fetchall()
    return sorted({int(r["bus_id"]) for r in rows})


# ---------------------------------------------------------------------------
# Retention helpers
# ---------------------------------------------------------------------------

async def purge_older_than(
    table: str, cutoff_ts: float, *, db_path: Optional[str] = None
) -> int:
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        cursor = await db.execute(
            f"DELETE FROM {table} WHERE ts < ?", (cutoff_ts,)
        )
        await db.commit()
        return cursor.rowcount or 0


async def fetch_old_forensics(
    cutoff_ts: float, *, db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, pdf_path FROM forensics WHERE ts < ?", (cutoff_ts,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def delete_forensic_ids(
    ids: Iterable[int], *, db_path: Optional[str] = None
) -> int:
    ids = list(ids)
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    async with aiosqlite.connect(db_path or get_db_path()) as db:
        cursor = await db.execute(
            f"DELETE FROM forensics WHERE id IN ({placeholders})", ids
        )
        await db.commit()
        return cursor.rowcount or 0
