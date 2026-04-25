"""Ingest endpoints: GPS/CCTV WebSockets, ticket POST, heartbeat, forensic upload."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import struct
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import (
    APIRouter, File, Form, HTTPException, Query, Request, UploadFile,
    WebSocket, WebSocketDisconnect,
)

from ..detection.gps_detector import ServerGpsDetector
from ..storage import db

logger = logging.getLogger(__name__)

router = APIRouter()

# GPS binary wire format: <I I d d>  ("GPS1", bus_id, pos_x, pos_y)
GPS_MAGIC = 0x47505331
GPS_FRAME_SIZE = 200
GPS_HEADER_FMT = "<IIdd"
GPS_HEADER_SIZE = struct.calcsize(GPS_HEADER_FMT)  # 24

CCTV_FRAME_SIZE = 1400
CCTV_FLUSH_INTERVAL_S = 5.0
MAX_HEARTBEAT_BUS_ID = 1_000_000

_SAFE_ATTACK_TYPE = re.compile(r"^[a-z0-9_\-]{1,32}$")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/health")
async def health() -> Dict[str, str]:
    build = os.environ.get("BUILD_SHA") or "dev"
    return {"status": "ok", "build": build}


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

@router.get("/health/heartbeat")
async def heartbeat(
    request: Request,
    bus_id: int = Query(..., ge=0, le=MAX_HEARTBEAT_BUS_ID),
    seq: int = Query(..., ge=0),
    ts: float = Query(..., gt=0),
) -> Dict[str, Any]:
    """Return server time so the client can compute RTT."""
    server_ts = time.time()
    app = request.app
    registry: Dict[int, Dict[str, float]] = app.state.heartbeat_state
    st = registry.setdefault(bus_id, {"last_seq": -1.0, "count": 0.0, "last_ts": 0.0})

    prev_seq = int(st["last_seq"])
    st["count"] += 1.0
    st["last_seq"] = float(seq)
    st["last_ts"] = server_ts

    rtt_ms: Optional[float] = None
    if ts > 0:
        rtt_candidate = (server_ts - ts) * 1000.0
        if 0.0 <= rtt_candidate <= 60_000.0:
            rtt_ms = rtt_candidate

    loss: Optional[float] = None
    if prev_seq >= 0 and seq > prev_seq:
        expected = seq - prev_seq
        if expected > 0:
            missed = expected - 1
            loss = max(0.0, min(1.0, missed / expected))

    try:
        await db.insert_metric(
            bus_id,
            ts=server_ts,
            heartbeat_loss=loss,
            rtt_ms=rtt_ms,
        )
    except Exception:
        logger.exception("heartbeat: metric insert failed (bus_id=%d)", bus_id)

    return {"server_ts": server_ts, "echo_seq": seq}


# ---------------------------------------------------------------------------
# GPS WebSocket
# ---------------------------------------------------------------------------

@router.websocket("/ingest/gps")
async def ingest_gps(ws: WebSocket) -> None:
    await ws.accept()
    src_addr = _format_client(ws)
    app = ws.app
    detector: ServerGpsDetector = app.state.gps_detector

    last_pps_mark = time.monotonic()
    pps_counter: Dict[int, int] = {}
    try:
        while True:
            frame = await ws.receive_bytes()
            if len(frame) < GPS_HEADER_SIZE:
                continue
            # Accept any frame >= header; enforce exact 200 B when possible.
            if len(frame) != GPS_FRAME_SIZE:
                logger.debug(
                    "GPS frame size %d (expected %d) from %s",
                    len(frame), GPS_FRAME_SIZE, src_addr,
                )
            try:
                magic, bus_id, pos_x, pos_y = struct.unpack(
                    GPS_HEADER_FMT, frame[:GPS_HEADER_SIZE]
                )
            except struct.error:
                continue
            if magic != GPS_MAGIC:
                continue

            ts = time.time()
            try:
                await db.insert_gps_position(
                    bus_id, pos_x, pos_y, src_addr, ts=ts
                )
            except Exception:
                logger.exception("GPS insert failed (bus_id=%d)", bus_id)

            pps_counter[bus_id] = pps_counter.get(bus_id, 0) + 1

            result = await detector.process(bus_id, pos_x, pos_y, src_addr)
            if result.triggered:
                try:
                    await db.insert_event(
                        bus_id,
                        "gps_spoof",
                        ts=ts,
                        value1=result.speed,
                        value2=result.corridor_dist,
                        detail=result.details,
                    )
                except Exception:
                    logger.exception("GPS event insert failed")

            # Flush per-bus pps into metrics every ~5 s.
            now = time.monotonic()
            if now - last_pps_mark >= CCTV_FLUSH_INTERVAL_S:
                window = now - last_pps_mark
                for b, count in pps_counter.items():
                    pps = count / window if window > 0 else 0.0
                    try:
                        await db.insert_metric(b, ts=ts, gps_pps=pps)
                    except Exception:
                        logger.exception("GPS pps metric insert failed")
                pps_counter.clear()
                last_pps_mark = now
    except WebSocketDisconnect:
        logger.info("GPS WS disconnected from %s", src_addr)
    except Exception:
        logger.exception("GPS WS error from %s", src_addr)
        try:
            await ws.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CCTV WebSocket
# ---------------------------------------------------------------------------

@router.websocket("/ingest/cctv")
async def ingest_cctv(
    ws: WebSocket,
    bus_id: int = Query(..., ge=0, le=MAX_HEARTBEAT_BUS_ID),
) -> None:
    await ws.accept()
    src_addr = _format_client(ws)
    last_flush = time.monotonic()
    bytes_since_flush = 0
    try:
        while True:
            frame = await ws.receive_bytes()
            bytes_since_flush += len(frame)

            now = time.monotonic()
            elapsed = now - last_flush
            if elapsed >= CCTV_FLUSH_INTERVAL_S:
                bps = (bytes_since_flush * 8.0) / elapsed if elapsed > 0 else 0.0
                try:
                    await db.insert_metric(
                        bus_id, ts=time.time(), cctv_bps=bps, rx_bps=bps
                    )
                except Exception:
                    logger.exception(
                        "CCTV metric insert failed (bus_id=%d)", bus_id
                    )
                bytes_since_flush = 0
                last_flush = now
    except WebSocketDisconnect:
        logger.info("CCTV WS disconnected from %s (bus_id=%d)", src_addr, bus_id)
    except Exception:
        logger.exception("CCTV WS error from %s (bus_id=%d)", src_addr, bus_id)
        try:
            await ws.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Ticketing POST
# ---------------------------------------------------------------------------

@router.post("/ingest/ticket")
async def ingest_ticket(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        bus_id = int(payload["bus_id"])
        ts = float(payload.get("ts") or time.time())
        txn_id = str(payload["txn_id"])
        size_bytes = int(payload.get("size_bytes") or 0)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid body: {exc}")

    detail = {"txn_id": txn_id, "size_bytes": size_bytes}
    event_id = await db.insert_event(
        bus_id, "ticket", ts=ts, value1=float(size_bytes), detail=detail
    )
    return {"id": event_id, "status": "ok"}


# ---------------------------------------------------------------------------
# Forensic upload
# ---------------------------------------------------------------------------

@router.post("/ingest/forensic")
async def ingest_forensic(
    metadata: str = Form(...),
    pdf: UploadFile = File(...),
) -> Dict[str, Any]:
    try:
        meta = json.loads(metadata)
        bus_id = int(meta["bus_id"])
        attack_type = str(meta["attack_type"]).lower().strip()
        trigger_ts = float(meta.get("trigger_ts") or time.time())
        details = meta.get("details") or {}
        if not isinstance(details, dict):
            raise ValueError("details must be an object")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid metadata: {exc}")

    if not _SAFE_ATTACK_TYPE.match(attack_type):
        raise HTTPException(status_code=400, detail="invalid attack_type")

    if pdf.content_type not in ("application/pdf", "application/octet-stream"):
        raise HTTPException(status_code=415, detail="expected application/pdf")

    forensics_dir = Path(db.get_forensics_dir())
    forensics_dir.mkdir(parents=True, exist_ok=True)

    # Allocate a DB row first to get the canonical id, then write the file.
    size_placeholder = 0
    pending_path = forensics_dir / f"_pending_{bus_id}_{int(trigger_ts*1000)}.pdf"
    forensic_id = await db.insert_forensic(
        bus_id, attack_type, str(pending_path), size_placeholder, ts=trigger_ts
    )

    final_name = f"{forensic_id}_{bus_id}_{attack_type}_{int(trigger_ts)}.pdf"
    final_path = forensics_dir / final_name

    try:
        size = await _save_upload_file(pdf, final_path)
    except Exception:
        # Best-effort cleanup: delete the DB row we just wrote.
        try:
            await db.delete_forensic_ids([forensic_id])
        except Exception:
            logger.exception("forensic: rollback delete failed")
        logger.exception("forensic: PDF save failed")
        raise HTTPException(status_code=500, detail="failed to save pdf")

    # Update the row with the real path + size.
    import aiosqlite
    async with aiosqlite.connect(db.get_db_path()) as conn:
        await conn.execute(
            "UPDATE forensics SET pdf_path = ?, bytes = ? WHERE id = ?",
            (str(final_path), size, forensic_id),
        )
        await conn.commit()

    try:
        await db.insert_event(
            bus_id,
            f"forensic_{attack_type}",
            ts=trigger_ts,
            value1=float(size),
            detail={"forensic_id": forensic_id, **details},
        )
    except Exception:
        logger.exception("forensic: event insert failed")

    return {"id": forensic_id, "url": f"/forensics/{forensic_id}.pdf"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_client(ws: WebSocket) -> str:
    client = ws.client
    if client is None:
        return "unknown"
    host = client.host or "unknown"
    return host


async def _save_upload_file(upload: UploadFile, dest: Path) -> int:
    """Stream ``upload`` to ``dest`` in 64 KiB chunks. Returns bytes written."""
    total = 0
    chunk_size = 64 * 1024
    # Write synchronously but in chunks to avoid blocking the loop excessively.
    # For a prototype under 10 MB typical payloads this is fine.
    loop = asyncio.get_running_loop()

    def _write() -> int:
        written = 0
        with open(dest, "wb") as fh:
            while True:
                chunk = upload.file.read(chunk_size)
                if not chunk:
                    break
                fh.write(chunk)
                written += len(chunk)
        return written

    total = await loop.run_in_executor(None, _write)
    return total
