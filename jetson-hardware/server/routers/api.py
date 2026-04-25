"""JSON API consumed by the HTMX dashboard."""

from __future__ import annotations

import time
from functools import lru_cache
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from jetson.routes import create_routes, get_bus_route_assignment

from ..storage import db

router = APIRouter(prefix="/api")


@lru_cache(maxsize=1)
def _routes_payload() -> Dict[str, Any]:
    return {
        "routes": [[(p[0], p[1]) for p in r] for r in create_routes()],
        "assignment": list(get_bus_route_assignment()),
    }


@router.get("/routes")
async def api_routes() -> Dict[str, Any]:
    return _routes_payload()

RANGE_WINDOWS_S: Dict[str, float] = {
    "1h": 3600.0,
    "24h": 86400.0,
    "7d": 7 * 86400.0,
}


@router.get("/events")
async def api_events(
    since: Optional[float] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    return await db.fetch_events(since=since, limit=limit)


@router.get("/metrics")
async def api_metrics(
    bus_id: Optional[int] = Query(None, ge=0),
    range: str = Query("1h", pattern=r"^(1h|24h|7d)$"),
    limit: int = Query(5000, ge=1, le=50000),
) -> Dict[str, Any]:
    window = RANGE_WINDOWS_S.get(range)
    if window is None:
        raise HTTPException(status_code=400, detail="invalid range")
    since = time.time() - window
    series = await db.fetch_metrics(bus_id, since=since, limit=limit)
    return {"bus_id": bus_id, "range": range, "series": series}


@router.get("/forensics")
async def api_forensics(
    bus_id: Optional[int] = Query(None, ge=0),
    attack_type: Optional[str] = Query(None),
    since: Optional[float] = Query(None),
    until: Optional[float] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    return await db.fetch_forensics(
        bus_id=bus_id,
        attack_type=attack_type,
        since=since,
        until=until,
        limit=limit,
    )


@router.post("/detector/reset")
async def reset_detector(
    request: Request,
    bus_id: Optional[int] = Query(None, ge=0),
) -> Dict[str, Any]:
    """Clear the server-side GPS detector's per-bus latch.

    With ``bus_id``: reset only that bus.
    Without ``bus_id``: reset every known bus.
    Subsequent spoof attempts can re-fire the one-shot detector.
    """
    detector = request.app.state.gps_detector
    cleared: List[int] = []
    if bus_id is not None:
        detector.reset_bus(bus_id)
        cleared.append(bus_id)
    else:
        for bid in list(detector._states.keys()):  # noqa: SLF001
            detector.reset_bus(bid)
            cleared.append(bid)
    return {"reset": cleared}


@router.get("/buses")
async def api_buses() -> List[Dict[str, Any]]:
    known = await db.fetch_known_buses()
    latest = {row["bus_id"]: row for row in await db.fetch_latest_metric_per_bus()}

    out: List[Dict[str, Any]] = []
    for bus_id in known:
        metric = latest.get(bus_id, {})
        gps_rows = await db.fetch_recent_gps(bus_id, limit=1)
        last_gps = gps_rows[0] if gps_rows else None
        out.append({
            "bus_id": bus_id,
            "last_metric_ts": metric.get("ts"),
            "rx_bps": metric.get("rx_bps"),
            "cctv_bps": metric.get("cctv_bps"),
            "gps_pps": metric.get("gps_pps"),
            "heartbeat_loss": metric.get("heartbeat_loss"),
            "rtt_ms": metric.get("rtt_ms"),
            "last_gps": last_gps,
        })
    return out
