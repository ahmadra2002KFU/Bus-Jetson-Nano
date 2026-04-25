"""FastAPI application factory for the Al-Ahsa Smart Bus server.

Mounts ingest, api, and dashboard routers; initialises SQLite; starts the
retention background task; wires up the async GPS spoof detector so the
ingest WebSocket can feed frames into it. On a server-side spoof
trigger, also renders a forensic PDF and stores it as a `forensics` row
so the dashboard archive can serve it.

Run under uvicorn:
    uvicorn server.app:app --host 0.0.0.0 --port 3232
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from jetson.routes import create_routes, get_bus_route_assignment

from server.detection.gps_detector import ServerGpsDetector
from server.forensic.pdf_builder import build_spoof_pdf
from server.routers import api as api_router
from server.routers import dashboard as dashboard_router
from server.routers import ingest as ingest_router
from server.storage import db
from server.storage import retention as retention_mod

logger = logging.getLogger(__name__)

_PACKAGE_DIR = Path(__file__).resolve().parent
_TEMPLATES_DIR = _PACKAGE_DIR / "templates"
_STATIC_DIR = _PACKAGE_DIR / "static"


def _configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    root = logging.getLogger()
    if root.handlers:
        root.setLevel(level)
        return
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _build_sha() -> str:
    return os.environ.get("BUILD_SHA") or "dev"


# ---------------------------------------------------------------------------
# GPS spoof handler — writes the event AND renders/stores the forensic PDF
# ---------------------------------------------------------------------------

def _make_gps_spoof_handler():
    routes = create_routes()
    assignment = get_bus_route_assignment()

    async def _handler(details: Dict[str, Any]) -> None:
        bus_id = int(details.get("bus_id", 0))
        ts = float(details.get("timestamp") or time.time())

        # 1. Persist the event row (the only place gps_spoof is recorded;
        #    the ingest router intentionally does not duplicate this).
        try:
            await db.insert_event(
                bus_id,
                "gps_spoof",
                ts=ts,
                value1=float(details.get("speed") or 0.0),
                value2=float(details.get("corridor_dist") or 0.0),
                detail=details,
            )
        except Exception:
            logger.exception("gps spoof event insert failed")

        # 2. Render + store the forensic PDF in the background so the WS
        #    handler that triggered us doesn't stall.
        asyncio.create_task(
            _render_and_store_spoof_pdf(bus_id, ts, details, routes, assignment),
            name=f"spoof-pdf-{bus_id}-{int(ts)}",
        )

    return _handler


async def _render_and_store_spoof_pdf(
    bus_id: int,
    trigger_ts: float,
    details: Dict[str, Any],
    routes,
    assignment,
) -> None:
    try:
        gps_rows = await db.fetch_recent_gps(bus_id, limit=60)
        gps_trace = [(r["pos_x"], r["pos_y"]) for r in reversed(gps_rows)]

        route_polyline = None
        if 0 <= bus_id < len(assignment):
            idx = assignment[bus_id]
            if 0 <= idx < len(routes):
                route_polyline = list(routes[idx])

        recent_events = await db.fetch_events(limit=8)

        pdf_bytes = await build_spoof_pdf(
            bus_id=bus_id,
            trigger_ts=trigger_ts,
            details=details,
            gps_trace=gps_trace,
            route_polyline=route_polyline,
            recent_events=recent_events,
            build=_build_sha(),
        )

        forensics_dir = Path(db.get_forensics_dir())
        forensics_dir.mkdir(parents=True, exist_ok=True)
        fname = f"spoof_{bus_id}_{int(trigger_ts)}_{uuid.uuid4().hex[:8]}.pdf"
        out_path = forensics_dir / fname
        out_path.write_bytes(pdf_bytes)

        forensic_id = await db.insert_forensic(
            bus_id, "gps_spoof", str(out_path), len(pdf_bytes), ts=trigger_ts
        )

        # System event so the dashboard "forensic uploaded" feed shows it.
        await db.insert_event(
            bus_id,
            "forensic_gps_spoof",
            ts=trigger_ts,
            value1=float(len(pdf_bytes)),
            detail={"forensic_id": forensic_id, "source": "server"},
        )
        logger.info(
            "server-side gps_spoof PDF stored: id=%d bus=%d bytes=%d",
            forensic_id, bus_id, len(pdf_bytes),
        )
    except Exception:
        logger.exception("gps spoof PDF generation failed (bus=%d)", bus_id)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    _configure_logging()
    await db.init_db()

    app.state.heartbeat_state = {}
    app.state.gps_detector = ServerGpsDetector(on_detect=_make_gps_spoof_handler())
    app.state.retention_stop = asyncio.Event()
    app.state.retention_task = asyncio.create_task(
        retention_mod.retention_loop(app.state.retention_stop),
        name="retention-loop",
    )

    logger.info("server startup complete (build=%s)", _build_sha())
    try:
        yield
    finally:
        app.state.retention_stop.set()
        task = app.state.retention_task
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        logger.info("server shutdown complete")


def create_app() -> FastAPI:
    """Build and return a FastAPI instance. Safe to import under tests."""
    app = FastAPI(
        title="Al-Ahsa Smart Bus Server",
        version="0.1.0",
        lifespan=_lifespan,
    )

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    app.state.templates = templates

    if _STATIC_DIR.is_dir():
        app.mount(
            "/static", StaticFiles(directory=str(_STATIC_DIR)), name="static"
        )

    app.include_router(ingest_router.router)
    app.include_router(api_router.router)
    app.include_router(dashboard_router.router)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "3232")),
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )
