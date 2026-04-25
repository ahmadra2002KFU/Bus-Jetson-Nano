"""FastAPI application factory for the Al-Ahsa Smart Bus server.

Mounts ingest, api, and dashboard routers; initialises SQLite; starts the
retention background task; wires up the async GPS spoof detector so the
ingest WebSocket can feed frames into it.

Run under uvicorn:
    uvicorn server.app:app --host 0.0.0.0 --port 3232
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from server.detection.gps_detector import ServerGpsDetector
from server.routers import api as api_router
from server.routers import dashboard as dashboard_router
from server.routers import ingest as ingest_router
from server.storage import db
from server.storage import retention as retention_mod
from server.storage.db import insert_event

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


def _make_gps_event_sink():
    """Return an async callback that persists GPS spoof events."""
    async def _sink(details: dict) -> None:
        try:
            await insert_event(
                int(details.get("bus_id", 0)),
                "gps_spoof",
                ts=float(details.get("timestamp") or 0) or None,
                value1=float(details.get("speed") or 0.0),
                value2=float(details.get("corridor_dist") or 0.0),
                detail=details,
            )
        except Exception:
            logger.exception("gps spoof sink failed")
    return _sink


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    _configure_logging()
    await db.init_db()

    app.state.heartbeat_state = {}
    app.state.gps_detector = ServerGpsDetector(on_detect=_make_gps_event_sink())
    app.state.retention_stop = asyncio.Event()
    app.state.retention_task = asyncio.create_task(
        retention_mod.retention_loop(app.state.retention_stop),
        name="retention-loop",
    )

    logger.info("server startup complete (build=%s)", os.environ.get("BUILD_SHA") or "dev")
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
