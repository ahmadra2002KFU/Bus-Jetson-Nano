"""Dashboard HTML + forensic PDF download routes."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from ..storage import db

router = APIRouter()

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def _asset_version() -> str:
    """Cache-bust token derived from the latest static-asset mtime.

    Recomputed per request (cheap stat) so any redeploy / file edit on
    the server invalidates browser caches without a hard refresh.
    """
    latest = 0.0
    for name in ("dashboard.css", "dashboard.js"):
        p = _STATIC_DIR / name
        try:
            latest = max(latest, p.stat().st_mtime)
        except OSError:
            pass
    return f"{int(latest)}"


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "build": os.environ.get("BUILD_SHA") or "dev",
            "asset_v": _asset_version(),
        },
    )


@router.get("/forensics/{forensic_id}.pdf")
async def forensic_pdf(forensic_id: int, request: Request) -> FileResponse:
    import json as _json
    row = await db.fetch_forensic(forensic_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    pdf_path = Path(row["pdf_path"])
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="file missing")
    filename = (
        f"forensic_{forensic_id}_bus{row['bus_id']}_{row['attack_type']}.pdf"
    )
    actor_ip = request.client.host if request.client else None
    try:
        await db.insert_audit(
            "DOWNLOAD",
            actor_ip=actor_ip,
            target=str(forensic_id),
            detail=_json.dumps({"sha256": row.get("sha256"),
                                "bytes": row.get("bytes")}),
        )
    except Exception:
        pass
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=filename,
    )
