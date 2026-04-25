"""Dashboard HTML + forensic PDF download routes."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from ..storage import db

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"build": os.environ.get("BUILD_SHA") or "dev"},
    )


@router.get("/forensics/{forensic_id}.pdf")
async def forensic_pdf(forensic_id: int) -> FileResponse:
    row = await db.fetch_forensic(forensic_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    pdf_path = Path(row["pdf_path"])
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="file missing")
    filename = (
        f"forensic_{forensic_id}_bus{row['bus_id']}_{row['attack_type']}.pdf"
    )
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=filename,
    )
