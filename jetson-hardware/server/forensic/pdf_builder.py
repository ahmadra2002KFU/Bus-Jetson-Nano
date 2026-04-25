"""Server-side WeasyPrint PDF builder for GPS spoofing incidents.

Mirrors the Jetson-side ``jetson.forensic.pdf_builder`` but tailored for
spoof events that originate on the server: there is no camera frame
because the server has no camera, and the GPS trace is reconstructed
from the ``gps_positions`` table.
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def _fmt_float(x: Any, digits: int = 2, suffix: str = "") -> str:
    try:
        return f"{float(x):.{digits}f}{suffix}"
    except (TypeError, ValueError):
        return "—"


def _ts_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _ts_human(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _png_data_uri(png_bytes: bytes) -> str:
    b64 = base64.b64encode(png_bytes).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _spoof_metric_rows(details: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Return [(label, value, css_class), ...] rows for the metrics table."""
    rows: List[Tuple[str, str, str]] = []
    rows.append(("Speed", _fmt_float(details.get("speed"), 2, " m/s"), "bad"))
    rows.append((
        "Position jump",
        _fmt_float(details.get("distance"), 1, " m"),
        "bad" if (details.get("jump_anomaly")) else "",
    ))
    rows.append((
        "Corridor offset",
        _fmt_float(details.get("corridor_dist"), 1, " m"),
        "bad" if (details.get("corridor_anomaly")) else "",
    ))
    rows.append(("Source address", str(details.get("src_addr") or "—"), ""))
    flags = []
    for label, key in (
        ("speed", "speed_anomaly"),
        ("jump", "jump_anomaly"),
        ("corridor", "corridor_anomaly"),
        ("src-change", "src_anomaly"),
    ):
        if details.get(key):
            flags.append(label)
    rows.append(("Anomaly flags", ", ".join(flags) or "—", "flag" if flags else ""))
    rows.append(("Streak length", str(details.get("streak") or "—"), ""))
    return rows


def _render_trace_png(
    gps_trace: Iterable[Tuple[float, float]],
    route_polyline: Optional[Iterable[Tuple[float, float]]],
    spoofed_pos: Optional[Tuple[float, float]] = None,
) -> Optional[bytes]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib unavailable; skipping GPS trace figure")
        return None

    trace = list(gps_trace or [])
    fig = plt.figure(figsize=(7.0, 4.5), dpi=110)
    try:
        ax = fig.add_subplot(1, 1, 1)
        if route_polyline:
            rp = list(route_polyline)
            if rp:
                rx = [p[0] for p in rp]
                ry = [p[1] for p in rp]
                ax.plot(rx, ry, color="#94a3b8", linewidth=1.4, alpha=0.85, label="Assigned route")
        if trace:
            tx = [p[0] for p in trace]
            ty = [p[1] for p in trace]
            ax.plot(tx, ty, color="#0b3d66", linewidth=1.4, label="Observed trace")
            ax.scatter(tx, ty, s=10, c="#0b3d66")
            ax.scatter([tx[-1]], [ty[-1]], s=46, c="#c0392b", marker="o", label="Latest fix")
        if spoofed_pos is not None:
            sx, sy = spoofed_pos
            ax.scatter([sx], [sy], s=80, c="#dc2626", marker="X", label="Spoofed position")
        ax.set_xlabel("X (m)")
        ax.set_ylabel("Y (m)")
        ax.set_title("Recent GPS positions vs. assigned route")
        ax.grid(True, linestyle=":", alpha=0.45)
        ax.legend(loc="best", fontsize=8)
        ax.set_aspect("equal", adjustable="datalim")
        buf = io.BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format="png", bbox_inches="tight")
        return buf.getvalue()
    finally:
        plt.close(fig)


def _prepare_events(rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for r in rows or []:
        try:
            ts = float(r.get("ts", 0.0))
        except (TypeError, ValueError):
            ts = 0.0
        detail = r.get("detail")
        if isinstance(detail, dict):
            try:
                import json
                detail = json.dumps(detail, separators=(",", ":"))[:200]
            except Exception:
                detail = str(detail)[:200]
        else:
            detail = str(detail or "")[:200]
        out.append({
            "ts_human": _ts_human(ts) if ts else "—",
            "type": str(r.get("type", "")),
            "detail": detail,
        })
    return out


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

def build_spoof_pdf_sync(
    *,
    bus_id: int,
    trigger_ts: float,
    details: Dict[str, Any],
    gps_trace: Optional[Iterable[Tuple[float, float]]],
    route_polyline: Optional[Iterable[Tuple[float, float]]],
    recent_events: Optional[List[Dict[str, Any]]],
    build: str,
) -> bytes:
    """Synchronous renderer (called from a thread executor)."""
    from weasyprint import HTML  # heavy import; defer

    spoofed = None
    try:
        spoofed = (float(details.get("last_pos_x")), float(details.get("last_pos_y")))
    except (TypeError, ValueError):
        # Fall back: the spoofed position is the latest trace point.
        if gps_trace:
            tail = list(gps_trace)
            if tail:
                spoofed = tail[-1]

    png = _render_trace_png(gps_trace or [], route_polyline, spoofed)
    gps_uri = _png_data_uri(png) if png else None

    ctx = {
        "bus_id": int(bus_id),
        "trigger_iso": _ts_iso(trigger_ts),
        "trigger_human": _ts_human(trigger_ts),
        "metric_rows": _spoof_metric_rows(details or {}),
        "gps_map_data_uri": gps_uri,
        "events": _prepare_events(recent_events or []),
        "generation_human": _ts_human(datetime.now(tz=timezone.utc).timestamp()),
        "build": build or "dev",
    }

    template = _env.get_template("spoof_report.html")
    html_str = template.render(**ctx)
    pdf = HTML(string=html_str, base_url=str(_TEMPLATE_DIR)).write_pdf()
    return pdf


async def build_spoof_pdf(
    *,
    bus_id: int,
    trigger_ts: float,
    details: Dict[str, Any],
    gps_trace: Optional[Iterable[Tuple[float, float]]],
    route_polyline: Optional[Iterable[Tuple[float, float]]],
    recent_events: Optional[List[Dict[str, Any]]],
    build: str,
) -> bytes:
    """Async wrapper that runs WeasyPrint + matplotlib in a thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: build_spoof_pdf_sync(
            bus_id=bus_id, trigger_ts=trigger_ts, details=details,
            gps_trace=gps_trace, route_polyline=route_polyline,
            recent_events=recent_events, build=build,
        ),
    )
