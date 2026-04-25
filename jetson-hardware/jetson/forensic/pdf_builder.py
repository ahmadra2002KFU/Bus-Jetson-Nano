"""WeasyPrint-based forensic incident PDF builder."""

from __future__ import annotations

import base64
import io
import logging
import os
from datetime import datetime, timezone
from typing import Any, Iterable

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "templates")

_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


# --------------------------------------------------------------------- helpers

def _fmt_float(x: Any, digits: int = 2, suffix: str = "") -> str:
    try:
        return f"{float(x):.{digits}f}{suffix}"
    except (TypeError, ValueError):
        return "—"


def _ts_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(
        timespec="seconds")


def _ts_human(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _png_data_uri(png_bytes: bytes) -> str:
    b64 = base64.b64encode(png_bytes).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _jpeg_data_uri(jpeg_bytes: bytes) -> str:
    b64 = base64.b64encode(jpeg_bytes).decode("ascii")
    return f"data:image/jpeg;base64,{b64}"


def _build_metric_rows(
    attack_type: str,
    details: dict[str, Any],
) -> list[tuple[str, str]]:
    at = (attack_type or "").lower()
    rows: list[tuple[str, str]] = []

    if at == "ddos":
        rate_bps = details.get("rate_bps")
        rate_mbps = (float(rate_bps) / 1_000_000.0) if rate_bps is not None else None
        rows.append(("Inbound rate", _fmt_float(rate_mbps, 2, " Mbps")
                     if rate_mbps is not None else "—"))
        rows.append(("Packet loss", _fmt_float(details.get("loss_pct"),
                                               2, " %")))
        rows.append(("Round-trip time", _fmt_float(details.get("rtt_ms"),
                                                   1, " ms")))
        triggers = details.get("triggers_fired") or []
        if isinstance(triggers, (list, tuple)):
            triggers_str = ", ".join(str(t) for t in triggers) or "—"
        else:
            triggers_str = str(triggers)
        rows.append(("Triggers fired", triggers_str))
    elif at in ("gps_spoof", "gps-spoof", "gps"):
        rows.append(("Speed", _fmt_float(details.get("speed_ms"),
                                         2, " m/s")))
        rows.append(("Position jump", _fmt_float(details.get("jump_m"),
                                                 1, " m")))
        rows.append(("Corridor offset",
                     _fmt_float(details.get("corridor_m"), 1, " m")))
        rows.append(("Source address",
                     str(details.get("src_addr") or "—")))
        flags = details.get("anomaly_flags") or []
        if isinstance(flags, (list, tuple)):
            flags_str = ", ".join(str(f) for f in flags) or "—"
        else:
            flags_str = str(flags)
        rows.append(("Anomaly flags", flags_str))
    else:
        for k, v in (details or {}).items():
            rows.append((str(k), str(v)))

    return rows


def _render_gps_trace_png(
    gps_trace: Iterable[tuple[float, float]],
    route_polyline: Iterable[tuple[float, float]] | None,
) -> bytes | None:
    """Render a small PNG of the GPS trace + route overlay."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib unavailable; skipping GPS trace figure")
        return None

    trace_pts = list(gps_trace or [])
    if not trace_pts:
        return None

    fig = plt.figure(figsize=(6.5, 4.0), dpi=110)
    try:
        ax = fig.add_subplot(1, 1, 1)

        if route_polyline:
            route_pts = list(route_polyline)
            if route_pts:
                rx = [p[0] for p in route_pts]
                ry = [p[1] for p in route_pts]
                ax.plot(rx, ry, color="#9aa8b8", linewidth=1.2,
                        alpha=0.6, label="Route")

            tx = [p[0] for p in trace_pts]
            ty = [p[1] for p in trace_pts]
            ax.plot(tx, ty, color="#0b3d66", linewidth=1.6,
                    label="Observed trace")
            ax.scatter(tx, ty, s=8, c="#0b3d66")
            ax.scatter([tx[-1]], [ty[-1]], s=40, c="#c0392b",
                       marker="o", label="Latest fix")
        else:
            tx = [p[0] for p in trace_pts]
            ty = [p[1] for p in trace_pts]
            ax.plot(tx, ty, color="#0b3d66", linewidth=1.6,
                    label="Observed trace")
            ax.scatter(tx, ty, s=8, c="#0b3d66")
            ax.scatter([tx[-1]], [ty[-1]], s=40, c="#c0392b",
                       marker="o", label="Latest fix")

        ax.set_xlabel("X (m)")
        ax.set_ylabel("Y (m)")
        ax.set_title("GPS trace (recent positions)")
        ax.grid(True, linestyle=":", alpha=0.5)
        ax.legend(loc="best", fontsize=8)
        ax.set_aspect("equal", adjustable="datalim")

        buf = io.BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format="png", bbox_inches="tight")
        return buf.getvalue()
    finally:
        plt.close(fig)


def _prepare_events(recent_events: list[dict[str, Any]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for ev in recent_events or []:
        try:
            ts = float(ev.get("ts", 0.0))
        except (TypeError, ValueError):
            ts = 0.0
        out.append({
            "ts_human": _ts_human(ts) if ts else "—",
            "type":     str(ev.get("type", "")),
            "value1":   str(ev.get("value1", "")),
            "value2":   str(ev.get("value2", "")),
            "detail":   str(ev.get("detail", "")),
        })
    return out


def _badge_class(attack_type: str) -> str:
    at = (attack_type or "").lower()
    if at == "ddos":
        return "badge-ddos"
    if at in ("gps_spoof", "gps-spoof", "gps"):
        return "badge-gps-spoof"
    return "badge-unknown"


def _attack_label(attack_type: str) -> str:
    at = (attack_type or "").lower()
    if at == "ddos":
        return "DDoS"
    if at in ("gps_spoof", "gps-spoof", "gps"):
        return "GPS SPOOF"
    return (attack_type or "UNKNOWN").upper()


# ------------------------------------------------------------------- public API

def build_incident_pdf(
    *,
    bus_id: int,
    attack_type: str,
    trigger_ts: float,
    detection_details: dict,
    camera_jpeg: bytes | None,
    recent_events: list[dict],
    gps_trace: list[tuple[float, float]] | None,
    route_polyline: list[tuple[float, float]] | None,
) -> bytes:
    """Render a forensic incident report as a PDF and return its bytes.

    The HTML template lives at ``jetson/forensic/templates/report.html`` and
    is rendered with Jinja2, then converted to PDF with WeasyPrint.
    """
    from weasyprint import HTML  # local import; heavy native deps

    camera_uri = _jpeg_data_uri(camera_jpeg) if camera_jpeg else None

    gps_png: bytes | None = None
    if gps_trace:
        gps_png = _render_gps_trace_png(gps_trace, route_polyline)
    gps_uri = _png_data_uri(gps_png) if gps_png else None

    ctx = {
        "bus_id":            int(bus_id),
        "attack_type_label": _attack_label(attack_type),
        "badge_class":       _badge_class(attack_type),
        "trigger_iso":       _ts_iso(trigger_ts),
        "trigger_human":     _ts_human(trigger_ts),
        "metric_rows":       _build_metric_rows(attack_type,
                                                detection_details or {}),
        "camera_data_uri":   camera_uri,
        "gps_map_data_uri":  gps_uri,
        "events":            _prepare_events(recent_events or []),
        "generation_ts":     _ts_human(
            datetime.now(tz=timezone.utc).timestamp()),
    }

    template = _env.get_template("report.html")
    html_str = template.render(**ctx)

    pdf_bytes = HTML(string=html_str, base_url=_TEMPLATE_DIR).write_pdf()
    logger.info(
        "forensic PDF built: bus=%d attack=%s size=%d bytes",
        bus_id, attack_type, len(pdf_bytes),
    )
    return pdf_bytes
