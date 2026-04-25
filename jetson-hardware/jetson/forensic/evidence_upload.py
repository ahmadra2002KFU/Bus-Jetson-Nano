"""Forensic upload — HTTPS multipart POST to {server_url}/ingest/forensic.

Replaces the TCP bulk uploader. Accepts the PDF bytes produced by
``evidence_capture.capture_evidence`` plus a metadata dict and uploads
both as multipart/form-data.

Return shape is preserved so the existing callback path keeps working:
    {"upload_start": float, "upload_finish": float,
     "completed": bool, "bytes_sent": int}
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict

import requests

logger = logging.getLogger(__name__)

_UPLOAD_TIMEOUT = 200.0


def upload_evidence(
    pdf_bytes: bytes,
    metadata: Dict[str, Any],
    *,
    server_url: str,
    session: "requests.Session | None" = None,
) -> Dict[str, Any]:
    """Upload the forensic PDF and metadata to the server.

    Parameters
    ----------
    pdf_bytes : bytes
        The rendered PDF file.
    metadata : dict
        Metadata for the forensic row. Serialised as the ``metadata``
        form field (JSON). Required keys: ``bus_id``, ``attack_type``,
        ``trigger_ts``. Optional: ``details`` (dict).
    server_url : str
        Base URL of the server.
    session : requests.Session, optional
        Reuse a session for connection pooling.

    Returns
    -------
    dict
        Status of the upload. Keys:
        ``upload_start``, ``upload_finish``, ``completed``, ``bytes_sent``.
        ``bytes_sent`` is the PDF size on success, 0 on failure.
    """
    url = server_url.rstrip("/") + "/ingest/forensic"
    sess = session or requests.Session()

    result: Dict[str, Any] = {
        "upload_start": time.time(),
        "upload_finish": 0.0,
        "completed": False,
        "bytes_sent": 0,
    }

    files = {"pdf": ("incident.pdf", pdf_bytes, "application/pdf")}
    data = {"metadata": json.dumps(metadata, separators=(",", ":"))}

    logger.info("forensic upload -> %s (%d bytes)", url, len(pdf_bytes))

    try:
        resp = sess.post(url, files=files, data=data, timeout=_UPLOAD_TIMEOUT)
        result["upload_finish"] = time.time()
        if resp.status_code >= 400:
            logger.error(
                "forensic upload failed status=%d body=%s",
                resp.status_code, resp.text[:200],
            )
            return result
        try:
            body = resp.json()
            logger.info("forensic uploaded: %s", body)
        except ValueError:
            logger.info("forensic uploaded (non-JSON response)")
        result["completed"] = True
        result["bytes_sent"] = len(pdf_bytes)
    except requests.RequestException as exc:
        result["upload_finish"] = time.time()
        logger.error("forensic upload error: %s", exc)
    return result
