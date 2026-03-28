"""Forensic evidence TCP upload to server — 10 MB in 1448-byte chunks."""

import socket
import logging
import time

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1448  # matching ns-3 BulkSendHelper SendSize (line 1287)
CONNECT_TIMEOUT = 10
UPLOAD_TIMEOUT = 200  # matching ns-3 forensic timeout


def upload_evidence(evidence_bytes, server_ip, port=8000):
    """Upload forensic evidence to the server via TCP.

    Args:
        evidence_bytes: The 10 MB evidence package
        server_ip: Server IP address
        port: Forensic upload port (default 8000)

    Returns:
        dict with upload_start, upload_finish, completed, bytes_sent
    """
    result = {
        'upload_start': time.time(),
        'upload_finish': 0.0,
        'completed': False,
        'bytes_sent': 0,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((server_ip, port))
        sock.settimeout(UPLOAD_TIMEOUT)

        total = len(evidence_bytes)
        sent = 0
        start = time.time()

        logger.info("Uploading %d bytes to %s:%d...", total, server_ip, port)

        while sent < total:
            chunk = evidence_bytes[sent:sent + CHUNK_SIZE]
            sock.sendall(chunk)
            sent += len(chunk)

            # Progress log every 1 MB
            if sent % (1024 * 1024) < CHUNK_SIZE:
                elapsed = time.time() - start
                rate = (sent * 8) / elapsed / 1e6 if elapsed > 0 else 0
                logger.info("  Upload progress: %d/%d bytes (%.1f Mbps)",
                            sent, total, rate)

        result['bytes_sent'] = sent
        result['completed'] = True
        result['upload_finish'] = time.time()

        elapsed = result['upload_finish'] - result['upload_start']
        logger.info("Upload complete: %d bytes in %.1f seconds", sent, elapsed)

    except socket.timeout:
        result['upload_finish'] = time.time()
        logger.error("Upload timed out after %d seconds", UPLOAD_TIMEOUT)
    except ConnectionRefusedError:
        result['upload_finish'] = time.time()
        logger.error("Connection refused — is the server running?")
    except Exception as e:
        result['upload_finish'] = time.time()
        logger.error("Upload failed: %s", e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result
