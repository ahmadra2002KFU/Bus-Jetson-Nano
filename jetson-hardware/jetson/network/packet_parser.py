"""
Al-Ahsa Smart Bus — GPS packet builder and parser.

Binary format matches the ns-3 GpsTelemetryApp (smart-bus.cc lines 470-486):

  Offset  Size  Type      Field
  ------  ----  --------  ------------------
  0       4     uint32    magic  (0x47505331 = "GPS1")
  4       4     uint32    bus_id
  8       8     double    pos_x  (meters)
  16      8     double    pos_y  (meters)
  24      176   zeros     padding

Total: 200 bytes, little-endian.

The ns-3 source uses raw memcpy with native byte order on x86-64 Linux,
which is little-endian.  We use struct '<IIdd' to match.
"""

import struct
from typing import Optional, Tuple

from jetson.constants import GPS_PAYLOAD_MAGIC, GPS_PACKET_SIZE, GPS_PAYLOAD_MIN_SIZE

# struct format: little-endian, uint32 magic, uint32 bus_id, double x, double y
_GPS_HEADER_FMT = "<IIdd"
_GPS_HEADER_SIZE = struct.calcsize(_GPS_HEADER_FMT)  # 24 bytes
_GPS_PADDING_SIZE = GPS_PACKET_SIZE - _GPS_HEADER_SIZE  # 176 bytes


def build_gps_packet(bus_id: int, pos_x: float, pos_y: float) -> bytes:
    """
    Build a 200-byte GPS telemetry packet.

    Parameters
    ----------
    bus_id : int
        Bus identifier (0-40).
    pos_x : float
        X position in meters.
    pos_y : float
        Y position in meters.

    Returns
    -------
    bytes
        200-byte packet matching the ns-3 wire format.
    """
    header = struct.pack(_GPS_HEADER_FMT, GPS_PAYLOAD_MAGIC, bus_id, pos_x, pos_y)
    padding = b"\x00" * _GPS_PADDING_SIZE
    return header + padding


def parse_gps_packet(
    data: bytes,
) -> Optional[Tuple[int, int, float, float]]:
    """
    Parse a GPS telemetry packet.

    Parameters
    ----------
    data : bytes
        Raw packet data (must be >= 24 bytes).

    Returns
    -------
    tuple or None
        (magic, bus_id, pos_x, pos_y) if valid, None otherwise.
        Returns None when:
        - data is too short (< 24 bytes)
        - magic does not match GPS_PAYLOAD_MAGIC
        - pos_x or pos_y is not finite
    """
    if len(data) < GPS_PAYLOAD_MIN_SIZE:
        return None

    magic, bus_id, pos_x, pos_y = struct.unpack_from(_GPS_HEADER_FMT, data, 0)

    if magic != GPS_PAYLOAD_MAGIC:
        return None

    # Reject non-finite coordinates (matches ns-3 isfinite check, line 936)
    if not (_is_finite(pos_x) and _is_finite(pos_y)):
        return None

    return (magic, bus_id, pos_x, pos_y)


def _is_finite(value: float) -> bool:
    """Check if a float is finite (not NaN or Inf)."""
    import math
    return math.isfinite(value)
