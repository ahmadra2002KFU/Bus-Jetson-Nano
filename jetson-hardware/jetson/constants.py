"""
Al-Ahsa Smart Bus — Constants ported from ns-3 simulation.

Source: scratch/smart-bus/smart-bus.cc
All line references are to that file.
"""

# ============================================================
# Fleet & infrastructure — lines 52-55
# ============================================================
MAX_BUSES: int = 41                    # line 52
NUM_ENB: int = 3                       # line 53
STATION_STOP_TIME: float = 30.0        # line 54  (seconds)
BUS_SPEED_MS: float = 11.1             # line 55  (~40 km/h)

# ============================================================
# DDoS detection thresholds — lines 58-60
# ============================================================
DDOS_RATE_THRESHOLD: float = 15e6      # line 58  (15 Mbps)
DDOS_LOSS_THRESHOLD: float = 0.05      # line 59  (5%)
DDOS_DELAY_THRESHOLD: float = 0.1      # line 60  (100 ms)

# ============================================================
# GPS spoofing detection thresholds — lines 61-63
# ============================================================
GPS_SPEED_THRESHOLD: float = 22.2      # line 61  (80 km/h)
GPS_JUMP_THRESHOLD: float = 1000.0     # line 62  (1 km)
GPS_CORRIDOR_THRESHOLD: float = 1500.0 # line 63  (1500 m)

# ============================================================
# Timing — lines 64-65
# ============================================================
DETECTION_WARMUP_TIME: float = 90.0    # line 64  (seconds)
SERVER_LINK_RATE_BPS: float = 1e9      # line 65  (1 Gbps)

# ============================================================
# GPS packet format — lines 68-73
# ============================================================
GPS_PAYLOAD_MAGIC: int = 0x47505331    # line 72  ("GPS1")
GPS_PAYLOAD_MIN_SIZE: int = 24         # line 73  (magic+id+x+y)

# ============================================================
# Ports — lines 76-79
# ============================================================
TELEMETRY_PORT: int = 5000             # line 76
CCTV_PORT: int = 6000                  # line 77
TICKET_PORT: int = 7000                # line 78
FORENSIC_PORT: int = 8000              # line 79

# ============================================================
# Packet sizes (from application setup, various lines)
# ============================================================
GPS_PACKET_SIZE: int = 200             # line 471  (SendPacket buffer)
CCTV_PACKET_SIZE: int = 1400           # line 1601
TICKET_PACKET_SIZE: int = 256          # line 561 / 1625
FORENSIC_UPLOAD_BYTES: int = 10485760  # line 1286 (10 MB)

# ============================================================
# Detection parameters (from CheckDDoS / GpsDetectorApp)
# ============================================================
DDOS_CHECK_INTERVAL: float = 10.0      # lines 1720-1725
GPS_STREAK_REQUIRED: int = 3           # line 1015

# ============================================================
# CCTV streaming — line 1600
# ============================================================
CCTV_DATA_RATE_KBPS: int = 1000        # 1000 kbps = 1 Mbps

# ============================================================
# DDoS attack defaults — line 1394
# ============================================================
DDOS_DEFAULT_RATE_BPS: float = 30e6    # 30 Mbps

# ============================================================
# GPS telemetry traffic — lines 421, 431-436, 1582
# ============================================================
GPS_TELEMETRY_PORT: int = TELEMETRY_PORT  # alias for clarity
GPS_SEND_INTERVAL: float = 1.0            # 1 pkt/s  (line 421)

# ============================================================
# CCTV streaming — derived from line 1600
# ============================================================
CCTV_BITRATE_BPS: int = CCTV_DATA_RATE_KBPS * 1000  # 1,000,000 bps

# ============================================================
# Ticketing — lines 555-567, 1621-1631
# ============================================================
TICKETING_PORT: int = TICKET_PORT         # alias for clarity
TICKET_MIN_INTERVAL: float = 6.0          # line 559
TICKET_MAX_INTERVAL: float = 20.0         # line 560
TICKET_MIN_BURST: int = 1                 # line 563
TICKET_MAX_BURST: int = 3                 # line 564
TICKET_RETRY_DELAY: float = 2.0           # line 640 (2s retry)

# ============================================================
# Forensic upload — lines 1284-1287
# ============================================================
FORENSIC_TOTAL_BYTES: int = FORENSIC_UPLOAD_BYTES  # alias
FORENSIC_SEND_SIZE: int = 1448            # line 1287

# ============================================================
# Heartbeat (real-deployment addition, not in ns-3)
# ============================================================
HEARTBEAT_PORT: int = 5001
