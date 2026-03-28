"""
Al-Ahsa Smart Bus — Configuration loader.

Reads deploy/config.ini and returns typed values.
Supports environment variable interpolation for secrets
(e.g. ${TELEGRAM_BOT_TOKEN}).
"""

import configparser
import os
import re
from pathlib import Path
from typing import Optional

# Default config path: deploy/config.ini relative to this file's package
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.ini"

# Pattern to match ${ENV_VAR} in config values
_ENV_VAR_PATTERN = re.compile(r"\$\{(\w+)\}")


def _interpolate_env(value: str) -> str:
    """Replace ${VAR} tokens with environment variable values."""
    def _replacer(match: re.Match) -> str:
        var_name = match.group(1)
        env_val = os.environ.get(var_name)
        if env_val is None:
            return match.group(0)  # leave placeholder if not set
        return env_val
    return _ENV_VAR_PATTERN.sub(_replacer, value)


class Config:
    """Typed accessor for deploy/config.ini values."""

    def __init__(self, config_path: Optional[str] = None):
        path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        self._parser = configparser.ConfigParser()
        self._parser.read(str(path))

    # ------------------------------------------------------------------
    # Raw accessors
    # ------------------------------------------------------------------
    def get(self, section: str, key: str, fallback: str = "") -> str:
        raw = self._parser.get(section, key, fallback=fallback)
        return _interpolate_env(raw)

    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        return self._parser.getint(section, key, fallback=fallback)

    def getfloat(self, section: str, key: str, fallback: float = 0.0) -> float:
        return self._parser.getfloat(section, key, fallback=fallback)

    def getboolean(self, section: str, key: str, fallback: bool = False) -> bool:
        return self._parser.getboolean(section, key, fallback=fallback)

    # ------------------------------------------------------------------
    # [network]
    # ------------------------------------------------------------------
    @property
    def server_ip(self) -> str:
        return self.get("network", "server_ip", fallback="192.168.1.100")

    @property
    def bus_id(self) -> int:
        return self.getint("network", "bus_id", fallback=0)

    @property
    def lte_interface(self) -> str:
        return self.get("network", "lte_interface", fallback="wwan0")

    # ------------------------------------------------------------------
    # [ports]
    # ------------------------------------------------------------------
    @property
    def telemetry_port(self) -> int:
        return self.getint("ports", "telemetry_port", fallback=5000)

    @property
    def cctv_port(self) -> int:
        return self.getint("ports", "cctv_port", fallback=6000)

    @property
    def ticket_port(self) -> int:
        return self.getint("ports", "ticket_port", fallback=7000)

    @property
    def forensic_port(self) -> int:
        return self.getint("ports", "forensic_port", fallback=8000)

    # ------------------------------------------------------------------
    # [thresholds]
    # ------------------------------------------------------------------
    @property
    def ddos_rate_bps(self) -> float:
        return self.getfloat("thresholds", "ddos_rate_bps", fallback=15e6)

    @property
    def ddos_loss_pct(self) -> float:
        return self.getfloat("thresholds", "ddos_loss_pct", fallback=0.05)

    @property
    def ddos_delay_s(self) -> float:
        return self.getfloat("thresholds", "ddos_delay_s", fallback=0.1)

    @property
    def gps_speed_ms(self) -> float:
        return self.getfloat("thresholds", "gps_speed_ms", fallback=22.2)

    @property
    def gps_jump_m(self) -> float:
        return self.getfloat("thresholds", "gps_jump_m", fallback=1000.0)

    @property
    def gps_corridor_m(self) -> float:
        return self.getfloat("thresholds", "gps_corridor_m", fallback=1500.0)

    @property
    def gps_streak_required(self) -> int:
        return self.getint("thresholds", "gps_streak_required", fallback=3)

    @property
    def detection_mode(self) -> str:
        return self.get("thresholds", "detection_mode", fallback="any")

    # ------------------------------------------------------------------
    # [traffic]
    # ------------------------------------------------------------------
    @property
    def gps_interval_s(self) -> float:
        return self.getfloat("traffic", "gps_interval_s", fallback=1.0)

    @property
    def gps_packet_size(self) -> int:
        return self.getint("traffic", "gps_packet_size", fallback=200)

    @property
    def cctv_packet_size(self) -> int:
        return self.getint("traffic", "cctv_packet_size", fallback=1400)

    @property
    def cctv_data_rate_kbps(self) -> int:
        return self.getint("traffic", "cctv_data_rate_kbps", fallback=1000)

    @property
    def ticket_packet_size(self) -> int:
        return self.getint("traffic", "ticket_packet_size", fallback=256)

    @property
    def forensic_upload_bytes(self) -> int:
        return self.getint("traffic", "forensic_upload_bytes", fallback=10485760)

    @property
    def ddos_check_interval_s(self) -> float:
        return self.getfloat("traffic", "ddos_check_interval_s", fallback=10.0)

    @property
    def warmup_time_s(self) -> float:
        return self.getfloat("traffic", "warmup_time_s", fallback=90.0)

    # ------------------------------------------------------------------
    # [camera]
    # ------------------------------------------------------------------
    @property
    def camera_device_index(self) -> int:
        return self.getint("camera", "device_index", fallback=0)

    @property
    def camera_frame_width(self) -> int:
        return self.getint("camera", "frame_width", fallback=1280)

    @property
    def camera_frame_height(self) -> int:
        return self.getint("camera", "frame_height", fallback=720)

    @property
    def camera_fps(self) -> int:
        return self.getint("camera", "fps", fallback=30)

    # ------------------------------------------------------------------
    # [telegram]
    # ------------------------------------------------------------------
    @property
    def telegram_bot_token(self) -> str:
        return self.get("telegram", "bot_token", fallback="")

    @property
    def telegram_chat_id(self) -> str:
        return self.get("telegram", "chat_id", fallback="")

    @property
    def telegram_alert_cooldown_s(self) -> float:
        return self.getfloat("telegram", "alert_cooldown_s", fallback=60.0)

    # ------------------------------------------------------------------
    # [route]
    # ------------------------------------------------------------------
    @property
    def route_index(self) -> int:
        return self.getint("route", "route_index", fallback=0)
