"""Al-Ahsa Smart Bus — typed configuration loader.

Reads ``config.ini`` (at the package root) and interpolates ``${ENV}``
tokens. Property accessors fall back to ns-3 defaults so a missing
config section still yields a working agent.
"""

from __future__ import annotations

import configparser
import logging
import os
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.ini"
_ENV_VAR_PATTERN = re.compile(r"\$\{(\w+)\}")


def _interpolate_env(value: str) -> str:
    def _sub(m: re.Match) -> str:
        return os.environ.get(m.group(1), m.group(0))
    return _ENV_VAR_PATTERN.sub(_sub, value)


class Config:
    """Typed accessor over ``config.ini``."""

    def __init__(self, config_path: Optional[str] = None):
        path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        self._parser = configparser.ConfigParser()
        self._parser.read(str(path))
        self._path = path

    # -- raw -----------------------------------------------------------

    def get(self, section: str, key: str, fallback: str = "") -> str:
        raw = self._parser.get(section, key, fallback=fallback)
        return _interpolate_env(raw)

    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        try:
            return self._parser.getint(section, key, fallback=fallback)
        except (ValueError, TypeError):
            return fallback

    def getfloat(self, section: str, key: str, fallback: float = 0.0) -> float:
        try:
            return self._parser.getfloat(section, key, fallback=fallback)
        except (ValueError, TypeError):
            return fallback

    def getbool(self, section: str, key: str, fallback: bool = False) -> bool:
        try:
            return self._parser.getboolean(section, key, fallback=fallback)
        except (ValueError, TypeError):
            return fallback

    # -- [network] -----------------------------------------------------

    @property
    def server_url(self) -> str:
        return self.get("network", "server_url",
                        fallback="https://jetson.testingdomainzforprototypes.website")

    @property
    def bus_id(self) -> int:
        return self.getint("network", "bus_id", fallback=0)

    @property
    def interface(self) -> str:
        return self.get("network", "interface", fallback="wlan0")

    # -- [camera] ------------------------------------------------------

    @property
    def use_real_camera(self) -> bool:
        return self.getbool("camera", "use_real_camera", fallback=False)

    @property
    def camera_device_index(self) -> int:
        return self.getint("camera", "device_index", fallback=0)

    @property
    def camera_width(self) -> int:
        return self.getint("camera", "frame_width", fallback=1280)

    @property
    def camera_height(self) -> int:
        return self.getint("camera", "frame_height", fallback=720)

    @property
    def camera_fps(self) -> int:
        return self.getint("camera", "fps", fallback=30)

    # -- [telegram] ----------------------------------------------------

    @property
    def telegram_enabled(self) -> bool:
        return self.getbool("telegram", "enabled", fallback=False)

    @property
    def telegram_bot_token(self) -> str:
        return self.get("telegram", "bot_token", fallback="")

    @property
    def telegram_chat_id(self) -> str:
        return self.get("telegram", "chat_id", fallback="")

    @property
    def telegram_alert_cooldown_s(self) -> float:
        return self.getfloat("telegram", "alert_cooldown_s", fallback=60.0)

    # -- [thresholds] --------------------------------------------------

    @property
    def ddos_rate_bps(self) -> float:
        return self.getfloat("thresholds", "ddos_rate_bps", fallback=15e6)

    @property
    def ddos_loss_pct(self) -> float:
        """DDoS packet-loss threshold as a ratio in [0, 1]."""
        return self.getfloat("thresholds", "ddos_loss_pct", fallback=0.05)

    @property
    def ddos_delay_s(self) -> float:
        """DDoS RTT threshold in seconds."""
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

    # -- [traffic] -----------------------------------------------------

    @property
    def gps_interval_s(self) -> float:
        return self.getfloat("traffic", "gps_interval_s", fallback=1.0)

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
    def ticket_min_interval_s(self) -> float:
        return self.getfloat("traffic", "ticket_min_interval_s", fallback=6.0)

    @property
    def ticket_max_interval_s(self) -> float:
        return self.getfloat("traffic", "ticket_max_interval_s", fallback=20.0)

    @property
    def ticket_min_burst(self) -> int:
        return self.getint("traffic", "ticket_min_burst", fallback=1)

    @property
    def ticket_max_burst(self) -> int:
        return self.getint("traffic", "ticket_max_burst", fallback=3)

    @property
    def ddos_check_interval_s(self) -> float:
        return self.getfloat("traffic", "ddos_check_interval_s", fallback=10.0)

    @property
    def warmup_time_s(self) -> float:
        return self.getfloat("traffic", "warmup_time_s", fallback=90.0)

    # -- [reliability] -------------------------------------------------

    @property
    def offline_db_path(self) -> str:
        return self.get("reliability", "offline_db_path",
                        fallback="./logs/offline_queue.db")

    @property
    def retry_max_backoff_s(self) -> float:
        return self.getfloat("reliability", "retry_max_backoff_s", fallback=60.0)

    @property
    def forensic_max_attempts(self) -> int:
        return self.getint("reliability", "forensic_max_attempts", fallback=10)

    # -- [logging] -----------------------------------------------------

    @property
    def log_dir(self) -> str:
        return self.get("logging", "log_dir", fallback="./logs")
