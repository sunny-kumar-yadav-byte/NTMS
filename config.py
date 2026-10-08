"""
Central configuration for the Network Threat Monitoring System (NTMS).

This version matches the interfaces currently used by:
- main.py
- database.py
- settings.py
- device_manager.py
- arp_detector.py
- risk_engine.py
- detection_engine.py
- notification.py
- packet_capture.py
- report_generator.py
- dashboard.py
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
ASSETS_DIR = BASE_DIR / "assets"

DB_PATH = DATA_DIR / "network_monitor.db"
LOG_FILE = LOGS_DIR / "network_monitor.log"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    MAC_ADDRESS_CHANGE = "MAC_ADDRESS_CHANGE"
    DUPLICATE_IP = "DUPLICATE_IP"
    DUPLICATE_MAC = "DUPLICATE_MAC"
    GRATUITOUS_ARP_ABUSE = "GRATUITOUS_ARP_ABUSE"
    EXCESSIVE_ARP_REPLIES = "EXCESSIVE_ARP_REPLIES"
    RAPID_MAC_SWITCHING = "RAPID_MAC_SWITCHING"
    SUSPICIOUS_ARP_FREQUENCY = "SUSPICIOUS_ARP_FREQUENCY"


# ---------------------------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------------------------

@dataclass
class DetectionConfig:
    mac_change_window_sec: float = 60.0
    max_mac_changes_per_window: int = 3

    rapid_mac_switch_window_sec: float = 60.0

    arp_reply_window_sec: float = 10.0
    max_arp_replies_per_window: int = 25

    gratuitous_arp_window_sec: float = 30.0
    max_gratuitous_arp_per_window: int = 10


# ---------------------------------------------------------------------------
# Risk configuration
# ---------------------------------------------------------------------------

@dataclass
class RiskWeights:
    mac_address_change: float = 60.0
    duplicate_ip: float = 70.0
    duplicate_mac: float = 50.0
    gratuitous_arp_abuse: float = 55.0
    excessive_arp_replies: float = 65.0
    rapid_mac_switching: float = 85.0
    suspicious_arp_frequency: float = 60.0


# ---------------------------------------------------------------------------
# Application configuration
# ---------------------------------------------------------------------------

@dataclass
class AppConfig:
    APP_NAME: str = "Network Threat Monitoring System"
    APP_VERSION: str = "1.0.0"

    # Empty string means Scapy will use its default interface.
    DEFAULT_INTERFACE: str = ""

    # ARP-only monitoring for the current detection module.
    ARP_FILTER: str = "arp"

    # Paths
    BASE_DIR: Path = field(default_factory=lambda: BASE_DIR)
    DATA_DIR: Path = field(default_factory=lambda: DATA_DIR)
    REPORTS_DIR: Path = field(default_factory=lambda: REPORTS_DIR)
    LOGS_DIR: Path = field(default_factory=lambda: LOGS_DIR)
    ASSETS_DIR: Path = field(default_factory=lambda: ASSETS_DIR)
    DB_PATH: Path = field(default_factory=lambda: DB_PATH)
    LOG_FILE: Path = field(default_factory=lambda: LOG_FILE)

    # Sub-configurations
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    risk_weights: RiskWeights = field(default_factory=RiskWeights)

    # Notification settings
    enable_desktop_notifications: bool = True
    enable_sound_alerts: bool = False
    min_risk_for_notification: str = RiskLevel.MEDIUM.value
    sound_file: str = field(
    default_factory=lambda: str(ASSETS_DIR / "alert.wav")
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the configuration."""
        data = asdict(self)

        def convert(value: Any) -> Any:
            if isinstance(value, Path):
                return str(value)
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, dict):
                return {key: convert(item) for key, item in value.items()}
            if isinstance(value, list):
                return [convert(item) for item in value]
            return value

        return {key: convert(value) for key, value in data.items()}

    def save(self, path: str | Path | None = None) -> Path:
        """Save configuration as JSON."""
        target = Path(path) if path else DATA_DIR / "config.json"
        target.parent.mkdir(parents=True, exist_ok=True)

        target.write_text(
            json.dumps(self.to_dict(), indent=4),
            encoding="utf-8",
        )
        return target

    @classmethod
    def load(cls, path: str | Path) -> "AppConfig":
        """Load configuration from JSON, retaining defaults for missing fields."""
        source = Path(path)

        if not source.exists():
            return cls()

        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()

        config = cls()

        scalar_fields = (
            "APP_NAME",
            "APP_VERSION",
            "DEFAULT_INTERFACE",
            "ARP_FILTER",
            "enable_desktop_notifications",
            "enable_sound_alerts",
            "min_risk_for_notification",
            "sound_file",
        )

        for key in scalar_fields:
            if key in raw:
                setattr(config, key, raw[key])

        if isinstance(raw.get("detection"), dict):
            for key, value in raw["detection"].items():
                if hasattr(config.detection, key):
                    setattr(config.detection, key, value)

        if isinstance(raw.get("risk_weights"), dict):
            for key, value in raw["risk_weights"].items():
                if hasattr(config.risk_weights, key):
                    setattr(config.risk_weights, key, value)

        return config


# ---------------------------------------------------------------------------
# Helpers required by main.py
# ---------------------------------------------------------------------------

def ensure_directories(config: AppConfig | None = None) -> None:
    """Create directories required by the application."""
    cfg = config or AppConfig()

    for directory in (
        cfg.DATA_DIR,
        cfg.REPORTS_DIR,
        cfg.LOGS_DIR,
        cfg.ASSETS_DIR,
    ):
        Path(directory).mkdir(parents=True, exist_ok=True)


def setup_logging(
    config: AppConfig | None = None,
    debug: bool = False,
) -> logging.Logger:
    """Configure and return the main NTMS logger."""
    cfg = config or AppConfig()
    ensure_directories(cfg)

    logger = logging.getLogger("ntms")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    # Avoid duplicate handlers when startup code is called more than once.
    if not logger.handlers:
        file_handler = logging.FileHandler(
            cfg.LOG_FILE,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(
            logging.DEBUG if debug else logging.INFO
        )
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


def get_network_interfaces() -> list[str]:
    """Return interfaces available to Scapy."""
    try:
        from scapy.all import get_if_list
        return list(get_if_list())
    except ImportError:
        return []
    except Exception:
        return []


def list_network_interfaces() -> list[str]:
    """Backward-compatible alias used by main.py."""
    return get_network_interfaces()


def is_admin() -> bool:
    """Return True when the process has administrator/root privileges."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


DEFAULT_CONFIG = AppConfig()


if __name__ == "__main__":
    config = AppConfig()
    ensure_directories(config)

    print(f"Application : {config.APP_NAME}")
    print(f"Version     : {config.APP_VERSION}")
    print(f"Database    : {config.DB_PATH}")
    print(
        "Interfaces  : "
        f"{', '.join(get_network_interfaces()) or 'Unavailable'}"
    )
