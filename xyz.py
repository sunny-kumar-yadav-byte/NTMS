"""
config.py
=========
Central configuration for the Network Threat Monitoring System.

This file contains:
- Application information
- Database and report paths
- ARP detection thresholds
- Risk weights
- Notification settings
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
# Project directories
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
    # How long a MAC-change history is kept.
    mac_change_window_sec: float = 60.0

    # Number of MAC changes inside the window considered suspicious.
    max_mac_changes_per_window: int = 3

    # How long rapid MAC switching is tracked.
    rapid_mac_switch_window_sec: float = 60.0

    # ARP reply frequency monitoring.
    arp_reply_window_sec: float = 10.0
    max_arp_replies_per_window: int = 25

    # Gratuitous ARP monitoring.
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
# Main application configuration
# ---------------------------------------------------------------------------

@dataclass
class AppConfig:
    APP_NAME: str = "Network Threat Monitoring System"
    APP_VERSION: str = "1.0.0"

    # Network interface. Leave empty to let Scapy use the default interface.
    DEFAULT_INTERFACE: str = ""

    # Packet capture.
    ARP_FILTER: str = "arp"

    # Paths.
    BASE_DIR: Path = field(default_factory=lambda: BASE_DIR)
    DATA_DIR: Path = field(default_factory=lambda: DATA_DIR)
    REPORTS_DIR: Path = field(default_factory=lambda: REPORTS_DIR)
    LOGS_DIR: Path = field(default_factory=lambda: LOGS_DIR)
    ASSETS_DIR: Path = field(default_factory=lambda: ASSETS_DIR)
    DB_PATH: Path = field(default_factory=lambda: DB_PATH)
    LOG_FILE: Path = field(default_factory=lambda: LOG_FILE)

    # Sub-configurations.
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    risk_weights: RiskWeights = field(default_factory=RiskWeights)

    # Notification defaults.
    enable_desktop_notifications: bool = True
    enable_sound_alerts: bool = False
    min_risk_for_notification: str = RiskLevel.MEDIUM.value
    sound_file: str = str(ASSETS_DIR / "alert.wav")

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to a JSON-serializable dictionary."""
        data = asdict(self)

        for key, value in list(data.items()):
            if isinstance(value, Path):
                data[key] = str(value)

        return data

    def save(self, path: str | Path | None = None) -> Path:
        """Save the current configuration as JSON."""
        target = Path(path) if path else DATA_DIR / "config.json"
        target.parent.mkdir(parents=True, exist_ok=True)

        target.write_text(
            json.dumps(self.to_dict(), indent=4),
            encoding="utf-8",
        )

        return target

    @classmethod
    def load(cls, path: str | Path) -> "AppConfig":
        """
        Load configuration from JSON.

        Unknown fields are ignored so that an older config file does not
        break a newer version of the application.
        """
        source = Path(path)

        if not source.exists():
            return cls()

        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()

        config = cls()

        for key in (
            "APP_NAME",
            "APP_VERSION",
            "DEFAULT_INTERFACE",
            "ARP_FILTER",
            "enable_desktop_notifications",
            "enable_sound_alerts",
            "min_risk_for_notification",
            "sound_file",
        ):
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
# Helper functions used by main.py
# ---------------------------------------------------------------------------

def ensure_directories(config: AppConfig | None = None) -> None:
    """Create required project directories."""
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
    """Configure application logging and return the NTMS logger."""
    cfg = config or AppConfig()
    ensure_directories(cfg)

    logger = logging.getLogger("ntms")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Avoid installing duplicate handlers if setup_logging() is called again.
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(
        cfg.LOG_FILE,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# ---------------------------------------------------------------------------
# Network-interface helper
# ---------------------------------------------------------------------------

def get_network_interfaces() -> list[str]:
    """Return available network interfaces."""
    try:
        from scapy.all import get_if_list

        return list(get_if_list())
    except ImportError:
        return []
    except Exception:
        return []


# Backward-compatible alias for main.py.
def list_network_interfaces() -> list[str]:
    return get_network_interfaces()


# ---------------------------------------------------------------------------
# Backward-compatible default configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = AppConfig()


if __name__ == "__main__":
    config = AppConfig()
    ensure_directories(config)

    print(f"Application : {config.APP_NAME}")
    print(f"Version     : {config.APP_VERSION}")
    print(f"Database    : {config.DB_PATH}")
    print(f"Interfaces  : {', '.join(get_network_interfaces()) or 'Unavailable'}")