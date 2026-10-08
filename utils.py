"""
utils.py
========
Common utility functions for the Network Threat Monitoring System.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAC_PATTERN = re.compile(
    r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
)


def normalize_mac(mac_address: str) -> str:
    """Normalize a MAC address to uppercase colon-separated format."""
    if not isinstance(mac_address, str):
        return ""

    value = mac_address.strip().replace("-", ":").upper()

    # Convert compact form such as AABBCCDDEEFF.
    compact = value.replace(":", "")
    if len(compact) == 12 and all(
        character in "0123456789ABCDEF" for character in compact
    ):
        return ":".join(
            compact[index:index + 2]
            for index in range(0, 12, 2)
        )

    return value


def is_valid_mac(mac_address: str) -> bool:
    """Return True if the supplied value is a valid MAC address."""
    if not isinstance(mac_address, str):
        return False

    return bool(MAC_PATTERN.match(mac_address.strip()))


def is_valid_ipv4(ip_address: str) -> bool:
    """Return True if the supplied value is a valid IPv4 address."""
    try:
        return ipaddress.ip_address(ip_address).version == 4
    except (ValueError, TypeError):
        return False


def is_valid_ipv6(ip_address: str) -> bool:
    """Return True if the supplied value is a valid IPv6 address."""
    try:
        return ipaddress.ip_address(ip_address).version == 6
    except (ValueError, TypeError):
        return False


def is_valid_ip(ip_address: str) -> bool:
    """Return True for either IPv4 or IPv6."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except (ValueError, TypeError):
        return False


def iso_timestamp() -> str:
    """Return a UTC timestamp suitable for database storage."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_timestamp() -> str:
    """Backward-compatible timestamp helper."""
    return iso_timestamp()


def ensure_directory(path: str | Path) -> Path:
    """Create a directory if it does not already exist."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_project_root() -> Path:
    """Return the directory containing this project."""
    return Path(__file__).resolve().parent


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to integer."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def setup_logger(
    name: str = "ntms",
    level: int = logging.INFO,
) -> logging.Logger:
    """Return a simple configured logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            )
        )
        logger.addHandler(handler)

    return logger

def setup_logging(config, debug: bool = False):
    """Configure logging for the NTMS application."""
    from config import ensure_directories

    ensure_directories(config)

    logger = logging.getLogger("ntms")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(
        config.LOG_FILE,
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


def is_admin() -> bool:
    """
    Check whether the application has administrator/root privileges.

    On Unix-like systems this checks the effective UID.
    On Windows it uses ctypes when available.
    """
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


def list_network_interfaces() -> list[str]:
    """Return network interfaces available to Scapy."""
    try:
        from scapy.all import get_if_list

        return list(get_if_list())
    except ImportError:
        return []
    except Exception:
        return []


def get_interface_info(interface: str) -> dict[str, Any]:
    """Return basic information about a network interface."""
    info: dict[str, Any] = {
        "name": interface,
        "ip": None,
        "mac": None,
    }

    try:
        from scapy.all import get_if_addr, get_if_hwaddr

        info["ip"] = get_if_addr(interface)
        info["mac"] = normalize_mac(get_if_hwaddr(interface))
    except Exception:
        pass

    return info


def extract_arp_fields(packet: Any) -> dict[str, Any] | None:
    """
    Extract useful fields from a Scapy ARP packet.

    Returns None when the packet does not contain an ARP layer.
    """
    try:
        from scapy.layers.l2 import ARP

        if not packet.haslayer(ARP):
            return None

        arp = packet[ARP]

        return {
            "operation": int(getattr(arp, "op", 0) or 0),
            "source_ip": getattr(arp, "psrc", "") or "",
            "source_mac": normalize_mac(
                getattr(arp, "hwsrc", "") or ""
            ),
            "target_ip": getattr(arp, "pdst", "") or "",
            "target_mac": normalize_mac(
                getattr(arp, "hwdst", "") or ""
            ),
        }
    except Exception:
        return None


def format_alert_message(
    threat_type: str,
    ip_address: str | None = None,
    mac_address: str | None = None,
    risk_level: str | None = None,
) -> str:
    """Create a consistent human-readable alert message."""
    parts = [f"Threat detected: {threat_type}"]

    if ip_address:
        parts.append(f"IP: {ip_address}")

    if mac_address:
        parts.append(f"MAC: {mac_address}")

    if risk_level:
        parts.append(f"Risk: {risk_level}")

    return " | ".join(parts)
