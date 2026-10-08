"""
device_manager.py
=================
Tracks devices and their IP/MAC relationships for NTMS.
"""

from __future__ import annotations

from typing import Any

from database import DatabaseManager
from utils import normalize_mac, is_valid_ipv4, is_valid_mac, iso_timestamp


class DeviceManager:
    """Maintains discovered devices and their current state."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def upsert_device(
        self,
        ip_address: str,
        mac_address: str,
        hostname: str | None = None,
        status: str = "ACTIVE",
        trust_level: str = "UNKNOWN",
    ) -> bool:
        if not is_valid_ipv4(ip_address):
            return False
        if not is_valid_mac(mac_address):
            return False

        mac_address = normalize_mac(mac_address)
        now = iso_timestamp()

        existing = self.get_device(ip_address)

        if existing:
            self.db_manager.execute(
                """
                UPDATE devices
                SET mac_address=?,
                    hostname=COALESCE(?, hostname),
                    status=?,
                    trust_level=?,
                    last_seen=?
                WHERE ip_address=?
                """,
                (
                    mac_address,
                    hostname,
                    status,
                    trust_level,
                    now,
                    ip_address,
                ),
            )
        else:
            self.db_manager.execute(
                """
                INSERT INTO devices(
                    ip_address, mac_address, hostname, status,
                    trust_level, first_seen, last_seen
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    ip_address,
                    mac_address,
                    hostname,
                    status,
                    trust_level,
                    now,
                    now,
                ),
            )

        return True

    def get_device(self, ip_address: str) -> dict[str, Any] | None:
        return self.db_manager.fetch_one(
            "SELECT * FROM devices WHERE ip_address=?",
            (ip_address,),
        )

    def get_all_devices(self) -> list[dict[str, Any]]:
        return self.db_manager.fetch_all(
            "SELECT * FROM devices ORDER BY last_seen DESC"
        )

    def get_mac_for_ip(self, ip_address: str) -> str | None:
        device = self.get_device(ip_address)
        return device["mac_address"] if device else None

    def update_status(self, ip_address: str, status: str) -> None:
        self.db_manager.execute(
            "UPDATE devices SET status=? WHERE ip_address=?",
            (status, ip_address),
        )

    def set_trust_level(self, ip_address: str, trust_level: str) -> None:
        self.db_manager.execute(
            "UPDATE devices SET trust_level=? WHERE ip_address=?",
            (trust_level, ip_address),
        )

    def record_arp_event(
        self,
        source_ip: str,
        source_mac: str,
        target_ip: str | None = None,
        target_mac: str | None = None,
        operation: str | None = None,
        threat_type: str | None = None,
        risk_score: float = 0,
    ) -> None:
        self.db_manager.execute(
            """
            INSERT INTO arp_events(
                timestamp, source_ip, source_mac, target_ip,
                target_mac, operation, threat_type, risk_score
            )
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                iso_timestamp(),
                source_ip,
                normalize_mac(source_mac),
                target_ip,
                normalize_mac(target_mac) if target_mac else None,
                operation,
                threat_type,
                risk_score,
            ),
        )
