"""
alert_manager.py
================
Alert creation and lifecycle management for NTMS.
"""

from __future__ import annotations

import logging
from typing import Any

from config import RiskLevel
from database import DatabaseManager
from utils import iso_timestamp


class AlertManager:
    """Creates, stores, retrieves and resolves security alerts."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        notification_service: Any,
    ):
        self.db_manager = db_manager
        self.notification_service = notification_service
        self.logger = logging.getLogger("ntms.alert")

    def create_alert(
        self,
        threat_type: str,
        risk_level: str,
        risk_score: float,
        message: str,
        ip_address: str | None = None,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        """Persist an alert and trigger notifications when appropriate."""
        timestamp = iso_timestamp()

        cursor = self.db_manager.execute(
            """
            INSERT INTO alerts(
                timestamp, ip_address, mac_address,
                threat_type, risk_level, risk_score,
                message, status
            )
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                timestamp,
                ip_address,
                mac_address,
                threat_type,
                risk_level,
                float(risk_score),
                message,
                "NEW",
            ),
        )

        alert_id = cursor.lastrowid

        notification_level = self._configured_notification_level()

        if self._should_notify(risk_level, notification_level):
            try:
                self.notification_service.send_alert(
                    title=f"NTMS Alert - {risk_level}",
                    message=message,
                    risk_level=risk_level,
                )
            except Exception:
                self.logger.exception(
                    "Notification failed for alert %s.",
                    alert_id,
                )

        return {
            "id": alert_id,
            "timestamp": timestamp,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "threat_type": threat_type,
            "risk_level": risk_level,
            "risk_score": float(risk_score),
            "message": message,
            "status": "NEW",
        }

    def _configured_notification_level(self) -> str:
        try:
            value = self.notification_service.settings_manager.get(
                "min_risk_for_notification",
                RiskLevel.MEDIUM.value,
            )
            return (
                value.value
                if isinstance(value, RiskLevel)
                else str(value).upper()
            )
        except Exception:
            return RiskLevel.MEDIUM.value

    @staticmethod
    def _should_notify(
        current_level: str,
        minimum_level: str,
    ) -> bool:
        order = {
            RiskLevel.LOW.value: 0,
            RiskLevel.MEDIUM.value: 1,
            RiskLevel.HIGH.value: 2,
            RiskLevel.CRITICAL.value: 3,
        }

        return order.get(str(current_level).upper(), 0) >= order.get(
            str(minimum_level).upper(),
            1,
        )

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        return self.db_manager.fetch_one(
            "SELECT * FROM alerts WHERE id=?",
            (alert_id,),
        )

    def get_alerts(
        self,
        limit: int = 100,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        if status:
            return self.db_manager.fetch_all(
                """
                SELECT * FROM alerts
                WHERE status=?
                ORDER BY id DESC
                LIMIT ?
                """,
                (status, limit),
            )

        return self.db_manager.fetch_all(
            """
            SELECT * FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

    def acknowledge_alert(self, alert_id: int) -> None:
        self.db_manager.execute(
            "UPDATE alerts SET status='ACKNOWLEDGED' WHERE id=?",
            (alert_id,),
        )

    def resolve_alert(self, alert_id: int) -> None:
        self.db_manager.execute(
            "UPDATE alerts SET status='RESOLVED' WHERE id=?",
            (alert_id,),
        )

    def ignore_alert(self, alert_id: int) -> None:
        self.db_manager.execute(
            "UPDATE alerts SET status='IGNORED' WHERE id=?",
            (alert_id,),
        )

    def active_alert_count(self) -> int:
        row = self.db_manager.fetch_one(
            """
            SELECT COUNT(*) AS count
            FROM alerts
            WHERE status IN ('NEW', 'ACKNOWLEDGED')
            """
        )
        return int(row["count"]) if row else 0
