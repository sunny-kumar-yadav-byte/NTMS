"""
statistics.py
=============
Statistics and monitoring summaries for NTMS.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from database import DatabaseManager


class StatisticsManager:
    """Provides dashboard and reporting statistics."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def get_alert_counts(self) -> dict[str, int]:
        rows = self.db_manager.fetch_all(
            "SELECT risk_level, COUNT(*) AS count FROM alerts GROUP BY risk_level"
        )
        result = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for row in rows:
            result[str(row["risk_level"]).upper()] = int(row["count"])
        return result

    def get_threat_counts(self) -> list[dict[str, Any]]:
        return self.db_manager.fetch_all(
            """
            SELECT threat_type, COUNT(*) AS count
            FROM alerts
            GROUP BY threat_type
            ORDER BY count DESC
            """
        )

    def get_recent_alerts(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.db_manager.fetch_all(
            """
            SELECT * FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

    def get_device_count(self) -> int:
        row = self.db_manager.fetch_one(
            "SELECT COUNT(*) AS count FROM devices"
        )
        return int(row["count"]) if row else 0

    def get_active_alert_count(self) -> int:
        row = self.db_manager.fetch_one(
            """
            SELECT COUNT(*) AS count
            FROM alerts
            WHERE status IN ('NEW', 'ACKNOWLEDGED')
            """
        )
        return int(row["count"]) if row else 0

    def get_summary(self) -> dict[str, Any]:
        return {
            "device_count": self.get_device_count(),
            "active_alerts": self.get_active_alert_count(),
            "alert_counts": self.get_alert_counts(),
            "threat_counts": self.get_threat_counts(),
            "recent_alerts": self.get_recent_alerts(),
        }

    def get_alerts_last_hours(self, hours: int = 24) -> int:
        cutoff = (
            datetime.now() - timedelta(hours=hours)
        ).isoformat(timespec="seconds")

        row = self.db_manager.fetch_one(
            "SELECT COUNT(*) AS count FROM alerts WHERE timestamp >= ?",
            (cutoff,),
        )
        return int(row["count"]) if row else 0
