"""
settings.py
===========
Runtime settings management for the Network Threat Monitoring System.
"""

from __future__ import annotations

from typing import Any

from database import DatabaseManager


class SettingsManager:
    """Stores user-editable runtime settings in the database."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def get(self, key: str, default: Any = None) -> Any:
        return self.db_manager.get_setting(key, default)

    def set(self, key: str, value: Any) -> None:
        self.db_manager.save_setting(key, value)

    def update(self, values: dict[str, Any]) -> None:
        for key, value in values.items():
            self.set(key, value)

    def all(self) -> dict[str, Any]:
        rows = self.db_manager.fetch_all(
            "SELECT key, value FROM settings ORDER BY key"
        )

        import json

        result: dict[str, Any] = {}
        for row in rows:
            try:
                result[row["key"]] = json.loads(row["value"])
            except (TypeError, json.JSONDecodeError):
                result[row["key"]] = row["value"]
        return result
