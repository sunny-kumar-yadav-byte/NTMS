"""
database.py
===========
SQLite persistence layer for the Network Threat Monitoring System.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from config import AppConfig


class DatabaseManager:
    """Small SQLite manager used by the NTMS modules."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._connection: sqlite3.Connection | None = None
        self.connect()

    def connect(self) -> None:
        if self._connection is None:
            self._connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row

    @property
    def connection(self) -> sqlite3.Connection:
        self.connect()
        assert self._connection is not None
        return self._connection

    def initialize_schema(self) -> None:
        """Create the basic tables used by the project."""
        with self._lock:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    mac_address TEXT NOT NULL,
                    hostname TEXT,
                    status TEXT DEFAULT 'UNKNOWN',
                    trust_level TEXT DEFAULT 'UNKNOWN',
                    first_seen TEXT,
                    last_seen TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT,
                    mac_address TEXT,
                    threat_type TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score REAL DEFAULT 0,
                    message TEXT,
                    status TEXT DEFAULT 'NEW'
                );

                CREATE TABLE IF NOT EXISTS arp_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    source_mac TEXT,
                    target_ip TEXT,
                    target_mac TEXT,
                    operation TEXT,
                    threat_type TEXT,
                    risk_score REAL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS statistics (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    report_path TEXT NOT NULL
                );
                """
            )
            self.connection.commit()

    def execute(
        self,
        query: str,
        parameters: tuple[Any, ...] = (),
    ) -> sqlite3.Cursor:
        with self._lock:
            cursor = self.connection.execute(query, parameters)
            self.connection.commit()
            return cursor

    def fetch_all(
        self,
        query: str,
        parameters: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(query, parameters).fetchall()
            return [dict(row) for row in rows]

    def fetch_one(
        self,
        query: str,
        parameters: tuple[Any, ...] = (),
    ) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self.connection.execute(query, parameters).fetchone()
            return dict(row) if row else None

    def save_setting(self, key: str, value: Any) -> None:
        self.execute(
            """
            INSERT INTO settings(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (key, json.dumps(value)),
        )

    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.fetch_one("SELECT value FROM settings WHERE key=?", (key,))
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except (TypeError, json.JSONDecodeError):
            return row["value"]

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
