"""
detection_engine.py
===================
Coordinates packet analysis, risk scoring and alert creation.
"""

from __future__ import annotations

import logging
from threading import Event, Lock
from typing import Any

from config import AppConfig
from risk_engine import RiskEngine


class DetectionEngine:
    """Central coordinator for registered network threat detectors."""

    def __init__(
        self,
        device_manager: Any,
        risk_engine: RiskEngine,
        alert_manager: Any,
        config: AppConfig | None = None,
    ):
        self.config = config or AppConfig()
        self.device_manager = device_manager
        self.risk_engine = risk_engine
        self.alert_manager = alert_manager

        self.detectors: list[Any] = []
        self.logger = logging.getLogger("ntms.detection")
        self._lock = Lock()
        self._stop_event = Event()
        self._running = True
        self.total_packets = 0
        self.total_threats = 0

    def register_detector(self, detector: Any) -> None:
        if detector not in self.detectors:
            self.detectors.append(detector)

    def process_packet(self, packet: Any) -> list[dict[str, Any]]:
        """Send a captured packet through every registered detector."""
        if self._stop_event.is_set():
            return []

        with self._lock:
            self.total_packets += 1

        all_findings: list[dict[str, Any]] = []

        for detector in self.detectors:
            try:
                findings = detector.analyze_packet(packet) or []
                all_findings.extend(findings)
            except Exception:
                self.logger.exception(
                    "Detector %s failed while processing a packet.",
                    type(detector).__name__,
                )

        for finding in all_findings:
            assessment = self.risk_engine.assess(
                finding.get("threat_type", "UNKNOWN")
            )
            finding.update(assessment)

            with self._lock:
                self.total_threats += 1

            try:
                self.alert_manager.create_alert(
                    threat_type=finding["threat_type"],
                    risk_level=finding["risk_level"],
                    risk_score=finding["risk_score"],
                    message=finding.get("message", "Network threat detected."),
                    ip_address=finding.get("source_ip"),
                    mac_address=finding.get("source_mac"),
                )
            except Exception:
                self.logger.exception("Failed to create alert.")

        return all_findings

    def start(self) -> None:
        self._stop_event.clear()
        self._running = True

    def stop(self) -> None:
        self._stop_event.set()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running and not self._stop_event.is_set()

    def get_stats(self) -> dict[str, int]:
        return {
            "total_packets": self.total_packets,
            "total_threats": self.total_threats,
        }
