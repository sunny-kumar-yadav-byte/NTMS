"""
risk_engine.py
==============
Risk scoring for the Network Threat Monitoring System.
"""

from __future__ import annotations

from typing import Any

from config import AppConfig, RiskLevel, ThreatType


class RiskEngine:
    """Converts detected threat types into a risk score and level."""

    def __init__(self, config: AppConfig | None = None):
        self.config = config or AppConfig()
        self.weights = self.config.risk_weights

    def score(
        self,
        threat_type: ThreatType | str,
        extra_score: float = 0,
    ) -> float:
        """Return a bounded 0-100 risk score."""
        key = threat_type.value if isinstance(threat_type, ThreatType) else str(threat_type)

        mapping = {
            ThreatType.MAC_ADDRESS_CHANGE.value: self.weights.mac_address_change,
            ThreatType.DUPLICATE_IP.value: self.weights.duplicate_ip,
            ThreatType.DUPLICATE_MAC.value: self.weights.duplicate_mac,
            ThreatType.GRATUITOUS_ARP_ABUSE.value: self.weights.gratuitous_arp_abuse,
            ThreatType.EXCESSIVE_ARP_REPLIES.value: self.weights.excessive_arp_replies,
            ThreatType.RAPID_MAC_SWITCHING.value: self.weights.rapid_mac_switching,
            ThreatType.SUSPICIOUS_ARP_FREQUENCY.value: self.weights.suspicious_arp_frequency,
        }

        value = float(mapping.get(key, 0)) + float(extra_score)
        return max(0.0, min(100.0, value))

    def level(self, score: float) -> RiskLevel:
        """Map a numeric score to a risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 30:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def assess(
        self,
        threat_type: ThreatType | str,
        extra_score: float = 0,
    ) -> dict[str, Any]:
        score = self.score(threat_type, extra_score)
        return {
            "threat_type": (
                threat_type.value
                if isinstance(threat_type, ThreatType)
                else str(threat_type)
            ),
            "risk_score": score,
            "risk_level": self.level(score).value,
        }
