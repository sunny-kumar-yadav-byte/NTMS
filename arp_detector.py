"""
arp_detector.py
===============
ARP spoofing detection logic for the Network Threat Monitoring System.
"""

from __future__ import annotations

from collections import defaultdict, deque
from time import monotonic
from typing import Any

from config import AppConfig, ThreatType
from device_manager import DeviceManager
from utils import normalize_mac


class ARPSpoofDetector:
    """Detects suspicious changes and patterns in ARP traffic."""

    def __init__(self, device_manager: DeviceManager, config: AppConfig | None = None):
        self.device_manager = device_manager
        self.config = config or AppConfig()

        self._ip_to_mac: dict[str, str] = {}
        self._mac_to_ips: dict[str, set[str]] = defaultdict(set)
        self._mac_changes: dict[str, deque[float]] = defaultdict(deque)
        self._gratuitous_events: deque[float] = deque()
        self._arp_replies: deque[float] = deque()
        self._mac_switches: dict[str, deque[float]] = defaultdict(deque)

    def _trim(self, queue: deque[float], window: float, now: float) -> None:
        while queue and now - queue[0] > window:
            queue.popleft()

    def analyze_packet(self, packet: Any) -> list[dict[str, Any]]:
        """
        Analyze a Scapy ARP packet.

        Returns a list because one packet can trigger more than one rule.
        """
        try:
            from scapy.layers.l2 import ARP
        except ImportError:
            return []

        if not packet.haslayer(ARP):
            return []

        arp = packet[ARP]
        now = monotonic()

        source_ip = getattr(arp, "psrc", "") or ""
        source_mac = getattr(arp, "hwsrc", "") or ""
        target_ip = getattr(arp, "pdst", "") or ""
        target_mac = getattr(arp, "hwdst", "") or ""
        operation = int(getattr(arp, "op", 0) or 0)

        if not source_ip or not source_mac:
            return []

        source_mac = normalize_mac(source_mac)
        findings: list[dict[str, Any]] = []

        previous_mac = self._ip_to_mac.get(source_ip)

        if previous_mac and previous_mac != source_mac:
            self._mac_to_ips[previous_mac].discard(source_ip)
            
            changes = self._mac_changes[source_ip]
            changes.append(now)
            self._trim(
                changes,
                self.config.detection.mac_change_window_sec,
                now,
            )

            findings.append(
                self._finding(
                    ThreatType.MAC_ADDRESS_CHANGE,
                    source_ip,
                    source_mac,
                    target_ip,
                    target_mac,
                    operation,
                    "IP-to-MAC mapping changed.",
                )
            )

            if len(changes) >= self.config.detection.max_mac_changes_per_window:
                findings.append(
                    self._finding(
                        ThreatType.RAPID_MAC_SWITCHING,
                        source_ip,
                        source_mac,
                        target_ip,
                        target_mac,
                        operation,
                        "MAC address changed repeatedly in a short window.",
                    )
                )

            self._mac_switches[source_ip].append(now)
            self._trim(
                self._mac_switches[source_ip],
                self.config.detection.rapid_mac_switch_window_sec,
                now,
            )

        self._ip_to_mac[source_ip] = source_mac
        self._mac_to_ips[source_mac].add(source_ip)

        # Multiple IP addresses claiming the same MAC can be suspicious.
        if len(self._mac_to_ips[source_mac]) > 1:
            findings.append(
                self._finding(
                    ThreatType.DUPLICATE_MAC,
                    source_ip,
                    source_mac,
                    target_ip,
                    target_mac,
                    operation,
                    "The same MAC address is associated with multiple IP addresses.",
                )
            )

        # ARP reply = 2. Gratuitous ARP commonly has psrc == pdst.
        if operation == 2:
            self._arp_replies.append(now)
            self._trim(
                self._arp_replies,
                self.config.detection.arp_reply_window_sec,
                now,
            )

            if len(self._arp_replies) > self.config.detection.max_arp_replies_per_window:
                findings.append(
                    self._finding(
                        ThreatType.EXCESSIVE_ARP_REPLIES,
                        source_ip,
                        source_mac,
                        target_ip,
                        target_mac,
                        operation,
                        "ARP replies exceeded the configured threshold.",
                    )
                )

        if source_ip == target_ip and source_ip:
            self._gratuitous_events.append(now)
            self._trim(
                self._gratuitous_events,
                self.config.detection.gratuitous_arp_window_sec,
                now,
            )

            if (
                len(self._gratuitous_events)
                > self.config.detection.max_gratuitous_arp_per_window
            ):
                findings.append(
                    self._finding(
                        ThreatType.GRATUITOUS_ARP_ABUSE,
                        source_ip,
                        source_mac,
                        target_ip,
                        target_mac,
                        operation,
                        "Excessive gratuitous ARP activity detected.",
                    )
                )

        self.device_manager.upsert_device(
            source_ip,
            source_mac,
            status="ACTIVE",
        )

        for finding in findings:
            self.device_manager.record_arp_event(
                source_ip=source_ip,
                source_mac=source_mac,
                target_ip=target_ip,
                target_mac=target_mac,
                operation=str(operation),
                threat_type=finding["threat_type"],
            )

        return findings

    def _finding(
        self,
        threat_type: ThreatType,
        source_ip: str,
        source_mac: str,
        target_ip: str,
        target_mac: str,
        operation: int,
        message: str,
    ) -> dict[str, Any]:
        return {
            "threat_type": threat_type.value,
            "source_ip": source_ip,
            "source_mac": source_mac,
            "target_ip": target_ip,
            "target_mac": target_mac,
            "operation": operation,
            "message": message,
        }

    def get_ip_mac_map(self) -> dict[str, str]:
        return dict(self._ip_to_mac)

    def reset(self) -> None:
        self._ip_to_mac.clear()
        self._mac_to_ips.clear()
        self._mac_changes.clear()
        self._gratuitous_events.clear()
        self._arp_replies.clear()
        self._mac_switches.clear()