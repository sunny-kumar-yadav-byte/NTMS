"""
packet_capture.py
=================
Scapy-based ARP packet capture for the Network Threat Monitoring System.
"""

from __future__ import annotations

import logging
from threading import Lock, Thread
from typing import Any, Callable


class PacketCapture:
    """Captures packets from a selected network interface."""

    def __init__(
        self,
        interface: str | None = None,
        on_packet_callback: Callable[[Any], Any] | None = None,
        bpf_filter: str = "arp",
    ):
        self.interface = interface
        self.on_packet_callback = on_packet_callback
        self.bpf_filter = bpf_filter

        self.logger = logging.getLogger("ntms.packet_capture")
        self._thread: Thread | None = None
        self._running = False
        self._lock = Lock()
        self._sniffer: Any = None

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:
        """Start packet capture in a background thread."""
        with self._lock:
            if self._running:
                return

            self._running = True

        self._thread = Thread(
            target=self._capture_loop,
            name="NTMS-PacketCapture",
            daemon=True,
        )
        self._thread.start()

    def _capture_loop(self) -> None:
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            self.logger.error(
                "Scapy is not installed. Install it with: pip install scapy"
            )
            self._running = False
            return

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
            )
            self._sniffer.start()

            self.logger.info(
                "Packet capture started on interface '%s'.",
                self.interface or "(default)",
            )

            while self._running:
                if self._thread is None:
                    break

                # Keep this thread alive while AsyncSniffer runs.
                self._thread.join(timeout=0.2)

        except PermissionError:
            self.logger.exception(
                "Packet capture requires administrator/root privileges."
            )
        except Exception:
            self.logger.exception("Packet capture failed.")
        finally:
            self._running = False

    def _handle_packet(self, packet: Any) -> None:
        if not self._running:
            return

        if self.on_packet_callback is None:
            return

        try:
            self.on_packet_callback(packet)
        except Exception:
            self.logger.exception(
                "Packet callback failed while processing a captured packet."
            )

    def stop(self) -> None:
        """Stop packet capture and release the sniffer."""
        with self._lock:
            self._running = False

        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        except Exception:
            self.logger.exception("Error while stopping packet capture.")
        finally:
            self._sniffer = None

    def capture_once(self, count: int = 1) -> list[Any]:
        """Capture a small number of packets synchronously for testing."""
        try:
            from scapy.all import sniff

            packets = sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                count=count,
                store=True,
            )
            return list(packets)

        except Exception:
            self.logger.exception("Synchronous packet capture failed.")
            return []
