"""
Network Threat Monitoring System
=================================

Application entry point.

This module wires together every subsystem of the Network Threat
Monitoring System (configuration, persistence, device management,
threat detection, risk scoring, alerting, reporting and the GUI
dashboard) and launches the application.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from types import FrameType

from config import AppConfig, ensure_directories
from utils import setup_logging, is_admin, list_network_interfaces
from database import DatabaseManager
from settings import SettingsManager
from device_manager import DeviceManager
from risk_engine import RiskEngine
from notification import NotificationService
from alert_manager import AlertManager
from arp_detector import ARPSpoofDetector
from detection_engine import DetectionEngine
from statistics import StatisticsManager
from report_generator import ReportGenerator
from packet_capture import PacketCapture
from dashboard import DashboardApp


class NetworkThreatMonitoringApp:
    """
    Top-level application object.

    Responsible for constructing every subsystem in the correct order,
    injecting dependencies, and providing a single, well-defined
    startup/shutdown lifecycle for the Network Threat Monitoring System.
    """

    def __init__(self, interface: str | None = None, debug: bool = False) -> None:
        self.config: AppConfig = AppConfig()
        ensure_directories(self.config)

        self.logger: logging.Logger = setup_logging(self.config, debug=debug)
        self.logger.info("Initializing %s v%s", self.config.APP_NAME, self.config.APP_VERSION)

        if not is_admin():
            self.logger.warning(
                "Application is not running with administrative/root privileges. "
                "Live packet capture may fail or be limited."
            )

        try:
            self.db_manager: DatabaseManager = DatabaseManager(self.config.DB_PATH)
            self.db_manager.initialize_schema()

            self.settings_manager: SettingsManager = SettingsManager(self.db_manager)
            self.device_manager: DeviceManager = DeviceManager(self.db_manager)
            self.risk_engine: RiskEngine = RiskEngine()
            self.notification_service: NotificationService = NotificationService(self.settings_manager)
            self.alert_manager: AlertManager = AlertManager(self.db_manager, self.notification_service)

            self.arp_detector: ARPSpoofDetector = ARPSpoofDetector(self.device_manager)

            self.detection_engine: DetectionEngine = DetectionEngine(
                device_manager=self.device_manager,
                risk_engine=self.risk_engine,
                alert_manager=self.alert_manager,
            )
            self.detection_engine.register_detector(self.arp_detector)

            self.statistics_manager: StatisticsManager = StatisticsManager(self.db_manager)
            self.report_generator: ReportGenerator = ReportGenerator(
                db_manager=self.db_manager,
                statistics_manager=self.statistics_manager,
                config=self.config,
            )

            self.interface: str = (
                interface
                or self.settings_manager.get("network_interface", self.config.DEFAULT_INTERFACE)
            )
            self.packet_capture: PacketCapture = PacketCapture(
                interface=self.interface,
                on_packet_callback=self.detection_engine.process_packet,
            )

            self.dashboard: DashboardApp | None = None
            self._shutting_down: bool = False

        except Exception:
            self.logger.critical("Fatal error during application initialization", exc_info=True)
            raise

    def run(self) -> None:
        """Build and launch the GUI dashboard, blocking until it is closed."""
        self.logger.info("Launching dashboard on interface '%s'", self.interface)
        try:
            self.dashboard = DashboardApp(
                config=self.config,
                device_manager=self.device_manager,
                alert_manager=self.alert_manager,
                statistics_manager=self.statistics_manager,
                settings_manager=self.settings_manager,
                report_generator=self.report_generator,
                packet_capture=self.packet_capture,
                detection_engine=self.detection_engine,
                risk_engine=self.risk_engine,
                on_close=self.shutdown,
            )
            self.dashboard.mainloop()
        except Exception:
            self.logger.critical("Fatal error while running the dashboard", exc_info=True)
            self.shutdown()
            raise

    def shutdown(self) -> None:
        """Gracefully stop background threads and release all resources."""
        if self._shutting_down:
            return
        self._shutting_down = True

        self.logger.info("Shutting down %s", self.config.APP_NAME)

        try:
            if self.packet_capture.is_running:
                self.packet_capture.stop()
        except Exception:
            self.logger.exception("Error while stopping packet capture")

        try:
            self.detection_engine.stop()
        except Exception:
            self.logger.exception("Error while stopping detection engine")

        try:
            self.db_manager.close()
        except Exception:
            self.logger.exception("Error while closing the database connection")

        self.logger.info("Shutdown complete")


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the application."""
    parser = argparse.ArgumentParser(
        prog="NetworkThreatMonitoringSystem",
        description="Network Threat Monitoring System - real-time network threat detection.",
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to monitor (e.g. eth0, wlan0). Defaults to configured interface.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the application version and exit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Application entry point."""
    args = parse_arguments(argv)

    if args.version:
        config = AppConfig()
        print(f"{config.APP_NAME} v{config.APP_VERSION}")
        return 0

    if args.list_interfaces:
        for name in list_network_interfaces():
            print(name)
        return 0

    app: NetworkThreatMonitoringApp | None = None

    def _handle_termination_signal(signum: int, frame: FrameType | None) -> None:
        if app is not None:
            app.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_termination_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_termination_signal)

    try:
        app = NetworkThreatMonitoringApp(interface=args.interface, debug=args.debug)
        app.run()
    except Exception as exc:
        logging.getLogger(__name__).critical("Unhandled exception: %s", exc, exc_info=True)
        return 1
    finally:
        if app is not None:
            app.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
