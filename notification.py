"""
notification.py
===============
Notification service for the Network Threat Monitoring System.
"""

from __future__ import annotations

import logging
import platform
import subprocess
from typing import Any


class NotificationService:
    """Provides desktop and sound notifications for security alerts."""

    def __init__(self, settings_manager: Any):
        self.settings_manager = settings_manager
        self.logger = logging.getLogger("ntms.notification")

    def notify(
        self,
        title: str,
        message: str,
        risk_level: str = "MEDIUM",
    ) -> bool:
        """Send a desktop notification when enabled."""
        enabled = self.settings_manager.get(
            "enable_desktop_notifications",
            True,
        )

        if not enabled:
            return False

        try:
            system = platform.system()

            if system == "Darwin":
                safe_title = title.replace('"', '\\"')
                safe_message = message.replace('"', '\\"')
                script = (
                    f'display notification "{safe_message}" '
                    f'with title "{safe_title}"'
                )
                subprocess.run(
                    ["osascript", "-e", script],
                    check=False,
                    capture_output=True,
                )
                return True

            if system == "Linux":
                result = subprocess.run(
                    ["notify-send", title, message],
                    check=False,
                    capture_output=True,
                )
                return result.returncode == 0

            if system == "Windows":
                # Avoid requiring a third-party package here.
                self.logger.info(
                    "Windows notification requested: %s - %s",
                    title,
                    message,
                )
                return True

        except Exception:
            self.logger.exception("Failed to send desktop notification.")

        return False

    def play_sound(self) -> bool:
        """Play the configured alert sound when sound alerts are enabled."""
        enabled = self.settings_manager.get("enable_sound_alerts", True)

        if not enabled:
            return False

        sound_file = self.settings_manager.get(
            "sound_file",
            "assets/alert.wav",
        )

        try:
            system = platform.system()

            if system == "Darwin":
                subprocess.run(
                    ["afplay", str(sound_file)],
                    check=False,
                    capture_output=True,
                )
                return True

            if system == "Linux":
                result = subprocess.run(
                    ["paplay", str(sound_file)],
                    check=False,
                    capture_output=True,
                )
                return result.returncode == 0

            if system == "Windows":
                import winsound

                winsound.PlaySound(
                    str(sound_file),
                    winsound.SND_FILENAME | winsound.SND_ASYNC,
                )
                return True

        except Exception:
            self.logger.exception("Failed to play alert sound.")

        return False

    def send_alert(
        self,
        title: str,
        message: str,
        risk_level: str = "MEDIUM",
    ) -> None:
        """Send both configured notification types."""
        self.notify(title, message, risk_level)
        self.play_sound()
