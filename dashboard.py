"""
dashboard.py
============
Lightweight Tkinter dashboard for the Network Threat Monitoring System.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any


class DashboardApp:
    """Simple desktop dashboard for live NTMS status and alerts."""

    def __init__(
        self,
        statistics_manager: Any,
        alert_manager: Any,
        device_manager: Any,
        packet_capture: Any = None,
        detection_engine: Any = None,
        config: Any = None,
        settings_manager: Any = None,
        report_generator: Any = None,
        risk_engine: Any = None,
        on_close: Any = None,
    ):
        self.statistics_manager = statistics_manager
        self.alert_manager = alert_manager
        self.device_manager = device_manager
        self.packet_capture = packet_capture
        self.detection_engine = detection_engine

        # Optional dependencies supplied by main.py.
        self.config = config
        self.settings_manager = settings_manager
        self.report_generator = report_generator
        self.risk_engine = risk_engine
        self.on_close = on_close

        self.root: tk.Tk | None = None
        self.device_label: ttk.Label | None = None
        self.alert_label: ttk.Label | None = None
        self.packet_label: ttk.Label | None = None
        self.threat_label: ttk.Label | None = None
        self.tree: ttk.Treeview | None = None

    def run(self) -> None:
        """Create and run the Tkinter dashboard."""
        self.root = tk.Tk()
        self.root.title("Network Threat Monitoring System")
        self.root.geometry("1050x650")
        self.root.minsize(850, 500)

        self.root.protocol("WM_DELETE_WINDOW", self._handle_close)

        self._build_ui()
        self.refresh()
        self.root.mainloop()

    def mainloop(self) -> None:
        """Compatibility method used by main.py."""
        self.run()

    def _handle_close(self) -> None:
        """Handle dashboard window closing."""
        if self.root is not None:
            self.root.destroy()
            self.root = None

        if self.on_close:
            try:
                self.on_close()
            except Exception:
                pass

    def _build_ui(self) -> None:
        assert self.root is not None

        header = ttk.Frame(self.root, padding=15)
        header.pack(fill="x")

        ttk.Label(
            header,
            text="Network Threat Monitoring System",
            font=("Arial", 20, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            header,
            text="ARP Spoofing Detection Dashboard",
            font=("Arial", 11),
        ).pack(anchor="w")

        cards = ttk.Frame(self.root, padding=(15, 0, 15, 10))
        cards.pack(fill="x")

        self.device_label = self._create_card(cards, "Devices")
        self.alert_label = self._create_card(cards, "Active Alerts")
        self.packet_label = self._create_card(cards, "Packets")
        self.threat_label = self._create_card(cards, "Threats")

        table_frame = ttk.Frame(self.root, padding=15)
        table_frame.pack(fill="both", expand=True)

        columns = (
            "time",
            "ip",
            "mac",
            "threat",
            "risk",
            "score",
            "status",
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
        )

        headings = {
            "time": "Time",
            "ip": "IP Address",
            "mac": "MAC Address",
            "threat": "Threat",
            "risk": "Risk",
            "score": "Score",
            "status": "Status",
        }

        for column in columns:
            self.tree.heading(
                column,
                text=headings[column],
            )
            self.tree.column(
                column,
                width=120,
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview,
        )

        self.tree.configure(
            yscrollcommand=scrollbar.set,
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        buttons = ttk.Frame(
            self.root,
            padding=15,
        )
        buttons.pack(fill="x")

        ttk.Button(
            buttons,
            text="Refresh",
            command=self.refresh,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Button(
            buttons,
            text="Start Capture",
            command=self.start_capture,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Button(
            buttons,
            text="Stop Capture",
            command=self.stop_capture,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Button(
            buttons,
            text="Resolve Selected Alert",
            command=self.resolve_selected,
        ).pack(
            side="left",
            padx=5,
        )

    def _create_card(
        self,
        parent: ttk.Frame,
        title: str,
    ) -> ttk.Label:
        frame = ttk.LabelFrame(
            parent,
            text=title,
            padding=12,
        )

        frame.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5,
        )

        label = ttk.Label(
            frame,
            text="0",
            font=("Arial", 18, "bold"),
        )

        label.pack()

        return label

    def refresh(self) -> None:
        """Refresh dashboard statistics and alerts."""
        if self.root is None:
            return

        try:
            summary = self.statistics_manager.get_summary()

            if self.device_label:
                self.device_label.config(
                    text=str(summary["device_count"])
                )

            if self.alert_label:
                self.alert_label.config(
                    text=str(summary["active_alerts"])
                )

            if self.detection_engine:
                stats = self.detection_engine.get_stats()

                packets = stats.get(
                    "total_packets",
                    0,
                )

                threats = stats.get(
                    "total_threats",
                    0,
                )

            else:
                packets = 0

                threats = sum(
                    int(item["count"])
                    for item in summary["threat_counts"]
                )

            if self.packet_label:
                self.packet_label.config(
                    text=str(packets)
                )

            if self.threat_label:
                self.threat_label.config(
                    text=str(threats)
                )

            self._refresh_alert_table()

        except Exception:
            # Prevent a temporary database/dashboard error
            # from killing the Tkinter event loop.
            pass

        if self.root is not None:
            self.root.after(
                3000,
                self.refresh,
            )

    def _refresh_alert_table(self) -> None:
        """Refresh the alert table."""
        if self.tree is None:
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        for alert in self.alert_manager.get_alerts(
            limit=100
        ):
            self.tree.insert(
                "",
                "end",
                iid=str(alert["id"]),
                values=(
                    alert.get("timestamp", ""),
                    alert.get("ip_address", ""),
                    alert.get("mac_address", ""),
                    alert.get("threat_type", ""),
                    alert.get("risk_level", ""),
                    alert.get("risk_score", ""),
                    alert.get("status", ""),
                ),
            )

    def start_capture(self) -> None:
        """Start network packet capture."""
        if self.packet_capture:
            self.packet_capture.start()

    def stop_capture(self) -> None:
        """Stop network packet capture."""
        if self.packet_capture:
            self.packet_capture.stop()

    def resolve_selected(self) -> None:
        """Resolve the selected alert."""
        if self.tree is None:
            return

        selected = self.tree.selection()

        if not selected:
            messagebox.showinfo(
                "No Alert Selected",
                "Please select an alert first.",
            )
            return

        alert_id = int(selected[0])

        self.alert_manager.resolve_alert(
            alert_id
        )

        self.refresh()