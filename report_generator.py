"""
report_generator.py
===================
Generates security reports from NTMS database information.
Includes Deception Technology (Honeypot) threat metrics.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any

from database import DatabaseManager
from statistics import StatisticsManager


class ReportGenerator:
    """Creates CSV and HTML reports for network security activity and deception metrics."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        statistics_manager: StatisticsManager,
        config: Any | None = None,
        output_directory: str | Path | None = None,
    ):
        self.db_manager = db_manager
        self.statistics_manager = statistics_manager

        if output_directory is not None:
            self.output_directory = Path(output_directory)
        elif config is not None:
            self.output_directory = Path(config.REPORTS_DIR)
        else:
            self.output_directory = Path("reports")

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def generate_csv(self, filename: str | None = None) -> str:
        if filename is None:
            filename = (
                f"ntms_report_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )

        path = self.output_directory / filename

        alerts = self.db_manager.fetch_all(
            "SELECT * FROM alerts ORDER BY id DESC"
        )

        fieldnames = [
            "id",
            "timestamp",
            "ip_address",
            "mac_address",
            "threat_type",
            "risk_level",
            "risk_score",
            "message",
            "status",
        ]

        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(alerts)

        self.db_manager.execute(
            "INSERT INTO reports(created_at, report_path) VALUES(?, ?)",
            (
                datetime.now().isoformat(timespec="seconds"),
                str(path),
            ),
        )

        return str(path)

    def generate_html(self, filename: str | None = None) -> str:
        if filename is None:
            filename = (
                f"ntms_report_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            )

        path = self.output_directory / filename
        summary = self.statistics_manager.get_summary()

        # Count Honeypot / Reconnaissance hits specifically for the summary
        honeypot_hits_count = 0
        rows = []

        for alert in summary.get("recent_alerts", []):
            threat_type = str(alert.get("threat_type", ""))
            
            # Highlight Honeypot / Deception events in the report
            is_honeypot = "HONEYPOT" in threat_type.upper() or "RECONNAISSANCE" in threat_type.upper()
            if is_honeypot:
                honeypot_hits_count += 1
                row_style = 'style="background-color: #fff3cd; font-weight: bold;"'
            else:
                row_style = ""

            rows.append(
                f"<tr {row_style}>"
                f"<td>{alert.get('timestamp', '')}</td>"
                f"<td>{alert.get('ip_address', '')}</td>"
                f"<td>{threat_type}</td>"
                f"<td>{alert.get('risk_level', '')}</td>"
                f"<td>{alert.get('risk_score', '')}</td>"
                f"<td>{alert.get('message', '')}</td>"
                "</tr>"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Threat Monitoring Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 30px; background-color: #f9f9f9; }}
h1 {{ margin-bottom: 5px; color: #1a252f; }}
.subtitle {{ color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }}
.card-container {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }}
.card {{
    background: #ffffff;
    padding: 15px 20px;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    min-width: 140px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
}}
.card-title {{ font-size: 0.8em; color: #7f8c8d; text-transform: uppercase; margin-bottom: 5px; }}
.card-value {{ font-size: 1.4em; font-weight: bold; color: #2c3e50; }}
.card-deception {{ border-left: 4px solid #e67e22; }}
.card-critical {{ border-left: 4px solid #e74c3c; }}
table {{
    border-collapse: collapse;
    width: 100%;
    background: #ffffff;
    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
}}
th, td {{
    border: 1px solid #e0e0e0;
    padding: 10px 12px;
    text-align: left;
}}
th {{ background: #2c3e50; color: #ffffff; }}
</style>
</head>
<body>

<h1>Network Threat Monitoring System</h1>
<div class="subtitle">
    Proactive Hybrid Security Report | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>

<div class="card-container">
    <div class="card">
        <div class="card-title">Monitored Devices</div>
        <div class="card-value">{summary.get('device_count', 0)}</div>
    </div>

    <div class="card">
        <div class="card-title">Active Alerts</div>
        <div class="card-value">{summary.get('active_alerts', 0)}</div>
    </div>

    <div class="card card-critical">
        <div class="card-title">Critical Threats</div>
        <div class="card-value">{summary.get('alert_counts', {{}}).get('CRITICAL', 0)}</div>
    </div>

    <div class="card">
        <div class="card-title">High Threats</div>
        <div class="card-value">{summary.get('alert_counts', {{}}).get('HIGH', 0)}</div>
    </div>

    <div class="card card-deception">
        <div class="card-title">🛡️️ Deception Traps Hit</div>
        <div class="card-value">{honeypot_hits_count}</div>
    </div>
</div>

<h2>Security Event Audit Logs</h2>

<table>
<tr>
<th>Time</th>
<th>IP Address</th>
<th>Threat Type</th>
<th>Risk Level</th>
<th>Score</th>
<th>Alert Details</th>
</tr>

{''.join(rows)}

</table>

</body>
</html>
"""

        path.write_text(
            html,
            encoding="utf-8",
        )

        self.db_manager.execute(
            "INSERT INTO reports(created_at, report_path) VALUES(?, ?)",
            (
                datetime.now().isoformat(timespec="seconds"),
                str(path),
            ),
        )

        return str(path)

    def generate(self, format: str = "html") -> str:
        if format.lower() == "csv":
            return self.generate_csv()

        return self.generate_html()