"""
report_generator.py
===================
Generates security reports from NTMS database information.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any

from database import DatabaseManager
from statistics import StatisticsManager


class ReportGenerator:
    """Creates CSV and HTML reports for network security activity."""

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

        rows = []

        for alert in summary["recent_alerts"]:
            rows.append(
                "<tr>"
                f"<td>{alert.get('timestamp', '')}</td>"
                f"<td>{alert.get('ip_address', '')}</td>"
                f"<td>{alert.get('threat_type', '')}</td>"
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
body {{ font-family: Arial, sans-serif; margin: 30px; }}
h1 {{ margin-bottom: 5px; }}
.card {{
    display: inline-block;
    margin: 8px;
    padding: 15px;
    border: 1px solid #ccc;
    border-radius: 8px;
}}
table {{
    border-collapse: collapse;
    width: 100%;
    margin-top: 20px;
}}
th, td {{
    border: 1px solid #ccc;
    padding: 8px;
    text-align: left;
}}
th {{ background: #f2f2f2; }}
</style>
</head>
<body>

<h1>Network Threat Monitoring System</h1>

<p>
Generated:
{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</p>

<div class="card">
    Devices: {summary['device_count']}
</div>

<div class="card">
    Active Alerts: {summary['active_alerts']}
</div>

<div class="card">
    Critical: {summary['alert_counts']['CRITICAL']}
</div>

<div class="card">
    High: {summary['alert_counts']['HIGH']}
</div>

<table>
<tr>
<th>Time</th>
<th>IP</th>
<th>Threat</th>
<th>Risk</th>
<th>Score</th>
<th>Message</th>
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