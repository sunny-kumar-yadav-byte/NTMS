# Network Threat Monitoring System (NTMS)

A modular, real-time LAN threat monitoring desktop application, built as
a professional-grade cybersecurity project. The first detection module
is **ARP Spoof Detection**; the architecture is designed so additional
detection modules (DHCP spoofing, DNS spoofing, port scans, rogue DHCP
servers, MITM, bandwidth monitoring, Wi-Fi threats...) can be added
later without restructuring the application.

## Architecture decisions (Module 1)

| Concern | Choice | Why |
|---|---|---|
| Packet capture | Scapy | De-facto standard for raw packet sniffing/crafting in Python |
| Desktop GUI | PyQt6 | Modern, native-feeling widgets; strong live-update support; embeds Matplotlib directly |
| Charts | Matplotlib | One charting library reused for both the live dashboard *and* PDF reports |
| PDF reports | ReportLab | Full layout/table/chart control for a polished report |
| Database | SQLite (stdlib `sqlite3`) | Zero-config, file-based, sufficient for a single-analyst desktop tool |
| Desktop notifications | Plyer | Cross-platform notification API |
| Sound alerts | Playsound | Minimal, dependency-light audio playback |
| MAC vendor lookup | `mac-vendor-lookup` | Offline IEEE OUI database, no external API calls |

If a browser-based dashboard (Flask/FastAPI) is preferred over PyQt6,
that's a reasonable pivot -- best done before Module 10 (`dashboard.py`).

## Project status

- [x] **Module 1 - Foundation**: `config.py`, `utils.py`, project scaffold
- [ ] Module 2 - Database layer (`database.py`)
- [ ] Module 3 - Packet capture engine (`packet_capture.py`)
- [ ] Module 4 - Device discovery (`device_manager.py`)
- [ ] Module 5 - ARP spoof detection (`arp_detector.py`)
- [ ] Module 6 - Risk engine (`risk_engine.py`)
- [ ] Module 7 - Detection orchestration (`detection_engine.py`)
- [ ] Module 8 - Alerts & notifications (`alert_manager.py`, `notification.py`)
- [ ] Module 9 - Report generation (`report_generator.py`)
- [ ] Module 10 - Dashboard GUI (`dashboard.py`)
- [ ] Module 11 - Application wiring (`main.py`, final)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Packet capture with Scapy needs elevated privileges:

- **Linux/macOS**: run with `sudo`, or grant the interpreter capabilities
  once: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`
- **Windows**: install [Npcap](https://npcap.com/) first.

## Running (current state)

```bash
python3 main.py
```

This currently only verifies configuration loading and logging are
working (Module 1); it becomes the full application entry point once
every module is complete.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

## Project layout

```
NetworkThreatMonitoringSystem/
├── main.py              # entry point (grows with each module)
├── config.py             # settings, enums, ConfigManager
├── utils.py               # logging setup, validation helpers, SingletonMeta
├── database.py             # (Module 2)
├── packet_capture.py        # (Module 3)
├── device_manager.py         # (Module 4)
├── arp_detector.py            # (Module 5)
├── risk_engine.py               # (Module 6)
├── detection_engine.py           # (Module 7)
├── alert_manager.py                # (Module 8)
├── notification.py                  # (Module 8)
├── report_generator.py               # (Module 9)
├── dashboard.py                       # (Module 10)
├── logs/
├── reports/
├── assets/
├── database/
└── tests/
```
