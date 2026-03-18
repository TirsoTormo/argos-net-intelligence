<div align="center">

# 🛡️ Argos Enterprise
### Advanced Network Intelligence & Packet Factory

[![Version](https://img.shields.io/badge/version-v1.2.0-purple.svg)](https://github.com/TirsoTormo/argos-net-intelligence)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Active-success.svg)](#)

*An elite cybersecurity suite designed for system administrators (ASIR) and network engineers.*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Architecture](#architecture) • [Disclaimer](#disclaimer)

</div>

---

## 📖 Overview

**Argos** is a high-performance, command-line network auditing tool built entirely in Python. Evolving from a simple Layer 2/3 network scanner into a full-fledged **Enterprise-Grade** intelligence suite, Argos integrates active network discovery, synthetic packet injection (Packet Factory), and L7 Application Service profiling into a highly visual, cinematic Terminal UI (TUI).

Built with the **"Elite Purple"** design aesthetic using Rich, Argos is meant to be the Swiss Army Knife for offensive and defensive network operations.

## ✨ Features

- **⚡ Resilient Auto-Discovery (L2/L3)**: High-speed ARP scans and ICMP ping sweeps with an integrated, multi-threaded Vendor MAC lookup engine `api.macvendors.com`, fortified with Exponential Backoff and local JSON caching.
- **🕵️‍♂️ L7 Service Intelligence**: Aggressive Banner Grabbing. Argos automatically interacts with Open Ports via raw sockets to detect SSH greetings, HTTP/HTTPS web server headers (`Server: Apache/2.4`), FTP, and SNMP hardware models.
- **🏭 Packet Factory (Raw Sockets)**: Synthesize your own packets across the OSI model.
  - Custom TCP Segments with specific flags (`SYN`, `ACK`, `FIN`, `RST`).
  - UDP Probing and ICMP payload control.
  - Evasion techniques and manual Traceroutes via custom TTL manipulation.
- **🎥 "Cinema" UX Dashboard**: Live, Matrix-style animated tables utilizing `SQUARE_DOUBLE_HEADED` glass-pane borders for real-time visual feedback without screen-tearing.
- **💾 Audit Persistence & Exports**: All scans are automatically archived into a local SQLite database (`storage/database.py`) and can be exported cleanly to JSON, Markdown, or CSV.

---

## 🚀 Installation

Argos uses Scapy for packet manipulation, which requires raw socket privileges (Root/Admin on your OS) and NPcap/WinPcap on Windows.

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/argos-net-intelligence.git
cd argos-net-intelligence

# 2. (Optional) Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows

# 3. Install dependencies
pip install -r requirements.txt
```

> **⚠️ OS Requirements for Packet Factory:**
> - **Windows**: Run your terminal (PowerShell/CMD) as **Administrator**. Needs NPCap.
> - **Linux**: Run via `sudo python main.py`.

---

## 💻 Usage

Argos can be run in **Interactive Mode** (High-End TUI) or **Unattended Mode** (direct CLI flags).

### Interactive Menu
To launch the interactive dashboard, simply run without arguments:
```bash
sudo python main.py
```
*(On Windows, run `python main.py` from an Administrator Shell).*

### Unattended CLI Examples

**Network Discovery & Scanning**
```bash
sudo python main.py --scan               # Quick LAN Scan
sudo python main.py --interfaces         # Show active local adapters
```

**Packet Factory (Injection & Probing)**
```bash
sudo python main.py --probe 192.168.1.1 --ports 80,443,22
sudo python main.py --probe 192.168.1.1 --ports web          # Predefined groups
sudo python main.py --dst 192.168.1.1 --flags S --port 443   # TCP SYN
sudo python main.py --ping 192.168.1.1 --count 10 --ttl 128  # Custom ICMP
sudo python main.py --traceroute 192.168.1.1
```

**LAN Speed Test**
```bash
python main.py --server                  # Start listener
python main.py --client 192.168.1.10     # Client injection test
```

---

## 🏗️ Architecture (v1.2.0)

Argos is designed around **Clean Architecture** patterns, separating the application into distinct packages:

```text
argos-net-intelligence/
├── main.py                # Main orchestration & CLI Router
├── core/                  # Engine Logic & Raw Sockets
│   ├── discovery.py       # ARP & Ping Sweeps
│   ├── packet_factory.py  # Layer 2/3/4 packet forging (Scapy)
│   ├── service_audit.py   # Layer 7 Banner Grabbing (HTTP/SSH/FTP)
│   └── vendor_manager.py  # Resilient Multi-threaded MAC resolving
├── ui/                    # Presentation Layer (Elite Purple)
│   ├── cli_ui.py          # Interactive TUI menus
│   ├── report.py          # Live Rich tables and dashboards
│   └── theme.py           # Aesthetic constants and color palettes
└── storage/               # Data Persistence
    ├── database.py        # SQLite history tracking
    ├── exporter.py        # JSON / CSV / MD exporters
    └── vendors_cache.json # Local OUI lookup table
```

---

## 🛣️ Roadmap

- [x] **v1.1.1**: Concurrent OUI Lookup & Architectural Decoupling.
- [x] **v1.2.0**: L7 Service Intelligence & TUI Cinema Rendering.
- [ ] **v2.0.0**: Rogue DHCP Hunting & Jitter/QoS Analysis for Enterprise VoIP.

---

## ⚖️ Disclaimer

Argos is a tool intended strictly for **authorized network auditing**, educational purposes, and systems administration tasks. The creators and contributors are **not responsible** for any misuse, damage, or illegal activities caused by the execution of this software. Always ensure you have explicit, written permission to audit the target network.

---
<div align="center">
  <i>Developed with precision and passion for Network Engineers.</i>
</div>