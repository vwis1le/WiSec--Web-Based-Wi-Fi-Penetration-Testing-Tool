# WiSec — Web-Based Wi-Fi Penetration Testing Tool

A Flask web application that wraps common Kali Linux wireless and network pentesting tools (Nmap, Aircrack-ng, Aireplay-ng, Hostapd) behind a simple browser dashboard — built as a final-year Computer Networking & Security capstone project (CNS3104), aimed at making basic Wi-Fi security assessments more accessible to Kenyan SMBs.

> ⚠️ **Authorized use only.** This tool performs active attacks (deauthentication, WPA2 handshake capture/cracking, rogue AP creation) against wireless networks and hosts. Only run it against networks and systems you own or have **explicit written permission** to test. Unauthorized use may violate the Kenya Computer Misuse and Cybercrimes Act and equivalent laws elsewhere.

## What it does

Log in, pick a target, select one or more test modules, and watch the scan run live in the browser. Results are scored with CVSS v3.1, stored in SQLite, and can be exported as a PDF report.

| Module | Underlying tool | What it does |
|---|---|---|
| **Network scan** | Nmap | Discovers live hosts and open/service ports on the target subnet |
| **WPA2 cracking** | Aircrack-ng suite | Captures a WPA2 handshake and runs a dictionary attack against it |
| **Deauthentication** | Aireplay-ng | Sends forged deauth frames to disconnect clients from the target AP |
| **Evil twin simulation** | Hostapd | Briefly broadcasts a rogue AP cloning the target SSID |

Each module's output is parsed and matched against a small library of known issues (e.g. vsftpd/UnrealIRCd backdoors, exposed Telnet/FTP/VNC/RPC services) to generate CVSS-scored findings with remediation recommendations.

## Architecture

- **`app.py`** — Flask routes: login/session handling, dashboard, module selection, live progress polling, results view, PDF download/regeneration
- **`scanner.py`** — Runs the actual scans as background threads, shells out to the Kali tools via `subprocess`, streams progress/log lines back to the UI, and maps raw tool output to stored vulnerability records
- **`database.py`** — SQLite schema (`users`, `scans`, `vulnerability_type`, `vulnerabilities`, `recommendations`, `reports`) and seeding (vulnerability types + a default admin account)
- **`report.py`** — Builds a branded PDF report per scan with ReportLab, colour-coded by CVSS severity (Critical/High/Medium/Low)
- **`templates/`** — `login.html`, `dashboard.html`, `modules.html`, `progress.html`, `results.html`

## Requirements

**Environment:** a Linux pentesting environment (developed and tested on Kali Linux, e.g. in a VirtualBox VM) with:
- Python 3
- A Wi-Fi adapter that supports monitor mode (tested with a Qualcomm Atheros AR9271 USB adapter) for the wireless modules
- `sudo` privileges, since `airodump-ng`, `aireplay-ng`, `aircrack-ng`, and `hostapd` are invoked with `sudo`
- System tools on `PATH`: `nmap`, `aircrack-ng`, `airodump-ng`, `aireplay-ng`, `hostapd`

**Python packages:**
```
flask
bcrypt
reportlab
```
(No `requirements.txt` is currently checked in — install the above with pip, or generate one with `pip freeze > requirements.txt` after installing them.)

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/vwis1le/web-wifi-pentester.git
cd web-wifi-pentester

# 2. Install Python dependencies
pip install flask bcrypt reportlab

# 3. Install system pentesting tools (Kali/Debian-based)
sudo apt install nmap aircrack-ng hostapd

# 4. Initialize the database (creates wifi_pentool.db + seeds an admin account)
python database.py

# 5. Run the app (needs sudo for the wireless modules to shell out correctly)
sudo python app.py
```

The app starts on `http://0.0.0.0:5000`. Default seeded login is `admin` / `admin123` — **change this before any real use**, since it's hardcoded in `database.py`.

## Usage

1. Log in at `/`.
2. From the dashboard, start a new scan and pick a target IP/subnet (auto-detected from your local network by default) and, for the wireless modules, the target SSID.
3. Select one or more modules (network scan, WPA2 cracking, deauthentication, evil twin).
4. Watch live progress and logs on the progress page.
5. Review CVSS-scored findings and recommendations on the results page, and download/regenerate a PDF report.

## Known limitations

- `app.secret_key` and the admin seed credentials are hardcoded — fine for a lab/academic demo, not for production.
- The evil twin module briefly disables monitor mode to launch `hostapd` on a single adapter, so it can't run concurrently with live capture on the same NIC — a hardware limitation of using one Wi-Fi adapter.
- Vulnerability detection is signature/service based rather than a full exploit framework; it's designed to illustrate common, well-known misconfigurations (e.g. against a target like Metasploitable 2) rather than to replace a tool like Metasploit.
