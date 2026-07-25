<div align="center">

<img src="static/img/logo.svg" width="90" alt="RDPShield logo">

# RDPShield

**Real-time RDP brute-force detection and response for Windows**

A defensive (blue-team) security tool that monitors the Windows Security Event Log for
remote-desktop attacks, enriches and geolocates attacker IPs, blocks them via Windows
Firewall, runs YARA scans for post-compromise indicators, and sends SMS alerts — all
surfaced through a live SOC-style web dashboard.

</div>

---

## Overview

RDPShield watches Windows logon events (4625 / 4624) in real time and applies five
detection algorithms to identify brute-force, slow-and-low, password-spray, persistent
low-and-slow, and reputation-flagged attacks. When an attack is detected it enriches the
attacker IP (geolocation + abuse reputation), blocks it at the firewall, triggers a YARA
scan of the host, and notifies the administrator by SMS. A Flask dashboard provides live
monitoring, geographic access control, and a YARA scan controller.

> Developed as an MSc dissertation project.

---

## Features

- **Six detection algorithms**
  - Fast brute force — 5 failed logins in 60 s
  - Slow-and-low — 10 failed logins in 600 s (with timing-regularity analysis)
  - Password spray — 4+ unique usernames in 300 s
  - Persistent / low-and-slow — 15 cumulative failed logins in 24 h (catch-all for very slow attackers)
  - Reputation / threat-intel — low-volume IPs flagged by AbuseIPDB (cached) and VirusTotal; tiered alert (≥50%) / auto-block (≥85%)
  - Campaign / coordinated-attack — 7-day correlation: a determined IP over many days, a country attacking with many IPs, or attacks recurring in the same time-of-day window; SMS the SOC + auto-block the worst single-IP campaigns
- **Automatic response** — blocks attacker IPs via Windows Firewall (`netsh`), with whitelist protection against self-lockout
- **IP enrichment** — geolocation (country / city / ISP) via [ip-api.com] and abuse reputation scoring via [AbuseIPDB]
- **Geographic access control** — three modes: allow anywhere, IP whitelist only, or country whitelist
- **YARA scanning** — automatic disk scan on block + on-demand memory scanning for post-compromise indicators, with false-positive suppression
- **SMS alerts** — real-time notifications via [Notify.lk]
- **Live SOC dashboard** — Flask + Chart.js: failed-login trend, alert breakdown, top attacker countries, blocked-IP management
- **Authenticated access** — password + **TOTP two-factor** login, admin/guest **roles** with fine-grained RBAC (only root manages root/admins), **SMS phone-verification** for new users and credential changes (lock-until-verified), CSRF protection, and temporary account lockouts with **SMS self-unlock** recovery (see [`SECURITY.md`](SECURITY.md))
- **Multi-tenant command centre (optional)** — **RDPShield Central** aggregates many independent deployments into one console: fleet-wide stat tiles, a searchable table of every managed server, per-customer drill-down, and single sign-on click-through into any server's own dashboard. Agents **push** aggregated counters to Central (no inbound access to a customer network, NAT-friendly) and raw attacker records never leave the instance. Off by default — see [`CENTRAL.md`](CENTRAL.md)

---

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  rdpshield.py    │     │   database.py    │     │   dashboard.py   │
│  (agent)         │────▶│   (SQLite)       │◀────│   (Flask web)    │
│                  │     │                  │     │                  │
│ • event log poll │     │ • failed_logins  │     │ • / dashboard    │
│ • detection algs │     │ • alerts         │     │ • /geo settings  │
│ • geo-check      │     │ • blocked_ips    │     │ • /yara control  │
└────────┬─────────┘     │ • geo_* tables   │     └──────────────────┘
         │               │ • yara_* tables  │
         ▼               └──────────────────┘
┌──────────────────┐     ┌──────────────────┐
│   firewall.py    │     │    alerts.py     │
│ • block / unblock│     │ • ip-api geo     │
│   (netsh rules)  │     │ • AbuseIPDB      │
└──────────────────┘     │ • Notify.lk SMS  │
         │               └──────────────────┘
         ▼
┌──────────────────┐
│ yara_scheduler / │
│ yara_scanner.py  │  ── disk + memory scans on block
└──────────────────┘
```

---

## Requirements

- **Windows** (Server or 10/11) — must run as Administrator for Event Log + firewall access
- **Python 3.11** (64-bit recommended)
- Python packages:
  ```
  pip install flask requests pywin32 yara-python psutil
  ```

---

## Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR-USERNAME/RDPShield.git
   cd RDPShield
   ```

2. **Create your configuration** from the template
   ```bash
   copy config.example.py config.py      # Windows
   # cp config.example.py config.py      # Linux/macOS
   ```
   Then edit `config.py` and add your own:
   - AbuseIPDB API key ([get one free](https://www.abuseipdb.com/))
   - Notify.lk credentials ([register](https://app.notify.lk/register))
   - Your admin IP(s) in `WHITELIST_IPS` (prevents self-lockout)

3. **Install dependencies**
   ```bash
   pip install flask requests pywin32 yara-python psutil
   ```

---

## Usage

Run both processes **as Administrator**, in separate terminals:

```bash
# Terminal 1 — detection agent
python -u rdpshield.py

# Terminal 2 — web dashboard
python dashboard.py
```

Open the dashboard at **http://localhost:5000** (or `http://<server-ip>:5000`).

### Run as background services (Windows Task Scheduler)

To keep RDPShield running after logout / reboot, register both as SYSTEM tasks:

```cmd
schtasks /create /tn "RDPShield-Agent"     /tr "C:\path\to\run_agent.bat"     /sc onstart /ru SYSTEM /f
schtasks /create /tn "RDPShield-Dashboard" /tr "C:\path\to\run_dashboard.bat" /sc onstart /ru SYSTEM /f
```

---

## Dashboard

| Page | Purpose |
|---|---|
| **Dashboard** (`/`) | Live stats, failed-login trend, alert breakdown, top attacker countries, blocked-IP management |
| **Geolocation** (`/geo`) | Access-control mode, country/IP whitelists, geo-event log |
| **YARA Controller** (`/yara`) | Trigger disk/memory scans, view scan history and findings |

---

## Configuration

Key settings in `config.py` (see `config.example.py` for the full template):

| Setting | Default | Description |
|---|---|---|
| `BRUTE_FORCE_MAX_FAILURES` / `_TIME_WINDOW` | 5 / 60 s | Fast brute-force threshold |
| `SLOW_ATTACK_MAX_FAILURES` / `_TIME_WINDOW` | 10 / 600 s | Slow-and-low threshold |
| `SPRAY_MAX_USERNAMES` / `_TIME_WINDOW` | 4 / 300 s | Password-spray threshold |
| `PERSISTENT_MAX_FAILURES` / `_TIME_WINDOW` | 15 / 86400 s | Persistent low-and-slow threshold |
| `REPUTATION_ALERT_SCORE` / `_BLOCK_SCORE` | 50 / 85 | Reputation alert / auto-block AbuseIPDB % |
| `AUTO_BLOCK_ENABLED` | `True` | Auto-block detected attackers |
| `WHITELIST_IPS` | localhost + server | IPs that are never blocked |
| `GEO_BLOCK_ENABLED` | `True` | Enable geographic access control |

---

## Security Notes

- **Account security model** — sign-in (password + TOTP), roles, account lockouts, SMS self-unlock recovery, session/cookie hardening, and CSRF are documented in **[`SECURITY.md`](SECURITY.md)**.
- **`config.py` is gitignored** and must never be committed — it holds live API keys and credentials. Use `config.example.py` as the template. The auto-generated **`.flask_secret_key`** (session signing) is also gitignored — keep it private and per-server.
- The dashboard runs over **plain HTTP** with a development server, with port 5000 restricted to the admin IP — the accepted setup for this dissertation deployment. **HTTPS/TLS is a documented future enhancement** (hooks are in place; see `INSTALL.md` §11), not a current step.
- **RDPShield Central is the exception: TLS is mandatory there** and it refuses to start without it. Central carries cross-tenant data and mints the tokens that grant dashboard sessions, so plaintext is not an acceptable trade-off the way it is for a single instance behind an IP allow-list. Its threat model — including what a compromised instance, a compromised Central, or a stolen `central.db` actually gets an attacker — is set out in **[`CENTRAL.md`](CENTRAL.md)** §8.
- RDPShield blocks **all inbound traffic** from a detected IP. Always add your own admin IP to `WHITELIST_IPS` before enabling geo-blocking or testing, to avoid locking yourself out.
- This is a **defensive** tool intended for systems you own or are authorized to protect.

---

## License

Released for academic and educational use.

[ip-api.com]: http://ip-api.com/
[AbuseIPDB]: https://www.abuseipdb.com/
[Notify.lk]: https://notify.lk/
