# RDPShield — Project Progress & Reference

> MSc Dissertation project. Windows blue-team tool for RDP brute-force detection with a Flask SOC-style dashboard.
> Last updated: 2026-06-21

---

## ⭐ CURRENT STATE (read this first)

**Live deployment:** AWS EC2 Windows Server, public IP `16.170.232.91`, dashboard at `http://16.170.232.91:5000` (and `http://localhost:5000` inside RDP).
**GitHub:** https://github.com/RaZa-97/RDPShield (branch `main`). The server is a git clone — deploy with `git pull`.
**Attacker test box:** BlackArch Linux VM (attacks from a mobile hotspot so the admin/home-wifi IP is never blocked).

### Deployment workflow (server)
```cmd
cd C:\Projects\RDPShield
git pull
:: clean restart so new code + DB migrations load (manual scans run in the dashboard process)
schtasks /end /tn "RDPShield-Agent" & schtasks /end /tn "RDPShield-Dashboard"
taskkill /F /IM python.exe
schtasks /run /tn "RDPShield-Agent" & schtasks /run /tn "RDPShield-Dashboard"
```
Browser hard-refresh (Ctrl+F5) after template/JS changes.

### NEW server dependencies (v3.3 — auth/MFA)
After this pull, install on the server before restarting:
```cmd
pip install pyotp qrcode
```
`pyotp` is **required** (login won't start without it). `qrcode` is optional — it renders the enrollment QR; without it the MFA page still shows the secret key for manual entry.

### First login (v3.3)
On first start with no users, an **admin / admin** account is auto-seeded (printed to the log). Log in → you're forced to **enroll TOTP** (scan QR / enter secret in Google Authenticator or Authy) → then change the password and add real users via **Users** (admin-only nav). Roles: **admin** = full control; **guest** = view + CSV export only. Lost-phone recovery: an admin can **Reset MFA** for any user from the Users page (they re-enroll next login). The seeded admin password is `admin` — change it / replace the account.

### config.py is GITIGNORED — new settings must be hand-added on the server
After a pull that introduces a new config setting, add it to the server's `config.py` by hand (the code imports it; missing → dashboard won't start with `ImportError`). Settings currently required beyond the original file:
```python
PERSISTENT_MAX_FAILURES = 5
PERSISTENT_TIME_WINDOW  = 86400          # 24h, any pacing
SMS_ALERT_TYPES = ["brute_force","password_spray","slow_attack","persistent_attack","geo_block","whitelist_block","yara_critical"]
YARA_QUARANTINE_DIR = r"C:\RDPShield_Quarantine"
VIRUSTOTAL_API_KEY  = "<your VT key>"    # gitignored; never pushed
VIRUSTOTAL_URL      = "https://www.virustotal.com/api/v3"
```
Live secrets in config.py: AbuseIPDB key, Notify.lk creds + phone, VirusTotal key. **All exposed in chat — rotate when convenient.**

### Scheduled tasks (run as SYSTEM, survive RDP disconnect + reboot)
| Task | Runs | Schedule |
|---|---|---|
| `RDPShield-Agent` | `run_agent.bat` → `rdpshield.py` | onstart |
| `RDPShield-Dashboard` | `run_dashboard.bat` → `dashboard.py` | onstart |
| `RDPShield-DailyReport` | `run_report.bat` → `daily_report.py` | daily 23:55 |

The three `run_*.bat` files are **gitignored** (server-specific) — recreate on a fresh server. Each is:
```
cd /d C:\Projects\RDPShield
set PYTHONUTF8=1
C:\Users\Administrator\AppData\Local\Programs\Python\Python311-32\python.exe <script>.py >> <log>.log 2>&1
```
Python on server: **3.11 32-bit**. UTF-8 mode (`set PYTHONUTF8=1`) is required or non-ASCII attacker data crashes under SYSTEM.

### Feature set as of 2026-06-21
- **Detection:** brute force (5/60s), slow-and-low (10/600s, shadowed by persistent), password spray (4 users/300s), **persistent/low-and-slow (5 failures/24h any pacing)**.
- **Geo access control (Advanced Security page, 2 sections):** Geolocation Settings (allow-anywhere / country-list → `geo_block`) and Whitelist Settings (IP-whitelist-only → `whitelist_block`). Each has its own mode control, lockout guard, allow-list, stats, Allowed-vs-Blocked chart, and category-tagged event log with **Unblock** buttons.
- **Response (strict order Block → YARA disk scan → SMS):** firewall block; post-block YARA disk scan; one rich SMS sent from the scan-completion handler containing IP, location (city/country), reason, failed-attempt count, "Valid login from blocked zone: YES" flag, YARA result, timestamp. Manual blocks run YARA + log an alert but send **no SMS** (auto-blocks only).
- **Enrichment:** ip-api geo (+ISP), AbuseIPDB score, **VirusTotal** (IP reputation on dashboard rows; file-hash lookup on YARA findings).
- **YARA Controller:** disk + memory scans; each disk finding has a **SHA-256** (click-to-copy); **Check VT** button. Findings carry a **status** (`active|quarantined|whitelisted|ignored|deleted`) shown as a badge with status-aware action buttons: **Whitelist / Quarantine / Delete / Ignore** (active) and **Restore / Un-whitelist** etc. Actions update status (rows are NOT deleted) and **propagate to sibling findings of the same file** (by location/hash) — so multiple rule matches on one file move together and acting on an already-removed file is graceful (marked, not errored). A **Managed Findings** panel gives categorised views (Quarantined / Whitelisted / Ignored / Deleted, with counts), each with relevant follow-up actions. Whitelisted hashes are skipped by future scans (`yara_whitelist` table). Quarantine moves files to `YARA_QUARANTINE_DIR`.
  - Routes: `/yara/finding/action` (delete|quarantine|whitelist|ignore|restore), `/yara/managed/<status>`, `/yara/managed_counts`, `/yara/vt/hash/<sha>`, `/yara/vt/ip/<ip>`. DB: `yara_findings.status` + `sha256` columns, `yara_whitelist` table, status setters that propagate by location/hash.
- **Dashboard:** live **in-place AJAX refresh** (no full-page reload — stat cards + 3 tables update via JSON, paused while a modal is open or a field is focused). Tables show attempts, country, ISP, abuse score, VT. Alert-breakdown chart labels: `geo_block`→"Geo Blocked", `whitelist_block`→"Non-Whitelisted IPs".
- **Preview tables + full-list pages:** every growing table/log shows only the **latest 5 rows inline** with a **"View all" button** that opens a clean, searchable, client-side-paginated full-list page in a **new tab** (`/list/<key>`). Covered: dashboard (alerts, blocked IPs, failed logins), Advanced Security (geo + whitelist event logs), YARA (scan history). Row-rendering markup is shared in `static/js/tables.js` (`TABLE_RENDERERS` + `initListPage`) so the 5-row preview and the full view render identically. List page = `templates/list.html`; registry = `LIST_VIEWS` in `dashboard.py`. Backed by `?limit=` on `/api/{alerts,blocked,events}`, plus new `/api/geo_events` (annotates each row with `is_blocked`) and `/api/yara_scans`. Block/unblock forms carry a `next` field so an action on a list page returns to that list.
- **Authentication + MFA + RBAC (v3.3):** username/password login (`/login`) → **TOTP two-factor** (`/mfa`, pyotp) with first-login QR enrollment (QR via `qrcode` **SvgPathImage** — needs a viewBox + plain `<path>` to render inline), then a session. Global `before_request` gate (`PUBLIC_ENDPOINTS` = login/mfa/logout/forgot/reset/static) means every page/API requires login; `auth.admin_required` guards all mutations. Roles: **admin** (full control) / **guest** (view + CSV export only). `auth.py` = decorators + password (werkzeug) + TOTP helpers; `users` table + CRUD in `database.py`. Templates: `login.html`, `mfa.html`, `users.html`, `403.html`.
- **User management (admin Users page, `/users`):** add user (username/password/**phone**/role), **Edit** (reset password and/or set phone via inline disclosure → `/users/update`), **Disable/Enable** (`disabled` column; disabled users can't log in), **Reset MFA**, **Delete**. **Root admin** model: the seeded/first admin has `is_root=1`; a **secondary admin cannot delete or disable the root admin** (UI hides the buttons + backend enforces), and you can't delete/disable yourself or the last admin. `current_user.is_root` is in the session + template context. New DB cols: `users.disabled`, `users.is_root`, `users.phone` (auto-migrated via `ALTER TABLE` in `create_users_table`).
- **Forgot password via SMS (Notify.lk):** `/forgot` (enter username) → 6-digit code texted to the user's stored phone (`alerts.send_sms_to`) → `/reset` (code + new password). Codes are in-memory (`_RESET_CODES`, 10-min TTL, 5-try cap, single-use), neutral responses to avoid username enumeration. "Forgot password?" link on the login page. Templates: `forgot.html`, `reset.html`. Requires a phone on the account; otherwise an admin resets via the Users page.
- **Operations top bar:** shared `templates/_topbar.html` (light theme) on all authed pages — brand, LIVE pill, UTC clock, **user chip** (avatar + name + role + live "active" session timer since login), Sign out. Admins also get a **Users** nav link. Sets `window.IS_ADMIN` so `tables.js` hides block/unblock buttons from guests. (Global search box removed — unused.)
- **UI polish (v3.5):** **Notification bell** in the top bar — dropdown of the 15 most recent alerts with an unread count badge (9+), unread tracked client-side in `localStorage`, polled every 30s from `/api/alerts`. **Custom SVG icon set** (`templates/_icons.html`, `{% from '_icons.html' import icon %}` → `{{ icon('name') }}`) replacing all emoji heading glyphs — line-art, `currentColor`, theme-aware (globe/alert/ban/log/lock/key/phone/bell/trash/audit/scan/findings/managed/etc.). **Compact action buttons** — "View all" / "Export CSV" are now small icon buttons (expand / download glyphs). All purely template/CSS; no backend change.
- **Animated/live charts (v3.5):** dashboard line + bar charts got a futuristic pass — neon glow on the trend line, gradient fills, ease-out draw-in, theme-aware gridlines, richer hover tooltips, a pulsing "live" dot at the latest trend point (throttled rAF, pauses when tab hidden), and live updates every 10s via new `/api/trend` + `/api/alert_breakdown` (`window.updateCharts`). Top Attacker Countries bars animate-grow with a glow. A geographic attack map is not yet added (needs viewer-browser internet for tiles, or a bundled geo dataset).
- **API key rotation reminders (v3.4):** every *N* days (default **2**, configurable in Settings → Rotation reminders, on/off) admins get an **SMS** (to alert recipients/root) and a **dashboard banner** nudging them to rotate API keys. Per-key age comes from the `settings` row `updated_at` (when a key was last set via the UI); the banner shows each key's age and flags any older than the interval as overdue (amber). Sent from a daemon thread (`_rotation_reminder_loop`, hourly check) throttled by the `last_rotation_reminder` setting so restarts don't re-spam. Helpers in `settings.py` (`rotation_interval_days`, `reminders_enabled`, `key_rotation_status`); route `/settings/rotation`. (Twilio / HashiCorp Vault were considered for key management — staying on the DB-backed Settings store for now; `settings.py` is the single seam if either is added later.)
- **Settings page + dark theme (v3.4):** new admin **Settings** page (`/settings`) — **API key rotation** (VirusTotal / AbuseIPDB / Notify.lk, stored in the DB and overriding `config.py` at runtime, masked display + last-rotated time; blank = keep, `-` = clear), **Alert Recipients** (add/edit/delete SMS numbers that receive breach/block alerts; normalised to `94…`; falls back to `config.ALERT_TO_NUMBER`), **SMS alert-type toggles**, **data retention** (set target days + "Purge now" for failed_logins/alerts/geo_events), and the **Admin Audit Log** (recent admin/security actions + `/list/audit` + CSV export, admin-only). Runtime config now flows through `settings.py` (DB→config fallback); `alerts.py` and `virustotal.py` read keys/recipients/SMS-types dynamically, and `_post_sms` fans out to all active recipients. New DB tables `settings`, `alert_recipients`, `audit_log` (auto-created). **Dark futuristic theme** with a per-user light/dark toggle (top-bar icon + Settings): all templates carry `<html data-theme>`, the theme is saved on `users.theme`, and the look is driven by a `[data-theme="dark"]` CSS-variable override (cyber navy/electric-blue + panel glows). Audit logging is wired into logins, logout, block/unblock, geo changes, user management, settings changes, and breach lockouts.
- **Session security + breach defence (v3.4):** **1-hour idle auto-logout** (server-side `last_active` in `before_request`; background `/api/*` + `/yara/status` polling enforces the timeout but does NOT count as activity, so an idle-but-open tab still expires). **Account lockout on suspicious login** — 5+ wrong passwords, OR a valid login while the account is already active (concurrent session, 10-min `CONCURRENT_WINDOW`) → the account is **disabled** and the **root admin is SMS'd immediately** (`alerts.send_sms_to`). Admin-account targets get a stronger "breach attempt" warning; the **root admin is never auto-locked** (warned only, to avoid permanent lockout). In-memory state (`_FAILED_LOGINS`, `_ACTIVE_USERS`). Root phone resolved from the root user's phone, falling back to `config.ALERT_TO_NUMBER`. Phone numbers are normalised to Notify.lk format (`94…`) on save and send. Flash messages are now colour-coded (green success / red error) via categories.
- **CSV export:** `/export/<key>.csv` (`EXPORT_VIEWS` registry) streams the full dataset for offline analysis — alerts, blocked IPs, failed logins, geo events, whitelist events, YARA scans. "Export CSV" buttons sit beside each "View all"; available to admins **and** guests (login required, not admin).
- No DB schema migration needed for the v3.2 table work; v3.3 adds the `users` table (auto-created on start). `get_blocked_ips(limit=…)` gained an optional cap.
- **Daily ML-ready report:** `daily_report.py` → `logs/rdpshield_report_<date>.json` (per-attacker aggregation; scheduled 23:55).
- **Tooling:** `verify_setup.py` (config/DB health check, masks secrets), `backfill_geo.py` (one-time geo backfill), `TESTING.md` (attack test plan).

### Helper scripts / files
`virustotal.py`, `daily_report.py`, `verify_setup.py`, `backfill_geo.py`, `countries.py`, `TESTING.md`.
Gitignored (server/local only): `config.py`, `rdpshield.db`, `*.log`, `logs/`, `run_*.bat`, `.claude/`.

### Known design notes
- **Detection, not prevention:** RDPShield reads the event log *after* a login, so an attacker with valid creds briefly connects before the firewall block kicks in (~20–30s). *Not yet built:* immediate RDP session-kill + proactive whitelist firewall (only-allow-3389-from-whitelist) — the "#1 prevention" enhancement, still pending.
- VT/AbuseIPDB scores are 0 for the user's own SL test IPs (not reported) — correct; real botnets score high.

---

## Project Structure

```
C:\Projects\RDPShield\          ← host dev folder
Z:\                             ← same folder, seen from VM via VirtualBox shared folder
C:\RDPShield\                   ← live deployment target on VM
```

```
rdpshield.py        Main monitoring agent (runs as Administrator, reads Security event log)
dashboard.py        Flask web app (dashboard + geo settings + YARA pages)
database.py         All SQLite CRUD — init_db(), logging, queries
alerts.py           IP enrichment: ip-api.com geolocation, AbuseIPDB reputation, Notify.lk SMS
firewall.py         block_ip() / unblock_ip() via Windows Firewall (netsh)
config.py           All thresholds, API keys, feature flags  ⚠ contains live secrets — never commit
countries.py        Static list ~200 COUNTRY_NAMES (ip-api.com format) for autocomplete datalist

yara_scanner.py     YARA disk + memory scan engine
yara_scheduler.py   Daemon thread: triggers scan_async() after each block event
yara_routes.py      Flask Blueprint — /yara/*, /yara/scan, /yara/status, /yara/findings/<id>
yara_fp_filter.py   False-positive suppressor (confidence threshold from config)
yara_rules/         YARA rule files: bruteforce_tools.yar, credential_files.yar, post_compromise.yar

static/style.css        Shared light SOC theme (CSS custom properties)
static/img/logo.svg     Custom shield + checkmark SVG logo
static/js/chart.umd.min.js  Chart.js 4.4.4 bundled locally (VM has no internet)
static/js/modal.js      Shared confirm-modal JS replacing all window.confirm() popups

templates/index.html    Main dashboard
templates/geo.html      Geolocation settings
templates/yara.html     YARA Controller
```

---

## Running the System

Both processes must run simultaneously on the VM (as Administrator):

```cmd
# Terminal 1 — detection agent
python -u rdpshield.py

# Terminal 2 — web dashboard
python dashboard.py

# Dashboard available at:
http://SERVER_IP:5000
```

### Deploy from host to VM

VirtualBox shared folder maps `C:\Projects\RDPShield` → `Z:\` on the VM.
Copy individual files with xcopy, then restart if Python files changed.

```cmd
# Python backend (requires dashboard restart)
xcopy "Z:\database.py"   "C:\RDPShield\" /Y
xcopy "Z:\dashboard.py"  "C:\RDPShield\" /Y
xcopy "Z:\rdpshield.py"  "C:\RDPShield\" /Y
xcopy "Z:\countries.py"  "C:\RDPShield\" /Y
xcopy "Z:\auth.py"       "C:\RDPShield\" /Y
xcopy "Z:\settings.py"   "C:\RDPShield\" /Y
xcopy "Z:\alerts.py"     "C:\RDPShield\" /Y
xcopy "Z:\virustotal.py" "C:\RDPShield\" /Y
xcopy "Z:\yara_routes.py" "C:\RDPShield\" /Y

# Frontend only (browser hard-refresh Ctrl+F5 is enough, no restart needed)
xcopy "Z:\static\style.css"       "C:\RDPShield\static\" /Y
xcopy "Z:\static\js\modal.js"     "C:\RDPShield\static\js\" /Y
xcopy "Z:\static\js\tables.js"    "C:\RDPShield\static\js\" /Y
xcopy "Z:\templates\index.html"   "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\geo.html"     "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\yara.html"    "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\list.html"    "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\_topbar.html" "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\login.html"   "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\mfa.html"     "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\users.html"   "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\403.html"     "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\forgot.html"  "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\reset.html"   "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\settings.html" "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\_topbar.html" "C:\RDPShield\templates\" /Y
xcopy "Z:\templates\_icons.html"  "C:\RDPShield\templates\" /Y
xcopy "Z:\static\js\tables.js"    "C:\RDPShield\static\js\" /Y
```
> All HTML templates changed (dark-theme `data-theme` attr) — copy the whole `templates\` folder. `settings.py` and `virustotal.py`/`alerts.py` are required for runtime key rotation.

---

## Database Schema (SQLite — rdpshield.db)

| Table | Purpose |
|---|---|
| `failed_logins` | Every Windows Event 4625 captured |
| `alerts` | Detection alerts (brute_force, slow_attack, password_spray, geo_block) |
| `blocked_ips` | Currently active firewall blocks |
| `geo_settings` | Single-row: current geo mode |
| `allowed_countries` | Country whitelist for `country_list` mode |
| `allowed_ips` | IP whitelist for `private_and_allowed` mode |
| `geo_cache` | Cached ip-api.com lookups (saves rate-limit quota) |
| `geo_events` | Log of every geo-checked connection (allowed + blocked) |
| `yara_scans` | Scan metadata (trigger, duration, findings count, max severity) |
| `yara_findings` | Individual YARA rule hits, linked to scan by scan_id |

---

## Detection Algorithms (config.py thresholds)

| Algorithm | Trigger | Window | Config keys |
|---|---|---|---|
| **Brute Force** | ≥ 5 failed logins from same IP | 60 s | `BRUTE_FORCE_MAX_FAILURES`, `BRUTE_FORCE_TIME_WINDOW` |
| **Slow & Low** | ≥ 10 failed logins from same IP | 600 s | `SLOW_ATTACK_MAX_FAILURES`, `SLOW_ATTACK_TIME_WINDOW` |
| **Password Spray** | ≥ 4 unique usernames from same IP | 300 s | `SPRAY_MAX_USERNAMES`, `SPRAY_TIME_WINDOW` |
| **Persistent / Low-and-Slow** | ≥ 12 cumulative failed logins from same IP | 3600 s (1 h) | `PERSISTENT_MAX_FAILURES`, `PERSISTENT_TIME_WINDOW` |
| **Geo Block** | IP not in whitelist / from blocked country | — | geo mode via dashboard |

> **Why the Persistent detector exists:** a real attacker (e.g. `106.0.54.50`) was observed pacing attempts ~90 s apart — too slow for Brute Force (5/60s), under the Slow & Low count (10/600s), and single-username (evades Spray). It slipped through all three rate-based detectors. The Persistent detector is a cumulative-total catch-all: any IP that racks up 12+ failures in an hour gets blocked + SMS regardless of pacing. Added to `SMS_ALERT_TYPES`.

All detections fire `handle_detection()` → AbuseIPDB enrichment → firewall block → YARA scan → SMS alert → DB log.

---

## Geo-Blocking Modes

Stored in `geo_settings.mode`. Changed via the Geolocation settings page.

### `allow_anywhere` (default)
No geo restrictions. Only attack detection is active.

### `private_and_allowed` — Whitelist Only
**Every IP must be explicitly in the `allowed_ips` table to pass** — public AND private.
No automatic bypass for private/internal IPs in this mode (changed from original behaviour).
Private IPs that are not whitelisted are blocked with country logged as "Private network".

> ⚠ Add your admin IP to the whitelist BEFORE applying this mode or you will lock yourself out.

### `country_list`
Only IPs from countries in `allowed_countries` can connect.
Private IPs still bypass geo in this mode (only country-based filtering makes sense for public IPs).

> ⚠ Add your country BEFORE applying or all RDP connections will be blocked.

Both risky modes have dashboard guards: Apply button disabled when whitelist is empty, plus a confirm modal before applying.

---

## Dashboard Pages

### `/` — Main Dashboard
- 4 stat cards: Failed Logins, Alerts Triggered, IPs Blocked, Unique Attackers
- Live refresh badge (auto-refreshes every 10 s via `<meta http-equiv="refresh">`)
- **Line chart** — Failed Login Trend (last 14 days), Chart.js bundled locally
- **Bar chart** — Alert Breakdown by type (last 30 days) with gradient fills + drop-shadow plugin
- Top Attacker Countries — horizontal bar list ranked by alert count
- Recent Alerts table with AbuseIPDB score colouring
- Blocked IPs table with Unblock button (custom modal confirm)
- Recent Failed Logins table

### `/geo` — Geolocation Settings
- Geo stats: total blocked, total allowed, top blocked country
- Mode selector with lockout-warning guard logic (JS: `MODE_GUARDS`, `updateApplyState()`)
- Country autocomplete via `<datalist>` populated from `countries.py:COUNTRY_NAMES`
- Allowed Countries table with Remove buttons (modal confirm)
- Allowed IPs table with Remove buttons (modal confirm)
- Geo Events log

### `/yara` — YARA Controller
- Run Disk Scan / Run Memory Scan buttons
- Live status card (polling `/yara/status` every 3 s)
- Scan History table (click row to load findings)
- Findings panel with severity badges (CRITICAL / HIGH / MEDIUM / LOW)

---

## UI / Frontend

### Theme — Light SOC Style
CSS custom properties in `:root` (style.css):
```
--bg: #f3f5f9        Page background
--surface: #ffffff   Cards
--border: #e3e8f0
--text: #1e2433
--muted: #6b7686
--brand: #2f5fe0
--brand-dark: #1e40af
--critical: #dc2626
--high: #ea580c
--purple: #7c3aed
--ok: #16a34a
```

### Logo
`static/img/logo.svg` — Custom shield + blue gradient + white checkmark stroke.
Used in all nav bars and as browser favicon (`<link rel="icon" type="image/svg+xml">`).

### Confirmation Modal (`static/js/modal.js`)
Replaces all native `window.confirm()` popups.

**Declarative use** — mark any form with:
```html
<form class="confirm-form"
      data-confirm-message="Are you sure?"
      data-confirm-title="Confirm action"
      data-confirm-ok="Yes, do it"
      data-confirm-danger="true">
```
modal.js auto-wires submit interception on DOMContentLoaded.

**Programmatic use:**
```js
showConfirm("Message text", () => { /* on OK */ }, {
    title: "Dialog title",
    okText: "Button label",
    danger: true,   // red OK button
});
```
Modal markup must be present in the page:
```html
<div class="modal-overlay" id="confirmModalOverlay">
  <div class="modal-box">
    <h3 id="confirmModalTitle"></h3>
    <p id="confirmModalMessage"></p>
    <div class="modal-actions">
      <button type="button" class="btn-modal-cancel" id="confirmModalCancel">Cancel</button>
      <button type="button" class="btn-modal-ok" id="confirmModalOk">Confirm</button>
    </div>
  </div>
</div>
```

---

## External Integrations

| Service | Purpose | Limit / Notes |
|---|---|---|
| **ip-api.com** | Geolocation (country, city, ISP) | 45 req/min, free, no key |
| **AbuseIPDB** | IP reputation score (0–100%) | 1000 req/day free tier, needs API key |
| **Notify.lk** | SMS alerts to mobile | Free demo credits; sender ID "NotifyDEMO" |

---

## Security Notes

- `config.py` contains the live AbuseIPDB API key, Notify.lk credentials, and phone number.
- **Never commit config.py to git or copy to shared/public drives.**
- The AbuseIPDB key visible in config.py should be treated as exposed — rotate it at https://www.abuseipdb.com/
- The WHITELIST_IPS list in config.py (`["127.0.0.1", "10.0.100.20"]`) is a hard bypass at the detection layer; it is separate from the geo-blocking IP whitelist in the database.

---

## Known Issues / Notes

- **IDE linter false-positives**: VSCode flags Jinja `{{ }}` expressions inside `<style>` attributes and `<script>` blocks as CSS/JS syntax errors. These are harmless — Flask/Jinja renders them server-side before the browser sees them.
- **countries.py is a new file** added in the dashboard redesign session. If deploying to a fresh VM path, it must be copied explicitly alongside the other Python files.
- **Chart.js is bundled** at `static/js/chart.umd.min.js` (v4.4.4) because the VM has no internet access. Do not remove this file.
- `config.py:YARA_MEMORY_SCAN_ON_BLOCK = False` — memory scans are intentionally off-by-default on block events (too slow); disk scan runs automatically instead.

---

## Completed Features (session log)

- [x] Full dashboard redesign — light SOC theme, CSS custom properties, consistent nav
- [x] SVG shield+checkmark logo, used in all pages and as favicon
- [x] Line chart: 14-day failed login trend (Chart.js, bundled locally)
- [x] Bar chart: 30-day alert type breakdown with gradient fills + drop-shadow plugin
- [x] Top Attacker Countries horizontal bar list
- [x] Country autocomplete `<datalist>` on Geo page (populated from countries.py)
- [x] `private_and_allowed` mode redesigned: private IPs no longer auto-pass; both public and private must be explicitly whitelisted
- [x] Lockout-warning guard on `private_and_allowed` mode: Apply disabled when IP list empty + confirm modal
- [x] Lockout-warning guard on `country_list` mode: Apply disabled when country list empty + confirm modal
- [x] Custom in-page modal replacing all `window.confirm()` popups (modal.js + CSS)
- [x] YARA Controller page migrated to shared light theme (removed embedded dark CSS)
- [x] Bug fix: `database.py init_db()` called `create_yara_tables()` before committing its own connection, causing `sqlite3.OperationalError: database is locked` on every fresh start. Fixed by committing and closing the main connection first, then calling `create_yara_tables()`
- [x] Cloud deployment to AWS EC2 Windows Server (public honeypot for real attack data collection)
- [x] Persistent / low-and-slow detector (`detect_persistent_attacker`): cumulative-failure catch-all that blocks + SMS attackers pacing under the rate thresholds. New config: `PERSISTENT_MAX_FAILURES` (12), `PERSISTENT_TIME_WINDOW` (3600 s); `persistent_attack` added to `SMS_ALERT_TYPES`
- [x] Manual block from dashboard: `/block` route + manual-block form in Blocked IPs section + per-row Block button on every Recent Failed Login
- [x] Attempts column (total failed logins per IP) in Blocked IPs and Recent Alerts tables (subquery on `failed_logins`)
- [x] Country column in Recent Failed Logins: agent now geo-caches public attacker IPs (`get_ip_geolocation` in `process_failed_login`); `get_recent_failed_logins` LEFT JOINs `geo_cache`
- [x] Badge + row styling and bar-chart label for the new `persistent_attack` alert type (teal `#0891b2`)

### Deploying these changes to the server
Code files (`rdpshield.py`, `database.py`, `dashboard.py`, `static/style.css`, `templates/index.html`) deploy normally. **No DB migration needed** (joins/subqueries, no new columns).
⚠ `config.py` is gitignored — the new `PERSISTENT_*` settings and updated `SMS_ALERT_TYPES` must be **added by hand** to the server's `config.py`, then restart both scheduled tasks.

---

## Cloud Deployment (AWS EC2)

### Instance details
- **Provider:** AWS EC2
- **AMI:** Windows Server (Windows 11 / Server 2022)
- **Public IP:** `16.170.232.91`
- **Dashboard URL:** `http://16.170.232.91:5000`
- **Python:** 3.11.x 32-bit (`C:\Users\Administrator\AppData\Local\Programs\Python\Python311-32\python.exe`)
- **Project path on server:** `C:\Projects\RDPShield\`

### AWS Security Group rules
| Port | Source | Purpose |
|---|---|---|
| 3389 | `0.0.0.0/0` | RDP — exposed publicly to attract real attack traffic |
| 5000 | Your IP only | Flask dashboard — restricted to admin |

### Windows Firewall rule added on server
```cmd
netsh advfirewall firewall add rule name="RDPShield Dashboard" dir=in action=allow protocol=TCP localport=5000
```

### Windows Defender exclusion added
```cmd
powershell -Command "Add-MpPreference -ExclusionPath 'C:\Projects\RDPShield'"
```

### Running as persistent background services (Task Scheduler)

Two batch files in `C:\Projects\RDPShield\`:

**run_agent.bat:**
```bat
cd /d C:\Projects\RDPShield
C:\Users\Administrator\AppData\Local\Programs\Python\Python311-32\python.exe rdpshield.py
```

**run_dashboard.bat:**
```bat
cd /d C:\Projects\RDPShield
C:\Users\Administrator\AppData\Local\Programs\Python\Python311-32\python.exe dashboard.py
```

Registered as SYSTEM scheduled tasks (survive RDP disconnect and server reboot):
```cmd
schtasks /create /tn "RDPShield-Agent" /tr "C:\Projects\RDPShield\run_agent.bat" /sc onstart /ru SYSTEM /f
schtasks /create /tn "RDPShield-Dashboard" /tr "C:\Projects\RDPShield\run_dashboard.bat" /sc onstart /ru SYSTEM /f
```

Start/stop/status commands:
```cmd
schtasks /run /tn "RDPShield-Agent"
schtasks /run /tn "RDPShield-Dashboard"
schtasks /end /tn "RDPShield-Agent"
schtasks /end /tn "RDPShield-Dashboard"
schtasks /query /tn "RDPShield-Agent"
```

### Packages installed on server
```cmd
pip install flask requests pywin32 yara-python psutil==6.1.1
```
> Note: psutil 7.x has no 32-bit wheel. Use `psutil==6.1.1` with 32-bit Python 3.11.

### Installation gotchas encountered
| Issue | Cause | Fix |
|---|---|---|
| `pip not recognized` | Python not installed yet | Install Python first, tick "Add to PATH" |
| `psutil` build fails | Python 3.13 has no pre-built wheel; 32-bit has no 7.x wheel | Use Python 3.11 + `psutil==6.1.1` |
| `database is locked` | `init_db()` held open connection while `create_yara_tables()` opened a second one | Fixed in `database.py` — commit+close before calling `create_yara_tables()` |
| Task Scheduler tasks run but nothing starts | SYSTEM account doesn't have Python in PATH | Use full python.exe path in bat files |
| Dashboard not reachable externally | Windows Firewall blocked port 5000 even though AWS SG was open | Added Windows Firewall inbound rule for port 5000 |

---

## Attack Testing (authorized — own infrastructure)

Testing RDPShield's detection by attacking the EC2 server from a self-owned BlackArch Linux VM. This validates the full detect → alert → block → enrich → YARA flow against a live public target.

### Lockout risk — critical
`firewall.py` blocks with `netsh ... action=block remoteip={ip}` and **no port** → blocks **ALL inbound traffic** from the attacker IP (RDP 3389 AND dashboard 5000), and the rule **persists across reboots**. So attacking from the same public IP used to administer the server = full self-lockout.

### Mitigation: attack from a different network
- BlackArch VM attacks via **mobile hotspot** (carrier public IP).
- Admin machine / RDP / dashboard stays on **home broadband** (different public IP).
- RDPShield blocks the carrier IP; home IP keeps full access.
- Recovery if locked out: disconnect hotspot → reconnect home wifi (different IP, never blocked) → RDP back in and unblock from dashboard. Backstop: reboot home router for a fresh residential IP.

### Detection thresholds to trip (from config.py)
| Attack | Trigger | Window |
|---|---|---|
| Brute Force | 5 failed logins | 60 s |
| Slow & Low | 10 failed logins | 600 s |
| Password Spray | 4 unique usernames | 300 s |

> Note: once any attack triggers a block, the attacker IP is blocked for ALL ports, so further attacks from the same IP can't reach the server. To demo multiple attack types, unblock between tests (or set `AUTO_BLOCK_ENABLED=False` temporarily to collect alerts without blocking).

### Attack commands (run on BlackArch VM)

Confirm attacker public IP (the one that should get blocked):
```bash
curl ifconfig.me
```

Confirm target RDP port reachable:
```bash
nc -zv 16.170.232.91 3389
```

Throwaway (all-fake) password list:
```bash
printf 'Winter2024\nPassword1\nadmin123\nLetmein2024\nQwerty123\nSummer2024\nWelcome1\nP@ssw0rd\nChangeme1\nAdmin@123\n' > /tmp/pw.txt
```

Brute-force attack (hydra ships with BlackArch):
```bash
hydra -t 4 -V -l administrator -P /tmp/pw.txt rdp://16.170.232.91
# --login is the long form of -l (lowercase L, not the number 1)
```

Password spray (many usernames, one password):
```bash
printf 'admin\nadministrator\nuser\nguest\ntest\nroot\n' > /tmp/users.txt
hydra -t 1 -L /tmp/users.txt -p 'Password123' rdp://16.170.232.91
```

### Testing gotchas
| Issue | Cause | Fix |
|---|---|---|
| `hydra: invalid option -- '1'` | Typed `-1` (number one) instead of `-l` (lowercase L); fonts make them look alike | Use `-l` or long form `--login` |
| If hydra complains about RDP parallelism | RDP sensitive to high `-t` | Drop to `-t 1` |
| Bots attacking on their own | Port 3389 public — internet scanners find it within minutes | Expected; real attack data accumulates without any manual attack |

---

## GitHub / Version Control

Repo initialised locally on `main` branch. Two commits:
- `Initial commit: RDPShield RDP brute-force detection system`
- `Add project README`

### Secret protection (critical)
`.gitignore` excludes secrets and runtime data — **verified before first commit** that `config.py` and the database are NOT staged:
```
config.py          ← live API keys / credentials — NEVER commit
*.db               ← rdpshield.db (runtime data)
*.log              ← agent/dashboard logs
__pycache__/
.claude/           ← local Claude Code settings
run_*.bat / panic_unblock.bat   ← server-specific deploy helpers
```

`config.example.py` is committed as a sanitised template (placeholder keys). New clones run `copy config.example.py config.py` and fill in their own values.

### Files added for the repo
- `.gitignore`
- `config.example.py` — sanitised config template
- `README.md` — overview, architecture diagram, setup/usage, security notes

### Pushing (manual — no gh CLI on dev machine)
1. Create an EMPTY repo at https://github.com/new (no README/.gitignore/license)
2. ```powershell
   git remote add origin https://github.com/YOUR-USERNAME/RDPShield.git
   git push -u origin main
   ```

### Outstanding security task
⚠ **Rotate the AbuseIPDB API key** — it was exposed in plaintext during development and lives on the EC2 server's `config.py`. Regenerate at abuseipdb.com → Account → API. Optionally rotate the Notify.lk key too. The repo is clean (config.py gitignored), but the live key on the server should still be replaced.
