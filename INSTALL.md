# RDPShield — Installation Guide

RDPShield is a Windows blue-team tool that detects and responds to RDP
brute-force attacks (Event ID 4625), enriches attacker IPs (geo + reputation),
blocks them at the Windows Firewall, runs YARA scans, sends SMS alerts, and
presents everything in a Flask SOC-style dashboard.

---

## ⚠️ Platform support (read first)

| Component | Runs on |
|---|---|
| **RDPShield agent + dashboard** (the product) | **Windows only** — it reads the Windows *Security* event log via `pywin32` and edits the firewall via `netsh`. It will **not** run on Linux/macOS. |
| **Attacker test box** (optional, to verify detection) | **Linux** (Kali / BlackArch / Debian) — used only to *attack* the Windows host for testing. See Section 9. |

So: install RDPShield on the **Windows machine you want to protect** (or an AWS
EC2 Windows honeypot). Use a separate Linux box only if you want to test it.

---

## What you'll install

1. **Python 3.11** (the build is tested on **3.11 32-bit**; avoid 3.13 — some
   native wheels aren't available for it).
2. **Git** (to clone the repo) — or just download the ZIP.
3. RDPShield's **Python dependencies** (Flask, pywin32, yara-python, psutil,
   requests, pyotp, qrcode).
4. A few **Windows settings** (firewall rule, Defender exclusion, scheduled
   tasks).

---

## 1. Prerequisites (Windows)

- Windows 10 / 11, or Windows Server 2019 / 2022
- An **Administrator** account (required: reads the Security log, edits firewall)
- **RDP enabled** on the host you're protecting (that's what you're defending)
- Outbound internet access (for ip-api, AbuseIPDB, VirusTotal, Notify.lk)
- For the **dashboard map tiles**, the browser you *view* the dashboard from needs internet (the map degrades gracefully without it)

### Install Python 3.11 (32-bit)
Download the **"Windows installer (32-bit)"** for the latest 3.11.x from
<https://www.python.org/downloads/windows/> and run it.

> During setup, tick **"Add python.exe to PATH"**.

Verify (open a new **Command Prompt**):
```cmd
python --version
```
You should see `Python 3.11.x`.

### Install Git (optional — skip if downloading the ZIP)
```cmd
winget install --id Git.Git -e
```
or download from <https://git-scm.com/download/win>.

---

## 2. Get the code

**Option A — Git (recommended, makes updates easy):**
```cmd
cd C:\Projects
git clone https://github.com/RaZa-97/RDPShield.git
cd RDPShield
```

**Option B — ZIP:** on the GitHub page click **Code ▸ Download ZIP**, extract it
to e.g. `C:\Projects\RDPShield`, and open a Command Prompt there.

> On **Linux** (only if you want to read/inspect the code — it won't run the agent):
> ```bash
> git clone https://github.com/RaZa-97/RDPShield.git && cd RDPShield
> ```

---

## 3. Install the Python dependencies

In the project folder (Command Prompt as Administrator is fine):
```cmd
python -m pip install --upgrade pip
python -m pip install flask requests pywin32 yara-python psutil==6.1.1 pyotp qrcode
```

Notes:
- `psutil==6.1.1` is pinned — newer 7.x has **no 32-bit wheel**.
- `pyotp` is **required** (two-factor login won't start without it). `qrcode`
  is optional but recommended (renders the MFA enrollment QR; without it you can
  still type the secret key manually).
- If you later get `ImportError: No module named win32evtlog`, finish the
  pywin32 setup:
  ```cmd
  python -m pywin32_postinstall -install
  ```

---

## 4. Configure (`config.py`)

Copy the template and edit it:
```cmd
copy config.example.py config.py
notepad config.py
```
(On Linux/macOS: `cp config.example.py config.py`.)

Fill in these values (everything else has sane defaults):

| Setting | What to put | Where to get it |
|---|---|---|
| `ABUSEIPDB_API_KEY` | Your AbuseIPDB key (IP reputation) | free key at <https://www.abuseipdb.com/> |
| `VIRUSTOTAL_API_KEY` | Your VirusTotal key (IP + file-hash rep) | free key at <https://www.virustotal.com/> (leave `""` to disable) |
| `NOTIFY_USER_ID` / `NOTIFY_API_KEY` | Notify.lk SMS credentials | register at <https://app.notify.lk/register> |
| `ALERT_TO_NUMBER` | Phone to receive alerts, format `94XXXXXXXXX` | your mobile |
| `WHITELIST_IPS` | **Add your own admin/management IP here** so you're never blocked | — |
| `DASHBOARD_USE_HTTPS` | *(optional)* set `= True` **only** if you serve the dashboard over HTTPS (reverse proxy/TLS). Marks the session cookie `Secure`. | leave unset/`False` for plain HTTP |

> 🔐 **Important:** add your admin IP to `WHITELIST_IPS` *before* exposing the
> host, or you could block yourself. `config.py` is gitignored — your keys are
> never committed.
>
> ⚠️ Do **not** set `DASHBOARD_USE_HTTPS = True` while still on plain HTTP — the
> browser will stop sending the session cookie and **you won't be able to log
> in**. Only enable it once TLS is actually in front of the dashboard.
>
> 💡 Most API keys can **also** be set/rotated later from the dashboard's
> **Settings** page (stored in the DB, overriding `config.py`).
>
> 🗝️ On first start the app also generates a random **`.flask_secret_key`** file
> (used to sign session cookies). It is **gitignored** — keep it, don't commit
> it, and don't copy it between servers. Deleting it just logs everyone out.

---

## 5. First run (quick test, foreground)

Open **two** Command Prompt windows **as Administrator** in the project folder:

```cmd
:: Terminal 1 — detection agent
python rdpshield.py
```
```cmd
:: Terminal 2 — web dashboard
python dashboard.py
```

Then open the dashboard:
```
http://localhost:5000
```

**First login:**
1. On the very first start, a root admin account **`admin`** is auto-created with a
   **random one-time password printed in the dashboard terminal** — look for:
   ```
   [AUTH] Seeded ROOT admin account 'admin'.
   [AUTH] TEMPORARY PASSWORD: <copy this>
   ```
   (There is **no** fixed `admin/admin` default — copy the printed password.)
2. Log in → you'll be asked to **set up two-factor**: scan the QR with Google
   Authenticator / Authy (or type the shown secret), enter the 6-digit code.
   (The seeded root admin is pre-verified, so it isn't gated by SMS.)
3. Go to **Users** and **change the admin password** (minimum **12 characters**),
   then add real users.

**Adding users (SMS verification):** every new user **requires a mobile number** —
on creation a **6-digit code is texted** to it and the user must enter it at
**`/verify`** before their first sign-in (login refuses an unverified account; an
admin can **Resend code**). Likewise, when an admin/root **changes a user's
password or resets their MFA**, that user is re-gated and must verify a fresh code.
This means **Notify.lk SMS must be working** for user onboarding — configure it in
**Settings** first. Role rules: only the **root** admin can create admin accounts
or change the root account; a non-root admin manages only itself and guests. Full
model in `SECURITY.md` §1 and §6.

Press `Ctrl+C` in both terminals to stop the test once it works.

---

## 6. Windows Firewall + Defender

**Allow the dashboard port** (restrict the source to your admin IP if the host is public):
```cmd
netsh advfirewall firewall add rule name="RDPShield Dashboard" dir=in action=allow protocol=TCP localport=5000
```

**Exclude the folder from Defender** (it's a security tool that runs YARA and
moves quarantined files — avoids false self-flagging):
```cmd
powershell -Command "Add-MpPreference -ExclusionPath 'C:\Projects\RDPShield'"
```

---

## 7. Run it 24/7 (survives reboot & logoff)

RDPShield runs as two **scheduled tasks** under `SYSTEM`, started **at boot** —
so a server restart does **not** stop it.

### 7a. Create the launcher batch files
In the project folder, create **`run_agent.bat`**:
```bat
cd /d C:\Projects\RDPShield
set PYTHONUTF8=1
python rdpshield.py >> agent.log 2>&1
```
…and **`run_dashboard.bat`**:
```bat
cd /d C:\Projects\RDPShield
set PYTHONUTF8=1
python dashboard.py >> dashboard.log 2>&1
```
> `set PYTHONUTF8=1` is required, or non-ASCII attacker data can crash the
> process under SYSTEM. If `python` isn't on SYSTEM's PATH, replace it with the
> full path, e.g. `C:\Users\<you>\AppData\Local\Programs\Python\Python311-32\python.exe`.

### 7b. Register the tasks (Command Prompt as Administrator)
```cmd
schtasks /create /tn "RDPShield-Agent"     /tr "C:\Projects\RDPShield\run_agent.bat"     /sc onstart /ru SYSTEM /f
schtasks /create /tn "RDPShield-Dashboard" /tr "C:\Projects\RDPShield\run_dashboard.bat" /sc onstart /ru SYSTEM /f
```

### 7c. Start them now (without rebooting)
```cmd
schtasks /run /tn "RDPShield-Agent"
schtasks /run /tn "RDPShield-Dashboard"
```

Useful task commands:
```cmd
schtasks /query /tn "RDPShield-Dashboard"     :: status
schtasks /end   /tn "RDPShield-Dashboard"     :: stop
schtasks /run   /tn "RDPShield-Dashboard"     :: start
```

> The dashboard also generates the **daily JSON report** on its own (background
> loop), so a separate report task isn't required.

---

## 8. (Optional) Public honeypot on AWS EC2

To collect **real** attack data, deploy on an EC2 **Windows** instance and set
the Security Group:

| Port | Source | Purpose |
|---|---|---|
| 3389 | `0.0.0.0/0` | RDP — exposed to attract real attacks |
| 5000 | **your IP only** | dashboard — keep it private |

Then follow Sections 1–7 on the instance. (Add a Windows Firewall inbound rule
for 5000 as in Section 6 — the AWS SG alone isn't enough.)

---

## 9. Verify detection — attacker test box (Linux)

> ⚠️ **Authorization:** only attack **your own** machine. Generate attacks from a
> **different network/IP** than the one you use to administer the host — RDPShield
> blocks *all* inbound traffic from an attacking IP (RDP **and** dashboard), so
> attacking from your admin IP will lock you out. A phone hotspot works well.

On a Linux box (Kali / BlackArch / Debian / Ubuntu):

**Install the tools:**
```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install -y hydra ncat

# Arch / BlackArch
sudo pacman -S hydra nmap
```

**Check the target's RDP port is reachable:**
```bash
nc -zv <WINDOWS_HOST_IP> 3389
```

**Brute-force test** (all-fake passwords — triggers the brute-force detector):
```bash
printf 'Winter2024\nPassword1\nadmin123\nLetmein2024\nQwerty123\nSummer2024\n' > /tmp/pw.txt
hydra -t 4 -V -l administrator -P /tmp/pw.txt rdp://<WINDOWS_HOST_IP>
```

**Password-spray test** (many usernames, one password — triggers the spray detector):
```bash
printf 'admin\nadministrator\nuser\nguest\ntest\nroot\n' > /tmp/users.txt
hydra -t 1 -L /tmp/users.txt -p 'Password123' rdp://<WINDOWS_HOST_IP>
```

Within a few seconds you should see, on the dashboard: a new **alert**, the IP
**blocked**, and (if SMS is configured) a **text**. Once an IP is blocked it
can't reach the host again, so **unblock it** from the dashboard between tests.

---

## 10. Updating to a new version
```cmd
cd C:\Projects\RDPShield
git pull
:: install any new dependency it mentions, then restart:
schtasks /end /tn "RDPShield-Agent" & schtasks /end /tn "RDPShield-Dashboard"
taskkill /F /IM python.exe
schtasks /run /tn "RDPShield-Agent" & schtasks /run /tn "RDPShield-Dashboard"
```
Then **hard-refresh the dashboard in the browser (`Ctrl+F5`)** — this is required
after an update: the dashboard enforces a CSRF token, and a stale cached page can
otherwise get **HTTP 400** on every button (block/unblock/settings/…). Database
schema migrations run automatically on start.

> ℹ️ After the first start on a brand-new server (or if `.flask_secret_key` is
> missing), existing browser sessions are invalidated and **everyone has to log
> in again** — this is expected. Use your existing credentials.

---

## 11. HTTPS / TLS — *future enhancement (not enabled for the dissertation)*

> **Current status:** RDPShield runs over plain **HTTP**, with the dashboard port
> restricted to the operator's IP in the AWS Security Group. For this controlled,
> single-operator **dissertation** deployment that is the accepted setup, so TLS
> is intentionally **left for a future enhancement**. The app already ships the
> TLS plumbing (the optional `config.py` flags + a service worker) so it can be
> switched on later without code changes — the recipe below is kept for that.

Trade-off to be aware of while on HTTP: the admin password, TOTP code, and
session cookie travel **unencrypted**, so keep port 5000 locked to your own IP.
Enabling TLS later also unlocks the **installable app on Android** + offline
support (the iOS home-screen install in §12 already works without it).

<details>
<summary><strong>Recipe for when you add TLS later (click to expand)</strong></summary>

### Option A — Reverse proxy with a free trusted certificate (recommended)

Uses **Caddy** (automatic HTTPS via Let's Encrypt). Let's Encrypt won't issue a
cert for a bare IP, so get a **free hostname** first.

1. **Free hostname:** sign up at <https://www.duckdns.org>, create e.g.
   `myrdpshield.duckdns.org`, and point it at your server's public IP
   (`16.170.232.91`).
2. **Open the ports:** in the AWS Security Group (and Windows Firewall) allow
   **TCP 443** (and **80**, needed once for the certificate challenge) — restrict
   the source to **your admin IP** just like 5000.
3. **Keep Flask private:** in `config.py` set `DASHBOARD_HOST = "127.0.0.1"` so
   Flask only listens locally; Caddy is the only thing exposed.
4. **Install Caddy:** `winget install CaddyServer.Caddy` (or download from
   <https://caddyserver.com/download>).
5. **Caddyfile** (create `C:\Caddy\Caddyfile`):
   ```
   myrdpshield.duckdns.org {
       reverse_proxy 127.0.0.1:5000
   }
   ```
6. **Run Caddy:** `caddy run --config C:\Caddy\Caddyfile` (it fetches and renews
   the certificate automatically). To run it permanently, register it as a
   service the same way as the RDPShield tasks.
7. **Tell RDPShield it's behind TLS** — in `config.py`:
   ```python
   DASHBOARD_USE_HTTPS   = True   # mark the session cookie Secure
   DASHBOARD_BEHIND_PROXY = True  # trust Caddy's forwarded headers + real client IP
   ```
   Restart the dashboard task.
8. Visit **`https://myrdpshield.duckdns.org`** — green padlock, no warnings.

### Option B — Direct self-signed cert (quick, encryption only)

No proxy/hostname, but browsers will warn (untrusted) and the Android
install/offline features won't work. Fine for a private lab.

1. Generate a cert (with OpenSSL, or PowerShell's `New-SelfSignedCertificate`):
   ```cmd
   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=16.170.232.91"
   ```
2. In `config.py`:
   ```python
   DASHBOARD_SSL_CERT = r"C:\Projects\RDPShield\cert.pem"
   DASHBOARD_SSL_KEY  = r"C:\Projects\RDPShield\key.pem"
   DASHBOARD_USE_HTTPS = True
   ```
3. Restart and visit **`https://16.170.232.91:5000`** (accept the one-time
   browser warning).

> ⚠️ Never set `DASHBOARD_USE_HTTPS = True` while still serving plain HTTP — the
> browser then refuses to send the (Secure) session cookie and you can't log in.
> Turn it on only once HTTPS is actually working.

</details>

---

## 12. Install it on your phone (Add to Home Screen)

RDPShield is a **PWA** — it can live on your home screen and open full-screen
like a native app.

### iPhone / iPad (works even over HTTP)
1. Open the dashboard in **Safari** (must be Safari, not Chrome) — e.g.
   `https://myrdpshield.duckdns.org` or `http://16.170.232.91:5000`.
2. Tap the **Share** button (the square with an up-arrow).
3. Scroll down and tap **Add to Home Screen**.
4. Confirm the name ("RDPShield") and tap **Add**.
5. Launch it from the home screen — it opens full-screen with the shield icon.
   Sign in as usual (password + TOTP).

> The device must be allowed to reach the dashboard first — i.e. its current
> public IP is in the AWS Security Group for port 5000 (HTTP) or 443 (HTTPS).
> Phone IPs change often (mobile data / Wi-Fi), so you may need to update that
> rule when switching networks.

### Android (requires HTTPS — Option A above)
1. Open the site in **Chrome**.
2. Chrome shows an **Install app** prompt, or use **⋮ menu → Install app /
   Add to Home screen**.
3. The app installs with offline shell support (service worker).

---

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `'python' is not recognized` | Python not on PATH | Reinstall Python with "Add to PATH", or use the full `python.exe` path |
| `No module named win32evtlog` | pywin32 post-install not run | `python -m pywin32_postinstall -install` |
| `psutil` build/install fails | wrong Python/bitness | Use **Python 3.11 (32-bit)** + `psutil==6.1.1` |
| Dashboard won't start, `ImportError` | missing dep or `config.py` value | Re-run the `pip install` line; ensure `config.py` exists (copied from the template) |
| `database is locked` on first run | rare init race | Just start it again |
| Dashboard not reachable from another PC | firewall | Add the port-5000 rule (Section 6); if cloud, open 5000 in the security group too |
| MFA page shows no QR | `qrcode` not installed | `pip install qrcode` (you can still type the secret key) |
| No SMS arriving | Notify.lk creds / plan | Check the dashboard log for `[SMS] …`; Notify.lk demo plans often only deliver to the account owner's verified number |
| Map is empty | older attacker IPs have no coordinates | run `python backfill_geo.py` once |
| Tasks run but nothing starts | SYSTEM lacks Python on PATH | Use the full `python.exe` path in the `.bat` files |
| Every button gives **HTTP 400 / "CSRF token … invalid"** | stale page cached after an update | Hard-refresh with **`Ctrl+F5`** (and log in again if prompted) |
| Can't log in: **"too many failed attempts"** | temporary lockout (5 wrong passwords or a concurrent login) | Wait 15 min, **or** use **"Account locked? Unlock via SMS"** on the login page (needs a phone on the account). See `SECURITY.md` |
| Locked out with **no phone** on the account | can't self-unlock by SMS | Wait 15 min for the auto-unlock, or have another admin reset things from **Users**. The **root** admin is never auto-locked |
| Forgot the seeded admin password | it was printed once at first start | If no other admin exists, stop the app, delete `rdpshield.db` **(loses data)** to re-seed, or restore from backup |

---

## 14. Security notes

- **Defensive / authorized use only.** Run it on systems you own or administer.
- `config.py` holds live API keys/credentials — it is **gitignored**; never
  commit or share it. Rotate keys you've exposed.
- `.flask_secret_key` (auto-generated) signs session cookies — **gitignored**;
  keep it private and per-server.
- Add your **admin IP to `WHITELIST_IPS`** before going live to avoid self-lockout.
- The dashboard runs over **plain HTTP** with a development server — for this
  dissertation deployment that's accepted, mitigated by keeping port 5000
  restricted to your admin IP. **TLS is a documented future enhancement** (§11),
  not a current step.
- Logins require **password + TOTP two-factor**; accounts auto-lock temporarily
  after repeated failures and can be unlocked by SMS. **Full details of the
  account-security model are in [`SECURITY.md`](SECURITY.md).**
- The executables/scripts are unsigned; Windows SmartScreen/AV may warn — this
  is expected for a self-built security tool.

---

For the **account-security & lockout model** (login, MFA, lockouts, SMS unlock,
roles, CSRF, recovery), see **[`SECURITY.md`](SECURITY.md)**. For architecture,
feature details, and the deployment cheat-sheet, see **`PROGRESS.md`**. For the
attack-test plan, see **`TESTING.md`**.
