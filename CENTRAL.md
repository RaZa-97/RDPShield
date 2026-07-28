# RDPShield Central — Multi-Tenant Command Center

One console for every customer's every protected server. Central aggregates the
status of many independent RDPShield deployments, lets an operator drill from
the whole fleet down to one customer down to one server, and hands them into
that server's own full dashboard without a second login.

> **TL;DR** — Central is a **separate Flask process** (default port 6100) that
> is **never installed on a customer box**. Agents **phone home** to it; it never
> connects out. Only **aggregated counters** leave an instance — raw attacker
> records stay local. Logging in is **password + TOTP** with tenancy scoping, and
> "Open Dashboard" issues a **60-second, single-use, agent-bound** signed token.
> **TLS is mandatory** — Central refuses to start without it.

---

## 1. Why it exists

Before this, every deployment was an island: one dashboard per customer server,
one login per island. Watching ten customers meant ten tabs and ten passwords.

Central adds the missing layer without disturbing the layer below it. Every
existing feature — the five detectors, the campaign correlator, YARA, geo
blocking, ML threat scoring, the account hardening — is untouched and still runs
entirely on the instance. Central only *watches*.

An instance with no `CENTRAL_*` settings in its `config.py` behaves exactly as
it did before Central existed. The feature is opt-in end to end.

---

## 2. Architecture

```
   ┌──────────────────────────────────────────────┐
   │  RDPShield Central          (your host)      │
   │  central_app.py  :6100  HTTPS                │
   │  central.db  — customers, agents, operators, │
   │                audit.  NO attacker records.  │
   └───────▲────────────────────────┬─────────────┘
           │                        │
   check-in│ HTTPS POST             │ 302 with a 60s
   (push)  │ Bearer <agent key>     │ single-use token
           │                        ▼
   ┌───────┴──────────────┐   ┌─────────────────────┐
   │ Customer A server    │   │ operator's browser  │
   │ dashboard.py :5000   │◄──┤ lands signed in     │
   │ central_reporter.py  │   └─────────────────────┘
   │ rdpshield.db (local) │
   └──────────────────────┘
```

### Push, not pull
Agents call Central. Central never opens a connection to a customer network.

That is the safer default for a server whose whole purpose is to sit exposed on
the internet: there is no extra inbound port, no management channel to attack,
and no credential on Central that grants shell-level access to a customer box.
It also just works behind NAT, which a pull model would not.

The trade-off is that Central's view is only as fresh as the last check-in. An
agent that stops reporting shows **Offline** after five minutes; Central cannot
distinguish "the box is off" from "the network is broken" and does not pretend
to.

### Aggregated data only
`central_report_schema.py` defines the payload **once** and both sides import
it, so they cannot drift. Every field is a counter, a version string, or an
enum:

| Field | Meaning |
|---|---|
| `failed_logins_24h` / `_total` | counts only |
| `alerts_24h` / `_total` | counts only |
| `blocked_ips_active` | how many firewall blocks are live |
| `unique_attackers` | distinct source IPs seen, as a number |
| `yara_findings_active` | count of unresolved findings |
| `campaigns_active` | count of open 7-day campaigns |
| `max_threat_score` | highest ML score 0–100, or `null` if no model |
| `risk_level` | `unknown\|low\|medium\|high\|critical`, computed **by the instance** |
| `top_alert_type` | most frequent alert type name in 24h |
| `detectors_ok` | boolean health signal |
| `agent_version`, `uptime_seconds`, `reported_at`, `schema_version` | metadata |

There is deliberately **no field** that can carry an attacker IP, a username, a
hostname, a country, a file path or a YARA match. This is enforced, not merely
intended: `validate()` **rejects unknown keys**, so an instance cannot start
sending extra data — by accident or by tampering — and have Central quietly
store it. Adding a field is a deliberate edit to that file on both sides.

Consequence: one customer's data cannot surface in another customer's view,
because there is nothing granular in `central.db` to leak.

### Risk is reported, not recomputed
Central never re-runs detection logic. `risk_level` is the instance's own
verdict (`central_report_schema.risk_from_counts`). Detection stays in exactly
one place, and Central stays a viewer.

---

## 3. Components

| File | Runs on | Purpose |
|---|---|---|
| `central/central_app.py` | Central | The Flask app: auth, overview, drill-down, management, ingestion API, SSO issuance |
| `central/central_db.py` | Central | `central.db` — customers, agents, users, audit_log, settings |
| `central/central_auth.py` | Central | Password/TOTP/CSRF patterns reused from `auth.py`, plus tenancy |
| `central/central_sso.py` | Central | Mints RS256 click-through tokens |
| `central/central_keygen.py` | Central | One-time keypair generation |
| `central/central_config.py` | Central | Gitignored; copy from `central_config.example.py` |
| `central_report_schema.py` | **both** | The payload contract |
| `central_sso_verify.py` | **instance** | Pure-stdlib token verification |
| `central_reporter.py` | **instance** | Background check-in thread |
| `static/central.css` | Central | Additive styling; inherits the shared light/dark theme |

`central/` lives in the same repository for convenience, but nothing in it is
ever executed on a customer box. A customer server that pulls the repo simply
carries some inert files.

### Dependencies
* **Central** needs `cryptography` in addition to the project's usual
  `flask requests pyotp`. `qrcode` is optional.
* **A customer instance needs nothing new.** Token verification is pure standard
  library.

> **⚠ Installing `cryptography` on 32-bit Python 3.11**
>
> ```cmd
> pip install "cryptography==48.0.1"
> ```
>
> Pin the version. `cryptography` **49.0.0 and later ship no 32-bit Windows
> wheel**, so a plain `pip install cryptography` falls back to building from
> source and fails without a Rust toolchain and MSVC build tools. **48.0.1** is
> the last release with a `cp311-abi3-win32` wheel. On 64-bit Python, plain
> `pip install cryptography` is fine.
>
> This is the same class of problem as `psutil` 7.x on this platform, and it is
> the reason the instance side of SSO is pure stdlib — a customer box never has
> to clear this hurdle at all.

That asymmetry is deliberate. The customer servers run **32-bit Python 3.11**,
where native wheels have repeatedly been a problem (`psutil` 7.x and
`scikit-learn` both needed workarounds). Central runs on a host we choose, so
the heavy audited library lives there. It is the same split the ML layer already
uses: train offline with `scikit-learn`, score on the server in pure stdlib.

---

## 4. Setting up Central

```cmd
cd central
copy central_config.example.py central_config.py
:: 64-bit Python:  pip install cryptography
:: 32-bit Python:  pin it — see the warning above
pip install "cryptography==48.0.1"
python central_keygen.py
python central_app.py
```

`central_keygen.py` writes:

* `central_sso_private.pem` — **secret**, gitignored, never leaves Central
* `central_sso_public.jwk.json` — public; goes into each instance's `config.py`

It prints the one-line `CENTRAL_SSO_PUBLIC_KEY = '…'` to paste. Re-running it
requires `--force` because regenerating invalidates the public key on **every**
enrolled instance at once.

On first start, browse to `/setup` **from the Central host itself or its local
network** and create the superadmin. Like the instance wizard, `/setup` exists
only while there are zero accounts and refuses public clients.

### Running Central 24/7 (Windows Task Scheduler)

Same pattern as the instance's `RDPShield-Agent` / `RDPShield-Dashboard` tasks,
so Central survives an RDP disconnect and a reboot.

Create `run_central.bat` in the project root (gitignored — it holds an absolute
interpreter path for one specific host):

```bat
cd /d C:\Projects\RDPShield\central
set PYTHONUTF8=1
C:\Users\Administrator\AppData\Local\Programs\Python\Python311-32\python.exe central_app.py >> ..\central.log 2>&1
```

`PYTHONUTF8=1` is required — without it, non-ASCII data crashes the process
under the SYSTEM account. Register it:

```cmd
schtasks /create /tn "RDPShield-Central" /tr "C:\Projects\RDPShield\run_central.bat" /sc onstart /ru SYSTEM /f
schtasks /run /tn "RDPShield-Central"
```

> **⚠ `taskkill /F /IM python.exe` now kills all three services.** The existing
> restart recipe was written when there were two. Either restart all three
> together, or stop only the one you mean:
>
> ```cmd
> :: restart everything cleanly
> schtasks /end /tn "RDPShield-Agent" & schtasks /end /tn "RDPShield-Dashboard" & schtasks /end /tn "RDPShield-Central"
> taskkill /F /IM python.exe
> schtasks /run /tn "RDPShield-Agent" & schtasks /run /tn "RDPShield-Dashboard" & schtasks /run /tn "RDPShield-Central"
> ```

Also note: if the task is running, starting `central_app.py` by hand in a
console fails with a port-in-use error. Stop the task first when you want a
foreground window to read startup output.

### TLS is not optional here
The per-instance dashboard is allowed to run on plain HTTP behind an IP
allow-list — an accepted trade-off for a single-operator academic deployment.
**Central is different**, because it carries cross-tenant data and mints tokens
that grant dashboard sessions. Both the agents' bearer keys and the SSO tokens
travel over this connection.

So `central_app.py` **refuses to start** unless one of these is true:

* `CENTRAL_SSL_CERT` + `CENTRAL_SSL_KEY` point at a cert and key, or
* `CENTRAL_BEHIND_PROXY = True` and a reverse proxy (Caddy/nginx) terminates TLS

`CENTRAL_ALLOW_INSECURE_HTTP = True` overrides this **for local development
only**. It prints a warning on every start and disables the Secure cookie flag.
Never set it on a networked host.

---

## 5. Enrolling an agent

1. **Central → Customers → Add** a customer.
2. **Central → Agents → Enrol a server.** Pick the customer, give the server a
   name, and set its **Dashboard URL** (e.g. `https://1.2.3.4:5000`) — that URL
   is where "Open Dashboard" sends the operator.
3. Central shows the generated `agent_uid` and API key **once**. Copy the block
   it displays into that server's `config.py`:

```python
CENTRAL_ENABLED  = True
CENTRAL_URL      = "https://central.example.com:6100"
CENTRAL_AGENT_ID = "ag_…"
CENTRAL_API_KEY  = "rdps_…"
CENTRAL_SSO_PUBLIC_KEY = '{"kty":"RSA",…}'
CENTRAL_MANAGED  = False      # see §7
```

4. Restart that instance's dashboard. It checks in within a minute and the row
   turns **Online**.

The key is stored **only as a werkzeug hash**. Central can verify it but can
never reproduce it — refreshing the Agents page does not re-reveal it. If it is
lost, use **Rotate key**, which issues a new one and immediately invalidates the
old.

`config.py` is gitignored, exactly like the VirusTotal / AbuseIPDB / Notify.lk
keys already stored there.

---

## 6. The console

**Overview** — summary tiles (Customers, Total Agents, Online, Offline,
High-Risk Alerts, Pending Enrolment) above a searchable, filterable table of
every server: name, customer, status, risk, 24-hour alert and failed-login
counts, live blocks, ML threat score, last check-in, and a row-level **Open
Dashboard**. Clicking a tile filters the table.

**Customer drill-down** (`/customer/<id>`) — the same layout scoped to one
customer, plus per-agent top alert type and agent version.

Tiles only count risk for agents that are **actually reporting**, so a stale
`critical` from a box that has been off for a week is not displayed as a live
incident.

### Roles

| Role | Sees | Can do |
|---|---|---|
| **superadmin** | every customer | everything: customers, enrolment, key rotation, operators, audit |
| **customer_admin** | exactly one customer | view their own fleet, open their own dashboards |

A `customer_admin`'s scope comes from **their account, via their session** —
`central_auth.scope()` is the only source, and it never reads a `customer_id`
from a URL, form field, query string or JSON body. Every database read that can
return agents takes that scope as an argument and filters in SQL.

Practically: incrementing the number in `/customer/12` gets a **403**, and
requesting another tenant's agent by uid gets a **404** — the same answer as a
nonexistent agent, so the URL cannot be used to confirm that another customer's
server exists.

---

## 7. Single sign-on

Clicking **Open Dashboard** makes Central mint an RS256 JWT and redirect the
browser to `<dashboard_url>/sso?token=…`.

| Claim | Value |
|---|---|
| `iss` | `rdpshield-central` |
| `aud` | that agent's `agent_uid` — **binds the token to one box** |
| `sub` | the Central operator's username |
| `role` | the mapped local role (`admin`) |
| `jti` | random id, so the instance can enforce single use |
| `iat`/`nbf`/`exp` | a ~60-second window |

The instance verifies, in order: exactly `RS256` (never `none`, never an HMAC
algorithm), the signature, `iss`, `aud` against **its own** `CENTRAL_AGENT_ID`,
expiry, a lifetime ceiling, then burns the `jti`. A rejected token logs its
reason locally and tells the browser nothing useful.

The operator is mapped to a **`central:<name>` shadow local account**, created
on first arrival with a random discarded password hash. It exists only as the
identity a session attaches to — which is what lets the instance's existing
session gate, RBAC, audit log and templates work unchanged — and it can never be
used to log in locally.

**A local admin can disable that shadow account**, and doing so blocks SSO for
that operator. The box owner keeps the last word over Central.

### `CENTRAL_MANAGED` and the break-glass path

`CENTRAL_MANAGED = True` withdraws the instance's own `/login` form (it returns
403 with an explanation), so identity for that server lives only in Central.

> ### ⚠ Break-glass: Central is unreachable
>
> On the affected server, set in `config.py`:
>
> ```python
> CENTRAL_LOCAL_LOGIN_FALLBACK = True
> ```
>
> and restart the dashboard. The local login form returns immediately, even with
> `CENTRAL_MANAGED = True`. Turn it back off once Central is healthy.
>
> This is **config-file-only on purpose** — it cannot be flipped from the web
> UI, so an attacker holding a dashboard session cannot re-open local password
> login. It requires filesystem access to the server, which is a meaningfully
> higher bar.
>
> If no local password is known either, `python reset_admin.py` on the server
> console resets the root admin and clears its MFA.

---

## 8. Threat model — the new trust boundary

Central introduces one boundary that did not exist before: **instance ↔ Central**.

### An instance is compromised
The attacker gets that agent's `agent_uid` and API key.

* They **can** push false statistics for **that one agent**.
* They **cannot** push as any other agent. The bearer key is validated against
  the specific `agent_uid` in the URL path, so a valid key for agent A is
  rejected on agent B's endpoint.
* They **cannot** read anything. The API is write-only; there is no endpoint
  that returns another agent's data.
* They **cannot** forge an SSO session anywhere. The instance holds only the
  **public** verification key. Even for itself, it cannot mint a token — though
  that is moot, since owning the box already means owning its dashboard.
* They **can** read Central's public key and URL from `config.py`. Neither is a
  secret.

Response: **Rotate key** in Central, then remove the agent.

### Central is compromised
This is the serious one, and it is the price of the feature. An attacker with
Central's private key can mint SSO tokens into **every** enrolled dashboard.

Mitigations: TLS is mandatory; the private key never leaves the host and is
written owner-readable; Central runs on a host you control rather than an
exposed honeypot; every SSO issuance is audited with its `jti`; and a local
admin can disable the `central:*` shadow account on any instance to shut Central
out of that box.

Recovery: `python central_keygen.py --force`, then update
`CENTRAL_SSO_PUBLIC_KEY` on every instance — which is precisely why the script
refuses to overwrite without `--force`.

### Central's database is stolen
`central.db` holds **no attacker records and no plaintext credentials**. API
keys are werkzeug hashes; operator passwords are werkzeug hashes. It cannot be
replayed as an agent. It does reveal the customer list, server names and
dashboard URLs — treat it as confidential.

### Someone spoofs check-ins
They need a valid key for a specific `agent_uid`. Failures are rate-limited per
agent and audited, and an unknown agent and a wrong key return an identical 401,
so `agent_uid`s cannot be probed.

### An operator escalates across tenants
`scope()` reads only the session. Cross-tenant routes are gated by
`superadmin_required`, and object lookups are scoped in SQL rather than filtered
in a template.

### Residual risks, stated plainly

* **The SSO token rides in a query string**, so it can reach browser history,
  the referrer header and any proxy log. Bounded by the token being ~60 seconds,
  single-use, and valid for one agent — by the time it appears in a log it is
  already spent. A POST-based hand-off would be strictly better and is the
  obvious future refinement.
* **Rate-limit and single-use state are in memory.** A Central restart forgives
  rate limits, and an instance restart forgets burned `jti`s. Both windows are
  bounded by the token's own 60-second lifetime.
* **`central.db` grows without a retention policy.** The instance dashboard has
  one; Central does not yet.
* **No mutual TLS.** Agents authenticate to Central, but Central is
  authenticated to agents only by its server certificate.

---

## 9. Config reference

### Central — `central/central_config.py`

| Setting | Default | Notes |
|---|---|---|
| `CENTRAL_HOST` / `CENTRAL_PORT` | `0.0.0.0` / `6100` | |
| `CENTRAL_PUBLIC_URL` | — | shown in enrolment instructions |
| `CENTRAL_SSL_CERT` / `_KEY` | `""` | direct TLS |
| `CENTRAL_BEHIND_PROXY` | `False` | TLS at a reverse proxy; adds `ProxyFix` |
| `CENTRAL_ALLOW_INSECURE_HTTP` | `False` | **development only** |
| `CENTRAL_DATABASE_PATH` | `central.db` | |
| `CENTRAL_SSO_TOKEN_TTL` / `_MAX_TTL` | `60` / `300` | seconds |
| `CENTRAL_AGENT_OFFLINE_AFTER` | `300` | seconds before a row shows Offline |
| `CENTRAL_REPORT_RATE_LIMIT` / `_WINDOW` | `20` / `60` | per agent |
| `CENTRAL_MAX_REPORT_BYTES` | `8192` | |
| `CENTRAL_IDLE_TIMEOUT` | `3600` | |
| `CENTRAL_MIN_PASSWORD_LEN` | `12` | matches the instance policy |
| `CENTRAL_FAILED_LOGIN_LIMIT` / `_LOCKOUT_DURATION` | `5` / `900` | temporary, auto-recovering |

### Instance — `config.py`

| Setting | Default | Notes |
|---|---|---|
| `CENTRAL_ENABLED` | `False` | turn check-ins on |
| `CENTRAL_URL` | `""` | must be `https://` |
| `CENTRAL_AGENT_ID` / `CENTRAL_API_KEY` | `""` | from enrolment |
| `CENTRAL_REPORT_INTERVAL` | `60` | seconds |
| `CENTRAL_VERIFY_TLS` | `True` | never `False` outside a lab |
| `CENTRAL_SSO_PUBLIC_KEY` | `""` | Central's public JWK; not a secret |
| `CENTRAL_SSO_ISSUER` | `rdpshield-central` | |
| `CENTRAL_SSO_MAX_TTL` | `300` | reject longer-lived tokens |
| `CENTRAL_MANAGED` | `False` | withdraw the local login form |
| `CENTRAL_LOCAL_LOGIN_FALLBACK` | `False` | **break-glass**, §7 |

---

## 10. API reference

### `POST /api/v1/agents/<agent_uid>/report`
Bearer-authenticated, session-less. The only endpoint an instance ever calls.

```
Authorization: Bearer rdps_…
Content-Type: application/json
```

| Response | Meaning |
|---|---|
| `200 {"ok":true,"next_check_in":60,"schema_version":1}` | accepted |
| `400` | not HTTPS, body not JSON, or schema violation |
| `401` | missing bearer, unknown agent, or wrong key *(identical response for the last two)* |
| `413` | body over `CENTRAL_MAX_REPORT_BYTES` |
| `429` | per-agent rate limit exceeded |

### `GET /healthz`
Unauthenticated liveness probe. Returns `{"ok": true}` and nothing else.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `pip install cryptography` fails with a Rust / build error | 32-bit Python; 49.0.0+ has no win32 wheel | `pip install "cryptography==48.0.1"` — the last release with a `cp311-abi3-win32` wheel |
| Central won't start, "TLS is not configured" | working as designed | set the cert/key, or `CENTRAL_BEHIND_PROXY`; `CENTRAL_ALLOW_INSECURE_HTTP` for local dev only |
| Central won't start, "No SSO signing keypair" | keygen not run | `python central_keygen.py` |
| Agent stuck on **Pending** | it has never checked in | confirm `CENTRAL_ENABLED = True` and restart the dashboard; check its log for `[CENTRAL]` |
| Agent log: `Central rejected our credentials (401)` | wrong or rotated key | re-copy `CENTRAL_AGENT_ID` / `CENTRAL_API_KEY`, or rotate again |
| Agent log: `CENTRAL_URL must be https://` | plaintext refused | use `https://`, or `CENTRAL_ALLOW_INSECURE_HTTP = True` for a local test only |
| Agent goes **Offline** every few minutes | interval above `CENTRAL_AGENT_OFFLINE_AFTER` | lower `CENTRAL_REPORT_INTERVAL` or raise the offline threshold |
| "Open Dashboard" is greyed out | no dashboard URL recorded | set it in **Agents** |
| SSO: "link is not valid or has expired" | clock skew, wrong public key, or genuinely expired | check the public key matches this Central; sync clocks (tokens allow ±30s) |
| SSO: "already been used" | tokens are single-use | click Open Dashboard again |
| Locked out of a managed instance | Central unreachable | break-glass, §7 |
| Every POST in Central returns 400 | stale CSRF token | hard-refresh (Ctrl+F5) |

---

## 12. Related documents

* [`SECURITY.md`](SECURITY.md) — account security for both consoles, including the break-glass procedure
* [`INSTALL.md`](INSTALL.md) — installing and running a single instance
* [`README.md`](README.md) — project overview
