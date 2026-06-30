# RDPShield — Account Security & Lockout Guide

How the dashboard protects accounts: sign-in, two-factor, lockouts, and how a
genuine owner recovers access. This covers the **dashboard operators** (the
people who log into the web UI) — it is separate from the *attacker* IP blocking
that RDPShield performs on the host it protects.

> TL;DR — Logins need **password + TOTP**. Five wrong passwords (or a suspicious
> concurrent login) **temporarily** locks the account for **15 minutes**. The
> real owner can clear that lock instantly with a **6-digit SMS code** sent to
> the account's registered phone. The **root** admin is never auto-locked.

---

## 1. How sign-in works

Sign-in is a two-step flow; a session is only granted after **both** succeed:

1. **`/login`** — username + password. Passwords are stored as salted
   **werkzeug hashes** (never in plaintext).
2. **`/mfa`** — a 6-digit **TOTP** code (Google Authenticator / Authy, via
   `pyotp`). On a brand-new account this is a one-time **enrollment** (scan the
   QR / type the secret); afterwards it's a **verify** each login.

Until the TOTP step passes, the session holds only a *pending* identity — no
access to any page or API.

### Roles (RBAC)
| Role | Can do |
|---|---|
| **admin** | Everything: block/unblock, geo/whitelist settings, YARA actions, user management, settings. |
| **guest** | View dashboards/logs **+ CSV export only**. No mutating actions. |

The first admin created is the **root admin** (`is_root`) and has extra
protections (Section 6).

### Who can manage whom
User management is **admin-only** (guests have no access at all). Among admins,
changes to *other* users are constrained:

| Actor | May change credentials / MFA of |
|---|---|
| **root** admin | **anyone** — and **only root** can change the **root** account |
| **admin** (non-root) | **itself** and **guest** users only — *not* other admins, *not* root |
| **guest** | nobody |

Only the **root** admin can **create admin accounts**; ordinary admins create
guests only (so a non-root admin can't mint admins it isn't allowed to manage).

### New users must verify their phone (SMS)
A user created from the console starts **Pending**: a **mobile number is
required**, a **6-digit code** is texted to it, and the user must enter it at
**`/verify`** before their first sign-in. **Login refuses an unverified account.**
An admin can **Resend code** from the Users page; codes expire in **30 minutes**.

### Credential / MFA changes re-verify the user
When an admin (or root) changes a user's **password** or **resets their MFA**, the
affected user is **re-gated**: a fresh code is texted and they must re-verify at
`/verify` before signing in again (*lock-until-verified*). Self-changes are gated
too, but **skipped when the account has no phone** — so the seeded root can never
lock itself out of its own console.

---

## 2. Password policy

- Minimum **12 characters**, enforced everywhere a password is set (add user,
  admin reset, self-service reset).
- There is **no `admin/admin` default**. On first start the root admin is seeded
  with a **random** password printed once to the dashboard log — change it
  immediately after first login.
- Existing passwords are never weakened; the policy applies only when a new
  password is chosen.

---

## 3. Account lockouts

RDPShield uses **temporary, auto-recovering** locks for suspicious activity — it
does **not** permanently disable an account behind your back. There are three
distinct states:

| State | What triggers it | Duration | How to recover |
|---|---|---|---|
| **Temporary lock** (failed passwords) | **5** wrong passwords for one username | **15 min**, auto-lifts | Wait it out, **or** SMS unlock (Section 4) |
| **Temporary lock** (concurrent login) | A valid login while another session for that account is **already active** (activity within the last 10 min) | **15 min**, auto-lifts | Wait it out, **or** SMS unlock (Section 4) |
| **Disabled** (admin action) | An admin clicks **Disable** on the Users page | Until an admin re-enables | **Admin only** — *cannot* be self-unlocked by SMS |

Key properties:

- **Temporary locks live in memory** and lift on their own after 15 minutes — a
  process restart also clears them. They can't be abused to lock someone out
  forever.
- Every lock **alerts the root admin by SMS** (and any configured alert
  recipients) for visibility, and is written to the **audit log**.
- The login response is deliberately **neutral** ("Too many failed attempts.
  Please try again in a few minutes.") so it doesn't reveal whether a username
  exists.
- The **concurrent-login** lock is a breach-defense feature: if an attacker
  logs in with stolen-but-valid credentials while you're working, the account
  locks and you're alerted. (Side effect: opening a second session yourself can
  trip it — just unlock by SMS.)

> Why "concurrent login" can fire on you: signing in from a second device/tab
> while your first session is still active looks identical to an intruder using
> stolen credentials. The SMS unlock makes recovery a 30-second step.

---

## 4. Recovering a locked account — SMS unlock

A temporarily-locked account is cleared by proving you own the account's
**registered phone**. This is the procedure the real admin should know:

1. On the login page click **"Account locked? Unlock via SMS"** (or go to
   **`/unlock`**).
2. Enter your **username**. If the account exists, isn't admin-disabled, and has
   a phone on file, a **6-digit code** is texted to that phone (Notify.lk).
3. Enter the code on the next screen. The temporary lock is cleared.
4. Sign in normally — **you still need your password and TOTP code**. Unlocking
   only removes the lock; it does not bypass authentication.

Code properties: **10-minute** expiry, **single-use**, **5-try** cap, and
neutral responses (it never confirms whether a username exists).

**Important boundary:** SMS unlock clears **only** a temporary security lock. An
account an **admin has explicitly Disabled** stays disabled — a user can't SMS
their way past an administrator's decision. Re-enabling a disabled account is an
**admin-only** action on the Users page.

> 📱 **Prerequisite:** the account must have a **phone number** set (Users → Edit
> → phone, normalised to `94…`). Accounts with no phone can only wait for the
> 15-minute auto-unlock, or be helped by another admin.

---

## 5. Forgotten password

Separate from unlock, the **`/forgot`** flow resets a password via SMS:

1. **`/forgot`** → enter username → a **6-digit reset code** is texted to the
   registered phone.
2. **`/reset`** → enter the code + a new password (min 12 chars).

Same protections as unlock (10-min TTL, 5-try cap, single-use, neutral
responses). If the account has no phone, an **admin** can reset the password
from the **Users** page instead.

---

## 6. Root admin protections

The first/seeded admin is the **root admin** and is hardened so the system can
never be fully locked out:

- **Never auto-locked.** Suspicious activity on the root account raises an SMS
  **warning** but does not lock it.
- **Cannot be deleted or disabled by a secondary admin** (UI hides the actions
  and the backend enforces it).
- **Only root changes the root account.** A secondary admin cannot change the
  root admin's password or MFA — closing the gap where any admin could take over
  root.
- **Only root creates admin accounts** (ordinary admins create guests only).
- You also **can't delete/disable yourself** or the **last remaining admin**.

Lost the root admin's phone? Another admin can **Reset MFA** for any user from
the Users page (they re-enroll TOTP on next login) and reset their password.

---

## 7. Session security

- **Two-factor required** on every login (Section 1).
- **Idle auto-logout** after **1 hour** of inactivity. Background polling (the
  live AJAX refresh, YARA status) does **not** count as activity — an idle but
  open tab still expires.
- **Bounded session lifetime:** "Remember this device" sessions last at most
  **12 hours**.
- **Cookie hardening:** session cookie is **HttpOnly** (not readable by JS) and
  **SameSite=Lax** (not sent on cross-site POSTs — a strong CSRF mitigation).
- **Transport:** the dissertation deployment runs over **plain HTTP**, mitigated
  by restricting the dashboard port to the operator's IP. **HTTPS/TLS is a
  planned future enhancement** — the hooks already exist (`DASHBOARD_USE_HTTPS`
  to mark the cookie `Secure`, `DASHBOARD_BEHIND_PROXY` for a reverse proxy, or
  `DASHBOARD_SSL_CERT`/`_KEY` for a direct cert; recipe in `INSTALL.md` §11) but
  are intentionally left off for now. On plain HTTP the `Secure` flag stays off
  so logins keep working.
- **Signed sessions:** cookies are signed with a random key stored in the
  gitignored **`.flask_secret_key`** file (generated on first run, or supplied
  via the `RDPSHIELD_SECRET` environment variable). Keep it private and
  per-server; deleting/rotating it simply forces everyone to log in again.

---

## 8. CSRF protection

Every state-changing request (block/unblock, settings, user management, YARA
actions, theme, …) requires a **per-session CSRF token**, supplied automatically
by `static/js/csrf.js` as a hidden form field and an `X-CSRFToken` header. The
auth flow (`/login`, `/mfa`, `/forgot`, `/reset`, `/unlock`) is exempt — those
run before a session exists and are already covered by `SameSite=Lax`.

> After updating the app, **hard-refresh (`Ctrl+F5`)**. A stale cached page won't
> carry the token and every action will return **HTTP 400** until you reload.

---

## 9. Other defensive measures

- **Firewall input validation:** IPs are validated (`ipaddress`) and passed to
  `netsh` as argument lists (no shell), so a malformed/hostile value can't be
  interpreted as a command.
- **Open-redirect guard:** post-action redirects (`next`) only accept local,
  same-site paths.
- **Cryptographic codes:** reset/unlock codes use `secrets`, not a predictable
  PRNG.
- **Audit log:** logins, logout, lockouts, unlocks, block/unblock, geo changes,
  user management, and settings changes are recorded (admin-only **Audit Log**
  in Settings, with CSV export).
- **Data retention:** failed logins / alerts / geo events can be auto-purged on
  a schedule (Settings → Data Retention).
- **API-key rotation reminders:** periodic SMS + dashboard nudges to rotate
  VirusTotal / AbuseIPDB / Notify.lk keys.

---

## 10. Hardening checklist for production

- [ ] Change the seeded admin password (min 12 chars) and enroll MFA.
- [ ] Set a **phone number** on every account (enables SMS reset/unlock).
- [ ] Keep dashboard **port 5000 restricted to your admin IP** (firewall + cloud SG).
- [ ] Add your admin/management IP to `WHITELIST_IPS` (host won't block you).
- [ ] *(Future enhancement)* Put the dashboard behind a **reverse proxy with
      TLS** (Caddy + a free DuckDNS hostname is the easy path — `INSTALL.md`
      §11), then set `DASHBOARD_USE_HTTPS = True` and
      `DASHBOARD_BEHIND_PROXY = True`. Not required for the dissertation demo.
- [ ] Keep `config.py` and `.flask_secret_key` **out of git** (already gitignored)
      and off shared drives.
- [ ] Rotate any API keys that were ever exposed.
- [ ] Review the **Audit Log** periodically.

---

## 11. Quick reference — "I'm locked out"

| Situation | Do this |
|---|---|
| "Too many failed attempts" after wrong passwords | Wait 15 min, or **Unlock via SMS** (`/unlock`). |
| Locked after logging in from a second device | **Unlock via SMS** (`/unlock`), then sign in. |
| Forgot password | **Forgot password?** (`/forgot`) → SMS code → set new password. |
| No phone on the account | Wait for the 15-min auto-unlock, or ask another admin to help via **Users**. |
| Account shows "disabled — contact an administrator" | An admin must **Enable** it on the Users page (SMS unlock won't work). |
| Lost MFA phone/app | An admin **Reset MFA** for you on the Users page; re-enroll next login. |
| Root admin issues | Root is never auto-locked; if its credentials are lost, another admin resets its password/MFA from **Users**. |

---

For installation and updates see **[`INSTALL.md`](INSTALL.md)**; for architecture
and feature details see **`PROGRESS.md`**.
