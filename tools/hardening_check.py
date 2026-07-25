"""
RDPShield — Security-Hardening Verification (Dissertation Table 8 / Appendix D)
==============================================================================

Automated black-box + unit checks for the five management-plane hardening
controls. Each check exercises the REAL application code (Flask test client or
the actual guard functions) and prints a PASS/FAIL line that maps 1:1 to the
rows of Table 8 in the dissertation.

    Control                     Test
    -----------------------------------------------------------------
    1. CSRF protection          State-changing POST without a token   -> 400
    2. Firewall input validation Injection payload in the IP field    -> rejected
    3. Authentication + MFA      Page/API without a session; bad TOTP -> denied
    4. Account lockout + recovery 5 wrong passwords -> temporary lock
    5. Open-redirect guard       POST with an external "next" URL      -> ignored

Run it from the project root (the same machine/venv that runs the app):

    python tools/hardening_check.py

It is SIDE-EFFECT SAFE:
  * No firewall rules are added (injection payloads are rejected before netsh).
  * No real SMS is sent (the root-notify function is stubbed for the run).
  * The lockout test creates a throwaway user and deletes it again afterwards.

Output is printed to the terminal (screenshot it for the figure) AND written to
    evidence/screenshots/hardening/table8_hardening_<YYYY-MM-DD>.txt
so the raw pass/fail log can be pasted into Appendix D.
"""

import os
import sys
import time
import datetime

# Make the project root importable when run as `python tools/hardening_check.py`.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import dashboard          # noqa: E402  (Flask app + guard functions live here)
import firewall           # noqa: E402
import auth               # noqa: E402
import database           # noqa: E402
from flask import url_for  # noqa: E402

app = dashboard.app
app.config["TESTING"] = True

# Collected (row_label, test_desc, passed, detail) tuples for the summary table.
RESULTS = []


def record(label, desc, passed, detail=""):
    RESULTS.append((label, desc, bool(passed), detail))
    tick = "PASS" if passed else "FAIL"
    print(f"  [{tick}] {label:<26} {detail}")


def _admin_session(client):
    """Give the test client a fully-logged-in admin session with a known CSRF
    token, exactly as the app would after login + MFA."""
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "hardening-bot"
        sess["role"] = "admin"
        sess["is_root"] = False
        sess["last_active"] = time.time()
        sess["csrf_token"] = "TESTTOKEN0123456789"
    return "TESTTOKEN0123456789"


# =========================================================================
# 1. CSRF PROTECTION  — state-changing POST without a token must be rejected.
# =========================================================================
def test_csrf():
    print("\n1. CSRF protection")
    client = app.test_client()
    token = _admin_session(client)

    # (a) POST a state-changing endpoint with NO token -> must be blocked (400).
    r_no = client.post("/theme/dark", data={})
    blocked = r_no.status_code == 400

    # (b) Same POST WITH the correct token -> must be accepted (proves it is the
    #     token being checked, not some unrelated failure).
    r_ok = client.post("/theme/dark", data={"csrf_token": token})
    accepted = r_ok.status_code in (200, 204, 302)

    record("CSRF protection",
           "state-changing POST without a token",
           blocked and accepted,
           f"no-token={r_no.status_code} (want 400), with-token={r_ok.status_code} (want 200/302)")


# =========================================================================
# 2. FIREWALL INPUT VALIDATION — injection payloads in the IP field rejected.
# =========================================================================
def test_firewall_input():
    print("\n2. Firewall input validation")
    payloads = [
        "10.0.0.5 & calc.exe",
        "1.2.3.4; rm -rf /",
        "8.8.8.8 && netsh advfirewall reset",
        "$(whoami)",
        "127.0.0.1|nc -e",
        "not-an-ip",
    ]
    # Every payload must fail _valid_ip AND be refused by block_ip (before netsh).
    rejected = all(not firewall._valid_ip(p) for p in payloads)
    block_refused = all(firewall.block_ip(p) is False for p in payloads)
    # Sanity: a genuine IP still validates (guard isn't just rejecting everything).
    real_ok = firewall._valid_ip("203.0.113.7")

    record("Firewall input validation",
           "injection payload in the IP field",
           rejected and block_refused and real_ok,
           f"{len(payloads)} payloads rejected, genuine IP accepted={real_ok}")


# =========================================================================
# 3. AUTHENTICATION + MFA — no session => no access; bad/absent TOTP => denied.
# =========================================================================
def test_auth_mfa():
    print("\n3. Authentication + MFA")
    client = app.test_client()  # fresh client, NO session

    # (a) Protected PAGE without a session -> redirect to /login.
    r_page = client.get("/", follow_redirects=False)
    page_gated = r_page.status_code in (302, 401, 403) and "login" in r_page.headers.get("Location", "")

    # (b) Protected API without a session -> not served (redirect/401/403).
    r_api = client.get("/api/blocked", follow_redirects=False)
    api_gated = r_api.status_code in (302, 401, 403)

    # (c) MFA second factor actually verifies: a wrong/empty TOTP is rejected,
    #     the correct current code is accepted (valid_window tolerance).
    import pyotp
    secret = auth.new_totp_secret()
    good_code = pyotp.TOTP(secret).now()
    totp_enforced = (not auth.verify_totp(secret, "000000")
                     and not auth.verify_totp(secret, "")
                     and auth.verify_totp(secret, good_code))

    record("Authentication + MFA",
           "access page/API without a session; login without TOTP",
           page_gated and api_gated and totp_enforced,
           f"page={r_page.status_code}, api={r_api.status_code}, "
           f"bad-TOTP-rejected={not auth.verify_totp(secret, '000000')}")


# =========================================================================
# 4. ACCOUNT LOCKOUT + RECOVERY — 5 wrong passwords => temporary lock.
# =========================================================================
def test_lockout():
    print("\n4. Account lockout + recovery")
    name = "_hardening_lockout_test"
    uid = None
    orig_notify = dashboard._notify_root
    dashboard._notify_root = lambda *a, **k: None  # stub: no real SMS during the test
    try:
        # Throwaway non-root user with a known password.
        pw_hash = auth.hash_password("CorrectHorse1234")
        uid = database.create_user(name, pw_hash, role="user", is_root=0, verified=1)
        if uid is None:  # a stale row from a previous run — reuse it
            uid = database.get_user_by_username(name)["id"]
        # Clean any leftover in-memory state for this username.
        dashboard._FAILED_LOGINS.pop(name, None)
        dashboard._LOCKED_UNTIL.pop(name, None)

        client = app.test_client()
        limit = dashboard.FAILED_LOGIN_LIMIT
        for _ in range(limit):
            client.post("/login", data={"username": name, "password": "wrong-password"})

        locked = dashboard._lock_seconds_left(name) > 0

        # While locked, even the CORRECT password is refused (early lockout reject).
        r = client.post("/login", data={"username": name, "password": "CorrectHorse1234"})
        still_locked = b"Too many failed attempts" in r.data

        # Recovery path exists: the SMS self-unlock route is registered.
        unlock_route = any(str(r_.rule) == "/unlock" for r_ in app.url_map.iter_rules())

        record("Account lockout + recovery",
               "5 wrong passwords -> temporary lock -> SMS unlock",
               locked and still_locked and unlock_route,
               f"limit={limit}, locked={locked}, correct-pw-refused={still_locked}, "
               f"/unlock route={unlock_route}")
    finally:
        dashboard._notify_root = orig_notify
        dashboard._FAILED_LOGINS.pop(name, None)
        dashboard._LOCKED_UNTIL.pop(name, None)
        if uid:
            database.delete_user(uid)


# =========================================================================
# 5. OPEN-REDIRECT GUARD — an external "next" URL must be ignored.
# =========================================================================
def test_open_redirect():
    print("\n5. Open-redirect guard")
    external = ["https://evil.example/steal", "//evil.example/x",
                "http:evil", "\\\\evil.example"]
    local = "/settings"
    with app.test_request_context("/login", method="POST"):
        home = url_for("index")

    def safe_next_for(value):
        with app.test_request_context("/login", method="POST", data={"next": value}):
            return dashboard._safe_next()

    # Every external target falls back to the local home page.
    external_blocked = all(safe_next_for(v) == home for v in external)
    # A genuine local path is preserved.
    local_allowed = safe_next_for(local) == local

    record("Open-redirect guard",
           'POST with an external "next" URL',
           external_blocked and local_allowed,
           f"external->home for {len(external)} URLs, local path preserved={local_allowed}")


def main():
    print("=" * 72)
    print("RDPShield — Security-Hardening Verification (Table 8 / Appendix D)")
    print("Run:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 72)

    test_csrf()
    test_firewall_input()
    test_auth_mfa()
    test_lockout()
    test_open_redirect()

    # ---- Summary table (paste-ready for Table 8) --------------------------
    print("\n" + "=" * 72)
    print("SUMMARY — Table 8")
    print("=" * 72)
    print(f"{'Control':<28}{'Test':<44}{'Result'}")
    print("-" * 72)
    for label, desc, passed, _ in RESULTS:
        print(f"{label:<28}{desc:<44}{'PASS' if passed else 'FAIL'}")
    total = len(RESULTS)
    passed_n = sum(1 for *_, ok, _ in [(r[0], r[1], r[2], r[3]) for r in RESULTS] if ok)
    print("-" * 72)
    print(f"{passed_n}/{total} controls PASS")

    # ---- Persist the raw log for Appendix D -------------------------------
    out_dir = os.path.join(_ROOT, "evidence", "screenshots", "hardening")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.date.today().isoformat()
    out_path = os.path.join(out_dir, f"table8_hardening_{stamp}.txt")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("RDPShield Security-Hardening Verification (Table 8)\n")
        fh.write("Run: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
        fh.write(f"{'Control':<28}{'Test':<44}{'Result'}\n")
        fh.write("-" * 72 + "\n")
        for label, desc, passed, detail in RESULTS:
            fh.write(f"{label:<28}{desc:<44}{'PASS' if passed else 'FAIL'}\n")
            fh.write(f"    detail: {detail}\n")
        fh.write("-" * 72 + "\n")
        fh.write(f"{passed_n}/{total} controls PASS\n")
    print(f"\nRaw log written to: {out_path}")

    # Non-zero exit if anything failed (useful for CI / a clean viva demo).
    sys.exit(0 if passed_n == total else 1)


if __name__ == "__main__":
    main()
