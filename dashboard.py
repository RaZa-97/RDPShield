"""
RDPShield Dashboard v2.1
=========================
Flask web interface with two pages:

1. Dashboard (/) - Main monitoring page with alerts, blocked IPs, events
2. Geolocation (/geo) - Geographic access control settings

Features:
- Live stats and alert feed
- Blocked IPs management with unblock buttons
- Geo-blocking mode selection (3 modes)
- Country whitelist management (add/remove)
- IP whitelist management (add/remove)
- Geo-block event log

Access: http://SERVER_IP:5000
"""

import csv
import hmac
import io
import os
import secrets
import re
import threading
import time
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, jsonify, request,
    redirect, url_for, flash, session, Response, send_from_directory
)
from werkzeug.middleware.proxy_fix import ProxyFix
from database import (
    init_db,
    get_recent_alerts,
    get_blocked_ips,
    get_recent_failed_logins,
    get_dashboard_stats,
    get_failed_login_trend,
    get_alert_type_breakdown,
    get_top_attacker_countries,
    get_attack_map_points,
    get_yara_history,
    log_alert,
    # Geo functions
    get_geo_mode,
    set_geo_mode,
    get_allowed_countries,
    add_allowed_country,
    remove_allowed_country,
    get_allowed_ips,
    add_allowed_ip,
    remove_allowed_ip,
    get_geo_events,
    get_geo_stats,
    get_geo_category_stats,
    # User accounts
    count_users,
    count_admins,
    create_user,
    get_user_by_username,
    get_user_by_id,
    list_users,
    delete_user,
    set_user_totp,
    update_last_login,
    set_user_disabled,
    set_user_role,
    update_user_phone,
    update_user_password,
    get_root_user,
    set_user_theme,
    set_user_verify_code,
    clear_user_verify,
    # Settings / recipients / audit / retention
    create_settings_tables,
    get_setting,
    set_setting,
    get_all_settings,
    list_alert_recipients,
    add_alert_recipient,
    update_alert_recipient,
    delete_alert_recipient,
    add_audit,
    get_audit,
    purge_old_data,
)
from firewall import unblock_ip, block_ip
from alerts import process_alert_enrichment, send_sms_to
from config import DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_DEBUG
from countries import COUNTRY_NAMES
import config
import auth
import settings
import yara_scheduler
import ml_model
from daily_report import write_report, REPORT_DIR

app = Flask(__name__)
from yara_routes import yara_bp
from database import create_yara_tables, create_users_table, get_campaigns

app.register_blueprint(yara_bp)
create_yara_tables()
create_users_table()
create_settings_tables()
def _load_secret_key():
    """Session-signing key. Read from the RDPSHIELD_SECRET env var, else from a
    gitignored .flask_secret_key file next to this script (generated once on
    first run). A persisted file means sessions survive restarts; never commit
    it. Replacing the key simply forces everyone to log in again."""
    env = os.environ.get("RDPSHIELD_SECRET")
    if env:
        return env
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".flask_secret_key")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            existing = fh.read().strip()
        if existing:
            return existing
    except FileNotFoundError:
        pass
    key = secrets.token_hex(32)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(key)
        print(f"[AUTH] Generated a new session secret at {path} (gitignored).")
    except OSError as e:
        print(f"[AUTH] WARNING: could not persist session secret ({e}); "
              "sessions will reset on restart.")
    return key


app.secret_key = _load_secret_key()  # Needed for sessions + flash messages

# --- Cookie / session hardening (#11) -------------------------------------
# HttpOnly keeps the cookie out of JS; SameSite=Lax blocks it on cross-site
# POSTs (a strong CSRF mitigation on its own). SESSION_COOKIE_SECURE is only
# turned on when the dashboard is actually served over HTTPS — otherwise the
# browser refuses to send the cookie over plain HTTP and everyone is locked
# out. Flip DASHBOARD_USE_HTTPS = True in config.py once TLS is in front.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(getattr(config, "DASHBOARD_USE_HTTPS", False)),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

# When TLS is terminated by a reverse proxy (e.g. Caddy/nginx), trust its
# forwarded headers so request.scheme is "https" and the audit log records the
# real client IP (X-Forwarded-For) instead of the proxy's. Off by default —
# enable DASHBOARD_BEHIND_PROXY = True in config.py only when actually proxied.
if getattr(config, "DASHBOARD_BEHIND_PROXY", False):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def _audit(action, detail=""):
    """Record an admin/security action in the audit trail."""
    try:
        add_audit(session.get("username", "?"), action, detail,
                  request.remote_addr or "")
    except Exception as e:
        print(f"[AUDIT] failed to record '{action}': {e}")


def _safe_next(default=None):
    """Return the form's `next` target only if it's a local, same-site path
    (starts with a single '/', not '//' or a scheme) — otherwise the default.
    Prevents the redirect from being abused as an open redirect."""
    nxt = request.form.get("next") or ""
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return default or url_for("index")


# =========================================================================
# AUTHENTICATION GATE + TEMPLATE CONTEXT
# =========================================================================

# Endpoints reachable WITHOUT a full login (the auth flow itself + assets).
PUBLIC_ENDPOINTS = {"setup", "login", "mfa", "logout", "forgot", "reset",
                    "unlock", "unlock_verify", "verify_account",
                    "sso", "service_worker", "static"}


@app.before_request
def require_login():
    """Global gate: every page/API needs a logged-in session except the
    auth flow and static assets. Also enforces a 1-hour idle timeout and
    refreshes the per-user 'last active' marker used to spot concurrent
    suspicious logins."""
    # First run (empty DB, no accounts): funnel everything to the setup wizard
    # so the operator can create the initial root admin. Without this there is
    # no way in — account creation is otherwise admin-only. Static assets and
    # the wizard itself are allowed through.
    if _needs_setup():
        if request.endpoint in ("setup", "static") or request.endpoint is None:
            return
        return redirect(url_for("setup"))

    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return
    uid = session.get("user_id")
    if not uid:
        return redirect(url_for("login", next=request.path))

    now = time.time()
    last = session.get("last_active", now)
    if now - last > IDLE_TIMEOUT:
        _ACTIVE_USERS.pop(uid, None)
        session.clear()
        return redirect(url_for("login", timeout=1))

    # Background polling (the dashboard's 10s AJAX refresh, YARA status) must
    # NOT count as user activity, or an idle-but-open tab would never time out.
    passive = request.path.startswith("/api/") or request.path.startswith("/yara/status")
    if not passive:
        session["last_active"] = now
        _ACTIVE_USERS[uid] = now


# =========================================================================
# CSRF PROTECTION (#6)
# =========================================================================
# A per-session token must accompany every state-changing request, supplied
# either as a `csrf_token` form field or an `X-CSRFToken` header (the JS shim
# in static/js/csrf.js adds both automatically). The auth-flow endpoints are
# exempt — they run before/around session establishment and SameSite=Lax
# already covers login CSRF.
CSRF_EXEMPT = {"setup", "login", "mfa", "logout", "forgot", "reset",
               "unlock", "unlock_verify", "verify_account",
               "sso", "service_worker", "static"}


def _ensure_csrf_token():
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_hex(32)
        session["csrf_token"] = tok
    return tok


@app.before_request
def csrf_protect():
    _ensure_csrf_token()  # so the token is available to render into pages
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    if request.endpoint in CSRF_EXEMPT or request.endpoint is None:
        return
    sent = (request.form.get("csrf_token")
            or request.headers.get("X-CSRFToken")
            or request.headers.get("X-CSRF-Token") or "")
    if not hmac.compare_digest(str(sent), str(session.get("csrf_token") or "")):
        return ("CSRF token missing or invalid. Reload the page and try again.", 400)


@app.context_processor
def inject_user():
    """Make the current user/role available to every template."""
    return {
        "current_user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role"),
            "is_root": session.get("is_root", False),
        } if session.get("user_id") else None,
        "is_admin": session.get("role") == "admin",
        "login_at": session.get("login_at"),
        # Per-user theme; dark futuristic is the default (also for pre-login pages).
        "theme": session.get("theme", "dark"),
        # CSRF token published to the page (read by static/js/csrf.js).
        "csrf_token": session.get("csrf_token", ""),
    }


@app.errorhandler(403)
def forbidden(_e):
    return render_template("403.html"), 403


# Minimum password length enforced everywhere a password is set (#5).
MIN_PASSWORD_LEN = 12


def _password_ok(pw):
    """A password is acceptable if it meets the minimum length."""
    return isinstance(pw, str) and len(pw) >= MIN_PASSWORD_LEN


# First-run bootstrap: on an empty database there are no accounts and no
# public signup, so the very first admin is created through a one-time /setup
# wizard (see the `setup` route). `_needs_setup()` gates it. The result is
# cached once accounts exist so we don't COUNT on every single request.
_setup_complete = False


def _needs_setup():
    """True only while the database has no user accounts at all."""
    global _setup_complete
    if _setup_complete:
        return False
    if count_users() > 0:
        _setup_complete = True
        return False
    return True


def _is_local_request():
    """Is this request coming from the server itself or the local network?

    The first-run wizard creates an unauthenticated admin, so we only expose it
    to loopback / private-LAN clients — never to the public internet. remote_addr
    already reflects the real client because ProxyFix is applied above."""
    ip = (request.remote_addr or "").strip()
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    # IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.5) -> compare the trailing IPv4.
    if ip.startswith("::ffff:"):
        ip = ip.rsplit(":", 1)[-1]
    return ip.startswith(config.PRIVATE_IP_PREFIXES)


# =========================================================================
# SESSION SECURITY: idle timeout + suspicious-login defence
# =========================================================================

IDLE_TIMEOUT = 3600        # auto-logout after 1h of inactivity
CONCURRENT_WINDOW = 600    # "still active" = activity within the last 10 min
FAILED_LOGIN_LIMIT = 5     # wrong passwords before a temporary lockout
LOCKOUT_DURATION = 900     # how long the temporary lockout lasts (15 min)

# In-memory, single-process state.
_FAILED_LOGINS = {}        # username -> consecutive wrong-password count
_ACTIVE_USERS = {}         # user_id  -> last-activity epoch seconds
_LOCKED_UNTIL = {}         # username -> epoch when the temporary lock lifts


def _lock_seconds_left(username):
    """Seconds remaining on a temporary lockout for `username`, or 0 if none.
    Expired locks are cleared on read."""
    until = _LOCKED_UNTIL.get(username)
    if not until:
        return 0
    left = until - time.time()
    if left <= 0:
        _LOCKED_UNTIL.pop(username, None)
        return 0
    return int(left)


def _temp_lock(user, reason):
    """Temporarily lock an account (in memory, auto-recovers) after a suspicious
    event, and alert the root admin. Unlike a DB disable this can't be abused
    for a permanent lockout — it lifts on its own after LOCKOUT_DURATION, and
    the real owner can clear it early via the SMS unlock flow (/unlock). The
    root admin is never locked (warned only).

    Returns True if the account was actually locked, False if it was spared
    (root) so the caller can let the login proceed."""
    name = user["username"]
    _FAILED_LOGINS.pop(name, None)
    add_audit(name, "security.temp_lock", reason, request.remote_addr or "")
    if user.get("is_root"):
        _notify_root(f"RDPShield WARNING: {reason} on ROOT admin '{name}'. "
                     f"Not locked (root) — investigate now.")
        print(f"[SECURITY] ROOT '{name}': {reason}; warned, not locked.")
        return False
    _LOCKED_UNTIL[name] = time.time() + LOCKOUT_DURATION
    _ACTIVE_USERS.pop(user["id"], None)
    tier = "ADMIN account" if user.get("role") == "admin" else "account"
    _notify_root(f"RDPShield: {reason} on {tier} '{name}'. Temporarily locked "
                 f"{LOCKOUT_DURATION // 60} min; owner can clear it via SMS unlock.")
    print(f"[SECURITY] '{name}': {reason}; temp-locked {LOCKOUT_DURATION // 60}m.")
    return True


def _normalize_phone(p):
    """Notify.lk wants a bare international number (e.g. 94771234567).
    Accepts 0XXXXXXXXX, +94…, spaces/dashes, or a 9-digit local number."""
    digits = re.sub(r"\D", "", p or "")
    if not digits:
        return ""
    if digits.startswith("94"):
        return digits
    if digits.startswith("0"):
        return "94" + digits[1:]
    if len(digits) == 9:
        return "94" + digits
    return digits


def _notify_root(message):
    """Send a security/breach alert to the root admin AND every active alert
    recipient (Settings). Falls back to config.ALERT_TO_NUMBER."""
    numbers = set()
    root = get_root_user()
    if root and root.get("phone"):
        numbers.add(_normalize_phone(root["phone"]))
    for n in settings.alert_numbers():
        numbers.add(_normalize_phone(n))
    numbers.discard("")
    if not numbers:
        print("[SECURITY] No alert recipients / root phone configured; SMS skipped.")
        return
    for num in numbers:
        ok = send_sms_to(num, message[:300])
        print(f"[SECURITY] Alert SMS to {num} ok={ok}")


def _is_user_active(user_id):
    ts = _ACTIVE_USERS.get(user_id)
    return ts is not None and (time.time() - ts) < CONCURRENT_WINDOW


# =========================================================================
# AUTH ROUTES: login -> MFA (enroll/verify) -> session
# =========================================================================

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """First-run wizard: create the initial ROOT admin on an empty database.

    This is the ONLY unauthenticated account-creation path, so it is locked
    down hard: it exists ONLY while there are zero accounts (it disappears the
    instant the first admin is created) and is reachable ONLY from loopback /
    the local network. After it succeeds the operator logs in normally and
    enrolls MFA on that first sign-in."""
    # Already set up -> this endpoint no longer exists; send them to login.
    if not _needs_setup():
        return redirect(url_for("login"))

    # Never expose unauthenticated admin creation to the public internet.
    if not _is_local_request():
        return render_template(
            "setup.html", local_only=True,
            error="For security, first-time setup must be done from the server "
                  "itself or the local network — not over a public address."), 403

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        phone = _normalize_phone(request.form.get("phone", "")) or None

        if not username:
            return render_template("setup.html", error="Choose a username.")
        if not _password_ok(password):
            return render_template(
                "setup.html",
                error=f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        if password != confirm:
            return render_template("setup.html", error="The two passwords don't match.")

        # Race guard: re-check under the same request in case a parallel setup
        # already created the first account.
        if not _needs_setup():
            return redirect(url_for("login"))

        # verified=1: the root admin is the trust anchor, so no SMS gate here.
        # A phone is optional but recommended (needed for the SMS unlock flow).
        uid = create_user(username, auth.hash_password(password),
                          role="admin", is_root=1, phone=phone, verified=1)
        if not uid:
            return render_template("setup.html", error="Could not create the account. Try again.")

        global _setup_complete
        _setup_complete = True
        print(f"[AUTH] First-run setup: created ROOT admin '{username}'.")
        flash("Root admin created. Sign in below — you'll set up MFA on this first login.",
              "success")
        return redirect(url_for("login"))

    return render_template("setup.html", error=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Already fully logged in -> straight to the dashboard.
    if session.get("user_id"):
        return redirect(url_for("index"))

    # Central-managed instance: identity lives in Central, so the public login
    # form is withdrawn and the only way in is a signed SSO token (/sso).
    # BREAK-GLASS: if Central is unreachable or an operator is locked out, set
    # CENTRAL_LOCAL_LOGIN_FALLBACK = True in config.py on the box and restart —
    # the form comes straight back. Documented in SECURITY.md and CENTRAL.md.
    if _central_managed() and not getattr(config, "CENTRAL_LOCAL_LOGIN_FALLBACK", False):
        return render_template("login.html", central_managed=True, error=None,
                               info="This server is managed centrally. Sign in at "
                                    "RDPShield Central and open it from there."), 403

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Temporary lockout: reject early with a neutral message (auto-recovers,
        # so this can't be abused to permanently lock an account out).
        if _lock_seconds_left(username):
            return render_template(
                "login.html",
                error="Too many failed attempts. Please try again in a few minutes.")

        user = get_user_by_username(username)

        # Wrong credentials -> count failures; temp-lock + alert root past the limit.
        if not user or not auth.verify_password(user["password_hash"], password):
            if user:
                _FAILED_LOGINS[username] = _FAILED_LOGINS.get(username, 0) + 1
                if _FAILED_LOGINS[username] >= FAILED_LOGIN_LIMIT and not user.get("disabled"):
                    if _temp_lock(user, f"{FAILED_LOGIN_LIMIT}+ failed password attempts"):
                        return render_template(
                            "login.html",
                            error="Too many failed attempts. This account is locked for "
                                  f"{LOCKOUT_DURATION // 60} minutes — or unlock it now via "
                                  "the SMS code sent to your registered phone.",
                            show_unlock=True)
            return render_template("login.html", error="Invalid username or password.")

        # Correct password -> clear the failure counter.
        _FAILED_LOGINS.pop(username, None)

        if user.get("disabled"):
            return render_template("login.html",
                                   error="This account is disabled. Contact an administrator.")

        # Phone-ownership gate: a pending/unverified account (new user, or a user
        # whose credentials were just changed) must confirm the SMS code first.
        if not user.get("verified", 1):
            flash("This account isn't verified yet — enter the code sent to your phone.",
                  "error")
            return redirect(url_for("verify_account", u=username))

        # Suspicious concurrent login: a valid password while the account is
        # already actively in use. Temporarily locks the account (root is only
        # warned); the owner can clear it via the SMS unlock flow.
        if _is_user_active(user["id"]):
            if _temp_lock(user, "login while an existing session was active"):
                return render_template(
                    "login.html",
                    error="A concurrent login was detected while this account was "
                          f"active, so it's locked for {LOCKOUT_DURATION // 60} minutes. "
                          "Unlock it now with the SMS code sent to your registered phone.",
                    show_unlock=True)

        # Password OK -> hand off to the MFA step. Stash a *pending* identity
        # only; the full session is not granted until TOTP succeeds.
        session.clear()
        session["pending_uid"] = user["id"]
        session["pending_name"] = user["username"]
        session["remember"] = bool(request.form.get("remember"))
        # No secret yet -> first-time enrollment; otherwise -> verify.
        session["mfa_enroll"] = not bool(user["totp_secret"])
        return redirect(url_for("mfa"))

    info = "You were signed out after 1 hour of inactivity." if request.args.get("timeout") else None
    return render_template("login.html", error=None, info=info)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    uid = session.get("pending_uid")
    if not uid:
        return redirect(url_for("login"))
    user = get_user_by_id(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    enrolling = session.get("mfa_enroll", False)

    # During enrollment we generate (once) a fresh secret held in the session
    # until the user proves they can produce a valid code.
    if enrolling:
        secret = session.get("enroll_secret")
        if not secret:
            secret = auth.new_totp_secret()
            session["enroll_secret"] = secret
    else:
        secret = user["totp_secret"]

    if request.method == "POST":
        code = request.form.get("code", "").replace(" ", "").replace("-", "")
        if not auth.verify_totp(secret, code):
            return render_template(
                "mfa.html", enrolling=enrolling, username=user["username"],
                secret=secret, otp_uri=auth.totp_uri(secret, user["username"]),
                qr_svg=_qr_svg(auth.totp_uri(secret, user["username"])),
                error="That code wasn't valid. Try the current one.")

        if enrolling:
            set_user_totp(user["id"], secret, enabled=1)

        # Promote pending -> full session.
        now = datetime.now()
        update_last_login(user["id"], now.strftime("%Y-%m-%d %H:%M:%S"))
        remember = session.get("remember", False)
        session.clear()
        session.permanent = remember
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["is_root"] = bool(user["is_root"])
        session["theme"] = user["theme"] if user["theme"] in ("dark", "light") else "dark"
        session["login_at"] = now.strftime("%Y-%m-%dT%H:%M:%S")
        session["last_active"] = time.time()
        _ACTIVE_USERS[user["id"]] = time.time()
        _audit("login", "signed in")
        return redirect(url_for("index"))

    return render_template(
        "mfa.html", enrolling=enrolling, username=user["username"],
        secret=secret, otp_uri=auth.totp_uri(secret, user["username"]),
        qr_svg=_qr_svg(auth.totp_uri(secret, user["username"])),
        error=None)


@app.route("/logout")
def logout():
    if session.get("user_id"):
        _audit("logout", "signed out")
    _ACTIVE_USERS.pop(session.get("user_id"), None)
    session.clear()
    return redirect(url_for("login"))


# =========================================================================
# CENTRAL SSO CONSUMER (v4.0)
# =========================================================================
# When this instance is enrolled in RDPShield Central, an operator clicking
# "Open Dashboard" there is redirected here with a short-lived signed token.
# We verify it with Central's PUBLIC key only — this box holds no signing key
# and therefore cannot mint a session for itself or anyone else.
#
# Everything below runs on the standard library (central_sso_verify.py); no new
# pip package is needed on the server.

# Spent token ids: jti -> expiry epoch. In-memory and single-process, the same
# approach as the SMS reset/unlock codes. A restart forgets them, but every
# token also expires within ~60s, so the replay window a restart could reopen
# is bounded by the token's own lifetime rather than by this dict.
_USED_SSO_JTI = {}


def _central_managed():
    """True when identity for this instance has been moved to Central."""
    try:
        import central_reporter
        return central_reporter.managed()
    except Exception:
        return False


def _sso_burn_jti(jti, exp):
    """Record a token id as spent. Returns False if it was already used."""
    now = time.time()
    for old, when in list(_USED_SSO_JTI.items()):
        if when < now:
            _USED_SSO_JTI.pop(old, None)
    if jti in _USED_SSO_JTI:
        return False
    _USED_SSO_JTI[jti] = exp
    return True


@app.route("/sso")
def sso():
    """Consume a Central-issued SSO token and establish a local session."""
    import central_sso_verify

    public_jwk = getattr(config, "CENTRAL_SSO_PUBLIC_KEY", "")
    agent_id = getattr(config, "CENTRAL_AGENT_ID", "")
    if not public_jwk or not agent_id:
        _audit("sso.reject", "instance not configured for Central SSO")
        return render_template("login.html", error=(
            "This server isn't configured for Central single sign-on."), info=None), 400

    try:
        claims = central_sso_verify.verify_token(
            request.args.get("token", ""),
            public_jwk,
            expected_audience=agent_id,
            expected_issuer=getattr(config, "CENTRAL_SSO_ISSUER", "rdpshield-central"),
            max_lifetime=int(getattr(config, "CENTRAL_SSO_MAX_TTL", 300)),
        )
    except central_sso_verify.SSOError as exc:
        # The reason is logged locally but never shown to the browser, so a
        # probing client learns nothing about why a token was refused.
        add_audit("central-sso", "sso.reject", str(exc), request.remote_addr or "")
        print(f"[SSO] rejected a token: {exc}")
        return render_template("login.html", error=(
            "That single sign-on link is not valid or has expired. "
            "Open this server from RDPShield Central again."), info=None), 403

    if not _sso_burn_jti(claims["jti"], claims["exp"]):
        add_audit("central-sso", "sso.replay", f"jti={claims['jti']}",
                  request.remote_addr or "")
        return render_template("login.html", error=(
            "That single sign-on link has already been used. "
            "Open this server from RDPShield Central again."), info=None), 403

    # Map the Central operator onto a local account. A shadow user is created on
    # first arrival so the existing session gate, RBAC, audit log and templates
    # all work unchanged. Its password hash is random and discarded, so the
    # account can never be used to log in locally — it exists only as the
    # identity an SSO session attaches to.
    local_role = "admin" if claims.get("role") == "admin" else "guest"
    username = f"central:{claims.get('sub', 'operator')}"[:64]
    user = get_user_by_username(username)
    if not user:
        create_user(username, auth.hash_password(secrets.token_urlsafe(32)),
                    role=local_role, mfa_enabled=0, verified=1)
        user = get_user_by_username(username)
        if not user:
            return render_template("login.html", error=(
                "Could not establish a local session for that Central operator."),
                info=None), 500
    if user.get("disabled"):
        # A local admin disabling a shadow account is a deliberate local veto
        # over Central — honour it.
        add_audit(username, "sso.reject", "shadow account disabled locally",
                  request.remote_addr or "")
        return render_template("login.html", error=(
            "That account has been disabled on this server."), info=None), 403
    if user["role"] != local_role:
        set_user_role(user["id"], local_role)

    now = datetime.now()
    update_last_login(user["id"], now.strftime("%Y-%m-%d %H:%M:%S"))
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = local_role
    session["is_root"] = False          # a Central operator is never local root
    session["via_sso"] = True
    session["theme"] = user.get("theme") if user.get("theme") in ("dark", "light") else "dark"
    session["login_at"] = now.strftime("%Y-%m-%dT%H:%M:%S")
    session["last_active"] = time.time()
    _ACTIVE_USERS[user["id"]] = time.time()
    _audit("sso.login", f"via Central as {claims.get('sub')} (jti={claims['jti']})")
    return redirect(url_for("index"))


@app.route("/sw.js")
def service_worker():
    """Serve the PWA service worker from the site root so its scope is '/'
    (a worker served from /static/ could only control /static/). Public + no
    cache so updates roll out promptly. Only registers in a secure context
    (the registration script in _pwa_head.html is gated to HTTPS/localhost)."""
    resp = send_from_directory(app.static_folder, "sw.js")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Content-Type"] = "application/javascript"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


def _qr_svg(uri):
    """Render an otpauth URI as an inline SVG QR code, if the optional
    `qrcode` library is installed. Returns None otherwise — the MFA page
    falls back to showing the secret key for manual entry.

    Uses SvgPathImage: it has a viewBox (so CSS width:100% scales it) and a
    plain <path> (no `svg:`-namespaced tags), both required to render inline
    inside HTML. The leading <?xml …?> declaration is stripped for the same
    reason — it's invalid inside an HTML body."""
    try:
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage,
                          box_size=10, border=2)
        buf = io.BytesIO()
        img.save(buf)
        svg = buf.getvalue().decode("utf-8")
        i = svg.find("<svg")
        return svg[i:] if i != -1 else svg
    except Exception as e:
        print(f"[AUTH] QR render unavailable ({e}); showing manual key only.")
        return None


# =========================================================================
# FORGOT / RESET PASSWORD (SMS code via Notify.lk)
# =========================================================================

# In-memory reset codes: username -> {"code", "expires", "tries"}.
# Lives in the dashboard process; fine for this single-process app.
_RESET_CODES = {}
_RESET_TTL = 600       # 10 minutes
_RESET_MAX_TRIES = 5


def _mask_phone(p):
    p = p or ""
    return ("•" * max(0, len(p) - 3)) + p[-3:] if p else ""


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_user_by_username(username)
        # Only send when the account exists, isn't disabled, and has a phone.
        masked = ""
        if user and not user.get("disabled") and user.get("phone"):
            code = f"{secrets.randbelow(1000000):06d}"
            _RESET_CODES[username] = {
                "code": code, "expires": time.time() + _RESET_TTL, "tries": 0,
            }
            number = _normalize_phone(user["phone"])
            ok = send_sms_to(number,
                             f"RDPShield password reset code: {code} "
                             f"(valid 10 min). If you didn't request this, ignore it.")
            masked = _mask_phone(number)
            print(f"[AUTH] Reset code SMS for {username} to {number} ok={ok}")
        # Neutral handoff regardless, to avoid leaking which accounts exist.
        session["reset_user"] = username
        return render_template("reset.html", error=None, sent=True, masked=masked)

    return render_template("forgot.html", error=None)


@app.route("/reset", methods=["GET", "POST"])
def reset():
    username = session.get("reset_user")
    if not username:
        return redirect(url_for("forgot"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        new_pw = request.form.get("password", "")
        rec = _RESET_CODES.get(username)

        if not rec or time.time() > rec["expires"]:
            _RESET_CODES.pop(username, None)
            return render_template("reset.html", sent=True, masked="",
                                   error="That code has expired. Request a new one.")
        rec["tries"] += 1
        if rec["tries"] > _RESET_MAX_TRIES:
            _RESET_CODES.pop(username, None)
            return render_template("reset.html", sent=True, masked="",
                                   error="Too many attempts. Request a new code.")
        if code != rec["code"]:
            return render_template("reset.html", sent=True, masked="",
                                   error="Incorrect code. Try again.")
        if not _password_ok(new_pw):
            return render_template("reset.html", sent=True, masked="",
                                   error=f"Choose a password of at least {MIN_PASSWORD_LEN} characters.")

        user = get_user_by_username(username)
        if user:
            update_user_password(user["id"], auth.hash_password(new_pw))
            print(f"[AUTH] Password reset completed for {username}")
        _RESET_CODES.pop(username, None)
        session.pop("reset_user", None)
        flash("Password updated. Sign in with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("reset.html", sent=True, masked="", error=None)


# =========================================================================
# UNLOCK A TEMPORARILY-LOCKED ACCOUNT (SMS code to the registered phone)
# =========================================================================
# Proves the requester owns the account's phone, then clears the in-memory
# security lockout so the owner can sign in normally (still needs password +
# MFA). It deliberately does NOT re-enable an admin-DISABLED account — that
# stays under admin control. Codes are in-memory, short-lived, single-use.
_UNLOCK_CODES = {}
_UNLOCK_TTL = 600        # 10 minutes
_UNLOCK_MAX_TRIES = 5


@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_user_by_username(username)
        masked = ""
        # Only text a code to a real, non-disabled account that has a phone.
        # (A disabled account can't be self-unlocked — that's an admin action.)
        if user and not user.get("disabled") and user.get("phone"):
            code = f"{secrets.randbelow(1000000):06d}"
            _UNLOCK_CODES[username] = {
                "code": code, "expires": time.time() + _UNLOCK_TTL, "tries": 0,
            }
            number = _normalize_phone(user["phone"])
            ok = send_sms_to(number,
                             f"RDPShield account unlock code: {code} "
                             f"(valid 10 min). If you didn't request this, ignore it.")
            masked = _mask_phone(number)
            print(f"[AUTH] Unlock code SMS for {username} to {number} ok={ok}")
        # Neutral handoff regardless, to avoid leaking which accounts exist.
        session["unlock_user"] = username
        return render_template("unlock.html", sent=True, masked=masked, error=None)

    return render_template("unlock.html", sent=False, masked="", error=None)


@app.route("/unlock/verify", methods=["POST"])
def unlock_verify():
    username = session.get("unlock_user")
    if not username:
        return redirect(url_for("unlock"))

    code = request.form.get("code", "").strip()
    rec = _UNLOCK_CODES.get(username)

    if not rec or time.time() > rec["expires"]:
        _UNLOCK_CODES.pop(username, None)
        return render_template("unlock.html", sent=True, masked="",
                               error="That code has expired. Request a new one.")
    rec["tries"] += 1
    if rec["tries"] > _UNLOCK_MAX_TRIES:
        _UNLOCK_CODES.pop(username, None)
        return render_template("unlock.html", sent=True, masked="",
                               error="Too many attempts. Request a new code.")
    if code != rec["code"]:
        return render_template("unlock.html", sent=True, masked="",
                               error="Incorrect code. Try again.")

    # Verified the phone owner: clear the temporary security lockout only.
    _LOCKED_UNTIL.pop(username, None)
    _FAILED_LOGINS.pop(username, None)
    _UNLOCK_CODES.pop(username, None)
    session.pop("unlock_user", None)
    user = get_user_by_username(username)
    if user:
        _ACTIVE_USERS.pop(user["id"], None)  # let the owner start a fresh session
        add_audit(username, "security.unlock", "unlocked via SMS code",
                  request.remote_addr or "")
    print(f"[AUTH] Account unlock completed for {username}")
    flash("Account unlocked. Sign in with your password.", "success")
    return redirect(url_for("login"))


# =========================================================================
# USER MANAGEMENT (admin only)
# =========================================================================

# --- Phone-ownership verification + RBAC for user management ---------------
_VERIFY_TTL = 1800   # a verification code is valid for 30 minutes


def _can_manage(actor, target):
    """RBAC for user-management actions on `target` by `actor`:
      - root admin           -> may manage anyone (incl. root / self)
      - admin (non-root)      -> may manage SELF and GUEST users only
      - guest                 -> never reaches these routes (admin_required)
    """
    if not actor or not target:
        return False
    if actor.get("is_root"):
        return True
    if target.get("is_root"):
        return False
    if target.get("role") == "admin" and target.get("id") != actor.get("id"):
        return False
    return True


def _issue_verification(user, purpose):
    """Mark `user` unverified and text a fresh 6-digit code to their phone.
    Returns (sent, masked_phone). If the user has no phone the account is left
    as-is (caller decides) and (False, "") is returned — we can't gate an
    account we can't text."""
    phone = _normalize_phone(user.get("phone") or "")
    if not phone:
        return False, ""
    code = f"{secrets.randbelow(1000000):06d}"
    set_user_verify_code(user["id"], auth.hash_password(code),
                         time.time() + _VERIFY_TTL, purpose)
    if purpose == "new_user":
        body = (f"RDPShield: verify your new account. Code: {code} (valid 30 min). "
                f"Enter it on the Verify page to activate your account.")
    else:
        body = (f"RDPShield: your account credentials were changed. Code: {code} "
                f"(valid 30 min). Enter it on the Verify page to re-activate your account.")
    ok = send_sms_to(phone, body)
    print(f"[AUTH] Verification code ({purpose}) for {user['username']} -> {phone} ok={ok}")
    return ok, _mask_phone(phone)


@app.route("/users")
@auth.admin_required
def users_page():
    me = get_user_by_id(session.get("user_id"))
    rows = list_users()
    # Pre-compute, per row, whether the current actor may manage it (drives the
    # template's show/hide of the change / MFA / delete / disable actions).
    for u in rows:
        u["can_manage"] = _can_manage(me, u)
    return render_template("users.html", users=rows, me=me,
                           i_am_root=bool(me and me.get("is_root")))


@app.route("/users/add", methods=["POST"])
@auth.admin_required
def users_add():
    actor = get_user_by_id(session.get("user_id"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    phone = _normalize_phone(request.form.get("phone", "")) or None
    role = request.form.get("role", "guest")
    if role not in ("admin", "guest"):
        role = "guest"
    # Only the root admin may create admin accounts; admins create guests only.
    if role == "admin" and not (actor and actor.get("is_root")):
        flash("Only the root admin can create admin accounts.", "error")
        return redirect(url_for("users_page"))
    if username and not _password_ok(password):
        flash(f"Password must be at least {MIN_PASSWORD_LEN} characters.", "error")
        return redirect(url_for("users_page"))
    # A mobile number is required: the new user must verify a code before login.
    if username and password and not phone:
        flash("A mobile number is required — the new user verifies a code before first login.",
              "error")
        return redirect(url_for("users_page"))
    if username and password:
        uid = create_user(username, auth.hash_password(password), role=role,
                          phone=phone, verified=0)
        if not uid:
            flash(f"Username '{username}' already exists.", "error")
        else:
            new_user = get_user_by_id(uid)
            sent, masked = _issue_verification(new_user, "new_user")
            _audit("user.add", f"{username} ({role}); pending verification")
            print(f"[AUTH] Created {role} user (pending verification): {username}")
            if sent:
                flash(f"Created '{username}'. A verification code was texted to {masked}; "
                      f"they must verify before they can sign in.", "success")
            else:
                flash(f"Created '{username}', but the verification SMS failed. Use "
                      f"'Resend code', or check the number / SMS settings.", "error")
    return redirect(url_for("users_page"))


def _i_am_root():
    me = get_user_by_id(session.get("user_id"))
    return bool(me and me.get("is_root"))


@app.route("/users/delete/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_delete(user_id):
    target = get_user_by_id(user_id)
    # Guard rails: no self-delete, no removing the last admin, and the ROOT
    # admin can only be deleted by root (i.e. never by a secondary admin).
    if not target:
        pass
    elif user_id == session.get("user_id"):
        flash("You can't delete your own account while signed in.", "error")
    elif not _can_manage(get_user_by_id(session.get("user_id")), target):
        flash("You don't have permission to delete that user.", "error")
    elif target["role"] == "admin" and count_admins() <= 1:
        flash("Can't delete the last remaining admin.", "error")
    else:
        delete_user(user_id)
        _audit("user.delete", target["username"])
        print(f"[AUTH] Deleted user: {target['username']}")
    return redirect(url_for("users_page"))


@app.route("/users/reset_mfa/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_reset_mfa(user_id):
    """Clear a user's TOTP so they re-enroll on next login (lost-phone case).
    The affected user must then verify an SMS code before signing in again."""
    actor = get_user_by_id(session.get("user_id"))
    target = get_user_by_id(user_id)
    if not target:
        return redirect(url_for("users_page"))
    if not _can_manage(actor, target):
        flash("You don't have permission to change that user's MFA.", "error")
        return redirect(url_for("users_page"))
    set_user_totp(user_id, None, enabled=0)
    _audit("user.reset_mfa", target["username"])
    print(f"[AUTH] Reset MFA for user: {target['username']}")
    sent, masked = _issue_verification(target, "cred_change")
    if sent:
        flash(f"Reset MFA for {target['username']}. They must verify the code sent to "
              f"{masked}, then re-enrol their authenticator on next sign-in.", "success")
    else:
        flash(f"Reset MFA for {target['username']} (re-enrols on next sign-in). "
              f"No phone on file, so no verification code was sent.", "success")
    return redirect(url_for("users_page"))


@app.route("/users/update/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_update(user_id):
    """Admin/root sets a new password and/or phone for a user (blank = unchanged).
    A password change requires the affected user to re-verify by SMS code."""
    actor = get_user_by_id(session.get("user_id"))
    target = get_user_by_id(user_id)
    if not target:
        return redirect(url_for("users_page"))
    if not _can_manage(actor, target):
        flash("You don't have permission to change that user.", "error")
        return redirect(url_for("users_page"))
    new_pw = request.form.get("password", "")
    phone = _normalize_phone(request.form.get("phone", ""))
    changed = []
    if new_pw:
        if not _password_ok(new_pw):
            flash(f"Password must be at least {MIN_PASSWORD_LEN} characters.", "error")
            return redirect(url_for("users_page"))
        update_user_password(user_id, auth.hash_password(new_pw))
        changed.append("password")
    if phone != (target.get("phone") or ""):
        update_user_phone(user_id, phone or None)
        changed.append("phone")
    if not changed:
        return redirect(url_for("users_page"))
    _audit("user.update", f"{target['username']}: {', '.join(changed)}")
    print(f"[AUTH] Updated {target['username']}: {', '.join(changed)}")
    if "password" in changed:
        # Re-read (phone may have changed in this request) then gate by SMS code.
        target = get_user_by_id(user_id)
        sent, masked = _issue_verification(target, "cred_change")
        if sent:
            flash(f"Updated {target['username']}. They must verify the code sent to "
                  f"{masked} before they can sign in again.", "success")
        else:
            flash(f"Updated {target['username']} ({', '.join(changed)}). No phone on "
                  f"file, so the change applies without a verification code.", "success")
    else:
        flash(f"Updated {target['username']} ({', '.join(changed)}).", "success")
    return redirect(url_for("users_page"))


@app.route("/users/disable/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_disable(user_id):
    target = get_user_by_id(user_id)
    if not target:
        pass
    elif user_id == session.get("user_id"):
        flash("You can't disable your own account.", "error")
    elif not _can_manage(get_user_by_id(session.get("user_id")), target):
        flash("You don't have permission to disable that user.", "error")
    elif target["role"] == "admin" and count_admins() <= 1:
        flash("Can't disable the last remaining admin.", "error")
    else:
        set_user_disabled(user_id, True)
        _audit("user.disable", target["username"])
        print(f"[AUTH] Disabled user: {target['username']}")
    return redirect(url_for("users_page"))


@app.route("/users/enable/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_enable(user_id):
    target = get_user_by_id(user_id)
    if target:
        set_user_disabled(user_id, False)
        _audit("user.enable", target["username"])
        print(f"[AUTH] Enabled user: {target['username']}")
    return redirect(url_for("users_page"))


@app.route("/users/resend_verify/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_resend_verify(user_id):
    """Re-send a pending user's verification code (subject to the same RBAC)."""
    actor = get_user_by_id(session.get("user_id"))
    target = get_user_by_id(user_id)
    if not target or not _can_manage(actor, target):
        flash("You can't resend a code for that user.", "error")
        return redirect(url_for("users_page"))
    if target.get("verified"):
        flash(f"{target['username']} is already verified.", "error")
        return redirect(url_for("users_page"))
    purpose = target.get("verify_purpose") or "new_user"
    sent, masked = _issue_verification(target, purpose)
    flash(f"Verification code resent to {masked}." if sent
          else "Couldn't send the code — check the phone number / SMS settings.",
          "success" if sent else "error")
    return redirect(url_for("users_page"))


@app.route("/verify", methods=["GET", "POST"])
def verify_account():
    """Public page where a pending user enters the SMS code to activate (or
    re-activate, after a credential change) their account. No login required."""
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        code = request.form.get("code", "").strip()
        user = get_user_by_username(username)
        # Neutral error for a missing user / bad code (no account enumeration).
        if not user or user.get("verified"):
            if user and user.get("verified"):
                flash("That account is already verified — please sign in.", "success")
                return redirect(url_for("login"))
            return render_template("verify.html", username=username,
                                   error="Incorrect username or code.")
        if not user.get("verify_code_hash") or time.time() > (user.get("verify_expires") or 0):
            return render_template("verify.html", username=username,
                                   error="That code has expired. Ask an administrator to resend it.")
        if not auth.verify_password(user["verify_code_hash"], code):
            return render_template("verify.html", username=username,
                                   error="Incorrect username or code.")
        clear_user_verify(user["id"])
        add_audit(username, "user.verified",
                  f"phone verified ({user.get('verify_purpose') or 'new_user'})",
                  request.remote_addr or "")
        print(f"[AUTH] Account verified: {username}")
        flash("Account verified. You can now sign in.", "success")
        return redirect(url_for("login"))
    return render_template("verify.html", username=request.args.get("u", ""), error=None)


# =========================================================================
# THEME (per-user, any logged-in user)
# =========================================================================

@app.route("/theme/<mode>", methods=["POST"])
@auth.login_required
def set_theme(mode):
    mode = "light" if mode == "light" else "dark"
    set_user_theme(session.get("user_id"), mode)
    session["theme"] = mode
    return redirect(_safe_next())


# =========================================================================
# SETTINGS (admin only): API keys, alert recipients, SMS types,
# data retention, audit log
# =========================================================================

# Masked display of a secret; never send the full value to the browser.
def _mask_key(v):
    if not v:
        return ""
    v = str(v)
    return ("•" * max(0, len(v) - 4)) + v[-4:] if len(v) > 4 else "••••"


@app.route("/settings")
@auth.admin_required
def settings_page():
    st = get_all_settings()

    def rotated(key):
        return st.get(key, {}).get("updated_at")

    keys = {
        "virustotal": {"masked": _mask_key(settings.vt_api_key()),
                       "rotated": rotated("vt_api_key")},
        "abuseipdb":  {"masked": _mask_key(settings.abuseipdb_key()),
                       "rotated": rotated("abuseipdb_api_key")},
        "notify":     {"masked": _mask_key(settings.notify_api_key()),
                       "user_id": settings.notify_user_id(),
                       "sender_id": settings.notify_sender_id(),
                       "rotated": rotated("notify_api_key")},
    }
    return render_template(
        "settings.html",
        keys=keys,
        recipients=list_alert_recipients(),
        all_sms_types=settings.ALL_SMS_TYPES,
        active_sms_types=settings.sms_alert_types(),
        retention_days=settings.retention_days(),
        audit=get_audit(limit=5),
        key_status=settings.key_rotation_status(),
        rotation_interval=settings.rotation_interval_days(),
        rotation_enabled=settings.reminders_enabled(),
        reports=_list_reports()[:5],
        report_retention_days=settings.report_retention_days(),
    )


@app.route("/settings/keys", methods=["POST"])
@auth.admin_required
def settings_keys():
    """Rotate API keys. Only non-blank fields are written (blank = unchanged);
    a literal '-' clears a key (revert to config.py)."""
    mapping = {
        "vt_api_key": "VirusTotal",
        "abuseipdb_api_key": "AbuseIPDB",
        "notify_api_key": "Notify.lk API key",
        "notify_user_id": "Notify.lk user ID",
        "notify_sender_id": "Notify.lk sender ID",
    }
    rotated = []
    for field, label in mapping.items():
        val = request.form.get(field, "").strip()
        if not val:
            continue
        set_setting(field, "" if val == "-" else val)
        rotated.append(label)
    if rotated:
        _audit("settings.keys", "rotated: " + ", ".join(rotated))
        flash("Updated: " + ", ".join(rotated) + ".", "success")
    return redirect(url_for("settings_page"))


@app.route("/settings/recipients/add", methods=["POST"])
@auth.admin_required
def settings_recipient_add():
    label = request.form.get("label", "").strip()
    phone = _normalize_phone(request.form.get("phone", ""))
    if phone:
        add_alert_recipient(label, phone)
        _audit("settings.recipient_add", f"{label or '(no label)'} {phone}")
        flash(f"Added alert recipient {phone}.", "success")
    else:
        flash("Enter a valid phone number.", "error")
    return redirect(url_for("settings_page"))


@app.route("/settings/recipients/update/<int:rid>", methods=["POST"])
@auth.admin_required
def settings_recipient_update(rid):
    label = request.form.get("label", "").strip()
    phone = _normalize_phone(request.form.get("phone", ""))
    active = bool(request.form.get("active"))
    if phone:
        update_alert_recipient(rid, label, phone, active)
        _audit("settings.recipient_update", f"#{rid} {phone} active={active}")
        flash("Recipient updated.", "success")
    return redirect(url_for("settings_page"))


@app.route("/settings/recipients/delete/<int:rid>", methods=["POST"])
@auth.admin_required
def settings_recipient_delete(rid):
    delete_alert_recipient(rid)
    _audit("settings.recipient_delete", f"#{rid}")
    flash("Recipient removed.", "success")
    return redirect(url_for("settings_page"))


@app.route("/settings/sms_types", methods=["POST"])
@auth.admin_required
def settings_sms_types():
    chosen = [t for t in settings.ALL_SMS_TYPES if request.form.get("type_" + t)]
    settings.set_sms_alert_types(chosen)
    _audit("settings.sms_types", ", ".join(chosen) or "(none)")
    flash("SMS alert types saved.", "success")
    return redirect(url_for("settings_page"))


@app.route("/settings/retention", methods=["POST"])
@auth.admin_required
def settings_retention():
    try:
        days = max(0, int(request.form.get("retention_days", "0")))
    except ValueError:
        days = 0
    set_setting("retention_days", str(days))
    # Re-arm the auto-purge so the new policy is applied at the next hourly tick.
    set_setting("last_retention_purge", "")
    _audit("settings.retention", f"{days} days")
    if days > 0:
        flash(f"Retention set to {days} days. Older failed logins / alerts / "
              f"geo events are now auto-purged daily (first run within the hour).", "success")
    else:
        flash("Retention set to keep data forever (auto-purge off).", "success")
    return redirect(url_for("settings_page"))


@app.route("/settings/purge", methods=["POST"])
@auth.admin_required
def settings_purge():
    try:
        days = max(1, int(request.form.get("days", "0")))
    except ValueError:
        days = 0
    if days:
        counts = purge_old_data(days)
        total = sum(counts.values())
        _audit("settings.purge", f">{days}d removed {counts}")
        flash(f"Purged {total} rows older than {days} days "
              f"({counts}).", "success")
    else:
        flash("Enter a day count to purge.", "error")
    return redirect(url_for("settings_page"))


@app.route("/settings/rotation", methods=["POST"])
@auth.admin_required
def settings_rotation():
    try:
        days = max(1, int(request.form.get("interval", "2")))
    except ValueError:
        days = 2
    enabled = bool(request.form.get("enabled"))
    set_setting("key_rotation_interval_days", str(days))
    set_setting("key_rotation_reminders", "1" if enabled else "0")
    _audit("settings.rotation", f"interval={days}d enabled={enabled}")
    flash("Key-rotation reminder settings saved.", "success")
    return redirect(url_for("settings_page"))


# --- Daily reports (list / generate / download) ---
def _list_reports():
    """Report JSON files on disk, newest first."""
    try:
        names = [f for f in os.listdir(REPORT_DIR)
                 if f.startswith("rdpshield_report_") and f.endswith(".json")]
    except FileNotFoundError:
        return []
    out = []
    for f in sorted(names, reverse=True):
        try:
            st = os.stat(os.path.join(REPORT_DIR, f))
            out.append({
                "name": f,
                "date": f.replace("rdpshield_report_", "").replace(".json", ""),
                "size_kb": round(st.st_size / 1024, 1),
                "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
        except OSError:
            pass
    return out


@app.route("/reports/generate", methods=["POST"])
@auth.admin_required
def reports_generate():
    day = datetime.now().strftime("%Y-%m-%d")
    try:
        _, s = write_report(day)
        _audit("report.generate", day)
        flash(f"Report for {day} generated — {s['total_failed_logins']} failed logins, "
              f"{s['total_alerts']} alerts, {s['total_blocks']} blocks.", "success")
    except Exception as e:
        flash(f"Report generation failed: {e}", "error")
    return redirect(url_for("settings_page"))


def _valid_report_name(name):
    """True only for our own report filenames (blocks path traversal)."""
    return ("/" not in name and "\\" not in name
            and name.startswith("rdpshield_report_") and name.endswith(".json"))


@app.route("/reports/download/<name>")
@auth.admin_required
def reports_download(name):
    # Only our report files; block path traversal.
    if not _valid_report_name(name):
        return "Not found", 404
    return send_from_directory(REPORT_DIR, name, as_attachment=True)


@app.route("/reports/delete/<name>", methods=["POST"])
@auth.admin_required
def reports_delete(name):
    if not _valid_report_name(name):
        return "Not found", 404
    path = os.path.join(REPORT_DIR, name)
    try:
        os.remove(path)
        _audit("report.delete", name)
        flash(f"Deleted report {name}.", "success")
    except FileNotFoundError:
        flash(f"Report {name} no longer exists.", "error")
    except OSError as e:
        flash(f"Couldn't delete {name}: {e}", "error")
    # A delete from the full-history page returns there; otherwise to Settings.
    return redirect(_safe_next(url_for("settings_page")))


@app.route("/reports/all")
@auth.admin_required
def reports_all():
    """Full daily-report history in its own tab (mirrors the audit 'View all')."""
    return render_template("reports.html", reports=_list_reports())


@app.route("/settings/report_retention", methods=["POST"])
@auth.admin_required
def settings_report_retention():
    try:
        days = max(0, int(request.form.get("report_retention_days", "0")))
    except ValueError:
        days = 0
    set_setting("report_retention_days", str(days))
    _audit("settings.report_retention", f"{days} days")
    if days > 0:
        flash(f"Report retention set to {days} days — older report files are "
              f"auto-deleted daily (first run within the hour).", "success")
    else:
        flash("Report retention set to keep reports forever.", "success")
    return redirect(url_for("settings_page"))


# --- background reminder: nudge admins to rotate API keys every N days -----
def _elapsed_days_since(setting_key):
    """Days since the UTC timestamp stored in `setting_key`, or None if unset."""
    last = get_setting(setting_key)
    if not last:
        return None
    try:
        dt = datetime.strptime(last[:19], "%Y-%m-%d %H:%M:%S")
        return (datetime.utcnow() - dt).total_seconds() / 86400.0
    except ValueError:
        return None


def _maintenance_loop():
    """Daemon thread (hourly): API-key rotation reminders + automatic data
    retention purge. Both throttled via stored timestamps so restarts don't
    re-trigger them."""
    while True:
        # --- API-key rotation reminder (every `interval` days) ---
        try:
            if settings.reminders_enabled():
                interval = settings.rotation_interval_days()
                elapsed = _elapsed_days_since("last_rotation_reminder")
                if elapsed is None or elapsed >= interval:
                    parts = []
                    for s in settings.key_rotation_status():
                        parts.append(f"{s['label']}: "
                                     + (f"{s['age_days']}d" if s['age_days'] is not None
                                        else "not rotated"))
                    _notify_root("RDPShield reminder: review & rotate your API keys "
                                 "in the dashboard (Settings). " + "; ".join(parts))
                    set_setting("last_rotation_reminder",
                                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
                    print("[REMINDER] API-key rotation reminder sent.")
        except Exception as e:
            print(f"[REMINDER] loop error: {e}")

        # --- Automatic data retention purge (once per day) ---
        try:
            days = settings.retention_days()
            if days > 0:
                elapsed = _elapsed_days_since("last_retention_purge")
                if elapsed is None or elapsed >= 1:
                    counts = purge_old_data(days)
                    total = sum(counts.values())
                    set_setting("last_retention_purge",
                                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
                    add_audit("system", "retention.auto_purge",
                              f">{days}d removed {total} ({counts})", "")
                    print(f"[RETENTION] Auto-purged {total} rows older than {days}d ({counts}).")
        except Exception as e:
            print(f"[RETENTION] loop error: {e}")

        # --- Daily JSON report (once per calendar day, self-contained) ---
        try:
            today = datetime.now().strftime("%Y-%m-%d")
            if get_setting("last_report_run") != today:
                yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
                write_report(yesterday)   # finalise the completed day
                write_report(today)       # current-day snapshot
                set_setting("last_report_run", today)
                add_audit("system", "report.generate", f"{yesterday}, {today}", "")
                print(f"[REPORT] Generated daily reports for {yesterday} and {today}.")
        except Exception as e:
            print(f"[REPORT] loop error: {e}")

        # --- Report-file retention (delete report JSONs older than N days) ---
        try:
            rdays = settings.report_retention_days()
            if rdays > 0:
                cutoff = time.time() - rdays * 86400
                removed = 0
                for r in _list_reports():
                    path = os.path.join(REPORT_DIR, r["name"])
                    try:
                        if os.path.getmtime(path) < cutoff:
                            os.remove(path)
                            removed += 1
                    except OSError:
                        pass
                if removed:
                    add_audit("system", "report.retention_purge",
                              f">{rdays}d removed {removed} report file(s)", "")
                    print(f"[REPORT] Retention purge removed {removed} report(s) older than {rdays}d.")
        except Exception as e:
            print(f"[REPORT] retention error: {e}")

        time.sleep(3600)  # re-check hourly


# =========================================================================
# MAIN DASHBOARD PAGE
# =========================================================================

# Number of rows each growing table shows inline before "View all".
DASHBOARD_PREVIEW = 5


@app.route("/")
def index():
    """Main dashboard page."""
    stats = get_dashboard_stats()
    alerts = get_recent_alerts(limit=DASHBOARD_PREVIEW)
    blocked = get_blocked_ips(limit=DASHBOARD_PREVIEW)
    recent = get_recent_failed_logins(limit=DASHBOARD_PREVIEW)
    trend = get_failed_login_trend(days=14)
    alert_breakdown_30d = get_alert_type_breakdown(days=30)
    top_countries = get_top_attacker_countries(limit=20)

    # API-key rotation reminder banner (admins only, when enabled).
    key_status = []
    if session.get("role") == "admin" and settings.reminders_enabled():
        key_status = settings.key_rotation_status()

    return render_template(
        "index.html",
        stats=stats,
        alerts=alerts,
        blocked=blocked,
        recent=recent,
        trend=trend,
        alert_breakdown_30d=alert_breakdown_30d,
        top_countries=top_countries,
        key_status=key_status,
        rotation_interval=settings.rotation_interval_days(),
    )


@app.route("/ml")
def ml_page():
    """ML Threat Scoring page: model status + a live, sortable table of the
    riskiest IPs by learned threat score. Renders fine before any model is
    trained (the template shows a 'no model yet' state)."""
    return render_template("ml.html", active="ml", info=ml_model.model_info())


# =========================================================================
# FULL-LIST PAGES (opened in a new tab from the "View all" buttons)
# =========================================================================

# key -> standalone list page config. `renderer` matches a TABLE_RENDERERS
# entry in static/js/tables.js; `api` is the JSON endpoint it pages through.
LIST_VIEWS = {
    "alerts":           {"title": "All Alerts",           "renderer": "alerts",       "api": "/api/alerts?limit=2000",                       "back": "/"},
    "blocked":          {"title": "All Blocked IPs",       "renderer": "blocked",      "api": "/api/blocked?limit=2000",                      "back": "/"},
    "events":           {"title": "Recent Failed Logins",  "renderer": "recent",       "api": "/api/events?limit=2000",                       "back": "/"},
    "geo_events":       {"title": "Geolocation Event Log", "renderer": "geo",          "api": "/api/geo_events?category=geo&limit=2000",      "back": "/geo"},
    "whitelist_events": {"title": "Whitelist Event Log",   "renderer": "geo",          "api": "/api/geo_events?category=whitelist&limit=2000", "back": "/geo"},
    "yara_scans":       {"title": "Scan History",          "renderer": "yara_history", "api": "/api/yara_scans?limit=2000",                   "back": "/yara"},
    "audit":            {"title": "Admin Audit Log",        "renderer": "audit",        "api": "/api/audit?limit=2000",                       "back": "/settings"},
}

# List views that require admin (sensitive data).
ADMIN_LIST_VIEWS = {"audit"}


@app.route("/list/<key>")
def list_view(key):
    """Generic clean, searchable, paginated full-list page in its own tab."""
    cfg = LIST_VIEWS.get(key)
    if not cfg:
        return "Unknown list", 404
    if key in ADMIN_LIST_VIEWS and session.get("role") != "admin":
        return auth._deny()
    return render_template(
        "list.html",
        key=key,
        title=cfg["title"],
        renderer=cfg["renderer"],
        api_url=cfg["api"],
        back_url=cfg["back"],
    )


# =========================================================================
# GEOLOCATION SETTINGS PAGE
# =========================================================================

@app.route("/geo")
def geo_settings():
    """
    Advanced Security page.
    Two sections — Geolocation Settings (allow-anywhere / country-list) and
    Whitelist Settings (whitelist-only) — each with its own event log + stats.
    """
    mode = get_geo_mode()
    countries = get_allowed_countries()
    allowed_ips = get_allowed_ips()

    geo_events = get_geo_events(limit=50, category="geo")
    whitelist_events = get_geo_events(limit=50, category="whitelist")
    geo_cat_stats = get_geo_category_stats("geo")
    whitelist_cat_stats = get_geo_category_stats("whitelist")
    active_blocked_ips = [b["ip_address"] for b in get_blocked_ips()]

    return render_template(
        "geo.html",
        mode=mode,
        countries=countries,
        allowed_ips=allowed_ips,
        geo_events=geo_events,
        whitelist_events=whitelist_events,
        geo_cat_stats=geo_cat_stats,
        whitelist_cat_stats=whitelist_cat_stats,
        active_blocked_ips=active_blocked_ips,
        country_suggestions=COUNTRY_NAMES,
    )


@app.route("/geo/set_mode", methods=["POST"])
@auth.admin_required
def geo_set_mode():
    """
    Handle the 'Apply Now' button — sets the geo-blocking mode.
    The mode comes from the radio button selection on the form.
    """
    mode = request.form.get("geo_mode", "allow_anywhere")
    set_geo_mode(mode)
    _audit("geo.set_mode", mode)
    print(f"[DASHBOARD] Geo mode changed to: {mode}")
    return redirect(url_for("geo_settings"))


@app.route("/geo/add_country", methods=["POST"])
@auth.admin_required
def geo_add_country():
    """
    Handle the 'Add Country' button.
    Country name comes from the text input field.
    """
    country = request.form.get("country_name", "").strip()
    if country:
        add_allowed_country(country)
        print(f"[DASHBOARD] Added allowed country: {country}")
    return redirect(url_for("geo_settings"))


@app.route("/geo/remove_country/<country_name>", methods=["POST"])
@auth.admin_required
def geo_remove_country(country_name):
    """Handle the 'Remove' button next to a country."""
    remove_allowed_country(country_name)
    print(f"[DASHBOARD] Removed allowed country: {country_name}")
    return redirect(url_for("geo_settings"))


@app.route("/geo/add_ip", methods=["POST"])
@auth.admin_required
def geo_add_ip():
    """
    Handle the 'Add IP' button.
    IP address and description come from the form fields.
    """
    ip = request.form.get("ip_address", "").strip()
    desc = request.form.get("description", "").strip()
    if ip:
        add_allowed_ip(ip, desc)
        print(f"[DASHBOARD] Added allowed IP: {ip}")
    return redirect(url_for("geo_settings"))


@app.route("/geo/remove_ip/<ip_address>", methods=["POST"])
@auth.admin_required
def geo_remove_ip(ip_address):
    """Handle the 'Remove' button next to an allowed IP."""
    remove_allowed_ip(ip_address)
    print(f"[DASHBOARD] Removed allowed IP: {ip_address}")
    return redirect(url_for("geo_settings"))


# =========================================================================
# EXISTING API ENDPOINTS + UNBLOCK
# =========================================================================

def _req_limit(default):
    """Read a ?limit= query param, clamped to a sane range."""
    try:
        return max(1, min(int(request.args.get("limit", default)), 5000))
    except (TypeError, ValueError):
        return default


@app.route("/api/stats")
def api_stats():
    return jsonify(get_dashboard_stats())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_recent_alerts(limit=_req_limit(50)))


@app.route("/api/blocked")
def api_blocked():
    return jsonify(get_blocked_ips(limit=_req_limit(100)))


@app.route("/api/events")
def api_events():
    return jsonify(get_recent_failed_logins(limit=_req_limit(100)))


@app.route("/api/geo_events")
def api_geo_events():
    """Geo / whitelist event log as JSON. Each row is annotated with
    `is_blocked` so the full-list view knows whether to offer Unblock."""
    category = request.args.get("category")  # "geo" | "whitelist" | None
    events = get_geo_events(limit=_req_limit(100), category=category)
    active = {b["ip_address"] for b in get_blocked_ips()}
    for e in events:
        e["is_blocked"] = e.get("source_ip") in active
    return jsonify(events)


@app.route("/api/yara_scans")
def api_yara_scans():
    return jsonify(get_yara_history(limit=_req_limit(200)))


@app.route("/api/audit")
@auth.admin_required
def api_audit():
    return jsonify(get_audit(limit=_req_limit(200)))


@app.route("/api/geo_stats")
def api_geo_stats():
    return jsonify(get_geo_stats())


@app.route("/api/trend")
def api_trend():
    return jsonify(get_failed_login_trend(days=14))


@app.route("/api/alert_breakdown")
def api_alert_breakdown():
    return jsonify(get_alert_type_breakdown(days=30))


@app.route("/api/attack_map")
def api_attack_map():
    return jsonify(get_attack_map_points(limit=500))


@app.route("/api/campaigns")
def api_campaigns():
    """Long-horizon campaign tracker rows (worst first) for the dashboard."""
    return jsonify(get_campaigns(limit=_req_limit(50)))


@app.route("/api/threat_scores")
def api_threat_scores():
    """ML per-IP threat scores (riskiest first). Empty list if no model is
    trained yet. Cached inside ml_model so the auto-refresh is cheap."""
    return jsonify(ml_model.score_active_ips(limit=_req_limit(200)))


@app.route("/api/ml_info")
def api_ml_info():
    """Model metadata (trained_at, sample counts, ROC-AUC, feature importance)
    for the ML page header."""
    return jsonify(ml_model.model_info())


@app.route("/unblock/<ip_address>", methods=["POST"])
@auth.admin_required
def unblock(ip_address):
    """Manually unblock an IP address. Returns to the page it was triggered
    from (the dashboard or the Advanced Security event logs)."""
    success = unblock_ip(ip_address)
    if success:
        _audit("ip.unblock", ip_address)
        print(f"[DASHBOARD] Manually unblocked {ip_address}")
    return redirect(_safe_next())


@app.route("/block", methods=["POST"])
@auth.admin_required
def block():
    """
    Manually block an IP address from the dashboard.

    Geo-enriches the IP, blocks it at the firewall, launches a post-block
    YARA disk scan, and logs an alert (so it appears in Top Attacker Countries
    and Recent Alerts). Manual blocks deliberately do NOT send an SMS — only
    automatic detections do.
    """
    ip = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "").strip() or "Manually blocked from dashboard"
    if ip:
        enrichment, _ = process_alert_enrichment(ip)
        success = block_ip(ip, reason=reason)
        if success:
            # No block_ctx and a non-"post_block" label => YARA runs but no SMS.
            yara_scheduler.trigger_scan_async("manual_block:" + ip)
            log_alert(
                alert_type="manual_block",
                source_ip=ip,
                description=reason,
                geo_country=enrichment.get("geo_country", ""),
                geo_city=enrichment.get("geo_city", ""),
                abuse_score=enrichment.get("abuse_score", 0),
                blocked=1,
                sms_sent=0,
            )
            _audit("ip.block", f"{ip} ({reason})")
            print(f"[DASHBOARD] Manually blocked {ip} ({reason})")
        else:
            print(f"[DASHBOARD] Could not block {ip} (whitelisted, already blocked, or disabled)")
    return redirect(_safe_next())


# =========================================================================
# CSV EXPORT (logs & history -> .csv for offline analysis)
# =========================================================================
# Available to admins AND guests (guests = view + export). Each entry defines
# the columns to emit and a fetcher that returns the full dataset as dict rows.

def _export_alerts():
    return get_recent_alerts(limit=100000)

def _export_blocked():
    return get_blocked_ips(limit=100000)

def _export_events():
    return get_recent_failed_logins(limit=100000)

def _export_geo():
    return get_geo_events(limit=100000, category="geo")

def _export_whitelist():
    return get_geo_events(limit=100000, category="whitelist")

def _export_yara():
    return get_yara_history(limit=100000)


def _export_audit():
    return get_audit(limit=100000)


EXPORT_VIEWS = {
    "alerts":           {"file": "rdpshield_alerts",          "fetch": _export_alerts,
                         "cols": ["timestamp", "alert_type", "type_label", "source_ip", "geo_country", "geo_city", "abuse_score", "description", "blocked", "sms_sent"]},
    "blocked":          {"file": "rdpshield_blocked_ips",      "fetch": _export_blocked,
                         "cols": ["ip_address", "attempts", "country", "isp", "abuse_score", "attack_method", "reason", "blocked_at"]},
    "events":           {"file": "rdpshield_failed_logins",    "fetch": _export_events,
                         "cols": ["timestamp", "source_ip", "geo_country", "geo_isp", "abuse_score", "username", "domain", "sub_status", "event_label"]},
    "geo_events":       {"file": "rdpshield_geo_events",       "fetch": _export_geo,
                         "cols": ["timestamp", "source_ip", "username", "country", "city", "isp", "abuse_score", "event_type", "event_label", "action", "reason"]},
    "whitelist_events": {"file": "rdpshield_whitelist_events", "fetch": _export_whitelist,
                         "cols": ["timestamp", "source_ip", "username", "country", "city", "isp", "abuse_score", "event_type", "event_label", "action", "reason"]},
    "yara_scans":       {"file": "rdpshield_yara_scans",       "fetch": _export_yara,
                         "cols": ["id", "triggered_by", "started_at", "completed_at", "duration", "total_findings", "critical_findings", "max_severity", "error"]},
    "audit":            {"file": "rdpshield_audit_log",        "fetch": _export_audit,
                         "cols": ["timestamp", "username", "action", "detail", "ip"]},
}


@app.route("/export/<key>.csv")
def export_csv(key):
    """Stream a dataset as a downloadable CSV. Login required (guests may
    export); admin rights are not needed for read-only analysis output."""
    cfg = EXPORT_VIEWS.get(key)
    if not cfg:
        return "Unknown export", 404
    # The audit log is admin-only.
    if key == "audit" and session.get("role") != "admin":
        return auth._deny()

    rows = cfg["fetch"]()
    cols = cfg["cols"]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    for r in rows:
        writer.writerow([r.get(c, "") for c in cols])

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{cfg['file']}_{stamp}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


if __name__ == "__main__":
    print("[DASHBOARD] Initializing database...")
    init_db()
    # No auto-seeded admin: on an empty database the first sign-in is handled by
    # the one-time /setup wizard (create the root admin, then log in + enroll MFA).
    if _needs_setup():
        print("[DASHBOARD] No accounts yet -> browse to /setup to create the first admin.")
    # Background maintenance: key-rotation reminders + auto data-retention purge.
    threading.Thread(target=_maintenance_loop, daemon=True).start()

    # Optional: check in with RDPShield Central. Off unless the CENTRAL_*
    # settings are present in config.py, so an unmanaged instance is unaffected.
    try:
        import central_reporter
        central_reporter.start()
        if central_reporter.managed():
            print("[CENTRAL] CENTRAL_MANAGED=True — the local /login form is "
                  "disabled; sign in via Central. Break-glass: set "
                  "CENTRAL_LOCAL_LOGIN_FALLBACK = True in config.py and restart.")
    except Exception as e:
        print(f"[CENTRAL] reporter not started: {e}")

    # Optional direct TLS: set DASHBOARD_SSL_CERT + DASHBOARD_SSL_KEY in
    # config.py to serve HTTPS from Flask itself (no reverse proxy). Leave them
    # unset to serve plain HTTP (the default; put Caddy/nginx in front for a
    # trusted cert instead — see INSTALL.md).
    cert = getattr(config, "DASHBOARD_SSL_CERT", "")
    key = getattr(config, "DASHBOARD_SSL_KEY", "")
    ssl_context = (cert, key) if cert and key else None
    scheme = "https" if ssl_context else "http"
    print(f"[DASHBOARD] Starting on {scheme}://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print("[DASHBOARD] Press Ctrl+C to stop.\n")
    app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=DASHBOARD_DEBUG,
        ssl_context=ssl_context,
    )