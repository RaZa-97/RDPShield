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
import io
import random
import re
import threading
import time
from datetime import datetime

from flask import (
    Flask, render_template, jsonify, request,
    redirect, url_for, flash, session, Response
)
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
    update_user_phone,
    update_user_password,
    get_root_user,
    set_user_theme,
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
import auth
import settings
import yara_scheduler

app = Flask(__name__)
from yara_routes import yara_bp
from database import create_yara_tables, create_users_table

app.register_blueprint(yara_bp)
create_yara_tables()
create_users_table()
create_settings_tables()
app.secret_key = "rdpshield_secret_key"  # Needed for sessions + flash messages


def _audit(action, detail=""):
    """Record an admin/security action in the audit trail."""
    try:
        add_audit(session.get("username", "?"), action, detail,
                  request.remote_addr or "")
    except Exception as e:
        print(f"[AUDIT] failed to record '{action}': {e}")


# =========================================================================
# AUTHENTICATION GATE + TEMPLATE CONTEXT
# =========================================================================

# Endpoints reachable WITHOUT a full login (the auth flow itself + assets).
PUBLIC_ENDPOINTS = {"login", "mfa", "logout", "forgot", "reset", "static"}


@app.before_request
def require_login():
    """Global gate: every page/API needs a logged-in session except the
    auth flow and static assets. Also enforces a 1-hour idle timeout and
    refreshes the per-user 'last active' marker used to spot concurrent
    suspicious logins."""
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
    }


@app.errorhandler(403)
def forbidden(_e):
    return render_template("403.html"), 403


def _seed_default_admin():
    """First run: create an admin/admin account so the operator can log in.
    MFA is enrolled on first login. The password MUST be changed after."""
    if count_users() == 0:
        create_user("admin", auth.hash_password("admin"), role="admin", is_root=1)
        print("[AUTH] Seeded default ROOT admin account (admin / admin) — "
              "change this password after first login.")


# =========================================================================
# SESSION SECURITY: idle timeout + suspicious-login defence
# =========================================================================

IDLE_TIMEOUT = 3600        # auto-logout after 1h of inactivity
CONCURRENT_WINDOW = 600    # "still active" = activity within the last 10 min
FAILED_LOGIN_LIMIT = 5     # wrong passwords before the account is locked

# In-memory, single-process state.
_FAILED_LOGINS = {}        # username -> consecutive wrong-password count
_ACTIVE_USERS = {}         # user_id  -> last-activity epoch seconds


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


def _handle_suspicious(user, reason):
    """Lock the account (except the root admin, to avoid permanent lockout)
    and immediately SMS the root admin. Admin/root targets get a stronger
    'breach attempt' warning."""
    name = user["username"]
    _FAILED_LOGINS.pop(name, None)
    add_audit(name, "security.suspicious", reason, request.remote_addr or "")
    if user.get("is_root"):
        _notify_root(f"RDPShield WARNING: breach attempt on ROOT admin '{name}' "
                     f"({reason}). Account NOT locked to avoid lockout — investigate now.")
        print(f"[SECURITY] ROOT '{name}' suspicious ({reason}); warned, not locked.")
        return False  # root is never auto-locked
    set_user_disabled(user["id"], True)
    _ACTIVE_USERS.pop(user["id"], None)
    if user.get("role") == "admin":
        _notify_root(f"RDPShield WARNING: breach attempt on ADMIN account '{name}' "
                     f"({reason}). The account has been LOCKED.")
    else:
        _notify_root(f"RDPShield: account '{name}' was LOCKED after {reason}.")
    print(f"[SECURITY] Locked '{name}' ({reason}); root notified.")
    return True


def _is_user_active(user_id):
    ts = _ACTIVE_USERS.get(user_id)
    return ts is not None and (time.time() - ts) < CONCURRENT_WINDOW


# =========================================================================
# AUTH ROUTES: login -> MFA (enroll/verify) -> session
# =========================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    # Already fully logged in -> straight to the dashboard.
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user_by_username(username)

        # Wrong credentials -> count failures; lock + alert root past the limit.
        if not user or not auth.verify_password(user["password_hash"], password):
            if user:
                _FAILED_LOGINS[username] = _FAILED_LOGINS.get(username, 0) + 1
                if _FAILED_LOGINS[username] >= FAILED_LOGIN_LIMIT and not user.get("disabled"):
                    locked = _handle_suspicious(
                        user, f"{FAILED_LOGIN_LIMIT}+ failed password attempts")
                    if locked:
                        return render_template(
                            "login.html",
                            error="Too many failed attempts — this account has been "
                                  "locked and an administrator alerted.")
            return render_template("login.html", error="Invalid username or password.")

        # Correct password -> clear the failure counter.
        _FAILED_LOGINS.pop(username, None)

        if user.get("disabled"):
            return render_template("login.html",
                                   error="This account is disabled. Contact an administrator.")

        # Suspicious concurrent login: a valid password while the account is
        # already actively in use. Locks the account (root is only warned).
        if _is_user_active(user["id"]):
            locked = _handle_suspicious(user, "login while an existing session was active")
            if locked:
                return render_template(
                    "login.html",
                    error="A concurrent login was detected while this account was "
                          "active. The account has been locked and an administrator alerted.")

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
            code = f"{random.randint(0, 999999):06d}"
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
        if len(new_pw) < 4:
            return render_template("reset.html", sent=True, masked="",
                                   error="Choose a password of at least 4 characters.")

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
# USER MANAGEMENT (admin only)
# =========================================================================

@app.route("/users")
@auth.admin_required
def users_page():
    return render_template("users.html", users=list_users())


@app.route("/users/add", methods=["POST"])
@auth.admin_required
def users_add():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    phone = _normalize_phone(request.form.get("phone", "")) or None
    role = request.form.get("role", "guest")
    if role not in ("admin", "guest"):
        role = "guest"
    if username and password:
        ok = create_user(username, auth.hash_password(password), role=role,
                         phone=phone)
        if not ok:
            flash(f"Username '{username}' already exists.", "error")
        else:
            print(f"[AUTH] Created {role} user: {username}")
            _audit("user.add", f"{username} ({role})")
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
    elif target.get("is_root") and not _i_am_root():
        flash("The root admin can't be deleted by a secondary admin.", "error")
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
    """Clear a user's TOTP so they re-enroll on next login (lost-phone case)."""
    target = get_user_by_id(user_id)
    if target:
        set_user_totp(user_id, None, enabled=0)
        _audit("user.reset_mfa", target["username"])
        print(f"[AUTH] Reset MFA for user: {target['username']}")
    return redirect(url_for("users_page"))


@app.route("/users/update/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_update(user_id):
    """Admin sets a new password and/or phone for a user (blank = unchanged)."""
    target = get_user_by_id(user_id)
    if not target:
        return redirect(url_for("users_page"))
    new_pw = request.form.get("password", "")
    phone = _normalize_phone(request.form.get("phone", ""))
    changed = []
    if new_pw:
        if len(new_pw) < 4:
            flash("Password must be at least 4 characters.", "error")
            return redirect(url_for("users_page"))
        update_user_password(user_id, auth.hash_password(new_pw))
        changed.append("password")
    if phone != (target.get("phone") or ""):
        update_user_phone(user_id, phone or None)
        changed.append("phone")
    if changed:
        _audit("user.update", f"{target['username']}: {', '.join(changed)}")
        print(f"[AUTH] Updated {target['username']}: {', '.join(changed)}")
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
    elif target.get("is_root") and not _i_am_root():
        flash("The root admin can't be disabled by a secondary admin.", "error")
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


# =========================================================================
# THEME (per-user, any logged-in user)
# =========================================================================

@app.route("/theme/<mode>", methods=["POST"])
@auth.login_required
def set_theme(mode):
    mode = "light" if mode == "light" else "dark"
    set_user_theme(session.get("user_id"), mode)
    session["theme"] = mode
    return redirect(request.form.get("next") or url_for("index"))


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
        audit=get_audit(limit=100),
        key_status=settings.key_rotation_status(),
        rotation_interval=settings.rotation_interval_days(),
        rotation_enabled=settings.reminders_enabled(),
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
    _audit("settings.retention", f"{days} days")
    flash(f"Retention set to {days} days (0 = keep forever).", "success")
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


# --- background reminder: nudge admins to rotate API keys every N days -----
def _rotation_reminder_loop():
    """Daemon thread: every `interval` days, SMS the alert recipients/root a
    reminder to rotate API keys. Throttled via the `last_rotation_reminder`
    setting so restarts don't re-spam."""
    while True:
        try:
            if settings.reminders_enabled():
                interval = settings.rotation_interval_days()
                last = get_setting("last_rotation_reminder")
                due = True
                if last:
                    try:
                        dt = datetime.strptime(last[:19], "%Y-%m-%d %H:%M:%S")
                        due = (datetime.utcnow() - dt).total_seconds() >= interval * 86400
                    except ValueError:
                        due = True
                if due:
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


@app.route("/unblock/<ip_address>", methods=["POST"])
@auth.admin_required
def unblock(ip_address):
    """Manually unblock an IP address. Returns to the page it was triggered
    from (the dashboard or the Advanced Security event logs)."""
    success = unblock_ip(ip_address)
    if success:
        _audit("ip.unblock", ip_address)
        print(f"[DASHBOARD] Manually unblocked {ip_address}")
    return redirect(request.form.get("next") or url_for("index"))


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
    return redirect(request.form.get("next") or url_for("index"))


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
                         "cols": ["timestamp", "alert_type", "source_ip", "geo_country", "geo_city", "abuse_score", "description", "blocked", "sms_sent"]},
    "blocked":          {"file": "rdpshield_blocked_ips",      "fetch": _export_blocked,
                         "cols": ["ip_address", "attempts", "country", "isp", "abuse_score", "reason", "blocked_at"]},
    "events":           {"file": "rdpshield_failed_logins",    "fetch": _export_events,
                         "cols": ["timestamp", "source_ip", "geo_country", "geo_isp", "abuse_score", "username", "domain", "sub_status"]},
    "geo_events":       {"file": "rdpshield_geo_events",       "fetch": _export_geo,
                         "cols": ["timestamp", "source_ip", "username", "country", "city", "isp", "abuse_score", "event_type", "action", "reason"]},
    "whitelist_events": {"file": "rdpshield_whitelist_events", "fetch": _export_whitelist,
                         "cols": ["timestamp", "source_ip", "username", "country", "city", "isp", "abuse_score", "event_type", "action", "reason"]},
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
    _seed_default_admin()
    # Background API-key rotation reminder (SMS). Daemon so it dies with the app.
    threading.Thread(target=_rotation_reminder_loop, daemon=True).start()
    print(f"[DASHBOARD] Starting on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print("[DASHBOARD] Press Ctrl+C to stop.\n")
    app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=DASHBOARD_DEBUG,
    )