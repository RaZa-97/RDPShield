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
)
from firewall import unblock_ip, block_ip
from alerts import process_alert_enrichment
from config import DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_DEBUG
from countries import COUNTRY_NAMES
import auth
import yara_scheduler

app = Flask(__name__)
from yara_routes import yara_bp
from database import create_yara_tables, create_users_table

app.register_blueprint(yara_bp)
create_yara_tables()
create_users_table()
app.secret_key = "rdpshield_secret_key"  # Needed for sessions + flash messages


# =========================================================================
# AUTHENTICATION GATE + TEMPLATE CONTEXT
# =========================================================================

# Endpoints reachable WITHOUT a full login (the auth flow itself + assets).
PUBLIC_ENDPOINTS = {"login", "mfa", "logout", "static"}


@app.before_request
def require_login():
    """Global gate: every page/API needs a logged-in session except the
    auth flow and static assets. Defence-in-depth on top of per-route
    admin checks, so no view can accidentally leak data unauthenticated."""
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return
    if not session.get("user_id"):
        return redirect(url_for("login", next=request.path))


@app.context_processor
def inject_user():
    """Make the current user/role available to every template."""
    return {
        "current_user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role"),
        } if session.get("user_id") else None,
        "is_admin": session.get("role") == "admin",
        "login_at": session.get("login_at"),
    }


@app.errorhandler(403)
def forbidden(_e):
    return render_template("403.html"), 403


def _seed_default_admin():
    """First run: create an admin/admin account so the operator can log in.
    MFA is enrolled on first login. The password MUST be changed after."""
    if count_users() == 0:
        create_user("admin", auth.hash_password("admin"), role="admin")
        print("[AUTH] Seeded default admin account (admin / admin) — "
              "change this password after first login.")


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
        if not user or not auth.verify_password(user["password_hash"], password):
            return render_template("login.html", error="Invalid username or password.")

        # Password OK -> hand off to the MFA step. Stash a *pending* identity
        # only; the full session is not granted until TOTP succeeds.
        session.clear()
        session["pending_uid"] = user["id"]
        session["pending_name"] = user["username"]
        session["remember"] = bool(request.form.get("remember"))
        # No secret yet -> first-time enrollment; otherwise -> verify.
        session["mfa_enroll"] = not bool(user["totp_secret"])
        return redirect(url_for("mfa"))

    return render_template("login.html", error=None)


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
        session["login_at"] = now.strftime("%Y-%m-%dT%H:%M:%S")
        return redirect(url_for("index"))

    return render_template(
        "mfa.html", enrolling=enrolling, username=user["username"],
        secret=secret, otp_uri=auth.totp_uri(secret, user["username"]),
        qr_svg=_qr_svg(auth.totp_uri(secret, user["username"])),
        error=None)


@app.route("/logout")
def logout():
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
    role = request.form.get("role", "guest")
    if role not in ("admin", "guest"):
        role = "guest"
    if username and password:
        ok = create_user(username, auth.hash_password(password), role=role)
        if not ok:
            flash(f"Username '{username}' already exists.")
        else:
            print(f"[AUTH] Created {role} user: {username}")
    return redirect(url_for("users_page"))


@app.route("/users/delete/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_delete(user_id):
    target = get_user_by_id(user_id)
    # Guard rails: never delete yourself, never remove the last admin.
    if not target:
        pass
    elif user_id == session.get("user_id"):
        flash("You can't delete your own account while signed in.")
    elif target["role"] == "admin" and count_admins() <= 1:
        flash("Can't delete the last remaining admin.")
    else:
        delete_user(user_id)
        print(f"[AUTH] Deleted user: {target['username']}")
    return redirect(url_for("users_page"))


@app.route("/users/reset_mfa/<int:user_id>", methods=["POST"])
@auth.admin_required
def users_reset_mfa(user_id):
    """Clear a user's TOTP so they re-enroll on next login (lost-phone case)."""
    target = get_user_by_id(user_id)
    if target:
        set_user_totp(user_id, None, enabled=0)
        print(f"[AUTH] Reset MFA for user: {target['username']}")
    return redirect(url_for("users_page"))


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

    return render_template(
        "index.html",
        stats=stats,
        alerts=alerts,
        blocked=blocked,
        recent=recent,
        trend=trend,
        alert_breakdown_30d=alert_breakdown_30d,
        top_countries=top_countries,
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
}


@app.route("/list/<key>")
def list_view(key):
    """Generic clean, searchable, paginated full-list page in its own tab."""
    cfg = LIST_VIEWS.get(key)
    if not cfg:
        return "Unknown list", 404
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


@app.route("/api/geo_stats")
def api_geo_stats():
    return jsonify(get_geo_stats())


@app.route("/unblock/<ip_address>", methods=["POST"])
@auth.admin_required
def unblock(ip_address):
    """Manually unblock an IP address. Returns to the page it was triggered
    from (the dashboard or the Advanced Security event logs)."""
    success = unblock_ip(ip_address)
    if success:
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
}


@app.route("/export/<key>.csv")
def export_csv(key):
    """Stream a dataset as a downloadable CSV. Login required (guests may
    export); admin rights are not needed for read-only analysis output."""
    cfg = EXPORT_VIEWS.get(key)
    if not cfg:
        return "Unknown export", 404

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
    print(f"[DASHBOARD] Starting on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print("[DASHBOARD] Press Ctrl+C to stop.\n")
    app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=DASHBOARD_DEBUG,
    )