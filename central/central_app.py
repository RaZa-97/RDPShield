"""
RDPShield Central — multi-tenant command centre
===============================================
A SEPARATE Flask process from the per-instance RDPShield dashboards. One place
to see every customer's every protected server, drill into a customer, then
click through into one agent's own full dashboard — without a second login.

Run it:
    cd central
    copy central_config.example.py central_config.py    # then edit
    python central_keygen.py                            # once, for SSO
    python central_app.py

Design boundaries (see CENTRAL.md for the full account):
  * Central NEVER connects out to a customer box. Agents phone home. That means
    no inbound access to a customer's network is required and NAT is a non-issue.
  * Only aggregated counters cross the wire (`central_report_schema.py`). Raw
    failed-login rows, attacker IPs and YARA findings stay in the instance's own
    database, so tenants' data can never mix here.
  * TLS is MANDATORY. Unlike the per-instance dashboard (which may run on HTTP
    behind an IP allow-list), Central handles cross-tenant data and mints SSO
    tokens, so it refuses to start without TLS unless explicitly overridden for
    local development.
"""

import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash,
    jsonify, abort,
)
from jinja2 import ChoiceLoader, FileSystemLoader
from werkzeug.middleware.proxy_fix import ProxyFix

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

try:
    import central_config as cfg
except ImportError:
    sys.exit(
        "No central_config.py found.\n"
        "    cd central\n"
        "    copy central_config.example.py central_config.py   (then edit it)\n"
    )

import central_db
import central_auth as cauth
import central_sso


# =========================================================================
# APP SETUP
# =========================================================================

# Static assets are shared with the per-instance dashboard so Central inherits
# the same CSS-variable theme (light + [data-theme="dark"]) and icon set rather
# than forking a second stylesheet that would drift.
app = Flask(
    __name__,
    static_folder=os.path.join(_ROOT, "static"),
    static_url_path="/static",
    template_folder=os.path.join(_HERE, "templates"),
)
# Central's own templates win; anything not found falls back to the main
# project's templates/ so `_icons.html` can be imported directly.
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(os.path.join(_HERE, "templates")),
    FileSystemLoader(os.path.join(_ROOT, "templates")),
])

central_db.init_db()


def _load_secret_key():
    """Session-signing key: the RDPSHIELD_CENTRAL_SECRET env var, else a
    gitignored .central_secret_key file generated once. Distinct from the
    instance dashboards' key — a leaked instance key must not forge a Central
    session."""
    env = os.environ.get("RDPSHIELD_CENTRAL_SECRET")
    if env:
        return env
    path = os.path.join(_HERE, ".central_secret_key")
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
        print(f"[CENTRAL] Generated a new session secret at {path} (gitignored).")
    except OSError as exc:
        print(f"[CENTRAL] WARNING: could not persist session secret ({exc}).")
    return key


app.secret_key = _load_secret_key()

USE_TLS = bool(getattr(cfg, "CENTRAL_SSL_CERT", "") and getattr(cfg, "CENTRAL_SSL_KEY", ""))
BEHIND_PROXY = bool(getattr(cfg, "CENTRAL_BEHIND_PROXY", False))
ALLOW_INSECURE = bool(getattr(cfg, "CENTRAL_ALLOW_INSECURE_HTTP", False))
SECURE_COOKIES = USE_TLS or BEHIND_PROXY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    SESSION_COOKIE_NAME="rdpshield_central_session",
    PERMANENT_SESSION_LIFETIME=timedelta(
        hours=int(getattr(cfg, "CENTRAL_SESSION_HOURS", 12))),
    MAX_CONTENT_LENGTH=int(getattr(cfg, "CENTRAL_MAX_REPORT_BYTES", 8192)) * 4,
)

if BEHIND_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

IDLE_TIMEOUT = int(getattr(cfg, "CENTRAL_IDLE_TIMEOUT", 3600))
MIN_PASSWORD_LEN = int(getattr(cfg, "CENTRAL_MIN_PASSWORD_LEN", 12))
FAILED_LOGIN_LIMIT = int(getattr(cfg, "CENTRAL_FAILED_LOGIN_LIMIT", 5))
LOCKOUT_DURATION = int(getattr(cfg, "CENTRAL_LOCKOUT_DURATION", 900))
OFFLINE_AFTER = int(getattr(cfg, "CENTRAL_AGENT_OFFLINE_AFTER", 300))

# In-memory, single-process security state (same approach as the instance
# dashboard: a temporary lock that auto-recovers can't be abused for a
# permanent lockout).
_FAILED_LOGINS = {}
_LOCKED_UNTIL = {}


def _audit(action, detail=""):
    try:
        central_db.add_audit(session.get("username", "?"), action, detail,
                             request.remote_addr or "")
    except Exception as exc:
        print(f"[CENTRAL-AUDIT] failed to record '{action}': {exc}")


def _safe_next(default=None):
    nxt = request.form.get("next") or request.args.get("next") or ""
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return default or url_for("overview")


def _password_ok(pw):
    return isinstance(pw, str) and len(pw) >= MIN_PASSWORD_LEN


# =========================================================================
# AUTH GATE + CSRF
# =========================================================================

# Reachable without a Central login. The ingestion API is here because it
# authenticates with a per-agent bearer key instead of a session — see
# api_agent_report(), which does its own auth.
PUBLIC_ENDPOINTS = {"setup", "login", "mfa", "logout", "static",
                    "api_agent_report", "healthz"}

CSRF_EXEMPT = {"setup", "login", "mfa", "logout", "static",
               "api_agent_report", "healthz"}

_setup_complete = False


def _needs_setup():
    global _setup_complete
    if _setup_complete:
        return False
    if central_db.count_users() > 0:
        _setup_complete = True
        return False
    return True


def _is_local_request():
    ip = (request.remote_addr or "").strip()
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    if ip.startswith("::ffff:"):
        ip = ip.rsplit(":", 1)[-1]
    return ip.startswith(tuple(getattr(cfg, "CENTRAL_PRIVATE_IP_PREFIXES", ("127.",))))


@app.before_request
def require_login():
    if _needs_setup():
        if request.endpoint in ("setup", "static", "healthz") or request.endpoint is None:
            return
        return redirect(url_for("setup"))

    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return
    if not session.get("user_id"):
        return redirect(url_for("login", next=request.path))

    now = time.time()
    last = session.get("last_active", now)
    if now - last > IDLE_TIMEOUT:
        session.clear()
        return redirect(url_for("login", timeout=1))
    # Background polling must not count as activity, or an idle open tab would
    # never time out.
    if not request.path.startswith("/api/"):
        session["last_active"] = now


def _ensure_csrf_token():
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_hex(32)
        session["csrf_token"] = tok
    return tok


@app.before_request
def csrf_protect():
    _ensure_csrf_token()
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
    return {
        "current_user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role"),
            "customer_id": session.get("customer_id"),
            "customer_name": session.get("customer_name"),
        } if session.get("user_id") else None,
        "is_superadmin": session.get("role") == cauth.ROLE_SUPERADMIN,
        "login_at": session.get("login_at"),
        "theme": session.get("theme", "dark"),
        "csrf_token": session.get("csrf_token", ""),
    }


@app.errorhandler(403)
def forbidden(_e):
    return render_template("central_403.html"), 403


@app.route("/healthz")
def healthz():
    """Unauthenticated liveness probe. Deliberately reveals nothing."""
    return jsonify({"ok": True})


# =========================================================================
# AGENT STATUS DERIVATION
# =========================================================================

def _agent_status(agent, now=None):
    """pending | online | offline, derived from last_seen.

    Central does not recompute any detection logic — it only decides whether an
    agent is still checking in. Everything else on the row is what the agent
    itself last reported."""
    if not agent.get("last_seen"):
        return "pending"
    now = now or datetime.utcnow()
    try:
        seen = datetime.strptime(agent["last_seen"][:19], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return "pending"
    return "online" if (now - seen).total_seconds() <= OFFLINE_AFTER else "offline"


def _decorate(agents):
    """Attach derived display fields to each agent row."""
    now = datetime.utcnow()
    for a in agents:
        a["status"] = _agent_status(a, now)
        s = a.get("summary") or {}
        a["failed_logins_24h"] = s.get("failed_logins_24h")
        a["alerts_24h"] = s.get("alerts_24h")
        a["blocked_ips_active"] = s.get("blocked_ips_active")
        a["max_threat_score"] = s.get("max_threat_score")
        a["top_alert_type"] = s.get("top_alert_type") or ""
        a["detectors_ok"] = s.get("detectors_ok")
        # An agent that has gone quiet keeps its last reported risk on the row,
        # but the tiles below only count risk for agents that are actually
        # reporting — a stale "critical" from last week is not a live incident.
        if a["status"] == "pending":
            a["risk_level"] = "unknown"
    return agents


def _tiles(agents):
    """The top-row summary counters for the overview/drill-down pages."""
    online = sum(1 for a in agents if a["status"] == "online")
    offline = sum(1 for a in agents if a["status"] == "offline")
    pending = sum(1 for a in agents if a["status"] == "pending")
    high_risk = sum(1 for a in agents
                    if a["status"] == "online" and a.get("risk_level") in ("high", "critical"))
    unhealthy = sum(1 for a in agents
                    if a["status"] == "online" and a.get("detectors_ok") is False)
    return {
        "agents": len(agents),
        "online": online,
        "offline": offline,
        "pending": pending,
        "high_risk": high_risk,
        "unhealthy": unhealthy,
    }


# =========================================================================
# AUTH ROUTES
# =========================================================================

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """First-run wizard: create the initial superadmin on an empty database.

    Same lockdown as the instance dashboard's /setup — it exists only while
    there are zero accounts and is reachable only from loopback / the local
    network, so unauthenticated account creation is never exposed publicly."""
    if not _needs_setup():
        return redirect(url_for("login"))
    if not _is_local_request():
        return render_template(
            "central_setup.html", local_only=True,
            error="For security, first-time setup must be done from the Central "
                  "server itself or its local network."), 403

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not username:
            return render_template("central_setup.html", error="Choose a username.")
        if not _password_ok(password):
            return render_template(
                "central_setup.html",
                error=f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        if password != confirm:
            return render_template("central_setup.html", error="The two passwords don't match.")
        if not _needs_setup():
            return redirect(url_for("login"))

        uid = central_db.create_user(username, cauth.hash_password(password),
                                     role=cauth.ROLE_SUPERADMIN, customer_id=None,
                                     is_root=1)
        if not uid:
            return render_template("central_setup.html",
                                   error="Could not create the account. Try again.")
        global _setup_complete
        _setup_complete = True
        central_db.add_audit(username, "central.setup", "created initial superadmin",
                             request.remote_addr or "")
        print(f"[CENTRAL] First-run setup: created superadmin '{username}'.")
        flash("Superadmin created. Sign in below — you'll set up MFA on this first login.",
              "success")
        return redirect(url_for("login"))

    return render_template("central_setup.html", error=None)


def _lock_seconds_left(username):
    until = _LOCKED_UNTIL.get(username)
    if not until:
        return 0
    left = until - time.time()
    if left <= 0:
        _LOCKED_UNTIL.pop(username, None)
        return 0
    return int(left)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("overview"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if _lock_seconds_left(username):
            return render_template(
                "central_login.html",
                error="Too many failed attempts. Please try again in a few minutes.")

        user = central_db.get_user_by_username(username)
        if not user or not cauth.verify_password(user["password_hash"], password):
            if user:
                _FAILED_LOGINS[username] = _FAILED_LOGINS.get(username, 0) + 1
                if _FAILED_LOGINS[username] >= FAILED_LOGIN_LIMIT:
                    _FAILED_LOGINS.pop(username, None)
                    _LOCKED_UNTIL[username] = time.time() + LOCKOUT_DURATION
                    central_db.add_audit(username, "central.temp_lock",
                                         f"{FAILED_LOGIN_LIMIT}+ failed passwords",
                                         request.remote_addr or "")
            return render_template("central_login.html",
                                   error="Invalid username or password.")

        _FAILED_LOGINS.pop(username, None)
        if user.get("disabled"):
            return render_template("central_login.html",
                                   error="This account is disabled. Contact a superadmin.")

        session.clear()
        session["pending_uid"] = user["id"]
        session["mfa_enroll"] = not bool(user["totp_secret"])
        return redirect(url_for("mfa"))

    info = "You were signed out after inactivity." if request.args.get("timeout") else None
    return render_template("central_login.html", error=None, info=info)


def _qr_svg(uri):
    """Inline SVG QR for TOTP enrolment, or None if `qrcode` isn't installed
    (the page then shows the secret key for manual entry).

    Same approach as the instance dashboard: SvgPathImage gives a viewBox and a
    plain <path>, both needed to render inline in HTML, and the leading
    <?xml …?> declaration is stripped because it is invalid inside a body."""
    try:
        import io
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage,
                          box_size=10, border=2)
        buf = io.BytesIO()
        img.save(buf)
        svg = buf.getvalue().decode("utf-8")
        i = svg.find("<svg")
        return svg[i:] if i != -1 else svg
    except Exception as exc:
        print(f"[CENTRAL] QR render unavailable ({exc}); showing manual key only.")
        return None


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    uid = session.get("pending_uid")
    if not uid:
        return redirect(url_for("login"))
    user = central_db.get_user_by_id(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    enrolling = session.get("mfa_enroll", False)
    if enrolling:
        secret = session.get("enroll_secret")
        if not secret:
            secret = cauth.new_totp_secret()
            session["enroll_secret"] = secret
    else:
        secret = user["totp_secret"]

    def _render(error=None):
        return render_template(
            "central_mfa.html", enrolling=enrolling, username=user["username"],
            secret=secret, qr_svg=_qr_svg(cauth.totp_uri(secret, user["username"])),
            error=error)

    if request.method == "POST":
        code = request.form.get("code", "").replace(" ", "").replace("-", "")
        if not cauth.verify_totp(secret, code):
            return _render("That code wasn't valid. Try the current one.")
        if enrolling:
            central_db.set_user_totp(user["id"], secret, enabled=1)

        customer = central_db.get_customer(user["customer_id"]) if user["customer_id"] else None
        now = datetime.now()
        central_db.update_last_login(user["id"], now.strftime("%Y-%m-%d %H:%M:%S"))
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["customer_id"] = user["customer_id"]
        session["customer_name"] = customer["name"] if customer else None
        session["is_root"] = bool(user["is_root"])
        session["theme"] = user["theme"] if user["theme"] in ("dark", "light") else "dark"
        session["login_at"] = now.strftime("%Y-%m-%dT%H:%M:%S")
        session["last_active"] = time.time()
        _audit("central.login", "signed in")
        return redirect(_safe_next(url_for("overview")))

    return _render()


@app.route("/logout")
def logout():
    if session.get("user_id"):
        _audit("central.logout", "signed out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/theme/<mode>", methods=["POST"])
@cauth.login_required
def set_theme(mode):
    if mode in ("dark", "light"):
        session["theme"] = mode
        central_db.set_user_theme(session["user_id"], mode)
    return redirect(_safe_next())


# =========================================================================
# OVERVIEW
# =========================================================================

@app.route("/")
@cauth.login_required
def overview():
    """Every agent the signed-in operator is allowed to see.

    `cauth.scope()` is None for a superadmin (all tenants) and the operator's
    own customer_id otherwise — the filter is applied in the SQL, not in the
    template, so a customer_admin's page is built from their rows only."""
    agents = _decorate(central_db.list_agents(customer_id=cauth.scope()))
    customers = central_db.list_customers(customer_id=cauth.scope())
    return render_template(
        "central_overview.html",
        active="overview",
        agents=agents,
        customers=customers,
        tiles=_tiles(agents),
        customer_count=len(customers),
        offline_after=OFFLINE_AFTER,
    )


@app.route("/customer/<int:customer_id>")
@cauth.login_required
def customer_page(customer_id):
    """Drill-down: the same console layout, scoped to one customer.

    A customer_admin may only reach their OWN id — `can_view_customer` is what
    stops the URL from being walked by incrementing the number."""
    if not cauth.can_view_customer(customer_id):
        abort(403)
    customer = central_db.get_customer(customer_id)
    if not customer:
        abort(404)
    agents = _decorate(central_db.list_agents(customer_id=customer_id))
    return render_template(
        "central_customer.html",
        active="overview",
        customer=customer,
        agents=agents,
        tiles=_tiles(agents),
        offline_after=OFFLINE_AFTER,
    )


# =========================================================================
# CUSTOMERS (superadmin only — managing tenants crosses tenant boundaries)
# =========================================================================

@app.route("/customers")
@cauth.superadmin_required
def customers_page():
    customers = central_db.list_customers()
    agents = central_db.list_agents()
    counts = {}
    for a in agents:
        counts[a["customer_id"]] = counts.get(a["customer_id"], 0) + 1
    for c in customers:
        c["agent_count"] = counts.get(c["id"], 0)
    return render_template("central_customers.html", active="customers",
                           customers=customers)


@app.route("/customers/add", methods=["POST"])
@cauth.superadmin_required
def customers_add():
    name = request.form.get("name", "").strip()
    email = request.form.get("contact_email", "").strip()
    notes = request.form.get("notes", "").strip()
    if not name:
        flash("A customer name is required.", "error")
    elif central_db.add_customer(name, email, notes):
        _audit("central.customer_add", name)
        flash(f"Customer '{name}' added.", "success")
    else:
        flash(f"A customer named '{name}' already exists.", "error")
    return redirect(url_for("customers_page"))


@app.route("/customers/delete/<int:customer_id>", methods=["POST"])
@cauth.superadmin_required
def customers_delete(customer_id):
    customer = central_db.get_customer(customer_id)
    if not customer:
        abort(404)
    # Deleting a customer cascades to their agents and scoped operators, so make
    # the operator confront the count rather than discovering it afterwards.
    agents = central_db.list_agents(customer_id=customer_id)
    if agents and request.form.get("confirm_agents") != str(len(agents)):
        flash(f"'{customer['name']}' still has {len(agents)} enrolled agent(s). "
              "Remove them first, or confirm the deletion.", "error")
        return redirect(url_for("customers_page"))
    central_db.delete_customer(customer_id)
    _audit("central.customer_delete", f"{customer['name']} (+{len(agents)} agents)")
    flash(f"Customer '{customer['name']}' deleted.", "success")
    return redirect(url_for("customers_page"))


# =========================================================================
# AGENTS + ENROLMENT (superadmin only)
# =========================================================================

def _new_agent_uid():
    """Opaque, unguessable public id. It appears in URLs and in the SSO
    audience, so it must not be a guessable sequence — an incrementing integer
    would let anyone enumerate the fleet."""
    return "ag_" + secrets.token_hex(12)


def _new_api_key():
    return "rdps_" + secrets.token_urlsafe(32)


@app.route("/agents")
@cauth.superadmin_required
def agents_page():
    agents = _decorate(central_db.list_agents())
    customers = central_db.list_customers()
    # A freshly enrolled agent's key is passed through the session exactly once
    # and popped on read, so a page refresh cannot re-reveal it.
    new_secret = session.pop("new_agent_secret", None)
    return render_template("central_agents.html", active="agents",
                           agents=agents, customers=customers,
                           new_secret=new_secret,
                           central_url=getattr(cfg, "CENTRAL_PUBLIC_URL", ""))


@app.route("/agents/enroll", methods=["POST"])
@cauth.superadmin_required
def agents_enroll():
    """Register one RDPShield instance and mint its API key.

    The key is shown ONCE here and stored only as a hash — Central can verify a
    key but can never reproduce it, so a stolen central.db yields no usable
    agent credentials."""
    try:
        customer_id = int(request.form.get("customer_id", ""))
    except (TypeError, ValueError):
        flash("Choose a customer.", "error")
        return redirect(url_for("agents_page"))
    if not central_db.get_customer(customer_id):
        flash("That customer no longer exists.", "error")
        return redirect(url_for("agents_page"))

    name = request.form.get("name", "").strip()
    if not name:
        flash("Give the server a name.", "error")
        return redirect(url_for("agents_page"))

    hostname = request.form.get("hostname", "").strip()
    dashboard_url = request.form.get("dashboard_url", "").strip().rstrip("/")
    if dashboard_url and not dashboard_url.startswith(("http://", "https://")):
        flash("The dashboard URL must start with http:// or https://.", "error")
        return redirect(url_for("agents_page"))

    agent_uid = _new_agent_uid()
    api_key = _new_api_key()
    ok = central_db.add_agent(agent_uid, customer_id, name,
                              cauth.hash_api_key(api_key),
                              dashboard_url=dashboard_url, hostname=hostname)
    if not ok:
        flash("Could not enrol that agent. Try again.", "error")
        return redirect(url_for("agents_page"))

    # NOTE: the key itself is never written to the audit log or the console.
    _audit("central.agent_enroll", f"{name} [{agent_uid}] for customer {customer_id}")
    session["new_agent_secret"] = {
        "agent_uid": agent_uid,
        "api_key": api_key,
        "name": name,
        "central_url": getattr(cfg, "CENTRAL_PUBLIC_URL", ""),
    }
    return redirect(url_for("agents_page"))


@app.route("/agents/rotate/<agent_uid>", methods=["POST"])
@cauth.superadmin_required
def agents_rotate(agent_uid):
    agent = central_db.get_agent_by_uid(agent_uid)
    if not agent:
        abort(404)
    api_key = _new_api_key()
    central_db.rotate_agent_key(agent_uid, cauth.hash_api_key(api_key))
    _audit("central.agent_rotate_key", f"{agent['name']} [{agent_uid}]")
    session["new_agent_secret"] = {
        "agent_uid": agent_uid,
        "api_key": api_key,
        "name": agent["name"],
        "central_url": getattr(cfg, "CENTRAL_PUBLIC_URL", ""),
        "rotated": True,
    }
    flash("Key rotated. The agent will fail to check in until the new key is "
          "installed in its config.py.", "message")
    return redirect(url_for("agents_page"))


@app.route("/agents/update/<agent_uid>", methods=["POST"])
@cauth.superadmin_required
def agents_update(agent_uid):
    if not central_db.get_agent_by_uid(agent_uid):
        abort(404)
    dashboard_url = request.form.get("dashboard_url", "").strip().rstrip("/")
    if dashboard_url and not dashboard_url.startswith(("http://", "https://")):
        flash("The dashboard URL must start with http:// or https://.", "error")
        return redirect(url_for("agents_page"))
    central_db.update_agent_meta(
        agent_uid,
        name=request.form.get("name", "").strip() or None,
        dashboard_url=dashboard_url,
        notes=request.form.get("notes", "").strip(),
    )
    _audit("central.agent_update", agent_uid)
    flash("Agent updated.", "success")
    return redirect(url_for("agents_page"))


@app.route("/agents/delete/<agent_uid>", methods=["POST"])
@cauth.superadmin_required
def agents_delete(agent_uid):
    agent = central_db.get_agent_by_uid(agent_uid)
    if not agent:
        abort(404)
    central_db.delete_agent(agent_uid)
    _audit("central.agent_delete", f"{agent['name']} [{agent_uid}]")
    flash(f"Agent '{agent['name']}' removed. Its own dashboard and data are "
          "untouched — only Central forgets it.", "success")
    return redirect(url_for("agents_page"))


# =========================================================================
# OPERATORS + AUDIT (superadmin only)
# =========================================================================

@app.route("/users")
@cauth.superadmin_required
def users_page():
    return render_template("central_users.html", active="users",
                           users=central_db.list_users(),
                           customers=central_db.list_customers())


@app.route("/users/add", methods=["POST"])
@cauth.superadmin_required
def users_add():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", cauth.ROLE_CUSTOMER_ADMIN)
    raw_customer = request.form.get("customer_id", "")

    if not username:
        flash("A username is required.", "error")
        return redirect(url_for("users_page"))
    if not _password_ok(password):
        flash(f"Password must be at least {MIN_PASSWORD_LEN} characters.", "error")
        return redirect(url_for("users_page"))
    if role not in cauth.ROLES:
        flash("Unknown role.", "error")
        return redirect(url_for("users_page"))

    # A customer_admin without a customer would be an operator with no scope —
    # `scope()` would return None, which is the superadmin sentinel. Refuse.
    customer_id = None
    if role == cauth.ROLE_CUSTOMER_ADMIN:
        try:
            customer_id = int(raw_customer)
        except (TypeError, ValueError):
            flash("A customer admin must be assigned to a customer.", "error")
            return redirect(url_for("users_page"))
        if not central_db.get_customer(customer_id):
            flash("That customer no longer exists.", "error")
            return redirect(url_for("users_page"))

    if central_db.create_user(username, cauth.hash_password(password),
                              role=role, customer_id=customer_id):
        _audit("central.user_add", f"{username} ({role})")
        flash(f"Operator '{username}' created. They enrol MFA on first sign-in.",
              "success")
    else:
        flash(f"A user named '{username}' already exists.", "error")
    return redirect(url_for("users_page"))


@app.route("/users/disable/<int:user_id>", methods=["POST"])
@cauth.superadmin_required
def users_disable(user_id):
    user = central_db.get_user_by_id(user_id)
    if not user:
        abort(404)
    if user.get("is_root") or user_id == session.get("user_id"):
        flash("You can't disable the root superadmin or your own account.", "error")
        return redirect(url_for("users_page"))
    central_db.set_user_disabled(user_id, not user.get("disabled"))
    _audit("central.user_disable", f"{user['username']} -> "
           f"{'enabled' if user.get('disabled') else 'disabled'}")
    return redirect(url_for("users_page"))


@app.route("/users/reset_mfa/<int:user_id>", methods=["POST"])
@cauth.superadmin_required
def users_reset_mfa(user_id):
    user = central_db.get_user_by_id(user_id)
    if not user:
        abort(404)
    central_db.set_user_totp(user_id, None, enabled=0)
    _audit("central.user_reset_mfa", user["username"])
    flash(f"MFA cleared for '{user['username']}' — they re-enrol on next sign-in.",
          "success")
    return redirect(url_for("users_page"))


@app.route("/users/delete/<int:user_id>", methods=["POST"])
@cauth.superadmin_required
def users_delete(user_id):
    user = central_db.get_user_by_id(user_id)
    if not user:
        abort(404)
    if user_id == session.get("user_id"):
        flash("You can't delete your own account.", "error")
        return redirect(url_for("users_page"))
    if not central_db.delete_user(user_id):
        flash("The root superadmin can't be deleted.", "error")
        return redirect(url_for("users_page"))
    _audit("central.user_delete", user["username"])
    flash(f"Operator '{user['username']}' deleted.", "success")
    return redirect(url_for("users_page"))


@app.route("/audit")
@cauth.superadmin_required
def audit_page():
    return render_template("central_audit.html", active="audit",
                           rows=central_db.get_audit(limit=300))


# =========================================================================
# AGENT INGESTION API
# =========================================================================
# The only endpoint an RDPShield instance ever calls. It is session-less: an
# agent authenticates with the bearer key it was given at enrolment.
#
# Security requirements implemented here:
#   1. The key is validated against the SPECIFIC agent_uid in the URL path, so
#      a compromised instance cannot push (or overwrite) another agent's stats
#      even though its own key is perfectly valid.
#   2. Per-agent rate limiting.
#   3. Strict schema validation before anything is written (unknown fields and
#      wrong types are rejected outright — see central_report_schema.py).
#   4. Nothing about the key is ever logged, not even a prefix.

sys.path.insert(0, _ROOT)
import central_report_schema as schema  # noqa: E402

# agent_uid -> [window_start_epoch, count]. In-memory and single-process, the
# same approach the instance dashboard uses for login lockouts. A restart
# forgives outstanding rate limits, which is acceptable: the limit exists to
# stop a runaway or abusive agent, not to be a durable quota.
_REPORT_RATE = {}
RATE_LIMIT = int(getattr(cfg, "CENTRAL_REPORT_RATE_LIMIT", 20))
RATE_WINDOW = int(getattr(cfg, "CENTRAL_REPORT_RATE_WINDOW", 60))
MAX_REPORT_BYTES = int(getattr(cfg, "CENTRAL_MAX_REPORT_BYTES", 8192))


def _rate_limited(agent_uid):
    now = time.time()
    start, count = _REPORT_RATE.get(agent_uid, (now, 0))
    if now - start >= RATE_WINDOW:
        start, count = now, 0
    count += 1
    _REPORT_RATE[agent_uid] = (start, count)
    return count > RATE_LIMIT


def _bearer_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return ""
    return header[7:].strip()


@app.route("/api/v1/agents/<agent_uid>/report", methods=["POST"])
def api_agent_report(agent_uid):
    """Accept one check-in from one agent."""
    # Refuse plaintext outright unless explicitly allowed for local dev: the
    # bearer key is in this request's headers.
    if not (request.is_secure or BEHIND_PROXY or ALLOW_INSECURE):
        return jsonify({"ok": False, "error": "HTTPS required."}), 400

    key = _bearer_token()
    if not key:
        return jsonify({"ok": False, "error": "Missing bearer token."}), 401

    agent = central_db.get_agent_by_uid(agent_uid)
    # Identical response and no early return for "no such agent" vs "wrong key":
    # a caller must not be able to probe which agent_uids exist.
    if not agent or not cauth.verify_api_key(agent["api_key_hash"], key):
        central_db.add_audit("agent:" + agent_uid, "central.report_auth_fail",
                             "bad agent id or key", request.remote_addr or "")
        return jsonify({"ok": False, "error": "Unauthorized."}), 401

    if _rate_limited(agent_uid):
        return jsonify({"ok": False, "error": "Rate limit exceeded."}), 429

    # Read the body ONCE and parse it ourselves. Using request.get_data() and
    # then request.get_json() would consume the stream twice and always see an
    # empty body the second time.
    raw = request.get_data(cache=True, as_text=False) or b""
    if len(raw) > MAX_REPORT_BYTES:
        return jsonify({"ok": False, "error": "Payload too large."}), 413

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return jsonify({"ok": False, "error": "Body must be JSON."}), 400

    try:
        clean = schema.validate(payload)
    except schema.SchemaError as exc:
        # The message names the offending field but never echoes its value.
        return jsonify({"ok": False, "error": f"Invalid payload: {exc}"}), 400

    central_db.update_agent_report(
        agent_uid, clean,
        agent_version=clean.get("agent_version", ""),
        risk_level=clean.get("risk_level", "unknown"),
    )
    return jsonify({
        "ok": True,
        "next_check_in": RATE_WINDOW,
        "schema_version": schema.SCHEMA_VERSION,
    })


# =========================================================================
# SSO CLICK-THROUGH
# =========================================================================

@app.route("/agents/open/<agent_uid>", methods=["POST"])
@cauth.login_required
def open_agent(agent_uid):
    """Mint a short-lived SSO token and hand the operator to that instance.

    Scoped by `cauth.scope()`, so a customer_admin clicking a uid that isn't
    theirs gets a 404 — the same answer they'd get for an agent that doesn't
    exist, which avoids confirming that another tenant's agent is real."""
    agent = central_db.get_agent_by_uid(agent_uid, customer_id=cauth.scope())
    if not agent:
        abort(404)
    if not agent.get("dashboard_url"):
        flash("That agent has no dashboard URL recorded. Add one from Agents.",
              "error")
        return redirect(request.referrer or url_for("overview"))

    try:
        token, claims = central_sso.issue_token(
            agent_uid=agent["agent_uid"],
            username=session.get("username", "?"),
            central_role=session.get("role", ""),
            customer_id=agent["customer_id"],
        )
    except central_sso.SSOIssueError as exc:
        flash(f"Could not issue an SSO token: {exc}", "error")
        return redirect(request.referrer or url_for("overview"))

    _audit("central.sso_open", f"{agent['name']} [{agent_uid}] jti={claims['jti']}")
    # The token rides in the query string of a one-shot redirect: it is valid
    # for ~60s, single-use, and bound to this one agent, so the usual "secrets
    # in URLs" objection (logs, referrer) is bounded to a window in which the
    # token is already spent.
    return redirect(f"{agent['dashboard_url']}/sso?token={token}")


# =========================================================================
# ENTRY POINT
# =========================================================================

def _preflight():
    """Refuse to start in an unsafe or non-working configuration."""
    problems = []

    if not (USE_TLS or BEHIND_PROXY):
        if ALLOW_INSECURE:
            print("[CENTRAL] *** WARNING: running WITHOUT TLS "
                  "(CENTRAL_ALLOW_INSECURE_HTTP=True). Development only — SSO "
                  "tokens and agent API keys are sent in clear text. ***")
        else:
            problems.append(
                "TLS is not configured. Central carries cross-tenant data and "
                "mints SSO tokens, so HTTPS is mandatory.\n"
                "  Set CENTRAL_SSL_CERT + CENTRAL_SSL_KEY, or put a TLS reverse "
                "proxy in front and set CENTRAL_BEHIND_PROXY = True.\n"
                "  For local development only: CENTRAL_ALLOW_INSECURE_HTTP = True.")

    if not central_sso.keys_present():
        problems.append(
            "No SSO signing keypair found. Run:  python central_keygen.py")
    else:
        ok, msg = central_sso.self_check()
        if ok:
            print(f"[CENTRAL] {msg}")
        else:
            problems.append(f"SSO key problem: {msg}")

    if problems:
        print("\n[CENTRAL] Refusing to start:\n")
        for p in problems:
            print("  * " + p + "\n")
        sys.exit(1)


if __name__ == "__main__":
    print("[CENTRAL] Initialising database…")
    central_db.init_db()
    _preflight()
    if _needs_setup():
        print("[CENTRAL] No accounts yet -> browse to /setup to create the first superadmin.")

    host = getattr(cfg, "CENTRAL_HOST", "0.0.0.0")
    port = int(getattr(cfg, "CENTRAL_PORT", 6100))
    ssl_context = ((cfg.CENTRAL_SSL_CERT, cfg.CENTRAL_SSL_KEY) if USE_TLS else None)
    scheme = "https" if (USE_TLS or BEHIND_PROXY) else "http"
    print(f"[CENTRAL] Starting on {scheme}://{host}:{port}")
    print("[CENTRAL] Press Ctrl+C to stop.\n")
    app.run(host=host, port=port,
            debug=bool(getattr(cfg, "CENTRAL_DEBUG", False)),
            ssl_context=ssl_context)
