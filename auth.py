"""
RDPShield — authentication, MFA (TOTP) and role-based access control (v3.3)
===========================================================================
Roles:
    admin  - full control (block/unblock, geo/whitelist settings, YARA
             actions, user management)
    guest  - view dashboards/logs + CSV export only

Auth flow:
    1. /login  - username + password.  On success, if the user has no TOTP
       secret yet they are sent to MFA *enrollment*; otherwise to MFA *verify*.
    2. /mfa    - 6-digit TOTP code from an authenticator app.  On success the
       full session is established (session["user_id"], role, login_at).

Passwords use werkzeug hashes; TOTP uses pyotp.  Install on the server with:
    pip install pyotp
"""

from functools import wraps

from flask import session, redirect, url_for, request, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

import database

ISSUER = "RDPShield"


# --- Passwords ------------------------------------------------------------
def hash_password(plain):
    return generate_password_hash(plain)


def verify_password(password_hash, plain):
    if not password_hash:
        return False
    return check_password_hash(password_hash, plain)


# --- TOTP -----------------------------------------------------------------
def new_totp_secret():
    return pyotp.random_base32()


def totp_uri(secret, username):
    """otpauth:// URI for QR provisioning in an authenticator app."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def verify_totp(secret, code):
    if not secret or not code:
        return False
    # valid_window=1 tolerates a +/-30s clock skew between server and phone.
    return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)


# --- Session helpers ------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return database.get_user_by_id(uid)


def is_authenticated():
    return bool(session.get("user_id"))


def is_admin():
    return session.get("role") == "admin"


def _deny():
    """403 for API/JSON callers, a 403 error page for normal requests."""
    if request.path.startswith("/api") or request.path.startswith("/yara/") \
            or request.is_json:
        return jsonify({"ok": False, "error": "Admin privileges required."}), 403
    abort(403)


# --- Decorators -----------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            return _deny()
        return f(*args, **kwargs)
    return wrapper
