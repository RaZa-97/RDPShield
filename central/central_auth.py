"""
RDPShield Central — authentication, MFA (TOTP) and multi-tenant RBAC
====================================================================
Deliberately mirrors the main project's `auth.py` (werkzeug password hashing,
pyotp TOTP, decorator-based gating) so the two codebases stay recognisable.
What is NEW here is TENANCY.

Roles
    superadmin      sees and manages every customer and every agent
    customer_admin  scoped to exactly one customer_id

The tenancy rule this module exists to enforce
----------------------------------------------
A customer_admin's scope comes from THEIR SESSION, which came from the `users`
row written at account creation. It is never read from a URL, a form field, a
query string or a JSON body. `scope()` is the single source of that value, and
every database read that can return agents takes it as an argument (see
`central_db.list_agents` / `get_agent_by_uid`).

That is why there is no `require_customer(id)` helper here: there is no
legitimate flow in which a client tells Central which customer it is. A
superadmin browsing one customer's drill-down page passes an id in the URL, but
that path is gated by `superadmin_required` first, so the id is authorised by
role rather than trusted from the request.
"""

from functools import wraps

from flask import session, redirect, url_for, request, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

import central_db

ISSUER = "RDPShield Central"

ROLE_SUPERADMIN = "superadmin"
ROLE_CUSTOMER_ADMIN = "customer_admin"
ROLES = (ROLE_SUPERADMIN, ROLE_CUSTOMER_ADMIN)


# --- Passwords ------------------------------------------------------------
def hash_password(plain):
    return generate_password_hash(plain)


def verify_password(password_hash, plain):
    if not password_hash:
        return False
    return check_password_hash(password_hash, plain)


# --- API keys -------------------------------------------------------------
# Agent bearer keys are hashed with the SAME primitive as passwords. Central
# stores only the hash, so a stolen central.db cannot be replayed as an agent,
# and the plaintext key exists exactly once: in the enrolment response.
def hash_api_key(plain):
    return generate_password_hash(plain)


def verify_api_key(key_hash, plain):
    if not key_hash or not plain:
        return False
    return check_password_hash(key_hash, plain)


# --- TOTP -----------------------------------------------------------------
def new_totp_secret():
    return pyotp.random_base32()


def totp_uri(secret, username):
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def verify_totp(secret, code):
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)


# --- Session helpers ------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return central_db.get_user_by_id(uid)


def is_authenticated():
    return bool(session.get("user_id"))


def is_superadmin():
    return session.get("role") == ROLE_SUPERADMIN


def scope():
    """The customer_id every agent query in this request must be filtered by.

    None  -> superadmin, no filter (sees all tenants)
    int   -> customer_admin, restricted to that one customer

    This value comes ONLY from the session. Never accept a customer_id from the
    client and pass it here."""
    if is_superadmin():
        return None
    return session.get("customer_id")


def _deny():
    """403 as JSON for API callers, as a page for browsers."""
    if request.path.startswith("/api") or request.is_json:
        return jsonify({"ok": False, "error": "Insufficient privileges."}), 403
    abort(403)


# --- Decorators -----------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def superadmin_required(f):
    """Only a superadmin may pass. Used for anything that crosses tenants:
    creating customers, enrolling agents, managing Central's own users."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if session.get("role") != ROLE_SUPERADMIN:
            return _deny()
        return f(*args, **kwargs)
    return wrapper


def can_view_customer(customer_id):
    """May the signed-in operator see this customer?

    Superadmins may see any. A customer_admin may see exactly their own — this
    is the check that stops /customer/<id> from being walked by incrementing the
    number in the URL."""
    if is_superadmin():
        return True
    try:
        return int(customer_id) == int(session.get("customer_id") or -1)
    except (TypeError, ValueError):
        return False
