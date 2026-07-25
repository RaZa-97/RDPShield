"""
RDPShield Central — database layer (central.db)
===============================================
Central's own SQLite database. Deliberately SEPARATE from every instance's
`rdpshield.db`: no instance ever opens this file, and this file never holds raw
attacker records (no failed-login rows, no attacker IPs, no YARA findings).
Agents push only aggregated counters, so one customer's data can never surface
in another customer's view — there is nothing granular here to leak.

The table designs for `users`, `audit_log` and `settings` intentionally mirror
the main project's `database.py` so the two codebases stay recognisable, but
they are independent tables in an independent file.

Tenancy rule enforced throughout this module: every read that can return agents
takes an explicit `customer_id` scope. A `customer_id` of None means "no scope
filter" and is only ever passed by a superadmin path — see central_auth.scope().
"""

import json
import os
import sqlite3
from datetime import datetime

import central_config as cfg

_HERE = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(_HERE, getattr(cfg, "CENTRAL_DATABASE_PATH", "central.db"))


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    # Central takes concurrent writes from every enrolled agent's check-in plus
    # the operator's browsing, so enable WAL and wait rather than failing fast.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _utcnow():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# =========================================================================
# SCHEMA
# =========================================================================

def init_db():
    """Create every table if missing. Safe to call on every start."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL UNIQUE,
            contact_email TEXT DEFAULT '',
            notes         TEXT DEFAULT '',
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP
        )""")

    # One agent == one RDPShield instance == one protected customer server.
    #   agent_uid       opaque public id used in URLs and the SSO audience
    #   api_key_hash    werkzeug hash of the bearer key; the key itself is shown
    #                   ONCE at enrolment and never stored or logged in clear
    #   last_summary_json  the last VALIDATED payload, as pushed by the agent
    c.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_uid         TEXT NOT NULL UNIQUE,
            customer_id       INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
            name              TEXT NOT NULL,
            hostname          TEXT DEFAULT '',
            dashboard_url     TEXT NOT NULL DEFAULT '',
            api_key_hash      TEXT NOT NULL,
            enrolled_at       TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen         TEXT,
            last_summary_json TEXT DEFAULT '',
            agent_version     TEXT DEFAULT '',
            risk_level        TEXT DEFAULT 'unknown',
            notes             TEXT DEFAULT ''
        )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_agents_customer ON agents(customer_id)")

    # Roles: superadmin (all customers) | customer_admin (own customer only).
    # customer_id is NULL for superadmin and REQUIRED for customer_admin.
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'customer_admin',
            customer_id   INTEGER REFERENCES customers(id) ON DELETE CASCADE,
            totp_secret   TEXT,
            mfa_enabled   INTEGER DEFAULT 0,
            disabled      INTEGER DEFAULT 0,
            is_root       INTEGER DEFAULT 0,
            theme         TEXT DEFAULT 'dark',
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login    TEXT
        )""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            username  TEXT,
            action    TEXT,
            detail    TEXT,
            ip        TEXT
        )""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key        TEXT PRIMARY KEY,
            value      TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")

    conn.commit()
    conn.close()


# =========================================================================
# CUSTOMERS
# =========================================================================

def add_customer(name, contact_email="", notes=""):
    conn = get_connection(); c = conn.cursor()
    try:
        c.execute("INSERT INTO customers (name, contact_email, notes) VALUES (?, ?, ?)",
                  (name, contact_email, notes))
        conn.commit()
        return c.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_customer(customer_id):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
    row = c.fetchone(); conn.close()
    return dict(row) if row else None


def list_customers(customer_id=None):
    """All customers, or just the one a customer_admin is scoped to."""
    conn = get_connection(); c = conn.cursor()
    if customer_id is None:
        c.execute("SELECT * FROM customers ORDER BY name COLLATE NOCASE ASC")
    else:
        c.execute("SELECT * FROM customers WHERE id = ? ", (customer_id,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def delete_customer(customer_id):
    conn = get_connection(); c = conn.cursor()
    c.execute("DELETE FROM customers WHERE id = ?", (customer_id,))
    conn.commit(); n = c.rowcount; conn.close()
    return n


# =========================================================================
# AGENTS
# =========================================================================

def add_agent(agent_uid, customer_id, name, api_key_hash, dashboard_url="",
              hostname="", notes=""):
    conn = get_connection(); c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO agents (agent_uid, customer_id, name, api_key_hash,
                                dashboard_url, hostname, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (agent_uid, customer_id, name, api_key_hash,
                   dashboard_url, hostname, notes))
        conn.commit()
        return c.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_agent_by_uid(agent_uid, customer_id=None):
    """One agent by its public uid.

    `customer_id` scopes the lookup: a customer_admin passes their own id, so a
    guessed/leaked uid belonging to another tenant returns None rather than
    leaking that the agent exists."""
    conn = get_connection(); c = conn.cursor()
    if customer_id is None:
        c.execute("SELECT * FROM agents WHERE agent_uid = ?", (agent_uid,))
    else:
        c.execute("SELECT * FROM agents WHERE agent_uid = ? AND customer_id = ?",
                  (agent_uid, customer_id))
    row = c.fetchone(); conn.close()
    return dict(row) if row else None


def list_agents(customer_id=None):
    """Agents joined to their customer name, newest check-in first.

    Passing customer_id restricts the result to that tenant. None means every
    agent and is only reachable from a superadmin code path."""
    conn = get_connection(); c = conn.cursor()
    sql = """
        SELECT a.*, cu.name AS customer_name
        FROM agents a
        JOIN customers cu ON cu.id = a.customer_id
    """
    params = ()
    if customer_id is not None:
        sql += " WHERE a.customer_id = ? "
        params = (customer_id,)
    sql += " ORDER BY cu.name COLLATE NOCASE ASC, a.name COLLATE NOCASE ASC"
    c.execute(sql, params)
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    for r in rows:
        r["summary"] = _parse_summary(r.get("last_summary_json"))
    return rows


def _parse_summary(raw):
    if not raw:
        return {}
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else {}
    except (ValueError, TypeError):
        return {}


def update_agent_report(agent_uid, summary, agent_version="", risk_level="unknown"):
    """Record an accepted check-in. `summary` must already be validated."""
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        UPDATE agents
        SET last_seen = ?, last_summary_json = ?, agent_version = ?, risk_level = ?
        WHERE agent_uid = ?""",
              (_utcnow(), json.dumps(summary), agent_version, risk_level, agent_uid))
    conn.commit(); n = c.rowcount; conn.close()
    return n


def update_agent_meta(agent_uid, name=None, dashboard_url=None, notes=None,
                      customer_id=None):
    """Edit an agent's descriptive fields. `customer_id` scopes the write."""
    sets, params = [], []
    if name is not None:
        sets.append("name = ?"); params.append(name)
    if dashboard_url is not None:
        sets.append("dashboard_url = ?"); params.append(dashboard_url)
    if notes is not None:
        sets.append("notes = ?"); params.append(notes)
    if not sets:
        return 0
    sql = f"UPDATE agents SET {', '.join(sets)} WHERE agent_uid = ?"
    params.append(agent_uid)
    if customer_id is not None:
        sql += " AND customer_id = ?"; params.append(customer_id)
    conn = get_connection(); c = conn.cursor()
    c.execute(sql, params)
    conn.commit(); n = c.rowcount; conn.close()
    return n


def rotate_agent_key(agent_uid, api_key_hash, customer_id=None):
    sql = "UPDATE agents SET api_key_hash = ? WHERE agent_uid = ?"
    params = [api_key_hash, agent_uid]
    if customer_id is not None:
        sql += " AND customer_id = ?"; params.append(customer_id)
    conn = get_connection(); c = conn.cursor()
    c.execute(sql, params)
    conn.commit(); n = c.rowcount; conn.close()
    return n


def delete_agent(agent_uid, customer_id=None):
    sql = "DELETE FROM agents WHERE agent_uid = ?"
    params = [agent_uid]
    if customer_id is not None:
        sql += " AND customer_id = ?"; params.append(customer_id)
    conn = get_connection(); c = conn.cursor()
    c.execute(sql, params)
    conn.commit(); n = c.rowcount; conn.close()
    return n


# =========================================================================
# USERS
# =========================================================================

def count_users():
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT COUNT(*) AS cnt FROM users")
    n = c.fetchone()["cnt"]; conn.close()
    return n


def create_user(username, password_hash, role="customer_admin", customer_id=None,
                totp_secret=None, is_root=0):
    conn = get_connection(); c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO users (username, password_hash, role, customer_id,
                               totp_secret, is_root)
            VALUES (?, ?, ?, ?, ?, ?)""",
                  (username, password_hash, role, customer_id, totp_secret, is_root))
        conn.commit()
        return c.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone(); conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone(); conn.close()
    return dict(row) if row else None


def list_users():
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT u.*, cu.name AS customer_name
        FROM users u LEFT JOIN customers cu ON cu.id = u.customer_id
        ORDER BY u.id ASC""")
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_root_user():
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE is_root = 1 ORDER BY id ASC LIMIT 1")
    row = c.fetchone(); conn.close()
    return dict(row) if row else None


def set_user_totp(user_id, secret, enabled=1):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET totp_secret = ?, mfa_enabled = ? WHERE id = ?",
              (secret, enabled, user_id))
    conn.commit(); conn.close()


def set_user_password(user_id, password_hash):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit(); conn.close()


def set_user_disabled(user_id, disabled):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, user_id))
    conn.commit(); conn.close()


def set_user_theme(user_id, theme):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET theme = ? WHERE id = ?", (theme, user_id))
    conn.commit(); conn.close()


def update_last_login(user_id, when):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET last_login = ? WHERE id = ?", (when, user_id))
    conn.commit(); conn.close()


def delete_user(user_id):
    conn = get_connection(); c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ? AND is_root = 0", (user_id,))
    conn.commit(); n = c.rowcount; conn.close()
    return n


# =========================================================================
# AUDIT + SETTINGS
# =========================================================================

def add_audit(username, action, detail="", ip=""):
    conn = get_connection(); c = conn.cursor()
    c.execute("INSERT INTO audit_log (username, action, detail, ip) VALUES (?, ?, ?, ?)",
              (username, action, detail, ip))
    conn.commit(); conn.close()


def get_audit(limit=200):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_setting(key):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone(); conn.close()
    return row["value"] if row else None


def set_setting(key, value):
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                       updated_at = CURRENT_TIMESTAMP""",
              (key, value))
    conn.commit(); conn.close()


if __name__ == "__main__":
    init_db()
    print(f"[CENTRAL-DB] Initialised {DATABASE_PATH}")
