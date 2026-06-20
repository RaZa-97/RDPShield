"""
RDPShield Database Module v2.0
===============================
Handles all SQLite operations.

Tables (existing):
  failed_logins    - Every Event ID 4625 captured
  alerts           - Detection alerts (brute force, spray, slow-and-low, geo_block)
  blocked_ips      - Currently blocked IP addresses

Tables (new in v2.0 - for geo-blocking):
  geo_settings     - Stores the current geo-blocking mode
  allowed_countries - Countries permitted to connect (Mode 3)
  allowed_ips      - Specific IPs permitted to connect (Mode 2)
  geo_cache        - Caches IP-to-country lookups to avoid re-querying ip-api
  geo_events       - Logs every geo-checked connection attempt
"""

import sqlite3
import os
from datetime import datetime, timedelta
from config import DATABASE_PATH


def get_connection():
    """
    Create a connection to the SQLite database.
    Creates the database file if it doesn't exist.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create all tables if they don't exist.
    Run this once when RDPShield starts.
    """
    conn = get_connection()
    cursor = conn.cursor()




    # =========================================================================
    # EXISTING TABLES (from v1.0)
    # =========================================================================

    # Table 1: Every failed login event captured from Event Log
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            domain TEXT DEFAULT '',
            logon_type INTEGER DEFAULT 3,
            sub_status TEXT DEFAULT '',
            workstation TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table 2: Detection alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            description TEXT NOT NULL,
            usernames TEXT DEFAULT '',
            failure_count INTEGER DEFAULT 0,
            geo_country TEXT DEFAULT '',
            geo_city TEXT DEFAULT '',
            abuse_score INTEGER DEFAULT 0,
            blocked INTEGER DEFAULT 0,
            sms_sent INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table 3: Currently blocked IPs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            reason TEXT NOT NULL,
            blocked_at TEXT DEFAULT CURRENT_TIMESTAMP,
            unblock_at TEXT DEFAULT '',
            is_active INTEGER DEFAULT 1
        )
    """)

    # =========================================================================
    # NEW TABLES (v2.0 - Geo-blocking)
    # =========================================================================

    # Table 4: Geo-blocking settings
    # Stores the current mode:
    #   "allow_anywhere"       - No geo-blocking (default)
    #   "private_and_allowed"  - Whitelist only: block everyone except IPs
    #                            in the allowed list (public AND private)
    #   "country_list"         - Only allow IPs from listed countries
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS geo_settings (
            id INTEGER PRIMARY KEY,
            mode TEXT NOT NULL DEFAULT 'allow_anywhere'
        )
    """)

    # Insert default setting if table is empty
    cursor.execute("SELECT COUNT(*) as cnt FROM geo_settings")
    if cursor.fetchone()["cnt"] == 0:
        cursor.execute(
            "INSERT INTO geo_settings (id, mode) VALUES (1, 'allow_anywhere')"
        )

    # Table 5: Allowed countries (for "country_list" mode)
    # Each row is one country that's permitted to connect.
    # Country names match what ip-api.com returns (e.g., "Sri Lanka", "India")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS allowed_countries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            country_name TEXT NOT NULL UNIQUE,
            added_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table 6: Allowed IPs (for "private_and_allowed" mode)
    # Specific IPs that are whitelisted to connect - public or private
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS allowed_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            added_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table 7: Geo cache
    # Caches IP-to-country lookups so we don't re-query ip-api.com
    # for the same IP. ip-api has a 45 requests/minute rate limit.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip_address TEXT PRIMARY KEY,
            country TEXT DEFAULT '',
            city TEXT DEFAULT '',
            isp TEXT DEFAULT '',
            country_code TEXT DEFAULT '',
            cached_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table 8: Geo events log
    # Logs every geo-checked connection with the result (allowed/blocked)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS geo_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            username TEXT DEFAULT '',
            country TEXT DEFAULT '',
            city TEXT DEFAULT '',
            isp TEXT DEFAULT '',
            event_type TEXT DEFAULT '',
            action TEXT NOT NULL,
            reason TEXT DEFAULT ''
        )
    """)

    conn.commit()
    conn.close()
    create_yara_tables()
    print("[DB] Database initialized successfully.")

# ============ YARA tables (v3.0) ============

def create_yara_tables():
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS yara_scans (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            triggered_by      TEXT,
            started_at        TEXT,
            completed_at      TEXT,
            duration          REAL,
            total_findings    INTEGER DEFAULT 0,
            critical_findings INTEGER DEFAULT 0,
            max_severity      TEXT,
            scanned_memory    INTEGER DEFAULT 0,
            scanned_disk      INTEGER DEFAULT 0,
            error             TEXT
        )""")
    c.execute("""
        CREATE TABLE IF NOT EXISTS yara_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER,
            rule_name       TEXT,
            severity        TEXT,
            category        TEXT,
            description     TEXT,
            match_type      TEXT,
            location        TEXT,
            matched_strings TEXT,
            detected_at     TEXT,
            confidence      REAL,
            suppressed      INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES yara_scans(id)
        )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_yara_findings_scan ON yara_findings(scan_id)")
    _migrate_yara_findings_columns(c)
    conn.commit(); conn.close()


def _migrate_yara_findings_columns(c):
    """Add confidence / suppressed columns to yara_findings if not present.
    Safe to run every startup: only adds a column when it's missing."""
    c.execute("PRAGMA table_info(yara_findings)")
    cols = {row[1] for row in c.fetchall()}   # row[1] = column name
    if "confidence" not in cols:
        c.execute("ALTER TABLE yara_findings ADD COLUMN confidence REAL")
    if "suppressed" not in cols:
        c.execute("ALTER TABLE yara_findings ADD COLUMN suppressed INTEGER DEFAULT 0")


def log_yara_scan(triggered_by, result, started_at, completed_at):
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        INSERT INTO yara_scans
            (triggered_by, started_at, completed_at, duration,
             total_findings, critical_findings, max_severity,
             scanned_memory, scanned_disk, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (triggered_by, started_at, completed_at, result.get("duration"),
          result.get("total", 0), result.get("critical_count", 0),
          result.get("max_severity"),
          1 if result.get("scanned_memory") else 0,
          1 if result.get("scanned_disk") else 0,
          result.get("error")))
    scan_id = c.lastrowid
    for f in result.get("findings", []):
        c.execute("""
            INSERT INTO yara_findings
                (scan_id, rule_name, severity, category, description,
                 match_type, location, matched_strings, detected_at,
                 confidence, suppressed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, f.get("rule_name"), f.get("severity"), f.get("category"),
              f.get("description"), f.get("match_type"), f.get("location"),
              f.get("matched_strings"), f.get("detected_at"),
              f.get("confidence"), 1 if f.get("suppressed") else 0))
    conn.commit(); conn.close()
    return scan_id


def get_yara_history(limit=50):
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT id, triggered_by, started_at, completed_at, duration,
               total_findings, critical_findings, max_severity, error
        FROM yara_scans ORDER BY id DESC LIMIT ?""", (limit,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_yara_findings(scan_id):
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT id, scan_id, rule_name, severity, category, description,
               match_type, location, matched_strings, detected_at,
               confidence, suppressed
        FROM yara_findings WHERE scan_id = ?
        ORDER BY suppressed ASC,
                 CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                               WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
                 id ASC""", (scan_id,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_suppressed_findings(limit=50):
    """Most recent suppressed (low-confidence) findings, newest first.
    Used for review and as future training data."""
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT scan_id, rule_name, severity, match_type, location, confidence
        FROM yara_findings
        WHERE suppressed = 1
        ORDER BY id DESC LIMIT ?""", (limit,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows
# =============================================================================
# EXISTING FUNCTIONS (from v1.0)
# =============================================================================

def log_failed_login(timestamp, source_ip, username, domain="",
                     logon_type=3, sub_status="", workstation=""):
    """Store a single failed login event."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO failed_logins
            (timestamp, source_ip, username, domain, logon_type,
             sub_status, workstation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, source_ip, username, domain, logon_type,
          sub_status, workstation))
    conn.commit()
    conn.close()


def log_alert(alert_type, source_ip, description, usernames="",
              failure_count=0, geo_country="", geo_city="",
              abuse_score=0, blocked=0, sms_sent=0):
    """Store a detection alert."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts
            (timestamp, alert_type, source_ip, description, usernames,
             failure_count, geo_country, geo_city, abuse_score,
             blocked, sms_sent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), alert_type, source_ip, description,
          usernames, failure_count, geo_country, geo_city, abuse_score,
          blocked, sms_sent))
    conn.commit()
    conn.close()


def log_blocked_ip(ip_address, reason, unblock_at=""):
    """
    Record that an IP has been blocked via Windows Firewall.
    If the IP was previously unblocked, reactivate it.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO blocked_ips (ip_address, reason, unblock_at)
            VALUES (?, ?, ?)
        """, (ip_address, reason, unblock_at))
        conn.commit()
    except sqlite3.IntegrityError:
        cursor.execute("""
            UPDATE blocked_ips
            SET is_active = 1, reason = ?, blocked_at = CURRENT_TIMESTAMP
            WHERE ip_address = ?
        """, (reason, ip_address))
        conn.commit()
    conn.close()


def unblock_ip_record(ip_address):
    """Mark an IP as unblocked in the database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ?
    """, (ip_address,))
    conn.commit()
    conn.close()


def is_ip_blocked(ip_address):
    """Check if an IP is currently in the blocked list."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM blocked_ips
        WHERE ip_address = ? AND is_active = 1
    """, (ip_address,))
    result = cursor.fetchone()
    conn.close()
    return result["cnt"] > 0


def get_failed_logins_for_ip(source_ip, since_seconds):
    """Get all failed logins for a specific IP within a time window."""
    conn = get_connection()
    cursor = conn.cursor()
    cutoff = datetime.now().timestamp() - since_seconds
    cutoff_str = datetime.fromtimestamp(cutoff).isoformat()
    cursor.execute("""
        SELECT * FROM failed_logins
        WHERE source_ip = ? AND timestamp >= ?
        ORDER BY timestamp ASC
    """, (source_ip, cutoff_str))
    rows = cursor.fetchall()
    conn.close()
    return rows


def count_failed_logins(source_ip):
    """Total number of failed logins ever recorded from an IP (for SMS/alerts)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM failed_logins WHERE source_ip = ?",
        (source_ip,)
    )
    result = cursor.fetchone()
    conn.close()
    return result["cnt"]


def get_unique_usernames_for_ip(source_ip, since_seconds):
    """Get unique usernames targeted by an IP within a time window."""
    conn = get_connection()
    cursor = conn.cursor()
    cutoff = datetime.now().timestamp() - since_seconds
    cutoff_str = datetime.fromtimestamp(cutoff).isoformat()
    cursor.execute("""
        SELECT DISTINCT username FROM failed_logins
        WHERE source_ip = ? AND timestamp >= ?
    """, (source_ip, cutoff_str))
    rows = cursor.fetchall()
    conn.close()
    return [row["username"] for row in rows]


def get_recent_alerts(limit=50):
    """
    Get the most recent alerts for the dashboard. Each alert also carries
    `attempts` — the total number of failed logins ever recorded from that
    attacker IP — so the dashboard can show how many tries the IP made.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.*,
               (SELECT COUNT(*) FROM failed_logins f
                WHERE f.source_ip = a.source_ip) AS attempts
        FROM alerts a
        ORDER BY a.created_at DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_blocked_ips():
    """
    Get all currently blocked IPs for the dashboard. Each row also carries
    `attempts` — the total failed logins recorded from that IP.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT b.*,
               (SELECT COUNT(*) FROM failed_logins f
                WHERE f.source_ip = b.ip_address) AS attempts
        FROM blocked_ips b
        WHERE b.is_active = 1
        ORDER BY b.blocked_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_failed_logins(limit=100):
    """
    Get the most recent failed login events, joined with the geo cache so
    each row carries the attacker's country (when known). geo_country is
    NULL/empty for private IPs or IPs not yet geolocated.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT fl.*, gc.country AS geo_country, gc.city AS geo_city
        FROM failed_logins fl
        LEFT JOIN geo_cache gc ON gc.ip_address = fl.source_ip
        ORDER BY fl.timestamp DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dashboard_stats():
    """Get summary statistics for the dashboard header."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM failed_logins")
    total_failed = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM alerts")
    total_alerts = cursor.fetchone()["cnt"]

    cursor.execute(
        "SELECT COUNT(*) as cnt FROM blocked_ips WHERE is_active = 1"
    )
    total_blocked = cursor.fetchone()["cnt"]

    cursor.execute(
        "SELECT COUNT(DISTINCT source_ip) as cnt FROM failed_logins"
    )
    unique_ips = cursor.fetchone()["cnt"]

    cursor.execute("""
        SELECT alert_type, COUNT(*) as cnt FROM alerts
        GROUP BY alert_type
    """)
    alert_types = {row["alert_type"]: row["cnt"] for row in cursor.fetchall()}

    conn.close()

    return {
        "total_failed_logins": total_failed,
        "total_alerts": total_alerts,
        "total_blocked": total_blocked,
        "unique_attacker_ips": unique_ips,
        "alerts_by_type": alert_types,
    }


def get_failed_login_trend(days=14):
    """
    Get a daily count of failed logins for the last N days, for the
    dashboard trend chart. Days with zero events are filled in with 0
    so the chart always shows a continuous range.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT substr(timestamp, 1, 10) as day, COUNT(*) as cnt
        FROM failed_logins
        WHERE timestamp >= date('now', ?)
        GROUP BY day
        ORDER BY day ASC
    """, (f"-{days - 1} days",))
    counts = {row["day"]: row["cnt"] for row in cursor.fetchall()}
    conn.close()

    labels, values = [], []
    for i in range(days - 1, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        labels.append(day)
        values.append(counts.get(day, 0))

    return {"labels": labels, "values": values}


def get_alert_type_breakdown(days=30):
    """Get alert counts by type within the last N days, for the dashboard bar chart."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT alert_type, COUNT(*) as cnt
        FROM alerts
        WHERE timestamp >= date('now', ?)
        GROUP BY alert_type
    """, (f"-{days} days",))
    breakdown = {row["alert_type"]: row["cnt"] for row in cursor.fetchall()}
    conn.close()
    return breakdown


def get_top_attacker_countries(limit=6):
    """Get the countries with the most alerts, for the dashboard breakdown panel."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT geo_country as country, COUNT(*) as cnt
        FROM alerts
        WHERE geo_country IS NOT NULL AND geo_country != ''
        GROUP BY geo_country
        ORDER BY cnt DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


# =============================================================================
# NEW FUNCTIONS (v2.0 - Geo-blocking)
# =============================================================================

# --- Geo Settings ---

def get_geo_mode():
    """
    Get the current geo-blocking mode.

    Returns one of:
    - "allow_anywhere" (default - no geo-blocking)
    - "private_and_allowed" (whitelist only - blocks everyone except
      whitelisted IPs, public or private)
    - "country_list" (only allow listed countries)
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT mode FROM geo_settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    return row["mode"] if row else "allow_anywhere"


def set_geo_mode(mode):
    """
    Set the geo-blocking mode.

    Args:
        mode: "allow_anywhere", "private_and_allowed", or "country_list"
    """
    valid_modes = ["allow_anywhere", "private_and_allowed", "country_list"]
    if mode not in valid_modes:
        print(f"[DB] Invalid geo mode: {mode}")
        return False

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE geo_settings SET mode = ? WHERE id = 1", (mode,))
    conn.commit()
    conn.close()
    print(f"[DB] Geo mode set to: {mode}")
    return True


# --- Allowed Countries ---

def get_allowed_countries():
    """Get all allowed countries as a list of dictionaries."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM allowed_countries ORDER BY country_name ASC"
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_allowed_country(country_name):
    """
    Add a country to the allowed list.
    Country name should match ip-api.com format (e.g., "Sri Lanka", "India").
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO allowed_countries (country_name) VALUES (?)",
            (country_name,)
        )
        conn.commit()
        print(f"[DB] Added allowed country: {country_name}")
        result = True
    except sqlite3.IntegrityError:
        print(f"[DB] Country already exists: {country_name}")
        result = False
    conn.close()
    return result


def remove_allowed_country(country_name):
    """Remove a country from the allowed list."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM allowed_countries WHERE country_name = ?",
        (country_name,)
    )
    conn.commit()
    conn.close()
    print(f"[DB] Removed allowed country: {country_name}")


def is_country_allowed(country_name):
    """Check if a country is in the allowed list."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM allowed_countries WHERE country_name = ?",
        (country_name,)
    )
    result = cursor.fetchone()
    conn.close()
    return result["cnt"] > 0


# --- Allowed IPs ---

def get_allowed_ips():
    """Get all allowed IPs as a list of dictionaries."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM allowed_ips ORDER BY ip_address ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_allowed_ip(ip_address, description=""):
    """Add an IP to the allowed list (for private_and_allowed / whitelist-only mode)."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO allowed_ips (ip_address, description) VALUES (?, ?)",
            (ip_address, description)
        )
        conn.commit()
        print(f"[DB] Added allowed IP: {ip_address}")
        result = True
    except sqlite3.IntegrityError:
        print(f"[DB] IP already exists: {ip_address}")
        result = False
    conn.close()
    return result


def remove_allowed_ip(ip_address):
    """Remove an IP from the allowed list."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM allowed_ips WHERE ip_address = ?", (ip_address,)
    )
    conn.commit()
    conn.close()
    print(f"[DB] Removed allowed IP: {ip_address}")


def is_ip_allowed(ip_address):
    """Check if an IP is in the allowed list."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM allowed_ips WHERE ip_address = ?",
        (ip_address,)
    )
    result = cursor.fetchone()
    conn.close()
    return result["cnt"] > 0


# --- Geo Cache ---

def get_cached_geo(ip_address):
    """
    Get cached geolocation data for an IP.
    Returns a dictionary with country, city, isp, or None if not cached.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM geo_cache WHERE ip_address = ?", (ip_address,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def cache_geo(ip_address, country="", city="", isp="", country_code=""):
    """
    Store geolocation data for an IP in the cache.
    Next time we see this IP, we won't need to call ip-api.com again.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO geo_cache
                (ip_address, country, city, isp, country_code)
            VALUES (?, ?, ?, ?, ?)
        """, (ip_address, country, city, isp, country_code))
        conn.commit()
    except sqlite3.IntegrityError:
        # Already cached - update it
        cursor.execute("""
            UPDATE geo_cache
            SET country = ?, city = ?, isp = ?, country_code = ?,
                cached_at = CURRENT_TIMESTAMP
            WHERE ip_address = ?
        """, (country, city, isp, country_code, ip_address))
        conn.commit()
    conn.close()


# --- Geo Events Log ---

def log_geo_event(source_ip, username, country, city, isp,
                  event_type, action, reason=""):
    """
    Log a geo-checked connection attempt.

    Args:
        source_ip: The connecting IP
        username: Who tried to log in
        country: Country from geolocation
        city: City from geolocation
        isp: Internet service provider
        event_type: "failed_login" or "successful_login"
        action: "allowed" or "blocked"
        reason: Why it was blocked (e.g., "Country not in allowed list")
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO geo_events
            (source_ip, username, country, city, isp,
             event_type, action, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (source_ip, username, country, city, isp,
          event_type, action, reason))
    conn.commit()
    conn.close()


def get_geo_events(limit=100):
    """Get recent geo events for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM geo_events ORDER BY timestamp DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_geo_stats():
    """Get geo-blocking statistics for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    # Total geo-blocked connections
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM geo_events WHERE action = 'blocked'"
    )
    total_blocked = cursor.fetchone()["cnt"]

    # Total geo-allowed connections
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM geo_events WHERE action = 'allowed'"
    )
    total_allowed = cursor.fetchone()["cnt"]

    # Most blocked country
    cursor.execute("""
        SELECT country, COUNT(*) as cnt FROM geo_events
        WHERE action = 'blocked' AND country != ''
        GROUP BY country ORDER BY cnt DESC LIMIT 1
    """)
    row = cursor.fetchone()
    top_blocked_country = dict(row) if row else {"country": "None", "cnt": 0}

    # Current mode
    mode = get_geo_mode()

    conn.close()

    return {
        "total_geo_blocked": total_blocked,
        "total_geo_allowed": total_allowed,
        "top_blocked_country": top_blocked_country,
        "geo_mode": mode,
    }


# If this file is run directly, initialize the database
if __name__ == "__main__":
    init_db()
    print("[DB] Tables created. Database is ready.")