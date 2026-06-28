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
from datetime import datetime, timedelta, timezone
from config import DATABASE_PATH


# =============================================================================
# DISPLAY HELPERS (timestamps + standardized attack/event labels)
# =============================================================================
# Some columns are stored in UTC (SQLite CURRENT_TIMESTAMP, and the Windows
# Event Log "...Z" times), while alerts.timestamp / yara_scans.* are written in
# local server time via datetime.now(). That mismatch made the dashboard tables
# disagree with each other and with the wall clock. These helpers convert the
# UTC columns to Colombo time *for display only* — stored data and the detection
# logic (which parses the raw UTC timestamps) are left completely untouched.

# Display timezone = Asia/Colombo (Sri Lanka). It's a FIXED UTC+5:30 (no DST),
# so a fixed-offset zone is exact and — unlike zoneinfo("Asia/Colombo") — needs
# no IANA tz database (tzdata), which Windows lacks by default. Pinning the
# offset means the dashboard reads in Sri Lanka time even if the server's OS
# clock is ever set to UTC.
DISPLAY_TZ = timezone(timedelta(hours=5, minutes=30))


def utc_to_local_str(ts):
    """Convert a stored UTC timestamp string to an Asia/Colombo display string.

    Tolerates the Event-Log form ('2026-06-27T09:03:28.6098517Z'), the SQLite
    CURRENT_TIMESTAMP form ('2026-06-27 09:03:28') and plain ISO 'T'. Returns
    'YYYY-MM-DD HH:MM:SS' in Colombo time. Empty / unparseable input is returned
    unchanged. Display-only — never use for detection windows.
    """
    if not ts:
        return ts
    s = str(ts).strip().replace("Z", "").replace("T", " ")
    if "." in s:
        s = s.split(".", 1)[0]                 # drop fractional seconds
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return ts


def local_ts_display(ts):
    """Normalize an ALREADY-local timestamp (alerts.timestamp / yara_scans.*,
    written by datetime.now()) for display: 'T' -> space, drop fractional
    seconds, trim to whole seconds. No timezone shift — these are already in the
    server's local (Colombo) time — just a uniform 'YYYY-MM-DD HH:MM:SS' format
    so every table matches."""
    if not ts:
        return ts
    s = str(ts).strip().replace("T", " ")
    if "." in s:
        s = s.split(".", 1)[0]
    return s[:19]


# Canonical, human-readable names for every detection / block reason and login
# event. Single source of truth so every table in the UI labels things the same
# way ("Persistent Attack", not "persistent_attack").
ATTACK_LABELS = {
    "brute_force":       "Brute Force",
    "slow_attack":       "Slow-and-Low",
    "password_spray":    "Password Spray",
    "persistent_attack": "Persistent Attack",
    "geo_block":         "Geo Block",
    "whitelist_block":   "Non-Whitelisted IP",
    "manual_block":      "Manual Block",
    "manual":            "Manual Block",
    "manual_memory":     "Manual (Memory)",
    "reputation_alert":  "Reputation Alert",
    "campaign_alert":    "Campaign",
}

EVENT_LABELS = {
    "failed_login":     "Login Failure",
    "successful_login": "Successful Login",
}


def attack_label(alert_type):
    """Standardized display name for an alert/block type. Unknown types are
    title-cased as a graceful fallback; empty/None becomes an em dash."""
    if not alert_type:
        return "—"
    return ATTACK_LABELS.get(alert_type, str(alert_type).replace("_", " ").title())


def event_label(event_type):
    """Standardized display name for a login event type."""
    if not event_type:
        return "—"
    return EVENT_LABELS.get(event_type, str(event_type).replace("_", " ").title())


def _derive_attack_method(reason, alert_type):
    """Best-effort canonical attack-method key for a blocked IP. Prefers the
    reason prefix the detector wrote ('brute_force: ...'), then a manual-block
    phrase, then the most recent alert type for the IP."""
    reason = (reason or "").strip()
    prefix = reason.split(":", 1)[0].strip().lower().replace(" ", "_")
    if prefix in ATTACK_LABELS:
        return prefix
    if "manual" in reason.lower():
        return "manual_block"
    if alert_type:
        return alert_type
    return "manual_block" if reason else ""


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
            lat REAL DEFAULT 0,
            lon REAL DEFAULT 0,
            cached_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migrate older installs that pre-date lat/lon (for the attack map).
    _gc_cols = {r["name"] for r in cursor.execute("PRAGMA table_info(geo_cache)").fetchall()}
    if "lat" not in _gc_cols:
        cursor.execute("ALTER TABLE geo_cache ADD COLUMN lat REAL DEFAULT 0")
    if "lon" not in _gc_cols:
        cursor.execute("ALTER TABLE geo_cache ADD COLUMN lon REAL DEFAULT 0")

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

    # Migration: tag each geo event with a category so the Advanced Security
    # page can show a separate log/graph per section:
    #   "geo"       = country-based check (allow_anywhere / country_list)
    #   "whitelist" = IP-whitelist check (private_and_allowed)
    # Existing rows are backfilled from their reason text.
    cursor.execute("PRAGMA table_info(geo_events)")
    geo_cols = {row[1] for row in cursor.fetchall()}
    if "category" not in geo_cols:
        cursor.execute("ALTER TABLE geo_events ADD COLUMN category TEXT DEFAULT ''")
        cursor.execute("UPDATE geo_events SET category='whitelist' WHERE reason LIKE 'IP %'")
        cursor.execute("UPDATE geo_events SET category='geo' WHERE reason LIKE 'Country%'")

    conn.commit()
    conn.close()
    create_yara_tables()
    create_users_table()
    create_abuse_cache_table()
    create_campaigns_table()
    print("[DB] Database initialized successfully.")


# =============================================================================
# ABUSE / REPUTATION CACHE (for the reputation-alert detector)
# =============================================================================
# Caches AbuseIPDB (+ optional VirusTotal) results per IP so the reputation
# check can run on low-volume attackers without burning API quota, and so the
# alert-only tier texts the SOC at most once per cache window per IP.

def create_abuse_cache_table():
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS abuse_cache (
            ip_address    TEXT PRIMARY KEY,
            abuse_score   INTEGER DEFAULT 0,
            total_reports INTEGER DEFAULT 0,
            is_tor        INTEGER DEFAULT 0,
            vt_malicious  INTEGER DEFAULT -1,   -- -1 = VT not checked
            alerted       INTEGER DEFAULT 0,    -- 1 = SOC already alerted this window
            checked_at    TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.commit(); conn.close()


def get_cached_abuse(ip_address, max_age_hours=24):
    """Return the cached reputation dict for an IP, or None if missing/stale."""
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM abuse_cache WHERE ip_address = ?", (ip_address,))
    row = c.fetchone(); conn.close()
    if not row:
        return None
    try:
        checked = datetime.strptime(row["checked_at"][:19].replace("T", " "),
                                    "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    # checked_at is UTC (CURRENT_TIMESTAMP); compare in naive UTC.
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    if now_utc - checked > timedelta(hours=max_age_hours):
        return None
    return dict(row)


def cache_abuse(ip_address, abuse_score, total_reports=0, is_tor=False,
                vt_malicious=-1):
    """Upsert a fresh reputation result. Resets the cache window and the
    'alerted' flag so a new window allows one fresh SOC alert."""
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        INSERT INTO abuse_cache
            (ip_address, abuse_score, total_reports, is_tor, vt_malicious,
             alerted, checked_at)
        VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
        ON CONFLICT(ip_address) DO UPDATE SET
            abuse_score=excluded.abuse_score,
            total_reports=excluded.total_reports,
            is_tor=excluded.is_tor,
            vt_malicious=excluded.vt_malicious,
            alerted=0,
            checked_at=CURRENT_TIMESTAMP
    """, (ip_address, int(abuse_score), int(total_reports),
          1 if is_tor else 0, int(vt_malicious)))
    conn.commit(); conn.close()


def mark_abuse_alerted(ip_address):
    """Record that the SOC has been alerted for this IP this cache window
    (so the alert-only tier doesn't re-text on every subsequent failed login)."""
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE abuse_cache SET alerted = 1 WHERE ip_address = ?", (ip_address,))
    conn.commit(); conn.close()


# =============================================================================
# CAMPAIGN / COORDINATED-ATTACK ANALYSIS (long-horizon, e.g. 7 days)
# =============================================================================
# Correlates failed logins over a multi-day window to surface campaigns that no
# single-window detector catches: a determined IP active across many days, a
# country attacking with many IPs, and attacks that recur in the same
# time-of-day band. Day/hour bucketing uses LOCAL time (SQLite 'localtime') so
# it matches the dashboard's localized timestamps.

def create_campaigns_table():
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            ckey           TEXT UNIQUE,        -- 'ip:1.2.3.4' or 'country:Vietnam'
            ctype          TEXT,               -- 'ip' | 'country'
            label          TEXT,               -- display label (IP or country name)
            country        TEXT DEFAULT '',
            total_fails    INTEGER DEFAULT 0,
            distinct_days  INTEGER DEFAULT 0,
            distinct_ips   INTEGER DEFAULT 0,  -- country campaigns only
            peak_window    TEXT DEFAULT '',    -- e.g. '02:00-05:00' local
            peak_pct       INTEGER DEFAULT 0,  -- % of attempts in that band
            scheduled      INTEGER DEFAULT 0,  -- 1 = recurring same-time-of-day
            blocked        INTEGER DEFAULT 0,
            first_detected TEXT DEFAULT CURRENT_TIMESTAMP,
            last_alerted_at TEXT,
            updated_at     TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.commit(); conn.close()


def get_campaign_ip_offenders(days, min_days, min_fails):
    """IPs active across >= min_days distinct days with >= min_fails failures in
    the last `days` days. The week-long determined single attacker."""
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT fl.source_ip AS source_ip,
               COUNT(*) AS total_fails,
               COUNT(DISTINCT substr(datetime(fl.timestamp,'localtime'),1,10)) AS distinct_days,
               (SELECT gc.country FROM geo_cache gc WHERE gc.ip_address = fl.source_ip) AS country,
               MIN(fl.timestamp) AS first_seen, MAX(fl.timestamp) AS last_seen
        FROM failed_logins fl
        WHERE datetime(fl.timestamp,'localtime') >= datetime('now','localtime', ?)
        GROUP BY fl.source_ip
        HAVING distinct_days >= ? AND total_fails >= ?
        ORDER BY total_fails DESC
    """, (f"-{days} days", min_days, min_fails))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_campaign_country_offenders(days, min_ips, min_fails):
    """Countries with >= min_ips distinct attacker IPs and >= min_fails failures
    in the window. The distributed / IP-rotating campaign."""
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT gc.country AS country,
               COUNT(DISTINCT fl.source_ip) AS distinct_ips,
               COUNT(*) AS total_fails,
               COUNT(DISTINCT substr(datetime(fl.timestamp,'localtime'),1,10)) AS distinct_days
        FROM failed_logins fl
        JOIN geo_cache gc ON gc.ip_address = fl.source_ip
        WHERE datetime(fl.timestamp,'localtime') >= datetime('now','localtime', ?)
          AND gc.country <> ''
        GROUP BY gc.country
        HAVING distinct_ips >= ? AND total_fails >= ?
        ORDER BY total_fails DESC
    """, (f"-{days} days", min_ips, min_fails))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_hour_histogram(days, scope, value):
    """24-bucket local-hour histogram of failed logins for one IP or country
    over the window. `scope` is 'ip' or 'country'. Used to find a recurring
    same-time-of-day band."""
    conn = get_connection(); c = conn.cursor()
    if scope == "ip":
        c.execute("""
            SELECT CAST(strftime('%H', datetime(timestamp,'localtime')) AS INT) AS hr,
                   COUNT(*) AS cnt
            FROM failed_logins
            WHERE source_ip = ?
              AND datetime(timestamp,'localtime') >= datetime('now','localtime', ?)
            GROUP BY hr
        """, (value, f"-{days} days"))
    else:
        c.execute("""
            SELECT CAST(strftime('%H', datetime(fl.timestamp,'localtime')) AS INT) AS hr,
                   COUNT(*) AS cnt
            FROM failed_logins fl
            JOIN geo_cache gc ON gc.ip_address = fl.source_ip
            WHERE gc.country = ?
              AND datetime(fl.timestamp,'localtime') >= datetime('now','localtime', ?)
            GROUP BY hr
        """, (value, f"-{days} days"))
    hist = [0] * 24
    for r in c.fetchall():
        if r["hr"] is not None:
            hist[r["hr"]] = r["cnt"]
    conn.close()
    return hist


def upsert_campaign(ckey, ctype, label, country, total_fails, distinct_days,
                    distinct_ips, peak_window, peak_pct, scheduled):
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        INSERT INTO campaigns
            (ckey, ctype, label, country, total_fails, distinct_days,
             distinct_ips, peak_window, peak_pct, scheduled, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(ckey) DO UPDATE SET
            total_fails=excluded.total_fails, distinct_days=excluded.distinct_days,
            distinct_ips=excluded.distinct_ips, peak_window=excluded.peak_window,
            peak_pct=excluded.peak_pct, scheduled=excluded.scheduled,
            country=excluded.country, label=excluded.label,
            updated_at=CURRENT_TIMESTAMP
    """, (ckey, ctype, label, country, total_fails, distinct_days, distinct_ips,
          peak_window, peak_pct, 1 if scheduled else 0))
    conn.commit(); conn.close()


def get_campaign(ckey):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM campaigns WHERE ckey = ?", (ckey,))
    row = c.fetchone(); conn.close()
    return dict(row) if row else None


def mark_campaign_alerted(ckey, blocked=False):
    conn = get_connection(); c = conn.cursor()
    c.execute("""UPDATE campaigns SET last_alerted_at = CURRENT_TIMESTAMP,
                 blocked = MAX(blocked, ?) WHERE ckey = ?""",
              (1 if blocked else 0, ckey))
    conn.commit(); conn.close()


def campaign_needs_alert(ckey, realert_hours):
    """True if this campaign has never been alerted, or not within realert_hours."""
    row = get_campaign(ckey)
    if not row or not row.get("last_alerted_at"):
        return True
    try:
        last = datetime.strptime(row["last_alerted_at"][:19].replace("T", " "),
                                 "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return True
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)   # CURRENT_TIMESTAMP is UTC
    return (now_utc - last) > timedelta(hours=realert_hours)


def get_campaigns(limit=50):
    """Active campaigns for the dashboard tracker, worst first. Localizes times."""
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT * FROM campaigns
        ORDER BY total_fails DESC, distinct_days DESC LIMIT ?""", (limit,))
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d["first_detected"] = utc_to_local_str(d.get("first_detected"))
        d["last_alerted_at"] = utc_to_local_str(d.get("last_alerted_at")) if d.get("last_alerted_at") else ""
        rows.append(d)
    conn.close()
    return rows

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
    # Operator-cleared file hashes; future disk scans skip these.
    c.execute("""
        CREATE TABLE IF NOT EXISTS yara_whitelist (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256    TEXT UNIQUE,
            path      TEXT,
            rule_name TEXT,
            added_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
    _migrate_yara_findings_columns(c)
    conn.commit(); conn.close()


def _migrate_yara_findings_columns(c):
    """Add confidence / suppressed / sha256 columns to yara_findings if not
    present. Safe to run every startup: only adds a column when it's missing."""
    c.execute("PRAGMA table_info(yara_findings)")
    cols = {row[1] for row in c.fetchall()}   # row[1] = column name
    if "confidence" not in cols:
        c.execute("ALTER TABLE yara_findings ADD COLUMN confidence REAL")
    if "suppressed" not in cols:
        c.execute("ALTER TABLE yara_findings ADD COLUMN suppressed INTEGER DEFAULT 0")
    if "sha256" not in cols:
        c.execute("ALTER TABLE yara_findings ADD COLUMN sha256 TEXT DEFAULT ''")
    if "status" not in cols:
        # active | quarantined | whitelisted | ignored | deleted
        c.execute("ALTER TABLE yara_findings ADD COLUMN status TEXT DEFAULT 'active'")


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
                 confidence, suppressed, sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, f.get("rule_name"), f.get("severity"), f.get("category"),
              f.get("description"), f.get("match_type"), f.get("location"),
              f.get("matched_strings"), f.get("detected_at"),
              f.get("confidence"), 1 if f.get("suppressed") else 0,
              f.get("sha256", "")))
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
               confidence, suppressed, sha256, status
        FROM yara_findings WHERE scan_id = ?
        ORDER BY suppressed ASC,
                 CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                               WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
                 id ASC""", (scan_id,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_yara_finding(finding_id):
    """One YARA finding by id (for delete/quarantine/whitelist actions)."""
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT id, scan_id, rule_name, severity, match_type, location, sha256, status
        FROM yara_findings WHERE id = ?""", (finding_id,))
    row = c.fetchone(); conn.close()
    return dict(row) if row else None


# --- finding status (active|quarantined|whitelisted|ignored|deleted) ---

def set_finding_status(finding_id, status):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE yara_findings SET status = ? WHERE id = ?", (status, finding_id))
    conn.commit(); conn.close()


def set_status_by_location(location, status):
    """Propagate a status to EVERY finding of the same file (multiple rules can
    match one file; deleting/quarantining the file must update all of them)."""
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE yara_findings SET status = ? WHERE location = ?", (status, location))
    n = c.rowcount; conn.commit(); conn.close()
    return n


def set_status_by_hash(sha256, status):
    """Propagate a status to every finding with the same file hash."""
    if not sha256:
        return 0
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE yara_findings SET status = ? WHERE sha256 = ?", (status, sha256))
    n = c.rowcount; conn.commit(); conn.close()
    return n


def get_findings_by_status(status, limit=200):
    """All findings currently in a given status, across every scan."""
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        SELECT id, scan_id, rule_name, severity, match_type, location,
               sha256, status, detected_at
        FROM yara_findings WHERE status = ?
        ORDER BY id DESC LIMIT ?""", (status, limit))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_finding_status_counts():
    """Counts per managed status, for the dashboard category buttons."""
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT status, COUNT(*) AS cnt FROM yara_findings GROUP BY status")
    counts = {r["status"]: r["cnt"] for r in c.fetchall()}; conn.close()
    return counts


# --- YARA finding whitelist (operator-cleared file hashes) ---

def add_yara_whitelist(sha256, path="", rule_name=""):
    """Mark a file hash as cleared so future disk scans skip it."""
    if not sha256:
        return False
    conn = get_connection(); c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO yara_whitelist (sha256, path, rule_name) VALUES (?, ?, ?)",
            (sha256, path, rule_name))
        conn.commit(); ok = True
    except sqlite3.IntegrityError:
        ok = False  # already whitelisted
    conn.close()
    return ok


def get_yara_whitelist_hashes():
    """Set of whitelisted SHA-256 hashes (used by the scanner to skip files)."""
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT sha256 FROM yara_whitelist WHERE sha256 != ''")
    rows = [r["sha256"] for r in c.fetchall()]; conn.close()
    return rows


def remove_yara_whitelist(sha256):
    """Remove a hash from the whitelist (so future scans detect it again)."""
    conn = get_connection(); c = conn.cursor()
    c.execute("DELETE FROM yara_whitelist WHERE sha256 = ?", (sha256,))
    conn.commit(); conn.close()


def remove_yara_finding(finding_id):
    """Delete a finding row (after the file is deleted/quarantined)."""
    conn = get_connection(); c = conn.cursor()
    c.execute("DELETE FROM yara_findings WHERE id = ?", (finding_id,))
    conn.commit(); conn.close()


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
    """Get all failed logins for a specific IP within a time window.

    failed_logins.timestamp is stored in UTC (Windows Event Log '...Z'), so the
    cutoff MUST be computed in UTC too. Using local time here (the old bug) made
    the window compare two clocks 5.5h apart on the Colombo server, so the short
    detectors (brute/slow/spray) never matched. The 'T' separator + UTC zone
    match the stored ISO format for a correct lexical string comparison.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cutoff_str = (datetime.now(timezone.utc)
                  - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S")
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


def count_failed_attempts(source_ip):
    """
    Total failed login attempts from an IP, for the post-block SMS.

    Counts failed_logins PLUS geo/whitelist-blocked failed events: in
    whitelist/geo mode a failed login is blocked by geo_check BEFORE it is
    written to failed_logins, so those attempts only exist in geo_events.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM failed_logins WHERE source_ip = ?",
        (source_ip,)
    )
    total = cursor.fetchone()["cnt"]
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM geo_events "
        "WHERE source_ip = ? AND event_type = 'failed_login' AND action = 'blocked'",
        (source_ip,)
    )
    total += cursor.fetchone()["cnt"]
    conn.close()
    return total


def get_unique_usernames_for_ip(source_ip, since_seconds):
    """Get unique usernames targeted by an IP within a time window.

    Same UTC requirement as get_failed_logins_for_ip: the cutoff is computed in
    UTC to match the UTC-stored timestamps (this powers password-spray detection).
    """
    conn = get_connection()
    cursor = conn.cursor()
    cutoff_str = (datetime.now(timezone.utc)
                  - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S")
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
                WHERE f.source_ip = a.source_ip) AS attempts,
               (SELECT gc.isp FROM geo_cache gc
                WHERE gc.ip_address = a.source_ip) AS isp
        FROM alerts a
        ORDER BY a.created_at DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    out = []
    for row in rows:
        d = dict(row)
        # alerts.timestamp is already local (datetime.now) — normalize its format
        # (no tz shift) and add a standardized label.
        d["timestamp"] = local_ts_display(d.get("timestamp"))
        d["type_label"] = attack_label(d.get("alert_type"))
        out.append(d)
    return out


def get_blocked_ips(limit=None):
    """
    Get all currently blocked IPs for the dashboard. Each row also carries
    `attempts` — the total failed logins recorded from that IP.
    Pass `limit` to cap the number of rows (None = all).
    """
    conn = get_connection()
    cursor = conn.cursor()
    sql = """
        SELECT b.*,
               (SELECT COUNT(*) FROM failed_logins f
                WHERE f.source_ip = b.ip_address) AS attempts,
               (SELECT gc.country FROM geo_cache gc
                WHERE gc.ip_address = b.ip_address) AS country,
               (SELECT gc.isp FROM geo_cache gc
                WHERE gc.ip_address = b.ip_address) AS isp,
               (SELECT a.abuse_score FROM alerts a
                WHERE a.source_ip = b.ip_address
                ORDER BY a.id DESC LIMIT 1) AS abuse_score,
               (SELECT a.alert_type FROM alerts a
                WHERE a.source_ip = b.ip_address
                ORDER BY a.id DESC LIMIT 1) AS alert_type
        FROM blocked_ips b
        WHERE b.is_active = 1
        ORDER BY b.blocked_at DESC
    """
    if limit is not None:
        cursor.execute(sql + " LIMIT ?", (limit,))
    else:
        cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    out = []
    for row in rows:
        d = dict(row)
        d["blocked_at"] = utc_to_local_str(d.get("blocked_at"))   # UTC -> local
        d["attack_method"] = attack_label(
            _derive_attack_method(d.get("reason"), d.get("alert_type")))
        out.append(d)
    return out


def get_recent_failed_logins(limit=100):
    """
    Get the most recent failed login events, joined with the geo cache so
    each row carries the attacker's country (when known). geo_country is
    NULL/empty for private IPs or IPs not yet geolocated.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT fl.*, gc.country AS geo_country, gc.city AS geo_city,
               gc.isp AS geo_isp,
               (SELECT a.abuse_score FROM alerts a
                WHERE a.source_ip = fl.source_ip
                ORDER BY a.id DESC LIMIT 1) AS abuse_score
        FROM failed_logins fl
        LEFT JOIN geo_cache gc ON gc.ip_address = fl.source_ip
        ORDER BY fl.timestamp DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    out = []
    for row in rows:
        d = dict(row)
        d["timestamp"] = utc_to_local_str(d.get("timestamp"))     # UTC(Z) -> local
        # Every row here is an Event 4625 — label it as such for consistency.
        d["event_label"] = "Login Failure"
        out.append(d)
    return out


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
    # failed_logins.timestamp is UTC; bucket by LOCAL calendar day (via SQLite's
    # 'localtime' modifier) so the trend chart's days line up with the localized
    # timestamps shown in the tables, instead of splitting late-night events
    # onto the wrong day.
    cursor.execute("""
        SELECT substr(datetime(timestamp, 'localtime'), 1, 10) as day, COUNT(*) as cnt
        FROM failed_logins
        WHERE datetime(timestamp, 'localtime') >= datetime('now', 'localtime', ?)
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
    # alerts.timestamp is stored in LOCAL time, so the window boundary is local
    # too ('now','localtime') for a correct day count.
    cursor.execute("""
        SELECT alert_type, COUNT(*) as cnt
        FROM alerts
        WHERE timestamp >= date('now', 'localtime', ?)
        GROUP BY alert_type
    """, (f"-{days} days",))
    breakdown = {row["alert_type"]: row["cnt"] for row in cursor.fetchall()}
    conn.close()
    return breakdown


def get_attack_map_points(limit=500):
    """
    Attacker locations for the dashboard map: every IP we've alerted on OR
    blocked that has cached lat/lon. Each point carries attempt count, abuse
    score, and whether it's currently blocked, so the map can size/colour it.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT gc.ip_address AS ip, gc.lat, gc.lon, gc.country, gc.city, gc.isp,
               (SELECT COUNT(*) FROM failed_logins f WHERE f.source_ip = gc.ip_address) AS attempts,
               (SELECT a.abuse_score FROM alerts a WHERE a.source_ip = gc.ip_address
                ORDER BY a.id DESC LIMIT 1) AS abuse_score,
               (SELECT COUNT(*) FROM blocked_ips b
                WHERE b.ip_address = gc.ip_address AND b.is_active = 1) AS blocked
        FROM geo_cache gc
        WHERE (gc.lat <> 0 OR gc.lon <> 0)
          AND gc.ip_address IN (
              SELECT source_ip FROM alerts
              UNION SELECT ip_address FROM blocked_ips
              UNION SELECT source_ip FROM failed_logins
          )
        ORDER BY attempts DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_top_attacker_countries(limit=20):
    """
    Countries of every currently-blocked IP, counted and sorted high to low,
    for the dashboard's Top Attacker Countries panel.

    Each active blocked IP contributes one to its country. The country is
    resolved from the most recent alert that carried geo data, falling back
    to the geo cache, so blocked IPs from any detection path are represented.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT country, COUNT(*) as cnt FROM (
            SELECT b.ip_address AS ip,
                   COALESCE(
                       NULLIF((SELECT a.geo_country FROM alerts a
                               WHERE a.source_ip = b.ip_address AND a.geo_country <> ''
                               ORDER BY a.id DESC LIMIT 1), ''),
                       NULLIF((SELECT g.country FROM geo_cache g
                               WHERE g.ip_address = b.ip_address), '')
                   ) AS country
            FROM blocked_ips b
            WHERE b.is_active = 1
        )
        WHERE country IS NOT NULL AND country <> ''
        GROUP BY country
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


def cache_geo(ip_address, country="", city="", isp="", country_code="",
              lat=0, lon=0):
    """
    Store geolocation data for an IP in the cache.
    Next time we see this IP, we won't need to call ip-api.com again.
    lat/lon power the dashboard attack map.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO geo_cache
                (ip_address, country, city, isp, country_code, lat, lon)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip_address, country, city, isp, country_code, lat, lon))
        conn.commit()
    except sqlite3.IntegrityError:
        # Already cached - update it
        cursor.execute("""
            UPDATE geo_cache
            SET country = ?, city = ?, isp = ?, country_code = ?,
                lat = ?, lon = ?, cached_at = CURRENT_TIMESTAMP
            WHERE ip_address = ?
        """, (country, city, isp, country_code, lat, lon, ip_address))
        conn.commit()
    conn.close()


# --- Geo Events Log ---

def log_geo_event(source_ip, username, country, city, isp,
                  event_type, action, reason="", category=""):
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
        category: "geo" (country-based) or "whitelist" (IP-whitelist-based)
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO geo_events
            (source_ip, username, country, city, isp,
             event_type, action, reason, category)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (source_ip, username, country, city, isp,
          event_type, action, reason, category))
    conn.commit()
    conn.close()


def get_geo_events(limit=100, category=None):
    """
    Get recent geo events for the dashboard.
    If category is given ("geo" or "whitelist"), only events of that category
    are returned (so each Advanced Security section gets its own log).
    """
    conn = get_connection()
    cursor = conn.cursor()
    if category:
        cursor.execute("""
            SELECT *,
                   (SELECT a.abuse_score FROM alerts a
                    WHERE a.source_ip = geo_events.source_ip
                    ORDER BY a.id DESC LIMIT 1) AS abuse_score
            FROM geo_events WHERE category = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (category, limit))
    else:
        cursor.execute("""
            SELECT *,
                   (SELECT a.abuse_score FROM alerts a
                    WHERE a.source_ip = geo_events.source_ip
                    ORDER BY a.id DESC LIMIT 1) AS abuse_score
            FROM geo_events ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    out = []
    for row in rows:
        d = dict(row)
        d["timestamp"] = utc_to_local_str(d.get("timestamp"))     # UTC -> local
        d["event_label"] = event_label(d.get("event_type"))
        out.append(d)
    return out


def get_geo_category_stats(category):
    """
    Allowed/blocked counts and top blocked country for one category
    ("geo" or "whitelist"), for that section's stat cards and graph.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) as cnt FROM geo_events WHERE category = ? AND action = 'blocked'",
        (category,)
    )
    blocked = cursor.fetchone()["cnt"]

    cursor.execute(
        "SELECT COUNT(*) as cnt FROM geo_events WHERE category = ? AND action = 'allowed'",
        (category,)
    )
    allowed = cursor.fetchone()["cnt"]

    cursor.execute("""
        SELECT country, COUNT(*) as cnt FROM geo_events
        WHERE category = ? AND action = 'blocked' AND country != ''
        GROUP BY country ORDER BY cnt DESC LIMIT 1
    """, (category,))
    row = cursor.fetchone()
    top_blocked = dict(row) if row else {"country": "None", "cnt": 0}

    conn.close()
    return {"allowed": allowed, "blocked": blocked, "top_blocked_country": top_blocked}


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


# =============================================================================
# USER ACCOUNTS + MFA (v3.3)
# =============================================================================
# Two roles:
#   admin - full control (block/unblock, settings, YARA actions, user mgmt)
#   guest - view dashboards/logs + CSV export only
# Passwords are stored as werkzeug hashes (hashing happens in the auth layer);
# this module is hashing-agnostic and only stores/returns the hash string.
# totp_secret is the per-user base32 TOTP seed; mfa_enabled flips to 1 once the
# user has confirmed enrollment with a valid code.

def create_users_table():
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'guest',
            totp_secret   TEXT,
            mfa_enabled   INTEGER DEFAULT 0,
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login    TEXT,
            disabled      INTEGER DEFAULT 0,
            is_root       INTEGER DEFAULT 0,
            phone         TEXT
        )""")
    # Migrate older installs that pre-date the disabled/is_root/phone columns.
    existing = {r["name"] for r in c.execute("PRAGMA table_info(users)").fetchall()}
    for col, ddl in (("disabled", "INTEGER DEFAULT 0"),
                     ("is_root", "INTEGER DEFAULT 0"),
                     ("phone", "TEXT"),
                     ("theme", "TEXT DEFAULT 'dark'")):
        if col not in existing:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
    # Ensure exactly one root admin exists: the earliest admin account.
    has_root = c.execute("SELECT COUNT(*) AS n FROM users WHERE is_root = 1").fetchone()["n"]
    if not has_root:
        row = c.execute(
            "SELECT id FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1"
        ).fetchone()
        if row:
            c.execute("UPDATE users SET is_root = 1 WHERE id = ?", (row["id"],))
    conn.commit(); conn.close()


def count_users():
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT COUNT(*) AS cnt FROM users")
    n = c.fetchone()["cnt"]; conn.close()
    return n


def create_user(username, password_hash, role="guest", totp_secret=None,
                mfa_enabled=0, phone=None, is_root=0):
    """Create a user. Returns True on success, False if the name is taken."""
    conn = get_connection(); c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO users (username, password_hash, role, totp_secret,
                               mfa_enabled, phone, is_root)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, password_hash, role, totp_secret, mfa_enabled,
              phone, is_root))
        conn.commit(); ok = True
    except sqlite3.IntegrityError:
        ok = False
    conn.close()
    return ok


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
        SELECT id, username, role, mfa_enabled, created_at, last_login,
               disabled, is_root, phone
        FROM users ORDER BY is_root DESC, role = 'admin' DESC, username ASC
    """)
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def get_root_user():
    """The root admin (is_root=1), or the earliest admin as a fallback."""
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE is_root = 1 ORDER BY id ASC LIMIT 1")
    row = c.fetchone()
    if not row:
        c.execute("SELECT * FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1")
        row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_phone(phone):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE phone = ?", (phone,))
    row = c.fetchone(); conn.close()
    return dict(row) if row else None


def set_user_disabled(user_id, disabled):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET disabled = ? WHERE id = ?",
              (1 if disabled else 0, user_id))
    conn.commit(); conn.close()


def update_user_phone(user_id, phone):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET phone = ? WHERE id = ?", (phone, user_id))
    conn.commit(); conn.close()


def delete_user(user_id):
    conn = get_connection(); c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    n = c.rowcount; conn.commit(); conn.close()
    return n > 0


def count_admins():
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin'")
    n = c.fetchone()["cnt"]; conn.close()
    return n


def set_user_totp(user_id, secret, enabled=1):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET totp_secret = ?, mfa_enabled = ? WHERE id = ?",
              (secret, enabled, user_id))
    conn.commit(); conn.close()


def update_user_password(user_id, password_hash):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?",
              (password_hash, user_id))
    conn.commit(); conn.close()


def update_last_login(user_id, when):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET last_login = ? WHERE id = ?", (when, user_id))
    conn.commit(); conn.close()


def set_user_theme(user_id, theme):
    if theme not in ("dark", "light"):
        theme = "dark"
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE users SET theme = ? WHERE id = ?", (theme, user_id))
    conn.commit(); conn.close()


# =============================================================================
# APP SETTINGS, ALERT RECIPIENTS, AUDIT LOG, DATA RETENTION (v3.4)
# =============================================================================

def create_settings_tables():
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key        TEXT PRIMARY KEY,
            value      TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_recipients (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            label      TEXT DEFAULT '',
            phone      TEXT NOT NULL,
            active     INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
    conn.commit(); conn.close()


# --- key/value settings ---
def get_setting(key):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone(); conn.close()
    return row["value"] if row else None


def set_setting(key, value):
    conn = get_connection(); c = conn.cursor()
    c.execute("""
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    """, (key, value))
    conn.commit(); conn.close()


def get_all_settings():
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT key, value, updated_at FROM settings")
    rows = {r["key"]: {"value": r["value"], "updated_at": r["updated_at"]} for r in c.fetchall()}
    conn.close()
    return rows


# --- alert recipients ---
def list_alert_recipients(active_only=False):
    conn = get_connection(); c = conn.cursor()
    sql = "SELECT * FROM alert_recipients"
    if active_only:
        sql += " WHERE active = 1"
    sql += " ORDER BY id ASC"
    c.execute(sql)
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return rows


def add_alert_recipient(label, phone):
    conn = get_connection(); c = conn.cursor()
    c.execute("INSERT INTO alert_recipients (label, phone) VALUES (?, ?)", (label, phone))
    conn.commit(); conn.close()


def update_alert_recipient(rid, label, phone, active):
    conn = get_connection(); c = conn.cursor()
    c.execute("UPDATE alert_recipients SET label = ?, phone = ?, active = ? WHERE id = ?",
              (label, phone, 1 if active else 0, rid))
    conn.commit(); conn.close()


def delete_alert_recipient(rid):
    conn = get_connection(); c = conn.cursor()
    c.execute("DELETE FROM alert_recipients WHERE id = ?", (rid,))
    conn.commit(); conn.close()


# --- audit log ---
def add_audit(username, action, detail="", ip=""):
    conn = get_connection(); c = conn.cursor()
    c.execute("INSERT INTO audit_log (username, action, detail, ip) VALUES (?, ?, ?, ?)",
              (username, action, detail, ip))
    conn.commit(); conn.close()


def get_audit(limit=200):
    conn = get_connection(); c = conn.cursor()
    c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    for d in rows:
        d["timestamp"] = utc_to_local_str(d.get("timestamp"))     # UTC -> local
    return rows


# --- data retention ---
def purge_old_data(days):
    """Delete failed_logins / alerts / geo_events older than `days`.
    Returns a dict of deleted-row counts per table."""
    conn = get_connection(); c = conn.cursor()
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    counts = {}
    for table, col in (("failed_logins", "timestamp"),
                       ("alerts", "created_at"),
                       ("geo_events", "timestamp")):
        c.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
        counts[table] = c.rowcount
    conn.commit(); conn.close()
    return counts


# If this file is run directly, initialize the database
if __name__ == "__main__":
    init_db()
    print("[DB] Tables created. Database is ready.")