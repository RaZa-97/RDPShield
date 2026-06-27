"""
RDPShield - ML Feature Engineering
==================================
Turns the raw event tables (failed_logins / alerts / blocked_ips / geo_cache)
into a flat, numeric per-IP feature vector that a machine-learning model can
consume.

This module is the SINGLE SOURCE OF TRUTH for what a "feature" is. Both the
offline trainer (train_model.py) and the live, on-server scorer (ml_model.py)
import FEATURE_NAMES and compute_all_features() from here, so the features a
model was trained on are guaranteed to be identical to the features it is
scored on. (A mismatch there is the #1 cause of silently-wrong ML predictions.)

It uses ONLY the Python standard library, so it runs unchanged on the 32-bit
server where scikit-learn / numpy are not installed.

----------------------------------------------------------------------------
THE FEATURES (all numeric, one row per attacker IP)
----------------------------------------------------------------------------
  failed_login_count   total failed logins ever recorded from this IP
  unique_usernames     how many distinct usernames it tried
  username_ratio       unique_usernames / failed_login_count  (1.0 => password
                       spray: a different username almost every time)
  active_span_hours    hours between its first and last failed login
  attempts_per_hour    failed_login_count / active_span_hours  (burst rate)
  max_burst_60s        most failed logins it packed into any 60-second window
                       (a fast brute-force signature)
  distinct_days        number of separate calendar days it was active on
                       (persistence / low-and-slow signature)
  night_ratio          fraction of attempts during 00:00-06:00 (bot hours)
  admin_target_ratio   fraction of attempts aimed at admin/administrator/root
  abuse_score          AbuseIPDB reputation 0-100 (external signal)
  has_geo              1 if we have a geolocation for it, else 0

----------------------------------------------------------------------------
THE LABEL (only used for TRAINING - see weak_label())
----------------------------------------------------------------------------
We have no human-labelled "this IP is malicious" column, so we derive a *weak*
label from the rule engine's own decisions: an IP is labelled malicious (1) if
RDPShield blocked it OR raised any alert on it. None of the label's inputs
(blocked / alert_count) are used as features, so the model is not just copying
the answer back to itself - it learns to predict the rule engine's verdict from
raw behaviour + reputation, which lets it then put a *continuous* score on IPs
the fixed thresholds never tripped.
"""

from datetime import datetime

from database import get_connection

# Order matters: a model is just an array of numbers indexed by position, so
# the trainer and the scorer must agree on this exact ordering.
FEATURE_NAMES = [
    "failed_login_count",
    "unique_usernames",
    "username_ratio",
    "active_span_hours",
    "attempts_per_hour",
    "max_burst_60s",
    "distinct_days",
    "night_ratio",
    "admin_target_ratio",
    "abuse_score",
    "has_geo",
]

# Usernames an attacker disproportionately targets.
_ADMIN_NAMES = {"admin", "administrator", "root", "sa", "guest", "user", "test"}


def _parse_ts(ts):
    """Parse the mixed timestamp formats in the DB into a datetime, or None.
    failed_logins.timestamp is ISO ('2026-06-24T11:22:33'); some rows use a
    space separator. We only need the parts up to seconds."""
    if not ts:
        return None
    ts = str(ts).strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(ts[:26], fmt)
        except ValueError:
            continue
    # Last resort: just the date.
    try:
        return datetime.strptime(ts[:10], "%Y-%m-%d")
    except ValueError:
        return None


def _max_burst(timestamps, window_seconds=60):
    """Largest number of events that fall inside any `window_seconds` window.
    Classic sliding-window over a sorted list of datetimes."""
    times = sorted(t for t in timestamps if t is not None)
    if len(times) < 2:
        return len(times)
    best = 1
    left = 0
    for right in range(len(times)):
        while (times[right] - times[left]).total_seconds() > window_seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def compute_all_features(conn=None):
    """Compute the feature vector for EVERY attacker IP seen in failed_logins.

    Returns a dict:  { ip_address: {feature_name: value, ...}, ... }

    A few cheap GROUP BY queries do the bulk aggregation; the per-event
    timestamps (needed for max_burst_60s and night_ratio) are streamed once and
    folded in Python. This is one pass over the data - fine for the offline
    trainer and, behind a short cache, for the dashboard.
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
    cur = conn.cursor()

    feats = {}

    # --- 1. Aggregates straight from SQL (one row per IP) -------------------
    cur.execute("""
        SELECT source_ip,
               COUNT(*)                  AS n,
               COUNT(DISTINCT username)  AS users,
               MIN(timestamp)            AS first_seen,
               MAX(timestamp)            AS last_seen,
               COUNT(DISTINCT substr(timestamp, 1, 10)) AS days
        FROM failed_logins
        GROUP BY source_ip
    """)
    for r in cur.fetchall():
        ip = r["source_ip"]
        n = r["n"] or 0
        users = r["users"] or 0
        first = _parse_ts(r["first_seen"])
        last = _parse_ts(r["last_seen"])
        span_h = ((last - first).total_seconds() / 3600.0) if (first and last) else 0.0
        feats[ip] = {
            "failed_login_count": float(n),
            "unique_usernames": float(users),
            "username_ratio": (users / n) if n else 0.0,
            "active_span_hours": round(span_h, 4),
            # span can be 0 for a single burst; treat <1h as 1h so the rate is
            # "attempts this hour" rather than a divide-by-zero explosion.
            "attempts_per_hour": (n / max(span_h, 1.0)),
            "max_burst_60s": 0.0,        # filled in pass 2
            "distinct_days": float(r["days"] or 0),
            "night_ratio": 0.0,          # filled in pass 2
            "admin_target_ratio": 0.0,   # filled in pass 2
            "abuse_score": 0.0,          # filled in pass 3
            "has_geo": 0.0,              # filled in pass 3
        }

    if not feats:
        if own_conn:
            conn.close()
        return feats

    # --- 2. Per-event pass: bursts, night ratio, admin-target ratio ---------
    # Stream rows ordered by IP so we can process one IP's events together.
    cur.execute("""
        SELECT source_ip, timestamp, username
        FROM failed_logins
        ORDER BY source_ip, timestamp
    """)
    cur_ip = None
    buf_times, n_night, n_admin, n_total = [], 0, 0, 0

    def _flush(ip):
        if ip is None or ip not in feats:
            return
        feats[ip]["max_burst_60s"] = float(_max_burst(buf_times, 60))
        feats[ip]["night_ratio"] = (n_night / n_total) if n_total else 0.0
        feats[ip]["admin_target_ratio"] = (n_admin / n_total) if n_total else 0.0

    for r in cur.fetchall():
        ip = r["source_ip"]
        if ip != cur_ip:
            _flush(cur_ip)
            cur_ip = ip
            buf_times, n_night, n_admin, n_total = [], 0, 0, 0
        t = _parse_ts(r["timestamp"])
        buf_times.append(t)
        n_total += 1
        if t is not None and 0 <= t.hour < 6:
            n_night += 1
        uname = (r["username"] or "").strip().lower()
        if uname in _ADMIN_NAMES:
            n_admin += 1
    _flush(cur_ip)

    # --- 3. External reputation + geolocation -------------------------------
    cur.execute("""
        SELECT source_ip, MAX(abuse_score) AS abuse
        FROM alerts GROUP BY source_ip
    """)
    for r in cur.fetchall():
        if r["source_ip"] in feats:
            feats[r["source_ip"]]["abuse_score"] = float(r["abuse"] or 0)

    cur.execute("SELECT ip_address FROM geo_cache WHERE country != '' OR city != ''")
    geo_ips = {r["ip_address"] for r in cur.fetchall()}
    for ip in feats:
        if ip in geo_ips:
            feats[ip]["has_geo"] = 1.0

    if own_conn:
        conn.close()
    return feats


def compute_labels(conn=None):
    """Weak training labels: { ip: 1 if blocked-or-alerted else 0 }.

    Positive set = every IP the rule engine blocked OR raised an alert on.
    These inputs are deliberately NOT features (see module docstring)."""
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
    cur = conn.cursor()

    positives = set()
    cur.execute("SELECT DISTINCT ip_address FROM blocked_ips")
    positives.update(r["ip_address"] for r in cur.fetchall())
    cur.execute("SELECT DISTINCT source_ip FROM alerts")
    positives.update(r["source_ip"] for r in cur.fetchall())

    if own_conn:
        conn.close()
    return positives


def features_to_row(feat):
    """Flatten a feature dict into the ordered numeric list a model expects."""
    return [float(feat.get(name, 0.0)) for name in FEATURE_NAMES]


def build_training_matrix(conn=None):
    """Assemble (ips, X, y) for the trainer.
        ips : list of IP strings        (row order)
        X   : list of feature lists     (len(FEATURE_NAMES) each)
        y   : list of 0/1 labels
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
    feats = compute_all_features(conn)
    positives = compute_labels(conn)
    if own_conn:
        conn.close()

    ips, X, y = [], [], []
    for ip, f in feats.items():
        ips.append(ip)
        X.append(features_to_row(f))
        y.append(1 if ip in positives else 0)
    return ips, X, y
