"""
RDPShield — Central check-in client (runs INSIDE each instance)
==============================================================
A background thread that periodically pushes this instance's own aggregated
status to RDPShield Central, the multi-tenant command centre.

OFF BY DEFAULT. With no `CENTRAL_*` settings in config.py nothing here runs and
the dashboard behaves exactly as it did before Central existed — the whole
feature is opt-in and backward compatible.

Direction of travel
-------------------
This instance PUSHES to Central. Central never connects in. That means the
customer's box needs no inbound firewall hole for Central, works behind NAT,
and Central being unreachable degrades to "this agent shows Offline" rather
than to anything failing locally.

What leaves this box
--------------------
Only the counters in `central_report_schema.py` — no attacker IPs, no
usernames, no hostnames, no YARA findings, no country data. The schema is
shared with Central, which rejects anything outside it, so this file cannot
quietly start exfiltrating more.

An instance pushes ONLY its own summary with its own agent id and key. It has
no credential for, and no way to address, any other agent or any of Central's
own data.

Config (add to config.py — all optional, see config.example.py)
    CENTRAL_ENABLED          False   turn check-ins on
    CENTRAL_URL              ""      https://central.example.com:6100
    CENTRAL_AGENT_ID         ""      "ag_…" issued at enrolment
    CENTRAL_API_KEY          ""      one-time key issued at enrolment
    CENTRAL_REPORT_INTERVAL  60      seconds between check-ins
    CENTRAL_VERIFY_TLS       True    never set False outside a lab
"""

import threading
import time
from datetime import datetime, timedelta

import requests

import config
import database
import central_report_schema as schema

# Reported as `agent_version`; bump alongside the app version in PROGRESS.md.
AGENT_VERSION = "4.0"

# The instance is considered to have a healthy detector if the agent process
# has written a failed-login row OR there has simply been no attack traffic to
# record. We can only observe the database from here, so "unhealthy" is claimed
# conservatively — see _detectors_ok().
_STALE_AFTER_HOURS = 24

_started = False


# --- config helpers -------------------------------------------------------
def _cfg(name, default):
    return getattr(config, name, default)


def enabled():
    """True only when check-ins are switched on AND fully configured."""
    return bool(_cfg("CENTRAL_ENABLED", False)
                and _cfg("CENTRAL_URL", "")
                and _cfg("CENTRAL_AGENT_ID", "")
                and _cfg("CENTRAL_API_KEY", ""))


def managed():
    """True when this instance's login has been moved to Central.

    Implies `enabled()` — an instance that cannot reach Central to be given a
    session must not also have its local login disabled, or it would be
    unreachable. dashboard.py re-checks this before disabling /login."""
    return bool(_cfg("CENTRAL_MANAGED", False)) and enabled()


# --- metric collection ----------------------------------------------------
def _scalar(sql, params=()):
    conn = database.get_connection()
    try:
        row = conn.execute(sql, params).fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    finally:
        conn.close()


def _failed_logins_24h():
    # failed_logins.timestamp is stored in UTC (see get_failed_login_trend,
    # which converts with 'localtime' for display), so the window is UTC too.
    return _scalar("""
        SELECT COUNT(*) FROM failed_logins
        WHERE timestamp >= datetime('now', '-1 day')
    """)


def _alerts_24h():
    # alerts.timestamp is stored in LOCAL time (see get_alert_type_breakdown),
    # so this window has to be local to match. The two tables genuinely differ;
    # this mismatch is a known project-wide issue tracked in PROGRESS.md, and is
    # deliberately NOT "fixed" here — changing storage conventions is a change
    # to the detection pipeline, which this feature must not touch.
    return _scalar("""
        SELECT COUNT(*) FROM alerts
        WHERE timestamp >= datetime('now', 'localtime', '-1 day')
    """)


def _top_alert_type():
    """The most frequent alert type in the last 24h, or "" if none."""
    conn = database.get_connection()
    try:
        row = conn.execute("""
            SELECT alert_type, COUNT(*) AS cnt FROM alerts
            WHERE timestamp >= datetime('now', 'localtime', '-1 day')
            GROUP BY alert_type ORDER BY cnt DESC LIMIT 1
        """).fetchone()
    finally:
        conn.close()
    if not row:
        return ""
    # Central rejects anything outside the shared allow-list, so map an
    # unrecognised local alert type to "" rather than having the whole report
    # bounce on one bad enum.
    value = row["alert_type"] or ""
    return value if value in schema.ALERT_TYPES else ""


def _yara_active():
    try:
        counts = database.get_finding_status_counts() or {}
        return int(counts.get("active", 0))
    except Exception:
        return 0


def _campaigns_active():
    try:
        return len(database.get_campaigns(limit=200) or [])
    except Exception:
        return 0


def _max_threat_score():
    """Highest ML threat score across active IPs, or None when no model is
    deployed on this instance (the common case — see PROGRESS.md v3.8)."""
    try:
        import ml_model
        if not ml_model.model_available():
            return None
        scores = ml_model.score_active_ips() or []
        best = 0
        for s in scores:
            try:
                best = max(best, int(s.get("score", 0)))
            except (TypeError, ValueError):
                continue
        return max(0, min(100, best))
    except Exception:
        return None


def _detectors_ok():
    """A best-effort health signal for the detection agent (`rdpshield.py`).

    The dashboard process cannot see whether the agent process is alive, so
    this reports False only on positive evidence of a problem: the database has
    failed-login history but nothing at all recently, which is what a stopped
    agent looks like on an internet-facing honeypot. A genuinely quiet box with
    no history reports True rather than crying wolf."""
    total = _scalar("SELECT COUNT(*) FROM failed_logins")
    if total == 0:
        return True
    recent = _scalar("SELECT COUNT(*) FROM failed_logins "
                     "WHERE timestamp >= datetime('now', ?)",
                     (f"-{_STALE_AFTER_HOURS} hours",))
    return recent > 0


_start_time = time.time()


def build_summary():
    """Assemble this instance's check-in payload.

    Validated locally against the shared schema before sending, so a bug here
    surfaces in this instance's own log instead of as a silent 400 at Central."""
    stats = database.get_dashboard_stats()
    alerts_24h = _alerts_24h()
    blocked = int(stats.get("total_blocked", 0))
    threat = _max_threat_score()
    yara_active = _yara_active()

    payload = {
        "schema_version": schema.SCHEMA_VERSION,
        "reported_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_version": AGENT_VERSION,
        "uptime_seconds": int(time.time() - _start_time),

        "failed_logins_24h": _failed_logins_24h(),
        "failed_logins_total": int(stats.get("total_failed_logins", 0)),
        "alerts_24h": alerts_24h,
        "alerts_total": int(stats.get("total_alerts", 0)),
        "blocked_ips_active": blocked,
        "unique_attackers": int(stats.get("unique_attacker_ips", 0)),
        "yara_findings_active": yara_active,
        "campaigns_active": _campaigns_active(),

        "max_threat_score": threat,
        "risk_level": schema.risk_from_counts(alerts_24h, blocked, threat, yara_active),
        "top_alert_type": _top_alert_type(),
        "detectors_ok": _detectors_ok(),
    }
    return schema.validate(payload)


# --- transport ------------------------------------------------------------
def send_once(timeout=15):
    """Push one check-in. Returns (ok, message). Never raises."""
    if not enabled():
        return False, "Central reporting is not enabled/configured."

    base = str(_cfg("CENTRAL_URL", "")).rstrip("/")
    agent_id = _cfg("CENTRAL_AGENT_ID", "")
    api_key = _cfg("CENTRAL_API_KEY", "")

    if not base.startswith("https://") and not _cfg("CENTRAL_ALLOW_INSECURE_HTTP", False):
        # Refuse to put the bearer key on the wire in clear. Central enforces
        # this at its end too; failing here means the mistake is visible in this
        # instance's own log.
        return False, ("CENTRAL_URL must be https:// — refusing to send the API "
                       "key over plain HTTP. Set CENTRAL_ALLOW_INSECURE_HTTP = "
                       "True only for a local test.")

    try:
        payload = build_summary()
    except schema.SchemaError as exc:
        return False, f"Refusing to send a payload that fails our own schema: {exc}"
    except Exception as exc:
        return False, f"Could not build the summary: {exc}"

    url = f"{base}/api/v1/agents/{agent_id}/report"
    try:
        resp = requests.post(
            url, json=payload, timeout=timeout,
            headers={"Authorization": f"Bearer {api_key}",
                     "User-Agent": f"RDPShield-Agent/{AGENT_VERSION}"},
            verify=bool(_cfg("CENTRAL_VERIFY_TLS", True)),
        )
    except requests.RequestException as exc:
        # Central being down is normal and non-fatal: this instance keeps
        # detecting and blocking regardless, it just shows as Offline centrally.
        return False, f"Central unreachable: {exc}"

    if resp.status_code == 200:
        return True, "ok"
    if resp.status_code == 401:
        return False, ("Central rejected our credentials (401). Check "
                       "CENTRAL_AGENT_ID / CENTRAL_API_KEY — the key may have "
                       "been rotated in Central.")
    if resp.status_code == 429:
        return False, "Central rate-limited us (429); backing off."
    # Truncate: never echo an unbounded remote response into our log.
    return False, f"Central returned {resp.status_code}: {resp.text[:200]}"


def _report_loop():
    """Daemon thread — same pattern as the dashboard's maintenance loop."""
    interval = max(15, int(_cfg("CENTRAL_REPORT_INTERVAL", 60)))
    # A small initial delay lets the dashboard finish starting before the first
    # check-in, so the very first report isn't skewed by boot-time work.
    time.sleep(5)
    backoff = interval
    while True:
        ok, msg = send_once()
        if ok:
            backoff = interval
        else:
            # Exponential backoff, capped, so an unreachable or misconfigured
            # Central doesn't spam the log or hammer the network every minute.
            backoff = min(backoff * 2, 900)
            print(f"[CENTRAL] check-in failed: {msg} (retrying in {backoff}s)")
        time.sleep(backoff if not ok else interval)


def start():
    """Start the background reporter if it's enabled. Safe to call twice."""
    global _started
    if _started:
        return False
    if not enabled():
        if _cfg("CENTRAL_ENABLED", False):
            print("[CENTRAL] CENTRAL_ENABLED is True but CENTRAL_URL / "
                  "CENTRAL_AGENT_ID / CENTRAL_API_KEY are incomplete — "
                  "check-ins are OFF.")
        return False
    _started = True
    threading.Thread(target=_report_loop, daemon=True).start()
    interval = max(15, int(_cfg("CENTRAL_REPORT_INTERVAL", 60)))
    print(f"[CENTRAL] Reporting to {_cfg('CENTRAL_URL', '')} as "
          f"{_cfg('CENTRAL_AGENT_ID', '')} every {interval}s.")
    return True


if __name__ == "__main__":
    # Manual check: build a payload and push one report.
    import json
    print(json.dumps(build_summary(), indent=2))
    print(send_once())
