"""
RDPShield - Daily Attack Report
===============================
Generates a structured, machine-readable JSON report of one day's attack
activity: failed logins, detections, blocks, geolocation, reputation, and
YARA scan results. Records are aggregated per attacker IP with consistent,
flat, ML/AI-training-friendly fields.

Output is written to  logs/rdpshield_report_<date>.json  on the server.
Later these files can be shipped to cold storage / a data lake unchanged.

Usage:
    python daily_report.py                 # today
    python daily_report.py 2026-06-19      # a specific date (YYYY-MM-DD)

Schedule it once a day with Task Scheduler to build a daily archive.
"""

import os
import sys
import json
from datetime import datetime, date

from database import get_connection

REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


def _rows(cur, query, args=()):
    cur.execute(query, args)
    return [dict(r) for r in cur.fetchall()]


def build_report(day):
    """Assemble the report dict for a single YYYY-MM-DD date."""
    conn = get_connection()
    cur = conn.cursor()

    # Failed logins for the day, aggregated per source IP.
    failed = _rows(cur, """
        SELECT source_ip,
               COUNT(*)                       AS failed_login_count,
               MIN(timestamp)                 AS first_seen,
               MAX(timestamp)                 AS last_seen,
               COUNT(DISTINCT username)       AS unique_usernames,
               GROUP_CONCAT(DISTINCT username) AS usernames
        FROM failed_logins
        WHERE substr(timestamp, 1, 10) = ?
        GROUP BY source_ip
    """, (day,))

    alerts = _rows(cur, """
        SELECT * FROM alerts
        WHERE substr(timestamp, 1, 10) = ?
        ORDER BY timestamp
    """, (day,))

    blocks = _rows(cur, """
        SELECT * FROM blocked_ips
        WHERE substr(blocked_at, 1, 10) = ?
    """, (day,))

    scans = _rows(cur, """
        SELECT id, triggered_by, started_at, completed_at, duration,
               total_findings, critical_findings, max_severity, error
        FROM yara_scans
        WHERE substr(started_at, 1, 10) = ?
        ORDER BY id
    """, (day,))
    for s in scans:
        s["findings"] = _rows(cur, """
            SELECT rule_name, severity, category, description,
                   match_type, location, matched_strings
            FROM yara_findings WHERE scan_id = ?
        """, (s["id"],))

    def geo_for(ip):
        cur.execute("SELECT country, city, isp FROM geo_cache WHERE ip_address = ?", (ip,))
        r = cur.fetchone()
        if r and (r["country"] or r["city"]):
            return {"country": r["country"], "city": r["city"], "isp": r["isp"]}
        cur.execute("""
            SELECT geo_country AS country, geo_city AS city
            FROM alerts WHERE source_ip = ? AND geo_country <> ''
            ORDER BY id DESC LIMIT 1
        """, (ip,))
        r = cur.fetchone()
        if r:
            return {"country": r["country"], "city": r["city"], "isp": ""}
        return {"country": "", "city": "", "isp": ""}

    alerts_by_ip = {}
    for a in alerts:
        alerts_by_ip.setdefault(a["source_ip"], []).append(a)
    blocks_by_ip = {b["ip_address"]: b for b in blocks}
    failed_by_ip = {f["source_ip"]: f for f in failed}

    all_ips = set(failed_by_ip) | set(alerts_by_ip) | set(blocks_by_ip)

    attackers = []
    for ip in sorted(all_ips,
                     key=lambda i: failed_by_ip.get(i, {}).get("failed_login_count", 0),
                     reverse=True):
        g = geo_for(ip)
        f = failed_by_ip.get(ip, {})
        blk = blocks_by_ip.get(ip)
        ip_scans = [s for s in scans if ip in (s.get("triggered_by") or "")]
        max_abuse = max([a["abuse_score"] for a in alerts_by_ip.get(ip, [])], default=0)

        attackers.append({
            "source_ip": ip,
            "country": g["country"],
            "city": g["city"],
            "isp": g["isp"],
            "failed_login_count": f.get("failed_login_count", 0),
            "unique_usernames": f.get("unique_usernames", 0),
            "usernames_targeted": sorted(f["usernames"].split(",")) if f.get("usernames") else [],
            "first_seen": f.get("first_seen"),
            "last_seen": f.get("last_seen"),
            "abuse_score": max_abuse,
            "detections": [
                {
                    "alert_type": a["alert_type"],
                    "description": a["description"],
                    "abuse_score": a["abuse_score"],
                    "blocked": bool(a["blocked"]),
                    "sms_sent": bool(a["sms_sent"]),
                    "timestamp": a["timestamp"],
                }
                for a in alerts_by_ip.get(ip, [])
            ],
            "blocked": bool(blk),
            "block_reason": blk["reason"] if blk else None,
            "blocked_at": blk["blocked_at"] if blk else None,
            "yara_scans": [
                {
                    "scan_id": s["id"],
                    "triggered_by": s["triggered_by"],
                    "total_findings": s["total_findings"],
                    "critical_findings": s["critical_findings"],
                    "max_severity": s["max_severity"],
                    "findings": s["findings"],
                }
                for s in ip_scans
            ],
        })

    alerts_by_type = {}
    for a in alerts:
        alerts_by_type[a["alert_type"]] = alerts_by_type.get(a["alert_type"], 0) + 1

    conn.close()

    return {
        "report_date": day,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "schema_version": 1,
        "summary": {
            "total_failed_logins": sum(f["failed_login_count"] for f in failed),
            "unique_source_ips": len(all_ips),
            "total_alerts": len(alerts),
            "alerts_by_type": alerts_by_type,
            "total_blocks": len(blocks),
            "total_yara_scans": len(scans),
            "yara_critical_findings": sum((s["critical_findings"] or 0) for s in scans),
        },
        "attackers": attackers,
        "yara_scans": scans,
    }


def main():
    day = sys.argv[1] if len(sys.argv) > 1 else date.today().isoformat()
    os.makedirs(REPORT_DIR, exist_ok=True)

    report = build_report(day)
    out_path = os.path.join(REPORT_DIR, f"rdpshield_report_{day}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    s = report["summary"]
    print(f"[REPORT] {day}: {s['total_failed_logins']} failed logins, "
          f"{s['unique_source_ips']} IPs, {s['total_alerts']} alerts, "
          f"{s['total_blocks']} blocks, {s['total_yara_scans']} YARA scans")
    print(f"[REPORT] Written to {out_path}")


if __name__ == "__main__":
    main()
