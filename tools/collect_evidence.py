#!/usr/bin/env python3
"""
RDPShield - evidence collector for the dissertation (Chapter 6)
===============================================================
Reads the RDPShield SQLite database and emits the empirical tables you need
for Chapter 6 -- as Markdown (paste straight into Word), CSV (open in Excel),
and a raw-row JSON dump (so in the viva you can show the exact rows behind
every number).

It produces:
  Table 4  Detection / block latency, per blocked attacker IP
  Table 5  Honeypot field summary (window, totals, distinct countries)
  Table 6  Alert breakdown by attack type (+ percentage)
  Table 7  Top attacker countries (+ how many IPs scored AbuseIPDB > 75)

Run it ON THE SERVER (where the live honeypot DB is) after a git pull:
    python tools/collect_evidence.py

Or locally against a copied-down snapshot:
    python tools/collect_evidence.py --db rdpshield_train.db

Output lands in evidence/data/<timestamp>/ by default. Pure standard library,
so it runs on the 32-bit server Python too.
"""
import argparse
import csv
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone


# --------------------------------------------------------------------------- #
# Timestamp parsing
# --------------------------------------------------------------------------- #
# The three time sources in the DB use DIFFERENT formats, all effectively UTC:
#   failed_logins.timestamp : "2026-06-18T15:49:12.6735031Z" (Win event log, Z)
#   alerts.timestamp        : "2026-06-23T09:03:28.123456"   (datetime.now isoformat)
#   blocked_ips.blocked_at  : "2026-06-23 09:03:28"          (SQLite CURRENT_TIMESTAMP)
# parse_ts() tolerates all of them and returns a tz-aware UTC datetime so
# latency subtraction across sources is correct.
def parse_ts(s):
    if not s:
        return None
    s = s.strip().replace("Z", "").replace("T", " ")
    if "." in s:                       # truncate fractional seconds to 6 digits
        head, frac = s.split(".", 1)
        frac = "".join(ch for ch in frac if ch.isdigit())[:6]
        s = f"{head}.{frac}" if frac else head
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def secs(a, b):
    """Whole seconds from a to b (b - a); None if either is missing."""
    if a is None or b is None:
        return None
    return round((b - a).total_seconds())


def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "-"


def fmt_secs(n):
    if n is None:
        return "n/a"
    if n < 0:
        return f"{n}s (check clock)"
    if n < 120:
        return f"{n}s"
    return f"{n // 60}m {n % 60}s"


# --------------------------------------------------------------------------- #
# Data pulls
# --------------------------------------------------------------------------- #
def connect(db_path):
    if not os.path.exists(db_path):
        sys.exit(f"[ERROR] database not found: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def table4_latency(conn):
    """Per blocked IP: first attempt -> first alert -> block, with latencies."""
    blocked = conn.execute(
        "SELECT ip_address, reason, blocked_at, is_active FROM blocked_ips "
        "ORDER BY blocked_at ASC"
    ).fetchall()
    rows = []
    for b in blocked:
        ip = b["ip_address"]
        first = conn.execute(
            "SELECT MIN(timestamp) AS t FROM failed_logins WHERE source_ip = ?",
            (ip,)).fetchone()["t"]
        alert = conn.execute(
            "SELECT MIN(timestamp) AS t, "
            "(SELECT alert_type FROM alerts WHERE source_ip = ? "
            " ORDER BY timestamp ASC LIMIT 1) AS atype "
            "FROM alerts WHERE source_ip = ?", (ip, ip)).fetchone()
        n_fail = conn.execute(
            "SELECT COUNT(*) AS n FROM failed_logins WHERE source_ip = ?",
            (ip,)).fetchone()["n"]
        t_first = parse_ts(first)
        t_alert = parse_ts(alert["t"])
        t_block = parse_ts(b["blocked_at"])
        rows.append({
            "ip": ip,
            "alert_type": alert["atype"] or b["reason"] or "-",
            "failed_logins": n_fail,
            "first_attempt": fmt_dt(t_first),
            "alert_time": fmt_dt(t_alert),
            "block_time": fmt_dt(t_block),
            "detect_latency_s": secs(t_first, t_alert),
            "block_latency_s": secs(t_first, t_block),
            "alert_to_block_s": secs(t_alert, t_block),
            "active": bool(b["is_active"]),
        })
    return rows


def table5_summary(conn):
    fl = conn.execute(
        "SELECT COUNT(*) AS n, COUNT(DISTINCT source_ip) AS ips, "
        "MIN(timestamp) AS first, MAX(timestamp) AS last FROM failed_logins"
    ).fetchone()
    alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
    blocked_active = conn.execute(
        "SELECT COUNT(*) AS n FROM blocked_ips WHERE is_active = 1").fetchone()["n"]
    blocked_total = conn.execute(
        "SELECT COUNT(*) AS n FROM blocked_ips").fetchone()["n"]
    # distinct countries among attacker IPs we have geo for
    countries = conn.execute(
        "SELECT COUNT(DISTINCT gc.country) AS n FROM geo_cache gc "
        "WHERE gc.country <> '' AND gc.ip_address IN "
        "(SELECT source_ip FROM failed_logins)").fetchone()["n"]
    t_first, t_last = parse_ts(fl["first"]), parse_ts(fl["last"])
    days = (t_last - t_first).days + 1 if (t_first and t_last) else 0
    return {
        "window_start": fmt_dt(t_first),
        "window_end": fmt_dt(t_last),
        "observation_days": days,
        "total_failed_logins": fl["n"],
        "unique_attacker_ips": fl["ips"],
        "total_alerts": alerts,
        "ips_blocked_active": blocked_active,
        "ips_blocked_total": blocked_total,
        "distinct_countries": countries,
    }


def table6_breakdown(conn):
    rows = conn.execute(
        "SELECT alert_type, COUNT(*) AS cnt FROM alerts "
        "GROUP BY alert_type ORDER BY cnt DESC").fetchall()
    total = sum(r["cnt"] for r in rows) or 1
    return [{"alert_type": r["alert_type"], "count": r["cnt"],
             "percent": round(100 * r["cnt"] / total, 1)} for r in rows]


def table7_countries(conn):
    # countries of active blocked IPs (alert geo first, geo_cache fallback)
    rows = conn.execute("""
        SELECT country, COUNT(*) AS cnt FROM (
            SELECT b.ip_address AS ip,
                   COALESCE(
                     NULLIF((SELECT a.geo_country FROM alerts a
                             WHERE a.source_ip = b.ip_address AND a.geo_country <> ''
                             ORDER BY a.id DESC LIMIT 1), ''),
                     NULLIF((SELECT g.country FROM geo_cache g
                             WHERE g.ip_address = b.ip_address), '')
                   ) AS country
            FROM blocked_ips b WHERE b.is_active = 1)
        WHERE country IS NOT NULL AND country <> ''
        GROUP BY country ORDER BY cnt DESC""").fetchall()
    high_abuse = conn.execute(
        "SELECT COUNT(DISTINCT source_ip) AS n FROM alerts WHERE abuse_score > 75"
    ).fetchone()["n"]
    return [dict(r) for r in rows], high_abuse


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def write_csv(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description="Generate Chapter 6 evidence tables from the RDPShield DB.")
    ap.add_argument("--db", default="rdpshield.db", help="DB path (default rdpshield.db; use rdpshield_train.db for a local snapshot)")
    ap.add_argument("--out", default=None, help="Output dir (default evidence/data/<timestamp>/)")
    args = ap.parse_args()

    conn = connect(args.db)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = args.out or os.path.join("evidence", "data", stamp)
    os.makedirs(outdir, exist_ok=True)

    t4 = table4_latency(conn)
    t5 = table5_summary(conn)
    t6 = table6_breakdown(conn)
    t7_rows, t7_high = table7_countries(conn)

    # ---- Markdown bundle ----
    md = [f"# RDPShield - Chapter 6 evidence", "",
          f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S} from `{args.db}`", ""]

    md += ["## Table 5 - Honeypot field summary", "",
           md_table(["Metric", "Value"], [
               ["Observation window start", t5["window_start"]],
               ["Observation window end", t5["window_end"]],
               ["Observation period (days)", t5["observation_days"]],
               ["Total failed logins (Event 4625)", t5["total_failed_logins"]],
               ["Unique attacker IPs", t5["unique_attacker_ips"]],
               ["Detection alerts raised", t5["total_alerts"]],
               ["IPs blocked (currently active)", t5["ips_blocked_active"]],
               ["IPs blocked (total, incl. unblocked)", t5["ips_blocked_total"]],
               ["Distinct attacker countries", t5["distinct_countries"]],
           ]), ""]

    md += ["## Table 6 - Alert breakdown by attack type", "",
           md_table(["Attack type", "Alerts", "% of alerts"],
                    [[r["alert_type"], r["count"], f'{r["percent"]}%'] for r in t6]), ""]

    md += ["## Table 7 - Top attacker countries (active blocks)", "",
           md_table(["Country", "Blocked IPs"],
                    [[r["country"], r["cnt"]] for r in t7_rows]),
           "",
           f"IPs scoring AbuseIPDB > 75%: **{t7_high}** "
           f"(evidence the blocks target genuinely malicious hosts).", ""]

    md += ["## Table 4 - Detection and block latency (per blocked IP)", "",
           "Latency = time from the attacker's first failed login to the alert / "
           "firewall block. `n/a` = no failed-login row for that IP (e.g. a geo / "
           "whitelist block that fires before the login is recorded, or a manual block).",
           "",
           md_table(
               ["Attacker IP", "Alert type", "Fails", "First attempt", "Alert",
                "Block", "Detect", "Block", "Alert->Block"],
               [[r["ip"], r["alert_type"], r["failed_logins"], r["first_attempt"],
                 r["alert_time"], r["block_time"],
                 fmt_secs(r["detect_latency_s"]), fmt_secs(r["block_latency_s"]),
                 fmt_secs(r["alert_to_block_s"])] for r in t4]),
           "",
           "> For Table 4 in the dissertation, keep only the rows matching your "
           "controlled-test IPs (T1-T4). Note timestamps are UTC; if any latency "
           "shows negative, the three time sources disagree on clock/timezone.", ""]

    with open(os.path.join(outdir, "tables.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    # ---- CSVs ----
    write_csv(os.path.join(outdir, "table4_latency.csv"),
              ["ip", "alert_type", "failed_logins", "first_attempt", "alert_time",
               "block_time", "detect_latency_s", "block_latency_s", "alert_to_block_s", "active"],
              [[r["ip"], r["alert_type"], r["failed_logins"], r["first_attempt"],
                r["alert_time"], r["block_time"], r["detect_latency_s"],
                r["block_latency_s"], r["alert_to_block_s"], r["active"]] for r in t4])
    write_csv(os.path.join(outdir, "table5_summary.csv"),
              ["metric", "value"], list(t5.items()))
    write_csv(os.path.join(outdir, "table6_breakdown.csv"),
              ["alert_type", "count", "percent"],
              [[r["alert_type"], r["count"], r["percent"]] for r in t6])
    write_csv(os.path.join(outdir, "table7_countries.csv"),
              ["country", "blocked_ips"], [[r["country"], r["cnt"]] for r in t7_rows])

    # ---- Raw backing rows (viva: "show me your data") ----
    raw = {t: [dict(r) for r in conn.execute(f"SELECT * FROM {t}").fetchall()]
           for t in ("failed_logins", "alerts", "blocked_ips", "geo_events")}
    raw["_high_abuse_ip_count"] = t7_high
    with open(os.path.join(outdir, "raw_rows.json"), "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2, default=str)

    conn.close()

    print("=" * 64)
    print("  RDPShield evidence pack written to:")
    print(f"    {os.path.abspath(outdir)}")
    print("=" * 64)
    print(f"  tables.md            <- paste tables 4-7 into Word")
    print(f"  table4..table7 .csv  <- open in Excel / re-chart")
    print(f"  raw_rows.json        <- raw rows behind every number (viva)")
    print()
    print(f"  Window : {t5['window_start']}  ->  {t5['window_end']}  ({t5['observation_days']} days)")
    print(f"  Totals : {t5['total_failed_logins']} fails / {t5['unique_attacker_ips']} IPs / "
          f"{t5['total_alerts']} alerts / {t5['ips_blocked_active']} active blocks")
    print(f"  AbuseIPDB > 75 : {t7_high} IPs")


if __name__ == "__main__":
    main()
