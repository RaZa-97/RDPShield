#!/usr/bin/env python3
"""
RDPShield - campaign / coordinated-attack detector
==================================================
Long-horizon (default 7-day) correlation that surfaces campaigns no single
short/24h detector catches:
  - a determined IP active across many days (week-long persistent),
  - a country attacking with many rotating IPs (distributed),
  - attacks that recur in the same time-of-day band (scheduled).

Tiered response (chosen design): SMS the SOC for EVERY detected campaign and
list it in the dashboard tracker; AUTO-BLOCK only the worst single-IP campaigns
(countries stay alert-only - act on a whole country via Geo-Block). De-duplicated
via the campaigns table so the SOC isn't re-texted every run.

Runs on a timer inside the agent, or standalone (dry run):
    python campaign_detector.py
"""
import config
import database
import firewall
from alerts import send_sms_alert


def _cfg(name, default):
    return getattr(config, name, default)


CAMPAIGN_ENABLED          = _cfg("CAMPAIGN_ENABLED", True)
CAMPAIGN_WINDOW_DAYS      = _cfg("CAMPAIGN_WINDOW_DAYS", 7)
CAMPAIGN_IP_MIN_DAYS      = _cfg("CAMPAIGN_IP_MIN_DAYS", 3)
CAMPAIGN_IP_MIN_FAILS     = _cfg("CAMPAIGN_IP_MIN_FAILS", 30)
CAMPAIGN_IP_BLOCK_FAILS   = _cfg("CAMPAIGN_IP_BLOCK_FAILS", 60)
CAMPAIGN_COUNTRY_MIN_IPS  = _cfg("CAMPAIGN_COUNTRY_MIN_IPS", 5)
CAMPAIGN_COUNTRY_MIN_FAILS = _cfg("CAMPAIGN_COUNTRY_MIN_FAILS", 100)
CAMPAIGN_TIME_PCT         = _cfg("CAMPAIGN_TIME_PCT", 50)
CAMPAIGN_REALERT_HOURS    = _cfg("CAMPAIGN_REALERT_HOURS", 24)
CAMPAIGN_AUTOBLOCK_IPS    = _cfg("CAMPAIGN_AUTOBLOCK_IPS", True)
WHITELIST_IPS             = _cfg("WHITELIST_IPS", [])
PRIVATE_IP_PREFIXES       = _cfg("PRIVATE_IP_PREFIXES",
                                 ("10.", "192.168.", "172.", "127.", "169.254."))


def _is_private(ip):
    return any(str(ip).startswith(p) for p in PRIVATE_IP_PREFIXES)


def peak_band(hist, width=3):
    """Find the `width`-hour band (with wraparound) holding the most attempts.
    Returns ('HH:00-HH:00', percentage_of_total)."""
    total = sum(hist) or 1
    best_start, best_sum = 0, -1
    for s in range(24):
        seg = sum(hist[(s + i) % 24] for i in range(width))
        if seg > best_sum:
            best_sum, best_start = seg, s
    pct = round(100 * best_sum / total)
    end = (best_start + width) % 24
    return f"{best_start:02d}:00-{end:02d}:00", pct


def _raise(source, detail, country, blocked, do_sms):
    sms_ok = False
    if do_sms:
        sms_ok = bool(send_sms_alert("campaign_alert", source, detail,
                                     {"city": "", "country": country}))
    database.log_alert(alert_type="campaign_alert", source_ip=source,
                       description=detail, usernames="", failure_count=0,
                       geo_country=country, geo_city="", abuse_score=0,
                       blocked=1 if blocked else 0, sms_sent=1 if sms_ok else 0)


def run_campaign_analysis(do_block=True, do_sms=True, verbose=False):
    """Analyse the rolling window and act on campaigns. Returns a small summary."""
    stats = {"ip_campaigns": 0, "country_campaigns": 0, "alerted": 0, "blocked": 0}
    if not CAMPAIGN_ENABLED:
        return stats
    days = CAMPAIGN_WINDOW_DAYS

    # --- Single-IP week-long campaigns (eligible for auto-block) ---
    for r in database.get_campaign_ip_offenders(days, CAMPAIGN_IP_MIN_DAYS,
                                                 CAMPAIGN_IP_MIN_FAILS):
        ip = r["source_ip"]
        if not ip or _is_private(ip) or ip in WHITELIST_IPS:
            continue
        stats["ip_campaigns"] += 1
        country = r.get("country") or ""
        window, pct = peak_band(database.get_hour_histogram(days, "ip", ip))
        scheduled = pct >= CAMPAIGN_TIME_PCT and r["distinct_days"] >= CAMPAIGN_IP_MIN_DAYS
        ckey = "ip:" + ip
        database.upsert_campaign(ckey, "ip", ip, country, r["total_fails"],
                                 r["distinct_days"], 0, window, pct, scheduled)
        if not database.campaign_needs_alert(ckey, CAMPAIGN_REALERT_HOURS):
            continue
        will_block = (do_block and CAMPAIGN_AUTOBLOCK_IPS
                      and r["total_fails"] >= CAMPAIGN_IP_BLOCK_FAILS
                      and not database.is_ip_blocked(ip))
        sched = f", recurring {window} ({pct}% of its attempts)" if scheduled else ""
        detail = (f"Week-long campaign: {r['total_fails']} failed logins across "
                  f"{r['distinct_days']} days from {ip}"
                  f"{(' (' + country + ')') if country else ''}{sched}")
        if will_block:
            firewall.block_ip(ip, reason=f"campaign_alert: {detail}")
            detail += " [auto-blocked]"
            stats["blocked"] += 1
        _raise(ip, detail, country, will_block, do_sms)
        database.mark_campaign_alerted(ckey, blocked=will_block)
        stats["alerted"] += 1
        if verbose:
            print("[CAMPAIGN]", detail)

    # --- Country (distributed) campaigns (alert-only) ---
    for r in database.get_campaign_country_offenders(days, CAMPAIGN_COUNTRY_MIN_IPS,
                                                      CAMPAIGN_COUNTRY_MIN_FAILS):
        country = r["country"]
        stats["country_campaigns"] += 1
        window, pct = peak_band(database.get_hour_histogram(days, "country", country))
        scheduled = pct >= CAMPAIGN_TIME_PCT and r["distinct_days"] >= CAMPAIGN_IP_MIN_DAYS
        ckey = "country:" + country
        database.upsert_campaign(ckey, "country", country, country, r["total_fails"],
                                 r["distinct_days"], r["distinct_ips"], window, pct, scheduled)
        if not database.campaign_needs_alert(ckey, CAMPAIGN_REALERT_HOURS):
            continue
        sched = f", recurring {window} ({pct}% of attempts)" if scheduled else ""
        detail = (f"Country campaign: {r['total_fails']} failed logins from "
                  f"{r['distinct_ips']} IPs in {country} over {r['distinct_days']} "
                  f"days{sched}")
        _raise(country, detail, country, False, do_sms)
        database.mark_campaign_alerted(ckey, blocked=False)
        stats["alerted"] += 1
        if verbose:
            print("[CAMPAIGN]", detail)

    return stats


if __name__ == "__main__":
    database.init_db()
    print("Running campaign analysis as a DRY RUN (no blocks, no SMS)...")
    s = run_campaign_analysis(do_block=False, do_sms=False, verbose=True)
    print("Summary:", s)
