"""
RDPShield - One-time geo backfill
=================================
Geolocates every attacker IP already recorded in `failed_logins` / `alerts` /
`blocked_ips` and stores the result (including lat/lon) in `geo_cache`.

Run this once after upgrading so historical rows get a country AND map
coordinates. IPs that already have coordinates are skipped; IPs cached WITHOUT
coordinates (from before the attack-map feature) are re-looked-up.

Usage (on the server):
    set PYTHONUTF8=1
    python backfill_geo.py

Safe to re-run. Honors ip-api's rate limit (45 req/min) with a short pause.
"""

import time

from database import get_connection, get_cached_geo, cache_geo
from alerts import lookup_geolocation
from config import PRIVATE_IP_PREFIXES


def is_private(ip):
    return ip.startswith(PRIVATE_IP_PREFIXES)


def _has_coords(cached):
    if not cached:
        return False
    try:
        return float(cached.get("lat") or 0) != 0 or float(cached.get("lon") or 0) != 0
    except (TypeError, ValueError):
        return False


def main():
    conn = get_connection()
    cur = conn.cursor()
    # Every IP we've ever seen as an attacker, from all three sources.
    cur.execute("""
        SELECT source_ip FROM failed_logins
        UNION SELECT source_ip FROM alerts
        UNION SELECT ip_address FROM blocked_ips
    """)
    ips = [row[0] for row in cur.fetchall() if row[0]]
    conn.close()

    print(f"[BACKFILL] {len(ips)} distinct attacker IP(s)")

    looked_up = skipped = 0
    for ip in ips:
        if is_private(ip):
            continue
        cached = get_cached_geo(ip)
        if _has_coords(cached):
            skipped += 1
            continue  # already has map coordinates

        geo = lookup_geolocation(ip)
        if geo:
            cache_geo(
                ip,
                country=geo.get("country", ""),
                city=geo.get("city", ""),
                isp=geo.get("isp", ""),
                country_code=geo.get("country_code", ""),
                lat=geo.get("lat", 0),
                lon=geo.get("lon", 0),
            )
            print(f"[BACKFILL] {ip} -> {geo.get('city', '?')}, {geo.get('country', '?')} "
                  f"({geo.get('lat', 0)}, {geo.get('lon', 0)})")
        else:
            print(f"[BACKFILL] {ip} -> lookup failed (will retry next run)")

        looked_up += 1
        time.sleep(1.5)  # stay under ip-api's 45/min limit

    print(f"[BACKFILL] Done. {looked_up} live lookup(s), {skipped} already had coords.")


if __name__ == "__main__":
    main()
