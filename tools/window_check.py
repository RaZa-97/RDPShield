#!/usr/bin/env python3
"""
RDPShield - detector window check (diagnostic)
==============================================
Shows EXACTLY what each detector sees for one attacker IP, using the same
database functions the live agent uses. Run it on the server right after an
attack to confirm whether the brute-force window actually contains >= 5 failed
logins in 60s (i.e. whether brute force *should* fire, vs only persistent).

    python tools/window_check.py 63.141.48.191

If brute is under its threshold but persistent is over its, your attempts
arrived too slowly to pack 5 into 60 seconds (common over a VPN) - use a denser
burst (hydra -t 4) rather than paced sequential attempts.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database as db
from datetime import datetime, timezone

import config

def _cfg(name, default):
    return getattr(config, name, default)

BRUTE_FORCE_MAX_FAILURES = _cfg("BRUTE_FORCE_MAX_FAILURES", 5)
BRUTE_FORCE_TIME_WINDOW  = _cfg("BRUTE_FORCE_TIME_WINDOW", 60)
SLOW_ATTACK_MAX_FAILURES = _cfg("SLOW_ATTACK_MAX_FAILURES", 10)
SLOW_ATTACK_TIME_WINDOW  = _cfg("SLOW_ATTACK_TIME_WINDOW", 600)
SPRAY_MAX_USERNAMES      = _cfg("SPRAY_MAX_USERNAMES", 4)
SPRAY_TIME_WINDOW        = _cfg("SPRAY_TIME_WINDOW", 300)
PERSISTENT_MAX_FAILURES  = _cfg("PERSISTENT_MAX_FAILURES", 5)
PERSISTENT_TIME_WINDOW   = _cfg("PERSISTENT_TIME_WINDOW", 86400)


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python tools/window_check.py <attacker_ip>")
    ip = sys.argv[1]

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 60)
    print(f"  Detector window check for {ip}")
    print(f"  Now (UTC): {now_utc}")
    print("=" * 60)

    brute = len(db.get_failed_logins_for_ip(ip, BRUTE_FORCE_TIME_WINDOW))
    slow = len(db.get_failed_logins_for_ip(ip, SLOW_ATTACK_TIME_WINDOW))
    users = db.get_unique_usernames_for_ip(ip, SPRAY_TIME_WINDOW)
    persistent = len(db.get_failed_logins_for_ip(ip, PERSISTENT_TIME_WINDOW))

    def line(name, got, need, window):
        fires = got >= need
        mark = "FIRES" if fires else "no"
        print(f"  {name:16} {got:>3} / {need} in {window:>6}s  -> {mark}")

    line("Brute force", brute, BRUTE_FORCE_MAX_FAILURES, BRUTE_FORCE_TIME_WINDOW)
    line("Slow-and-low", slow, SLOW_ATTACK_MAX_FAILURES, SLOW_ATTACK_TIME_WINDOW)
    line("Password spray", len(users), SPRAY_MAX_USERNAMES, SPRAY_TIME_WINDOW)
    line("Persistent", persistent, PERSISTENT_MAX_FAILURES, PERSISTENT_TIME_WINDOW)

    print("-" * 60)
    print(f"  Total failed logins ever from this IP: {db.count_failed_logins(ip)}")
    recent = db.get_failed_logins_for_ip(ip, BRUTE_FORCE_TIME_WINDOW)
    if recent:
        print(f"  Timestamps in the last {BRUTE_FORCE_TIME_WINDOW}s (UTC, as stored):")
        for r in recent:
            print(f"     {r['timestamp']}  user={r['username']}")
    else:
        print(f"  No failed logins in the last {BRUTE_FORCE_TIME_WINDOW}s.")
    print()
    if brute < BRUTE_FORCE_MAX_FAILURES and persistent >= PERSISTENT_MAX_FAILURES:
        print("  => Brute window is under threshold but persistent isn't: the")
        print("     attempts arrived too slowly to pack 5 into 60s. Use a denser")
        print("     burst (hydra -t 4) for a true fast brute-force test.")


if __name__ == "__main__":
    main()
