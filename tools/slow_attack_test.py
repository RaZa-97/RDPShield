#!/usr/bin/env python3
"""
RDPShield — paced RDP login generator (AUTHORISED TESTING ONLY)
================================================================
Drives slow-and-low (T2), persistent/low-and-slow (T4) and password-spray (T3)
RDP login attempts against YOUR OWN honeypot so you can validate RDPShield's
timing-aware detectors and record detection-to-block latency for Chapter 6.

It does NOT crack anything — it simply makes paced FAILED authentication
attempts (wrong passwords) to generate Windows Event ID 4625 on the target.

⚠  AUTHORISATION: only run this against a server you own and control, from a
   NETWORK DIFFERENT to the one you administer the box from (e.g. a phone
   hotspot), so RDPShield blocks the attacking IP and not your admin IP.

Requires FreeRDP's `xfreerdp` (Kali/BlackArch:  sudo apt install freerdp2-x11
or  sudo pacman -S freerdp). A Hydra fallback is documented at the bottom.

Examples
--------
  # Slow-and-low: 12 attempts, one every 60s (trips the 10-in-600s detector)
  python3 slow_attack_test.py -t 16.170.232.91 -u administrator --mode slow

  # Persistent: 14 attempts, one every 95s (trips the cumulative detector)
  python3 slow_attack_test.py -t 16.170.232.91 -u administrator --mode persistent

  # Password spray: one password across many usernames
  python3 slow_attack_test.py -t 16.170.232.91 --mode spray
"""
import argparse
import shutil
import subprocess
import sys
import time
from datetime import datetime

FAKE_PASSWORDS = [
    "Winter2024!", "Password1", "Admin@123", "Letmein2024", "Qwerty123!",
    "Summer2024", "Welcome1!", "P@ssw0rd", "Changeme1", "Server2022!",
    "Company123", "Rdp@2024", "Backup123!", "Test1234!",
]
SPRAY_USERS = ["administrator", "admin", "user", "guest", "test",
               "operator", "backup", "sql", "helpdesk", "scanner"]

MODES = {
    # mode      interval(s)  count   description
    "fast":       (2,   8, "Fast brute force: 8 attempts @2s → trips the 5-in-60s detector (T1)"),
    "slow":       (60,  12, "Slow-and-low: 12 attempts @60s (~11 min) → trips 10/600s detector (T2)"),
    "persistent": (95,  14, "Persistent: 14 attempts @95s (~22 min) → trips cumulative detector (T4)"),
    "spray":      (20,  10, "Password spray: one password across 10 usernames @20s (T3)"),
}


def banner(args, interval, count, desc):
    print("=" * 66)
    print("  RDPShield paced login generator — AUTHORISED TESTING ONLY")
    print("=" * 66)
    print(f"  Target      : {args.target}:{args.port}")
    print(f"  Mode        : {args.mode}  ({desc})")
    print(f"  Attempts    : {count}   Interval: {interval}s   ETA: ~{count*interval//60} min")
    print(f"  Username    : {'(spray list)' if args.mode == 'spray' else args.user}")
    print("=" * 66)
    print("  Confirm you OWN this server and are attacking from a DIFFERENT")
    print("  network than you administer it from (or you may lock yourself out).")
    try:
        if input("  Type 'yes' to proceed: ").strip().lower() != "yes":
            print("  Aborted."); sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Aborted."); sys.exit(1)


def one_attempt(target, port, user, password, timeout=12):
    """Make a single FAILED RDP auth attempt via xfreerdp +auth-only.
    Returns (succeeded, detail). A non-zero exit = auth rejected (expected)."""
    cmd = [
        "xfreerdp", f"/v:{target}:{port}", f"/u:{user}", f"/p:{password}",
        "/cert:ignore", "+auth-only", "/timeout:8000",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        # auth-only returns 0 if credentials were ACCEPTED (shouldn't happen with
        # fake passwords); non-zero means rejected, which is what we want.
        return (r.returncode == 0), (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
    except subprocess.TimeoutExpired:
        return False, ["timeout"]
    except FileNotFoundError:
        print("\n[ERROR] xfreerdp not found. Install FreeRDP:")
        print("        Debian/Kali:  sudo apt install freerdp2-x11")
        print("        Arch/BlackArch: sudo pacman -S freerdp")
        sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description="Paced RDP failed-login generator (authorised testing).")
    ap.add_argument("-t", "--target", required=True, help="Target server IP/host (your own)")
    ap.add_argument("-u", "--user", default="administrator", help="Username (non-spray modes)")
    ap.add_argument("-p", "--port", type=int, default=3389, help="RDP port (default 3389)")
    ap.add_argument("--mode", choices=MODES.keys(), default="fast", help="Attack pattern")
    ap.add_argument("--interval", type=int, help="Override seconds between attempts")
    ap.add_argument("--count", type=int, help="Override number of attempts")
    args = ap.parse_args()

    interval, count, desc = MODES[args.mode]
    if args.interval:
        interval = args.interval
    if args.count:
        count = args.count

    banner(args, interval, count, desc)
    start = datetime.now()
    print(f"\n[{start:%H:%M:%S}] START — record this as the first-attempt time for latency.\n")

    for i in range(1, count + 1):
        if args.mode == "spray":
            user = SPRAY_USERS[(i - 1) % len(SPRAY_USERS)]
            password = "Password123!"
        else:
            user = args.user
            password = FAKE_PASSWORDS[(i - 1) % len(FAKE_PASSWORDS)]

        ok, detail = one_attempt(args.target, args.port, user, password)
        ts = datetime.now().strftime("%H:%M:%S")
        status = "ACCEPTED?!" if ok else "rejected (4625 generated)"
        print(f"[{ts}] attempt {i:>2}/{count}  user={user:<14} -> {status}")
        if ok:
            print("        (a real password may have been guessed — stop and investigate)")

        if i < count:
            time.sleep(interval)

    end = datetime.now()
    print(f"\n[{end:%H:%M:%S}] DONE — {count} attempts over {str(end - start).split('.')[0]}.")
    print("Now check the RDPShield dashboard: note the alert time and the blocked-IP time,")
    print("then compute detection-to-block latency for Table 4.\n")


if __name__ == "__main__":
    main()

# -----------------------------------------------------------------------------
# Hydra fallback (if you prefer hydra and don't want xfreerdp):
#   Slow-and-low (paced by hand): run this 12 times, ~60s apart:
#     hydra -t 1 -l administrator -p Winter2024! rdp://YOUR_SERVER_IP
#   Password spray:
#     printf 'admin\nadministrator\nuser\nguest\ntest\n' > users.txt
#     hydra -t 1 -L users.txt -p 'Password123!' rdp://YOUR_SERVER_IP
# -----------------------------------------------------------------------------
