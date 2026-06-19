"""
RDPShield - Main Agent v2.1
============================
Now with Geographic Access Control (Phase 2).

Three geo-blocking modes:
  1. Allow from anywhere - no geo-blocking, attack detection only
  2. Whitelist only - nobody connects (public or private) except whitelisted IPs
  3. Country list - only allow IPs from listed countries

ALL modes still run attack detection (brute force, spray, slow-and-low)
on top. Being from an allowed country doesn't give you a free pass to
brute force.

Must run as Administrator (for Event Log access and firewall control).

Usage:
    python -u rdpshield.py
"""

import time
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict

# Check if running on Windows
try:
    import win32evtlog
    import win32con
except ImportError:
    print("[ERROR] pywin32 is not installed. Run: pip install pywin32")
    print("[ERROR] This script must run on Windows.")
    sys.exit(1)

from config import (
    EVENT_LOG_NAME,
    EVENT_ID_FAILED_LOGON,
    EVENT_ID_SUCCESS_LOGON,
    BRUTE_FORCE_MAX_FAILURES,
    BRUTE_FORCE_TIME_WINDOW,
    SLOW_ATTACK_MAX_FAILURES,
    SLOW_ATTACK_TIME_WINDOW,
    SPRAY_MAX_USERNAMES,
    SPRAY_TIME_WINDOW,
    PERSISTENT_MAX_FAILURES,
    PERSISTENT_TIME_WINDOW,
    WHITELIST_IPS,
    GEO_BLOCK_ENABLED,
    PRIVATE_IP_PREFIXES,
)
from database import (
    init_db,
    log_failed_login,
    log_alert,
    get_failed_logins_for_ip,
    get_unique_usernames_for_ip,
    is_ip_blocked,
    # Geo-blocking functions
    get_geo_mode,
    get_cached_geo,
    cache_geo,
    is_country_allowed,
    is_ip_allowed,
    log_geo_event,
)
from firewall import block_ip
import yara_scheduler
from alerts import (
    process_alert_enrichment,
    send_sms_alert,
    lookup_geolocation,
)


# Track which IPs have already triggered alerts (to avoid duplicates)
alerted_cache = {}
ALERT_COOLDOWN = 300  # Don't re-alert for same IP+type within 5 minutes

# How fast to check for new events (in seconds)
POLL_SPEED = 0.3


# =============================================================================
# GEO-BLOCKING FUNCTIONS
# =============================================================================

def is_private_ip(ip_address):
    """
    Check if an IP address is a private/internal IP.

    Private IPs are used inside local networks (like your lab's 10.0.100.10).
    They don't have real geolocation data, so we skip geo-checking them.

    How it works: checks if the IP starts with any known private prefix
    like "10.", "192.168.", "172.16.", etc.

    Args:
        ip_address: The IP to check (e.g., "10.0.100.10" or "185.220.101.34")

    Returns:
        True if it's a private IP, False if it's a public IP
    """
    return ip_address.startswith(PRIVATE_IP_PREFIXES)


def get_ip_geolocation(ip_address):
    """
    Get the country for an IP address, using cache when possible.

    Steps:
    1. Check the geo_cache table first — if we've looked up this IP before,
       use the stored result (saves API calls)
    2. If not cached, call ip-api.com to get the country
    3. Store the result in the cache for next time

    Args:
        ip_address: The public IP to look up

    Returns:
        Dictionary with country, city, isp, or empty dict if lookup fails
    """
    # Step 1: Check cache first
    cached = get_cached_geo(ip_address)
    if cached:
        return {
            "country": cached["country"],
            "city": cached["city"],
            "isp": cached["isp"],
            "country_code": cached.get("country_code", ""),
        }

    # Step 2: Not cached — call ip-api.com
    geo = lookup_geolocation(ip_address)
    if geo:
        # Step 3: Cache the result for next time
        cache_geo(
            ip_address,
            country=geo.get("country", ""),
            city=geo.get("city", ""),
            isp=geo.get("isp", ""),
            country_code=geo.get("country_code", ""),
        )
        return geo

    return {}


def geo_check_ip(ip_address, username, event_type="failed_login"):
    """
    THE MAIN GEO-BLOCKING FUNCTION

    Checks if an IP should be allowed or blocked based on the current
    geo-blocking mode. This runs BEFORE attack detection.

    Three modes:
    1. "allow_anywhere" — Skip geo-check, allow everything through
    2. "private_and_allowed" — Whitelist-only. Nobody connects unless their
       IP is explicitly in the allowed IPs list — public AND private. There
       is no automatic pass for internal network IPs in this mode.
    3. "country_list" — Look up the IP's country. If the country is in
       the allowed list, let it through. Otherwise, block it.

    Args:
        ip_address: The IP to check
        username: Who tried to log in (for logging)
        event_type: "failed_login" or "successful_login"

    Returns:
        True if the IP is ALLOWED (proceed with normal detection)
        False if the IP was GEO-BLOCKED (already handled)
    """
    # Master switch check
    if not GEO_BLOCK_ENABLED:
        return True  # Geo-blocking disabled, allow everything

    # Already blocked? Don't re-process
    if is_ip_blocked(ip_address):
        return True  # Let the existing block handle it

    # Get the current geo-blocking mode from the database
    mode = get_geo_mode()

    # ----- Mode 1: Allow from anywhere -----
    if mode == "allow_anywhere":
        return True  # No geo-blocking, just proceed to attack detection

    # ----- Mode 2: Whitelist only (public AND private IPs) -----
    elif mode == "private_and_allowed":
        # Every IP must be explicitly whitelisted to pass — private IPs
        # get no automatic bypass in this mode, unlike the other modes.
        if is_ip_allowed(ip_address):
            # IP is whitelisted — allow through
            geo = {} if is_private_ip(ip_address) else get_ip_geolocation(ip_address)
            log_geo_event(
                ip_address, username,
                geo.get("country", ""), geo.get("city", ""),
                geo.get("isp", ""),
                event_type, "allowed", "IP in allowed list"
            )
            return True
        else:
            # Not in whitelist — BLOCK IT
            geo = {} if is_private_ip(ip_address) else get_ip_geolocation(ip_address)
            country = geo.get("country", "Unknown") if not is_private_ip(ip_address) else "Private network"
            city = geo.get("city", "Unknown")

            print(f"\n{'='*60}")
            print(f"[GEO-BLOCK] Unwhitelisted IP: {ip_address}")
            print(f"[GEO-BLOCK] Location: {city}, {country}")
            print(f"[GEO-BLOCK] Mode: Whitelist only (public + private)")
            print(f"{'='*60}")

            log_geo_event(
                ip_address, username, country, city,
                geo.get("isp", ""),
                event_type, "blocked", "IP not in allowed list"
            )

            # Block and alert
            handle_detection(
                "geo_block", ip_address,
                f"IP from {city}, {country} - not in allowed list "
                f"(user: {username})"
            )
            return False

    # Private IPs bypass the remaining modes — they have no real
    # geolocation, and country-based filtering doesn't apply to them.
    if is_private_ip(ip_address):
        return True

    # ----- Mode 3: Country list -----
    if mode == "country_list":
        # Look up the IP's country
        geo = get_ip_geolocation(ip_address)
        country = geo.get("country", "")

        if not country:
            # Couldn't determine country — block to be safe
            log_geo_event(
                ip_address, username, "Unknown", "",
                geo.get("isp", ""),
                event_type, "blocked", "Country could not be determined"
            )
            handle_detection(
                "geo_block", ip_address,
                f"Country unknown - could not determine location "
                f"(user: {username})"
            )
            return False

        if is_country_allowed(country):
            # Country is in the allowed list — let through
            log_geo_event(
                ip_address, username, country, geo.get("city", ""),
                geo.get("isp", ""),
                event_type, "allowed", f"Country '{country}' is allowed"
            )
            print(
                f"[GEO] Allowed: {ip_address} from {country} "
                f"(user: {username})"
            )
            return True
        else:
            # Country NOT in the allowed list — BLOCK IT
            city = geo.get("city", "Unknown")

            print(f"\n{'='*60}")
            print(f"[GEO-BLOCK] Unauthorized country: {country}")
            print(f"[GEO-BLOCK] IP: {ip_address} ({city})")
            print(f"[GEO-BLOCK] User: {username}")
            print(f"{'='*60}")

            log_geo_event(
                ip_address, username, country, city,
                geo.get("isp", ""),
                event_type, "blocked",
                f"Country '{country}' not in allowed list"
            )

            handle_detection(
                "geo_block", ip_address,
                f"Login from {city}, {country} - country not allowed "
                f"(user: {username})"
            )
            return False

    # Unknown mode — allow through as fallback
    return True


# =============================================================================
# EVENT PARSING
# =============================================================================

def parse_event_xml(event_xml_string):
    """
    Parse a Windows Event XML string to extract key fields.
    Works for both Event ID 4625 (failed) and 4624 (successful) logons.
    """
    try:
        root = ET.fromstring(event_xml_string)
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"

        system = root.find(f"{ns}System")
        event_id_elem = system.find(f"{ns}EventID")
        event_id = int(event_id_elem.text) if event_id_elem is not None else 0
        time_created = system.find(f"{ns}TimeCreated").get("SystemTime", "")

        event_data = root.find(f"{ns}EventData")
        if event_data is None:
            return None

        data = {}
        for item in event_data.findall(f"{ns}Data"):
            name = item.get("Name", "")
            value = item.text or ""
            data[name] = value

        parsed = {
            "event_id": event_id,
            "timestamp": time_created,
            "username": data.get("TargetUserName", ""),
            "domain": data.get("TargetDomainName", ""),
            "source_ip": data.get("IpAddress", ""),
            "sub_status": data.get("SubStatus", ""),
            "logon_type": int(data.get("LogonType", 0)),
            "workstation": data.get("WorkstationName", ""),
        }

        return parsed

    except ET.ParseError as e:
        print(f"[PARSER] XML parse error: {e}")
        return None
    except Exception as e:
        print(f"[PARSER] Error parsing event: {e}")
        return None


# =============================================================================
# EVENT QUERY
# =============================================================================

def get_new_events():
    """
    Query the Windows Security Event Log for new 4624 and 4625 events.
    """
    global last_event_time

    events = []
    newest_event_time = None

    try:
        query = (
            f"<QueryList>"
            f"  <Query Id='0' Path='{EVENT_LOG_NAME}'>"
            f"    <Select Path='{EVENT_LOG_NAME}'>"
            f"      *[System[(EventID={EVENT_ID_FAILED_LOGON} or "
            f"EventID={EVENT_ID_SUCCESS_LOGON})]]"
            f"    </Select>"
            f"  </Query>"
            f"</QueryList>"
        )

        cutoff_time = last_event_time

        handle = win32evtlog.EvtQuery(
            EVENT_LOG_NAME,
            win32evtlog.EvtQueryReverseDirection,
            query,
        )

        while True:
            raw_events = win32evtlog.EvtNext(handle, 50, -1, 0)
            if not raw_events:
                break

            for event in raw_events:
                xml_string = win32evtlog.EvtRender(
                    event, win32evtlog.EvtRenderEventXml
                )

                parsed = parse_event_xml(xml_string)
                if parsed is None:
                    continue

                try:
                    event_time = datetime.fromisoformat(
                        parsed["timestamp"].replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    continue

                if cutoff_time and event_time <= cutoff_time:
                    break

                ip = parsed["source_ip"]
                if not ip or ip == "-" or ip == "127.0.0.1":
                    continue

                if newest_event_time is None or event_time > newest_event_time:
                    newest_event_time = event_time

                events.append(parsed)

            else:
                continue
            break

        if newest_event_time is not None:
            last_event_time = newest_event_time

        events.reverse()
        return events

    except Exception as e:
        print(f"[MONITOR] Error reading event log: {e}")
        return events


# =============================================================================
# EVENT PROCESSING
# =============================================================================

def process_failed_login(event):
    """
    Process a single Event ID 4625 (failed login) event.

    Flow:
    1. Run geo-check FIRST — if blocked by geo, stop here
    2. Store in database
    3. Run attack detection algorithms
    """
    ip = event["source_ip"]
    username = event["username"]
    timestamp = event["timestamp"]

    print(
        f"[EVENT] Failed login: user='{username}' "
        f"from={ip} at={timestamp}"
    )

    # STEP 1: Geo-check (runs before everything else)
    # If geo_check_ip returns False, the IP was geo-blocked — stop here
    if not geo_check_ip(ip, username, "failed_login"):
        return

    # STEP 2: Store in database
    log_failed_login(
        timestamp=timestamp,
        source_ip=ip,
        username=username,
        domain=event.get("domain", ""),
        logon_type=event.get("logon_type", 3),
        sub_status=event.get("sub_status", ""),
        workstation=event.get("workstation", ""),
    )

    # Best-effort: geolocate public attacker IPs so the dashboard can show
    # the country for each failed login. get_ip_geolocation caches results,
    # so repeated attempts from the same IP cost no extra API calls.
    if not is_private_ip(ip):
        get_ip_geolocation(ip)

    # Skip further analysis if already blocked
    if is_ip_blocked(ip):
        print(f"[DETECT] {ip} is already blocked. Skipping detection.")
        return

    # STEP 3: Run attack detection algorithms
    is_brute, count = detect_brute_force(ip)
    if is_brute:
        handle_detection(
            "brute_force", ip,
            f"{count} failed logins in {BRUTE_FORCE_TIME_WINDOW}s "
            f"(last user: {username})"
        )
        return

    is_slow, count = detect_slow_attack(ip)
    if is_slow:
        handle_detection(
            "slow_attack", ip,
            f"{count} failed logins in {SLOW_ATTACK_TIME_WINDOW}s "
            f"(slow-and-low pattern, last user: {username})"
        )
        return

    is_spray, usernames = detect_password_spray(ip)
    if is_spray:
        handle_detection(
            "password_spray", ip,
            f"{len(usernames)} unique usernames targeted: "
            f"{', '.join(usernames)}"
        )
        return

    is_persistent, total = detect_persistent_attacker(ip)
    if is_persistent:
        handle_detection(
            "persistent_attack", ip,
            f"{total} failed logins in {PERSISTENT_TIME_WINDOW // 60} min "
            f"(low-and-slow pattern, last user: {username})"
        )
        return


def process_successful_login(event):
    """
    Process a single Event ID 4624 (successful login) event.

    Flow:
    1. Filter out system accounts and non-RDP logons
    2. Run geo-check — if from unauthorized country/IP, block immediately
       even though they had a valid password
    """
    ip = event["source_ip"]
    username = event["username"]
    logon_type = event.get("logon_type", 0)

    # Only track network (3) and RemoteInteractive/RDP (10) logons
    if logon_type not in (3, 10):
        return

    # Skip system accounts that generate noise
    if username.endswith("$") or username in ("SYSTEM", "LOCAL SERVICE",
                                               "NETWORK SERVICE", ""):
        return

    print(
        f"[EVENT] Successful login: user='{username}' "
        f"from={ip} type={logon_type}"
    )

    # Run geo-check — this blocks IPs from unauthorized locations
    # even if they logged in with a valid password
    geo_check_ip(ip, username, "successful_login")


# =============================================================================
# DETECTION ALGORITHMS
# =============================================================================

def detect_brute_force(source_ip):
    """DETECTION ALGORITHM 1: Fast Brute Force (5 failures in 60s)"""
    records = get_failed_logins_for_ip(source_ip, BRUTE_FORCE_TIME_WINDOW)
    count = len(records)
    if count >= BRUTE_FORCE_MAX_FAILURES:
        return True, count
    return False, count


def detect_slow_attack(source_ip):
    """DETECTION ALGORITHM 2: Slow-and-Low (10 failures in 600s)"""
    records = get_failed_logins_for_ip(source_ip, SLOW_ATTACK_TIME_WINDOW)
    count = len(records)

    if count >= SLOW_ATTACK_MAX_FAILURES:
        if len(records) >= 3:
            timestamps = []
            for r in records:
                try:
                    ts = datetime.fromisoformat(
                        r["timestamp"].replace("Z", "+00:00")
                    )
                    timestamps.append(ts.timestamp())
                except (ValueError, KeyError):
                    continue

            if len(timestamps) >= 3:
                intervals = [
                    timestamps[i + 1] - timestamps[i]
                    for i in range(len(timestamps) - 1)
                ]
                if intervals:
                    avg = sum(intervals) / len(intervals)
                    variance = sum(
                        (x - avg) ** 2 for x in intervals
                    ) / len(intervals)

                    if variance < 2.0 and avg > 5.0:
                        print(
                            f"[DETECT] Slow-and-low: {source_ip} has "
                            f"suspiciously regular timing "
                            f"(avg interval: {avg:.1f}s, "
                            f"variance: {variance:.2f})"
                        )

        return True, count
    return False, count


def detect_password_spray(source_ip):
    """DETECTION ALGORITHM 3: Password Spraying (4 usernames in 300s)"""
    usernames = get_unique_usernames_for_ip(source_ip, SPRAY_TIME_WINDOW)
    if len(usernames) >= SPRAY_MAX_USERNAMES:
        return True, usernames
    return False, usernames


def detect_persistent_attacker(source_ip):
    """
    DETECTION ALGORITHM 4: Persistent / Low-and-Slow attacker.

    Catches attackers who deliberately pace their attempts to stay UNDER the
    brute-force (5/60s) and slow-attack (10/600s) thresholds — e.g. one try
    every ~90 seconds. No single short window trips the other detectors, but
    the cumulative total over a wide window (default 12 failures in 1 hour)
    exposes a determined attacker that would otherwise slip through.
    """
    records = get_failed_logins_for_ip(source_ip, PERSISTENT_TIME_WINDOW)
    count = len(records)
    if count >= PERSISTENT_MAX_FAILURES:
        return True, count
    return False, count


# =============================================================================
# ALERT HANDLING
# =============================================================================

def should_alert(source_ip, alert_type):
    """Prevent alert flooding with a cooldown period."""
    key = (source_ip, alert_type)
    now = time.time()
    if key in alerted_cache:
        elapsed = now - alerted_cache[key]
        if elapsed < ALERT_COOLDOWN:
            return False
    alerted_cache[key] = now
    return True


def handle_detection(alert_type, source_ip, detail_info):
    """Central handler for all detection alerts including geo_block."""
    if not should_alert(source_ip, alert_type):
        return

    if source_ip in WHITELIST_IPS:
        return

    print(f"\n{'='*60}")
    print(f"[ALERT] {alert_type.upper()} detected from {source_ip}")
    print(f"[ALERT] {detail_info}")
    print(f"{'='*60}")

    enrichment, geo = process_alert_enrichment(source_ip)
    blocked = block_ip(source_ip, reason=f"{alert_type}: {detail_info}")
    # v3.0: launch a post-breach YARA scan in the background (daemon thread).
    # SMS on CRITICAL findings is handled inside yara_scheduler, not here.
    if blocked:
        yara_scheduler.trigger_scan_async("post_block:" + source_ip)
    sms_sent = send_sms_alert(
        alert_type, source_ip, detail_info, geo_info=geo
    )

    log_alert(
        alert_type=alert_type,
        source_ip=source_ip,
        description=detail_info,
        usernames=str(detail_info),
        failure_count=0,
        geo_country=enrichment.get("geo_country", ""),
        geo_city=enrichment.get("geo_city", ""),
        abuse_score=enrichment.get("abuse_score", 0),
        blocked=1 if blocked else 0,
        sms_sent=1 if sms_sent else 0,
    )


# =============================================================================
# MAIN
# =============================================================================

def main():
    """
    Main function. Initializes everything and starts monitoring.
    """
    global last_event_time

    print(r"""
    ╔══════════════════════════════════════════╗
    ║         RDPShield Agent v2.1             ║
    ║   RDP Brute Force Detection System       ║
    ║   + Geographic Access Control            ║
    ╚══════════════════════════════════════════╝
    """)

    # Initialize database
    init_db()

    # Set the start time to NOW
    last_event_time = datetime.now().astimezone()

    # Get current geo mode
    geo_mode = get_geo_mode()
    geo_mode_display = {
        "allow_anywhere": "Allow from anywhere (no geo-blocking)",
        "private_and_allowed": "Whitelist only (public + private)",
        "country_list": "Country whitelist",
    }

    print(f"[MONITOR] Monitoring started at {last_event_time}")
    print(f"[MONITOR] Speed: {POLL_SPEED}s intervals")
    print(f"[MONITOR] Watching: Event ID {EVENT_ID_FAILED_LOGON} "
          f"(failed) + {EVENT_ID_SUCCESS_LOGON} (successful)")
    print(f"[MONITOR] Geo-blocking: {geo_mode_display.get(geo_mode, geo_mode)}")
    print(f"[MONITOR] Thresholds:")
    print(f"  Brute Force: {BRUTE_FORCE_MAX_FAILURES} failures "
          f"in {BRUTE_FORCE_TIME_WINDOW}s")
    print(f"  Slow Attack: {SLOW_ATTACK_MAX_FAILURES} failures "
          f"in {SLOW_ATTACK_TIME_WINDOW}s")
    print(f"  Spray: {SPRAY_MAX_USERNAMES} usernames "
          f"in {SPRAY_TIME_WINDOW}s")
    print(f"  Persistent: {PERSISTENT_MAX_FAILURES} failures "
          f"in {PERSISTENT_TIME_WINDOW}s")
    print(f"[MONITOR] Whitelist: {WHITELIST_IPS}")
    print(f"\n[MONITOR] Waiting for login events...\n")

    # Main monitoring loop
    try:
        while True:
            events = get_new_events()

            if events:
                for event in events:
                    if event["event_id"] == EVENT_ID_FAILED_LOGON:
                        process_failed_login(event)
                    elif event["event_id"] == EVENT_ID_SUCCESS_LOGON:
                        process_successful_login(event)

            time.sleep(POLL_SPEED)

    except KeyboardInterrupt:
        print("\n[MONITOR] Shutting down RDPShield...")
        print("[MONITOR] Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()