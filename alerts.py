"""
RDPShield Alerts Module
=======================
Handles three things when an attack is detected:

1. Geolocation Lookup (ip-api.com)
   - Finds the attacker's country, city, ISP
   - Free, no API key needed, 45 requests/minute limit

2. Reputation Check (AbuseIPDB)
   - Checks if the IP is known for abuse/attacks
   - Returns an abuse confidence score (0-100)
   - Free tier: 1000 lookups/day (needs API key)

3. SMS Alert (Twilio)
   - Sends you a text message when an attack is detected
   - Free trial gives you $15 credit
   - Requires account setup at twilio.com
"""

import requests
from config import (
    IP_API_URL,
    ABUSEIPDB_URL,
)
import settings  # DB-backed keys / recipients / SMS types (override config.py)


def lookup_geolocation(ip_address):
    """
    Look up the geographic location of an IP address.

    Uses ip-api.com (free, no key required).

    Args:
        ip_address: The IP to look up (e.g., "185.220.101.34")

    Returns:
        Dictionary with country, city, isp, etc.
        Returns empty dict if lookup fails.

    Note: For private IPs like 10.0.100.10 (our lab), this will return
    a "private range" result. It works properly with real public IPs.
    """
    try:
        url = IP_API_URL.format(ip=ip_address)
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", ""),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", ""),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                }
                print(
                    f"[GEO] {ip_address} -> "
                    f"{result['city']}, {result['country']} "
                    f"(ISP: {result['isp']})"
                )
                return result
            else:
                print(
                    f"[GEO] Lookup failed for {ip_address}: "
                    f"{data.get('message', 'unknown error')}"
                )
                return {}
        else:
            print(f"[GEO] HTTP error for {ip_address}: {response.status_code}")
            return {}

    except requests.exceptions.Timeout:
        print(f"[GEO] Timeout looking up {ip_address}")
        return {}
    except Exception as e:
        print(f"[GEO] Error looking up {ip_address}: {e}")
        return {}


def check_abuse_reputation(ip_address):
    """
    Check if an IP is reported for abuse on AbuseIPDB.

    Args:
        ip_address: The IP to check

    Returns:
        Dictionary with abuse confidence score and report count.
        Returns empty dict if API key is not set or lookup fails.

    The abuse_confidence_score ranges from 0 (clean) to 100 (definitely malicious).
    """
    abuse_key = settings.abuseipdb_key()
    if not abuse_key:
        print("[ABUSE] AbuseIPDB API key not configured. Skipping.")
        return {}

    try:
        headers = {
            "Accept": "application/json",
            "Key": abuse_key,
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,  # Check reports from last 90 days
        }

        response = requests.get(
            ABUSEIPDB_URL, headers=headers, params=params, timeout=5
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            result = {
                "abuse_score": data.get("abuseConfidencePercentage", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "is_tor": data.get("isTor", False),
            }
            print(
                f"[ABUSE] {ip_address} -> "
                f"Score: {result['abuse_score']}%, "
                f"Reports: {result['total_reports']}, "
                f"Tor: {result['is_tor']}"
            )
            return result
        else:
            print(
                f"[ABUSE] HTTP error for {ip_address}: {response.status_code}"
            )
            return {}

    except requests.exceptions.Timeout:
        print(f"[ABUSE] Timeout checking {ip_address}")
        return {}
    except Exception as e:
        print(f"[ABUSE] Error checking {ip_address}: {e}")
        return {}


# Human-readable reason labels for each block trigger, used in the block SMS.
REASON_LABELS = {
    "brute_force": "Brute force",
    "slow_attack": "Slow & low",
    "password_spray": "Password spray",
    "persistent_attack": "Persistent low-and-slow",
    "geo_block": "Geo blocked",
    "whitelist_block": "Non-whitelisted IP",
    "manual_block": "Manual block",
}


def _post_sms(message_body):
    """
    Low-level Notify.lk sender. Sends the message to EVERY active alert
    recipient (Settings) — falling back to config.ALERT_TO_NUMBER when none
    are configured. Returns True if at least one send succeeded.
    """
    uid, key, sender = (settings.notify_user_id(),
                        settings.notify_api_key(),
                        settings.notify_sender_id())
    numbers = settings.alert_numbers()
    if not all([uid, key]) or not numbers:
        print("[SMS] Notify.lk not configured / no recipients. Skipping SMS.")
        return False

    message_body = message_body[:621]  # Notify.lk hard limit
    url = "https://app.notify.lk/api/v1/send"
    sent_any = False
    for to in numbers:
        try:
            params = {"user_id": uid, "api_key": key, "sender_id": sender,
                      "to": to, "message": message_body}
            data = requests.get(url, params=params, timeout=10).json()
            if data.get("status") == "success":
                print(f"[SMS] Sent to {to}")
                sent_any = True
            else:
                print(f"[SMS] Notify.lk error for {to}: {data}")
        except Exception as e:
            print(f"[SMS] Error sending to {to}: {e}")
    return sent_any


def send_sms_to(to_number, message_body):
    """
    Send an SMS to a specific number via Notify.lk (used for password-reset
    codes and breach alerts to a specific phone). Returns True on success.
    """
    uid, key, sender = (settings.notify_user_id(),
                        settings.notify_api_key(),
                        settings.notify_sender_id())
    if not all([uid, key, to_number]):
        print("[SMS] Notify.lk not configured or no number. Skipping SMS.")
        return False
    try:
        message_body = message_body[:621]
        url = "https://app.notify.lk/api/v1/send"
        params = {
            "user_id": uid,
            "api_key": key,
            "sender_id": sender,
            "to": to_number,
            "message": message_body,
        }
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        if data.get("status") == "success":
            print(f"[SMS] Reset code sent to {to_number}")
            return True
        print(f"[SMS] Notify.lk error: {data}")
        return False
    except Exception as e:
        print(f"[SMS] Error sending SMS: {e}")
        return False


def send_block_sms(ip, country, alert_type, attempts, yara_summary,
                   city="", success_outside=False, timestamp=""):
    """
    Send the post-block notification SMS. Fired once per block, AFTER the
    YARA disk scan completes so the findings can be included.

    Body includes: IP, location, reason, failed-attempt count, whether a
    successful login came from the blocked zone, YARA results, and timestamp.
    """
    reason = REASON_LABELS.get(alert_type, alert_type)
    location = f"{city}, {country}" if city and country else (country or city or "Unknown")
    lines = [
        f"RDPShield BLOCKED {ip}",
        f"Location: {location}",
        f"Reason: {reason}",
        f"Failed attempts: {attempts}",
    ]
    if success_outside:
        lines.append("Valid login from blocked zone: YES")
    lines.append(f"YARA disk scan: {yara_summary}")
    if timestamp:
        lines.append(f"Time: {timestamp}")
    return _post_sms("\n".join(lines))


def send_sms_alert(alert_type, source_ip, description, geo_info=None):
    """
    Send a generic alert SMS via Notify.lk (used by the YARA-critical path).

    Args:
        alert_type: Type of alert ("yara_critical", "brute_force", etc.)
        source_ip: The attacker's IP
        description: Human-readable description of the attack
        geo_info: Optional geolocation dictionary

    Returns:
        True if SMS sent successfully, False otherwise
    """
    # Check if this alert type should trigger SMS (DB toggles override config)
    if alert_type not in settings.sms_alert_types():
        print(f"[SMS] Alert type '{alert_type}' not in SMS list. Skipping.")
        return False

    location = ""
    if geo_info:
        location = (
            f"\nLocation: {geo_info.get('city', '?')}, "
            f"{geo_info.get('country', '?')}"
        )

    message_body = (
        f"RDPShield ALERT!\n"
        f"Type: {alert_type.upper()}\n"
        f"Attacker: {source_ip}{location}\n"
        f"{description}"
    )
    return _post_sms(message_body)


def process_alert_enrichment(source_ip):
    """
    Run all enrichment lookups for an attacker IP.
    Called by the detection engine when an attack is identified.

    Returns a dictionary with combined results from all lookups.
    """
    enrichment = {
        "geo_country": "",
        "geo_city": "",
        "geo_isp": "",
        "abuse_score": 0,
        "abuse_reports": 0,
    }

    # Geolocation
    geo = lookup_geolocation(source_ip)
    if geo:
        enrichment["geo_country"] = geo.get("country", "")
        enrichment["geo_city"] = geo.get("city", "")
        enrichment["geo_isp"] = geo.get("isp", "")

    # Reputation
    abuse = check_abuse_reputation(source_ip)
    if abuse:
        enrichment["abuse_score"] = abuse.get("abuse_score", 0)
        enrichment["abuse_reports"] = abuse.get("total_reports", 0)

    return enrichment, geo


# If run directly, test with a sample IP
if __name__ == "__main__":
    print("Testing IP enrichment with 8.8.8.8 (Google DNS)...")
    enrichment, geo = process_alert_enrichment("8.8.8.8")
    print(f"\nResults: {enrichment}")
