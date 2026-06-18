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
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_URL,
    NOTIFY_USER_ID,
    NOTIFY_API_KEY,
    NOTIFY_SENDER_ID,
    ALERT_TO_NUMBER,
    SMS_ALERT_TYPES,
)


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
    if not ABUSEIPDB_API_KEY:
        print("[ABUSE] AbuseIPDB API key not configured. Skipping.")
        return {}

    try:
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY,
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


def send_sms_alert(alert_type, source_ip, description, geo_info=None):
    """
    Send an SMS alert via Notify.lk.

    Args:
        alert_type: Type of alert ("brute_force", "password_spray", etc.)
        source_ip: The attacker's IP
        description: Human-readable description of the attack
        geo_info: Optional geolocation dictionary

    Returns:
        True if SMS sent successfully, False otherwise
    """
    # Check if SMS is configured
    if not all([NOTIFY_USER_ID, NOTIFY_API_KEY, ALERT_TO_NUMBER]):
        print("[SMS] Notify.lk not configured. Skipping SMS alert.")
        return False

    # Check if this alert type should trigger SMS
    if alert_type not in SMS_ALERT_TYPES:
        print(f"[SMS] Alert type '{alert_type}' not in SMS list. Skipping.")
        return False

    try:
        # Build the message (max 621 chars for Notify.lk)
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

        # Trim to 621 chars max
        message_body = message_body[:621]

        # Send via Notify.lk API
        url = "https://app.notify.lk/api/v1/send"
        params = {
            "user_id": NOTIFY_USER_ID,
            "api_key": NOTIFY_API_KEY,
            "sender_id": NOTIFY_SENDER_ID,
            "to": ALERT_TO_NUMBER,
            "message": message_body,
        }

        response = requests.get(url, params=params, timeout=10)
        data = response.json()

        if data.get("status") == "success":
            print(f"[SMS] Alert sent via Notify.lk!")
            return True
        else:
            print(f"[SMS] Notify.lk error: {data}")
            return False

    except Exception as e:
        print(f"[SMS] Error sending alert: {e}")
        return False


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
