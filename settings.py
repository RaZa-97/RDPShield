"""
RDPShield runtime settings (v3.4)
=================================
DB-backed settings that OVERRIDE config.py at runtime, so admins can rotate API
keys, manage alert recipients, choose SMS alert types, and set data retention
from the Settings page without editing config.py / restarting.

Everything falls back to config.py when nothing is stored in the DB, so a fresh
install keeps working with the existing config values. Both the dashboard and
the agent import this module, so changes apply to both processes (shared DB).
"""

import json

import database
import config


def _val(key):
    """A stored setting value, or None if unset/blank."""
    v = database.get_setting(key)
    return v if v else None


# --- API keys (DB overrides config.py) ----------------------------------
def vt_api_key():       return _val("vt_api_key") or getattr(config, "VIRUSTOTAL_API_KEY", "")
def vt_url():           return getattr(config, "VIRUSTOTAL_URL", "")
def abuseipdb_key():    return _val("abuseipdb_api_key") or getattr(config, "ABUSEIPDB_API_KEY", "")
def notify_user_id():   return _val("notify_user_id") or getattr(config, "NOTIFY_USER_ID", "")
def notify_api_key():   return _val("notify_api_key") or getattr(config, "NOTIFY_API_KEY", "")
def notify_sender_id(): return _val("notify_sender_id") or getattr(config, "NOTIFY_SENDER_ID", "")


# --- SMS alert types -----------------------------------------------------
ALL_SMS_TYPES = [
    "brute_force", "password_spray", "slow_attack", "persistent_attack",
    "geo_block", "whitelist_block", "yara_critical",
]


def sms_alert_types():
    raw = _val("sms_alert_types")
    if raw:
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            pass
    return list(getattr(config, "SMS_ALERT_TYPES", ALL_SMS_TYPES))


def set_sms_alert_types(types):
    database.set_setting("sms_alert_types", json.dumps(list(types)))


# --- alert recipients (SMS) ---------------------------------------------
def alert_numbers():
    """All active recipient numbers, falling back to config.ALERT_TO_NUMBER."""
    nums = [r["phone"] for r in database.list_alert_recipients(active_only=True) if r["phone"]]
    if not nums:
        fallback = getattr(config, "ALERT_TO_NUMBER", "")
        if fallback:
            nums = [fallback]
    return nums


# --- data retention ------------------------------------------------------
def retention_days():
    try:
        return int(_val("retention_days") or 0)
    except (ValueError, TypeError):
        return 0
