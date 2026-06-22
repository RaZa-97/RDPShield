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
from datetime import datetime

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


# --- API key rotation reminders -----------------------------------------
# We reminder-nudge every `interval` days (SMS + dashboard) so keys get rotated
# regularly. Per-key "last rotated" = the settings-row updated_at written when a
# key is changed via the UI; keys still living in config.py are untracked.
_ROTATABLE_KEYS = [
    ("VirusTotal", "vt_api_key"),
    ("AbuseIPDB", "abuseipdb_api_key"),
    ("Notify.lk", "notify_api_key"),
]


def rotation_interval_days():
    try:
        return max(1, int(_val("key_rotation_interval_days") or 2))
    except (ValueError, TypeError):
        return 2


def reminders_enabled():
    return _val("key_rotation_reminders") != "0"  # default ON


def key_rotation_status():
    """Per-key rotation age. Returns a list of dicts:
    {label, key, rotated_at, age_days (or None), due (bool)}."""
    interval = rotation_interval_days()
    allset = database.get_all_settings()
    out = []
    for label, skey in _ROTATABLE_KEYS:
        meta = allset.get(skey)
        rotated = meta["updated_at"] if (meta and meta.get("value")) else None
        age = None
        due = False
        if rotated:
            try:
                dt = datetime.strptime(rotated[:19], "%Y-%m-%d %H:%M:%S")
                age = (datetime.utcnow() - dt).days
                due = age >= interval
            except ValueError:
                pass
        out.append({"label": label, "key": skey, "rotated_at": rotated,
                    "age_days": age, "due": due})
    return out


def any_key_due():
    return any(s["due"] for s in key_rotation_status())
