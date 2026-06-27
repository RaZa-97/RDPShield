"""
RDPShield - Setup Verification
==============================
Prints a report of the current configuration and runtime state so you can
confirm everything is deployed correctly. Secrets are masked (never printed).

Run on the server:
    python verify_setup.py
"""

import config
import database


OK = "[ OK ]"
BAD = "[FAIL]"
INFO = "[info]"


def line(label, value, status=INFO):
    print(f"  {status}  {label}: {value}")


def masked(secret):
    if not secret or "YOUR_" in str(secret) or "XXXX" in str(secret):
        return "NOT SET"
    s = str(secret)
    return f"set ({s[:3]}..{s[-2:]}, len {len(s)})"


def main():
    print("=" * 64)
    print(" RDPShield Setup Verification")
    print("=" * 64)

    # --- Detection thresholds ---
    print("\n[1] Detection thresholds")
    line("Brute force", f"{config.BRUTE_FORCE_MAX_FAILURES} fails / {config.BRUTE_FORCE_TIME_WINDOW}s")
    line("Slow attack", f"{config.SLOW_ATTACK_MAX_FAILURES} fails / {config.SLOW_ATTACK_TIME_WINDOW}s")
    line("Password spray", f"{config.SPRAY_MAX_USERNAMES} users / {config.SPRAY_TIME_WINDOW}s")
    # Verify the setting exists and is sane (not a specific value — the
    # threshold is tunable; 15 is the recommended default, was 5).
    _pmf = getattr(config, "PERSISTENT_MAX_FAILURES", None)
    p_ok = isinstance(_pmf, int) and _pmf > 0
    line("Persistent",
         f"{getattr(config,'PERSISTENT_MAX_FAILURES','MISSING')} fails / "
         f"{getattr(config,'PERSISTENT_TIME_WINDOW','MISSING')}s",
         OK if p_ok else BAD)

    # --- Response / alerts ---
    print("\n[2] Response & alerts")
    line("Auto-block enabled", config.AUTO_BLOCK_ENABLED, OK if config.AUTO_BLOCK_ENABLED else BAD)
    line("Geo-block enabled", config.GEO_BLOCK_ENABLED, OK if config.GEO_BLOCK_ENABLED else BAD)
    needed_sms = {"brute_force", "password_spray", "persistent_attack", "geo_block", "whitelist_block"}
    have_sms = set(config.SMS_ALERT_TYPES)
    missing = needed_sms - have_sms
    line("SMS alert types", config.SMS_ALERT_TYPES, OK if not missing else BAD)
    if missing:
        line("  -> missing", ", ".join(sorted(missing)), BAD)
    line("Never-block IPs", config.WHITELIST_IPS)

    # --- Integrations (masked) ---
    print("\n[3] Integrations (secrets masked)")
    line("AbuseIPDB key", masked(config.ABUSEIPDB_API_KEY),
         OK if "set" in masked(config.ABUSEIPDB_API_KEY) else BAD)
    line("Notify.lk key", masked(config.NOTIFY_API_KEY),
         OK if "set" in masked(config.NOTIFY_API_KEY) else BAD)
    line("Alert phone", masked(config.ALERT_TO_NUMBER),
         OK if "set" in masked(config.ALERT_TO_NUMBER) else BAD)

    # --- Database ---
    print("\n[4] Database")
    conn = database.get_connection()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in c.fetchall()}
    needed_tables = {
        "failed_logins", "alerts", "blocked_ips", "geo_settings",
        "allowed_countries", "allowed_ips", "geo_cache", "geo_events",
        "yara_scans", "yara_findings",
    }
    line("Tables present", f"{len(needed_tables & tables)}/{len(needed_tables)}",
         OK if needed_tables.issubset(tables) else BAD)
    c.execute("PRAGMA table_info(geo_events)")
    geo_cols = {r[1] for r in c.fetchall()}
    line("geo_events.category column", "yes" if "category" in geo_cols else "MISSING",
         OK if "category" in geo_cols else BAD)
    for t in ("failed_logins", "alerts", "blocked_ips", "geo_events", "yara_scans"):
        c.execute(f"SELECT COUNT(*) FROM {t}")
        line(f"{t} rows", c.fetchone()[0])
    c.execute("SELECT COUNT(*) FROM blocked_ips WHERE is_active=1")
    line("Active blocks", c.fetchone()[0])
    conn.close()

    # --- Current access mode ---
    print("\n[5] Access control")
    line("Active geo mode", database.get_geo_mode())

    print("\n" + "=" * 64)
    print(" Review any [FAIL] lines above. Everything else is informational.")
    print("=" * 64)


if __name__ == "__main__":
    main()
