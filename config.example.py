"""
RDPShield Configuration — TEMPLATE
==================================
Copy this file to `config.py` and fill in your own values.
`config.py` is gitignored so your real keys never get committed.

    cp config.example.py config.py      # Linux/macOS
    copy config.example.py config.py    # Windows
"""

# =============================================================================
# DETECTION THRESHOLDS
# =============================================================================

# --- Fast Brute Force ---
BRUTE_FORCE_MAX_FAILURES = 5
BRUTE_FORCE_TIME_WINDOW = 60  # seconds

# --- Slow-and-Low Attack ---
SLOW_ATTACK_MAX_FAILURES = 10
SLOW_ATTACK_TIME_WINDOW = 600  # seconds (10 minutes)

# --- Password Spraying ---
SPRAY_MAX_USERNAMES = 4
SPRAY_TIME_WINDOW = 300  # seconds (5 minutes)

# --- Persistent / Low-and-Slow Attack ---
# Catches attackers that pace attempts to stay under the rate thresholds.
# Flags an IP that accumulates X total failures within a wide window.
# Example: 15 failed logins from one IP within 24 hours, regardless of pacing.
# Set to 15 (not 5) so "persistent" means GENUINE persistence: at 5/24h this
# catch-all fired on almost every scanner and shadowed the brute/slow/spray
# detectors (everything got labelled persistent_attack). 15-20 is a defensible
# range; raise toward 20 if the honeypot is very noisy.
PERSISTENT_MAX_FAILURES = 15
PERSISTENT_TIME_WINDOW = 86400  # seconds (24 hours)

# =============================================================================
# AUTO-BLOCK SETTINGS
# =============================================================================

AUTO_BLOCK_ENABLED = True
BLOCK_DURATION = 3600  # 1 hour (0 = permanent until manual unblock)

# IPs that should NEVER be blocked (your own machines, management IPs)
WHITELIST_IPS = [
    "127.0.0.1",
    "10.0.100.20",   # This server itself
    # Add your management / admin IPs here
]

# =============================================================================
# IP LOOKUP SETTINGS (Geolocation + Reputation)
# =============================================================================

# ip-api.com (free, no key needed, 45 requests/minute limit)
IP_API_URL = "http://ip-api.com/json/{ip}"

# AbuseIPDB (free tier: 1000 lookups/day) — get a key at https://www.abuseipdb.com/
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# --- Reputation / Threat-Intel alert ----------------------------------------
# Catches LOW-VOLUME malicious IPs that never trip the count-based detectors
# (e.g. 6 failed logins spread across a day). Once an IP passes a small attempt
# floor, RDPShield checks its AbuseIPDB reputation (cached to respect quota) and,
# for flagged IPs, VirusTotal. Tiered response so the SOC isn't spammed and good
# IPs aren't wrongly blocked:
#   abuse >= REPUTATION_ALERT_SCORE          -> SMS the SOC (alert only)
#   abuse >= REPUTATION_BLOCK_SCORE          -> auto-block + SMS
#   abuse >= ALERT_SCORE *and* VT malicious  -> auto-block + SMS (two sources agree)
REPUTATION_ALERT_ENABLED = True
REPUTATION_MIN_ATTEMPTS  = 3      # failed logins before a reputation lookup runs
REPUTATION_ALERT_SCORE   = 50     # AbuseIPDB confidence % -> alert the SOC
REPUTATION_BLOCK_SCORE   = 85     # AbuseIPDB confidence % -> auto-block
REPUTATION_USE_VT        = True   # also consult VirusTotal for already-flagged IPs
REPUTATION_CACHE_HOURS   = 24     # cache a reputation result this long (quota + dedup)

# --- Campaign / coordinated-attack detector ---------------------------------
# Long-horizon correlation (default 7 days) that catches campaigns no single
# detector sees: one IP active across many days, a country attacking with many
# rotating IPs, and attacks that recur in the same time-of-day band. Runs on a
# timer in the agent. Tiered response: SMS the SOC for every campaign + list it
# in the dashboard tracker; AUTO-BLOCK only the worst single-IP campaigns
# (countries stay alert-only — use Geo-Block to act on a whole country).
CAMPAIGN_ENABLED           = True
CAMPAIGN_WINDOW_DAYS       = 7    # rolling analysis window
CAMPAIGN_CHECK_INTERVAL_HOURS = 6  # how often the agent re-runs the analysis
CAMPAIGN_IP_MIN_DAYS       = 3    # an IP must be active on >= this many days
CAMPAIGN_IP_MIN_FAILS      = 30   # ...and have >= this many failures, to flag
CAMPAIGN_IP_BLOCK_FAILS    = 60   # single-IP campaign auto-blocks at/above this
CAMPAIGN_COUNTRY_MIN_IPS   = 5    # a country needs >= this many distinct IPs...
CAMPAIGN_COUNTRY_MIN_FAILS = 100  # ...and >= this many failures, to flag
CAMPAIGN_TIME_PCT          = 50   # >= this % of attempts in a 3h band = "scheduled"
CAMPAIGN_REALERT_HOURS     = 24   # don't re-SMS the same campaign within this
CAMPAIGN_AUTOBLOCK_IPS     = True # auto-block the worst single-IP campaigns

# =============================================================================
# SMS ALERTS (Notify.lk) — register at https://app.notify.lk/register
# =============================================================================

NOTIFY_USER_ID = "YOUR_USER_ID"
NOTIFY_API_KEY = "YOUR_API_KEY"
NOTIFY_SENDER_ID = "NotifyDEMO"   # Use "NotifyDEMO" for testing
ALERT_TO_NUMBER = "94XXXXXXXXX"   # Your phone number (format: 9471XXXXXXX)

SMS_ALERT_TYPES = ["brute_force", "password_spray", "slow_attack", "persistent_attack", "geo_block", "whitelist_block", "yara_critical", "reputation_alert", "campaign_alert"]

# =============================================================================
# DASHBOARD SETTINGS
# =============================================================================

DASHBOARD_HOST = "0.0.0.0"  # Listen on all interfaces
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = False      # Set True only during development

# --- HTTPS / TLS (all optional; default = plain HTTP) --------------------
# Mark the session cookie "Secure" so it is only sent over HTTPS. Turn this ON
# only once the dashboard is actually served over TLS (via a reverse proxy or
# the direct cert below) — enabling it on plain HTTP locks you out of login.
DASHBOARD_USE_HTTPS = False

# Set True when a reverse proxy (Caddy/nginx) terminates TLS in front of Flask,
# so the app trusts X-Forwarded-* (correct scheme + real client IP in the audit
# log). See INSTALL.md §"HTTPS".
DASHBOARD_BEHIND_PROXY = False

# Direct TLS without a proxy: point these at a cert + key (PEM) and Flask serves
# HTTPS itself. Leave blank to serve HTTP. (A reverse proxy is recommended for a
# trusted certificate — see INSTALL.md.)
DASHBOARD_SSL_CERT = ""
DASHBOARD_SSL_KEY = ""

# =============================================================================
# DATABASE
# =============================================================================

DATABASE_PATH = "rdpshield.db"

# =============================================================================
# GEO-BLOCKING SETTINGS
# =============================================================================

GEO_BLOCK_ENABLED = True

# Private IP ranges — never geo-checked (internal network IPs)
PRIVATE_IP_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",          # Localhost
    "169.254.",      # Link-local
)

# =============================================================================
# EVENT LOG MONITORING
# =============================================================================

EVENT_LOG_NAME = "Security"
EVENT_ID_FAILED_LOGON = 4625
EVENT_ID_SUCCESS_LOGON = 4624

# =============================================================================
# YARA (v3.0)
# =============================================================================

YARA_SCAN_PATHS = [
    r"C:\Windows\Temp",
    r"C:\Users\Public",
    r"C:\Temp",
]
YARA_MEMORY_SCAN_ON_BLOCK = False
YARA_MAX_FILE_SIZE        = 10 * 1024 * 1024   # skip files larger than 10 MB
YARA_MATCH_TIMEOUT        = 20
YARA_SCAN_TIMEOUT         = 120
YARA_FP_THRESHOLD = 0.40

YARA_MEMORY_EXCLUDE_CMDLINE = ["rdpshield.py", "dashboard.py", "yara_scanner.py"]
YARA_MEMORY_EXCLUDE_NAMES = [
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
    "opera.exe", "brave.exe", "msedgewebview2.exe",
]

# Where quarantined files are moved to (created automatically).
YARA_QUARANTINE_DIR = r"C:\RDPShield_Quarantine"

# =============================================================================
# VIRUSTOTAL (file-hash + IP reputation enrichment)
# =============================================================================
# Free API key from https://www.virustotal.com/  (Account -> API Key).
# Free tier: 4 lookups/min, 500/day. Leave blank to disable VT lookups.
VIRUSTOTAL_API_KEY = ""
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"
