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

# =============================================================================
# SMS ALERTS (Notify.lk) — register at https://app.notify.lk/register
# =============================================================================

NOTIFY_USER_ID = "YOUR_USER_ID"
NOTIFY_API_KEY = "YOUR_API_KEY"
NOTIFY_SENDER_ID = "NotifyDEMO"   # Use "NotifyDEMO" for testing
ALERT_TO_NUMBER = "94XXXXXXXXX"   # Your phone number (format: 9471XXXXXXX)

SMS_ALERT_TYPES = ["brute_force", "password_spray", "slow_attack", "geo_block", "yara_critical"]

# =============================================================================
# DASHBOARD SETTINGS
# =============================================================================

DASHBOARD_HOST = "0.0.0.0"  # Listen on all interfaces
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = False      # Set True only during development

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
