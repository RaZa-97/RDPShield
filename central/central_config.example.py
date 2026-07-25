"""
RDPShield Central Configuration — TEMPLATE
==========================================
Copy this file to `central_config.py` and fill in your own values.
`central_config.py` is gitignored so your real keys never get committed.

    cp central_config.example.py central_config.py      # Linux/macOS
    copy central_config.example.py central_config.py    # Windows

Central is the multi-tenant command centre. It is a SEPARATE Flask process
from the per-instance RDPShield dashboards and is NEVER deployed to a customer
box — see CENTRAL.md.
"""

# =============================================================================
# SERVER
# =============================================================================

CENTRAL_HOST = "0.0.0.0"
CENTRAL_PORT = 6100
CENTRAL_DEBUG = False        # Set True only during development

# The externally reachable base URL of this Central, no trailing slash. Used in
# enrolment instructions and as the SSO token issuer audience base.
CENTRAL_PUBLIC_URL = "https://central.example.com:6100"

# =============================================================================
# TLS — NOT OPTIONAL FOR CENTRAL
# =============================================================================
# Unlike the per-instance dashboard (which is allowed to run on plain HTTP
# behind an IP allow-list), Central carries cross-tenant data and mints SSO
# tokens that grant dashboard sessions. Those tokens and the agents' bearer API
# keys travel over this connection, so it MUST be encrypted.
#
# Either terminate TLS at a reverse proxy (Caddy/nginx) and set
# CENTRAL_BEHIND_PROXY = True, or point Central at a cert + key directly.
# central_app.py REFUSES TO START if neither is configured.

CENTRAL_SSL_CERT = ""        # e.g. r"C:\certs\central.crt"
CENTRAL_SSL_KEY = ""         # e.g. r"C:\certs\central.key"
CENTRAL_BEHIND_PROXY = False # True when Caddy/nginx terminates TLS in front

# Escape hatch for LOCAL DEVELOPMENT ONLY. Setting this True lets Central start
# on plain HTTP. Never enable it on anything reachable from a network you do
# not control — it disables the Secure cookie flag and exposes SSO tokens.
CENTRAL_ALLOW_INSECURE_HTTP = False

# =============================================================================
# DATABASE
# =============================================================================
# Central's own SQLite file. It is a SEPARATE database from any instance's
# rdpshield.db — no instance ever reads or writes it, and it never holds raw
# attacker records (only the aggregated counters agents push).

CENTRAL_DATABASE_PATH = "central.db"   # relative to the central/ folder

# =============================================================================
# SSO SIGNING KEYS (RS256)
# =============================================================================
# Generate once with:   python central_keygen.py
#
# The PRIVATE key never leaves Central. Each instance is given only the PUBLIC
# JWK, which can verify a token but can never mint one — so a compromised
# customer box cannot forge sessions into any dashboard, including its own.

CENTRAL_SSO_PRIVATE_KEY_PATH = "central_sso_private.pem"
CENTRAL_SSO_PUBLIC_JWK_PATH = "central_sso_public.jwk.json"

CENTRAL_SSO_ISSUER = "rdpshield-central"
CENTRAL_SSO_TOKEN_TTL = 60      # seconds a click-through token stays valid
CENTRAL_SSO_MAX_TTL = 300       # hard ceiling the instance also enforces

# =============================================================================
# AGENT INGESTION
# =============================================================================

# An agent that has not checked in for this many seconds is shown as Offline.
CENTRAL_AGENT_OFFLINE_AFTER = 300      # 5 minutes

# Per-agent rate limit on POST /api/v1/agents/<uid>/report.
CENTRAL_REPORT_RATE_LIMIT = 20         # max accepted reports ...
CENTRAL_REPORT_RATE_WINDOW = 60        # ... per this many seconds

# Reject report bodies larger than this (bytes). The documented payload is well
# under 2 KB; anything bigger is a bug or an attack.
CENTRAL_MAX_REPORT_BYTES = 8192

# =============================================================================
# SESSIONS / AUTH
# =============================================================================

CENTRAL_SESSION_HOURS = 12     # absolute session lifetime
CENTRAL_IDLE_TIMEOUT = 3600    # auto-logout after 1h of inactivity
CENTRAL_MIN_PASSWORD_LEN = 12
CENTRAL_FAILED_LOGIN_LIMIT = 5
CENTRAL_LOCKOUT_DURATION = 900 # 15-minute temporary lock, auto-recovers

# Private ranges allowed to reach the one-time first-run /setup wizard.
CENTRAL_PRIVATE_IP_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "169.254.",
)
