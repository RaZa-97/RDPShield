"""
RDPShield — the agent check-in payload, defined once
====================================================
The single source of truth for what an agent may push to Central. Both sides
import this module: `central_reporter.py` builds a payload against it, and
Central's ingestion API validates against it. They therefore cannot drift.
(Same trick as `ml_features.py`, which is shared by the offline trainer and the
on-server scorer for exactly this reason.)

Pure standard library — it ships to customer boxes.

PRIVACY IS A SCHEMA PROPERTY HERE
---------------------------------
Every field below is a counter, a version string, or an enum. There is
deliberately no field that can carry an attacker IP, a username, a hostname, a
country, a file path or a YARA finding. Raw records stay in the instance's own
`rdpshield.db` and never cross the network.

That is not just a policy statement — `validate()` REJECTS unknown keys, so an
instance cannot start sending extra data (by accident or because it was
tampered with) and have Central quietly store it. Adding a field is a
deliberate, reviewable edit to this file on both sides.
"""

import re

SCHEMA_VERSION = 1

RISK_LEVELS = ("unknown", "low", "medium", "high", "critical")

# Alert-type names the instance may report as its most significant recent
# alert. Mirrors settings.ALL_SMS_TYPES plus the two detectors added later.
ALERT_TYPES = (
    "", "brute_force", "password_spray", "slow_attack", "persistent_attack",
    "geo_block", "whitelist_block", "yara_critical", "reputation_alert",
    "campaign_alert", "manual_block",
)

_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}Z?$")
_VERSION = re.compile(r"^[A-Za-z0-9._+-]{0,32}$")

# name -> (kind, required, extra)
#   kind "int"   extra = (min, max)
#   kind "enum"  extra = allowed tuple
#   kind "str"   extra = compiled regex
#   kind "bool"  extra = None
#   kind "int?"  as "int" but None is allowed (metric unavailable)
FIELDS = {
    "schema_version":       ("int",  True,  (1, 1)),
    "reported_at":          ("str",  True,  _ISO_UTC),
    "agent_version":        ("str",  True,  _VERSION),
    "uptime_seconds":       ("int",  True,  (0, 10 ** 9)),

    "failed_logins_24h":    ("int",  True,  (0, 10 ** 9)),
    "failed_logins_total":  ("int",  True,  (0, 10 ** 12)),
    "alerts_24h":           ("int",  True,  (0, 10 ** 9)),
    "alerts_total":         ("int",  True,  (0, 10 ** 12)),
    "blocked_ips_active":   ("int",  True,  (0, 10 ** 7)),
    "unique_attackers":     ("int",  True,  (0, 10 ** 9)),
    "yara_findings_active": ("int",  True,  (0, 10 ** 7)),
    "campaigns_active":     ("int",  True,  (0, 10 ** 6)),

    # None when no ML model is deployed on that instance.
    "max_threat_score":     ("int?", True,  (0, 100)),

    "risk_level":           ("enum", True,  RISK_LEVELS),
    "top_alert_type":       ("enum", True,  ALERT_TYPES),

    # False if the instance knows its own detection agent is not running.
    "detectors_ok":         ("bool", True,  None),
}

MAX_PAYLOAD_BYTES = 8192


class SchemaError(ValueError):
    """The payload did not match the contract."""


def validate(payload):
    """Return a clean, canonical copy of `payload`, or raise SchemaError.

    Strict in both directions: unknown keys are rejected (so nothing
    unreviewed is ever persisted) and required keys must be present. The
    returned dict contains exactly the keys in FIELDS, nothing else."""
    if not isinstance(payload, dict):
        raise SchemaError("payload must be a JSON object")

    unknown = sorted(set(payload) - set(FIELDS))
    if unknown:
        raise SchemaError(f"unexpected field(s): {', '.join(unknown[:5])}")

    clean = {}
    for name, (kind, required, extra) in FIELDS.items():
        if name not in payload:
            if required:
                raise SchemaError(f"missing field: {name}")
            continue
        value = payload[name]

        if kind in ("int", "int?"):
            if value is None:
                if kind == "int?":
                    clean[name] = None
                    continue
                raise SchemaError(f"{name} must not be null")
            # bool is a subclass of int in Python; do not let True become 1.
            if isinstance(value, bool) or not isinstance(value, int):
                raise SchemaError(f"{name} must be an integer")
            lo, hi = extra
            if not (lo <= value <= hi):
                raise SchemaError(f"{name} out of range ({lo}..{hi})")
            clean[name] = value

        elif kind == "bool":
            if not isinstance(value, bool):
                raise SchemaError(f"{name} must be a boolean")
            clean[name] = value

        elif kind == "enum":
            if not isinstance(value, str) or value not in extra:
                # Built outside the f-string: backslashes are not allowed inside
                # f-string expressions before Python 3.12, and the servers run 3.11.
                allowed = ", ".join(repr(x) for x in extra)
                raise SchemaError(f"{name} must be one of: {allowed}")
            clean[name] = value

        elif kind == "str":
            if not isinstance(value, str) or not extra.match(value):
                raise SchemaError(f"{name} is missing or malformed")
            clean[name] = value

    return clean


def risk_from_counts(alerts_24h, blocked_active, max_threat_score, yara_active):
    """The instance's own view of how bad things currently look.

    Central deliberately does NOT recompute this — it aggregates what each agent
    reports, so all the detection logic stays in one place (the instance).
    Kept here rather than in the reporter so Central can document, in code, the
    exact meaning of the value it displays."""
    if yara_active > 0 or (max_threat_score or 0) >= 85 or alerts_24h >= 25:
        return "critical"
    if (max_threat_score or 0) >= 60 or alerts_24h >= 10 or blocked_active >= 10:
        return "high"
    if alerts_24h >= 3 or blocked_active >= 3:
        return "medium"
    if alerts_24h > 0 or blocked_active > 0:
        return "low"
    # Reporting in, nothing to report: a quiet box is "low", not "unknown".
    # "unknown" is reserved for agents Central has never heard from.
    return "low"
