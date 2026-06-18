"""
RDPShield v3.0  --  yara_fp_filter.py
Confidence scorer / false-positive filter for YARA findings.

Sits between yara_scanner.run_scan() and the logging + SMS path in
yara_scheduler._run(). It scores every finding 0.0-1.0 and tags each one with
a 'confidence' float and a 'suppressed' bool. Low-confidence findings are
suppressed: they are still logged (for review / training data) but are removed
from the CRITICAL count that drives the SMS policy.

Keys match yara_scanner._finding_from_match():
    severity    -> "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    match_type  -> "disk" | "memory"      (lowercase)
    location    -> file path, or "PID 1234 (name.exe)" for memory findings
There is no 'process_name' key; the process name is parsed out of 'location'.
"""

import re
import config

# Base confidence by severity tier.
BASE_SCORE = {"CRITICAL": 0.85, "HIGH": 0.65, "MEDIUM": 0.40, "LOW": 0.25}

# Memory-scan per-process multipliers. Browsers were the documented FP source
# (they hold arbitrary web text in memory), so they get crushed. Shells and
# script hosts that real post-compromise tooling runs in stay at 1.0.
MEMORY_MULTIPLIERS = {
    "cmd.exe": 1.00, "powershell.exe": 1.00, "pwsh.exe": 1.00,
    "wscript.exe": 1.00, "cscript.exe": 1.00, "mshta.exe": 1.00,
    "rundll32.exe": 0.90, "regsvr32.exe": 0.90,
    "svchost.exe": 0.60, "lsass.exe": 0.55,
    "msedge.exe": 0.10, "chrome.exe": 0.10, "firefox.exe": 0.10,
    "iexplore.exe": 0.10, "opera.exe": 0.10, "brave.exe": 0.10,
    "msedgewebview2.exe": 0.10,
}

DISK_BOOST = 1.15            # disk findings are inherently more reliable
DEFAULT_MEMORY_MULT = 0.70   # unknown process in memory: treat as suspect

THRESHOLD = getattr(config, "YARA_FP_THRESHOLD", 0.40)

# location for a memory finding looks like: "PID 1234 (name.exe)"
_PROC_RE = re.compile(r"\(([^)]+)\)\s*$")


def _process_name_from_location(location):
    """Pull 'name.exe' out of a memory finding's location string."""
    if not location:
        return ""
    m = _PROC_RE.search(location)
    return m.group(1).lower() if m else ""


def score_finding(finding):
    """Return a 0.0-1.0 confidence score for a single finding dict."""
    score = BASE_SCORE.get(finding.get("severity", "MEDIUM"), 0.40)
    if finding.get("match_type") == "memory":
        proc = _process_name_from_location(finding.get("location", ""))
        score *= MEMORY_MULTIPLIERS.get(proc, DEFAULT_MEMORY_MULT)
    else:  # disk (or anything non-memory)
        score *= DISK_BOOST
    return min(round(score, 2), 1.0)


def annotate_result(result):
    """Score every finding in a scan result dict (from yara_scanner.run_scan).

    Mutates each finding dict in place, adding:
        'confidence' : float 0.0-1.0
        'suppressed' : bool  (confidence < THRESHOLD)

    Then recomputes 'critical_count' to count only KEPT (non-suppressed)
    criticals -- this is what keeps the SMS policy honest, since a suppressed
    critical must not trigger a text. 'total' is left as the true finding count
    (everything is still logged and visible on the dashboard).

    Returns the same result dict, plus a 'suppressed_count' convenience key.
    """
    findings = result.get("findings", [])
    suppressed_count = 0
    kept_critical = 0
    for f in findings:
        conf = score_finding(f)
        f["confidence"] = conf
        f["suppressed"] = conf < THRESHOLD
        if f["suppressed"]:
            suppressed_count += 1
        elif f.get("severity") == "CRITICAL":
            kept_critical += 1

    result["critical_count"] = kept_critical
    result["suppressed_count"] = suppressed_count
    return result


if __name__ == "__main__":
    # Quick smoke test:  python yara_fp_filter.py
    sample = {
        "findings": [
            {"severity": "CRITICAL", "match_type": "disk",   "location": r"C:\Temp\shell.php",          "rule_name": "PostComp_Web_Shell"},
            {"severity": "MEDIUM",   "match_type": "disk",   "location": r"C:\Temp\test_wordlist.txt",   "rule_name": "Credential_Wordlist"},
            {"severity": "CRITICAL", "match_type": "memory", "location": "PID 4821 (msedge.exe)",        "rule_name": "PostComp_Encoded_PowerShell"},
            {"severity": "CRITICAL", "match_type": "memory", "location": "PID 1337 (cmd.exe)",           "rule_name": "PostComp_Web_Shell"},
            {"severity": "MEDIUM",   "match_type": "memory", "location": "PID 712 (svchost.exe)",        "rule_name": "Credential_Wordlist"},
        ],
        "total": 5, "critical_count": 3, "max_severity": "CRITICAL",
        "scanned_memory": True, "scanned_disk": True,
    }
    annotate_result(sample)
    print(f"THRESHOLD = {THRESHOLD}")
    print(f"kept critical_count = {sample['critical_count']}  (was 3)")
    print(f"suppressed_count    = {sample['suppressed_count']}")
    for f in sample["findings"]:
        flag = "SUPPRESSED" if f["suppressed"] else "kept"
        print(f"  {f['confidence']:.2f}  {flag:11s} [{f['severity']}/{f['match_type']}]  {f['location']}")
