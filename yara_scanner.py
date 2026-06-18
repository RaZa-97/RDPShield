"""
RDPShield v3.0  --  yara_scanner.py
Core YARA engine.  Compiles the rule set, scans process memory and a small set
of disk paths, and returns structured findings.

Design notes:
  * Disk scanning is capped at files under config.YARA_MAX_FILE_SIZE (10 MB) and
    only walks config.YARA_SCAN_PATHS -- never the full filesystem.
  * Memory scanning enumerates processes with psutil and matches each PID.
    Protected/system processes that cannot be opened are skipped silently.
  * Findings record rule name, severity, matched string identifiers and the
    location -- NOT the raw matched bytes (which could be sensitive/binary).
  * No background loop or timer lives here; this module is pure on-demand work.
    The scheduler decides WHEN to call run_scan().
"""

import os
import time

try:
    import yara
except ImportError as e:  # pragma: no cover
    raise ImportError("yara-python is required:  pip install yara-python") from e

try:
    import psutil
except ImportError as e:  # pragma: no cover
    raise ImportError("psutil is required:  pip install psutil") from e

import config

# --- configuration with safe fallbacks -------------------------------------

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")
MAX_FILE_SIZE = getattr(config, "YARA_MAX_FILE_SIZE", 10 * 1024 * 1024)   # 10 MB
SCAN_PATHS = getattr(config, "YARA_SCAN_PATHS",
                     [r"C:\Windows\Temp", r"C:\Users\Public", r"C:\Temp"])
PER_MATCH_TIMEOUT = getattr(config, "YARA_MATCH_TIMEOUT", 20)             # seconds
OVERALL_BUDGET = getattr(config, "YARA_SCAN_TIMEOUT", 120)                # soft cap

# Processes to skip during memory scanning.  A process that has the YARA rules
# loaded holds the rule literal strings ("mimikatz", "meterpreter", ...) in its
# own memory and will self-match -- a false positive.  RDPShield's own agent and
# dashboard processes load the rules, so they are excluded by their command line.
SELF_EXCLUDE_CMDLINE = getattr(config, "YARA_MEMORY_EXCLUDE_CMDLINE",
                               ["rdpshield.py", "dashboard.py", "yara_scanner.py"])
_OWN_PID = os.getpid()
MEMORY_EXCLUDE_NAMES = getattr(config, "YARA_MEMORY_EXCLUDE_NAMES", [])
# Severity ranking used to compute the "worst" finding of a scan.
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}


# --- rule compilation -------------------------------------------------------

def compile_rules(rules_dir=RULES_DIR):
    """Compile every .yar/.yara file in rules_dir into one ruleset.

    Each file becomes its own namespace so identically named rules across
    files won't collide.  Raises yara.SyntaxError on a bad rule (surfaced to
    the caller so the rule-compile test can report it).
    """
    if not os.path.isdir(rules_dir):
        raise FileNotFoundError(f"YARA rules directory not found: {rules_dir}")

    filepaths = {}
    for fn in sorted(os.listdir(rules_dir)):
        if fn.lower().endswith((".yar", ".yara")):
            namespace = os.path.splitext(fn)[0]
            filepaths[namespace] = os.path.join(rules_dir, fn)

    if not filepaths:
        raise FileNotFoundError(f"No .yar files in {rules_dir}")

    return yara.compile(filepaths=filepaths)


# --- helpers ----------------------------------------------------------------

def _matched_string_ids(match):
    """Return sorted unique string identifiers for a match.

    Handles both yara-python 4.x (StringMatch objects with .identifier) and
    the older tuple format (offset, identifier, data).  Never returns the
    matched bytes themselves.
    """
    ids = set()
    try:
        for s in match.strings:
            ident = getattr(s, "identifier", None)
            if ident is None and isinstance(s, (tuple, list)) and len(s) >= 2:
                ident = s[1]
            if ident:
                ids.add(ident if isinstance(ident, str) else str(ident))
    except Exception:
        pass
    return sorted(ids)


def _finding_from_match(match, match_type, location):
    sev = match.meta.get("severity")
    return {
        "rule_name": match.rule,
        "namespace": match.namespace,
        "severity": sev if sev in _SEVERITY_RANK else "LOW",
        "category": match.meta.get("category", ""),
        "description": match.meta.get("description", ""),
        "match_type": match_type,          # "disk" or "memory"
        "location": location,              # file path or "PID 1234 (name.exe)"
        "matched_strings": ",".join(_matched_string_ids(match)),
        "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# --- disk scan --------------------------------------------------------------

def scan_disk(rules, paths=None, deadline=None):
    """Walk each path and match files under the size cap. Returns list of findings."""
    paths = paths if paths is not None else SCAN_PATHS
    findings = []

    for base in paths:
        if not base or not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            if deadline and time.monotonic() > deadline:
                return findings
            for name in files:
                fp = os.path.join(root, name)
                try:
                    if not os.path.isfile(fp):
                        continue
                    if os.path.getsize(fp) > MAX_FILE_SIZE:
                        continue
                    matches = rules.match(fp, timeout=PER_MATCH_TIMEOUT)
                except (PermissionError, FileNotFoundError, OSError):
                    continue
                except yara.Error:
                    continue
                for m in matches:
                    findings.append(_finding_from_match(m, "disk", fp))
    return findings


# --- memory scan ------------------------------------------------------------

def _is_excluded_process(proc, pid):
    """True if this process is the scanner, a sibling RDPShield process, or an
    excluded-by-name process (e.g. a browser)."""
    if pid == _OWN_PID:
        return True
    # Skip excluded process names (browsers etc.)
    try:
        pname = (proc.info.get("name") or "").lower()
    except Exception:
        pname = ""
    if pname in (n.lower() for n in MEMORY_EXCLUDE_NAMES):
        return True
    try:
        cmdline = " ".join(proc.cmdline()).lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return False
    return any(token.lower() in cmdline for token in SELF_EXCLUDE_CMDLINE)

def scan_memory(rules, deadline=None):
    """Match the rule set against each running process's memory. Returns findings."""
    findings = []
    for proc in psutil.process_iter(["pid", "name"]):
        if deadline and time.monotonic() > deadline:
            return findings
        pid = proc.info.get("pid")
        pname = proc.info.get("name") or "?"
        if not pid:
            continue
        if _is_excluded_process(proc, pid):
            continue
        try:
            matches = rules.match(pid=pid, timeout=PER_MATCH_TIMEOUT)
        except (yara.Error, psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess, PermissionError, OSError):
            continue
        for m in matches:
            findings.append(_finding_from_match(m, "memory", f"PID {pid} ({pname})"))
    return findings


# --- public entry point -----------------------------------------------------

def run_scan(scan_memory_flag=True, scan_disk_flag=True, paths=None):
    """Run a full scan and return a result dict.

    Returns:
        {
          "findings":        [ {finding}, ... ],
          "total":           int,
          "critical_count":  int,
          "max_severity":    "CRITICAL" | "HIGH" | ... | None,
          "duration":        float seconds,
          "scanned_memory":  bool,
          "scanned_disk":    bool,
          "error":           str | None,
        }
    """
    start = time.monotonic()
    deadline = start + OVERALL_BUDGET
    result = {
        "findings": [], "total": 0, "critical_count": 0, "max_severity": None,
        "duration": 0.0, "scanned_memory": scan_memory_flag,
        "scanned_disk": scan_disk_flag, "error": None,
    }

    try:
        rules = compile_rules()
    except Exception as e:
        result["error"] = f"rule compile failed: {e}"
        result["duration"] = round(time.monotonic() - start, 2)
        return result

    findings = []
    try:
        if scan_disk_flag:
            findings += scan_disk(rules, paths=paths, deadline=deadline)
        if scan_memory_flag:
            findings += scan_memory(rules, deadline=deadline)
    except Exception as e:               # defensive: never let a scan crash the agent
        result["error"] = f"scan error: {e}"

    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    worst = max((f["severity"] for f in findings),
                key=lambda s: _SEVERITY_RANK.get(s, 0), default=None)

    result.update({
        "findings": findings,
        "total": len(findings),
        "critical_count": crit,
        "max_severity": worst,
        "duration": round(time.monotonic() - start, 2),
    })
    return result


if __name__ == "__main__":
    # Quick manual smoke test:  python yara_scanner.py
    print("[*] Compiling rules...")
    r = compile_rules()
    print("[+] Rules OK. Running scan over:", SCAN_PATHS)
    out = run_scan()
    print(f"[+] Done in {out['duration']}s -- {out['total']} findings, "
          f"{out['critical_count']} critical, worst={out['max_severity']}")
    for f in out["findings"]:
        print(f"    [{f['severity']}] {f['rule_name']}  @ {f['location']}")
    if out["error"]:
        print("[!] error:", out["error"])
