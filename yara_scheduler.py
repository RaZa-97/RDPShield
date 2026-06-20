"""
RDPShield v3.0  --  yara_scheduler.py   (v3.2)
Thin trigger layer for YARA scans. No loop, no timer.

Scan triggers:
  1. trigger_scan_async("post_block:<ip>")        -- automatic, after a block
  2. trigger_scan_async("manual",        scan_memory=False)  -- dashboard "Disk Scan"
  3. trigger_scan_async("manual_memory", scan_memory=True)   -- dashboard "Memory Scan"

Each scan runs in a daemon thread so it never blocks the agent's event polling.

SMS policy (single source of truth):
  An SMS fires ONLY for a DISK scan -- never for a memory scan -- and only when
      triggered_by.startswith("post_block")  AND  critical_count >= 1  AND  the
      scan did NOT include memory.
  Rationale: disk findings (staged tooling / payloads) are high-confidence and
  worth a text; full-process memory scanning is noisier and reviewed on the
  dashboard, so it never sends SMS. Memory scans are operator-initiated anyway.
"""

import threading
import time

import yara_scanner
import database
import config
import yara_fp_filter

_state_lock = threading.Lock()
_status = {
    "state": "Idle",              # "Idle" | "Scanning"
    "triggered_by": None,
    "last_scan_at": None,
    "last_duration": None,
    "last_total": 0,
    "last_critical": 0,
    "last_max_severity": None,
    "last_scan_id": None,
    "last_scanned_memory": False,
    "last_error": None,
}


def get_status():
    with _state_lock:
        return dict(_status)


def is_scanning():
    with _state_lock:
        return _status["state"] == "Scanning"


def _set(**kwargs):
    with _state_lock:
        _status.update(kwargs)


def _maybe_send_sms(triggered_by, result):
    """Fire the post-breach SMS iff: post_block AND critical AND DISK-only scan."""
    if not triggered_by.startswith("post_block"):
        return False
    if result.get("scanned_memory"):          # memory scans never SMS
        return False
    if result.get("critical_count", 0) < 1:
        return False

    ip = "unknown"
    if ":" in triggered_by:
        ip = triggered_by.split(":", 1)[1].strip() or "unknown"

    crit_rules = sorted({f["rule_name"] for f in result.get("findings", [])
                         if f["severity"] == "CRITICAL"})
    msg = (f"RDPShield CRITICAL: post-breach YARA hit after block of {ip}. "
           f"{result['critical_count']} critical finding(s): "
           f"{', '.join(crit_rules[:3])}. Investigate {ip} immediately.")

    try:
        from alerts import send_sms_alert
        send_sms_alert("yara_critical", ip, msg)
        return True
    except Exception as e:
        _set(last_error=f"SMS send failed: {e}")
        return False


def _yara_summary(result):
    """One-line YARA result summary for the post-block SMS."""
    if result.get("error"):
        return f"error ({str(result['error'])[:40]})"
    total = result.get("total", 0)
    if total == 0:
        return "clean (0 findings)"
    return (f"{total} finding(s), {result.get('critical_count', 0)} critical; "
            f"worst {result.get('max_severity') or '?'}")


def _send_block_sms(block_ctx, result):
    """Send the rich post-block SMS (IP, country, reason, attempts, YARA result)."""
    try:
        from alerts import send_block_sms
        return send_block_sms(
            block_ctx.get("ip", "?"),
            block_ctx.get("country", ""),
            block_ctx.get("alert_type", "manual_block"),
            block_ctx.get("attempts", 0),
            _yara_summary(result),
        )
    except Exception as e:
        _set(last_error=f"block SMS failed: {e}")
        return False


def _run(triggered_by, scan_memory, block_ctx=None):
    started_at = time.strftime("%Y-%m-%d %H:%M:%S")
    _set(state="Scanning", triggered_by=triggered_by, last_error=None)
    print(f"[YARA] scan starting (triggered_by={triggered_by})", flush=True)

    # scan_memory: None -> use config default (governs the automatic post_block
    # path); True/False -> explicit override (used by the two dashboard buttons).
    if scan_memory is None:
        mem_flag = bool(getattr(config, "YARA_MEMORY_SCAN_ON_BLOCK", False))
    else:
        mem_flag = bool(scan_memory)

    result = yara_scanner.run_scan(scan_memory_flag=mem_flag, scan_disk_flag=True)
    yara_fp_filter.annotate_result(result)
    completed_at = time.strftime("%Y-%m-%d %H:%M:%S")

    scan_id = None
    try:
        scan_id = database.log_yara_scan(triggered_by, result,
                                         started_at, completed_at  )
    except Exception as e:
        _set(last_error=f"DB log failed: {e}")
        print(f"[YARA] DB log failed: {e}", flush=True)

    # When this scan was triggered by a block, send ONE rich SMS that includes
    # the scan results. Otherwise fall back to the critical-only memory policy.
    if block_ctx:
        sms_sent = _send_block_sms(block_ctx, result)
    else:
        sms_sent = _maybe_send_sms(triggered_by, result)

    _set(
        state="Idle",
        last_scan_at=completed_at,
        last_duration=result.get("duration"),
        last_total=result.get("total", 0),
        last_critical=result.get("critical_count", 0),
        last_max_severity=result.get("max_severity"),
        last_scan_id=scan_id,
        last_scanned_memory=bool(result.get("scanned_memory")),
    )
    print(f"[YARA] scan complete: {result.get('total',0)} findings, "
          f"{result.get('critical_count',0)} critical, "
          f"worst={result.get('max_severity')}, {result.get('duration')}s, "
          f"memory={'yes' if mem_flag else 'no'}"
          f"{' [SMS SENT]' if sms_sent else ''}", flush=True)


def trigger_scan_async(triggered_by="manual", scan_memory=None, block_ctx=None):
    """Start a scan in a daemon thread.

    triggered_by : label stored with the scan ("manual", "manual_memory",
                   "post_block:<ip>").
    scan_memory  : None -> use config flag; True/False -> explicit override.
    block_ctx    : optional dict {ip, country, alert_type, attempts}. When
                   present, a rich post-block SMS (with YARA results) is sent
                   when the scan finishes.

    Returns True if a scan was started, False if one is already running.
    """
    with _state_lock:
        if _status["state"] == "Scanning":
            return False
        _status["state"] = "Scanning"
        _status["triggered_by"] = triggered_by

    t = threading.Thread(target=_run, args=(triggered_by, scan_memory, block_ctx),
                         name="yara-scan", daemon=True)
    t.start()
    return True
