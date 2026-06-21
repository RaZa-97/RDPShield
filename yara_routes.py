"""
RDPShield v3.0  --  yara_routes.py   (v3.2)
Flask blueprint for the YARA controller.

Routes:
    GET  /yara                  -> dashboard page (templates/yara.html)
    POST /yara/scan             -> manual DISK scan   (fast, accurate, SMS-eligible)
    POST /yara/scan_memory      -> manual MEMORY scan (deep, on-demand, never SMS)
    GET  /yara/status           -> live scheduler status + recent scan history (JSON)
    GET  /yara/findings/<id>    -> findings for one scan (JSON)
"""

import os
import shutil
import time

from flask import Blueprint, render_template, jsonify, request

import yara_scheduler
import database
import virustotal
from config import YARA_QUARANTINE_DIR

yara_bp = Blueprint("yara", __name__)


@yara_bp.route("/yara")
def yara_dashboard():
    return render_template("yara.html")


@yara_bp.route("/yara/scan", methods=["POST"])
def yara_scan():
    # Disk-only manual scan: fast and accurate.
    started = yara_scheduler.trigger_scan_async("manual", scan_memory=False)
    if started:
        return jsonify({"started": True, "message": "Disk scan started."})
    return jsonify({"started": False,
                    "message": "A scan is already in progress."}), 409


@yara_bp.route("/yara/scan_memory", methods=["POST"])
def yara_scan_memory():
    # Full memory + disk scan: deeper, slower, reviewed on the dashboard.
    # Never sends SMS (handled by the scheduler's disk-only SMS policy).
    started = yara_scheduler.trigger_scan_async("manual_memory", scan_memory=True)
    if started:
        return jsonify({"started": True,
                        "message": "Memory scan started (this takes longer)."})
    return jsonify({"started": False,
                    "message": "A scan is already in progress."}), 409


@yara_bp.route("/yara/status")
def yara_status():
    status = yara_scheduler.get_status()
    try:
        history = database.get_yara_history(limit=25)
    except Exception as e:
        history = []
        status["history_error"] = str(e)
    return jsonify({"status": status, "history": history})


@yara_bp.route("/yara/findings/<int:scan_id>")
def yara_findings(scan_id):
    try:
        findings = database.get_yara_findings(scan_id)
    except Exception as e:
        return jsonify({"scan_id": scan_id, "findings": [], "error": str(e)}), 500
    return jsonify({"scan_id": scan_id, "findings": findings})


# =========================================================================
# VirusTotal enrichment (on-demand, button-triggered to respect quota)
# =========================================================================

@yara_bp.route("/yara/vt/hash/<sha256>")
def yara_vt_hash(sha256):
    return jsonify(virustotal.vt_lookup_hash(sha256))


@yara_bp.route("/yara/vt/ip/<ip>")
def yara_vt_ip(ip):
    return jsonify(virustotal.vt_lookup_ip(ip))


# =========================================================================
# Finding handling: delete / quarantine / whitelist
# =========================================================================

@yara_bp.route("/yara/finding/action", methods=["POST"])
def yara_finding_action():
    """
    Act on a single YARA finding.
    JSON body: {"finding_id": <int>, "action": "delete"|"quarantine"|"whitelist"}
    """
    data = request.get_json(silent=True) or {}
    finding_id = data.get("finding_id")
    action = (data.get("action") or "").lower()

    if action not in ("delete", "quarantine", "whitelist"):
        return jsonify({"ok": False, "message": "Unknown action."}), 400

    finding = database.get_yara_finding(finding_id)
    if not finding:
        return jsonify({"ok": False, "message": "Finding not found."}), 404

    path = finding.get("location") or ""
    sha256 = finding.get("sha256") or ""

    # delete/quarantine only apply to disk findings (real files on disk).
    if action in ("delete", "quarantine"):
        if finding.get("match_type") != "disk" or not os.path.isfile(path):
            return jsonify({"ok": False,
                            "message": "File not found (already removed?) "
                                       "or this is a memory finding."}), 400

    try:
        if action == "delete":
            os.remove(path)
            database.remove_yara_finding(finding_id)
            msg = f"Deleted {os.path.basename(path)}"

        elif action == "quarantine":
            os.makedirs(YARA_QUARANTINE_DIR, exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(YARA_QUARANTINE_DIR,
                                f"{stamp}_{os.path.basename(path)}")
            shutil.move(path, dest)
            database.remove_yara_finding(finding_id)
            msg = f"Quarantined to {dest}"

        else:  # whitelist
            if not sha256:
                return jsonify({"ok": False,
                                "message": "No file hash to whitelist "
                                           "(memory finding)."}), 400
            database.add_yara_whitelist(sha256, path, finding.get("rule_name", ""))
            msg = "Whitelisted - future scans will skip this file hash."

        print(f"[YARA] finding #{finding_id} action={action}: {msg}", flush=True)
        return jsonify({"ok": True, "message": msg})

    except Exception as e:
        return jsonify({"ok": False, "message": f"Action failed: {e}"}), 500
