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
    Act on a YARA finding. Updates a status instead of deleting the row, and
    propagates to sibling findings of the same file so multiple rule matches on
    one file all move together (and acting on an already-handled file is safe).

    JSON body: {"finding_id": <int>,
                "action": delete|quarantine|whitelist|ignore|restore}
    """
    data = request.get_json(silent=True) or {}
    finding_id = data.get("finding_id")
    action = (data.get("action") or "").lower()

    if action not in ("delete", "quarantine", "whitelist", "ignore", "restore"):
        return jsonify({"ok": False, "message": "Unknown action."}), 400

    finding = database.get_yara_finding(finding_id)
    if not finding:
        return jsonify({"ok": False, "message": "Finding not found."}), 404

    path = finding.get("location") or ""
    sha256 = finding.get("sha256") or ""
    is_disk = finding.get("match_type") == "disk"

    try:
        if action == "ignore":
            database.set_finding_status(finding_id, "ignored")
            return jsonify({"ok": True, "status": "ignored", "message": "Finding ignored."})

        if action == "restore":
            database.set_finding_status(finding_id, "active")
            if sha256:
                database.remove_yara_whitelist(sha256)  # re-enable detection
            return jsonify({"ok": True, "status": "active",
                            "message": "Restored to active."})

        if action == "whitelist":
            if not sha256:
                return jsonify({"ok": False,
                                "message": "No file hash to whitelist (memory finding)."}), 400
            database.add_yara_whitelist(sha256, path, finding.get("rule_name", ""))
            database.set_status_by_hash(sha256, "whitelisted")
            msg = "Whitelisted - future scans will skip this hash."

        elif action == "delete":
            if not is_disk:
                return jsonify({"ok": False, "message": "Not a disk finding."}), 400
            if os.path.isfile(path):
                os.remove(path)
                msg = f"Deleted {os.path.basename(path)}"
            else:
                msg = "File already removed - marked as deleted."
            database.set_status_by_location(path, "deleted")

        else:  # quarantine
            if not is_disk:
                return jsonify({"ok": False, "message": "Not a disk finding."}), 400
            if os.path.isfile(path):
                os.makedirs(YARA_QUARANTINE_DIR, exist_ok=True)
                stamp = time.strftime("%Y%m%d_%H%M%S")
                dest = os.path.join(YARA_QUARANTINE_DIR,
                                    f"{stamp}_{os.path.basename(path)}")
                shutil.move(path, dest)
                msg = f"Quarantined to {dest}"
            else:
                msg = "File already removed - marked as quarantined."
            database.set_status_by_location(path, "quarantined")

        print(f"[YARA] finding #{finding_id} action={action}: {msg}", flush=True)
        return jsonify({"ok": True, "status": action.replace("quarantine", "quarantined")
                                              .replace("delete", "deleted")
                                              .replace("whitelist", "whitelisted"),
                        "message": msg})

    except Exception as e:
        return jsonify({"ok": False, "message": f"Action failed: {e}"}), 500


@yara_bp.route("/yara/managed/<status>")
def yara_managed(status):
    """Findings currently in a managed status (for the category views)."""
    if status not in ("quarantined", "whitelisted", "ignored", "deleted", "active"):
        return jsonify({"findings": [], "error": "bad status"}), 400
    return jsonify({"status": status,
                    "findings": database.get_findings_by_status(status)})


@yara_bp.route("/yara/managed_counts")
def yara_managed_counts():
    return jsonify(database.get_finding_status_counts())
