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

from flask import Blueprint, render_template, jsonify

import yara_scheduler
import database

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
