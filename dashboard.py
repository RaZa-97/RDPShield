"""
RDPShield Dashboard v2.1
=========================
Flask web interface with two pages:

1. Dashboard (/) - Main monitoring page with alerts, blocked IPs, events
2. Geolocation (/geo) - Geographic access control settings

Features:
- Live stats and alert feed
- Blocked IPs management with unblock buttons
- Geo-blocking mode selection (3 modes)
- Country whitelist management (add/remove)
- IP whitelist management (add/remove)
- Geo-block event log

Access: http://SERVER_IP:5000
"""

from flask import (
    Flask, render_template, jsonify, request,
    redirect, url_for, flash
)
from database import (
    init_db,
    get_recent_alerts,
    get_blocked_ips,
    get_recent_failed_logins,
    get_dashboard_stats,
    get_failed_login_trend,
    get_alert_type_breakdown,
    get_top_attacker_countries,
    count_failed_logins,
    log_alert,
    # Geo functions
    get_geo_mode,
    set_geo_mode,
    get_allowed_countries,
    add_allowed_country,
    remove_allowed_country,
    get_allowed_ips,
    add_allowed_ip,
    remove_allowed_ip,
    get_geo_events,
    get_geo_stats,
)
from firewall import unblock_ip, block_ip
from alerts import process_alert_enrichment, send_block_sms
from config import DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_DEBUG
from countries import COUNTRY_NAMES
import yara_scheduler

app = Flask(__name__)
from yara_routes import yara_bp
from database import create_yara_tables

app.register_blueprint(yara_bp)
create_yara_tables()
app.secret_key = "rdpshield_secret_key"  # Needed for flash messages


# =========================================================================
# MAIN DASHBOARD PAGE
# =========================================================================

@app.route("/")
def index():
    """Main dashboard page."""
    stats = get_dashboard_stats()
    alerts = get_recent_alerts(limit=50)
    blocked = get_blocked_ips()
    recent = get_recent_failed_logins(limit=50)
    trend = get_failed_login_trend(days=14)
    alert_breakdown_30d = get_alert_type_breakdown(days=30)
    top_countries = get_top_attacker_countries(limit=6)

    return render_template(
        "index.html",
        stats=stats,
        alerts=alerts,
        blocked=blocked,
        recent=recent,
        trend=trend,
        alert_breakdown_30d=alert_breakdown_30d,
        top_countries=top_countries,
    )


# =========================================================================
# GEOLOCATION SETTINGS PAGE
# =========================================================================

@app.route("/geo")
def geo_settings():
    """
    Geolocation settings page.
    Shows the three mode options, country list, IP list, and event log.
    """
    mode = get_geo_mode()
    countries = get_allowed_countries()
    allowed_ips = get_allowed_ips()
    geo_events = get_geo_events(limit=50)
    geo_stats = get_geo_stats()

    return render_template(
        "geo.html",
        mode=mode,
        countries=countries,
        allowed_ips=allowed_ips,
        geo_events=geo_events,
        geo_stats=geo_stats,
        country_suggestions=COUNTRY_NAMES,
    )


@app.route("/geo/set_mode", methods=["POST"])
def geo_set_mode():
    """
    Handle the 'Apply Now' button — sets the geo-blocking mode.
    The mode comes from the radio button selection on the form.
    """
    mode = request.form.get("geo_mode", "allow_anywhere")
    set_geo_mode(mode)
    print(f"[DASHBOARD] Geo mode changed to: {mode}")
    return redirect(url_for("geo_settings"))


@app.route("/geo/add_country", methods=["POST"])
def geo_add_country():
    """
    Handle the 'Add Country' button.
    Country name comes from the text input field.
    """
    country = request.form.get("country_name", "").strip()
    if country:
        add_allowed_country(country)
        print(f"[DASHBOARD] Added allowed country: {country}")
    return redirect(url_for("geo_settings"))


@app.route("/geo/remove_country/<country_name>", methods=["POST"])
def geo_remove_country(country_name):
    """Handle the 'Remove' button next to a country."""
    remove_allowed_country(country_name)
    print(f"[DASHBOARD] Removed allowed country: {country_name}")
    return redirect(url_for("geo_settings"))


@app.route("/geo/add_ip", methods=["POST"])
def geo_add_ip():
    """
    Handle the 'Add IP' button.
    IP address and description come from the form fields.
    """
    ip = request.form.get("ip_address", "").strip()
    desc = request.form.get("description", "").strip()
    if ip:
        add_allowed_ip(ip, desc)
        print(f"[DASHBOARD] Added allowed IP: {ip}")
    return redirect(url_for("geo_settings"))


@app.route("/geo/remove_ip/<ip_address>", methods=["POST"])
def geo_remove_ip(ip_address):
    """Handle the 'Remove' button next to an allowed IP."""
    remove_allowed_ip(ip_address)
    print(f"[DASHBOARD] Removed allowed IP: {ip_address}")
    return redirect(url_for("geo_settings"))


# =========================================================================
# EXISTING API ENDPOINTS + UNBLOCK
# =========================================================================

@app.route("/api/stats")
def api_stats():
    return jsonify(get_dashboard_stats())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_recent_alerts(limit=50))


@app.route("/api/blocked")
def api_blocked():
    return jsonify(get_blocked_ips())


@app.route("/api/events")
def api_events():
    return jsonify(get_recent_failed_logins(limit=100))


@app.route("/api/geo_stats")
def api_geo_stats():
    return jsonify(get_geo_stats())


@app.route("/unblock/<ip_address>", methods=["POST"])
def unblock(ip_address):
    """Manually unblock an IP address."""
    success = unblock_ip(ip_address)
    if success:
        print(f"[DASHBOARD] Manually unblocked {ip_address}")
    return redirect(url_for("index"))


@app.route("/block", methods=["POST"])
def block():
    """
    Manually block an IP address from the dashboard.

    Runs the same response flow as an automatic block: geo-enrich the IP,
    block it at the firewall, launch a post-block YARA disk scan, log an
    alert (so it appears in Top Attacker Countries and Recent Alerts), and
    send the rich post-block SMS once the scan finishes.
    """
    ip = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "").strip() or "Manually blocked from dashboard"
    if ip:
        enrichment, geo = process_alert_enrichment(ip)
        country = enrichment.get("geo_country", "") or (geo.get("country", "") if geo else "")
        attempts = count_failed_logins(ip)
        success = block_ip(ip, reason=reason)
        if success:
            ctx = {
                "ip": ip,
                "country": country,
                "alert_type": "manual_block",
                "attempts": attempts,
            }
            started = yara_scheduler.trigger_scan_async("post_block:" + ip, block_ctx=ctx)
            if not started:
                send_block_sms(ip, country, "manual_block", attempts, "deferred - scanner busy")
            log_alert(
                alert_type="manual_block",
                source_ip=ip,
                description=reason,
                geo_country=enrichment.get("geo_country", ""),
                geo_city=enrichment.get("geo_city", ""),
                abuse_score=enrichment.get("abuse_score", 0),
                blocked=1,
                sms_sent=1,
            )
            print(f"[DASHBOARD] Manually blocked {ip} ({reason})")
        else:
            print(f"[DASHBOARD] Could not block {ip} (whitelisted, already blocked, or disabled)")
    return redirect(url_for("index"))


if __name__ == "__main__":
    print("[DASHBOARD] Initializing database...")
    init_db()
    print(f"[DASHBOARD] Starting on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print("[DASHBOARD] Press Ctrl+C to stop.\n")
    app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=DASHBOARD_DEBUG,
    )