/* RDPShield — shared table renderers
 * ====================================
 * Row-building logic for every growing table/log, used in TWO places:
 *   1. The dashboard's live in-place AJAX refresh (index.html).
 *   2. The standalone full-list pages (list.html) opened in a new tab.
 * Keeping the markup in one file means the compact 5-row dashboard view and
 * the paginated "View all" view always look identical.
 *
 * Each build*(rows) returns a complete <table>…</table> string for the rows
 * it is given; the caller decides how many rows to pass (5 on the dashboard,
 * a page slice on the list page).
 */

function esc(t) {
    return (t == null ? '' : String(t)).replace(/[&<>"]/g,
        c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function abuseCell(s) {
    if (s === null || s === undefined) return '&mdash;';
    if (s >= 75) return '<span class="score-high">' + s + '%</span>';
    if (s >= 25) return '<span class="score-medium">' + s + '%</span>';
    return '<span class="score-low">' + s + '%</span>';
}

function setNum(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

// Where unblock/block POSTs should return to. On the dashboard this is "/",
// on a list page it's that list's URL — so an action returns you where you were.
const NEXT_URL = (typeof window !== 'undefined')
    ? window.location.pathname + window.location.search : '/';

// Admin-only action buttons (block/unblock) are hidden for guests, who get
// view + CSV export only. window.IS_ADMIN is set by the shared top bar.
function canAdmin() { return typeof window !== 'undefined' && window.IS_ADMIN === true; }

// VirusTotal IP reputation: cached client-side so a looked-up result survives
// the dashboard's 10s table refresh (and doesn't burn extra VT quota).
const vtCache = {};
function vtCellHtml(ip) {
    const d = vtCache[ip];
    if (!d) return '<button class="btn-sm" onclick="vtIp(\'' + esc(ip) + '\', this)">VT</button>';
    if (d.found) {
        const cls = d.malicious > 0 ? 'score-high' : 'score-low';
        return '<a href="' + d.permalink + '" target="_blank" class="' + cls + '">'
            + d.malicious + '/' + d.total + '</a>';
    }
    return '<span class="muted" title="' + esc(d.reason || '') + '">n/a</span>';
}
async function vtIp(ip, btn) {
    btn.disabled = true; btn.textContent = '…';
    try {
        const r = await fetch('/yara/vt/ip/' + ip); const d = await r.json();
        vtCache[ip] = d;
        const cell = btn.parentElement;
        if (cell) cell.innerHTML = vtCellHtml(ip);
    } catch (e) { btn.disabled = false; btn.textContent = 'VT'; }
}

function buildAlerts(rows) {
    if (!rows.length) return '<p class="empty">No alerts yet. Waiting for attack detection...</p>';
    let h = '<table><thead><tr><th>Time</th><th>Type</th><th>Attacker IP</th><th>Attempts</th><th>Location</th><th>ISP</th><th>Abuse Score</th><th>VirusTotal</th><th>Description</th><th>Blocked</th><th>SMS</th></tr></thead><tbody>';
    for (const a of rows) {
        const loc = esc(a.geo_city || '') + (a.geo_country ? ', ' + esc(a.geo_country) : '');
        h += '<tr class="alert-row-' + esc(a.alert_type) + '">'
            + '<td>' + esc((a.timestamp || '').slice(0, 19)) + '</td>'
            + '<td><span class="badge badge-' + esc(a.alert_type) + '">' + esc(a.type_label || a.alert_type) + '</span></td>'
            + '<td class="ip">' + esc(a.source_ip) + '</td>'
            + '<td><strong>' + (a.attempts != null ? a.attempts : 0) + '</strong></td>'
            + '<td>' + loc + '</td>'
            + '<td>' + esc(a.isp || '—') + '</td>'
            + '<td>' + abuseCell(a.abuse_score) + '</td>'
            + '<td class="vt-cell">' + vtCellHtml(a.source_ip) + '</td>'
            + '<td class="description">' + esc(a.description || '') + '</td>'
            + '<td>' + (a.blocked ? '&#9989;' : '&#10060;') + '</td>'
            + '<td>' + (a.sms_sent ? '&#9989;' : '&#10060;') + '</td></tr>';
    }
    return h + '</tbody></table>';
}

function buildBlocked(rows) {
    if (!rows.length) return '<p class="empty">No IPs currently blocked.</p>';
    const admin = canAdmin();
    let h = '<table><thead><tr><th>IP Address</th><th>Attempts</th><th>Location</th><th>ISP</th><th>Abuse Score</th><th>VirusTotal</th><th>Attack Method</th><th>Reason</th><th>Blocked At</th>'
        + (admin ? '<th>Action</th>' : '') + '</tr></thead><tbody>';
    for (const ip of rows) {
        const action = admin
            ? '<td><form method="POST" action="/unblock/' + encodeURIComponent(ip.ip_address) + '" class="confirm-form"'
              + ' data-confirm-message="Unblock ' + esc(ip.ip_address) + '? It will be able to attempt logins again."'
              + ' data-confirm-title="Unblock IP address" data-confirm-ok="Unblock" style="display:inline;">'
              + '<input type="hidden" name="next" value="' + esc(NEXT_URL) + '">'
              + '<button type="submit" class="btn-unblock">Unblock</button></form></td>'
            : '';
        h += '<tr><td class="ip">' + esc(ip.ip_address) + '</td>'
            + '<td><strong>' + (ip.attempts != null ? ip.attempts : 0) + '</strong></td>'
            + '<td>' + esc(ip.country || '—') + '</td>'
            + '<td>' + esc(ip.isp || '—') + '</td>'
            + '<td>' + abuseCell(ip.abuse_score) + '</td>'
            + '<td class="vt-cell">' + vtCellHtml(ip.ip_address) + '</td>'
            + '<td><span class="badge badge-' + esc(ip.alert_type || 'manual_block') + '">' + esc(ip.attack_method || '—') + '</span></td>'
            + '<td>' + esc(ip.reason || '') + '</td>'
            + '<td>' + esc(ip.blocked_at || '') + '</td>'
            + action + '</tr>';
    }
    return h + '</tbody></table>';
}

function buildRecent(rows) {
    if (!rows.length) return '<p class="empty">No failed login events recorded yet.</p>';
    const admin = canAdmin();
    let h = '<table><thead><tr><th>Time</th><th>Source IP</th><th>Country</th><th>ISP</th><th>Abuse Score</th><th>Username</th><th>Domain</th><th>Sub Status</th>'
        + (admin ? '<th>Action</th>' : '') + '</tr></thead><tbody>';
    for (const e of rows) {
        const action = admin
            ? '<td><form method="POST" action="/block" class="confirm-form"'
              + ' data-confirm-message="Block ' + esc(e.source_ip) + ' at the Windows Firewall? All inbound traffic from it will be dropped."'
              + ' data-confirm-title="Block IP address" data-confirm-ok="Block" data-confirm-danger="true" style="display:inline;">'
              + '<input type="hidden" name="ip_address" value="' + esc(e.source_ip) + '">'
              + '<input type="hidden" name="reason" value="Manually blocked from failed-login list">'
              + '<input type="hidden" name="next" value="' + esc(NEXT_URL) + '">'
              + '<button type="submit" class="btn-remove">Block</button></form></td>'
            : '';
        h += '<tr><td>' + esc((e.timestamp || '').slice(0, 19)) + '</td>'
            + '<td class="ip">' + esc(e.source_ip) + '</td>'
            + '<td>' + esc(e.geo_country || '—') + '</td>'
            + '<td>' + esc(e.geo_isp || '—') + '</td>'
            + '<td>' + abuseCell(e.abuse_score) + '</td>'
            + '<td>' + esc(e.username || '') + '</td>'
            + '<td>' + esc(e.domain || '') + '</td>'
            + '<td><code>' + esc(e.sub_status || '') + '</code></td>'
            + action + '</tr>';
    }
    return h + '</tbody></table>';
}

// Geolocation / Whitelist event log. Each row carries `is_blocked` (added by
// the API) so we know whether to offer an Unblock button in the Manage column.
function buildGeoEvents(rows) {
    if (!rows.length) return '<p class="empty">No events recorded yet.</p>';
    let h = '<table><thead><tr><th>Time</th><th>IP Address</th><th>User</th><th>Country</th><th>City</th><th>ISP</th><th>Abuse</th><th>Event</th><th>Action</th><th>Reason</th><th>Manage</th></tr></thead><tbody>';
    for (const e of rows) {
        const blocked = e.action === 'blocked';
        let manage = '&mdash;';
        if (e.is_blocked && canAdmin()) {
            manage = '<form method="POST" action="/unblock/' + encodeURIComponent(e.source_ip) + '" class="confirm-form"'
                + ' data-confirm-message="Unblock ' + esc(e.source_ip) + '? It will be able to connect again."'
                + ' data-confirm-title="Unblock IP address" data-confirm-ok="Unblock" style="display:inline;">'
                + '<input type="hidden" name="next" value="' + esc(NEXT_URL) + '">'
                + '<button type="submit" class="btn-unblock">Unblock</button></form>';
        }
        h += '<tr class="' + (blocked ? 'geo-row-blocked' : 'geo-row-allowed') + '">'
            + '<td>' + esc((e.timestamp || '').slice(0, 19)) + '</td>'
            + '<td class="ip">' + esc(e.source_ip) + '</td>'
            + '<td>' + esc(e.username || '') + '</td>'
            + '<td>' + esc(e.country || '') + '</td>'
            + '<td>' + esc(e.city || '') + '</td>'
            + '<td>' + esc(e.isp || '') + '</td>'
            + '<td>' + abuseCell(e.abuse_score) + '</td>'
            + '<td>' + esc(e.event_label || e.event_type || '') + '</td>'
            + '<td>' + (blocked ? '<span class="badge badge-geo-blocked">BLOCKED</span>'
                              : '<span class="badge badge-geo-allowed">ALLOWED</span>') + '</td>'
            + '<td class="description">' + esc(e.reason || '') + '</td>'
            + '<td>' + manage + '</td></tr>';
    }
    return h + '</tbody></table>';
}

// YARA scan history. Each row is click-to-expand: it reveals that scan's
// findings (the actual scan result) inline, so the full paginated history page
// is just as drillable as the YARA dashboard panel. A clean scan says so.
function buildYaraHistory(rows) {
    if (!rows.length) return '<p class="empty">No scans yet.</p>';
    const sev = s => { s = s || 'none'; return '<span class="badge b-' + s + '">' + (s === 'none' ? '—' : s) + '</span>'; };
    let h = '<table><thead><tr><th>ID</th><th>Time</th><th>Trigger</th><th>Findings</th><th>Critical</th><th>Worst</th><th>Duration</th></tr></thead><tbody>';
    for (const r of rows) {
        h += '<tr class="scan-row" style="cursor:pointer;" title="Click to view this scan\'s result"'
            + ' onclick="toggleScanFindings(' + r.id + ')">'
            + '<td class="mono">#' + r.id + '</td>'
            + '<td>' + esc(r.completed_at || r.started_at || '') + '</td>'
            + '<td class="mono">' + esc(r.triggered_by || '') + '</td>'
            + '<td>' + (r.total_findings != null ? r.total_findings : 0) + '</td>'
            + '<td>' + (r.critical_findings != null ? r.critical_findings : 0) + '</td>'
            + '<td>' + sev(r.max_severity) + '</td>'
            + '<td class="muted">' + (r.duration != null ? r.duration + 's' : '—') + '</td></tr>'
            + '<tr id="scan-findings-' + r.id + '" class="scan-findings" style="display:none;">'
            + '<td colspan="7"><span class="muted">Loading…</span></td></tr>';
    }
    return h + '</tbody></table>';
}

// Expand/collapse a scan row to show its findings (fetched on demand).
async function toggleScanFindings(id) {
    const detail = document.getElementById('scan-findings-' + id);
    if (!detail) return;
    if (detail.style.display !== 'none') { detail.style.display = 'none'; return; }
    detail.style.display = '';
    const cell = detail.firstElementChild;
    cell.innerHTML = '<span class="muted">Loading…</span>';
    try {
        const r = await fetch('/yara/findings/' + id);
        const d = await r.json();
        const f = d.findings || [];
        if (!f.length) { cell.innerHTML = '<span class="muted">No findings — clean scan.</span>'; return; }
        let t = '<table class="sub-table"><thead><tr><th>Severity</th><th>Rule</th><th>Type</th>'
              + '<th>Location</th><th>SHA-256</th><th>Status</th></tr></thead><tbody>';
        for (const x of f) {
            const sevb = '<span class="badge b-' + esc(x.severity || 'none') + '">' + esc(x.severity || '—') + '</span>';
            const sha = x.sha256 ? esc(String(x.sha256).slice(0, 16)) + '…' : '—';
            t += '<tr><td>' + sevb + '</td>'
               + '<td class="mono">' + esc(x.rule_name || '') + '</td>'
               + '<td>' + esc(x.match_type || '') + '</td>'
               + '<td class="mono" title="' + esc(x.location || '') + '">' + esc(x.location || '') + '</td>'
               + '<td class="mono">' + sha + '</td>'
               + '<td>' + esc(x.status || 'active') + '</td></tr>';
        }
        cell.innerHTML = t + '</tbody></table>';
    } catch (e) { cell.innerHTML = '<span class="muted">Failed to load findings.</span>'; }
}

// Admin audit log (read-only).
function buildAudit(rows) {
    if (!rows.length) return '<p class="empty">No audit entries.</p>';
    let h = '<table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead><tbody>';
    for (const a of rows) {
        h += '<tr><td>' + esc((a.timestamp || '').slice(0, 19)) + '</td>'
            + '<td><strong>' + esc(a.username) + '</strong></td>'
            + '<td><span class="badge badge-manual_block">' + esc(a.action) + '</span></td>'
            + '<td class="description">' + esc(a.detail || '') + '</td>'
            + '<td class="mono">' + esc(a.ip || '') + '</td></tr>';
    }
    return h + '</tbody></table>';
}

const TABLE_RENDERERS = {
    alerts: buildAlerts,
    blocked: buildBlocked,
    recent: buildRecent,
    geo: buildGeoEvents,
    yara_history: buildYaraHistory,
    audit: buildAudit,
};

// --- Standalone full-list page: search + client-side pagination ------------
function initListPage(key, apiUrl) {
    const render = TABLE_RENDERERS[key];
    const container = document.getElementById('listTable');
    const pager = document.getElementById('listPager');
    const info = document.getElementById('listInfo');
    const search = document.getElementById('listSearch');
    const PER = 25;
    let ALL = [], filtered = [], page = 1;

    function apply() {
        const q = (search.value || '').trim().toLowerCase();
        filtered = q ? ALL.filter(r => JSON.stringify(r).toLowerCase().includes(q)) : ALL.slice();
        page = 1;
        draw();
    }

    function draw() {
        const total = filtered.length;
        const pages = Math.max(1, Math.ceil(total / PER));
        if (page > pages) page = pages;
        const start = (page - 1) * PER;
        const slice = filtered.slice(start, start + PER);
        container.innerHTML = total ? render(slice) : '<p class="empty">No matching records.</p>';
        info.textContent = total
            ? 'Showing ' + (start + 1) + '–' + Math.min(start + PER, total) + ' of ' + total
            : 'No records';
        drawPager(pages);
    }

    function pageBtn(label, target, opts) {
        opts = opts || {};
        if (opts.disabled) return '<button class="pg" disabled>' + label + '</button>';
        if (opts.active) return '<button class="pg active">' + label + '</button>';
        return '<button class="pg" data-page="' + target + '">' + label + '</button>';
    }

    function drawPager(pages) {
        if (pages <= 1) { pager.innerHTML = ''; return; }
        let h = pageBtn('‹ Prev', page - 1, { disabled: page === 1 });
        // Windowed page numbers: always show first/last, a window around current.
        const win = [];
        for (let i = 1; i <= pages; i++) {
            if (i === 1 || i === pages || (i >= page - 2 && i <= page + 2)) win.push(i);
        }
        let prev = 0;
        for (const i of win) {
            if (i - prev > 1) h += '<span class="pg-gap">…</span>';
            h += pageBtn(i, i, { active: i === page });
            prev = i;
        }
        h += pageBtn('Next ›', page + 1, { disabled: page === pages });
        pager.innerHTML = h;
        pager.querySelectorAll('button[data-page]').forEach(b => {
            b.addEventListener('click', () => { page = parseInt(b.dataset.page, 10); draw(); });
        });
    }

    if (search) {
        search.addEventListener('input', apply);
        // Prefill from a ?q= passed in by the global top-bar search.
        const q = new URLSearchParams(window.location.search).get('q');
        if (q) search.value = q;
    }
    fetch(apiUrl)
        .then(r => r.json())
        .then(d => { ALL = Array.isArray(d) ? d : (d.history || d.rows || []); apply(); })
        .catch(() => { container.innerHTML = '<p class="empty">Failed to load data.</p>'; });
}
