/* RDPShield service worker — minimal, security-conscious offline shell.
 * ====================================================================
 * Registers only in a secure context (see _pwa_head.html). It caches the
 * STATIC app shell (CSS/JS/icons) cache-first so the installed app launches
 * instantly and survives brief network blips. It deliberately does NOT cache
 * pages or /api responses — those are always fetched live, so the dashboard
 * never shows stale or sensitive data from cache.
 */
const CACHE = 'rdpshield-shell-v1';
const SHELL = [
    '/static/style.css',
    '/static/js/tables.js',
    '/static/js/modal.js',
    '/static/js/csrf.js',
    '/static/js/chart.umd.min.js',
    '/static/img/logo.svg',
    '/static/img/icon-192.png',
    '/static/img/icon-512.png',
    '/static/manifest.webmanifest',
];

self.addEventListener('install', (e) => {
    e.waitUntil(
        caches.open(CACHE)
            .then((c) => c.addAll(SHELL))
            .then(() => self.skipWaiting())
            .catch(() => { /* a missing asset shouldn't block install */ })
    );
});

self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (e) => {
    const req = e.request;
    if (req.method !== 'GET') return;                       // never touch POST/PUT/etc.
    const url = new URL(req.url);
    if (url.origin !== self.location.origin) return;        // only our own origin
    // Static shell: cache-first, then fill the cache on first miss.
    if (url.pathname.startsWith('/static/')) {
        e.respondWith(
            caches.match(req).then((hit) => hit || fetch(req).then((res) => {
                const copy = res.clone();
                caches.open(CACHE).then((c) => c.put(req, copy));
                return res;
            }))
        );
    }
    // Pages and /api/* fall through to the network (no caching) for freshness
    // and to avoid persisting sensitive data on the device.
});
