/* RDPShield — CSRF protection shim
 * =================================
 * The server (dashboard.py) requires a per-session CSRF token on every
 * state-changing request. This shim supplies it automatically so individual
 * forms/fetches don't each need editing:
 *
 *   1. Injects a hidden `csrf_token` field into every same-origin, non-GET
 *      <form> — done up-front (not on submit) so modal.js's programmatic
 *      form.submit() still carries it. A MutationObserver covers forms that
 *      tables.js renders later during the live AJAX refresh.
 *   2. Patches window.fetch to add an `X-CSRFToken` header to same-origin
 *      mutating requests (used by the YARA scan / finding-action buttons).
 *
 * The token value is published by the server in window.CSRF_TOKEN (set in
 * templates/_topbar.html).
 */
(function () {
    var TOKEN = window.CSRF_TOKEN || '';

    function addFieldTo(form) {
        if (!form || !form.tagName || form.tagName.toLowerCase() !== 'form') return;
        if ((form.method || 'get').toLowerCase() === 'get') return;     // GETs don't need it
        if (form.querySelector('input[name="csrf_token"]')) return;      // already present
        var inp = document.createElement('input');
        inp.type = 'hidden';
        inp.name = 'csrf_token';
        inp.value = TOKEN;
        form.appendChild(inp);
    }

    function injectAll(root) {
        (root || document).querySelectorAll('form').forEach(addFieldTo);
    }

    // Initial pass once the DOM is ready.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { injectAll(); });
    } else {
        injectAll();
    }

    // Cover dynamically-rendered forms (tables.js block/unblock rows).
    if (window.MutationObserver) {
        new MutationObserver(function (mutations) {
            for (var m = 0; m < mutations.length; m++) {
                var nodes = mutations[m].addedNodes;
                for (var n = 0; n < nodes.length; n++) {
                    var node = nodes[n];
                    if (node.nodeType !== 1) continue;          // elements only
                    if (node.tagName && node.tagName.toLowerCase() === 'form') addFieldTo(node);
                    if (node.querySelectorAll) injectAll(node);
                }
            }
        }).observe(document.documentElement, { childList: true, subtree: true });
    }

    // Patch fetch() to attach the token header on same-origin mutating calls.
    var _fetch = window.fetch;
    if (_fetch) {
        window.fetch = function (input, init) {
            init = init || {};
            var method = (init.method
                || (input && typeof input !== 'string' && input.method)
                || 'GET').toUpperCase();
            var url = (typeof input === 'string') ? input : (input && input.url) || '';
            // Treat relative URLs and our own origin as same-origin.
            var sameOrigin = !/^https?:\/\//i.test(url) || url.indexOf(window.location.origin) === 0;
            if (sameOrigin && method !== 'GET' && method !== 'HEAD') {
                var headers = new Headers(
                    init.headers || (input && typeof input !== 'string' && input.headers) || {});
                if (!headers.has('X-CSRFToken')) headers.set('X-CSRFToken', TOKEN);
                init.headers = headers;
                return _fetch(input, init);
            }
            return _fetch(input, init);
        };
    }
})();
