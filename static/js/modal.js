/* RDPShield - Shared confirmation modal
 * Replaces native window.confirm() popups with an in-page modal that
 * matches the dashboard's design. Two ways to use it:
 *
 * 1. Declarative - mark a form with class="confirm-form" and a
 *    data-confirm-message attribute; submission is intercepted and
 *    routed through the modal automatically. Optional data-confirm-title,
 *    data-confirm-ok, data-confirm-danger="true".
 *
 * 2. Programmatic - call showConfirm(message, onConfirm, opts) directly
 *    for custom flows (e.g. picking the message based on other state).
 */

function showConfirm(message, onConfirm, opts) {
    opts = opts || {};
    const overlay = document.getElementById('confirmModalOverlay');
    const titleEl = document.getElementById('confirmModalTitle');
    const msgEl = document.getElementById('confirmModalMessage');
    const okBtn = document.getElementById('confirmModalOk');
    const cancelBtn = document.getElementById('confirmModalCancel');
    if (!overlay) { onConfirm(); return; } // modal markup missing - fail open

    titleEl.textContent = opts.title || 'Please confirm';
    msgEl.textContent = message;
    okBtn.textContent = opts.okText || 'Confirm';
    okBtn.className = 'btn-modal-ok' + (opts.danger ? ' danger' : '');

    overlay.classList.add('show');

    function cleanup() {
        overlay.classList.remove('show');
        okBtn.removeEventListener('click', onOk);
        cancelBtn.removeEventListener('click', onCancel);
        overlay.removeEventListener('click', onOverlayClick);
        document.removeEventListener('keydown', onKeydown);
    }
    function onOk() { cleanup(); onConfirm(); }
    function onCancel() { cleanup(); }
    function onOverlayClick(e) { if (e.target === overlay) cleanup(); }
    function onKeydown(e) { if (e.key === 'Escape') cleanup(); }

    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    overlay.addEventListener('click', onOverlayClick);
    document.addEventListener('keydown', onKeydown);
}

document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('form.confirm-form').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            showConfirm(form.dataset.confirmMessage, function () { form.submit(); }, {
                title: form.dataset.confirmTitle,
                okText: form.dataset.confirmOk,
                danger: form.dataset.confirmDanger === 'true',
            });
        });
    });
});
