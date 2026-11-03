/*
 * Passkeys on the site's login, 2FA and profile pages. No dependencies.
 *
 * The server (task login.passkey) sends WebAuthn options as JSON with binary
 * fields in base64url and takes the browser's answer back the same way. Each
 * call carries the one-use ticket its options came with and the login-form
 * nonce.
 *
 * Markup hooks (templates/partials/passkey-*.html.twig):
 *   [data-passkeys-root]       url, nonce and strings for the page
 *   [data-passkey-signin]      button: sign in with a passkey alone
 *   [data-passkey-second-step] button: a passkey instead of the 2FA code
 *   [data-passkeys-manage]     the profile page's list of passkeys
 */
(function () {
    'use strict';

    var root = document.querySelector('[data-passkeys-root]');
    if (!root) return;

    var url = root.getAttribute('data-url');
    var nonceInput = root.querySelector('input[name="login-form-nonce"]');
    var nonce = nonceInput ? nonceInput.value : '';
    var t = {};
    try { t = JSON.parse(root.getAttribute('data-strings') || '{}'); } catch (e) {}

    var supported = !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create && window.isSecureContext);

    function toBytes(b64u) {
        var b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        var bin = atob(b64), out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out.buffer;
    }

    function toB64u(buf) {
        var bytes = new Uint8Array(buf), bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function withIds(list) {
        return (list || []).map(function (c) { return Object.assign({}, c, { id: toBytes(c.id) }); });
    }

    function credentialJSON(cred) {
        var r = cred.response, response = { clientDataJSON: toB64u(r.clientDataJSON) };
        if (r.attestationObject) {
            response.attestationObject = toB64u(r.attestationObject);
            if (r.getTransports) { try { response.transports = r.getTransports(); } catch (e) {} }
        } else {
            response.authenticatorData = toB64u(r.authenticatorData);
            response.signature = toB64u(r.signature);
            if (r.userHandle) response.userHandle = toB64u(r.userHandle);
        }
        return { id: cred.id, rawId: toB64u(cred.rawId), type: cred.type, response: response };
    }

    function post(step, data) {
        var body = new URLSearchParams();
        body.set('step', step);
        body.set('data', JSON.stringify(data || {}));
        body.set('login-form-nonce', nonce);
        return fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
            body: body
        }).then(function (res) {
            return res.json().catch(function () { return {}; }).then(function (json) {
                if (!res.ok) {
                    var err = new Error(json.error || t.failed);
                    err.data = json;
                    err.status = res.status;
                    throw err;
                }
                return json;
            });
        });
    }

    function remember() { try { localStorage.setItem('grav-passkey', '1'); } catch (e) {} }
    function known() { try { return localStorage.getItem('grav-passkey') === '1'; } catch (e) { return false; } }
    function cancelled(e) { return e && (e.name === 'NotAllowedError' || e.name === 'AbortError'); }

    function message(e) {
        if (e && e.name === 'InvalidStateError') return t.alreadySaved;
        if (cancelled(e)) return t.cancelled;
        return (e && e.message) || t.failed;
    }

    /** Sign in or pass a step: options from `<step>-options`, the answer to `<step>`. */
    function get(step, extra, mediation, signal) {
        return post(step + '-options', extra).then(function (start) {
            var o = start.options;
            var req = { publicKey: Object.assign({}, o, { challenge: toBytes(o.challenge), allowCredentials: withIds(o.allowCredentials) }) };
            if (mediation) req.mediation = mediation;
            if (signal) req.signal = signal;
            return navigator.credentials.get(req).then(function (cred) {
                return post(step, Object.assign({}, extra, { ticket: start.ticket, credential: credentialJSON(cred) }));
            });
        }).then(function (r) { remember(); return r; });
    }

    function create(extra) {
        return post('add-options', extra).then(function (start) {
            var o = start.options;
            var pk = Object.assign({}, o, {
                challenge: toBytes(o.challenge),
                user: Object.assign({}, o.user, { id: toBytes(o.user.id) }),
                excludeCredentials: withIds(o.excludeCredentials)
            });
            return navigator.credentials.create({ publicKey: pk }).then(function (cred) {
                return post('add', { ticket: start.ticket, credential: credentialJSON(cred) });
            });
        }).then(function (r) { remember(); return r; });
    }

    function busy(btn, on) {
        if (on) {
            btn.setAttribute('data-label', btn.innerHTML);
            btn.disabled = true;
            btn.setAttribute('aria-busy', 'true');
            btn.textContent = t.waiting;
        } else {
            btn.disabled = false;
            btn.removeAttribute('aria-busy');
            if (btn.hasAttribute('data-label')) btn.innerHTML = btn.getAttribute('data-label');
        }
    }

    function showError(slot, text) {
        if (!slot) return;
        slot.textContent = text || '';
        slot.style.display = text ? '' : 'none';
    }

    function go(r) { if (r && r.redirect) location.href = r.redirect; }

    // ------------------------------------------------------------------
    // Login form: a passkey alone
    // ------------------------------------------------------------------

    var signin = document.querySelector('[data-passkey-signin]');
    if (signin) {
        var box = signin.closest('[data-passkey-box]') || signin.parentNode;
        var slot = box.querySelector('[data-passkey-error]');
        if (supported) {
            box.hidden = false;
            var form = document.querySelector('form.login-form');
            var rememberBox = form ? form.querySelector('input[name="rememberme"]') : null;
            var waiting = null;

            // Passkeys offered in the username field's autofill.
            var username = form ? form.querySelector('input[name="username"]') : null;
            if (username && window.PublicKeyCredential.isConditionalMediationAvailable) {
                PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
                    if (!ok) return;
                    username.setAttribute('autocomplete', 'username webauthn');
                    waiting = new AbortController();
                    get('sign-in', { rememberme: rememberBox && rememberBox.checked ? 1 : 0 }, 'conditional', waiting.signal)
                        .then(go)
                        // Autofill is a quiet extra: a browser that can't do it
                        // here says nothing. Only a refused sign-in is shown.
                        .catch(function (e) { if (e && e.status) showError(slot, message(e)); });
                }).catch(function () {});
            }

            signin.addEventListener('click', function (ev) {
                ev.preventDefault();
                if (waiting) { waiting.abort(); waiting = null; }
                showError(slot, '');
                busy(signin, true);
                get('sign-in', { rememberme: rememberBox && rememberBox.checked ? 1 : 0 })
                    .then(go)
                    .catch(function (e) { busy(signin, false); showError(slot, message(e)); });
            });
            if (known()) signin.classList.add('passkey-known');
        }
    }

    // ------------------------------------------------------------------
    // 2FA step: a passkey instead of the code
    // ------------------------------------------------------------------

    var second = document.querySelector('[data-passkey-second-step]');
    if (second) {
        var box2 = second.closest('[data-passkey-box]') || second.parentNode;
        var slot2 = box2.querySelector('[data-passkey-error]');
        if (supported) {
            box2.hidden = false;
            second.addEventListener('click', function (ev) {
                ev.preventDefault();
                showError(slot2, '');
                busy(second, true);
                get('second-step', {})
                    .then(go)
                    .catch(function (e) {
                        busy(second, false);
                        // The sign-in in progress ended (expired or too many tries).
                        if (e.status === 410) { location.reload(); return; }
                        showError(slot2, message(e));
                    });
            });
        }
    }

    // ------------------------------------------------------------------
    // Profile: the account's passkeys
    // ------------------------------------------------------------------

    var manage = document.querySelector('[data-passkeys-manage]');
    if (manage) {
        var slot3 = manage.querySelector('[data-passkey-error]');
        var proofRow = manage.querySelector('[data-passkey-proof]');
        var proofInput = proofRow ? proofRow.querySelector('input') : null;
        var proofKind = proofRow ? proofRow.getAttribute('data-passkey-proof') : '';
        var addBtn = manage.querySelector('[data-passkey-add]');

        function proof() {
            var v = proofInput ? proofInput.value : '';
            return proofKind === 'code' ? { code: v } : { password: v };
        }
        function needProof() {
            if (proofRow && proofInput && proofInput.value === '') {
                proofRow.hidden = false;
                proofInput.focus();
                showError(slot3, proofKind === 'code' ? t.proofCode : t.proofPassword);
                return true;
            }
            return false;
        }
        function failed(e, btn) {
            if (btn) busy(btn, false);
            if (e.data && e.data.proof && proofRow) { proofRow.hidden = false; if (proofInput) { proofInput.value = ''; proofInput.focus(); } }
            showError(slot3, message(e));
        }

        if (addBtn) {
            if (!supported) {
                addBtn.disabled = true;
                showError(slot3, t.unsupported);
            }
            addBtn.addEventListener('click', function (ev) {
                ev.preventDefault();
                showError(slot3, '');
                if (needProof()) return;
                busy(addBtn, true);
                create(proof()).then(function () { location.reload(); }).catch(function (e) { failed(e, addBtn); });
            });
        }

        manage.addEventListener('click', function (ev) {
            var remove = ev.target.closest('[data-passkey-remove]');
            var rename = ev.target.closest('[data-passkey-rename]');
            if (remove) {
                ev.preventDefault();
                showError(slot3, '');
                if (needProof()) return;
                if (!window.confirm(t.removeConfirm)) return;
                busy(remove, true);
                post('remove', Object.assign({ id: remove.getAttribute('data-passkey-remove') }, proof()))
                    .then(function () { location.reload(); })
                    .catch(function (e) { failed(e, remove); });
            } else if (rename) {
                ev.preventDefault();
                var row = rename.closest('[data-passkey-row]');
                var current = row.querySelector('[data-passkey-name]').textContent;
                var name = window.prompt(t.rename, current);
                if (name === null || name.trim() === '' || name === current) return;
                post('rename', { id: rename.getAttribute('data-passkey-rename'), name: name })
                    .then(function () { location.reload(); })
                    .catch(function (e) { failed(e); });
            }
        });
    }
})();
