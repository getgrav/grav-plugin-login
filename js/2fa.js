/*
 * The profile page's 2-Factor Authentication panel. No dependencies.
 *
 * Steps (templates/forms/fields/2fa_secret/2fa_secret.html.twig):
 *   off     "Enable 2FA"        -> login.regenerate2FASecret -> finish
 *   finish  "Verify & Enable"   -> login.twofaEnable         -> on
 *   on      "Regenerate" + code -> login.regenerate2FASecret -> finish
 *           "Disable" + code    -> login.twofaDisable        -> off
 *
 * Every call is a POST with the login-form nonce and answers
 * { status, message?, image?, secret? }. Nothing here is posted with the
 * profile form: the inputs have no name.
 */
(function () {
    'use strict';

    var panel = document.querySelector('[data-2fa-panel]');
    if (!panel) return;

    var nonceInput = panel.querySelector('input[name="login-form-nonce"]');
    var errorBox = panel.querySelector('[data-2fa-error]');
    var noticeBox = panel.querySelector('[data-2fa-notice]');
    var t = {};
    try { t = JSON.parse(panel.getAttribute('data-strings') || '{}'); } catch (e) {}

    // A profile form from before the panel may still carry the old Yes/No
    // toggle; the panel replaces it, and the server ignores what it posts.
    var form = panel.closest('form');
    if (form) {
        form.querySelectorAll('.twofa-toggle').forEach(function (el) {
            var field = el.closest('.form-field');
            if (field) field.hidden = true;
        });
    }

    function say(box, text) {
        box.textContent = text || '';
        box.hidden = !text;
    }

    function clearMessages() {
        say(errorBox, '');
        say(noticeBox, '');
    }

    function show(stage) {
        panel.setAttribute('data-stage', stage);
        panel.querySelectorAll('[data-2fa-step]').forEach(function (step) {
            step.hidden = step.getAttribute('data-2fa-step') !== stage;
        });
        panel.querySelectorAll('[data-2fa-confirm]').forEach(function (box) { box.hidden = true; });
        panel.querySelectorAll('[data-2fa-input]').forEach(function (input) { input.value = ''; });
        var actions = panel.querySelector('[data-2fa-on-actions]');
        if (actions) actions.hidden = false;
    }

    function code(name) {
        var input = panel.querySelector('[data-2fa-input="' + name + '"]');
        return input ? input.value.replace(/\s+/g, '') : '';
    }

    function post(kind, data, button) {
        var body = new URLSearchParams();
        body.set('login-form-nonce', nonceInput ? nonceInput.value : '');
        Object.keys(data || {}).forEach(function (key) { body.set(key, data[key]); });

        clearMessages();
        if (button) button.disabled = true;
        panel.setAttribute('aria-busy', 'true');

        return fetch(panel.getAttribute('data-url-' + kind), {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
            body: body
        }).then(function (res) {
            return res.json().catch(function () { return {}; });
        }).then(function (json) {
            if (json.status !== 'success') {
                throw new Error(json.message || t.failed);
            }
            return json;
        }).catch(function (err) {
            say(errorBox, (err && err.message) || t.failed);
            throw err;
        }).finally(function () {
            if (button) button.disabled = false;
            panel.removeAttribute('aria-busy');
        });
    }

    function newSecret(json) {
        panel.querySelector('[data-2fa-image]').src = json.image;
        panel.querySelector('[data-2fa-secret]').textContent = json.secret;
        show('finish');
        var input = panel.querySelector('[data-2fa-input="enable"]');
        if (input) input.focus();
    }

    var actions = {
        enable: function (button) {
            var value = code('enable');
            if (!/^\d{6,8}$/.test(value)) return say(errorBox, t.enterCode);
            post('enable', { twofa_code: value }, button).then(function (json) {
                show('on');
                say(noticeBox, json.message);
            }, function () {});
        },
        regenerate: function (button) {
            var value = code('regenerate');
            if (!/^\d{6,8}$/.test(value)) return say(errorBox, t.enterCode);
            post('generate', { twofa_code: value }, button).then(newSecret, function () {});
        },
        disable: function (button) {
            var value = code('disable');
            if (!/^\d{6,8}$/.test(value)) return say(errorBox, t.enterCode);
            post('disable', { twofa_code: value }, button).then(function (json) {
                show('off');
                say(noticeBox, json.message);
            }, function () {});
        }
    };

    panel.addEventListener('click', function (event) {
        var target = event.target.closest('button');
        if (!target || !panel.contains(target)) return;

        if (target.hasAttribute('data-2fa-generate')) {
            event.preventDefault();
            post('generate', {}, target).then(newSecret, function () {});
        } else if (target.hasAttribute('data-2fa-action')) {
            event.preventDefault();
            actions[target.getAttribute('data-2fa-action')](target);
        } else if (target.hasAttribute('data-2fa-ask')) {
            event.preventDefault();
            var name = target.getAttribute('data-2fa-ask');
            clearMessages();
            panel.querySelector('[data-2fa-on-actions]').hidden = true;
            var box = panel.querySelector('[data-2fa-confirm="' + name + '"]');
            box.hidden = false;
            box.querySelector('input').focus();
        } else if (target.hasAttribute('data-2fa-cancel')) {
            event.preventDefault();
            clearMessages();
            show('on');
        }
    });

    // Enter in a code box runs that box's action instead of saving the profile form.
    panel.addEventListener('keydown', function (event) {
        if (event.key !== 'Enter') return;
        var input = event.target.closest('[data-2fa-input]');
        if (!input) return;
        event.preventDefault();
        var name = input.getAttribute('data-2fa-input');
        actions[name](panel.querySelector('[data-2fa-action="' + name + '"]'));
    });
})();
