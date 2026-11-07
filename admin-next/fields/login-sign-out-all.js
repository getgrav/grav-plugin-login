/**
 * "Sign out all users": Admin2 field for the Login plugin settings (Options →
 * Sessions). One button that, after a confirmation, calls
 * POST /login/sign-out-all (Login::signOutEveryone()).
 *
 * Holds no value and emits none. The blueprint passes the button text as
 * `text` and the confirmation as `content` (both translated by the API).
 */

const TAG = window.__GRAV_FIELD_TAG;

class LoginSignOutAll extends HTMLElement {
    constructor() {
        super();
        this._field = null;
        this._value = null;
        this._busy = false;
    }

    set field(v) { this._field = v; if (this.isConnected) this._render(); }
    get field() { return this._field; }

    set value(v) { this._value = v; }
    get value() { return this._value; }

    connectedCallback() {
        this._render();
    }

    get _label() { return (this._field && this._field.text) || 'Sign out all users'; }

    _render() {
        this.innerHTML = `
            <style>
                .lso-button {
                    display: inline-flex; align-items: center; gap: 8px;
                    padding: 6px 14px; border-radius: 6px; font: inherit; font-size: 13px; font-weight: 500;
                    cursor: pointer; border: 1px solid var(--destructive, #dc2626);
                    color: var(--destructive, #dc2626); background: transparent;
                }
                .lso-button:hover:not(:disabled) { background: var(--destructive, #dc2626); color: var(--destructive-foreground, #fff); }
                .lso-button:disabled { opacity: .6; cursor: default; }
            </style>
            <button type="button" class="lso-button"><i class="fa-solid fa-right-from-bracket"></i><span></span></button>
        `;
        this._button = this.querySelector('button');
        this.querySelector('span').textContent = this._label;
        this._button.disabled = this._busy;
        this._button.addEventListener('click', () => this._run());
    }

    async _run() {
        const field = this._field || {};
        const label = this._label;
        const dialogs = window.__GRAV_DIALOGS;
        const message = field.content || 'Sign out every account now, yours included?';
        const confirmed = await dialogs.confirm({ title: field.label || label, message, confirmLabel: label, variant: 'destructive' });
        if (!confirmed) return;

        this._busy = true;
        this._button.disabled = true;
        const toast = window.__GRAV_TOAST;
        try {
            const result = await window.__GRAV_API.post('/login/sign-out-all');
            const done = (result && result.message) || 'Signed out.';
            // Some accounts couldn't be saved, or the other sessions couldn't be ended (the message says which).
            const partial = result && ((Array.isArray(result.failed) && result.failed.length > 0) || result.sessions_ended === false);
            (partial ? toast.warning : toast.success)(done);
        } catch (err) {
            const failed = (err && err.message) || 'Signing out failed.';
            toast.error(failed);
        } finally {
            this._busy = false;
            this._button.disabled = false;
        }
    }
}

customElements.define(TAG, LoginSignOutAll);
