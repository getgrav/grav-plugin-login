# Threat model: Grav Login plugin

The scanner reads this file before it starts. It covers the Grav Login plugin (`getgrav/grav-plugin-login`). Severity follows Grav's own policy, [SECURITY.md](https://github.com/getgrav/grav/blob/develop/SECURITY.md) in core, which rates an issue by **whether it crosses a trust boundary**, not by what a CVSS calculator says.

## What this project does and where untrusted input enters

The Login plugin handles front-end authentication for Grav sites: login and logout, remember-me cookies, password reset, user registration with email activation, magic-link (passwordless) login, two-factor authentication (TOTP), profile editing with email-change confirmation, and invitations. Admin2 and the REST API reuse its accounts, rate limiters and email helpers, so a weakness here usually affects the admin too.

Every one of these flows is reachable by anonymous visitors, so treat all of their input as untrusted: form posts (`task=login.*`, nonces, usernames, passwords, emails, 2FA codes), URL parameters on the token routes (`/reset_password`, `/activate_user`, `/confirm_email`, `/magic_link`, `/user_register/:<invite token>`), the `grav-rememberme` cookie, redirect targets (`_redirect`, the session's `redirect_after_login`, the `Referer` header), and the `Host` header that email links can be built from.

### Where the code is

| Path | What it is |
| --- | --- |
| `/src` | The plugin checkout (`develop`). Patches belong here. |
| `/src/login.php` | Route matching (`initializeLogin`), the task dispatcher (`loginController`), registration, activation, profile, email-change and magic-link handlers. |
| `/src/classes/Controller.php` | The login, forgot, reset, 2FA, logout and invite tasks. |
| `/src/classes/Login.php`, `Email.php`, `RememberMe/`, `TwoFactorAuth/`, `RateLimiter.php` | Registration and validation, email links and trusted-host checks, remember-me token storage, TOTP, rate limiting. |
| `/var/www/grav` | A working Grav site built from the latest `grav-admin` release, served by Apache with `.htaccess` enabled. |
| `/var/www/grav/user/plugins/login` | A symlink to `/src`, so the site runs this checkout and edits are live immediately. |

Registration (with activation emails), magic-link login and 2FA are off by default; this site turns them on (`/var/www/grav/user/config/plugins/login.yaml`) so they can be exercised. Sites commonly enable them, so they are in scope.

Grav core and the other bundled plugins are in the site but live in their own repositories. If a bug is in their code, say which repository owns it.

### Trust model

- **Anonymous visitors** are untrusted. They must not log in as anyone else, reset or take over another account, activate or confirm on someone else's behalf, or pick their own privileges at registration.
- **Registered members** may change only their own profile fields (`user_registration.fields` decides which). Setting `access`, `groups`, `state` or any field outside that list, changing another user's data, or keeping a session alive after the account is disabled or its password reset elsewhere is a finding.
- **Inviters** (accounts with `admin.users` or `api.users.write`) must not hand out more access than they hold (`stripSuperGrants`).
- **Admins and super admins** are trusted, including everything they configure in `login.yaml`.
- **The operator** is trusted: `user/config/**`, `security-private.php`, the environment and the filesystem.

## Components that matter most / least

Highest priority:

1. Account takeover: password reset (`taskForgot`, `taskReset`), activation, email-change confirmation, magic links, remember-me (`RememberMe/`, `TokenStorage`), invitations, and any token that can be guessed, reused, replayed after use, or validated for the wrong user.
2. 2FA bypass: reaching an authorized session without a valid code, or the pending-2FA state leaking into a full login.
3. Privilege escalation at registration or in the profile (mass assignment past `user_registration.fields`, `access`, `groups`, `state`).
4. Open redirects after login and logout (`_redirect`, `redirect_after_login`, referrer handling).
5. CSRF on state-changing tasks (logout, profile update, 2FA secret regeneration, email-change resend or cancel).
6. Email links that use the request `Host` header even when a trusted host (`plugins.login.site_host` or `system.custom_base_url`) is configured, or when `require_trusted_host` is on.
7. Rate-limit bypass on login, reset, 2FA and token submission when it makes brute force practical.
8. XSS in the login, registration, profile and reset pages from reflected parameters or stored profile fields.

Lower priority or out of scope:

- `vendor/` (bacon-qr-code, mober/rememberme, robthree/twofactorauth). Report upstream unless this plugin uses a library unsafely.
- `cli/` commands (local console only), `languages/`, `css/`, `js/`.
- Grav core and the other plugins in `/var/www/grav`.

## How to exercise it

- Run `grav-start` first (there is no init system). The site is at `http://127.0.0.1/`. Routes: `/login`, `/forgot_password`, `/reset_password`, `/user_register`, `/activate_user`, `/confirm_email`, `/magic_login`, `/magic_link`, `/user_profile`. `grav-stop` stops Apache. Grav's log is `/var/www/grav/logs/grav.log`.
- Accounts: `admin` / `Admin-pass-1` (super admin), `editor` / `Editor-pass-1` (page and media editing through the API), `member` / `Member-pass-1` (front-end login only). They are YAML files in `/var/www/grav/user/accounts/`, and reset, activation and magic-link tokens are stored in those files.
- Every email the site sends (activation, reset, magic links, email-change confirmation, invitations) is written to `/var/mail-catcher/*.eml` instead of being delivered, so the links and tokens in them can be read.
- Logging in from the command line: fetch `/login` with a cookie jar, read the `login-form-nonce` hidden field, then POST `username`, `password`, `task=login.login` and `login-form-nonce` back to `/login` with the same jar. The other forms follow the same pattern (`forgot-form-nonce` with `task=login.forgot`, `magic-form-nonce` for magic links).
- Rate-limit state lives in `/var/www/grav/cache/login`; delete it to reset the counters between attempts.
- Run Grav CLI commands as the web server user with `grav-cli`, for example `grav-cli bin/plugin login new-user`.
- The plugin has no automated test suite.

## How you rate severity

| Severity | When to use |
| --- | --- |
| **Critical** | An **unauthenticated** attacker logs in as another user, takes over an account, or gains admin-equivalent control. No Grav account needed. |
| **High** | A **cross-trust-boundary** issue: a member gains privileges they were not granted, a 2FA-protected account is entered without the second factor, stored XSS fires in another user's or an admin's session, or CSRF changes another user's credentials. |
| **Moderate** | An authenticated user does something **outside the documented scope of their role**, but the impact stays within their own account or affects only users at the same level. Open redirects after login land here unless they leak a token. |
| **Low** | An admin or super admin doing something within the capabilities they already hold. Grav does not publish advisories for these; report them only as hardening. |

Rate by the starting access and the boundary crossed, not by the CVSS calculator, which assumes `PR:N` far too often.

## Anything to leave alone

These are closed without an advisory under Grav's policy, so please do not report them as vulnerabilities:

- **Account or email enumeration** through login, registration, password-reset or magic-link messages. This is documented default behavior.
- **Email links built from the request `Host` header when no trusted host is configured.** This is documented, the admin shows a warning until `site_host` or `system.custom_base_url` is set, and `require_trusted_host` turns the fallback off. A link that ignores a configured trusted host is in scope.
- Anything an admin can do within their granted capabilities, including weakening the defaults in `login.yaml`.
- Self-XSS, or anything that needs the victim to paste a payload into their own browser.
- Missing hardening with no demonstrated exploit: absent security headers, rate limits we do not have, non-constant-time comparisons without a practical timing oracle, token entropy findings without a practical attack.
- Bypasses of core's `Security::detectXss()` denylist. Content that renders unescaped at an output sink is in scope; show the sink.
- Dependency CVEs without a reachable call path from this plugin.

## How we would like reports

Each report should state the account the attacker starts with, what they end up with, and which trust boundary is crossed. Include a reproducer that runs against this image (curl commands with a cookie jar are ideal) and a patch against `/src`. If the root cause is in Grav core or another plugin, name that repository.
