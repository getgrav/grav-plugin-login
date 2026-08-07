<?php declare(strict_types=1);

namespace Grav\Plugin\Login;

use Grav\Common\Config\Config;
use Grav\Common\Grav;
use Grav\Common\Language\Language;
use Grav\Common\User\Interfaces\UserInterface;
use Grav\Common\Utils;
use Grav\Plugin\Login\Invitations\Invitation;
use Psr\Log\LoggerInterface;

class Email
{
    /**
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendActivationEmail(UserInterface $user, ?UserInterface $actor = null): void
    {
        $email = $user->email;
        $token = (string)$user->get('activation_token', '');

        if (!$email || !str_contains($token, '::')) {
            return;
        }

        [$token, $expire] = explode('::', $token, 2);

        try {
            $config = static::getConfig();

            $param_sep = $config->get('system.param_sep', ':');
            $activationRoute = static::getLogin()->getRoute('activate');
            if (!$activationRoute) {
                throw new \RuntimeException('User activation route does not exist!');
            }

            $site_host = $config->get('plugins.login.site_host');
            if (!empty($site_host)) {
                $activationRoute = rtrim($site_host, '/') . '/' . ltrim($activationRoute, '/');
            }

            if (static::refuseIfUntrustedHost('account activation')) {
                return;
            }

            static::warnIfUntrustedHost('account activation');

            $activationLink = Utils::url(
                $activationRoute . '/token' . $param_sep . $token . '/username' . $param_sep . $user->username,
                null,
                true
            );

            $context = [
                'activation_link' => $activationLink,
                'expire' => $expire,
            ];

            $params = [
                'to' => $user->email,
            ];

            static::sendEmail('activate', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }


    /**
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendResetPasswordEmail(UserInterface $user, ?UserInterface $actor = null): void
    {
        $email = $user->email;
        $token = (string)$user->get('reset', '');

        if (!$email || !str_contains($token, '::')) {
            return;
        }

        [$token, $expire] = explode('::', $token, 2);

        try {
            $param_sep = static::getConfig()->get('system.param_sep', ':');
            $resetRoute = static::getLogin()->getRoute('reset');
            if (!$resetRoute) {
                throw new \RuntimeException('Password reset route does not exist!');
            }

            $site_host = static::getConfig()->get('plugins.login.site_host');
            if (!empty($site_host)) {
                $resetRoute = rtrim($site_host, '/') . '/' . ltrim($resetRoute, '/');
            }

            if (static::refuseIfUntrustedHost('password reset')) {
                return;
            }

            static::warnIfUntrustedHost('password reset');

            $resetLink = Utils::url(
                "{$resetRoute}/task{$param_sep}login.reset/token{$param_sep}{$token}/user{$param_sep}{$user->username}/nonce{$param_sep}" . Utils::getNonce('reset-form'),
                true,
                true
            );

            $context = [
                'reset_link' => $resetLink,
                'expire' => $expire,
            ];

            $params = [
                'to' => $user->email,
            ];

            static::sendEmail('reset-password', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    /**
     * Tell the owner of an address that someone tried to register with it.
     *
     * This is what the registration form sends instead of answering "that
     * address is already taken" back to whoever submitted it
     * (GHSA-crh8-xm27-j9g9).
     *
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendAlreadyRegisteredEmail(UserInterface $user, ?UserInterface $actor = null): void
    {
        if (!$user->email) {
            return;
        }

        try {
            $forgotRoute = static::getLogin()->getRoute('forgot') ?: '/';

            $site_host = static::getConfig()->get('plugins.login.site_host');
            if (!empty($site_host)) {
                $forgotRoute = rtrim($site_host, '/') . '/' . ltrim($forgotRoute, '/');
            }

            // Warn only, deliberately no refuseIfUntrustedHost() here. This mail
            // carries no token, and not sending it would make registration behave
            // differently for a taken address, which is the enumeration this whole
            // flow exists to prevent (GHSA-crh8-xm27-j9g9).
            static::warnIfUntrustedHost('already registered notice');

            $context = [
                'forgot_link' => Utils::url($forgotRoute, null, true),
            ];

            $params = [
                'to' => $user->email,
            ];

            static::sendEmail('already-registered', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    /**
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendWelcomeEmail(UserInterface $user, ?UserInterface $actor = null): void
    {
        if (!$user->email) {
            return;
        }

        try {
            $context = [];

            $params = [
                'to' => $user->email,
            ];

            static::sendEmail('welcome', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    /**
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendNotificationEmail(UserInterface $user, ?UserInterface $actor = null): void
    {
        try {
            $to = static::getConfig()->get('plugins.email.to');
            if (!$to) {
                throw new \RuntimeException(static::getLanguage()->translate('PLUGIN_LOGIN.EMAIL_NOT_CONFIGURED'));
            }

            $context = [];

            $params = [
                'to' => $to,
            ];

            static::sendEmail('notification', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    /**
     * @param Invitation $invitation
     * @param string|null $message
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendInvitationEmail(Invitation $invitation, ?string $message = null, ?UserInterface $actor = null): void
    {
        if (!$invitation->email) {
            return;
        }

        try {
            $config = static::getConfig();
            $param_sep = $config->get('system.param_sep', ':');
            $inviteRoute = static::getLogin()->getRoute('register', true);
            if (!$inviteRoute) {
                throw new \RuntimeException('User registration route does not exist!');
            }

            // Pin the link to the configured host, the same way the other flows do.
            // Without this the route stays relative and Utils::url() resolves it
            // against the Host-derived rootUrl(), so setting site_host had no effect
            // on invitation links at all while isTrustedHostConfigured() still
            // reported the site as protected. (GHSA-69vf-mjxw-x79j)
            $site_host = $config->get('plugins.login.site_host');
            if (!empty($site_host)) {
                $inviteRoute = rtrim($site_host, '/') . '/' . ltrim($inviteRoute, '/');
            }

            // An invitation is sent by an authenticated actor, so unlike a password
            // reset there is no account to enumerate and refusing quietly would just
            // look like a silent failure. Throw instead: Login::sendInviteEmail()
            // turns it into a visible error for the sender.
            if (static::refuseIfUntrustedHost('invitation')) {
                throw new \RuntimeException('Refusing to send an invitation link built from an untrusted host.');
            }

            static::warnIfUntrustedHost('invitation');

            $invitationLink = Utils::url("{$inviteRoute}/{$param_sep}{$invitation->token}", true, true);

            $context = [
                'invitation_link' => $invitationLink,
                'invitation' => $invitation,
                'message' => $message,
            ];

            $params = [
                'to' => $invitation->email,
            ];

            static::sendEmail('invite', $context, $params, null, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    /**
     * @param UserInterface $user
     * @param string $token
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendMagicLoginEmail(UserInterface $user, string $token, ?UserInterface $actor = null): void
    {
        if (!$user->email || $token === '') {
            return;
        }

        try {
            $config = static::getConfig();
            $param_sep = $config->get('system.param_sep', ':');
            $magicRoute = static::getLogin()->getRoute('magic_login');
            if (!$magicRoute) {
                throw new \RuntimeException('Magic login route does not exist!');
            }

            $site_host = $config->get('plugins.login.site_host');
            if (!empty($site_host)) {
                $magicRoute = rtrim($site_host, '/') . '/' . ltrim($magicRoute, '/');
            }

            if (static::refuseIfUntrustedHost('magic login')) {
                return;
            }

            static::warnIfUntrustedHost('magic login');

            $loginLink = Utils::url(
                "{$magicRoute}/token{$param_sep}{$token}/username{$param_sep}{$user->username}",
                true,
                true
            );

            $context = [
                'login_link' => $loginLink,
            ];

            $params = [
                'to' => $user->email,
            ];

            static::sendEmail('magic-login', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    protected static function sendEmail(string $template, array $context, array $params, ?UserInterface $user = null, ?UserInterface $actor = null): void
    {
        $actor = $actor ?? static::getUser();

        $config = static::getConfig();

        $site_host = $config->get('plugins.login.site_host');
        if (empty($site_host)) {
            $site_host = Grav::instance()['uri']->host();
        }

        // Twig context.
        $context += [
            'actor' => $actor,
            'user' => $user,
            'site_name' => $config->get('site.title', 'Website'),
            'site_host' => $site_host,
            'author' => $config->get('site.author.name', ''),
        ];

        if (!isset($params['body']) && !isset($params['template'])) {
            $body = [
                [
                    'content_type' => 'text/html',
                    'template' => "emails/login/{$template}.html.twig",
                    'body' => '',
                ],
            ];

            if (static::templateExists("emails/login/{$template}.txt.twig")) {
                $body[] = [
                    'content_type' => 'text/plain',
                    'template' => "emails/login/{$template}.txt.twig",
                    'body' => '',
                ];
            }

            $params['body'] = $body;
        }

        $email = static::getEmail();

        $message = $email->buildMessage($params, $context);

        $failedRecipients = null;
        $email->send($message, $failedRecipients);
        if ($failedRecipients) {
            $language = static::getLanguage();

            throw new \RuntimeException($language->translate(['PLUGIN_LOGIN.FAILED_TO_SEND_EMAILS', implode(', ', $failedRecipients)]));
        }
    }

    /**
     * @return Login
     */
    protected static function getLogin(): Login
    {
        return Grav::instance()['login'];
    }

    /**
     * @return LoggerInterface
     */
    protected static function getLogger(): LoggerInterface
    {
        return Grav::instance()['log'];
    }

    /**
     * Warn when a security-sensitive email link has to be built from the
     * incoming request `Host` header.
     *
     * When neither `plugins.login.site_host` nor `system.custom_base_url` is
     * set, password reset, activation and magic-login links are made absolute
     * using the request host, which a client can spoof to redirect the link to
     * an attacker-controlled host and capture the token (GHSA-46jp-rc59-w2gc).
     * On a default install there is no trusted server-side host to substitute,
     * so rather than silently emit a spoofable link we make the weak
     * configuration visible. Setting either value pins the link to a trusted
     * host and silences this warning.
     *
     * @param string $context Human label for the email flow, e.g. "password reset".
     * @return void
     */
    /**
     * Fail closed when the operator has opted into `require_trusted_host` but no
     * trusted host is actually configured.
     *
     * warnIfUntrustedHost() only records the weak configuration. This is the
     * opt-in enforcement that refuses to emit a spoofable token-bearing link at
     * all (GHSA-46jp-rc59-w2gc). Every security-sensitive send path calls it, so
     * a newly added email flow cannot quietly opt out of the setting by omission,
     * which is how the invitation flow came to be missing it.
     *
     * taskForgot() keeps its own earlier check as well: that one has to refuse
     * before the user lookup, so the response cannot reveal whether an account
     * exists.
     *
     * @param string $context Human label for the email flow, e.g. "invitation".
     * @return bool True when the caller must not send.
     */
    protected static function refuseIfUntrustedHost(string $context): bool
    {
        if (!static::getConfig()->get('plugins.login.require_trusted_host', false)
            || static::isTrustedHostConfigured()) {
            return false;
        }

        static::getLogger()->error(sprintf(
            'login: %s email refused because require_trusted_host is enabled but neither plugins.login.site_host nor system.custom_base_url is set.',
            $context
        ));

        return true;
    }

    protected static function warnIfUntrustedHost(string $context): void
    {
        if (static::isTrustedHostConfigured()) {
            return;
        }

        static::getLogger()->warning(sprintf(
            'login: %s email link built from the request Host header because neither plugins.login.site_host nor system.custom_base_url is set. A spoofed Host can redirect this link to an attacker (GHSA-46jp-rc59-w2gc); set one of those to pin it to a trusted host.',
            $context
        ));
    }

    /**
     * Whether a trusted, server-side host is configured for building absolute
     * email links.
     *
     * Returns true when either the login plugin's `site_host` or the core
     * `system.custom_base_url` is set. When both are empty, security-sensitive
     * links fall back to the request `Host` header, which a client can spoof
     * (GHSA-46jp-rc59-w2gc). The admin notices and the optional
     * `require_trusted_host` enforcement both key off this.
     *
     * @return bool
     */
    public static function isTrustedHostConfigured(): bool
    {
        $config = static::getConfig();

        return !empty($config->get('plugins.login.site_host'))
            || !empty($config->get('system.custom_base_url'));
    }

    /**
     * @return UserInterface
     */
    protected static function getUser(): UserInterface
    {
        return Grav::instance()['user'];
    }

    /**
     * @return \Grav\Plugin\Email\Email
     */
    protected static function getEmail(): \Grav\Plugin\Email\Email
    {
        return Grav::instance()['Email'];
    }

    /**
     * @return Config
     */
    protected static function getConfig(): Config
    {
        return Grav::instance()['config'];
    }

    /**
     * @return Language
     */
    protected static function getLanguage(): Language
    {
        return Grav::instance()['language'];
    }

    protected static function templateExists(string $template): bool
    {
        try {
            $twig = Grav::instance()['twig'];
            $twig->init();

            $loader = $twig->twig()->getLoader();

            return method_exists($loader, 'exists') ? $loader->exists($template) : false;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
