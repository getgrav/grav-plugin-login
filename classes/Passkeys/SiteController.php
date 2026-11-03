<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2026 Trilby Media, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login\Passkeys;

use Grav\Common\Grav;
use Grav\Common\User\Interfaces\UserInterface;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Plugin\Login\Login;

/**
 * The `login.passkey` task: passkey ceremonies for the site's own pages.
 *
 * One task, a `step` per call, JSON back (the 2FA field's regenerate task
 * works the same way). POST with the `login-form` nonce only.
 *
 *   sign-in-options / sign-in          a passkey alone, from the login form
 *   second-step-options / second-step  a passkey in place of the app code
 *   add-options / add                  a new passkey, from the profile page
 *   remove, rename                     the account's passkeys
 *
 * Adding or removing a passkey takes the current password (or, for an account
 * without one, the current 2FA code when 2FA is on), so a session left open
 * somewhere can't add its own way in. An account with neither can't change
 * its passkeys until it sets one.
 */
class SiteController
{
    /** @var Grav */
    private $grav;
    /** @var Login */
    private $login;
    /** @var Passkeys */
    private $passkeys;
    /** @var array */
    private $post;

    public function __construct(Grav $grav, Login $login, Passkeys $passkeys, array $post)
    {
        $this->grav = $grav;
        $this->login = $login;
        $this->passkeys = $passkeys;
        $this->post = $post;
    }

    /** Handle the step and return [status, body]. */
    public function handle(): array
    {
        $step = (string)($this->post['step'] ?? '');
        $data = json_decode((string)($this->post['data'] ?? '{}'), true);
        $data = is_array($data) ? $data : [];
        $ip = $this->login->getIpKey();

        if (substr($step, -8) === '-options') {
            $limiter = $this->login->getRateLimiter('passkey_options');
            if ($limiter->hasReachedLimit($ip, 'ip')) {
                return $this->error('PLUGIN_LOGIN.PASSKEY_TOO_MANY_TRIES', 429);
            }
            $limiter->registerRateLimitedAction($ip, 'ip');
        } elseif (in_array($step, ['sign-in', 'second-step'], true)
            && $this->login->getRateLimiter('passkey_attempts')->hasReachedLimit($ip, 'ip')) {
            return $this->error('PLUGIN_LOGIN.PASSKEY_TOO_MANY_TRIES', 429);
        }

        switch ($step) {
            case 'sign-in-options':
                return [200, $this->passkeys->assertionOptions(null, 'sign-in')];

            case 'sign-in':
                return $this->signIn($data);

            case 'second-step-options':
                $user = $this->pendingUser();
                return $user !== null
                    ? [200, $this->passkeys->assertionOptions($user, 'second-step')]
                    : $this->error('PLUGIN_LOGIN.PASSKEY_EXPIRED', 410);

            case 'second-step':
                return $this->secondStep($data);

            case 'add-options':
                $user = $this->signedInUser();
                if ($user === null) {
                    return $this->error('PLUGIN_LOGIN.ACCESS_DENIED', 403);
                }
                $proof = $this->proofError($user, $data);
                return $proof ?? [200, $this->passkeys->registrationOptions($user)];

            case 'add':
                $user = $this->signedInUser();
                if ($user === null) {
                    return $this->error('PLUGIN_LOGIN.ACCESS_DENIED', 403);
                }
                try {
                    $passkey = $this->passkeys->finishRegistration($user, (string)($data['ticket'] ?? ''), (array)($data['credential'] ?? []));
                } catch (PasskeyException $e) {
                    return $this->error($e->getMessage(), 422);
                }
                $this->grav->fireEvent('onUserPasskeyAdded', new \RocketTheme\Toolbox\Event\Event(['user' => $user, 'passkey' => $passkey]));
                $this->flash($this->translate(['PLUGIN_LOGIN.PASSKEY_ADDED', $passkey['name']]), 'info');
                return [200, ['passkey' => $passkey]];

            case 'remove':
                $user = $this->signedInUser();
                if ($user === null) {
                    return $this->error('PLUGIN_LOGIN.ACCESS_DENIED', 403);
                }
                $proof = $this->proofError($user, $data);
                if ($proof !== null) {
                    return $proof;
                }
                $name = $this->passkeys->remove($user, (string)($data['id'] ?? ''));
                if ($name === null) {
                    return $this->error('PLUGIN_LOGIN.PASSKEY_NOT_FOUND', 404);
                }
                $this->grav->fireEvent('onUserPasskeyRemoved', new \RocketTheme\Toolbox\Event\Event(['user' => $user, 'name' => $name]));
                $this->flash($this->translate(['PLUGIN_LOGIN.PASSKEY_REMOVED', $name]), 'info');
                return [200, ['removed' => true]];

            case 'rename':
                $user = $this->signedInUser();
                if ($user === null) {
                    return $this->error('PLUGIN_LOGIN.ACCESS_DENIED', 403);
                }
                return $this->passkeys->rename($user, (string)($data['id'] ?? ''), (string)($data['name'] ?? ''))
                    ? [200, ['renamed' => true]]
                    : $this->error('PLUGIN_LOGIN.PASSKEY_NOT_FOUND', 404);
        }

        return $this->error('PLUGIN_LOGIN.ACCESS_DENIED', 400);
    }

    /** A passkey alone: both steps at once. */
    private function signIn(array $data): array
    {
        $user = $this->passkeys->verifyAssertion((string)($data['ticket'] ?? ''), (array)($data['credential'] ?? []), 'sign-in');
        if ($user === null) {
            $this->login->getRateLimiter('passkey_attempts')->registerRateLimitedAction($this->login->getIpKey(), 'ip');
            return $this->error('PLUGIN_LOGIN.PASSKEY_SIGN_IN_FAILED', 401);
        }

        $remember = !empty($data['rememberme']) && $this->grav['config']->get('plugins.login.rememberme.enabled');
        $event = $this->login->login(
            ['username' => (string)$user->get('username')],
            ['passkey' => true, 'twofa' => false, 'rate_limit' => false, 'remember_me' => $remember],
            ['user' => $user, 'return_event' => true]
        );
        $user = $event->getUser();
        if (!$user->authenticated || !$user->authorized) {
            $message = $event->getMessage() ?: 'PLUGIN_LOGIN.ACCESS_DENIED';
            return $this->error($message, 403);
        }

        $this->flash($this->translate($event->getMessage() ?: 'PLUGIN_LOGIN.LOGIN_SUCCESSFUL'), $event->getMessage() ? $event->getMessageType() : 'info');

        return [200, ['redirect' => $this->afterLogin($event->getRedirect())]];
    }

    /** A passkey in place of the authenticator-app code, after the password. */
    private function secondStep(array $data): array
    {
        $user = $this->pendingUser();
        if ($user === null) {
            return $this->error('PLUGIN_LOGIN.PASSKEY_EXPIRED', 410);
        }
        $username = (string)$user->get('username');

        if ($this->passkeys->verifyAssertion((string)($data['ticket'] ?? ''), (array)($data['credential'] ?? []), 'second-step', $user) === null) {
            $this->login->getRateLimiter('passkey_attempts')->registerRateLimitedAction($this->login->getIpKey(), 'ip');
            // Counts against the same cap as wrong app codes.
            $twofa = $this->login->getRateLimiter('twofa_attempts');
            $twofa->registerRateLimitedAction($username);
            if ($twofa->hasReachedLimit($username)) {
                $user->authenticated = false;
                $user->authorized = false;
                $this->grav['session']->invalidate()->start();
                return $this->error('PLUGIN_LOGIN.PASSKEY_EXPIRED', 410);
            }
            return $this->error('PLUGIN_LOGIN.PASSKEY_NOT_THIS_ACCOUNT', 401);
        }

        $this->login->getRateLimiter('twofa_attempts')->resetRateLimit($username);

        // As taskTwoFa() does when the code is right.
        $event = new UserLoginEvent([
            'credentials' => ['username' => $username],
            'options' => ['twofa' => true, 'passkey' => true],
        ]);
        $event->setUser($user);
        $event->setStatus(UserLoginEvent::AUTHENTICATION_SUCCESS | UserLoginEvent::AUTHORIZATION_CHALLENGE);
        $event->setMessage($this->translate('PLUGIN_LOGIN.LOGIN_SUCCESSFUL'), 'info');
        $this->grav->fireEvent('onUserLoginAuthorized', $event);

        $user = $event->getUser();
        $user->authenticated = $event->isSuccess();
        $user->authorized = !$event->isDelayed();
        if (!$user->authorized) {
            return $this->error('PLUGIN_LOGIN.ACCESS_DENIED', 403);
        }

        $this->flash((string)$event->getMessage(), $event->getMessageType() ?: 'info');

        return [200, ['redirect' => $this->afterLogin($event->getRedirect())]];
    }

    /**
     * Proof for adding or removing a passkey: the current password, or for an
     * account without one the current 2FA code when 2FA is on. Null when it
     * checks out. An account with neither can't change its passkeys.
     */
    private function proofError(UserInterface $user, array $data): ?array
    {
        if ($this->login->hasPassword($user)) {
            $result = $this->login->verifyCurrentPassword($user, (string)($data['password'] ?? ''));
            if ($result > 0) {
                return $this->error($this->translate(['PLUGIN_LOGIN.PASSKEY_PROOF_WAIT', $result]), 429);
            }
            return $result < 0 ? $this->error('PLUGIN_LOGIN.PASSKEY_PROOF_PASSWORD', 422, ['proof' => 'password']) : null;
        }
        if ($this->login->hasActiveTwoFactor($user)) {
            $error = $this->login->twoFactorCodeError($user, (string)($data['code'] ?? ''));
            return $error !== null ? $this->error($error, 422, ['proof' => 'code']) : null;
        }

        // Nothing to prove with (an account made by a sign-in service or a
        // magic link): a signed-in session alone must not add a way in that
        // outlives it.
        return $this->error('PLUGIN_LOGIN.PASSKEY_PROOF_NONE', 403, ['proof' => 'unavailable']);
    }

    /** The fully signed-in session user, or null. */
    private function signedInUser(): ?UserInterface
    {
        $user = $this->grav['user'] ?? null;

        return $user instanceof UserInterface && $user->exists() && $user->authenticated && $user->authorized ? $user : null;
    }

    /** The user waiting at the 2FA step (password accepted, code not yet), or null. */
    private function pendingUser(): ?UserInterface
    {
        $user = $this->grav['user'] ?? null;

        return $user instanceof UserInterface && $user->exists() && $user->authenticated && !$user->authorized
            && $this->login->hasActiveTwoFactor($user) ? $user : null;
    }

    /**
     * Where the page goes next, as the browser's URL for a route: the same
     * target a password sign-in redirects to (redirectLangSafe()).
     */
    private function afterLogin(?string $route = null): string
    {
        $route = $route ?: ($this->grav['session']->redirect_after_login ?: $this->login->getRoute('after_login') ?: '/');
        if (!is_string($route) || $this->grav['uri']->isExternal($route)) {
            $route = '/';
        }

        return $this->grav['pages']->route($route);
    }

    private function flash(string $message, string $type): void
    {
        if ($message !== '') {
            $this->grav['messages']->add($message, $type);
        }
    }

    /** @param string|array $key */
    private function translate($key): string
    {
        return (string)$this->grav['language']->translate($key);
    }

    private function error(string $message, int $status, array $extra = []): array
    {
        return [$status, ['error' => strpos($message, 'PLUGIN_LOGIN.') === 0 ? $this->translate($message) : $message] + $extra];
    }
}
