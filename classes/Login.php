<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2021 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login;

use Birke\Rememberme\Cookie;
use Grav\Common\Config\Config;
use Grav\Common\Data\Data;
use Grav\Common\Debugger;
use Grav\Common\Grav;
use Grav\Common\Language\Language;
use Grav\Common\Language\LanguageCodes;
use Grav\Common\Page\Interfaces\PageInterface;
use Grav\Common\Page\Page;
use Grav\Common\Page\Pages;
use Grav\Common\Security;
use Grav\Common\Session;
use Grav\Common\User\Interfaces\UserCollectionInterface;
use Grav\Common\User\Interfaces\UserInterface;
use Grav\Common\Uri;
use Grav\Common\Utils;
use Grav\Plugin\Login\Events\PageAuthorizeEvent;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Plugin\Login\Invitations\Invitation;
use Grav\Plugin\Login\RememberMe\RememberMe;
use Grav\Plugin\Login\RememberMe\TokenStorage;
use Grav\Plugin\Login\TwoFactorAuth\TwoFactorAuth;

/**
 * Class Login
 * @package Grav\Plugin
 */
class Login
{
    public const DEBUG = 0;

    /** @var int How long an email change confirmation link works, in seconds (one day). */
    public const EMAIL_CHANGE_TTL = 86400;

    /** @var Grav */
    protected $grav;

    /** @var Config */
    protected $config;

    /** @var Language $language */
    protected $language;

    /** @var Session */
    protected $session;

    /** @var Uri */
    protected $uri;

    /** @var RememberMe */
    protected $rememberMe;

    /** @var TwoFactorAuth */
    protected $twoFa;

    /** @var RateLimiter[] */
    protected $rateLimiters = [];

    /** @var array  */
    protected $provider_login_templates = [];

    /**
     * Login constructor.
     *
     * @param Grav $grav
     */
    public function __construct(Grav $grav)
    {
        $this->grav = $grav;
        $this->config = $this->grav['config'];
        $this->language = $this->grav['language'];
        $this->session = $this->grav['session'];
        $this->uri = $this->grav['uri'];
    }

    /**
     * @param string $message
     * @param object|array $data
     */
    public static function addDebugMessage(string $message, $data = []): void
    {
        /** @var Debugger $debugger */
        $debugger = Grav::instance()['debugger'];
        $debugger->addMessage($message, 'debug', $data);
    }

    /**
     * Whether the current session user is logged in, optionally narrowed to a
     * permission and/or group. Shared by the `authenticated()` Twig function
     * and the `[authenticated]` / `[guest]` shortcodes:
     *
     *     $grav['login']->isAuthenticated()                  fully logged in
     *     $grav['login']->isAuthenticated('admin.super')     logged in + authorized
     *     $grav['login']->isAuthenticated(null, 'editors')   logged in + in group
     *
     * `permission` and `group` each accept a single value or a list, and match
     * if the user satisfies any one of them. When both are given the user must
     * satisfy both.
     *
     * A session which has passed the password step but has not yet answered the
     * two-factor challenge is `authenticated` but not `authorized`, and is not
     * logged in for any of these checks.
     *
     * @param string|array|null $permission Permission action(s) to authorize.
     * @param string|array|null $group      Group name(s) the user must be in.
     */
    public function isAuthenticated($permission = null, $group = null): bool
    {
        $user = $this->grav['user'] ?? null;
        if (!$user instanceof UserInterface || !$user->authenticated) {
            return false;
        }

        // Two-factor challenge still open: the password step alone is not a login.
        // The permission branch below inherits this from UserObject::authorize(), but
        // the no-argument and group forms never reach it, so gate all three here.
        // Same test as Login::isUserAuthorizedForPage(). (GHSA-636m-8598-45r9)
        if (!$user->authorized) {
            return false;
        }

        // Group membership: pass if the user is in any of the named groups.
        if ($group !== null && !array_intersect((array)$group, (array)$user->get('groups', []))) {
            return false;
        }

        // Permission: pass if the user is authorized for any of the actions.
        if ($permission !== null) {
            foreach ((array)$permission as $action) {
                if ($user->authorize((string)$action) === true) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    /**
     * Login user.
     *
     * @param array $credentials    Login credentials, eg: ['username' => '', 'password' => '']
     * @param array $options        Login options, eg: ['remember_me' => true]
     * @param array $extra          Example: ['authorize' => 'site.login', 'user' => null], undefined variables get set.
     * @return UserInterface|UserLoginEvent  Returns event if $extra['return_event'] is true.
     */
    public function login(array $credentials, array $options = [], array $extra = [])
    {
        $grav = Grav::instance();

        $eventOptions = [
            'credentials' => $credentials,
            'options' => $options
        ] + $extra;

        // Attempt to authenticate the user.
        $event = new UserLoginEvent($eventOptions);
        $grav->fireEvent('onUserLoginAuthenticate', $event);

        if ($event->isSuccess()) {
            static::DEBUG && static::addDebugMessage('Login onUserLoginAuthenticate: success', $event);

            // Make sure that event didn't mess up with the user authorization.
            $user = $event->getUser();
            $user->authenticated = true;
            $user->authorized = false;

            // Allow plugins to prevent login after successful authentication.
            $event = new UserLoginEvent($event->toArray());
            $grav->fireEvent('onUserLoginAuthorize', $event);
        }

        if ($event->isSuccess()) {
            static::DEBUG && static::addDebugMessage('Login onUserLoginAuthorize: success', $event);

            // User has been logged in, let plugins know.
            $event = new UserLoginEvent($event->toArray());
            $grav->fireEvent('onUserLogin', $event);

            // Make sure that event didn't mess up with the user authorization.
            $user = $event->getUser();
            $user->authenticated = true;
            $user->authorized = !$event->isDelayed();
            if ($user->authorized) {
                $event = new UserLoginEvent($event->toArray());
                $this->grav->fireEvent('onUserLoginAuthorized', $event);
            }
        } else {
            static::DEBUG && static::addDebugMessage('Login failed', $event);

            // Allow plugins to log errors or do other tasks on failure.
            $eventName = $event->getOption('failureEvent') ?? 'onUserLoginFailure';
            $event = new UserLoginEvent($event->toArray());
            $grav->fireEvent($eventName, $event);

            // Make sure that event didn't mess up with the user authorization.
            $user = $event->getUser();
            $user->authenticated = false;
            $user->authorized = false;
        }

        $user = $event->getUser();
        $user->def('language', 'en');

        return !empty($event['return_event']) ? $event : $user;
    }

    /**
     * Logout user.
     *
     * @param array                         $options
     * @param array|UserInterface           $extra      Array of: ['user' => $user, ...] or UserInterface object (deprecated).
     * @return UserInterface|UserLoginEvent Returns event if $extra['return_event'] is true.
     */
    public function logout(array $options = [], $extra = [])
    {
        $grav = Grav::instance();

        if ($extra instanceof UserInterface) {
            user_error(__METHOD__ . '($options, $user) is deprecated since Login Plugin 3.5.0, use logout($options, [\'user\' => $user]) instead', E_USER_DEPRECATED);

            $extra = ['user' => $extra];
        } elseif (isset($extra['user'])) {
            $extra['user'] = $grav['user'];
        }

        $eventOptions = [
            'options' => $options
        ] + $extra;

        $event = new UserLoginEvent($eventOptions);

        // Logout the user.
        $grav->fireEvent('onUserLogout', $event);

        $user = $event->getUser();
        $user->authenticated = false;
        $user->authorized = false;

        return !empty($event['return_event']) ? $event : $user;
    }

    /**
     * Authenticate user.
     *
     * @param array $credentials Form fields.
     * @param array $options
     *
     * @return bool
     * @deprecated Uses the Controller::taskLogin() event
     */
    public function authenticate($credentials, $options = ['remember_me' => true])
    {
        $event = $this->login($credentials, $options, ['return_event' => true]);
        $user = $event['user'];

        $redirect = $event->getRedirect();
        $message = $event->getMessage();
        $messageType = $event->getMessageType();

        if ($user->authenticated && $user->authorized) {
            if (!$message) {
                $message = 'PLUGIN_LOGIN.LOGIN_SUCCESSFUL';
                $messageType = 'info';
            }

            if (!$redirect) {
                $redirect = $this->uri->route();
            }
        }

        if ($message) {
            $this->grav['messages']->add($this->language->translate($message, [$user->language]), $messageType);
        }

        if ($redirect) {
            $this->grav->redirectLangSafe($redirect, $event->getRedirectCode());
        }

        return $user->authenticated && $user->authorized;
    }

    /**
     * Create a new user file
     *
     * @param array $data
     * @param array $files
     *
     * @return UserInterface
     */
    public function register(array $data, array $files = [])
    {
        // Add defaults and mandatory fields.
        $data += [
            'username' => null,
            'email' => null
        ];

        if (!isset($data['groups'])) {
            //Add new user ACL settings
            $groups = (array) $this->config->get('plugins.login.user_registration.groups', []);
            if (\count($groups) > 0) {
                $data['groups'] = $groups;
            }
        }

        if (!isset($data['access'])) {
            $access = (array) $this->config->get('plugins.login.user_registration.access.site', []);
            if (\count($access) > 0) {
                $data['access']['site'] = $access;
            }
        }

        // Validate fields from the form.
        $password = $this->validateField('password1', $data['password'] ?? $data['password1'] ?? null);
        foreach ($data as $key => &$value) {
            $value = $this->validateField($key, $value, $key === 'password2' ? $password : '');
        }
        unset($value);

        /** @var UserCollectionInterface $accounts */
        $accounts = $this->grav['accounts'];

        // Check whether username already exists.
        $username = $data['username'];
        if (!$username || $accounts->find($username, ['username'])->exists()) {
            /** @var Language $language */
            $language = $this->grav['language'];

            throw new \RuntimeException($language->translate(['PLUGIN_LOGIN.USERNAME_NOT_AVAILABLE', $username]));
        }
        // Check whether email already exists.
        $email = $data['email'];
        if (!$email || $accounts->find($email, ['email'])->exists()) {
            /** @var Language $language */
            $language = $this->grav['language'];

            throw new \RuntimeException($language->translate(['PLUGIN_LOGIN.EMAIL_NOT_AVAILABLE', $email]));
        }

        $user = $accounts->load($username);
        $user->update($data, $files);
        if (isset($data['groups'])) {
            $user->groups = $data['groups'];
        }
        if (isset($data['access'])) {
            $user->access = $data['access'];
        }
        $user->save();

        return $user;
    }

    /**
     * @param string $username
     * @param string|null $ip
     * @return int Return positive number if rate limited, otherwise return 0.
     */
    public function checkLoginRateLimit(string $username, ?string $ip = null): int
    {
        $ipKey = $this->getIpKey($ip);
        $rateLimiter = $this->getRateLimiter('login_attempts');

        // Refuse at the limit without registering the attempt, so retrying while
        // locked out can't keep pushing the end of the lockout further away.
        if (!$rateLimiter->hasReachedLimit($ipKey, 'ip') && !$rateLimiter->hasReachedLimit($username)) {
            // Link the IP counter to the username so an administrator unlocking the
            // account can clear the IP side too.
            $rateLimiter->registerRateLimitedAction($ipKey, 'ip', ['username' => $username])
                ->registerRateLimitedAction($username);

            return 0;
        }

        // Still record which account was tried from a locked IP, without counting
        // the attempt, so the lockout lists and unlock-user can find it.
        $rateLimiter->addLinks($ipKey, 'ip', ['username' => $username]);

        $seconds = max($rateLimiter->getRetryAfter($ipKey, 'ip'), $rateLimiter->getRetryAfter($username));

        // The oldest attempt can expire between the check above and this one.
        return max(1, (int)ceil($seconds / 60));
    }

    /**
     * @param string $username
     * @param string|null $ip
     */
    public function resetLoginRateLimit(string $username, ?string $ip = null): void
    {
        $ipKey = $this->getIpKey($ip);
        $rateLimiter = $this->getRateLimiter('login_attempts');
        $rateLimiter->resetRateLimit($ipKey, 'ip')->resetRateLimit($username);
    }

    /**
     * Whether the account has a password of its own. An account created by a
     * sign-in service (OAuth2, LDAP and the like) may have none, and then
     * there is no current password to ask for before setting one. Read from
     * the stored account, like hasActiveTwoFactor().
     *
     * @param UserInterface $user
     * @return bool
     */
    public function hasPassword(UserInterface $user): bool
    {
        $stored = $this->loadStoredAccount($user);
        $hash = $stored->get('hashed_password');
        $plain = $stored->get('password');

        return (is_string($hash) && $hash !== '') || (is_string($plain) && $plain !== '');
    }

    /**
     * Check the current password someone typed to change their own. Each try
     * counts against the same limits as signing in (per account and per IP),
     * so the form can't be used to guess the password, and a right password
     * clears the count the way a successful sign-in does.
     *
     * Checked against the stored account rather than the session's copy.
     *
     * @param UserInterface $user
     * @param string $password
     * @return int 0 when the password is right, -1 when it is wrong, or the minutes
     *             to wait when too many wrong passwords were tried.
     */
    public function verifyCurrentPassword(UserInterface $user, string $password): int
    {
        $username = (string)$user->get('username');

        $wait = $this->checkLoginRateLimit($username);
        if ($wait > 0) {
            return $wait;
        }

        /** @var UserCollectionInterface $accounts */
        $accounts = $this->grav['accounts'];
        $stored = $accounts->load($username);
        if (is_callable([$stored, 'refresh'])) {
            $stored->refresh(true);
        }

        if ($password === '' || !$stored->exists() || !$stored->authenticate($password)) {
            return -1;
        }

        $this->resetLoginRateLimit($username);

        return 0;
    }

    /**
     * Whether the stored account has 2-Factor Authentication switched on with a
     * secret to check codes against. Read from the stored account, so a session
     * copy from before 2FA was turned on elsewhere can't skip the code.
     *
     * @param UserInterface $user
     * @return bool
     */
    public function hasActiveTwoFactor(UserInterface $user): bool
    {
        $stored = $this->loadStoredAccount($user);

        return (bool)$stored->get('twofa_enabled') && (string)$stored->get('twofa_secret') !== '';
    }

    /**
     * Check a current 2FA code someone typed to turn off or replace their
     * second factor. Wrong codes count against the same limit as the sign-in
     * challenge (twofa_attempts), and a right one clears it.
     *
     * @param UserInterface $user
     * @param string|null $code
     * @return int 0 when the code is right, -1 when it is wrong, or the minutes
     *             to wait when too many wrong codes were tried.
     */
    public function verifyCurrentTwoFactorCode(UserInterface $user, ?string $code): int
    {
        $username = (string)$user->get('username');
        $limiter = $this->getRateLimiter('twofa_attempts');
        if ($limiter->hasReachedLimit($username)) {
            return max(1, (int)ceil($limiter->getRetryAfter($username) / 60));
        }

        $secret = (string)$this->loadStoredAccount($user)->get('twofa_secret');
        $code = trim((string)$code);
        if ($code === '' || $secret === '' || !$this->twoFactorAuth()->verifyCode($secret, $code)) {
            $limiter->registerRateLimitedAction($username);

            return -1;
        }

        $limiter->resetRateLimit($username);

        return 0;
    }

    /**
     * Check the current 2FA code given to turn off or replace an active second
     * factor, and say why it was refused (null when it is right).
     *
     * @param UserInterface $user
     * @param mixed $code
     * @return string|null
     */
    public function twoFactorCodeError(UserInterface $user, $code): ?string
    {
        /** @var Language $language */
        $language = $this->grav['language'];

        if (!is_string($code) || trim($code) === '') {
            return $language->translate('PLUGIN_LOGIN.2FA_CODE_REQUIRED');
        }

        $result = $this->verifyCurrentTwoFactorCode($user, $code);
        if ($result > 0) {
            return $language->translate(['PLUGIN_LOGIN.2FA_CODE_TOO_MANY', $result]);
        }
        if ($result < 0) {
            return $language->translate('PLUGIN_LOGIN.2FA_CODE_WRONG');
        }

        return null;
    }

    /**
     * @param UserInterface $user
     * @return UserInterface The account as stored, freshly read.
     */
    protected function loadStoredAccount(UserInterface $user): UserInterface
    {
        /** @var UserCollectionInterface $accounts */
        $accounts = $this->grav['accounts'];
        $stored = $accounts->load((string)$user->get('username'));
        if ($stored !== $user && is_callable([$stored, 'refresh'])) {
            $stored->refresh(true);
        }

        return $stored->exists() ? $stored : $user;
    }

    /**
     * Sign an account out everywhere else after its password changed. Stamps
     * `api_tokens_valid_after`, which API tokens and signed-in browsers are
     * checked against (see isSessionOutdated()), and forgets the account's
     * remember-me cookies. When the account changes its own password the
     * browser making the change stays signed in: its session gets the same
     * stamp, and a remember-me cookie it had is issued again. Pass
     * `$keepCurrent = false` when someone else changed it.
     *
     * The caller saves the account.
     *
     * @param UserInterface $user
     * @param bool $keepCurrent
     * @return void
     */
    public function endOtherSessions(UserInterface $user, bool $keepCurrent = true): void
    {
        $now = time();
        $username = (string)$user->get('username');
        $user->set('api_tokens_valid_after', $now);

        $sessionUser = null;
        if ($keepCurrent) {
            /** @var Session $session */
            $session = $this->grav['session'];
            $sessionUser = $session->isStarted() ? ($session->user ?? null) : null;
        }
        $ownSession = $sessionUser instanceof UserInterface
            && $sessionUser->authenticated
            && (string)$sessionUser->get('username') === $username;
        if ($ownSession && $sessionUser !== $user) {
            $sessionUser->set('api_tokens_valid_after', $now);
        }

        if ($username === '' || !$this->grav['config']->get('plugins.login.rememberme.enabled')) {
            return;
        }

        $rememberMe = $this->rememberMe();
        $cookie = $_COOKIE[(string)$this->grav['config']->get('plugins.login.rememberme.name')] ?? '';
        $keepCookie = $ownSession
            && is_string($cookie)
            && explode('|', $cookie, 2)[0] === $username
            && $rememberMe->cookieIsValid();

        $rememberMe->getStorage()->cleanAllTriplets($username);
        if ($keepCookie) {
            $rememberMe->createCookie($username);
        }
    }

    /**
     * Whether a signed-in session began before the account's password last
     * changed (or before it was otherwise signed out everywhere), so it has to
     * sign in again. Compares the session copy's `api_tokens_valid_after` with
     * the stored account's.
     *
     * @param UserInterface $sessionUser
     * @return bool
     */
    public function isSessionOutdated(UserInterface $sessionUser): bool
    {
        if (!$sessionUser->exists() || !$sessionUser->authenticated) {
            return false;
        }

        /** @var UserCollectionInterface $accounts */
        $accounts = $this->grav['accounts'];
        $stored = $accounts->load((string)$sessionUser->get('username'));
        if ($stored === $sessionUser || !$stored->exists()) {
            return false;
        }
        if (is_callable([$stored, 'refresh'])) {
            $stored->refresh(true);
        }

        $cutoff = (int)$stored->get('api_tokens_valid_after', 0);

        return $cutoff > 0 && (int)$sessionUser->get('api_tokens_valid_after', 0) < $cutoff;
    }

    /**
     * The rate limiter contexts an administrator can clear on someone's behalf.
     *
     * @return array<int, string>
     */
    public static function getRateLimitContexts(): array
    {
        return ['login_attempts', 'twofa_attempts', 'pw_resets', 'magic_links', 'token_attempts', 'registrations', 'email_changes'];
    }

    /**
     * Every account currently locked out of logging in.
     *
     * Mirrors checkLoginRateLimit(): an account counts as locked when its own
     * counter has reached the limit, or when an IP it has been tried from has. The
     * whole set is resolved in one sweep of the index so that listing N accounts
     * costs one pass, not N.
     *
     * @return array<string, array{attempts: int, last: int|null, by_ip: bool}> Keyed by username.
     */
    public function getLockedAccounts(): array
    {
        $rateLimiter = $this->getRateLimiter('login_attempts');

        $locked = [];
        foreach ($rateLimiter->getRegisteredKeys(null, true, true) as $entry) {
            if ($entry['type'] === 'username') {
                $existing = $locked[$entry['key']] ?? ['attempts' => 0, 'last' => null, 'by_ip' => false];
                $locked[$entry['key']] = [
                    'attempts' => max($existing['attempts'], $entry['attempts']),
                    'last' => max($existing['last'], $entry['last']),
                    'by_ip' => $existing['by_ip'],
                ];
                continue;
            }

            // A limited IP locks out every account tried from it.
            foreach (array_keys($entry['links']['username'] ?? []) as $username) {
                $existing = $locked[$username] ?? ['attempts' => 0, 'last' => null, 'by_ip' => false];
                $locked[$username] = [
                    'attempts' => max($existing['attempts'], $entry['attempts']),
                    'last' => max($existing['last'], $entry['last']),
                    'by_ip' => true,
                ];
            }
        }

        return $locked;
    }

    /**
     * Is this account currently locked out of logging in?
     *
     * @param string $username
     * @return bool
     */
    public function isAccountLocked(string $username): bool
    {
        return $username !== '' && isset($this->getLockedAccounts()[$username]);
    }

    /**
     * Clear every rate limit standing against an account, across all contexts.
     *
     * @param string $username
     * @return int Number of counters that existed and were cleared.
     */
    public function unlockUser(string $username): int
    {
        if ($username === '') {
            return 0;
        }

        $cleared = 0;
        foreach (static::getRateLimitContexts() as $context) {
            $cleared += $this->getRateLimiter($context)->resetRelatedRateLimits($username);
        }

        return $cleared;
    }

    /**
     * Clear every rate limit registered against an IP address, across all contexts.
     *
     * @param string $ip
     * @return int Number of counters that existed and were cleared.
     */
    public function unlockIp(string $ip): int
    {
        if ($ip === '') {
            return 0;
        }

        $ipKey = $this->getIpKey($ip);

        $cleared = 0;
        foreach (static::getRateLimitContexts() as $context) {
            $cleared += $this->getRateLimiter($context)->resetRelatedRateLimits($ipKey, 'ip');
        }

        return $cleared;
    }

    /**
     * Wipe every rate limiter counter in every context.
     *
     * @return void
     */
    public function unlockAll(): void
    {
        foreach (static::getRateLimitContexts() as $context) {
            $this->getRateLimiter($context)->resetAllRateLimits();
        }
    }

    /**
     * Every key currently registered with a rate limiter, keyed by context.
     *
     * @param bool $limitedOnly Only include keys that are currently over the limit.
     * @return array<string, array<int, array<string, mixed>>>
     */
    public function getRateLimitedKeys(bool $limitedOnly = true): array
    {
        $out = [];
        foreach (static::getRateLimitContexts() as $context) {
            $entries = $this->getRateLimiter($context)->getRegisteredKeys(null, $limitedOnly, $context === 'login_attempts');
            if ($entries) {
                $out[$context] = $entries;
            }
        }

        return $out;
    }

    /**
     * @param string|null $ip
     * @return string
     */
    public function getIpKey(?string $ip = null): string
    {
        if (null === $ip) {
            $ip = Uri::ip();
        }
        $isIPv4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        $ipKey = $isIPv4 ? $ip : Utils::getSubnet($ip, $this->grav['config']->get('plugins.login.ipv6_subnet_size'));

        // Pseudonymization of the IP. Grav 2.0 moved the HMAC key out of Config
        // (GHSA-3f29-pqwf-v4j4); fall back to the legacy key on Grav 1.7.
        $key = method_exists(Security::class, 'getNonceKey')
            ? Security::getNonceKey()
            : (string) $this->grav['config']->get('security.salt');

        return sha1($ipKey . $key);
    }

    /**
     * @param string $type
     * @param mixed  $value
     * @param string $extra
     *
     * @return string
     */
    public function validateField($type, $value, $extra = '')
    {
        switch ($type) {
            case 'user':
            case 'username':
                /** @var Config $config */
                $config = Grav::instance()['config'];
                $username_regex = '/' . $config->get('system.username_regex') . '/';

                $value = \is_string($value) ? trim($value) : '';
                if ($value === '' || !preg_match($username_regex, $value)) {
                    throw new \RuntimeException('Username does not pass the minimum requirements');
                }

                break;

            case 'password':
            case 'password1':
                /** @var Config $config */
                $config = Grav::instance()['config'];
                $pwd_regex = '/' . $config->get('system.pwd_regex') . '/';

                $value = \is_string($value) ? $value : '';
                if ($value === '' || !preg_match($pwd_regex, $value)) {
                    throw new \RuntimeException('Password does not pass the minimum requirements');
                }

                break;

            case 'password2':
                $value = \is_string($value) ? $value : '';
                if ($value === '' || $value !== $extra) {
                    throw new \RuntimeException('Passwords did not match.');
                }

                break;

            case 'email':
                $value = \is_string($value) ? trim($value) : '';
                if ($value === '' || !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    throw new \RuntimeException('Not a valid email address');
                }

                break;

            case 'permissions':
                if (!\in_array($value, ['a', 's', 'b'], true)) {
                    throw new \RuntimeException('Permissions ' . $value . ' are invalid.');
                }

                break;

            case 'state':
                if ($value !== 'enabled' && $value !== 'disabled') {
                    throw new \RuntimeException('State is not valid');
                }

                break;

            case 'language':
                $languages = new LanguageCodes();
                if ($value !== null && !array_key_exists($value, $languages->getList())) {
                    throw new \RuntimeException('Language code is not valid');
                }

                break;
        }

        return $value;
    }

    /**
     * Handle the email to notify the user account creation to the site admin.
     *
     * @param UserInterface $user
     *
     * @return bool True if the action was performed.
     * @throws \RuntimeException
     */
    public function sendNotificationEmail(UserInterface $user)
    {
        if (empty($user->email)) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.USER_NEEDS_EMAIL_FIELD'));
        }

        try {
            Email::sendNotificationEmail($user);
        } catch (\Exception $e) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_SENDING_FAILURE'));
        }

        return true;
    }

    /**
     * Handle the email to welcome the new user
     *
     * @param UserInterface $user
     *
     * @return bool True if the action was performed.
     * @throws \RuntimeException
     */
    public function sendWelcomeEmail(UserInterface $user)
    {
        if (empty($user->email)) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.USER_NEEDS_EMAIL_FIELD'));
        }

        try {
            Email::sendWelcomeEmail($user);
        } catch (\Exception $e) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_SENDING_FAILURE'));
        }

        return true;
    }

    /**
     * Handle the email to activate the user account.
     *
     * @param UserInterface $user
     *
     * @return bool True if the action was performed.
     * @throws \RuntimeException
     */
    public function sendActivationEmail(UserInterface $user)
    {
        if (empty($user->email)) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.USER_NEEDS_EMAIL_FIELD'));
        }

        try {
            $random_bytes = random_bytes(16);
        } catch (\Exception $e) {
            $random_bytes = mt_rand();
        }

        $token = md5(uniqid($random_bytes, true));
        $expire = time() + 604800; // next week
        $user->activation_token = $token . '::' . $expire;
        // The link only proves the address it was mailed to, so remember which one.
        $user->activation_email = (string)$user->email;
        $user->save();

        try {
            Email::sendActivationEmail($user);
        } catch (\Exception $e) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_SENDING_FAILURE'));
        }

        return true;
    }

    /**
     * Whether the account's current email address has been proven by its owner.
     *
     * True when the address on the account is the one recorded by the last
     * confirmed email change or account activation. An administrator editing the
     * address afterwards, or a profile save with `profile.verify_email_change`
     * turned off, makes this false again until the new address is confirmed.
     *
     * @param UserInterface $user
     * @return bool
     */
    public function isEmailVerified(UserInterface $user): bool
    {
        $email = trim((string)$user->get('email', ''));
        $verified = trim((string)$user->get('email_verified', ''));

        return $email !== '' && $verified !== '' && mb_strtolower($email) === mb_strtolower($verified);
    }

    /**
     * Record that the account's current email address has been proven.
     *
     * Sets `email_verified` (the address) and `email_verified_at` (a Unix
     * timestamp). The caller saves the account.
     *
     * @param UserInterface $user
     * @return void
     */
    public function markEmailVerified(UserInterface $user): void
    {
        $user->email_verified = (string)$user->get('email', '');
        $user->email_verified_at = time();
    }

    /**
     * Whether an address already belongs to an account other than this one.
     *
     * @param UserInterface $user
     * @param string $email
     * @return bool
     */
    public function emailBelongsToAnother(UserInterface $user, string $email): bool
    {
        /** @var UserCollectionInterface $users */
        $users = $this->grav['accounts'];
        $existing = $users->find($email, ['email']);

        return $existing->exists() && $existing->username !== $user->username;
    }

    /**
     * Start an email change: keep the new address as pending on the account and
     * mail a confirmation link to it. The account's `email` is left alone until
     * the link is opened. A second request replaces the first one, so an older
     * link stops working.
     *
     * When the address already belongs to another account nothing is mailed,
     * but the account still shows the change as waiting, so the profile form
     * answers the same way it does for a free address.
     *
     * @param UserInterface $user
     * @param string $email
     * @return bool True if the action was performed.
     * @throws \RuntimeException
     */
    public function requestEmailChange(UserInterface $user, string $email)
    {
        try {
            $token = bin2hex(random_bytes(16));
        } catch (\Exception $e) {
            $token = md5(uniqid((string)mt_rand(), true));
        }

        $expire = time() + static::EMAIL_CHANGE_TTL;

        $user->email_pending = $email;
        $user->email_change_token = $token . '::' . $expire;
        $user->save();

        if ($this->emailBelongsToAnother($user, $email)) {
            $this->grav['log']->info(sprintf('plugin.login: email change for "%s" not mailed, the address belongs to another account', $user->username));

            return true;
        }

        try {
            Email::sendEmailChangeEmail($user);
        } catch (\Exception $e) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_SENDING_FAILURE'));
        }

        return true;
    }

    /**
     * Copy the email fields from the stored account onto the session's copy.
     *
     * The session keeps its own copy of the account, and the confirmation link
     * is often opened in another browser. Without this, the profile page would
     * show the old address and the next profile save would write it back.
     *
     * @param UserInterface $user
     * @return void
     */
    public function refreshEmailFields(UserInterface $user): void
    {
        $this->refreshStoredFields($user, ['email', 'email_pending', 'email_change_token', 'email_verified', 'email_verified_at']);
    }

    /**
     * Copy the 2-Factor Authentication fields from the stored account onto the
     * session's copy, for the same reason as refreshEmailFields(): 2FA turned
     * on or off in the admin or another browser would otherwise show wrongly
     * on the profile page and be written back by the next profile save.
     *
     * @param UserInterface $user
     * @return void
     */
    public function refreshTwoFactorFields(UserInterface $user): void
    {
        $this->refreshStoredFields($user, ['twofa_enabled', 'twofa_secret']);
    }

    /**
     * @param UserInterface $user
     * @param array<int, string> $fields
     * @return void
     */
    protected function refreshStoredFields(UserInterface $user, array $fields): void
    {
        if (!$user->exists()) {
            return;
        }

        /** @var UserCollectionInterface $users */
        $users = $this->grav['accounts'];
        $stored = $users->load($user->username);
        if ($stored === $user || !$stored->exists()) {
            return;
        }
        if (is_callable([$stored, 'refresh'])) {
            $stored->refresh(true);
        }

        foreach ($fields as $field) {
            $value = $stored->get($field);
            if ($value === null) {
                unset($user->{$field});
            } else {
                $user->{$field} = $value;
            }
        }
    }

    /**
     * Drop a waiting email change. The caller saves the account.
     *
     * @param UserInterface $user
     * @return void
     */
    public function clearEmailChange(UserInterface $user): void
    {
        unset($user->email_pending, $user->email_change_token);
    }

    /**
     * Tell the old address that the account's email has changed. A delivery
     * failure is logged, since the change itself has already happened.
     *
     * @param UserInterface $user
     * @param string $oldEmail
     * @return bool True if the action was performed.
     */
    public function sendEmailChangedNotice(UserInterface $user, string $oldEmail)
    {
        if ($oldEmail === '') {
            return false;
        }

        try {
            Email::sendEmailChangedNotice($user, $oldEmail);
        } catch (\Exception $e) {
            $this->grav['log']->error('plugin.login: could not send email changed notice: ' . $e->getMessage());

            return false;
        }

        return true;
    }

    /**
     * Tell the owner of an address that someone tried to register with it.
     *
     * Sent instead of telling the person at the registration form that the
     * address is taken (GHSA-crh8-xm27-j9g9). A delivery failure must not
     * change what that person sees, so it is logged rather than thrown.
     *
     * @param UserInterface $user
     * @return bool True if the action was performed.
     */
    public function sendAlreadyRegisteredEmail(UserInterface $user)
    {
        if (empty($user->email)) {
            return false;
        }

        try {
            Email::sendAlreadyRegisteredEmail($user);
        } catch (\Exception $e) {
            $this->grav['log']->error('plugin.login: could not send already-registered notice: ' . $e->getMessage());

            return false;
        }

        return true;
    }

    /**
     * Handle the email to invite user.
     *
     * @param Invitation $invitation
     * @param string|null $message
     * @param UserInterface|null $user
     * @return bool True if the action was performed.
     * @throws \RuntimeException
     */
    public function sendInviteEmail(Invitation $invitation, ?string $message = null, ?UserInterface $user = null)
    {
        try {
            Email::sendInvitationEmail($invitation, $message, $user);
        } catch (\Exception $e) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_SENDING_FAILURE'));
        }

        return true;
    }

    /**
     * Handle the email to login user by one-time link.
     *
     * @param UserInterface $user
     * @param string $token
     * @return bool True if the action was performed.
     * @throws \RuntimeException
     */
    public function sendMagicLoginEmail(UserInterface $user, string $token)
    {
        if (empty($user->email)) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.USER_NEEDS_EMAIL_FIELD'));
        }

        try {
            Email::sendMagicLoginEmail($user, $token);
        } catch (\Exception $e) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_SENDING_FAILURE'));
        }

        return true;
    }

    /**
     * Gets and sets the RememberMe class
     *
     * @param  mixed $var A rememberMe instance to set
     *
     * @return RememberMe Returns the current rememberMe instance
     * @throws \InvalidArgumentException
     */
    public function rememberMe($var = null)
    {
        if ($var !== null) {
            $this->rememberMe = $var;
        }

        if (!$this->rememberMe) {
            /** @var Config $config */
            $config = $this->grav['config'];
            $cookieName = $config->get('plugins.login.rememberme.name');
            $timeout = $config->get('plugins.login.rememberme.timeout');

            // Setup storage for RememberMe cookies
            $storage = new TokenStorage('user-data://rememberme', $timeout);
            $this->rememberMe = new RememberMe($storage);
            $this->rememberMe->setCookieName($cookieName);
            $this->rememberMe->setExpireTime($timeout);

            // Hardening cookies with user-agent and random salt or
            // fallback to use system based cache key. Grav 2.0 moved the HMAC key
            // out of Config (GHSA-3f29-pqwf-v4j4); use it when available.
            $server_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            $saltKey = method_exists(Security::class, 'getNonceKey')
                ? Security::getNonceKey()
                : (string) $config->get('security.salt', $this->grav['cache']->getKey());
            $data = $server_agent . $saltKey;
            $this->rememberMe->setSalt(hash('sha512', $data));

            // Set cookie with correct base path of Grav install
            $cookie = new Cookie;
            $cookie->setPath($this->grav['base_url_relative'] ?: '/');
            $this->rememberMe->setCookie($cookie);
        }

        return $this->rememberMe;
    }

    /**
     * Gets and sets the TwoFactorAuth object
     *
     * @param TwoFactorAuth $var
     * @return TwoFactorAuth
     * @throws \RobThree\Auth\TwoFactorAuthException
     */
    public function twoFactorAuth($var = null)
    {
        if ($var !== null) {
            $this->twoFa = $var;
        }

        if (!$this->twoFa) {
            $this->twoFa = new TwoFactorAuth;
        }

        return $this->twoFa;
    }

    /**
     * @param string $context
     * @param int $maxCount
     * @param int $interval
     * @return RateLimiter
     */
    public function getRateLimiter($context, $maxCount = null, $interval = null)
    {
        if (!isset($this->rateLimiters[$context])) {
            switch ($context) {
                case 'login_attempts':
                    $maxCount = $this->grav['config']->get('plugins.login.max_login_count', 5);
                    $interval = $this->grav['config']->get('plugins.login.max_login_interval', 10);
                    break;
                case 'pw_resets':
                    $maxCount = $this->grav['config']->get('plugins.login.max_pw_resets_count', 2);
                    $interval = $this->grav['config']->get('plugins.login.max_pw_resets_interval', 60);
                    break;
                case 'token_attempts':
                    $maxCount = $this->grav['config']->get('plugins.login.max_token_attempts_count', 5);
                    $interval = $this->grav['config']->get('plugins.login.max_token_attempts_interval', 60);
                    break;
                case 'twofa_attempts':
                    // The 2FA code is six digits with three valid windows, so the
                    // throttle IS the second factor's boundary, not depth behind
                    // it. It needs its own counter: login_attempts is cleared the
                    // moment the password verifies, which is exactly what an
                    // attacker re-doing the password to get a fresh challenge does.
                    $maxCount = $this->grav['config']->get('plugins.login.max_twofa_count', 5);
                    $interval = $this->grav['config']->get('plugins.login.max_twofa_interval', 10);
                    break;
                case 'registrations':
                    $maxCount = $this->grav['config']->get('plugins.login.user_registration.max_attempts_count', 10);
                    $interval = $this->grav['config']->get('plugins.login.user_registration.max_attempts_interval', 60);
                    break;
                case 'magic_links':
                    $maxCount = $this->grav['config']->get('plugins.login.magic_link.max_requests_count', 3);
                    $interval = $this->grav['config']->get('plugins.login.magic_link.max_requests_interval', 60);
                    break;
                case 'email_changes':
                    $maxCount = $this->grav['config']->get('plugins.login.profile.max_email_changes_count', 5);
                    $interval = $this->grav['config']->get('plugins.login.profile.max_email_changes_interval', 60);
                    break;
            }
            $this->rateLimiters[$context] = new RateLimiter($context, $maxCount, $interval);
        }

        return $this->rateLimiters[$context];
    }

    /**
     * @param string $type
     * @param string|null $route
     * @param PageInterface|null $page
     * @return PageInterface|null
     */
    public function getPage(string $type, ?string $route = null, ?PageInterface $page = null): ?PageInterface
    {
        $route = $route ?? $this->getRoute($type, true);
        if (null === $route) {
            return null;
        }

        // Password-reset URLs carry a bearer credential. Never render a
        // user-authored page at that route: page content is sandboxed, but it
        // can still read request parameters and ordinary template variables.
        // The bundled page and trusted template are the only renderers allowed
        // to receive the reset request.
        if ($type === 'reset') {
            $page = null;
        } elseif ($page) {
            $page->route($route);
            $page->slug(basename($route));
        } else {
            /** @var Pages $pages */
            $pages = $this->grav['pages'];
            $page = $pages->find($route);
        }

        if (!$page instanceof PageInterface) {
            // Only add login page if it hasn't already been defined.
            $page = new Page();
            $page->init(new \SplFileInfo('plugin://login/pages/' . $type . '.md'));
            $page->route($route);
            $page->slug(basename($route));
            $this->translatePageTitle($page, $type);
        }

        // Login page may not have the correct Cache-Control header set, force no-store for the proxies.
        $cacheControl = $page->cacheControl();
        if (!$cacheControl) {
            $page->cacheControl('private, no-cache, must-revalidate');
        }

        return $page;
    }

    /**
     * Translate the title of a page the plugin provides itself.
     *
     * Page frontmatter is plain YAML: `title:` is never run through the
     * translator, and Twig in frontmatter is gated off by default on Grav 2, so
     * there is no in-content equivalent for the title the way there is for the
     * body ([translate] shortcode). Only pages the plugin built are touched: a
     * page the site provides at the same route keeps its own title.
     *
     * @param PageInterface $page
     * @param string $type
     * @return void
     */
    protected function translatePageTitle(PageInterface $page, string $type): void
    {
        $keys = [
            'login' => 'PLUGIN_LOGIN.LOGIN_PAGE_TITLE',
            'forgot' => 'PLUGIN_LOGIN.FORGOT_PAGE_TITLE',
            'magic' => 'PLUGIN_LOGIN.MAGIC_PAGE_TITLE',
            'reset' => 'PLUGIN_LOGIN.RESET_PAGE_TITLE',
            'register' => 'PLUGIN_LOGIN.REGISTER_PAGE_TITLE',
            'profile' => 'PLUGIN_LOGIN.PROFILE_PAGE_TITLE',
            'unauthorized' => 'PLUGIN_LOGIN.UNAUTHORIZED_PAGE_TITLE',
        ];

        $key = $keys[$type] ?? null;
        if (null === $key) {
            return;
        }

        /** @var Language $language */
        $language = $this->grav['language'];
        $title = $language->translate([$key]);

        // translate() hands back the key itself when nothing matched.
        if ($title !== $key && $title !== '') {
            $page->title($title);
        }
    }

    /**
     * Add Login page.
     *
     * @param string $type
     * @param string|null $route Optional route if we want to force-add the page.
     * @param PageInterface|null $page
     * @return PageInterface|null
     */
    public function addPage(string $type, ?string $route = null, ?PageInterface $page = null): ?PageInterface
    {
        $page = $this->getPage($type, $route, $page);
        if (null === $page) {
            return null;
        }

        /** @var Pages $pages */
        $pages = $this->grav['pages'];
        $pages->addPage($page, $route);

        return $page;
    }

    /**
     * Get route to a given login page.
     *
     * @param string $type Use one of: login, activate, confirm_email, forgot, reset, magic, magic_login, profile, unauthorized,
     *                     after_login, after_logout, register, after_registration, after_activation
     * @param bool|null $enabled
     * @return string|null Returns route or null if the route has been disabled.
     */
    public function getRoute(string $type, ?bool $enabled = null): ?string
    {
        switch ($type) {
            case 'login':
                $route = $this->config->get('plugins.login.route');
                break;
            case 'activate':
            case 'confirm_email':
            case 'forgot':
            case 'reset':
            case 'magic':
            case 'magic_login':
            case 'profile':
                $route = $this->config->get('plugins.login.route_' . $type);
                break;
            case 'unauthorized':
                $route = $this->config->get('plugins.login.route_' . $type, '/');
                break;
            case 'after_login':
            case 'after_logout':
                $route = $this->config->get('plugins.login.redirect_' . $type);
                if ($route === true) {
                    $route = $this->config->get('plugins.login.route_' . $type);
                }
                break;
            case 'register':
                $enabled = $enabled ?? $this->config->get('plugins.login.user_registration.enabled', false);
                $route = $enabled === true ? $this->config->get('plugins.login.route_' . $type) : null;
                break;
            case 'after_registration':
            case 'after_activation':
                $route = $this->config->get('plugins.login.redirect_' . $type);
                break;
            default:
                $route = null;
        }

        if (!is_string($route) || $route === '') {
            return null;
        }

        return $route;
    }

    /**
     * @param UserInterface $user
     * @param PageInterface $page
     * @param Data|null $config
     * @return bool
     */
    public function isUserAuthorizedForPage(UserInterface $user, PageInterface $page, ?Data $config = null): bool
    {
        /** @var PageAuthorizeEvent $event */
        $event = $this->grav->dispatchEvent(new PageAuthorizeEvent($page, $user, $config));
        if (!$event->hasProtectedAccess()) {
            return true;
        }

        // All access protected pages have a private cache-control. This includes pages which are for guests only.
        $cacheControl = $page->cacheControl();
        if (!$cacheControl) {
            $cacheControl = 'private, no-cache, must-revalidate';
        } else {
            // The response is intended for a single user only and must not be stored by a shared cache.
            $cacheControl = str_replace('public', 'private', $cacheControl);
            if (strpos($cacheControl, 'private') === false) {
                $cacheControl = 'private, ' . $cacheControl;
            }
            // The cache will send the request to the origin server for validation before releasing a cached copy.
            if (strpos($cacheControl, 'no-cache') === false) {
                $cacheControl .= ', no-cache';
            }
            // The cache must verify the status of the stale resources before using the copy and expired ones should not be used.
            if (strpos($cacheControl, 'must-revalidate') === false) {
                $cacheControl .= ', must-revalidate';
            }
        }
        $page->cacheControl($cacheControl);

        // Deny access if user has not completed 2FA challenge.
        $user = $event->user;
        if ($user->authenticated && !$user->authorized) {
            $event->deny();
        }

        return $event->isAllowed();
    }

    /**
     * Check if user may use password reset functionality.
     *
     * @param UserInterface $user
     * @param string        $field
     * @param int           $count
     * @param int           $interval
     * @return bool
     * @deprecated 2.5.0 Use $grav['login']->getRateLimiter($context) instead. See Grav\Plugin\Login\RateLimiter class.
     */
    public function isUserRateLimited(UserInterface $user, $field, $count, $interval)
    {
        if ($count > 0) {
            if (!isset($user->{$field})) {
                $user->{$field} = [];
            }
            //remove older than $interval x minute attempts
            $actual_resets = [];
            foreach ((array)$user->{$field} as $reset) {
                if ($reset > (time() - $interval * 60)) {
                    $actual_resets[] = $reset;
                }
            }

            if (\count($actual_resets) >= $count) {
                return true;
            }
            $actual_resets[] = time(); // current reset
            $user->{$field} = $actual_resets;

        }
        return false;
    }

    /**
     * Reset the rate limit counter.
     *
     * @param UserInterface $user
     * @param string        $field
     * @deprecated 2.5.0 Use $grav['login']->getRateLimiter($context) instead. See Grav\Plugin\Login\RateLimiter class.
     */
    public function resetRateLimit(UserInterface $user, $field)
    {
        $user->{$field} = [];
    }

    /**
     * Get Current logged in user
     *
     * @return UserInterface
     * @deprecated 2.5.0 Use $grav['user'] instead.
     */
    public function getUser()
    {
        /** @var UserInterface $user */
        return $this->grav['user'];
    }

    public function addProviderLoginTemplate($template)
    {
        $this->provider_login_templates[] = $template;
    }

    public function getProviderLoginTemplates()
    {
        return $this->provider_login_templates;
    }
}
