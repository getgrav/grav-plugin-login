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
use Grav\Common\File\CompiledYamlFile;
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
use Grav\Plugin\Login\Passkeys\Passkeys;
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

    /** @var Passkeys|null|false false until first asked */
    protected $passkeys = false;

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

        // Read again also when the caller's object is the stored one itself.
        $stored = $this->loadAccount($username, false);
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
     * The stored account of $user (a session's copy), to check against it.
     *
     * @param UserInterface $user
     * @return UserInterface The account as stored, freshly read, or $user when it has none.
     */
    protected function loadStoredAccount(UserInterface $user): UserInterface
    {
        $stored = $this->loadAccount((string)$user->get('username'), false, $user);

        return $stored->exists() ? $stored : $user;
    }

    /**
     * The account as stored now: this request may have read it a while ago, and
     * someone may have saved it since.
     *
     * To read it ($forWrite false) a Flex object keeps what it holds in memory
     * but isn't stored, and $sessionCopy, should load() return that very object,
     * is left as it is. To change and save it ($forWrite true) it is only what is
     * stored; a regular account, whose file stays in memory for the whole
     * request, is then read again.
     *
     * @param string $username
     * @param bool $forWrite
     * @param UserInterface|null $sessionCopy
     * @return UserInterface
     */
    private function loadAccount(string $username, bool $forWrite, ?UserInterface $sessionCopy = null): UserInterface
    {
        if ($forWrite) {
            clearstatcache();
        }

        /** @var UserCollectionInterface $accounts */
        $accounts = $this->grav['accounts'];
        $account = $accounts->load($username);
        if (is_callable([$account, 'refresh'])) {
            if ($account !== $sessionCopy) {
                $account->refresh(!$forWrite);
            }
        } elseif ($forWrite && ($file = $account->file()) !== null) {
            // Grav caches the file object per request: drop it, so load() reads the file again.
            $file->free();
            $account = $accounts->load($username);
        }

        return $account;
    }

    /**
     * Sign an account out everywhere else after its password changed. Stamps
     * `api_tokens_valid_after`, which API tokens and signed-in browsers are
     * checked against (see sessionSignOutReason()), notes why in `signed_out`
     * so those browsers can tell their user, and forgets the account's
     * remember-me cookies, also while "Remember me" is off, so turning it on
     * again can't bring them back. When the account changes its own password the
     * browser making the change stays signed in: its session gets the same
     * stamp and note, and a remember-me cookie it had is issued again. Pass
     * `$keepCurrent = false` when someone else changed it.
     *
     * The caller saves the account.
     *
     * @param UserInterface $user
     * @param bool $keepCurrent
     * @param string $reason 'password', 'email' (its address changed), 'email_cancelled' (a change of it was cancelled) or 'everywhere' (signOutEverywhere())
     * @return void
     */
    public function endOtherSessions(UserInterface $user, bool $keepCurrent = true, string $reason = 'password'): void
    {
        $now = time();
        $username = (string)$user->get('username');
        $mark = ['at' => $now, 'reason' => $reason];
        $user->set('api_tokens_valid_after', $now);
        $user->set('signed_out', $mark);

        $sessionUser = $keepCurrent ? $this->currentSessionUser($username) : null;
        if ($sessionUser && $sessionUser !== $user) {
            // Also the note, so a later save of the session's copy doesn't put the old one back.
            $sessionUser->set('api_tokens_valid_after', $now);
            $sessionUser->set('signed_out', $mark);
        }

        if ($username === '') {
            return;
        }

        $rememberMe = $this->rememberMe();
        $cookie = $_COOKIE[(string)$this->grav['config']->get('plugins.login.rememberme.name')] ?? '';
        $keepCookie = $sessionUser
            && $this->grav['config']->get('plugins.login.rememberme.enabled')
            && is_string($cookie)
            && explode('|', $cookie, 2)[0] === $username
            && $rememberMe->cookieIsValid();

        $rememberMe->getStorage()->cleanAllTriplets($username);
        if ($keepCookie) {
            $rememberMe->createCookie($username);
        }
    }

    /**
     * The signed-in user of the session making this request, when it is $username.
     *
     * @param string $username
     * @return UserInterface|null
     */
    private function currentSessionUser(string $username): ?UserInterface
    {
        if ($username === '') {
            return null;
        }

        /** @var Session $session */
        $session = $this->grav['session'];
        $user = $session->isStarted() ? ($session->user ?? null) : null;

        return $user instanceof UserInterface && $user->authenticated && (string)$user->get('username') === $username
            ? $user
            : null;
    }

    /**
     * Whether a signed-in session began before the account's password last
     * changed, or before it was otherwise signed out everywhere, so it has to
     * sign in again. Compares the session copy's `api_tokens_valid_after` with
     * the stored account's. sessionSignOutReason() also says why, and checks
     * "sign out everyone".
     *
     * @param UserInterface $sessionUser
     * @return bool
     */
    public function isSessionOutdated(UserInterface $sessionUser): bool
    {
        return $sessionUser->authenticated && $this->accountSignOutReason($sessionUser) !== null;
    }

    /**
     * Why a signed-in session has to sign in again, or null if it may stay:
     *
     * - its account was signed out since the session logged in, with the reason
     *   endOtherSessions() noted ('password', 'email', 'email_cancelled',
     *   'everywhere'), or 'changed' when the stamp has no note, e.g. the account
     *   was disabled through the API. Compares the session's copy of the account
     *   with the stored one, so no clocks are involved;
     * - 'everyone': it logged in before the last "sign out everyone" finished
     *   (signOutEveryone()), which also reaches users without an account file.
     *
     * @param Session $session
     * @param UserInterface $sessionUser
     * @return string|null
     */
    public function sessionSignOutReason($session, UserInterface $sessionUser): ?string
    {
        if (!$sessionUser->authenticated) {
            return null;
        }

        return $this->accountSignOutReason($sessionUser)
            ?? ($this->signedOutWithEveryone($session) ? 'everyone' : null);
    }

    /**
     * See sessionSignOutReason().
     *
     * @param UserInterface $sessionUser
     * @return string|null
     */
    private function accountSignOutReason(UserInterface $sessionUser): ?string
    {
        if (!$sessionUser->exists()) {
            return null;
        }

        $stored = $this->loadStoredAccount($sessionUser);
        if ($stored === $sessionUser) {
            // Gone, or the session holds the stored object itself.
            return null;
        }

        return self::signOutReason(
            (int)$stored->get('api_tokens_valid_after', 0),
            (array)$stored->get('signed_out', []),
            (int)$sessionUser->get('api_tokens_valid_after', 0),
            (array)$sessionUser->get('signed_out', [])
        );
    }

    /**
     * Why a session's copy of an account has to sign in again, from the stored
     * account's stamp (`api_tokens_valid_after`) and note (`signed_out`, see
     * endOtherSessions()) and the copy's, or null if the copy is current. The
     * reason is the note's when it belongs to the stamp, else 'changed' (the stamp
     * was set some other way, e.g. the account was disabled through the API).
     * Times are whole seconds: a copy holding the stored stamp is current, unless
     * that second also saw another sign-out, which the notes tell apart.
     *
     * @param int $storedStamp 0 if the account was never signed out
     * @param array<string, mixed> $storedMark
     * @param int $copyStamp
     * @param array<string, mixed> $copyMark
     * @return string|null
     */
    public static function signOutReason(int $storedStamp, array $storedMark, int $copyStamp, array $copyMark): ?string
    {
        if ($storedStamp <= 0 || $copyStamp > $storedStamp || ($copyStamp === $storedStamp && $copyMark == $storedMark)) {
            return null;
        }

        $reason = (int)($storedMark['at'] ?? 0) === $storedStamp ? (string)($storedMark['reason'] ?? '') : '';

        return $reason !== '' ? $reason : 'changed';
    }

    /**
     * The PLUGIN_LOGIN message for a signed-out browser, from its reason
     * (sessionSignOutReason()): a password change says so, as it did before;
     * any other reason gets one neutral message, naming neither the cause nor
     * who signed it out.
     *
     * @param string $reason
     * @return string
     */
    public static function signedOutMessage(string $reason): string
    {
        return $reason === 'password' ? 'SIGNED_OUT_PASSWORD_CHANGED' : 'SIGNED_OUT';
    }

    /**
     * Sign an account out everywhere: its browser sessions end on their next
     * request, its "remember me" cookies stop working and its API tokens
     * (Admin2) are refused, as after someone else changed its password
     * (endOtherSessions()). Its API keys keep working. Stamps and saves the
     * account as stored now, not the object given (signOutStored()), and logs
     * it; throws if it can't be read or saved. With $keepFor (the caller's
     * username) the browser session making the request stays signed in when
     * it is that user's, so signing out your own account ends only your other
     * sessions, as after changing your own password; your API tokens end too.
     *
     * @param UserInterface $user
     * @param string $by Who signed it out and where, for the log, e.g. 'by "admin" through the API'
     * @param string $keepFor
     * @return bool False if the account doesn't exist (nothing is saved then)
     */
    public function signOutEverywhere(UserInterface $user, string $by = '', string $keepFor = ''): bool
    {
        return $this->signOutStored((string)$user->get('username'), $by, $keepFor, false) !== null;
    }

    /**
     * Sign the account out everywhere as it is stored now (loadAccount()),
     * rather than an object a caller holds: that may be the session's own copy,
     * which has to keep its old stamp to be signed out, or a copy read earlier
     * in the request that would overwrite a change saved since.
     *
     * @param string $username
     * @param string $by
     * @param string $keepFor Keep the browser session making the request when it is this user's (signOutEverywhere(), signOutEveryone())
     * @param bool $bulk Log at debug level only (the caller logs the total)
     * @return string|null The username as stored, null if there is no such account
     * @throws \Throwable When the account can't be read or saved
     */
    private function signOutStored(string $username, string $by, string $keepFor, bool $bulk): ?string
    {
        $account = $this->loadAccount($username, true);
        if (!$account->exists()) {
            return null;
        }

        $username = (string)$account->get('username');
        $this->endOtherSessions($account, $keepFor !== '' && $username === $keepFor, 'everywhere');
        $account->save();
        $this->grav['log']->log($bulk ? 'debug' : 'info', $this->signedOutLogLine($username, $by));

        return $username;
    }

    /**
     * signOutEverywhere() for each of these accounts, each logged. An account
     * that can't be saved doesn't stop the others: it is logged and listed under
     * `failed`; a username without an account is listed under `missing`.
     *
     * @param string[] $usernames
     * @param string $by See signOutEverywhere()
     * @return array{signed_out: string[], failed: list<array{username: string, error: string}>, missing: string[]}
     */
    public function signOutAccounts(array $usernames, string $by = ''): array
    {
        return $this->signOutList($usernames, $by, '', false);
    }

    /** Where "sign out everyone" keeps its site-wide cutoff (signOutEveryone()). */
    private const SIGN_OUT_ALL_FILE = 'user-data://login/sign-out-all.yaml';

    /** @var int|null The site-wide cutoff as read for this request by signOutAllCutoff() (0: none), null until read */
    private $signOutAllAt;

    /**
     * The cutoff file is written right after its cutoff, so a session that logged
     * in this much later than the file's time can't be older: it isn't read. Leaves
     * room for a file system whose clock is off.
     */
    private const SIGN_OUT_ALL_CLOCK_SLACK = 3600;

    /**
     * Sign every account out everywhere, then every session that logged in
     * before now, also those of users without an account file (e.g. OAuth2
     * logins that aren't saved), which no account reaches: a site-wide cutoff
     * that each session checks when it starts (sessionSignOutReason()). Someone
     * who logs in while this runs has to log in once more.
     *
     * Each account is read again and stamped when its turn comes, so a change
     * saved to it meanwhile isn't overwritten. With $keepFor (the caller's
     * username) the browser session making the request stays signed in when it
     * is that user's, as after changing your own password; the caller's API
     * tokens end like everyone's. Logs one line with the number of accounts, and
     * each account only at debug level. An account that can't be read or saved
     * doesn't stop the others: it is logged and listed under `failed`. If the
     * cutoff can't be written, the accounts stay signed out, `sessions_ended` is
     * false and the error is logged.
     *
     * @param string $by See signOutEverywhere()
     * @param string $keepFor
     * @return array{signed_out: string[], failed: list<array{username: string, error: string}>, sessions_ended: bool}
     */
    public function signOutEveryone(string $by = '', string $keepFor = ''): array
    {
        // Listed, not loaded: each account is read when its turn comes.
        $list = $this->signOutList($this->accountUsernames(), $by, $keepFor, true);
        $result = ['signed_out' => $list['signed_out'], 'failed' => $list['failed'], 'sessions_ended' => false];

        // Last, so it also ends the sessions that logged in while the accounts were signed out.
        $at = time();
        $file = CompiledYamlFile::instance((string)$this->grav['locator']->findResource(self::SIGN_OUT_ALL_FILE, true, true));
        try {
            $file->save(['at' => $at]);
            $result['sessions_ended'] = true;
            $this->signOutAllAt = $at;
            if ($this->currentSessionUser($keepFor)) {
                $this->grav['session']->sign_out_all_kept = $at;
            }
        } catch (\Throwable $e) {
            $this->grav['log']->error(sprintf('Login: could not write %s, so the sessions of users without an account file stay: %s', $file->filename(), $e->getMessage()));
        } finally {
            // Release Grav's per-request file object.
            $file->free();
        }

        $count = count($result['signed_out']);
        $this->grav['log']->info(sprintf(
            'Login: signed everyone out: %s%d account%s%s%s',
            $result['sessions_ended'] ? 'every session that logged in before now, and ' : '',
            $count,
            $count === 1 ? '' : 's',
            $result['failed'] ? sprintf(' (%d failed)', count($result['failed'])) : '',
            $by !== '' ? " ({$by})" : ''
        ));

        return $result;
    }

    /**
     * @param string[] $usernames
     * @param string $by
     * @param string $keepFor See signOutEveryone()
     * @param bool $bulk Log each account at debug level only (the caller logs the total)
     * @return array{signed_out: string[], failed: list<array{username: string, error: string}>, missing: string[]}
     */
    private function signOutList(array $usernames, string $by, string $keepFor, bool $bulk): array
    {
        $result = ['signed_out' => [], 'failed' => [], 'missing' => []];
        foreach ($usernames as $username) {
            try {
                $stored = $this->signOutStored($username, $by, $keepFor, $bulk);
            } catch (\Throwable $e) {
                $result['failed'][] = ['username' => $username, 'error' => $e->getMessage()];
                $this->grav['log']->error(sprintf('Login: could not sign "%s" out everywhere: %s', $username, $e->getMessage()));

                continue;
            }
            if ($stored === null) {
                // Removed since it was listed, or a file Grav can't load (e.g. Bob.yaml on a case-sensitive file system: usernames are lowercase).
                $result['missing'][] = $username;
                $this->grav['log']->debug(sprintf('Login: no account "%s" to sign out', $username));

                continue;
            }

            $result['signed_out'][] = $stored;
        }

        return $result;
    }

    private function signedOutLogLine(string $username, string $by): string
    {
        return sprintf('Login: signed "%s" out everywhere%s', $username, $by !== '' ? " ({$by})" : '');
    }

    /**
     * Whether a session ends with the last "sign out everyone": it logged in
     * before it finished, or in the same second, and isn't the session that ran
     * it. A session that doesn't know when it logged in (from before 3.12.2, or
     * signed in by a plugin that sets the session's user itself instead of
     * logging in through Login::login()) counts
     * as older while the cutoff is younger than a session can stay idle (the
     * session cookie's lifetime: system.session.timeout, or the admin's). Later
     * it counts from when it is first seen (the caller notes that), so such
     * logins aren't locked out for good.
     *
     * @param Session $session
     * @return bool
     */
    private function signedOutWithEveryone($session): bool
    {
        $loginAt = (int)($session->login_at ?? 0);
        $path = $this->grav['locator']->findResource(self::SIGN_OUT_ALL_FILE);
        if (!is_string($path)) {
            return false;
        }
        $modified = @filemtime($path);
        if ($loginAt > 0 && $modified !== false && $loginAt > $modified + self::SIGN_OUT_ALL_CLOCK_SLACK) {
            return false;
        }

        return self::endedBySignOutEveryone(
            $this->signOutAllCutoff($path),
            $loginAt,
            (int)($session->sign_out_all_kept ?? 0),
            (int)ini_get('session.cookie_lifetime') ?: (int)ini_get('session.gc_maxlifetime'),
            time()
        );
    }

    /**
     * Whether a session ends with the last "sign out everyone", given its cutoff
     * (signOutEveryone()): the session logged in before it finished, or in the
     * same second, and isn't the one that ran it. A session that doesn't know
     * when it logged in counts as older while the cutoff is younger than a
     * session can stay idle; later it counts from when it is first seen.
     *
     * @param int $at When "sign out everyone" last finished, 0 if never
     * @param int $loginAt When the session logged in, 0 if unknown
     * @param int $kept The cutoff the session itself ran, 0 if none
     * @param int $idle How long a session can stay idle, in seconds
     * @param int $now
     * @return bool
     */
    public static function endedBySignOutEveryone(int $at, int $loginAt, int $kept, int $idle, int $now): bool
    {
        if ($at <= 0 || $kept === $at) {
            return false;
        }

        return $loginAt > 0 ? $loginAt <= $at : $at > $now - $idle;
    }

    /**
     * When "sign out everyone" last finished (0: never), from the file at $path.
     * A file that can't be read is ignored, so it can't lock anyone out, and
     * logged once per version of it rather than on every request.
     *
     * @param string $path
     * @return int
     */
    private function signOutAllCutoff(string $path): int
    {
        if ($this->signOutAllAt !== null) {
            return $this->signOutAllAt;
        }

        $this->signOutAllAt = 0;
        $file = CompiledYamlFile::instance($path);
        try {
            $this->signOutAllAt = (int)(((array)$file->content())['at'] ?? 0);
        } catch (\Throwable $e) {
            if ($this->firstSightOf($path)) {
                $this->grav['log']->error(sprintf('Login: could not read %s, so it signs no session out: %s', $path, $e->getMessage()));
            }
        } finally {
            // Release Grav's per-request file object.
            $file->free();
        }

        return $this->signOutAllAt;
    }

    /**
     * Whether this version of the file (its path, time and size) hasn't been
     * seen before, so a problem with it is logged once rather than on every
     * request. Says yes if that can't be remembered.
     *
     * @param string $path
     * @return bool
     */
    private function firstSightOf(string $path): bool
    {
        try {
            $seen = new LoginCache('sign-out-all');
            $version = sha1($path . '|' . @filemtime($path) . '|' . @filesize($path));
            if ($seen->has($version)) {
                return false;
            }
            $seen->set($version, true, 86400);
        } catch (\Throwable $e) {
            // Nothing to remember it with: log every time rather than not at all.
        }

        return true;
    }

    /**
     * Every existing account: from the Flex index when accounts are Flex
     * objects, else one per account file (the regular collection can't be
     * iterated). An account file that can't be read is logged and skipped; the
     * Flex index skips those itself.
     *
     * @return iterable<UserInterface>
     */
    public function getAccounts(): iterable
    {
        /** @var UserCollectionInterface $accounts */
        $accounts = $this->grav['accounts'];
        if (is_iterable($accounts)) {
            foreach ($accounts as $account) {
                if ($account instanceof UserInterface && $account->exists()) {
                    yield $account;
                }
            }

            return;
        }

        foreach ($this->accountUsernames() as $username) {
            try {
                $account = $accounts->load($username);
            } catch (\Throwable $e) {
                $this->grav['log']->error(sprintf('Login: could not read the account "%s": %s', $username, $e->getMessage()));

                continue;
            }
            if ($account->exists()) {
                yield $account;
            }
        }
    }

    /**
     * Every account's username, without loading the accounts: the Flex index's
     * keys (what load() takes), else the account files' names in every
     * account:// path, as load() looks in all of them.
     *
     * @return string[]
     */
    private function accountUsernames(): array
    {
        $accounts = $this->grav['accounts'];
        if (is_iterable($accounts) && is_callable([$accounts, 'getKeys'])) {
            return array_map('strval', $accounts->getKeys());
        }

        $usernames = [];
        foreach ((array)$this->grav['locator']->findResources('account://') as $accountDir) {
            foreach (scandir($accountDir) ?: [] as $file) {
                if (Utils::endsWith($file, YAML_EXT)) {
                    $usernames[trim(Utils::pathinfo($file, PATHINFO_FILENAME))] = true;
                }
            }
        }

        return array_map('strval', array_keys($usernames));
    }

    /**
     * The rate limiter contexts an administrator can clear on someone's behalf.
     *
     * @return array<int, string>
     */
    public static function getRateLimitContexts(): array
    {
        return ['login_attempts', 'twofa_attempts', 'pw_resets', 'magic_links', 'token_attempts', 'registrations', 'email_changes', 'passkey_attempts', 'passkey_options'];
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
     * Whether a value holds the opening of a Twig expression, statement or comment.
     *
     * @param string $value
     * @return bool
     */
    public static function hasTemplateSyntax(string $value): bool
    {
        return (bool)preg_match('/\{[{%#]/', $value);
    }

    /**
     * Whether a value is an email address Login accepts: a valid address that
     * doesn't contain Twig syntax, since addresses end up in page and email templates.
     *
     * @param mixed $value
     * @return bool
     */
    public static function isAcceptableEmail($value): bool
    {
        if (!is_string($value)) {
            return false;
        }

        $value = trim($value);

        return $value !== '' && !static::hasTemplateSyntax($value) && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * The name a login counter is kept under: the stored account's username
     * when the submitted name opens one, so spellings of one account (case,
     * or its email address) share a counter, otherwise the submitted name.
     *
     * @param string $submitted
     * @param UserInterface|null $user The account the submitted name opened.
     * @return string
     */
    public function rateLimitName(string $submitted, $user = null): string
    {
        if (!$user || !$user->exists()) {
            /** @var UserCollectionInterface $accounts */
            $accounts = $this->grav['accounts'];
            $user = $submitted !== '' ? $accounts->find($submitted, ['email']) : null;
        }

        $stored = $user && $user->exists() ? (string)$user->get('username') : '';

        return $stored !== '' ? $stored : $submitted;
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
                if (!static::isAcceptableEmail($value)) {
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
     * A request for a new address also tells the current address, with a link
     * to cancel it (sendEmailChangeRequestedNotice()). Sending the link again
     * for the same address keeps the cancel link already mailed, so it isn't
     * mailed twice.
     *
     * When the address already belongs to another account nothing is mailed
     * to it, but the account still shows the change as waiting, so the profile
     * form answers the same way it does for a free address.
     *
     * @param UserInterface $user
     * @param string $email
     * @return bool True if the action was performed.
     * @throws \RuntimeException
     */
    public function requestEmailChange(UserInterface $user, string $email)
    {
        $expire = time() + static::EMAIL_CHANGE_TTL;

        $newRequest = mb_strtolower((string)$user->get('email_pending', '')) !== mb_strtolower($email)
            || (string)$user->get('email_change_cancel_token', '') === '';

        $user->email_pending = $email;
        $user->email_change_token = static::newToken() . '::' . $expire;
        if ($newRequest) {
            // Its own token, so the confirm link can't be worked out from it.
            $user->email_change_cancel_token = static::newToken();
        }
        $user->save();

        if ($newRequest) {
            $this->sendEmailChangeRequestedNotice($user);
        }

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
        $this->refreshStoredFields($user, ['email', 'email_pending', 'email_change_token', 'email_change_cancel_token', 'email_verified', 'email_verified_at']);
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

        $stored = $this->loadStoredAccount($user);
        if ($stored === $user) {
            return;
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
        unset($user->email_pending, $user->email_change_token, $user->email_change_cancel_token);
    }

    /**
     * Tell the current address that a change to a new one was asked for, with
     * a link to cancel it. A delivery failure is logged, since the request
     * itself has gone through.
     *
     * @param UserInterface $user
     * @return bool True if the action was performed.
     */
    public function sendEmailChangeRequestedNotice(UserInterface $user)
    {
        if ((string)$user->get('email', '') === '') {
            return false;
        }

        try {
            Email::sendEmailChangeRequestedNotice($user);
        } catch (\Exception $e) {
            $this->grav['log']->error('plugin.login: could not send email change requested notice: ' . $e->getMessage());

            return false;
        }

        return true;
    }

    /**
     * A random token for an emailed link.
     *
     * @return string
     */
    public static function newToken(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (\Exception $e) {
            return md5(uniqid((string)mt_rand(), true));
        }
    }

    /**
     * Whether a token from a link matches the one stored on the account. An
     * empty token never matches, so a cleared one can't be used.
     *
     * @param string $stored
     * @param string $given
     * @return bool
     */
    public static function tokenMatches(string $stored, string $given): bool
    {
        return $stored !== '' && $given !== '' && hash_equals($stored, $given);
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
     * Passkeys, when this site offers them: Grav 2 (Passkeys::supported())
     * and `passkeys.enabled` on. Null otherwise, and always null on Grav 1.7,
     * so callers never reach the WebAuthn code there.
     *
     * @return Passkeys|null
     */
    public function passkeys()
    {
        if ($this->passkeys === false) {
            $this->passkeys = Passkeys::supported() && $this->grav['config']->get('plugins.login.passkeys.enabled', false)
                ? new Passkeys($this->grav, $this)
                : null;
        }

        return $this->passkeys;
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
                case 'passkey_attempts':
                    // Passkey answers that didn't check out, per IP.
                    $maxCount = $this->grav['config']->get('plugins.login.passkeys.max_attempts_count', 10);
                    $interval = $this->grav['config']->get('plugins.login.passkeys.max_attempts_interval', 10);
                    break;
                case 'passkey_options':
                    // Passkey ceremonies started, per IP (each stores a challenge).
                    $maxCount = $this->grav['config']->get('plugins.login.passkeys.max_options_count', 60);
                    $interval = $this->grav['config']->get('plugins.login.passkeys.max_options_interval', 10);
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

    /**
     * Whether the site login page shows the username and password form. The show_password_form setting turns it off,
     * and a plugin can turn it off for the request (e.g. Login OAuth2's "Enforce OAuth2"). The setting may be a string
     * such as 'false' or 'off' (hand-edited YAML, an environment override): anything not clearly false (null, a typo,
     * an array) keeps the form. Turned off, the form still shows while the page offers no other way in: a provider's
     * buttons (addProviderLoginTemplate()), an older plugin's buttons that can sign in (getLegacyLoginOptions()) or a
     * Login by link that can send (isMagicLinkAvailable()). Passkeys don't count: their button shows only in browsers that can use
     * one, and only accounts that already added a passkey can sign in with it.
     *
     * Ask after onLoginPage, where plugins add their buttons. A theme that overrides partials/login-form.html.twig
     * honours the setting by showing its password fields only while this is true.
     */
    public function showPasswordForm(): bool
    {
        $value = $this->config->get('plugins.login.show_password_form');

        // filter_var() reads null as false, so it is handled first.
        if ($value === null || (filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? true)) {
            return true;
        }

        return !($this->getProviderLoginTemplates()
            || $this->getLegacyLoginOptions()
            || $this->isMagicLinkAvailable());
    }

    /**
     * The older plugins' login templates (plugins_hooked_loginPage, by plugin) that offer a way in. Their buttons
     * submit the login form, so the login page keeps it while there are any. Login OAuth v1 ('LoginOauth') adds its
     * template even without a provider it can use, and then only asks to enable one: it counts only with a provider
     * that is enabled and has credentials, the ones Login OAuth v1 shows.
     *
     * @return array<string, string>
     */
    public function getLegacyLoginOptions(): array
    {
        $twig = $this->grav['twig'] ?? null;
        $templates = (array)($twig->plugins_hooked_loginPage ?? []);

        if (isset($templates['LoginOauth']) && !$this->hasLoginOauthProvider()) {
            unset($templates['LoginOauth']);
        }

        return $templates;
    }

    /**
     * Whether Login OAuth v1 has a provider to show: one that is enabled and has credentials, as its
     * onTwigSiteVariables picks them for its template.
     */
    protected function hasLoginOauthProvider(): bool
    {
        foreach ((array)$this->config->get('plugins.login-oauth.providers', []) as $options) {
            if (is_array($options) && !empty($options['enabled']) && isset($options['credentials'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether Login by link can send a link: magic_link.enabled is on, both its routes are set (the request page and
     * the link in the email) and the Email plugin can send (it is enabled and plugins.email.from is set). The login
     * page and the request handler (Controller::taskMagicRequest()) both check this, so they can't disagree.
     */
    public function isMagicLinkAvailable(): bool
    {
        return $this->config->get('plugins.login.magic_link.enabled', false)
            && $this->getRoute('magic') !== null
            && $this->getRoute('magic_login') !== null
            && isset($this->grav['Email'])
            && $this->config->get('plugins.email.from');
    }
}
