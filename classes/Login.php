<?php
/**
 * @package    Grav.Plugin.Login
 *
 * @copyright  Copyright (C) 2014 - 2017 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */
namespace Grav\Plugin\Login;

use Birke\Rememberme\Cookie;
use Grav\Common\Config\Config;
use Grav\Common\Grav;
use Grav\Common\File\CompiledYamlFile;
use Grav\Common\Language\Language;
use Grav\Common\Session;
use Grav\Common\User\User;
use Grav\Common\Uri;
use Grav\Common\Utils;
use Grav\Plugin\Email\Utils as EmailUtils;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Plugin\Login\RememberMe\RememberMe;
use Grav\Plugin\Login\RememberMe\TokenStorage;
use RocketTheme\Toolbox\Session\Message;

/**
 * Class Login
 * @package Grav\Plugin
 */
class Login
{
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
     * Login user.
     *
     * @param array $credentials
     * @param array $options
     * @return User
     */
    public function login(array $credentials, array $options = [])
    {
        $grav = Grav::instance();

        $eventOptions = [
            'credentials' => $credentials,
            'options' => $options
        ];

        // Attempt to authenticate the user.
        $event = new UserLoginEvent($eventOptions);
        $grav->fireEvent('onUserLoginAuthenticate', $event);

        // Allow plugins to prevent login after successful authentication.
        if ($event->status === UserLoginEvent::AUTHENTICATION_SUCCESS) {
            $event = new UserLoginEvent($event->toArray());
            $grav->fireEvent('onUserLoginAuthorize', $event);
        }

        if ($event->status !== UserLoginEvent::AUTHENTICATION_SUCCESS) {
            // Allow plugins to log errors or do other tasks on failure.
            $event = new UserLoginEvent($event->toArray());
            $grav->fireEvent('onUserLoginFailure', $event);

            $event->user->authenticated = false;

        } else {
            // User has been logged in, let plugins know.
            $event = new UserLoginEvent($event->toArray());
            $grav->fireEvent('onUserLogin', $event);

            $event->user->authenticated = true;
        }

        $user = $event->user;
        $user->def('language', 'en');

        return $user;
    }

    /**
     * Logout user.
     *
     * @param array $options
     * @param User $user
     * @return User
     */
    public function logout(array $options = [], User $user = null)
    {
        $grav = Grav::instance();

        $eventOptions = [
            'user' => $user ?: $grav['user'],
            'options' => $options
        ];

        $event = new UserLoginEvent($eventOptions);

        // Logout the user.
        $grav->fireEvent('onUserLogout', $event);

        $event->user->authenticated = false;

        return $event->user;
    }

    /**
     * Add message into the session queue.
     *
     * @param string $msg
     * @param string $type
     */
    public function setMessage($msg, $type = 'info')
    {
        /** @var Message $messages */
        $messages = $this->grav['messages'];
        $messages->add($msg, $type);
    }

    /**
     * Fetch and delete messages from the session queue.
     *
     * @param string $type
     *
     * @return array
     */
    public function messages($type = null)
    {
        /** @var Message $messages */
        $messages = $this->grav['messages'];

        return $messages->fetch($type);
    }

    /**
     * Authenticate user.
     *
     * @param array $credentials Form fields.
     * @param array $options
     *
     * @return bool
     */
    public function authenticate($credentials, $options = ['remember_me' => true])
    {
        $user = $this->login($credentials, $options);

        if ($user->authenticated) {
            $this->setMessage($this->language->translate('PLUGIN_LOGIN.LOGIN_SUCCESSFUL',
                [$user->language]), 'info');

            $redirect_route = $this->uri->route();
            $this->grav->redirect($redirect_route);
        }

        return $user->authenticated;
    }

    /**
     * Create a new user file
     *
     * @param array $data
     *
     * @return User
     */
    public function register($data)
    {
        //Add new user ACL settings
        $groups = $this->config->get('plugins.login.user_registration.groups', []);

        if (count($groups) > 0) {
            $data['groups'] = $groups;
        }

        $access = $this->config->get('plugins.login.user_registration.access.site', []);
        if (count($access) > 0) {
            $data['access']['site'] = $access;
        }

        $username = $data['username'];
        $file = CompiledYamlFile::instance($this->grav['locator']->findResource('account://' . $username . YAML_EXT,
            true, true));

        // Create user object and save it
        $user = new User($data);
        $user->file($file);
        $user->save();

        if (isset($data['state']) && $data['state'] === 'enabled' && $this->config->get('plugins.login.user_registration.options.login_after_registration', false)) {
            //Login user
            $this->session->user = $user;
            unset($this->grav['user']);
            $this->grav['user'] = $user;
            $user->authenticated = $user->authorize('site.login');
        }

        return $user;
    }

    /**
     * Handle the email to notify the user account creation to the site admin.
     *
     * @param User $user
     *
     * @return bool True if the action was performed.
     */
    public function sendNotificationEmail(User $user)
    {
        if (empty($user->email)) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.USER_NEEDS_EMAIL_FIELD'));
        }

        $site_name = $this->config->get('site.title', 'Website');

        $subject = $this->language->translate(['PLUGIN_LOGIN.NOTIFICATION_EMAIL_SUBJECT', $site_name]);
        $content = $this->language->translate([
            'PLUGIN_LOGIN.NOTIFICATION_EMAIL_BODY',
            $site_name,
            $user->username,
            $user->email
        ]);
        $to = $this->config->get('plugins.email.from');

        if (empty($to)) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_NOT_CONFIGURED'));
        }

        $sent = EmailUtils::sendEmail($subject, $content, $to);

        if ($sent < 1) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_SENDING_FAILURE'));
        }

        return true;
    }

    /**
     * Handle the email to welcome the new user
     *
     * @param User $user
     *
     * @return bool True if the action was performed.
     */
    public function sendWelcomeEmail(User $user)
    {
        if (empty($user->email)) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.USER_NEEDS_EMAIL_FIELD'));
        }

        $site_name = $this->config->get('site.title', 'Website');

        $subject = $this->language->translate(['PLUGIN_LOGIN.WELCOME_EMAIL_SUBJECT', $site_name]);
        $content = $this->language->translate(['PLUGIN_LOGIN.WELCOME_EMAIL_BODY', $user->username, $site_name]);
        $to = $user->email;

        $sent = EmailUtils::sendEmail($subject, $content, $to);

        if ($sent < 1) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.EMAIL_SENDING_FAILURE'));
        }

        return true;
    }

    /**
     * Handle the email to activate the user account.
     *
     * @param User $user
     *
     * @return bool True if the action was performed.
     */
    public function sendActivationEmail(User $user)
    {
        if (empty($user->email)) {
            throw new \RuntimeException($this->language->translate('PLUGIN_LOGIN.USER_NEEDS_EMAIL_FIELD'));
        }

        $token = md5(uniqid(mt_rand(), true));
        $expire = time() + 604800; // next week
        $user->activation_token = $token . '::' . $expire;
        $user->save();

        $param_sep = $this->config->get('system.param_sep', ':');
        $activation_link = $this->grav['base_url_absolute'] . $this->config->get('plugins.login.route_activate') . '/token' . $param_sep . $token . '/username' . $param_sep . $user->username . '/nonce' . $param_sep . Utils::getNonce('user-activation');

        $site_name = $this->config->get('site.title', 'Website');

        $subject = $this->language->translate(['PLUGIN_LOGIN.ACTIVATION_EMAIL_SUBJECT', $site_name]);
        $content = $this->language->translate([
            'PLUGIN_LOGIN.ACTIVATION_EMAIL_BODY',
            $user->username,
            $activation_link,
            $site_name
        ]);
        $to = $user->email;

        $sent = EmailUtils::sendEmail($subject, $content, $to);

        if ($sent < 1) {
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
     */
    public function rememberMe($var = null)
    {
        if ($var !== null) {
            $this->rememberMe = $var;
        }

        if (!$this->rememberMe) {
            /** @var Config $config */
            $config = $this->grav['config'];

            // Setup storage for RememberMe cookies
            $storage = new TokenStorage;
            $this->rememberMe = new RememberMe($storage);
            $this->rememberMe->setCookieName($config->get('plugins.login.rememberme.name'));
            $this->rememberMe->setExpireTime($config->get('plugins.login.rememberme.timeout'));

            // Hardening cookies with user-agent and random salt or
            // fallback to use system based cache key
            $server_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'unknown';
            $data = $server_agent . $config->get('security.salt', $this->grav['cache']->getKey());
            $this->rememberMe->setSalt(hash('sha512', $data));

            // Set cookie with correct base path of Grav install
            $cookie = new Cookie;
            $cookie->setPath($this->grav['base_url_relative'] ?: '/');
            $this->rememberMe->setCookie($cookie);
        }

        return $this->rememberMe;
    }

    /**
     * Check if user may use password reset functionality.
     *
     * @param User   $user
     * @param string $field
     * @param int    $count
     * @param int    $interval
     * @return bool
     */
    public function isUserRateLimited(User $user, $field, $count, $interval)
    {
        if ($count > 0) {
            if (!isset($user->{$field})) {
                $user->{$field} = array();
            }
            //remove older than 1 hour attempts
            $actual_resets = array();
            foreach ($user->{$field} as $reset) {
                if ($reset > (time() - $interval * 60)) {
                    $actual_resets[] = $reset;
                }
            }

            if (count($actual_resets) >= $count) {
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
     * @param User   $user
     * @param string $field
     */
    public function resetRateLimit(User $user, $field)
    {
        $user->{$field} = [];
    }
}
