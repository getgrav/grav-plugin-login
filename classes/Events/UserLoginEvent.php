<?php
/**
 * @package    Grav.Plugin.Login
 *
 * @copyright  Copyright (C) 2014 - 2017 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */
namespace Grav\Plugin\Login\Events;

use Grav\Common\User\User;
use RocketTheme\Toolbox\Event\Event;

/**
 * Class UserLoginEvent
 * @package Grav\Common\User\Events
 *
 * @property int                $status
 * @property array              $credentials
 * @property string|string[]    $authorize
 * @property array              $options
 * @property User               $user
 * @property string             $message
 *
 */
class UserLoginEvent extends Event
{
    /**
     * Undefined event state.
     */
    const AUTHENTICATION_UNDEFINED = 0;

    /**
     * onUserAuthenticate success.
     */
    const AUTHENTICATION_SUCCESS = 1;

    /**
     * onUserAuthenticate fails on bad username/password.
     */
    const AUTHENTICATION_FAILURE = 2;

    /**
     * onUserAuthenticate fails on auth cancellation.
     */
    const AUTHENTICATION_CANCELLED = 4;

    /**
     * onUserAuthorizeLogin fails on expired account.
     */
    const AUTHORIZATION_EXPIRED = 8;

    /**
     * onUserAuthorizeLogin fails for other reasons.
     */
    const AUTHORIZATION_DENIED = 16;

    public function __construct(array $items = [])
    {
        $defaults = [
            'credentials' => ['username' => '', 'password' => ''],
            'options' => [],
            'authorize' => 'site.login',
            'status' => static::AUTHENTICATION_UNDEFINED,
            'user' => null,
            'message' => ''
        ];

        parent::__construct(array_replace_recursive($defaults, $items));

        if (!isset($this['user'])) {
            $this['user'] = User::load($this['credentials']['username'], false);
        }
    }
}
