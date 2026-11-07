<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2021 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login\Api;

use Grav\Plugin\Api\Controllers\AbstractApiController;
use Grav\Plugin\Api\Exceptions\ForbiddenException;
use Grav\Plugin\Api\Response\ApiResponse;
use Grav\Plugin\Login\Login;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * API routes of the Login plugin, registered on onApiRegisterRoutes (only
 * loaded when the API plugin dispatches to them).
 */
class SignOutController extends AbstractApiController
{
    /**
     * POST /login/sign-out-all: Login::signOutEveryone() for the caller. Super
     * admins only, as it signs out super admin accounts.
     *
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function signOutAll(ServerRequestInterface $request): ResponseInterface
    {
        $this->requirePermission($request, 'api.users.write');
        $language = $this->grav['language'];
        $user = $this->getUser($request);
        if (!$this->hasPermission($user, 'api.super') && !$this->hasPermission($user, 'admin.super')) {
            throw new ForbiddenException($language->translate('PLUGIN_LOGIN.SIGN_OUT_ALL_SUPER_ONLY'));
        }
        // A super admin: the API's own gate still applies its API-key scope cap, with its own message.
        $this->requireSuper($request);

        /** @var Login $login */
        $login = $this->grav['login'];
        $caller = (string)$this->getUser($request)->get('username');
        // Runs to the end also when the browser or a proxy stops waiting: the
        // accounts not reached yet would stay signed in. Many accounts take a
        // while (each save makes Grav read the account index again).
        if (function_exists('ignore_user_abort')) {
            ignore_user_abort(true);
        }
        if (function_exists('set_time_limit')) {
            @set_time_limit(0);
        }
        $result = $login->signOutEveryone(sprintf('by "%s" through the API', $caller), $caller);

        $signedOut = $result['signed_out'];
        $failed = array_column($result['failed'], 'username');
        $count = count($signedOut);
        $message = $language->translate(match ($count) {
            0 => 'PLUGIN_LOGIN.SIGN_OUT_ALL_DONE_NONE',
            1 => 'PLUGIN_LOGIN.SIGN_OUT_ALL_DONE_ONE',
            default => ['PLUGIN_LOGIN.SIGN_OUT_ALL_DONE', $count],
        });
        if ($failed) {
            $message .= ' ' . $language->translate(['PLUGIN_LOGIN.SIGN_OUT_ALL_FAILED', implode(', ', $failed)]);
        }
        $message .= ' ' . $language->translate($result['sessions_ended'] ? 'PLUGIN_LOGIN.SIGN_OUT_ALL_SESSIONS' : 'PLUGIN_LOGIN.SIGN_OUT_ALL_SESSIONS_FAILED');
        if (in_array($caller, $signedOut, true) && $request->getAttribute('api_auth_method') === 'jwt') {
            $message .= ' ' . $language->translate('PLUGIN_LOGIN.SIGN_OUT_RELOGIN');
        }

        return ApiResponse::create([
            'signed_out' => $signedOut,
            'failed' => $failed,
            'sessions_ended' => $result['sessions_ended'],
            'message' => $message,
        ]);
    }
}
