<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2026 Trilby Media, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login\Passkeys;

/**
 * A passkey step that failed for a reason the person can act on. The message
 * is a language key (PLUGIN_LOGIN.PASSKEY_*), translated where it is shown.
 */
class PasskeyException extends \RuntimeException
{
}
