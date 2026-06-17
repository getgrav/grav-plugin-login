<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2021 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Shortcodes;

use Thunder\Shortcode\Shortcode\ShortcodeInterface;

/**
 * Optional shortcode wrappers around the Login plugin's `authenticated()`
 * helper, for showing or hiding content by the visitor's login state,
 * permissions or groups:
 *
 *     [authenticated]Only logged-in visitors see this.[/authenticated]
 *     [authenticated=admin.super]Supers only.[/authenticated]
 *     [authenticated permission="admin.login,admin.pages"]...[/authenticated]
 *     [authenticated group="editors"]...[/authenticated]
 *     [guest]Please log in.[/guest]
 *
 * Registered only when the shortcode-core plugin is installed; the Login plugin
 * does not depend on it. The same checks are always available in Twig via the
 * `authenticated()` function.
 */
class AuthenticatedShortcode extends Shortcode
{
    public function init()
    {
        // Content shown only to a logged-in visitor, optionally narrowed by
        // permission (bbcode `=value` or `permission=`) and/or `group=`.
        $this->shortcode->getHandlers()->add('authenticated', function (ShortcodeInterface $sc) {
            $permission = $this->splitList($sc->getParameter('permission', $this->getBbCode($sc)));
            $group = $this->splitList($sc->getParameter('group'));

            return $this->grav['login']->isAuthenticated($permission, $group) ? $sc->getContent() : '';
        });

        // The inverse: content shown only when no one is logged in.
        $this->shortcode->getHandlers()->add('guest', function (ShortcodeInterface $sc) {
            return $this->grav['login']->isAuthenticated() ? '' : $sc->getContent();
        });
    }

    /**
     * Normalize a `a,b,c` parameter into a list, a lone value, or null.
     *
     * @param string|null $value
     * @return string|array|null
     */
    protected function splitList($value)
    {
        if ($value === null || $value === '') {
            return null;
        }

        $items = array_values(array_filter(array_map('trim', explode(',', (string)$value)), 'strlen'));

        return count($items) > 1 ? $items : ($items[0] ?? null);
    }
}
