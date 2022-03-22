<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2022 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login\Events;

use Grav\Common\Data\Data;
use Grav\Common\Page\Interfaces\PageInterface;
use Grav\Common\User\Interfaces\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Class PageAuthorizationEvent
 * @package Grav\Plugin\Login\Events
 */
class PageAuthorizeEvent extends Event
{
    /** @var PageInterface */
    public $page;
    /** @var UserInterface */
    public $user;
    /** @var Data */
    public $config;

    /** @var bool */
    private $protected = false;
    /** @var bool|null */
    private $access;

    /**
     * @param PageInterface $page
     * @param UserInterface $user
     * @param Data|null $config
     */
    public function __construct(PageInterface $page, UserInterface $user, Data $config = null)
    {
        $this->page = $page;
        $this->user = $user;
        $this->config = $config ?? new Data();
    }

    /**
     * @return bool
     */
    public function hasProtectedAccess(): bool
    {
        return $this->protected;
    }

    /**
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this->getAccess() === true;
    }

    /**
     * @return bool
     */
    public function isDenied(): bool
    {
        return $this->getAccess() === false;
    }

    /**
     * @return bool
     */
    public function isUndecided(): bool
    {
        return $this->getAccess() === null;
    }

    /**
     * @return bool|null
     */
    public function getAccess(): ?bool
    {
        return $this->access;
    }

    /**
     * @return void
     */
    public function setProtectedAccess(): void
    {
        $this->protected = true;
    }

    /**
     * @return bool|null
     */
    public function allow(): ?bool
    {
        return $this->setAccess(true);
    }

    /**
     * @return bool|null
     */
    public function deny(): ?bool
    {
        return $this->setAccess(false);
    }

    /**
     * @param bool|null $access
     * @return void
     */
    public function setAccess(?bool $access): ?bool
    {
        if ($this->access !== false && is_bool($access)) {
            $this->access = $access;
            $this->setProtectedAccess();
        }

        return $this->access;
    }

    /**
     * @return array
     */
    public function __debugInfo(): array
    {
        return [
            'page' => $this->page->route(),
            'user' => $this->user->username ?: 'guest',
//            'config' => $this->config->jsonSerialize(),
        ];
    }
}
