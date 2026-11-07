<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2021 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login\Invitations;

use Grav\Common\File\CompiledYamlFile;
use Grav\Common\Grav;
use Grav\Common\Utils;
use RocketTheme\Toolbox\File\YamlFile;
use RocketTheme\Toolbox\ArrayTraits\ArrayAccess;
use RocketTheme\Toolbox\ArrayTraits\Countable;
use RocketTheme\Toolbox\ArrayTraits\Iterator;

/**
 * Invite users to the site.
 *
 * Tools to send emails for invites and handle invite registrations.
 */
class Invitations implements \Countable, \Iterator, \ArrayAccess
{
    use ArrayAccess;
    use Countable;
    use Iterator;

    /** @var static */
    public static $instance;

    /** @var string */
    private $inviteFile = 'user-data://accounts/invites.yaml';
    /** @var array|null */
    private $items;
    /** @var array|null */
    private $emails;

    public static function getInstance()
    {
        if (null === static::$instance) {
            static::$instance = new static();
        }

        return static::$instance;
    }

    public function __construct()
    {
        $this->items = $this->load();
    }

    public function offsetGet($offset): ?Invitation
    {
        $data = $this->items[$offset] ?? null;

        return $data ? new Invitation($offset, $data) :null;
    }

    public function offsetSet($offset, $value): void
    {
        if (!$value instanceof Invitation) {
            throw new \RuntimeException('Value has to be instance of Invitation');
        }

        if (null === $offset) {
            $offset = $value->token;
        }

        $this->items[$offset] = $value->toArray();
    }

    public function current(): ?Invitation
    {
        return $this->offsetGet($this->key());
    }

    public function get(string $token): ?Invitation
    {
        return $this->offsetGet($token);
    }

    public function getByEmail(string $email): ?Invitation
    {
        if (null === $this->emails) {
            $this->emails = [];
            foreach ($this->items as $token => $invite) {
                $this->emails[$invite['email']] = $token;
            }

        }

        if (isset($this->emails[$email])) {
            return $this->offsetGet($this->emails[$email]);
        }

        return null;
    }

    public function getByIssuer(string $email): array
    {
        $list = [];
        foreach ($this->items as $token => $invite) {
            $test = $invite['email'] ?? null;
            if ($email === $test) {
                $list[] = $this->offsetGet($token);
            }
        }

        return $list;
    }

    public function add(Invitation $invitation): void
    {
        $this->offsetSet(null, $invitation);
    }

    public function remove(Invitation $invitation): void
    {
        $this->offsetUnset($invitation->token);
    }

    /**
     * Remove an invitation and return it, or null when it is already gone.
     *
     * The file is re-read and written back under an exclusive lock on a
     * sidecar `invites.yaml.lock` (the save replaces the YAML file by rename,
     * so the lock can't live on the file itself). Of several requests
     * redeeming one token at the same moment, only one gets it back.
     */
    public function take(string $token): ?Invitation
    {
        $path = (string)Grav::instance()['locator']->findResource($this->inviteFile, true, true);
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new \RuntimeException(sprintf('Unable to create directory "%s"', $dir));
        }

        $lock = @fopen($path . '.lock', 'c');
        if ($lock === false) {
            throw new \RuntimeException(sprintf('Unable to open "%s.lock"', $path));
        }

        try {
            if (!flock($lock, LOCK_EX)) {
                throw new \RuntimeException(sprintf('Unable to lock "%s.lock"', $path));
            }

            $file = YamlFile::instance($path);
            $file->free();
            $items = (array)$file->content();
            $data = $items[$token] ?? null;
            if (!is_array($data)) {
                $file->free();

                return null;
            }

            unset($items[$token]);
            $file->save($items);
            $file->free();

            $this->items = $items;
            $this->emails = null;

            return new Invitation($token, $data);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function removeExpired(): int
    {
        $now = time();
        $count = 0;
        foreach ($this->items as $token => $invite) {
            if ($invite['expiration_timestamp'] < $now) {
                $this->offsetUnset($token);
                $count++;
            }
        }

        return $count;
    }

    public function save(): void
    {
        $file = $this->getFile();
        $file->save($this->items);
    }

    public function generateToken(): string
    {
        do {
            $id = Utils::uniqueId(24);
        } while (isset($this->items[$id]));

        return $id;
    }

    private function load(): array
    {
        $file = $this->getFile();
        $data = $file->content();
        $file->free();

        return $data;
    }

    private function getFile(): CompiledYamlFile
    {
        return CompiledYamlFile::instance($this->inviteFile);
    }
}
