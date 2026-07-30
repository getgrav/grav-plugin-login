<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2021 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login;

/**
 * Class RateLimiter
 * @package Grav\Plugin\Login\RateLimiter
 */
class RateLimiter
{
    /**
     * Cache key holding this context's index of registered keys.
     *
     * The cache driver is a plain key/value store with no way to enumerate what
     * is in it, so registering an action also records the key here. That is what
     * lets an administrator see who is currently locked out and clear a specific
     * lockout, rather than flushing the whole context blind.
     *
     * Real entries are always stored under "<type><key>", so this literal can
     * never collide with one.
     */
    protected const INDEX_KEY = '__index';

    /** Cap on tracked keys, so a flood of made-up usernames can't grow the index without bound. */
    protected const INDEX_MAX_KEYS = 1000;

    /** Cap on linked keys recorded against a single index entry. */
    protected const INDEX_MAX_LINKS = 25;

    /** @var LoginCache */
    protected $cache;

    /** @var int */
    protected $maxCount;

    /** @var int */
    protected $interval;

    /**
     * RateLimiter constructor.
     * @param string $context
     * @param int $maxCount
     * @param int|null $interval
     */
    public function __construct($context, $maxCount, $interval)
    {
        $this->cache = new LoginCache($context, (int)$interval * 60);
        $this->maxCount = (int) $maxCount;
        $this->interval = (int) $interval;
    }

    /**
     * @return int
     */
    public function getInterval()
    {
        return $this->interval;
    }

    /**
     * Check if user has hit rate limiter. Remember to use registerRateLimitedAction() before doing the check.
     *
     * @param string $key
     * @param string $type
     * @return bool
     */
    public function isRateLimited($key, $type = 'username')
    {
        if (!$key || !$this->interval) {
            return false;
        }

        return $this->maxCount && \count($this->getAttempts($key, $type)) > $this->maxCount;
    }

    /**
     *
     *
     * @param string $key
     * @param string $type
     * @return array
     */
    public function getAttempts($key, $type = 'username')
    {
        return (array) $this->cache->get($type . $key, []);
    }

    /**
     * Register rate limited action.
     *
     * @param string $key
     * @param string $type
     * @param array<string, string> $links Other type => key pairs this action belongs with, e.g.
     *                                     ['username' => 'bob'] when registering an IP attempt, so
     *                                     unlocking bob can also clear the IP counters he tripped.
     * @return $this
     */
    public function registerRateLimitedAction($key, $type = 'username', array $links = [])
    {
        if ($key && $this->interval) {
            $tries = (array)$this->cache->get($type . $key, []);
            $tries[] = time();

            $this->cache->set($type . $key, $tries);
            $this->indexKey($key, $type, $links);
        }

        return $this;
    }

    /**
     * Reset the user rate limit counter.
     *
     * @param string $key
     * @param string $type
     * @return $this
     */
    public function resetRateLimit($key, $type = 'username')
    {
        if ($key) {
            $this->cache->delete($type . $key);

            $index = $this->getIndex();
            $id = $this->indexId($key, $type);
            if (isset($index[$id])) {
                unset($index[$id]);
                $this->cache->set(static::INDEX_KEY, $index);
            }
        }

        return $this;
    }

    /**
     * Reset a key's counter along with every counter linked to it.
     *
     * Unlocking an account by username alone is usually not enough: a failed
     * login registers against both the username and the caller's IP, and the IP
     * counter is checked first. This clears both sides in one pass.
     *
     * @param string $key
     * @param string $type
     * @return int Number of counters that existed and were cleared.
     */
    public function resetRelatedRateLimits($key, $type = 'username'): int
    {
        if (!$key) {
            return 0;
        }

        $index = $this->getIndex();

        // Always target the key itself, even if the index never saw it — lockouts
        // registered before this plugin version have no index entry.
        $targets = [$this->indexId($key, $type) => ['type' => $type, 'key' => $key]];
        foreach ($index as $id => $entry) {
            if (isset($entry['links'][$type][$key])) {
                $targets[$id] = $entry;
            }
        }

        $cleared = 0;
        $touched = false;
        foreach ($targets as $id => $entry) {
            $cacheKey = $entry['type'] . $entry['key'];
            if ($this->cache->has($cacheKey)) {
                $cleared++;
            }
            $this->cache->delete($cacheKey);
            if (isset($index[$id])) {
                unset($index[$id]);
                $touched = true;
            }
        }

        if ($touched) {
            $this->cache->set(static::INDEX_KEY, $index);
        }

        return $cleared;
    }

    /**
     * Wipe every counter in this context, index included.
     *
     * @return $this
     */
    public function resetAllRateLimits()
    {
        $this->cache->clear();

        return $this;
    }

    /**
     * List the keys this context has registered, newest last.
     *
     * @param string|null $type Restrict to one key type, or null for all.
     * @param bool $limitedOnly Only return keys that are currently over the limit.
     * @return array<int, array<string, mixed>> Each: type, key, attempts, first, last, limited, links
     */
    public function getRegisteredKeys(?string $type = null, bool $limitedOnly = false): array
    {
        $entries = [];
        foreach ($this->getIndex() as $entry) {
            if ($type !== null && $entry['type'] !== $type) {
                continue;
            }

            $limited = $this->isRateLimited($entry['key'], $entry['type']);
            if ($limitedOnly && !$limited) {
                continue;
            }

            $attempts = $this->getAttempts($entry['key'], $entry['type']);
            $entries[] = [
                'type' => $entry['type'],
                'key' => $entry['key'],
                'attempts' => \count($attempts),
                'first' => $attempts ? min($attempts) : null,
                'last' => $attempts ? max($attempts) : ($entry['time'] ?? null),
                'limited' => $limited,
                'links' => $entry['links'] ?? [],
            ];
        }

        return $entries;
    }

    /**
     * Read the key index, dropping entries whose counter has since expired.
     *
     * @return array<string, array<string, mixed>>
     */
    protected function getIndex(): array
    {
        $index = (array)$this->cache->get(static::INDEX_KEY, []);

        $pruned = false;
        foreach ($index as $id => $entry) {
            if (!\is_array($entry) || !isset($entry['type'], $entry['key'])
                || !$this->cache->has($entry['type'] . $entry['key'])) {
                unset($index[$id]);
                $pruned = true;
            }
        }

        if ($pruned) {
            $this->cache->set(static::INDEX_KEY, $index);
        }

        return $index;
    }

    /**
     * Record a key in the index and refresh its links.
     *
     * @param string $key
     * @param string $type
     * @param array<string, string> $links
     * @return void
     */
    protected function indexKey($key, $type, array $links = []): void
    {
        $index = $this->getIndex();
        $id = $this->indexId($key, $type);

        $entry = $index[$id] ?? ['type' => $type, 'key' => $key, 'links' => []];
        $entry['time'] = time();

        foreach ($links as $linkType => $linkKey) {
            if (!\is_string($linkType) || !\is_string($linkKey) || $linkKey === '') {
                continue;
            }
            if (\count($entry['links'][$linkType] ?? []) >= static::INDEX_MAX_LINKS) {
                continue;
            }
            $entry['links'][$linkType][$linkKey] = true;
        }

        // Re-append so the array stays ordered oldest-first and the cap below
        // evicts the least recently seen keys.
        unset($index[$id]);
        $index[$id] = $entry;

        if (\count($index) > static::INDEX_MAX_KEYS) {
            $index = \array_slice($index, -static::INDEX_MAX_KEYS, null, true);
        }

        $this->cache->set(static::INDEX_KEY, $index);
    }

    /**
     * @param string $key
     * @param string $type
     * @return string
     */
    protected function indexId($key, $type): string
    {
        return $type . '|' . $key;
    }
}
