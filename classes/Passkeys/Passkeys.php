<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2026 Trilby Media, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login\Passkeys;

use Grav\Common\Grav;
use Grav\Common\User\Interfaces\UserCollectionInterface;
use Grav\Common\User\Interfaces\UserInterface;
use Grav\Plugin\Login\Login;
use Grav\Plugin\Login\LoginCache;
use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\WebAuthnException;

/**
 * Passkeys (WebAuthn) for Grav accounts: adding one, and signing in with one.
 *
 * Grav 2 only. Login still installs on Grav 1.7 and PHP 7.3, so nothing here
 * may run there: Login::passkeys() hands this class out only when
 * self::supported() says so, and this file is the only one that touches the
 * WebAuthn library (which needs PHP 8). The library ships in vendor/ with
 * composer's platform check off, so it costs nothing until this class loads.
 *
 * A passkey is both factors at once (the device, and the face, finger or PIN
 * that unlocks it), so user verification is always required and signing in
 * with one skips the authenticator-app step. It can also stand in for the
 * app code after a password.
 *
 * Passkeys live on the account (`passkeys:` list, `webauthn_id` user handle),
 * so a site and its admin share them: same host, same account. An index from
 * credential id to username (rebuilt from the accounts when it misses) lets a
 * passkey sign in without a username typed first.
 *
 * Every ceremony is a one-use ticket: the browser gets the ticket and the
 * options, signs the challenge, and sends both back. The challenge is spent
 * whether or not the answer checks out.
 */
class Passkeys
{
    public const CHALLENGE_TTL = 300;
    public const MAX_PER_ACCOUNT = 20;
    public const NAME_MAX = 60;

    /** Account fields only this class may write. Never mass-assigned. */
    public const ACCOUNT_FIELDS = ['passkeys', 'webauthn_id'];

    private const INDEX_KEY = 'index';
    private const INDEX_REBUILD_GAP = 60;

    /** Names for the common password managers and devices, by AAGUID. */
    private const AUTHENTICATORS = [
        'bada5566-a7aa-401f-bd96-45619a55120d' => '1Password',
        'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' => 'iCloud Keychain',
        'dd4ec289-e01d-41c9-bb89-70fa845d4bf2' => 'iCloud Keychain',
        'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' => 'Google Password Manager',
        'adce0002-35bc-c60a-648b-0b25f1f05503' => 'Chrome on Mac',
        '08987058-cadc-4b81-b6e1-30de50dcbe96' => 'Windows Hello',
        '9ddd1817-af5a-4672-a2b9-3e3dd95000a9' => 'Windows Hello',
        '6028b017-b1d4-4c02-b4b3-afcdafc96bb2' => 'Windows Hello',
        'd548826e-79b4-db40-a3d8-11116f7e8349' => 'Bitwarden',
        '531126d6-e717-415c-9320-3d9aa6981239' => 'Dashlane',
        '50726f74-6f6e-5061-7373-50726f746f6e' => 'Proton Pass',
        'fdb141b2-5d84-443e-8a35-4698c205a502' => 'KeePassXC',
        '53414d53-554e-4700-0000-000000000000' => 'Samsung Pass',
    ];

    /** @var Grav */
    private $grav;
    /** @var Login|null */
    private $login;
    /** @var LoginCache|null */
    private $challenges;
    /** @var LoginCache|null */
    private $index;
    /** @var string|null */
    private $usedName;

    public function __construct(Grav $grav, ?Login $login = null)
    {
        $this->grav = $grav;
        $this->login = $login;
    }

    /**
     * Whether this install can run passkeys at all: Grav 2, PHP 8, OpenSSL
     * and the bundled library. Safe to call on any version.
     */
    public static function supported(): bool
    {
        return PHP_VERSION_ID >= 80000
            && defined('GRAV_VERSION')
            && version_compare(GRAV_VERSION, '2.0.0-dev', '>=')
            && extension_loaded('openssl')
            && class_exists(WebAuthn::class);
    }

    // ------------------------------------------------------------------
    // Relying party
    // ------------------------------------------------------------------

    /** scheme://host[:port] the browser reports as the origin. */
    public function origin(): string
    {
        $configured = trim((string)$this->config('origin', ''));
        if ($configured !== '') {
            return rtrim($configured, '/');
        }

        $base = (string)$this->grav['config']->get('system.custom_base_url', '');
        $url = parse_url($base !== '' && preg_match('#^https?://#i', $base) ? $base : $this->grav['uri']->rootUrl(true));
        $origin = strtolower(($url['scheme'] ?? 'https') . '://' . ($url['host'] ?? ''));

        return isset($url['port']) ? $origin . ':' . $url['port'] : $origin;
    }

    /** The host passkeys belong to. */
    public function rpId(): string
    {
        $configured = trim((string)$this->config('rp_id', ''));

        return $configured !== '' ? strtolower($configured) : (string)parse_url($this->origin(), PHP_URL_HOST);
    }

    private function rpName(): string
    {
        $name = trim((string)$this->grav['config']->get('site.title', ''));

        return $name !== '' ? mb_substr($name, 0, 64) : $this->rpId();
    }

    // ------------------------------------------------------------------
    // Adding a passkey
    // ------------------------------------------------------------------

    /**
     * Options for navigator.credentials.create(), and the ticket that goes
     * back with the answer.
     *
     * @return array{options: array, ticket: string}
     */
    public function registrationOptions(UserInterface $user): array
    {
        $username = (string)$user->get('username');
        $challenge = random_bytes(32);
        $ticket = $this->saveChallenge($challenge, 'add', $username);

        $exclude = [];
        foreach ($this->rows($user) as $row) {
            $exclude[] = ['type' => 'public-key', 'id' => $row['id']] + $this->transportsFor($row);
        }

        $fullname = trim((string)$user->get('fullname', ''));

        return [
            'ticket' => $ticket,
            'options' => [
                'rp' => ['id' => $this->rpId(), 'name' => $this->rpName()],
                'user' => [
                    'id' => $this->userHandle($user),
                    'name' => $username,
                    'displayName' => $fullname !== '' ? $fullname : $username,
                ],
                'challenge' => self::b64u($challenge),
                'pubKeyCredParams' => [
                    ['type' => 'public-key', 'alg' => -7],    // ES256
                    ['type' => 'public-key', 'alg' => -8],    // EdDSA
                    ['type' => 'public-key', 'alg' => -257],  // RS256 (Windows Hello)
                ],
                'timeout' => self::CHALLENGE_TTL * 1000,
                'excludeCredentials' => $exclude,
                'authenticatorSelection' => [
                    'residentKey' => 'required',
                    'requireResidentKey' => true,
                    'userVerification' => 'required',
                ],
                'attestation' => 'none',
            ],
        ];
    }

    /**
     * Check the browser's answer and store the passkey on the account.
     *
     * @param array $credential PublicKeyCredential as JSON (toJSON() form)
     * @return array The new passkey, as list() shows it
     * @throws PasskeyException with a message for the person
     */
    public function finishRegistration(UserInterface $user, string $ticket, array $credential): array
    {
        $username = (string)$user->get('username');
        $challenge = $this->spendChallenge($ticket, 'add', $username);
        if ($challenge === null) {
            throw new PasskeyException('PLUGIN_LOGIN.PASSKEY_EXPIRED');
        }

        $clientDataJSON = self::unb64u($credential['response']['clientDataJSON'] ?? null);
        $attestation = self::unb64u($credential['response']['attestationObject'] ?? null);
        if ($clientDataJSON === null || $attestation === null) {
            throw new PasskeyException('PLUGIN_LOGIN.PASSKEY_UNREADABLE');
        }

        try {
            $this->checkOrigin($clientDataJSON);
            $data = $this->webAuthn()->processCreate($clientDataJSON, $attestation, $challenge, true, true, false);
        } catch (WebAuthnException | \RuntimeException $e) {
            $this->grav['log']->info(sprintf('plugin.login: passkey for "%s" refused: %s', $username, $e->getMessage()));
            throw new PasskeyException('PLUGIN_LOGIN.PASSKEY_NOT_CHECKED');
        }

        $account = $this->freshAccount($username);
        if ($account === null) {
            throw new PasskeyException('PLUGIN_LOGIN.PASSKEY_NOT_CHECKED');
        }
        $rows = $this->rows($account);
        if (count($rows) >= self::MAX_PER_ACCOUNT) {
            throw new PasskeyException('PLUGIN_LOGIN.PASSKEY_TOO_MANY');
        }

        $id = self::b64u((string)$data->credentialId);
        if ($this->findOwner($id) !== null) {
            throw new PasskeyException('PLUGIN_LOGIN.PASSKEY_IN_USE');
        }

        $aaguid = $data->AAGUID instanceof ByteBuffer ? $data->AAGUID->getBinaryString() : (string)$data->AAGUID;
        $transports = array_values(array_filter(
            (array)($credential['response']['transports'] ?? []),
            static function ($t): bool {
                return is_string($t) && preg_match('/^[a-z-]{1,20}$/', $t) === 1;
            }
        ));

        $row = [
            'id' => $id,
            'name' => $this->defaultName($aaguid),
            'public_key' => (string)$data->credentialPublicKey,
            'sign_count' => (int)($data->signatureCounter ?? 0),
            'aaguid' => strlen($aaguid) === 16 ? bin2hex($aaguid) : null,
            'transports' => $transports,
            'synced' => (bool)($data->isBackupEligible ?? false),
            'created' => time(),
            'last_used' => null,
        ];
        $rows[] = $row;
        $account->set('passkeys', $rows);
        $account->save();
        $this->indexSet($id, $username);
        $this->syncSession($account);

        return $this->present($row);
    }

    // ------------------------------------------------------------------
    // Signing in with a passkey
    // ------------------------------------------------------------------

    /**
     * Options for navigator.credentials.get(). With $user, only that
     * account's passkeys are offered (the step after a password); without,
     * the browser offers whatever passkey it holds for this site.
     *
     * @param string $purpose 'sign-in' or 'second-step'
     * @return array{options: array, ticket: string}
     */
    public function assertionOptions(?UserInterface $user, string $purpose): array
    {
        $username = $user !== null ? (string)$user->get('username') : null;
        $challenge = random_bytes(32);
        $ticket = $this->saveChallenge($challenge, $purpose, $username);

        $allow = [];
        if ($user !== null) {
            foreach ($this->rows($user) as $row) {
                $allow[] = ['type' => 'public-key', 'id' => $row['id']] + $this->transportsFor($row);
            }
        }

        return [
            'ticket' => $ticket,
            'options' => [
                'challenge' => self::b64u($challenge),
                'rpId' => $this->rpId(),
                'timeout' => self::CHALLENGE_TTL * 1000,
                'allowCredentials' => $allow,
                'userVerification' => 'required',
            ],
        ];
    }

    /**
     * Check a passkey answer. Returns the account it signs in, or null. With
     * $user the passkey must belong to that account. usedName() then names
     * the passkey that was used.
     *
     * @param array $credential PublicKeyCredential as JSON (toJSON() form)
     */
    public function verifyAssertion(string $ticket, array $credential, string $purpose, ?UserInterface $user = null): ?UserInterface
    {
        $username = $user !== null ? (string)$user->get('username') : null;
        $challenge = $this->spendChallenge($ticket, $purpose, $username);
        if ($challenge === null) {
            return null;
        }

        $rawId = self::unb64u($credential['rawId'] ?? ($credential['id'] ?? null));
        $clientDataJSON = self::unb64u($credential['response']['clientDataJSON'] ?? null);
        $authenticatorData = self::unb64u($credential['response']['authenticatorData'] ?? null);
        $signature = self::unb64u($credential['response']['signature'] ?? null);
        if ($rawId === null || $clientDataJSON === null || $authenticatorData === null || $signature === null) {
            return null;
        }

        $id = self::b64u($rawId);
        $owner = $this->findOwner($id);
        if ($owner === null || ($username !== null && !hash_equals($username, (string)$owner->get('username')))) {
            return null;
        }
        if ($owner->get('state', 'enabled') !== 'enabled') {
            return null;
        }

        // The account the authenticator says this passkey is for. Absent is
        // allowed (older authenticators); present but unreadable is refused.
        $sentHandle = $credential['response']['userHandle'] ?? null;
        if ($sentHandle !== null && $sentHandle !== '') {
            $userHandle = self::unb64u($sentHandle);
            $handle = self::unb64u((string)$owner->get('webauthn_id', ''));
            if ($userHandle === null || $handle === null || !hash_equals($handle, $userHandle)) {
                return null;
            }
        }

        $rows = $this->rows($owner);
        $index = null;
        foreach ($rows as $i => $row) {
            if (hash_equals($row['id'], $id)) {
                $index = $i;
                break;
            }
        }
        if ($index === null) {
            return null;
        }

        try {
            $this->checkOrigin($clientDataJSON);
            $webAuthn = $this->webAuthn();
            // Synced passkeys always count 0; a counter that goes backwards
            // on a key that counts is a cloned key.
            $webAuthn->processGet($clientDataJSON, $authenticatorData, $signature, (string)$rows[$index]['public_key'], $challenge, (int)$rows[$index]['sign_count'], true, true);
        } catch (WebAuthnException | \RuntimeException $e) {
            $this->grav['log']->info(sprintf('plugin.login: passkey sign-in for "%s" refused: %s', $owner->get('username'), $e->getMessage()));
            return null;
        }

        $rows[$index]['sign_count'] = max((int)$rows[$index]['sign_count'], (int)($webAuthn->getSignatureCounter() ?? 0));
        $rows[$index]['last_used'] = time();
        $owner->set('passkeys', $rows);
        $owner->save();
        $this->usedName = (string)$rows[$index]['name'];

        return $owner;
    }

    /** The name of the passkey the last verifyAssertion() accepted. */
    public function usedName(): ?string
    {
        return $this->usedName;
    }

    // ------------------------------------------------------------------
    // The account's passkeys
    // ------------------------------------------------------------------

    /** @return list<array{id: string, name: string, created: ?int, last_used: ?int, synced: bool}> */
    public function list(UserInterface $user): array
    {
        return array_map(function (array $row): array {
            return $this->present($row);
        }, $this->rows($user));
    }

    public function count(UserInterface $user): int
    {
        return count($this->rows($user));
    }

    public function rename(UserInterface $user, string $id, string $name): bool
    {
        $name = self::cleanName($name);
        $account = $this->freshAccount((string)$user->get('username'));
        if ($account === null || $name === '') {
            return false;
        }
        $rows = $this->rows($account);
        foreach ($rows as $i => $row) {
            if (hash_equals($row['id'], $id)) {
                $rows[$i]['name'] = $name;
                $account->set('passkeys', $rows);
                $account->save();
                $this->syncSession($account);

                return true;
            }
        }

        return false;
    }

    /** Remove a passkey. Returns its name, or null when the account has no such passkey. */
    public function remove(UserInterface $user, string $id): ?string
    {
        $account = $this->freshAccount((string)$user->get('username'));
        if ($account === null) {
            return null;
        }
        $rows = $this->rows($account);
        foreach ($rows as $i => $row) {
            if (hash_equals($row['id'], $id)) {
                unset($rows[$i]);
                $account->set('passkeys', array_values($rows));
                $account->save();
                $this->indexDelete($id);
                $this->syncSession($account);

                return (string)$row['name'];
            }
        }

        return null;
    }

    public static function cleanName(string $name): string
    {
        $name = trim(preg_replace('/\s+/u', ' ', strip_tags($name)) ?? '');

        return mb_substr($name, 0, self::NAME_MAX);
    }

    // ------------------------------------------------------------------

    private function present(array $row): array
    {
        return [
            'id' => (string)$row['id'],
            'name' => (string)$row['name'],
            'created' => isset($row['created']) ? (int)$row['created'] : null,
            'last_used' => !empty($row['last_used']) ? (int)$row['last_used'] : null,
            'synced' => !empty($row['synced']),
        ];
    }

    /** The account's stored passkeys, the malformed ones left out. */
    private function rows(UserInterface $user): array
    {
        $rows = [];
        foreach ((array)$user->get('passkeys', []) as $row) {
            if (is_array($row) && is_string($row['id'] ?? null) && $row['id'] !== '' && is_string($row['public_key'] ?? null)) {
                $row['sign_count'] = (int)($row['sign_count'] ?? 0);
                $row['name'] = (string)($row['name'] ?? 'Passkey');
                $rows[] = $row;
            }
        }

        return $rows;
    }

    private function transportsFor(array $row): array
    {
        $transports = $row['transports'] ?? null;

        return is_array($transports) && $transports !== [] ? ['transports' => array_values($transports)] : [];
    }

    /** The account's passkey user handle (base64url), made on first use. */
    private function userHandle(UserInterface $user): string
    {
        $account = $this->freshAccount((string)$user->get('username')) ?? $user;
        $handle = (string)$account->get('webauthn_id', '');
        if ($handle === '' || self::unb64u($handle) === null) {
            $handle = self::b64u(random_bytes(32));
            $account->set('webauthn_id', $handle);
            $account->save();
            $this->syncSession($account);
        }

        return $handle;
    }

    private function defaultName(string $aaguid): string
    {
        if (strlen($aaguid) === 16) {
            $hex = bin2hex($aaguid);
            $uuid = substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
            if (isset(self::AUTHENTICATORS[$uuid])) {
                return self::AUTHENTICATORS[$uuid];
            }
        }

        return 'Passkey';
    }

    /** The stored account, read again from disk (not the session copy). */
    private function freshAccount(string $username): ?UserInterface
    {
        if ($username === '') {
            return null;
        }
        /** @var UserCollectionInterface $accounts */
        $accounts = $this->grav['accounts'];
        $account = $accounts->load($username);
        if (is_callable([$account, 'refresh'])) {
            $account->refresh(true);
        }

        return $account->exists() ? $account : null;
    }

    /** Keep the signed-in session's copy of the account in step with a change. */
    private function syncSession(UserInterface $account): void
    {
        $sessionUser = $this->grav['user'] ?? null;
        if ($sessionUser instanceof UserInterface && $sessionUser->get('username') === $account->get('username')) {
            foreach (self::ACCOUNT_FIELDS as $field) {
                $sessionUser->set($field, $account->get($field));
            }
        }
    }

    // ------------------------------------------------------------------
    // Credential id → account
    // ------------------------------------------------------------------

    /** The active account holding this passkey, or null. */
    private function findOwner(string $id): ?UserInterface
    {
        $map = $this->indexCache()->get(self::INDEX_KEY, []);
        $username = is_array($map) ? ($map[$id] ?? null) : null;
        if (is_string($username)) {
            $account = $this->freshAccount($username);
            if ($account !== null && $this->holds($account, $id)) {
                return $account;
            }
        }

        // A miss: the index is a cache (cleared with Grav's cache), so build
        // it again from the accounts, at most once a minute.
        $map = $this->rebuildIndex();
        $username = $map[$id] ?? null;
        if (!is_string($username)) {
            return null;
        }
        $account = $this->freshAccount($username);

        return $account !== null && $this->holds($account, $id) ? $account : null;
    }

    private function holds(UserInterface $account, string $id): bool
    {
        foreach ($this->rows($account) as $row) {
            if (hash_equals($row['id'], $id)) {
                return true;
            }
        }

        return false;
    }

    /** @return array<string, string> */
    private function rebuildIndex(): array
    {
        $cache = $this->indexCache();
        $map = $cache->get(self::INDEX_KEY, []);
        $map = is_array($map) ? $map : [];
        $last = (int)$cache->get('rebuilt', 0);
        if ($last > time() - self::INDEX_REBUILD_GAP) {
            return $map;
        }

        // One rebuild at a time: a request that finds one running uses the
        // index as it is rather than scanning the accounts again.
        $lock = $this->lock('passkey-index.lock', false);
        if ($lock === null) {
            return $map;
        }
        try {
            $cache->set('rebuilt', time(), 0);
            $map = [];
            foreach (($this->login ?? $this->grav['login'])->getAccounts() as $account) {
                foreach ($this->rows($account) as $row) {
                    $map[$row['id']] = (string)$account->get('username');
                }
            }
            $cache->set(self::INDEX_KEY, $map, 0);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }

        return $map;
    }

    private function indexSet(string $id, string $username): void
    {
        $map = $this->indexCache()->get(self::INDEX_KEY, []);
        $map = is_array($map) ? $map : [];
        $map[$id] = $username;
        $this->indexCache()->set(self::INDEX_KEY, $map, 0);
    }

    private function indexDelete(string $id): void
    {
        $map = $this->indexCache()->get(self::INDEX_KEY, []);
        if (is_array($map) && isset($map[$id])) {
            unset($map[$id]);
            $this->indexCache()->set(self::INDEX_KEY, $map, 0);
        }
    }

    // ------------------------------------------------------------------
    // Challenges
    // ------------------------------------------------------------------

    private function saveChallenge(string $challenge, string $purpose, ?string $username): string
    {
        // Tickets nobody answers are never read again, so their files would
        // stay; clear out the stale ones now and then.
        if (random_int(1, 50) === 1) {
            $this->pruneChallenges();
        }

        $ticket = bin2hex(random_bytes(32));
        $this->challengeCache()->set(hash('sha256', $ticket), [
            'challenge' => base64_encode($challenge),
            'purpose' => $purpose,
            'user' => $username,
            'expires' => time() + self::CHALLENGE_TTL + 30,
        ], self::CHALLENGE_TTL + 30);

        return $ticket;
    }

    /** The challenge behind $ticket, spent, when it was made for exactly this. */
    private function spendChallenge(string $ticket, string $purpose, ?string $username): ?string
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $ticket)) {
            return null;
        }
        $key = hash('sha256', $ticket);
        $cache = $this->challengeCache();

        // Read and delete under one lock, so two requests racing with the same
        // ticket can't both get its challenge. Fail closed without the lock.
        $lock = $this->lock('passkey-challenges.lock', true);
        if ($lock === null) {
            return null;
        }
        try {
            $saved = $cache->get($key);
            if ($saved !== null && !$cache->delete($key)) {
                return null;
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }

        if (!is_array($saved) || (int)($saved['expires'] ?? 0) < time() || ($saved['purpose'] ?? null) !== $purpose) {
            return null;
        }
        $savedUser = $saved['user'] ?? null;
        if ($username === null ? $savedUser !== null : (!is_string($savedUser) || !hash_equals($savedUser, $username))) {
            return null;
        }
        $challenge = base64_decode((string)($saved['challenge'] ?? ''), true);

        return $challenge === false || $challenge === '' ? null : $challenge;
    }

    /** Exactly this origin; the library alone accepts any host ending in the RP ID. */
    private function checkOrigin(string $clientDataJSON): void
    {
        $clientData = json_decode($clientDataJSON, true);
        if (!is_array($clientData) || !is_string($clientData['origin'] ?? null) || !hash_equals($this->origin(), strtolower($clientData['origin']))) {
            throw new \RuntimeException('origin ' . (is_array($clientData) ? json_encode($clientData['origin'] ?? null) : 'unreadable') . ' is not ' . $this->origin());
        }
    }

    private function webAuthn(): WebAuthn
    {
        return new WebAuthn($this->rpName(), $this->rpId(), ['none', 'packed', 'fido-u2f', 'apple', 'android-key', 'tpm'], true);
    }

    /** Delete challenge files older than any ticket can live. */
    private function pruneChallenges(): void
    {
        $dir = $this->grav['locator']->findResource('cache://login/passkey-challenges', true, true);
        if (!is_string($dir) || !is_dir($dir)) {
            return;
        }
        $cutoff = time() - self::CHALLENGE_TTL - 120;
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($files as $file) {
            if ($file->isFile() && $file->getMTime() < $cutoff) {
                @unlink($file->getPathname());
            }
        }
    }

    /**
     * An exclusive lock on a file in the login cache folder, or null when it
     * can't be had (busy, with $wait false, or the folder isn't writable).
     *
     * @return resource|null
     */
    private function lock(string $name, bool $wait)
    {
        $dir = $this->grav['locator']->findResource('cache://login', true, true);
        if (!is_string($dir) || (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir))) {
            return null;
        }
        $handle = @fopen($dir . '/' . $name, 'c');
        if ($handle === false) {
            return null;
        }
        if (!flock($handle, $wait ? LOCK_EX : LOCK_EX | LOCK_NB)) {
            fclose($handle);
            return null;
        }

        return $handle;
    }

    private function challengeCache(): LoginCache
    {
        return $this->challenges ?? ($this->challenges = new LoginCache('passkey-challenges', self::CHALLENGE_TTL + 30));
    }

    private function indexCache(): LoginCache
    {
        return $this->index ?? ($this->index = new LoginCache('passkey-index', 0));
    }

    /** @return mixed */
    private function config(string $key, $default = null)
    {
        return $this->grav['config']->get('plugins.login.passkeys.' . $key, $default);
    }

    public static function b64u(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** @param mixed $value */
    public static function unb64u($value): ?string
    {
        if (!is_string($value) || $value === '' || preg_match('/^[A-Za-z0-9_-]+={0,2}$/', $value) !== 1) {
            return null;
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
