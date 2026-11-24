<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Common\Data\Blueprint;
use Grav\Common\Filesystem\Folder;
use Grav\Common\User\DataUser\User;
use Grav\Plugin\Login\Login;
use Grav\Plugin\Login\RememberMe\TokenStorage;
use PHPUnit\Framework\TestCase;

/**
 * A remember-me cookie dies with its account, and a profile save doesn't write back stale state, access, password
 * or passkeys.
 * Needs Grav core's classes: run it with core's phpunit (../grav/vendor/bin/phpunit).
 */
final class AccountStateTest extends TestCase
{
    /** @var string|null The token folder of a test, removed after it. */
    private $sandbox;
    /** @var string|null The compiled file cache the test made, when there was none before. */
    private $madeCache;

    public static function setUpBeforeClass(): void
    {
        if (!class_exists(\Grav\Common\Plugin::class)) {
            self::markTestSkipped('Needs Grav core on the autoloader.');
        }
    }

    protected function tearDown(): void
    {
        if ($this->sandbox !== null) {
            Folder::delete($this->sandbox);
            $this->sandbox = null;
        }
        if ($this->madeCache !== null) {
            Folder::delete($this->madeCache);
            $this->madeCache = null;
        }
    }

    public function testARememberMeTokenIsRefusedOnceItsAccountWasCreatedAgain(): void
    {
        $storage = $this->storage(['jdoe' => 1000]);

        $storage->storeTriplet('jdoe', 'token-1', 'persistent-1');
        self::assertSame(TokenStorage::TRIPLET_FOUND, $storage->findTriplet('jdoe', 'token-1', 'persistent-1'));
        self::assertSame(TokenStorage::TRIPLET_INVALID, $storage->findTriplet('jdoe', 'token-2', 'persistent-1'));

        // The account was deleted and created again under the same username.
        $storage->created['jdoe'] = 2000;
        self::assertSame(TokenStorage::TRIPLET_NOT_FOUND, $storage->findTriplet('jdoe', 'token-1', 'persistent-1'));

        // A cookie issued to the new account works.
        $storage->storeTriplet('jdoe', 'token-3', 'persistent-3');
        self::assertSame(TokenStorage::TRIPLET_FOUND, $storage->findTriplet('jdoe', 'token-3', 'persistent-3'));
    }

    public function testARememberMeTokenStillWorksForAnAccountWithNoCreatedTime(): void
    {
        $storage = $this->storage(['jdoe' => 0]);

        $storage->storeTriplet('jdoe', 'token-1', 'persistent-1');
        self::assertSame(TokenStorage::TRIPLET_FOUND, $storage->findTriplet('jdoe', 'token-1', 'persistent-1'));
    }

    public function testARememberMeTokenStoredBeforeTheCheckStillWorks(): void
    {
        $storage = $this->storage(['jdoe' => 1000]);

        // The format before the account's created time was kept with the token.
        $file = \Grav\Common\File\CompiledYamlFile::instance($storage->path() . '/' . sha1('jdoe') . '.yaml');
        $file->save([sha1('persistent-1') => [sha1('token-1') => time()]]);

        self::assertSame(TokenStorage::TRIPLET_FOUND, $storage->findTriplet('jdoe', 'token-1', 'persistent-1'));
    }

    public function testAProfileSaveStartsFromTheStoredAccountNotTheSessionsCopy(): void
    {
        $session = new class([
            'username' => 'jdoe',
            'state' => 'enabled',
            'access' => ['site' => ['login' => true], 'admin' => ['super' => true]],
            'groups' => ['editors'],
            'hashed_password' => 'old-hash',
            'passkeys' => ['abc' => ['name' => 'Laptop']],
            'webauthn_id' => 'old-id',
            'language' => 'en',
        ], new Blueprint('user/account')) extends User {
            public function exists()
            {
                return true;
            }
        };
        $stored = new User([
            'username' => 'jdoe',
            'state' => 'enabled',
            'access' => ['site' => ['login' => true]],
            'hashed_password' => 'new-hash',
            'language' => 'fr',
        ], new Blueprint('user/account'));

        $login = $this->getMockBuilder(Login::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['loadStoredAccount'])
            ->getMock();
        $login->method('loadStoredAccount')->willReturn($stored);

        $login->refreshAccountFields($session);

        self::assertSame(['site' => ['login' => true]], $session->get('access'));
        self::assertNull($session->get('groups'));
        self::assertSame('new-hash', $session->get('hashed_password'));
        self::assertNull($session->get('passkeys'));
        self::assertNull($session->get('webauthn_id'));
        // Fields the profile form changes, and the rest of the account, are left alone.
        self::assertSame('en', $session->get('language'));
    }

    /**
     * @param array<string, int> $created The `created` time of each account, by username.
     */
    private function storage(array $created): TokenStorage
    {
        // Compiled YAML files are cached in core's cache folder, which is only removed when this test made it.
        if (defined('CACHE_DIR') && !is_dir(CACHE_DIR)) {
            $this->madeCache = rtrim(CACHE_DIR, '/');
        }
        $this->sandbox = sys_get_temp_dir() . '/login-rememberme-' . bin2hex(random_bytes(4));
        $dir = $this->sandbox . '/tokens';
        mkdir($dir, 0777, true);

        $storage = new class($created, $dir) extends TokenStorage {
            /** @var array<string, int> */
            public $created;

            public function __construct(array $created, string $dir)
            {
                $this->created = $created;
                $this->path = $dir;
                $this->timeout = 604800;
            }

            public function path(): string
            {
                return $this->path;
            }

            protected function accountCreated(string $credential): int
            {
                return $this->created[$credential] ?? 0;
            }
        };

        return $storage;
    }
}
