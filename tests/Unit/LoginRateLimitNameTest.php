<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Plugin\Login\Login;
use PHPUnit\Framework\TestCase;

final class LoginRateLimitNameTest extends TestCase
{
    public function testRateLimitNameUsesTheStoredUsername(): void
    {
        $login = $this->loginWithAccounts(null);

        self::assertSame('admin', $login->rateLimitName('Admin', $this->account('admin')));
        self::assertSame('admin', $login->rateLimitName('ADMIN', $this->account('admin')));
    }

    public function testRateLimitNameResolvesAnEmailAddress(): void
    {
        $login = $this->loginWithAccounts($this->account('admin'));

        self::assertSame('admin', $login->rateLimitName('Admin@Example.com', $this->account(null)));
    }

    public function testRateLimitNameKeepsTheSubmittedNameForAnUnknownAccount(): void
    {
        $login = $this->loginWithAccounts($this->account(null));

        self::assertSame('nobody', $login->rateLimitName('nobody', $this->account(null)));
        self::assertSame('', $login->rateLimitName('', null));
    }

    /**
     * @param object|null $found What the account lookup by email returns.
     */
    private function loginWithAccounts(?object $found): Login
    {
        $accounts = new class($found) {
            public function __construct(private ?object $found) {}

            public function find(string $query, array $fields = [])
            {
                return $this->found ?? new class { public function exists(): bool { return false; } };
            }
        };

        $login = (new \ReflectionClass(Login::class))->newInstanceWithoutConstructor();
        $property = new \ReflectionProperty(Login::class, 'grav');
        $property->setValue($login, new \ArrayObject(['accounts' => $accounts]));

        return $login;
    }

    private function account(?string $username): object
    {
        return new class($username) {
            public function __construct(private ?string $username) {}

            public function exists(): bool
            {
                return $this->username !== null;
            }

            public function get(string $name)
            {
                return $name === 'username' ? $this->username : null;
            }
        };
    }
}
