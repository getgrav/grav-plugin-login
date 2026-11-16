<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Common\Data\Blueprint;
use Grav\Common\User\DataUser\User;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Plugin\Login\Login;
use Grav\Plugin\Login\Passkeys\Passkeys;
use Grav\Plugin\Login\Passkeys\SiteController;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A passkey sign-in with "Remember me" ticked hands the box to Login::login() as the `rememberme` credential, the
 * same as the login form does, since that is what LoginPlugin::userLogin() issues the cookie from (and only while
 * plugins.login.rememberme.enabled is on, see RememberMeCookieTest). It used to arrive as the `remember_me` option
 * only, so a passkey login was never remembered.
 * Needs Grav core's classes: run it with core's phpunit (../grav/vendor/bin/phpunit).
 */
final class PasskeyRememberMeTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!class_exists(\Grav\Common\Plugin::class)) {
            self::markTestSkipped('Needs Grav core on the autoloader.');
        }
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function boxes(): array
    {
        return [
            'ticked' => [['rememberme' => 1], true],
            'not ticked' => [['rememberme' => 0], false],
            'not sent' => [[], false],
        ];
    }

    /** @param array<string, mixed> $data */
    #[DataProvider('boxes')]
    public function testTheBoxBecomesTheRemembermeCredential(array $data, bool $remember): void
    {
        $user = new User(['username' => 'jdoe'], new Blueprint('user/account'));
        $user->authenticated = true;
        $user->authorized = true;

        $passkeys = $this->createMock(Passkeys::class);
        $passkeys->method('verifyAssertion')->willReturn($user);

        $seen = [];
        $login = $this->createMock(Login::class);
        $login->method('getRoute')->willReturn('/');
        $login->expects(self::once())->method('login')->willReturnCallback(
            static function (array $credentials, array $options) use (&$seen, $user) {
                $seen = [$credentials, $options];

                return new UserLoginEvent(['credentials' => $credentials, 'options' => $options, 'user' => $user, 'session' => new \stdClass()]);
            }
        );

        $grav = new \ArrayObject([
            'session' => (object)['redirect_after_login' => null],
            'messages' => new class { public function add(): void {} },
            'language' => new class { public function translate($key): string { return (string)(is_array($key) ? $key[0] : $key); } },
            'uri' => new class { public function isExternal(): bool { return false; } },
            'pages' => new class { public function route(string $route): string { return $route; } },
        ]);

        $controller = (new \ReflectionClass(SiteController::class))->newInstanceWithoutConstructor();
        foreach (['grav' => $grav, 'login' => $login, 'passkeys' => $passkeys, 'post' => []] as $name => $value) {
            (new \ReflectionProperty(SiteController::class, $name))->setValue($controller, $value);
        }

        [$status] = (new \ReflectionMethod(SiteController::class, 'signIn'))->invoke($controller, ['ticket' => 't', 'credential' => []] + $data);

        self::assertSame(200, $status);
        [$credentials, $options] = $seen;
        self::assertSame('jdoe', $credentials['username']);
        self::assertSame($remember, $credentials['rememberme'] ?? false);
        // userLogin() only looks at the credential when this option is set.
        self::assertTrue($options['remember_me']);
        self::assertTrue($options['passkey']);
    }
}
