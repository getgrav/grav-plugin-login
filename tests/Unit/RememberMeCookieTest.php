<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Common\User\Interfaces\UserInterface;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Plugin\Login\Login;
use Grav\Plugin\Login\RememberMe\RememberMe;
use Grav\Plugin\LoginPlugin;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * LoginPlugin::userLogin() gives a login the "remember me" cookie only while plugins.login.rememberme.enabled is on,
 * whatever the login asked for: the form's rememberme field, or a plugin such as Login OAuth2 that always asks.
 * With 2FA the cookie waits for the second factor (remember_me_pending), and that waits for the setting too.
 * Needs Grav core's classes: run it with core's phpunit (../grav/vendor/bin/phpunit).
 */
final class RememberMeCookieTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!class_exists(\Grav\Common\Plugin::class)) {
            self::markTestSkipped('Needs Grav core on the autoloader.');
        }
        require_once dirname(__DIR__, 2) . '/login.php';
    }

    /**
     * @return array<string, array{0: bool, 1: mixed, 2: bool, 3: int, 4: bool}>
     */
    public static function logins(): array
    {
        // setting on, rememberme credential, 2FA pending, cookies created, pending set
        return [
            'on, asked for'                       => [true, '1', false, 1, false],
            'on, not asked for'                   => [true, null, false, 0, false],
            'off, asked for by the form'          => [false, '1', false, 0, false],
            'off, asked for by a plugin (OAuth2)' => [false, true, false, 0, false],
            'on, asked for, 2FA still to come'    => [true, '1', true, 0, true],
            'off, asked for, 2FA still to come'   => [false, '1', true, 0, false],
        ];
    }

    #[DataProvider('logins')]
    public function testTheCookieFollowsTheSetting(bool $enabled, mixed $asked, bool $delayed, int $cookies, bool $pending): void
    {
        $rememberMe = $this->createMock(RememberMe::class);
        $rememberMe->expects(self::exactly($cookies))->method('createCookie')->with('jdoe');

        $config = new class(['plugins.login.rememberme.enabled' => $enabled, 'system.session.initialize' => false]) {
            /** @param array<string, mixed> $settings */
            public function __construct(private array $settings) {}

            public function get(string $key, mixed $default = null): mixed
            {
                return array_key_exists($key, $this->settings) ? $this->settings[$key] : $default;
            }
        };

        $login = (new \ReflectionClass(Login::class))->newInstanceWithoutConstructor();
        $login->rememberMe($rememberMe);

        $session = new \stdClass();
        $plugin = (new \ReflectionClass(LoginPlugin::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(LoginPlugin::class, 'grav'))->setValue($plugin, new \ArrayObject(['session' => $session, 'login' => $login, 'config' => $config]));
        (new \ReflectionProperty(LoginPlugin::class, 'config'))->setValue($plugin, $config);

        $user = $this->createMock(UserInterface::class);
        $user->method('get')->willReturnCallback(static fn (string $name) => $name === 'username' ? 'jdoe' : null);

        $status = UserLoginEvent::AUTHENTICATION_SUCCESS | ($delayed ? UserLoginEvent::AUTHORIZATION_DELAYED : 0);
        $event = new UserLoginEvent([
            'credentials' => $asked === null ? [] : ['rememberme' => $asked],
            'options' => ['remember_me' => true],
            'session' => $session,
            'user' => $user,
            'status' => $status,
        ]);

        $plugin->userLogin($event);

        self::assertSame($pending, isset($session->remember_me_pending));
    }
}
