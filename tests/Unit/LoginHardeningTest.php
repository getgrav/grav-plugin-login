<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Common\Data\Blueprint;
use Grav\Common\Grav;
use Grav\Common\User\DataUser\User;
use Grav\Plugin\Login\Controller;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Plugin\Login\Login;
use Grav\Plugin\LoginPlugin;
use PHPUnit\Framework\TestCase;

/**
 * A non-string task is ignored, a login event never hands credentials to a dumper, and a message built from an
 * exception is escaped.
 * Needs Grav core's classes: run it with core's phpunit (../grav/vendor/bin/phpunit).
 */
final class LoginHardeningTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!class_exists(\Grav\Common\Plugin::class)) {
            self::markTestSkipped('Needs Grav core on the autoloader.');
        }
        require_once dirname(__DIR__, 2) . '/login.php';
    }

    protected function tearDown(): void
    {
        unset($_POST['task']);
        (new \ReflectionProperty(Grav::class, 'instance'))->setValue(null, null);
    }

    public function testAnArrayTaskDoesNotBreakTheLoginPage(): void
    {
        $_POST['task'] = ['x'];

        $twig = new \stdClass();
        $twig->twig_vars = [];
        $twig->template = '';

        $grav = new class(['twig' => $twig, 'uri' => new class {
            public function param($id, $default = false)
            {
                return $default;
            }

            public function extension()
            {
                return null;
            }
        }, 'assets' => new \stdClass(), 'session' => new class {
            public function getFlashCookieObject($name)
            {
                return null;
            }
        }]) extends \ArrayObject {
            public function fireEvent($name, $event = null)
            {
                return $event;
            }
        };

        // Stand the stub in for Grav::instance(), which booting would give error handlers.
        (new \ReflectionProperty(Grav::class, 'instance'))->setValue(null, $grav);

        $login = $this->createMock(Login::class);
        $login->method('passkeys')->willReturn(null);

        $config = new class {
            public function get(string $key, $default = null)
            {
                return false;
            }
        };

        $plugin = (new \ReflectionClass(LoginPlugin::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(LoginPlugin::class, 'grav'))->setValue($plugin, $grav);
        (new \ReflectionProperty(LoginPlugin::class, 'config'))->setValue($plugin, $config);
        (new \ReflectionProperty(LoginPlugin::class, 'login'))->setValue($plugin, $login);
        (new \ReflectionProperty(LoginPlugin::class, 'authenticated'))->setValue($plugin, true);

        $plugin->onTwigSiteVariables();

        self::assertArrayNotHasKey('username', $twig->twig_vars);
        self::assertArrayNotHasKey('token', $twig->twig_vars);
    }

    public function testADumpOfALoginEventHoldsNoCredentialsOrAccountData(): void
    {
        $user = new User([
            'username' => 'jdoe',
            'hashed_password' => '$2y$10$hashhashhashhashhashhashhashhashhash',
            'twofa_secret' => 'TWOFASECRETVALUE',
        ], new Blueprint('user/account'));

        $event = new UserLoginEvent([
            'credentials' => ['username' => 'jdoe', 'password' => 'plain-text-password', 'twofa' => '123456'],
            'user' => $user,
            'session' => new \stdClass(),
            'status' => UserLoginEvent::AUTHENTICATION_FAILURE,
        ]);
        $event->setMessage('Login failed', 'error');
        $event->setRedirect('/login');

        $dump = print_r($event, true);
        ob_start();
        var_dump($event);
        $dump .= ob_get_clean();

        foreach (['plain-text-password', '123456', 'hashhash', 'TWOFASECRETVALUE'] as $secret) {
            self::assertStringNotContainsString($secret, $dump);
        }
        self::assertStringContainsString('jdoe', $dump);
        self::assertStringContainsString('Login failed', $dump);
        self::assertStringContainsString('/login', $dump);
    }

    public function testAnExceptionMessageIsEscapedBeforeItIsShown(): void
    {
        $messages = new class {
            public $added = [];

            public function add($message, $scope = 'default'): void
            {
                $this->added[] = [$message, $scope];
            }
        };
        $log = new class {
            public $errors = [];

            public function error($message): void
            {
                $this->errors[] = $message;
            }
        };
        $grav = new \ArrayObject(['messages' => $messages, 'log' => $log]);

        $controller = new class($grav, 'x') extends Controller {
            public function __construct($grav, $action)
            {
                $this->grav = $grav;
                $this->action = $action;
                $this->post = [];
            }

            public function taskX(): bool
            {
                throw new \RuntimeException('Username <img src=x onerror=alert(1)> isn\'t "valid"');
            }
        };

        $controller->execute();

        self::assertSame([['Username &lt;img src=x onerror=alert(1)&gt; isn&apos;t &quot;valid&quot;', 'error']], $messages->added);
        // The log keeps the message as it was.
        self::assertSame(['plugin.login: Username <img src=x onerror=alert(1)> isn\'t "valid"'], $log->errors);
    }
}
