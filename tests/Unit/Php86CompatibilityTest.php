<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Common\Data\Blueprint;
use Grav\Common\Data\Data;
use Grav\Common\Grav;
use Grav\Common\User\DataUser\User;
use Grav\Common\User\Interfaces\UserInterface;
use Grav\Framework\Form\Interfaces\FormInterface;
use Grav\Plugin\Login\Controller;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Plugin\Login\Login;
use Grav\Plugin\Login\RateLimiter;
use Grav\Plugin\Login\TwoFactorAuth\TwoFactorAuth;
use Grav\Plugin\LoginPlugin;
use PHPUnit\Framework\TestCase;
use RocketTheme\Toolbox\Event\Event;

/**
 * Regression tests for PHP 8.6 compatibility fixes in grav-plugin-login (while keeping PHP 7.3+ support).
 *
 * PHP 8.6 file functions (file_exists(), stat(), is_file() ...) throw ValueError on a NUL byte, and a regular
 * (non-Flex) account collection hands the username straight to them. Every place a request can bring a username
 * to the account storage turns a NUL byte away with the answer it already gives for an unknown or bad name.
 * The accounts stub here throws the same ValueError, so the tests prove the guards on any PHP 8 version.
 * Needs Grav core's classes: run it with core's phpunit (../grav/vendor/bin/phpunit).
 */
final class Php86CompatibilityTest extends TestCase
{
    private const NUL_NAME = "ad\0min";

    public static function setUpBeforeClass(): void
    {
        if (!class_exists(\Grav\Common\Plugin::class)) {
            self::markTestSkipped('Needs Grav core on the autoloader.');
        }
        require_once dirname(__DIR__, 2) . '/login.php';
    }

    protected function tearDown(): void
    {
        self::useGrav(null);
    }

    /**
     * Stand a stub in for Grav::instance(), which UserLoginEvent and Login::validateField() read. Booting the
     * real one would install Grav's error handlers.
     */
    private static function useGrav(?\ArrayObject $grav): void
    {
        (new \ReflectionProperty(Grav::class, 'instance'))->setValue(null, $grav);
    }

    /**
     * Run a callback and fail if any E_DEPRECATED / E_USER_DEPRECATED is triggered.
     *
     * @param callable $callback
     * @return mixed
     */
    private function assertNoDeprecation(callable $callback)
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            if ($errno === E_DEPRECATED || $errno === E_USER_DEPRECATED) {
                $deprecations[] = $errstr;
                return true;
            }
            return false;
        });

        try {
            $result = $callback();
        } finally {
            restore_error_handler();
        }

        $this->assertSame([], $deprecations, 'Unexpected deprecation(s): ' . implode('; ', $deprecations));

        return $result;
    }

    public function testLoginEventOpensTheEmptyAccountForANulByteUsername(): void
    {
        $accounts = new NulStrictAccounts();
        self::useGrav(new GravStub(['accounts' => $accounts]));

        $event = $this->assertNoDeprecation(static function () {
            return new UserLoginEvent([
                'credentials' => ['username' => self::NUL_NAME, 'password' => 'secret'],
                'session' => new \stdClass(),
            ]);
        });

        self::assertSame([['load', '']], $accounts->calls);
        self::assertFalse($event->getUser()->exists());
        // The name as typed is kept for the failure event and the counters.
        self::assertSame(self::NUL_NAME, $event->getCredential('username'));
    }

    public function testLoginEventStillLoadsAnOrdinaryUsername(): void
    {
        $accounts = new NulStrictAccounts();
        self::useGrav(new GravStub(['accounts' => $accounts]));

        new UserLoginEvent(['credentials' => ['username' => 'admin'], 'session' => new \stdClass()]);

        self::assertSame([['load', 'admin']], $accounts->calls);
    }

    public function testLoginByEmailSkipsANulByteName(): void
    {
        $accounts = new NulStrictAccounts();
        $plugin = $this->plugin(new GravStub(['accounts' => $accounts]));
        $user = self::missingUser();
        $event = new UserLoginEvent(['credentials' => ['username' => self::NUL_NAME], 'session' => new \stdClass(), 'user' => $user]);

        $plugin->userLoginAuthenticateByEmail($event);

        self::assertSame([], $accounts->calls);
        self::assertSame($user, $event->getUser());
    }

    public function testActivationLinkWithANulByteGivesTheInvalidRequestAnswer(): void
    {
        $accounts = new NulStrictAccounts();
        $grav = $this->siteGrav($accounts, ['username' => self::NUL_NAME, 'token' => 'abc']);
        $plugin = $this->plugin($grav, $this->loginStub());

        $plugin->handleUserActivation();

        self::assertSame([['load', '']], $accounts->calls);
        self::assertSame([['PLUGIN_LOGIN.INVALID_REQUEST', 'error']], $grav['messages']->added);
        self::assertSame('/', $grav->redirectedTo);
    }

    public function testEmailChangeLinkWithANulByteGivesTheInvalidRequestAnswer(): void
    {
        $accounts = new NulStrictAccounts();
        $grav = $this->siteGrav($accounts, ['username' => self::NUL_NAME, 'token' => 'abc']);
        $plugin = $this->plugin($grav, $this->loginStub());

        $plugin->handleEmailChangeConfirmation();

        self::assertSame([], $accounts->calls);
        self::assertSame([['PLUGIN_LOGIN.INVALID_REQUEST', 'error']], $grav['messages']->added);
        self::assertSame('/login', $grav->redirectedTo);
    }

    public function testMagicLinkWithANulByteGoesBackToTheRequestPage(): void
    {
        $accounts = new NulStrictAccounts();
        $grav = $this->siteGrav($accounts, ['username' => self::NUL_NAME, 'token' => 'abc']);
        $plugin = $this->plugin($grav, $this->loginStub(), ['plugins.login.magic_link.enabled' => true]);

        $plugin->handleMagicLogin();

        self::assertSame([], $accounts->calls);
        self::assertSame('/magic', $grav->redirectedTo);
    }

    public function testRegistrationWithANulByteUsernameIsAValidationError(): void
    {
        $accounts = new NulStrictAccounts();
        $grav = $this->siteGrav($accounts, []);
        $plugin = $this->plugin($grav, $this->loginStub(), [
            'plugins.login.enabled' => true,
            'plugins.login.user_registration.enabled' => true,
        ]);

        $form = $this->createMock(RegistrationFormStub::class);
        $form->method('getData')->willReturn(new Data(['username' => self::NUL_NAME, 'email' => 'someone@example.com']));
        $event = new Event();

        (new \ReflectionMethod(LoginPlugin::class, 'processUserRegistration'))->invoke($plugin, $form, $event);

        self::assertSame([], $accounts->calls);
        self::assertTrue($event->isPropagationStopped());
        self::assertSame([['onFormValidationError', 'PLUGIN_LOGIN.USERNAME_NOT_VALID']], $grav->fired);
    }

    public function testPasswordResetWithANulByteUsernameGivesTheInvalidLinkAnswer(): void
    {
        $accounts = new NulStrictAccounts();
        $grav = $this->siteGrav($accounts, []);

        $controller = (new \ReflectionClass(Controller::class))->newInstanceWithoutConstructor();
        $controller->grav = $grav;
        $controller->post = ['username' => self::NUL_NAME, 'token' => 'abc', 'password' => 'Secret123!'];
        (new \ReflectionProperty(Controller::class, 'login'))->setValue($controller, $this->loginStub());

        self::assertTrue($controller->taskReset());

        self::assertSame([], $accounts->calls);
        self::assertSame([['PLUGIN_LOGIN.RESET_INVALID_LINK', 'error']], $grav['messages']->added);
        self::assertSame('/forgot', $grav->redirectedTo);
    }

    public function testRowActionWithANulByteUsernameHasNoTarget(): void
    {
        $accounts = new NulStrictAccounts();
        $plugin = $this->plugin(new GravStub(['accounts' => $accounts]));

        $target = (new \ReflectionMethod(LoginPlugin::class, 'rowActionTarget'))
            ->invoke($plugin, new Event(['username' => self::NUL_NAME]), 'Super admins only.');

        self::assertNull($target);
        self::assertSame([], $accounts->calls);
    }

    public function testValidateFieldRefusesANulByteWhateverTheUsernameRegex(): void
    {
        self::useGrav(new GravStub(['config' => new ConfigStub(['system.username_regex' => '^.+$'])]));
        $login = (new \ReflectionClass(Login::class))->newInstanceWithoutConstructor();

        self::assertSame('admin', $login->validateField('username', 'admin'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Username does not pass the minimum requirements');
        $login->validateField('username', self::NUL_NAME);
    }

    /**
     * The 2FA check fell back to the stored secret with `??=`, which PHP 7.3 can't parse.
     */
    public function testTwoFactorCheckUsesTheStoredSecretOnlyWhenNoneIsGiven(): void
    {
        $seen = [];
        $twoFa = $this->createMock(TwoFactorAuth::class);
        $twoFa->method('verifyCode')->willReturnCallback(static function (string $secret, string $code) use (&$seen): bool {
            $seen[] = $secret;

            return $code === '123456';
        });

        $limiter = $this->createMock(RateLimiter::class);
        $limiter->method('attempt')->willReturn(true);

        $stored = new User(['username' => 'jdoe', 'twofa_secret' => 'STOREDSECRET'], new Blueprint('user/account'));

        $login = $this->getMockBuilder(Login::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getRateLimiter', 'twoFactorAuth', 'loadStoredAccount'])
            ->getMock();
        $login->method('getRateLimiter')->willReturn($limiter);
        $login->method('twoFactorAuth')->willReturn($twoFa);
        $login->expects(self::once())->method('loadStoredAccount')->willReturn($stored);

        $user = new User(['username' => 'jdoe'], new Blueprint('user/account'));

        self::assertSame(0, $login->verifyCurrentTwoFactorCode($user, '123 456'));
        self::assertSame(0, $login->verifyNewTwoFactorCode($user, 'NEWSECRET', '123456'));
        self::assertSame(['STOREDSECRET', 'NEWSECRET'], $seen);
    }

    /**
     * The plugin's own PHP keeps to PHP 7.3 syntax, since Grav 1.7 sites run it there.
     */
    public function testPluginSourceKeepsToPhp73Syntax(): void
    {
        $banned = [];
        foreach (['T_COALESCE_EQUAL' => '??=', 'T_FN' => 'fn', 'T_MATCH' => 'match', 'T_NULLSAFE_OBJECT_OPERATOR' => '?->'] as $name => $label) {
            if (defined($name)) {
                $banned[constant($name)] = $label;
            }
        }

        $root = dirname(__DIR__, 2);
        $files = [$root . '/login.php'];
        foreach (['classes', 'cli'] as $dir) {
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/' . $dir, \FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if ($file->getExtension() === 'php') {
                    $files[] = $file->getPathname();
                }
            }
        }

        $found = [];
        foreach ($files as $file) {
            foreach (token_get_all((string)file_get_contents($file)) as $token) {
                if (is_array($token) && isset($banned[$token[0]])) {
                    $found[] = substr($file, strlen($root) + 1) . ':' . $token[2] . ' ' . $banned[$token[0]];
                }
            }
        }

        self::assertSame([], $found, 'Syntax newer than PHP 7.3: ' . implode(', ', $found));
    }

    // ------------------------------------------------------------------

    /**
     * @param array<string, mixed> $settings
     */
    private function plugin(GravStub $grav, ?Login $login = null, array $settings = []): LoginPlugin
    {
        $plugin = (new \ReflectionClass(LoginPlugin::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(LoginPlugin::class, 'grav'))->setValue($plugin, $grav);
        (new \ReflectionProperty(LoginPlugin::class, 'config'))->setValue($plugin, new ConfigStub($settings));
        if ($login !== null) {
            (new \ReflectionProperty(LoginPlugin::class, 'login'))->setValue($plugin, $login);
        }

        return $plugin;
    }

    /**
     * @param array<string, string> $params The URI params of the request.
     */
    private function siteGrav(NulStrictAccounts $accounts, array $params): GravStub
    {
        $current = $this->createMock(UserInterface::class);
        $current->method('exists')->willReturn(false);

        return new GravStub([
            'accounts' => $accounts,
            'uri' => new UriStub($params),
            'messages' => new MessagesStub(),
            'language' => new LanguageStub(),
            'user' => $current,
        ]);
    }

    private function loginStub(): Login
    {
        $limiter = $this->createMock(RateLimiter::class);
        $limiter->method('isRateLimited')->willReturn(false);

        $login = $this->createMock(Login::class);
        $login->method('getRateLimiter')->willReturn($limiter);
        $login->method('getIpKey')->willReturn('127.0.0.1');
        $login->method('getRoute')->willReturnCallback(static function (string $type): ?string {
            return ['login' => '/login', 'forgot' => '/forgot', 'magic' => '/magic'][$type] ?? null;
        });

        return $login;
    }

    private static function missingUser(): User
    {
        return new User([], new Blueprint('user/account'));
    }
}

/**
 * An account collection that throws like a regular (non-Flex) one does on PHP 8.6 when a name has a NUL byte.
 */
final class NulStrictAccounts
{
    /** @var array<int, array{0: string, 1: mixed}> */
    public $calls = [];

    public function load($username)
    {
        $this->calls[] = ['load', $username];
        self::guard($username);

        return new User([], new Blueprint('user/account'));
    }

    public function find($query, $fields = ['username', 'email'])
    {
        $this->calls[] = ['find', $query];
        self::guard($query);

        return new User([], new Blueprint('user/account'));
    }

    private static function guard($value): void
    {
        if (is_string($value) && strpos($value, "\0") !== false) {
            throw new \ValueError('file_exists(): Argument #1 ($filename) must not contain any null bytes');
        }
    }
}

/**
 * The form the registration handler is given: a FormInterface with the validate() a Form plugin form has.
 */
abstract class RegistrationFormStub implements FormInterface
{
    public function __serialize(): array
    {
        return [];
    }

    public function __unserialize(array $data): void
    {
    }

    abstract public function validate(): bool;
}

final class GravStub extends \ArrayObject
{
    /** @var string|null */
    public $redirectedTo;
    /** @var array<int, array{0: string, 1: mixed}> */
    public $fired = [];

    public function redirectLangSafe($route, $code = null): void
    {
        $this->redirectedTo = $route;
    }

    public function fireEvent($name, $event = null)
    {
        $this->fired[] = [$name, $event['message'] ?? null];

        return $event;
    }
}

final class ConfigStub
{
    /** @var array<string, mixed> */
    private $settings;

    /** @param array<string, mixed> $settings */
    public function __construct(array $settings)
    {
        $this->settings = $settings;
    }

    public function get($key, $default = null)
    {
        return array_key_exists($key, $this->settings) ? $this->settings[$key] : $default;
    }
}

final class UriStub
{
    /** @var array<string, string> */
    private $params;

    /** @param array<string, string> $params */
    public function __construct(array $params)
    {
        $this->params = $params;
    }

    public function param($id, $default = false)
    {
        return $this->params[$id] ?? $default;
    }
}

final class MessagesStub
{
    /** @var array<int, array{0: string, 1: string}> */
    public $added = [];

    public function add($message, $scope = 'default'): void
    {
        $this->added[] = [$message, $scope];
    }
}

final class LanguageStub
{
    public function translate($key)
    {
        return is_array($key) ? (string)$key[0] : (string)$key;
    }
}
