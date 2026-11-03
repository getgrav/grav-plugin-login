<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Plugin\Login\Login;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Login::showPasswordForm() reads the show_password_form setting the way the API plugin does: a string such as
 * 'false' or 'off' turns the form off, and anything not clearly false keeps it. Turned off, the form still shows
 * while the login page offers no other way in. Login::isMagicLinkAvailable() decides whether Login by link is one.
 */
final class LoginShowPasswordFormTest extends TestCase
{
    private const MISSING = '__missing__';

    /** Login by link with everything it needs to send a link (and the Email plugin, see login()). */
    private const MAGIC_LINK = [
        'plugins.login.magic_link.enabled' => true,
        'plugins.login.route_magic'        => '/magic_login',
        'plugins.login.route_magic_login'  => '/magic_link',
        'plugins.email.from'               => 'site@example.com',
    ];

    /**
     * @return array<string, array{0: mixed, 1: bool}>
     */
    public static function values(): array
    {
        return [
            'not set'              => [self::MISSING, true],
            'null'                 => [null, true],
            'true'                 => [true, true],
            'false'                => [false, false],
            'the string "false"'   => ['false', false],
            'the string "off"'     => ['off', false],
            'the string "Off"'     => ['Off', false],
            'the string "no"'      => ['no', false],
            'the string "0"'       => ['0', false],
            'the number 0'         => [0, false],
            'the string "true"'    => ['true', true],
            'the string "yes"'     => ['yes', true],
            'junk'                 => ['garbage', true],
            'an array'             => [[], true],
        ];
    }

    #[DataProvider('values')]
    public function testShowPasswordFormReadsTheSetting(mixed $value, bool $expected): void
    {
        // A provider's buttons are offered, so only the setting decides.
        $login = $this->login($value === self::MISSING ? [] : ['plugins.login.show_password_form' => $value]);
        $login->addProviderLoginTemplate('login-oauth2/login-oauth2.html.twig');

        self::assertSame($expected, $login->showPasswordForm());
    }

    public function testTheFormShowsWhileNoOtherLoginOptionIsOffered(): void
    {
        self::assertTrue($this->login(['plugins.login.show_password_form' => false])->showPasswordForm());
    }

    /**
     * @return array<string, array{0: array<string, string>, 1: mixed, 2: bool}>
     */
    public static function olderPlugins(): array
    {
        $v1 = ['LoginOauth' => 'partials/login-oauth.html.twig'];
        $github = ['enabled' => true, 'credentials' => ['key' => 'k', 'secret' => 's']];

        return [
            // plugins_hooked_loginPage, plugins.login-oauth.providers, whether they count as a login option
            'none'                                   => [[], null, false],
            'another plugin\'s buttons'              => [['Other' => 'partials/other.html.twig'], null, true],
            'Login OAuth v1 with a provider'         => [$v1, ['github' => $github], true],
            'Login OAuth v1 without providers'       => [$v1, null, false],
            'Login OAuth v1, provider turned off'    => [$v1, ['github' => ['enabled' => false] + $github], false],
            'Login OAuth v1, provider without keys'  => [$v1, ['github' => ['enabled' => true]], false],
            'Login OAuth v1, a broken provider'      => [$v1, ['github' => 'yes'], false],
        ];
    }

    /**
     * @param array<string, string> $hooked
     */
    #[DataProvider('olderPlugins')]
    public function testAnOlderPluginsButtonsAreALoginOptionOnlyWhenTheyCanSignIn(array $hooked, mixed $providers, bool $counts): void
    {
        $settings = ['plugins.login.show_password_form' => false];
        if ($providers !== null) {
            $settings['plugins.login-oauth.providers'] = $providers;
        }
        $login = $this->login($settings, false, $hooked);

        self::assertSame($counts ? $hooked : [], $login->getLegacyLoginOptions());
        self::assertSame(!$counts, $login->showPasswordForm());
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: bool, 2: bool}>
     */
    public static function magicLinks(): array
    {
        return [
            'everything set'       => [self::MAGIC_LINK, true, true],
            'turned off'           => [['plugins.login.magic_link.enabled' => false] + self::MAGIC_LINK, true, false],
            'no request page'      => [['plugins.login.route_magic' => ''] + self::MAGIC_LINK, true, false],
            'no link route'        => [['plugins.login.route_magic_login' => null] + self::MAGIC_LINK, true, false],
            'no sender address'    => [['plugins.email.from' => ''] + self::MAGIC_LINK, true, false],
            'no Email plugin'      => [self::MAGIC_LINK, false, false],
        ];
    }

    /**
     * @param array<string, mixed> $settings
     */
    #[DataProvider('magicLinks')]
    public function testLoginByLinkIsALoginOptionOnlyWhenItCanSend(array $settings, bool $email, bool $available): void
    {
        $login = $this->login(['plugins.login.show_password_form' => false] + $settings, $email);

        self::assertSame($available, $login->isMagicLinkAvailable());
        self::assertSame(!$available, $login->showPasswordForm());
    }

    /**
     * @param array<string, mixed> $settings Config values by their full key.
     * @param bool $email Whether the Email plugin is set up (it then registers $grav['Email']).
     * @param array<string, string>|null $legacy plugins_hooked_loginPage, or null when no plugin set it.
     */
    private function login(array $settings, bool $email = true, ?array $legacy = null): Login
    {
        $config = new class($settings) {
            /** @param array<string, mixed> $settings */
            public function __construct(private array $settings) {}

            public function get(string $key, mixed $default = null): mixed
            {
                return array_key_exists($key, $this->settings) ? $this->settings[$key] : $default;
            }
        };

        $twig = new \stdClass();
        if ($legacy !== null) {
            $twig->plugins_hooked_loginPage = $legacy;
        }
        $grav = ['twig' => $twig];
        if ($email) {
            $grav['Email'] = new \stdClass();
        }

        $login = (new \ReflectionClass(Login::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(Login::class, 'config'))->setValue($login, $config);
        (new \ReflectionProperty(Login::class, 'grav'))->setValue($login, new \ArrayObject($grav));

        return $login;
    }
}
