<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Plugin\Login\Login;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Turning 2FA on from the profile form keeps the secret the page posted, once a code from it checks out.
 * These are the helpers that clean what was posted before it is checked.
 */
final class TwoFactorSetupHelpersTest extends TestCase
{
    /**
     * @return array<string, array{0: mixed, 1: string|null}>
     */
    public static function secrets(): array
    {
        return [
            'as the page posts it'        => ['3QGW3MKOW32F7OPL4SALBNF4GLHIKGG7', '3QGW3MKOW32F7OPL4SALBNF4GLHIKGG7'],
            'grouped in fours, as shown'  => ['3QGW 3MKO W32F 7OPL 4SAL BNF4 GLHI KGG7', '3QGW3MKOW32F7OPL4SALBNF4GLHIKGG7'],
            'lower case'                  => ['3qgw3mkow32f7opl', '3QGW3MKOW32F7OPL'],
            'shortest allowed (80 bits)'  => [str_repeat('A', 16), str_repeat('A', 16)],
            'too short'                   => [str_repeat('A', 15), null],
            'too long'                    => [str_repeat('A', 129), null],
            'not base32 (0, 1, 8, 9)'     => ['0189ABCDEFGHIJKL', null],
            'padding'                     => ['ABCDEFGHIJKLMNOP====', null],
            'empty'                       => ['', null],
            'missing'                     => [null, null],
            'an array'                    => [['ABCDEFGHIJKLMNOP'], null],
        ];
    }

    #[DataProvider('secrets')]
    public function testCleanTwoFactorSecret(mixed $posted, ?string $expected): void
    {
        self::assertSame($expected, Login::cleanTwoFactorSecret($posted));
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function codes(): array
    {
        return [
            'as typed'                  => ['123456', '123456'],
            'as the app shows it'       => ['123 456', '123456'],
            'pasted with a line break'  => ["123456\n", '123456'],
            'empty'                     => ['', ''],
            'missing'                   => [null, ''],
            'an array'                  => [['123456'], ''],
        ];
    }

    #[DataProvider('codes')]
    public function testCleanTwoFactorCode(mixed $typed, string $expected): void
    {
        self::assertSame($expected, Login::cleanTwoFactorCode($typed));
    }
}
