<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Plugin\Login\Email;
use Grav\Plugin\Login\Login;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EmailChangeHelpersTest extends TestCase
{
    public static function maskedAddresses(): array
    {
        return [
            'long name' => ['andy@example.com', 'an***@example.com'],
            'three letters' => ['bob@example.com', 'b***@example.com'],
            'two letters' => ['al@example.com', 'a***@example.com'],
            'one letter' => ['a@example.com', '***@example.com'],
            'multibyte name' => ['jürgen@example.de', 'jü***@example.de'],
            'no at sign' => ['not-an-address', '***'],
            'nothing before the at' => ['@example.com', '***'],
        ];
    }

    #[DataProvider('maskedAddresses')]
    public function testMaskEmail(string $email, string $expected): void
    {
        self::assertSame($expected, Email::maskEmail($email));
    }

    public function testNewTokenIsRandomHex(): void
    {
        $a = Login::newToken();
        $b = Login::newToken();

        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $a);
        self::assertNotSame($a, $b);
    }

    public function testTokenMatches(): void
    {
        $token = Login::newToken();

        self::assertTrue(Login::tokenMatches($token, $token));
        self::assertFalse(Login::tokenMatches($token, Login::newToken()));
        self::assertFalse(Login::tokenMatches('', ''), 'a cleared token never matches');
        self::assertFalse(Login::tokenMatches($token, ''));
        self::assertFalse(Login::tokenMatches('', $token));
    }
}
