<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Plugin\Login\Login;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EmailAddressAcceptanceTest extends TestCase
{
    public static function addresses(): array
    {
        return [
            'plain' => ['andy@example.com', true],
            'padded' => ['  andy@example.com ', true],
            'plus tag' => ['andy+tag@example.com', true],
            'single braces' => ['{andy}@example.com', true],
            'expression' => ['{{7*7}}@example.com', false],
            'expression in the middle' => ['a{{b}}@example.com', false],
            'statement' => ['a{%b@example.com', false],
            'comment' => ['a{#b@example.com', false],
            'not an address' => ['not-an-address', false],
            'empty' => ['', false],
        ];
    }

    #[DataProvider('addresses')]
    public function testIsAcceptableEmail(string $email, bool $expected): void
    {
        self::assertSame($expected, Login::isAcceptableEmail($email));
    }

    public function testIsAcceptableEmailRefusesNonStrings(): void
    {
        self::assertFalse(Login::isAcceptableEmail(null));
        self::assertFalse(Login::isAcceptableEmail(['andy@example.com']));
    }
}
