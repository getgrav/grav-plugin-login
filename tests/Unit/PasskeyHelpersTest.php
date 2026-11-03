<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Plugin\Login\Passkeys\Passkeys;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PasskeyHelpersTest extends TestCase
{
    public function testBase64UrlRoundTrip(): void
    {
        $bytes = random_bytes(64);
        $encoded = Passkeys::b64u($bytes);

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $encoded);
        self::assertSame($bytes, Passkeys::unb64u($encoded));
    }

    public static function notBase64Url(): array
    {
        return [
            'empty' => [''],
            'standard alphabet' => ['ab+/cd'],
            'spaces' => ['ab cd'],
            'not a string' => [123],
            'null' => [null],
            'array' => [['abc']],
        ];
    }

    #[DataProvider('notBase64Url')]
    public function testUnb64uRefusesAnythingElse($value): void
    {
        self::assertNull(Passkeys::unb64u($value));
    }

    public function testCleanNameStripsMarkupAndSpaceAndCapsLength(): void
    {
        self::assertSame('My key', Passkeys::cleanName("  <b>My</b>\n\t key  "));
        self::assertSame(Passkeys::NAME_MAX, mb_strlen(Passkeys::cleanName(str_repeat('ä', 200))));
        self::assertSame('', Passkeys::cleanName('<script></script>'));
    }

    public function testAccountFieldsAreTheOnesTheApiAndProfileMustNeverWrite(): void
    {
        self::assertSame(['passkeys', 'webauthn_id'], Passkeys::ACCOUNT_FIELDS);
    }

    /**
     * The guard that keeps the WebAuthn code off Grav 1.7. GRAV_VERSION is
     * not defined in this test run (no Grav is booted), which must read as
     * "not supported" rather than fail.
     */
    public function testNotSupportedWithoutGrav2(): void
    {
        if (defined('GRAV_VERSION')) {
            self::markTestSkipped('GRAV_VERSION is defined in this run.');
        }
        self::assertFalse(Passkeys::supported());
    }
}
