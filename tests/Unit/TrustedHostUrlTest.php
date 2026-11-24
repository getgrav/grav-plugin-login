<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Plugin\Login\Email;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Only an absolute http(s) address pins email links. A bare host name used to
 * count as configured while the link was still built from the request Host.
 */
final class TrustedHostUrlTest extends TestCase
{
    public static function values(): array
    {
        return [
            'https' => ['https://example.com', 'https://example.com'],
            'trailing slash' => ['https://example.com/', 'https://example.com'],
            'subfolder' => ['https://example.com/site', 'https://example.com/site'],
            'http with port' => ['http://example.com:8080', 'http://example.com:8080'],
            'padded' => ['  https://example.com  ', 'https://example.com'],
            'bare host' => ['example.com', null],
            'bare host and path' => ['example.com/site', null],
            'protocol relative' => ['//example.com', null],
            'other scheme' => ['ftp://example.com', null],
            'scheme only' => ['https://', null],
            'empty' => ['', null],
        ];
    }

    #[DataProvider('values')]
    public function testAbsoluteHttpUrl(string $value, ?string $expected): void
    {
        self::assertSame($expected, Email::absoluteHttpUrl($value));
    }
}
