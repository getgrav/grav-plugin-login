<?php declare(strict_types=1);

namespace Grav\Plugin\Login\Tests\Unit;

use Grav\Plugin\Login\Login;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The rules behind signing sessions out, as plain functions: whether a session's copy of an account is still current
 * (Login::signOutReason()), whether a session ends with the last "sign out everyone" (Login::endedBySignOutEveryone()),
 * and what a signed-out browser is told (Login::signedOutMessage()). Times are whole seconds.
 */
final class SignOutRulesTest extends TestCase
{
    private const T = 1700000000;

    /**
     * @return array<string, array{0: int, 1: array<string, mixed>, 2: int, 3: array<string, mixed>, 4: string|null}>
     */
    public static function copies(): array
    {
        $password = ['at' => self::T, 'reason' => 'password'];
        $everywhere = ['at' => self::T, 'reason' => 'everywhere'];

        // stored stamp, stored note, the session copy's stamp, its note, reason (null: the copy is current)
        return [
            'never signed out'                                   => [0, [], 0, [], null],
            'copy made at login, nothing since'                  => [self::T, $password, self::T, $password, null],
            'copy newer than stored (its save failed)'           => [self::T, $password, self::T + 1, [], null],
            'copy from before a password change'                 => [self::T, $password, self::T - 100, [], 'password'],
            'copy from before an email change'                   => [self::T, ['at' => self::T, 'reason' => 'email'], self::T - 1, [], 'email'],
            'copy from before a cancelled email change'          => [self::T, ['at' => self::T, 'reason' => 'email_cancelled'], self::T - 1, [], 'email_cancelled'],
            'copy from before "sign out everywhere"'             => [self::T, $everywhere, self::T - 1, $password, 'everywhere'],
            'stamp set without a note (disabled through the API)' => [self::T, [], self::T - 1, [], 'changed'],
            'an older note does not explain this stamp'          => [self::T, ['at' => self::T - 50, 'reason' => 'password'], self::T - 100, [], 'changed'],
            'same second: own password change, then an admin signs out' => [self::T, $everywhere, self::T, $password, 'everywhere'],
            'same second, the same sign-out'                     => [self::T, $everywhere, self::T, $everywhere, null],
            'before 3.13.0: equal stamps, no notes'              => [self::T, [], self::T, [], null],
        ];
    }

    /**
     * @param array<string, mixed> $storedMark
     * @param array<string, mixed> $copyMark
     */
    #[DataProvider('copies')]
    public function testASessionsCopyIsCurrentOrSaysWhyNot(int $storedStamp, array $storedMark, int $copyStamp, array $copyMark, ?string $reason): void
    {
        self::assertSame($reason, Login::signOutReason($storedStamp, $storedMark, $copyStamp, $copyMark));
    }

    /**
     * @return array<string, array{0: int, 1: int, 2: int, 3: int, 4: int, 5: bool}>
     */
    public static function sessions(): array
    {
        // cutoff, login time (0: unknown), the cutoff this session ran, idle limit, now, ended?
        return [
            'no "sign out everyone" yet'                         => [0, self::T - 10, 0, 1800, self::T, false],
            'logged in after it'                                 => [self::T, self::T + 1, 0, 1800, self::T + 5, false],
            'logged in the same second'                          => [self::T, self::T, 0, 1800, self::T + 5, true],
            'logged in before it'                                => [self::T, self::T - 10, 0, 1800, self::T + 5, true],
            'the browser that ran it'                            => [self::T, self::T - 10, self::T, 1800, self::T + 5, false],
            'the browser that ran an earlier one'                => [self::T, self::T - 10, self::T - 500, 1800, self::T + 5, true],
            'unknown login time, cutoff younger than the idle limit' => [self::T, 0, 0, 1800, self::T + 60, true],
            'unknown login time, cutoff as old as the idle limit' => [self::T, 0, 0, 1800, self::T + 1800, false],
            'unknown login time, cutoff older than the idle limit' => [self::T, 0, 0, 1800, self::T + 4000, false],
            'unknown login time, no idle limit known'            => [self::T, 0, 0, 0, self::T + 1, false],
        ];
    }

    #[DataProvider('sessions')]
    public function testASessionEndsWithSignOutEveryoneWhenItLoggedInBeforeIt(int $at, int $loginAt, int $kept, int $idle, int $now, bool $ended): void
    {
        self::assertSame($ended, Login::endedBySignOutEveryone($at, $loginAt, $kept, $idle, $now));
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function messages(): array
    {
        return [
            'password'        => ['password', 'SIGNED_OUT_PASSWORD_CHANGED'],
            'email'           => ['email', 'SIGNED_OUT'],
            'email_cancelled' => ['email_cancelled', 'SIGNED_OUT'],
            'everywhere'      => ['everywhere', 'SIGNED_OUT'],
            'everyone'        => ['everyone', 'SIGNED_OUT'],
            'changed'         => ['changed', 'SIGNED_OUT'],
            'unknown reason'  => ['something-new', 'SIGNED_OUT'],
        ];
    }

    #[DataProvider('messages')]
    public function testWhatASignedOutBrowserIsTold(string $reason, string $message): void
    {
        self::assertSame($message, Login::signedOutMessage($reason));
    }
}
