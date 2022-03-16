<?php declare(strict_types=1);

namespace Grav\Plugin\Login;

use Grav\Common\Config\Config;
use Grav\Common\Grav;
use Grav\Common\Language\Language;
use Grav\Common\Page\Pages;
use Grav\Common\User\Interfaces\UserInterface;
use Grav\Common\Utils;
use Grav\Plugin\Login\Invitations\Invitation;
use Psr\Log\LoggerInterface;

class Email
{
    /**
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendActivationEmail(UserInterface $user, UserInterface $actor = null): void
    {
        $email = $user->email;
        $token = (string)$user->get('activation_token', '');

        if (!$email || !str_contains($token, '::')) {
            return;
        }

        [$token, $expire] = explode('::', $token, 2);

        try {
            $config = static::getConfig();

            $param_sep = $config->get('system.param_sep', ':');
            $activationRoute = static::getLogin()->getRoute('activate');
            if (!$activationRoute) {
                throw new \RuntimeException('User activation route does not exist!');
            }

            /** @var Pages $pages */
            $pages = Grav::instance()['pages'];
            $activationLink = $pages->url(
                $activationRoute . '/token' . $param_sep . $token . '/username' . $param_sep . $user->username,
                null,
                true
            );

            $context = [
                'activation_link' => $activationLink,
                'expire' => $expire,
            ];

            $params = [
                'to' => $user->email,
            ];

            static::sendEmail('activate', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }


    /**
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendResetPasswordEmail(UserInterface $user, UserInterface $actor = null): void
    {
        $email = $user->email;
        $token = (string)$user->get('reset', '');

        if (!$email || !str_contains($token, '::')) {
            return;
        }

        [$token, $expire] = explode('::', $token, 2);

        try {
            $param_sep = static::getConfig()->get('system.param_sep', ':');
            $resetRoute = static::getLogin()->getRoute('reset');
            if (!$resetRoute) {
                throw new \RuntimeException('Password reset route does not exist!');
            }

            /** @var Pages $pages */
            $pages = Grav::instance()['pages'];
            $resetLink = $pages->url(
                "{$resetRoute}/task{$param_sep}login.reset/token{$param_sep}{$token}/user{$param_sep}{$user->username}/nonce{$param_sep}" . Utils::getNonce('reset-form'),
                null,
                true
            );

            $context = [
                'reset_link' => $resetLink,
                'expire' => $expire,
            ];

            $params = [
                'to' => $user->email,
            ];

            static::sendEmail('reset-password', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    /**
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendWelcomeEmail(UserInterface $user, UserInterface $actor = null): void
    {
        if (!$user->email) {
            return;
        }

        try {
            $context = [];

            $params = [
                'to' => $user->email,
            ];

            static::sendEmail('welcome', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    /**
     * @param UserInterface $user
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendNotificationEmail(UserInterface $user, UserInterface $actor = null): void
    {
        try {
            $to = static::getConfig()->get('plugins.email.to');
            if (!$to) {
                throw new \RuntimeException(static::getLanguage()->translate('PLUGIN_LOGIN.EMAIL_NOT_CONFIGURED'));
            }

            $context = [];

            $params = [
                'to' => $to,
            ];

            static::sendEmail('notification', $context, $params, $user, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    /**
     * @param Invitation $invitation
     * @param string|null $message
     * @param UserInterface|null $actor
     * @return void
     * @throws \Exception
     */
    public static function sendInvitationEmail(Invitation $invitation, string $message = null, UserInterface $actor = null): void
    {
        if (!$invitation->email) {
            return;
        }

        try {
            $config = static::getConfig();
            $param_sep = $config->get('system.param_sep', ':');
            $inviteRoute = static::getLogin()->getRoute('register', true);
            if (!$inviteRoute) {
                throw new \RuntimeException('User registration route does not exist!');
            }

            /** @var Pages $pages */
            $pages = Grav::instance()['pages'];
            $invitationLink = $pages->url("{$inviteRoute}/{$param_sep}{$invitation->token}", null, true);

            $context = [
                'invitation_link' => $invitationLink,
                'invitation' => $invitation,
                'message' => $message,
            ];

            $params = [
                'to' => $invitation->email,
            ];

            static::sendEmail('invite', $context, $params, null, $actor);
        } catch (\Exception $e) {
            static::getLogger()->error($e->getMessage());

            throw $e;
        }
    }

    protected static function sendEmail(string $template, array $context, array $params, UserInterface $user = null, UserInterface $actor = null): void
    {
        $actor = $actor ?? static::getUser();

        $config = static::getConfig();

        // Twig context.
        $context += [
            'actor' => $actor,
            'user' => $user,
            'site_name' => $config->get('site.title', 'Website'),
            'author' => $config->get('site.author.name', ''),
        ];

        $params += [
            'body' => '',
            'template' => "emails/login/{$template}.html.twig",
        ];

        $email = static::getEmail();

        $message = $email->buildMessage($params, $context);

        $failedRecipients = null;
        $email->send($message, $failedRecipients);
        if ($failedRecipients) {
            $language = static::getLanguage();

            throw new \RuntimeException($language->translate(['PLUGIN_LOGIN.FAILED_TO_SEND_EMAILS', implode(', ', $failedRecipients)]));
        }
    }

    /**
     * @return Login
     */
    protected static function getLogin(): Login
    {
        return Grav::instance()['login'];
    }

    /**
     * @return LoggerInterface
     */
    protected static function getLogger(): LoggerInterface
    {
        return Grav::instance()['log'];
    }

    /**
     * @return UserInterface
     */
    protected static function getUser(): UserInterface
    {
        return Grav::instance()['user'];
    }

    /**
     * @return \Grav\Plugin\Email\Email
     */
    protected static function getEmail(): \Grav\Plugin\Email\Email
    {
        return Grav::instance()['Email'];
    }

    /**
     * @return Config
     */
    protected static function getConfig(): Config
    {
        return Grav::instance()['config'];
    }

    /**
     * @return Language
     */
    protected static function getLanguage(): Language
    {
        return Grav::instance()['language'];
    }
}
