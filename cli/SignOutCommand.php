<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2021 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Console;

use Grav\Common\Grav;
use Grav\Console\ConsoleCommand;
use Grav\Plugin\Login\Login;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Class SignOutCommand
 *
 * Signs accounts out everywhere: their browser sessions, "remember me" cookies
 * and API tokens (Admin2), as a password change by an administrator does.
 *
 * @package Grav\Console\Cli
 */
class SignOutCommand extends ConsoleCommand
{
    /** @var Login */
    protected $login;

    /**
     * Configure the command
     */
    protected function configure()
    {
        $this
            ->setName('sign-out')
            ->setAliases(['signout', 'logout-user'])
            ->addOption(
                'user',
                'u',
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Sign out this account (repeat for several)'
            )
            ->addOption(
                'all',
                'a',
                InputOption::VALUE_NONE,
                'Sign out every account'
            )
            ->addOption(
                'yes',
                'y',
                InputOption::VALUE_NONE,
                'Do not ask before signing out every account'
            )
            ->setDescription('Signs accounts out everywhere: browser sessions, "remember me" cookies and API tokens')
            ->setHelp(
                "The <info>sign-out</info> command signs accounts out everywhere, as a password change by an administrator does.\n" .
                "Their browser sessions end on their next request, their \"remember me\" cookies stop working, and their API\n" .
                "tokens (Admin2) are refused. The accounts and their passwords stay as they are, and so do their API keys:\n" .
                "revoke those in Admin2 if needed.\n\n" .
                "  <info>bin/plugin login sign-out -u bob</info>             sign out the account 'bob'\n" .
                "  <info>bin/plugin login sign-out -u bob -u alice</info>    sign out several accounts\n" .
                "  <info>bin/plugin login sign-out --all</info>              sign out every account, and the sessions of users\n" .
                "                                                 without an account file (asks first)\n" .
                "  <info>bin/plugin login sign-out --all --yes</info>        the same, without asking (scripts)\n\n" .
                "--user and --all can't be combined."
            )
        ;
    }

    /**
     * @return int|null|void
     */
    protected function serve()
    {
        include __DIR__ . '/../vendor/autoload.php';

        $io = new SymfonyStyle($this->input, $this->output);

        $grav = Grav::instance();
        $grav->setup();
        $grav['plugins']->init();
        $grav->fireEvent('onCliInitialize');

        if (!isset($grav['login'])) {
            $grav['login'] = new Login($grav);
        }
        $this->login = $grav['login'];

        $usernames = array_values(array_filter(array_map('trim', (array)$this->input->getOption('user')), 'strlen'));
        $all = (bool)$this->input->getOption('all');

        if ($usernames && $all) {
            $io->error('Pass either --user or --all, not both.');

            return 1;
        }
        if (!$usernames && !$all) {
            $io->error('Nothing to do. Pass --user <username> (repeatable) or --all.');
            $io->note('Run `bin/plugin login sign-out --help` for examples.');

            return 1;
        }

        $failed = 0;
        $by = 'from the command line';
        if ($all) {
            if (!$this->input->getOption('yes')) {
                if (!$this->input->isInteractive()) {
                    $io->error('Signing out every account needs confirmation: add --yes.');

                    return 1;
                }

                $question = new ConfirmationQuestion('Sign out every account and every session on this site? [y/N] ', false);
                if (!$this->getHelper('question')->ask($this->input, $this->output, $question)) {
                    $io->note('Nothing changed.');

                    return 0;
                }
            }

            // Also ends the sessions of users without an account file, so it runs without any account too.
            $result = $this->login->signOutEveryone($by);
        } else {
            $result = $this->login->signOutAccounts($usernames, $by);
            foreach ($result['missing'] as $username) {
                $io->error(sprintf(
                    'User "%s" does not exist. Users who log in without an account file (e.g. OAuth2 logins without "Save Grav user") can only be signed out with --all.',
                    $username
                ));
                $failed++;
            }
        }

        foreach ($result['signed_out'] as $username) {
            $io->text(sprintf('  Signed out "%s"', $username));
        }
        foreach ($result['failed'] as $failure) {
            $io->error(sprintf('Could not sign out "%s": %s', $failure['username'], $failure['error']));
            $failed++;
        }

        $signedOut = count($result['signed_out']);
        if ($signedOut) {
            // Signed-in web processes may hold the accounts in Grav's cache (Flex accounts).
            $this->invalidateCache();
        }
        $sessionsEnded = $all && $result['sessions_ended'];
        if ($all && !$sessionsEnded) {
            $io->error('The sessions of users without an account file could not be ended: user/data/login/sign-out-all.yaml could not be written (see the Grav log).');
            $failed++;
        }
        if ($all || $signedOut) {
            $io->success(sprintf(
                '%sSigned %d account%s out everywhere.',
                $sessionsEnded ? 'Every session that logged in before now ends on its next request. ' : '',
                $signedOut,
                $signedOut === 1 ? '' : 's'
            ));
            $io->note('API keys keep working: revoke them in Admin2 if needed.');
        }

        return $failed ? 1 : 0;
    }
}
