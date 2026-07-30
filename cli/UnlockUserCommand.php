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
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Class UnlockUserCommand
 *
 * Clears the login plugin's rate limiter counters, which are what temporarily
 * lock an account out after too many failed login attempts.
 *
 * @package Grav\Console\Cli
 */
class UnlockUserCommand extends ConsoleCommand
{
    /** @var Login */
    protected $login;

    /**
     * Configure the command
     */
    protected function configure()
    {
        $this
            ->setName('unlock-user')
            ->setAliases(['unlock', 'reset-rate-limit'])
            ->addOption(
                'user',
                'u',
                InputOption::VALUE_REQUIRED,
                'Clear the lockout for this username, plus the IP counters it tripped'
            )
            ->addOption(
                'ip',
                'i',
                InputOption::VALUE_REQUIRED,
                'Clear the lockout for this IP address'
            )
            ->addOption(
                'all',
                'a',
                InputOption::VALUE_NONE,
                'Clear every lockout on the site'
            )
            ->addOption(
                'list',
                'l',
                InputOption::VALUE_NONE,
                'List the lockouts currently in effect and exit'
            )
            ->setDescription('Clears login lockouts caused by too many failed attempts')
            ->setHelp(
                "The <info>unlock-user</info> command clears the temporary lockout applied after too many failed logins.\n\n" .
                "  <info>bin/plugin login unlock-user --list</info>            show who is locked out right now\n" .
                "  <info>bin/plugin login unlock-user -u bob</info>            unlock the account 'bob'\n" .
                "  <info>bin/plugin login unlock-user -i 203.0.113.4</info>    unlock everything from that IP\n" .
                "  <info>bin/plugin login unlock-user --all</info>             clear every lockout\n\n" .
                'Lockouts also expire on their own after the interval set in the Login plugin configuration.'
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

        $username = $this->input->getOption('user');
        $ip = $this->input->getOption('ip');
        $all = $this->input->getOption('all');
        $list = $this->input->getOption('list');

        if ($list) {
            return $this->listLockouts($io);
        }

        if (!$username && !$ip && !$all) {
            $io->error('Nothing to do. Pass --user, --ip or --all, or use --list to see what is locked.');
            $io->note('Run `bin/plugin login unlock-user --help` for examples.');

            return 1;
        }

        if ($all) {
            $this->login->unlockAll();
            $io->success('Cleared every login lockout.');

            return 0;
        }

        if ($username) {
            $cleared = $this->login->unlockUser($username);
            if ($cleared) {
                $io->success(sprintf('Unlocked "%s" (cleared %d counter%s).', $username, $cleared, $cleared === 1 ? '' : 's'));
            } else {
                $io->note(sprintf('Nothing to clear — "%s" was not locked out.', $username));
            }
        }

        if ($ip) {
            $cleared = $this->login->unlockIp($ip);
            if ($cleared) {
                $io->success(sprintf('Unlocked %s (cleared %d counter%s).', $ip, $cleared, $cleared === 1 ? '' : 's'));
            } else {
                $io->note(sprintf('Nothing to clear — %s was not locked out.', $ip));
            }
        }

        return 0;
    }

    /**
     * Print the lockouts currently in effect.
     *
     * @param SymfonyStyle $io
     * @return int
     */
    protected function listLockouts(SymfonyStyle $io): int
    {
        $contexts = $this->login->getRateLimitedKeys();
        if (!$contexts) {
            $io->success('No lockouts are in effect.');

            return 0;
        }

        foreach ($contexts as $context => $entries) {
            $io->section($context);

            $rows = [];
            foreach ($entries as $entry) {
                // IP keys are stored pseudonymized, so the raw address is not
                // recoverable — show the accounts tried from it instead.
                $subject = $entry['type'] === 'ip'
                    ? 'IP (' . substr($entry['key'], 0, 8) . '…)'
                    : $entry['key'];

                $linked = array_keys($entry['links']['username'] ?? []);

                $rows[] = [
                    $subject,
                    $entry['attempts'],
                    $entry['last'] ? date('Y-m-d H:i:s', $entry['last']) : '-',
                    $linked ? implode(', ', $linked) : '-',
                ];
            }

            $io->table(['Locked', 'Attempts', 'Last attempt', 'Accounts tried'], $rows);
        }

        $io->note('Clear one with `-u <username>` or `-i <ip>`, or all of them with `--all`.');

        return 0;
    }
}
