<?php
/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2021 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */
namespace Grav\Plugin\Console;

use Grav\Common\User\Interfaces\UserCollectionInterface;
use Grav\Console\ConsoleCommand;
use Grav\Common\Grav;
use Grav\Plugin\Login\Login;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Helper\Helper;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\Question;

/**
 * Class CleanCommand
 *
 * @package Grav\Console\Cli
 */
class NewUserCommand extends ConsoleCommand
{
    /** @var array */
    protected $options = [];

    /** @var Login */
    protected $login;

    /**
     * Configure the command
     */
    protected function configure()
    {
        $this
            ->setName('new-user')
            ->setAliases(['add-user', 'newuser'])
            ->addOption(
                'user',
                'u',
                InputOption::VALUE_REQUIRED,
                'The username'
            )
            ->addOption(
                'password',
                'p',
                InputOption::VALUE_REQUIRED,
                "The password. Note that this option is not recommended because the password will be visible by users listing the processes. You should also make sure the password respects Grav's password policy."
            )
            ->addOption(
                'email',
                'e',
                InputOption::VALUE_REQUIRED,
                'The user email'
            )
            ->addOption(
                'language',
                'l',
                InputOption::VALUE_OPTIONAL,
                'The default language of the account. [default: "en"]'
            )
            ->addOption(
                'permissions',
                'P',
                InputOption::VALUE_REQUIRED,
                'The user permissions. It can be either `a` for Admin access only, `s` for Site access only, or `b` for Admin and Site access.'
            )
            ->addOption(
                'admin-type',
                null,
                InputOption::VALUE_REQUIRED,
                'Which admin permission type to grant when permissions include Admin: `admin` (classic Admin plugin, admin.*), `api` (Admin2, api.*), or `both`. If omitted, auto-detects from which admin plugin is installed.'
            )
            ->addOption(
                'fullname',
                'N',
                InputOption::VALUE_REQUIRED,
                'The user full name.'
            )
            ->addOption(
                'title',
                't',
                InputOption::VALUE_REQUIRED,
                'The title of the user. Usually used as a subtext. Example: Admin, Collaborator, Developer'
            )
            ->addOption(
                'state',
                's',
                InputOption::VALUE_REQUIRED,
                'The state of the account. Can be either `enabled` or `disabled`. [default: "enabled"]'
            )
            ->setDescription('Creates a new user')
            ->setHelp('The <info>new-user</info> creates a new user file in user/accounts/ folder')
        ;
    }

    /**
     * @return int|null|void
     */
    protected function serve()
    {
        include __DIR__ . '/../vendor/autoload.php';

        $grav = Grav::instance();
        if (!isset($grav['login'])) {
            $grav['login'] = new Login($grav);
        }
        $this->login = $grav['login'];

        $this->options = [
            'user'        => $this->input->getOption('user'),
            'password1'   => $this->input->getOption('password'),
            'email'       => $this->input->getOption('email'),
            'language'    => $this->input->getOption('language'),
            'permissions' => $this->input->getOption('permissions'),
            'admin-type'  => $this->input->getOption('admin-type'),
            'fullname'    => $this->input->getOption('fullname'),
            'title'       => $this->input->getOption('title'),
            'state'       => $this->input->getOption('state')
        ];

        $this->validateOptions();

        $helper = $this->getHelper('question');
        $data   = [];

        $this->output->writeln('<green>Creating new user</green>');
        $this->output->writeln('');

        /** @var UserCollectionInterface $users */
        $users = $grav['accounts'];

        if (!$this->options['user']) {
            // Get username and validate
            $question = new Question('Enter a <yellow>username</yellow>: ', 'admin');
            $question->setValidator(function ($value) use ($users) {
                $this->validate('user', $value);

                if ($users->find($value, ['username'])->exists()) {
                    throw new \RuntimeException('Username "' . $value . '" already exists, please pick another username');
                };

                return $value;
            });

            $username = $helper->ask($this->input, $this->output, $question);
        } else {
            $username = $this->options['user'];
        }

        $user = $users->load($username);
        if ($user->exists()) {
            $this->output->writeln('<red>Failure!</red> User <cyan>' . $data['username'] . '</cyan> already exists!');
            exit();
        }

        if (!$this->options['password1']) {
            // Get password and validate
            $password = $this->askForPassword($helper, 'Enter a <yellow>password</yellow>: ', function ($password1) use ($helper) {
                $this->validate('password1', $password1);

                // Since input is hidden when prompting for passwords, the user is asked to repeat the password
                return $this->askForPassword($helper, 'Repeat the <yellow>password</yellow>: ', function ($password2) use ($password1) {
                    return $this->validate('password2', $password2, $password1);
                });
            });

            $user->set('password', $password);
        } else {
            $user->set('password', $this->options['password1']);
        }

        if (!$this->options['email']) {
            // Get email and validate
            $question = new Question('Enter an <yellow>email</yellow>:   ');
            $question->setValidator(function ($value) {
                return $this->validate('email', $value);
            });

            $user->set('email', $helper->ask($this->input, $this->output, $question));
        } else {
            $user->set('email', $this->options['email']);
        }

        if (!$this->options['language']) {
            // Get language and validate.
            $question = new Question('Enter a <yellow>language abbreviation</yellow> [en]:   ');
            $question->setValidator(function ($value) {
                return $this->validate('language', $value);
            });

            $user->set('language', $helper->ask($this->input, $this->output, $question));
            if ($user->get('language') == null) {
                $user->set('language', 'en');
            }
        } else {
            $user->set('language', $this->options['language']);
        }

        if (!$this->options['permissions']) {
            // Choose permissions
            $question = new ChoiceQuestion(
                'Please choose a set of <yellow>permissions</yellow>:',
                array('a' => 'Admin Access', 's' => 'Site Access', 'b' => 'Admin and Site Access'),
                'a'
            );

            $question->setErrorMessage('Permissions %s is invalid.');
            $permissions_choice = $helper->ask($this->input, $this->output, $question);
        } else {
            $permissions_choice = $this->options['permissions'];
        }

        // When "Admin" is selected — either alone or combined with "Site" — we
        // need to decide which admin permission type(s) to grant:
        //   - `admin` : legacy classic-Admin tree (admin.login / admin.super),
        //               consumed by the Admin plugin on Grav 1.7.
        //   - `api`   : newer Admin2 tree (api.login / api.super), consumed
        //               by the Admin2 plugin on Grav 2.0.
        //   - `both`  : write both, so the user can log into whichever admin
        //               the site is running now or migrates to later.
        //
        // Auto-detection peeks at `user/plugins/` to infer which admin is
        // installed (grav-plugin-login#329). The non-interactive `--admin-type`
        // CLI option overrides the auto-detected default.
        $admin_type = null;
        if (in_array($permissions_choice, ['a', 'b'], true)) {
            $detected = $this->detectAdminTree();
            $admin_type = $this->options['admin-type'];

            if ($admin_type === null) {
                // Interactive iff --permissions wasn't supplied on the CLI.
                // A script passing --permissions but not --admin-type gets the
                // auto-detected default silently.
                if ($this->options['permissions']) {
                    $admin_type = $detected;
                } else {
                    $detectedLabel = [
                        'admin' => 'classic Admin only (admin.*)',
                        'api'   => 'Admin2 only (api.*)',
                        'both'  => 'classic Admin + Admin2 (admin.* + api.*)',
                    ][$detected];
                    $this->output->writeln("<yellow>Detected admin installation:</yellow> {$detectedLabel}");

                    $question = new ChoiceQuestion(
                        'Please choose an <yellow>admin permission type</yellow>:',
                        [
                            'admin' => 'Classic Admin plugin (admin.*)',
                            'api'   => 'Admin2 plugin (api.*)',
                            'both'  => 'Both — grant admin.* and api.*',
                        ],
                        $detected
                    );
                    $question->setErrorMessage('Admin tree %s is invalid.');
                    $admin_type = $helper->ask($this->input, $this->output, $question);
                }
            }

            if (!in_array($admin_type, ['admin', 'api', 'both'], true)) {
                throw new \RuntimeException("Invalid --admin-type value '{$admin_type}'. Must be one of: admin, api, both.");
            }
        }

        $adminAccess = ['login' => true, 'super' => true];
        switch ($permissions_choice) {
            case 'a':
                $access = [];
                if ($admin_type === 'admin' || $admin_type === 'both') {
                    $access['admin'] = $adminAccess;
                }
                if ($admin_type === 'api' || $admin_type === 'both') {
                    $access['api'] = $adminAccess;
                }
                break;
            case 's':
                $access = [
                    'site' => [
                        'login' => true
                    ]
                ];
                break;
            case 'b':
                $access = [];
                if ($admin_type === 'admin' || $admin_type === 'both') {
                    $access['admin'] = $adminAccess;
                }
                if ($admin_type === 'api' || $admin_type === 'both') {
                    $access['api'] = $adminAccess;
                }
                $access['site'] = ['login' => true];
        }

        if (isset($access)) {
            $user->set('access', $access);
        }

        if (!$this->options['fullname']) {
            // Get fullname
            $question = new Question('Enter a <yellow>fullname</yellow>: ');
            $question->setValidator(function ($value) {
                return $this->validate('fullname', $value);
            });

            $user->set('fullname', $helper->ask($this->input, $this->output, $question));
        } else {
            $user->set('fullname', $this->options['fullname']);
        }


        if (!$this->options['title'] && !count(array_filter($this->options))) {
            // Get title
            $question      = new Question('Enter a <yellow>title</yellow>:    ');
            $user->set('title', $helper->ask($this->input, $this->output, $question));
        } else {
            $user->set('title', $this->options['title']);
        }

        if (!$this->options['state'] && !count(array_filter($this->options))) {
            // Choose State
            $question = new ChoiceQuestion(
                'Please choose the <yellow>state</yellow> for the account:',
                array('enabled' => 'Enabled', 'disabled' => 'Disabled'),
                'enabled'
            );

            $question->setErrorMessage('State %s is invalid.');
            $user->set('state', $helper->ask($this->input, $this->output, $question));
        } else {
            $user->set('state', $this->options['state'] ?: 'enabled');
        }

        $user->validate();
        $user->save();

        $this->invalidateCache();

        $this->output->writeln('');
        $this->output->writeln('<green>Success!</green> User <cyan>' . $user->username . '</cyan> created.');
    }

    /**
     *
     */
    protected function validateOptions()
    {
        foreach (array_filter($this->options) as $type => $value) {
            $this->validate($type, $value);
        }
    }

    /**
     * @param string $type
     * @param mixed  $value
     * @param string $extra
     *
     * @return string
     */
    protected function validate($type, $value, $extra = '')
    {
        return $this->login->validateField($type, $value, $extra);
    }

    /**
     * Get password and validate.
     *
     * @param Helper   $helper
     * @param string   $question
     * @param callable $validator
     *
     * @return string
     */
    protected function askForPassword(Helper $helper, $question, callable $validator)
    {
        $question = new Question($question);
        $question->setValidator($validator);
        $question->setHidden(true);
        $question->setHiddenFallback(true);
        return $helper->ask($this->input, $this->output, $question);
    }

    /**
     * Infer which admin permission type the site expects by looking at which
     * admin plugin is installed under user/plugins/.
     *
     *   - both installed → 'both'
     *   - only classic Admin → 'admin'
     *   - only Admin2 → 'api'
     *   - neither installed → 'both' (safe default; user can prune the YAML
     *     later, and "both" means the account will work if either plugin is
     *     installed afterward)
     *
     * @return string One of 'admin' | 'api' | 'both'.
     */
    protected function detectAdminTree(): string
    {
        $root = defined('GRAV_ROOT') ? GRAV_ROOT : getcwd();
        $hasClassic = is_dir($root . '/user/plugins/admin');
        $hasAdmin2  = is_dir($root . '/user/plugins/admin2');

        if ($hasClassic && $hasAdmin2) {
            return 'both';
        }
        if ($hasAdmin2) {
            return 'api';
        }
        if ($hasClassic) {
            return 'admin';
        }
        return 'both';
    }
}
