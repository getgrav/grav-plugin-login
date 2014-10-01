<?php
namespace Grav\Plugin;

use Grav\Common\Page\Page;
use Grav\Common\Page\Pages;
use Grav\Common\Plugin;
use Grav\Common\Twig;
use Grav\Common\Uri;
use Grav\Common\User\User;
use RocketTheme\Toolbox\Session\Message;
use RocketTheme\Toolbox\Session\Session;

class LoginPlugin extends Plugin
{
    /** @var string */
    protected $route;

    /**
     * @var bool
     */
    protected $authenticated = true;
    protected $authorised = true;

    /**
     * @return array
     */
    public static function getSubscribedEvents() {
        return [
            'onPluginsInitialized' => ['initialize', 10000],
            'onTask.login.login' => ['loginController', 0],
            'onTask.login.logout' => ['loginController', 0],
            'onPageInitialized' => ['authorizePage', 0],
            'onTwigTemplatePaths' => ['onTwigTemplatePaths', 0],
            'onTwigSiteVariables' => ['onTwigSiteVariables', -100000]
        ];
    }

    /**
     * Initialize login plugin if path matches.
     */
    public function initialize()
    {
        /** @var Uri $uri */
        $uri = $this->grav['uri'];

        // Define session service.
        $this->grav['session'] = function ($c) use ($uri) {
            $session = new Session($this->config->get('plugins.login.timeout', 1800), $uri->rootUrl(false));
            $session->start();

            return $session;
        };

        /// Define session message service.
        $this->grav['messages'] = function ($c) {
            $session = $c['session'];

            if (!isset($session->messages)) {
                $session->messages = new Message;
            }

            return $session->messages;
        };

        // Define current user service.
        $this->grav['user'] = function ($c) {
            $session = $c['session'];

            if (!isset($session->user)) {
                $session->user = new User;
            }

            return $session->user;
        };

        // Register route to login page if it has been set.
        $this->route = $this->config->get('plugins.login.route');
        if ($this->route) {
            $this->enable([
                'onPagesInitialized' => ['addLoginPage', 0]
            ]);
        }
    }

    public function addLoginPage()
    {
        /** @var Pages $pages */
        $pages = $this->grav['pages'];
        $page = $pages->dispatch($this->route);

        if (!$page) {
            // Only add login page if it hasn't already been defined.
            $page = new Page;
            $page->init(new \SplFileInfo(__DIR__ . "/pages/login.md"));
            $page->slug(basename($this->route));

            $pages->addPage($page, $this->route);
        }
    }

    public function loginController()
    {
        /** @var Uri $uri */
        $uri = $this->grav['uri'];
        $task = !empty($_POST['task']) ? $_POST['task'] : $uri->param('task');
        $task = substr($task, strlen('login.'));
        $post = !empty($_POST) ? $_POST : [];

        require_once __DIR__ . '/classes/controller.php';
        $controller = new LoginController($this->grav, $task, $post);
        $controller->execute();
        $controller->redirect();
    }

    public function authorizePage()
    {
        /** @var Page $page */
        $page = $this->grav['page'];

        $header = $page->header();
        $rules = isset($header->access) ? (array) $header->access : [];

        // Continue to the page if it has no ACL rules.
        if (!$rules) {
            return;
        }

        /** @var User $user */
        $user = $this->grav['user'];

        // Continue to the page if user is authorized to access the page.
        foreach ($rules as $rule => $value) {
            if ($user->authorise($rule) == $value) {
                return;
            }
        }

        // User is not logged in; redirect to login page.
        if ($this->route && !$user->authenticated) {
            $this->grav->redirect($this->route, 302);
        }

        // Reset page with login page.
        if (!$user->authenticated) {
            $page = new Page;
            $page->init(new \SplFileInfo(__DIR__ . "/pages/login.md"));
            $page->slug(basename($this->route));

            $this->authenticated = false;
        } else {
            $page = new Page;
            $page->init(new \SplFileInfo(__DIR__ . "/pages/denied.md"));
            $page->slug(basename($this->route));

            $this->authorised = false;
        }

        unset($this->grav['page']);
        $this->grav['page'] = $page;
    }


    /**
     * Add twig paths to plugin templates.
     */
    public function onTwigTemplatePaths()
    {
        $twig = $this->grav['twig'];
        $twig->twig_paths[] = __DIR__ . '/templates';
    }

    /**
     * Set all twig variables for generating output.
     */
    public function onTwigSiteVariables()
    {
        /** @var Twig $twig */
        $twig = $this->grav['twig'];

        if (!$this->authenticated) {
            $twig->template = "login.html.twig";
        } elseif (!$this->authorised) {
            $twig->template = "denied.html.twig";
        }
    }
}
