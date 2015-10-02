<?php
namespace Grav\Plugin\Login;

use Grav\Common\Grav;
use Grav\Common\User\User;
use Grav\Common\File\CompiledYamlFile;
use RocketTheme\Toolbox\Session\Message;

class LoginController extends Controller
{
    /**
     * @var string
     */
    protected $prefix = 'task';

    /**
     * Handle login.
     *
     * @return bool True if the action was performed.
     */
    public function taskLogin()
    {
        $t = $this->grav['language'];
        $user = $this->grav['user'];

        if ($this->authenticate($this->post)) {
            $this->setMessage($t->translate('LOGIN_PLUGIN.LOGIN_SUCCESSFUL'));
            $referrer = $this->grav['uri']->referrer('/');
            $this->setRedirect($referrer);
        } else {
            if ($user->username) {
                $this->setMessage($t->translate('LOGIN_PLUGIN.ACCESS_DENIED'));
            } else {
                $this->setMessage($t->translate('LOGIN_PLUGIN.LOGIN_FAILED'));
            }
        }

        return true;
    }

    /**
     * Handle logout.
     *
     * @return bool True if the action was performed.
     */
    public function taskLogout()
    {
        $this->grav['session']->invalidate()->start();
        $this->setRedirect('/');

        return true;
    }

    /**
     * Authenticate user.
     *
     * @param  array $form Form fields.
     * @return bool
     */
    protected function authenticate($form)
    {
        /** @var User $user */
        $user = $this->grav['user'];

        if (!$user->authenticated && isset($form['username']) && isset($form['password'])) {
            $user = User::load($form['username']);
            if ($user->exists()) {

                // Authenticate user.
                $result = $user->authenticate($form['password']);

                if ($result) {
                    $this->grav['session']->user = $user;
                }
            }
        }
        $user->authenticated = $user->authorize('site.login');

        return $user->authenticated;
    }
}
