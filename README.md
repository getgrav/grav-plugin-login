grav-plugin-login
=================

Grav Login Plugin adds login, session handling, basic ACL and session wide messages.

You can add ACL to any page by typing something like below into the page header:

    access:
      site.hidden: true
      admin.login: true

Users who have any of the listed ACL roles enabled will have access to the page.
Others will be forwarded to login screen.

Here is example user (user/accounts/admin.yaml):

    username: admin
    password: password
    email: admin@email.com
    fullname: John Doe

    access:
      admin:
        login: true
        super: true
      site:
        login: true
        hidden: true

