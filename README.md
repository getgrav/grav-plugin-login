# Grav Login Plugin

The **login plugin** for [Grav](http://github.com/getgrav/grav) adds login, basic ACL, and session wide messages to Grav.  It is designed to provide a way to secure front-end and admin content throughout Grav.

| IMPORTANT!!! This plugin is currently in development as is to be considered a **beta release**.  As such, use this in a production environment **at your own risk!**. More features will be added in the future.


# Installation

The **login** plugin actually requires the help of the **email** and **form** plugins. The **email** plugin is needed to ensure that you can recover a password via email if required.  The **form** plugin is used to generate the forms required.
 
These are available via GPM, and because the plugin has dependencies you just need to proceed and install the login plugin, and agree when prompted to install the others:

```
$ bin/gpm install login
```

# Usage

You can add ACL to any page by typing something like below into the page header:

```
access:
  site.login: true
  admin.login: true
```  

Users who have any of the listed ACL roles enabled will have access to the page.
Others will be forwarded to login screen.

Here is example user defined in `user/accounts/admin.yaml`:

```
username: admin
password: password
email: youremail@mail.com
fullname: Johnny Appleseed
title: Site Administrator
access:
  admin:
    login: true
    super: true
```

Because the admin user contains an `admin.login: true` refernece he will be able to login to the secured page becuase that is one of the conditions defined in the page header.

