---
title: Login by email link
cache_control: private, no-cache, must-revalidate

login_redirect_here: false

form:
  fields:
    - name: email
      type: email
      placeholder: PLUGIN_LOGIN.ENTER_EMAIL
      autofocus: true
      validate:
        required: true
        type: email
---

Enter your email address to receive a one-time sign-in link.
