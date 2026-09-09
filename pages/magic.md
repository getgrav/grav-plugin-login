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

[translate=PLUGIN_LOGIN.MAGIC_PAGE_DESC /]
