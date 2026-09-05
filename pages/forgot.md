---
title: Forgot password
cache_control: private, no-cache, must-revalidate

login_redirect_here: false

form:

    fields:
        - name: email
          type: email
          label: PLUGIN_LOGIN.EMAIL
          autofocus: true
          validate:
            required: true
            type: email
---


# [translate=PLUGIN_LOGIN.FORGOT_PAGE_HEADING /]

[translate=PLUGIN_LOGIN.FORGOT_PAGE_DESC /]
