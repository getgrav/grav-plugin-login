---
title: Profile
cache_control: private, no-cache, must-revalidate
access:
    site.login: true

form:
  fields:
    avatar_img:
      type: avatar

    username:
      id: username
      type: text
      readonly: true
      disabled: true

    email:
      id: email
      type: email
      placeholder: PLUGIN_LOGIN.ENTER_EMAIL
      validate:
        required: true
        message: PLUGIN_LOGIN.EMAIL_VALIDATION_MESSAGE

    email_change:
      type: email_change

    fullname:
      id: fullname
      type: text

    title:
      id: title
      type: text

    current_password:
      id: current_password
      type: current_password
      label: PLUGIN_LOGIN.CURRENT_PASSWORD
      autocomplete: current-password
      validate:
        type: password

    password:
      id: password
      type: password
      label: PLUGIN_LOGIN.ENTER_NEW_PASSWORD
      autocomplete: new-password
      validate:
        message: PLUGIN_LOGIN.PASSWORD_VALIDATION_MESSAGE
        config-pattern@: system.pwd_regex

    password_confirm:
      id: password_confirm
      type: password
      label: PLUGIN_LOGIN.CONFIRM_NEW_PASSWORD
      autocomplete: new-password

    twofa_check:
      type: conditional
      condition: config.plugins.login.twofa_enabled

      fields:

        twofa:
          title: PLUGIN_LOGIN.2FA_TITLE
          type: section
          underline: true

        twofa_enabled:
          type: toggle
          label: PLUGIN_LOGIN.2FA_ENABLED
          classes: twofa-toggle
          highlight: 1
          default: 0
          options:
            1: GRAV.YES
            0: GRAV.NO
          validate:
            type: bool

        twofa_code:
          id: twofa_code
          type: twofa_code
          label: PLUGIN_LOGIN.2FA_CURRENT_CODE
          help: PLUGIN_LOGIN.2FA_CURRENT_CODE_HELP
          autocomplete: one-time-code
          validate:
            type: text

        twofa_secret:
            type: 2fa_secret
            outerclasses: 'twofa-secret'
            markdown: true
            label: PLUGIN_LOGIN.2FA_SECRET
            sublabel: PLUGIN_LOGIN.2FA_SECRET_HELP


  buttons:
      -
          type: submit
          value: PLUGIN_LOGIN.BTN_SUBMIT_PROFILE
      -
          type: reset
          value: PLUGIN_LOGIN.BTN_RESET

  process:
      update_user: true
      message: PLUGIN_LOGIN.PROFILE_UPDATED
---

# [translate=PLUGIN_LOGIN.PROFILE_PAGE_TITLE /]
