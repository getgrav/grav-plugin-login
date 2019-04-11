---
title: Profile
access:
    site.login: true
    
form:
  fields:
    avatar_img:
      type: avatar
  
    username:
      type: text
      readonly: true
      disabled: true

    email:
      type: email
      placeholder: "Enter your email"
      validate:
        required: true
        message: PLUGIN_LOGIN.EMAIL_VALIDATION_MESSAGE
        
    fullname:
      type: text
      
    title:
      type: text  

    password:
      type: password
      label: Enter new password
      validate:
        message: PLUGIN_LOGIN.PASSWORD_VALIDATION_MESSAGE
        config-pattern@: system.pwd_regex
        
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

        twofa_secret:
            type: 2fa_secret
            outerclasses: 'twofa-secret'
            markdown: true
            label: PLUGIN_LOGIN.2FA_SECRET
            sublabel: PLUGIN_LOGIN.2FA_SECRET_HELP    


  buttons:
      -
          type: submit
          value: Submit
      -
          type: reset
          value: Reset

  process:
      update_user: true
      message: "Your profile has been updated"
---

# Profile