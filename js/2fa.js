(function($) {
    if (typeof window.GravForm === 'undefined') { return; }

    var config = window.GravForm.config;
    var body = $('body');

    body.on('click', '[data-2fa-regenerate]', function(event) {
        event.preventDefault();
        let element = $(this);
        let url = `${config.base_url_relative}/task${config.param_sep}login.regenerate2FASecret`;
        let nonce = element.closest('.twofa-wrapper').find('input[name="login-form-nonce"]').val();
        // With 2FA on, a new secret takes the current code from the field above.
        let code = $('[data-2fa-code]').val() || '';
        let error = $('[data-2fa-error]');

        element.attr('disabled', 'disabled').find('> .fa').addClass('fa-spin');
        error.text('').hide();

        jQuery.post(url, { 'login-form-nonce': nonce, 'twofa_code': code }, function(response) {
            if (response.status === 'success') {
                $('[data-2fa-image]').attr('src', response.image);
                $('[data-2fa-secret]').text(response.secret);
                $('[data-2fa-value]').val(response.secret);
                $('[data-2fa-code]').val('');
            } else {
                error.text(response.message || '').show();
            }
        }).always(function() {
            element.removeAttr('disabled').find('> .fa').removeClass('fa-spin');
        });
    });

    var toggleSecret = function() {
        const toggle = $('#toggle_twofa_enabled1');
        const secret = $('.twofa-secret');

        secret.css('display', toggle.is(':checked') ? 'inherit' : 'none');
        // [toggle.is(':checked') ? 'addClass' : 'removeClass']('login-show');
    };

    body.on('click', '.twofa-toggle input', toggleSecret);
    toggleSecret();

})(jQuery);
