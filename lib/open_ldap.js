define('admin/plugins/open_ldap', ['settings'], function (Settings) {
    'use strict';
    /* globals $, app, socket, require */

    var ACP = {};

    ACP.init = function () {
        Settings.load('openldap', $('.ldap-settings'));
        $('#save').on('click', function () {
            Settings.save('openldap', $('.ldap-settings'), function () {
                app.alert({
                    type: 'success',
                    alert_id: 'openldap-saved',
                    title: 'Settings Saved',
                    message: 'Please reload your NodeBB to apply these settings',
                });
                socket.emit('admin.reload');
            });
        });
    };

    return ACP;
});
