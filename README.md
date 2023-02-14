# NodeBB OpenLDAP authentication Plugin

This is a fork of the fork that has been heavily modified by [meredrica](https://github.com/meredrica/nodebb-plugin-open-ldap) from the original office-ldap plugin, which was written by [smartameer](https://github.com/smartameer/nodebb-plugin-office-ldap)

This plugin overrides the default authentication mechanism and tries to authenticate users via OpenLDAP.
If this fails, the plugin falls back to local login.

This fork allows LDAP authentification by the fields `uid` and `mail` depending on your LDAP filter rules.


## Requirements

In the OpenLDAP the fields `uid`, `sn` and `mail` must be available.


## Installation

    npm install nodebb-plugin-openldap-maufi

Navigate to the settings and fill in the relevant ldap settings.
Use the placeholder `%logon%` in the LDAP filter rules for the entered username.

Note: you have to build and restart every time the config has been altered, that including LDAP filter modifications.
