# NodeBB OpenLDAP authentication Plugin

This is a heavily modified fork from the original office-ldap plugin was written by [smartameer](https://github.com/smartameer/nodebb-plugin-office-ldap)

This plugin overrides the default authentication mechanism and tries to authenticate users via OpenLDAP.

If this fails, the plugin falls back to local login.

# Requirements
UID must be configured in OpenLDAP

## Installation

    npm install nodebb-plugin-sso-open-ldap

navigate to the settings and fill in the relevant ldap settings
