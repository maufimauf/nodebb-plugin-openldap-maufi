# NodeBB OpenLDAP authentication Plugin

This is a fork of the fork that has been heavily modified by [meredrica](https://github.com/meredrica/nodebb-plugin-open-ldap) from the original office-ldap plugin, which was written by [smartameer](https://github.com/smartameer/nodebb-plugin-office-ldap)

This plugin overrides the default authentication mechanism and tries to authenticate users via OpenLDAP.

If this fails, the plugin falls back to local login.

# Requirements
uid, sn and mail must be configured in OpenLDAP

## Installation

    npm install nodebb-plugin-openldap-maufi

navigate to the settings and fill in the relevant ldap settings

Note: you have to build and restart after every config/filter modification.
