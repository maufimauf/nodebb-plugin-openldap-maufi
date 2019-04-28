(function (module) {
    "use strict";
    /* globals app, socket */
    var User = require.main.require('./src/user'),
        Groups = require.main.require('./src/groups'),
        Meta = require.main.require('./src/meta'),
        db = require.main.require('./src/database'),
        winston = require.main.require('winston'),
        passport = require.main.require('passport'),
        async = require.main.require('async'),
        local_strategy = require.main.require('passport-local').Strategy,
        ldapjs = require('ldapjs');

    var master_config = {};
    var open_ldap = {
        whitelistFields: (params, callback) => {
            params.whitelist.push('openldap:data');
            callback(null, params);
        },

        adminHeader: (custom_header, callback) => {
            custom_header.plugins.push({
                "route": "/plugins/open_ldap",
                "icon": "fa-cog",
                "name": "OpenLDAP Settings"
            });
            callback(null, custom_header);
        },

        getConfig: (options, callback) => {
            options = options ? options : {};
            Meta.settings.get('openldap', (err, settings) => {
                if (err) {
                    return callback(err);
                }
                options.openldap = settings;
                callback(null, options);
            });
        },

        init: (params, callback) => {
            const render = (req, res, next) => {
                res.render('open_ldap', {});
            }

            params.router.get('/admin/plugins/open_ldap', params.middleware.admin.buildHeader, render);
            params.router.get('/api/admin/plugins/open_ldap', render);

            async.waterfall([
                open_ldap.updateConfig,
                open_ldap.findLdapGroups,
                (groups, next) => {
                    async.each(groups, open_ldap.createGroup, next);
                }
            ], callback);
        },

        updateConfig: (callback) => {
            open_ldap.getConfig(null, (err, config) => {
                if (err) {
                    return callback(err);
                }
                master_config = config.openldap;
                callback();
            });
        },

        override: () => {
            passport.use(new local_strategy({
                passReqToCallback: true
            }, (req, username, password, next) => {
                if (!username) {
                    return next(new Error('[[error:invalid-email]]'));
                }
                if (!password) {
                    return next(new Error('[[error:invalid-password]]'));
                }
                open_ldap.process(username, password, next);
            }));
        },

        findLdapGroups: (callback) => {
            if (!master_config.groups_query) {
                return callback(null, []);
            }
            open_ldap.adminClient((err, adminClient) => {
                if (err) {
                    return callback(err);
                }
                var groups_search = {
                    filter: master_config.groups_query,
                    scope: 'sub',
                    attributes: ['cn', 'memberUid']
                };

                adminClient.search(master_config.base, groups_search, (err, res) => {
                    let groups = [];
                    if (err) {
                        return callback(new Error('groups could not be found'));
                    }
                    res.on('searchEntry', (entry) => {
                        const group = entry.object;
                        groups.push(group)
                    });
                    res.on('end', () => {
                        adminClient.unbind();
                        callback(null, groups);
                    });
                });
            });
        },

        adminClient: (callback) => {
            var client = ldapjs.createClient({ url: master_config.server + ':' + master_config.port });
            client.bind(master_config.admin_user, master_config.password, (err) => {
                if (err) {
                    return callback(new Error('could not bind with admin config ' + err.message));
                }
                callback(null, client);
            });
        },

        createGroup: (ldapGroup, callback) => {
            const groupName = "ldap-" + ldapGroup.cn;
            const groupData = {
                name: groupName,
                userTitleEnabled: false,
                description: 'LDAP Group ' + ldapGroup.cn,
                hidden: 1,
                system: 1,
                private: 1,
                disableJoinRequests: true,
            };
            Groups.create(groupData, () => {
                callback(null, groupName);
            });
        },

        process: (username, password, next) => {
            async.waterfall([
                open_ldap.updateConfig,
                (next) => {

                    open_ldap.adminClient((err, adminClient) => {
                        if (err) {
                            return next(err);
                        }
                        var opt = {
                            filter: master_config.user_query.replace('%uid', username),
                            sizeLimit: 1,
                            scope: 'sub',
                            attributes: ['dn', 'uid', 'sn', 'mail', //these fields are mandatory
                                // optional fields. used to create the user id/fullname
                                'givenName', 'displayName',
                            ]
                        };

                        adminClient.search(master_config.base, opt, (err, res) => {
                            if (err) {
                                return next(err);
                            }
                            res.on('searchEntry', (entry) => {
                                var profile = entry.object;
                                // now we check the password
                                const userClient = ldapjs.createClient({ url: master_config.server + ':' + master_config.port });
                                userClient.bind(profile.dn, password, (err) => {
                                    userClient.unbind();

                                    if (err) {
                                        return next(new Error('[[error:invalid-email]]'));
                                    }

                                    open_ldap.login(profile, (err, userObject) => {
                                        if (err) {
                                            return next(new Error('[[error:invalid-email]]'));
                                        }
                                        return next(null, userObject);
                                    });

                                });

                            });
                            res.on('end', () => {
                                adminClient.unbind();
                            });
                            res.on('error', (err) => {
                                adminClient.unbind();
                                winston.error('OpenLDAP Error:' + err.message);
                                return next(new Error('[[error:invalid-email]]'));
                            });

                        });
                    });
                }
            ], next);
        },

        login: (profile, callback) => {
            // build the username
            let fullname = profile.sn;
            if (profile.givenName) {
                fullname = profile.givenName + " " + fullname;
            }
            if (profile.displayName) {
                fullname = profile.displayName;
            }

            open_ldap.getUserByLdapUid(profile.uid, (err, dbUser) => {
                if (err) {
                    return callback(err);
                }
                if (dbUser.uid !== 0) {
                    // user exists
                    // now we check the user groups
                    return open_ldap.postLogin(dbUser.uid, profile.uid, callback);
                } else {
                    // New User
                    var pattern = new RegExp(/[\ ]*\(.*\)/);
                    let username = fullname;
                    if (pattern.test(username)) {
                        username = username.replace(pattern, '');
                    }
                    return User.create({ username: username, fullname: fullname, email: profile.mail }, (err, uid) => {
                        if (err) {
                            return callback(err);
                        }

                        User.setUserFields(uid, {
                            'openldap:uid:': profile.uid,
                            'email:confirmed': 1
                        });
                        db.setObjectField('ldapid:uid', profile.uid, uid)
                        return open_ldap.postLogin(uid, profile.uid, callback);
                    });
                }
            });
        },
        postLogin: (uid, ldapId, callback) => {
            async.waterfall([
                open_ldap.findLdapGroups,
                (groups, next) => {
                    async.each(groups,
                        (ldapGroup, next) => {
                            open_ldap.groupJoin(ldapGroup, ldapId, uid, next);
                        }, next);
                }],
                () => {
                    callback(null, { uid: uid });
                }
            );
        },

        groupJoin: (ldapGroup, ldapId, uid, callback) => {
            open_ldap.createGroup(ldapGroup,
                (err, groupId) => {
                    if (err) {
                        return callback(err);
                    }
                    let members = ldapGroup.memberUid;
                    if (!Array.isArray(members)) {
                        members = [members];
                    }
                    if (members.includes(ldapId)) {
                        const groupsToJoin = [groupId];
                        if ((master_config.admin_groups || '').split(',').includes(ldapGroup.cn)) {
                            groupsToJoin.push('administrators');
                        }
                        if ((master_config.moderator_groups || '').split(',').includes(ldapGroup.cn)) {
                            groupsToJoin.push('Global Moderators');
                        }
                        return Groups.join(groupsToJoin, uid, callback);
                    }
                    else {
                        callback();
                    }
                }
            );
        },

        getUserByLdapUid: (ldapUid, callback) => {
            db.getObjectField('ldapid:uid', ldapUid, (err, uid) => {
                if (err) {
                    return callback(err);
                }
                User.getUserData(uid, (err, data) => {
                    if (err) {
                        return callback(err);
                    }
                    callback(null, data);
                });
            });
        },

    };

    module.exports = open_ldap;

}(module));
