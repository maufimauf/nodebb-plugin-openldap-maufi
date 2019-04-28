(function (module) {
    "use strict";
    /*
    2019-04-24T18:53:24.599Z [4567/18557] - warn: [deprecated] requiring core modules with `module.parent.require('./user')` is deprecated. Please use `require.main.require("./src/<module_name>")` instead.
    at /home/meredrica/github/nodebb-plugin-office-ldap/index.js:4:30
2019-04-24T18:53:24.599Z [4567/18557] - warn: [deprecated] requiring core modules with `module.parent.require('./meta')` is deprecated. Please use `require.main.require("./src/<module_name>")` instead.
    at /home/meredrica/github/nodebb-plugin-office-ldap/index.js:5:30
2019-04-24T18:53:24.600Z [4567/18557] - warn: [deprecated] requiring core modules with `module.parent.require('./database')` is deprecated. Please use `require.main.require("./src/<module_name>")` instead.
    at /home/meredrica/github/nodebb-plugin-office-ldap/index.js:6:28

    */
    /* globals app, socket */
    var user = require.main.require('./src/user'),
        Groups = require.main.require('./src/groups'),
        meta = require.main.require('./src/meta'),
        db = require.main.require('./src/database'),
        winston = require.main.require('winston'),
        passport = require.main.require('passport'),
        async = require.main.require('async'),
        // fs = module.parent.require('fs'),
        // path = module.parent.require('path'),
        // nconf = module.parent.require('nconf'),
        local_strategy = require.main.require('passport-local').Strategy,
        ldapjs = require('ldapjs');
    const Hashes = require('jshashes');

    var master_config = {};
    var global_ldap_options = {};
    var open_ldap = {
        name: "OpenLDAP",

        adminHeader: function (custom_header, callback) {
            custom_header.plugins.push({
                "route": "/plugins/open_ldap",
                "icon": "fa-cog",
                "name": "OpenLDAP Settings"
            });
            callback(null, custom_header);
        },

        getConfig: function (options, callback) {
            winston.info("get config");
            meta.settings.get('openldap', function (err, settings) {
                if (err) {
                    return callback(err);
                }
                options.openldap = settings;
                callback(null, options);
            });
        },

        init: function (params, callback) {
            winston.info("openldap init");
            function render(req, res, next) {
                res.render('open_ldap', {});
            }

            params.router.get('/admin/plugins/open_ldap', params.middleware.admin.buildHeader, render);
            params.router.get('/api/admin/plugins/open_ldap', render);

            const defaultOptions = {
                server: "ldap://172.17.0.3",
                port: "",
                base: "dc=example,dc=org",
                admin_user: "cn=admin,dc=example,dc=org",
                password: "admin",
                user_query: "(&(|(objectclass=inetOrgPerson))(uid=%uid))",
                groups_query: "(&(|(objectclass=posixGroup)))",
                admin_groups: "admins",
                moderator_groups: "mods"
            };


            async.waterfall([
                function (next) {
                    open_ldap.getConfig({}, function (err, config) {
                        if (err) {
                            return next(err);
                        }
                        master_config = config.openldap.server ? config.openldap : defaultOptions;
                        global_ldap_options.url = master_config.server + ':' + master_config.port
                        winston.info("master_config: " + JSON.stringify(master_config));
                        next();
                    });
                },
                open_ldap.findLdapGroups,
                function (groups, next) {
                    async.each(groups, open_ldap.createGroup, next);
                }
            ], callback);
        },

        override: function () {
            passport.use(new local_strategy({
                passReqToCallback: true
            }, function (req, username, password, next) {
                if (!username) {
                    return next(new Error('[[error:invalid-email]]'));
                }
                if (!password) {
                    return next(new Error('[[error:invalid-password]]'));
                }
                open_ldap.process(username, password, next);
            }));
        },


        findLdapGroups: function (callback) {
            winston.info("load groups");
            open_ldap.adminClient(function (err, adminClient) {
                if (err) {
                    return callback(err);
                }
                var groups_search = {
                    filter: master_config.groups_query,
                    scope: 'sub',
                    attributes: ['cn', 'memberUid']
                };

                adminClient.search(master_config.base, groups_search, function (err, res) {
                    let groups = [];
                    if (err) {
                        return callback(new Error('groups could not be found'));
                    }
                    res.on('searchEntry', function (entry) {
                        const group = entry.object;
                        groups.push(group)
                    });
                    res.on('end', function () {
                        adminClient.unbind();
                        callback(null, groups);
                    });
                });
            });
        },

        adminClient: function (callback) {
            var client = ldapjs.createClient(global_ldap_options);
            client.bind(master_config.admin_user, master_config.password, function (err) {
                if (err) {
                    return callback(new Error('could not bind with admin config ' + err.message));
                }
                callback(null, client);
            });
        },

        createGroup: function (ldapGroup, callback) {
            // creates the group 
            const groupName = "ldap-" + ldapGroup.cn;
            winston.info("create group " + groupName);
            const groupData = {
                name: groupName,
                userTitleEnabled: false,
                description: 'LDAP Group ' + ldapGroup.cn,
                // hidden: true,
                // system: true,
                // private: true,
                disableJoinRequests: true,
            };
            Groups.create(groupData, function (err, group) {
                callback(null, groupName);
            });
        },

        process: function (username, password, next) {
            try {
                open_ldap.adminClient(function (err, adminClient) {
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

                    adminClient.search(master_config.base, opt, function (err, res) {
                        if (err) {
                            return next(err);
                        }
                        res.on('searchEntry', function (entry) {
                            var profile = entry.object;
                            winston.info('profile: ' + JSON.stringify(profile));
                            // now we check the password
                            const userClient = ldapjs.createClient(global_ldap_options);
                            userClient.bind(profile.dn, password, function (err) {
                                winston.info("user authenticated");
                                userClient.unbind();

                                if (err) {
                                    return next(new Error('[[error:invalid-email]]'));
                                }

                                open_ldap.login(profile, function (err, userObject) {
                                    if (err) {
                                        winston.error(err);
                                        return next(new Error('[[error:invalid-email]]'));
                                    }
                                    return next(null, userObject);
                                });

                            });

                        });
                        res.on('end', function (result) {
                            adminClient.unbind();
                        });
                        res.on('error', function (err) {
                            adminClient.unbind();
                            winston.error('OpenLDAP Error:' + err.message);
                            return next(new Error('[[error:invalid-email]]'));
                        });

                    });
                });
            } catch (err) {
                winston.error('OpenLDAP Error :' + err.message);
            }
        },

        login: (profile, callback) => {
            winston.info("doing login: " + JSON.stringify(profile));
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
                    winston.info("user exists:" + JSON.stringify(dbUser));
                    return open_ldap.postLogin(dbUser.uid, profile.uid, callback);
                } else {
                    // New User
                    var pattern = new RegExp(/[\ ]*\(.*\)/);
                    let username = fullname;
                    if (pattern.test(username)) {
                        username = username.replace(pattern, '');
                    }
                    winston.info("create user: " + JSON.stringify(profile))
                    return user.create({ username: username, fullname: fullname, email: profile.mail }, function (err, uid) {
                        if (err) {
                            return callback(err);
                        }
                        user.setUserField(uid, 'email:confirmed', 1);
                        db.setObjectField('ldapid:uid', profile.uid, uid)
                        db.setObjectField('ldapid:ldapid', uid, profile.uid)
                        return open_ldap.postLogin(uid, profile.uid, callback);
                    });
                }
            });
        },
        postLogin: function (uid, ldapId, callback) {
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

        groupJoin: function (ldapGroup, ldapId, uid, callback) {
            open_ldap.createGroup(ldapGroup,
                function (err, groupId) {
                    if (err) {
                        return callback(err);
                    }
                    let members = ldapGroup.memberUid;
                    if (!Array.isArray(members)) {
                        members = [members];
                    }
                    if (members.includes(ldapId)) {
                        const groupsToJoin = [groupId];
                        console.log("groupId, ldapid, uid", groupId, ldapId, uid);
                        if (master_config.admin_groups.split(',').includes(ldapGroup.cn)) {
                            groupsToJoin.push('administrators');
                        }
                        if (master_config.moderator_groups.split(',').includes(ldapGroup.cn)) {
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

        getUserByLdapUid: function (ldapUid, callback) {
            db.getObjectField('ldapid:uid', ldapUid, function (err, uid) {
                if (err) {
                    return callback(err);
                }
                user.getUserData(uid, function (err, data) {
                    if (err) {
                        return callback(err);
                    }
                    winston.info("user data from db: " + JSON.stringify(data));
                    callback(null, data);
                });
            });
        },

    };

    module.exports = open_ldap;

}(module));
