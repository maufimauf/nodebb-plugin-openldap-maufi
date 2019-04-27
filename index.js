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
    var user = module.parent.require('./user'),
        meta = module.parent.require('./meta'),
        db = module.parent.require('./database'),
        winston = module.parent.require('winston'),
        passport = module.parent.require('passport'),
        fs = module.parent.require('fs'),
        path = module.parent.require('path'),
        nconf = module.parent.require('nconf'),
        async = module.parent.require('async'),
        local_strategy = module.parent.require('passport-local').Strategy,
        ldapjs = require('ldapjs');
    const Hashes = require('jshashes');

    var master_config = {};
    var open_ldap = {
        name: "OpenLDAP",

        get_domain: function (base) {
            var domain = '';
            if (base !== '') {
                var temp = base.match(/dc=([^,]*)/gi);
                if (temp && temp.length > 0) {
                    domain = temp.map(function (str) {
                        return str.match(/dc=([^,]*)/i)[1];
                    }).reduce(function (current, previous) {
                        return current + '.' + previous;
                    });
                }
            }
            return domain;
        },

        admin: function (custom_header, callback) {
            custom_header.plugins.push({
                "route": "/plugins/open_ldap",
                "icon": "fa-cog",
                "name": "OpenLDAP Settings"
            });
            callback(null, custom_header);
        },

        init: function (params, callback) {
            function render(req, res, next) {
                res.render('open_ldap', {});
            }

            meta.settings.get('openldap', function (err, options) {
                master_config = options;
            });
            params.router.get('/admin/plugins/open_ldap', params.middleware.admin.buildHeader, render);
            params.router.get('/api/admin/plugins/open_ldap', render);

            callback();
        },

        get_config: function (options, callback) {
            meta.settings.get('openldap', function (err, settings) {
                if (err) {
                    return callback(null, options);
                }
                master_config = settings;
                options.openldap = settings;
                callback(null, options);
            });
        },

        fetch_config: function (callback) {
            meta.settings.get('openldap', function (err, options) {
                callback(options);
            });
        },


        stringtoint: function (str) {
            return str.split('').map(function (char) {
                return char.charCodeAt(0);
            }).reduce(function (current, previous) {
                return previous + current;
            });
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
                if (typeof master_config.server === 'undefined') {
                    open_ldap.fetch_config(function (config) {
                        var options = {
                            url: config.server + ':' + config.port
                        };
                        master_config = config;
                        open_ldap.process(options, username, password, next);
                    });
                } else {
                    var options = {
                        url: master_config.server + ':' + master_config.port
                    };
                    open_ldap.process(options, username, password, next);
                }
            }));
        },

        process: function (options, username, password, next) {
            try {
                var adminClient = ldapjs.createClient(options);
                winston.info("client created with master_config: " + JSON.stringify(master_config));
                // try user login first
                adminClient.bind(master_config.admin_user, master_config.password, function (err) {
                    if (err) {
                        winston.error("admin login failed, check your config" + err.message);
                        return next(new Error('[[error:invalid-email]]')); // we don't leak information
                    }
                    // client.bind(master_config.user_query.replace("%uid", username), password, function (err) {
                    if (err) {
                        winston.error(err.message);
                        return next(new Error('[[error:invalid-email]]')); // we don't leak information
                    }
                    var opt = {
                        filter: master_config.user_query.replace('%uid', username),
                        scope: 'sub',
                        sizeLimit: 1
                    };

                    adminClient.search(master_config.base, opt, function (err, res) {
                        winston.info("search");
                        if (err) {
                            return next(new Error('[[error:invalid-email]]'));
                        }

                        res.on('searchEntry', function (entry) {
                            var profile = entry.object;
                            winston.info('profile: ' + JSON.stringify(profile));
                            // now we check the password
                            const userClient = ldapjs.createClient(options);
                            userClient.bind(profile.dn, password, function (err) {
                                if (err) {
                                    return next(new Error('[[error:invalid-email]]'));
                                }
                                userClient.unbind();
                                // auth worked :)
                                var SHA512 = new Hashes.SHA512
                                var id = SHA512.b64(profile.uid);
                                open_ldap.login(id, profile.cn, profile.givenName + " " + profile.sn, profile.mail, function (err, userObject) {
                                    if (err) {
                                        winston.error(err);
                                        return next(new Error('[[error:invalid-email]]'));
                                    }
                                    return next(null, userObject);
                                });

                            });
                        });
                        res.on('searchReference', function (referral) {
                            winston.info('referral: ' + JSON.stringify(referral));
                        });
                        res.on('error', function (err) {
                            winston.error('OpenLDAP Error:' + err.message);
                            return next(new Error('[[error:invalid-email]]'));
                        });
                    });
                    // });
                });
            } catch (err) {
                winston.error('OpenLDAP Error :' + err.message);
            }
        },

        login: function (ldapid, fullname, username, email, callback) {
            winston.info("doing login");
            var _self = this;
            _self.getuidby_ldapid(ldapid, function (err, uid) {
                if (err) {
                    return callback(err);
                }

                if (uid !== null) {
                    return callback(null, {
                        uid: uid
                    });
                } else {
                    winston.info("no uid in the db")
                    // New User
                    var success = function (uid) {
                        // Save provider-specific information to the user
                        user.setUserField(uid, 'ldapid', ldapid);
                        db.setObjectField('ldapid:uid', ldapid, uid);
                        // TODO: set groups here #2
                        callback(null, {
                            uid: uid
                        });
                    };

                    return user.getUidByEmail(email, function (err, uid) {
                        if (err) {
                            return callback(err);
                        }

                        if (!uid) {
                            var pattern = new RegExp(/[\ ]*\(.*\)/);
                            if (pattern.test(username)) {
                                username = username.replace(pattern, '');
                            }
                            winston.info("create user")
                            return user.create({ username: username, fullname: fullname, email: email }, function (err, uid) {
                                if (err) {
                                    return callback(err);
                                }
                                if (master_config.autovalidate == 1) {
                                    user.setUserField(uid, 'email:confirmed', 1);
                                }
                                return success(uid);
                            });
                        } else {
                            return success(uid); // Existing account -- merge
                        }
                    });
                }
            });
        },

        getuidby_ldapid: function (ldapid, callback) {
            db.getObjectField('ldapid:uid', ldapid, function (err, uid) {
                if (err) {
                    return callback(err);
                }
                return callback(null, uid);
            });
        }
    };

    module.exports = open_ldap;

}(module));
