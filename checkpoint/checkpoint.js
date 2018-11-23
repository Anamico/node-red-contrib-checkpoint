'use strict';

var request = require('request');
var parser = require('fast-xml-parser');

module.exports = function(RED) {

    function Checkpoint(config) {
        RED.nodes.createNode(this, config);

        var node = this;

        const user = this.credentials.user;
        const password = this.credentials.password;

        function apiCall(command, sid, body, callback) {
            if (!config.server) {
                callback(new Error('Missing Hostname/IP'));
                return;
            }
            const server = config.server.trim();
            var port = parseInt((config.port && config.port.trim && config.port.trim()) || "443");
            if (isNaN(port)) {
                port = 443;
            }
            request({
                method: 'POST',
                headers: sid ? { 'X-chkp-sid' : sid } : {},
                uri: 'https://' + server + ':' + port + '/web_api/' + command,
                json: true,
                body: body
            }, function (error, response, body) {
                if (error || (!response.statusCode == 200)) {
                    return callback(error || new Error('Request Error'));
                }
                try {
                    var json = parser.parse(body);
                } catch(err) {
                    return callback(err);
                }
                callback(null, json);
            });
        }

        this.login = function(callback) {
            if (!user) {
                callback(new Error('Missing Username'));
                return;
            }
            if (!password) {
                callback(new Error('Missing Password'));
                return;
            }

            const body = Object.assign({}, params, {
                user: user,
                password: password,
                'continue-last-session': 'true'     // todo: confirm this meant to be a string and not a boolean
            });

            apiCall('login', null, body, function(err, json) {
                if (err) { return callback(err); }
                if (!json || !json.sid) { return callback(new Error('Login Failed')); }
                return callback(null, json.sid);
            });
        }

        this.addGroup = function(sid, groupName, callback) {
            if (!sid) { return callback(new Error('Not Logged In')); }
            if (!groupName)  { return callback(new Error('Missing groupName')); }
            apiCall('add-group', sid, {
                name: groupName
            }, function(err, json) {
                if (err) { return callback(err); }
                //if (!json || !json.sid) { return callback(new Error('Add Group Failed')); }
                return callback(null, json);
            });
        }

        this.addHost = function(sid, ip, comments, callback) {
            if (!sid) { return callback(new Error('Not Logged In')); }
            if (!ip)  { return callback(new Error('Missing ip')); }
            apiCall('add-host', sid, {
                name: ip,
                'ip-address': ip,
                comments: comments || 'Set Via node-red-contrib-checkpoint'
            }, function(err, json) {
                if (err) { return callback(err); }
                //if (!json || !json.sid) { return callback(new Error('Add Host Failed')); }
                return callback(null, json);
            });
        }

        this.setHost = function(sid, ip, groupName, callback) {
            if (!sid) { return callback(new Error('Not Logged In')); }
            if (!ip)  { return callback(new Error('Missing ip')); }
            if (!groupName)  { return callback(new Error('Missing groupName')); }
            apiCall('add-host', sid, {
                name: ip,
                groups: groupName
            }, function(err, json) {
                if (err) { return callback(err); }
                //if (!json || !json.sid) { return callback(new Error('Add Host Failed')); }
                return callback(null, json);
            });
        }

        // warning: should pause 2 seconds before this call? and up to 5 seconds after?
        // ref: https://github.com/mohlcyber/OpenDXL-ATD-Checkpoint/blob/master/cp_push.py
        this.publish = function(sid, callback) {
            if (!sid) { return callback(new Error('Not Logged In')); }
            apiCall('publish', sid, {}, function(err, json) {
                if (err) { return callback(err); }
                //if (!json || !json.sid) { return callback(new Error('Add Host Failed')); }
                return callback(null, json);
            });
        }

        this.logout = function(sid, callback) {
            if (!sid) { return callback(new Error('Not Logged In')); }
            apiCall('logout', sid, {}, function(err, json) {
                if (err) { return callback(err); }
                //if (!json || !json.sid) { return callback(new Error('Add Host Failed')); }
                return callback(null, json);
            });
        }
    }

    RED.nodes.registerType("checkpoint", Checkpoint, {
        credentials: {
            user: { type:"text" },
            password: { type:"password" }
        }
    });
};
