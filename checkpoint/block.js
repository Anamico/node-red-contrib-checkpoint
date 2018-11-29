const async = require('async');

/*
<div class="form-row">
        <input type="checkbox" id="node-input-includeUrls" style="display: inline-block; width: auto; vertical-align: top;">
        <label for="node-input-includeUrls" style="width: 70%;"><span data-i18n="node-red:httpin.basicauth">Use basic authentication</span></label>
    </div>
 */

module.exports = function(RED) {

    function Block(config) {
        RED.nodes.createNode(this, config);
        var node = this;

        this._checkpoint = RED.nodes.getNode(config.checkpoint);

        node.on('input', function(msg) {

            const ip = msg.payload.ip;
            const group = msg.payload.group || config.group || 'BadIpList';
            const comment = msg.payload.comment || config.comment || 'Set via node-red';

            if (!ip) {
                node.status({ fill: "red", shape: "dot", text: "Missing ip" });
                node.error("Missing payload.ip", msg);
                return;
            }
            node.status({ fill: "blue", shape: "dot", text: "Connecting" });
            async.auto({
                sid: this._checkpoint.login,
            
                addGroup: ['sid', function(data, callback) {
                    node.status({ fill: "blue", shape: "dot", text: "Set Group" });
                    node.log('addGroup', data.sid);
                    node._checkpoint.addGroup(data.sid, group, callback);
                }],
            
                addHost: ['sid', function(data, callback) {     // can be in parallel?
                    node.status({ fill: "blue", shape: "dot", text: "Add Host" });
                    node.log('addHost');
                    node._checkpoint.addHost(data.sid, ip, comment, callback);
                }],

                setHost: ['addGroup', 'addHost', function(data, callback) {
                    node.status({ fill: "blue", shape: "dot", text: "Link Host" });
                    node.log('setHost', data.sid);
                    node._checkpoint.setHost(data.sid, ip, group, callback);
                }],

                publish: ['setHost', function(data, callback) {
                    setTimeout(function() {
                        node.status({ fill: "blue", shape: "dot", text: "Publishing" });
                        node.log('publish', data.sid);
                        node._checkpoint.publish(data.sid, callback);
                    }, 2000);
                }],

                logout: ['publish', function(data, callback) {
                    setTimeout(function() {
                        node.status({ fill: "blue", shape: "dot", text: "Disconnect" });
                        node._checkpoint.logout(callback);
                    }, 2000);
                }]
            
            }, function(err, data) {
                if (err) {
                    node.error(err.message, msg);
                    node.status({ fill: "red", shape: "dot", text: err.message});
                    return console.log(err);
                }
                node.log("Blocked " + ip);
                node.status({ fill: "green", shape: "dot", text: "Blocked " + ip });
            });
        });
    }
    RED.nodes.registerType("checkpoint block", Block);
};
