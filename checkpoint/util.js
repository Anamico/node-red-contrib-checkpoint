const fs = require('fs');
const async = require('async');

const constant = {
    hashType: {
        MD5: "md5",
        SHA1: "sha1",
        SHA256: "sha256"
    },

    fileProvider: {
        ENTERPRISE: 3
    },

    certProvider: {
        ENTERPRISE: 4
    },

    trustLevel: {
        KNOWN_TRUSTED_INSTALLER: 100,
        KNOWN_TRUSTED: 99,
        MOST_LIKELY_TRUSTED: 85,
        MIGHT_BE_TRUSTED: 70,
        UNKNOWN: 50,
        MIGHT_BE_MALICIOUS: 30,
        MOST_LIKELY_MALICIOUS: 15,
        KNOWN_MALICIOUS: 1,
        NOT_SET: 0,

        // reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
        // todo: make these default but customizable per environment/install?
        fromWildfire: function(verdict) {
            if (verdict == '1') {
                return trustLevel.KNOWN_MALICIOUS;
            }
            return null;
        }
    }
};





module.exports = {

    hashType: constant.hashType,
    fileProvider: constant.fileProvider,
    certProvider: constant.certProvider,
    trustLevel: constant.trustLevel,


    /**
     * Retrieve last timestamp from persistence file
     */
    retrieveLastTimeStamp: function (persistenceFilePath, callback) {

        if (!fs.existsSync(persistenceFilePath)) {
            return callback(null, null);
        }

        fs.readFile(persistenceFilePath, function read(err, data) {
            if (err) {
                return callback(err);
            }
            content = JSON.parse(data);
            console.log('decoded persistent file content', content);
            callback(null, content && content.lastTimestamp);
        });
    },

    /**
     * 
     * Generate 
     * @param {*} config 
     */
    wildfireParams: function (lastTimestamp) {
        // const now = (new Date()).getTime() / 1000; //- tzoffset
        // const oldestAllowed = now - (14 * 24 * 60 * 60) + 60; // allow a 1 minute buffer

        // const startUnix = Math.max(
        //     (lastTimestamp && ((new Date(lastTimestamp)).getTime() / 1000)) || 0,
        //     oldestAllowed);

        // const endUnix = Math.min(
        //     startUnix + (60 * 60),
        //     now);

        // const startTime = new Date(startUnix * 1000).toISOString();
        // const endTime = new Date(endUnix * 1000).toISOString();
        // const param = startUnix + (60 * 60) > now ?
        //             "sinceTime=" + startTime :
        //             "interval=" + startTime + "/" + endTime;
                    
        return {
            date: lastTimestamp
        };
    },

    extractReputations: function(verdicts, processReputation, callback) {
        async.eachSeries(verdicts, function(verdict, callback) {
            if (verdict.verdict != 1) {
                return callback(null);
            }
            const trustLevel = 1; //constant.trustLevel.fromWildfire(verdict.verdict);
            const payload = {
                trustLevel: trustLevel,
                providerId: constant.fileProvider.ENTERPRISE,
                filename: 'WildFire.unknown',
                comment: "from Wildfire",
                hashes: {
                    md5: verdict.md5,
                    sha256: verdict.sha256
                }
            };
            processReputation(payload, callback);
        }, function(err) {
            console.log('completed', err);
        });
    },

    persistLastTimeStamp: function (persistenceFilePath, timestamp, callback) {
        const jsonString = JSON.stringify({
            lastTimestamp: timestamp
        });
        fs.writeFile(persistenceFilePath, jsonString, callback);
    }
};