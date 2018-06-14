var AWS = require('aws-sdk'),
    http = require('http'),
    zlib = require('zlib');

// Uses the current region for KMS encryption/decryption
AWS.config.update({ region: process.env.AWS_REGION });

const encrypted = process.env['LOGGLY_TOKEN'];
let decrypted;

const hostName = (process.env['LOGGLY_URL'].trim() === "") ? 'logs-01.loggly.com' : process.env['LOGGLY_URL'].trim();
var tags = (process.env['LOGGLY_TAGS'].trim() === "") ? 'CloudWatch2Loggly' : process.env['LOGGLY_TAGS'].split(',').map(item => { return item.trim() });

// loggly url, token and tag configuration
// user need to edit while uploading code via blueprint
var logglyConfiguration = {
    hostName: hostName,
    tags: tags
};

var cloudWatchLogs = new AWS.CloudWatchLogs({
    apiVersion: '2014-03-28'
});

var kms = new AWS.KMS({
    apiVersion: '2014-11-01'
});

function processEvent(event, context, callback) {
    var payload = new Buffer(event.awslogs.data, 'base64');

    zlib.gunzip(payload, function (error, result) {
        if (error) {
            context.fail(error);
        } else {
            var result_parsed = JSON.parse(result.toString('ascii'));
            var parsedEvents = result_parsed.logEvents.map(function(logEvent) {
                return parseEvent(logEvent, result_parsed.logGroup, result_parsed.logStream);
            });

            postEventsToLoggly(parsedEvents);
        }
    });

    // converts the event to a valid JSON object with the sufficient information required
    function parseEvent(logEvent, logGroupName, logStreamName) {
        console.log("logEvent: " + JSON.stringify(logEvent));
        return {
            // remove '\n' character at the end of the event
            message: logEvent.message.trim(),
            logGroupName: logGroupName,
            logStreamName: logStreamName,
            timestamp: new Date(logEvent.timestamp).toISOString()
        };
    }

    // joins all the events to a single event
    // and sends to Loggly using bulk endpoint
    function postEventsToLoggly(parsedEvents) {
        if (!logglyConfiguration.customerToken) {
            if (logglyConfiguration.tokenInitError) {
                console.log('error in decrypt the token. Not retrying.');
                return context.fail(logglyConfiguration.tokenInitError);
            }
            console.log('Cannot flush logs since authentication token has not been initialized yet. Trying again in 100 ms.');
            setTimeout(function () { postEventsToLoggly(parsedEvents) }, 100);
            return;
        }

        // get all the events, stringify them and join them
        // with the new line character which can be sent to Loggly
        // via bulk endpoint
        var finalEvent = parsedEvents.map(JSON.stringify).join('\n');

        // creating logglyURL at runtime, so that user can change the tag or customer token in the go
        // by modifying the current script
        // create request options to send logs
        try {
            var options = {
                hostname: logglyConfiguration.hostName,
                path: '/bulk/' + logglyConfiguration.customerToken + '/tag/' + encodeURIComponent(logglyConfiguration.tags),
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': finalEvent.length
                }
            };

            var req = http.request(options, function (res) {
                res.on('data', function (result) {
                    result = JSON.parse(result.toString());
                    if (result.response === 'ok') {
                        context.succeed('all events are sent to Loggly');
                    } else {
                        console.log(result.response);
                    }
                });
                res.on('end', function () {
                    console.log('No more data in response.');
                    context.done();
                });
            });

            req.on('error', function (e) {
                console.log('problem with request: ' + e.toString());
                context.fail(e);
            });

            // write data to request body
            req.write(finalEvent);
            req.end();

        } catch (ex) {
            console.log(ex.message);
            context.fail(ex.message);
        }
    }
}

// entry point
exports.handler = (event, context, callback) => {
    if(decrypted) {
        processEvent(event, context, callback);
    } else {
        // Decrypt code should run once and variables stored outside of the function
        // handler so that these are decrypted once per container
        // use KMS to decrypt customer token
        const kms = new AWS.KMS();
        kms.decrypt({ CiphertextBlob: new Buffer(encrypted, 'base64') }, (err, data) => {
            if (err) {
                logglyConfiguration.tokenInitError = error;
                console.log('Decrypt error:', err);
                return callback(err);
            }
            decrypted = data.Plaintext.toString('ascii');
            logglyConfiguration.customerToken = decrypted;
            processEvent(event, context, callback);
        });
    }
};