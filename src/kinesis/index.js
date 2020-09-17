/**
 * AWS Kinesis Lambda function for Coralogix
 *
 * @file        This file is lambda function source code
 * @author      Coralogix Ltd. <info@coralogix.com>
 * @link        https://coralogix.com/
 * @copyright   Coralogix Ltd.
 * @licence     Apache-2.0
 * @version     1.0.0
 * @since       1.0.0
 */

"use strict";

// Import required libraries
const https = require("https");
const assert = require("assert");

// Check Lambda function parameters
assert(process.env.private_key, "No private key!")
const appName = process.env.app_name ? process.env.app_name : "NO_APPLICATION";
const subName = process.env.sub_name ? process.env.sub_name : "NO_SUBSYSTEM";
const newlinePattern = (process.env.newline_pattern) ? RegExp(process.env.newline_pattern) : /(?:\r\n|\r|\n)/g;
const coralogixUrl = (process.env.CORALOGIX_URL) ? process.env.CORALOGIX_URL : "api.coralogix.com";

/**
 * Decode payload to simple string
 * @param {string} streamEventRecord - Kinesis data payload
 * @returns {string} Decoded payload
 */
function extractEvent(streamEventRecord) {
    return new Buffer(streamEventRecord.kinesis.data, "base64").toString("ascii");
}

/**
 * @description Split payload to records
 * @param {string} eventsData - Kinesis data payload
 * @returns {Array} Log records
 */
function parseEvents(eventsData) {
    return eventsData.split(newlinePattern).map((eventRecord) => {
        return {
            "timestamp": Date.now(),
            "severity": getSeverityLevel(eventRecord),
            "text": eventRecord
        };
    });
}

/**
 * @description Send logs to Coralogix via API
 * @param {object} parsedEvents - Log message
 */
function postEventsToCoralogix(parsedEvents) {
    try {
        let retries = 3;
        let timeoutMs = 10000;
        let retryNum = 0;
        let sendRequest = function sendRequest() {
            let req = https.request({
                hostname: coralogixUrl,
                port: 443,
                path: "/api/v1/logs",
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                }
            }, function (res) {
                console.log("Status: %d", res.statusCode);
                console.log("Headers: %s", JSON.stringify(res.headers));
                res.setEncoding("utf8");
                res.on("data", function (body) {
                    console.log("Body: %s", body);
                });
            });
            req.setTimeout(timeoutMs, () => {
                req.abort();
                if (retryNum++ < retries) {
                    console.log("Problem with request: timeout reached. retrying %d/%d", retryNum, retries);
                    sendRequest();
                } else {
                    console.log("Problem with request: timeout reached. failed all retries.");
                }
            });
            req.on("error", function (e) {
                console.log("Problem with request: %s", e.message);
            });
            req.write(JSON.stringify(parsedEvents));
            req.end();
        };
        sendRequest();
    } catch (ex) {
        console.log(ex.message);
    }
}

/**
 * @description Extract serverity from log record
 * @param {string} message - Log message
 * @returns {int} Severity level
 */
function getSeverityLevel(message) {
    let severity = 3;
    if (message.includes("debug"))
        severity = 1;
    if (message.includes("verbose"))
        severity = 2;
    if (message.includes("info"))
        severity = 3;
    if (message.includes("warn") || message.includes("warning"))
        severity = 4;
    if (message.includes("error"))
        severity = 5;
    if (message.includes("critical") || message.includes("panic"))
        severity = 6;
    return severity;
}

/**
 * @description Lambda function handler
 * @param {object} event - Event data
 * @param {object} context - Function context
 * @param {object} callback - Function callback
 */
function handler(event, context, callback) {
    postEventsToCoralogix({
        "privateKey": process.env.private_key,
        "applicationName": appName,
        "subsystemName": subName,
        "logEntries": parseEvents(event.Records.map(extractEvent).join("\n"))
    });
};

exports.handler = handler;
