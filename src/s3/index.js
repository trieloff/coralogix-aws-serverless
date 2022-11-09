/**
 * AWS S3 Lambda function for Coralogix
 *
 * @file        This file is lambda function source code
 * @author      Coralogix Ltd. <info@coralogix.com>
 * @link        https://coralogix.com/
 * @copyright   Coralogix Ltd.
 * @licence     Apache-2.0
 * @version     1.0.18
 * @since       1.0.0
 */

"use strict";

// Import required libraries
const aws = require("aws-sdk");
const zlib = require("zlib");
const assert = require("assert");
const coralogix = require("coralogix-logger");
const s3 = new aws.S3();


const exampleinput = {
    "ZoneID": 549103045,
    "ClientMTLSAuthStatus": "unknown",
    "OriginResponseTime": 0,
    "OriginTLSHandshakeDurationMs": 0,
    "ZoneName": "hlx.page",
    "OriginResponseHTTPExpires": "",
    "RayID": "722716067dff9112",
    "SecurityLevel": "med",
    "EdgeResponseCompressionRatio": 3.61,
    "RequestHeaders": {
        "accept": "*\/*",
        "accept-encoding": "gzip, deflate",
        "connection": "keep-alive"
    },
    "ClientRequestScheme": "https",
    "OriginRequestHeaderSendDurationMs": 0,
    "EdgeColoID": 472,
    "ClientRequestProtocol": "HTTP\/1.1",
    "UpperTierColoID": 0,
    "ClientSrcPort": 63378,
    "EdgeResponseStatus": 200,
    "OriginResponseHTTPLastModified": "",
    "OriginResponseBytes": 0,
    "ClientSSLProtocol": "TLSv1.3",
    "EdgePathingOp": "wl",
    "ResponseHeaders": {
        "last-modified": "Wed, 25 May 2022 12:38:15 GMT",
        "vary": "Accept-Encoding"
    },
    "ClientIP": "130.248.57.10",
    "CacheTieredFill": false,
    "ClientTCPRTTMs": 12,
    "ClientMTLSAuthCertFingerprint": "",
    "ClientSSLCipher": "AEAD-AES256-GCM-SHA384",
    "ParentRayID": "00",
    "OriginTCPHandshakeDurationMs": 0,
    "EdgeRequestHost": "cloufflare--helix-website--adobe.hlx.page",
    "ClientRequestUserAgent": "HTTPie\/3.2.1",
    "EdgePathingSrc": "macro",
    "OriginResponseHeaderReceiveDurationMs": 0,
    "EdgeCFConnectingO2O": false,
    "EdgeRateLimitID": 0,
    "ClientDeviceType": "desktop",
    "ClientIPClass": "noRecord",
    "WorkerSubrequestCount": 0,
    "OriginSSLProtocol": "unknown",
    "EdgeResponseBodyBytes": 863,
    "EdgeRateLimitAction": "",
    "EdgeResponseBytes": 1893,
    "ClientRequestURI": "\/",
    "WorkerSubrequest": false,
    "EdgeStartTimestamp": "2022-06-28T14:24:26Z",
    "EdgeTimeToFirstByteMs": 506,
    "ClientRequestHost": "cloufflare--helix-website--adobe.hlx.page",
    "ClientRequestPath": "\/",
    "WorkerStatus": "ok",
    "OriginResponseStatus": 0,
    "CacheCacheStatus": "unknown",
    "OriginIP": "",
    "ClientASN": 44786,
    "ClientCountry": "de",
    "ClientRequestReferer": "",
    "OriginResponseDurationMs": 0,
    "ClientRequestBytes": 3114,
    "EdgeResponseContentType": "text\/html",
    "WorkerCPUTime": 105335,
    "SmartRouteColoID": 0,
    "EdgeColoCode": "FRA",
    "EdgeServerIP": "",
    "OriginDNSResponseTimeMs": 0,
    "EdgePathingStatus": "nr",
    "CacheResponseBytes": 3734,
    "ClientXRequestedWith": "",
    "ClientRequestMethod": "GET",
    "ClientRequestSource": "eyeball",
    "CacheResponseStatus": 200,
    "EdgeEndTimestamp": "2022-06-28T14:24:27Z"
};
console.log(cloudflare2fastly(exampleinput));

// Check Lambda function parameters
assert(process.env.private_key, "No private key!");
const newlinePattern = process.env.newline_pattern ? RegExp(process.env.newline_pattern) : /(?:\r\n|\r|\n)/g;
const blockingPattern = process.env.blocking_pattern ? RegExp(process.env.blocking_pattern) : null;
const sampling = process.env.sampling ? parseInt(process.env.sampling) : 1;
const debug = JSON.parse(process.env.debug || false);

// Initialize new Coralogix logger
coralogix.CoralogixCentralLogger.configure(new coralogix.LoggerConfig({
    privateKey: process.env.private_key,
    debug: debug
}));
const logger = new coralogix.CoralogixCentralLogger();

/**
 * @description Send logs records to Coralogix
 * @param {Buffer} content - Logs records data
 * @param {string} filename - Logs filename S3 path
 */
function sendLogs(content, filename) {
    const logs = content.toString("utf8").split(newlinePattern);

    for (let i = 0; i < logs.length; i += sampling) {
        if (!logs[i]) continue;
        if (blockingPattern && logs[i].match(blockingPattern)) continue;
        let appName = process.env.app_name || "NO_APPLICATION";
        let subName = process.env.sub_name || "NO_SUBSYSTEM";

        try {
            appName = appName.startsWith("$.") ? dig(appName, JSON.parse(logs[i])) : appName;
            subName = subName.startsWith("$.") ? dig(subName, JSON.parse(logs[i])) : subName;
        } catch { }

        try {
            const cloudflarejson = JSON.parse(logs[i]);
            subName = cloudflarejson.ZoneName;

            const fastlyjson = cloudflare2fastly(cloudflarejson);
            logger.addLog(
                appName,
                subName,
                new coralogix.Log({
                    severity: getSeverityLevelFromStatusCode(cloudflarejson.EdgeResponseStatus),
                    text: JSON.stringify(fastlyjson),
                    threadId: cloudflarejson.RayID,
                })
            );
        } catch {
            logger.addLog(
                appName,
                subName,
                new coralogix.Log({
                    severity: getSeverityLevel(logs[i]),
                    text: logs[i],
                    threadId: filename
                })
            );
        }

    }
}
/**
 * Transforms Cloudflare JSON log messages to Fastly JSON log messages
 * @param {object} cloudflarejson 
 * @returns {object} Fastly JSON log message
 */
function cloudflare2fastly(cloudflarejson) {
    return {
        request: {
            method: cloudflarejson.ClientRequestMethod, // ClientRequestMethod
            host: cloudflarejson.ClientRequestHost, // ClientRequestHost
            url: cloudflarejson.ClientRequestURI, // ClientRequestURI
            protocol: cloudflarejson.ClientRequestProtocol, // ClientRequestProtocol
            size: cloudflarejson.ClientRequestBytes, // ClientRequestBytes
            headers: Object.entries(cloudflarejson.RequestHeaders).reduce((acc, [key, value]) => {
                acc[key.toLowerCase().replace(/-/g, '_')] = value;
                return acc;
            }, {}), // RequestHeaders
        },
        response: {
            status: cloudflarejson.EdgeResponseStatus, // EdgeResponseStatus
            size: cloudflarejson.EdgeResponseBytes, // EdgeResponseBytes
            header_size: cloudflarejson.EdgeResponseBytes - cloudflarejson.EdgeResponseBodyBytes, // EdgeResponseBytes
            body_size: cloudflarejson.EdgeResponseBodyBytes, // EdgeResponseBodyBytes
            headers: Object.entries(cloudflarejson.ResponseHeaders).reduce((acc, [key, value]) => {
                acc[key.toLowerCase().replace(/-/g, '_')] = value;
                return acc;
            }, {}), // RequestHeaders
        },
        client: {
            number: cloudflarejson.ClientASN, // ClientASN
            region_code: cloudflarejson.ClientRegionCode, // ClientRegionCode
            country_name: cloudflarejson.ClientCountry, // ClientCountry
            ip: cloudflarejson.ClientIP, // ClientIP
        },
        cdn: {
            zone_name: cloudflarejson.ZoneName, // ZoneName
            zone_id: cloudflarejson.ZoneID, // ZoneID
            url: new URL(cloudflarejson.ClientRequestURI, cloudflarejson.ClientRequestScheme + "://" + cloudflarejson.ClientRequestHost).href,
            originating_ip: cloudflarejson.RequestHeaders['x-forwarded-for'] ? cloudflarejson.RequestHeaders['x-forwarded-for'].split(',')[0] : cloudflarejson.ClientIP,
            time: {
                start: cloudflarejson.EdgeStartTimestamp, // EdgeStartTimestamp
                start_msec: new Date(cloudflarejson.EdgeStartTimestamp).getTime(),
                end: cloudflarejson.EdgeEndTimestamp, // EdgeEndTimestamp
                end_msec: new Date(cloudflarejson.EdgeEndTimestamp).getTime(),
                elapsed: cloudflarejson.EdgeTimeToFirstByteMs,
                worker_cpu_time_us: cloudflarejson.WorkerCPUTime, // WorkerCPUTime
                worker_wall_time_us: cloudflarejson.WorkerWallTimeUs, // WorkerWallTimeUs
            },
            is_edge: cloudflarejson.ClientRequestSource === 'eyeball',
            request_source: cloudflarejson.ClientRequestSource, // WorkerWallTimeUs
            worker: {
                subrequest: cloudflarejson.WorkerSubrequest, // WorkerSubrequest
                subrequest_count: cloudflarejson.WorkerSubrequestCount, // WorkerSubrequestCount
                status: cloudflarejson.WorkerStatus, // WorkerStatus
            }, 
            colo_code: cloudflarejson.EdgeColoCode, // EdgeColoCode
            colo_id: cloudflarejson.EdgeColoID, // EdgeColoID
            ip: cloudflarejson.EdgeServerIP, // EdgeServerIP
            cache_status: cloudflarejson.CacheCacheStatus, // CacheCacheStatus
            cache_tier_fill: cloudflarejson.CacheTieredFill, // CacheTieredFill
            smart_route_colo_id: cloudflarejson.SmartRouteColoID, // SmartRouteColoID
            upper_tier_colo_id: cloudflarejson.UpperTierColoID, // UpperTierColoID
        }
    };
}

/**
 * @description Extract nested field from object
 * @param {string} path - Path to field
 * @param {*} object - JavaScript object
 * @returns {*} Field value
 */
function dig(path, object) {
    if (path.startsWith("$.")) {
        return path.split(".").slice(1).reduce((xs, x) => (xs && xs[x]) ? xs[x] : path, object);
    }
    return path;
}

/**
 * @description Extract serverity from log record
 * @param {string} message - Log message
 * @returns {number} Severity level
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

function getSeverityLevelFromStatusCode(code) {
    let severity = 3;
    if (code >= 400 && code < 500)
        severity = 4;
    if (code >= 500 && code < 600)
        severity = 5;
    return severity;
}

/**
 * @description Lambda function handler
 * @param {object} event - Event data
 * @param {object} context - Function context
 * @param {function} callback - Function callback
 */
function handler(event, context, callback) {
    const bucket = event.Records[0].s3.bucket.name;
    const key = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, " "));

    s3.getObject({
        Bucket: bucket,
        Key: key
    }, (error, data) => {
        if (error) {
            callback(error);
        } else {
            if (data.ContentType == "application/x-gzip" ||
                data.ContentEncoding == "gzip" ||
                data.ContentEncoding == "compress" ||
                key.endsWith(".gz")
            ) {
                zlib.gunzip(data.Body, (error, result) => {
                    if (error) {
                        callback(error);
                    } else {
                        sendLogs(Buffer.from(result));
                        callback(null, data.ContentType);
                    }
                });
            } else {
                sendLogs(Buffer.from(data.Body), `s3://${bucket}/${key}`);
            }
        }
    });
}

exports.handler = handler;