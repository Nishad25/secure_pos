const axios = require("axios");

// Real application-layer signal for the compliance dashboard (Gap #16).
// Fire-and-forget: never let a telemetry POST slow down or fail a real request.
const COMPLIANCE_API = process.env.COMPLIANCE_API_URL || "http://localhost:9000";

const WINDOW_MS = 60 * 1000;
const FAILED_LOGIN_THRESHOLD = 5;
const SERVER_ERROR_THRESHOLD = 10;

const failedLoginsByIp = new Map(); // ip -> [timestamps]
const serverErrorTimestamps = [];

function pruneOld(timestamps, now) {
    while (timestamps.length && now - timestamps[0] > WINDOW_MS) {
        timestamps.shift();
    }
}

function sendAlert(message, severity, source = "pos-backend") {
    axios.post(`${COMPLIANCE_API}/api/alert`, { message, severity, source })
        .catch(() => {}); // dashboard may not be running — that's fine, don't crash the app over it
}

function securityTelemetry(req, res, next) {
    res.on("finish", () => {
        const now = Date.now();
        const ip = req.ip || req.socket.remoteAddress || "unknown";

        if (req.path === "/api/user/login" && res.statusCode === 401) {
            const attempts = failedLoginsByIp.get(ip) || [];
            attempts.push(now);
            pruneOld(attempts, now);
            failedLoginsByIp.set(ip, attempts);

            if (attempts.length >= FAILED_LOGIN_THRESHOLD) {
                sendAlert(
                    `${attempts.length} failed login attempts from ${ip} in the last minute`,
                    "warning"
                );
                failedLoginsByIp.set(ip, []); // reset so it doesn't re-alert every request after threshold
            }
        }

        if (res.statusCode >= 500) {
            serverErrorTimestamps.push(now);
            pruneOld(serverErrorTimestamps, now);

            if (serverErrorTimestamps.length >= SERVER_ERROR_THRESHOLD) {
                sendAlert(
                    `${serverErrorTimestamps.length} server errors (5xx) in the last minute`,
                    "critical"
                );
                serverErrorTimestamps.length = 0;
            }
        }
    });

    next();
}

module.exports = securityTelemetry;
