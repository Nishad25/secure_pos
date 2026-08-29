const axios = require('axios');

// Real application-layer signal for the compliance dashboard (Gap #16).
// Fire-and-forget: never let a telemetry POST slow down or fail a real request.
const COMPLIANCE_API = process.env.COMPLIANCE_API_URL || 'http://localhost:9000';

const WINDOW_MS = 60 * 1000;
const FAILED_PAYMENT_THRESHOLD = 5;
const SERVER_ERROR_THRESHOLD = 10;

const failedPaymentTimestamps = [];
const serverErrorTimestamps = [];

function pruneOld(timestamps, now)
{
    while (timestamps.length && now - timestamps[0] > WINDOW_MS)
    {
        timestamps.shift();
    }
}

function sendAlert(message, severity, source = 'payment-gateway')
{
    axios.post(`${COMPLIANCE_API}/api/alert`, { message, severity, source })
        .catch(() => {}); // dashboard may not be running — never crash the gateway over it
}

async function securityTelemetry(ctx, next)
{
    await next();

    const now = Date.now();
    const status = ctx.response.status;
    const isPaymentRoute = ctx.request.path.startsWith('/api/v1/payment');

    if (isPaymentRoute && ctx.request.method === 'POST' && status >= 400 && status < 500)
    {
        failedPaymentTimestamps.push(now);
        pruneOld(failedPaymentTimestamps, now);

        if (failedPaymentTimestamps.length >= FAILED_PAYMENT_THRESHOLD)
        {
            sendAlert(
                `${failedPaymentTimestamps.length} rejected payment attempts in the last minute`,
                'warning',
            );
            failedPaymentTimestamps.length = 0;
        }
    }

    if (status >= 500)
    {
        serverErrorTimestamps.push(now);
        pruneOld(serverErrorTimestamps, now);

        if (serverErrorTimestamps.length >= SERVER_ERROR_THRESHOLD)
        {
            sendAlert(
                `${serverErrorTimestamps.length} server errors (5xx) in the last minute`,
                'critical',
            );
            serverErrorTimestamps.length = 0;
        }
    }
}

module.exports = securityTelemetry;
