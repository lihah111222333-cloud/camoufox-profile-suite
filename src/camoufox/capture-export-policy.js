import { readCaptureFile } from './capture-io.js';

const MAX_EXPORT_INDEX_BYTES = 32 * 1024 * 1024;

/** Read optional report metadata without treating an unreadable index as permission to share bodies. */
export function readCaptureExportIndex(trafficDir, { trustedLocal = false, recordBodies } = {}) {
    let indexData = null;
    let reason = null;
    try {
        const bytes = readCaptureFile(trafficDir, 'attribution-index.json', {
            optional: true, trustedLocal, maxBytes: MAX_EXPORT_INDEX_BYTES
        });
        if (bytes === null) {
            reason = 'missing-index';
        } else {
            try {
                const data = JSON.parse(bytes.toString('utf8'));
                if (data && typeof data === 'object' && !Array.isArray(data)) {
                    indexData = data;
                } else {
                    reason = 'invalid-index';
                }
            } catch {
                reason = 'invalid-index';
            }
        }
    } catch {
        reason = 'unreadable-index';
    }

    const session = indexData?.session;
    const traceId = session?.traceId ?? null;
    if (!reason) {
        if (recordBodies === false) reason = 'export-disabled';
        else if (session?.recordBodies === false) reason = 'capture-disabled';
        else if (session?.recordBodies !== true) reason = 'missing-session-policy';
        else if (traceId !== null && (typeof traceId !== 'string' || !traceId.trim())) {
            reason = 'invalid-session-policy';
        }
    }
    return { indexData, bodyPolicy: { recordBodies: reason === null, traceId, reason } };
}

export function captureEventTraceId(event) {
    return event?.attribution?.traceId ?? event?.traceId ?? null;
}

export function capturePolicyAllowsBody(bodyPolicy, event) {
    return Boolean(event && bodyPolicy.recordBodies && captureEventTraceId(event) === bodyPolicy.traceId);
}
