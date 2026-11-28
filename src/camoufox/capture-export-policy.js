import { readCaptureFile } from './capture-io.js';
import { validateProfileId } from './profile-storage.js';
import { allowsTrafficBody, redirectDropsUpload } from './traffic-body.js';
import { redactProfileId } from './traffic-redaction.js';

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

    return { indexData, bodyPolicy: captureBodyPolicy(indexData?.session, { recordBodies, reason }) };
}

export function captureBodyPolicy(session, { recordBodies, reason = null } = {}) {
    const traceId = session?.traceId ?? null;
    const recordingNamespace = session?.recordingNamespace;
    if (!reason) {
        if (recordBodies === false) reason = 'export-disabled';
        else if (session?.recordBodies === false) reason = 'capture-disabled';
        else if (session?.recordBodies !== true) reason = 'missing-session-policy';
        else if (traceId !== null && (typeof traceId !== 'string' || !traceId.trim())) {
            reason = 'invalid-session-policy';
        } else if (recordingNamespace !== undefined && (
            traceId === null || typeof recordingNamespace !== 'string' ||
            !RECORDING_NAMESPACE_REGEX.test('corr-' + recordingNamespace + '-1')
        )) {
            reason = 'invalid-session-policy';
        }
    }
    return { recordBodies: reason === null, traceId, recordingNamespace, reason };
}

export function captureEventTraceId(event) {
    return event?.attribution?.traceId ?? event?.traceId ?? null;
}

export function captureEventProfileId(event) {
    return event?.attribution?.profileId ?? event?.profileId ?? null;
}

export function validRecordedProfileId(value) {
    try {
        return validateProfileId(value);
    } catch {
        return null;
    }
}

export function sameRecordedProfile(first, second) {
    return first != null && second != null && (
        first === second || first === redactProfileId(second) || redactProfileId(first) === second
    );
}

export function observedProfileIdentity(profileIds) {
    let profileId = null;
    for (const value of profileIds) {
        const id = validRecordedProfileId(value);
        if (!id) continue;
        if (profileId !== null && !sameRecordedProfile(profileId, id)) return { profileIdentity: 'mixed' };
        // Retain a raw legacy ID if both it and its anonymous label appear.
        if (!profileId || id !== redactProfileId(id)) profileId = id;
    }
    return { profileId };
}

const RECORDING_NAMESPACE_REGEX =
    /^(?:corr|ws|sec|act)-([a-z0-9]{1,8})-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})-\d+$/i;

/** Detect multiple recording boundaries without assigning another persistent identity. */
export function createCaptureProfileContinuityCheck() {
    let namespace = null;
    let opaqueCorrelation = null;
    let unproven = false;
    return (event) => {
        const continuity = event?.attribution?.profileContinuityUnproven;
        if (unproven || continuity === true) {
            unproven = true;
            return true;
        }
        const traceId = captureEventTraceId(event);
        const id = event?.type === 'trigger-action' ? event.actionId : event?.correlationId;
        const match = typeof id === 'string' && RECORDING_NAMESPACE_REGEX.exec(id);
        if (match && typeof traceId === 'string') {
            const tracePrefix = traceId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8) || 'trace000';
            if (match[1] === tracePrefix) {
                namespace ??= match[2];
                unproven = namespace !== match[2];
                return unproven;
            }
        }
        // Older custom correlation IDs do not show whether different transactions
        // were recorded together. A single transaction still supports lookup.
        const correlation = event?.correlationId;
        if (continuity !== false && (typeof correlation === 'string' && correlation || Number.isSafeInteger(correlation))) {
            opaqueCorrelation ??= correlation;
            unproven = opaqueCorrelation !== correlation;
        }
        return unproven;
    };
}

export function capturePolicyAllowsBody(bodyPolicy, event) {
    if (!event || !bodyPolicy.recordBodies || captureEventTraceId(event) !== bodyPolicy.traceId) return false;
    const { recordingNamespace } = bodyPolicy;
    if (recordingNamespace === undefined) return true;
    const match = typeof event.correlationId === 'string' && RECORDING_NAMESPACE_REGEX.exec(event.correlationId);
    return Boolean(match && match[1] + '-' + match[2] === recordingNamespace);
}

/** Index observed redirects before exporting any of their body attachments. */
export function createCaptureRedirectBodyCheck(events = []) {
    const transactions = new Map();
    const ancestry = new Map();
    const keyFor = (traceId, correlationId) => JSON.stringify([traceId, correlationId]);
    const observe = (event) => {
        if (!event?.correlationId || (event.type !== 'egress' && event.type !== 'ingress')) return;
        const key = keyFor(captureEventTraceId(event), event.correlationId);
        const profileId = captureEventProfileId(event);
        const entry = transactions.get(key) ?? { profileId };
        transactions.set(key, entry);
        entry.ambiguous ||= entry.profileId !== profileId;

        const parent = event.redirectedFromCorrelationId;
        if (parent != null) {
            entry.ambiguous ||= entry.parent != null && entry.parent !== parent;
            entry.parent = parent;
        }
        if (event.type === 'egress') {
            entry.ambiguous ||= entry.request !== undefined;
            entry.request = { method: event.method, urlAllowed: allowsTrafficBody(event.url) };
        }
    };
    for (const event of events) observe(event);

    const allowsBody = (event) => {
        const traceId = captureEventTraceId(event);
        const profileId = captureEventProfileId(event);
        const key = keyFor(traceId, event.correlationId);
        const entry = transactions.get(key);
        if (entry?.ambiguous) return false;

        let parent = entry?.parent ?? event.redirectedFromCorrelationId;
        if (parent == null) return true;
        const method = entry?.request?.method ?? event.method;
        if (typeof method !== 'string' || !method) return false;
        const checked = new Set();
        let allowed = true;
        while (parent != null) {
            const sourceKey = keyFor(traceId, parent);
            const source = transactions.get(sourceKey);
            const sourceMethod = source?.request?.method;
            if (sourceKey === key || checked.has(sourceKey) || source?.ambiguous || source?.profileId !== profileId ||
                typeof sourceMethod !== 'string' || !sourceMethod) {
                allowed = false;
                break;
            }
            if (method !== sourceMethod) {
                allowed = redirectDropsUpload(method, sourceMethod);
                break;
            }
            const previous = ancestry.get(sourceKey);
            if (previous !== undefined) {
                allowed = previous;
                break;
            }
            checked.add(sourceKey);
            if (!source.request.urlAllowed) {
                allowed = false;
                break;
            }
            parent = source.parent;
        }
        for (const sourceKey of checked) ancestry.set(sourceKey, allowed);
        return allowed;
    };

    return { observe, allowsBody };
}
