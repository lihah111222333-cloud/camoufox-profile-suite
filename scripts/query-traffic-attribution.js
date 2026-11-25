#!/usr/bin/env node
/**
 * Offline Pre-TLS Traffic Attribution Auditor & Wire-Dump Reconstruction CLI
 *
 * Standalone Node.js ESM CLI and programmatic query engine (`queryProfileTraffic`)
 * with zero external npm dependencies.
 *
 * Supported CLI flags:
 *   --profiles-dir=<path>      Root profiles directory (defaults to ./profiles or CAMOUFOX_STORAGE_DIR)
 *   --profile=<profileId>      Inspect a specific profile (if omitted, lists & summarizes all profiles)
 *   --step=<actionStep>        Filter events/anomalies matching attribution.actionStep
 *   --trigger=<actionOrTarget> Filter events/anomalies triggered by a specific UI action (e.g. page.click or #submit)
 *   --domain=<hostSubstring>   Filter events/anomalies matching host substring
 *   --status=<codeOrClass>     Filter by HTTP status code or class (e.g. 429, 403, 4xx, 5xx, 200)
 *   --anomalies-only           Show only anomalies & risk signals from attribution-index.json / traffic.ndjson
 *   --correlation=<corrId>     Reconstruct complete Pre-TLS Egress + Post-TLS Ingress wire dump & payloads
 *   --dump-wire=<corrId>       Alias for --correlation=<corrId>
 *   --json                     Emit structured JSON output to stdout
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Resolve default profiles directory from environment or repository root.
 *
 * @param {string} [overrideDir]
 * @returns {string}
 */
export function resolveProfilesDir(overrideDir) {
    if (overrideDir) {
        return path.resolve(String(overrideDir));
    }
    if (process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR) {
        return path.resolve(process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR);
    }
    return path.resolve(__dirname, '../profiles');
}

/**
 * Parse CLI arguments (`--key=value`, `--key value`, and boolean flags).
 *
 * @param {string[]} [argv=process.argv.slice(2)]
 * @returns {object}
 */
export function parseCliArgs(argv = process.argv.slice(2)) {
    const opts = {
        profilesDir: null,
        profile: null,
        step: null,
        trigger: null,
        domain: null,
        status: null,
        anomaliesOnly: false,
        correlation: null,
        dumpWire: null,
        json: false,
        help: false
    };

    for (let i = 0; i < argv.length; i += 1) {
        const arg = String(argv[i] || '');
        if (!arg.startsWith('--')) {
            continue;
        }

        const eqIdx = arg.indexOf('=');
        const rawKey = eqIdx >= 0 ? arg.slice(2, eqIdx) : arg.slice(2);
        let value = eqIdx >= 0 ? arg.slice(eqIdx + 1) : null;

        const readNextValue = () => {
            if (value !== null) return value;
            if (i + 1 < argv.length && !String(argv[i + 1]).startsWith('--')) {
                i += 1;
                return String(argv[i]);
            }
            return '';
        };

        switch (rawKey) {
            case 'profiles-dir':
            case 'profilesDir':
                opts.profilesDir = readNextValue();
                break;
            case 'profile':
            case 'profile-id':
            case 'profileId':
                opts.profile = readNextValue();
                break;
            case 'step':
            case 'action-step':
            case 'actionStep':
                opts.step = readNextValue();
                break;
            case 'trigger':
            case 'trigger-action':
            case 'triggerAction':
                opts.trigger = readNextValue();
                break;
            case 'domain':
            case 'host':
                opts.domain = readNextValue();
                break;
            case 'status':
                opts.status = readNextValue();
                break;
            case 'anomalies-only':
            case 'anomaliesOnly':
            case 'anomalies':
                opts.anomaliesOnly = value === null ? true : value !== 'false' && value !== '0';
                break;
            case 'correlation':
            case 'correlation-id':
            case 'correlationId':
                opts.correlation = readNextValue();
                break;
            case 'dump-wire':
            case 'dumpWire':
                opts.dumpWire = readNextValue();
                opts.correlation = opts.correlation || opts.dumpWire;
                break;
            case 'json':
                opts.json = value === null ? true : value !== 'false' && value !== '0';
                break;
            case 'help':
            case 'h':
                opts.help = true;
                break;
            default:
                break;
        }
    }

    return opts;
}

/**
 * Read and parse an NDJSON file safely.
 *
 * @param {string} filePath
 * @returns {Array<object>}
 */
export function readNdjsonEvents(filePath) {
    if (!filePath || !fs.existsSync(filePath)) {
        return [];
    }
    const raw = fs.readFileSync(filePath, 'utf8');
    const lines = raw.split(/\r?\n/);
    const events = [];
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
            events.push(JSON.parse(trimmed));
        } catch {
            // Skip malformed trailing line
        }
    }
    return events;
}

/**
 * Read and parse a JSON file safely.
 *
 * @param {string} filePath
 * @returns {object|null}
 */
function readJsonSafe(filePath) {
    if (!filePath || !fs.existsSync(filePath)) {
        return null;
    }
    try {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
        return null;
    }
}

/**
 * Extract the causal UI trigger action from an event or anomaly record.
 *
 * @param {object} record
 * @returns {object|null}
 */
function extractTriggerAction(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    if (record.triggerAction && typeof record.triggerAction === 'object') {
        return record.triggerAction;
    }
    if (record.attribution?.triggerAction && typeof record.attribution.triggerAction === 'object') {
        return record.attribution.triggerAction;
    }
    return null;
}

/**
 * Extract the action step name from an event or anomaly record.
 *
 * @param {object} record
 * @returns {string|null}
 */
function extractActionStep(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    return record.attribution?.actionStep || record.actionStep || null;
}

/**
 * Extract host / domain from an event or anomaly record.
 *
 * @param {object} record
 * @returns {string}
 */
function extractHost(record) {
    if (!record || typeof record !== 'object') {
        return '';
    }
    if (record.host) return String(record.host);
    if (record.hostname) return String(record.hostname);
    if (record.url) {
        try {
            return new URL(String(record.url)).host || '';
        } catch {
            return String(record.url);
        }
    }
    return '';
}

/**
 * Check if a numeric HTTP status code matches a filter like `429`, `403`, `4xx`, `5xx`, `200`.
 *
 * @param {number|null|undefined} statusValue
 * @param {string|number|null|undefined} statusFilter
 * @returns {boolean}
 */
export function matchesStatusFilter(statusValue, statusFilter) {
    if (statusFilter === null || statusFilter === undefined || statusFilter === '') {
        return true;
    }
    if (statusValue === null || statusValue === undefined) {
        return false;
    }
    const numericStatus = Number(statusValue);
    if (!Number.isFinite(numericStatus)) {
        return false;
    }

    const filterStr = String(statusFilter).trim().toLowerCase();
    const classMatch = filterStr.match(/^([1-5])xx$/);
    if (classMatch) {
        const classDigit = Number(classMatch[1]);
        return numericStatus >= classDigit * 100 && numericStatus < (classDigit + 1) * 100;
    }

    const exactCode = Number(filterStr);
    if (Number.isFinite(exactCode)) {
        return numericStatus === exactCode;
    }

    return String(numericStatus) === filterStr;
}

/**
 * Check if a triggerAction object matches a `--trigger=<actionTypeOrTarget>` filter.
 *
 * @param {object|null} triggerAction
 * @param {string|null|undefined} triggerFilter
 * @returns {boolean}
 */
export function matchesTriggerFilter(triggerAction, triggerFilter) {
    if (!triggerFilter) {
        return true;
    }
    if (!triggerAction || typeof triggerAction !== 'object') {
        return false;
    }

    const needle = String(triggerFilter).trim().toLowerCase();
    const actionType = String(triggerAction.actionType || triggerAction.type || '').toLowerCase();
    const target = String(triggerAction.target || triggerAction.selector || '').toLowerCase();
    const key = String(triggerAction.key || '').toLowerCase();
    const combined = `${actionType}:${target}`;

    return (
        actionType === needle ||
        target === needle ||
        key === needle ||
        combined === needle ||
        actionType.includes(needle) ||
        target.includes(needle) ||
        key.includes(needle) ||
        combined.includes(needle)
    );
}

/**
 * Check if a record matches all active filter criteria (`step`, `trigger`, `domain`, `status`, `correlation`).
 *
 * @param {object} record
 * @param {object} filters
 * @param {Map<string, number>} [txStatusByCorrelation]
 * @param {object} [options]
 * @param {boolean} [options.useTransactionStatusFallback=false]
 * @returns {boolean}
 */
function recordMatchesFilters(
    record,
    filters = {},
    txStatusByCorrelation = null,
    { useTransactionStatusFallback = false } = {}
) {
    if (!record || typeof record !== 'object') {
        return false;
    }

    if (filters.correlation) {
        if (record.correlationId !== filters.correlation) {
            return false;
        }
    }

    if (filters.step) {
        const stepName = extractActionStep(record);
        if (!stepName || stepName !== String(filters.step)) {
            return false;
        }
    }

    if (filters.trigger) {
        const triggerAction = extractTriggerAction(record);
        if (!matchesTriggerFilter(triggerAction, filters.trigger)) {
            return false;
        }
    }

    if (filters.domain) {
        const host = extractHost(record).toLowerCase();
        const url = String(record.url || '').toLowerCase();
        const domainNeedle = String(filters.domain).trim().toLowerCase();
        if (!host.includes(domainNeedle) && !url.includes(domainNeedle)) {
            return false;
        }
    }

    if (filters.status !== null && filters.status !== undefined && filters.status !== '') {
        let statusCandidate = record.status;
        if (
            (statusCandidate === null || statusCandidate === undefined) &&
            useTransactionStatusFallback &&
            record.correlationId &&
            txStatusByCorrelation &&
            txStatusByCorrelation.has(record.correlationId)
        ) {
            statusCandidate = txStatusByCorrelation.get(record.correlationId);
        }
        if (!matchesStatusFilter(statusCandidate, filters.status)) {
            return false;
        }
    }

    return true;
}

/**
 * Locate the profile directory and `traffic/` folder for a given `profileId`.
 *
 * @param {string} profilesDir
 * @param {string} profileId
 * @returns {{ profileId: string, profileDir: string, trafficDir: string }|null}
 */
function resolveProfileTrafficPaths(profilesDir, profileId) {
    const directDir = path.join(profilesDir, String(profileId));
    const sanitizedId = String(profileId).replace(/[^a-zA-Z0-9._-]/g, '_');
    const sanitizedDir = path.join(profilesDir, sanitizedId);

    for (const candidateDir of [directDir, sanitizedDir]) {
        const trafficDir = path.join(candidateDir, 'traffic');
        if (fs.existsSync(trafficDir)) {
            return {
                profileId: path.basename(candidateDir),
                profileDir: candidateDir,
                trafficDir
            };
        }
    }

    // Fallback: check profile.json or attribution-index.json in subdirectories
    if (fs.existsSync(profilesDir)) {
        const entries = fs.readdirSync(profilesDir, { withFileTypes: true });
        for (const entry of entries) {
            if (!entry.isDirectory()) continue;
            const candidateDir = path.join(profilesDir, entry.name);
            const trafficDir = path.join(candidateDir, 'traffic');
            if (!fs.existsSync(trafficDir)) continue;

            const indexObj = readJsonSafe(path.join(trafficDir, 'attribution-index.json'));
            const metaObj = readJsonSafe(path.join(candidateDir, 'profile.json'));
            if (
                indexObj?.session?.profileId === profileId ||
                metaObj?.profileId === profileId ||
                metaObj?.id === profileId
            ) {
                return {
                    profileId: indexObj?.session?.profileId || entry.name,
                    profileDir: candidateDir,
                    trafficDir
                };
            }
        }
    }

    return null;
}

/**
 * List and summarize all profiles under `profilesDir` that contain a `traffic/` directory.
 *
 * @param {string} profilesDir
 * @returns {Array<object>}
 */
export function listTrafficProfiles(profilesDir) {
    const resolvedDir = resolveProfilesDir(profilesDir);
    if (!fs.existsSync(resolvedDir)) {
        return [];
    }

    const entries = fs.readdirSync(resolvedDir, { withFileTypes: true });
    const summaries = [];

    for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const profileDir = path.join(resolvedDir, entry.name);
        const trafficDir = path.join(profileDir, 'traffic');
        if (!fs.existsSync(trafficDir)) continue;

        const attributionIndexPath = path.join(trafficDir, 'attribution-index.json');
        const trafficNdjsonPath = path.join(trafficDir, 'traffic.ndjson');
        const sslKeyLogPath = path.join(trafficDir, 'sslkeylog.txt');
        const preTlsWireLogPath = path.join(trafficDir, 'pre-tls-wire.log');

        const indexData = readJsonSafe(attributionIndexPath);
        const events = !indexData && fs.existsSync(trafficNdjsonPath)
            ? readNdjsonEvents(trafficNdjsonPath)
            : [];

        const profileId = indexData?.session?.profileId || entry.name;
        const totals = indexData?.totals || {
            totalRequests: events.filter((e) => e.type === 'egress').length,
            totalResponses: events.filter((e) => e.type === 'ingress').length,
            failedRequests: events.filter((e) => e.type === 'request-failed').length,
            wsFramesSent: events.filter((e) => e.type === 'ws-egress').length,
            wsFramesReceived: events.filter((e) => e.type === 'ws-ingress').length
        };
        const anomalies = indexData?.anomaliesAndRiskSignals || [];

        summaries.push({
            profileId,
            profileDir,
            trafficDir,
            accountId: indexData?.session?.accountId ?? null,
            accountEmail: indexData?.session?.accountEmail ?? null,
            os: indexData?.session?.os ?? null,
            proxyServer: indexData?.session?.proxyServer ?? null,
            startedAt: indexData?.session?.startedAt ?? null,
            endedAt: indexData?.session?.endedAt ?? null,
            totals,
            anomalyCount: anomalies.length,
            steps: indexData?.byActionStep ? Object.keys(indexData.byActionStep) : [],
            domains: indexData?.byDomain ? Object.keys(indexData.byDomain) : [],
            triggers: indexData?.byTriggerAction ? Object.keys(indexData.byTriggerAction) : [],
            artifacts: {
                trafficNdjsonPath: fs.existsSync(trafficNdjsonPath) ? trafficNdjsonPath : null,
                attributionIndexPath: fs.existsSync(attributionIndexPath) ? attributionIndexPath : null,
                sslKeyLogPath: fs.existsSync(sslKeyLogPath) ? sslKeyLogPath : null,
                preTlsWireLogPath: fs.existsSync(preTlsWireLogPath) ? preTlsWireLogPath : null
            }
        });
    }

    return summaries;
}

/**
 * Read a payload file from `trafficDir` (e.g. `payloads/req-1-abcd1234.json`),
 * returning both UTF-8 text and size info.
 *
 * @param {string} trafficDir
 * @param {string|null} relativePayloadFile
 * @returns {{ exists: boolean, fullPath: string|null, content: string|null, byteLength: number }}
 */
function readPayloadContent(trafficDir, relativePayloadFile) {
    if (!trafficDir || !relativePayloadFile) {
        return { exists: false, fullPath: null, content: null, byteLength: 0 };
    }
    const fullPath = path.isAbsolute(relativePayloadFile)
        ? relativePayloadFile
        : path.join(trafficDir, relativePayloadFile);

    if (!fs.existsSync(fullPath)) {
        return { exists: false, fullPath, content: null, byteLength: 0 };
    }

    const buf = fs.readFileSync(fullPath);
    return {
        exists: true,
        fullPath,
        content: buf.toString('utf8'),
        byteLength: buf.byteLength
    };
}

/**
 * Reconstruct the complete redirect chain (both upstream predecessors and downstream hops)
 * for a given `correlationId`.
 *
 * @param {string} correlationId
 * @param {Array<object>} events
 * @returns {Array<{ correlationId: string, method: string, url: string, status: number|null, redirectedFromCorrelationId: string|null }>}
 */
function buildRedirectChain(correlationId, events) {
    const egressByCorr = new Map();
    const ingressByCorr = new Map();
    const childByParentCorr = new Map();

    for (const ev of events) {
        if (!ev || !ev.correlationId) continue;
        if (ev.type === 'egress') {
            egressByCorr.set(ev.correlationId, ev);
            if (ev.redirectedFromCorrelationId) {
                childByParentCorr.set(ev.redirectedFromCorrelationId, ev.correlationId);
            }
        } else if (ev.type === 'ingress') {
            ingressByCorr.set(ev.correlationId, ev);
        }
    }

    if (!egressByCorr.has(correlationId) && !ingressByCorr.has(correlationId)) {
        return [];
    }

    // Walk backward to root hop
    let rootCorr = correlationId;
    const visitedBack = new Set([rootCorr]);
    while (true) {
        const eg = egressByCorr.get(rootCorr);
        const inEv = ingressByCorr.get(rootCorr);
        const parentCorr = eg?.redirectedFromCorrelationId || inEv?.redirectedFromCorrelationId || null;
        if (!parentCorr || visitedBack.has(parentCorr) || (!egressByCorr.has(parentCorr) && !ingressByCorr.has(parentCorr))) {
            break;
        }
        visitedBack.add(parentCorr);
        rootCorr = parentCorr;
    }

    // Walk forward from root hop
    const chain = [];
    let cursor = rootCorr;
    const visitedForward = new Set();
    while (cursor && !visitedForward.has(cursor)) {
        visitedForward.add(cursor);
        const eg = egressByCorr.get(cursor);
        const inEv = ingressByCorr.get(cursor);
        chain.push({
            correlationId: cursor,
            method: eg?.method || inEv?.method || 'GET',
            url: eg?.url || inEv?.url || '',
            status: inEv?.status ?? null,
            redirectedFromCorrelationId:
                eg?.redirectedFromCorrelationId || inEv?.redirectedFromCorrelationId || null
        });
        cursor = childByParentCorr.get(cursor) || null;
    }

    return chain;
}

/**
 * Reconstruct and format a transaction's complete Pre-TLS Egress Request + Post-TLS
 * Decrypted Ingress Response wire dump, including headers, causal `triggerAction`,
 * `actionStep`, redirect chain, timing, and full payload content from `payloads/`.
 *
 * @param {object} params
 * @param {string} params.profileId
 * @param {string} params.trafficDir
 * @param {string} params.correlationId
 * @param {Array<object>} params.events
 * @param {Array<object>} [params.anomalies=[]]
 * @returns {object}
 */
export function reconstructTransactionWireDump({
    profileId,
    trafficDir,
    correlationId,
    events = [],
    anomalies = []
}) {
    const corrEvents = events.filter((e) => e && e.correlationId === correlationId);
    const egress = corrEvents.find((e) => e.type === 'egress') || null;
    const ingress = corrEvents.find((e) => e.type === 'ingress') || null;
    const finished = corrEvents.find((e) => e.type === 'request-finished') || null;
    const failed = corrEvents.find((e) => e.type === 'request-failed') || null;
    const wsEvents = corrEvents.filter((e) => typeof e.type === 'string' && e.type.startsWith('ws-'));

    const matchingAnomalies = anomalies.filter((a) => a && a.correlationId === correlationId);
    const redirectChain = buildRedirectChain(correlationId, events);

    const primaryEvent = egress || ingress || failed || finished || wsEvents[0] || null;
    const attribution = primaryEvent?.attribution || null;
    const actionStep = extractActionStep(primaryEvent) || 'unknown';
    const stepIndex = attribution?.stepIndex ?? primaryEvent?.stepIndex ?? 0;
    const triggerAction =
        extractTriggerAction(egress) ||
        extractTriggerAction(ingress) ||
        extractTriggerAction(failed) ||
        extractTriggerAction(primaryEvent) ||
        null;

    const reqPayloadDisk = readPayloadContent(trafficDir, egress?.payloadFile || null);
    const resPayloadDisk = readPayloadContent(trafficDir, ingress?.payloadFile || null);

    const requestPayload = reqPayloadDisk.exists
        ? reqPayloadDisk.content
        : (egress?.bodyPreview ?? egress?.postData ?? null);
    const responsePayload = resPayloadDisk.exists
        ? resPayloadDisk.content
        : (ingress?.bodyPreview ?? null);

    const durationMs = finished?.durationMs ?? failed?.durationMs ?? null;
    const timing = finished?.timing ?? null;
    const sizes = finished?.sizes ?? null;
    const redirectedFromCorrelationId =
        egress?.redirectedFromCorrelationId || ingress?.redirectedFromCorrelationId || null;

    const lines = [];
    lines.push('================================================================================');
    lines.push(`PRE-TLS / POST-TLS WIRE TRANSACTION DUMP [${correlationId}]`);
    lines.push('================================================================================');
    lines.push(`Profile ID       : ${profileId}`);
    lines.push(`Correlation ID   : ${correlationId}`);
    lines.push(`Action Step      : ${actionStep} (stepIndex=${stepIndex})`);

    if (triggerAction) {
        const trigType = triggerAction.actionType || triggerAction.type || 'unknown';
        const trigTarget = triggerAction.target || triggerAction.selector || '';
        const elapsed = triggerAction.elapsedSinceActionMs !== undefined
            ? `${triggerAction.elapsedSinceActionMs}ms`
            : 'n/a';
        lines.push(`Trigger Action   : ${trigType} target="${trigTarget}" (elapsed=${elapsed})`);
    } else {
        lines.push('Trigger Action   : none');
    }

    if (redirectChain.length > 1) {
        const chainStr = redirectChain
            .map((hop) => `${hop.correlationId}(${hop.method} ${hop.url} -> ${hop.status ?? 'PENDING'})`)
            .join(' => ');
        lines.push(`Redirect Chain   : ${chainStr}`);
    } else if (redirectedFromCorrelationId) {
        lines.push(`Redirected From  : ${redirectedFromCorrelationId}`);
    }

    if (durationMs !== null && durationMs !== undefined) {
        lines.push(`Duration         : ${durationMs} ms`);
    }
    if (timing) {
        lines.push(`Necko Timing     : ${JSON.stringify(timing)}`);
    }
    if (ingress?.serverAddr) {
        lines.push(`Server Address   : ${ingress.serverAddr.ipAddress || ''}:${ingress.serverAddr.port || ''}`);
    }
    if (ingress?.securityDetails) {
        lines.push(
            `TLS Security     : protocol=${ingress.securityDetails.protocol || 'unknown'} subject=${ingress.securityDetails.subjectName || ''}`
        );
    }
    if (matchingAnomalies.length > 0) {
        lines.push(
            `Anomalies (${matchingAnomalies.length})    : ${matchingAnomalies.map((a) => `${a.type}[${a.severity}]`).join(', ')}`
        );
    }

    if (egress) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(
            `>>> EGRESS [PRE-TLS NECKO CHANNEL] [${correlationId}] ${egress.timestamp || ''}`
        );
        const searchStr =
            egress.searchParams && Object.keys(egress.searchParams).length > 0
                ? `?${new URLSearchParams(egress.searchParams).toString()}`
                : '';
        const targetPath = `${egress.pathname || '/'}${searchStr}`;
        lines.push(`${egress.method || 'GET'} ${targetPath} HTTP/1.1`);
        lines.push(`X-Camoufox-Full-Url: ${egress.url || ''}`);

        const reqHeaders = Array.isArray(egress.headersArray) && egress.headersArray.length > 0
            ? egress.headersArray
            : Object.entries(egress.headers || {}).map(([name, value]) => ({ name, value }));

        for (const h of reqHeaders) {
            lines.push(`${h.name}: ${h.value}`);
        }
        lines.push('');
        if (requestPayload !== null && requestPayload !== undefined && requestPayload !== '') {
            lines.push(String(requestPayload));
        } else {
            lines.push('[no egress body]');
        }
    }

    if (ingress) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(
            `<<< INGRESS [POST-TLS NECKO CHANNEL] [${correlationId}] ${ingress.timestamp || ''}`
        );
        lines.push(`HTTP/1.1 ${ingress.status ?? 0} ${ingress.statusText || ''}`.trim());

        const resHeaders = Array.isArray(ingress.headersArray) && ingress.headersArray.length > 0
            ? ingress.headersArray
            : Object.entries(ingress.headers || {}).map(([name, value]) => ({ name, value }));

        for (const h of resHeaders) {
            lines.push(`${h.name}: ${h.value}`);
        }
        lines.push('');
        if (responsePayload !== null && responsePayload !== undefined && responsePayload !== '') {
            lines.push(String(responsePayload));
        } else {
            lines.push('[no ingress body]');
        }
    }

    if (failed) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(
            `!!! FAILURE [NECKO CHANNEL ERROR] [${correlationId}] ${failed.failureText || 'UNKNOWN_ERROR'}`
        );
    }

    if (wsEvents.length > 0) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(`=== WEBSOCKET FRAMES [${correlationId}] (${wsEvents.length} events) ===`);
        for (const wsEv of wsEvents) {
            lines.push(
                `[${wsEv.type}] ${wsEv.timestamp || ''} bytes=${wsEv.payloadBytes ?? 0} preview=${wsEv.bodyPreview ?? ''}`
            );
        }
    }

    lines.push('================================================================================');
    const wireDump = lines.join('\n');

    return {
        mode: 'wire-dump',
        profileId,
        trafficDir,
        correlationId,
        found: Boolean(egress || ingress || failed || finished || wsEvents.length > 0),
        actionStep,
        stepIndex,
        triggerAction,
        attribution,
        redirectedFromCorrelationId,
        redirectChain,
        durationMs,
        timing,
        sizes,
        egress,
        ingress,
        finished,
        failed,
        wsEvents,
        requestPayload,
        requestPayloadFile: egress?.payloadFile || null,
        requestPayloadExistsOnDisk: reqPayloadDisk.exists,
        responsePayload,
        responsePayloadFile: ingress?.payloadFile || null,
        responsePayloadExistsOnDisk: resPayloadDisk.exists,
        anomalies: matchingAnomalies,
        wireDump
    };
}

/**
 * Group matching NDJSON events into correlated transaction summaries.
 *
 * @param {Array<object>} events
 * @returns {Array<object>}
 */
function buildTransactionsList(events) {
    const txMap = new Map();

    for (const ev of events) {
        if (!ev || !ev.correlationId) continue;
        if (!txMap.has(ev.correlationId)) {
            txMap.set(ev.correlationId, {
                correlationId: ev.correlationId,
                method: ev.method || null,
                url: ev.url || null,
                host: extractHost(ev) || null,
                status: null,
                actionStep: extractActionStep(ev),
                triggerAction: extractTriggerAction(ev),
                redirectedFromCorrelationId: ev.redirectedFromCorrelationId || null,
                durationMs: null,
                failureText: null,
                requestPayloadFile: null,
                responsePayloadFile: null,
                egress: null,
                ingress: null,
                finished: null,
                failed: null
            });
        }
        const tx = txMap.get(ev.correlationId);
        if (!tx.method && ev.method) tx.method = ev.method;
        if (!tx.url && ev.url) tx.url = ev.url;
        if (!tx.host) tx.host = extractHost(ev) || null;
        if (!tx.actionStep) tx.actionStep = extractActionStep(ev);
        if (!tx.triggerAction) tx.triggerAction = extractTriggerAction(ev);

        if (ev.type === 'egress') {
            tx.egress = ev;
            tx.requestPayloadFile = ev.payloadFile || null;
            if (ev.redirectedFromCorrelationId) {
                tx.redirectedFromCorrelationId = ev.redirectedFromCorrelationId;
            }
        } else if (ev.type === 'ingress') {
            tx.ingress = ev;
            tx.status = ev.status ?? tx.status;
            tx.responsePayloadFile = ev.payloadFile || null;
        } else if (ev.type === 'request-finished') {
            tx.finished = ev;
            if (ev.status !== null && ev.status !== undefined) {
                tx.status = ev.status;
            }
            tx.durationMs = ev.durationMs ?? tx.durationMs;
        } else if (ev.type === 'request-failed') {
            tx.failed = ev;
            tx.failureText = ev.failureText || null;
            tx.durationMs = ev.durationMs ?? tx.durationMs;
        }
    }

    return Array.from(txMap.values());
}

/**
 * Query, filter, and reconstruct pre-TLS / post-TLS traffic attribution for one or all profiles.
 *
 * @param {object} [options={}]
 * @param {string} [options.profilesDir]
 * @param {string} [options.profile]
 * @param {string} [options.profileId]
 * @param {string} [options.trafficDir]
 * @param {string} [options.step]
 * @param {string} [options.actionStep]
 * @param {string} [options.trigger]
 * @param {string} [options.triggerAction]
 * @param {string} [options.domain]
 * @param {string} [options.host]
 * @param {string|number} [options.status]
 * @param {boolean} [options.anomaliesOnly=false]
 * @param {string} [options.correlation]
 * @param {string} [options.correlationId]
 * @param {string} [options.dumpWire]
 * @returns {object}
 */
export function queryProfileTraffic(options = {}) {
    const profilesDir = resolveProfilesDir(options.profilesDir);
    let targetProfileId = options.profile || options.profileId || null;
    const correlationId =
        options.dumpWire || options.correlation || options.correlationId || null;

    const filters = {
        step: options.step || options.actionStep || null,
        trigger: options.trigger || options.triggerAction || null,
        domain: options.domain || options.host || null,
        status: options.status ?? null,
        anomaliesOnly: Boolean(options.anomaliesOnly),
        correlation: correlationId
    };

    // If no profile is specified and no direct trafficDir or correlationId is given,
    // list and summarize all profiles in profilesDir that have a traffic/ directory.
    if (!targetProfileId && !options.trafficDir && !correlationId) {
        const profiles = listTrafficProfiles(profilesDir);
        return {
            mode: 'list-profiles',
            profilesDir,
            count: profiles.length,
            profiles
        };
    }

    let resolvedPaths = null;
    if (options.trafficDir) {
        const trafficDir = path.resolve(options.trafficDir);
        const profileDir = path.dirname(trafficDir);
        resolvedPaths = {
            profileId: targetProfileId || path.basename(profileDir),
            profileDir,
            trafficDir
        };
    } else if (targetProfileId) {
        resolvedPaths = resolveProfileTrafficPaths(profilesDir, targetProfileId);
    } else if (correlationId) {
        // Auto-discover which profile contains the requested correlationId
        const candidates = listTrafficProfiles(profilesDir);
        for (const cand of candidates) {
            const evs = readNdjsonEvents(path.join(cand.trafficDir, 'traffic.ndjson'));
            if (evs.some((e) => e && e.correlationId === correlationId)) {
                resolvedPaths = {
                    profileId: cand.profileId,
                    profileDir: cand.profileDir,
                    trafficDir: cand.trafficDir
                };
                break;
            }
        }
    }

    if (!resolvedPaths || !fs.existsSync(resolvedPaths.trafficDir)) {
        throw new Error(
            `Traffic directory not found for profile "${targetProfileId || correlationId || 'unknown'}" in ${profilesDir}`
        );
    }

    const { profileId, profileDir, trafficDir } = resolvedPaths;
    const trafficNdjsonPath = path.join(trafficDir, 'traffic.ndjson');
    const attributionIndexPath = path.join(trafficDir, 'attribution-index.json');
    const sslKeyLogPath = path.join(trafficDir, 'sslkeylog.txt');
    const preTlsWireLogPath = path.join(trafficDir, 'pre-tls-wire.log');

    const allEvents = readNdjsonEvents(trafficNdjsonPath);
    const indexData = readJsonSafe(attributionIndexPath);

    // Map correlationId -> HTTP status from ingress / request-finished events
    const txStatusByCorrelation = new Map();
    const txTriggerByCorrelation = new Map();
    for (const ev of allEvents) {
        if (!ev || !ev.correlationId) continue;
        if (typeof ev.status === 'number') {
            txStatusByCorrelation.set(ev.correlationId, ev.status);
        }
        const trig = extractTriggerAction(ev);
        if (trig && !txTriggerByCorrelation.has(ev.correlationId)) {
            txTriggerByCorrelation.set(ev.correlationId, trig);
        }
    }

    // Collect anomalies from attribution-index.json (or synthesize from NDJSON if index missing)
    const rawAnomalies = Array.isArray(indexData?.anomaliesAndRiskSignals)
        ? indexData.anomaliesAndRiskSignals.map((a) => ({
              ...a,
              triggerAction:
                  a.triggerAction ||
                  (a.correlationId ? txTriggerByCorrelation.get(a.correlationId) || null : null)
          }))
        : allEvents
              .filter(
                  (e) =>
                      e.type === 'request-failed' ||
                      e.type === 'ws-error' ||
                      (e.type === 'ingress' &&
                          (e.status === 401 || e.status === 403 || e.status === 429 || e.status >= 500))
              )
              .map((e) => ({
                  timestamp: e.timestamp,
                  correlationId: e.correlationId || null,
                  actionStep: extractActionStep(e),
                  triggerAction: extractTriggerAction(e),
                  type:
                      e.type === 'request-failed'
                          ? 'network-request-failed'
                          : e.type === 'ws-error'
                            ? 'websocket-error'
                            : `http-${e.status}`,
                  severity: 'high',
                  method: e.method || null,
                  url: e.url || null,
                  status: e.status ?? null,
                  failureText: e.failureText ?? null,
                  payloadFile: e.payloadFile ?? null
              }));

    // Mode 1: Wire dump / correlationId reconstruction
    if (correlationId) {
        return reconstructTransactionWireDump({
            profileId,
            trafficDir,
            correlationId,
            events: allEvents,
            anomalies: rawAnomalies
        });
    }

    // Filter anomalies and NDJSON events
    const filteredAnomalies = rawAnomalies.filter((anomaly) =>
        recordMatchesFilters(anomaly, filters, txStatusByCorrelation, {
            useTransactionStatusFallback: true
        })
    );

    const filteredEvents = allEvents.filter((event) =>
        recordMatchesFilters(event, filters, txStatusByCorrelation, {
            useTransactionStatusFallback: false
        })
    );

    // Build transactions matching filters (using transaction status fallback so egress+ingress stay paired)
    const eventsForTransactions = allEvents.filter((event) =>
        recordMatchesFilters(event, filters, txStatusByCorrelation, {
            useTransactionStatusFallback: true
        })
    );
    const transactions = buildTransactionsList(eventsForTransactions);

    if (filters.anomaliesOnly) {
        return {
            mode: 'anomalies',
            profileId,
            profileDir,
            trafficDir,
            filters,
            session: indexData?.session || { profileId },
            totals: indexData?.totals || null,
            count: filteredAnomalies.length,
            anomalies: filteredAnomalies,
            anomaliesAndRiskSignals: filteredAnomalies
        };
    }

    return {
        mode: 'profile-query',
        profileId,
        profileDir,
        trafficDir,
        filters,
        session: indexData?.session || { profileId },
        artifacts: {
            trafficNdjsonPath: fs.existsSync(trafficNdjsonPath) ? trafficNdjsonPath : null,
            attributionIndexPath: fs.existsSync(attributionIndexPath) ? attributionIndexPath : null,
            sslKeyLogPath: fs.existsSync(sslKeyLogPath) ? sslKeyLogPath : null,
            preTlsWireLogPath: fs.existsSync(preTlsWireLogPath) ? preTlsWireLogPath : null
        },
        totals: indexData?.totals || {
            totalRequests: allEvents.filter((e) => e.type === 'egress').length,
            totalResponses: allEvents.filter((e) => e.type === 'ingress').length,
            failedRequests: allEvents.filter((e) => e.type === 'request-failed').length
        },
        byActionStep: indexData?.byActionStep || {},
        byTriggerAction: indexData?.byTriggerAction || {},
        byDomain: indexData?.byDomain || {},
        anomalies: filteredAnomalies,
        anomaliesAndRiskSignals: filteredAnomalies,
        eventsCount: filteredEvents.length,
        events: filteredEvents,
        transactionsCount: transactions.length,
        transactions
    };
}

/**
 * Format human-readable CLI report for stdout when `--json` is not specified.
 *
 * @param {object} result
 * @returns {string}
 */
export function formatCliReport(result) {
    if (!result) return '';

    if (result.mode === 'wire-dump') {
        return result.wireDump;
    }

    const lines = [];

    if (result.mode === 'list-profiles') {
        lines.push(`📂 Profiles Directory: ${result.profilesDir}`);
        lines.push(`Found ${result.count} profile(s) with recorded pre-TLS traffic:`);
        for (const p of result.profiles) {
            lines.push(
                `  - ${p.profileId} | OS=${p.os || 'n/a'} | req=${p.totals?.totalRequests ?? 0} res=${p.totals?.totalResponses ?? 0} fail=${p.totals?.failedRequests ?? 0} anomalies=${p.anomalyCount}`
            );
        }
        return lines.join('\n');
    }

    if (result.mode === 'anomalies') {
        lines.push(`🚨 Anomalies & Risk Signals for Profile: ${result.profileId} (${result.count})`);
        for (const a of result.anomalies) {
            const trig = a.triggerAction
                ? ` trigger=${a.triggerAction.actionType}:${a.triggerAction.target || ''}`
                : '';
            lines.push(
                `  - [${a.severity || 'medium'}] ${a.type} | corr=${a.correlationId || 'n/a'} | step=${a.actionStep || 'n/a'}${trig} | status=${a.status ?? 'ERR'} | url=${a.url || ''} | payload=${a.payloadFile || 'none'}`
            );
        }
        return lines.join('\n');
    }

    lines.push(`📊 Pre-TLS Traffic Attribution Report — Profile: ${result.profileId}`);
    lines.push(
        `   Requests: ${result.totals?.totalRequests ?? 0} | Responses: ${result.totals?.totalResponses ?? 0} | Failed: ${result.totals?.failedRequests ?? 0}`
    );
    lines.push(
        `   Matching Events: ${result.eventsCount} | Transactions: ${result.transactionsCount} | Anomalies: ${result.anomalies.length}`
    );

    if (result.anomalies.length > 0) {
        lines.push('   Anomalies:');
        for (const a of result.anomalies) {
            lines.push(
                `     * [${a.severity}] ${a.type} (corr=${a.correlationId}, step=${a.actionStep}, status=${a.status ?? a.failureText ?? 'n/a'})`
            );
        }
    }

    if (result.transactions.length > 0) {
        lines.push('   Transactions:');
        for (const tx of result.transactions) {
            const trig = tx.triggerAction
                ? ` [trigger=${tx.triggerAction.actionType}:${tx.triggerAction.target || ''}]`
                : '';
            lines.push(
                `     - ${tx.correlationId}: ${tx.method || 'GET'} ${tx.url || ''} -> ${tx.status ?? tx.failureText ?? 'PENDING'} (step=${tx.actionStep || 'n/a'})${trig}`
            );
        }
    }

    return lines.join('\n');
}

/**
 * CLI entry point.
 *
 * @param {string[]} [argv]
 */
export function runCli(argv = process.argv.slice(2)) {
    const args = parseCliArgs(argv);

    if (args.help) {
        console.log(
            [
                'Usage: node scripts/query-traffic-attribution.js [options]',
                '',
                'Options:',
                '  --profiles-dir=<path>       Profiles root directory',
                '  --profile=<profileId>       Inspect a specific profile',
                '  --step=<actionStep>         Filter by attribution.actionStep',
                '  --trigger=<actionOrTarget>  Filter by causal UI triggerAction (e.g. page.click or #submit)',
                '  --domain=<hostSubstring>    Filter by host substring',
                '  --status=<codeOrClass>      Filter by HTTP status code or class (429, 403, 4xx, 5xx, 200)',
                '  --anomalies-only            Show only anomalies & risk signals',
                '  --correlation=<corrId>      Reconstruct Pre-TLS Egress + Post-TLS Ingress wire dump',
                '  --dump-wire=<corrId>        Alias for --correlation=<corrId>',
                '  --json                      Output structured JSON'
            ].join('\n')
        );
        return 0;
    }

    const result = queryProfileTraffic({
        profilesDir: args.profilesDir,
        profile: args.profile,
        step: args.step,
        trigger: args.trigger,
        domain: args.domain,
        status: args.status,
        anomaliesOnly: args.anomaliesOnly,
        correlation: args.correlation,
        dumpWire: args.dumpWire
    });

    if (args.json) {
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
        process.stdout.write(`${formatCliReport(result)}\n`);
    }
    return 0;
}

const isMainModule =
    process.argv[1] &&
    path.resolve(process.argv[1]) === path.resolve(__filename);

if (isMainModule) {
    try {
        runCli(process.argv.slice(2));
    } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
}

export default {
    queryProfileTraffic,
    listTrafficProfiles,
    reconstructTransactionWireDump,
    parseCliArgs,
    formatCliReport,
    runCli
};
