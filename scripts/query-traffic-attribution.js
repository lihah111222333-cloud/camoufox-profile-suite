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
 *   --cookies                  List all tracked cookies & anti-bot tokens in cookieLineage
 *   --cookie=<name>            Inspect full causal lineage and value history for a specific cookie name
 *   --signatures               List all detected anti-bot platform signatures and their causal actionStep / triggerAction
 *   --platform=<platformName>  Filter signatures & events by platform (bytedance, twitter, meta, google, arkose, cloudflare)
 *   --verify-integrity         Verify cryptographic SHA-256 event hash chain & payload manifest integrity
 *   --json                     Emit structured JSON output to stdout
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    verifyTrafficIntegrity,
    exportTrafficToHar,
    parseSslKeyLog,
    parseNeckoMozLog,
    parseSetCookieHeader,
    parseCookieHeader,
    detectWireHeaderAnomalies,
    extractPlatformSignatures,
    redactUrlSecrets
} from '../src/camoufox/traffic-recorder.js';

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
        cookies: false,
        cookie: null,
        signatures: false,
        platform: null,
        verifyIntegrity: false,
        exportHar: null,
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
            case 'cookies':
                opts.cookies = value === null ? true : value !== 'false' && value !== '0';
                break;
            case 'cookie':
            case 'cookie-name':
            case 'cookieName':
                opts.cookie = readNextValue();
                break;
            case 'signatures':
            case 'platform-signatures':
            case 'platformSignatures':
                opts.signatures = value === null ? true : value !== 'false' && value !== '0';
                break;
            case 'platform':
            case 'platform-name':
            case 'platformName':
                opts.platform = readNextValue();
                break;
            case 'verify-integrity':
            case 'verifyIntegrity':
                opts.verifyIntegrity = value === null ? true : value !== 'false' && value !== '0';
                break;
            case 'export-har':
            case 'exportHar':
                if (value !== null) {
                    opts.exportHar =
                        value === '' || value === 'true'
                            ? true
                            : value === 'false' || value === '0'
                              ? false
                              : value;
                } else if (i + 1 < argv.length && !String(argv[i + 1]).startsWith('--')) {
                    i += 1;
                    opts.exportHar = String(argv[i]);
                } else {
                    opts.exportHar = true;
                }
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
    { useTransactionStatusFallback = false, platformCorrelations = null } = {}
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
        const triggerAction =
            extractTriggerAction(record) ||
            (record.triggerActionId || record.triggerTarget
                ? {
                      actionId: record.triggerActionId || null,
                      target: record.triggerTarget || null
                  }
                : null);
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

    if (filters.platform) {
        const targetPlatform = String(filters.platform).trim().toLowerCase();
        if (typeof record.platform === 'string') {
            if (record.platform.toLowerCase() !== targetPlatform) {
                return false;
            }
        } else {
            const hasDirectPlatformSig =
                Array.isArray(record.platformSignatures) &&
                record.platformSignatures.some(
                    (s) => s && String(s.platform || '').toLowerCase() === targetPlatform
                );
            const hasCorrelatedPlatformSig =
                Boolean(record.correlationId) &&
                platformCorrelations instanceof Set &&
                platformCorrelations.has(record.correlationId);
            if (!hasDirectPlatformSig && !hasCorrelatedPlatformSig) {
                return false;
            }
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
            failedRequests: events.filter(
                (e) => e.type === 'request-failed' || e.type === 'security-block'
            ).length,
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
    const securityBlock = corrEvents.find((e) => e.type === 'security-block') || null;
    const wsEvents = corrEvents.filter((e) => typeof e.type === 'string' && e.type.startsWith('ws-'));

    const matchingAnomalies = anomalies.filter((a) => a && a.correlationId === correlationId);
    const redirectChain = buildRedirectChain(correlationId, events);

    const primaryEvent = egress || ingress || failed || securityBlock || finished || wsEvents[0] || null;
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

    if (securityBlock) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(
            `!!! SECURITY BLOCK [ZINIAO ACTIVE GUARD] [${correlationId}] type=${securityBlock.blockType || 'probe'} reason="${securityBlock.reason || securityBlock.failureText || ''}"`
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
        found: Boolean(egress || ingress || failed || securityBlock || finished || wsEvents.length > 0),
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
        securityBlock,
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
        if (
            ev.type !== 'egress' &&
            ev.type !== 'ingress' &&
            ev.type !== 'request-finished' &&
            ev.type !== 'request-failed' &&
            ev.type !== 'security-block'
        ) {
            continue;
        }
        if (!txMap.has(ev.correlationId)) {
            txMap.set(ev.correlationId, {
                correlationId: ev.correlationId,
                method: ev.method || null,
                url: ev.url || null,
                host: extractHost(ev) || null,
                status: null,
                statusText: null,
                blocked: false,
                blockType: null,
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
                failed: null,
                securityBlock: null
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
            tx.statusText = ev.statusText ?? tx.statusText;
            tx.responsePayloadFile = ev.payloadFile || null;
        } else if (ev.type === 'request-finished') {
            tx.finished = ev;
            if (ev.status !== null && ev.status !== undefined) {
                tx.status = ev.status;
            }
            tx.durationMs = ev.durationMs ?? tx.durationMs;
        } else if (ev.type === 'request-failed') {
            tx.failed = ev;
            tx.failureText = ev.failureText || 'REQUEST_FAILED';
            tx.durationMs = ev.durationMs ?? tx.durationMs;
        } else if (ev.type === 'security-block') {
            tx.securityBlock = ev;
            tx.failed = tx.failed || ev;
            tx.blocked = true;
            tx.blockType = ev.blockType || 'security-probe';
            tx.status = tx.status ?? 0;
            tx.statusText = 'BLOCKED_BY_ZINIAO_SECURITY_GUARD';
            tx.failureText = ev.reason || ev.failureText || 'BLOCKED_BY_ZINIAO_SECURITY_GUARD';
            tx.durationMs = ev.durationMs ?? tx.durationMs ?? 0;
        }
    }

    return Array.from(txMap.values());
}

/**
 * Rebuild cookieLineage map from recorded NDJSON events when attribution-index.json
 * does not already contain a `cookieLineage` block.
 *
 * @param {Array<object>} events
 * @returns {Record<string, object>}
 */
function buildCookieLineageFromEvents(events = []) {
    const lineageMap = new Map();

    for (const ev of events) {
        if (!ev || typeof ev !== 'object') continue;
        const headers = ev.headers || {};
        const headersArray = Array.isArray(ev.headersArray) ? ev.headersArray : [];
        const correlationId = ev.correlationId || null;
        const actionStep = extractActionStep(ev) || 'init';
        const triggerAction = extractTriggerAction(ev);
        const triggerActionId = triggerAction?.actionId || null;
        const timestamp = ev.timestamp || null;
        const host = extractHost(ev) || null;

        if (ev.type === 'ingress') {
            const rawSetCookies = [];
            for (const h of headersArray) {
                if (h && String(h.name || '').toLowerCase() === 'set-cookie' && h.value) {
                    rawSetCookies.push(String(h.value));
                }
            }
            if (rawSetCookies.length === 0) {
                for (const [k, v] of Object.entries(headers)) {
                    if (String(k).toLowerCase() === 'set-cookie' && v) {
                        rawSetCookies.push(String(v));
                    }
                }
            }

            for (const rawBlock of rawSetCookies) {
                for (const line of String(rawBlock).split(/\r?\n/)) {
                    const parsed = parseSetCookieHeader(line);
                    if (!parsed) continue;
                    let entry = lineageMap.get(parsed.name);
                    if (!entry) {
                        entry = {
                            name: parsed.name,
                            isAntiBotToken: Boolean(parsed.isAntiBotToken),
                            domain: parsed.domain ?? host,
                            path: parsed.path ?? '/',
                            secure: Boolean(parsed.secure),
                            httpOnly: Boolean(parsed.httpOnly),
                            sameSite: parsed.sameSite ?? null,
                            firstSetAt: timestamp,
                            firstSetByCorrelationId: correlationId,
                            firstSetAtStep: actionStep,
                            firstSetByTrigger: triggerActionId,
                            firstSetUrl: ev.url || null,
                            lastSetAt: timestamp,
                            lastSetByCorrelationId: correlationId,
                            lastSetAtStep: actionStep,
                            lastValueSha256: null,
                            lastMaskedValue: null,
                            mutationsCount: 0,
                            sentCount: 0,
                            lastSentAt: null,
                            lastSentByCorrelationId: null,
                            lastSentAtStep: null,
                            matchesLatestSetCookie: null,
                            valueHistory: [],
                            sentInCorrelationIds: new Set()
                        };
                        lineageMap.set(parsed.name, entry);
                    } else {
                        if (parsed.domain) entry.domain = parsed.domain;
                        if (parsed.path) entry.path = parsed.path;
                        entry.secure = Boolean(parsed.secure);
                        entry.httpOnly = Boolean(parsed.httpOnly);
                        if (parsed.sameSite) entry.sameSite = parsed.sameSite;
                        if (!entry.firstSetAt) {
                            entry.firstSetAt = timestamp;
                            entry.firstSetByCorrelationId = correlationId;
                            entry.firstSetAtStep = actionStep;
                            entry.firstSetByTrigger = triggerActionId;
                            entry.firstSetUrl = ev.url || null;
                        }
                    }

                    if (entry.lastValueSha256 !== parsed.valueSha256) {
                        entry.mutationsCount += 1;
                    }
                    entry.lastSetAt = timestamp;
                    entry.lastSetByCorrelationId = correlationId;
                    entry.lastSetAtStep = actionStep;
                    entry.lastValueSha256 = parsed.valueSha256;
                    entry.lastMaskedValue = parsed.maskedValue;
                    entry.valueHistory.push({
                        correlationId,
                        actionStep,
                        triggerActionId,
                        timestamp,
                        status: ev.status ?? null,
                        valueSha256: parsed.valueSha256,
                        maskedValue: parsed.maskedValue,
                        isDeleted: Boolean(parsed.isDeleted)
                    });
                }
            }
        } else if (ev.type === 'egress') {
            const rawCookies = [];
            for (const h of headersArray) {
                if (h && String(h.name || '').toLowerCase() === 'cookie' && h.value) {
                    rawCookies.push(String(h.value));
                }
            }
            if (rawCookies.length === 0) {
                for (const [k, v] of Object.entries(headers)) {
                    if (String(k).toLowerCase() === 'cookie' && v) {
                        rawCookies.push(String(v));
                    }
                }
            }

            for (const rawCookieHeader of rawCookies) {
                for (const cookie of parseCookieHeader(rawCookieHeader)) {
                    let entry = lineageMap.get(cookie.name);
                    if (!entry) {
                        entry = {
                            name: cookie.name,
                            isAntiBotToken: Boolean(cookie.isAntiBotToken),
                            domain: host,
                            path: '/',
                            secure: String(ev.url || '').startsWith('https://'),
                            httpOnly: false,
                            sameSite: null,
                            firstSetAt: null,
                            firstSetByCorrelationId: null,
                            firstSetAtStep: null,
                            firstSetByTrigger: null,
                            firstSetUrl: null,
                            lastSetAt: null,
                            lastSetByCorrelationId: null,
                            lastSetAtStep: null,
                            lastValueSha256: null,
                            lastMaskedValue: cookie.maskedValue,
                            mutationsCount: 0,
                            sentCount: 0,
                            lastSentAt: null,
                            lastSentByCorrelationId: null,
                            lastSentAtStep: null,
                            matchesLatestSetCookie: false,
                            valueHistory: [],
                            sentInCorrelationIds: new Set()
                        };
                        lineageMap.set(cookie.name, entry);
                    }
                    if (correlationId) {
                        entry.sentInCorrelationIds.add(correlationId);
                    }
                    entry.sentCount += 1;
                    entry.lastSentAt = timestamp;
                    entry.lastSentByCorrelationId = correlationId;
                    entry.lastSentAtStep = actionStep;
                    entry.matchesLatestSetCookie = Boolean(
                        entry.lastValueSha256 && cookie.valueSha256 === entry.lastValueSha256
                    );
                }
            }
        }
    }

    const out = {};
    for (const [name, entry] of lineageMap.entries()) {
        out[name] = {
            ...entry,
            sentInCorrelationIds: Array.from(entry.sentInCorrelationIds)
        };
    }
    return out;
}

/**
 * Rebuild or normalize the list of detected anti-bot platform signatures from
 * `attribution-index.json` or recorded NDJSON egress events.
 *
 * @param {Array<object>} events
 * @param {object|null} [indexData=null]
 * @returns {Array<object>}
 */
function buildPlatformSignaturesFromEvents(events = [], indexData = null) {
    const triggerByCorr = new Map();
    for (const ev of events) {
        if (!ev || !ev.correlationId) continue;
        const trig = extractTriggerAction(ev);
        if (trig && !triggerByCorr.has(ev.correlationId)) {
            triggerByCorr.set(ev.correlationId, trig);
        }
    }

    if (
        Array.isArray(indexData?.platformSignatures?.signatures) &&
        indexData.platformSignatures.signatures.length > 0
    ) {
        return indexData.platformSignatures.signatures.map((sig) => {
            const triggerAction =
                sig.triggerAction ||
                (sig.correlationId ? triggerByCorr.get(sig.correlationId) || null : null);
            return {
                ...sig,
                triggerAction:
                    triggerAction ||
                    (sig.triggerActionId || sig.triggerTarget
                        ? {
                              actionId: sig.triggerActionId || null,
                              target: sig.triggerTarget || null
                          }
                        : null)
            };
        });
    }

    const signatures = [];
    for (const ev of events) {
        if (!ev || ev.type !== 'egress') continue;
        const actionStep = extractActionStep(ev) || 'init';
        const stepIndex = ev.attribution?.stepIndex ?? ev.stepIndex ?? 0;
        const triggerAction = extractTriggerAction(ev);
        const host = extractHost(ev) || 'unknown';
        const detected = Array.isArray(ev.platformSignatures)
            ? ev.platformSignatures
            : extractPlatformSignatures({
                  url: ev.url || '',
                  searchParams: ev.searchParams || null,
                  headers: ev.headers || {},
                  bodyPreview: ev.bodyPreview ?? ev.postData ?? null
              });

        for (const sig of detected) {
            if (!sig || typeof sig !== 'object') continue;
            signatures.push({
                timestamp: ev.timestamp || null,
                correlationId: ev.correlationId || null,
                actionStep,
                stepIndex,
                triggerActionId: triggerAction?.actionId || null,
                triggerTarget: triggerAction?.target || null,
                triggerAction: triggerAction || null,
                method: ev.method || 'GET',
                url: ev.url || '',
                host,
                platform: sig.platform,
                signatureName: sig.signatureName,
                location: sig.location,
                valueLength: sig.valueLength,
                valueSha256: sig.valueSha256,
                maskedPreview: sig.maskedPreview
            });
        }
    }

    return signatures;
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
 * @param {boolean} [options.cookies=false]
 * @param {string} [options.cookie]
 * @param {string} [options.cookieName]
 * @returns {object}
 */
export function queryProfileTraffic(options = {}) {
    const profilesDir = resolveProfilesDir(options.profilesDir);
    let targetProfileId = options.profile || options.profileId || null;
    const correlationId =
        options.dumpWire || options.correlation || options.correlationId || null;
    const cookieNameFilter =
        typeof options.cookie === 'string' && options.cookie.trim().length > 0
            ? options.cookie.trim()
            : typeof options.cookieName === 'string' && options.cookieName.trim().length > 0
              ? options.cookieName.trim()
              : null;
    const cookiesRequested = Boolean(options.cookies || cookieNameFilter);
    const signaturesRequested = Boolean(options.signatures);
    const platformFilter =
        typeof options.platform === 'string' && options.platform.trim().length > 0
            ? options.platform.trim().toLowerCase()
            : typeof options.platformName === 'string' && options.platformName.trim().length > 0
              ? options.platformName.trim().toLowerCase()
              : null;

    const filters = {
        step: options.step || options.actionStep || null,
        trigger: options.trigger || options.triggerAction || null,
        domain: options.domain || options.host || null,
        status: options.status ?? null,
        anomaliesOnly: Boolean(options.anomaliesOnly),
        correlation: correlationId,
        cookies: cookiesRequested,
        cookie: cookieNameFilter,
        signatures: signaturesRequested,
        platform: platformFilter
    };

    // If no profile is specified and no direct trafficDir or correlationId is given,
    // list and summarize all profiles in profilesDir that have a traffic/ directory
    // (unless --verify-integrity, --export-har, --cookies/--cookie, or --signatures/--platform is requested).
    if (
        !targetProfileId &&
        !options.trafficDir &&
        !correlationId &&
        !options.verifyIntegrity &&
        !options.exportHar &&
        !cookiesRequested &&
        !signaturesRequested &&
        !platformFilter
    ) {
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
    } else if (options.verifyIntegrity) {
        const candidates = listTrafficProfiles(profilesDir);
        if (candidates.length === 1) {
            resolvedPaths = {
                profileId: candidates[0].profileId,
                profileDir: candidates[0].profileDir,
                trafficDir: candidates[0].trafficDir
            };
        } else if (candidates.length > 1) {
            const perProfile = candidates.map((cand) => {
                const check = verifyTrafficIntegrity(cand.trafficDir);
                return {
                    profileId: cand.profileId,
                    trafficDir: cand.trafficDir,
                    ...check
                };
            });
            const allValid = perProfile.every((p) => p.valid);
            const totalEvents = perProfile.reduce((acc, p) => acc + p.eventCount, 0);
            const totalPayloads = perProfile.reduce((acc, p) => acc + p.verifiedPayloads, 0);
            const allErrors = perProfile.flatMap((p) =>
                p.errors.map((err) => `[${p.profileId}] ${err}`)
            );
            return {
                mode: 'verify-integrity',
                profileId: 'all-profiles',
                profilesDir,
                valid: allValid,
                eventCount: totalEvents,
                verifiedPayloads: totalPayloads,
                chainHeadHash: perProfile[perProfile.length - 1]?.chainHeadHash || '0'.repeat(64),
                errors: allErrors,
                profiles: perProfile
            };
        }
    } else if (options.exportHar || cookiesRequested || signaturesRequested || platformFilter) {
        const candidates = listTrafficProfiles(profilesDir);
        if (candidates.length >= 1) {
            resolvedPaths = {
                profileId: candidates[0].profileId,
                profileDir: candidates[0].profileDir,
                trafficDir: candidates[0].trafficDir
            };
        }
    }

    if (!resolvedPaths || !fs.existsSync(resolvedPaths.trafficDir)) {
        throw new Error(
            `Traffic directory not found for profile "${targetProfileId || correlationId || 'unknown'}" in ${profilesDir}`
        );
    }

    const { profileId, profileDir, trafficDir } = resolvedPaths;

    if (options.verifyIntegrity) {
        const integrityResult = verifyTrafficIntegrity(trafficDir);
        return {
            mode: 'verify-integrity',
            profileId,
            profileDir,
            trafficDir,
            ...integrityResult,
            integrity: integrityResult
        };
    }

    if (options.exportHar) {
        const customHarPath =
            typeof options.exportHar === 'string' &&
            options.exportHar.trim().length > 0 &&
            options.exportHar !== 'true'
                ? path.resolve(options.exportHar)
                : path.join(trafficDir, 'traffic.har');
        const harResult = exportTrafficToHar(trafficDir, customHarPath, { profileId });
        return {
            mode: 'export-har',
            profileId,
            profileDir,
            trafficDir,
            harPath: harResult.harPath,
            outputPath: harResult.outputPath,
            entryCount: harResult.entryCount,
            entriesCount: harResult.entriesCount,
            pageCount: harResult.pageCount,
            bytes: harResult.bytes,
            log: harResult.log,
            har: harResult.har
        };
    }
    const trafficNdjsonPath = path.join(trafficDir, 'traffic.ndjson');
    const attributionIndexPath = path.join(trafficDir, 'attribution-index.json');
    const sslKeyLogPath = path.join(trafficDir, 'sslkeylog.txt');
    const preTlsWireLogPath = path.join(trafficDir, 'pre-tls-wire.log');
    const neckoMozLogPath = path.join(trafficDir, 'necko-pre-tls.moz_log');

    const allEvents = readNdjsonEvents(trafficNdjsonPath);
    const indexData = readJsonSafe(attributionIndexPath);
    const fullCookieLineage =
        indexData?.cookieLineage &&
        typeof indexData.cookieLineage === 'object' &&
        Object.keys(indexData.cookieLineage).length > 0
            ? indexData.cookieLineage
            : buildCookieLineageFromEvents(allEvents);
    const neckoMozLog = indexData?.neckoMozLog || parseNeckoMozLog(neckoMozLogPath);

    if (cookiesRequested) {
        if (cookieNameFilter) {
            let matchedEntry = fullCookieLineage[cookieNameFilter] || null;
            if (!matchedEntry) {
                const lowerTarget = cookieNameFilter.toLowerCase();
                for (const [k, v] of Object.entries(fullCookieLineage)) {
                    if (k.toLowerCase() === lowerTarget) {
                        matchedEntry = v;
                        break;
                    }
                }
            }
            const matchedList = matchedEntry ? [matchedEntry] : [];
            const filteredLineage = matchedEntry
                ? { [matchedEntry.name || cookieNameFilter]: matchedEntry }
                : {};
            return {
                mode: 'cookies',
                profileId,
                profileDir,
                trafficDir,
                filters,
                cookieName: cookieNameFilter,
                found: Boolean(matchedEntry),
                count: matchedList.length,
                antiBotTokenCount: matchedEntry?.isAntiBotToken ? 1 : 0,
                cookie: matchedEntry,
                cookies: matchedList,
                cookieLineage: filteredLineage,
                allCookieLineage: fullCookieLineage
            };
        }

        const cookiesList = Object.values(fullCookieLineage);
        const antiBotTokenCount = cookiesList.filter((c) => c && c.isAntiBotToken).length;
        return {
            mode: 'cookies',
            profileId,
            profileDir,
            trafficDir,
            filters,
            cookieName: null,
            found: cookiesList.length > 0,
            count: cookiesList.length,
            antiBotTokenCount,
            cookie: null,
            cookies: cookiesList,
            cookieLineage: fullCookieLineage
        };
    }

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

    const allPlatformSignatures = buildPlatformSignaturesFromEvents(allEvents, indexData);
    const filteredSignatures = allPlatformSignatures.filter((sig) =>
        recordMatchesFilters(sig, filters, txStatusByCorrelation, {
            useTransactionStatusFallback: true
        })
    );
    const filteredByPlatform = {};
    for (const sig of filteredSignatures) {
        if (!sig || !sig.platform) continue;
        filteredByPlatform[sig.platform] = (filteredByPlatform[sig.platform] || 0) + 1;
    }

    const platformCorrelations = new Set();
    if (platformFilter) {
        for (const sig of allPlatformSignatures) {
            if (
                sig &&
                sig.correlationId &&
                String(sig.platform || '').toLowerCase() === platformFilter
            ) {
                platformCorrelations.add(sig.correlationId);
            }
        }
        for (const ev of allEvents) {
            if (!ev || !ev.correlationId) continue;
            const evSigs = Array.isArray(ev.platformSignatures)
                ? ev.platformSignatures
                : ev.type === 'egress'
                  ? extractPlatformSignatures({
                        url: ev.url || '',
                        searchParams: ev.searchParams || null,
                        headers: ev.headers || {},
                        bodyPreview: ev.bodyPreview ?? ev.postData ?? null
                    })
                  : [];
            if (evSigs.some((s) => s && String(s.platform || '').toLowerCase() === platformFilter)) {
                platformCorrelations.add(ev.correlationId);
            }
        }
    }

    if (signaturesRequested) {
        return {
            mode: 'signatures',
            profileId,
            profileDir,
            trafficDir,
            filters,
            platform: platformFilter,
            found: filteredSignatures.length > 0,
            count: filteredSignatures.length,
            totalDetected: filteredSignatures.length,
            byPlatform: filteredByPlatform,
            signatures: filteredSignatures,
            platformSignatures: {
                totalDetected: filteredSignatures.length,
                byPlatform: filteredByPlatform,
                signatures: filteredSignatures
            }
        };
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
                      e.type === 'security-block' ||
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
                          : e.type === 'security-block'
                            ? `security-block:${e.blockType || 'security-probe'}`
                            : e.type === 'ws-error'
                              ? 'websocket-error'
                              : `http-${e.status}`,
                  severity: e.type === 'security-block' ? e.severity || 'critical' : 'high',
                  method: e.method || null,
                  url: e.url || null,
                  status: e.status ?? null,
                  failureText: e.reason ?? e.failureText ?? null,
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
            useTransactionStatusFallback: true,
            platformCorrelations
        })
    );

    const filteredEvents = allEvents.filter((event) =>
        recordMatchesFilters(event, filters, txStatusByCorrelation, {
            useTransactionStatusFallback: false,
            platformCorrelations
        })
    );

    // Build transactions matching filters (using transaction status fallback so egress+ingress stay paired)
    const eventsForTransactions = allEvents.filter((event) =>
        recordMatchesFilters(event, filters, txStatusByCorrelation, {
            useTransactionStatusFallback: true,
            platformCorrelations
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
            preTlsWireLogPath: fs.existsSync(preTlsWireLogPath) ? preTlsWireLogPath : null,
            neckoMozLogPath: fs.existsSync(neckoMozLogPath) ? neckoMozLogPath : null
        },
        totals: indexData?.totals || {
            totalRequests: allEvents.filter((e) => e.type === 'egress').length,
            totalResponses: allEvents.filter((e) => e.type === 'ingress').length,
            failedRequests: allEvents.filter(
                (e) => e.type === 'request-failed' || e.type === 'security-block'
            ).length
        },
        byActionStep: indexData?.byActionStep || {},
        byTriggerAction: indexData?.byTriggerAction || {},
        byDomain: indexData?.byDomain || {},
        cookieLineage: fullCookieLineage,
        platformSignatures: {
            totalDetected: filteredSignatures.length,
            byPlatform: filteredByPlatform,
            signatures: filteredSignatures
        },
        signaturesCount: filteredSignatures.length,
        signatures: filteredSignatures,
        neckoMozLog,
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

    if (result.mode === 'verify-integrity') {
        const statusText = result.valid
            ? 'VALID (SHA-256 HASH CHAIN & PAYLOAD MANIFEST VERIFIED)'
            : 'INVALID (TAMPERING OR CORRUPTION DETECTED)';
        lines.push(`🔐 Traffic Cryptographic Integrity Verification — Profile: ${result.profileId}`);
        lines.push(`   Status           : ${statusText}`);
        lines.push(`   Chained Events   : ${result.eventCount}`);
        lines.push(`   Verified Payloads: ${result.verifiedPayloads}`);
        lines.push(`   Chain Head Hash  : ${result.chainHeadHash}`);
        if (Array.isArray(result.errors) && result.errors.length > 0) {
            lines.push(`   Errors (${result.errors.length}):`);
            for (const err of result.errors) {
                lines.push(`     - ${err}`);
            }
        }
        return lines.join('\n');
    }

    if (result.mode === 'export-har') {
        lines.push(`📦 W3C HAR 1.2 Archive Exported — Profile: ${result.profileId}`);
        lines.push(`   Output Path : ${result.harPath}`);
        lines.push(`   Entry Count : ${result.entryCount}`);
        lines.push(`   Page Count  : ${result.pageCount ?? 0}`);
        lines.push(`   File Size   : ${result.bytes ?? 0} bytes`);
        return lines.join('\n');
    }

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
            const reasonPart = a.failureText ? ` | reason=${a.failureText}` : '';
            lines.push(
                `  - [${a.severity || 'medium'}] ${a.type} | corr=${a.correlationId || 'n/a'} | step=${a.actionStep || 'n/a'}${trig} | status=${a.status ?? 'ERR'}${reasonPart} | url=${a.url || ''} | payload=${a.payloadFile || 'none'}`
            );
        }
        return lines.join('\n');
    }

    if (result.mode === 'cookies') {
        if (result.cookieName) {
            lines.push(
                `🍪 Cookie & Anti-Bot Token Lineage — Profile: ${result.profileId} | Filter: ${result.cookieName}`
            );
            if (!result.found || !result.cookie) {
                lines.push(`   No cookie matching "${result.cookieName}" found in cookieLineage.`);
                return lines.join('\n');
            }
        } else {
            lines.push(
                `🍪 Cookie & Anti-Bot Token Causal Lineage — Profile: ${result.profileId} (${result.count} total, ${result.antiBotTokenCount ?? 0} anti-bot/auth tokens)`
            );
        }

        for (const c of result.cookies || []) {
            const badge = c.isAntiBotToken ? '[ANTI-BOT/AUTH TOKEN]' : '[COOKIE]';
            lines.push(
                `  - ${c.name} ${badge} | domain=${c.domain || 'n/a'} path=${c.path || '/'} secure=${Boolean(c.secure)} httpOnly=${Boolean(c.httpOnly)} sameSite=${c.sameSite || 'n/a'}`
            );
            lines.push(
                `    firstSet: corr=${c.firstSetByCorrelationId || 'n/a'} step=${c.firstSetAtStep || 'n/a'} trigger=${c.firstSetByTrigger || 'none'} url=${c.firstSetUrl || 'n/a'}`
            );
            lines.push(
                `    latest  : masked=${c.lastMaskedValue || '[REDACTED]'} sha256=${c.lastValueSha256 || 'n/a'} mutations=${c.mutationsCount ?? 0} sent=${c.sentCount ?? 0} matchesLatestSetCookie=${c.matchesLatestSetCookie ?? 'n/a'}`
            );
            if (Array.isArray(c.valueHistory) && c.valueHistory.length > 0) {
                lines.push(`    valueHistory (${c.valueHistory.length}):`);
                for (const h of c.valueHistory) {
                    lines.push(
                        `      * corr=${h.correlationId || 'n/a'} step=${h.actionStep || 'n/a'} trigger=${h.triggerActionId || 'none'} status=${h.status ?? 'n/a'} masked=${h.maskedValue} sha256=${h.valueSha256} deleted=${Boolean(h.isDeleted)}`
                    );
                }
            }
        }
        return lines.join('\n');
    }

    if (result.mode === 'signatures') {
        const platformLabel = result.platform ? ` | Platform: ${result.platform}` : '';
        lines.push(
            `🛡️ Anti-Bot Platform Signature Attribution — Profile: ${result.profileId}${platformLabel} (${result.count} detected)`
        );
        if (result.byPlatform && Object.keys(result.byPlatform).length > 0) {
            const breakdown = Object.entries(result.byPlatform)
                .map(([plat, cnt]) => `${plat}=${cnt}`)
                .join(', ');
            lines.push(`   By Platform: ${breakdown}`);
        }
        for (const s of result.signatures || []) {
            const trig = s.triggerActionId
                ? `${s.triggerActionId}${s.triggerTarget ? `(${s.triggerTarget})` : ''}`
                : s.triggerAction
                  ? `${s.triggerAction.actionType || ''}:${s.triggerAction.target || ''}`
                  : 'none';
            lines.push(
                `  - [${s.platform}] ${s.signatureName} (${s.location}) | corr=${s.correlationId || 'n/a'} | step=${s.actionStep || 'n/a'} | trigger=${trig} | len=${s.valueLength} masked=${s.maskedPreview} sha256=${s.valueSha256} | url=${s.url || ''}`
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
                '  --cookies                   List all tracked cookies & anti-bot tokens in cookieLineage',
                '  --cookie=<name>             Show full lineage and value history for a specific cookie name',
                '  --signatures                List all detected anti-bot platform signatures and causal step/trigger',
                '  --platform=<platformName>   Filter signatures & events by platform (bytedance, twitter, meta, google, arkose, cloudflare)',
                '  --verify-integrity          Verify SHA-256 tamper-evident hash chain & payload manifest',
                '  --export-har[=<path>]       Export recorded profile traffic to W3C HAR 1.2 archive',
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
        dumpWire: args.dumpWire,
        cookies: args.cookies,
        cookie: args.cookie,
        signatures: args.signatures,
        platform: args.platform,
        verifyIntegrity: args.verifyIntegrity,
        exportHar: args.exportHar
    });

    if (args.json) {
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
        process.stdout.write(`${formatCliReport(result)}\n`);
    }

    if (args.verifyIntegrity && result && result.valid === false) {
        return 1;
    }
    return 0;
}

const isMainModule =
    process.argv[1] &&
    path.resolve(process.argv[1]) === path.resolve(__filename);

if (isMainModule) {
    try {
        const exitCode = runCli(process.argv.slice(2));
        if (typeof exitCode === 'number' && exitCode !== 0) {
            process.exit(exitCode);
        }
    } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
}

export {
    verifyTrafficIntegrity,
    exportTrafficToHar,
    parseSslKeyLog,
    parseNeckoMozLog,
    parseSetCookieHeader,
    parseCookieHeader,
    detectWireHeaderAnomalies,
    extractPlatformSignatures,
    redactUrlSecrets
};

export default {
    queryProfileTraffic,
    listTrafficProfiles,
    reconstructTransactionWireDump,
    verifyTrafficIntegrity,
    exportTrafficToHar,
    parseSslKeyLog,
    parseNeckoMozLog,
    parseSetCookieHeader,
    parseCookieHeader,
    detectWireHeaderAnomalies,
    extractPlatformSignatures,
    redactUrlSecrets,
    parseCliArgs,
    formatCliReport,
    runCli
};
