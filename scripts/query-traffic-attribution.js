#!/usr/bin/env node
/**
 * Offline Pre-TLS Traffic Attribution Auditor & Wire-Dump Reconstruction CLI
 *
 * Standalone Node.js ESM CLI and programmatic query engine (`queryProfileTraffic`)
 * with zero external npm dependencies.
 *
 * Supported CLI flags:
 *   --profiles-dir=<path>      Root profiles directory (defaults to the application configuration)
 *   --traffic-dir=<path>       Select a specific capture directory
 *   --profile=<profileId>      Inspect a specific profile (if omitted, lists & summarizes all profiles)
 *   --step=<actionStep>        Filter events/anomalies matching attribution.actionStep
 *   --trigger=<actionOrTarget> Filter events/anomalies triggered by a specific UI action (e.g. page.click or #submit)
 *   --domain=<hostSubstring>   Filter events/anomalies matching host substring
 *   --status=<codeOrClass>     Filter by HTTP status code or class (e.g. 429, 403, 4xx, 5xx, 200)
 *   --anomalies-only           Show anomalies and security blocks from the capture
 *   --correlation=<corrId>     Reconstruct complete Pre-TLS Egress + Post-TLS Ingress wire dump & payloads
 *   --dump-wire=<corrId>       Alias for --correlation=<corrId>
 *   --cookies                  Private cookie lineage with stable value digests
 *   --cookie=<name>            Private lineage and digest history for a specific cookie name
 *   --signatures               List all detected anti-bot platform signatures and their causal actionStep / triggerAction
 *   --platform=<platformName>  Filter signatures & events by platform (bytedance, twitter, meta, google, arkose, cloudflare)
 *   --verify-integrity         Verify cryptographic SHA-256 event hash chain & payload manifest integrity
 *   --export-har[=<path>]       Export HAR 1.2 to a new ./traffic.har or to the selected path
 *   --json                     Emit structured JSON output to stdout
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { getConfiguredProfilesDirectory } from '../src/utils/private-env.js';
import { CookieLineage } from '../src/camoufox/cookie-lineage.js';
import { readCaptureFile } from '../src/camoufox/capture-io.js';
import {
    captureEventProfileId, captureEventTraceId, capturePolicyAllowsBody,
    createCaptureProfileContinuityCheck, createCaptureRedirectBodyCheck, observedProfileIdentity, readCaptureExportIndex,
    sameRecordedProfile, validRecordedProfileId
} from '../src/camoufox/capture-export-policy.js';
import {
    inspectProfileDirectory, readProfileMetadata, resolveProfileNativeDirectory, resolveProfilesRoot, validateProfileId
} from '../src/camoufox/profile-storage.js';
import {
    captureEventAccountId, captureIdentityObservation, captureTransactionPhase, createCaptureTransactionIndex
} from '../src/camoufox/capture-transaction-identity.js';
import { createCorrelationIdProjection, isAnonymousProfileId, redactPressKeys } from '../src/camoufox/traffic-redaction.js';
import {
    verifyTrafficIntegrity,
    exportTrafficToHar,
    MAX_HAR_LEDGER_BYTES,
    MAX_HAR_RECORD_BYTES,
    parseSslKeyLog,
    parseNeckoMozLog,
    parseSetCookieHeader,
    parseCookieHeader,
    detectWireHeaderAnomalies,
    extractPlatformSignatures,
    observedHttpResponseBodyBytes,
    observedWebSocketPayloadBytes,
    classifyTrafficLifecycleAnomaly,
    trafficAnomalyKey,
    securityBlockAnomaly,
    getCaptureWireLogFileName,
    readCaptureExportBody,
    redactDiagnosticMetadata,
    redactDiagnosticText,
    redactNeckoMozLogSummary,
    redactProfileId,
    redactSensitiveHeaders,
    redactTriggerAction,
    redactUrlSecrets
} from '../src/camoufox/traffic-recorder.js';

import { createDiagnosticKeyProjector } from '../src/camoufox/traffic-redaction.js';

const __filename = fileURLToPath(import.meta.url);
const WIRE_EXPORT_INDEX = Symbol('wire export index');
const SOURCE_EVENT = Symbol('source ledger event');
const EVENT_COUNT_FIELDS = new Map([
    ['egress', 'totalRequests'],
    ['ingress', 'totalResponses'],
    ['request-failed', 'failedRequests'],
    ['security-block', 'failedRequests'],
    ['ws-egress', 'wsFramesSent'],
    ['ws-ingress', 'wsFramesReceived']
]);
const UNKNOWN_WS_COUNT_FIELDS = new Map([
    ['ws-egress', 'unknownWsFramesSent'],
    ['ws-ingress', 'unknownWsFramesReceived']
]);

function emptyTrafficTotals() {
    return Object.fromEntries(
        [...EVENT_COUNT_FIELDS.values(), ...UNKNOWN_WS_COUNT_FIELDS.values()].map((field) => [field, 0])
    );
}

function countTrafficEvent(event, totals) {
    const field = EVENT_COUNT_FIELDS.get(event.type);
    if (!field) return;
    totals[field] += 1;
    const unknownField = UNKNOWN_WS_COUNT_FIELDS.get(event.type);
    if (unknownField && observedWebSocketPayloadBytes(event) === null) totals[unknownField] += 1;
    return field;
}

/**
 * Resolve the explicit directory or the configured profiles directory.
 *
 * @param {string} [overrideDir]
 * @returns {string}
 */
export function resolveProfilesDir(overrideDir) {
    if (overrideDir == null) return getConfiguredProfilesDirectory();
    if (typeof overrideDir !== 'string' || !overrideDir.trim()) {
        throw new Error('Profiles root directory must be nonempty');
    }
    return path.resolve(overrideDir);
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
        trafficDir: null,
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
        const arg = String(argv[i] ?? '');
        if (!arg.startsWith('--')) {
            throw new Error('Unexpected positional argument. See --help.');
        }

        const eqIdx = arg.indexOf('=');
        const rawKey = eqIdx >= 0 ? arg.slice(2, eqIdx) : arg.slice(2);
        const value = eqIdx >= 0 ? arg.slice(eqIdx + 1) : null;

        const readNextValue = () => {
            if (value !== null) return value;
            if (i + 1 < argv.length && !String(argv[i + 1]).startsWith('--')) {
                i += 1;
                return String(argv[i]);
            }
            return null;
        };
        const readBoolean = () => {
            const flagValue = readNextValue();
            if (flagValue === null || flagValue === 'true' || flagValue === '1') return true;
            if (flagValue === 'false' || flagValue === '0') return false;
            throw new Error(`--${rawKey} requires a boolean value (true or false)`);
        };

        switch (rawKey) {
            case 'profiles-dir':
            case 'profilesDir':
                opts.profilesDir = readNextValue() ?? '';
                break;
            case 'traffic-dir':
            case 'trafficDir':
                opts.trafficDir = readNextValue() ?? '';
                break;
            case 'profile':
            case 'profile-id':
            case 'profileId':
                opts.profile = readNextValue() ?? '';
                break;
            case 'step':
            case 'action-step':
            case 'actionStep':
                opts.step = readNextValue() ?? '';
                break;
            case 'trigger':
            case 'trigger-action':
            case 'triggerAction':
                opts.trigger = readNextValue() ?? '';
                break;
            case 'domain':
            case 'host':
                opts.domain = readNextValue() ?? '';
                break;
            case 'status':
                opts.status = readNextValue() ?? '';
                break;
            case 'anomalies-only':
            case 'anomaliesOnly':
            case 'anomalies':
                opts.anomaliesOnly = readBoolean();
                break;
            case 'correlation':
            case 'correlation-id':
            case 'correlationId':
                opts.correlation = readNextValue() ?? '';
                break;
            case 'dump-wire':
            case 'dumpWire':
                opts.dumpWire = readNextValue() ?? '';
                opts.correlation = opts.correlation || opts.dumpWire;
                break;
            case 'cookies':
                opts.cookies = readBoolean();
                break;
            case 'cookie':
            case 'cookie-name':
            case 'cookieName':
                opts.cookie = readNextValue() ?? '';
                break;
            case 'signatures':
            case 'platform-signatures':
            case 'platformSignatures':
                opts.signatures = readBoolean();
                break;
            case 'platform':
            case 'platform-name':
            case 'platformName':
                opts.platform = readNextValue() ?? '';
                break;
            case 'verify-integrity':
            case 'verifyIntegrity':
                opts.verifyIntegrity = readBoolean();
                break;
            case 'export-har':
            case 'exportHar': {
                const destination = readNextValue();
                if (destination === null || destination === 'true') opts.exportHar = true;
                else if (destination === 'false' || destination === '0') opts.exportHar = false;
                else if (!destination.trim()) throw new Error('HAR output path must be nonempty');
                else opts.exportHar = destination;
                break;
            }
            case 'json':
                opts.json = readBoolean();
                break;
            case 'help':
            case 'h':
                opts.help = readBoolean();
                break;
            default:
                throw new Error(`Unknown option --${rawKey}. See --help.`);
        }
    }

    return opts;
}

function readNdjsonBytes(filePath, { trustedLocal = false, maxBytes } = {}) {
    if (!filePath) return null;
    return readCaptureFile(path.dirname(filePath), path.basename(filePath), {
        optional: true, trustedLocal, maxBytes
    });
}

function* parseNdjsonEvents(bytes, { maxRecordBytes = Infinity } = {}) {
    if (!bytes) return;
    let start = 0;
    let lineNumber = 0;
    while (start < bytes.length) {
        lineNumber += 1;
        const newline = bytes.indexOf(0x0a, start);
        const end = newline === -1 ? bytes.length : newline;
        if (end - start > maxRecordBytes) {
            throw Object.assign(new Error('HAR export exceeds its ledger record byte limit'), { code: 'ERR_HAR_LIMIT' });
        }
        const line = bytes.toString('utf8', start, end).trim();
        start = end + 1;
        if (!line) continue;
        let event;
        try {
            event = JSON.parse(line);
        } catch {
            throw new Error('Line ' + lineNumber + ' of traffic.ndjson: Invalid JSON');
        }
        if (!event || typeof event !== 'object' || Array.isArray(event)) {
            throw new Error('Line ' + lineNumber + ' of traffic.ndjson: Expected an event object');
        }
        yield event;
    }
}

function* iterateNdjsonEvents(filePath, options) {
    yield* parseNdjsonEvents(readNdjsonBytes(filePath, options), options);
}

/** Read and parse an NDJSON capture. */
export function readNdjsonEvents(filePath, options) {
    return [...iterateNdjsonEvents(filePath, options)];
}

/**
 * Read and parse a JSON file safely.
 *
 * @param {string} filePath
 * @returns {object|null}
 */
function readJsonSafe(filePath) {
    if (!filePath) return null;
    const raw = readCaptureFile(path.dirname(filePath), path.basename(filePath), { optional: true });
    if (!raw) return null;
    try {
        return JSON.parse(raw.toString('utf8'));
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

function inferredLabel(triggerAction) {
    return triggerAction?.association === 'inferred' ? ' (inferred)' : '';
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

function createStepNameProjection(events, index) {
    const names = new Set(Object.keys(index?.byActionStep ?? {}));
    for (const event of events) {
        for (const name of [
            event?.actionStep, event?.attribution?.actionStep, event?.previousStep,
            event?.triggerAction?.actionStep, event?.attribution?.triggerAction?.actionStep
        ]) {
            if (typeof name === 'string') names.add(name);
        }
    }
    const project = createDiagnosticKeyProjector(names, redactDiagnosticText);
    const labels = new Map(Array.from(names, (name) => [name, project(name)]));
    return (name) => labels.get(name) ?? redactDiagnosticText(name);
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

function parsedUrlHost(record) {
    if (typeof record?.url !== 'string') return '';
    try {
        return new URL(record.url).host;
    } catch {
        return '';
    }
}

function observedStatus(value) {
    const status = typeof value === 'string' && value.trim() ? Number(value) : value;
    return Number.isFinite(status) ? status : null;
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
    const numericStatus = observedStatus(statusValue);
    if (numericStatus === null) {
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
    const safeTrigger = redactPressKeys(triggerAction);
    const key = String(safeTrigger.key || '').toLowerCase();
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
    {
        useTransactionStatusFallback = false, txTriggerByCorrelation = null, platformCorrelations = null,
        getTransactionKey = () => null
    } = {}
) {
    if (!record || typeof record !== 'object') {
        return false;
    }

    if (filters.correlation) {
        if (record.correlationId !== filters.correlation) {
            return false;
        }
    }

    const txKey = getTransactionKey(record);
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
                : txTriggerByCorrelation?.get(txKey));
        if (!matchesTriggerFilter(triggerAction, filters.trigger)) {
            return false;
        }
    }

    if (filters.domain) {
        const domainNeedle = String(filters.domain).trim().toLowerCase();
        if (!domainNeedle || !parsedUrlHost(record).toLowerCase().includes(domainNeedle)) return false;
    }

    if (filters.platform) {
        const targetPlatform = String(filters.platform).trim().toLowerCase();
        const matched = platformCorrelations
            ? platformCorrelations.has(txKey)
            : String(record.platform || '').toLowerCase() === targetPlatform;
        if (!matched) return false;
    }

    if (filters.status !== null && filters.status !== undefined && filters.status !== '') {
        let statusCandidate =
            record.status !== null && record.status !== undefined
                ? record.status
                : record.type === 'security-block' ||
                    (typeof record.type === 'string' && record.type.startsWith('security-block:'))
                  ? 0
                  : null;
        if (
            (statusCandidate === null || statusCandidate === undefined) &&
            useTransactionStatusFallback &&
            txKey !== null
        ) {
            statusCandidate = txStatusByCorrelation?.get(txKey);
        }
        if (!matchesStatusFilter(statusCandidate, filters.status)) {
            return false;
        }
    }

    return true;
}

function inspectProfileTrafficPaths(profilesDir, profileId) {
    const profileDir = path.join(profilesDir, profileId);
    if (!inspectProfileDirectory({ profileDir })) return null;
    const trafficDir = path.join(profileDir, 'traffic');
    if (!inspectProfileDirectory({ profileDir: trafficDir })) return null;
    return { profileId, profileDir, trafficDir };
}

function enumerateProfileTrafficPaths(profilesDir) {
    let entries;
    try {
        entries = fs.readdirSync(profilesDir, { withFileTypes: true });
    } catch (error) {
        if (error.code === 'ENOENT') return [];
        throw error;
    }

    return entries
        .filter((entry) => entry.isDirectory())
        .map((entry) => inspectProfileTrafficPaths(profilesDir, entry.name))
        .filter(Boolean);
}

/** Resolve the directory ID first, then compare legacy labels inside the selected root. */
function resolveProfileTrafficPaths(profilesDir, selector) {
    let id;
    try {
        id = validateProfileId(selector);
    } catch (error) {
        if (typeof selector !== 'string' || !selector.trim() ||
            selector === '.' || selector === '..' || /[\\/:\p{Cc}]/u.test(selector)) {
            throw error;
        }
    }

    const isLegacyAlias = isAnonymousProfileId(id);
    if (id) {
        const direct = inspectProfileTrafficPaths(profilesDir, id);
        if (direct) return direct;
    }

    const candidates = enumerateProfileTrafficPaths(profilesDir);
    if (!id) {
        const direct = candidates.find((candidate) => candidate.profileId === selector);
        if (direct) return direct;
    }
    const directoriesByAlias = isLegacyAlias
        ? candidates.filter((candidate) => redactProfileId(candidate.profileId) === id)
        : [];
    const matches = directoriesByAlias.length > 0 ? directoriesByAlias : candidates.filter(({ trafficDir, profileDir }) => {
        const index = readJsonSafe(path.join(trafficDir, 'attribution-index.json'));
        const meta = readJsonSafe(path.join(profileDir, 'profile.json'));
        return [index?.session?.profileId, meta?.profileId, meta?.id].some((label) =>
            (typeof label === 'string' || Number.isSafeInteger(label)) && (
                String(label) === String(selector) || (isLegacyAlias && redactProfileId(label) === id)
            )
        );
    });
    if (matches.length > 1) {
        throw new Error('Profile label matches multiple directories. Select one with --traffic-dir.');
    }
    return matches[0] || null;
}

function selectedTrafficSession(records, profileId, profileScoped, checkpointSession, ownership) {
    if (records.some((record) => record.attributionStatus === 'unresolved')) return { profileId };
    const events = records.map((record) => record[SOURCE_EVENT] ?? record);
    const traceId = captureEventTraceId(events[0]);
    if (typeof traceId !== 'string' || !traceId.trim() ||
        events.some((event) => captureEventTraceId(event) !== traceId)) {
        return { profileId };
    }
    const profileIds = new Set(events.map(ownership.profileOf));
    const recorded = observedProfileIdentity(profileIds);
    if (recorded.profileIdentity === 'mixed' ||
        (profileScoped && [...profileIds].some((id) => {
            const validId = validRecordedProfileId(id);
            return !validId || isAnonymousProfileId(validId);
        }))) return { profileId };

    const fields = ['accountId', 'os', 'proxyServer'];
    const observed = (event, field) => event.attribution?.[field] ?? event[field] ?? null;
    const attribution = Object.fromEntries(fields.map((field) => [field, observed(events[0], field)]));
    if (events.some((event) => fields.some((field) => observed(event, field) !== attribution[field]))) {
        return { profileId };
    }

    const owner = recorded.profileId ?? profileId;
    const checkpointMatches = checkpointSession?.traceId === traceId &&
        sameRecordedProfile(validRecordedProfileId(checkpointSession.profileId), owner) &&
        fields.every((field) => (checkpointSession[field] ?? null) === attribution[field]);
    return {
        ...(checkpointMatches && checkpointSession),
        ...attribution,
        profileId: profileScoped ? owner : profileId,
        traceId
    };
}

function managedCaptureProfileId({ profileDir, trafficDir }) {
    if (path.basename(trafficDir) !== 'traffic') return null;
    const id = validRecordedProfileId(path.basename(profileDir));
    if (!id) return null;
    const location = { id, profileDir: path.join(resolveProfilesRoot(path.dirname(profileDir)), id) };
    try {
        return readProfileMetadata(location, { readOnly: true }) ? id : null;
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        return null;
    }
}

function profileIdForExplicitDirectory({ profileId, explicitProfilesDir, profileDir, trafficDir }, observedId) {
    if (profileId !== null || !observedId || observedId !== path.basename(profileDir) ||
        path.basename(trafficDir) !== 'traffic' || isAnonymousProfileId(observedId)) return null;
    const root = resolveProfilesRoot(path.dirname(profileDir));
    if (explicitProfilesDir !== null && resolveProfilesRoot(explicitProfilesDir) !== root) return null;
    return inspectProfileTrafficPaths(root, observedId)?.profileId ?? null;
}

function captureProfileSelector(paths, selector = null) {
    const directoryId = paths.profileId;
    const requestedId = selector === null ? null
        : directoryId === null ? validateProfileId(selector) : (validRecordedProfileId(selector) ?? selector);
    const managedId = managedCaptureProfileId(paths);
    const requireMatchingId = (profileId) => {
        if (requestedId === null) return;
        if (profileId !== null && (requestedId === profileId || requestedId === redactProfileId(profileId))) return;
        if (requestedId === directoryId && sameRecordedProfile(directoryId, profileId)) return;
        throw new Error('Selected profile ID does not match the traffic directory or its recorded identity');
    };
    if (managedId && directoryId === null) requireMatchingId(managedId);

    return {
        fallbackProfileId: managedId ?? directoryId ?? 'standalone-capture',
        resolve(profileIds, session, traceIds, profileContinuityUnproven) {
            if (managedId) return { profileId: managedId };
            const observed = observedProfileIdentity(profileIds);
            if (!observed.profileIdentity && !observed.profileId && directoryId) {
                // Directory-based lookup of historical recordings without named events.
                return { profileId: directoryId };
            }
            const indexedId = validRecordedProfileId(session?.profileId);
            const indexedTrace = session?.traceId ?? null;
            const spansTraces = traceIds.size > 1 ||
                (indexedTrace !== null && traceIds.size > 0 && !traceIds.has(indexedTrace));
            const hasAnonymousSource = isAnonymousProfileId(indexedId) || [...profileIds].some(isAnonymousProfileId);
            // An anonymous timestamp label does not prove continuity between recording traces.
            if ((hasAnonymousSource && (spansTraces || profileContinuityUnproven)) ||
                observed.profileIdentity === 'mixed' ||
                (observed.profileId && indexedId && !sameRecordedProfile(observed.profileId, indexedId))) {
                if (selector !== null) throw new Error('Selected traffic capture contains multiple recording profiles');
                return { profileId: 'standalone-capture', profileIdentity: 'mixed' };
            }
            const profileId = indexedId
                ? (observed.profileId ?? indexedId)
                : sameRecordedProfile(directoryId, observed.profileId) ? directoryId
                  : profileIdForExplicitDirectory(paths, observed.profileId);
            requireMatchingId(profileId);
            return { profileId: profileId ?? 'standalone-capture' };
        }
    };
}

function ledgerAnomaly(event) {
    const { type } = event;
    const traceId = captureEventTraceId(event);
    if (type === 'security-block') return { ...securityBlockAnomaly(event), traceId, [SOURCE_EVENT]: event };
    const classification = classifyTrafficLifecycleAnomaly(event);
    if (!classification) return null;

    const status = type === 'ingress' ? Number(event.status) : null;
    return {
        timestamp: event.timestamp,
        correlationId: event.correlationId || null,
        traceId,
        [SOURCE_EVENT]: event,
        actionStep: extractActionStep(event),
        triggerAction: extractTriggerAction(event),
        ...classification,
        method: type === 'ws-error' ? 'WEBSOCKET' : event.method || null,
        url: event.url || null,
        status,
        failureText: type === 'ingress' ? event.statusText || `HTTP ${status}` : event.failureText ?? null,
        payloadFile: event.payloadFile ?? null
    };
}

function anomalyKey(anomaly) {
    const type = anomaly.type === 'network-proxy-or-tls-failure'
        ? 'network-request-failed'
        : (/^http-\d{3}\b/.exec(anomaly.type)?.[0] ?? anomaly.type);
    return trafficAnomalyKey({
        ...anomaly,
        type,
        url: normalizedAnomalyUrl(anomaly.url),
        failureText: redactDiagnosticText(anomaly.failureText)
    });
}

function normalizedAnomalyUrl(url) {
    if (typeof url !== 'string' || !url) return null;
    const redacted = redactUrlSecrets(url);
    try {
        return new URL(redacted).href;
    } catch {
        return redacted;
    }
}

function indexedAnomaliesWithSources(anomalies, ownership) {
    const byCorrelation = new Map();
    const keyFor = (fields, required) => JSON.stringify(required.map((index) => fields[index]));
    const matches = anomalies.map((anomaly) => {
        const correlationId = anomaly.correlationId;
        if (!byCorrelation.has(correlationId)) byCorrelation.set(correlationId, new Map());
        const criteria = byCorrelation.get(correlationId);
        const fields = [
            captureEventTraceId(anomaly), validRecordedProfileId(captureEventProfileId(anomaly)),
            captureEventAccountId(anomaly), normalizedAnomalyUrl(anomaly.url),
            typeof anomaly.method === 'string' ? anomaly.method.toUpperCase() : null, observedStatus(anomaly.status)
        ];
        const required = fields.flatMap((field, index) => field === null ? [] : [index]);
        const pattern = required.join(',');
        if (!criteria.has(pattern)) criteria.set(pattern, { required, byKey: new Map() });
        const { byKey } = criteria.get(pattern);
        const key = keyFor(fields, required);
        if (!byKey.has(key)) byKey.set(key, { source: null, transaction: null, multiple: false });
        return { anomaly, match: byKey.get(key) };
    });

    // Index only requested evidence combinations so a reused correlation does not trigger a scan per anomaly.
    for (const [correlationId, criteria] of byCorrelation) {
        for (const transaction of ownership.byCorrelation.get(correlationId) ?? []) {
            const { traceId, profileId, accountId, observations } = transaction;
            const requestMethod = observations.find((event) => event.type === 'egress')?.method;
            const displayProfile = redactProfileId(profileId);
            for (const event of observations) {
                const method = event.type === 'ws-error' ? 'WEBSOCKET' : (event.method ?? requestMethod);
                const fields = [
                    traceId, profileId, accountId, normalizedAnomalyUrl(event.url ?? event.targetUrl),
                    typeof method === 'string' ? method.toUpperCase() : null, observedStatus(event.status)
                ];
                for (const { required, byKey } of criteria.values()) {
                    const found = [byKey.get(keyFor(fields, required))];
                    if (profileId !== displayProfile && required.includes(1)) {
                        fields[1] = displayProfile;
                        found.push(byKey.get(keyFor(fields, required)));
                        fields[1] = profileId;
                    }
                    for (const match of found) {
                        if (!match || match.multiple) continue;
                        if (match.transaction && match.transaction !== transaction) {
                            match.multiple = true;
                        } else {
                            match.transaction = transaction;
                            match.source ??= event;
                        }
                    }
                }
            }
        }
    }

    return matches.map(({ anomaly, match }) => {
        if (!match.source || match.multiple) return { ...anomaly, attributionStatus: 'unresolved' };
        const traceId = captureEventTraceId(match.source);
        return { ...anomaly, ...(traceId !== null && { traceId }), [SOURCE_EVENT]: match.source };
    });
}

function summarizeCapture(events, indexData, ownership) {
    const ownershipRows = ownership ? null : [];
    const observedTotals = emptyTrafficTotals();
    const steps = new Set();
    const domains = new Set();
    const triggers = new Set();
    const profileIds = new Set();
    const profileTraces = new Set();
    let profileContinuityUnproven = false;
    const profileContinuity = createCaptureProfileContinuityCheck();
    const securityBlocks = [];
    const observedAnomalies = [];
    const checkpoint = indexData?.integrity;
    let checkpointHash = checkpoint?.eventCount === 0 ? '0'.repeat(64) : null;
    let eventCount = 0;
    for (const event of events) {
        if (!event || typeof event !== 'object' || Array.isArray(event)) continue;
        let source = event;
        if (ownershipRows) {
            source = {
                ...captureIdentityObservation(event),
                url: event.url ?? event.targetUrl,
                method: event.method,
                status: event.status
            };
            ownershipRows.push(source);
        }
        eventCount += 1;
        if (eventCount === checkpoint?.eventCount) checkpointHash = event.eventHash;
        countTrafficEvent(event, observedTotals);
        profileIds.add(captureEventProfileId(event));
        profileTraces.add(captureEventTraceId(event));
        profileContinuityUnproven ||= profileContinuity(event);
        const step = extractActionStep(event);
        const host = extractHost(event);
        const triggerId = extractTriggerAction(event)?.actionId;
        if (step) steps.add(step);
        if (host) domains.add(host);
        if (triggerId) triggers.add(triggerId);
        const anomaly = ledgerAnomaly(event);
        if (event.type === 'security-block') securityBlocks.push(anomaly);
        else if (anomaly) observedAnomalies.push({ ...anomaly, [SOURCE_EVENT]: source });
    }

    const checkpointMatches = typeof checkpointHash === 'string' && /^[0-9a-f]{64}$/.test(checkpointHash) &&
        checkpointHash === checkpoint?.chainHeadHash;
    const staleIndex = checkpoint != null && (!checkpointMatches || checkpoint.eventCount !== eventCount);
    const summaryIndex = staleIndex ? null : indexData;
    const indexedTotals = summaryIndex?.totals;
    const totals = { ...indexedTotals, ...observedTotals };
    const indexedAnomalies = Array.isArray(indexData?.anomaliesAndRiskSignals)
        ? indexData.anomaliesAndRiskSignals.filter((anomaly) => anomaly && typeof anomaly === 'object')
        : null;
    const isSecurityBlock = (anomaly) => /^security-block(?::|$)/.test(anomaly.type);
    const indexWarnings = [];
    if (staleIndex) {
        indexWarnings.push('The capture index is out of sync with the traffic ledger. The report uses ledger counts.');
    }
    const withoutTrace = ({ traceId, [SOURCE_EVENT]: source, ...anomaly }) => anomaly;
    if (indexData && (indexedAnomalies || securityBlocks.length) &&
        !isDeepStrictEqual(indexedAnomalies?.filter(isSecurityBlock).map(withoutTrace), securityBlocks.map(withoutTrace))) {
        indexWarnings.push('Security block anomalies in the capture index differ from the traffic ledger. The report uses the ledger.');
    }
    const profileScoped = observedProfileIdentity(profileIds).profileIdentity === 'mixed' || (profileContinuityUnproven &&
        [...profileIds].some(isAnonymousProfileId));
    const attribution = ownership ?? createCaptureTransactionIndex(ownershipRows, { profileScoped });
    const observedByTransaction = new Map();
    const otherAnomalies = [];
    for (const anomaly of observedAnomalies) {
        const source = anomaly[SOURCE_EVENT];
        const transaction = attribution.get(source) ?? source;
        const key = anomalyKey(anomaly);
        if (!observedByTransaction.has(transaction)) observedByTransaction.set(transaction, new Set());
        const observedKeys = observedByTransaction.get(transaction);
        if (observedKeys.has(key)) continue;
        observedKeys.add(key);
        otherAnomalies.push(anomaly);
    }

    if ((checkpoint == null || checkpointMatches) && indexedAnomalies) {
        let unresolved = false;
        const candidates = indexedAnomalies.filter((anomaly) => !isSecurityBlock(anomaly));
        for (const resolved of indexedAnomaliesWithSources(candidates, attribution)) {
            const transaction = attribution.get(resolved[SOURCE_EVENT]);
            if (observedByTransaction.get(transaction)?.has(anomalyKey(resolved))) continue;
            unresolved ||= resolved.attributionStatus === 'unresolved';
            otherAnomalies.push(resolved);
        }
        if (unresolved) indexWarnings.push('Some capture index anomalies have no unique recorded transaction.');
    }

    for (const name of Object.keys(summaryIndex?.byActionStep || {})) steps.add(name);
    for (const host of Object.keys(summaryIndex?.byDomain || {})) domains.add(host);
    for (const id of Object.keys(summaryIndex?.byTriggerAction || {})) triggers.add(id);
    return {
        summaryIndex, totals, anomalies: [...securityBlocks, ...otherAnomalies],
        indexWarnings, steps, domains, triggers, profileIds, profileTraces, profileContinuityUnproven
    };
}

function summarizeFilteredTraffic(events, txTriggerByCorrelation, getTransactionKey, displayStepName) {
    const totals = emptyTrafficTotals();
    const steps = new Map();
    const domains = new Map();
    const triggers = new Map();

    const countGroup = (groups, key, event, metadata) => {
        if (!key) return;
        if (!groups.has(key)) groups.set(key, { ...metadata?.(), ...emptyTrafficTotals(), statusCounts: {} });
        const group = groups.get(key);
        countTrafficEvent(event, group);
        if (event.type !== 'ingress') return;
        const status = Number(event.status);
        if (Number.isInteger(status) && status >= 100 && status <= 599) {
            group.statusCounts[status] = (group.statusCounts[status] || 0) + 1;
        }
    };

    for (const event of events) {
        if (!countTrafficEvent(event, totals)) continue;
        const step = extractActionStep(event);
        const trigger = extractTriggerAction(event) ?? txTriggerByCorrelation.get(getTransactionKey(event));
        const actionId = redactDiagnosticText(trigger?.actionId);
        countGroup(steps, step === null ? null : String(step), event);
        countGroup(domains, parsedUrlHost(event), event);
        countGroup(triggers, actionId, event, () => redactTriggerAction(redactDiagnosticMetadata(trigger)));
    }

    const groupedTotals = (groups, displayKey) => Object.fromEntries(Array.from(groups, ([key, stats]) => {
        const { totalRequests: requests, totalResponses: responses, ...otherStats } = stats;
        return [displayKey ? displayKey(key) : key, { ...otherStats, requests, responses }];
    }));
    return {
        totals,
        byActionStep: groupedTotals(steps, displayStepName),
        byDomain: groupedTotals(domains),
        byTriggerAction: groupedTotals(triggers)
    };
}

function reportLocation({ profileId, profileDir, trafficDir, profileIdentity }, includeLocalPaths) {
    return {
        profileId: redactProfileId(profileId),
        ...(profileIdentity === 'mixed' && { profileIdentity }),
        ...(includeLocalPaths === true && { profileDir, trafficDir })
    };
}

function reportArtifactPaths(artifacts, includeLocalPaths) {
    if (includeLocalPaths === true) return artifacts;
    return Object.fromEntries(Object.entries(artifacts).map(([field, file]) => [
        field, file == null ? null : redactDiagnosticText(path.basename(file))
    ]));
}

function hasEmptyLedgerCheckpoint(indexData) {
    const checkpoint = indexData?.integrity;
    const genesis = '0'.repeat(64);
    return checkpoint?.eventCount === 0 && checkpoint.chainHeadHash === genesis &&
        (checkpoint.genesisHash === undefined || checkpoint.genesisHash === genesis);
}

function reportCaptureLimits(indexData) {
    const stoppedReason = indexData?.captureLimits?.stoppedReason;
    if (['event-limit', 'storage-limit', 'pending-event-limit'].includes(stoppedReason)) return { stoppedReason };
}

/**
 * List and summarize all profiles under the given directory that contain traffic.
 *
 * @param {string} profilesDir
 * @param {object} [options]
 * @param {boolean} [options.includeLocalPaths=false] Include exact locations in private output.
 * @returns {Array<object>}
 */
export function listTrafficProfiles(profilesDir, { includeLocalPaths = false } = {}) {
    const resolvedDir = resolveProfilesRoot(resolveProfilesDir(profilesDir));
    const summaries = [];

    for (const { profileId, profileDir, trafficDir } of enumerateProfileTrafficPaths(resolvedDir)) {
        const attributionIndexPath = path.join(trafficDir, 'attribution-index.json');
        const trafficNdjsonPath = path.join(trafficDir, 'traffic.ndjson');
        const sslKeyLogPath = path.join(trafficDir, 'sslkeylog.txt');

        const indexData = readJsonSafe(attributionIndexPath);
        const ledger = readNdjsonBytes(trafficNdjsonPath);
        if (ledger === null && !hasEmptyLedgerCheckpoint(indexData)) continue;

        const captureLimits = reportCaptureLimits(indexData);
        const preTlsWireLogPath = path.join(trafficDir, getCaptureWireLogFileName(indexData?.integrity));
        const { totals, anomalies, indexWarnings, steps, domains, triggers, profileIds, profileTraces, profileContinuityUnproven } =
            summarizeCapture(parseNdjsonEvents(ledger), indexData);
        const paths = { profileId, profileDir, trafficDir };
        const identity = captureProfileSelector(paths).resolve(profileIds, indexData?.session, profileTraces, profileContinuityUnproven);
        const session = shareableRecord(identity.profileIdentity === 'mixed' ? {} : indexData?.session || {});

        const location = reportLocation({ ...paths, ...identity }, includeLocalPaths);
        summaries.push({
            ...redactDiagnosticMetadata({
                accountId: session.accountId ?? null,
                accountEmail: session.accountEmail ?? null,
                os: session.os ?? null,
                proxyServer: session.proxyServer ?? null,
                startedAt: session.startedAt ?? null,
                endedAt: session.endedAt ?? null,
                totals,
                anomalyCount: anomalies.length,
                indexWarnings,
                steps: [...steps].map(redactDiagnosticText),
                domains: [...domains],
                triggers: [...triggers]
            }),
            ...location,
            ...(captureLimits && { captureLimits }),
            artifacts: reportArtifactPaths({
                trafficNdjsonPath: ledger !== null ? trafficNdjsonPath : null,
                attributionIndexPath: fs.existsSync(attributionIndexPath) ? attributionIndexPath : null,
                sslKeyLogPath: fs.existsSync(sslKeyLogPath) ? sslKeyLogPath : null,
                preTlsWireLogPath: fs.existsSync(preTlsWireLogPath) ? preTlsWireLogPath : null
            }, includeLocalPaths)
        });
    }

    return summaries;
}

function shareableRecord(record, {
    body, url = record?.url, recordBodies = true, redirects, requestMethod, displayCorrelationId, displayStepName
} = {}) {
    if (!record || typeof record !== 'object') return record;
    const {
        headers, headersArray, cookieObservations, cookieJarId, bodyPreview, postData, payloadFile, payloadStorage,
        postDataSha256, bodySha256, payloadSha256, eventHash, prevEventHash, ...metadata
    } = record;
    const safe = { ...redactDiagnosticMetadata(redactPressKeys(metadata)) };
    if (displayCorrelationId) {
        for (const field of ['correlationId', 'redirectedFromCorrelationId']) {
            if (typeof record[field] === 'string') safe[field] = displayCorrelationId(record[field]);
        }
    }
    if (safe.attribution && typeof safe.attribution === 'object') safe.attribution = { ...safe.attribution };
    if (headers || headersArray) Object.assign(safe, redactSensitiveHeaders({ headers, headersArray }));
    if (record.type === 'ingress') safe.bodyBytes = observedHttpResponseBodyBytes(record, requestMethod);
    if (UNKNOWN_WS_COUNT_FIELDS.has(record.type)) safe.payloadBytes = observedWebSocketPayloadBytes(record);

    if (Array.isArray(cookieObservations)) {
        safe.cookieObservations = cookieObservations.filter(Boolean).map(
            ({ value, rawValue, valueSha256, ...observation }) => ({
                ...redactDiagnosticMetadata(observation), maskedValue: '[REDACTED]'
            })
        );
    }
    if (safe.maskedPreview != null) safe.maskedPreview = '[REDACTED]';
    if (safe.signatureName && safe.location === 'body') {
        safe.valueSha256 = null;
        safe.valueLength = null;
    }
    if (Array.isArray(safe.platformSignatures)) {
        safe.platformSignatures = safe.platformSignatures.filter(Boolean).map((signature) => ({
            ...signature,
            maskedPreview: '[REDACTED]',
            ...(signature.location === 'body' && { valueSha256: null, valueLength: null })
        }));
    }
    if (displayStepName && typeof record.previousStep === 'string') {
        safe.previousStep = displayStepName(record.previousStep);
    }
    for (const [source, target] of [[record, safe], [record.attribution, safe.attribution]]) {
        if (!target || typeof target !== 'object') continue;
        if (displayStepName && typeof source?.actionStep === 'string') {
            target.actionStep = displayStepName(source.actionStep);
        }
        if (target.triggerAction) {
            target.triggerAction = redactTriggerAction(target.triggerAction);
            if (displayStepName && typeof source?.triggerAction?.actionStep === 'string') {
                target.triggerAction.actionStep = displayStepName(source.triggerAction.actionStep);
            }
        }
    }
    if (Object.hasOwn(record, 'payloadFile')) safe.payloadFile = body?.payloadFile ?? null;
    if (Object.hasOwn(record, 'postDataSha256')) safe.postDataSha256 = null;
    if (Object.hasOwn(record, 'bodySha256')) safe.bodySha256 = null;
    if (Object.hasOwn(record, 'payloadSha256')) safe.payloadSha256 = null;
    if (['stored', 'failed', 'omitted'].includes(payloadStorage?.status)) {
        safe.payloadStorage = { status: payloadStorage.status };
        if (Number.isSafeInteger(payloadStorage.bytes) && payloadStorage.bytes >= 0) {
            safe.payloadStorage.bytes = payloadStorage.bytes;
        }
        if (['write-failed', 'storage-limit'].includes(payloadStorage.reason)) {
            safe.payloadStorage.reason = payloadStorage.reason;
        }
    }
    if (Object.hasOwn(record, 'bodyPreview') || Object.hasOwn(record, 'postData')) {
        const preview = body === undefined
            ? readCaptureExportBody(null, record, { recordBodies, url, redirects }).text
            : body.text;
        if (Object.hasOwn(record, 'bodyPreview')) safe.bodyPreview = preview;
        if (Object.hasOwn(record, 'postData')) safe.postData = preview;
    }
    return safe;
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
            url: redactUrlSecrets(eg?.url || inEv?.url),
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
 * `actionStep`, redirect chain, timing, and shareable body projections.
 *
 * @param {object} params
 * @param {string} params.profileId
 * @param {string} params.trafficDir
 * @param {string} params.correlationId
 * @param {Array<object>} params.events
 * @param {Array<object>} [params.anomalies=[]]
 * @param {boolean} [params.recordBodies] - Set false to omit bodies permitted by the capture policy.
 * @param {boolean} [params.includeLocalPaths=false] Include exact locations in private output.
 * @returns {object}
 */
export function reconstructTransactionWireDump({
    profileId,
    trafficDir,
    correlationId,
    events = [],
    anomalies = [],
    recordBodies,
    trustedLocal = false,
    includeLocalPaths = false,
    [WIRE_EXPORT_INDEX]: suppliedIndex
}) {
    const { bodyPolicy, indexData } = suppliedIndex ?? (
        recordBodies === false
            ? { bodyPolicy: { recordBodies: false, reason: 'export-disabled' } }
            : readCaptureExportIndex(trafficDir, { recordBodies, trustedLocal })
    );
    const corrEvents = events.filter((e) => e && e.correlationId === correlationId);
    const traceId = captureEventTraceId(corrEvents[0]);
    if (corrEvents.some((event) => captureEventTraceId(event) !== traceId)) {
        throw new Error('Correlation ID matches multiple recording sessions in the selected traffic capture');
    }
    const recorded = observedProfileIdentity(new Set(corrEvents.map(captureEventProfileId)));
    if (recorded.profileIdentity === 'mixed') {
        throw new Error('Correlation ID has multiple recorded profile identities');
    }
    if (suppliedIndex?.useRecordedProfileId) profileId = recorded.profileId ?? profileId;

    const ownership = suppliedIndex?.ownership ?? createCaptureTransactionIndex(events);
    const transaction = ownership.get(corrEvents[0]);
    const accounts = new Set(corrEvents.map(captureEventAccountId).filter((id) => id !== null));
    if (accounts.size > 1) throw new Error('Correlation ID matches multiple recorded accounts');
    if (transaction?.hasAmbiguousAlias) throw new Error('Correlation ID has ambiguous recorded profile identity');
    if (corrEvents.some((event) => ownership.get(event) !== transaction)) {
        throw new Error('Correlation ID matches multiple recorded transactions');
    }

    const traceEvents = events.filter((event) => event && captureEventTraceId(event) === traceId);
    const traceProfileIds = new Set(traceEvents.map((event) => validRecordedProfileId(captureEventProfileId(event))));
    const mixedTrace = observedProfileIdentity(traceProfileIds).profileIdentity === 'mixed';
    const recordedLabel = redactProfileId(recorded.profileId);
    const aliasOwners = [...traceProfileIds].filter((id) => id && id !== recordedLabel && redactProfileId(id) === recordedLabel);
    const ownsObservation = (record) => {
        const source = record?.[SOURCE_EVENT] ?? record;
        const observedAccount = ownership.get(source)?.accountId ?? captureEventAccountId(source);
        if (observedAccount !== (transaction?.accountId ?? null)) return false;
        const observedId = validRecordedProfileId(captureEventProfileId(source));
        if (!recorded.profileId || !observedId) return !mixedTrace;
        if (aliasOwners.length > 1) return observedId === recorded.profileId && !isAnonymousProfileId(observedId);
        return sameRecordedProfile(recorded.profileId, observedId);
    };
    if (corrEvents.length > 1 && corrEvents.some((event) => !ownsObservation(event))) {
        throw new Error('Correlation ID has ambiguous recorded profile identity');
    }
    const request = corrEvents.find((e) => e.type === 'egress') || null;
    const response = corrEvents.find((e) => e.type === 'ingress') || null;
    const requestUrl = request?.url || response?.url;
    const redirects = suppliedIndex?.redirects ??
        (bodyPolicy.recordBodies ? createCaptureRedirectBodyCheck(events) : undefined);
    const ownedEvents = traceEvents.filter(ownsObservation);
    const ownedCorrelationIds = new Set(ownedEvents.map((event) => event.correlationId));
    const excludedCorrelationIds = new Set(traceEvents.map((event) => event.correlationId)
        .filter((id) => id && !ownedCorrelationIds.has(id)));
    const rawRedirectChain = buildRedirectChain(correlationId, ownedEvents);
    const displayCorrelationId = createCorrelationIdProjection([
        correlationId,
        ...corrEvents.map((event) => event.redirectedFromCorrelationId),
        ...rawRedirectChain.flatMap((hop) => [hop.correlationId, hop.redirectedFromCorrelationId])
    ]);
    const publicCorrelationId = displayCorrelationId(correlationId);
    const displayRedirectId = (id) => excludedCorrelationIds.has(id) ? null : displayCorrelationId(id);
    const redirectChain = rawRedirectChain.map((hop) => ({
        ...hop,
        correlationId: displayCorrelationId(hop.correlationId),
        redirectedFromCorrelationId: displayRedirectId(hop.redirectedFromCorrelationId)
    }));
    const displayStepName = suppliedIndex?.displayStepName ?? createStepNameProjection(events, indexData);
    const project = (record, options) => {
        const projected = shareableRecord(record, {
            recordBodies: capturePolicyAllowsBody(bodyPolicy, record), redirects, requestMethod: request?.method,
            displayStepName, ...options
        });
        if (record?.correlationId != null) projected.correlationId = displayCorrelationId(record.correlationId);
        if (record?.redirectedFromCorrelationId != null) {
            projected.redirectedFromCorrelationId = displayRedirectId(record.redirectedFromCorrelationId);
        }
        return projected;
    };
    const projectBody = (record) => readCaptureExportBody(trafficDir, record, {
        recordBodies: capturePolicyAllowsBody(bodyPolicy, record),
        redirects,
        trustedLocal,
        url: requestUrl,
        payloadManifest: indexData?.integrity?.payloadManifest
    });
    const reqBody = projectBody(request);
    const resBody = projectBody(response);
    const egress = project(request, { body: reqBody, url: requestUrl });
    const ingress = project(response, { body: resBody, url: requestUrl });
    const finished = project(corrEvents.find((e) => e.type === 'request-finished') || null);
    const failed = project(corrEvents.find((e) => e.type === 'request-failed') || null);
    const securityBlock = project(corrEvents.find((e) => e.type === 'security-block') || null);
    const wsEvents = corrEvents.filter((e) => typeof e.type === 'string' && e.type.startsWith('ws-'))
        .map((event) => project(event));

    const matchingAnomalies = anomalies.filter((a) =>
        a && a.attributionStatus !== 'unresolved' &&
        a.correlationId === correlationId && captureEventTraceId(a) === traceId && ownsObservation(a)
    ).map((anomaly) => project(anomaly));

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

    const requestPayload = reqBody.text;
    const responsePayload = resBody.text;
    const indexTraceId = indexData?.session?.traceId ?? null;
    const captureLimits = primaryEvent && traceId === indexTraceId && ownsObservation(indexData?.session)
        ? reportCaptureLimits(indexData)
        : null;

    const publicLocation = reportLocation({ profileId, trafficDir }, includeLocalPaths);
    const durationMs = finished?.durationMs ?? failed?.durationMs ?? null;
    const timing = finished?.timing ?? null;
    const sizes = finished?.sizes ?? null;
    const redirectedFromCorrelationId =
        egress?.redirectedFromCorrelationId || ingress?.redirectedFromCorrelationId || null;

    const lines = [];
    lines.push('================================================================================');
    lines.push(`PRE-TLS / POST-TLS WIRE TRANSACTION DUMP [${publicCorrelationId}]`);
    lines.push('================================================================================');
    lines.push(`Profile ID       : ${publicLocation.profileId}`);
    lines.push(`Correlation ID   : ${publicCorrelationId}`);
    lines.push(`Action Step      : ${actionStep} (stepIndex=${stepIndex})`);

    if (triggerAction) {
        const trigType = triggerAction.actionType || triggerAction.type || 'unknown';
        const trigTarget = triggerAction.target || triggerAction.selector || '';
        const elapsed = triggerAction.elapsedSinceActionMs !== undefined
            ? `${triggerAction.elapsedSinceActionMs}ms`
            : 'n/a';
        lines.push(`Trigger Action   : ${trigType} target="${trigTarget}" (elapsed=${elapsed})${inferredLabel(triggerAction)}`);
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

    if (captureLimits) lines.push('Capture stopped  : ' + captureLimits.stoppedReason);
    for (const [kind, event, body] of [['Request', egress, reqBody], ['Response', ingress, resBody]]) {
        if (event?.payloadStorage?.status === 'failed') lines.push(kind + ' attachment write failed');
        if (event?.payloadStorage?.status === 'omitted') lines.push(kind + ' attachment omitted by storage limit');
        if (body.reason === 'payload-integrity') lines.push(kind + ' attachment failed integrity verification');
    }

    if (egress) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(
            `>>> EGRESS [PRE-TLS NECKO CHANNEL] [${publicCorrelationId}] ${egress.timestamp || ''}`
        );
        let targetPath;
        if (egress.url) {
            try {
                const requestUrl = new URL(egress.url, 'https://capture.invalid');
                targetPath = requestUrl.pathname + requestUrl.search;
            } catch {
                // Legacy entries can have only pathname and searchParams available.
            }
        }
        if (!targetPath) {
            const entries = Object.entries(egress.searchParams || {}).flatMap(([name, value]) =>
                [].concat(value).map((item) => [name, item])
            );
            const search = new URLSearchParams(entries).toString();
            targetPath = redactUrlSecrets((egress.pathname || '/') + (search ? '?' + search : ''));
        }
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
            `<<< INGRESS [POST-TLS NECKO CHANNEL] [${publicCorrelationId}] ${ingress.timestamp || ''}`
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
        } else if (ingress.bodyBytes === 0 || sizes?.responseBodySize === 0) {
            lines.push('[no ingress body]');
        } else {
            const wireBytes = sizes?.responseBodySize;
            const measuredSize = Number.isSafeInteger(wireBytes) && wireBytes > 0 ? ` (${wireBytes} wire bytes)` : '';
            lines.push(`[ingress body unavailable${measuredSize}]`);
        }
    }

    if (failed) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(
            `!!! FAILURE [NECKO CHANNEL ERROR] [${publicCorrelationId}] ${failed.failureText || 'UNKNOWN_ERROR'}`
        );
    }

    if (securityBlock) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(
            `!!! SECURITY BLOCK [ZINIAO ACTIVE GUARD] [${publicCorrelationId}] type=${securityBlock.blockType || 'probe'} reason="${securityBlock.reason || securityBlock.failureText || ''}"`
        );
    }

    if (wsEvents.length > 0) {
        lines.push('--------------------------------------------------------------------------------');
        lines.push(`=== WEBSOCKET FRAMES [${publicCorrelationId}] (${wsEvents.length} events) ===`);
        for (const wsEv of wsEvents) {
            const bytes = UNKNOWN_WS_COUNT_FIELDS.has(wsEv.type) ? ` bytes=${wsEv.payloadBytes ?? 'unknown'}` : '';
            lines.push(`[${wsEv.type}] ${wsEv.timestamp || ''}${bytes}`);
        }
    }

    lines.push('================================================================================');
    const wireDump = primaryEvent
        ? joinTerminalLines(lines)
        : escapeTerminalText(`Correlation ID "${publicCorrelationId}" not found in profile "${publicLocation.profileId}".`);

    return {
        mode: 'wire-dump',
        bodyPolicyReason: bodyPolicy.reason,
        ...(captureLimits && { captureLimits }),
        ...publicLocation,
        correlationId: publicCorrelationId,
        found: Boolean(primaryEvent),
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
        requestPayloadExistsOnDisk: reqBody.byteLength !== null,
        ...(reqBody.reason === 'payload-integrity' && { requestPayloadOmittedReason: reqBody.reason }),
        responsePayload,
        responsePayloadFile: ingress?.payloadFile || null,
        responsePayloadExistsOnDisk: resBody.byteLength !== null,
        ...(resBody.reason === 'payload-integrity' && { responsePayloadOmittedReason: resBody.reason }),
        anomalies: matchingAnomalies,
        wireDump
    };
}

/**
 * Group matching NDJSON events into correlated transaction summaries.
 *
 * @param {Array<object>} events
 * @param {function(object): object} project
 * @returns {Array<object>}
 */
function buildTransactionsList(events, project, getTransactionKey) {
    const txMap = new Map();

    for (const event of events) {
        if (!captureTransactionPhase(event)) continue;
        const txKey = getTransactionKey(event);
        if (txKey === null) continue;

        // Group before projecting the recorded identities.
        const ev = project(event);
        if (!txMap.has(txKey)) {
            txMap.set(txKey, {
                correlationId: ev.correlationId,
                traceId: captureEventTraceId(ev),
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
        const tx = txMap.get(txKey);
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

function buildCookieLineageFromEvents(events, { includeEvent, includeDigests = false, displayCorrelationId }) {
    const lineage = new CookieLineage({ limit: Infinity });
    lineage.observeAll(events, includeEvent);
    const snapshot = lineage.snapshot();
    if (includeDigests) return snapshot;

    const byDisplayName = new Map();
    const displayReference = (id) => typeof id === 'string' ? displayCorrelationId(id)
        : Number.isSafeInteger(id) ? id : null;
    for (const [name, entry] of Object.entries(snapshot)) {
        const displayName = redactDiagnosticText(name);
        const instances = byDisplayName.get(displayName) ?? [];
        for (const {
            lastValueSha256, valueHistory, firstSetByCorrelationId, lastSetByCorrelationId,
            lastSentByCorrelationId, sentInCorrelationIds, ...cookie
        } of entry.instances ?? [entry]) {
            instances.push({
                ...redactDiagnosticMetadata(cookie),
                name: displayName,
                firstSetByCorrelationId: displayReference(firstSetByCorrelationId),
                lastSetByCorrelationId: displayReference(lastSetByCorrelationId),
                lastSentByCorrelationId: displayReference(lastSentByCorrelationId),
                sentInCorrelationIds: sentInCorrelationIds.map(displayReference),
                valueHistory: valueHistory.map(({ valueSha256, correlationId, ...observation }) => ({
                    ...redactDiagnosticMetadata(observation),
                    correlationId: displayReference(correlationId)
                }))
            });
        }
        byDisplayName.set(displayName, instances);
    }
    return Object.fromEntries(Array.from(byDisplayName, ([name, instances]) => [
        name,
        instances.length === 1
            ? instances[0]
            : { name, isAntiBotToken: instances.some((entry) => entry.isAntiBotToken), instances }
    ]));
}

/** Rebuild platform signatures from recorded egress, including legacy captures. */
function buildPlatformSignaturesFromEvents(events = []) {
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
                traceId: captureEventTraceId(ev),
                [SOURCE_EVENT]: ev,
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
 * @param {string} [options.trafficDir] Explicit capture directory. A profile selector must match its directory ID or standalone recording identity.
 * @param {boolean} [options.includeLocalPaths=false] Include exact locations in private output.
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
 * @param {boolean} [options.recordBodies] - Set false to omit bodies permitted by the capture policy.
 * @returns {object}
 */
export function queryProfileTraffic(options = {}) {
    if (options.trafficDir != null && (typeof options.trafficDir !== 'string' || !options.trafficDir.trim())) {
        throw new Error('Traffic directory must be nonempty');
    }
    const explicitProfilesDir = options.trafficDir && options.profilesDir != null
        ? resolveProfilesDir(options.profilesDir) : null;
    const profilesDir = options.trafficDir ? null : resolveProfilesRoot(resolveProfilesDir(options.profilesDir));
    const trustedLocal = options.trustedLocal === true;
    const includeLocalPaths = options.includeLocalPaths === true;
    const verifyResolvedCapture = (paths, selector = null) => {
        const { profileDir, trafficDir } = paths;
        const scope = captureProfileSelector(paths, selector);
        let identity = { profileId: scope.fallbackProfileId };
        const nativeDir = options.trafficDir ? options.nativeDir
            : resolveProfileNativeDirectory(path.basename(profileDir), profilesDir, { trustedLocal });
        const captureDir = !options.trafficDir && nativeDir ? path.join(path.dirname(nativeDir), 'traffic') : trafficDir;
        const integrity = verifyTrafficIntegrity(captureDir, {
            nativeDir, trustedLocal,
            validateCaptureProfile: (profileIds, session, profileTraces, profileContinuityUnproven) => {
                identity = scope.resolve(profileIds, session, profileTraces, profileContinuityUnproven);
            }
        });
        return {
            location: reportLocation({ ...paths, ...identity }, includeLocalPaths),
            integrity: structuredClone(redactDiagnosticMetadata(integrity))
        };
    };
    const targetProfileId = options.profile ?? options.profileId ?? null;
    const correlationId =
        options.dumpWire || options.correlation || options.correlationId || null;
    const requestedCookieName = options.cookie ?? options.cookieName;
    const cookieNameFilter = typeof requestedCookieName === 'string' ? requestedCookieName.trim() : null;
    const cookiesRequested = Boolean(options.cookies || cookieNameFilter !== null);
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

    const filterInputs = [
        options.step, options.actionStep, options.trigger, options.triggerAction, options.domain, options.host,
        options.status, options.correlation, options.correlationId, options.dumpWire,
        options.platform, options.platformName
    ];
    if (filterInputs.some((value) => typeof value === 'string' && !value.trim())) {
        const context = options.exportHar ? 'HAR export' : 'Query';
        throw new Error(`${context} filter values must be nonempty`);
    }
    if (filters.status != null &&
        ((typeof filters.status !== 'string' && typeof filters.status !== 'number') ||
            !/^(?:0|[1-5](?:[0-9]{2}|xx))$/i.test(String(filters.status).trim()))) {
        throw new Error('Status filter must be an HTTP status code, a class like 4xx, or 0 for blocked requests');
    }
    const publicFilters = Object.fromEntries(Object.entries(filters).map(([name, value]) => [
        name, typeof value === 'string' ? redactDiagnosticText(value) : value
    ]));
    const hasEventFilters = Boolean(filters.step || filters.trigger || filters.domain || filters.status != null);
    if (options.exportHar &&
        (options.verifyIntegrity || filters.anomaliesOnly || cookiesRequested || signaturesRequested || platformFilter)) {
        throw new Error('HAR export supports only step, trigger, domain, status, and correlation filters');
    }
    if (options.verifyIntegrity && (hasEventFilters || filters.anomaliesOnly ||
        cookiesRequested || signaturesRequested || platformFilter ||
        (correlationId && (targetProfileId !== null || options.trafficDir)))) {
        throw new Error('Integrity verification checks entire captures; use a profile or correlation to select one');
    }
    if (((cookiesRequested || signaturesRequested) && filters.anomaliesOnly) ||
        (cookiesRequested && signaturesRequested)) {
        throw new Error('Choose one of cookie lineage, platform signatures, or anomaly reporting');
    }
    if (correlationId && !options.exportHar && !options.verifyIntegrity && !cookiesRequested && !signaturesRequested &&
        (hasEventFilters || filters.anomaliesOnly || platformFilter)) {
        throw new Error('Wire dumps reconstruct an entire correlation; choose the correlation without event filters');
    }

    // If no profile is specified and no direct trafficDir or correlationId is given,
    // list and summarize all profiles in profilesDir that have a traffic/ directory
    // (unless --verify-integrity, --export-har, --cookies/--cookie, or --signatures/--platform is requested).
    if (
        targetProfileId === null &&
        !options.trafficDir &&
        !correlationId &&
        !options.verifyIntegrity &&
        !options.exportHar &&
        !hasEventFilters &&
        !filters.anomaliesOnly &&
        !cookiesRequested &&
        !signaturesRequested &&
        !platformFilter
    ) {
        const profiles = listTrafficProfiles(profilesDir, { includeLocalPaths });
        return {
            mode: 'list-profiles',
            ...(includeLocalPaths && { profilesDir }),
            count: profiles.length,
            profiles
        };
    }

    let resolvedPaths = null;
    let selectedEvents;
    if (options.trafficDir) {
        const trafficDir = path.resolve(options.trafficDir);
        resolvedPaths = { profileId: null, profileDir: path.dirname(trafficDir), trafficDir, explicitProfilesDir };
    } else if (targetProfileId !== null) {
        resolvedPaths = resolveProfileTrafficPaths(profilesDir, targetProfileId);
    } else if (correlationId) {
        const retainEvents = !options.exportHar;
        const readOptions = retainEvents ? { trustedLocal } : {
            trustedLocal, maxBytes: MAX_HAR_LEDGER_BYTES, maxRecordBytes: MAX_HAR_RECORD_BYTES
        };
        for (const candidate of enumerateProfileTrafficPaths(profilesDir)) {
            const ledger = path.join(candidate.trafficDir, 'traffic.ndjson');
            const events = [];
            let matched = false;
            for (const event of iterateNdjsonEvents(ledger, readOptions)) {
                if (retainEvents) events.push(event);
                if (event?.correlationId !== correlationId) continue;
                matched = true;
                if (!retainEvents) break;
            }
            if (!matched) continue;
            if (resolvedPaths) {
                throw new Error('Correlation ID matches multiple profiles. Use --profile for a unique ID or --traffic-dir for an exact capture.');
            }
            resolvedPaths = candidate;
            if (retainEvents) selectedEvents = events;
        }
    } else if (options.verifyIntegrity) {
        const candidates = enumerateProfileTrafficPaths(profilesDir);
        if (candidates.length === 1) {
            resolvedPaths = candidates[0];
        } else if (candidates.length > 1) {
            const perProfile = candidates.map((cand) => {
                const { location, integrity } = verifyResolvedCapture(cand);
                return { ...location, ...integrity };
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
                ...(includeLocalPaths && { profilesDir }),
                valid: allValid,
                scope: perProfile.every((profile) => profile.scope === 'profile') ? 'profile' : 'capture',
                unverifiedNativeArtifacts: perProfile.flatMap((profile) =>
                    profile.unverifiedNativeArtifacts.map((name) => `${profile.profileId}/${name}`)
                ),
                eventCount: totalEvents,
                verifiedPayloads: totalPayloads,
                payloadManifestVerified: perProfile.every((profile) => profile.payloadManifestVerified),
                unverifiedPayloads: perProfile.flatMap((profile) =>
                    profile.unverifiedPayloads.map((entry) => ({ ...entry, path: profile.profileId + '/' + entry.path }))
                ),
                payloadCaptureIssues: perProfile.reduce((totals, profile) => ({
                    writeFailures: totals.writeFailures + profile.payloadCaptureIssues.writeFailures,
                    storageOmissions: totals.storageOmissions + profile.payloadCaptureIssues.storageOmissions
                }), { writeFailures: 0, storageOmissions: 0 }),
                chainHeadHash: perProfile[perProfile.length - 1]?.chainHeadHash || '0'.repeat(64),
                errors: allErrors,
                profiles: perProfile
            };
        }
    } else {
        const candidates = enumerateProfileTrafficPaths(profilesDir).filter(({ trafficDir }) =>
            options.exportHar ||
            fs.lstatSync(path.join(trafficDir, 'traffic.ndjson'), { throwIfNoEntry: false }) ||
            hasEmptyLedgerCheckpoint(readCaptureExportIndex(trafficDir, { trustedLocal }).indexData)
        );
        if (candidates.length > 1) {
            throw new Error('Multiple traffic captures are available. Use --profile for a unique ID or --traffic-dir for an exact capture.');
        }
        resolvedPaths = candidates[0] ?? null;
    }

    if (!resolvedPaths && correlationId && targetProfileId === null && !options.trafficDir) {
        throw new Error(`Correlation ID "${correlationId}" not found in traffic captures`);
    }
    if (!resolvedPaths || (options.trafficDir && !fs.existsSync(resolvedPaths.trafficDir))) {
        throw new Error('Traffic directory not found for the selected profile');
    }

    const { trafficDir } = resolvedPaths;
    if (options.verifyIntegrity) {
        const { location, integrity } = verifyResolvedCapture(resolvedPaths, targetProfileId);
        return { mode: 'verify-integrity', ...location, ...integrity, integrity };
    }

    const scope = captureProfileSelector(resolvedPaths, targetProfileId);
    if (options.exportHar) {
        const customHarPath =
            typeof options.exportHar === 'string' &&
            options.exportHar.trim().length > 0 &&
            options.exportHar !== 'true'
                ? path.resolve(options.exportHar)
                : undefined;
        let identity;
        const harResult = exportTrafficToHar(trafficDir, customHarPath, { profileId: scope.fallbackProfileId }, {
            recordBodies: options.recordBodies,
            trustedLocal,
            requiredCorrelationId: correlationId,
            validateCaptureProfile: (profileIds, session, profileTraces, profileContinuityUnproven) => {
                identity = scope.resolve(profileIds, session, profileTraces, profileContinuityUnproven);
            },
            matchTransaction: hasEventFilters || correlationId
                ? (transaction) => recordMatchesFilters(transaction, filters) : undefined
        });
        return {
            mode: 'export-har',
            ...reportLocation({ ...resolvedPaths, ...identity }, includeLocalPaths),
            ...reportArtifactPaths({ harPath: harResult.harPath, outputPath: harResult.outputPath }, includeLocalPaths),
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
    const neckoMozLogPath = path.join(trafficDir, 'necko-pre-tls.moz_log');

    const ledger = selectedEvents === undefined ? readNdjsonBytes(trafficNdjsonPath, { trustedLocal }) : null;
    const ledgerExists = selectedEvents !== undefined || ledger !== null;
    const allEvents = selectedEvents ?? [...parseNdjsonEvents(ledger)];
    const { indexData, bodyPolicy } = readCaptureExportIndex(trafficDir, {
        recordBodies: options.recordBodies, trustedLocal
    });
    const profileIds = new Set();
    const profileTraces = new Set();
    let profileContinuityUnproven = false;
    const profileContinuity = createCaptureProfileContinuityCheck();
    for (const event of allEvents) {
        profileIds.add(captureEventProfileId(event));
        profileTraces.add(captureEventTraceId(event));
        profileContinuityUnproven ||= profileContinuity(event);
    }
    const identity = scope.resolve(profileIds, indexData?.session, profileTraces, profileContinuityUnproven);
    if (!ledgerExists && !hasEmptyLedgerCheckpoint(indexData)) {
        throw new Error('Traffic ledger is missing and there is no zero-event checkpoint');
    }
    const captureLimits = reportCaptureLimits(indexData);
    const coverage = captureLimits ? { captureLimits } : {};
    const { profileId } = identity;
    const mixedProfiles = identity.profileIdentity === 'mixed';
    const profileScoped = mixedProfiles || observedProfileIdentity(profileIds).profileIdentity === 'mixed';
    const ownership = createCaptureTransactionIndex(allEvents, { profileScoped });
    const getTransactionKey = (record) => ownership.get(record?.[SOURCE_EVENT] ?? record);
    const publicLocation = reportLocation({ ...resolvedPaths, ...identity }, includeLocalPaths);

    // Associate request observations with the response status of their transaction.
    const txStatusByCorrelation = new Map();
    const txTriggerByCorrelation = new Map();
    const requestsByTransaction = new Map();
    const redirects = bodyPolicy.recordBodies ? createCaptureRedirectBodyCheck() : undefined;
    for (const ev of allEvents) {
        redirects?.observe(ev);
        const txKey = getTransactionKey(ev);
        if (txKey === null) continue;
        const status = observedStatus(ev.status);
        if (status !== null) {
            txStatusByCorrelation.set(txKey, status);
        } else if (ev.type === 'security-block' && !txStatusByCorrelation.has(txKey)) {
            txStatusByCorrelation.set(txKey, 0);
        }
        const trigger = extractTriggerAction(ev);
        if (trigger && !txTriggerByCorrelation.has(txKey)) {
            txTriggerByCorrelation.set(txKey, trigger);
        }
        if (ev.type === 'egress' && capturePolicyAllowsBody(bodyPolicy, ev)) {
            requestsByTransaction.set(txKey, ev);
        }
    }
    const allPlatformSignatures = !cookiesRequested || platformFilter ? buildPlatformSignaturesFromEvents(allEvents) : [];
    const platformCorrelations = platformFilter ? new Set(allPlatformSignatures
        .filter((signature) => signature.correlationId && String(signature.platform || '').toLowerCase() === platformFilter)
        .map(getTransactionKey)) : null;
    const matchesTransactionFilters = (record) => recordMatchesFilters(record, filters, txStatusByCorrelation, {
        useTransactionStatusFallback: true, txTriggerByCorrelation, platformCorrelations, getTransactionKey
    });

    const displayCorrelationId = createCorrelationIdProjection(allEvents.flatMap((event) => [
        event.correlationId, event.redirectedFromCorrelationId
    ]));
    const displayStepName = createStepNameProjection(allEvents, indexData);
    const project = (record) => {
        const request = requestsByTransaction.get(getTransactionKey(record));
        return shareableRecord(record, {
            displayCorrelationId,
            displayStepName,
            recordBodies: !getTransactionKey(record)?.hasSharedCorrelation && capturePolicyAllowsBody(bodyPolicy, record),
            url: request?.url ?? record?.url,
            requestMethod: request?.method,
            redirects
        });
    };

    if (cookiesRequested) {
        const fullCookieLineage = buildCookieLineageFromEvents(allEvents, {
            includeEvent: matchesTransactionFilters, includeDigests: true
        });
        let cookie = null;
        let cookieLineage = fullCookieLineage;
        if (cookieNameFilter !== null) {
            cookie = Object.hasOwn(fullCookieLineage, cookieNameFilter)
                ? fullCookieLineage[cookieNameFilter]
                : Object.values(fullCookieLineage).find((entry) =>
                    entry.name.toLowerCase() === cookieNameFilter.toLowerCase()
                ) || null;
            cookieLineage = cookie ? Object.fromEntries([[cookie.name, cookie]]) : {};
        }
        const cookies = Object.values(cookieLineage).flatMap((entry) => entry.instances || [entry]);
        return {
            mode: 'cookies',
            ...coverage,
            privacy: 'private',
            ...publicLocation,
            filters: publicFilters,
            cookieName: cookieNameFilter,
            found: cookies.length > 0,
            count: cookies.length,
            antiBotTokenCount: cookies.filter((entry) => entry.isAntiBotToken).length,
            cookie,
            cookies,
            cookieLineage
        };
    }

    const filteredSignatures = allPlatformSignatures.filter((sig) =>
        recordMatchesFilters(sig, filters, txStatusByCorrelation, {
            useTransactionStatusFallback: true, getTransactionKey
        })
    ).map(project);
    const platformCounts = new Map();
    for (const sig of filteredSignatures) {
        if (!sig?.platform) continue;
        platformCounts.set(sig.platform, (platformCounts.get(sig.platform) || 0) + 1);
    }
    const filteredByPlatform = Object.fromEntries(platformCounts);

    if (signaturesRequested) {
        return {
            mode: 'signatures',
            ...coverage,
            ...publicLocation,
            filters: publicFilters,
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

    const { summaryIndex, totals: captureTotals, anomalies, indexWarnings } =
        summarizeCapture(allEvents, indexData, ownership);
    const rawAnomalies = anomalies.map((anomaly) => {
        const trigger = txTriggerByCorrelation.get(getTransactionKey(anomaly));
        return !anomaly.triggerAction && trigger ? { ...anomaly, triggerAction: trigger } : anomaly;
    }).sort((a, b) => String(a.timestamp ?? '').localeCompare(String(b.timestamp ?? '')));

    // Mode 1: Wire dump / correlationId reconstruction
    if (correlationId) {
        return {
            ...reconstructTransactionWireDump({
                profileId,
                trafficDir,
                correlationId,
                events: allEvents,
                anomalies: rawAnomalies,
                trustedLocal,
                includeLocalPaths,
                [WIRE_EXPORT_INDEX]: { bodyPolicy, indexData, redirects, ownership, displayStepName, useRecordedProfileId: mixedProfiles }
            }),
            indexWarnings
        };
    }

    // Filter anomalies and NDJSON events
    const matchedAnomalies = rawAnomalies.filter(matchesTransactionFilters);
    const filteredAnomalies = matchedAnomalies.map(project);

    // Include related request and response observations in transaction counts and aggregates.
    const eventsForTransactions = allEvents.filter(matchesTransactionFilters);
    const scopedSummary = hasEventFilters || platformFilter
        ? summarizeFilteredTraffic(eventsForTransactions, txTriggerByCorrelation, getTransactionKey, displayStepName)
        : null;
    const totals = scopedSummary?.totals ?? captureTotals;
    const checkpointSession = !profileScoped && profileTraces.size === 1 && !profileContinuityUnproven
        ? summaryIndex?.session : null;
    const session = project(scopedSummary
        ? selectedTrafficSession([...eventsForTransactions, ...matchedAnomalies], profileId, profileScoped, checkpointSession, ownership)
        : mixedProfiles ? { profileId } : { ...indexData?.session, profileId });

    if (filters.anomaliesOnly) {
        return {
            mode: 'anomalies',
            ...coverage,
            bodyPolicyReason: bodyPolicy.reason,
            ...publicLocation,
            filters: publicFilters,
            session,
            totals,
            count: filteredAnomalies.length,
            indexWarnings,
            anomalies: filteredAnomalies,
            anomaliesAndRiskSignals: filteredAnomalies
        };
    }

    const filteredEvents = eventsForTransactions.map(project);
    const transactions = buildTransactionsList(eventsForTransactions, project, getTransactionKey);
    const indexGroups = scopedSummary ? {} : (summaryIndex ?? {});
    const ledgerGroups = scopedSummary ?? (
        indexGroups.byActionStep && indexGroups.byTriggerAction && indexGroups.byDomain
            ? {}
            : summarizeFilteredTraffic(eventsForTransactions, txTriggerByCorrelation, getTransactionKey, displayStepName)
    );
    const preTlsWireLogPath = path.join(trafficDir, getCaptureWireLogFileName(indexData?.integrity));

    return {
        mode: 'profile-query',
        ...coverage,
        bodyPolicyReason: bodyPolicy.reason,
        ...publicLocation,
        filters: publicFilters,
        session,
        artifacts: reportArtifactPaths({
            trafficNdjsonPath: ledgerExists ? trafficNdjsonPath : null,
            attributionIndexPath: fs.existsSync(attributionIndexPath) ? attributionIndexPath : null,
            sslKeyLogPath: fs.existsSync(sslKeyLogPath) ? sslKeyLogPath : null,
            preTlsWireLogPath: fs.existsSync(preTlsWireLogPath) ? preTlsWireLogPath : null,
            neckoMozLogPath: fs.existsSync(neckoMozLogPath) ? neckoMozLogPath : null
        }, includeLocalPaths),
        totals,
        byActionStep: indexGroups.byActionStep
            ? Object.fromEntries(Object.entries(indexGroups.byActionStep).map(([name, stats]) => [
                displayStepName(name), redactDiagnosticMetadata(stats)
            ]))
            : ledgerGroups.byActionStep,
        byTriggerAction: indexGroups.byTriggerAction
            ? Object.fromEntries(Object.entries(indexGroups.byTriggerAction).map(([id, stats]) => [
                id, redactTriggerAction(redactDiagnosticMetadata(stats))
            ]))
            : ledgerGroups.byTriggerAction,
        byDomain: indexGroups.byDomain ?? ledgerGroups.byDomain,
        cookieLineage: buildCookieLineageFromEvents(allEvents, {
            includeEvent: matchesTransactionFilters, displayCorrelationId
        }),
        platformSignatures: {
            totalDetected: filteredSignatures.length,
            byPlatform: filteredByPlatform,
            signatures: filteredSignatures
        },
        signaturesCount: filteredSignatures.length,
        signatures: filteredSignatures,
        // The native summary has no reliable correlation to the filtered ledger.
        neckoMozLog: scopedSummary || mixedProfiles ? null : (redactNeckoMozLogSummary(indexData?.neckoMozLog) ?? null),
        indexWarnings,
        anomalies: filteredAnomalies,
        anomaliesAndRiskSignals: filteredAnomalies,
        eventsCount: filteredEvents.length,
        events: filteredEvents,
        transactionsCount: transactions.length,
        transactions
    };
}

function escapeTerminalText(value) {
    return String(value).replace(/[\p{Cc}\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/gu, (character) =>
        '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0')
    );
}

function joinTerminalLines(lines) {
    return lines.map(escapeTerminalText).join('\n');
}

function integrityOutcome(result) {
    if (!result.valid) return { statusText: 'INVALID (INTEGRITY CHECK FAILED)', exitCode: 1 };
    if (!result.payloadManifestVerified || result.unverifiedNativeArtifacts?.length) {
        return { statusText: 'INCOMPLETE (SHA-256 HASH CHAIN VERIFIED, SOME MATERIAL UNVERIFIED)', exitCode: 2 };
    }
    return { statusText: 'VALID (SHA-256 HASH CHAIN & PAYLOAD MANIFEST VERIFIED)', exitCode: 0 };
}

function formatCaptureCoverage({ stoppedReason }) {
    return `Warning — Capture coverage is incomplete (recording stopped: ${stoppedReason}).`;
}

/**
 * Format human-readable CLI report for stdout when `--json` is not specified.
 *
 * @param {object} result
 * @returns {string}
 */
export function formatCliReport(result) {
    if (!result) return '';

    const lines = (result.indexWarnings || []).map((warning) => `Warning — ${warning}`);
    if (result.profileIdentity === 'mixed') {
        lines.push('Multiple recording profiles are present in this capture.');
    }
    if (result.mode === 'wire-dump') {
        const blocks = [...lines.map(escapeTerminalText), result.wireDump];
        if (result.found && result.bodyPolicyReason) {
            blocks.push(escapeTerminalText(`   Body export omitted (${result.bodyPolicyReason})`));
        }
        return blocks.join('\n');
    }
    if (result.captureLimits) lines.push(formatCaptureCoverage(result.captureLimits));

    if (result.mode === 'verify-integrity') {
        const { statusText } = integrityOutcome(result);
        lines.push(`🔐 Traffic Cryptographic Integrity Verification — Profile: ${result.profileId}`);
        lines.push(`   Status           : ${statusText}`);
        lines.push(`   Scope            : ${result.scope}`);
        if (result.unverifiedNativeArtifacts?.length) {
            lines.push(`   Unverified profile files: ${result.unverifiedNativeArtifacts.join(', ')}`);
        }
        lines.push(`   Chained Events   : ${result.eventCount}`);
        lines.push(`   Verified Payloads: ${result.verifiedPayloads}`);
        if (result.unverifiedPayloads?.length) {
            lines.push(`   Unverified payloads: ${result.unverifiedPayloads.length}`);
        }
        if (result.payloadCaptureIssues?.writeFailures) {
            lines.push(`   Failed attachment writes: ${result.payloadCaptureIssues.writeFailures}`);
        }
        if (result.payloadCaptureIssues?.storageOmissions) {
            lines.push(`   Attachments omitted by storage limit: ${result.payloadCaptureIssues.storageOmissions}`);
        }
        lines.push(`   Chain Head Hash  : ${result.chainHeadHash}`);
        if (Array.isArray(result.errors) && result.errors.length > 0) {
            lines.push(`   Errors (${result.errors.length}):`);
            for (const err of result.errors) {
                lines.push(`     - ${err}`);
            }
        }
        return joinTerminalLines(lines);
    }

    if (result.mode === 'export-har') {
        lines.push(`📦 W3C HAR 1.2 Archive Exported — Profile: ${result.profileId}`);
        lines.push(`   Output Path : ${result.harPath}`);
        lines.push(`   Entry Count : ${result.entryCount}`);
        lines.push(`   Page Count  : ${result.pageCount ?? 0}`);
        lines.push(`   File Size   : ${result.bytes ?? 0} bytes`);
        if (result.log?._bodyPolicy?.reason) {
            lines.push(`   Body export omitted (${result.log._bodyPolicy.reason})`);
        }
        if (result.log?._captureLimits?.stoppedReason) {
            lines.push('   Capture stopped (' + result.log._captureLimits.stoppedReason + ')');
        }
        return joinTerminalLines(lines);
    }

    if (result.mode === 'list-profiles') {
        if (result.profilesDir) lines.push(`📂 Profiles Directory: ${result.profilesDir}`);
        lines.push(`Found ${result.count} profile(s) with recorded pre-TLS traffic:`);
        for (const p of result.profiles) {
            lines.push(
                `  - ${p.profileId} | OS=${p.os || 'n/a'} | req=${p.totals?.totalRequests ?? 0} res=${p.totals?.totalResponses ?? 0} fail=${p.totals?.failedRequests ?? 0} anomalies=${p.anomalyCount}`
            );
            if (p.profileIdentity === 'mixed') lines.push('    Multiple recording profiles are present in this capture.');
            if (p.captureLimits) lines.push('    ' + formatCaptureCoverage(p.captureLimits));
            for (const warning of p.indexWarnings || []) lines.push(`    Warning — ${warning}`);
        }
        return joinTerminalLines(lines);
    }

    if (result.mode === 'anomalies') {
        lines.push(`🚨 Anomalies & Risk Signals for Profile: ${result.profileId} (${result.count})`);
        if (result.bodyPolicyReason) lines.push(`   Body export omitted (${result.bodyPolicyReason})`);
        for (const a of result.anomalies) {
            const trig = a.triggerAction
                ? ` trigger=${a.triggerAction.actionType}:${a.triggerAction.target || ''}${inferredLabel(a.triggerAction)}`
                : '';
            const reasonPart = a.failureText ? ` | reason=${a.failureText}` : '';
            lines.push(
                `  - [${a.severity || 'medium'}] ${a.type} | corr=${a.correlationId || 'n/a'} | step=${a.actionStep || 'n/a'}${trig} | status=${a.status ?? 'ERR'}${reasonPart} | url=${a.url || ''} | payload=${a.payloadFile || 'none'}`
            );
        }
        return joinTerminalLines(lines);
    }

    if (result.mode === 'cookies') {
        lines.push('Private report. Cookie value digests are included when available.');
        if (result.cookieName !== null) {
            lines.push(
                `🍪 Cookie & Anti-Bot Token Lineage — Profile: ${result.profileId} | Filter: ${result.cookieName}`
            );
            if (!result.found || !result.cookie) {
                lines.push(`   No cookie matching "${result.cookieName}" found in cookieLineage.`);
                return joinTerminalLines(lines);
            }
        } else {
            lines.push(
                `🍪 Cookie & Anti-Bot Token Causal Lineage — Profile: ${result.profileId} (${result.count} instances, ${result.antiBotTokenCount ?? 0} anti-bot/auth tokens)`
            );
        }

        for (const c of result.cookies || []) {
            const badge = c.isAntiBotToken ? '[ANTI-BOT/AUTH TOKEN]' : '[COOKIE]';
            lines.push(
                `  - ${c.name} ${badge} | scope=${c.scopeStatus} domain=${c.domain || 'n/a'} hostOnly=${c.hostOnly ?? 'unknown'} path=${c.path || 'unknown'} partition=${c.partitionKey ?? (c.partitioned ? 'unknown' : 'n/a')} secure=${c.secure ?? 'unknown'} httpOnly=${c.httpOnly ?? 'unknown'} sameSite=${c.sameSite || 'n/a'}`
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
        return joinTerminalLines(lines);
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
                `  - [${s.platform}] ${s.signatureName} (${s.location}) | corr=${s.correlationId || 'n/a'} | step=${s.actionStep || 'n/a'} | trigger=${trig}${inferredLabel(s.triggerAction)} | len=${s.valueLength} masked=${s.maskedPreview} sha256=${s.valueSha256} | url=${s.url || ''}`
            );
        }
        return joinTerminalLines(lines);
    }

    lines.push(`📊 Pre-TLS Traffic Attribution Report — Profile: ${result.profileId}`);
    if (result.bodyPolicyReason) lines.push(`   Body export omitted (${result.bodyPolicyReason})`);
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
                ? ` [trigger=${tx.triggerAction.actionType}:${tx.triggerAction.target || ''}${inferredLabel(tx.triggerAction)}]`
                : '';
            lines.push(
                `     - ${tx.correlationId}: ${tx.method || 'GET'} ${tx.url || ''} -> ${tx.status ?? tx.failureText ?? 'PENDING'} (step=${tx.actionStep || 'n/a'})${trig}`
            );
        }
    }

    return joinTerminalLines(lines);
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
                '  --profiles-dir=<path>       Profiles root (defaults to the application configuration)',
                '  --traffic-dir=<path>        Select a specific capture directory',
                '  --profile=<profileId>       Inspect a profile or confirm the selected capture identity',
                '  --step=<actionStep>         Filter by attribution.actionStep',
                '  --trigger=<actionOrTarget>  Filter by recorded UI action (e.g. page.click or #submit)',
                '  --domain=<hostSubstring>    Filter by host substring',
                '  --status=<codeOrClass>      Filter by HTTP status code or class (429, 403, 4xx, 5xx, 200)',
                '  --anomalies-only            Show only anomalies & risk signals',
                '  --correlation=<corrId>      Reconstruct Pre-TLS Egress + Post-TLS Ingress wire dump',
                '  --dump-wire=<corrId>        Alias for --correlation=<corrId>',
                '  --cookies                   Private cookie lineage with stable value digests',
                '  --cookie=<name>             Private lineage and digest history for one cookie',
                '  --signatures                List all detected anti-bot platform signatures and causal step/trigger',
                '  --platform=<platformName>   Filter signatures & events by platform (bytedance, twitter, meta, google, arkose, cloudflare)',
                '  --verify-integrity          Verify SHA-256 tamper-evident hash chain & payload manifest',
                '  --export-har[=<path>]       Export HAR 1.2 with step, trigger, domain, status, or correlation filters',
                '  --json                      Output structured JSON',
                '',
                'Integrity verification exits with 0 when complete, 1 on invalid data or an error, and 2 when incomplete.'
            ].join('\n')
        );
        return 0;
    }

    const result = queryProfileTraffic({
        profilesDir: args.profilesDir,
        trafficDir: args.trafficDir,
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
        const indent = result.mode === 'export-har' ? undefined : 2;
        process.stdout.write(`${JSON.stringify(result, null, indent)}\n`);
    } else {
        process.stdout.write(`${formatCliReport(result)}\n`);
    }

    if (result.mode === 'verify-integrity') return integrityOutcome(result).exitCode;
    if (result.mode === 'wire-dump' && !result.found) return 1;
    return 0;
}

const isMainModule =
    process.argv[1] &&
    path.resolve(process.argv[1]) === path.resolve(__filename);

if (isMainModule) {
    try {
        process.exitCode = runCli(process.argv.slice(2));
    } catch (err) {
        const systemCode = typeof err?.errno === 'number' && /^E[A-Z0-9_]+$/.test(err.code) ? ' (' + err.code + ')' : '';
        const message = err?.path || err?.dest
            ? 'Could not read or write the local traffic capture' + systemCode
            : redactDiagnosticText(err.message);
        console.error(`Error: ${escapeTerminalText(message)}`);
        process.exitCode = 1;
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
