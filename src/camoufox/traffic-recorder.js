/**
 * Camoufox Pre-TLS Egress/Ingress Traffic Recorder & Multi-Dimensional Attribution Engine
 *
 * Hooks Gecko / Necko channel lifecycle events exposed through Playwright's Juggler
 * bridge (`http-on-modify-request` prior to NSS TLS encryption on egress, and
 * `onDataAvailable` / `onStopRequest` immediately after NSS TLS decryption on ingress)
 * together with NSS `SSLKEYLOGFILE` key material reservation.
 *
 * Records HTTP and WebSocket attribution and optional request and frame bodies
 * without an external MITM proxy. Response metadata remains available when the
 * browser transport cannot enforce a bounded response body read.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
    appendPrivateFile, ensurePrivateDirectory, restrictPrivateFile, writePrivateFile
} from '../utils/private-storage.js';
import { getDefaultProfilesDirectory } from '../utils/state-paths.js';
import {
    hashCaptureFile, hashCapturePayload, listCaptureDirectory, listCapturePayloads, measureCapturePayload, readCaptureFile,
    readCapturePayload, removeCapturePayload, resolveFilesystemPath, truncateCaptureFile, writeCaptureExport
} from './capture-io.js';
import { captureEventTraceId, capturePolicyAllowsBody, readCaptureExportIndex } from './capture-export-policy.js';
import { CookieLineage, deriveCookieObservations } from './cookie-lineage.js';
import {
    acquireDirectoryLease, archiveLegacyNativeLogs, assertExternalNativePath, assertProfileLease, inspectProfileDirectory,
    locateProfile, PROFILE_LEASE_DIRECTORY, releaseProfileLease, validateProfileId
} from './profile-storage.js';
import { allowsTrafficBody, projectTrafficBody, sampleTrafficBody, shareableBodyFormat } from './traffic-body.js';
import {
    redactDiagnosticMetadata,
    redactDiagnosticText,
    redactProfileId,
    redactProxyUrl,
    redactSensitiveHeaders,
    redactTriggerAction,
    redactUrlSecrets,
    SENSITIVE_URL_PARAM_REGEX
} from './traffic-redaction.js';

export { ANTI_BOT_COOKIE_REGEX, parseSetCookieHeader, parseCookieHeader } from './cookie-lineage.js';
export {
    redactDiagnosticMetadata,
    redactDiagnosticText,
    redactProfileId,
    redactProxyUrl,
    redactSensitiveHeaders,
    redactTriggerAction,
    redactUrlSecrets,
    SENSITIVE_HEADER_REGEX,
    SENSITIVE_URL_PARAM_REGEX
} from './traffic-redaction.js';

const DEFAULT_PROFILES_DIR = getDefaultProfilesDirectory();

const DEFAULT_MAX_INLINE_PREVIEW_BYTES = 4096;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024; // 5MB (5242880 bytes)
const DEFAULT_MAX_CAPTURE_BYTES = 32 * 1024 * 1024;
const MAX_CAPTURE_BYTES = 128 * 1024 * 1024;
const MAX_CAPTURE_EVENTS = 20_000;
const MAX_PENDING_TRAFFIC_EVENTS = 512;
const MAX_TRIGGER_DELAY_MS = 30_000;
const PAYLOAD_CLASSIFICATION_BYTES = 512;
const TRAFFIC_GENESIS_HASH = '0'.repeat(64);
const MAX_INTEGRITY_LOG_BYTES = 128 * 1024 * 1024;
const HAR_SESSION_RANGE = Symbol('HAR session range');
const HAR_PROTECTED_PATHS = Symbol('HAR protected paths');
const MAX_HAR_BYTES = 32 * 1024 * 1024;
const MAX_HAR_ENTRIES = 10_000;
const MAX_HAR_EVENT_BYTES = 2 * 1024 * 1024;
const PAYLOAD_OWNER_TYPES = new Set(['egress', 'ingress', 'ws-egress', 'ws-ingress']);
const PENDING_PAYLOAD_PATTERN = /^payloads\/\.pending-((?:req|res|ws)-[1-9]\d*-[a-f\d]{12}\.(?:json|txt|bin))$/;
const INTEGRITY_ARTIFACTS = {
    preTlsWireLog: 'pre-tls-wire.log',
    sslKeyLog: 'sslkeylog.txt',
    neckoMozLog: 'necko-pre-tls.moz_log'
};

/**
 * Risk-control, challenge, and anti-bot signal patterns inspected across request URLs,
 * response URLs, status codes, headers, and text/JSON bodies.
 */
const RISK_SIGNAL_PATTERNS = [
    { name: 'captcha', regex: /\b(captcha|g-recaptcha|recaptcha|hcaptcha|funcaptcha)\b/i, severity: 'high' },
    { name: 'arkose', regex: /\b(arkose|arkoselabs|enforcement\.[a-z0-9.-]+)\b/i, severity: 'high' },
    { name: 'turnstile', regex: /\b(turnstile|cf-chl-|cf_chl_opt|challenges\.cloudflare\.com)\b/i, severity: 'high' },
    { name: 'botguard', regex: /\b(botguard|bgRequest|baa\.google|accounts\.google\.com\/v3\/signin\/challenge)\b/i, severity: 'medium' },
    { name: 'challenge', regex: /(?:\/challenge\b|[?&]challenge=|signin\/challenge|challenge\/ootp|challenge\/ipp|challenge\/pwd)/i, severity: 'high' },
    { name: 'checkpoint', regex: /(?:\/checkpoint\b|security_checkpoint|checkpoint_required)/i, severity: 'high' },
    { name: 'verify', regex: /(?:\/verify\b|phoneverification|idvreenable|sendidv|verifyphone)/i, severity: 'medium' },
    { name: 'deny', regex: /(?:\/deny\b|access_denied|account_disabled|unusual[_\s-]+traffic|automated[_\s-]+queries|sorry\/index)/i, severity: 'critical' }
];

const TEXTUAL_MIME_PATTERNS =
    /\b(json|text|html|xml|javascript|ecmascript|x-www-form-urlencoded|graphql|csv|plain|svg|css)\b/i;

/**
 * Determine default desktop OS name in Camoufox format ('windows' | 'macos' | 'linux').
 */
function detectDefaultOs() {
    if (process.env.CAMOUFOX_OS) {
        const cleaned = String(process.env.CAMOUFOX_OS).trim().toLowerCase();
        if (cleaned.startsWith('win')) return 'windows';
        if (cleaned.startsWith('mac') || cleaned === 'darwin' || cleaned === 'osx') return 'macos';
        if (cleaned.startsWith('lin') || cleaned === 'ubuntu') return 'linux';
    }
    if (process.platform === 'win32') return 'windows';
    if (process.platform === 'darwin') return 'macos';
    return 'linux';
}

/**
 * Compute full SHA-256 hex digest and 12-char content-address prefix.
 *
 * @param {Buffer|string} bufferOrString
 * @returns {{ sha256: string, shortSha256: string, byteLength: number, buffer: Buffer }}
 */
function hashPayload(bufferOrString) {
    const buffer = Buffer.isBuffer(bufferOrString)
        ? bufferOrString
        : Buffer.from(String(bufferOrString ?? ''), 'utf8');
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    return {
        sha256,
        shortSha256: sha256.slice(0, 12),
        byteLength: buffer.byteLength,
        buffer
    };
}

/** Return a measured frame length, including normalization of older withheld frames. */
export function observedWebSocketPayloadBytes(event) {
    if (event?.payloadBytes === 0 && (event.bodyOmittedReason === 'body-recording-disabled' ||
        event.bodyOmittedReason === 'sensitive-or-unsupported-url')) return null;
    return Number.isSafeInteger(event?.payloadBytes) && event.payloadBytes >= 0 ? event.payloadBytes : null;
}

/**
 * Determine appropriate payload file extension (`.json`, `.txt`, or `.bin`)
 * based on MIME type and payload content.
 *
 * @param {string|null|undefined} mimeType
 * @param {Buffer} buffer
 * @returns {'json'|'txt'|'bin'}
 */
export function inferPayloadExtension(mimeType, buffer) {
    const normalizedMime = String(mimeType || '').toLowerCase();
    if (normalizedMime.includes('json')) {
        return 'json';
    }
    const sample = buffer?.subarray(0, PAYLOAD_CLASSIFICATION_BYTES);
    if (sample?.byteLength && sample.byteLength === buffer.byteLength &&
        (sample[0] === 0x7b || sample[0] === 0x5b)) {
        try {
            JSON.parse(sample.toString('utf8'));
            return 'json';
        } catch {
            // A small JSON-looking payload can still be ordinary text or binary.
        }
    }
    if (TEXTUAL_MIME_PATTERNS.test(normalizedMime)) {
        return 'txt';
    }
    if (sample?.byteLength) {
        let nonPrintable = 0;
        for (const byte of sample) {
            if (byte === 0x00) {
                return 'bin';
            }
            if (byte < 0x09 || (byte > 0x0d && byte < 0x20)) {
                nonPrintable += 1;
            }
        }
        if (nonPrintable / sample.byteLength < 0.05) {
            return 'txt';
        }
    }
    return 'bin';
}

/**
 * Safely parse a URL into structured host, pathname, and search parameters.
 *
 * @param {string} rawUrl
 * @returns {{
 *   protocol: string|null,
 *   host: string,
 *   hostname: string,
 *   port: string|null,
 *   pathname: string,
 *   search: string,
 *   searchParams: Record<string, string|string[]>
 * }}
 */
function parseUrlComponents(rawUrl) {
    const redactedUrl = redactUrlSecrets(rawUrl);
    try {
        const parsed = new URL(String(redactedUrl));
        const searchParams = {};
        for (const [key, value] of parsed.searchParams.entries()) {
            if (Object.prototype.hasOwnProperty.call(searchParams, key)) {
                if (Array.isArray(searchParams[key])) {
                    searchParams[key].push(value);
                } else {
                    searchParams[key] = [searchParams[key], value];
                }
            } else {
                searchParams[key] = value;
            }
        }
        return {
            protocol: parsed.protocol ? parsed.protocol.replace(/:$/, '') : null,
            host: parsed.host || parsed.hostname || 'unknown',
            hostname: parsed.hostname || 'unknown',
            port: parsed.port || null,
            pathname: parsed.pathname || '/',
            search: parsed.search,
            searchParams
        };
    } catch {
        return {
            protocol: null,
            host: 'unknown',
            hostname: 'unknown',
            port: null,
            pathname: String(redactedUrl || ''),
            search: '',
            searchParams: {}
        };
    }
}

/** Classify anomalies directly represented by traffic lifecycle events. */
export function classifyTrafficLifecycleAnomaly({ type, status, failureText }) {
    if (type === 'ingress') {
        const code = Number(status);
        if (code === 401) return { type: 'http-401-unauthorized', severity: 'medium' };
        if (code === 403) return { type: 'http-403-forbidden', severity: 'high' };
        if (code === 429) return { type: 'http-429-rate-limit', severity: 'high' };
        if (code >= 500) return { type: `http-${code}-server-error`, severity: 'high' };
    }
    if (type === 'request-failed') {
        const isProxyOrTlsFailure =
            /proxy|tunnel|ssl|tls|cert|ns_error_proxy|ns_error_net_timeout|ns_error_connection_refused|timed?\s*out/i.test(
                failureText
            );
        return isProxyOrTlsFailure
            ? { type: 'network-proxy-or-tls-failure', severity: 'high' }
            : { type: 'network-request-failed', severity: 'medium' };
    }
    if (type === 'ws-error') return { type: 'websocket-error', severity: 'medium' };
    return null;
}

export function trafficAnomalyKey({ correlationId, type, status, failureText, url }) {
    return [correlationId || '', type || '', status ?? '', failureText || '', url || ''].join('|');
}

/** Project a security block from the event ledger into the anomaly report. */
export function securityBlockAnomaly(event) {
    return {
        timestamp: event.timestamp || null,
        correlationId: event.correlationId || null,
        actionStep: event.attribution?.actionStep || event.actionStep || 'init',
        triggerAction: event.triggerAction || event.attribution?.triggerAction || null,
        type: `security-block:${event.blockType || 'security-probe'}`,
        severity: event.severity || 'critical',
        method: event.method || 'GET',
        url: event.url || event.targetUrl || null,
        status: null,
        failureText: event.reason || event.failureText || null,
        payloadFile: null
    };
}

/**
 * Mask a platform anti-bot signature / telemetry parameter value
 * (`first 4 chars + '***' + last 3 chars`).
 *
 * @param {string} rawValue
 * @returns {string}
 */
function maskPlatformSignatureValue(rawValue) {
    const str = String(rawValue ?? '');
    if (str.length === 0) {
        return '***';
    }
    if (str.length <= 4) {
        return `${str.slice(0, 1)}***${str.slice(-1)}`;
    }
    return `${str.slice(0, 4)}***${str.slice(-3)}`;
}

const PLATFORM_SIGNATURE_DEFINITIONS = [
    // 1. bytedance (Douyin / TikTok)
    { platform: 'bytedance', signatureName: 'a_bogus', regex: /^a[_-]bogus$/i, locations: ['query', 'header', 'body'] },
    { platform: 'bytedance', signatureName: 'X-Bogus', regex: /^x[_-]bogus$/i, locations: ['query', 'header', 'body'] },
    { platform: 'bytedance', signatureName: 'X-Gnarly', regex: /^x[_-]gnarly$/i, locations: ['query', 'header', 'body'] },
    { platform: 'bytedance', signatureName: 'msToken', regex: /^mstoken$/i, locations: ['query', 'header', 'body'] },
    { platform: 'bytedance', signatureName: 'verifyFp', regex: /^verifyfp$/i, locations: ['query', 'header', 'body'] },
    { platform: 'bytedance', signatureName: 's_v_web_id', regex: /^s_v_web_id$/i, locations: ['query', 'header', 'body'] },
    { platform: 'bytedance', signatureName: 'odin_tt', regex: /^odin_tt$/i, locations: ['query', 'header', 'body'] },
    { platform: 'bytedance', signatureName: 'ttwid', regex: /^ttwid$/i, locations: ['query', 'header', 'body'] },

    // 2. twitter (X)
    { platform: 'twitter', signatureName: 'x-client-transaction-id', regex: /^x-client-transaction-id$/i, locations: ['header', 'query', 'body'] },
    { platform: 'twitter', signatureName: 'x-csrf-token', regex: /^x-csrf-token$/i, locations: ['header', 'query', 'body'] },
    { platform: 'twitter', signatureName: 'x-guest-token', regex: /^x-guest-token$/i, locations: ['header', 'query', 'body'] },
    { platform: 'twitter', signatureName: 'ui_metrics', regex: /^ui_metrics$/i, locations: ['query', 'header', 'body'] },

    // 3. meta (Facebook / Instagram)
    { platform: 'meta', signatureName: 'x-ig-app-id', regex: /^x-ig-app-id$/i, locations: ['header', 'body', 'query'] },
    { platform: 'meta', signatureName: 'x-asbd-id', regex: /^x-asbd-id$/i, locations: ['header', 'body', 'query'] },
    { platform: 'meta', signatureName: 'x-csrftoken', regex: /^x-csrftoken$/i, locations: ['header', 'body', 'query'] },
    { platform: 'meta', signatureName: 'x-ig-www-claim', regex: /^x-ig-www-claim$/i, locations: ['header', 'body', 'query'] },
    { platform: 'meta', signatureName: 'x-fb-friendly-name', regex: /^x-fb-friendly-name$/i, locations: ['header', 'body', 'query'] },
    { platform: 'meta', signatureName: 'x-fb-lsd', regex: /^x-fb-lsd$/i, locations: ['header', 'body', 'query'] },
    { platform: 'meta', signatureName: 'jazoest', regex: /^jazoest$/i, locations: ['body', 'query', 'header'] },
    { platform: 'meta', signatureName: 'lsd', regex: /^lsd$/i, locations: ['body', 'query', 'header'] },

    // 4. google (Gmail / Accounts / BotGuard)
    { platform: 'google', signatureName: 'bgRequest', regex: /^bgrequest$/i, locations: ['query', 'header', 'body'] },
    { platform: 'google', signatureName: 'f.req', regex: /^f\.req$/i, locations: ['query', 'header', 'body'] },
    { platform: 'google', signatureName: 'TL', regex: /^tl$/i, locations: ['query', 'header', 'body'] },
    { platform: 'google', signatureName: 'at', regex: /^at$/i, locations: ['query', 'header', 'body'] },
    { platform: 'google', signatureName: 'x-goog-ext-278367001-jspb', regex: /^x-goog-ext-278367001-jspb$/i, locations: ['header', 'query', 'body'] },

    // 5. arkose (FunCaptcha)
    { platform: 'arkose', signatureName: 'bda', regex: /^bda$/i, locations: ['body', 'query', 'header'] },
    { platform: 'arkose', signatureName: 'fc-token', regex: /^fc[-_]token$/i, locations: ['body', 'query', 'header'] },
    { platform: 'arkose', signatureName: 'public_key', regex: /^public_key$/i, locations: ['body', 'query'], requiresArkoseUrl: true },

    // 6. cloudflare (Turnstile / Challenge)
    { platform: 'cloudflare', signatureName: 'cf-turnstile-response', regex: /^cf-turnstile-response$/i, locations: ['body', 'query', 'header'] },
    { platform: 'cloudflare', signatureName: 'cf_chl_opt', regex: /^_?cf_chl_opt$/i, locations: ['body', 'query', 'header'] },
    { platform: 'cloudflare', signatureName: 'cf-ray', regex: /^cf-ray$/i, locations: ['header', 'query', 'body'] }
];

/**
 * Recursively collect key-value pairs from a parsed JSON payload up to a bounded depth.
 *
 * @param {any} node
 * @param {Array<{ key: string, value: string }>} out
 * @param {number} [depth=0]
 */
function collectJsonKeyValues(node, out, depth = 0) {
    if (!node || typeof node !== 'object' || depth > 6) {
        return;
    }
    if (Array.isArray(node)) {
        // Also detect Google / BotGuard ["bgRequest", "<value>"] tuple patterns in arrays
        if (
            node.length >= 2 &&
            typeof node[0] === 'string' &&
            /^(bgRequest|ui_metrics|bda|fc-token|cf_chl_opt)$/i.test(node[0]) &&
            node[1] !== null &&
            node[1] !== undefined
        ) {
            out.push({
                key: node[0],
                value: typeof node[1] === 'string' ? node[1] : JSON.stringify(node[1])
            });
        }
        for (const item of node) {
            collectJsonKeyValues(item, out, depth + 1);
        }
        return;
    }
    for (const [k, v] of Object.entries(node)) {
        if (v !== null && v !== undefined) {
            const strVal = typeof v === 'string' ? v : JSON.stringify(v);
            out.push({ key: k, value: strVal });
            if (typeof v === 'object') {
                collectJsonKeyValues(v, out, depth + 1);
            }
        }
    }
}

/**
 * Detect and extract metadata for major platform anti-bot telemetry & cryptographic
 * signature parameters across ByteDance (Douyin/TikTok), Twitter/X, Meta (Facebook/Instagram),
 * Google (Gmail/Accounts/BotGuard), Arkose (FunCaptcha), and Cloudflare (Turnstile/Challenge).
 *
 * @param {object} [params={}]
 * @param {string} [params.url='']
 * @param {Record<string, string|string[]>|URLSearchParams|null} [params.searchParams=null]
 * @param {Record<string, string>|Array<{ name: string, value: string }>} [params.headers={}]
 * @param {string|null} [params.bodyPreview=null]
 * @returns {Array<{
 *   platform: 'bytedance'|'twitter'|'meta'|'google'|'arkose'|'cloudflare',
 *   signatureName: string,
 *   location: 'query'|'header'|'body',
 *   valueLength: number|null,
 *   valueSha256: string|null,
 *   maskedPreview: string
 * }>}
 */
export function extractPlatformSignatures({
    url = '',
    searchParams = null,
    headers = {},
    bodyPreview = null
} = {}) {
    const urlText = String(url || '');
    const bodyText =
        typeof bodyPreview === 'string' && !bodyPreview.startsWith('[binary ')
            ? bodyPreview
            : '';

    const isArkoseContext =
        /\b(arkose|arkoselabs|funcaptcha|client-api|enforcement\.[a-z0-9.-]+)\b/i.test(urlText) ||
        /\b(bda|fc-token|fc_token|arkose|funcaptcha)\b/i.test(bodyText);

    // 1. Collect query entries
    const queryEntries = [];
    const seenQueryKeys = new Set();
    const pushQueryEntry = (k, v) => {
        if (k === null || k === undefined || v === null || v === undefined) return;
        const keyStr = String(k).trim();
        const valStr = String(v);
        if (!keyStr || !valStr) return;
        const dedupe = `${keyStr}=${valStr}`;
        if (seenQueryKeys.has(dedupe)) return;
        seenQueryKeys.add(dedupe);
        queryEntries.push({ key: keyStr, value: valStr });
    };

    if (searchParams) {
        if (typeof searchParams.entries === 'function') {
            for (const [k, v] of searchParams.entries()) {
                pushQueryEntry(k, v);
            }
        } else if (typeof searchParams === 'object') {
            for (const [k, v] of Object.entries(searchParams)) {
                if (Array.isArray(v)) {
                    for (const item of v) pushQueryEntry(k, item);
                } else {
                    pushQueryEntry(k, v);
                }
            }
        }
    }

    if (urlText.includes('?')) {
        try {
            const parsed = new URL(urlText);
            for (const [k, v] of parsed.searchParams.entries()) {
                pushQueryEntry(k, v);
            }
        } catch {
            const qIdx = urlText.indexOf('?');
            const qStr = urlText.slice(qIdx + 1).split('#')[0];
            const usp = new URLSearchParams(qStr);
            for (const [k, v] of usp.entries()) {
                pushQueryEntry(k, v);
            }
        }
    }

    // 2. Collect header entries
    const headerEntries = [];
    if (Array.isArray(headers)) {
        for (const h of headers) {
            if (h && h.name) {
                headerEntries.push({
                    key: String(h.name).trim(),
                    value: String(h.value ?? '')
                });
            }
        }
    } else if (headers && typeof headers === 'object') {
        for (const [k, v] of Object.entries(headers)) {
            if (v !== null && v !== undefined && String(v) !== '') {
                headerEntries.push({
                    key: String(k).trim(),
                    value: String(v)
                });
            }
        }
    }

    // 3. Collect body entries (JSON, URL-encoded form parameters, or embedded telemetry)
    const bodyEntries = [];
    if (bodyText) {
        const trimmedBody = bodyText.trim();
        let jsonParsed = false;

        if (trimmedBody.startsWith('{') || trimmedBody.startsWith('[')) {
            try {
                const parsedJson = JSON.parse(trimmedBody);
                collectJsonKeyValues(parsedJson, bodyEntries);
                jsonParsed = true;
            } catch {
                jsonParsed = false;
            }
        }

        if (!jsonParsed && trimmedBody.includes('=') && !trimmedBody.startsWith('<')) {
            try {
                const formParams = new URLSearchParams(trimmedBody);
                for (const [k, v] of formParams.entries()) {
                    if (k && v !== '') {
                        bodyEntries.push({ key: k.trim(), value: v });
                        // If a form value itself is JSON (e.g. Google f.req), inspect nested tokens like bgRequest
                        const trimVal = v.trim();
                        if (trimVal.startsWith('{') || trimVal.startsWith('[')) {
                            try {
                                collectJsonKeyValues(JSON.parse(trimVal), bodyEntries);
                            } catch {}
                        }
                    }
                }
            } catch {}
        }

        // Regex fallback for truncated JSON or script-embedded keys
        const jsonKeyRegex =
            /"(a_bogus|X-Bogus|X-Gnarly|msToken|verifyFp|s_v_web_id|odin_tt|ttwid|x-client-transaction-id|x-csrf-token|x-guest-token|ui_metrics|x-ig-app-id|x-asbd-id|x-csrftoken|x-ig-www-claim|x-fb-friendly-name|x-fb-lsd|jazoest|lsd|bgRequest|f\.req|TL|at|x-goog-ext-278367001-jspb|bda|fc-token|fc_token|public_key|cf-turnstile-response|cf_chl_opt|_cf_chl_opt|cf-ray)"\s*:\s*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|(\{[^{}]*\})|(\[[^\[\]]*\])|([^,\s}\]]+))/gi;
        let match;
        while ((match = jsonKeyRegex.exec(bodyText)) !== null) {
            const key = match[1];
            const val = match[2] ?? match[3] ?? match[4] ?? match[5] ?? '';
            if (key && val) {
                bodyEntries.push({ key, value: val });
            }
        }
    }

    const results = [];
    const seenSignatures = new Set();

    const addSignature = (platform, signatureName, location, rawValue) => {
        const valueStr = String(rawValue ?? '');
        if (!valueStr) return;
        const valueSha256 = crypto.createHash('sha256').update(valueStr, 'utf8').digest('hex');
        const dedupeKey = `${platform}|${signatureName}|${location}|${valueSha256}`;
        if (seenSignatures.has(dedupeKey)) {
            return;
        }
        seenSignatures.add(dedupeKey);
        const sensitive = location === 'body' || SENSITIVE_URL_PARAM_REGEX.test(signatureName);
        results.push({
            platform,
            signatureName,
            location,
            valueLength: sensitive ? null : valueStr.length,
            valueSha256: sensitive ? null : valueSha256,
            maskedPreview: sensitive ? '[REDACTED]' : maskPlatformSignatureValue(valueStr)
        });
    };

    const entriesByLocation = {
        query: queryEntries,
        header: headerEntries,
        body: bodyEntries
    };

    for (const def of PLATFORM_SIGNATURE_DEFINITIONS) {
        if (def.requiresArkoseUrl && !isArkoseContext) {
            continue;
        }
        for (const loc of def.locations) {
            const candidateEntries = entriesByLocation[loc] || [];
            for (const entry of candidateEntries) {
                if (def.regex.test(entry.key)) {
                    addSignature(def.platform, def.signatureName, loc, entry.value);
                }
            }
        }
    }

    // Special handling for Arkose URL path `/public_key/<KEY>`
    if (isArkoseContext && !results.some((r) => r.platform === 'arkose' && r.signatureName === 'public_key')) {
        const pkPathMatch = urlText.match(/\/public_key\/([A-Za-z0-9-]+)(?:[/?#]|$)/i);
        if (pkPathMatch && pkPathMatch[1]) {
            addSignature('arkose', 'public_key', 'query', pkPathMatch[1]);
        }
    }

    // Special handling for Twitter `ui_metrics` when URL or body contains `ui_metrics`
    if (!results.some((r) => r.platform === 'twitter' && r.signatureName === 'ui_metrics')) {
        if (/ui_metrics/i.test(urlText)) {
            const metricQueryEntry = queryEntries.find((e) => /ui_metrics/i.test(e.value));
            addSignature(
                'twitter',
                'ui_metrics',
                'query',
                metricQueryEntry ? metricQueryEntry.value : urlText
            );
        }
        if (/ui_metrics/i.test(bodyText)) {
            addSignature('twitter', 'ui_metrics', 'body', bodyText);
        }
    }

    // Special handling for Cloudflare `cf_chl_opt` script assignment in body (`window._cf_chl_opt = ...`)
    if (
        /cf_chl_opt/i.test(bodyText) &&
        !results.some((r) => r.platform === 'cloudflare' && r.signatureName === 'cf_chl_opt')
    ) {
        const chlMatch = bodyText.match(/_?cf_chl_opt\s*=\s*(\{[\s\S]{1,1024}?\})/);
        addSignature(
            'cloudflare',
            'cf_chl_opt',
            'body',
            chlMatch ? chlMatch[1] : bodyText
        );
    }

    // Special handling for Google `bgRequest` embedded inside body (e.g. URL-encoded or nested JSON in f.req)
    if (
        /bgRequest/i.test(bodyText) &&
        !results.some((r) => r.platform === 'google' && r.signatureName === 'bgRequest')
    ) {
        const bgMatch = bodyText.match(/bgRequest["'\\,\s:=]+([A-Za-z0-9_!.-]{8,})/i);
        addSignature(
            'google',
            'bgRequest',
            'body',
            bgMatch ? bgMatch[1] : bodyText
        );
    }

    return results;
}

/**
 * Detect risk-control / challenge signals in a URL and optional body preview.
 *
 * @param {object} params
 * @param {string} params.url
 * @param {string|null} [params.bodyPreview]
 * @param {Record<string, string>} [params.headers]
 * @returns {Array<{ name: string, severity: string }>}
 */
export function detectRiskSignals({ url = '', bodyPreview = null, headers = {} } = {}) {
    const matched = [];
    const seen = new Set();

    const urlText = String(url || '');
    const headerText = headers && typeof headers === 'object'
        ? Object.entries(headers)
            .filter(([k]) => /location|www-authenticate|cf-mitigated|x-frame-options|server/i.test(k))
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n')
        : '';
    const bodyText = typeof bodyPreview === 'string' && !bodyPreview.startsWith('[binary ')
        ? bodyPreview.slice(0, 2048)
        : '';

    for (const pattern of RISK_SIGNAL_PATTERNS) {
        const hitInUrl = pattern.regex.test(urlText);
        const hitInHeaders = !hitInUrl && headerText ? pattern.regex.test(headerText) : false;
        // For body inspection, only flag high-confidence challenge markers or small challenge payloads
        const hitInBody = !hitInUrl && !hitInHeaders && bodyText
            ? (pattern.name !== 'verify' && pattern.regex.test(bodyText))
            : false;

        if ((hitInUrl || hitInHeaders || hitInBody) && !seen.has(pattern.name)) {
            seen.add(pattern.name);
            matched.push({
                name: pattern.name,
                severity: pattern.severity,
                source: hitInUrl ? 'url' : hitInHeaders ? 'headers' : 'body'
            });
        }
    }

    return matched;
}

const CHROMIUM_CLIENT_HINT_HEADER_REGEX =
    /^sec-ch-ua(-mobile|-platform|-platform-version|-arch|-bitness|-full-version|-full-version-list|-model|-wow64|-form-factors)?$/i;

const PROXY_ANONYMITY_LEAK_HEADER_REGEX =
    /^(x-forwarded-for|x-real-ip|forwarded|via|x-proxy-id|proxy-connection)$/i;

/**
 * Detect Pre-TLS egress wire header coherence anomalies (Chromium Client-Hints leaked on Gecko,
 * non-Firefox User-Agent, User-Agent vs configured OS mismatch) and proxy anonymity leaks.
 *
 * @param {object} [params={}]
 * @param {Record<string, string>} [params.headers={}]
 * @param {Array<{ name: string, value: string }>} [params.headersArray=[]]
 * @param {string|null} [params.expectedOs=null]
 * @param {'egress'|'ingress'|string} [params.direction='egress']
 * @returns {Array<{
 *   type: string,
 *   name: string,
 *   severity: 'critical'|'high',
 *   direction: string,
 *   headerName: string,
 *   headerValue: string,
 *   matchedHeaders: Array<{ name: string, value: string }>,
 *   reason: string
 * }>}
 */
export function detectWireHeaderAnomalies({
    headers = {},
    headersArray = [],
    expectedOs = null,
    direction = 'egress'
} = {}) {
    const normDirection = String(direction || 'egress').trim().toLowerCase();
    const isEgress = normDirection === 'egress' || normDirection === 'request';
    const entries = [];

    if (Array.isArray(headersArray) && headersArray.length > 0) {
        for (const h of headersArray) {
            if (h && h.name !== undefined && h.name !== null) {
                entries.push({
                    name: String(h.name),
                    value: String(h.value ?? '')
                });
            }
        }
    }

    if (headers && typeof headers === 'object') {
        const seenLower = new Set(entries.map((e) => e.name.toLowerCase()));
        for (const [k, v] of Object.entries(headers)) {
            const lower = String(k).toLowerCase();
            if (!seenLower.has(lower)) {
                seenLower.add(lower);
                entries.push({
                    name: String(k),
                    value: String(v ?? '')
                });
            }
        }
    }

    const anomalies = [];

    if (isEgress) {
        // 1. Chromium Sec-CH-UA client-hint headers must never appear on a Firefox/Gecko Necko wire channel
        const clientHintMatches = entries.filter((e) => CHROMIUM_CLIENT_HINT_HEADER_REGEX.test(e.name));
        if (clientHintMatches.length > 0) {
            const type = 'wire-header-anomaly:chromium-client-hints-on-gecko';
            anomalies.push({
                type,
                name: type,
                severity: 'critical',
                direction: normDirection,
                headerName: clientHintMatches[0].name,
                headerValue: clientHintMatches[0].value,
                matchedHeaders: clientHintMatches,
                reason: `Chromium Client-Hints header(s) detected on Gecko egress wire: ${clientHintMatches.map((m) => m.name).join(', ')}`
            });
        }

        // 2. User-Agent engine & OS coherence inspection
        const uaEntry = entries.find((e) => e.name.toLowerCase() === 'user-agent');
        if (uaEntry && uaEntry.value.trim().length > 0) {
            const uaValue = uaEntry.value.trim();
            const hasNonFirefoxToken = /(Chrome\/|Safari\/|AppleWebKit\/|Edg\/)/i.test(uaValue);
            const hasFirefoxAndGecko = /Firefox\//i.test(uaValue) && /Gecko/i.test(uaValue);

            if (hasNonFirefoxToken || !hasFirefoxAndGecko) {
                const type = 'wire-header-anomaly:non-firefox-wire-ua';
                anomalies.push({
                    type,
                    name: type,
                    severity: 'critical',
                    direction: normDirection,
                    headerName: uaEntry.name,
                    headerValue: uaValue,
                    matchedHeaders: [uaEntry],
                    reason: `Non-Firefox User-Agent detected on Gecko egress wire: ${uaValue}`
                });
            }

            const normOs = expectedOs ? String(expectedOs).trim().toLowerCase() : '';
            if (normOs) {
                let osMismatch = false;
                if ((normOs === 'windows' || normOs === 'win32' || normOs === 'win') && !/Windows NT/i.test(uaValue)) {
                    osMismatch = true;
                } else if (
                    (normOs === 'macos' || normOs === 'mac' || normOs === 'darwin' || normOs === 'osx') &&
                    !/Macintosh/i.test(uaValue)
                ) {
                    osMismatch = true;
                } else if (
                    (normOs === 'linux' || normOs === 'ubuntu') &&
                    (!/Linux/i.test(uaValue) || /Android/i.test(uaValue))
                ) {
                    osMismatch = true;
                }

                if (osMismatch) {
                    const type = 'wire-header-anomaly:ua-os-mismatch';
                    anomalies.push({
                        type,
                        name: type,
                        severity: 'critical',
                        direction: normDirection,
                        headerName: uaEntry.name,
                        headerValue: uaValue,
                        matchedHeaders: [uaEntry],
                        reason: `User-Agent OS token mismatch for configured OS "${normOs}": ${uaValue}`
                    });
                }
            }
        }
    }

    // 3. Proxy anonymity leak headers (on both egress and ingress)
    const proxyLeakMatches = entries.filter((e) => PROXY_ANONYMITY_LEAK_HEADER_REGEX.test(e.name));
    if (proxyLeakMatches.length > 0) {
        const type = 'proxy-anonymity-leak';
        anomalies.push({
            type,
            name: type,
            severity: 'high',
            direction: normDirection,
            headerName: proxyLeakMatches[0].name,
            headerValue: proxyLeakMatches[0].value,
            matchedHeaders: proxyLeakMatches,
            reason: `Proxy anonymity leak header(s) detected on ${normDirection}: ${proxyLeakMatches.map((m) => m.name).join(', ')}`
        });
    }

    return anomalies;
}

/**
 * Parse and validate an NSS `sslkeylog.txt` file (`<LABEL> <CLIENT_RANDOM_HEX> <SECRET_HEX>`),
 * computing SHA-256 integrity and TLS 1.2 / TLS 1.3 session statistics.
 *
 * @param {string} sslKeyLogPath
 * @returns {{
 *   exists: boolean,
 *   sha256: string|null,
 *   bytes: number,
 *   entryCount: number,
 *   uniqueClientRandoms: number,
 *   tls13SessionCount: number,
 *   tls12SessionCount: number,
 *   labelCounts: Record<string, number>,
 *   malformedLineCount: number
 * }}
 */
export function parseSslKeyLog(sslKeyLogPath) {
    return parseSslKeyLogBytes(readNativeLogFile(sslKeyLogPath));
}

function readNativeLogFile(filePath) {
    if (!filePath) return null;
    return readCaptureFile(path.dirname(filePath), path.basename(filePath), {
        optional: true, trustedLocal: true, maxBytes: MAX_INTEGRITY_LOG_BYTES
    });
}

function parseSslKeyLogBytes(rawBuffer) {
    if (!rawBuffer) {
        return {
            exists: false,
            sha256: null,
            bytes: 0,
            entryCount: 0,
            uniqueClientRandoms: 0,
            tls13SessionCount: 0,
            tls12SessionCount: 0,
            labelCounts: {},
            malformedLineCount: 0
        };
    }

    const sha256 = crypto.createHash('sha256').update(rawBuffer).digest('hex');
    const bytes = rawBuffer.byteLength;
    const lines = rawBuffer.toString('utf8').split(/\r?\n/);

    let entryCount = 0;
    let malformedLineCount = 0;
    const labelCounts = {};
    const allClientRandoms = new Set();
    const tls13ClientRandoms = new Set();
    const tls12ClientRandoms = new Set();

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) {
            continue;
        }

        const parts = trimmed.split(/\s+/);
        if (
            parts.length === 3 &&
            /^[A-Za-z0-9_]+$/.test(parts[0]) &&
            /^[0-9a-fA-F]{64}$/.test(parts[1]) &&
            /^[0-9a-fA-F]{16,256}$/.test(parts[2]) &&
            parts[2].length % 2 === 0
        ) {
            const label = parts[0].toUpperCase();
            const clientRandom = parts[1].toLowerCase();
            entryCount += 1;
            labelCounts[label] = (labelCounts[label] || 0) + 1;
            allClientRandoms.add(clientRandom);

            if (label === 'CLIENT_RANDOM') {
                tls12ClientRandoms.add(clientRandom);
            } else if (
                label.includes('TRAFFIC_SECRET') ||
                label.includes('EXPORTER_SECRET') ||
                label.includes('HANDSHAKE')
            ) {
                tls13ClientRandoms.add(clientRandom);
            }
        } else {
            malformedLineCount += 1;
        }
    }

    return {
        exists: true,
        sha256,
        bytes,
        entryCount,
        uniqueClientRandoms: allClientRandoms.size,
        tls13SessionCount: tls13ClientRandoms.size,
        tls12SessionCount: tls12ClientRandoms.size,
        labelCounts,
        malformedLineCount
    };
}

/** Project native log metadata into a diagnostic summary without retaining credential headers. */
export function redactNeckoMozLogSummary(summary) {
    if (!summary || typeof summary !== 'object') return summary;
    const requests = Array.isArray(summary.parsedRequests) ? summary.parsedRequests : [];
    const responses = Array.isArray(summary.parsedResponses) ? summary.parsedResponses : [];

    return {
        ...summary,
        parsedRequests: requests.filter(Boolean).map((request) => {
            const { headers } = redactSensitiveHeaders({ headers: request.headers });
            const requestLine = redactDiagnosticText(request.requestLine).replace(
                /^(\S+\s+)(\S+)(\s+HTTP\/[\d.]+)$/i,
                (_, method, target, version) => `${method}${redactUrlSecrets(target)}${version}`
            );
            return { requestLine, host: headers.host || headers[':authority'] || null, headers };
        }),
        parsedResponses: responses.filter(Boolean).map((response) => ({
            statusLine: redactDiagnosticText(response.statusLine),
            headers: redactSensitiveHeaders({ headers: response.headers }).headers
        }))
    };
}

/**
 * Parse and validate a Firefox C++ Necko `MOZ_LOG` file (`necko-pre-tls.moz_log`
 * generated with `MOZ_LOG=timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4,sync`),
 * extracting `http request [ ... ]` and `http response [ ... ]` header blocks,
 * HTTP/2 frame counts, DNS resolver lookups, socket transport events, and SHA-256 integrity.
 *
 * @param {string} neckoLogPath
 * @returns {{
 *   exists: boolean,
 *   sha256: string|null,
 *   bytes: number,
 *   lineCount: number,
 *   requestBlockCount: number,
 *   responseBlockCount: number,
 *   http2FrameCount: number,
 *   dnsLookupCount: number,
 *   socketEventCount: number,
 *   parsedRequests: Array<{ requestLine: string, host: string|null, headers: Record<string, string> }>,
 *   parsedResponses: Array<{ statusLine: string, headers: Record<string, string> }>
 * }}
 */
export function parseNeckoMozLog(neckoLogPath) {
    return parseNeckoMozLogBytes(readNativeLogFile(neckoLogPath));
}

function parseNeckoMozLogBytes(rawBuffer) {
    if (!rawBuffer) {
        return {
            exists: false,
            sha256: null,
            bytes: 0,
            lineCount: 0,
            requestBlockCount: 0,
            responseBlockCount: 0,
            http2FrameCount: 0,
            dnsLookupCount: 0,
            socketEventCount: 0,
            parsedRequests: [],
            parsedResponses: []
        };
    }

    const sha256 = crypto.createHash('sha256').update(rawBuffer).digest('hex');
    const bytes = rawBuffer.byteLength;
    const rawLines = rawBuffer.toString('utf8').split(/\r?\n/);

    let lineCount = 0;
    let requestBlockCount = 0;
    let responseBlockCount = 0;
    let http2FrameCount = 0;
    let dnsLookupCount = 0;
    let socketEventCount = 0;
    const parsedRequests = [];
    const parsedResponses = [];

    let currentBlock = null;

    const finalizeBlock = (block) => {
        if (!block || block.lines.length === 0) {
            return;
        }
        const firstLine = block.lines[0].trim();
        const headers = {};

        for (let i = 1; i < block.lines.length; i += 1) {
            const hdrLine = block.lines[i].trim();
            if (!hdrLine) continue;

            const colonIdx = hdrLine.startsWith(':')
                ? hdrLine.indexOf(':', 1)
                : hdrLine.indexOf(':');
            if (colonIdx <= 0) continue;

            const rawName = hdrLine.slice(0, colonIdx).trim();
            const lowerName = rawName.toLowerCase();
            const value = hdrLine.slice(colonIdx + 1).trim();

            if (Object.prototype.hasOwnProperty.call(headers, lowerName)) {
                headers[lowerName] = `${headers[lowerName]}\n${value}`;
            } else {
                headers[lowerName] = value;
            }
        }

        if (block.type === 'request') {
            requestBlockCount += 1;
            const host = headers.host || headers[':authority'] || null;
            parsedRequests.push({
                requestLine: firstLine,
                host,
                headers
            });
        } else if (block.type === 'response') {
            responseBlockCount += 1;
            parsedResponses.push({
                statusLine: firstLine,
                headers
            });
        }
    };

    for (const rawLine of rawLines) {
        const trimmedRaw = rawLine.trim();
        if (!trimmedRaw) {
            continue;
        }
        lineCount += 1;

        if (
            /\bHttp2Session\b|\bHttp2Stream\b|\bHTTP\/2\s+frame\b|\[(HEADERS|DATA|SETTINGS|WINDOW_UPDATE|PING|RST_STREAM|GOAWAY|PRIORITY|PUSH_PROMISE)\s+frame\]/i.test(
                trimmedRaw
            )
        ) {
            http2FrameCount += 1;
        }

        if (/\bnsHostResolver\b|\bResolving\s+host\b|\bDNS\s+lookup\b/i.test(trimmedRaw)) {
            dnsLookupCount += 1;
        }

        if (
            /\bnsSocketTransport\b|\bSocketTransport\b|\bPR_Connect\b|\bMSG_ENSURE_CONNECT\b|\bMSG_DNS_LOOKUP_COMPLETE\b/i.test(
                trimmedRaw
            )
        ) {
            socketEventCount += 1;
        }

        // Strip optional MOZ_LOG timestamp/thread/module prefix (e.g. "...: V/nsHttp ")
        const nsHttpPrefixMatch = trimmedRaw.match(/(?:^|\s)[IDVWE]\/nsHttp:?\s+(.*)$/i);
        const payloadText = nsHttpPrefixMatch ? nsHttpPrefixMatch[1].trim() : trimmedRaw;

        if (!currentBlock) {
            if (/^http\s+request\s*\[$/i.test(payloadText)) {
                currentBlock = { type: 'request', lines: [] };
            } else if (/^http\s+response\s*\[$/i.test(payloadText)) {
                currentBlock = { type: 'response', lines: [] };
            }
        } else if (payloadText === ']') {
            finalizeBlock(currentBlock);
            currentBlock = null;
        } else {
            currentBlock.lines.push(payloadText);
        }
    }

    if (currentBlock) {
        finalizeBlock(currentBlock);
    }

    return redactNeckoMozLogSummary({
        exists: true,
        sha256,
        bytes,
        lineCount,
        requestBlockCount,
        responseBlockCount,
        http2FrameCount,
        dnsLookupCount,
        socketEventCount,
        parsedRequests,
        parsedResponses
    });
}

/**
 * Normalize headers object and optional headersArray so Firefox's exact pre-TLS
 * header order is preserved whenever Playwright's `headersArray()` is available.
 *
 * @param {object} target - Playwright Request or Response
 * @param {'cookie'|'set-cookie'} cookieHeaderName
 */
async function extractHeadersWithOrder(target, cookieHeaderName, observedAt) {
    let headers = {};
    try {
        if (target && typeof target.headers === 'function') {
            headers = target.headers() || {};
        }
    } catch {
        headers = {};
    }

    let headersArray = [];
    try {
        if (target && typeof target.headersArray === 'function') {
            const rawArray = await target.headersArray();
            if (Array.isArray(rawArray)) {
                headersArray = rawArray.map((entry) => ({
                    name: String(entry.name ?? ''),
                    value: String(entry.value ?? '')
                }));
            }
        }
    } catch {
        headersArray = [];
    }

    if (headersArray.length === 0 && headers && typeof headers === 'object') {
        headersArray = Object.entries(headers).map(([name, value]) => ({
            name: String(name),
            value: String(value ?? '')
        }));
    }

    const cookieObservations = deriveCookieObservations({ headers, headersArray }, cookieHeaderName, observedAt);
    return { ...redactSensitiveHeaders({ headers, headersArray }), cookieObservations };
}

function computeEventHash(record) {
    const canonicalPayload = JSON.stringify({ ...record, eventHash: undefined });
    const preimage = `${record.prevEventHash}|${record.seq ?? 0}|${canonicalPayload}`;
    return crypto.createHash('sha256').update(preimage, 'utf8').digest('hex');
}

function isUnfinishedLedgerRecord(line, error) {
    const parseOffset = /\bin JSON at position (\d+)\b/.exec(error.message);
    return line.startsWith('{') && (error.message === 'Unexpected end of JSON input' ||
        Number(parseOffset?.[1]) === line.length);
}

function parseTrafficLedger(raw, { recover = false } = {}) {
    const events = [];
    let head = TRAFFIC_GENESIS_HASH;
    const lines = raw?.toString('utf8').split('\n') ?? [];
    for (const [index, line] of lines.entries()) {
        if (!line.trim()) continue;
        const label = `Line ${index + 1} of traffic.ndjson`;
        let record;
        try {
            record = JSON.parse(line);
        } catch (error) {
            if (recover && index === lines.length - 1 && isUnfinishedLedgerRecord(line, error)) {
                // A prefix of the final JSON object can be left by an interrupted append.
                return { events, head, truncateTo: raw.lastIndexOf(0x0a) + 1 };
            }
            throw new Error(`${label}: Invalid JSON`);
        }

        if (!record || typeof record !== 'object' || Array.isArray(record)) {
            throw new Error(`${label}: Expected an event object`);
        }
        if (record.prevEventHash !== head) {
            throw new Error(`${label}: prevEventHash mismatch`);
        }
        if (record.eventHash !== computeEventHash(record)) {
            throw new Error(`${label}: eventHash mismatch`);
        }
        head = record.eventHash;
        events.push(record);
    }
    return { events, head, truncateTo: null };
}

function readTrafficIndex(trafficDir, { optional = false, trustedLocal = false } = {}) {
    const raw = readCaptureFile(trafficDir, 'attribution-index.json', { optional, trustedLocal });
    if (!raw) return null;
    let index;
    try {
        index = JSON.parse(raw.toString('utf8'));
    } catch {
        throw new Error('Failed to parse attribution-index.json');
    }
    if (!index?.integrity || typeof index.integrity !== 'object' || Array.isArray(index.integrity)) {
        throw new Error('Missing integrity block in attribution-index.json');
    }
    const nativeArtifacts = index.integrity.nativeArtifacts;
    if (nativeArtifacts !== undefined && (
        !nativeArtifacts || typeof nativeArtifacts !== 'object' || Array.isArray(nativeArtifacts) ||
        Object.entries(nativeArtifacts).some(([type, entry]) => !validNativeGenerations(type, entry))
    )) {
        throw new Error('Invalid native artifact declarations in attribution-index.json');
    }
    return index;
}

function verifyLedgerCheckpoint(integrity, events, { allowLaterEvents = false } = {}) {
    const { genesisHash, eventCount, chainHeadHash } = integrity;
    if (genesisHash !== undefined && genesisHash !== TRAFFIC_GENESIS_HASH) {
        throw new Error('Genesis hash mismatch in attribution-index.json');
    }
    if (
        !Number.isSafeInteger(eventCount) || eventCount < 0 ||
        eventCount > events.length || (!allowLaterEvents && eventCount !== events.length)
    ) {
        throw new Error('Event count mismatch between traffic.ndjson and attribution-index.json');
    }
    const checkpoint = eventCount === 0 ? TRAFFIC_GENESIS_HASH : events[eventCount - 1].eventHash;
    if (chainHeadHash !== checkpoint) {
        throw new Error('Chain head hash mismatch between traffic.ndjson and attribution-index.json');
    }
}

function getPayloadManifest(integrity) {
    const manifest = integrity?.payloadManifest ?? {};
    if (typeof manifest !== 'object' || Array.isArray(manifest)) {
        throw new Error('Invalid payload manifest in attribution-index.json');
    }
    if (integrity?.payloadCount !== undefined && integrity.payloadCount !== Object.keys(manifest).length) {
        throw new Error('Payload count mismatch in attribution-index.json');
    }
    return manifest;
}

function isSha256(value) {
    return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function isByteCount(value) {
    return Number.isSafeInteger(value) && value >= 0;
}

function comparePayloadEvidence(expected, actual, label) {
    const { sha256, bytes } = expected;
    if (sha256 != null && !isSha256(sha256)) {
        throw new Error(`Payload SHA-256 digest is invalid for ${label}`);
    }
    if (bytes != null && !isByteCount(bytes)) {
        throw new Error(`Payload byte length is invalid for ${label}`);
    }
    if (sha256 != null && sha256 !== actual.sha256) {
        throw new Error(`Payload SHA-256 mismatch for ${label}`);
    }
    if (bytes != null && bytes !== actual.bytes) {
        throw new Error(`Payload byte length mismatch for ${label}`);
    }
    return sha256 != null && bytes != null;
}

function verifyEventPayload(event, entry, actual, relativePath) {
    const original = {
        sha256: event.postDataSha256 ?? event.bodySha256 ?? event.payloadSha256,
        bytes: event.postDataBytes ?? event.bodyBytes ?? event.payloadBytes
    };
    const isOwner = PAYLOAD_OWNER_TYPES.has(event.type) || event.payloadStorage?.status === 'stored' ||
        original.sha256 != null || original.bytes != null || event.payloadTruncated != null;
    if (!isOwner) return null;

    const label = `${relativePath} (event ${event.seq})`;
    const truncated = event.payloadTruncated ?? false;
    if (typeof truncated !== 'boolean' || (entry?.truncated != null && entry.truncated !== truncated)) {
        throw new Error(`Payload truncation mismatch for ${label}`);
    }
    const stored = event.payloadStorage;
    if (stored && !comparePayloadEvidence(stored, actual, label)) {
        throw new Error(`Missing stored payload digest or length for ${label}`);
    }
    if (!truncated) {
        return comparePayloadEvidence(original, actual, label);
    }
    if (original.sha256 != null && !isSha256(original.sha256)) {
        throw new Error(`Payload SHA-256 digest is invalid for ${label}`);
    }
    if (original.bytes != null && (!isByteCount(original.bytes) || original.bytes <= actual.bytes)) {
        throw new Error(`Payload byte length mismatch for ${label}`);
    }
    return Boolean(stored);
}

function getPayloadCaptureIssues(events) {
    let writeFailures = 0;
    let storageOmissions = 0;
    for (const event of events) {
        if (event?.payloadStorage?.status === 'failed') writeFailures += 1;
        if (event?.payloadStorage?.status === 'omitted') storageOmissions += 1;
    }
    return { writeFailures, storageOmissions };
}

function verifyPayloads(trafficDir, manifest, events, { trustedLocal, check, recoverAfter = null }) {
    const byPath = new Map(Object.keys(manifest).map((relativePath) => [relativePath, []]));
    const unverifiedPayloads = [];
    let verifiedPayloads = 0;
    let observedPayloadBytes = 0;

    for (const [position, event] of events.entries()) {
        check(() => {
            const { payloadFile, payloadStorage } = event;
            if (payloadStorage !== undefined) {
                const stored = payloadStorage?.status === 'stored' && typeof payloadFile === 'string';
                const unavailable = payloadFile == null && !event.payloadTruncated && (
                    (payloadStorage?.status === 'failed' && payloadStorage.reason === 'write-failed') ||
                    (payloadStorage?.status === 'omitted' && payloadStorage.reason === 'storage-limit')
                );
                if (!stored && !unavailable) {
                    throw new Error(`Invalid payload storage state for event ${event.seq}`);
                }
            }
            if (payloadFile == null) return;
            if (typeof payloadFile !== 'string') throw new Error('Invalid event payload file reference');
            const references = byPath.get(payloadFile) ?? [];
            references.push({ event, position });
            byPath.set(payloadFile, references);
        });
    }

    for (const [relativePath, references] of byPath) {
        check(() => {
            const indexed = Object.hasOwn(manifest, relativePath);
            const entry = manifest[relativePath];
            if (!indexed && (recoverAfter === null || references.some(({ position }) => position < recoverAfter))) {
                throw new Error('An event payload file is absent from the payload manifest');
            }
            if (indexed && (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
                (entry.truncated != null && typeof entry.truncated !== 'boolean'))) {
                throw new Error('Invalid entry in payload manifest');
            }

            const actual = hashCapturePayload(trafficDir, relativePath, { trustedLocal });
            observedPayloadBytes += actual.bytes;
            const manifestVerified = indexed && comparePayloadEvidence(entry, actual, relativePath);
            let owner = null;
            let eventVerified = true;
            for (const { event } of references) {
                const result = verifyEventPayload(event, entry, actual, relativePath);
                if (result !== null) {
                    owner ??= event;
                    eventVerified &&= result;
                }
            }
            eventVerified &&= owner !== null;

            if (!indexed) {
                manifest[relativePath] = {
                    ...(eventVerified ? actual : { bytes: actual.bytes }),
                    truncated: Boolean(owner?.payloadTruncated),
                    seq: owner?.seq ?? references[0].event.seq,
                    prefix: owner?.type === 'egress' ? 'req' : owner?.type === 'ingress' ? 'res' : 'ws'
                };
            }
            if (manifestVerified && eventVerified) {
                verifiedPayloads += 1;
            } else {
                unverifiedPayloads.push({
                    path: relativePath,
                    reason: !manifestVerified ? 'missing-manifest-digest-or-length' : 'missing-event-digest-or-length'
                });
            }
        });
    }

    return { verifiedPayloads, unverifiedPayloads, observedPayloadBytes };
}

function nativeArtifactName(trafficDir, configuredPath, fileName) {
    if (!configuredPath) return null;
    const relative = path.relative(trafficDir, configuredPath).split(path.sep).join('/');
    return relative === fileName || relative === `.private/${fileName}` ? relative : null;
}

function profileNativeArtifactName(prefix, fileName) {
    const defaultName = INTEGRITY_ARTIFACTS[prefix];
    if (prefix !== 'sslKeyLog' && prefix !== 'neckoMozLog') return false;
    if (fileName === defaultName) return true;
    const rotationPrefix = `${defaultName}.generation-`;
    return typeof fileName === 'string' && fileName.startsWith(rotationPrefix) &&
        /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(fileName.slice(rotationPrefix.length));
}

function validNativeGenerations(prefix, entry) {
    if (!entry || (entry.previous !== undefined && !Array.isArray(entry.previous))) return false;
    const names = new Set();
    return [entry, ...(entry.previous ?? [])].every((generation) => {
        const fileName = generation?.file ?? INTEGRITY_ARTIFACTS[prefix];
        if (!profileNativeArtifactName(prefix, fileName) || names.has(fileName) ||
            !isSha256(generation?.sha256) || !isByteCount(generation?.bytes) ||
            (generation.closed !== undefined && typeof generation.closed !== 'boolean')) return false;
        names.add(fileName);
        return true;
    });
}

function verifyArtifact(trafficDir, integrity, prefix, { describe, allowAppendedBytes = false, trustedLocal = false } = {}) {
    const fileName = INTEGRITY_ARTIFACTS[prefix];
    const digest = integrity[`${prefix}Sha256`];
    const bytes = integrity[`${prefix}Bytes`];
    const recordedFileName = integrity[`${prefix}File`];
    if (
        recordedFileName !== undefined &&
        recordedFileName !== fileName &&
        (prefix === 'preTlsWireLog' || recordedFileName !== `.private/${fileName}`)
    ) {
        throw new Error(`Invalid capture file reference for ${fileName}`);
    }
    const location = recordedFileName ?? fileName;
    // Legacy summaries used null/zero for an optional artifact that was never written.
    const hasLegacyAbsenceMarker = digest === null && bytes === 0;
    if (recordedFileName === undefined && ((digest == null && bytes == null) || hasLegacyAbsenceMarker)) {
        return null;
    }
    const options = { optional: true, trustedLocal, maxBytes: MAX_INTEGRITY_LOG_BYTES };
    const prefixBytes = allowAppendedBytes && isByteCount(bytes) ? bytes : undefined;
    const file = describe ? readCaptureFile(trafficDir, location, options) : hashCaptureFile(trafficDir, location, {
        ...options, prefixBytes
    });
    if (!file) throw new Error(`Missing ${location} on disk`);
    const actual = describe
        ? { sha256: hashPayload(file.subarray(0, prefixBytes)).sha256, bytes: file.length }
        : file;
    if (digest != null && digest !== actual.sha256) throw new Error(`${fileName} SHA-256 mismatch`);
    if (bytes != null && (
        !isByteCount(bytes) || (allowAppendedBytes ? bytes > actual.bytes : bytes !== actual.bytes)
    )) {
        throw new Error(`${fileName} byte length mismatch`);
    }
    return describe ? describe(file) : file;
}

function verifyProfileNativeGenerations(index, nativeDir, { trustedLocal, check, descriptions = {} }) {
    const unverified = [];
    const artifacts = {};
    const summaries = {};
    for (const [prefix, entry] of Object.entries(index?.integrity.nativeArtifacts ?? {})) {
        const base = INTEGRITY_ARTIFACTS[prefix];
        const verifyGeneration = (generation, describe) => {
            const file = generation.file ?? base;
            const closed = generation.closed ?? Boolean(index.session?.endedAt);
            if (!nativeDir || !closed) unverified.push(file);
            if (nativeDir) {
                const summary = check(() => {
                    const options = { trustedLocal, optional: true, maxBytes: MAX_INTEGRITY_LOG_BYTES };
                    const raw = describe ? readCaptureFile(nativeDir, file, options) : null;
                    const observed = describe
                        ? raw && { sha256: hashPayload(closed ? raw : raw.subarray(0, generation.bytes)).sha256, bytes: raw.length }
                        : hashCaptureFile(nativeDir, file, {
                            ...options, prefixBytes: closed ? undefined : generation.bytes
                        });
                    if (!observed) throw new Error(`Missing ${file} on disk`);
                    if (observed.sha256 !== generation.sha256) throw new Error(`${file} SHA-256 mismatch`);
                    if (closed ? observed.bytes !== generation.bytes : observed.bytes < generation.bytes) {
                        throw new Error(`${file} byte length mismatch`);
                    }
                    if (describe) return describe(raw);
                });
                if (summary) summaries[prefix] = summary;
            }
            return { file, sha256: generation.sha256, bytes: generation.bytes, closed };
        };
        const generation = verifyGeneration(entry, descriptions[prefix]);
        const previous = (entry.previous ?? []).map((older) => verifyGeneration(older));
        artifacts[prefix] = { ...generation, ...(previous.length > 0 ? { previous } : {}) };
    }
    return { artifacts, unverified, summaries };
}

function nextProfileNativePath(nativeDir, prefix, pathName, existing) {
    if (!nativeDir || !pathName || path.dirname(pathName) !== nativeDir) return pathName;
    if (!existing && !fs.lstatSync(pathName, { throwIfNoEntry: false })) return pathName;
    const file = path.basename(pathName);
    if (!profileNativeArtifactName(prefix, file)) return pathName;
    return path.join(nativeDir, `${INTEGRITY_ARTIFACTS[prefix]}.generation-${crypto.randomUUID()}`);
}

/** Select private log paths for a dedicated profile session without a traffic recorder. */
export function selectProfileNativeLogPaths(trafficDir, nativeDir, paths) {
    const trustedLocal = true;
    const index = readTrafficIndex(trafficDir, { optional: true, trustedLocal });
    const { artifacts } = verifyProfileNativeGenerations(index, nativeDir, {
        trustedLocal, check: (verify) => verify()
    });
    return {
        sslKeyLogPath: nextProfileNativePath(nativeDir, 'sslKeyLog', paths.sslKeyLogPath, artifacts.sslKeyLog),
        neckoMozLogPath: nextProfileNativePath(nativeDir, 'neckoMozLog', paths.neckoMozLogPath, artifacts.neckoMozLog)
    };
}

function captureWriterLeaseDirectory(trafficDir) {
    const key = crypto.createHash('sha256').update(path.basename(trafficDir)).digest('hex');
    return path.join(path.dirname(trafficDir), `.camoufox-traffic-${key}~`);
}

function profileDeletionLease(profileDir) {
    const key = crypto.createHash('sha256').update(path.basename(profileDir)).digest('hex');
    return path.join(path.dirname(profileDir), PROFILE_LEASE_DIRECTORY, `~delete-${key}`);
}

function requireLeaseIdle(directory) {
    if (!fs.lstatSync(directory, { throwIfNoEntry: false })) return;
    // The existing lease protocol rejects a live owner and reclaims a dead owner.
    releaseProfileLease(acquireDirectoryLease(directory));
}

function checkDeletingAncestors(directory) {
    for (let current = path.resolve(directory); current !== path.dirname(current); current = path.dirname(current)) {
        requireLeaseIdle(profileDeletionLease(current));
    }
}

/** Hold this outside the profile while checking writers and removing its directory. */
export function acquireProfileTrafficDeletionLease(profileDir) {
    const deletion = acquireDirectoryLease(profileDeletionLease(profileDir));
    try {
        // Explicit trafficDir may name the profile itself or any of its subdirectories.
        requireLeaseIdle(captureWriterLeaseDirectory(profileDir));
        const pending = [profileDir];
        while (pending.length) {
            const directory = pending.pop();
            const entries = listCaptureDirectory(directory, { trustedLocal: true });
            for (const entry of entries) {
                if (!entry.isDirectory()) continue;
                const child = path.join(directory, entry.name);
                if (/^\.camoufox-traffic-[a-f0-9]{64}~$/.test(entry.name)) requireLeaseIdle(child);
                else pending.push(child);
            }
        }
        return deletion;
    } catch (error) {
        releaseProfileLease(deletion);
        throw error;
    }
}

/** Lock the capture at its pathname across both appends and whole-directory migration. */
export function acquireTrafficDirectoryLease(trafficDir) {
    checkDeletingAncestors(trafficDir);
    ensurePrivateDirectory(trafficDir);
    const directory = fs.realpathSync.native(trafficDir);
    const lease = acquireDirectoryLease(captureWriterLeaseDirectory(directory));
    try {
        // Check after publishing the writer too. A concurrent delete must see this
        // writer or this writer must see the deletion before it can append any data.
        checkDeletingAncestors(directory);
        assertProfileLease(lease);
        return lease;
    } catch (error) {
        releaseProfileLease(lease);
        throw error;
    }
}

/** Find the recorder-written ownership and export settings for HAR-only scratch data. */
export function inspectHarScratch(trafficDir, profileId, harDirectory) {
    const options = { optional: true, trustedLocal: true };
    try {
        const index = readTrafficIndex(trafficDir, options);
        const raw = readCaptureFile(trafficDir, 'traffic.ndjson', options);
        const { events } = parseTrafficLedger(raw, { recover: true });
        if (!events.every((event) => event.attribution?.profileId === profileId)) return null;
        const payloads = new Set(events.map((event) => event.payloadFile));
        if (listCapturePayloads(trafficDir, options).some((file) => !payloads.has(file))) return null;

        if (!index) return events.length ? {} : null;
        const { session, artifacts } = index;
        if (session?.profileId !== profileId || !session.traceId ||
            artifacts?.trafficNdjsonPath !== path.join(trafficDir, 'traffic.ndjson') ||
            typeof artifacts.harPath !== 'string' || path.dirname(artifacts.harPath) !== harDirectory ||
            path.extname(artifacts.harPath).toLowerCase() !== '.har') return null;
        verifyLedgerCheckpoint(index.integrity, events);
        return { harPath: artifacts.harPath, recordBodies: session.recordBodies === true };
    } catch {
        return null;
    }
}

const BROWSER_ENV_KEYS = [
    'PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'TZ', 'LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE',
    'LC_COLLATE', 'LC_MESSAGES', 'LC_MONETARY', 'LC_NUMERIC', 'LC_TIME',
    'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'MOZ_ENABLE_WAYLAND', 'GDK_BACKEND',
    'XDG_SESSION_TYPE', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME',
    'XDG_DATA_HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
    'SystemRoot', 'SystemDrive', 'WINDIR', 'COMSPEC', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
    'ProgramFiles', 'ProgramFiles(x86)', 'PROGRAMDATA'
];

export function buildBrowserEnvironment(env, defaults = {}) {
    return Object.fromEntries(BROWSER_ENV_KEYS.flatMap((name) => {
        const value = env[name] ?? defaults[name];
        return typeof value === 'string' ? [[name, value]] : [];
    }));
}

export function buildNativeLogEnvironment(env, { sslKeyLogPath, neckoMozLogPath, neckoMozLogModules } = {}) {
    return {
        ...env,
        SSLKEYLOGFILE: sslKeyLogPath || '',
        MOZ_LOG: neckoMozLogPath ? neckoMozLogModules || '' : '',
        MOZ_LOG_FILE: neckoMozLogPath || '',
        NSPR_LOG_MODULES: '',
        NSPR_LOG_FILE: ''
    };
}

/**
 * Camoufox Pre-TLS Traffic Recorder & Multi-Dimensional Attribution Engine.
 */
export class CamoufoxTrafficRecorder {
    #captureLease;
    #finalSummary = null;
    #finalizationError = null;
    #nativeLogsClosed = false;
    #nativeLogsAreClosed;
    #observationSequence = 0;

    /**
     * @param {object} [options]
     * @param {string} [options.profileId='default-profile']
     * @param {string} [options.profilesDir]
     * @param {string} [options.profileDir]
     * @param {string} [options.trafficDir]
     * @param {string} [options.traceId]
     * @param {string|null} [options.accountId=null]
     * @param {string} [options.os]
     * @param {string|object|null} [options.proxy]
     * @param {string|null} [options.proxyServer]
     * @param {string} [options.actionStep='init']
     * @param {number} [options.maxInlinePreviewBytes=4096]
     * @param {number} [options.inlinePayloadThresholdBytes=0]
     * @param {boolean} [options.capturePayloads=false]
     * @param {boolean} [options.recordBodies=false]
     * @param {number} [options.maxBodyBytes=5242880]
     * @param {number} [options.maxCaptureBytes=33554432] Cumulative ledger, wire and payload bytes.
     * @param {number} [options.maxCaptureEvents=20000] Cumulative ledger event limit.
     * @param {number} [options.maxPendingEvents=512] Concurrent HTTP handler limit.
     * @param {boolean} [options.recordWireLog=true]
     * @param {string|null} [options.preTlsWireLogPath=null]
     * @param {boolean} [options.sslKeyLog=false]
     * @param {string|null} [options.sslKeyLogPath=null]
     * @param {boolean} [options.neckoMozLog=false]
     * @param {string|null} [options.neckoMozLogPath=null]
     * @param {function(): boolean} [options.nativeLogsAreClosed] Managed shutdown confirmation.
     * @param {string|null} [options.profileNativeDir=null]
     * @param {boolean} [options.trustedLocal=false]
     * @param {string|null} [options.harPath=null]
     */
    constructor(options = {}) {
        this.#nativeLogsAreClosed = options.nativeLogsAreClosed;
        const profileId = validateProfileId(options.profileId ?? 'default-profile');
        const requestedRoot = options.profilesDir
            ? path.resolve(options.profilesDir)
            : DEFAULT_PROFILES_DIR;
        const location = !options.profileDir && !options.trafficDir
            ? locateProfile(profileId, requestedRoot, true)
            : null;
        const profilesDir = location?.profilesDir ?? requestedRoot;
        const profileDir = options.profileDir
            ? path.resolve(options.profileDir)
            : location?.profileDir ?? path.join(profilesDir, profileId);
        const trafficDir = options.trafficDir
            ? path.resolve(options.trafficDir)
            : path.join(profileDir, 'traffic');
        if (location) {
            inspectProfileDirectory(location);
            inspectProfileDirectory({ profileDir: trafficDir });
        }

        this.profileId = profileId;
        this.profilesDir = profilesDir;
        this.profileDir = profileDir;
        this.trafficDir = trafficDir;
        this.trustedLocal = options.trustedLocal === true;
        const captureName = path.basename(trafficDir);
        const nativeDirectoryName = captureName === 'traffic' ? '.native' : `.${captureName}-native`;
        const defaultNativeDir = options.trafficDir && !options.profileDir
            ? path.join(path.dirname(trafficDir), nativeDirectoryName)
            : path.join(profileDir, '.native');
        this.profileNativeDir = path.resolve(options.profileNativeDir || defaultNativeDir);

        this.payloadsDir = path.join(this.trafficDir, 'payloads');
        this.trafficNdjsonPath = path.join(this.trafficDir, 'traffic.ndjson');
        this.preTlsWireLogPath = options.preTlsWireLogPath
            ? path.resolve(options.preTlsWireLogPath)
            : path.join(this.trafficDir, 'pre-tls-wire.log');
        this.recordWireLog = options.recordWireLog !== false;
        const neckoMozLog = options.neckoMozLog ?? Boolean(options.neckoMozLogPath);
        const sslKeyLog = options.sslKeyLog ?? Boolean(options.sslKeyLogPath);
        this.neckoMozLogPath = neckoMozLog === true
            ? path.resolve(options.neckoMozLogPath || path.join(this.profileNativeDir, INTEGRITY_ARTIFACTS.neckoMozLog))
            : null;
        this.sslKeyLogPath = sslKeyLog === true
            ? path.resolve(options.sslKeyLogPath || path.join(this.profileNativeDir, INTEGRITY_ARTIFACTS.sslKeyLog))
            : null;
        for (const nativePath of [this.profileNativeDir, this.neckoMozLogPath, this.sslKeyLogPath]) {
            if (nativePath) assertExternalNativePath(this.trafficDir, nativePath);
        }
        this.attributionIndexPath = path.join(this.trafficDir, 'attribution-index.json');
        this.harPath = options.harPath
            ? path.resolve(options.harPath)
            : null;

        this.maxInlinePreviewBytes = Number.isFinite(options.maxInlinePreviewBytes)
            ? Math.max(0, Number(options.maxInlinePreviewBytes))
            : DEFAULT_MAX_INLINE_PREVIEW_BYTES;
        this.inlinePayloadThresholdBytes = Number.isFinite(options.inlinePayloadThresholdBytes)
            ? Math.max(0, Number(options.inlinePayloadThresholdBytes))
            : 0;
        const capturePayloads = options.recordBodies !== undefined
            ? options.recordBodies === true
            : options.capturePayloads === true;
        this.capturePayloads = capturePayloads;
        this.recordBodies = capturePayloads;
        this.maxBodyBytes =
            Number.isFinite(options.maxBodyBytes) && Number(options.maxBodyBytes) > 0
                ? Math.min(MAX_CAPTURE_BYTES, Math.max(1, Math.floor(options.maxBodyBytes)))
                : DEFAULT_MAX_BODY_BYTES;
        this.maxCaptureBytes = Number.isSafeInteger(options.maxCaptureBytes) && options.maxCaptureBytes >= 0
            ? Math.min(options.maxCaptureBytes, MAX_CAPTURE_BYTES) : DEFAULT_MAX_CAPTURE_BYTES;
        this.maxCaptureEvents = Number.isSafeInteger(options.maxCaptureEvents) && options.maxCaptureEvents >= 0
            ? Math.min(options.maxCaptureEvents, MAX_CAPTURE_EVENTS) : MAX_CAPTURE_EVENTS;
        this.maxPendingEvents = Number.isSafeInteger(options.maxPendingEvents) && options.maxPendingEvents >= 0
            ? Math.min(options.maxPendingEvents, MAX_PENDING_TRAFFIC_EVENTS) : MAX_PENDING_TRAFFIC_EVENTS;
        this.captureBytes = 0;
        this.ledgerBytes = 0;
        this.captureStoppedReason = null;
        this.pendingEventLimitReached = false;
        this.omittedWireBlocks = 0;
        this.omittedPayloadFiles = 0;

        const traceId = options.traceId || crypto.randomUUID();
        this.traceId = traceId;
        this.traceIdShort = String(traceId).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8) || 'trace000';
        this.correlationNamespace = `${this.traceIdShort}-${crypto.randomUUID()}`;

        const initialStep = redactDiagnosticText(options.actionStep || 'init');
        const redactedProxy = redactProxyUrl(options.proxyServer || options.proxy || null);

        this.attribution = {
            traceId: this.traceId,
            profileId: this.profileId,
            accountId: options.accountId ?? null,
            os: options.os ? String(options.os).toLowerCase() : detectDefaultOs(),
            proxyServer: redactedProxy,
            actionStep: initialStep,
            stepIndex: 0
        };

        this.startedAt = new Date().toISOString();
        this.startedAtEpochMs = Date.now();
        this.endedAt = null;
        this.stopped = false;

        this.seq = 0;
        this.wsSeq = 0;
        this.triggerSeq = 0;
        this.activeFrameTriggers = new WeakMap();

        // Cryptographic SHA-256 tamper-evident hash chain & payload integrity manifest
        this.genesisHash = TRAFFIC_GENESIS_HASH;
        this.chainHeadHash = this.genesisHash;
        this.chainedEventCount = 0;
        this.payloadManifest = {};
        this.payloadCaptureIssues = { writeFailures: 0, storageOmissions: 0 };
        this.ledgerNeedsSeparator = false;
        this.ledgerWriteError = null;
        this.wireWriteError = null;
        this.priorArtifactIntegrity = null;
        this.priorWireLog = false;
        this.profileNativeArtifacts = {};

        // Correlation & tracking stores
        this.requestCorrelationMap = new WeakMap();
        this.requestAttributions = new WeakMap();
        this.requestTasks = new WeakMap();
        this.recordedRequests = new WeakSet();
        this.transactions = new Map();
        this.attachedContexts = new WeakSet();
        this.attachedPagesHttp = new WeakMap();
        this.attachedPagesWs = new WeakSet();
        this.attachedWebSockets = new WeakSet();
        this.webSocketDisposers = new Set();
        this.listenerDisposers = new Set();
        this.pendingTasks = new Set();

        // Aggregated metrics
        this.totals = {
            totalRequests: 0,
            totalResponses: 0,
            failedRequests: 0,
            wsFramesSent: 0,
            wsFramesReceived: 0,
            unknownWsFramesSent: 0,
            unknownWsFramesReceived: 0,
            totalEgressBytes: 0,
            totalIngressBytes: 0
        };

        this.byActionStep = new Map();
        this.byDomain = new Map();
        this.byTriggerAction = new Map();
        this.cookieLineage = new CookieLineage();
        this.platformSignatures = [];
        this.anomaliesAndRiskSignals = [];
        this.recordedAnomalyKeys = new Set();

        if (location) inspectProfileDirectory({ profileDir: this.profileNativeDir });
        this.#captureLease = acquireTrafficDirectoryLease(this.trafficDir);
        try {
            archiveLegacyNativeLogs({
                trafficDir: this.trafficDir,
                payloadsDir: this.payloadsDir,
                nativeDir: this.profileNativeDir
            });

            this.resetTrafficOnStart = options.resetTrafficOnStart === true;
            if (this.resetTrafficOnStart) {
                for (const artifactPath of [
                    this.trafficNdjsonPath,
                    this.preTlsWireLogPath,
                    this.attributionIndexPath
                ]) {
                    try {
                        if (artifactPath && fs.existsSync(artifactPath)) {
                            fs.rmSync(artifactPath, { force: true });
                        }
                    } catch {}
                }
                try {
                    if (this.payloadsDir && fs.existsSync(this.payloadsDir)) {
                        fs.rmSync(this.payloadsDir, { recursive: true, force: true });
                    }
                } catch {}
            } else {
                this._resumeExistingChainIfPresent();
            }
            this.sslKeyLogPath = nextProfileNativePath(this.profileNativeDir, 'sslKeyLog', this.sslKeyLogPath,
                this.profileNativeArtifacts.sslKeyLog);
            this.neckoMozLogPath = nextProfileNativePath(this.profileNativeDir, 'neckoMozLog', this.neckoMozLogPath,
                this.profileNativeArtifacts.neckoMozLog);
            this.harStartEventCount = this.chainedEventCount;
            this._ensureDirectories();

            const previousWirePath = path.join(this.trafficDir, INTEGRITY_ARTIFACTS.preTlsWireLog);
            const wireFiles = new Map();
            for (const wirePath of new Set([this.preTlsWireLogPath, previousWirePath])) {
                const stats = fs.lstatSync(wirePath, { bigint: true, throwIfNoEntry: false });
                if (stats?.isFile()) wireFiles.set(`${stats.dev}:${stats.ino}`, Number(stats.size));
            }
            for (const bytes of wireFiles.values()) this.captureBytes += bytes;
            this._ensureStepRecord(this.attribution.actionStep, this.attribution.stepIndex);
        } catch (error) {
            releaseProfileLease(this.#captureLease);
            throw error;
        }
    }

    /**
     * Resume an existing persistent profile's SHA-256 tamper-evident event hash chain
     * across process restarts and self-heal any trailing truncated/crashed line in `traffic.ndjson`.
     */
    _resumeExistingChainIfPresent() {
        const trustedLocal = this.trustedLocal;
        const rawContent = readCaptureFile(this.trafficDir, 'traffic.ndjson', { optional: true, trustedLocal });
        const { events: validEvents, head, truncateTo } = parseTrafficLedger(rawContent, {
            recover: true
        });
        const existingIndex = readTrafficIndex(this.trafficDir, { optional: true, trustedLocal });
        if (existingIndex) {
            verifyLedgerCheckpoint(existingIndex.integrity, validEvents, { allowLaterEvents: true });
            this.resumedWireBodyPolicy = {
                recordBodies: existingIndex.session?.recordBodies === true,
                traceId: existingIndex.session?.traceId ?? null
            };
            this.profileNativeArtifacts = verifyProfileNativeGenerations(existingIndex, this.profileNativeDir, {
                trustedLocal,
                check: (verify) => verify()
            }).artifacts;
            for (const artifact of Object.keys(INTEGRITY_ARTIFACTS)) {
                const verified = verifyArtifact(this.trafficDir, existingIndex.integrity, artifact, {
                    allowAppendedBytes: true,
                    trustedLocal
                });
                if (artifact === 'preTlsWireLog' && verified) {
                    this.priorWireLog = true;
                }
            }
            this.priorArtifactIntegrity = existingIndex.integrity;
        }

        let maxSeq = 0;
        let maxStepIndex = 0;
        for (const [index, event] of validEvents.entries()) {
            if (!Number.isSafeInteger(event.seq) || event.seq < 1 || event.seq >= Number.MAX_SAFE_INTEGER - 1) {
                throw new Error(`Invalid or exhausted traffic event sequence at event ${index + 1}`);
            }
            const stepIndex = event.attribution?.stepIndex ?? event.stepIndex ?? 0;
            if (!Number.isSafeInteger(stepIndex) || stepIndex < 0 || stepIndex >= Number.MAX_SAFE_INTEGER) {
                throw new Error(`Invalid or exhausted traffic step index at event ${index + 1}`);
            }
            maxSeq = Math.max(maxSeq, event.seq);
            maxStepIndex = Math.max(maxStepIndex, stepIndex);
            if (Number.isSafeInteger(event.observationSequence)) {
                this.#observationSequence = Math.max(this.#observationSequence, event.observationSequence);
            }
        }

        this.chainHeadHash = head;
        this.seq = maxSeq;
        this.chainedEventCount = validEvents.length;
        if (maxStepIndex > this.attribution.stepIndex) {
            this.attribution.stepIndex = maxStepIndex;
        }

        this.payloadManifest = { ...getPayloadManifest(existingIndex?.integrity) };
        const { observedPayloadBytes } = verifyPayloads(this.trafficDir, this.payloadManifest, validEvents, {
            trustedLocal,
            check: (verify) => verify(),
            recoverAfter: existingIndex?.integrity.eventCount ?? 0
        });
        this.payloadCaptureIssues = getPayloadCaptureIssues(validEvents);
        this.cookieLineage.observeAll(validEvents);

        for (const ev of validEvents) {
            if (ev.type === 'trigger-action' && ev.actionId) {
                this.triggerSeq += 1;
            }
            if (ev.type === 'ws-open') {
                this.wsSeq += 1;
            }
        }

        // Rebuild cumulative totals, byActionStep, byDomain, byTriggerAction, and anomalies from validEvents
        // so stats are always consistent even if the previous session crashed before flushSummary()
        const validCorrIds = new Set();
        const txSizesByCorr = new Map();
        const txStepByCorr = new Map();
        const txTriggerByCorr = new Map();
        const txReqPayloadByCorr = new Map();

        for (const ev of validEvents) {
            if (ev.correlationId) {
                validCorrIds.add(ev.correlationId);
            }
        }

        for (const event of validEvents) {
            const ev = { ...event };
            if (event.triggerAction) ev.triggerAction = redactTriggerAction(event.triggerAction);
            if (event.url) ev.url = redactUrlSecrets(event.url);
            if (event.targetUrl) ev.targetUrl = redactUrlSecrets(event.targetUrl);
            if (event.failureText) ev.failureText = redactDiagnosticText(event.failureText);
            if (event.reason) ev.reason = redactDiagnosticText(event.reason);

            const stepName = ev.attribution?.actionStep || ev.actionStep || 'init';
            const stepIndex = ev.attribution?.stepIndex ?? ev.stepIndex ?? 0;
            this._ensureStepRecord(stepName, stepIndex);

            if (ev.type === 'trigger-action' && ev.triggerAction) {
                this._ensureTriggerActionRecord(ev.triggerAction);
            } else if (ev.type === 'egress') {
                const headersArr = Array.isArray(ev.headersArray) ? ev.headersArray : [];
                const parsedUrl = parseUrlComponents(ev.url || '');
                const headerByteEstimate = headersArr.reduce(
                    (acc, h) => acc + Buffer.byteLength(`${h.name}: ${h.value}\r\n`, 'utf8'),
                    Buffer.byteLength(
                        `${ev.method || 'GET'} ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1\r\n\r\n`,
                        'utf8'
                    )
                );
                const estimatedEgressBytes = headerByteEstimate + (Number(ev.postDataBytes) || 0);
                if (ev.correlationId) {
                    txSizesByCorr.set(ev.correlationId, {
                        estimatedEgressBytes,
                        countedIngressBytes: txSizesByCorr.get(ev.correlationId)?.countedIngressBytes ?? 0
                    });
                    txStepByCorr.set(ev.correlationId, { stepName, stepIndex });
                    if (ev.triggerAction) {
                        txTriggerByCorr.set(ev.correlationId, ev.triggerAction);
                    }
                }

                this.totals.totalRequests += 1;
                this.totals.totalEgressBytes += estimatedEgressBytes;

                const stepBucket = this._ensureStepRecord(stepName, stepIndex);
                stepBucket.requests += 1;
                stepBucket.egressBytes += estimatedEgressBytes;
                stepBucket.domainsSet.add(parsedUrl.host);

                const domainBucket = this._ensureDomainRecord(parsedUrl.host);
                domainBucket.requests += 1;
                domainBucket.egressBytes += estimatedEgressBytes;

                const triggerBucket = this._ensureTriggerActionRecord(ev.triggerAction);
                if (triggerBucket) {
                    triggerBucket.requests += 1;
                    triggerBucket.egressBytes += estimatedEgressBytes;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    if (ev.correlationId) {
                        triggerBucket.correlationIdsSet.add(ev.correlationId);
                    }
                }

                const restoredSignatures = Array.isArray(ev.platformSignatures)
                    ? ev.platformSignatures
                    : extractPlatformSignatures({
                          url: ev.url || '',
                          searchParams: ev.searchParams || parsedUrl.searchParams,
                          headers: ev.headers || {},
                          bodyPreview: ev.bodyPreview ?? ev.postData ?? null
                      });
                for (const signature of restoredSignatures) {
                    if (!signature || typeof signature !== 'object') continue;
                    const sig = redactDiagnosticMetadata(signature);
                    this.platformSignatures.push({
                        timestamp: ev.timestamp || null,
                        correlationId: ev.correlationId || null,
                        actionStep: stepName,
                        stepIndex,
                        triggerActionId: ev.triggerAction?.actionId || null,
                        triggerTarget: ev.triggerAction?.target || null,
                        method: ev.method || 'GET',
                        url: ev.url || '',
                        host: parsedUrl.host,
                        platform: sig.platform,
                        signatureName: sig.signatureName,
                        location: sig.location,
                        valueLength: sig.location === 'body' ? null : sig.valueLength,
                        valueSha256: sig.location === 'body' ? null : sig.valueSha256,
                        maskedPreview: sig.location === 'body' ? '[REDACTED]' : sig.maskedPreview
                    });
                }

                if (ev.correlationId && ev.payloadFile) {
                    txReqPayloadByCorr.set(ev.correlationId, ev.payloadFile);
                }

                const egressRiskSignals = Array.isArray(ev.riskSignals)
                    ? RISK_SIGNAL_PATTERNS.flatMap(({ name, severity }) => {
                          const source = ev.riskSignals.find((signal) => signal?.name === name)?.source;
                          return ['url', 'headers', 'body'].includes(source) ? [{ name, severity, source }] : [];
                      })
                    : detectRiskSignals({
                          url: ev.url || '',
                          bodyPreview: ev.bodyPreview ?? ev.postData ?? null,
                          headers: ev.headers || {}
                      });
                if (egressRiskSignals.length > 0) {
                    const highestSeverity = egressRiskSignals.some((s) => s.severity === 'critical')
                        ? 'critical'
                        : egressRiskSignals.some((s) => s.severity === 'high')
                          ? 'high'
                          : 'medium';
                    this._recordAnomaly({
                        timestamp: ev.timestamp,
                        correlationId: ev.correlationId || null,
                        actionStep: stepName,
                        triggerAction: ev.triggerAction || null,
                        type: `risk-signal:${egressRiskSignals.map((s) => s.name).join('+')}`,
                        severity: highestSeverity,
                        method: ev.method || 'GET',
                        url: ev.url || null,
                        status: null,
                        failureText: null,
                        payloadFile: ev.payloadFile || null,
                        matchedSignals: egressRiskSignals
                    });
                }

                const egressWireAnomalies = detectWireHeaderAnomalies({
                    headers: ev.headers || {},
                    headersArray: headersArr,
                    expectedOs: ev.attribution?.os || this.attribution.os,
                    direction: 'egress'
                });
                for (const wa of egressWireAnomalies) {
                    this._recordAnomaly({
                        timestamp: ev.timestamp,
                        correlationId: ev.correlationId || null,
                        actionStep: stepName,
                        triggerAction: ev.triggerAction || null,
                        type: wa.type,
                        severity: wa.severity,
                        method: ev.method || 'GET',
                        url: ev.url || null,
                        status: null,
                        failureText: wa.reason,
                        payloadFile: ev.payloadFile || null
                    });
                }
            } else if (ev.type === 'ingress') {
                const headersArr = Array.isArray(ev.headersArray) ? ev.headersArray : [];
                const parsedUrl = parseUrlComponents(ev.url || '');
                const status = Number(ev.status ?? 0);
                const statusText = ev.statusText || '';
                const headerByteEstimate = headersArr.reduce(
                    (acc, h) => acc + Buffer.byteLength(`${h.name}: ${h.value}\r\n`, 'utf8'),
                    Buffer.byteLength(`HTTP/1.1 ${status} ${statusText}\r\n\r\n`, 'utf8')
                );
                const estimatedIngressBytes = headerByteEstimate + (Number(ev.bodyBytes) || 0);
                if (ev.correlationId) {
                    txSizesByCorr.set(ev.correlationId, {
                        estimatedEgressBytes: txSizesByCorr.get(ev.correlationId)?.estimatedEgressBytes ?? 0,
                        countedIngressBytes: estimatedIngressBytes
                    });
                }

                const txStep = ev.correlationId ? txStepByCorr.get(ev.correlationId) : null;
                const effectiveStepName = txStep?.stepName || stepName;
                const effectiveStepIndex = txStep?.stepIndex ?? stepIndex;
                const effectiveTrigger =
                    ev.triggerAction ||
                    (ev.correlationId ? txTriggerByCorr.get(ev.correlationId) || null : null);

                this.totals.totalResponses += 1;
                this.totals.totalIngressBytes += estimatedIngressBytes;

                const statusKey = String(status);
                const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
                stepBucket.responses += 1;
                stepBucket.ingressBytes += estimatedIngressBytes;
                stepBucket.domainsSet.add(parsedUrl.host);
                stepBucket.statusCounts[statusKey] = (stepBucket.statusCounts[statusKey] || 0) + 1;

                const domainBucket = this._ensureDomainRecord(parsedUrl.host);
                domainBucket.responses += 1;
                domainBucket.ingressBytes += estimatedIngressBytes;
                domainBucket.statusCounts[statusKey] = (domainBucket.statusCounts[statusKey] || 0) + 1;

                const triggerBucket = this._ensureTriggerActionRecord(effectiveTrigger);
                if (triggerBucket) {
                    triggerBucket.responses += 1;
                    triggerBucket.ingressBytes += estimatedIngressBytes;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    if (ev.correlationId) {
                        triggerBucket.correlationIdsSet.add(ev.correlationId);
                    }
                    triggerBucket.statusCounts[statusKey] = (triggerBucket.statusCounts[statusKey] || 0) + 1;
                }

                const effectivePayloadFile =
                    ev.payloadFile ||
                    (ev.correlationId ? txReqPayloadByCorr.get(ev.correlationId) || null : null);

                const httpAnomaly = classifyTrafficLifecycleAnomaly(ev);
                if (httpAnomaly) {
                    this._recordAnomaly({
                        timestamp: ev.timestamp,
                        correlationId: ev.correlationId || null,
                        actionStep: effectiveStepName,
                        triggerAction: effectiveTrigger,
                        ...httpAnomaly,
                        method: ev.method || 'GET',
                        url: ev.url || null,
                        status,
                        failureText: statusText || `HTTP ${status}`,
                        payloadFile: effectivePayloadFile
                    });
                }

                const ingressRiskSignals = detectRiskSignals({
                    url: ev.url || '',
                    bodyPreview: ev.bodyPreview ?? null,
                    headers: ev.headers || {}
                });
                if (ingressRiskSignals.length > 0) {
                    const highestSeverity = ingressRiskSignals.some((s) => s.severity === 'critical')
                        ? 'critical'
                        : ingressRiskSignals.some((s) => s.severity === 'high')
                          ? 'high'
                          : 'medium';
                    this._recordAnomaly({
                        timestamp: ev.timestamp,
                        correlationId: ev.correlationId || null,
                        actionStep: effectiveStepName,
                        triggerAction: effectiveTrigger,
                        type: `risk-signal:${ingressRiskSignals.map((s) => s.name).join('+')}`,
                        severity: highestSeverity,
                        method: ev.method || 'GET',
                        url: ev.url || null,
                        status,
                        failureText: null,
                        payloadFile: effectivePayloadFile,
                        matchedSignals: ingressRiskSignals
                    });
                }

                const ingressWireAnomalies = detectWireHeaderAnomalies({
                    headers: ev.headers || {},
                    headersArray: headersArr,
                    expectedOs: ev.attribution?.os || this.attribution.os,
                    direction: 'ingress'
                });
                for (const wa of ingressWireAnomalies) {
                    this._recordAnomaly({
                        timestamp: ev.timestamp,
                        correlationId: ev.correlationId || null,
                        actionStep: effectiveStepName,
                        triggerAction: effectiveTrigger,
                        type: wa.type,
                        severity: wa.severity,
                        method: ev.method || 'GET',
                        url: ev.url || null,
                        status,
                        failureText: wa.reason,
                        payloadFile: effectivePayloadFile
                    });
                }
            } else if (ev.type === 'request-finished') {
                const parsedUrl = parseUrlComponents(ev.url || '');
                const domainBucket = this._ensureDomainRecord(parsedUrl.host);
                if (typeof ev.durationMs === 'number' && Number.isFinite(ev.durationMs)) {
                    domainBucket.totalDurationMs += ev.durationMs;
                    domainBucket.completedWithDurationCount += 1;
                }
                const txSizes = txSizesByCorr.get(ev.correlationId);
                if (txSizes && ev.sizes && typeof ev.sizes === 'object') {
                    const txStep = txStepByCorr.get(ev.correlationId);
                    const stepBucket = this._ensureStepRecord(
                        txStep?.stepName || stepName,
                        txStep?.stepIndex ?? stepIndex
                    );
                    const triggerBucket = this._ensureTriggerActionRecord(
                        ev.triggerAction || txTriggerByCorr.get(ev.correlationId) || null
                    );
                    this._reconcileTransactionSizes(ev.sizes, txSizes, stepBucket, domainBucket, triggerBucket);
                }
            } else if (ev.type === 'request-failed') {
                const parsedUrl = parseUrlComponents(ev.url || '');
                const txStep = ev.correlationId ? txStepByCorr.get(ev.correlationId) : null;
                const effectiveStepName = txStep?.stepName || stepName;
                const effectiveStepIndex = txStep?.stepIndex ?? stepIndex;
                const effectiveTrigger =
                    ev.triggerAction ||
                    (ev.correlationId ? txTriggerByCorr.get(ev.correlationId) || null : null);

                this.totals.failedRequests += 1;
                const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
                stepBucket.failedRequests += 1;
                stepBucket.domainsSet.add(parsedUrl.host);

                const domainBucket = this._ensureDomainRecord(parsedUrl.host);
                domainBucket.failedRequests += 1;
                if (typeof ev.durationMs === 'number' && Number.isFinite(ev.durationMs)) {
                    domainBucket.totalDurationMs += ev.durationMs;
                    domainBucket.completedWithDurationCount += 1;
                }

                const triggerBucket = this._ensureTriggerActionRecord(effectiveTrigger);
                if (triggerBucket) {
                    triggerBucket.failedRequests += 1;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    if (ev.correlationId) {
                        triggerBucket.correlationIdsSet.add(ev.correlationId);
                    }
                }
                const failureText = ev.failureText || 'UNKNOWN_NETWORK_FAILURE';
                this._recordAnomaly({
                    timestamp: ev.timestamp,
                    correlationId: ev.correlationId || null,
                    actionStep: effectiveStepName,
                    triggerAction: effectiveTrigger,
                    ...classifyTrafficLifecycleAnomaly(ev),
                    method: ev.method || null,
                    url: ev.url || null,
                    status: null,
                    failureText
                });
            } else if (ev.type === 'security-block') {
                this.totals.failedRequests += 1;
                const parsedUrl = parseUrlComponents(ev.url || ev.targetUrl || '');
                const effectiveTrigger = ev.triggerAction || null;
                const stepBucket = this._ensureStepRecord(stepName, stepIndex);
                stepBucket.failedRequests += 1;
                stepBucket.domainsSet.add(parsedUrl.host);

                const domainBucket = this._ensureDomainRecord(parsedUrl.host);
                domainBucket.failedRequests += 1;

                const triggerBucket = this._ensureTriggerActionRecord(effectiveTrigger);
                if (triggerBucket) {
                    triggerBucket.failedRequests += 1;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    if (ev.correlationId) {
                        triggerBucket.correlationIdsSet.add(ev.correlationId);
                    }
                }
                this._recordAnomaly(securityBlockAnomaly(ev));
            } else if (ev.type === 'ws-egress' || ev.type === 'ws-ingress') {
                const parsedUrl = parseUrlComponents(ev.url || '');
                const stepBucket = this._ensureStepRecord(stepName, stepIndex);
                const domainBucket = this._ensureDomainRecord(parsedUrl.host);
                const triggerBucket = this._ensureTriggerActionRecord(ev.triggerAction);
                stepBucket.domainsSet.add(parsedUrl.host);
                this._countWebSocketFrame(ev, stepBucket, domainBucket, triggerBucket);
            } else if (ev.type === 'ws-error') {
                const parsedUrl = parseUrlComponents(ev.url || '');
                const stepBucket = this._ensureStepRecord(stepName, stepIndex);
                stepBucket.domainsSet.add(parsedUrl.host);
                this._ensureDomainRecord(parsedUrl.host);
                const triggerBucket = this._ensureTriggerActionRecord(ev.triggerAction || null);
                if (triggerBucket) {
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    if (ev.correlationId) {
                        triggerBucket.correlationIdsSet.add(ev.correlationId);
                    }
                }
                this._recordAnomaly({
                    timestamp: ev.timestamp,
                    correlationId: ev.correlationId || null,
                    actionStep: stepName,
                    triggerAction: ev.triggerAction || null,
                    ...classifyTrafficLifecycleAnomaly(ev),
                    method: 'WEBSOCKET',
                    url: ev.url || null,
                    status: null,
                    failureText: ev.failureText || 'WEBSOCKET_ERROR',
                    payloadFile: null
                });
            }
        }

        // Restore persisted anomalies from attribution-index.json if available
        if (Array.isArray(existingIndex?.anomaliesAndRiskSignals)) {
            for (const anomaly of existingIndex.anomaliesAndRiskSignals) {
                if (!anomaly || typeof anomaly !== 'object' ||
                    /^security-block(?::|$)/.test(anomaly.type)) continue;
                if (anomaly.correlationId && !validCorrIds.has(anomaly.correlationId)) {
                    continue;
                }
                this._recordAnomaly({
                    ...anomaly,
                    triggerAction: redactTriggerAction(anomaly.triggerAction)
                });
            }
        }

        this.omittedPayloadFiles = this.payloadCaptureIssues.storageOmissions;
        const omittedWireBlocks = existingIndex?.captureLimits?.omittedWireBlocks;
        if (Number.isSafeInteger(omittedWireBlocks) && omittedWireBlocks >= 0) {
            this.omittedWireBlocks = Math.min(omittedWireBlocks, validEvents.length);
        }
        if (truncateTo !== null) {
            truncateCaptureFile(this.trafficDir, 'traffic.ndjson', rawContent, truncateTo, { trustedLocal });
        } else {
            // An interrupted write may have stored the full event except its line delimiter.
            this.ledgerNeedsSeparator = Boolean(rawContent?.length && rawContent.at(-1) !== 0x0a);
        }
        this.ledgerBytes = truncateTo ?? rawContent?.byteLength ?? 0;
        this.captureBytes = this.ledgerBytes + observedPayloadBytes + this._recoverPendingPayloads();
    }

    _recoverPendingPayloads() {
        if (!fs.lstatSync(this.payloadsDir, { throwIfNoEntry: false })) return 0;
        const storage = { trustedLocal: this.trustedLocal };
        const inventory = new Set(listCapturePayloads(this.trafficDir, storage));
        for (const pendingFile of inventory) {
            const match = PENDING_PAYLOAD_PATTERN.exec(pendingFile);
            const temporaryFile = `${pendingFile}.tmp`;
            if (!match || Object.hasOwn(this.payloadManifest, pendingFile) ||
                Object.hasOwn(this.payloadManifest, temporaryFile) ||
                measureCapturePayload(this.trafficDir, pendingFile, storage) !== 0) continue;
            const payloadFile = `payloads/${match[1]}`;
            const keepPayload = Object.hasOwn(this.payloadManifest, payloadFile);
            this._resolvePendingPayload(payloadFile, pendingFile, keepPayload);
            inventory.delete(pendingFile);
            inventory.delete(temporaryFile);
            if (!keepPayload) inventory.delete(payloadFile);
        }
        // Older unindexed files lack a write marker. Preserve them and account for their disk space.
        let unindexedBytes = 0;
        for (const relativePath of inventory) {
            if (!Object.hasOwn(this.payloadManifest, relativePath)) {
                unindexedBytes += measureCapturePayload(this.trafficDir, relativePath, storage);
            }
        }
        return unindexedBytes;
    }

    /** Ensure diagnostic storage and explicitly enabled private logging are ready. */
    _ensureDirectories() {
        ensurePrivateDirectory(this.payloadsDir);
        for (const [nativeLogPath, initialText] of [
            [this.sslKeyLogPath, '# NSS SSL/TLS Secrets Log (Camoufox Pre-TLS Traffic Recorder)\n'],
            [this.neckoMozLogPath, '']
        ]) {
            if (!nativeLogPath) continue;
            assertExternalNativePath(this.trafficDir, nativeLogPath);
            const parent = path.dirname(nativeLogPath);
            if (parent === this.profileNativeDir) {
                ensurePrivateDirectory(parent);
            } else {
                fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
            }
            try {
                restrictPrivateFile(nativeLogPath);
            } catch (error) {
                if (error.code !== 'ENOENT') throw error;
                appendPrivateFile(nativeLogPath, initialText);
            }
        }
        if (this.recordWireLog && !fs.existsSync(this.preTlsWireLogPath)) {
            appendPrivateFile(this.preTlsWireLogPath, '');
        }
    }

    /**
     * Return the launch environment with only this recorder's enabled native log destinations.
     *
     * @param {Record<string, string>} [baseEnv=process.env]
     * @returns {Record<string, string>}
     */
    getLaunchEnv(baseEnv = process.env) {
        this._ensureDirectories();
        return buildNativeLogEnvironment(buildBrowserEnvironment(baseEnv), {
            sslKeyLogPath: this.sslKeyLogPath,
            neckoMozLogPath: this.neckoMozLogPath,
            neckoMozLogModules: baseEnv.MOZ_LOG
        });
    }

    /**
     * Return the reserved NSS `SSLKEYLOGFILE` path.
     *
     * @returns {string|null}
     */
    getSslKeyLogPath() {
        return this.sslKeyLogPath;
    }

    /**
     * Append a validated NSS TLS secret line (`<LABEL> <CLIENT_RANDOM_HEX> <SECRET_HEX>`)
     * to `this.sslKeyLogPath`.
     *
     * @param {string} label - NSS key log label (e.g. `CLIENT_RANDOM`, `CLIENT_TRAFFIC_SECRET_0`)
     * @param {string} clientRandomHex - 64-character hex string (32-byte client random)
     * @param {string} secretHex - Hex-encoded TLS secret material
     * @returns {{ label: string, clientRandomHex: string, secretHex: string, line: string }|null}
     */
    recordSslKeyLogSecret(label, clientRandomHex, secretHex) {
        if (this.stopped || !this.sslKeyLogPath) return null;

        const cleanLabel = String(label || '').trim().toUpperCase();
        const cleanRandom = String(clientRandomHex || '').trim().toLowerCase();
        const cleanSecret = String(secretHex || '').trim().toLowerCase();

        if (
            !/^[A-Z0-9_]+$/.test(cleanLabel) ||
            !/^[0-9a-f]{64}$/.test(cleanRandom) ||
            !/^[0-9a-f]{16,256}$/.test(cleanSecret) ||
            cleanSecret.length % 2 !== 0
        ) {
            throw new Error(
                `Invalid NSS SSLKEYLOGFILE secret format: label="${cleanLabel}" randomLen=${cleanRandom.length} secretLen=${cleanSecret.length}`
            );
        }

        this._ensureDirectories();
        const line = `${cleanLabel} ${cleanRandom} ${cleanSecret}`;
        appendPrivateFile(this.sslKeyLogPath, `${line}\n`);
        return {
            label: cleanLabel,
            clientRandomHex: cleanRandom,
            secretHex: cleanSecret,
            line
        };
    }

    /**
     * Append raw or simulated Firefox C++ Necko `MOZ_LOG` lines to `this.neckoMozLogPath`.
     *
     * @param {string} rawLogText
     * @returns {{ neckoMozLogPath: string|null, appendedBytes: number }}
     */
    recordNeckoMozLogBlock(rawLogText) {
        if (this.stopped || !this.neckoMozLogPath || rawLogText == null) {
            return {
                neckoMozLogPath: this.neckoMozLogPath,
                appendedBytes: 0
            };
        }
        const text = String(rawLogText);
        if (text.length === 0) {
            return {
                neckoMozLogPath: this.neckoMozLogPath,
                appendedBytes: 0
            };
        }

        this._ensureDirectories();
        const normalized = text.endsWith('\n') ? text : `${text}\n`;
        appendPrivateFile(this.neckoMozLogPath, normalized);
        return {
            neckoMozLogPath: this.neckoMozLogPath,
            appendedBytes: Buffer.byteLength(normalized, 'utf8')
        };
    }

    /**
     * Return a shallow immutable snapshot of the current attribution envelope.
     */
    getAttributionSnapshot() {
        return {
            traceId: this.attribution.traceId,
            profileId: this.attribution.profileId,
            accountId: this.attribution.accountId,
            accountEmail: null,
            os: this.attribution.os,
            proxyServer: this.attribution.proxyServer,
            actionStep: this.attribution.actionStep,
            stepIndex: this.attribution.stepIndex
        };
    }

    /**
     * Update attribution metadata (`accountId`, `proxyServer`, `os`, etc.) dynamically.
     *
     * @param {object} [partial={}]
     * @returns {object} Updated attribution snapshot
     */
    updateAttribution(partial = {}) {
        if (this.stopped || !partial || typeof partial !== 'object') {
            return this.getAttributionSnapshot();
        }

        if (partial.profileId !== undefined && partial.profileId !== null) {
            this.attribution.profileId = String(partial.profileId);
            this.profileId = this.attribution.profileId;
        }
        if (partial.accountId !== undefined) {
            this.attribution.accountId = partial.accountId ?? null;
        }
        if (partial.os !== undefined && partial.os !== null) {
            this.attribution.os = String(partial.os).toLowerCase();
        }
        if (partial.proxyServer !== undefined || partial.proxy !== undefined) {
            this.attribution.proxyServer = redactProxyUrl(partial.proxyServer ?? partial.proxy);
        }
        if (partial.actionStep !== undefined && partial.actionStep !== null) {
            const nextStep = String(partial.actionStep);
            if (nextStep !== this.attribution.actionStep) {
                this.setStep(nextStep, partial.metadata || {});
            }
        }

        return this.getAttributionSnapshot();
    }

    /**
     * Advance workflow attribution to a named action step, incrementing `stepIndex`
     * and recording a `step-transition` event in `traffic.ndjson`.
     *
     * @param {string} stepName
     * @param {object} [metadata={}]
     * @returns {object} Current attribution snapshot
     */
    setStep(stepName, metadata = {}) {
        if (!this._canStartRecording()) return this.getAttributionSnapshot();
        const cleanedStep = redactDiagnosticText(stepName || 'unnamed-step').trim() || 'unnamed-step';
        const previousStep = this.attribution.actionStep;
        const previousStepIndex = this.attribution.stepIndex;

        const seq = this._nextSeq();
        const stepIndex = previousStepIndex + 1;
        const recorded = this._appendNdjsonEvent({
            type: 'step-transition',
            eventType: 'step-transition',
            direction: 'internal',
            stage: 'workflow-attribution',
            timestamp: new Date().toISOString(),
            epochMs: Date.now(),
            seq,
            previousStep,
            previousStepIndex,
            actionStep: cleanedStep,
            stepIndex,
            metadata: redactDiagnosticMetadata(metadata),
            attribution: { ...this.getAttributionSnapshot(), actionStep: cleanedStep, stepIndex }
        });
        if (recorded) {
            this.attribution.stepIndex = stepIndex;
            this.attribution.actionStep = cleanedStep;
            this._ensureStepRecord(cleanedStep, stepIndex);
        }
        return this.getAttributionSnapshot();
    }

    /**
     * Record a UI action. A page or frame allows time-based association with
     * later requests in that frame.
     *
     * @param {string} actionType - e.g. 'page.click', 'page.goto', 'page.fill'
     * @param {string|null} [target=null] - CSS selector, URL, or element descriptor
     * @param {object} [metadata={}] - Additional action metadata
     * @param {object|null} [source=null] - Originating Playwright page or frame
     * @returns {object|null} Recorded trigger action snapshot
     */
    recordTriggerAction(actionType, target = null, metadata = {}, source = null) {
        if (!this._canStartRecording()) return null;
        this.triggerSeq += 1;
        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const action = redactTriggerAction({
            actionId: `act-${this.correlationNamespace}-${this.triggerSeq}`,
            actionType: String(actionType || 'unknown'),
            target: target ? String(target) : null,
            timestamp,
            epochMs,
            actionStep: this.attribution.actionStep,
            stepIndex: this.attribution.stepIndex,
            metadata
        });

        const seq = this._nextSeq();
        const recorded = this._appendNdjsonEvent({
            type: 'trigger-action',
            eventType: 'trigger-action',
            direction: 'internal',
            stage: 'ui-driver-action',
            timestamp,
            epochMs,
            seq,
            actionId: action.actionId,
            actionType: action.actionType,
            target: action.target,
            actionStep: action.actionStep,
            stepIndex: action.stepIndex,
            metadata: action.metadata,
            triggerAction: {
                ...action,
                elapsedSinceActionMs: 0
            },
            attribution: this.getAttributionSnapshot()
        });

        if (!recorded) return null;
        try {
            const frame = source?.mainFrame?.() || source;
            if (frame && typeof frame === 'object') this.activeFrameTriggers.set(frame, action);
        } catch {}
        this._ensureTriggerActionRecord(action);
        return { ...action };
    }

    /** Associate a new request with a recent recorded action in its own frame. */
    getActiveTriggerSnapshot(nowEpochMs = Date.now(), frame = null) {
        const action = this.activeFrameTriggers.get(frame);
        if (!action) return null;
        const elapsedSinceActionMs = nowEpochMs - action.epochMs;
        if (elapsedSinceActionMs < 0 || elapsedSinceActionMs > MAX_TRIGGER_DELAY_MS) return null;
        return { ...action, elapsedSinceActionMs, association: 'inferred' };
    }

    /**
     * Allocate the next monotonic event sequence integer.
     *
     * @returns {number}
     */
    _nextSeq() {
        if (!Number.isSafeInteger(this.seq) || this.seq < 0 || this.seq >= Number.MAX_SAFE_INTEGER) {
            const error = new RangeError('Traffic event sequence exhausted');
            this.ledgerWriteError = error;
            throw error;
        }
        this.seq += 1;
        return this.seq;
    }

    _canStartRecording() {
        return !this.stopped && !this.pendingEventLimitReached && this._canRecordEvent();
    }

    _canRecordEvent() {
        if (this.captureStoppedReason || this.ledgerWriteError) return false;
        if (this.chainedEventCount >= this.maxCaptureEvents) {
            this.captureStoppedReason = 'event-limit';
        } else if (this.captureBytes >= this.maxCaptureBytes) {
            this.captureStoppedReason = 'storage-limit';
        }
        return !this.captureStoppedReason;
    }

    /**
     * Ensure per-step stats bucket exists.
     *
     * @param {string} stepName
     * @param {number} stepIndex
     */
    _ensureStepRecord(stepName, stepIndex) {
        if (!this.byActionStep.has(stepName)) {
            this.byActionStep.set(stepName, {
                stepIndex,
                requests: 0,
                responses: 0,
                failedRequests: 0,
                egressBytes: 0,
                ingressBytes: 0,
                statusCounts: {},
                domainsSet: new Set(),
                anomalyCount: 0
            });
        }
        return this.byActionStep.get(stepName);
    }

    /**
     * Ensure per-domain stats bucket exists.
     *
     * @param {string} host
     */
    _ensureDomainRecord(host) {
        const key = String(host || 'unknown').toLowerCase();
        if (!this.byDomain.has(key)) {
            this.byDomain.set(key, {
                requests: 0,
                responses: 0,
                failedRequests: 0,
                egressBytes: 0,
                ingressBytes: 0,
                statusCounts: {},
                totalDurationMs: 0,
                completedWithDurationCount: 0
            });
        }
        return this.byDomain.get(key);
    }

    /**
     * Ensure per-trigger-action stats bucket exists.
     *
     * @param {object|null} triggerAction
     * @returns {object|null}
     */
    _ensureTriggerActionRecord(triggerAction) {
        if (!triggerAction || !triggerAction.actionId) {
            return null;
        }
        const key = triggerAction.actionId;
        if (!this.byTriggerAction.has(key)) {
            this.byTriggerAction.set(key, {
                actionId: triggerAction.actionId,
                actionType: triggerAction.actionType || 'unknown',
                target: triggerAction.target ?? null,
                actionStep: triggerAction.actionStep || this.attribution.actionStep,
                stepIndex: triggerAction.stepIndex ?? this.attribution.stepIndex,
                timestamp: triggerAction.timestamp || new Date().toISOString(),
                metadata: triggerAction.metadata || {},
                requests: 0,
                responses: 0,
                failedRequests: 0,
                wsFramesSent: 0,
                wsFramesReceived: 0,
                egressBytes: 0,
                ingressBytes: 0,
                statusCounts: {},
                domainsSet: new Set(),
                correlationIdsSet: new Set(),
                anomalyCount: 0
            });
        }
        return this.byTriggerAction.get(key);
    }

    _reconcileTransactionSizes(sizes, tx, stepBucket, domainBucket, triggerBucket) {
        const actualReqBytes = (Number(sizes.requestHeadersSize) || 0) + (Number(sizes.requestBodySize) || 0);
        const actualResBytes = (Number(sizes.responseHeadersSize) || 0) + (Number(sizes.responseBodySize) || 0);
        const egressDelta = Math.max(0, actualReqBytes - tx.estimatedEgressBytes);
        const ingressDelta = Math.max(0, actualResBytes - tx.countedIngressBytes);
        tx.estimatedEgressBytes += egressDelta;
        tx.countedIngressBytes += ingressDelta;
        this.totals.totalEgressBytes += egressDelta;
        this.totals.totalIngressBytes += ingressDelta;
        stepBucket.egressBytes += egressDelta;
        stepBucket.ingressBytes += ingressDelta;
        domainBucket.egressBytes += egressDelta;
        domainBucket.ingressBytes += ingressDelta;
        if (triggerBucket) {
            triggerBucket.egressBytes += egressDelta;
            triggerBucket.ingressBytes += ingressDelta;
        }
    }

    /**
     * Format a concise human-readable summary of a triggerAction snapshot for wire log headers.
     *
     * @param {object|null} triggerSnapshot
     * @returns {string}
     */
    _formatTriggerSummary(triggerSnapshot) {
        if (!triggerSnapshot?.actionId) return 'none';
        const trigger = redactTriggerAction(triggerSnapshot);
        const targetPart = trigger.target ? `(${trigger.target})` : '';
        return `${trigger.actionType || trigger.type || 'unknown'}${targetPart}#${trigger.actionId}`;
    }

    /**
     * Append a single event line to `traffic.ndjson` with a deterministic
     * cryptographic SHA-256 tamper-evident chain link (`prevEventHash` -> `eventHash`).
     *
     * @param {object} record
     */
    _appendNdjsonEvent(record, payloadBuffer = null) {
        if (!this._canRecordEvent()) return false;
        const availableBytes = this.maxCaptureBytes - this.captureBytes;
        const separator = this.ledgerNeedsSeparator ? '\n' : '';
        const encode = () => {
            record.prevEventHash = this.chainHeadHash;
            record.eventHash = computeEventHash(record);
            return `${separator}${JSON.stringify(record)}\n`;
        };
        let line = encode();
        let bytes = Buffer.byteLength(line, 'utf8');
        const omitAttachment = (status, reason) => {
            payloadBuffer = null;
            record.payloadFile = null;
            record.payloadTruncated = false;
            record.payloadStorage = { status, reason };
            line = encode();
            bytes = Buffer.byteLength(line, 'utf8');
        };
        if (payloadBuffer && bytes + payloadBuffer.byteLength > availableBytes) {
            omitAttachment('omitted', 'storage-limit');
        }
        if (bytes > availableBytes) {
            this.captureStoppedReason = 'storage-limit';
            return false;
        }

        let pendingFile = null;
        if (payloadBuffer) {
            try {
                pendingFile = this._writePendingPayload(record.payloadFile, payloadBuffer);
            } catch {
                if (this.ledgerWriteError) return false;
                omitAttachment('failed', 'write-failed');
                if (bytes > availableBytes) {
                    this.captureStoppedReason = 'storage-limit';
                    return false;
                }
            }
        }

        try {
            appendPrivateFile(this.trafficNdjsonPath, line);
        } catch (error) {
            this.ledgerWriteError = error;
            if (pendingFile) this._rollbackFailedAppend(record.payloadFile, pendingFile, line);
            return false;
        }
        if (pendingFile) {
            const { sha256, bytes: storedBytes } = record.payloadStorage;
            this.payloadManifest[record.payloadFile] = {
                sha256,
                bytes: storedBytes,
                truncated: record.payloadTruncated,
                seq: record.seq,
                prefix: path.posix.basename(record.payloadFile).split('-', 1)[0]
            };
            this.captureBytes += storedBytes;
            try {
                this._unlinkPayload(pendingFile);
            } catch (error) {
                this.ledgerWriteError = error;
            }
        }
        this.captureBytes += bytes;
        this.ledgerBytes += bytes;
        this.ledgerNeedsSeparator = false;
        this.chainHeadHash = record.eventHash;
        this.chainedEventCount += 1;
        if (record.payloadStorage?.status === 'failed') this.payloadCaptureIssues.writeFailures += 1;
        if (record.payloadStorage?.status === 'omitted') {
            this.payloadCaptureIssues.storageOmissions += 1;
            if (record.payloadStorage.reason === 'storage-limit') this.omittedPayloadFiles += 1;
        }
        return true;
    }

    /**
     * Append a canonical pre-TLS / post-TLS raw HTTP or WebSocket wire block to `pre-tls-wire.log`.
     *
     * @param {string} wireBlock
     */
    _appendWireLogBlock(wireBlock) {
        if (!this.recordWireLog || this.wireWriteError || !wireBlock) {
            return;
        }
        const entry = wireBlock.endsWith('\n') ? wireBlock : `${wireBlock}\n`;
        const bytes = Buffer.byteLength(entry, 'utf8');
        if (bytes > this.maxCaptureBytes - this.captureBytes) {
            this.omittedWireBlocks += 1;
            return;
        }
        try {
            appendPrivateFile(this.preTlsWireLogPath, entry);
            this.captureBytes += bytes;
        } catch (error) {
            this.wireWriteError = error;
        }
    }

    _samplePayload(content) {
        // Keep exact digests within the diagnostic preview budget even with smaller attachments.
        const maxBytes = Math.min(this.maxCaptureBytes - this.captureBytes,
            Math.max(this.maxBodyBytes, DEFAULT_MAX_INLINE_PREVIEW_BYTES));
        const sampled = sampleTrafficBody(content, maxBytes);
        if (!sampled) return null;
        const { buffer, byteLength } = sampled;
        const sha256 = buffer.byteLength > 0 && buffer.byteLength === byteLength
            ? hashPayload(buffer).sha256 : null;
        return { buffer, byteLength, sha256 };
    }

    _preparePayloadFile(prefix, seq, body, mimeType) {
        if (!body?.buffer.byteLength || (body.byteLength ?? body.buffer.byteLength) < this.inlinePayloadThresholdBytes) {
            return null;
        }
        const buffer = body.buffer.subarray(0, this.maxBodyBytes);
        const payloadTruncated = buffer.byteLength !== body.byteLength;
        const storedSha256 = payloadTruncated ? hashPayload(buffer).sha256 : body.sha256;
        const ext = inferPayloadExtension(mimeType, buffer);
        const fileName = `${prefix}-${seq}-${(body.sha256 ?? storedSha256).slice(0, 12)}.${ext}`;
        return {
            buffer,
            event: {
                payloadFile: path.posix.join('payloads', fileName),
                payloadTruncated,
                payloadStorage: { status: 'stored', sha256: storedSha256, bytes: buffer.byteLength }
            }
        };
    }

    _unlinkPayload(relativePath) {
        try {
            removeCapturePayload(this.trafficDir, relativePath, { trustedLocal: this.trustedLocal });
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
    }

    _resolvePendingPayload(payloadFile, pendingFile, keepPayload) {
        if (!keepPayload) this._unlinkPayload(payloadFile);
        this._unlinkPayload(`${pendingFile}.tmp`);
        this._unlinkPayload(pendingFile);
    }

    _writePendingPayload(payloadFile, buffer) {
        ensurePrivateDirectory(this.payloadsDir);
        const fullPath = path.join(this.trafficDir, payloadFile);
        if (fs.lstatSync(fullPath, { throwIfNoEntry: false })) {
            throw new Error('Refusing to replace an existing capture attachment');
        }
        const pendingFile = path.posix.join('payloads', `.pending-${path.posix.basename(payloadFile)}`);
        const markerPath = path.join(this.trafficDir, pendingFile);
        // The marker precedes the first raw byte and survives until the ledger append is confirmed.
        const fd = fs.openSync(markerPath, 'wx', 0o600);
        try {
            fs.closeSync(fd);
            writePrivateFile(fullPath, buffer, { temporaryPath: `${markerPath}.tmp` });
        } catch (error) {
            try {
                this._resolvePendingPayload(payloadFile, pendingFile, false);
            } catch (cleanupError) {
                this.ledgerWriteError = cleanupError;
            }
            throw error;
        }
        return pendingFile;
    }

    _rollbackFailedAppend(payloadFile, pendingFile, line) {
        try {
            const bytes = readCaptureFile(this.trafficDir, 'traffic.ndjson', {
                optional: true, trustedLocal: this.trustedLocal, maxBytes: this.maxCaptureBytes
            });
            if ((bytes?.byteLength ?? 0) < this.ledgerBytes) return;
            const expected = Buffer.from(line, 'utf8');
            const suffix = bytes?.subarray(this.ledgerBytes) ?? Buffer.alloc(0);
            // A complete event can survive an append error, including loss of only the newline.
            if (suffix.byteLength < expected.byteLength - 1 && expected.subarray(0, suffix.byteLength).equals(suffix)) {
                this._resolvePendingPayload(payloadFile, pendingFile, false);
            }
        } catch {
            // Keep the marker until recovery can inspect a validated ledger.
        }
    }

    /**
     * Register the capture before its handler calls methods on the event target.
     */
    _trackTask(handler, target) {
        if (!this._canStartRecording()) return;
        if (this.pendingTasks.size >= this.maxPendingEvents) {
            this.pendingEventLimitReached = true;
            return;
        }

        const epochMs = Date.now();
        const observationSequence = ++this.#observationSequence;
        const attributionSnapshot = this.getAttributionSnapshot();

        let capture;
        let request;
        const wrapped = new Promise((resolve) => {
            capture = resolve;
        })
            .catch(() => {})
            .finally(() => {
                this.pendingTasks.delete(wrapped);
                if (request && this.requestTasks.get(request) === wrapped) {
                    this.requestTasks.delete(request);
                }
            });
        this.pendingTasks.add(wrapped);

        try {
            const key = handler === this._handleResponse ? target?.request?.() : target;
            if (key && typeof key === 'object') request = key;
        } catch {}
        const previous = request ? this.requestTasks.get(request) : null;
        if (request) this.requestTasks.set(request, wrapped);

        let frame = null;
        try {
            frame = request?.frame?.() ?? null;
        } catch {}
        const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs, frame);
        const eventContext = { request, frame, epochMs, observationSequence, attributionSnapshot, triggerSnapshot };
        const run = async () => {
            if (this._canRecordEvent()) return handler.call(this, target, eventContext);
        };
        capture(previous ? previous.then(run) : run());
        return wrapped;
    }

    /**
     * Assign or retrieve a `correlationId` in this recorder's session namespace
     * for a Playwright `Request` instance.
     *
     * @param {object} request
     * @returns {{ correlationId: string, seq: number, isNew: boolean, redirectedFromCorrelationId: string|null }}
     */
    _resolveRequestCorrelation(request) {
        if (request && typeof request === 'object' && this.requestCorrelationMap.has(request)) {
            const existing = this.requestCorrelationMap.get(request);
            return {
                ...existing,
                isNew: false
            };
        }

        const seq = this._nextSeq();
        const correlationId = `corr-${this.correlationNamespace}-${seq}`;
        let redirectedFromCorrelationId = null;

        try {
            if (request && typeof request.redirectedFrom === 'function') {
                const parentReq = request.redirectedFrom();
                if (parentReq && this.requestCorrelationMap.has(parentReq)) {
                    redirectedFromCorrelationId = this.requestCorrelationMap.get(parentReq).correlationId;
                }
            }
        } catch {
            redirectedFromCorrelationId = null;
        }

        const entry = {
            correlationId,
            seq,
            redirectedFromCorrelationId
        };

        if (request && typeof request === 'object') {
            this.requestCorrelationMap.set(request, entry);
        }

        return {
            ...entry,
            isNew: true
        };
    }

    /**
     * Record a deduplicated anomaly or risk signal entry and increment step and trigger anomaly counters.
     *
     * @param {object} anomaly
     */
    _recordAnomaly(anomaly) {
        const url = anomaly.url ? redactUrlSecrets(anomaly.url) : null;
        const failureText = anomaly.failureText == null ? null : redactDiagnosticText(anomaly.failureText);
        const dedupeKey = trafficAnomalyKey({ ...anomaly, url, failureText });

        if (this.recordedAnomalyKeys.has(dedupeKey)) {
            return;
        }
        this.recordedAnomalyKeys.add(dedupeKey);

        const stepName = anomaly.actionStep || this.attribution.actionStep;
        const stepBucket = this._ensureStepRecord(stepName, this.attribution.stepIndex);
        stepBucket.anomalyCount += 1;

        const effectiveTrigger = anomaly.triggerAction ?? null;
        const triggerBucket = this._ensureTriggerActionRecord(effectiveTrigger);
        if (triggerBucket) {
            triggerBucket.anomalyCount += 1;
        }

        this.anomaliesAndRiskSignals.push({
            timestamp: anomaly.timestamp || new Date().toISOString(),
            correlationId: anomaly.correlationId || null,
            actionStep: stepName,
            triggerAction: effectiveTrigger || null,
            type: anomaly.type,
            severity: anomaly.severity || 'medium',
            method: anomaly.method || null,
            url,
            status: anomaly.status ?? null,
            failureText,
            payloadFile: anomaly.payloadFile ?? null,
            ...(anomaly.matchedSignals ? { matchedSignals: anomaly.matchedSignals } : {})
        });
    }

    /**
     * Record a blocked security probe from Ziniao-absorbed active security guards
     * (`local-port-scan-probe` or `internal-scheme-probe`) into the tamper-evident
     * NDJSON event chain, pre-TLS wire log, and anomalies ledger.
     *
     * @param {object} blockEvent
     * @returns {object | null}
     */
    recordSecurityBlock(blockEvent = {}) {
        if (!this._canStartRecording() || !blockEvent || typeof blockEvent !== 'object') {
            return null;
        }
        const seq = this._nextSeq();
        const correlationId = blockEvent.correlationId || `sec-${this.correlationNamespace}-${seq}`;
        const rawUrl = String(blockEvent.targetUrl || blockEvent.url || '');
        const redactedUrl = redactUrlSecrets(rawUrl);
        const parsedUrl = parseUrlComponents(redactedUrl);
        const blockType = String(blockEvent.type || 'security-probe');
        const method = String(blockEvent.method || 'GET');
        const rawReason = String(blockEvent.reason || `Blocked ${blockType} to ${redactedUrl}`);
        const reason = redactDiagnosticText(rawUrl ? rawReason.replaceAll(rawUrl, redactedUrl) : rawReason);
        const severity = String(blockEvent.severity || 'critical');
        const attributionSnapshot = this.getAttributionSnapshot();

        const record = {
            seq,
            type: 'security-block',
            eventType: 'security-block',
            direction: 'internal',
            stage: 'ziniao-active-guard',
            blockType,
            timestamp: blockEvent.timestamp || new Date().toISOString(),
            epochMs: Date.now(),
            correlationId,
            attribution: attributionSnapshot,
            triggerAction: null,
            method,
            url: redactedUrl,
            host: blockEvent.host || parsedUrl.host,
            port: blockEvent.port ?? null,
            scope: blockEvent.scope || null,
            service: blockEvent.service || null,
            category: blockEvent.category || null,
            matchedScheme: blockEvent.matchedScheme || null,
            initiatorUrl: blockEvent.initiatorUrl ? redactUrlSecrets(String(blockEvent.initiatorUrl)) : null,
            severity,
            reason,
            failureText: reason
        };

        if (!this._appendNdjsonEvent(record)) return null;

        this.totals.failedRequests += 1;
        const stepBucket = this._ensureStepRecord(
            attributionSnapshot.actionStep,
            attributionSnapshot.stepIndex
        );
        stepBucket.failedRequests += 1;
        stepBucket.domainsSet.add(parsedUrl.host);

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        domainBucket.failedRequests += 1;

        if (this.recordWireLog) this._appendWireLogBlock(this._formatSecurityBlockWireBlock(record));

        this._recordAnomaly(securityBlockAnomaly(record));

        return record;
    }

    _listenUntilClose(emitter, subscriptions) {
        const remove = typeof emitter.off === 'function' ? emitter.off : emitter.removeListener;
        const dispose = () => {
            if (!this.listenerDisposers.delete(dispose) || typeof remove !== 'function') return;
            for (const [event, callback] of subscriptions) {
                try {
                    remove.call(emitter, event, callback);
                } catch {}
            }
        };
        subscriptions.push(['close', dispose]);
        this.listenerDisposers.add(dispose);
        for (const [event, callback] of subscriptions) emitter.on(event, callback);
        return dispose;
    }

    /**
     * Attach pre-TLS egress & post-TLS ingress listeners to a Playwright `BrowserContext`.
     * Also attaches WebSocket listeners to all existing and future pages in the context.
     *
     * @param {object} context - Playwright BrowserContext
     * @returns {this}
     */
    attachContext(context) {
        if (!this._canStartRecording() || !context || typeof context.on !== 'function' || this.attachedContexts.has(context)) {
            return this;
        }
        this.attachedContexts.add(context);

        const onRequest = (request) => this._trackTask(this._handleRequest, request);
        const onResponse = (response) => this._trackTask(this._handleResponse, response);
        const onRequestFinished = (request) => this._trackTask(this._handleRequestFinished, request);
        const onRequestFailed = (request) => this._trackTask(this._handleRequestFailed, request);
        const onPage = (page) => {
            this.attachedPagesHttp.get(page)?.();
            this.attachedPagesHttp.delete(page);
            this._attachPageWebSocketsOnly(page);
        };

        this._listenUntilClose(context, [
            ['request', onRequest],
            ['response', onResponse],
            ['requestfinished', onRequestFinished],
            ['requestfailed', onRequestFailed],
            ['page', onPage]
        ]);

        try {
            if (typeof context.pages === 'function') {
                const existingPages = context.pages() || [];
                for (const page of existingPages) {
                    onPage(page);
                }
            }
        } catch {
            // Ignore if context.pages() is unavailable on mock context
        }

        return this;
    }

    /**
     * Attach pre-TLS egress, post-TLS ingress, and WebSocket listeners to a Playwright `Page`.
     * Automatically avoids double-hooking HTTP events if the page's parent `BrowserContext`
     * is already attached to this recorder.
     *
     * @param {object} page - Playwright Page
     * @returns {this}
     */
    attachPage(page) {
        if (!this._canStartRecording() || !page || typeof page.on !== 'function') {
            return this;
        }

        // Always attach WebSocket hooks at page level
        this._attachPageWebSocketsOnly(page);

        // Check if parent BrowserContext is already capturing HTTP events
        let parentContextAttached = false;
        try {
            if (typeof page.context === 'function') {
                const ctx = page.context();
                if (ctx && this.attachedContexts.has(ctx)) {
                    parentContextAttached = true;
                }
            }
        } catch {
            parentContextAttached = false;
        }

        if (parentContextAttached || this.attachedPagesHttp.has(page)) {
            return this;
        }
        const onRequest = (request) => this._trackTask(this._handleRequest, request);
        const onResponse = (response) => this._trackTask(this._handleResponse, response);
        const onRequestFinished = (request) => this._trackTask(this._handleRequestFinished, request);
        const onRequestFailed = (request) => this._trackTask(this._handleRequestFailed, request);

        this.attachedPagesHttp.set(page, this._listenUntilClose(page, [
            ['request', onRequest],
            ['response', onResponse],
            ['requestfinished', onRequestFinished],
            ['requestfailed', onRequestFailed]
        ]));

        return this;
    }

    /**
     * Attach `page.on('websocket')` listener without duplicating HTTP listeners.
     *
     * @param {object} page
     */
    _attachPageWebSocketsOnly(page) {
        if (!this._canStartRecording() || !page || typeof page.on !== 'function' || this.attachedPagesWs.has(page)) {
            return;
        }
        this.attachedPagesWs.add(page);

        const onWebSocket = (ws) => this._handleWebSocket(ws, page);
        const clearTrigger = (frame) => this.activeFrameTriggers.delete(frame);
        const clearPageTriggers = () => {
            clearTrigger(page);
            try { clearTrigger(page.mainFrame?.()); } catch {}
            try {
                for (const frame of page.frames?.() || []) clearTrigger(frame);
            } catch {}
        };
        this._listenUntilClose(page, [
            ['websocket', onWebSocket],
            ['framenavigated', clearTrigger],
            ['framedetached', clearTrigger],
            ['close', clearPageTriggers]
        ]);
    }

    /**
     * Format a canonical pre-TLS egress raw HTTP wire dump block.
     *
     * @param {object} params
     * @returns {string}
     */
    _formatEgressWireBlock({
        timestamp,
        correlationId,
        actionStep,
        triggerSummary,
        method,
        parsedUrl,
        headersArray,
        bodyPreview
    }) {
        const headersText = Array.isArray(headersArray)
            ? headersArray.map((h) => `${h.name}: ${h.value}`).join('\r\n')
            : '';
        return [
            '================================================================================',
            `>>> EGRESS [PRE-TLS NECKO CHANNEL] [${timestamp}] [corr=${correlationId}] [step=${actionStep}] [trigger=${triggerSummary}]`,
            `${method} ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1`,
            `Host: ${parsedUrl.host}`,
            headersText,
            '',
            bodyPreview || '',
            '================================================================================'
        ].join('\n');
    }

    /**
     * Format a canonical post-TLS decrypted ingress raw HTTP wire dump block.
     *
     * @param {object} params
     * @returns {string}
     */
    _formatIngressWireBlock({
        timestamp,
        correlationId,
        effectiveStepName,
        serverAddr,
        securityDetails,
        status,
        statusText,
        headersArray,
        bodyPreview
    }) {
        const headersText = Array.isArray(headersArray)
            ? headersArray.map((h) => `${h.name}: ${h.value}`).join('\r\n')
            : '';
        return [
            '--------------------------------------------------------------------------------',
            `<<< INGRESS [POST-TLS NECKO CHANNEL] [${timestamp}] [corr=${correlationId}] [step=${effectiveStepName}] [remote=${serverAddr?.ipAddress || 'unknown'}:${serverAddr?.port || ''}] [tls=${securityDetails?.protocol || 'plain'}]`,
            `HTTP/1.1 ${status} ${statusText}`,
            headersText,
            '',
            bodyPreview || '',
            '--------------------------------------------------------------------------------'
        ].join('\n');
    }

    _formatWebSocketWireBlock(event) {
        const egress = event.type === 'ws-egress';
        const separator = egress
            ? '================================================================================'
            : '--------------------------------------------------------------------------------';
        const direction = egress ? '>>> WS-EGRESS [PRE-TLS]' : '<<< WS-INGRESS [POST-TLS]';
        const actionStep = redactDiagnosticText(event.attribution?.actionStep || event.actionStep || 'init');
        const trigger = this._formatTriggerSummary(event.triggerAction ?? event.attribution?.triggerAction);
        const url = redactUrlSecrets(event.url);
        const bytes = observedWebSocketPayloadBytes(event) ?? 'unknown';
        return [
            separator,
            `${direction} [${event.timestamp}] [corr=${event.correlationId}] [step=${actionStep}] [trigger=${trigger}] [url=${url}] [bytes=${bytes}]`,
            '',
            separator
        ].join('\n');
    }

    _formatSecurityBlockWireBlock(event) {
        const profileId = redactProfileId(event.attribution?.profileId || this.attribution.profileId);
        const actionStep = redactDiagnosticText(event.attribution?.actionStep || event.actionStep || 'init');
        const blockType = redactDiagnosticText(event.blockType || 'security-probe');
        const severity = redactDiagnosticText(event.severity || 'critical');
        const url = redactUrlSecrets(event.url);
        const reason = redactDiagnosticText(event.reason || event.failureText);
        return [
            '================================================================================',
            `!!! SECURITY-BLOCK [ZINIAO ACTIVE GUARD] [seq=${event.seq}] [corr=${event.correlationId}] ${event.timestamp}`,
            `[ATTRIBUTION] profile=${profileId} step=${actionStep}(#${event.attribution?.stepIndex ?? 0})`,
            `[BLOCK-DETAIL] type=${blockType} severity=${severity} target="${url}" reason="${reason}"`,
            ''
        ].join('\n');
    }

    /**
     * Reconstruct a redacted HTTP or WebSocket wire dump from the bounded ledger.
     *
     * @param {string} correlationId
     * @returns {string}
     */
    formatTransactionWireDump(correlationId) {
        if (!correlationId) return '';

        // Apply the current shareable projection to historical captures before formatting.
        try {
            const trustedLocal = this.trustedLocal;
            const raw = readCaptureFile(this.trafficDir, 'traffic.ndjson', {
                optional: true, trustedLocal, maxBytes: MAX_CAPTURE_BYTES
            });
            if (!raw) return '';
            const { events } = parseTrafficLedger(raw);
            const matching = [];
            for (const [index, event] of events.entries()) {
                if (event.correlationId === correlationId) matching.push({ index, event });
            }
            const requestUrl = matching.find(({ event }) => event.type === 'egress')?.event.url;
            const { bodyPolicy } = readCaptureExportIndex(this.trafficDir, {
                recordBodies: this.recordBodies, trustedLocal
            });
            const currentPolicy = { recordBodies: this.recordBodies, traceId: this.traceId };
            const ownsCurrentEvents = this.chainedEventCount > 0 &&
                events[this.chainedEventCount - 1]?.eventHash === this.chainHeadHash;
            const parts = [];
            for (const { index, event } of matching) {
                const currentEvent = ownsCurrentEvents && index >= this.harStartEventCount &&
                    index < this.chainedEventCount;
                const priorPolicy = this.resumedWireBodyPolicy;
                const bodyAllowed = currentEvent
                    ? capturePolicyAllowsBody(currentPolicy, event)
                    : capturePolicyAllowsBody(bodyPolicy, event) &&
                        (!priorPolicy || capturePolicyAllowsBody(priorPolicy, event));
                const actionStep = redactDiagnosticText(event.attribution?.actionStep || event.actionStep || 'init');
                if (event.type === 'egress' || event.type === 'ingress') {
                    const { text: bodyPreview } = readCaptureExportBody(this.trafficDir, event, {
                        recordBodies: bodyAllowed,
                        trustedLocal,
                        url: requestUrl || event.url,
                        maxBytes: this.maxInlinePreviewBytes,
                        payloadManifest: this.payloadManifest
                    });
                    const common = {
                        timestamp: event.timestamp,
                        correlationId,
                        headersArray: harHeaders(event),
                        bodyPreview
                    };
                    if (event.type === 'egress') {
                        parts.push(this._formatEgressWireBlock({
                            ...common,
                            actionStep,
                            triggerSummary: this._formatTriggerSummary(event.triggerAction ?? event.attribution?.triggerAction),
                            method: redactDiagnosticText(event.method || 'GET'),
                            parsedUrl: parseUrlComponents(event.url || '')
                        }));
                    } else {
                        parts.push(this._formatIngressWireBlock({
                            ...common,
                            effectiveStepName: actionStep,
                            serverAddr: redactDiagnosticMetadata(event.serverAddr),
                            securityDetails: redactDiagnosticMetadata(event.securityDetails),
                            status: Number(event.status) || 0,
                            statusText: redactDiagnosticText(event.statusText)
                        }));
                    }
                } else if (event.type === 'ws-egress' || event.type === 'ws-ingress') {
                    parts.push(this._formatWebSocketWireBlock(event));
                } else if (event.type === 'security-block') {
                    parts.push(this._formatSecurityBlockWireBlock(event));
                }
            }
            return parts.join('\n');
        } catch {
            return '';
        }
    }

    /**
     * Handle pre-TLS egress `request` event (`http-on-modify-request` in Firefox Necko).
     *
     * @param {object} request - Playwright Request
     */
    async _handleRequest(request, { epochMs, observationSequence, attributionSnapshot, triggerSnapshot, frame }) {
        if (!request || this.recordedRequests.has(request)) return;
        this.recordedRequests.add(request);

        const timestamp = new Date(epochMs).toISOString();
        const { correlationId, seq, redirectedFromCorrelationId } =
            this._resolveRequestCorrelation(request);

        let method = 'GET';
        let url = '';
        let resourceType = 'other';
        let isNavigationRequest = false;
        let frameUrl = null;

        try {
            if (typeof request.method === 'function') method = request.method() || 'GET';
        } catch {}
        try {
            if (typeof request.url === 'function') url = request.url() || '';
        } catch {}
        try {
            if (typeof request.resourceType === 'function') resourceType = request.resourceType() || 'other';
        } catch {}
        try {
            if (typeof request.isNavigationRequest === 'function') {
                isNavigationRequest = Boolean(request.isNavigationRequest());
            }
        } catch {}
        try {
            const rawFrameUrl = frame?.url?.();
            if (rawFrameUrl) frameUrl = redactUrlSecrets(rawFrameUrl);
        } catch {}

        const bodyOmittedReason = !this.capturePayloads
            ? 'body-recording-disabled'
            : (allowsTrafficBody(url) ? null : 'sensitive-or-unsupported-url');
        url = redactUrlSecrets(url);
        const parsedUrl = parseUrlComponents(url);
        const { headers, headersArray, cookieObservations } = await extractHeadersWithOrder(request, 'cookie', epochMs);
        if (!this._canRecordEvent()) return;
        const contentType = headersArray.find((header) => header.name.trim().toLowerCase() === 'content-type')?.value ||
            headers['content-type'] || headers['Content-Type'] || null;

        // Playwright delivers the upload with the request. Read it only when capture is allowed.
        let body = null;
        if (!bodyOmittedReason) {
            let postData;
            try {
                postData = request.postDataBuffer?.();
            } catch {}
            if (postData == null) {
                try {
                    const fallback = request.postData?.();
                    if (fallback !== undefined) postData = fallback;
                } catch {}
            }
            body = this._samplePayload(postData === null ? '' : postData);
        }

        const postDataSha256 = body?.sha256 ?? null;
        const postDataBytes = body?.byteLength ?? null;
        let bodyPreview = null;
        let bodyPreviewTruncated = false;
        let bodyTextForInspection = null;
        const payload = this._preparePayloadFile('req', seq, body, contentType);

        if (body?.buffer.byteLength > 0) {
            const previewLimit = Math.min(this.maxInlinePreviewBytes, DEFAULT_MAX_BODY_BYTES);
            bodyPreviewTruncated = postDataBytes === null || postDataBytes > previewLimit ||
                postDataBytes > body.buffer.byteLength;
            if (!payload?.event.payloadTruncated && !bodyPreviewTruncated) {
                const format = shareableBodyFormat({ headers, headersArray });
                bodyPreview = projectTrafficBody(body.buffer, format, previewLimit);
            }

            // The existing signal detectors receive a bounded in-memory prefix. Only their
            // diagnostic metadata is recorded.
            const inspectionLimit = Math.min(previewLimit, DEFAULT_MAX_INLINE_PREVIEW_BYTES);
            if (inspectionLimit > 0) {
                const prefix = body.buffer.subarray(0, inspectionLimit);
                if (inferPayloadExtension(contentType, prefix) !== 'bin') {
                    bodyTextForInspection = redactDiagnosticText(prefix.toString('utf8'));
                }
            }
        }

        const platformSignatures = extractPlatformSignatures({
            url,
            searchParams: parsedUrl.searchParams,
            headers,
            bodyPreview: bodyTextForInspection
        });
        const riskSignals = detectRiskSignals({ url, bodyPreview: bodyTextForInspection, headers });
        const egressEvent = {
            type: 'egress',
            eventType: 'egress',
            direction: 'egress',
            stage: 'pre-tls-necko-channel',
            timestamp,
            epochMs,
            seq,
            correlationId,
            redirectedFromCorrelationId,
            method,
            url,
            host: parsedUrl.host,
            hostname: parsedUrl.hostname,
            port: parsedUrl.port,
            pathname: parsedUrl.pathname,
            searchParams: parsedUrl.searchParams,
            resourceType,
            isNavigationRequest,
            frameUrl,
            recordBodies: this.capturePayloads,
            ...(bodyOmittedReason && { bodyOmittedReason }),
            headers,
            headersArray,
            cookieObservations,
            ...(cookieObservations.length > 0 && { observationSequence }),
            postData: bodyPreview,
            bodyPreview,
            bodyPreviewTruncated,
            postDataSha256,
            postDataBytes,
            ...(payload?.event ?? { payloadFile: null, payloadTruncated: false }),
            platformSignatures,
            riskSignals,
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        };

        if (!this._appendNdjsonEvent(egressEvent, payload?.buffer)) return;
        const { payloadFile } = egressEvent;

        // Estimate header byte size + body bytes for pre-TLS egress accounting
        const headerByteEstimate = headersArray.reduce(
            (acc, h) => acc + Buffer.byteLength(`${h.name}: ${h.value}\r\n`, 'utf8'),
            Buffer.byteLength(`${method} ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1\r\n\r\n`, 'utf8')
        );
        const estimatedEgressBytes = headerByteEstimate + (postDataBytes ?? 0);

        // Update counters
        this.totals.totalRequests += 1;
        this.totals.totalEgressBytes += estimatedEgressBytes;

        const stepBucket = this._ensureStepRecord(
            attributionSnapshot.actionStep,
            attributionSnapshot.stepIndex
        );
        stepBucket.requests += 1;
        stepBucket.egressBytes += estimatedEgressBytes;
        stepBucket.domainsSet.add(parsedUrl.host);

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        domainBucket.requests += 1;
        domainBucket.egressBytes += estimatedEgressBytes;

        const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
        if (triggerBucket) {
            triggerBucket.requests += 1;
            triggerBucket.egressBytes += estimatedEgressBytes;
            triggerBucket.domainsSet.add(parsedUrl.host);
            triggerBucket.correlationIdsSet.add(correlationId);
        }

        const triggerSummary = this._formatTriggerSummary(triggerSnapshot);
        const egressWireBlock = this.recordWireLog ? this._formatEgressWireBlock({
            timestamp,
            correlationId,
            actionStep: attributionSnapshot.actionStep,
            triggerSummary,
            method,
            parsedUrl,
            headersArray,
            bodyPreview
        }) : null;

        // Store transaction metadata for response / finish / failure linking
        this.transactions.set(correlationId, {
            correlationId,
            seq,
            method,
            url,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            resourceType,
            attributionSnapshot,
            actionStep: attributionSnapshot.actionStep,
            stepIndex: attributionSnapshot.stepIndex,
            triggerAction: triggerSnapshot,
            startedAtEpochMs: epochMs,
            estimatedEgressBytes,
            countedIngressBytes: 0,
            requestPayloadFile: payloadFile,
            responsePayloadFile: null,
            status: null
        });

        for (const sig of platformSignatures) {
            this.platformSignatures.push({
                timestamp,
                correlationId,
                actionStep: attributionSnapshot.actionStep,
                stepIndex: attributionSnapshot.stepIndex,
                triggerActionId: triggerSnapshot?.actionId || null,
                triggerTarget: triggerSnapshot?.target || null,
                method,
                url,
                host: parsedUrl.host,
                platform: sig.platform,
                signatureName: sig.signatureName,
                location: sig.location,
                valueLength: sig.valueLength,
                valueSha256: sig.valueSha256,
                maskedPreview: sig.maskedPreview
            });
        }
        this._appendWireLogBlock(egressWireBlock);

        this.cookieLineage.observe(egressEvent);

        // Record the risk metadata computed from this request.
        if (riskSignals.length > 0) {
            const highestSeverity = riskSignals.some((s) => s.severity === 'critical')
                ? 'critical'
                : riskSignals.some((s) => s.severity === 'high')
                    ? 'high'
                    : 'medium';
            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: attributionSnapshot.actionStep,
                triggerAction: triggerSnapshot,
                type: `risk-signal:${riskSignals.map((s) => s.name).join('+')}`,
                severity: highestSeverity,
                method,
                url,
                status: null,
                failureText: null,
                payloadFile,
                matchedSignals: riskSignals
            });
        }

        // Inspect pre-TLS egress wire headers for Client-Hints leaks, UA/OS mismatch, and proxy anonymity leaks
        const wireAnomalies = detectWireHeaderAnomalies({
            headers,
            headersArray,
            expectedOs: attributionSnapshot.os,
            direction: 'egress'
        });
        for (const wa of wireAnomalies) {
            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: attributionSnapshot.actionStep,
                triggerAction: triggerSnapshot,
                type: wa.type,
                severity: wa.severity,
                method,
                url,
                status: null,
                failureText: wa.reason,
                payloadFile
            });
        }
    }

    /**
     * Handle post-TLS decrypted ingress `response` event (`onDataAvailable`/`onStopRequest` in Necko).
     *
     * @param {object} response - Playwright Response
     */
    async _handleResponse(response, { request, epochMs, observationSequence, attributionSnapshot: eventAttribution }) {
        if (!response) return;

        const timestamp = new Date(epochMs).toISOString();
        const seq = this._nextSeq();

        const { correlationId, redirectedFromCorrelationId } = request
            ? this._resolveRequestCorrelation(request)
            : { correlationId: `corr-${this.correlationNamespace}-${seq}`, redirectedFromCorrelationId: null };

        const tx = this.transactions.get(correlationId);
        const attributionSnapshot = tx?.attributionSnapshot || eventAttribution;
        const triggerSnapshot = tx?.triggerAction ?? null;

        let url = tx?.url || '';
        let method = tx?.method || 'GET';
        let status = 0;
        let statusText = '';
        let ok = false;

        try {
            if (typeof response.url === 'function') url = response.url() || url;
        } catch {}
        try {
            if (request && typeof request.method === 'function') method = request.method() || method;
        } catch {}
        try {
            if (typeof response.status === 'function') status = Number(response.status() ?? 0);
        } catch {}
        try {
            if (typeof response.statusText === 'function') statusText = redactDiagnosticText(response.statusText());
        } catch {}
        try {
            if (typeof response.ok === 'function') {
                ok = Boolean(response.ok());
            } else {
                ok = status >= 200 && status < 300;
            }
        } catch {
            ok = status >= 200 && status < 300;
        }

        url = redactUrlSecrets(url);
        const parsedUrl = parseUrlComponents(url);
        const { headers, headersArray, cookieObservations } = await extractHeadersWithOrder(response, 'set-cookie', epochMs);

        let serverAddr = null;
        try {
            if (typeof response.serverAddr === 'function') {
                serverAddr = (await response.serverAddr()) || null;
            }
        } catch {
            serverAddr = null;
        }

        let securityDetails = null;
        try {
            if (typeof response.securityDetails === 'function') {
                securityDetails = (await response.securityDetails()) || null;
            }
        } catch {
            securityDetails = null;
        }

        if (!this._canRecordEvent()) return;
        const rawContentType = headers['content-type'] || headers['Content-Type'] || '';
        const mimeType = rawContentType ? String(rawContentType).split(';')[0].trim().toLowerCase() : null;

        // Playwright's response.body() and response.text() acquire an entire decoded body.
        // The wire size and Content-Length cannot bound that read, so keep response metadata only.
        const isBodylessResponse = method === 'HEAD' || (status >= 100 && status < 200) ||
            status === 204 || status === 205 || status === 304;
        const bodyOmittedReason = !this.capturePayloads
            ? 'body-recording-disabled'
            : isBodylessResponse ? 'response-without-body' : 'unbounded-response-reader';

        const headerByteEstimate = headersArray.reduce(
            (acc, h) => acc + Buffer.byteLength(`${h.name}: ${h.value}\r\n`, 'utf8'),
            Buffer.byteLength(`HTTP/1.1 ${status} ${statusText}\r\n\r\n`, 'utf8')
        );
        const estimatedIngressBytes = headerByteEstimate;

        const effectiveStepName = tx?.actionStep || attributionSnapshot.actionStep;
        const effectiveStepIndex = tx?.stepIndex ?? attributionSnapshot.stepIndex;

        const ingressEvent = {
            type: 'ingress',
            eventType: 'ingress',
            direction: 'ingress',
            stage: 'post-tls-necko-channel',
            timestamp,
            epochMs,
            seq,
            correlationId,
            redirectedFromCorrelationId,
            method,
            url,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            status,
            statusText,
            ok,
            mimeType,
            headers,
            headersArray,
            cookieObservations,
            ...(cookieObservations.length > 0 && { observationSequence }),
            serverAddr,
            securityDetails,
            recordBodies: this.capturePayloads,
            bodyOmittedReason,
            bodySha256: null,
            bodyBytes: 0,
            bodyPreview: null,
            bodyPreviewTruncated: false,
            payloadFile: null,
            payloadTruncated: false,
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        };

        if (!this._appendNdjsonEvent(ingressEvent)) return;

        // Update totals, step counters, domain counters, and triggerAction counters
        this.totals.totalResponses += 1;
        this.totals.totalIngressBytes += estimatedIngressBytes;

        const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
        stepBucket.responses += 1;
        stepBucket.ingressBytes += estimatedIngressBytes;
        stepBucket.domainsSet.add(parsedUrl.host);
        const statusKey = String(status);
        stepBucket.statusCounts[statusKey] = (stepBucket.statusCounts[statusKey] || 0) + 1;

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        domainBucket.responses += 1;
        domainBucket.ingressBytes += estimatedIngressBytes;
        domainBucket.statusCounts[statusKey] = (domainBucket.statusCounts[statusKey] || 0) + 1;

        const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
        if (triggerBucket) {
            triggerBucket.responses += 1;
            triggerBucket.ingressBytes += estimatedIngressBytes;
            triggerBucket.domainsSet.add(parsedUrl.host);
            triggerBucket.correlationIdsSet.add(correlationId);
            triggerBucket.statusCounts[statusKey] = (triggerBucket.statusCounts[statusKey] || 0) + 1;
        }

        const ingressWireBlock = this.recordWireLog ? this._formatIngressWireBlock({
            timestamp,
            correlationId,
            effectiveStepName,
            serverAddr,
            securityDetails,
            status,
            statusText,
            headersArray,
            bodyPreview: null
        }) : null;

        if (tx) {
            tx.status = status;
            tx.responsePayloadFile = null;
            tx.countedIngressBytes = estimatedIngressBytes;
            const elapsed = Math.max(0, epochMs - tx.startedAtEpochMs);
            tx.responseDurationMs = elapsed;
        } else {
            this.transactions.set(correlationId, {
                correlationId,
                seq,
                method,
                url,
                host: parsedUrl.host,
                pathname: parsedUrl.pathname,
                resourceType: 'other',
                attributionSnapshot,
                actionStep: effectiveStepName,
                stepIndex: effectiveStepIndex,
                triggerAction: triggerSnapshot,
                startedAtEpochMs: epochMs,
                estimatedEgressBytes: 0,
                countedIngressBytes: estimatedIngressBytes,
                requestPayloadFile: null,
                responsePayloadFile: null,
                status
            });
        }
        this._appendWireLogBlock(ingressWireBlock);

        this.cookieLineage.observe(ingressEvent);

        // Automatic HTTP Status & Risk Signal Anomaly Attribution
        const httpAnomaly = classifyTrafficLifecycleAnomaly(ingressEvent);
        if (httpAnomaly) {
            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: effectiveStepName,
                triggerAction: triggerSnapshot,
                ...httpAnomaly,
                method,
                url,
                status,
                failureText: statusText || `HTTP ${status}`,
                payloadFile: tx?.requestPayloadFile || null
            });
        }

        const riskSignals = detectRiskSignals({ url, headers });
        if (riskSignals.length > 0) {
            const highestSeverity = riskSignals.some((s) => s.severity === 'critical')
                ? 'critical'
                : riskSignals.some((s) => s.severity === 'high')
                    ? 'high'
                    : 'medium';
            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: effectiveStepName,
                triggerAction: triggerSnapshot,
                type: `risk-signal:${riskSignals.map((s) => s.name).join('+')}`,
                severity: highestSeverity,
                method,
                url,
                status,
                failureText: null,
                payloadFile: tx?.requestPayloadFile || null,
                matchedSignals: riskSignals
            });
        }

        // Inspect post-TLS ingress headers for proxy anonymity leaks
        const wireAnomalies = detectWireHeaderAnomalies({
            headers,
            headersArray,
            expectedOs: attributionSnapshot.os,
            direction: 'ingress'
        });
        for (const wa of wireAnomalies) {
            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: effectiveStepName,
                triggerAction: triggerSnapshot,
                type: wa.type,
                severity: wa.severity,
                method,
                url,
                status,
                failureText: wa.reason,
                payloadFile: tx?.requestPayloadFile || null
            });
        }
    }

    /**
     * Handle `requestfinished` lifecycle event to record Necko timing and exact wire sizes.
     *
     * @param {object} request - Playwright Request
     */
    async _handleRequestFinished(request, { epochMs, attributionSnapshot: eventAttribution }) {
        if (!request) return;

        const timestamp = new Date(epochMs).toISOString();
        const seq = this._nextSeq();
        const { correlationId } = this._resolveRequestCorrelation(request);
        const tx = this.transactions.get(correlationId);
        this.transactions.delete(correlationId);
        const attributionSnapshot = tx?.attributionSnapshot || eventAttribution;
        const triggerSnapshot = tx?.triggerAction ?? null;

        let url = tx?.url || '';
        let method = tx?.method || 'GET';
        try {
            if (typeof request.url === 'function') url = request.url() || url;
        } catch {}
        try {
            if (typeof request.method === 'function') method = request.method() || method;
        } catch {}

        url = redactUrlSecrets(url);
        const parsedUrl = parseUrlComponents(url);

        let timing = null;
        try {
            if (typeof request.timing === 'function') {
                timing = request.timing() || null;
            }
        } catch {
            timing = null;
        }

        let sizes = null;
        try {
            if (typeof request.sizes === 'function') {
                sizes = (await request.sizes()) || null;
            }
        } catch {
            sizes = null;
        }

        let durationMs = null;
        if (timing && typeof timing.responseEnd === 'number' && timing.responseEnd >= 0) {
            const startOffset = typeof timing.requestStart === 'number' && timing.requestStart >= 0
                ? timing.requestStart
                : 0;
            durationMs = Number(Math.max(0, timing.responseEnd - startOffset).toFixed(2));
        } else if (tx && typeof tx.startedAtEpochMs === 'number') {
            durationMs = Math.max(0, epochMs - tx.startedAtEpochMs);
        }

        if (!this._appendNdjsonEvent({
            type: 'request-finished',
            eventType: 'request-finished',
            direction: 'lifecycle',
            stage: 'necko-transaction-complete',
            timestamp,
            epochMs,
            seq,
            correlationId,
            method,
            url,
            host: parsedUrl.host,
            status: tx?.status ?? null,
            durationMs,
            timing,
            sizes,
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        })) return;

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        if (typeof durationMs === 'number' && Number.isFinite(durationMs)) {
            domainBucket.totalDurationMs += durationMs;
            domainBucket.completedWithDurationCount += 1;
        }

        // Reconcile wire byte sizes if Playwright's `request.sizes()` reported larger actual totals
        if (tx && sizes && typeof sizes === 'object') {
            const effectiveStepName = tx.actionStep || attributionSnapshot.actionStep;
            const effectiveStepIndex = tx.stepIndex ?? attributionSnapshot.stepIndex;
            const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
            const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
            this._reconcileTransactionSizes(sizes, tx, stepBucket, domainBucket, triggerBucket);
        }
    }

    /**
     * Handle `requestfailed` event (e.g. `NS_ERROR_*`, proxy error, reset, abort, timeout).
     *
     * @param {object} request - Playwright Request
     */
    async _handleRequestFailed(request, { epochMs, attributionSnapshot: eventAttribution }) {
        if (!request) return;

        const timestamp = new Date(epochMs).toISOString();
        const seq = this._nextSeq();
        const { correlationId } = this._resolveRequestCorrelation(request);
        const tx = this.transactions.get(correlationId);
        this.transactions.delete(correlationId);
        const attributionSnapshot = tx?.attributionSnapshot || eventAttribution;
        const triggerSnapshot = tx?.triggerAction ?? null;

        let url = tx?.url || '';
        let method = tx?.method || 'GET';
        let resourceType = tx?.resourceType || 'other';
        let failureText = 'UNKNOWN_NETWORK_FAILURE';

        try {
            if (typeof request.url === 'function') url = request.url() || url;
        } catch {}
        try {
            if (typeof request.method === 'function') method = request.method() || method;
        } catch {}
        try {
            if (typeof request.resourceType === 'function') {
                resourceType = request.resourceType() || resourceType;
            }
        } catch {}
        try {
            if (typeof request.failure === 'function') {
                const failureObj = request.failure();
                if (failureObj && failureObj.errorText) {
                    failureText = redactDiagnosticText(failureObj.errorText);
                }
            }
        } catch {}

        url = redactUrlSecrets(url);
        const parsedUrl = parseUrlComponents(url);
        const durationMs = tx && typeof tx.startedAtEpochMs === 'number'
            ? Math.max(0, epochMs - tx.startedAtEpochMs)
            : null;

        const effectiveStepName = tx?.actionStep || attributionSnapshot.actionStep;
        const effectiveStepIndex = tx?.stepIndex ?? attributionSnapshot.stepIndex;

        if (!this._appendNdjsonEvent({
            type: 'request-failed',
            eventType: 'request-failed',
            direction: 'egress-failed',
            stage: 'necko-channel-error',
            timestamp,
            epochMs,
            seq,
            correlationId,
            method,
            url,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            resourceType,
            failureText,
            durationMs,
            payloadFile: tx?.requestPayloadFile || null,
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        })) return;

        this.totals.failedRequests += 1;

        const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
        stepBucket.failedRequests += 1;
        stepBucket.domainsSet.add(parsedUrl.host);

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        domainBucket.failedRequests += 1;
        if (typeof durationMs === 'number' && Number.isFinite(durationMs)) {
            domainBucket.totalDurationMs += durationMs;
            domainBucket.completedWithDurationCount += 1;
        }

        const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
        if (triggerBucket) {
            triggerBucket.failedRequests += 1;
            triggerBucket.domainsSet.add(parsedUrl.host);
            triggerBucket.correlationIdsSet.add(correlationId);
        }

        this._recordAnomaly({
            timestamp,
            correlationId,
            actionStep: effectiveStepName,
            triggerAction: triggerSnapshot,
            ...classifyTrafficLifecycleAnomaly({ type: 'request-failed', failureText }),
            method,
            url,
            status: null,
            failureText,
            payloadFile: tx?.requestPayloadFile || null
        });
    }

    /**
     * Hook Playwright `WebSocket` lifecycle events (`framesent`, `framereceived`, `socketerror`, `close`).
     *
     * @param {object} ws - Playwright WebSocket instance
     */
    _handleWebSocket(ws) {
        if (!this._canStartRecording() || !ws || typeof ws.on !== 'function' || this.attachedWebSockets.has(ws)) {
            return;
        }
        this.attachedWebSockets.add(ws);

        this.wsSeq += 1;
        const wsCorrelationId = `ws-${this.correlationNamespace}-${this.wsSeq}`;
        let wsUrl = '';
        try {
            if (typeof ws.url === 'function') {
                wsUrl = ws.url() || '';
            }
        } catch {}

        const bodyOmittedReason = !this.capturePayloads
            ? 'body-recording-disabled'
            : (allowsTrafficBody(wsUrl) ? null : 'sensitive-or-unsupported-url');
        wsUrl = redactUrlSecrets(wsUrl);
        const parsedUrl = parseUrlComponents(wsUrl);
        const openEpochMs = Date.now();

        if (!this._appendNdjsonEvent({
            type: 'ws-open',
            eventType: 'ws-open',
            direction: 'ws-open',
            stage: 'pre-tls-websocket-open',
            timestamp: new Date().toISOString(),
            epochMs: openEpochMs,
            seq: this._nextSeq(),
            correlationId: wsCorrelationId,
            url: wsUrl,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            triggerAction: null,
            attribution: this.getAttributionSnapshot()
        })) return;

        const recordWsFrame = (direction, stage, frameData) => {
            if (!this._canStartRecording() || !this.webSocketDisposers.has(dispose)) return;
            const timestamp = new Date().toISOString();
            const epochMs = Date.now();
            const seq = this._nextSeq();
            const attributionSnapshot = this.getAttributionSnapshot();

            let body = null;
            let omission = bodyOmittedReason;
            if (!bodyOmittedReason) {
                try {
                    const rawPayload = frameData && typeof frameData === 'object' && 'payload' in frameData
                        ? frameData.payload
                        : frameData;
                    body = this._samplePayload(rawPayload);
                } catch {}
                if (!body) omission = 'unavailable-frame-payload';
            }
            const payload = this._preparePayloadFile('ws', seq, body, 'application/octet-stream');

            const event = {
                type: direction,
                eventType: direction,
                direction,
                stage,
                timestamp,
                epochMs,
                seq,
                correlationId: wsCorrelationId,
                url: wsUrl,
                host: parsedUrl.host,
                recordBodies: this.capturePayloads,
                ...(omission && { bodyOmittedReason: omission }),
                payloadSha256: body?.sha256 ?? null,
                payloadBytes: body?.byteLength ?? null,
                bodyPreview: null,
                bodyPreviewTruncated: false,
                ...(payload?.event ?? { payloadFile: null, payloadTruncated: false }),
                triggerAction: null,
                attribution: attributionSnapshot
            };
            if (!this._appendNdjsonEvent(event, payload?.buffer)) return;

            const stepBucket = this._ensureStepRecord(
                attributionSnapshot.actionStep,
                attributionSnapshot.stepIndex
            );
            const domainBucket = this._ensureDomainRecord(parsedUrl.host);
            stepBucket.domainsSet.add(parsedUrl.host);

            this._countWebSocketFrame(event, stepBucket, domainBucket);
            if (this.recordWireLog) this._appendWireLogBlock(this._formatWebSocketWireBlock(event));
        };

        const onFrameSent = (frame) =>
            recordWsFrame('ws-egress', 'pre-tls-websocket-frame', frame);
        const onFrameReceived = (frame) =>
            recordWsFrame('ws-ingress', 'post-tls-websocket-frame', frame);

        const onSocketError = (errorMsg) => {
            if (!this._canStartRecording() || !this.webSocketDisposers.has(dispose)) return;
            const timestamp = new Date().toISOString();
            const epochMs = Date.now();
            const seq = this._nextSeq();
            const attributionSnapshot = this.getAttributionSnapshot();
            const failureText = redactDiagnosticText(errorMsg || 'WEBSOCKET_ERROR');

            if (!this._appendNdjsonEvent({
                type: 'ws-error',
                eventType: 'ws-error',
                direction: 'ws-error',
                stage: 'websocket-channel-error',
                timestamp,
                epochMs,
                seq,
                correlationId: wsCorrelationId,
                url: wsUrl,
                host: parsedUrl.host,
                failureText,
                triggerAction: null,
                attribution: attributionSnapshot
            })) return;

            this._recordAnomaly({
                timestamp,
                correlationId: wsCorrelationId,
                actionStep: attributionSnapshot.actionStep,
                triggerAction: null,
                ...classifyTrafficLifecycleAnomaly({ type: 'ws-error' }),
                method: 'WEBSOCKET',
                url: wsUrl,
                status: null,
                failureText,
                payloadFile: null
            });
        };

        const onClose = () => {
            if (!this.webSocketDisposers.has(dispose)) return;
            dispose();
            if (!this._canStartRecording()) return;
            const closeEpochMs = Date.now();
            this._appendNdjsonEvent({
                type: 'ws-close',
                eventType: 'ws-close',
                direction: 'ws-close',
                stage: 'websocket-channel-closed',
                timestamp: new Date().toISOString(),
                epochMs: closeEpochMs,
                seq: this._nextSeq(),
                correlationId: wsCorrelationId,
                url: wsUrl,
                host: parsedUrl.host,
                triggerAction: null,
                attribution: this.getAttributionSnapshot()
            });
        };

        const listeners = [
            ['framesent', onFrameSent],
            ['framereceived', onFrameReceived],
            ['socketerror', onSocketError],
            ['close', onClose]
        ];
        const remove = typeof ws.off === 'function' ? ws.off : ws.removeListener;
        const dispose = () => {
            this.webSocketDisposers.delete(dispose);
            if (typeof remove === 'function') {
                for (const [event, callback] of listeners) {
                    try {
                        remove.call(ws, event, callback);
                    } catch {}
                }
            }
        };
        this.webSocketDisposers.add(dispose);
        for (const [event, callback] of listeners) {
            ws.on(event, callback);
        }
    }

    _countWebSocketFrame(event, stepBucket, domainBucket, triggerBucket = null) {
        const sent = event.type === 'ws-egress';
        const frameCount = sent ? 'wsFramesSent' : 'wsFramesReceived';
        const bytes = observedWebSocketPayloadBytes(event);
        this.totals[frameCount] += 1;
        if (triggerBucket) {
            triggerBucket[frameCount] += 1;
            triggerBucket.domainsSet.add(parseUrlComponents(event.url).host);
            if (event.correlationId) triggerBucket.correlationIdsSet.add(event.correlationId);
        }
        if (bytes === null) {
            this.totals[sent ? 'unknownWsFramesSent' : 'unknownWsFramesReceived'] += 1;
            return;
        }
        const byteCount = sent ? 'egressBytes' : 'ingressBytes';
        this.totals[sent ? 'totalEgressBytes' : 'totalIngressBytes'] += bytes;
        stepBucket[byteCount] += bytes;
        domainBucket[byteCount] += bytes;
        if (triggerBucket) triggerBucket[byteCount] += bytes;
    }

    /**
     * Build the structured multi-dimensional attribution and root-cause summary report.
     *
     * @returns {object}
     */
    buildAttributionSummary({ nativeLogsClosed = this.#nativeLogsClosed } = {}) {
        if (this.#finalSummary) return structuredClone(this.#finalSummary);
        if (this.cookieLineage.needsReplay) {
            // A slow capture can finish after other observations. Rebuild from
            // the ledger so the original order also corrects any earlier sends.
            const raw = readCaptureFile(this.trafficDir, 'traffic.ndjson', { trustedLocal: this.trustedLocal });
            const { events } = parseTrafficLedger(raw);
            verifyLedgerCheckpoint({ eventCount: this.chainedEventCount, chainHeadHash: this.chainHeadHash }, events);
            const replay = new CookieLineage();
            replay.observeAll(events);
            this.cookieLineage = replay;
        }
        const endedAtIso = this.endedAt || new Date().toISOString();
        const endedAtMs = this.endedAt ? Date.parse(this.endedAt) : Date.now();
        const totalDurationMs = Math.max(0, endedAtMs - this.startedAtEpochMs);

        const byActionStepObj = Object.create(null);
        for (const [stepName, stats] of this.byActionStep.entries()) {
            byActionStepObj[stepName] = {
                stepIndex: stats.stepIndex,
                requests: stats.requests,
                responses: stats.responses,
                failedRequests: stats.failedRequests,
                egressBytes: stats.egressBytes,
                ingressBytes: stats.ingressBytes,
                statusCounts: { ...stats.statusCounts },
                domains: Array.from(stats.domainsSet),
                anomalyCount: stats.anomalyCount
            };
        }

        const byDomainObj = Object.create(null);
        for (const [host, stats] of this.byDomain.entries()) {
            const avgDurationMs = stats.completedWithDurationCount > 0
                ? Number((stats.totalDurationMs / stats.completedWithDurationCount).toFixed(2))
                : 0;
            byDomainObj[host] = {
                requests: stats.requests,
                responses: stats.responses,
                failedRequests: stats.failedRequests,
                egressBytes: stats.egressBytes,
                ingressBytes: stats.ingressBytes,
                statusCounts: { ...stats.statusCounts },
                avgDurationMs
            };
        }

        const byTriggerActionObj = Object.create(null);
        for (const [actionId, stats] of this.byTriggerAction.entries()) {
            byTriggerActionObj[actionId] = {
                actionId: stats.actionId,
                actionType: stats.actionType,
                target: stats.target,
                actionStep: stats.actionStep,
                stepIndex: stats.stepIndex,
                timestamp: stats.timestamp,
                metadata: stats.metadata,
                requests: stats.requests,
                responses: stats.responses,
                failedRequests: stats.failedRequests,
                wsFramesSent: stats.wsFramesSent,
                wsFramesReceived: stats.wsFramesReceived,
                egressBytes: stats.egressBytes,
                ingressBytes: stats.ingressBytes,
                statusCounts: { ...stats.statusCounts },
                domains: Array.from(stats.domainsSet),
                correlationIds: Array.from(stats.correlationIdsSet),
                anomalyCount: stats.anomalyCount
            };
        }

        const nativeArtifacts = { ...this.profileNativeArtifacts };
        const readLog = (type, logPath, describe) => {
            const file = logPath && path.basename(logPath);
            if (this.profileNativeDir && logPath && path.dirname(logPath) === this.profileNativeDir &&
                profileNativeArtifactName(type, file)) {
                const raw = readCaptureFile(this.profileNativeDir, file, {
                    trustedLocal: this.trustedLocal, maxBytes: MAX_INTEGRITY_LOG_BYTES
                });
                const summary = describe(raw);
                const prior = this.profileNativeArtifacts[type];
                const { previous = [], ...generation } = prior ?? {};
                nativeArtifacts[type] = {
                    file,
                    sha256: summary.sha256,
                    bytes: summary.bytes,
                    closed: this.#canSealNativeLogs(nativeLogsClosed),
                    ...(prior ? { previous: [...previous, generation] } : {})
                };
                return summary;
            }
            return describe(readNativeLogFile(logPath));
        };
        const sslKeyLogSummary = readLog('sslKeyLog', this.sslKeyLogPath, parseSslKeyLogBytes);
        const neckoMozLogSummary = readLog('neckoMozLog', this.neckoMozLogPath, parseNeckoMozLogBytes);
        const sslKeyLogFile = nativeArtifactName(this.trafficDir, this.sslKeyLogPath, INTEGRITY_ARTIFACTS.sslKeyLog);
        const neckoMozLogFile = nativeArtifactName(this.trafficDir, this.neckoMozLogPath, INTEGRITY_ARTIFACTS.neckoMozLog);
        const prior = this.priorArtifactIntegrity;

        const captureNative = (type, summary, file) => {
            if (file && summary.exists) return { sha256: summary.sha256, bytes: summary.bytes, file };
            return { sha256: prior?.[type + 'Sha256'] ?? null, bytes: prior?.[type + 'Bytes'] ?? 0,
                file: prior?.[type + 'File'] };
        };
        const sslArtifact = captureNative('sslKeyLog', sslKeyLogSummary, sslKeyLogFile);
        const neckoArtifact = captureNative('neckoMozLog', neckoMozLogSummary, neckoMozLogFile);

        const wirePath = this.recordWireLog ? this.preTlsWireLogPath
            : this.priorWireLog ? path.join(this.trafficDir, INTEGRITY_ARTIFACTS.preTlsWireLog) : null;
        const wire = wirePath ? hashCaptureFile(path.dirname(wirePath), path.basename(wirePath), {
            trustedLocal: this.trustedLocal, maxBytes: MAX_INTEGRITY_LOG_BYTES
        }) : null;
        const preTlsWireLogSha256 = wire?.sha256 ?? prior?.preTlsWireLogSha256 ?? null;
        const preTlsWireLogBytes = wire?.bytes ?? prior?.preTlsWireLogBytes ?? 0;

        const signatures = this.platformSignatures.map(redactDiagnosticMetadata);
        const byPlatform = Object.create(null);
        for (const signature of signatures) {
            if (!signature.platform) continue;
            byPlatform[signature.platform] = (byPlatform[signature.platform] || 0) + 1;
        }

        return {
            session: {
                traceId: this.attribution.traceId,
                profileId: this.attribution.profileId,
                accountId: this.attribution.accountId,
                accountEmail: null,
                os: this.attribution.os,
                proxyServer: this.attribution.proxyServer,
                recordBodies: this.recordBodies,
                startedAt: this.startedAt,
                endedAt: endedAtIso,
                totalDurationMs
            },
            artifacts: {
                trafficNdjsonPath: this.trafficNdjsonPath,
                preTlsWireLogPath: wirePath,
                neckoMozLogPath: neckoMozLogFile ? this.neckoMozLogPath : null,
                payloadsDir: this.payloadsDir,
                sslKeyLogPath: sslKeyLogFile ? this.sslKeyLogPath : null,
                harPath: this.harPath,
                attributionIndexPath: this.attributionIndexPath
            },
            sslKeyLog: sslKeyLogFile ? sslKeyLogSummary : { ...sslKeyLogSummary, sha256: null },
            neckoMozLog: neckoMozLogFile ? neckoMozLogSummary : { ...neckoMozLogSummary, sha256: null },
            totals: {
                totalRequests: this.totals.totalRequests,
                totalResponses: this.totals.totalResponses,
                failedRequests: this.totals.failedRequests,
                wsFramesSent: this.totals.wsFramesSent,
                wsFramesReceived: this.totals.wsFramesReceived,
                unknownWsFramesSent: this.totals.unknownWsFramesSent,
                unknownWsFramesReceived: this.totals.unknownWsFramesReceived,
                totalEgressBytes: this.totals.totalEgressBytes,
                totalIngressBytes: this.totals.totalIngressBytes
            },
            captureLimits: {
                maxBytes: this.maxCaptureBytes,
                maxEvents: this.maxCaptureEvents,
                maxPendingEvents: this.maxPendingEvents,
                bytes: this.captureBytes,
                stoppedReason: this.captureStoppedReason ??
                    (this.pendingEventLimitReached ? 'pending-event-limit' : null),
                omittedWireBlocks: this.omittedWireBlocks,
                omittedPayloadFiles: this.omittedPayloadFiles
            },
            byActionStep: { ...byActionStepObj },
            byDomain: { ...byDomainObj },
            byTriggerAction: { ...byTriggerActionObj },
            cookieLineage: this.cookieLineage.snapshot(),
            platformSignatures: {
                totalDetected: signatures.length,
                byPlatform: { ...byPlatform },
                signatures
            },
            anomaliesAndRiskSignals: [...this.anomaliesAndRiskSignals],
            integrity: {
                algorithm: 'sha256-chain',
                genesisHash: this.genesisHash,
                eventCount: this.chainedEventCount,
                chainHeadHash: this.chainHeadHash,
                payloadCount: Object.keys(this.payloadManifest).length,
                payloadManifest: { ...this.payloadManifest },
                payloadCaptureIssues: { ...this.payloadCaptureIssues },
                preTlsWireLogSha256,
                preTlsWireLogBytes,
                ...(!wire && prior?.preTlsWireLogFile ? { preTlsWireLogFile: prior.preTlsWireLogFile } : {}),
                sslKeyLogSha256: sslArtifact.sha256,
                sslKeyLogBytes: sslArtifact.bytes,
                ...(sslArtifact.file ? { sslKeyLogFile: sslArtifact.file } : {}),
                neckoMozLogSha256: neckoArtifact.sha256,
                neckoMozLogBytes: neckoArtifact.bytes,
                ...(neckoArtifact.file ? { neckoMozLogFile: neckoArtifact.file } : {}),
                ...(Object.keys(nativeArtifacts).length > 0 ? { nativeArtifacts } : {})
            }
        };
    }

    #harSessionRange() {
        return {
            start: this.harStartEventCount,
            end: this.chainedEventCount,
            head: this.chainHeadHash,
            payloadManifest: this.payloadManifest
        };
    }

    /**
     * Reconstruct a W3C HAR 1.2 archive object (`{ log: { version: '1.2', ... } }`)
     * from this recorder's persisted `traffic.ndjson` events and `payloads/` directory.
     *
     * @returns {{ log: object }}
     */
    buildHarArchive() {
        return buildHarFromTrafficDir(this.trafficDir, {
            ...this.getAttributionSnapshot(),
            startedAt: this.startedAt
        }, {
            recordBodies: this.recordBodies,
            trustedLocal: this.trustedLocal,
            [HAR_SESSION_RANGE]: this.#harSessionRange()
        }).archive;
    }

    /**
     * Export the recorded traffic to a W3C HAR 1.2 file on disk.
     *
     * @param {string} [outputPath=this.harPath]
     * @returns {{
     *   harPath: string,
     *   outputPath: string,
     *   entryCount: number,
     *   entriesCount: number,
     *   pageCount: number,
     *   bytes: number,
     *   log: object,
     *   har: { log: object }
     * }}
     */
    exportHar(outputPath = this.harPath, { recordBodies = this.recordBodies } = {}) {
        return exportTrafficToHar(this.trafficDir, outputPath ?? this.harPath, {
            ...this.getAttributionSnapshot(),
            startedAt: this.startedAt
        }, {
            recordBodies: this.recordBodies && recordBodies === true,
            trustedLocal: this.trustedLocal,
            [HAR_SESSION_RANGE]: this.#harSessionRange(),
            [HAR_PROTECTED_PATHS]: [this.profileNativeDir, this.sslKeyLogPath, this.neckoMozLogPath,
                this.preTlsWireLogPath].filter(Boolean)
        });
    }

    /**
     * Wait for any in-flight asynchronous payload captures to complete and write
     * `attribution-index.json` to disk.
     *
     * @returns {Promise<object>} Written attribution summary object
     */
    async flushSummary({ nativeLogsClosed = this.#nativeLogsClosed } = {}) {
        if (this.pendingTasks.size > 0) {
            await Promise.allSettled(Array.from(this.pendingTasks));
        }
        if (this.#finalSummary || this.#finalizationError) {
            this.#releaseCaptureLease();
            if (this.#finalizationError) throw this.#finalizationError;
            return structuredClone(this.#finalSummary);
        }
        const logsClosed = this.#canSealNativeLogs(nativeLogsClosed);
        const finalizing = this.stopped && logsClosed;
        let summary;
        try {
            if (this.stopped) this.endedAt ??= new Date().toISOString();
            if (this.ledgerWriteError) {
                throw new Error('Could not append to traffic.ndjson', { cause: this.ledgerWriteError });
            }
            if (this.wireWriteError) {
                throw new Error('Could not append to pre-tls-wire.log', { cause: this.wireWriteError });
            }

            summary = this.buildAttributionSummary({ nativeLogsClosed: logsClosed });
            writePrivateFile(this.attributionIndexPath, `${JSON.stringify(summary, null, 2)}\n`);
        } catch (error) {
            if (finalizing && !this.#nativeLogsAreClosed) {
                this.#finalizationError = error;
                this.#releaseCaptureLease();
            }
            throw error;
        }
        this.#nativeLogsClosed = logsClosed;
        if (finalizing) {
            this.#finalSummary = structuredClone(summary);
            this.#releaseCaptureLease();
        }
        return summary;
    }

    #canSealNativeLogs(requested) {
        return Boolean(requested && (!this.#nativeLogsAreClosed || this.#nativeLogsAreClosed()));
    }

    #releaseCaptureLease() {
        if (this.#captureLease) {
            releaseProfileLease(this.#captureLease);
            this.#captureLease = null;
        }
    }

    #detachRecordingListeners() {
        if (this.stopped) return;
        this.stopped = true;
        this.activeFrameTriggers = new WeakMap();
        for (const dispose of this.webSocketDisposers) dispose();
        for (const dispose of this.listenerDisposers) dispose();
    }

    async abandon() {
        if (!this.#canSealNativeLogs(true)) throw new Error('Camoufox has not confirmed browser closure');
        this.#detachRecordingListeners();
        const error = new Error('Camoufox capture could not be finalized');
        this.ledgerWriteError ??= error;
        this.wireWriteError ??= error;
        if (this.pendingTasks.size > 0) {
            await Promise.allSettled(Array.from(this.pendingTasks));
        }
        this.transactions.clear();
        if (!this.#finalSummary) this.#finalizationError ??= error;
        this.#releaseCaptureLease();
    }

    /**
     * Detach all active event listeners, await in-flight traffic captures,
     * mark the recording session as ended, and flush `attribution-index.json`.
     *
     * @returns {Promise<object>} Final attribution summary object
     */
    async stop({ nativeLogsClosed = !this.stopped || this.#nativeLogsClosed } = {}) {
        this.#detachRecordingListeners();
        try {
            return await this.flushSummary({ nativeLogsClosed });
        } finally {
            this.transactions.clear();
        }
    }
}

/**
 * Verify the cryptographic SHA-256 tamper-evident hash chain across `traffic.ndjson`
 * and verify every payload file listed in `attribution-index.json` (`integrity.payloadManifest`).
 *
 * @param {string} trafficDir
 * @param {object} [options]
 * @param {string|null} [options.nativeDir=null] Authorized directory for profile native logs
 * @param {boolean} [options.trustedLocal=false] Use only for application-managed storage
 * @returns {{
 *   valid: boolean,
 *   eventCount: number,
 *   verifiedPayloads: number,
 *   chainHeadHash: string,
 *   errors: string[]
 * }}
 */
export function verifyTrafficIntegrity(trafficDir, { nativeDir = null, trustedLocal = false } = {}) {
    const errors = [];
    const scope = nativeDir ? 'profile' : 'capture';
    let chainHeadHash = TRAFFIC_GENESIS_HASH;
    let eventCount = 0;
    let verifiedPayloads = 0;
    let unverifiedPayloads = [];
    let payloadManifestVerified = false;
    const payloadCaptureIssues = { writeFailures: 0, storageOmissions: 0 };

    if (!trafficDir) {
        return {
            valid: false, scope, unverifiedNativeArtifacts: [], eventCount, verifiedPayloads, chainHeadHash,
            unverifiedPayloads, payloadManifestVerified, payloadCaptureIssues,
            errors: ['trafficDir path is required']
        };
    }

    const resolvedTrafficDir = path.resolve(String(trafficDir));
    if (!fs.existsSync(resolvedTrafficDir)) {
        return {
            valid: false,
            scope,
            unverifiedNativeArtifacts: [],
            eventCount,
            verifiedPayloads,
            chainHeadHash,
            unverifiedPayloads,
            payloadManifestVerified,
            payloadCaptureIssues,
            errors: [`Traffic directory does not exist: ${resolvedTrafficDir}`]
        };
    }

    const check = (verify) => {
        try {
            return verify();
        } catch (error) {
            errors.push(error.message);
            return null;
        }
    };
    const summary = check(() => readTrafficIndex(resolvedTrafficDir, { trustedLocal }));
    const integrity = summary?.integrity;
    let unverifiedNativeArtifacts = [];
    const ledger = check(() => {
        const raw = readCaptureFile(resolvedTrafficDir, 'traffic.ndjson', { optional: true, trustedLocal });
        if (!raw && (integrity?.eventCount ?? 0) > 0) {
            throw new Error('Missing traffic.ndjson on disk');
        }
        return parseTrafficLedger(raw);
    });
    if (ledger) {
        eventCount = ledger.events.length;
        chainHeadHash = ledger.head;
        Object.assign(payloadCaptureIssues, getPayloadCaptureIssues(ledger.events));
        if (integrity) {
            check(() => verifyLedgerCheckpoint(integrity, ledger.events));
        }
    }

    let sslKeyLog = parseSslKeyLogBytes(null);
    let neckoMozLog = parseNeckoMozLogBytes(null);
    if (integrity) {
        const manifest = check(() => getPayloadManifest(integrity));
        if (manifest) {
            const errorCount = errors.length;
            ({ verifiedPayloads, unverifiedPayloads } = verifyPayloads(resolvedTrafficDir, manifest, ledger?.events ?? [], {
                trustedLocal,
                check
            }));
            const files = check(() => listCapturePayloads(resolvedTrafficDir, { trustedLocal })) ?? [];
            for (const relativePath of files) {
                if (!Object.hasOwn(manifest, relativePath)) {
                    errors.push(`Orphan unindexed payload file found in payloads/: ${relativePath}`);
                }
            }
            payloadManifestVerified = Boolean(ledger) && errorCount === 0 &&
                errors.length === errorCount && unverifiedPayloads.length === 0;
        }

        const indexedIssues = integrity.payloadCaptureIssues;
        if (ledger && indexedIssues !== undefined && (
            indexedIssues?.writeFailures !== payloadCaptureIssues.writeFailures ||
            indexedIssues?.storageOmissions !== payloadCaptureIssues.storageOmissions
        )) {
            errors.push('Payload capture issue count mismatch in attribution-index.json');
        }
        if (payloadCaptureIssues.writeFailures > 0) {
            errors.push(`${payloadCaptureIssues.writeFailures} payload attachment write(s) failed`);
        }
        if (payloadCaptureIssues.writeFailures || payloadCaptureIssues.storageOmissions) {
            payloadManifestVerified = false;
        }

        check(() => verifyArtifact(resolvedTrafficDir, integrity, 'preTlsWireLog', { trustedLocal }));
        const legacySslKeyLog = check(() => verifyArtifact(resolvedTrafficDir, integrity, 'sslKeyLog', {
            describe: parseSslKeyLogBytes, trustedLocal
        }));
        const legacyNeckoMozLog = check(() => verifyArtifact(resolvedTrafficDir, integrity, 'neckoMozLog', {
            describe: parseNeckoMozLogBytes, trustedLocal
        }));
        const native = verifyProfileNativeGenerations(summary, nativeDir, {
            trustedLocal, check, descriptions: { sslKeyLog: parseSslKeyLogBytes, neckoMozLog: parseNeckoMozLogBytes }
        });
        unverifiedNativeArtifacts = native.unverified;
        sslKeyLog = native.summaries.sslKeyLog ?? legacySslKeyLog ?? sslKeyLog;
        neckoMozLog = native.summaries.neckoMozLog ?? legacyNeckoMozLog ?? neckoMozLog;

        if (sslKeyLog.malformedLineCount > 0 || legacySslKeyLog?.malformedLineCount > 0) {
            errors.push(
                `sslkeylog.txt contains ${Math.max(sslKeyLog.malformedLineCount, legacySslKeyLog?.malformedLineCount ?? 0)} malformed NSS keylog line(s)`
            );
        }
    }

    return {
        valid: errors.length === 0,
        scope,
        unverifiedNativeArtifacts,
        eventCount,
        verifiedPayloads,
        unverifiedPayloads,
        payloadManifestVerified,
        payloadCaptureIssues,
        chainHeadHash,
        sslKeyLog,
        neckoMozLog,
        errors
    };
}

export const MAX_HAR_LEDGER_BYTES = 32 * 1024 * 1024;
export { MAX_HAR_EVENT_BYTES as MAX_HAR_RECORD_BYTES };

/** Project a complete recorded HTTP body without returning the original bytes. */
export function readCaptureExportBody(trafficDir, event, {
    recordBodies = false,
    trustedLocal = false,
    url = event?.url,
    mimeType,
    maxBytes,
    payloadManifest
} = {}) {
    const omitted = { byteLength: null, text: null, payloadFile: null };
    if (!event || recordBodies !== true || event.recordBodies === false ||
        event.bodyOmittedReason || event.payloadTruncated ||
        !allowsTrafficBody(url) || (event.url && event.url !== url && !allowsTrafficBody(event.url))) {
        return omitted;
    }

    const format = shareableBodyFormat(event, mimeType);
    if (!format) return omitted;

    const hasBudget = Number.isFinite(maxBytes) && maxBytes <= DEFAULT_MAX_BODY_BYTES;
    const limit = hasBudget ? Math.max(0, Math.floor(maxBytes)) : DEFAULT_MAX_BODY_BYTES;
    const limited = hasBudget ? { ...omitted, reason: 'body-byte-limit' } : omitted;
    const expectedBytes = event.postDataBytes ?? event.bodyBytes ?? event.payloadBytes;

    if (trafficDir != null && event.payloadFile != null) {
        const recorded = {
            sha256: event.postDataSha256 ?? event.bodySha256 ?? event.payloadSha256,
            bytes: expectedBytes
        };
        const manifest = payloadManifest && Object.hasOwn(payloadManifest, event.payloadFile)
            ? payloadManifest[event.payloadFile] : null;
        const evidence = [recorded, event.payloadStorage, manifest].filter((entry) => entry?.sha256 != null);
        try {
            const bytes = readCapturePayload(trafficDir, event.payloadFile, { maxBytes: limit, trustedLocal });
            const expandedBytes = bytes.byteLength;
            if (evidence.length) {
                const actual = { sha256: hashPayload(bytes).sha256, bytes: expandedBytes };
                try {
                    for (const proof of evidence) comparePayloadEvidence(proof, actual, 'recorded attachment');
                } catch {
                    return { ...omitted, expandedBytes, reason: 'payload-integrity' };
                }
            }
            if (Number.isSafeInteger(expectedBytes) && expandedBytes !== expectedBytes) {
                return { ...omitted, expandedBytes };
            }
            const text = projectTrafficBody(bytes, format, limit);
            if (text === null) return { ...omitted, expandedBytes };
            if (Buffer.byteLength(text) > limit) return { ...limited, expandedBytes };
            return {
                byteLength: expandedBytes,
                expandedBytes,
                text,
                payloadFile: /(?:^|\/)(?:req|res|ws)-\d+-[a-f\d]{12}\.[a-z\d]+$/i.test(event.payloadFile)
                    ? null
                    : redactDiagnosticText(event.payloadFile)
            };
        } catch (error) {
            if (error.code === 'ERR_CAPTURE_TOO_LARGE') return limited;
            if (evidence.length) return { ...omitted, reason: 'payload-integrity' };
            if (error.code !== 'ENOENT') return omitted;
        }
    }

    // The preview flag covers inline text independently of the attachment flag.
    if (event.recordBodies !== true || event.bodyPreviewTruncated) return omitted;
    const preview = event.bodyPreview ?? event.postData;
    if (typeof preview !== 'string') return omitted;
    const previewBytes = Buffer.byteLength(preview);
    if (previewBytes > limit) return limited;
    if (event.bodyPreviewTruncated !== false && Number.isSafeInteger(expectedBytes) &&
        previewBytes !== expectedBytes) return omitted;
    const text = projectTrafficBody(preview, format, limit);
    return text !== null && Buffer.byteLength(text) > limit
        ? { ...limited, expandedBytes: previewBytes }
        : { ...omitted, text, expandedBytes: previewBytes };
}

function harHeaders(record) {
    const { headers, headersArray } = redactSensitiveHeaders(record || {});
    return headersArray.length > 0 ? headersArray : Object.entries(headers).map(([name, value]) => ({ name, value }));
}

function harLimitError(resource) {
    return Object.assign(new Error(`HAR export exceeds its ${resource} limit`), { code: 'ERR_HAR_LIMIT' });
}

function harIntegrityError(message) {
    return Object.assign(new Error(message), { code: 'ERR_CAPTURE_INTEGRITY' });
}

/** Reconstruct a bounded W3C HAR 1.2 document from a profile's traffic directory. */
function buildHarFromTrafficDir(trafficDir, fallbackSession = {}, {
    recordBodies,
    trustedLocal = false,
    matchTransaction,
    [HAR_SESSION_RANGE]: sessionRange = null
} = {}) {
    const resolvedTrafficDir = path.resolve(String(trafficDir));
    const contextual = sessionRange !== null;
    const { start: sessionStart, end: sessionEnd } = sessionRange ?? { start: 0, end: Infinity };
    const { indexData, bodyPolicy } = contextual
        ? {
            indexData: null,
            bodyPolicy: {
                recordBodies: recordBodies === true,
                traceId: fallbackSession.traceId,
                reason: recordBodies === true ? null : 'export-disabled'
            }
        }
        : readCaptureExportIndex(resolvedTrafficDir, { recordBodies, trustedLocal });
    const sessionMeta = indexData?.session ?? {};
    const sessionForTrace = (traceId) => ({
        ...(traceId === (fallbackSession?.traceId ?? null) ? fallbackSession : {}),
        ...(traceId === (sessionMeta.traceId ?? null) ? sessionMeta : {})
    });
    const payloadManifest = contextual ? sessionRange.payloadManifest : indexData?.integrity?.payloadManifest;
    const log = {
        version: '1.2',
        creator: { name: 'CamoufoxTrafficRecorder', version: '1.0.0' },
        browser: { name: 'Camoufox Firefox', version: '135.0' },
        _bodyPolicy: { recordBodies: bodyPolicy.recordBodies, reason: bodyPolicy.reason },
        pages: [],
        entries: []
    };

    // Account for JSON escaping, field names and delimiters using the output representation.
    let remainingBytes = MAX_HAR_BYTES - Buffer.byteLength(JSON.stringify({ log })) - 1;
    let remainingBodyBytes = MAX_HAR_BYTES;
    const reserve = (bytes) => {
        if (bytes > remainingBytes) throw harLimitError('serialized byte');
        remainingBytes -= bytes;
    };
    const retain = (items, item) => {
        reserve(Buffer.byteLength(JSON.stringify(item)) + (items.length ? 1 : 0));
        items.push(item);
    };
    const readBody = (event, url, mimeType) => {
        const maxBytes = Math.min(remainingBodyBytes, remainingBytes);
        const body = readCaptureExportBody(resolvedTrafficDir, event, {
            recordBodies: capturePolicyAllowsBody(bodyPolicy, event), trustedLocal, url, mimeType, maxBytes, payloadManifest
        });
        if (body.reason === 'body-byte-limit') throw harLimitError('body byte');
        if (body.reason === 'payload-integrity') {
            throw harIntegrityError('HAR attachment does not match recorded capture evidence');
        }
        const expandedBytes = Math.max(body.expandedBytes ?? 0, Buffer.byteLength(body.text ?? ''));
        if (expandedBytes > maxBytes) throw harLimitError('body byte');
        remainingBodyBytes -= expandedBytes;
        return body;
    };

    const payloadCaptureIssues = { writeFailures: 0, storageOmissions: 0 };
    const countPayloadIssues = (events) => {
        const counts = getPayloadCaptureIssues(events);
        payloadCaptureIssues.writeFailures += counts.writeFailures;
        payloadCaptureIssues.storageOmissions += counts.storageOmissions;
    };
    const captureBytes = readCaptureFile(resolvedTrafficDir, 'traffic.ndjson', {
        optional: true, trustedLocal, maxBytes: MAX_HAR_LEDGER_BYTES
    });
    const pagesMap = new Map();
    const ensurePageForStep = (stepName, stepIndex, timestamp) => {
        const cleanStep = redactDiagnosticText(stepName || 'init');
        const idx = Number.isFinite(Number(stepIndex)) ? Number(stepIndex) : pagesMap.size;
        const pageKey = `${idx}:${cleanStep}`;
        if (!pagesMap.has(pageKey)) {
            if (pagesMap.size >= MAX_HAR_ENTRIES) throw harLimitError('page count');
            const page = {
                startedDateTime: timestamp || new Date().toISOString(),
                id: `page_${idx}_${cleanStep}`,
                title: `${cleanStep} (step ${idx})`,
                pageTimings: {
                    onContentLoad: -1,
                    onLoad: -1
                }
            };
            retain(log.pages, page);
            pagesMap.set(pageKey, page.id);
        }
        return pagesMap.get(pageKey);
    };

    const txMap = new Map();
    let eventCount = 0;
    let chainHead = TRAFFIC_GENESIS_HASH;
    for (let offset = 0; eventCount < sessionEnd && offset < (captureBytes?.length ?? 0);) {
        const newline = captureBytes.indexOf(0x0a, offset);
        const end = newline === -1 ? captureBytes.length : newline;
        if (end - offset > MAX_HAR_EVENT_BYTES) throw harLimitError('ledger event byte');
        const rawLine = captureBytes.subarray(offset, end);
        const line = rawLine.toString('utf8').trim();
        offset = end + 1;
        if (!line) continue;
        let ev;
        try {
            ev = JSON.parse(line);
        } catch (error) {
            if (!contextual && newline === -1 && isUnfinishedLedgerRecord(line, error)) break;
            throw harIntegrityError(`Invalid JSON in traffic ledger record ${eventCount + 1}`);
        }
        if (!ev || typeof ev !== 'object' || Array.isArray(ev)) {
            throw harIntegrityError(`Expected an event object in traffic ledger record ${eventCount + 1}`);
        }
        eventCount += 1;
        const traceId = captureEventTraceId(ev);
        if (contextual) {
            if (ev.prevEventHash !== chainHead || ev.eventHash !== computeEventHash(ev)) {
                throw harIntegrityError(`Traffic ledger integrity mismatch at record ${eventCount}`);
            }
            chainHead = ev.eventHash;
            if (eventCount <= sessionStart || traceId !== bodyPolicy.traceId) continue;
        }
        if (!matchTransaction && ev.payloadStorage) countPayloadIssues([ev]);
        if (ev.type === 'step-transition') {
            if (!matchTransaction) {
                ensurePageForStep(
                    ev.actionStep || ev.attribution?.actionStep || 'init',
                    ev.stepIndex ?? ev.attribution?.stepIndex ?? 0,
                    ev.timestamp || sessionForTrace(traceId).startedAt
                );
            }
            continue;
        }

        if (!ev.correlationId) continue;
        if (
            ev.type !== 'egress' &&
            ev.type !== 'ingress' &&
            ev.type !== 'request-finished' &&
            ev.type !== 'request-failed' &&
            ev.type !== 'security-block'
        ) {
            continue;
        }

        const txKey = JSON.stringify([traceId, ev.correlationId]);
        if (!txMap.has(txKey)) {
            if (txMap.size >= MAX_HAR_ENTRIES) throw harLimitError('transaction count');
            txMap.set(txKey, {
                correlationId: ev.correlationId,
                traceId,
                egress: null,
                ingress: null,
                finished: null,
                failed: null,
                securityBlock: null
            });
        }
        const tx = txMap.get(txKey);
        // Retain slices of the bounded ledger. Inflate each transaction only when building its entry.
        if (ev.type === 'egress') tx.egress = rawLine;
        else if (ev.type === 'ingress') tx.ingress = rawLine;
        else if (ev.type === 'request-finished') tx.finished = rawLine;
        else if (ev.type === 'request-failed') tx.failed = rawLine;
        else if (ev.type === 'security-block') tx.securityBlock = rawLine;
    }

    if (contextual && (eventCount !== sessionEnd || chainHead !== sessionRange.head)) {
        throw harIntegrityError('Traffic ledger no longer contains the recorded HAR session');
    }

    const decodeEvent = (rawLine) => rawLine ? JSON.parse(rawLine.toString('utf8').trim()) : null;
    for (const tx of txMap.values()) {
        const { correlationId, traceId } = tx;
        const egress = decodeEvent(tx.egress);
        const ingress = decodeEvent(tx.ingress);
        const finished = decodeEvent(tx.finished);
        const failed = decodeEvent(tx.failed);
        const securityBlock = decodeEvent(tx.securityBlock);

        const attribution =
            egress?.attribution ||
            ingress?.attribution ||
            failed?.attribution ||
            securityBlock?.attribution ||
            finished?.attribution ||
            {};
        const transactionSession = sessionForTrace(traceId);
        const observedAttributions = [egress, ingress, failed, securityBlock, finished]
            .filter(Boolean).flatMap((event) => [event.attribution, event].filter(Boolean));
        const attributed = (field) => {
            const observed = observedAttributions.find((record) => Object.hasOwn(record, field));
            return observed ? observed[field] : transactionSession[field];
        };
        const actionStep =
            attribution.actionStep ||
            egress?.actionStep ||
            ingress?.actionStep ||
            failed?.actionStep ||
            securityBlock?.actionStep ||
            finished?.actionStep ||
            'init';
        const stepIndex =
            attribution.stepIndex ??
            egress?.stepIndex ??
            ingress?.stepIndex ??
            failed?.stepIndex ??
            securityBlock?.stepIndex ??
            finished?.stepIndex ??
            0;
        const triggerAction =
            egress?.triggerAction ||
            ingress?.triggerAction ||
            failed?.triggerAction ||
            securityBlock?.triggerAction ||
            finished?.triggerAction ||
            attribution.triggerAction ||
            null;

        const rawUrl =
            egress?.url ||
            ingress?.url ||
            failed?.url ||
            securityBlock?.url ||
            finished?.url ||
            '';
        const status = ingress?.status ?? finished?.status ?? (securityBlock ? 0 : null);
        if (matchTransaction && !matchTransaction({
            correlationId, url: rawUrl, actionStep, triggerAction, status
        })) continue;
        if (matchTransaction) countPayloadIssues([egress, ingress]);

        const startedDateTime =
            egress?.timestamp ||
            ingress?.timestamp ||
            failed?.timestamp ||
            securityBlock?.timestamp ||
            finished?.timestamp ||
            transactionSession.startedAt ||
            new Date().toISOString();

        const pageref = ensurePageForStep(actionStep, stepIndex, startedDateTime);

        let totalTimeMs = 0;
        if (typeof finished?.durationMs === 'number' && Number.isFinite(finished.durationMs)) {
            totalTimeMs = Math.max(0, finished.durationMs);
        } else if (typeof failed?.durationMs === 'number' && Number.isFinite(failed.durationMs)) {
            totalTimeMs = Math.max(0, failed.durationMs);
        } else if (
            typeof egress?.epochMs === 'number' &&
            typeof ingress?.epochMs === 'number'
        ) {
            totalTimeMs = Math.max(0, ingress.epochMs - egress.epochMs);
        }

        const method =
            egress?.method ||
            ingress?.method ||
            failed?.method ||
            securityBlock?.method ||
            finished?.method ||
            'GET';

        const requestUrl = redactUrlSecrets(rawUrl);
        const reqHeaders = harHeaders(egress);

        // Build queryString array
        const queryString = [];
        try {
            const base = requestUrl.includes('?') ? 'https://capture.invalid' : undefined;
            const parsed = new URL(requestUrl, base);
            for (const [name, value] of parsed.searchParams.entries()) {
                queryString.push({ name: String(name), value: String(value) });
            }
        } catch {
            if (egress?.searchParams && typeof egress.searchParams === 'object') {
                const { searchParams } = redactDiagnosticMetadata({ searchParams: egress.searchParams });
                for (const [k, v] of Object.entries(searchParams)) {
                    if (Array.isArray(v)) {
                        for (const item of v) {
                            queryString.push({ name: String(k), value: String(item ?? '') });
                        }
                    } else {
                        queryString.push({ name: String(k), value: String(v ?? '') });
                    }
                }
            }
        }

        // Reconstruct request postData from payloadFile on disk or inline preview
        const reqMimeType = egress?.mimeType ||
            reqHeaders.find((h) => h.name.toLowerCase() === 'content-type')?.value || '';
        const requestBody = readBody(egress, rawUrl, reqMimeType);
        const reqBodyText = requestBody.text || '';
        const reqBodySize =
            Number(egress?.postDataBytes) ||
            Number(finished?.sizes?.requestBodySize) ||
            (reqBodyText ? Buffer.byteLength(reqBodyText, 'utf8') : 0);

        const postData = {
            mimeType: reqMimeType || (reqBodyText ? 'application/octet-stream' : ''),
            text: reqBodyText,
            params: []
        };

        const resHeaders = harHeaders(ingress);

        const resContentTypeHeader =
            resHeaders.find((h) => h.name.toLowerCase() === 'content-type')?.value || '';
        const resMimeType =
            ingress?.mimeType ||
            (resContentTypeHeader ? resContentTypeHeader.split(';')[0].trim() : '') ||
            'application/octet-stream';

        const responseBody = readBody(ingress, rawUrl, resMimeType);
        const resBodyText = responseBody.text || '';
        const resBodySize = responseBody.byteLength ?? (Number(ingress?.bodyBytes) ||
            Number(finished?.sizes?.responseBodySize) || Buffer.byteLength(resBodyText, 'utf8'));

        const redirectURL =
            resHeaders.find((h) => h.name.toLowerCase() === 'location')?.value || '';

        const statusText = redactDiagnosticText(
            ingress?.statusText ??
            (securityBlock
                ? 'BLOCKED_BY_ZINIAO_SECURITY_GUARD'
                : failed
                  ? String(failed.failureText || 'FAILED')
                  : '')
        );

        retain(log.entries, {
            pageref,
            startedDateTime,
            time: totalTimeMs,
            request: {
                method,
                url: requestUrl,
                httpVersion: 'HTTP/1.1',
                cookies: [],
                headers: reqHeaders,
                queryString,
                postData,
                headersSize: Number(finished?.sizes?.requestHeadersSize) || -1,
                bodySize: reqBodySize
            },
            response: {
                status: Number(status ?? 0),
                statusText,
                httpVersion: 'HTTP/1.1',
                cookies: [],
                headers: resHeaders,
                content: {
                    size: resBodySize,
                    mimeType: resMimeType,
                    text: resBodyText
                },
                redirectURL,
                headersSize: Number(finished?.sizes?.responseHeadersSize) || -1,
                bodySize: resBodySize
            },
            cache: {},
            timings: {
                blocked: 0,
                dns: -1,
                connect: -1,
                ssl: -1,
                send: 0,
                wait: totalTimeMs,
                receive: 0
            },
            serverIPAddress: ingress?.serverAddr?.ipAddress || '',
            ...(securityBlock
                ? {
                      _camoufoxSecurityBlock: {
                          blocked: true,
                          blockType: securityBlock.blockType || 'security-probe',
                          severity: securityBlock.severity || 'critical',
                          reason: redactDiagnosticText(
                              securityBlock.reason ||
                              securityBlock.failureText ||
                              'BLOCKED_BY_ZINIAO_SECURITY_GUARD',
                          ),
                          host: securityBlock.host || null,
                          port: securityBlock.port ?? null,
                          scope: securityBlock.scope || null,
                          service: securityBlock.service || null,
                          category: securityBlock.category || null,
                          matchedScheme: securityBlock.matchedScheme || null,
                          initiatorUrl: redactUrlSecrets(securityBlock.initiatorUrl) || null
                      }
                  }
                : {}),
            _attribution: {
                correlationId,
                actionStep: redactDiagnosticText(actionStep),
                stepIndex,
                triggerAction: triggerAction ? redactTriggerAction(redactDiagnosticMetadata(triggerAction)) : null,
                ...redactDiagnosticMetadata({
                    profileId: attributed('profileId') || fallbackSession?.profileId || 'default-profile',
                    accountId: attributed('accountId') ?? null,
                    traceId,
                    os: attributed('os') ?? null
                }),
                accountEmail: null,
                proxyServer: redactProxyUrl(attributed('proxyServer')),
                preTlsStage:
                    egress?.stage ||
                    ingress?.stage ||
                    failed?.stage ||
                    securityBlock?.stage ||
                    'pre-tls-necko-channel',
                redirectedFromCorrelationId:
                    egress?.redirectedFromCorrelationId ||
                    ingress?.redirectedFromCorrelationId ||
                    null,
                requestPayloadFile: requestBody.payloadFile,
                responsePayloadFile: responseBody.payloadFile,
                ...(egress?.payloadStorage?.status === 'failed' ? { requestPayloadIssue: 'write-failed' } : {}),
                ...(egress?.payloadStorage?.status === 'omitted' ? { requestPayloadIssue: 'storage-limit' } : {}),
                ...(ingress?.payloadStorage?.status === 'failed' ? { responsePayloadIssue: 'write-failed' } : {}),
                ...(ingress?.payloadStorage?.status === 'omitted' ? { responsePayloadIssue: 'storage-limit' } : {}),
                failureText: redactDiagnosticText(
                    failed?.failureText ||
                    securityBlock?.reason ||
                    securityBlock?.failureText ||
                    null
                ) || null
            }
        });
    }

    if (pagesMap.size === 0 && !matchTransaction) {
        ensurePageForStep('init', 0, sessionMeta.startedAt || fallbackSession?.startedAt);
    }

    if (payloadCaptureIssues.writeFailures || payloadCaptureIssues.storageOmissions) {
        // The added property costs its serialized bytes and comma, excluding object braces.
        reserve(Buffer.byteLength(JSON.stringify({ _payloadCaptureIssues: payloadCaptureIssues })) - 1);
        log._payloadCaptureIssues = payloadCaptureIssues;
    }
    return { archive: { log }, artifacts: indexData?.artifacts };
}

function* serializeHar({ log: { pages, entries, ...metadata } }) {
    yield `{"log":${JSON.stringify(metadata).slice(0, -1)},"pages":[`;
    for (const [index, page] of pages.entries()) {
        yield `${index ? ',' : ''}${JSON.stringify(page)}`;
    }
    yield '],"entries":[';
    for (const [index, entry] of entries.entries()) {
        yield `${index ? ',' : ''}${JSON.stringify(entry)}`;
    }
    yield ']}}\n';
}

/**
 * Standalone exporter that reconstructs a W3C HAR 1.2 archive from a profile's
 * `trafficDir` (`traffic.ndjson` + `payloads/`) and writes it to `outputPath`.
 *
 * @param {string} trafficDir
 * @param {string} [outputPath]
 * @param {object} [fallbackSession={}]
 * @returns {{
 *   harPath: string,
 *   outputPath: string,
 *   entryCount: number,
 *   entriesCount: number,
 *   pageCount: number,
 *   bytes: number,
 *   log: object,
 *   har: { log: object }
 * }}
 */
export function exportTrafficToHar(trafficDir, outputPath, fallbackSession = {}, options = {}) {
    if (!trafficDir) {
        throw new Error('trafficDir is required for exportTrafficToHar');
    }
    const resolvedTrafficDir = path.resolve(String(trafficDir));
    const resolvedOutputPath = path.resolve(outputPath ? String(outputPath) : 'traffic.har');
    const captureRoot = fs.realpathSync.native(resolvedTrafficDir);
    const source = fs.statSync(captureRoot, { bigint: true });
    if (!source.isDirectory()) throw new Error('HAR input must be a traffic directory');
    if (!outputPath) {
        const fromCapture = path.relative(captureRoot, process.cwd());
        if (fromCapture !== '..' && !fromCapture.startsWith(`..${path.sep}`) && !path.isAbsolute(fromCapture)) {
            throw new Error('Choose a HAR output path when running inside the input capture directory');
        }
    }

    const { archive: harArchive, artifacts } = buildHarFromTrafficDir(resolvedTrafficDir, fallbackSession, options);
    const current = fs.statSync(resolvedTrafficDir, { bigint: true });
    if (current.dev !== source.dev || current.ino !== source.ino) {
        throw harIntegrityError('Traffic directory changed during HAR export');
    }
    const captureName = path.basename(captureRoot);
    const nativeDir = path.join(path.dirname(captureRoot), captureName === 'traffic' ? '.native' : `.${captureName}-native`);
    const declaredLedger = artifacts?.trafficNdjsonPath;
    const recordedLedger = typeof declaredLedger === 'string' && path.isAbsolute(declaredLedger)
        ? resolveFilesystemPath(declaredLedger) : null;
    const inputLedgers = [resolveFilesystemPath(path.join(resolvedTrafficDir, 'traffic.ndjson')),
        path.join(captureRoot, 'traffic.ndjson')];
    const recordedWirePath = inputLedgers.includes(recordedLedger) ? artifacts.preTlsWireLogPath : null;
    const bytes = writeCaptureExport(resolvedOutputPath, serializeHar(harArchive), {
        replace: Boolean(outputPath),
        recordedWirePath,
        protectedPaths: [
            ...['traffic.ndjson', 'attribution-index.json', 'payloads', '.private', ...Object.values(INTEGRITY_ARTIFACTS)]
                .map((name) => path.join(captureRoot, name)),
            captureWriterLeaseDirectory(captureRoot),
            nativeDir,
            ...(options[HAR_PROTECTED_PATHS] ?? [])
        ]
    });

    return {
        harPath: resolvedOutputPath,
        outputPath: resolvedOutputPath,
        entryCount: harArchive.log.entries.length,
        entriesCount: harArchive.log.entries.length,
        pageCount: harArchive.log.pages.length,
        bytes,
        log: harArchive.log,
        har: harArchive
    };
}

/**
 * Factory helper to create a new `CamoufoxTrafficRecorder` instance.
 *
 * @param {object} [options={}]
 * @returns {CamoufoxTrafficRecorder}
 */
export function createTrafficRecorder(options = {}) {
    return new CamoufoxTrafficRecorder(options);
}

export default CamoufoxTrafficRecorder;
