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
import { constants as bufferLimits } from 'node:buffer';
import { fileURLToPath } from 'url';
import {
    appendPrivateFile, ensurePrivateDirectory, restrictPrivateFile, writePrivateFile
} from '../utils/private-storage.js';
import {
    listCapturePayloads, readCaptureFile, readCapturePayload, truncateCaptureFile, writeCaptureExport
} from './capture-io.js';
import {
    redactDiagnosticMetadata,
    redactDiagnosticText,
    redactSensitiveHeaders,
    redactTriggerAction,
    redactUrlSecrets
} from './traffic-redaction.js';

export {
    redactDiagnosticMetadata,
    redactDiagnosticText,
    redactSensitiveHeaders,
    redactTriggerAction,
    redactUrlSecrets,
    SENSITIVE_HEADER_REGEX,
    SENSITIVE_URL_PARAM_REGEX
} from './traffic-redaction.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEFAULT_PROFILES_DIR = (process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR)
    ? path.resolve(process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR)
    : path.resolve(__dirname, '../../profiles');

const DEFAULT_MAX_INLINE_PREVIEW_BYTES = 4096;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024; // 5MB (5242880 bytes)
const TRAFFIC_GENESIS_HASH = '0'.repeat(64);
const MAX_INTEGRITY_PAYLOAD_BYTES = 128 * 1024 * 1024;
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
 * Known anti-bot, risk-control, and session authentication cookie/token names across
 * Google, Cloudflare, Meta/Instagram, TikTok, and X/Twitter.
 */
export const ANTI_BOT_COOKIE_REGEX =
    /^(datr|sb|fr|c_user|xs|ig_did|mid|csrftoken|rur|ttwid|msToken|s_v_web_id|verifyFp|odin_tt|passport_csrf_token|guest_id|guest_id_marketing|guest_id_ads|ct0|auth_token|kdt|_twitter_sess|__cf_bm|cf_clearance|_cfuvid|NID|AEC|SOCS|SID|HSID|SSID|APISID|SAPISID|__Secure-[0-9A-Za-z_-]+|__Host-[0-9A-Za-z_-]+)$/i;

const COOKIE_VALUE_MASK = '[REDACTED]';

/**
 * Parse a `Set-Cookie` response header string into structured metadata with a full
 * SHA-256 value digest (`valueSha256`) and masked preview (`maskedValue`) for
 * tamper-evident token rotation and lineage tracking.
 *
 * @param {string} rawSetCookieValue
 * @returns {{
 *   name: string,
 *   value: string,
 *   valueSha256: string,
 *   maskedValue: string,
 *   domain: string|null,
 *   path: string|null,
 *   secure: boolean,
 *   httpOnly: boolean,
 *   sameSite: string|null,
 *   expires: string|null,
 *   maxAge: number|null,
 *   isDeleted: boolean,
 *   isAntiBotToken: boolean
 * }|null}
 */
export function parseSetCookieHeader(rawSetCookieValue) {
    if (typeof rawSetCookieValue !== 'string') {
        return null;
    }
    const trimmedHeader = rawSetCookieValue.trim();
    if (!trimmedHeader) {
        return null;
    }

    const parts = trimmedHeader.split(';');
    const firstPart = (parts[0] || '').trim();
    const eqIdx = firstPart.indexOf('=');
    if (eqIdx <= 0) {
        return null;
    }

    const name = firstPart.slice(0, eqIdx).trim();
    if (!name) {
        return null;
    }
    const value = firstPart.slice(eqIdx + 1).trim();
    const valueSha256 = crypto.createHash('sha256').update(value, 'utf8').digest('hex');
    const maskedValue = COOKIE_VALUE_MASK;

    let domain = null;
    let cookiePath = null;
    let secure = false;
    let httpOnly = false;
    let sameSite = null;
    let expires = null;
    let maxAge = null;

    for (let i = 1; i < parts.length; i += 1) {
        const attrSegment = parts[i].trim();
        if (!attrSegment) continue;

        const attrEqIdx = attrSegment.indexOf('=');
        const attrName = (attrEqIdx >= 0 ? attrSegment.slice(0, attrEqIdx) : attrSegment)
            .trim()
            .toLowerCase();
        const attrVal = attrEqIdx >= 0 ? attrSegment.slice(attrEqIdx + 1).trim() : null;

        if (attrName === 'domain') {
            domain = attrVal || null;
        } else if (attrName === 'path') {
            cookiePath = attrVal ? redactUrlSecrets(attrVal) : null;
        } else if (attrName === 'secure') {
            secure = true;
        } else if (attrName === 'httponly') {
            httpOnly = true;
        } else if (attrName === 'samesite') {
            sameSite = attrVal || null;
        } else if (attrName === 'expires') {
            expires = attrVal || null;
        } else if (attrName === 'max-age') {
            const parsedMaxAge = attrVal !== null && attrVal !== '' ? Number(attrVal) : NaN;
            maxAge = Number.isFinite(parsedMaxAge) ? parsedMaxAge : null;
        }
    }

    let expiredByDate = false;
    if (expires) {
        const parsedExpiresMs = Date.parse(expires);
        if (Number.isFinite(parsedExpiresMs) && parsedExpiresMs <= Date.now()) {
            expiredByDate = true;
        }
    }

    const isDeleted =
        value === '' ||
        /^deleted$/i.test(value) ||
        (maxAge !== null && maxAge <= 0) ||
        expiredByDate;

    const isAntiBotToken = ANTI_BOT_COOKIE_REGEX.test(name);

    return {
        name,
        value,
        valueSha256,
        maskedValue,
        domain,
        path: cookiePath,
        secure,
        httpOnly,
        sameSite,
        expires,
        maxAge,
        isDeleted,
        isAntiBotToken
    };
}

/**
 * Parse an egress `Cookie` request header string (`"k1=v1; k2=v2"`) into an array
 * of structured cookie descriptors with SHA-256 value digests and masked previews.
 *
 * @param {string} rawCookieHeader
 * @returns {Array<{
 *   name: string,
 *   value: string,
 *   valueSha256: string,
 *   maskedValue: string,
 *   isAntiBotToken: boolean
 * }>}
 */
export function parseCookieHeader(rawCookieHeader) {
    if (typeof rawCookieHeader !== 'string' || !rawCookieHeader.trim()) {
        return [];
    }

    const results = [];
    const segments = rawCookieHeader.split(/[;\r\n]+/);

    for (const seg of segments) {
        const trimmed = seg.trim();
        if (!trimmed) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx <= 0) continue;

        const name = trimmed.slice(0, eqIdx).trim();
        if (!name) continue;
        const value = trimmed.slice(eqIdx + 1).trim();
        const valueSha256 = crypto.createHash('sha256').update(value, 'utf8').digest('hex');
        const maskedValue = COOKIE_VALUE_MASK;
        const isAntiBotToken = ANTI_BOT_COOKIE_REGEX.test(name);

        results.push({
            name,
            value,
            valueSha256,
            maskedValue,
            isAntiBotToken
        });
    }

    return results;
}

function deriveCookieObservations({ headers = {}, headersArray = [] }, name) {
    const orderedValues = headersArray
        .filter((header) => String(header?.name).toLowerCase() === name)
        .map((header) => header.value);
    const rawValues = orderedValues.length ? orderedValues : Object.entries(headers)
        .filter(([headerName]) => headerName.toLowerCase() === name)
        .flatMap(([, value]) => value);

    const parsed = name === 'set-cookie'
        ? rawValues.flatMap((value) => String(value ?? '').split(/\r?\n/).map(parseSetCookieHeader))
        : rawValues.flatMap(parseCookieHeader);
    return parsed.filter(Boolean).map(({ value, ...observation }) => observation);
}

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
 * Redact credentials from a proxy configuration string or object.
 * Never persists raw proxy usernames or passwords to disk.
 *
 * @param {string|object|null|undefined} proxyInput
 * @returns {string|null}
 */
export function redactProxyUrl(proxyInput) {
    if (!proxyInput) {
        return null;
    }

    let rawServer = null;
    if (typeof proxyInput === 'string') {
        rawServer = proxyInput.trim();
    } else if (typeof proxyInput === 'object') {
        rawServer = proxyInput.server || proxyInput.url || proxyInput.host || null;
        if (rawServer && proxyInput.port && !String(rawServer).includes(`:${proxyInput.port}`)) {
            rawServer = `${rawServer}:${proxyInput.port}`;
        }
    }

    if (!rawServer) {
        return null;
    }

    const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawServer)
        ? rawServer
        : `http://${rawServer}`;

    try {
        const parsed = new URL(candidate);
        parsed.username = '';
        parsed.password = '';
        const formatted = parsed.toString();
        return redactUrlSecrets(formatted.endsWith('/') && !rawServer.endsWith('/')
            ? formatted.slice(0, -1)
            : formatted);
    } catch {
        // Fallback regex strip for user:pass@host:port
        return redactUrlSecrets(String(rawServer).replace(/(\/\/|^)([^/@:\s]+:[^/@\s]+@)/, '$1'));
    }
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
    if (buffer && buffer.byteLength > 0) {
        const firstByte = buffer[0];
        if (firstByte === 0x7b || firstByte === 0x5b) {
            try {
                const sample = buffer.toString('utf8');
                JSON.parse(sample);
                return 'json';
            } catch {
                // Not valid JSON; continue classification
            }
        }
    }
    if (TEXTUAL_MIME_PATTERNS.test(normalizedMime)) {
        return 'txt';
    }
    if (buffer && buffer.byteLength > 0) {
        const checkLen = Math.min(buffer.byteLength, 512);
        let nonPrintable = 0;
        for (let i = 0; i < checkLen; i += 1) {
            const byte = buffer[i];
            if (byte === 0x00) {
                return 'bin';
            }
            if (byte < 0x09 || (byte > 0x0d && byte < 0x20)) {
                nonPrintable += 1;
            }
        }
        if (nonPrintable / checkLen < 0.05) {
            return 'txt';
        }
    }
    return 'bin';
}

/**
 * Build a safe UTF-8 inline preview for text/JSON payloads or a diagnostic summary
 * for binary payloads.
 *
 * @param {Buffer} buffer
 * @param {string|null|undefined} mimeType
 * @param {number} maxBytes
 * @returns {{ preview: string|null, truncated: boolean, encoding: 'utf8'|'hex-preview' }}
 */
function buildBodyPreview(buffer, mimeType, maxBytes = DEFAULT_MAX_INLINE_PREVIEW_BYTES) {
    if (!buffer || buffer.byteLength === 0 || maxBytes <= 0) {
        return { preview: null, truncated: false, encoding: 'utf8' };
    }

    const ext = inferPayloadExtension(mimeType, buffer);
    const truncated = buffer.byteLength > maxBytes;
    const slice = truncated ? buffer.subarray(0, maxBytes) : buffer;

    if (ext === 'json' || ext === 'txt') {
        return {
            preview: redactDiagnosticText(slice.toString('utf8')),
            truncated,
            encoding: 'utf8'
        };
    }

    const hexPreviewBytes = Math.min(slice.byteLength, 128);
    return {
        preview: `[binary ${buffer.byteLength} bytes; head_hex=${slice.subarray(0, hexPreviewBytes).toString('hex')}]`,
        truncated: buffer.byteLength > hexPreviewBytes,
        encoding: 'hex-preview'
    };
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
        const cleanSearch = (parsed.search || '').replace(
            /%5BREDACTED%3A([0-9a-f]{8})%5D/gi,
            '[REDACTED:$1]'
        );
        return {
            protocol: parsed.protocol ? parsed.protocol.replace(/:$/, '') : null,
            host: parsed.host || parsed.hostname || 'unknown',
            hostname: parsed.hostname || 'unknown',
            port: parsed.port || null,
            pathname: parsed.pathname || '/',
            search: cleanSearch,
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
 *   valueLength: number,
 *   valueSha256: string,
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
        results.push({
            platform,
            signatureName,
            location,
            valueLength: valueStr.length,
            valueSha256,
            maskedPreview: maskPlatformSignatureValue(valueStr)
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
    try {
        return fs.readFileSync(filePath);
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
    }
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
async function extractHeadersWithOrder(target, cookieHeaderName) {
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

    const cookieObservations = deriveCookieObservations({ headers, headersArray }, cookieHeaderName);
    return { ...redactSensitiveHeaders({ headers, headersArray }), cookieObservations };
}

function computeEventHash(record) {
    const canonicalPayload = JSON.stringify({ ...record, eventHash: undefined });
    const preimage = `${record.prevEventHash}|${record.seq ?? 0}|${canonicalPayload}`;
    return crypto.createHash('sha256').update(preimage, 'utf8').digest('hex');
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
            const parseOffset = /\bin JSON at position (\d+)\b/.exec(error.message);
            if (
                recover &&
                index === lines.length - 1 &&
                line.startsWith('{') &&
                (error.message === 'Unexpected end of JSON input' ||
                    Number(parseOffset?.[1]) === line.length)
            ) {
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
        Object.entries(nativeArtifacts).some(([type, entry]) =>
            (type !== 'sslKeyLog' && type !== 'neckoMozLog') ||
            typeof entry?.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256) ||
            !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 ||
            index.integrity[`${type}Sha256`] != null ||
            (index.integrity[`${type}Bytes`] ?? 0) !== 0 ||
            index.integrity[`${type}File`] !== undefined
        )
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

function readIntegrityPayload(trafficDir, relativePath, trustedLocal) {
    return readCapturePayload(trafficDir, relativePath, {
        trustedLocal,
        maxBytes: trustedLocal ? bufferLimits.MAX_STRING_LENGTH : MAX_INTEGRITY_PAYLOAD_BYTES
    });
}

function verifyPayloadEntry(trafficDir, relativePath, entry, trustedLocal) {
    const buffer = readIntegrityPayload(trafficDir, relativePath, trustedLocal);
    if (entry?.sha256 != null && hashPayload(buffer).sha256 !== entry.sha256) {
        throw new Error(`Payload SHA-256 mismatch for ${relativePath}`);
    }
    if (entry?.bytes != null && buffer.byteLength !== entry.bytes) {
        throw new Error(`Payload byte length mismatch for ${relativePath}`);
    }
}

function nativeArtifactName(trafficDir, configuredPath, fileName) {
    if (!configuredPath) return null;
    const relative = path.relative(trafficDir, configuredPath).split(path.sep).join('/');
    return relative === fileName || relative === `.private/${fileName}` ? relative : null;
}

function verifyArtifact(trafficDir, integrity, prefix, {
    describe, allowAppendedBytes = false, nativeDir = null, trustedLocal = false
} = {}) {
    const fileName = INTEGRITY_ARTIFACTS[prefix];
    const profileArtifact = integrity.nativeArtifacts?.[prefix];
    if (profileArtifact && !nativeDir) return null;
    const digest = profileArtifact?.sha256 ?? integrity[`${prefix}Sha256`];
    const bytes = profileArtifact?.bytes ?? integrity[`${prefix}Bytes`];
    const recordedFileName = integrity[`${prefix}File`];
    if (
        recordedFileName !== undefined &&
        recordedFileName !== fileName &&
        (prefix === 'preTlsWireLog' || recordedFileName !== `.private/${fileName}`)
    ) {
        throw new Error(`Invalid capture file reference for ${fileName}`);
    }
    const location = profileArtifact ? fileName : recordedFileName ?? fileName;
    // Legacy summaries used null/zero for an optional artifact that was never written.
    const hasLegacyAbsenceMarker = digest === null && bytes === 0;
    if (recordedFileName === undefined && ((digest == null && bytes == null) || hasLegacyAbsenceMarker)) {
        return null;
    }

    const raw = readCaptureFile(profileArtifact ? nativeDir : trafficDir, location, {
        optional: true,
        trustedLocal
    });
    if (!raw) {
        throw new Error(`Missing ${location} on disk`);
    }
    const stats = describe?.(raw);
    const prefixEnd = allowAppendedBytes && Number.isSafeInteger(bytes) && bytes >= 0 ? bytes : raw.length;
    if (digest != null && digest !== (stats?.sha256 ?? hashPayload(raw.subarray(0, prefixEnd)).sha256)) {
        throw new Error(`${fileName} SHA-256 mismatch`);
    }
    if (bytes != null && (
        !Number.isSafeInteger(bytes) || bytes < 0 ||
        (allowAppendedBytes ? bytes > raw.byteLength : bytes !== raw.byteLength)
    )) {
        throw new Error(`${fileName} byte length mismatch`);
    }
    return stats;
}

/**
 * Camoufox Pre-TLS Traffic Recorder & Multi-Dimensional Attribution Engine.
 */
export class CamoufoxTrafficRecorder {
    /**
     * @param {object} [options]
     * @param {string} [options.profileId='default-profile']
     * @param {string} [options.profilesDir]
     * @param {string} [options.profileDir]
     * @param {string} [options.trafficDir]
     * @param {string} [options.traceId]
     * @param {string|null} [options.accountId=null]
     * @param {string|null} [options.accountEmail=null]
     * @param {string} [options.os]
     * @param {string|object|null} [options.proxy]
     * @param {string|null} [options.proxyServer]
     * @param {string} [options.actionStep='init']
     * @param {number} [options.maxInlinePreviewBytes=4096]
     * @param {number} [options.inlinePayloadThresholdBytes=0]
     * @param {boolean} [options.capturePayloads=true]
     * @param {boolean} [options.recordBodies=true]
     * @param {number} [options.maxBodyBytes=5242880]
     * @param {boolean} [options.recordWireLog=true]
     * @param {string|null} [options.preTlsWireLogPath=null]
     * @param {boolean} [options.sslKeyLog=true]
     * @param {string|null} [options.sslKeyLogPath=null]
     * @param {boolean} [options.neckoMozLog=true]
     * @param {string|null} [options.neckoMozLogPath=null]
     * @param {string|null} [options.profileNativeDir=null]
     * @param {boolean} [options.trustedLocal=false]
     * @param {string|null} [options.harPath=null]
     */
    constructor(options = {}) {
        const profileId = String(options.profileId || 'default-profile');
        const profilesDir = options.profilesDir
            ? path.resolve(options.profilesDir)
            : DEFAULT_PROFILES_DIR;
        const profileDir = options.profileDir
            ? path.resolve(options.profileDir)
            : path.join(profilesDir, profileId);
        const trafficDir = options.trafficDir
            ? path.resolve(options.trafficDir)
            : path.join(profileDir, 'traffic');

        this.profileId = profileId;
        this.profilesDir = profilesDir;
        this.profileDir = profileDir;
        this.trafficDir = trafficDir;
        this.trustedLocal = options.trustedLocal === true;
        this.profileNativeDir = options.profileNativeDir ? path.resolve(options.profileNativeDir) : null;

        this.payloadsDir = path.join(this.trafficDir, 'payloads');
        this.trafficNdjsonPath = path.join(this.trafficDir, 'traffic.ndjson');
        this.preTlsWireLogPath = options.preTlsWireLogPath
            ? path.resolve(options.preTlsWireLogPath)
            : path.join(this.trafficDir, 'pre-tls-wire.log');
        this.recordWireLog = options.recordWireLog !== false;
        const privateNativeDir = path.join(this.trafficDir, '.private');
        this.neckoMozLogPath = options.neckoMozLog === false
            ? null
            : path.resolve(options.neckoMozLogPath || path.join(privateNativeDir, 'necko-pre-tls.moz_log'));
        this.sslKeyLogPath = options.sslKeyLog === false
            ? null
            : path.resolve(options.sslKeyLogPath || path.join(privateNativeDir, 'sslkeylog.txt'));
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
            ? options.recordBodies !== false
            : options.capturePayloads !== false;
        this.capturePayloads = capturePayloads;
        this.recordBodies = capturePayloads;
        this.maxBodyBytes =
            Number.isFinite(options.maxBodyBytes) && Number(options.maxBodyBytes) > 0
                ? Math.floor(Number(options.maxBodyBytes))
                : DEFAULT_MAX_BODY_BYTES;

        const traceId = options.traceId || crypto.randomUUID();
        this.traceId = traceId;
        this.traceIdShort = String(traceId).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8) || 'trace000';

        const initialStep = String(options.actionStep || 'init');
        const redactedProxy = redactProxyUrl(options.proxyServer || options.proxy || null);

        this.attribution = {
            traceId: this.traceId,
            profileId: this.profileId,
            accountId: options.accountId ?? null,
            accountEmail: options.accountEmail ?? null,
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
        this.lastTriggerAction = null;

        // Cryptographic SHA-256 tamper-evident hash chain & payload integrity manifest
        this.genesisHash = TRAFFIC_GENESIS_HASH;
        this.chainHeadHash = this.genesisHash;
        this.chainedEventCount = 0;
        this.payloadManifest = {};
        this.ledgerNeedsSeparator = false;
        this.ledgerWriteError = null;
        this.wireWriteError = null;

        // Correlation & tracking stores
        this.requestCorrelationMap = new WeakMap();
        this.transactions = new Map();
        this.wsWireBlocks = new Map();
        this.attachedContexts = new WeakSet();
        this.attachedPagesHttp = new WeakSet();
        this.attachedPagesWs = new WeakSet();
        this.attachedWebSockets = new WeakSet();
        this.webSocketDisposers = new Set();
        this.listenerDisposers = [];
        this.pendingTasks = new Set();

        // Aggregated metrics
        this.totals = {
            totalRequests: 0,
            totalResponses: 0,
            failedRequests: 0,
            wsFramesSent: 0,
            wsFramesReceived: 0,
            totalEgressBytes: 0,
            totalIngressBytes: 0
        };

        this.byActionStep = new Map();
        this.byDomain = new Map();
        this.byTriggerAction = new Map();
        this.cookieLineage = new Map();
        this.platformSignatures = [];
        this.anomaliesAndRiskSignals = [];
        this.recordedAnomalyKeys = new Set();

        this.resetTrafficOnStart = options.resetTrafficOnStart === true;
        if (this.resetTrafficOnStart) {
            for (const artifactPath of [
                this.trafficNdjsonPath,
                this.preTlsWireLogPath,
                this.neckoMozLogPath,
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
        }

        if (!this.resetTrafficOnStart) {
            this._resumeExistingChainIfPresent();
        }
        this._ensureDirectories();
        this._ensureStepRecord(this.attribution.actionStep, this.attribution.stepIndex);
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
            // The browser owns the current profile-native logs and may recreate them on launch.
            for (const artifact of Object.keys(INTEGRITY_ARTIFACTS)) {
                verifyArtifact(this.trafficDir, existingIndex.integrity, artifact, {
                    allowAppendedBytes: true,
                    trustedLocal
                });
            }
        }

        const maxSeq = validEvents.reduce((max, ev) => Math.max(max, Number(ev.seq) || 0), 0);
        const maxStepIndex = validEvents.reduce(
            (max, ev) => Math.max(max, Number(ev.attribution?.stepIndex ?? ev.stepIndex) || 0),
            0
        );

        this.chainHeadHash = head;
        this.seq = maxSeq || validEvents.length;
        this.chainedEventCount = validEvents.length;
        if (maxStepIndex > this.attribution.stepIndex) {
            this.attribution.stepIndex = maxStepIndex;
        }

        for (const [relativePath, entry] of Object.entries(getPayloadManifest(existingIndex?.integrity))) {
            verifyPayloadEntry(this.trafficDir, relativePath, entry, trustedLocal);
            this.payloadManifest[relativePath] = { ...entry };
        }

        for (const ev of validEvents) {
            if (ev.payloadFile != null && !Object.hasOwn(this.payloadManifest, ev.payloadFile)) {
                const buffer = readIntegrityPayload(this.trafficDir, ev.payloadFile, trustedLocal);
                const { sha256, byteLength } = hashPayload(buffer);
                const { postDataSha256, bodySha256, payloadSha256 } = ev;
                const requiredDigest = postDataSha256 ?? bodySha256 ?? payloadSha256;
                const requiredBytes = ev.postDataBytes ?? ev.bodyBytes ?? ev.payloadBytes;
                if (!ev.payloadTruncated && (
                    (requiredDigest != null && requiredDigest !== sha256) ||
                    (requiredBytes != null && requiredBytes !== byteLength)
                )) {
                    throw new Error(`Payload mismatch for event ${ev.seq} during traffic recovery`);
                }
                this.payloadManifest[ev.payloadFile] = {
                    sha256,
                    bytes: byteLength,
                    truncated: Boolean(ev.payloadTruncated),
                    seq: ev.seq ?? 0,
                    prefix: ev.type === 'egress' ? 'req' : ev.type === 'ingress' ? 'res' : 'ws'
                };
            }
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
        const txEgressEstimated = new Map();
        const txIngressCounted = new Map();
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
                    txEgressEstimated.set(ev.correlationId, estimatedEgressBytes);
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

                this._updateCookieLineageFromEgress({
                    headers: ev.headers || {},
                    headersArray: headersArr,
                    cookieObservations: ev.cookieObservations,
                    correlationId: ev.correlationId,
                    actionStep: stepName,
                    timestamp: ev.timestamp,
                    parsedUrl,
                    isReplay: true
                });

                const restoredSignatures = Array.isArray(ev.platformSignatures)
                    ? ev.platformSignatures
                    : extractPlatformSignatures({
                          url: ev.url || '',
                          searchParams: ev.searchParams || parsedUrl.searchParams,
                          headers: ev.headers || {},
                          bodyPreview: ev.bodyPreview ?? ev.postData ?? null
                      });
                for (const sig of restoredSignatures) {
                    if (!sig || typeof sig !== 'object') continue;
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
                        valueLength: sig.valueLength,
                        valueSha256: sig.valueSha256,
                        maskedPreview: sig.maskedPreview
                    });
                }

                if (ev.correlationId && ev.payloadFile) {
                    txReqPayloadByCorr.set(ev.correlationId, ev.payloadFile);
                }

                const egressBodyPreview = ev.bodyPreview ?? ev.postData ?? null;
                const egressRiskSignals = detectRiskSignals({
                    url: ev.url || '',
                    bodyPreview: egressBodyPreview,
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
                    txIngressCounted.set(ev.correlationId, estimatedIngressBytes);
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

                this._updateCookieLineageFromIngress({
                    headers: ev.headers || {},
                    headersArray: headersArr,
                    cookieObservations: ev.cookieObservations,
                    correlationId: ev.correlationId,
                    actionStep: effectiveStepName,
                    triggerAction: effectiveTrigger,
                    timestamp: ev.timestamp,
                    url: ev.url || '',
                    parsedUrl,
                    status
                });

                const effectivePayloadFile =
                    ev.payloadFile ||
                    (ev.correlationId ? txReqPayloadByCorr.get(ev.correlationId) || null : null);

                if (status === 401 || status === 403 || status === 429 || status >= 500) {
                    const severity =
                        status === 429 || status === 403 || status >= 500 ? 'high' : 'medium';
                    const typeLabel =
                        status === 429
                            ? 'http-429-rate-limit'
                            : status === 403
                              ? 'http-403-forbidden'
                              : status === 401
                                ? 'http-401-unauthorized'
                                : `http-${status}-server-error`;
                    this._recordAnomaly({
                        timestamp: ev.timestamp,
                        correlationId: ev.correlationId || null,
                        actionStep: effectiveStepName,
                        triggerAction: effectiveTrigger,
                        type: typeLabel,
                        severity,
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
                if (ev.sizes && typeof ev.sizes === 'object' && ev.correlationId) {
                    const actualReqBytes =
                        (Number(ev.sizes.requestHeadersSize) || 0) + (Number(ev.sizes.requestBodySize) || 0);
                    const actualResBytes =
                        (Number(ev.sizes.responseHeadersSize) || 0) + (Number(ev.sizes.responseBodySize) || 0);
                    const prevEgress = txEgressEstimated.get(ev.correlationId) || 0;
                    const prevIngress = txIngressCounted.get(ev.correlationId) || 0;
                    const txStep = txStepByCorr.get(ev.correlationId);
                    const stepBucket = this._ensureStepRecord(
                        txStep?.stepName || stepName,
                        txStep?.stepIndex ?? stepIndex
                    );
                    const triggerBucket = this._ensureTriggerActionRecord(
                        ev.triggerAction || txTriggerByCorr.get(ev.correlationId) || null
                    );
                    if (prevEgress > 0 && actualReqBytes > prevEgress) {
                        const delta = actualReqBytes - prevEgress;
                        txEgressEstimated.set(ev.correlationId, actualReqBytes);
                        this.totals.totalEgressBytes += delta;
                        stepBucket.egressBytes += delta;
                        domainBucket.egressBytes += delta;
                        if (triggerBucket) triggerBucket.egressBytes += delta;
                    }
                    if (prevIngress > 0 && actualResBytes > prevIngress) {
                        const delta = actualResBytes - prevIngress;
                        txIngressCounted.set(ev.correlationId, actualResBytes);
                        this.totals.totalIngressBytes += delta;
                        stepBucket.ingressBytes += delta;
                        domainBucket.ingressBytes += delta;
                        if (triggerBucket) triggerBucket.ingressBytes += delta;
                    }
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
                const isProxyOrTlsFailure =
                    /proxy|tunnel|ssl|tls|cert|ns_error_proxy|ns_error_net_timeout|ns_error_connection_refused|timed?\s*out/i.test(
                        failureText
                    );
                this._recordAnomaly({
                    timestamp: ev.timestamp,
                    correlationId: ev.correlationId || null,
                    actionStep: effectiveStepName,
                    triggerAction: effectiveTrigger,
                    type: isProxyOrTlsFailure
                        ? 'network-proxy-or-tls-failure'
                        : 'network-request-failed',
                    severity: isProxyOrTlsFailure ? 'high' : 'medium',
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
                this._recordAnomaly({
                    timestamp: ev.timestamp,
                    correlationId: ev.correlationId || null,
                    actionStep: stepName,
                    triggerAction: effectiveTrigger,
                    type: `security-block:${ev.blockType || 'security-probe'}`,
                    severity: ev.severity || 'critical',
                    method: ev.method || 'GET',
                    url: ev.url || ev.targetUrl || '',
                    status: null,
                    failureText: ev.reason || ev.failureText || null
                });
            } else if (ev.type === 'ws-egress' || ev.type === 'ws-ingress') {
                const parsedUrl = parseUrlComponents(ev.url || '');
                const bytes = Number(ev.payloadBytes) || 0;
                const stepBucket = this._ensureStepRecord(stepName, stepIndex);
                const domainBucket = this._ensureDomainRecord(parsedUrl.host);
                const triggerBucket = this._ensureTriggerActionRecord(ev.triggerAction);
                stepBucket.domainsSet.add(parsedUrl.host);

                if (ev.type === 'ws-egress') {
                    this.totals.wsFramesSent += 1;
                    this.totals.totalEgressBytes += bytes;
                    stepBucket.egressBytes += bytes;
                    domainBucket.egressBytes += bytes;
                    if (triggerBucket) {
                        triggerBucket.wsFramesSent += 1;
                        triggerBucket.egressBytes += bytes;
                        triggerBucket.domainsSet.add(parsedUrl.host);
                        if (ev.correlationId) triggerBucket.correlationIdsSet.add(ev.correlationId);
                    }
                } else {
                    this.totals.wsFramesReceived += 1;
                    this.totals.totalIngressBytes += bytes;
                    stepBucket.ingressBytes += bytes;
                    domainBucket.ingressBytes += bytes;
                    if (triggerBucket) {
                        triggerBucket.wsFramesReceived += 1;
                        triggerBucket.ingressBytes += bytes;
                        triggerBucket.domainsSet.add(parsedUrl.host);
                        if (ev.correlationId) triggerBucket.correlationIdsSet.add(ev.correlationId);
                    }
                }
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
                    type: 'websocket-error',
                    severity: 'medium',
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
                if (!anomaly || typeof anomaly !== 'object') continue;
                if (anomaly.correlationId && !validCorrIds.has(anomaly.correlationId)) {
                    continue;
                }
                this._recordAnomaly({
                    ...anomaly,
                    triggerAction: redactTriggerAction(anomaly.triggerAction)
                });
            }
        }

        if (truncateTo !== null) {
            truncateCaptureFile(this.trafficDir, 'traffic.ndjson', rawContent, truncateTo, { trustedLocal });
        } else {
            // An interrupted write may have stored the full event except its line delimiter.
            this.ledgerNeedsSeparator = Boolean(rawContent?.length && rawContent.at(-1) !== 0x0a);
        }
    }

    /** Ensure diagnostic storage and explicitly enabled private logging are ready. */
    _ensureDirectories() {
        ensurePrivateDirectory(this.trafficDir);
        ensurePrivateDirectory(this.payloadsDir);
        const privateNativeDir = path.join(this.trafficDir, '.private');
        for (const nativeLogPath of [this.sslKeyLogPath, this.neckoMozLogPath]) {
            if (!nativeLogPath) continue;
            const parent = path.dirname(nativeLogPath);
            if (parent === privateNativeDir) {
                ensurePrivateDirectory(parent);
            } else {
                fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
            }
            if (fs.existsSync(nativeLogPath)) restrictPrivateFile(nativeLogPath);
        }
        if (this.sslKeyLogPath && !fs.existsSync(this.sslKeyLogPath)) {
            appendPrivateFile(this.sslKeyLogPath, '# NSS SSL/TLS Secrets Log (Camoufox Pre-TLS Traffic Recorder)\n');
        }
        if (this.recordWireLog && !fs.existsSync(this.preTlsWireLogPath)) {
            appendPrivateFile(this.preTlsWireLogPath, '');
        }
    }

    /**
     * Return environment variables dictionary containing `SSLKEYLOGFILE` for Firefox/Camoufox NSS.
     *
     * @param {Record<string, string>} [baseEnv=process.env]
     * @returns {Record<string, string>}
     */
    getLaunchEnv(baseEnv = process.env) {
        this._ensureDirectories();
        const launchEnv = { ...baseEnv };
        if (this.sslKeyLogPath) {
            launchEnv.SSLKEYLOGFILE = this.sslKeyLogPath;
        } else {
            delete launchEnv.SSLKEYLOGFILE;
        }
        return launchEnv;
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
     * Extract `Set-Cookie` headers from an ingress response and update `this.cookieLineage`.
     *
     * @param {object} params
     */
    _updateCookieLineageFromIngress({
        headers = {},
        headersArray = [],
        cookieObservations = deriveCookieObservations({ headers, headersArray }, 'set-cookie'),
        correlationId = null,
        actionStep = 'init',
        triggerAction = null,
        timestamp = new Date().toISOString(),
        url = '',
        parsedUrl = null,
        status = null
    } = {}) {
        const fallbackDomain =
            parsedUrl?.hostname && parsedUrl.hostname !== 'unknown'
                ? parsedUrl.hostname
                : parsedUrl?.host && parsedUrl.host !== 'unknown'
                  ? parsedUrl.host
                  : null;
        const triggerActionId = triggerAction?.actionId || null;

        for (const parsed of cookieObservations) {
            let entry = this.cookieLineage.get(parsed.name);
            if (!entry) {
                entry = {
                    name: parsed.name,
                    isAntiBotToken: Boolean(parsed.isAntiBotToken),
                    domain: parsed.domain ?? fallbackDomain,
                    path: parsed.path ?? '/',
                    secure: Boolean(parsed.secure),
                    httpOnly: Boolean(parsed.httpOnly),
                    sameSite: parsed.sameSite ?? null,
                    firstSetAt: timestamp,
                    firstSetByCorrelationId: correlationId,
                    firstSetAtStep: actionStep,
                    firstSetByTrigger: triggerActionId,
                    firstSetUrl: url || null,
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
                this.cookieLineage.set(parsed.name, entry);
            } else {
                if (parsed.domain) entry.domain = parsed.domain;
                else if (!entry.domain && fallbackDomain) entry.domain = fallbackDomain;
                if (parsed.path) entry.path = parsed.path;
                entry.secure = Boolean(parsed.secure);
                entry.httpOnly = Boolean(parsed.httpOnly);
                if (parsed.sameSite) entry.sameSite = parsed.sameSite;
                if (!entry.firstSetAt) {
                    entry.firstSetAt = timestamp;
                    entry.firstSetByCorrelationId = correlationId;
                    entry.firstSetAtStep = actionStep;
                    entry.firstSetByTrigger = triggerActionId;
                    entry.firstSetUrl = url || null;
                }
            }

            const alreadyInHistory = entry.valueHistory.some(
                (h) =>
                    h.correlationId === correlationId &&
                    h.valueSha256 === parsed.valueSha256
            );
            if (!alreadyInHistory) {
                if (entry.lastValueSha256 !== parsed.valueSha256) {
                    entry.mutationsCount = (Number(entry.mutationsCount) || 0) + 1;
                }
                entry.lastSetAt = timestamp;
                entry.lastSetByCorrelationId = correlationId;
                entry.lastSetAtStep = actionStep;
                entry.lastValueSha256 = parsed.valueSha256;
                entry.lastMaskedValue = COOKIE_VALUE_MASK;
                entry.valueHistory.push({
                    correlationId,
                    actionStep,
                    triggerActionId,
                    timestamp,
                    status: status ?? null,
                    valueSha256: parsed.valueSha256,
                    maskedValue: COOKIE_VALUE_MASK,
                    isDeleted: Boolean(parsed.isDeleted)
                });
            }
        }
    }

    /**
     * Extract `Cookie` headers from an egress request and update `this.cookieLineage`.
     *
     * @param {object} params
     */
    _updateCookieLineageFromEgress({
        headers = {},
        headersArray = [],
        cookieObservations = deriveCookieObservations({ headers, headersArray }, 'cookie'),
        correlationId = null,
        actionStep = 'init',
        timestamp = new Date().toISOString(),
        parsedUrl = null,
        isReplay = false
    } = {}) {
        const fallbackDomain =
            parsedUrl?.hostname && parsedUrl.hostname !== 'unknown'
                ? parsedUrl.hostname
                : parsedUrl?.host && parsedUrl.host !== 'unknown'
                  ? parsedUrl.host
                  : null;

        for (const cookie of cookieObservations) {
            let entry = this.cookieLineage.get(cookie.name);
            if (!entry) {
                entry = {
                    name: cookie.name,
                    isAntiBotToken: Boolean(cookie.isAntiBotToken),
                    domain: fallbackDomain,
                    path: '/',
                    secure: parsedUrl?.protocol === 'https',
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
                    lastMaskedValue: COOKIE_VALUE_MASK,
                    mutationsCount: 0,
                    sentCount: 0,
                    lastSentAt: null,
                    lastSentByCorrelationId: null,
                    lastSentAtStep: null,
                    matchesLatestSetCookie: false,
                    valueHistory: [],
                    sentInCorrelationIds: new Set()
                };
                this.cookieLineage.set(cookie.name, entry);
            }

            if (isReplay && correlationId && entry.sentInCorrelationIds.has(correlationId)) {
                continue;
            }

            if (correlationId) {
                entry.sentInCorrelationIds.add(correlationId);
            }
            entry.sentCount = (Number(entry.sentCount) || 0) + 1;
            entry.lastSentAt = timestamp;
            entry.lastSentByCorrelationId = correlationId;
            entry.lastSentAtStep = actionStep;
            entry.matchesLatestSetCookie = Boolean(
                entry.lastValueSha256 && cookie.valueSha256 === entry.lastValueSha256
            );
            if (!entry.lastMaskedValue) {
                entry.lastMaskedValue = COOKIE_VALUE_MASK;
            }
        }
    }

    /**
     * Return a shallow immutable snapshot of the current attribution envelope.
     */
    getAttributionSnapshot() {
        return {
            traceId: this.attribution.traceId,
            profileId: this.attribution.profileId,
            accountId: this.attribution.accountId,
            accountEmail: this.attribution.accountEmail,
            os: this.attribution.os,
            proxyServer: this.attribution.proxyServer,
            actionStep: this.attribution.actionStep,
            stepIndex: this.attribution.stepIndex
        };
    }

    /**
     * Update attribution metadata (`accountId`, `accountEmail`, `proxyServer`, `os`, etc.) dynamically.
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
        if (partial.accountEmail !== undefined) {
            this.attribution.accountEmail = partial.accountEmail ?? null;
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
        if (this.stopped) return this.getAttributionSnapshot();
        const cleanedStep = String(stepName || 'unnamed-step').trim() || 'unnamed-step';
        const previousStep = this.attribution.actionStep;
        const previousStepIndex = this.attribution.stepIndex;

        this.attribution.stepIndex += 1;
        this.attribution.actionStep = cleanedStep;

        this._ensureStepRecord(cleanedStep, this.attribution.stepIndex);

        const seq = this._nextSeq();
        this._appendNdjsonEvent({
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
            stepIndex: this.attribution.stepIndex,
            metadata: redactDiagnosticMetadata(metadata),
            attribution: this.getAttributionSnapshot()
        });

        return this.getAttributionSnapshot();
    }

    /**
     * Record a causal UI driver action (`page.goto`, `page.click`, `page.fill`, `locator.press`, etc.)
     * so all subsequent pre-TLS network requests and responses are attributed to the exact UI trigger.
     *
     * @param {string} actionType - e.g. 'page.click', 'page.goto', 'page.fill'
     * @param {string|null} [target=null] - CSS selector, URL, or element descriptor
     * @param {object} [metadata={}] - Additional causal action metadata
     * @returns {object|null} Recorded trigger action snapshot
     */
    recordTriggerAction(actionType, target = null, metadata = {}) {
        if (this.stopped) return null;
        this.triggerSeq += 1;
        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        this.lastTriggerAction = redactTriggerAction({
            actionId: `act-${this.traceIdShort}-${this.triggerSeq}`,
            actionType: String(actionType || 'unknown'),
            target: target ? String(target) : null,
            timestamp,
            epochMs,
            actionStep: this.attribution.actionStep,
            stepIndex: this.attribution.stepIndex,
            metadata
        });

        this._ensureTriggerActionRecord(this.lastTriggerAction);

        const seq = this._nextSeq();
        this._appendNdjsonEvent({
            type: 'trigger-action',
            eventType: 'trigger-action',
            direction: 'internal',
            stage: 'ui-driver-action',
            timestamp,
            epochMs,
            seq,
            actionId: this.lastTriggerAction.actionId,
            actionType: this.lastTriggerAction.actionType,
            target: this.lastTriggerAction.target,
            actionStep: this.lastTriggerAction.actionStep,
            stepIndex: this.lastTriggerAction.stepIndex,
            metadata: this.lastTriggerAction.metadata,
            triggerAction: {
                ...this.lastTriggerAction,
                elapsedSinceActionMs: 0
            },
            attribution: this.getAttributionSnapshot()
        });

        return { ...this.lastTriggerAction };
    }

    /**
     * Return a snapshot of the currently active causal UI trigger action with `elapsedSinceActionMs`.
     *
     * @param {number} [nowEpochMs=Date.now()]
     * @returns {object|null}
     */
    getActiveTriggerSnapshot(nowEpochMs = Date.now()) {
        if (!this.lastTriggerAction) {
            return null;
        }
        return {
            ...this.lastTriggerAction,
            elapsedSinceActionMs: Math.max(0, nowEpochMs - this.lastTriggerAction.epochMs)
        };
    }

    /**
     * Allocate the next monotonic event sequence integer.
     *
     * @returns {number}
     */
    _nextSeq() {
        this.seq += 1;
        return this.seq;
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

    /**
     * Format a concise human-readable summary of a triggerAction snapshot for wire log headers.
     *
     * @param {object|null} triggerSnapshot
     * @returns {string}
     */
    _formatTriggerSummary(triggerSnapshot) {
        if (!triggerSnapshot || !triggerSnapshot.actionId) {
            return 'none';
        }
        const targetPart = triggerSnapshot.target ? `(${triggerSnapshot.target})` : '';
        return `${triggerSnapshot.actionType}${targetPart}#${triggerSnapshot.actionId}`;
    }

    /**
     * Append a single event line to `traffic.ndjson` with a deterministic
     * cryptographic SHA-256 tamper-evident chain link (`prevEventHash` -> `eventHash`).
     *
     * @param {object} record
     */
    _appendNdjsonEvent(record) {
        if (this.ledgerWriteError || !record || typeof record !== 'object') {
            return;
        }

        record.prevEventHash = this.chainHeadHash;
        record.eventHash = computeEventHash(record);
        const separator = this.ledgerNeedsSeparator ? '\n' : '';
        try {
            appendPrivateFile(this.trafficNdjsonPath, `${separator}${JSON.stringify(record)}\n`);
        } catch (error) {
            // The append may have persisted a partial event, so further appends must stop.
            this.ledgerWriteError = error;
            return;
        }
        this.ledgerNeedsSeparator = false;
        this.chainHeadHash = record.eventHash;
        this.chainedEventCount += 1;
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
        try {
            appendPrivateFile(this.preTlsWireLogPath, entry);
        } catch (error) {
            this.wireWriteError = error;
        }
    }

    /**
     * Persist a request/response/websocket payload buffer into `payloads/`.
     * Respects `this.capturePayloads` (`this.recordBodies`) and truncates at `this.maxBodyBytes`.
     *
     * @param {'req'|'res'|'ws'} prefix
     * @param {number} seq
     * @param {Buffer} buffer
     * @param {string} shortSha256
     * @param {string|null} mimeType
     * @returns {{ payloadFile: string|null, payloadPath: string|null, extension: string|null, payloadTruncated: boolean }}
     */
    _writePayloadFile(prefix, seq, buffer, shortSha256, mimeType) {
        if (!this.capturePayloads || !buffer || buffer.byteLength === 0) {
            return { payloadFile: null, payloadPath: null, extension: null, payloadTruncated: false };
        }
        if (buffer.byteLength < this.inlinePayloadThresholdBytes) {
            return { payloadFile: null, payloadPath: null, extension: null, payloadTruncated: false };
        }

        const payloadTruncated = this.maxBodyBytes > 0 && buffer.byteLength > this.maxBodyBytes;
        const toWriteBuffer = payloadTruncated ? buffer.subarray(0, this.maxBodyBytes) : buffer;

        const ext = inferPayloadExtension(mimeType, toWriteBuffer);
        const fileName = `${prefix}-${seq}-${shortSha256}.${ext}`;
        const relativePath = path.posix.join('payloads', fileName);
        const fullPath = path.join(this.payloadsDir, fileName);

        try {
            writePrivateFile(fullPath, toWriteBuffer);
            const writtenSha256 = crypto.createHash('sha256').update(toWriteBuffer).digest('hex');
            this.payloadManifest[relativePath] = {
                sha256: writtenSha256,
                bytes: toWriteBuffer.byteLength,
                truncated: Boolean(payloadTruncated),
                seq,
                prefix
            };
            return {
                payloadFile: relativePath,
                payloadPath: fullPath,
                extension: ext,
                payloadTruncated
            };
        } catch {
            return { payloadFile: null, payloadPath: null, extension: ext, payloadTruncated };
        }
    }

    /**
     * Register the capture before its handler calls methods on the event target.
     */
    _trackTask(handler, target) {
        if (this.stopped) return;
        let capture;
        const wrapped = new Promise((resolve) => {
            capture = resolve;
        })
            .catch(() => {})
            .finally(() => {
                this.pendingTasks.delete(wrapped);
            });
        this.pendingTasks.add(wrapped);
        capture((async () => handler.call(this, target))());
        return wrapped;
    }

    /**
     * Assign or retrieve a deterministic `correlationId` (`corr-<traceId_short>-<seq>`)
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
        const correlationId = `corr-${this.traceIdShort}-${seq}`;
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
        const dedupeKey = [
            anomaly.correlationId || '',
            anomaly.type || '',
            anomaly.status ?? '',
            failureText || '',
            url || ''
        ].join('|');

        if (this.recordedAnomalyKeys.has(dedupeKey)) {
            return;
        }
        this.recordedAnomalyKeys.add(dedupeKey);

        const stepName = anomaly.actionStep || this.attribution.actionStep;
        const stepBucket = this._ensureStepRecord(stepName, this.attribution.stepIndex);
        stepBucket.anomalyCount += 1;

        const effectiveTrigger =
            anomaly.triggerAction !== undefined
                ? anomaly.triggerAction
                : this.getActiveTriggerSnapshot();
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
        if (this.stopped || !blockEvent || typeof blockEvent !== 'object') {
            return null;
        }
        const seq = this._nextSeq();
        const correlationId = blockEvent.correlationId || `sec-${this.traceIdShort}-${seq}`;
        const rawUrl = String(blockEvent.targetUrl || blockEvent.url || '');
        const redactedUrl = redactUrlSecrets(rawUrl);
        const parsedUrl = parseUrlComponents(redactedUrl);
        const blockType = String(blockEvent.type || 'security-probe');
        const method = String(blockEvent.method || 'GET');
        const rawReason = String(blockEvent.reason || `Blocked ${blockType} to ${redactedUrl}`);
        const reason = redactDiagnosticText(rawUrl ? rawReason.replaceAll(rawUrl, redactedUrl) : rawReason);
        const severity = String(blockEvent.severity || 'critical');
        const triggerSnapshot = this.getActiveTriggerSnapshot();
        const attributionSnapshot = this.getAttributionSnapshot();

        this.totals.failedRequests += 1;
        const stepBucket = this._ensureStepRecord(
            attributionSnapshot.actionStep,
            attributionSnapshot.stepIndex
        );
        stepBucket.failedRequests += 1;
        stepBucket.domainsSet.add(parsedUrl.host);

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        domainBucket.failedRequests += 1;

        const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
        if (triggerBucket) {
            triggerBucket.failedRequests += 1;
            triggerBucket.domainsSet.add(parsedUrl.host);
            triggerBucket.correlationIdsSet.add(correlationId);
        }

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
            triggerAction: triggerSnapshot,
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

        this._appendNdjsonEvent(record);
        this._appendWireLogBlock([
            '================================================================================',
            `!!! SECURITY-BLOCK [ZINIAO ACTIVE GUARD] [seq=${seq}] [corr=${correlationId}] ${record.timestamp}`,
            `[ATTRIBUTION] profile=${this.attribution.profileId} step=${this.attribution.actionStep}(#${this.attribution.stepIndex})`,
            `[BLOCK-DETAIL] type=${blockType} severity=${severity} target="${redactedUrl}" reason="${reason}"`,
            ''
        ].join('\n'));

        this._recordAnomaly({
            timestamp: record.timestamp,
            correlationId,
            actionStep: this.attribution.actionStep,
            triggerAction: triggerSnapshot,
            type: `security-block:${blockType}`,
            severity,
            method,
            url: redactedUrl,
            failureText: reason
        });

        return record;
    }

    /**
     * Attach pre-TLS egress & post-TLS ingress listeners to a Playwright `BrowserContext`.
     * Also attaches WebSocket listeners to all existing and future pages in the context.
     *
     * @param {object} context - Playwright BrowserContext
     * @returns {this}
     */
    attachContext(context) {
        if (this.stopped || !context || typeof context.on !== 'function' || this.attachedContexts.has(context)) {
            return this;
        }
        this.attachedContexts.add(context);

        const onRequest = (request) => this._trackTask(this._handleRequest, request);
        const onResponse = (response) => this._trackTask(this._handleResponse, response);
        const onRequestFinished = (request) => this._trackTask(this._handleRequestFinished, request);
        const onRequestFailed = (request) => this._trackTask(this._handleRequestFailed, request);
        const onPage = (page) => this._attachPageWebSocketsOnly(page);

        context.on('request', onRequest);
        context.on('response', onResponse);
        context.on('requestfinished', onRequestFinished);
        context.on('requestfailed', onRequestFailed);
        context.on('page', onPage);

        this.listenerDisposers.push(() => {
            if (typeof context.off === 'function') {
                context.off('request', onRequest);
                context.off('response', onResponse);
                context.off('requestfinished', onRequestFinished);
                context.off('requestfailed', onRequestFailed);
                context.off('page', onPage);
            } else if (typeof context.removeListener === 'function') {
                context.removeListener('request', onRequest);
                context.removeListener('response', onResponse);
                context.removeListener('requestfinished', onRequestFinished);
                context.removeListener('requestfailed', onRequestFailed);
                context.removeListener('page', onPage);
            }
        });

        try {
            if (typeof context.pages === 'function') {
                const existingPages = context.pages() || [];
                for (const page of existingPages) {
                    this._attachPageWebSocketsOnly(page);
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
        if (this.stopped || !page || typeof page.on !== 'function') {
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
        this.attachedPagesHttp.add(page);

        const onRequest = (request) => this._trackTask(this._handleRequest, request);
        const onResponse = (response) => this._trackTask(this._handleResponse, response);
        const onRequestFinished = (request) => this._trackTask(this._handleRequestFinished, request);
        const onRequestFailed = (request) => this._trackTask(this._handleRequestFailed, request);

        page.on('request', onRequest);
        page.on('response', onResponse);
        page.on('requestfinished', onRequestFinished);
        page.on('requestfailed', onRequestFailed);

        this.listenerDisposers.push(() => {
            if (typeof page.off === 'function') {
                page.off('request', onRequest);
                page.off('response', onResponse);
                page.off('requestfinished', onRequestFinished);
                page.off('requestfailed', onRequestFailed);
            } else if (typeof page.removeListener === 'function') {
                page.removeListener('request', onRequest);
                page.removeListener('response', onResponse);
                page.removeListener('requestfinished', onRequestFinished);
                page.removeListener('requestfailed', onRequestFailed);
            }
        });

        return this;
    }

    /**
     * Attach `page.on('websocket')` listener without duplicating HTTP listeners.
     *
     * @param {object} page
     */
    _attachPageWebSocketsOnly(page) {
        if (this.stopped || !page || typeof page.on !== 'function' || this.attachedPagesWs.has(page)) {
            return;
        }
        this.attachedPagesWs.add(page);

        const onWebSocket = (ws) => this._handleWebSocket(ws, page);
        page.on('websocket', onWebSocket);

        this.listenerDisposers.push(() => {
            if (typeof page.off === 'function') {
                page.off('websocket', onWebSocket);
            } else if (typeof page.removeListener === 'function') {
                page.removeListener('websocket', onWebSocket);
            }
        });
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

    /**
     * Reconstruct the full egress + ingress raw HTTP wire dump string for a given `correlationId`
     * from recorded transactions or persisted `traffic.ndjson` events.
     *
     * @param {string} correlationId
     * @returns {string}
     */
    formatTransactionWireDump(correlationId) {
        if (!correlationId) {
            return '';
        }

        const tx = this.transactions.get(correlationId);
        if (tx && (tx.egressWireBlock || tx.ingressWireBlock)) {
            const parts = [];
            if (tx.egressWireBlock) parts.push(tx.egressWireBlock);
            if (tx.ingressWireBlock) parts.push(tx.ingressWireBlock);
            return parts.join('\n');
        }

        const wsBlocks = this.wsWireBlocks.get(correlationId);
        if (wsBlocks && wsBlocks.length > 0) {
            return wsBlocks.join('\n');
        }

        // Fallback: reconstruct from traffic.ndjson if events were flushed to disk
        if (fs.existsSync(this.trafficNdjsonPath)) {
            try {
                const lines = fs.readFileSync(this.trafficNdjsonPath, 'utf8').split('\n');
                const parts = [];
                for (const line of lines) {
                    if (!line.trim()) continue;
                    const evt = JSON.parse(line);
                    if (evt.correlationId !== correlationId) continue;
                    if (evt.type === 'egress') {
                        const parsedUrl = parseUrlComponents(evt.url || '');
                        const triggerSummary = this._formatTriggerSummary(evt.triggerAction);
                        parts.push(
                            this._formatEgressWireBlock({
                                timestamp: evt.timestamp,
                                correlationId: evt.correlationId,
                                actionStep: evt.attribution?.actionStep || 'init',
                                triggerSummary,
                                method: evt.method || 'GET',
                                parsedUrl,
                                headersArray: evt.headersArray || [],
                                bodyPreview: evt.bodyPreview || ''
                            })
                        );
                    } else if (evt.type === 'ingress') {
                        parts.push(
                            this._formatIngressWireBlock({
                                timestamp: evt.timestamp,
                                correlationId: evt.correlationId,
                                effectiveStepName: evt.attribution?.actionStep || 'init',
                                serverAddr: evt.serverAddr || null,
                                securityDetails: evt.securityDetails || null,
                                status: evt.status ?? 0,
                                statusText: evt.statusText || '',
                                headersArray: evt.headersArray || [],
                                bodyPreview: evt.bodyPreview || ''
                            })
                        );
                    } else if (evt.type === 'security-block') {
                        parts.push(
                            [
                                '================================================================================',
                                `!!! SECURITY-BLOCK [ZINIAO ACTIVE GUARD] [seq=${evt.seq}] [corr=${evt.correlationId}] ${evt.timestamp}`,
                                `[ATTRIBUTION] profile=${evt.attribution?.profileId || this.attribution.profileId} step=${evt.attribution?.actionStep || 'init'}(#${evt.attribution?.stepIndex ?? 0})`,
                                `[BLOCK-DETAIL] type=${evt.blockType || 'security-probe'} severity=${evt.severity || 'critical'} target="${evt.url || ''}" reason="${evt.reason || evt.failureText || ''}"`,
                                ''
                            ].join('\n')
                        );
                    }
                }
                return parts.join('\n');
            } catch {
                return '';
            }
        }

        return '';
    }

    /**
     * Handle pre-TLS egress `request` event (`http-on-modify-request` in Firefox Necko).
     *
     * @param {object} request - Playwright Request
     */
    async _handleRequest(request) {
        if (!request) return;

        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const { correlationId, seq, redirectedFromCorrelationId } =
            this._resolveRequestCorrelation(request);
        const attributionSnapshot = this.getAttributionSnapshot();
        const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs);

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
            if (typeof request.frame === 'function') {
                const frame = request.frame();
                if (frame && typeof frame.url === 'function') {
                    const rawFrameUrl = frame.url() || null;
                    frameUrl = rawFrameUrl ? redactUrlSecrets(rawFrameUrl) : null;
                }
            }
        } catch {}

        url = redactUrlSecrets(url);
        const parsedUrl = parseUrlComponents(url);
        const { headers, headersArray, cookieObservations } = await extractHeadersWithOrder(request, 'cookie');
        const contentType = headers['content-type'] || headers['Content-Type'] || null;

        // Playwright delivers the upload with the request. Read it only in body capture mode.
        let postDataBuffer = null;
        if (this.capturePayloads) {
            try {
                if (typeof request.postDataBuffer === 'function') {
                    postDataBuffer = request.postDataBuffer();
                }
            } catch {}
            if (!postDataBuffer) {
                try {
                    const postData = request.postData?.();
                    if (typeof postData === 'string' && postData.length > 0) {
                        postDataBuffer = Buffer.from(postData, 'utf8');
                    }
                } catch {}
            }
        }

        let postDataSha256 = null;
        let postDataBytes = 0;
        let bodyPreview = null;
        let bodyPreviewTruncated = false;
        let payloadFile = null;
        let payloadTruncated = false;

        if (postDataBuffer && postDataBuffer.byteLength > 0) {
            const hashed = hashPayload(postDataBuffer);
            postDataSha256 = hashed.sha256;
            postDataBytes = hashed.byteLength;

            const previewObj = buildBodyPreview(
                hashed.buffer,
                contentType || 'application/octet-stream',
                this.maxInlinePreviewBytes
            );
            bodyPreview = previewObj.preview;
            bodyPreviewTruncated = previewObj.truncated;

            const saved = this._writePayloadFile(
                'req',
                seq,
                hashed.buffer,
                hashed.shortSha256,
                contentType
            );
            payloadFile = saved.payloadFile;
            payloadTruncated = Boolean(saved.payloadTruncated);
        }

        // Estimate header byte size + body bytes for pre-TLS egress accounting
        const headerByteEstimate = headersArray.reduce(
            (acc, h) => acc + Buffer.byteLength(`${h.name}: ${h.value}\r\n`, 'utf8'),
            Buffer.byteLength(`${method} ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1\r\n\r\n`, 'utf8')
        );
        const estimatedEgressBytes = headerByteEstimate + postDataBytes;

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
        const egressWireBlock = this._formatEgressWireBlock({
            timestamp,
            correlationId,
            actionStep: attributionSnapshot.actionStep,
            triggerSummary,
            method,
            parsedUrl,
            headersArray,
            bodyPreview
        });

        // Store transaction metadata for response / finish / failure linking
        this.transactions.set(correlationId, {
            correlationId,
            seq,
            method,
            url,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            resourceType,
            actionStep: attributionSnapshot.actionStep,
            stepIndex: attributionSnapshot.stepIndex,
            triggerAction: triggerSnapshot,
            startedAtEpochMs: epochMs,
            estimatedEgressBytes,
            countedIngressBytes: 0,
            requestPayloadFile: payloadFile,
            responsePayloadFile: null,
            status: null,
            egressWireBlock,
            ingressWireBlock: null
        });

        const platformSignatures = extractPlatformSignatures({
            url,
            searchParams: parsedUrl.searchParams,
            headers,
            bodyPreview
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
            ...(!this.capturePayloads ? { bodyOmittedReason: 'body-recording-disabled' } : {}),
            headers,
            headersArray,
            cookieObservations,
            postData: bodyPreview,
            bodyPreview,
            bodyPreviewTruncated,
            postDataSha256,
            postDataBytes,
            payloadFile,
            payloadTruncated,
            platformSignatures,
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        };

        this._appendNdjsonEvent(egressEvent);
        this._appendWireLogBlock(egressWireBlock);

        // Update Cookie & Anti-Bot Token causal lineage on egress
        this._updateCookieLineageFromEgress({
            cookieObservations,
            correlationId,
            actionStep: attributionSnapshot.actionStep,
            timestamp,
            parsedUrl
        });

        // Inspect pre-TLS request URL for risk-control / challenge endpoints
        const riskSignals = detectRiskSignals({ url, bodyPreview, headers });
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
    async _handleResponse(response) {
        if (!response) return;

        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const seq = this._nextSeq();
        const attributionSnapshot = this.getAttributionSnapshot();

        let request = null;
        try {
            if (typeof response.request === 'function') {
                request = response.request();
            }
        } catch {}

        const { correlationId, redirectedFromCorrelationId } = request
            ? this._resolveRequestCorrelation(request)
            : { correlationId: `corr-${this.traceIdShort}-${seq}`, redirectedFromCorrelationId: null };

        const tx = this.transactions.get(correlationId);
        const triggerSnapshot = tx?.triggerAction || this.getActiveTriggerSnapshot(epochMs);

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
        const { headers, headersArray, cookieObservations } = await extractHeadersWithOrder(response, 'set-cookie');

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

        // Update totals, step counters, domain counters, and triggerAction counters
        const effectiveStepName = tx?.actionStep || attributionSnapshot.actionStep;
        const effectiveStepIndex = tx?.stepIndex ?? attributionSnapshot.stepIndex;

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

        const ingressWireBlock = this._formatIngressWireBlock({
            timestamp,
            correlationId,
            effectiveStepName,
            serverAddr,
            securityDetails,
            status,
            statusText,
            headersArray,
            bodyPreview: null
        });

        if (tx) {
            tx.status = status;
            tx.responsePayloadFile = null;
            tx.countedIngressBytes = estimatedIngressBytes;
            tx.ingressWireBlock = ingressWireBlock;
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
                actionStep: effectiveStepName,
                stepIndex: effectiveStepIndex,
                triggerAction: triggerSnapshot,
                startedAtEpochMs: epochMs,
                estimatedEgressBytes: 0,
                countedIngressBytes: estimatedIngressBytes,
                requestPayloadFile: null,
                responsePayloadFile: null,
                status,
                egressWireBlock: null,
                ingressWireBlock
            });
        }

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

        this._appendNdjsonEvent(ingressEvent);
        this._appendWireLogBlock(ingressWireBlock);

        // Update Cookie & Anti-Bot Token causal lineage on ingress (Set-Cookie)
        this._updateCookieLineageFromIngress({
            cookieObservations,
            correlationId,
            actionStep: effectiveStepName,
            triggerAction: triggerSnapshot,
            timestamp,
            url,
            parsedUrl,
            status
        });

        // Automatic HTTP Status & Risk Signal Anomaly Attribution
        if (status === 401 || status === 403 || status === 429 || status >= 500) {
            const severity = status === 429 || status === 403
                ? 'high'
                : status >= 500
                    ? 'high'
                    : 'medium';
            const typeLabel = status === 429
                ? 'http-429-rate-limit'
                : status === 403
                    ? 'http-403-forbidden'
                    : status === 401
                        ? 'http-401-unauthorized'
                        : `http-${status}-server-error`;

            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: effectiveStepName,
                triggerAction: triggerSnapshot,
                type: typeLabel,
                severity,
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
    async _handleRequestFinished(request) {
        if (!request) return;

        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const seq = this._nextSeq();
        const { correlationId } = this._resolveRequestCorrelation(request);
        const tx = this.transactions.get(correlationId);
        const attributionSnapshot = this.getAttributionSnapshot();
        const triggerSnapshot = tx?.triggerAction || this.getActiveTriggerSnapshot(epochMs);

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

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        if (typeof durationMs === 'number' && Number.isFinite(durationMs)) {
            domainBucket.totalDurationMs += durationMs;
            domainBucket.completedWithDurationCount += 1;
        }

        // Reconcile wire byte sizes if Playwright's `request.sizes()` reported larger actual totals
        if (sizes && typeof sizes === 'object') {
            const actualReqBytes =
                (Number(sizes.requestHeadersSize) || 0) + (Number(sizes.requestBodySize) || 0);
            const actualResBytes =
                (Number(sizes.responseHeadersSize) || 0) + (Number(sizes.responseBodySize) || 0);

            const effectiveStepName = tx?.actionStep || attributionSnapshot.actionStep;
            const effectiveStepIndex = tx?.stepIndex ?? attributionSnapshot.stepIndex;
            const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
            const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);

            if (tx && actualReqBytes > tx.estimatedEgressBytes) {
                const deltaEgress = actualReqBytes - tx.estimatedEgressBytes;
                tx.estimatedEgressBytes = actualReqBytes;
                this.totals.totalEgressBytes += deltaEgress;
                stepBucket.egressBytes += deltaEgress;
                domainBucket.egressBytes += deltaEgress;
                if (triggerBucket) {
                    triggerBucket.egressBytes += deltaEgress;
                }
            }
            if (tx && actualResBytes > tx.countedIngressBytes) {
                const deltaIngress = actualResBytes - tx.countedIngressBytes;
                tx.countedIngressBytes = actualResBytes;
                this.totals.totalIngressBytes += deltaIngress;
                stepBucket.ingressBytes += deltaIngress;
                domainBucket.ingressBytes += deltaIngress;
                if (triggerBucket) {
                    triggerBucket.ingressBytes += deltaIngress;
                }
            }
        }

        this._appendNdjsonEvent({
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
        });
    }

    /**
     * Handle `requestfailed` event (e.g. `NS_ERROR_*`, proxy error, reset, abort, timeout).
     *
     * @param {object} request - Playwright Request
     */
    async _handleRequestFailed(request) {
        if (!request) return;

        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const seq = this._nextSeq();
        const { correlationId } = this._resolveRequestCorrelation(request);
        const tx = this.transactions.get(correlationId);
        const attributionSnapshot = this.getAttributionSnapshot();
        const triggerSnapshot = tx?.triggerAction || this.getActiveTriggerSnapshot(epochMs);

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

        this._appendNdjsonEvent({
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
        });

        const isProxyOrTlsFailure =
            /proxy|tunnel|ssl|tls|cert|ns_error_proxy|ns_error_net_timeout|ns_error_connection_refused|timed?\s*out/i.test(
                failureText
            );

        this._recordAnomaly({
            timestamp,
            correlationId,
            actionStep: effectiveStepName,
            triggerAction: triggerSnapshot,
            type: isProxyOrTlsFailure ? 'network-proxy-or-tls-failure' : 'network-request-failed',
            severity: isProxyOrTlsFailure ? 'high' : 'medium',
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
        if (this.stopped || !ws || typeof ws.on !== 'function' || this.attachedWebSockets.has(ws)) {
            return;
        }
        this.attachedWebSockets.add(ws);

        this.wsSeq += 1;
        const wsCorrelationId = `ws-${this.traceIdShort}-${this.wsSeq}`;
        this.wsWireBlocks.set(wsCorrelationId, []);
        let wsUrl = '';
        try {
            if (typeof ws.url === 'function') {
                wsUrl = ws.url() || '';
            }
        } catch {}

        wsUrl = redactUrlSecrets(wsUrl);
        const parsedUrl = parseUrlComponents(wsUrl);
        const openEpochMs = Date.now();

        this._appendNdjsonEvent({
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
            triggerAction: this.getActiveTriggerSnapshot(openEpochMs),
            attribution: this.getAttributionSnapshot()
        });

        const recordWsFrame = (direction, stage, frameData) => {
            if (this.stopped || !this.webSocketDisposers.has(dispose)) return;
            const timestamp = new Date().toISOString();
            const epochMs = Date.now();
            const seq = this._nextSeq();
            const attributionSnapshot = this.getAttributionSnapshot();
            const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs);

            let hashed = null;
            let preview = null;
            if (this.capturePayloads) {
                const rawPayload = frameData && typeof frameData === 'object' && 'payload' in frameData
                    ? frameData.payload
                    : frameData;
                hashed = hashPayload(rawPayload);
                preview = buildBodyPreview(hashed.buffer, 'text/plain', this.maxInlinePreviewBytes);
            }
            const payloadBytes = hashed?.byteLength ?? 0;

            let payloadFile = null;
            let payloadTruncated = false;
            if (payloadBytes > this.maxInlinePreviewBytes) {
                const saved = this._writePayloadFile(
                    'ws',
                    seq,
                    hashed.buffer,
                    hashed.shortSha256,
                    'application/octet-stream'
                );
                payloadFile = saved.payloadFile;
                payloadTruncated = Boolean(saved.payloadTruncated);
            }

            const stepBucket = this._ensureStepRecord(
                attributionSnapshot.actionStep,
                attributionSnapshot.stepIndex
            );
            const domainBucket = this._ensureDomainRecord(parsedUrl.host);
            const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
            stepBucket.domainsSet.add(parsedUrl.host);

            if (direction === 'ws-egress') {
                this.totals.wsFramesSent += 1;
                this.totals.totalEgressBytes += payloadBytes;
                stepBucket.egressBytes += payloadBytes;
                domainBucket.egressBytes += payloadBytes;
                if (triggerBucket) {
                    triggerBucket.wsFramesSent += 1;
                    triggerBucket.egressBytes += payloadBytes;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    triggerBucket.correlationIdsSet.add(wsCorrelationId);
                }
            } else {
                this.totals.wsFramesReceived += 1;
                this.totals.totalIngressBytes += payloadBytes;
                stepBucket.ingressBytes += payloadBytes;
                domainBucket.ingressBytes += payloadBytes;
                if (triggerBucket) {
                    triggerBucket.wsFramesReceived += 1;
                    triggerBucket.ingressBytes += payloadBytes;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    triggerBucket.correlationIdsSet.add(wsCorrelationId);
                }
            }

            const triggerSummary = this._formatTriggerSummary(triggerSnapshot);
            const wsWireBlock =
                direction === 'ws-egress'
                    ? [
                          '================================================================================',
                          `>>> WS-EGRESS [PRE-TLS] [${timestamp}] [corr=${wsCorrelationId}] [step=${attributionSnapshot.actionStep}] [trigger=${triggerSummary}] [url=${wsUrl}] [bytes=${payloadBytes}]`,
                          preview?.preview || '',
                          '================================================================================'
                      ].join('\n')
                    : [
                          '--------------------------------------------------------------------------------',
                          `<<< WS-INGRESS [POST-TLS] [${timestamp}] [corr=${wsCorrelationId}] [step=${attributionSnapshot.actionStep}] [trigger=${triggerSummary}] [url=${wsUrl}] [bytes=${payloadBytes}]`,
                          preview?.preview || '',
                          '--------------------------------------------------------------------------------'
                      ].join('\n');

            const storedWsBlocks = this.wsWireBlocks.get(wsCorrelationId);
            if (storedWsBlocks) {
                storedWsBlocks.push(wsWireBlock);
            }

            this._appendNdjsonEvent({
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
                ...(!this.capturePayloads ? { bodyOmittedReason: 'body-recording-disabled' } : {}),
                payloadSha256: hashed?.sha256 ?? null,
                payloadBytes,
                bodyPreview: preview?.preview ?? null,
                bodyPreviewTruncated: preview?.truncated ?? false,
                payloadFile,
                payloadTruncated,
                triggerAction: triggerSnapshot,
                attribution: attributionSnapshot
            });
            this._appendWireLogBlock(wsWireBlock);
        };

        const onFrameSent = (frame) =>
            recordWsFrame('ws-egress', 'pre-tls-websocket-frame', frame);
        const onFrameReceived = (frame) =>
            recordWsFrame('ws-ingress', 'post-tls-websocket-frame', frame);

        const onSocketError = (errorMsg) => {
            if (this.stopped || !this.webSocketDisposers.has(dispose)) return;
            const timestamp = new Date().toISOString();
            const epochMs = Date.now();
            const seq = this._nextSeq();
            const attributionSnapshot = this.getAttributionSnapshot();
            const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs);
            const failureText = redactDiagnosticText(errorMsg || 'WEBSOCKET_ERROR');

            this._appendNdjsonEvent({
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
                triggerAction: triggerSnapshot,
                attribution: attributionSnapshot
            });

            this._recordAnomaly({
                timestamp,
                correlationId: wsCorrelationId,
                actionStep: attributionSnapshot.actionStep,
                triggerAction: triggerSnapshot,
                type: 'websocket-error',
                severity: 'medium',
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
            if (this.stopped) return;
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
                triggerAction: this.getActiveTriggerSnapshot(closeEpochMs),
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

    /**
     * Build the structured multi-dimensional attribution and root-cause summary report.
     *
     * @returns {object}
     */
    buildAttributionSummary() {
        const endedAtIso = this.endedAt || new Date().toISOString();
        const endedAtMs = this.endedAt ? Date.parse(this.endedAt) : Date.now();
        const totalDurationMs = Math.max(0, endedAtMs - this.startedAtEpochMs);

        const byActionStepObj = {};
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

        const byDomainObj = {};
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

        const byTriggerActionObj = {};
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

        const nativeArtifacts = {};
        const readLog = (type, logPath, describe) => {
            const fileName = INTEGRITY_ARTIFACTS[type];
            if (
                this.profileNativeDir && logPath === path.join(this.profileNativeDir, fileName) &&
                !nativeArtifactName(this.trafficDir, logPath, fileName)
            ) {
                const raw = readCaptureFile(this.profileNativeDir, fileName, {
                    trustedLocal: this.trustedLocal
                });
                const summary = describe(raw);
                nativeArtifacts[type] = { sha256: summary.sha256, bytes: summary.bytes };
                return summary;
            }
            return describe(readNativeLogFile(logPath));
        };
        const sslKeyLogSummary = readLog('sslKeyLog', this.sslKeyLogPath, parseSslKeyLogBytes);
        const neckoMozLogSummary = readLog('neckoMozLog', this.neckoMozLogPath, parseNeckoMozLogBytes);
        const sslKeyLogFile = nativeArtifactName(this.trafficDir, this.sslKeyLogPath, INTEGRITY_ARTIFACTS.sslKeyLog);
        const neckoMozLogFile = nativeArtifactName(this.trafficDir, this.neckoMozLogPath, INTEGRITY_ARTIFACTS.neckoMozLog);

        let preTlsWireLogSha256 = null;
        let preTlsWireLogBytes = 0;
        if (this.preTlsWireLogPath && fs.existsSync(this.preTlsWireLogPath)) {
            try {
                const rawWireBuf = fs.readFileSync(this.preTlsWireLogPath);
                preTlsWireLogBytes = rawWireBuf.byteLength;
                preTlsWireLogSha256 = crypto
                    .createHash('sha256')
                    .update(rawWireBuf)
                    .digest('hex');
            } catch {
                preTlsWireLogSha256 = null;
                preTlsWireLogBytes = 0;
            }
        }

        const byPlatform = {};
        for (const sig of this.platformSignatures) {
            if (!sig || !sig.platform) continue;
            byPlatform[sig.platform] = (byPlatform[sig.platform] || 0) + 1;
        }

        const cookieLineageObj = {};
        for (const [cookieName, entry] of this.cookieLineage.entries()) {
            cookieLineageObj[cookieName] = {
                name: entry.name,
                isAntiBotToken: Boolean(entry.isAntiBotToken),
                domain: entry.domain ?? null,
                path: entry.path ?? null,
                secure: Boolean(entry.secure),
                httpOnly: Boolean(entry.httpOnly),
                sameSite: entry.sameSite ?? null,
                firstSetAt: entry.firstSetAt ?? null,
                firstSetByCorrelationId: entry.firstSetByCorrelationId ?? null,
                firstSetAtStep: entry.firstSetAtStep ?? null,
                firstSetByTrigger: entry.firstSetByTrigger ?? null,
                firstSetUrl: entry.firstSetUrl ?? null,
                lastSetAt: entry.lastSetAt ?? null,
                lastSetByCorrelationId: entry.lastSetByCorrelationId ?? null,
                lastSetAtStep: entry.lastSetAtStep ?? null,
                lastValueSha256: entry.lastValueSha256 ?? null,
                lastMaskedValue: entry.lastMaskedValue ?? null,
                mutationsCount: Number(entry.mutationsCount) || 0,
                sentCount: Number(entry.sentCount) || 0,
                lastSentAt: entry.lastSentAt ?? null,
                lastSentByCorrelationId: entry.lastSentByCorrelationId ?? null,
                lastSentAtStep: entry.lastSentAtStep ?? null,
                matchesLatestSetCookie: entry.matchesLatestSetCookie ?? null,
                valueHistory: Array.isArray(entry.valueHistory)
                    ? entry.valueHistory.map((h) => ({ ...h }))
                    : [],
                sentInCorrelationIds: Array.from(entry.sentInCorrelationIds || [])
            };
        }

        return {
            session: {
                traceId: this.attribution.traceId,
                profileId: this.attribution.profileId,
                accountId: this.attribution.accountId,
                accountEmail: this.attribution.accountEmail,
                os: this.attribution.os,
                proxyServer: this.attribution.proxyServer,
                recordBodies: this.recordBodies,
                startedAt: this.startedAt,
                endedAt: endedAtIso,
                totalDurationMs
            },
            artifacts: {
                trafficNdjsonPath: this.trafficNdjsonPath,
                preTlsWireLogPath: this.preTlsWireLogPath,
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
                totalEgressBytes: this.totals.totalEgressBytes,
                totalIngressBytes: this.totals.totalIngressBytes
            },
            byActionStep: byActionStepObj,
            byDomain: byDomainObj,
            byTriggerAction: byTriggerActionObj,
            cookieLineage: cookieLineageObj,
            platformSignatures: {
                totalDetected: this.platformSignatures.length,
                byPlatform,
                signatures: [...this.platformSignatures]
            },
            anomaliesAndRiskSignals: [...this.anomaliesAndRiskSignals],
            integrity: {
                algorithm: 'sha256-chain',
                genesisHash: this.genesisHash,
                eventCount: this.chainedEventCount,
                chainHeadHash: this.chainHeadHash,
                payloadCount: Object.keys(this.payloadManifest).length,
                payloadManifest: { ...this.payloadManifest },
                preTlsWireLogSha256,
                preTlsWireLogBytes,
                sslKeyLogSha256: sslKeyLogFile ? sslKeyLogSummary.sha256 : null,
                sslKeyLogBytes: sslKeyLogFile ? sslKeyLogSummary.bytes : 0,
                ...(sslKeyLogFile && sslKeyLogSummary.exists ? { sslKeyLogFile } : {}),
                neckoMozLogSha256: neckoMozLogFile ? neckoMozLogSummary.sha256 : null,
                neckoMozLogBytes: neckoMozLogFile ? neckoMozLogSummary.bytes : 0,
                ...(neckoMozLogFile && neckoMozLogSummary.exists ? { neckoMozLogFile } : {}),
                ...(Object.keys(nativeArtifacts).length > 0 ? { nativeArtifacts } : {})
            }
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
            profileId: this.attribution.profileId,
            accountId: this.attribution.accountId,
            accountEmail: this.attribution.accountEmail,
            traceId: this.attribution.traceId,
            os: this.attribution.os,
            proxyServer: this.attribution.proxyServer,
            startedAt: this.startedAt
        }, { recordBodies: this.recordBodies, trustedLocal: this.trustedLocal });
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
            profileId: this.attribution.profileId,
            accountId: this.attribution.accountId,
            accountEmail: this.attribution.accountEmail,
            traceId: this.attribution.traceId,
            os: this.attribution.os,
            proxyServer: this.attribution.proxyServer,
            startedAt: this.startedAt
        }, { recordBodies: this.recordBodies && recordBodies !== false, trustedLocal: this.trustedLocal });
    }

    /**
     * Wait for any in-flight asynchronous payload captures to complete and write
     * `attribution-index.json` to disk.
     *
     * @returns {Promise<object>} Written attribution summary object
     */
    async flushSummary() {
        if (this.pendingTasks.size > 0) {
            await Promise.allSettled(Array.from(this.pendingTasks));
        }
        if (this.stopped) {
            this.endedAt ??= new Date().toISOString();
        }
        if (this.ledgerWriteError) {
            throw new Error('Could not append to traffic.ndjson', { cause: this.ledgerWriteError });
        }
        if (this.wireWriteError) {
            throw new Error('Could not append to pre-tls-wire.log', { cause: this.wireWriteError });
        }

        const summary = this.buildAttributionSummary();
        writePrivateFile(this.attributionIndexPath, `${JSON.stringify(summary, null, 2)}\n`);
        return summary;
    }

    /**
     * Detach all active event listeners, await in-flight traffic captures,
     * mark the recording session as ended, and flush `attribution-index.json`.
     *
     * @returns {Promise<object>} Final attribution summary object
     */
    async stop() {
        if (!this.stopped) {
            this.stopped = true;
            for (const dispose of this.webSocketDisposers) {
                dispose();
            }

            while (this.listenerDisposers.length > 0) {
                const dispose = this.listenerDisposers.pop();
                try {
                    dispose();
                } catch {}
            }
        }

        return this.flushSummary();
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

    if (!trafficDir) {
        return {
            valid: false, scope, unverifiedNativeArtifacts: [], eventCount, verifiedPayloads, chainHeadHash,
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
    const unverifiedNativeArtifacts = nativeDir
        ? []
        : Object.keys(integrity?.nativeArtifacts ?? {}).map((type) => INTEGRITY_ARTIFACTS[type]);
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
        if (integrity) {
            check(() => verifyLedgerCheckpoint(integrity, ledger.events));
        }
    }

    let sslKeyLog = parseSslKeyLogBytes(null);
    let neckoMozLog = parseNeckoMozLogBytes(null);
    if (integrity) {
        const manifest = check(() => getPayloadManifest(integrity));
        if (manifest) {
            for (const [relativePath, entry] of Object.entries(manifest)) {
                check(() => {
                    verifyPayloadEntry(resolvedTrafficDir, relativePath, entry, trustedLocal);
                    verifiedPayloads += 1;
                });
            }

            const referencedPayloads = new Set(ledger?.events.map((event) => event.payloadFile));
            referencedPayloads.delete(undefined);
            referencedPayloads.delete(null);
            for (const relativePath of referencedPayloads) {
                if (!Object.hasOwn(manifest, relativePath)) {
                    errors.push('An event payload file is absent from the payload manifest');
                }
            }

            const entries = check(() => listCapturePayloads(resolvedTrafficDir, { trustedLocal })) ?? [];
            for (const entry of entries) {
                if (!entry.isFile() && !entry.isSymbolicLink()) continue;
                const relativePath = path.posix.join('payloads', entry.name);
                if (!Object.hasOwn(manifest, relativePath)) {
                    errors.push(`Orphan unindexed payload file found in payloads/: ${relativePath}`);
                }
            }
        }

        check(() => verifyArtifact(resolvedTrafficDir, integrity, 'preTlsWireLog', { trustedLocal }));
        sslKeyLog = check(() => verifyArtifact(resolvedTrafficDir, integrity, 'sslKeyLog', {
            describe: parseSslKeyLogBytes,
            nativeDir,
            trustedLocal
        })) ?? sslKeyLog;
        neckoMozLog = check(() => verifyArtifact(resolvedTrafficDir, integrity, 'neckoMozLog', {
            describe: parseNeckoMozLogBytes,
            nativeDir,
            trustedLocal
        })) ?? neckoMozLog;

        if (sslKeyLog.malformedLineCount > 0) {
            errors.push(
                `sslkeylog.txt contains ${sslKeyLog.malformedLineCount} malformed NSS keylog line(s)`
            );
        }
    }

    return {
        valid: errors.length === 0,
        scope,
        unverifiedNativeArtifacts,
        eventCount,
        verifiedPayloads,
        chainHeadHash,
        sslKeyLog,
        neckoMozLog,
        errors
    };
}

function redactCaptureBodyText(raw, mimeType) {
    const text = redactDiagnosticText(raw);
    if (/^application\/x-www-form-urlencoded\b/i.test(mimeType)) {
        return redactUrlSecrets(`?${text}`).slice(1);
    }
    if (/^\s*[\[{]/.test(raw)) {
        try {
            const data = JSON.parse(raw);
            const sanitized = JSON.stringify(redactDiagnosticMetadata(data));
            if (sanitized !== JSON.stringify(data)) return sanitized;
        } catch {
            // A truncated or otherwise non-JSON preview is still handled as text.
        }
    }
    return text;
}

/** Use a recorded attachment or inline body while honoring capture and export policy. */
export function readCaptureExportBody(trafficDir, event, {
    recordBodies = true,
    trustedLocal = false,
    url = event?.url,
    mimeType = event?.mimeType || 'application/octet-stream'
} = {}) {
    const omitted = { bytes: null, text: null, payloadFile: null };
    if (!event || recordBodies === false || event.recordBodies === false || event.bodyOmittedReason) return omitted;

    const requestUrl = String(url || '');
    const safeUrl = redactUrlSecrets(requestUrl);
    const authPath = /(?:^|\/)(?:sign-?in|log-?in|oauth2?|authenticate|password|token)(?:[/?#.]|$)/i;
    if (safeUrl !== requestUrl || /\[REDACTED(?::[0-9a-f]{8})?\]/i.test(safeUrl) || authPath.test(safeUrl)) {
        return omitted;
    }

    if (event.payloadFile != null) {
        try {
            const bytes = readCapturePayload(trafficDir, event.payloadFile, { trustedLocal });
            return {
                bytes,
                text: redactCaptureBodyText(bytes.toString('utf8'), mimeType),
                payloadFile: redactDiagnosticText(event.payloadFile)
            };
        } catch (error) {
            if (error.code !== 'ENOENT') return omitted;
        }
    }
    // Older ledgers can contain previews even when recording bodies was disabled.
    if (event.recordBodies !== true) return omitted;
    const preview = event.bodyPreview ?? event.postData;
    return typeof preview === 'string'
        ? { ...omitted, text: redactCaptureBodyText(preview, mimeType) }
        : omitted;
}

function harHeaders(record) {
    const { headers, headersArray } = redactSensitiveHeaders(record || {});
    return headersArray.length > 0 ? headersArray : Object.entries(headers).map(([name, value]) => ({ name, value }));
}

/** Reconstruct a W3C HAR 1.2 document from a profile's `traffic/` directory. */
function buildHarFromTrafficDir(trafficDir, fallbackSession = {}, { recordBodies = true, trustedLocal = false } = {}) {
    const resolvedTrafficDir = path.resolve(String(trafficDir));

    const indexBytes = readCaptureFile(resolvedTrafficDir, 'attribution-index.json', { optional: true, trustedLocal });
    let indexData = null;
    if (indexBytes) {
        try {
            indexData = JSON.parse(indexBytes.toString('utf8'));
        } catch {
            indexData = null;
        }
    }

    const sessionMeta = {
        ...fallbackSession,
        ...(indexData?.session || {})
    };
    const includeBodies = recordBodies !== false && sessionMeta.recordBodies !== false;

    const captureBytes = readCaptureFile(resolvedTrafficDir, 'traffic.ndjson', { optional: true, trustedLocal });
    const events = [];
    if (captureBytes) {
        const raw = captureBytes.toString('utf8');
        for (const line of raw.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            try {
                events.push(JSON.parse(trimmed));
            } catch {
                // Skip malformed trailing line
            }
        }
    }

    const pagesMap = new Map();
    const ensurePageForStep = (stepName, stepIndex, timestamp) => {
        const cleanStep = redactDiagnosticText(stepName || 'init');
        const idx = Number.isFinite(Number(stepIndex)) ? Number(stepIndex) : pagesMap.size;
        const pageKey = `${idx}:${cleanStep}`;
        if (!pagesMap.has(pageKey)) {
            pagesMap.set(pageKey, {
                startedDateTime: timestamp || sessionMeta.startedAt || new Date().toISOString(),
                id: `page_${idx}_${cleanStep}`,
                title: `${cleanStep} (step ${idx})`,
                pageTimings: {
                    onContentLoad: -1,
                    onLoad: -1
                }
            });
        }
        return pagesMap.get(pageKey).id;
    };

    // Seed pages from step-transition events and group HTTP transactions by correlationId
    const txMap = new Map();
    for (const ev of events) {
        if (!ev || typeof ev !== 'object') continue;
        if (ev.type === 'step-transition') {
            ensurePageForStep(
                ev.actionStep || ev.attribution?.actionStep || 'init',
                ev.stepIndex ?? ev.attribution?.stepIndex ?? 0,
                ev.timestamp
            );
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

        if (!txMap.has(ev.correlationId)) {
            txMap.set(ev.correlationId, {
                correlationId: ev.correlationId,
                egress: null,
                ingress: null,
                finished: null,
                failed: null,
                securityBlock: null
            });
        }
        const tx = txMap.get(ev.correlationId);
        if (ev.type === 'egress') tx.egress = ev;
        else if (ev.type === 'ingress') tx.ingress = ev;
        else if (ev.type === 'request-finished') tx.finished = ev;
        else if (ev.type === 'request-failed') tx.failed = ev;
        else if (ev.type === 'security-block') tx.securityBlock = ev;
    }

    const entries = [];
    for (const [correlationId, tx] of txMap.entries()) {
        const { egress, ingress, finished, failed, securityBlock } = tx;
        const primary = egress || ingress || failed || securityBlock || finished;
        if (!primary) continue;

        const attribution =
            egress?.attribution ||
            ingress?.attribution ||
            failed?.attribution ||
            securityBlock?.attribution ||
            finished?.attribution ||
            {};
        const actionStep =
            attribution.actionStep ||
            egress?.actionStep ||
            ingress?.actionStep ||
            securityBlock?.actionStep ||
            'init';
        const stepIndex =
            attribution.stepIndex ??
            egress?.stepIndex ??
            ingress?.stepIndex ??
            securityBlock?.stepIndex ??
            0;
        const triggerAction =
            egress?.triggerAction ||
            ingress?.triggerAction ||
            failed?.triggerAction ||
            securityBlock?.triggerAction ||
            finished?.triggerAction ||
            null;

        const startedDateTime =
            egress?.timestamp ||
            ingress?.timestamp ||
            failed?.timestamp ||
            securityBlock?.timestamp ||
            finished?.timestamp ||
            sessionMeta.startedAt ||
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

        const rawUrl =
            egress?.url ||
            ingress?.url ||
            failed?.url ||
            securityBlock?.url ||
            finished?.url ||
            '';
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
            const parsed = new URL(requestUrl);
            for (const [name, value] of parsed.searchParams.entries()) {
                queryString.push({ name: String(name), value: String(value) });
            }
        } catch {
            if (egress?.searchParams && typeof egress.searchParams === 'object') {
                for (const [k, v] of Object.entries(redactDiagnosticMetadata(egress.searchParams))) {
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
        const reqContentTypeHeader =
            reqHeaders.find((h) => h.name.toLowerCase() === 'content-type')?.value || '';
        const requestBody = readCaptureExportBody(resolvedTrafficDir, egress, {
            recordBodies: includeBodies, trustedLocal, url: rawUrl, mimeType: reqContentTypeHeader
        });
        const reqBodyText = requestBody.text || '';
        const reqBodySize =
            Number(egress?.postDataBytes) ||
            Number(finished?.sizes?.requestBodySize) ||
            (reqBodyText ? Buffer.byteLength(reqBodyText, 'utf8') : 0);

        const postData = {
            mimeType: reqContentTypeHeader || (reqBodyText ? 'application/octet-stream' : ''),
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

        const responseBody = readCaptureExportBody(resolvedTrafficDir, ingress, {
            recordBodies: includeBodies, trustedLocal, url: ingress?.url || rawUrl, mimeType: resMimeType
        });
        const resBuf = responseBody.bytes;
        const binaryResponse = resBuf && inferPayloadExtension(resMimeType, resBuf) === 'bin' &&
            responseBody.text === resBuf.toString('utf8');
        const resBodyText = binaryResponse ? resBuf.toString('base64') : responseBody.text || '';
        const resBodySize = resBuf?.byteLength ?? (Number(ingress?.bodyBytes) ||
            Number(finished?.sizes?.responseBodySize) || Buffer.byteLength(resBodyText, 'utf8'));

        const redirectURL =
            resHeaders.find((h) => h.name.toLowerCase() === 'location')?.value || '';

        const status = Number(ingress?.status ?? finished?.status ?? 0);
        const statusText = redactDiagnosticText(
            ingress?.statusText ??
            (securityBlock
                ? 'BLOCKED_BY_ZINIAO_SECURITY_GUARD'
                : failed
                  ? String(failed.failureText || 'FAILED')
                  : '')
        );

        entries.push({
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
                status,
                statusText,
                httpVersion: 'HTTP/1.1',
                cookies: [],
                headers: resHeaders,
                content: {
                    size: resBodySize,
                    mimeType: resMimeType,
                    text: resBodyText,
                    ...(binaryResponse ? { encoding: 'base64' } : {})
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
                profileId: attribution.profileId || sessionMeta.profileId || 'default-profile',
                accountId: attribution.accountId ?? sessionMeta.accountId ?? null,
                accountEmail: null,
                traceId: attribution.traceId ?? sessionMeta.traceId ?? null,
                os: attribution.os ?? sessionMeta.os ?? null,
                proxyServer: redactUrlSecrets(redactProxyUrl(attribution.proxyServer ?? sessionMeta.proxyServer)) || null,
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
                failureText: redactDiagnosticText(
                    failed?.failureText ||
                    securityBlock?.reason ||
                    securityBlock?.failureText ||
                    null
                ) || null
            }
        });
    }

    if (pagesMap.size === 0) {
        ensurePageForStep('init', 0, sessionMeta.startedAt || new Date().toISOString());
    }

    return {
        log: {
            version: '1.2',
            creator: {
                name: 'CamoufoxTrafficRecorder',
                version: '1.0.0'
            },
            browser: {
                name: 'Camoufox Firefox',
                version: '135.0'
            },
            pages: Array.from(pagesMap.values()),
            entries
        }
    };
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
    if (!outputPath) {
        let captureRoot = resolvedTrafficDir;
        try {
            captureRoot = fs.realpathSync.native(captureRoot);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
        const fromCapture = path.relative(captureRoot, process.cwd());
        if (fromCapture !== '..' && !fromCapture.startsWith(`..${path.sep}`) && !path.isAbsolute(fromCapture)) {
            throw new Error('Choose a HAR output path when running inside the input capture directory');
        }
    }

    const harArchive = buildHarFromTrafficDir(resolvedTrafficDir, fallbackSession, options);
    const serialized = `${JSON.stringify(harArchive, null, 2)}\n`;
    writeCaptureExport(resolvedOutputPath, serialized, { replace: Boolean(outputPath) });
    const bytes = Buffer.byteLength(serialized, 'utf8');

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
