/**
 * Camoufox Pre-TLS Egress/Ingress Traffic Recorder & Multi-Dimensional Attribution Engine
 *
 * Hooks Gecko / Necko channel lifecycle events exposed through Playwright's Juggler
 * bridge (`http-on-modify-request` prior to NSS TLS encryption on egress, and
 * `onDataAvailable` / `onStopRequest` immediately after NSS TLS decryption on ingress)
 * together with NSS `SSLKEYLOGFILE` key material reservation.
 *
 * Captures 100% plaintext HTTP/1.1, HTTP/2, and WebSocket traffic to disk without
 * any external MITM proxy, preserving authentic Firefox TLS (JA3/JA4) and HTTP/2
 * fingerprints while providing full correlation and root-cause anomaly attribution.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEFAULT_PROFILES_DIR = (process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR)
    ? path.resolve(process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR)
    : path.resolve(__dirname, '../../profiles');

const DEFAULT_MAX_INLINE_PREVIEW_BYTES = 4096;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024; // 5MB (5242880 bytes)

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

export const SENSITIVE_HEADER_REGEX =
    /^(proxy-authorization|x-proxy-authorization|authorization|x-api-key|omocaptcha-key)$/i;

const SENSITIVE_HEADER_NAME_REGEX = SENSITIVE_HEADER_REGEX;

export const SENSITIVE_URL_PARAM_REGEX =
    /^(api_key|apikey|access_token|refresh_token|client_secret|password|passwd|pwd|secret|private_key)$/i;

/**
 * Known anti-bot, risk-control, and session authentication cookie/token names across
 * Google, Cloudflare, Meta/Instagram, TikTok, and X/Twitter.
 */
export const ANTI_BOT_COOKIE_REGEX =
    /^(datr|sb|fr|c_user|xs|ig_did|mid|csrftoken|rur|ttwid|msToken|s_v_web_id|verifyFp|odin_tt|passport_csrf_token|guest_id|guest_id_marketing|guest_id_ads|ct0|auth_token|kdt|_twitter_sess|__cf_bm|cf_clearance|_cfuvid|NID|AEC|SOCS|SID|HSID|SSID|APISID|SAPISID|__Secure-[0-9A-Za-z_-]+|__Host-[0-9A-Za-z_-]+)$/i;

/**
 * Mask a cookie value so raw session secrets are never leaked while keeping a short
 * diagnostic prefix/suffix for longer values (`first 3 chars + *** + last 2 chars`,
 * or `[REDACTED]` for short values).
 *
 * @param {string} rawValue
 * @returns {string}
 */
function maskCookieValue(rawValue) {
    const str = String(rawValue ?? '');
    if (str.length <= 6) {
        return '[REDACTED]';
    }
    return `${str.slice(0, 3)}***${str.slice(-2)}`;
}

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
    const maskedValue = maskCookieValue(value);

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
            cookiePath = attrVal || null;
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
        const maskedValue = maskCookieValue(value);
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

/**
 * Redact a sensitive header value while preserving an authentication scheme prefix
 * (e.g. `Basic dXNlcjpzZWNyZXQ=` -> `Basic [REDACTED]`, `Bearer eyJ...` -> `Bearer [REDACTED]`,
 * raw API key -> `[REDACTED]`).
 *
 * @param {string} rawValue
 * @returns {string}
 */
function redactSensitiveHeaderValue(rawValue) {
    const str = String(rawValue ?? '').trim();
    const schemeMatch = str.match(/^([A-Za-z0-9._-]+)\s+\S+.*$/);
    if (schemeMatch) {
        return `${schemeMatch[1]} [REDACTED]`;
    }
    return '[REDACTED]';
}

/**
 * Redact sensitive query parameter values in a URL (`api_key`, `apikey`, `access_token`,
 * `refresh_token`, `client_secret`, `password`, `passwd`, `pwd`, `secret`, `private_key`),
 * replacing each value with `[REDACTED:${sha256_8}]` so plaintext credentials never leak
 * to `traffic.ndjson` or `pre-tls-wire.log` while remaining deterministically traceable.
 *
 * @param {string} rawUrl
 * @returns {string}
 */
export function redactUrlSecrets(rawUrl) {
    if (rawUrl === null || rawUrl === undefined) {
        return '';
    }
    const urlStr = String(rawUrl);
    if (!urlStr || !urlStr.includes('?')) {
        return urlStr;
    }

    const hashIdx = urlStr.indexOf('#');
    const beforeHash = hashIdx >= 0 ? urlStr.slice(0, hashIdx) : urlStr;
    const hashPart = hashIdx >= 0 ? urlStr.slice(hashIdx) : '';

    const qIdx = beforeHash.indexOf('?');
    if (qIdx < 0) {
        return urlStr;
    }

    const basePart = beforeHash.slice(0, qIdx);
    const queryPart = beforeHash.slice(qIdx + 1);
    if (!queryPart) {
        return urlStr;
    }

    let modified = false;
    const redactedSegments = queryPart.split('&').map((segment) => {
        if (!segment) return segment;
        const eqIdx = segment.indexOf('=');
        if (eqIdx <= 0) return segment;

        const rawKey = segment.slice(0, eqIdx);
        const rawVal = segment.slice(eqIdx + 1);
        let decodedKey = rawKey;
        try {
            decodedKey = decodeURIComponent(rawKey.replace(/\+/g, '%20'));
        } catch {
            decodedKey = rawKey;
        }

        if (!SENSITIVE_URL_PARAM_REGEX.test(decodedKey)) {
            return segment;
        }

        let decodedVal = rawVal;
        try {
            decodedVal = decodeURIComponent(rawVal.replace(/\+/g, '%20'));
        } catch {
            decodedVal = rawVal;
        }

        if (/^\[REDACTED:[0-9a-f]{8}\]$/i.test(decodedVal)) {
            if (rawVal !== decodedVal) {
                modified = true;
            }
            return `${rawKey}=${decodedVal}`;
        }

        const sha256_8 = crypto
            .createHash('sha256')
            .update(String(decodedVal), 'utf8')
            .digest('hex')
            .slice(0, 8);
        modified = true;
        return `${rawKey}=[REDACTED:${sha256_8}]`;
    });

    if (!modified) {
        return urlStr;
    }

    return `${basePart}?${redactedSegments.join('&')}${hashPart}`;
}

/**
 * Automatically redact sensitive proxy and API-key headers (`Proxy-Authorization`,
 * `X-Proxy-Authorization`, `X-Api-Key`, `Omocaptcha-Key`) in both `headers` object
 * and ordered `headersArray`.
 *
 * @param {{ headers?: Record<string, string>, headersArray?: Array<{ name: string, value: string }> }} input
 * @returns {{ headers: Record<string, string>, headersArray: Array<{ name: string, value: string }> }}
 */
export function redactSensitiveHeaders({ headers = {}, headersArray = [] } = {}) {
    const redactedHeaders = {};
    if (headers && typeof headers === 'object') {
        for (const [key, value] of Object.entries(headers)) {
            redactedHeaders[key] = SENSITIVE_HEADER_NAME_REGEX.test(key)
                ? redactSensitiveHeaderValue(value)
                : String(value ?? '');
        }
    }

    const redactedHeadersArray = Array.isArray(headersArray)
        ? headersArray.map((entry) => {
              const name = String(entry?.name ?? '');
              const value = String(entry?.value ?? '');
              const redactedValue = SENSITIVE_HEADER_NAME_REGEX.test(name)
                  ? redactSensitiveHeaderValue(value)
                  : value;
              if (SENSITIVE_HEADER_NAME_REGEX.test(name)) {
                  const lowerName = name.toLowerCase();
                  if (Object.prototype.hasOwnProperty.call(redactedHeaders, name)) {
                      redactedHeaders[name] = redactedValue;
                  }
                  if (Object.prototype.hasOwnProperty.call(redactedHeaders, lowerName)) {
                      redactedHeaders[lowerName] = redactedValue;
                  }
              }
              return {
                  name,
                  value: redactedValue
              };
          })
        : [];

    return {
        headers: redactedHeaders,
        headersArray: redactedHeadersArray
    };
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
        return formatted.endsWith('/') && !rawServer.endsWith('/')
            ? formatted.slice(0, -1)
            : formatted;
    } catch {
        // Fallback regex strip for user:pass@host:port
        return String(rawServer).replace(/(\/\/|^)([^/@:\s]+:[^/@\s]+@)/, '$1');
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
            preview: slice.toString('utf8'),
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
        for (const [key, rawValue] of parsed.searchParams.entries()) {
            let value = rawValue;
            if (
                SENSITIVE_URL_PARAM_REGEX.test(key) &&
                !/^\[REDACTED:[0-9a-f]{8}\]$/i.test(value)
            ) {
                const sha256_8 = crypto
                    .createHash('sha256')
                    .update(String(value), 'utf8')
                    .digest('hex')
                    .slice(0, 8);
                value = `[REDACTED:${sha256_8}]`;
            }
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
    if (!sslKeyLogPath || !fs.existsSync(sslKeyLogPath)) {
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

    const rawBuffer = fs.readFileSync(sslKeyLogPath);
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
    if (!neckoLogPath || !fs.existsSync(neckoLogPath)) {
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

    const rawBuffer = fs.readFileSync(neckoLogPath);
    if (rawBuffer.byteLength === 0) {
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

    return {
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
    };
}

/**
 * Normalize headers object and optional headersArray so Firefox's exact pre-TLS
 * header order is preserved whenever Playwright's `headersArray()` is available.
 *
 * @param {object} target - Playwright Request or Response
 * @returns {Promise<{ headers: Record<string, string>, headersArray: Array<{ name: string, value: string }> }>}
 */
async function extractHeadersWithOrder(target) {
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

    return redactSensitiveHeaders({ headers, headersArray });
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
     * @param {string|null} [options.neckoMozLogPath=null]
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

        this.payloadsDir = path.join(this.trafficDir, 'payloads');
        this.trafficNdjsonPath = path.join(this.trafficDir, 'traffic.ndjson');
        this.preTlsWireLogPath = options.preTlsWireLogPath
            ? path.resolve(options.preTlsWireLogPath)
            : path.join(this.trafficDir, 'pre-tls-wire.log');
        this.recordWireLog = options.recordWireLog !== false;
        this.neckoMozLogPath = options.neckoMozLogPath
            ? path.resolve(options.neckoMozLogPath)
            : path.join(this.trafficDir, 'necko-pre-tls.moz_log');
        this.sslKeyLogPath = options.sslKeyLogPath
            ? path.resolve(options.sslKeyLogPath)
            : path.join(this.trafficDir, 'sslkeylog.txt');
        this.attributionIndexPath = path.join(this.trafficDir, 'attribution-index.json');
        this.harPath = options.harPath
            ? path.resolve(options.harPath)
            : path.join(this.trafficDir, 'traffic.har');

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
        this.genesisHash = '0'.repeat(64);
        this.chainHeadHash = this.genesisHash;
        this.chainedEventCount = 0;
        this.payloadManifest = {};

        // Correlation & tracking stores
        this.requestCorrelationMap = new WeakMap();
        this.transactions = new Map();
        this.wsWireBlocks = new Map();
        this.attachedContexts = new WeakSet();
        this.attachedPagesHttp = new WeakSet();
        this.attachedPagesWs = new WeakSet();
        this.attachedWebSockets = new WeakSet();
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
                this.attributionIndexPath,
                this.harPath
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

        this._ensureDirectories();
        if (!this.resetTrafficOnStart) {
            this._resumeExistingChainIfPresent();
        }
        this._ensureStepRecord(this.attribution.actionStep, this.attribution.stepIndex);
    }

    /**
     * Resume an existing persistent profile's SHA-256 tamper-evident event hash chain
     * across process restarts and self-heal any trailing truncated/crashed line in `traffic.ndjson`.
     */
    _resumeExistingChainIfPresent() {
        if (!fs.existsSync(this.trafficNdjsonPath)) {
            return;
        }

        let rawContent = '';
        try {
            rawContent = fs.readFileSync(this.trafficNdjsonPath, 'utf8');
        } catch {
            return;
        }

        const nonEmptyLines = rawContent
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter((l) => l.length > 0);

        if (nonEmptyLines.length === 0) {
            return;
        }

        const validLines = [];
        const validEvents = [];
        let needsRewrite = false;
        let runningHead = this.genesisHash;

        for (let i = 0; i < nonEmptyLines.length; i += 1) {
            const rawLine = nonEmptyLines[i];
            let parsed = null;
            try {
                parsed = JSON.parse(rawLine);
            } catch {
                needsRewrite = true;
                continue;
            }

            if (
                !parsed ||
                typeof parsed !== 'object' ||
                typeof parsed.eventHash !== 'string' ||
                !/^[0-9a-f]{64}$/i.test(parsed.eventHash)
            ) {
                needsRewrite = true;
                continue;
            }

            const canonicalPayload = JSON.stringify({ ...parsed, eventHash: undefined });
            const preimage = `${parsed.prevEventHash ?? ''}|${parsed.seq ?? 0}|${canonicalPayload}`;
            const expectedHash = crypto.createHash('sha256').update(preimage, 'utf8').digest('hex');
            if (parsed.prevEventHash !== runningHead || parsed.eventHash !== expectedHash) {
                needsRewrite = true;
                break;
            }

            runningHead = parsed.eventHash;
            validLines.push(rawLine);
            validEvents.push(parsed);
        }

        if (needsRewrite) {
            const cleanContent = validLines.length > 0 ? `${validLines.join('\n')}\n` : '';
            try {
                fs.writeFileSync(this.trafficNdjsonPath, cleanContent, 'utf8');
            } catch {}
        }

        if (validEvents.length === 0) {
            return;
        }

        const lastValidEvent = validEvents[validEvents.length - 1];
        const maxSeq = validEvents.reduce((max, ev) => Math.max(max, Number(ev.seq) || 0), 0);
        const maxStepIndex = validEvents.reduce(
            (max, ev) => Math.max(max, Number(ev.attribution?.stepIndex ?? ev.stepIndex) || 0),
            0
        );

        this.chainHeadHash = lastValidEvent.eventHash;
        this.seq = maxSeq || validEvents.length;
        this.chainedEventCount = validEvents.length;
        if (maxStepIndex > this.attribution.stepIndex) {
            this.attribution.stepIndex = maxStepIndex;
        }

        // Load existing attribution-index.json if present
        let existingIndex = null;
        if (fs.existsSync(this.attributionIndexPath)) {
            try {
                existingIndex = JSON.parse(fs.readFileSync(this.attributionIndexPath, 'utf8'));
            } catch {
                existingIndex = null;
            }
        }

        // Restore payloadManifest from attribution-index.json and cross-verify against validEvents
        if (
            existingIndex?.integrity?.payloadManifest &&
            typeof existingIndex.integrity.payloadManifest === 'object'
        ) {
            for (const [relPath, entry] of Object.entries(existingIndex.integrity.payloadManifest)) {
                const fullPayloadPath = path.join(this.trafficDir, relPath);
                if (fs.existsSync(fullPayloadPath)) {
                    this.payloadManifest[relPath] = { ...entry };
                }
            }
        }

        for (const ev of validEvents) {
            if (ev.payloadFile && !this.payloadManifest[ev.payloadFile]) {
                const fullPayloadPath = path.join(this.trafficDir, ev.payloadFile);
                if (fs.existsSync(fullPayloadPath)) {
                    try {
                        const buf = fs.readFileSync(fullPayloadPath);
                        const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
                        this.payloadManifest[ev.payloadFile] = {
                            sha256,
                            bytes: buf.byteLength,
                            truncated: Boolean(ev.payloadTruncated),
                            seq: ev.seq ?? 0,
                            prefix: ev.type === 'egress' ? 'req' : ev.type === 'ingress' ? 'res' : 'ws'
                        };
                    } catch {}
                }
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

        for (const ev of validEvents) {
            if (ev.correlationId) {
                validCorrIds.add(ev.correlationId);
            }
        }

        // Restore persisted cookieLineage from attribution-index.json if present
        if (existingIndex?.cookieLineage && typeof existingIndex.cookieLineage === 'object') {
            for (const [cookieName, rawEntry] of Object.entries(existingIndex.cookieLineage)) {
                if (!rawEntry || typeof rawEntry !== 'object') continue;
                const restoredSentCorrIds = new Set(
                    Array.isArray(rawEntry.sentInCorrelationIds)
                        ? rawEntry.sentInCorrelationIds.filter(
                              (id) => !validCorrIds.size || validCorrIds.has(id)
                          )
                        : []
                );
                const restoredHistory = Array.isArray(rawEntry.valueHistory)
                    ? rawEntry.valueHistory
                          .filter(
                              (h) =>
                                  h &&
                                  (!h.correlationId ||
                                      !validCorrIds.size ||
                                      validCorrIds.has(h.correlationId))
                          )
                          .map((h) => ({ ...h }))
                    : [];
                this.cookieLineage.set(cookieName, {
                    name: rawEntry.name || cookieName,
                    isAntiBotToken: Boolean(
                        rawEntry.isAntiBotToken ?? ANTI_BOT_COOKIE_REGEX.test(cookieName)
                    ),
                    domain: rawEntry.domain ?? null,
                    path: rawEntry.path ?? '/',
                    secure: Boolean(rawEntry.secure),
                    httpOnly: Boolean(rawEntry.httpOnly),
                    sameSite: rawEntry.sameSite ?? null,
                    firstSetAt: rawEntry.firstSetAt ?? null,
                    firstSetByCorrelationId: rawEntry.firstSetByCorrelationId ?? null,
                    firstSetAtStep: rawEntry.firstSetAtStep ?? null,
                    firstSetByTrigger: rawEntry.firstSetByTrigger ?? null,
                    firstSetUrl: rawEntry.firstSetUrl ?? null,
                    lastSetAt: rawEntry.lastSetAt ?? null,
                    lastSetByCorrelationId: rawEntry.lastSetByCorrelationId ?? null,
                    lastSetAtStep: rawEntry.lastSetAtStep ?? null,
                    lastValueSha256: rawEntry.lastValueSha256 ?? null,
                    lastMaskedValue: rawEntry.lastMaskedValue ?? null,
                    mutationsCount:
                        Number(rawEntry.mutationsCount) || restoredHistory.length || 0,
                    sentCount: Number(rawEntry.sentCount) || restoredSentCorrIds.size || 0,
                    lastSentAt: rawEntry.lastSentAt ?? null,
                    lastSentByCorrelationId: rawEntry.lastSentByCorrelationId ?? null,
                    lastSentAtStep: rawEntry.lastSentAtStep ?? null,
                    matchesLatestSetCookie: rawEntry.matchesLatestSetCookie ?? null,
                    valueHistory: restoredHistory,
                    sentInCorrelationIds: restoredSentCorrIds
                });
            }
        }

        for (const ev of validEvents) {
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
                    correlationId: ev.correlationId,
                    actionStep: effectiveStepName,
                    triggerAction: effectiveTrigger,
                    timestamp: ev.timestamp,
                    url: ev.url || '',
                    parsedUrl,
                    status
                });
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
                this._recordAnomaly({
                    timestamp: ev.timestamp,
                    correlationId: ev.correlationId || null,
                    actionStep: effectiveStepName,
                    triggerAction: effectiveTrigger,
                    type: 'network-request-failed',
                    severity: 'high',
                    method: ev.method || null,
                    url: ev.url || null,
                    status: null,
                    failureText: ev.failureText || 'UNKNOWN_ERROR'
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
            }
        }

        // Restore persisted anomalies from attribution-index.json if available
        if (Array.isArray(existingIndex?.anomaliesAndRiskSignals)) {
            for (const anomaly of existingIndex.anomaliesAndRiskSignals) {
                if (!anomaly || typeof anomaly !== 'object') continue;
                if (anomaly.correlationId && !validCorrIds.has(anomaly.correlationId)) {
                    continue;
                }
                this._recordAnomaly(anomaly);
            }
        }
    }

    /**
     * Ensure `profiles/<profileId>/traffic/`, `payloads/`, `sslkeylog.txt`, and `pre-tls-wire.log` exist on disk.
     */
    _ensureDirectories() {
        fs.mkdirSync(this.trafficDir, { recursive: true });
        fs.mkdirSync(this.payloadsDir, { recursive: true });
        if (!fs.existsSync(this.sslKeyLogPath)) {
            fs.writeFileSync(
                this.sslKeyLogPath,
                '# NSS SSL/TLS Secrets Log (Camoufox Pre-TLS Traffic Recorder)\n',
                'utf8'
            );
        }
        if (this.recordWireLog && !fs.existsSync(this.preTlsWireLogPath)) {
            fs.writeFileSync(this.preTlsWireLogPath, '', 'utf8');
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
        return {
            ...(baseEnv || {}),
            SSLKEYLOGFILE: this.sslKeyLogPath
        };
    }

    /**
     * Return the reserved NSS `SSLKEYLOGFILE` path.
     *
     * @returns {string}
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
     * @returns {{ label: string, clientRandomHex: string, secretHex: string, line: string }}
     */
    recordSslKeyLogSecret(label, clientRandomHex, secretHex) {
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
        fs.appendFileSync(this.sslKeyLogPath, `${line}\n`, 'utf8');
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
     * @returns {{ neckoMozLogPath: string, appendedBytes: number }}
     */
    recordNeckoMozLogBlock(rawLogText) {
        if (rawLogText === null || rawLogText === undefined) {
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
        fs.appendFileSync(this.neckoMozLogPath, normalized, 'utf8');
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
        correlationId = null,
        actionStep = 'init',
        triggerAction = null,
        timestamp = new Date().toISOString(),
        url = '',
        parsedUrl = null,
        status = null
    } = {}) {
        const rawSetCookieValues = [];
        if (Array.isArray(headersArray) && headersArray.length > 0) {
            for (const h of headersArray) {
                if (h && String(h.name || '').toLowerCase() === 'set-cookie' && h.value) {
                    rawSetCookieValues.push(String(h.value));
                }
            }
        }
        if (rawSetCookieValues.length === 0 && headers && typeof headers === 'object') {
            for (const [k, v] of Object.entries(headers)) {
                if (String(k).toLowerCase() === 'set-cookie' && v) {
                    if (Array.isArray(v)) {
                        for (const item of v) {
                            if (item) rawSetCookieValues.push(String(item));
                        }
                    } else {
                        rawSetCookieValues.push(String(v));
                    }
                }
            }
        }

        if (rawSetCookieValues.length === 0) {
            return;
        }

        const fallbackDomain =
            parsedUrl?.hostname && parsedUrl.hostname !== 'unknown'
                ? parsedUrl.hostname
                : parsedUrl?.host && parsedUrl.host !== 'unknown'
                  ? parsedUrl.host
                  : null;
        const triggerActionId = triggerAction?.actionId || null;

        for (const rawBlock of rawSetCookieValues) {
            const lines = String(rawBlock).split(/\r?\n/);
            for (const rawLine of lines) {
                const parsed = parseSetCookieHeader(rawLine);
                if (!parsed) continue;

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
                    entry.lastMaskedValue = parsed.maskedValue;
                    entry.valueHistory.push({
                        correlationId,
                        actionStep,
                        triggerActionId,
                        timestamp,
                        status: status ?? null,
                        valueSha256: parsed.valueSha256,
                        maskedValue: parsed.maskedValue,
                        isDeleted: Boolean(parsed.isDeleted)
                    });
                }
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
        correlationId = null,
        actionStep = 'init',
        timestamp = new Date().toISOString(),
        parsedUrl = null,
        isReplay = false
    } = {}) {
        const rawCookieValues = [];
        if (Array.isArray(headersArray) && headersArray.length > 0) {
            for (const h of headersArray) {
                if (h && String(h.name || '').toLowerCase() === 'cookie' && h.value) {
                    rawCookieValues.push(String(h.value));
                }
            }
        }
        if (rawCookieValues.length === 0 && headers && typeof headers === 'object') {
            for (const [k, v] of Object.entries(headers)) {
                if (String(k).toLowerCase() === 'cookie' && v) {
                    rawCookieValues.push(String(v));
                }
            }
        }

        if (rawCookieValues.length === 0) {
            return;
        }

        const fallbackDomain =
            parsedUrl?.hostname && parsedUrl.hostname !== 'unknown'
                ? parsedUrl.hostname
                : parsedUrl?.host && parsedUrl.host !== 'unknown'
                  ? parsedUrl.host
                  : null;

        for (const rawCookieHeader of rawCookieValues) {
            const parsedCookies = parseCookieHeader(rawCookieHeader);
            for (const cookie of parsedCookies) {
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
                    entry.lastMaskedValue = cookie.maskedValue;
                }
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
        if (!partial || typeof partial !== 'object') {
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
            metadata: metadata && typeof metadata === 'object' ? metadata : {},
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
     * @returns {object} Recorded trigger action snapshot
     */
    recordTriggerAction(actionType, target = null, metadata = {}) {
        this.triggerSeq += 1;
        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        this.lastTriggerAction = {
            actionId: `act-${this.traceIdShort}-${this.triggerSeq}`,
            actionType: String(actionType || 'unknown'),
            target: target ? String(target) : null,
            timestamp,
            epochMs,
            actionStep: this.attribution.actionStep,
            stepIndex: this.attribution.stepIndex,
            metadata: metadata && typeof metadata === 'object' ? metadata : {}
        };

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
        if (!record || typeof record !== 'object') {
            return;
        }

        record.prevEventHash = this.chainHeadHash;
        const canonicalPayload = JSON.stringify({ ...record, eventHash: undefined });
        const preimage = `${record.prevEventHash}|${record.seq ?? 0}|${canonicalPayload}`;
        const eventHash = crypto.createHash('sha256').update(preimage, 'utf8').digest('hex');
        record.eventHash = eventHash;
        this.chainHeadHash = eventHash;
        this.chainedEventCount += 1;

        const line = `${JSON.stringify(record)}\n`;
        try {
            fs.appendFileSync(this.trafficNdjsonPath, line, 'utf8');
        } catch {
            // Ensure directory exists and retry once if needed
            try {
                this._ensureDirectories();
                fs.appendFileSync(this.trafficNdjsonPath, line, 'utf8');
            } catch {
                // Swallow disk error to avoid crashing active browser automation
            }
        }
    }

    /**
     * Append a canonical pre-TLS / post-TLS raw HTTP or WebSocket wire block to `pre-tls-wire.log`.
     *
     * @param {string} wireBlock
     */
    _appendWireLogBlock(wireBlock) {
        if (!this.recordWireLog || !wireBlock) {
            return;
        }
        const entry = wireBlock.endsWith('\n') ? wireBlock : `${wireBlock}\n`;
        try {
            fs.appendFileSync(this.preTlsWireLogPath, entry, 'utf8');
        } catch {
            try {
                this._ensureDirectories();
                fs.appendFileSync(this.preTlsWireLogPath, entry, 'utf8');
            } catch {
                // Swallow disk error to avoid crashing active browser automation
            }
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
            fs.writeFileSync(fullPath, toWriteBuffer);
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
     * Track an asynchronous event handler promise so `flushSummary()` and `stop()`
     * await all in-flight body and header captures before writing summary files.
     *
     * @param {Promise<any>} promise
     * @returns {Promise<any>}
     */
    _trackTask(promise) {
        const wrapped = Promise.resolve(promise)
            .catch(() => {})
            .finally(() => {
                this.pendingTasks.delete(wrapped);
            });
        this.pendingTasks.add(wrapped);
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
        const dedupeKey = [
            anomaly.correlationId || '',
            anomaly.type || '',
            anomaly.status ?? '',
            anomaly.failureText || '',
            anomaly.url || ''
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
            url: anomaly.url || null,
            status: anomaly.status ?? null,
            failureText: anomaly.failureText ?? null,
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
        const reason = String(blockEvent.reason || `Blocked ${blockType} to ${redactedUrl}`);
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
        if (!context || typeof context.on !== 'function' || this.attachedContexts.has(context)) {
            return this;
        }
        this.attachedContexts.add(context);

        const onRequest = (request) => this._trackTask(this._handleRequest(request));
        const onResponse = (response) => this._trackTask(this._handleResponse(response));
        const onRequestFinished = (request) => this._trackTask(this._handleRequestFinished(request));
        const onRequestFailed = (request) => this._trackTask(this._handleRequestFailed(request));
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
        if (!page || typeof page.on !== 'function') {
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

        const onRequest = (request) => this._trackTask(this._handleRequest(request));
        const onResponse = (response) => this._trackTask(this._handleResponse(response));
        const onRequestFinished = (request) => this._trackTask(this._handleRequestFinished(request));
        const onRequestFailed = (request) => this._trackTask(this._handleRequestFailed(request));

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
        if (!page || typeof page.on !== 'function' || this.attachedPagesWs.has(page)) {
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
        const { headers, headersArray } = await extractHeadersWithOrder(request);
        const contentType = headers['content-type'] || headers['Content-Type'] || null;

        // Capture pre-TLS postData / postDataBuffer
        let postDataBuffer = null;
        let postDataString = null;
        try {
            if (typeof request.postDataBuffer === 'function') {
                postDataBuffer = request.postDataBuffer();
            }
        } catch {}
        try {
            if (typeof request.postData === 'function') {
                postDataString = request.postData();
            }
        } catch {}

        if (!postDataBuffer && typeof postDataString === 'string' && postDataString.length > 0) {
            postDataBuffer = Buffer.from(postDataString, 'utf8');
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
            headers,
            headersArray,
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
            headers,
            headersArray,
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
            if (typeof response.statusText === 'function') statusText = response.statusText() || '';
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
        const { headers, headersArray } = await extractHeadersWithOrder(response);

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

        // Capture decrypted response body from Necko channel when capturePayloads (recordBodies) is enabled
        let bodyBuffer = null;
        let bodyReadError = null;
        const isRedirectStatus = status >= 300 && status < 400;
        const isEmptyBodyStatus = status === 204 || status === 205 || status === 304;

        if (this.capturePayloads && !isRedirectStatus && !isEmptyBodyStatus) {
            try {
                if (typeof response.body === 'function') {
                    const rawBody = await response.body();
                    if (rawBody) {
                        bodyBuffer = Buffer.isBuffer(rawBody)
                            ? rawBody
                            : Buffer.from(rawBody);
                    }
                } else if (typeof response.text === 'function') {
                    const rawText = await response.text();
                    if (rawText) {
                        bodyBuffer = Buffer.from(String(rawText), 'utf8');
                    }
                }
            } catch (err) {
                bodyReadError = err?.message || String(err);
            }
        }

        let bodySha256 = null;
        let bodyBytes = 0;
        let bodyPreview = null;
        let bodyPreviewTruncated = false;
        let payloadFile = null;
        let payloadTruncated = false;

        if (bodyBuffer && bodyBuffer.byteLength > 0) {
            const hashed = hashPayload(bodyBuffer);
            bodySha256 = hashed.sha256;
            bodyBytes = hashed.byteLength;

            const previewObj = buildBodyPreview(
                hashed.buffer,
                mimeType,
                this.maxInlinePreviewBytes
            );
            bodyPreview = previewObj.preview;
            bodyPreviewTruncated = previewObj.truncated;

            const saved = this._writePayloadFile(
                'res',
                seq,
                hashed.buffer,
                hashed.shortSha256,
                mimeType
            );
            payloadFile = saved.payloadFile;
            payloadTruncated = Boolean(saved.payloadTruncated);
        }

        const headerByteEstimate = headersArray.reduce(
            (acc, h) => acc + Buffer.byteLength(`${h.name}: ${h.value}\r\n`, 'utf8'),
            Buffer.byteLength(`HTTP/1.1 ${status} ${statusText}\r\n\r\n`, 'utf8')
        );
        const estimatedIngressBytes = headerByteEstimate + bodyBytes;

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
            bodyPreview
        });

        if (tx) {
            tx.status = status;
            tx.responsePayloadFile = payloadFile;
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
                responsePayloadFile: payloadFile,
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
            serverAddr,
            securityDetails,
            bodySha256,
            bodyBytes,
            bodyPreview,
            bodyPreviewTruncated,
            payloadFile,
            payloadTruncated,
            ...(bodyReadError ? { bodyReadError } : {}),
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        };

        this._appendNdjsonEvent(ingressEvent);
        this._appendWireLogBlock(ingressWireBlock);

        // Update Cookie & Anti-Bot Token causal lineage on ingress (Set-Cookie)
        this._updateCookieLineageFromIngress({
            headers,
            headersArray,
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
                payloadFile: payloadFile || tx?.requestPayloadFile || null
            });
        }

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
                actionStep: effectiveStepName,
                triggerAction: triggerSnapshot,
                type: `risk-signal:${riskSignals.map((s) => s.name).join('+')}`,
                severity: highestSeverity,
                method,
                url,
                status,
                failureText: null,
                payloadFile: payloadFile || tx?.requestPayloadFile || null,
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
                payloadFile: payloadFile || tx?.requestPayloadFile || null
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
                    failureText = String(failureObj.errorText);
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
        if (!ws || typeof ws.on !== 'function' || this.attachedWebSockets.has(ws)) {
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
            const timestamp = new Date().toISOString();
            const epochMs = Date.now();
            const seq = this._nextSeq();
            const attributionSnapshot = this.getAttributionSnapshot();
            const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs);

            const rawPayload = frameData && typeof frameData === 'object' && 'payload' in frameData
                ? frameData.payload
                : frameData;

            const payloadBuffer = Buffer.isBuffer(rawPayload)
                ? rawPayload
                : Buffer.from(String(rawPayload ?? ''), 'utf8');

            const hashed = hashPayload(payloadBuffer);
            const previewObj = buildBodyPreview(
                hashed.buffer,
                'text/plain',
                this.maxInlinePreviewBytes
            );

            let payloadFile = null;
            let payloadTruncated = false;
            if (hashed.byteLength > this.maxInlinePreviewBytes) {
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
                this.totals.totalEgressBytes += hashed.byteLength;
                stepBucket.egressBytes += hashed.byteLength;
                domainBucket.egressBytes += hashed.byteLength;
                if (triggerBucket) {
                    triggerBucket.wsFramesSent += 1;
                    triggerBucket.egressBytes += hashed.byteLength;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    triggerBucket.correlationIdsSet.add(wsCorrelationId);
                }
            } else {
                this.totals.wsFramesReceived += 1;
                this.totals.totalIngressBytes += hashed.byteLength;
                stepBucket.ingressBytes += hashed.byteLength;
                domainBucket.ingressBytes += hashed.byteLength;
                if (triggerBucket) {
                    triggerBucket.wsFramesReceived += 1;
                    triggerBucket.ingressBytes += hashed.byteLength;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    triggerBucket.correlationIdsSet.add(wsCorrelationId);
                }
            }

            const triggerSummary = this._formatTriggerSummary(triggerSnapshot);
            const wsWireBlock =
                direction === 'ws-egress'
                    ? [
                          '================================================================================',
                          `>>> WS-EGRESS [PRE-TLS] [${timestamp}] [corr=${wsCorrelationId}] [step=${attributionSnapshot.actionStep}] [trigger=${triggerSummary}] [url=${wsUrl}] [bytes=${hashed.byteLength}]`,
                          previewObj.preview || '',
                          '================================================================================'
                      ].join('\n')
                    : [
                          '--------------------------------------------------------------------------------',
                          `<<< WS-INGRESS [POST-TLS] [${timestamp}] [corr=${wsCorrelationId}] [step=${attributionSnapshot.actionStep}] [trigger=${triggerSummary}] [url=${wsUrl}] [bytes=${hashed.byteLength}]`,
                          previewObj.preview || '',
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
                payloadSha256: hashed.sha256,
                payloadBytes: hashed.byteLength,
                bodyPreview: previewObj.preview,
                bodyPreviewTruncated: previewObj.truncated,
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
            const timestamp = new Date().toISOString();
            const epochMs = Date.now();
            const seq = this._nextSeq();
            const attributionSnapshot = this.getAttributionSnapshot();
            const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs);
            const failureText = String(errorMsg || 'WEBSOCKET_ERROR');

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

        ws.on('framesent', onFrameSent);
        ws.on('framereceived', onFrameReceived);
        ws.on('socketerror', onSocketError);
        ws.on('close', onClose);
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

        const sslKeyLogSummary = parseSslKeyLog(this.sslKeyLogPath);
        const neckoMozLogSummary = parseNeckoMozLog(this.neckoMozLogPath);

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
                startedAt: this.startedAt,
                endedAt: endedAtIso,
                totalDurationMs
            },
            artifacts: {
                trafficNdjsonPath: this.trafficNdjsonPath,
                preTlsWireLogPath: this.preTlsWireLogPath,
                neckoMozLogPath: this.neckoMozLogPath,
                payloadsDir: this.payloadsDir,
                sslKeyLogPath: this.sslKeyLogPath,
                harPath: this.harPath,
                attributionIndexPath: this.attributionIndexPath
            },
            sslKeyLog: sslKeyLogSummary,
            neckoMozLog: neckoMozLogSummary,
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
                sslKeyLogSha256: sslKeyLogSummary.sha256,
                sslKeyLogBytes: sslKeyLogSummary.bytes,
                neckoMozLogSha256: neckoMozLogSummary.sha256,
                neckoMozLogBytes: neckoMozLogSummary.bytes
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
        });
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
    exportHar(outputPath = this.harPath) {
        const resolvedOut = outputPath ? path.resolve(String(outputPath)) : this.harPath;
        return exportTrafficToHar(this.trafficDir, resolvedOut, {
            profileId: this.attribution.profileId,
            accountId: this.attribution.accountId,
            accountEmail: this.attribution.accountEmail,
            traceId: this.attribution.traceId,
            os: this.attribution.os,
            proxyServer: this.attribution.proxyServer,
            startedAt: this.startedAt
        });
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

        this._ensureDirectories();
        const summary = this.buildAttributionSummary();
        fs.writeFileSync(
            this.attributionIndexPath,
            `${JSON.stringify(summary, null, 2)}\n`,
            'utf8'
        );
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
            this.endedAt = new Date().toISOString();

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
 * @returns {{
 *   valid: boolean,
 *   eventCount: number,
 *   verifiedPayloads: number,
 *   chainHeadHash: string,
 *   errors: string[]
 * }}
 */
export function verifyTrafficIntegrity(trafficDir) {
    const errors = [];
    const defaultGenesisHash = '0'.repeat(64);
    let chainHeadHash = defaultGenesisHash;
    let eventCount = 0;
    let verifiedPayloads = 0;

    if (!trafficDir) {
        errors.push('trafficDir path is required');
        return {
            valid: false,
            eventCount,
            verifiedPayloads,
            chainHeadHash,
            errors
        };
    }

    const resolvedTrafficDir = path.resolve(String(trafficDir));
    if (!fs.existsSync(resolvedTrafficDir)) {
        errors.push(`Traffic directory does not exist: ${resolvedTrafficDir}`);
        return {
            valid: false,
            eventCount,
            verifiedPayloads,
            chainHeadHash,
            errors
        };
    }

    const attributionIndexPath = path.join(resolvedTrafficDir, 'attribution-index.json');
    const trafficNdjsonPath = path.join(resolvedTrafficDir, 'traffic.ndjson');

    let summary = null;
    if (!fs.existsSync(attributionIndexPath)) {
        errors.push(`Missing attribution-index.json at ${attributionIndexPath}`);
    } else {
        try {
            summary = JSON.parse(fs.readFileSync(attributionIndexPath, 'utf8'));
        } catch (err) {
            errors.push(`Failed to parse attribution-index.json: ${err.message}`);
        }
    }

    const integrity = summary?.integrity || null;
    if (summary && (!integrity || typeof integrity !== 'object')) {
        errors.push('Missing integrity block in attribution-index.json');
    }

    const genesisHash =
        typeof integrity?.genesisHash === 'string' && integrity.genesisHash.length === 64
            ? integrity.genesisHash
            : defaultGenesisHash;
    chainHeadHash = genesisHash;

    if (fs.existsSync(trafficNdjsonPath)) {
        const rawNdjson = fs.readFileSync(trafficNdjsonPath, 'utf8');
        const lines = rawNdjson.split(/\r?\n/);

        for (let i = 0; i < lines.length; i += 1) {
            const trimmed = lines[i].trim();
            if (!trimmed) continue;

            const lineNumber = i + 1;
            let record = null;
            try {
                record = JSON.parse(trimmed);
            } catch (err) {
                errors.push(`Line ${lineNumber}: Invalid JSON in traffic.ndjson (${err.message})`);
                continue;
            }

            eventCount += 1;

            if (record.prevEventHash !== chainHeadHash) {
                errors.push(
                    `Line ${lineNumber} (seq=${record.seq ?? 'n/a'}): prevEventHash mismatch (expected ${chainHeadHash}, got ${record.prevEventHash ?? 'missing'})`
                );
            }

            const canonicalPayload = JSON.stringify({ ...record, eventHash: undefined });
            const preimage = `${record.prevEventHash}|${record.seq ?? 0}|${canonicalPayload}`;
            const expectedEventHash = crypto
                .createHash('sha256')
                .update(preimage, 'utf8')
                .digest('hex');

            if (record.eventHash !== expectedEventHash) {
                errors.push(
                    `Line ${lineNumber} (seq=${record.seq ?? 'n/a'}): eventHash mismatch (expected ${expectedEventHash}, got ${record.eventHash ?? 'missing'})`
                );
            }

            chainHeadHash =
                typeof record.eventHash === 'string' && record.eventHash.length === 64
                    ? record.eventHash
                    : expectedEventHash;
        }
    } else if ((integrity?.eventCount ?? 0) > 0) {
        errors.push(`Missing traffic.ndjson at ${trafficNdjsonPath}`);
    }

    if (integrity && typeof integrity === 'object') {
        if (typeof integrity.eventCount === 'number' && eventCount !== integrity.eventCount) {
            errors.push(
                `Event count mismatch: traffic.ndjson has ${eventCount} event(s), attribution-index.json expects ${integrity.eventCount}`
            );
        }
        if (
            typeof integrity.chainHeadHash === 'string' &&
            chainHeadHash !== integrity.chainHeadHash
        ) {
            errors.push(
                `Chain head hash mismatch: computed ${chainHeadHash}, attribution-index.json expects ${integrity.chainHeadHash}`
            );
        }

        const manifest =
            integrity.payloadManifest && typeof integrity.payloadManifest === 'object'
                ? integrity.payloadManifest
                : {};

        for (const [relativePath, manifestEntry] of Object.entries(manifest)) {
            const fullPayloadPath = path.join(resolvedTrafficDir, relativePath);
            if (!fs.existsSync(fullPayloadPath)) {
                errors.push(`Missing payload file on disk: ${relativePath}`);
                continue;
            }

            const diskBuffer = fs.readFileSync(fullPayloadPath);
            const actualSha256 = crypto.createHash('sha256').update(diskBuffer).digest('hex');
            const actualBytes = diskBuffer.byteLength;

            let payloadOk = true;
            if (manifestEntry?.sha256 && actualSha256 !== manifestEntry.sha256) {
                errors.push(
                    `Payload SHA-256 mismatch for ${relativePath}: expected ${manifestEntry.sha256}, got ${actualSha256}`
                );
                payloadOk = false;
            }
            if (typeof manifestEntry?.bytes === 'number' && actualBytes !== manifestEntry.bytes) {
                errors.push(
                    `Payload byte length mismatch for ${relativePath}: expected ${manifestEntry.bytes}, got ${actualBytes}`
                );
                payloadOk = false;
            }

            if (payloadOk) {
                verifiedPayloads += 1;
            }
        }

        // Scan payloads/ directory on disk to detect any orphan/unindexed files not listed in payloadManifest
        const payloadsDir = path.join(resolvedTrafficDir, 'payloads');
        if (fs.existsSync(payloadsDir)) {
            const indexedPayloadPaths = new Set(
                Object.keys(manifest).map((k) => String(k).replace(/\\/g, '/'))
            );
            const diskEntries = fs.readdirSync(payloadsDir, { withFileTypes: true });
            for (const entry of diskEntries) {
                if (!entry.isFile() && !entry.isSymbolicLink()) continue;
                const relPosix = path.posix.join('payloads', entry.name);
                if (!indexedPayloadPaths.has(relPosix) && !indexedPayloadPaths.has(entry.name)) {
                    errors.push(`Orphan unindexed payload file found in payloads/: ${relPosix}`);
                }
            }
        }

        // Verify pre-tls-wire.log SHA-256 and byte length if recorded in summary.integrity
        const preTlsWireLogPath = path.join(resolvedTrafficDir, 'pre-tls-wire.log');
        if (integrity.preTlsWireLogSha256) {
            if (!fs.existsSync(preTlsWireLogPath)) {
                errors.push('Missing pre-tls-wire.log on disk');
            } else {
                const rawWireBuf = fs.readFileSync(preTlsWireLogPath);
                const actualWireSha256 = crypto
                    .createHash('sha256')
                    .update(rawWireBuf)
                    .digest('hex');
                const actualWireBytes = rawWireBuf.byteLength;

                if (actualWireSha256 !== integrity.preTlsWireLogSha256) {
                    errors.push(
                        `pre-tls-wire.log SHA-256 mismatch: expected ${integrity.preTlsWireLogSha256}, got ${actualWireSha256}`
                    );
                }
                if (
                    typeof integrity.preTlsWireLogBytes === 'number' &&
                    actualWireBytes !== integrity.preTlsWireLogBytes
                ) {
                    errors.push(
                        `pre-tls-wire.log byte length mismatch: expected ${integrity.preTlsWireLogBytes}, got ${actualWireBytes}`
                    );
                }
            }
        }

        const sslKeyLogPath = path.join(resolvedTrafficDir, 'sslkeylog.txt');
        const sslKeyLogStats = parseSslKeyLog(sslKeyLogPath);
        if (integrity.sslKeyLogSha256 && sslKeyLogStats.exists) {
            if (sslKeyLogStats.sha256 !== integrity.sslKeyLogSha256) {
                errors.push(
                    `sslkeylog.txt SHA-256 mismatch: expected ${integrity.sslKeyLogSha256}, got ${sslKeyLogStats.sha256}`
                );
            }
            if (
                typeof integrity.sslKeyLogBytes === 'number' &&
                sslKeyLogStats.bytes !== integrity.sslKeyLogBytes
            ) {
                errors.push(
                    `sslkeylog.txt byte length mismatch: expected ${integrity.sslKeyLogBytes}, got ${sslKeyLogStats.bytes}`
                );
            }
        }
        if (sslKeyLogStats.exists && sslKeyLogStats.malformedLineCount > 0) {
            errors.push(
                `sslkeylog.txt contains ${sslKeyLogStats.malformedLineCount} malformed NSS keylog line(s)`
            );
        }

        const neckoMozLogPath = path.join(resolvedTrafficDir, 'necko-pre-tls.moz_log');
        const hasRecordedNeckoMozLog =
            Boolean(integrity.neckoMozLogSha256) ||
            (typeof integrity.neckoMozLogBytes === 'number' && integrity.neckoMozLogBytes > 0);
        if (hasRecordedNeckoMozLog || fs.existsSync(neckoMozLogPath)) {
            if (!fs.existsSync(neckoMozLogPath)) {
                if (hasRecordedNeckoMozLog) {
                    errors.push('Missing necko-pre-tls.moz_log on disk');
                }
            } else {
                const rawNeckoBuf = fs.readFileSync(neckoMozLogPath);
                const actualNeckoBytes = rawNeckoBuf.byteLength;
                const actualNeckoSha256 =
                    actualNeckoBytes > 0
                        ? crypto.createHash('sha256').update(rawNeckoBuf).digest('hex')
                        : null;

                if (
                    integrity.neckoMozLogSha256 &&
                    actualNeckoSha256 !== integrity.neckoMozLogSha256
                ) {
                    errors.push(
                        `necko-pre-tls.moz_log SHA-256 mismatch: expected ${integrity.neckoMozLogSha256}, got ${actualNeckoSha256 ?? 'empty'}`
                    );
                }
                if (
                    hasRecordedNeckoMozLog &&
                    typeof integrity.neckoMozLogBytes === 'number' &&
                    actualNeckoBytes !== integrity.neckoMozLogBytes
                ) {
                    errors.push(
                        `necko-pre-tls.moz_log byte length mismatch: expected ${integrity.neckoMozLogBytes}, got ${actualNeckoBytes}`
                    );
                }
            }
        }
    }

    const sslKeyLog = parseSslKeyLog(path.join(resolvedTrafficDir, 'sslkeylog.txt'));
    const neckoMozLog = parseNeckoMozLog(path.join(resolvedTrafficDir, 'necko-pre-tls.moz_log'));

    return {
        valid: errors.length === 0,
        eventCount,
        verifiedPayloads,
        chainHeadHash,
        sslKeyLog,
        neckoMozLog,
        errors
    };
}

/**
 * Reconstruct a W3C HAR 1.2 document from a profile's `traffic/` directory.
 *
 * @param {string} trafficDir
 * @param {object} [fallbackSession={}]
 * @returns {{ log: object }}
 */
function buildHarFromTrafficDir(trafficDir, fallbackSession = {}) {
    const resolvedTrafficDir = path.resolve(String(trafficDir));
    const trafficNdjsonPath = path.join(resolvedTrafficDir, 'traffic.ndjson');
    const attributionIndexPath = path.join(resolvedTrafficDir, 'attribution-index.json');

    let indexData = null;
    if (fs.existsSync(attributionIndexPath)) {
        try {
            indexData = JSON.parse(fs.readFileSync(attributionIndexPath, 'utf8'));
        } catch {
            indexData = null;
        }
    }

    const sessionMeta = {
        ...fallbackSession,
        ...(indexData?.session || {})
    };

    const events = [];
    if (fs.existsSync(trafficNdjsonPath)) {
        const raw = fs.readFileSync(trafficNdjsonPath, 'utf8');
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
        const cleanStep = String(stepName || 'init');
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

        // Build request headers array
        const reqHeaders =
            Array.isArray(egress?.headersArray) && egress.headersArray.length > 0
                ? egress.headersArray.map((h) => ({
                      name: String(h.name ?? ''),
                      value: String(h.value ?? '')
                  }))
                : Object.entries(egress?.headers || {}).map(([name, value]) => ({
                      name: String(name),
                      value: String(value ?? '')
                  }));

        // Build queryString array
        const queryString = [];
        try {
            const parsed = new URL(rawUrl);
            for (const [name, value] of parsed.searchParams.entries()) {
                queryString.push({ name: String(name), value: String(value) });
            }
        } catch {
            if (egress?.searchParams && typeof egress.searchParams === 'object') {
                for (const [k, v] of Object.entries(egress.searchParams)) {
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
        let reqBodyText = '';
        if (egress?.payloadFile) {
            const fullReqPayloadPath = path.join(resolvedTrafficDir, egress.payloadFile);
            if (fs.existsSync(fullReqPayloadPath)) {
                try {
                    const reqBuf = fs.readFileSync(fullReqPayloadPath);
                    reqBodyText = reqBuf.toString('utf8');
                } catch {}
            }
        }
        if (!reqBodyText && (egress?.bodyPreview || egress?.postData)) {
            reqBodyText = String(egress.bodyPreview ?? egress.postData ?? '');
        }
        const reqBodySize =
            Number(egress?.postDataBytes) ||
            Number(finished?.sizes?.requestBodySize) ||
            (reqBodyText ? Buffer.byteLength(reqBodyText, 'utf8') : 0);

        const postData = {
            mimeType: reqContentTypeHeader || (reqBodyText ? 'application/octet-stream' : ''),
            text: reqBodyText,
            params: []
        };

        // Build response headers array
        const resHeaders =
            Array.isArray(ingress?.headersArray) && ingress.headersArray.length > 0
                ? ingress.headersArray.map((h) => ({
                      name: String(h.name ?? ''),
                      value: String(h.value ?? '')
                  }))
                : Object.entries(ingress?.headers || {}).map(([name, value]) => ({
                      name: String(name),
                      value: String(value ?? '')
                  }));

        const resContentTypeHeader =
            resHeaders.find((h) => h.name.toLowerCase() === 'content-type')?.value || '';
        const resMimeType =
            ingress?.mimeType ||
            (resContentTypeHeader ? resContentTypeHeader.split(';')[0].trim() : '') ||
            'application/octet-stream';

        let resBodyText = '';
        let resEncoding = null;
        let resBodySize = Number(ingress?.bodyBytes) || Number(finished?.sizes?.responseBodySize) || 0;

        if (ingress?.payloadFile) {
            const fullResPayloadPath = path.join(resolvedTrafficDir, ingress.payloadFile);
            if (fs.existsSync(fullResPayloadPath)) {
                try {
                    const resBuf = fs.readFileSync(fullResPayloadPath);
                    resBodySize = resBuf.byteLength;
                    const ext = inferPayloadExtension(resMimeType, resBuf);
                    if (ext === 'bin') {
                        resBodyText = resBuf.toString('base64');
                        resEncoding = 'base64';
                    } else {
                        resBodyText = resBuf.toString('utf8');
                    }
                } catch {}
            }
        }
        if (!resBodyText && ingress?.bodyPreview) {
            resBodyText = String(ingress.bodyPreview);
            if (!resBodySize) {
                resBodySize = Buffer.byteLength(resBodyText, 'utf8');
            }
        }

        const redirectURL =
            resHeaders.find((h) => h.name.toLowerCase() === 'location')?.value || '';

        const status = Number(ingress?.status ?? finished?.status ?? 0);
        const statusText =
            ingress?.statusText ??
            (securityBlock
                ? 'BLOCKED_BY_ZINIAO_SECURITY_GUARD'
                : failed
                  ? String(failed.failureText || 'FAILED')
                  : '');

        entries.push({
            pageref,
            startedDateTime,
            time: totalTimeMs,
            request: {
                method,
                url: rawUrl,
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
                    ...(resEncoding ? { encoding: resEncoding } : {})
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
                          reason:
                              securityBlock.reason ||
                              securityBlock.failureText ||
                              'BLOCKED_BY_ZINIAO_SECURITY_GUARD',
                          host: securityBlock.host || null,
                          port: securityBlock.port ?? null,
                          scope: securityBlock.scope || null,
                          service: securityBlock.service || null,
                          category: securityBlock.category || null,
                          matchedScheme: securityBlock.matchedScheme || null,
                          initiatorUrl: securityBlock.initiatorUrl || null
                      }
                  }
                : {}),
            _attribution: {
                correlationId,
                actionStep,
                stepIndex,
                triggerAction,
                profileId: attribution.profileId || sessionMeta.profileId || 'default-profile',
                accountId: attribution.accountId ?? sessionMeta.accountId ?? null,
                accountEmail: attribution.accountEmail ?? sessionMeta.accountEmail ?? null,
                traceId: attribution.traceId ?? sessionMeta.traceId ?? null,
                os: attribution.os ?? sessionMeta.os ?? null,
                proxyServer: attribution.proxyServer ?? sessionMeta.proxyServer ?? null,
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
                requestPayloadFile: egress?.payloadFile || null,
                responsePayloadFile: ingress?.payloadFile || null,
                failureText:
                    failed?.failureText ||
                    securityBlock?.reason ||
                    securityBlock?.failureText ||
                    null
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
export function exportTrafficToHar(trafficDir, outputPath, fallbackSession = {}) {
    if (!trafficDir) {
        throw new Error('trafficDir is required for exportTrafficToHar');
    }
    const resolvedTrafficDir = path.resolve(String(trafficDir));
    const resolvedOutputPath = outputPath
        ? path.resolve(String(outputPath))
        : path.join(resolvedTrafficDir, 'traffic.har');

    const harArchive = buildHarFromTrafficDir(resolvedTrafficDir, fallbackSession);
    fs.mkdirSync(path.dirname(resolvedOutputPath), { recursive: true });
    const serialized = `${JSON.stringify(harArchive, null, 2)}\n`;
    fs.writeFileSync(resolvedOutputPath, serialized, 'utf8');
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
