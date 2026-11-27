import { redactUrlSecrets } from './traffic-redaction.js';

const AUTHENTICATION_PATH = /(?:^|\/)(?:auth(?:enticate|entication|orize)?|oauth2?|sign[-_]?(?:in|out|up)|log[-_]?(?:in|out)|register|password|token|sessions?|verify|verification|challenge|otp|mfa)(?:[/;._-]|$)/i;
const BOOLEAN_FIELDS = new Set(['ok', 'success', 'enabled', 'complete', 'completed', 'done']);
const COUNT_FIELDS = new Set(['count', 'limit', 'offset', 'page', 'pageSize', 'total']);
const STATUS_VALUES = new Set([
    'accepted', 'cancelled', 'complete', 'completed', 'error', 'failed', 'in_progress',
    'ok', 'pending', 'ready', 'success', 'succeeded', 'timeout'
]);
const JSON_CONTAINERS = new Set(['data', 'items', 'pagination', 'result', 'results']);
const utf8 = new TextDecoder('utf-8', { fatal: true });

/** Keep bodies off authentication endpoints and URLs with stripped or concealed credentials. */
export function allowsTrafficBody(url) {
    if (typeof url !== 'string' || !url || redactUrlSecrets(url) !== url) return false;
    try {
        const parsed = url.startsWith('/') ? new URL(url, 'https://capture.invalid') : new URL(url);
        return ['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol) &&
            !parsed.username && !parsed.password &&
            !/\[REDACTED(?::[0-9a-f]{8})?\]/i.test(decodeURIComponent(url)) &&
            !AUTHENTICATION_PATH.test(decodeURIComponent(parsed.pathname));
    } catch {
        return false;
    }
}

/** A redirect that switches to GET or HEAD discards the preceding upload. */
export function redirectDropsUpload(method, sourceMethod) {
    return (method === 'GET' || method === 'HEAD') &&
        typeof sourceMethod === 'string' && sourceMethod.length > 0 && sourceMethod !== method;
}

export function isBodylessHttpResponse(method, status) {
    return method === 'HEAD' || (status >= 100 && status < 200) ||
        status === 204 || status === 205 || status === 304;
}

/** Bound the recorder's work on a body already delivered by the browser transport. */
export function sampleTrafficBody(content, maxBytes) {
    if (Buffer.isBuffer(content)) {
        return { buffer: content.subarray(0, maxBytes), byteLength: content.byteLength };
    }
    if (typeof content !== 'string') return null;

    // Each UTF-16 code unit contributes at least one UTF-8 byte. A longer string can
    // exceed the budget without measuring or encoding the rest of it.
    const sample = content.slice(0, maxBytes + 1);
    const sampleBytes = Buffer.byteLength(sample, 'utf8');
    const byteLength = sample.length === content.length ? sampleBytes : null;
    if (sampleBytes <= maxBytes) return { buffer: Buffer.from(sample, 'utf8'), byteLength };

    // Leave room for the character at the boundary so the result is a byte prefix.
    const scratch = Buffer.allocUnsafe(Math.min(sampleBytes, maxBytes + 3));
    const encodedBytes = scratch.write(sample, 0, scratch.length, 'utf8');
    return { buffer: scratch.subarray(0, Math.min(maxBytes, encodedBytes)), byteLength };
}

function bodyFormat(mimeType) {
    if (typeof mimeType !== 'string') return null;
    const [type, ...params] = mimeType.toLowerCase().split(';');
    if (params.some((param) => /^\s*charset\s*=/i.test(param) && !/^\s*charset\s*=\s*(?:utf-8|"utf-8")\s*$/i.test(param))) {
        return null;
    }
    const mediaType = type.trim();
    if (/^application\/(?:json|[a-z0-9][\w!#$&^.+-]*\+json)$/.test(mediaType)) return 'json';
    if (mediaType === 'application/x-www-form-urlencoded') return 'form';
    return null;
}

/** Derive the body format only when its captured declarations agree. */
export function shareableBodyFormat(record, mimeType) {
    if (!record || /^ws-/i.test(record.type || record.eventType || '')) return null;
    const types = [record.mimeType, mimeType].filter(Boolean);
    for (const [name, value] of Object.entries(record.headers || {})) {
        if (name.trim().toLowerCase() === 'content-type') types.push(value);
    }
    for (const header of Array.isArray(record.headersArray) ? record.headersArray : []) {
        if (String(header?.name).trim().toLowerCase() === 'content-type') types.push(header.value);
    }
    const format = bodyFormat(types[0]);
    return format && types.every((type) => bodyFormat(type) === format) ? format : null;
}

function projectField(name, value, form = false) {
    if (BOOLEAN_FIELDS.has(name)) {
        if (form && (value === 'true' || value === 'false')) return value === 'true';
        if (typeof value === 'boolean') return value;
    }
    if (COUNT_FIELDS.has(name)) {
        const count = form && /^(?:0|[1-9]\d*)$/.test(value) ? Number(value) : value;
        if (Number.isSafeInteger(count) && count >= 0) return count;
    }
    if (name === 'status' && typeof value === 'string' && STATUS_VALUES.has(value.toLowerCase())) {
        return value.toLowerCase();
    }
    return null;
}

function projectJson(value, depth = 0) {
    if (value === null || typeof value !== 'object' || depth >= 8) return null;
    if (Array.isArray(value)) {
        const entries = value.map((item) => projectJson(item, depth + 1)).filter((item) => item !== null);
        return entries.length ? entries : null;
    }
    const fields = [];
    for (const [name, item] of Object.entries(value)) {
        const field = JSON_CONTAINERS.has(name) ? projectJson(item, depth + 1) : projectField(name, item);
        if (field !== null) fields.push([name, field]);
    }
    return fields.length ? Object.fromEntries(fields) : null;
}

/** Project a complete UTF-8 body using only predefined diagnostic fields and value types. */
export function projectTrafficBody(content, format, maxBytes) {
    if (!format || (!Buffer.isBuffer(content) && typeof content !== 'string')) return null;
    const length = Buffer.byteLength(content);
    if (!length || length > maxBytes) return null;
    try {
        const text = Buffer.isBuffer(content) ? utf8.decode(content) : content;
        if (format === 'json') {
            const projected = projectJson(JSON.parse(text));
            return projected === null ? null : JSON.stringify(projected);
        }
        if (format !== 'form') return null;
        // URLSearchParams accepts broken percent escapes. Validate the encoding before parsing.
        decodeURIComponent(text.replace(/\+/g, ' '));
        const fields = new URLSearchParams();
        for (const [name, value] of new URLSearchParams(text)) {
            const projected = projectField(name, value, true);
            if (projected !== null) fields.append(name, String(projected));
        }
        return fields.toString() || null;
    } catch {
        return null;
    }
}
