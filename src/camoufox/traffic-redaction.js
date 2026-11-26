const SESSION_TOKEN_FIELD =
    '(?:x[-_]?)?(?:csrf|xsrf)(?:[-_]?token)?|passport[-_]?csrf[-_]?token|(?:x[-_]?)?guest[-_]?token|ct0|lsd|x-fb-lsd';

export const SENSITIVE_HEADER_REGEX = new RegExp(
    '^(?:cookie2?|set-cookie2?|authorization|proxy-authorization|x-proxy-authorization|x-api-key|omocaptcha-key|' +
    SESSION_TOKEN_FIELD + ')$', 'i'
);

export const SENSITIVE_URL_PARAM_REGEX = new RegExp(
    '^(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|session[_-]?(?:id|token)|' +
    'authorization[_-]?code|code|client[_-]?secret|password|passwd|pwd|secret|private[_-]?key|' +
    SESSION_TOKEN_FIELD + ')$', 'i'
);

const URL_HEADER_REGEX =
    /^(?::path|referer|referrer|origin|sec-websocket-origin|location|content-location|destination|.+[-_]ur[il])$/i;
const URL_METADATA_KEY_REGEX = /(?:url|uri|href|referrer|referer|location|origin|destination)$/i;
const AUTHORIZATION_HEADER_REGEX = /^(?:authorization|(?:x-)?proxy-authorization)$/i;
const MASK = '[REDACTED]';
const URL_REFERENCE_REGEX = /(?:[a-z][a-z\d+.-]{0,31}:\/\/|\/|\.\.?\/)[^\s"'<>()]+/gi;
const URL_VALUE_REGEX = /^(?:[a-z][a-z\d+.-]*:|\/|\.\.?\/|[?#])|^[^\s?#]+[?#][^#]*=/i;
const ENCODED_URL_SYNTAX_REGEX = /%(?:25)*(?:23|2f|3a|3d|3f|40)/i;
const MAX_URL_BYTES = 64 * 1024;
const MAX_NESTED_URL_DEPTH = 4;
const MAX_URL_DECODING_PASSES = 4;
const ACCOUNT_FIELD_REGEX =
    /^(?:(?:account[-_]?)?e[-_]?mail(?:[-_]?address)?|(?:account[-_]?)?user[-_]?name|(?:first|last|full|given|family|display|profile)[-_]?name)$/i;
// Start at a token boundary so a long ordinary value is scanned once.
const EMAIL_REGEX = /(?<![a-z\d._%+-])[a-z\d._%+-]+(?:@|%40)[a-z\d-]+(?:\.[a-z\d-]+)+/gi;
const LEGACY_PROFILE_REGEX = /\bGmail_[a-z\d._-]{1,80}?_(\d{13})(?:_(\d{1,8}))?(?![a-z\d_-])/gi;
const LEGACY_MASK_REGEX = /\[REDACTED:[a-f\d]{8}\]|%5BREDACTED%3A[a-f\d]{8}%5D/gi;
const PROXY_SCHEMES = new Set(['http', 'https', 'socks4', 'socks5', 'socks5h']);
const PROXY_HOST_PATTERN = String.raw`(\[[a-f\d:.]+\]|[^%/?#:@\\\s]+)`;
const PROXY_COMPACT_REGEX = new RegExp('^' + PROXY_HOST_PATTERN + ':[ \\t]*(\\d+)[ \\t]*:', 'i');
const PROXY_ENDPOINT_REGEX = new RegExp('^' + PROXY_HOST_PATTERN + '(?::(\\d+))?$', 'i');

function redactDiagnosticIdentity(text) {
    return text
        .replace(LEGACY_PROFILE_REGEX, (_, timestamp, suffix) => 'profile-legacy-' + timestamp + (suffix ? '-' + suffix : ''))
        .replace(EMAIL_REGEX, MASK);
}

export function redactProfileId(rawId) {
    return typeof rawId === 'string' ? redactDiagnosticIdentity(rawId) : rawId;
}

export function redactProxyUrl(proxyInput) {
    const descriptor = proxyInput && typeof proxyInput === 'object' ? proxyInput : null;
    const raw = typeof proxyInput === 'string' ? proxyInput : descriptor?.server || descriptor?.url;
    let address;
    let explicitPort;
    let protocol = 'http';
    if (typeof raw === 'string') {
        address = raw.trim();
        const prefix = /^([a-z][a-z\d+.-]*):\/\//i.exec(address);
        if (prefix) {
            protocol = prefix[1].toLowerCase();
            address = address.slice(prefix[0].length);
        }
        const compact = PROXY_COMPACT_REGEX.exec(address);
        [, address, explicitPort] = compact ||
            PROXY_ENDPOINT_REGEX.exec(address.split(/[/?#]/, 1)[0].split('@').at(-1)) || [];
    } else if (descriptor) {
        address = descriptor.ip || descriptor.host;
        if (typeof address !== 'string') return null;
        address = address.trim();
        if (!address.startsWith('[') && address.indexOf(':') !== address.lastIndexOf(':')) {
            address = '[' + address + ']';
        }
        [, address, explicitPort] = PROXY_ENDPOINT_REGEX.exec(address) || [];
        protocol = String(descriptor.type || descriptor.protocol || 'http').trim().toLowerCase().replace(/:\/\/$/, '');
    }
    if (!address || !PROXY_SCHEMES.has(protocol)) return null;

    const port = explicitPort ?? descriptor?.port;
    const portText = port == null ? null : String(port).trim();
    if (portText !== null && (!/^\d+$/.test(portText) || Number(portText) < 1 || Number(portText) > 65535)) return null;
    try {
        // Parse the validated host only. Userinfo and extra compact fields never reach the output.
        const host = new URL('http://' + address).hostname;
        return protocol + '://' + host + (portText === null ? '' : ':' + Number(portText));
    } catch {
        return null;
    }
}

function decodeParameter(raw) {
    try {
        return decodeURIComponent(raw.replace(/\+/g, '%20'));
    } catch {
        return raw;
    }
}

function exceedsUrlLimit(value) {
    return value.length > MAX_URL_BYTES || Buffer.byteLength(value, 'utf8') > MAX_URL_BYTES;
}

function redactUrlValue(raw, depth = 0) {
    let value = raw;
    for (let decodingPass = 0; decodingPass <= MAX_URL_DECODING_PASSES; decodingPass += 1) {
        if (URL_VALUE_REGEX.test(value.trim())) {
            if (depth > MAX_NESTED_URL_DEPTH) return MASK;

            const sanitized = redactUrl(value, depth);
            if (sanitized !== value) {
                try {
                    let encoded = sanitized;
                    for (let i = 0; i < decodingPass; i += 1) encoded = encodeURIComponent(encoded);
                    return encoded;
                } catch {
                    return MASK;
                }
            }
            if (/[?#]/.test(value) && value.includes('=')) return raw;
        }
        if (!ENCODED_URL_SYNTAX_REGEX.test(value)) return raw;
        if (exceedsUrlLimit(value)) return MASK;

        const decoded = decodeParameter(value);
        if (decoded === value) return MASK;
        value = decoded;
    }
    return MASK;
}

function redactParameters(parameters, depth) {
    if (!parameters.includes('=')) return parameters;
    return parameters.split('&').map((pair) => {
        const equals = pair.indexOf('=');
        if (equals <= 0) return pair;
        const name = pair.slice(0, equals);
        const decodedName = decodeParameter(name).trim();
        const value = SENSITIVE_URL_PARAM_REGEX.test(decodedName) ||
            SENSITIVE_HEADER_REGEX.test(decodedName) || ACCOUNT_FIELD_REGEX.test(decodedName)
            ? MASK
            : redactUrlValue(pair.slice(equals + 1), depth + 1);
        return name + '=' + value;
    }).join('&');
}

function redactUrl(value, depth) {
    if (exceedsUrlLimit(value)) return MASK;
    const opaqueUrl = /^(\s*(?:data|javascript):)/i.exec(value);
    if (opaqueUrl) return opaqueUrl[1] + MASK;

    // Strip userinfo while preserving the original form of absolute and relative references.
    const url = redactDiagnosticIdentity(value.replace(/^(\s*(?:[a-z][a-z\d+.-]*:)?\/\/)[^/?#]*@/i, '$1'))
        .replace(LEGACY_MASK_REGEX, MASK);
    const fragmentStart = url.indexOf('#');
    const beforeFragment = fragmentStart < 0 ? url : url.slice(0, fragmentStart);
    const queryStart = beforeFragment.indexOf('?');
    const base = queryStart < 0
        ? beforeFragment
        : beforeFragment.slice(0, queryStart + 1) + redactParameters(beforeFragment.slice(queryStart + 1), depth);
    if (fragmentStart < 0) return exceedsUrlLimit(base) ? MASK : base;

    const fragment = url.slice(fragmentStart + 1);
    const fragmentQueryStart = fragment.indexOf('?');
    const sanitizedFragment = fragmentQueryStart < 0
        ? redactParameters(fragment, depth)
        : fragment.slice(0, fragmentQueryStart + 1) + redactParameters(fragment.slice(fragmentQueryStart + 1), depth);
    const result = base + '#' + sanitizedFragment;
    return exceedsUrlLimit(result) ? MASK : result;
}

export function redactUrlSecrets(rawUrl) {
    const value = String(rawUrl ?? '');
    if (exceedsUrlLimit(value)) return MASK;
    if (URL_VALUE_REGEX.test(value.trim())) return redactUrl(value, 0);
    return redactUrl(redactUrlValue(value), 0);
}

function redactCredentialHeader(name, value) {
    // Keep only a recognized authentication scheme, never an arbitrary first word.
    const scheme = AUTHORIZATION_HEADER_REGEX.test(name)
        ? /^\s*(Basic|Bearer|Digest|Negotiate|NTLM|AWS4-HMAC-SHA256)(?:\s|$)/i.exec(value)?.[1]
        : null;
    return scheme ? `${scheme} ${MASK}` : MASK;
}

export function redactDiagnosticText(rawText) {
    const cleaned = String(rawText ?? '')
        .replace(/^([ \t]*)([\w-]+):[ \t]*([^\r\n]*)(?:\r?\n[ \t][^\r\n]*)*/gm,
            (line, indent, name, value) => SENSITIVE_HEADER_REGEX.test(name)
                ? `${indent}${name}: ${redactCredentialHeader(name, value)}`
                : line)
        .replace(URL_REFERENCE_REGEX, redactUrlSecrets)
        .replace(LEGACY_MASK_REGEX, MASK);
    return redactDiagnosticIdentity(cleaned);
}

function redactHeaderValue(rawName, rawValue) {
    const name = rawName.trim();
    const value = String(rawValue ?? '');
    if (SENSITIVE_HEADER_REGEX.test(name)) return redactCredentialHeader(name, value);
    if (/^link$/i.test(name)) return value.replace(/<([^>]+)>/g, (_, url) => `<${redactUrlSecrets(url)}>`);
    if (/^refresh$/i.test(name)) {
        return value.replace(/(\burl\s*=\s*)(?:(['"])(.*?)\2|(.*))$/i,
            (_, prefix, quote, quotedUrl, unquotedUrl) =>
                `${prefix}${quote ?? ''}${redactUrlSecrets(quotedUrl ?? unquotedUrl)}${quote ?? ''}`);
    }
    if (URL_HEADER_REGEX.test(name)) return value.split(/(\r?\n)/).map(redactUrlSecrets).join('');
    return redactDiagnosticText(value);
}

/** Redact both header representations without collapsing duplicates or changing their order. */
export function redactSensitiveHeaders({ headers = {}, headersArray = [] } = {}) {
    return {
        headers: Object.fromEntries(Object.entries(headers || {}).map(([name, value]) => [
            name, redactHeaderValue(name, value)
        ])),
        headersArray: Array.isArray(headersArray)
            ? headersArray.map((entry) => {
                const name = String(entry?.name ?? '');
                return { name, value: redactHeaderValue(name, entry?.value) };
            })
            : []
    };
}

export function redactDiagnosticMetadata(metadata) {
    const visited = new WeakSet();
    const copy = (value, key = '') => {
        if (value == null) return value;
        if (/^proxy(?:server|url)?$/i.test(key)) return redactProxyUrl(value);
        if (/^profile[-_]?id$/i.test(key) && typeof value === 'string') return redactProfileId(value);
        if (/^account[-_]?email$/i.test(key)) return null;
        if (/^account[-_]?id$/i.test(key) && !Number.isSafeInteger(value)) return MASK;
        if (SENSITIVE_HEADER_REGEX.test(key) || SENSITIVE_URL_PARAM_REGEX.test(key) ||
            ACCOUNT_FIELD_REGEX.test(key) || /^cookies$/i.test(key)) {
            return MASK;
        }
        if (/^headersArray$/i.test(key) && Array.isArray(value)) {
            return Object.freeze(redactSensitiveHeaders({ headersArray: value }).headersArray.map(Object.freeze));
        }
        if (typeof value === 'string') {
            if (URL_METADATA_KEY_REGEX.test(key) || /^search$/i.test(key)) {
                return redactUrlSecrets(redactUrlValue(value));
            }
            return redactDiagnosticText(value);
        }
        if (typeof value !== 'object') return value;
        if (value instanceof Date) return value.toJSON();
        if (visited.has(value)) return null;

        visited.add(value);
        const sensitiveSignature = typeof value.signatureName === 'string' &&
            (value.location === 'body' || SENSITIVE_URL_PARAM_REGEX.test(value.signatureName));
        const copyEntry = ([name, item]) => {
            if (sensitiveSignature) {
                if (name === 'maskedPreview') return [name, MASK];
                if (/^(?:rawValue|value|valueLength|valueSha256)$/.test(name)) return [name, null];
            }
            if (/^searchParams$/i.test(key)) {
                const sanitize = (param) => copy(typeof param === 'string' ? redactUrlValue(param, 1) : param, name);
                return [name, Array.isArray(item) ? Object.freeze(item.map(sanitize)) : sanitize(item)];
            }
            return [name, copy(item, name)];
        };
        const sanitized = Array.isArray(value)
            ? value.map((item) => copy(item, key))
            : Object.fromEntries(Object.entries(value).map(copyEntry));
        visited.delete(value);
        return Object.freeze(sanitized);
    };
    return metadata && typeof metadata === 'object' ? copy(metadata) : {};
}

const RECORDED_CONTROL_KEYS = new Set([
    'Alt', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'Backspace', 'Control', 'Delete',
    'End', 'Enter', 'Escape', 'Home', 'Insert', 'Meta', 'PageDown', 'PageUp', 'Shift', 'Tab'
]);

export function recordedControlKey(value) {
    return RECORDED_CONTROL_KEYS.has(value) ? value : undefined;
}

export function redactPressKeys(record) {
    if (!record || !/(?:^|\.)press$/i.test(record.actionType ?? record.type)) return record;
    const { key, ...safe } = record;
    const controlKey = recordedControlKey(key);
    if (controlKey !== undefined) safe.key = controlKey;

    if (safe.metadata && Object.hasOwn(safe.metadata, 'key')) {
        const { key: metadataKey, ...metadata } = safe.metadata;
        const metadataControlKey = recordedControlKey(metadataKey);
        if (metadataControlKey !== undefined) metadata.key = metadataControlKey;
        safe.metadata = metadata;
    }
    return safe;
}

export function redactTriggerAction(trigger) {
    if (!trigger) return null;
    trigger = redactPressKeys(trigger);
    const actionType = trigger.actionType ?? trigger.type;
    const isNavigation = /(?:^|\.)goto$/i.test(actionType) || /^security\./i.test(actionType);
    const redactTarget = (value) => value
        ? (isNavigation ? redactUrlSecrets(value) : redactDiagnosticText(value))
        : null;
    return {
        ...trigger,
        target: redactTarget(trigger.target ?? trigger.selector),
        ...(trigger.selector !== undefined ? { selector: redactTarget(trigger.selector) } : {}),
        metadata: redactDiagnosticMetadata(trigger.metadata)
    };
}
