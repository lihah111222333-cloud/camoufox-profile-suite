import { parseProxyAddress } from '../utils/proxy-protocol.js';

const SESSION_TOKEN_FIELD =
    '(?:x[-_]?)?(?:csrf|xsrf)(?:[-_]?token)?|passport[-_]?csrf[-_]?token|(?:x[-_]?)?guest[-_]?token|ct0|lsd|x-fb-lsd';
const AUTHORIZATION_HEADER = '(?:x-)?(?:proxy-)?authorization';
const CREDENTIAL_FIELD =
    '(?:x[-_]?)?(?:(?:(?:auth(?:entication|orization)?|access|refresh|id|session|security|' +
    'api|bearer|client|user|private|job|deploy)[-_]?)?token|(?:api|auth|access|subscription)[-_]?key|client[-_]?(?:secret|assertion)|code[-_]?verifier)';
const SIGNATURE_FIELD = '(?:x[-_]?)?sig(?:nature)?|hmac';
const CLOUD_SIGNATURE_FIELD =
    'x[-_](?:amz|goog|oss)[-_](?:signature|credential|security[-_]token)|x-amz-s3session-token';
const CLOUDFRONT_KEY_ID = 'key-pair-id';
const PRIVATE_PLATFORM_FIELD =
    'mstoken|verifyfp|s_v_web_id|odin_tt|ttwid|x-ig-www-claim|fc[-_]token|cf-turnstile-response';

const SENSITIVE_HEADER_NAME =
    '(?:cookie2?|set-cookie2?|(?:proxy-)?authentication-info|(?:x-)?authentication|x-auth|(?:x-)?session-id|' +
    AUTHORIZATION_HEADER + '|' +
    'omocaptcha-key|x-goog-api-key|x-rapidapi-key|ocp-apim-subscription-key|x-auth-request-access-token|' +
    'x-(?:shopify-access|vault)-token|cf-access-(?:jwt-assertion|client-secret)|' +
    CREDENTIAL_FIELD + '|' + SIGNATURE_FIELD + '|' + CLOUD_SIGNATURE_FIELD + '|' + SESSION_TOKEN_FIELD + '|' +
    PRIVATE_PLATFORM_FIELD + ')';
export const SENSITIVE_HEADER_REGEX = new RegExp('^' + SENSITIVE_HEADER_NAME + '$', 'i');
const DIAGNOSTIC_CREDENTIAL_HEADER_REGEX = new RegExp(
    '^([ \\t]*)(' + SENSITIVE_HEADER_NAME + '):[ \\t]*([^\\r\\n]*(?:\\r?\\n[ \\t][^\\r\\n]*)*)', 'gmi'
);

export const SENSITIVE_URL_PARAM_REGEX = new RegExp(
    '^(?:session[_-]?id|authorization[_-]?code|code|password|passwd|pwd|secret|private[_-]?key|' +
    '(?:aws|oss)?access[-_]?key[-_]?id|googleaccessid|' + CLOUDFRONT_KEY_ID + '|' +
    CREDENTIAL_FIELD + '|' + SIGNATURE_FIELD + '|' + CLOUD_SIGNATURE_FIELD + '|' +
    SESSION_TOKEN_FIELD + '|' + PRIVATE_PLATFORM_FIELD + ')$', 'i'
);

const URL_HEADER_REGEX =
    /^(?::path|referer|referrer|origin|sec-websocket-origin|location|content-location|destination|.+[-_]ur[il])$/i;
const URL_METADATA_KEY_REGEX = /(?:url|uri|href|referrer|referer|location|origin|destination)$/i;
const AUTHORIZATION_HEADER_REGEX = new RegExp('^' + AUTHORIZATION_HEADER + '$', 'i');
const INLINE_AUTHORIZATION_REGEX = new RegExp(
    '([ \\t([{,;])(' + AUTHORIZATION_HEADER + '):[ \\t]*(' +
    String.raw`(?:\[REDACTED\]|"(?:\\[^\r\n]|[^"\\\r\n])*(?:"|(?=\r?\n|$))|'(?:\\[^\r\n]|[^'\\\r\n])*(?:'|(?=\r?\n|$))|[^\r\n)\]}"'])*)`,
    'gi'
);
const ABSOLUTE_FILE_PATH_PREFIX = String.raw`(?:[a-z]:[\\/]|\\\\|\/(?!\/))`;
const DIAGNOSTIC_FILE_PATH_REGEX = new RegExp(
    String.raw`(\b(?:access|chmod|chown|copyfile|directory|file|lstat|mkdir|open|path|read(?:file|link)?|realpath|rename|rmdir|scandir|stat|symlink|unlink|write(?:file)?)[ \t]+|[ \t]+->[ \t]+)` +
    '(?:(["\'])' + ABSOLUTE_FILE_PATH_PREFIX + String.raw`[^\r\n]*?(?:\2|(?=\r?\n|$))|` +
    ABSOLUTE_FILE_PATH_PREFIX + String.raw`[^\s"'<>()[\]{},;]+)`, 'gi'
);
const LINK_HEADER_REGEX = /^link$/i;
const REFRESH_HEADER_REGEX = /^refresh$/i;
const LINK_COMPONENT_REGEX =
    /<([^<>]*)>|(;\s*[-\w!#$%&'*+.^`|~]+\s*=\s*)(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|([^;,\s]+))/g;
const MASK = '[REDACTED]';
const PRIVATE_URL_SCHEME = '(?:(?:blob|filesystem|view-source|jar):){0,4}(?:data|javascript|file):';
const PRIVATE_URL_PREFIX_REGEX = new RegExp('^(\\s*' + PRIVATE_URL_SCHEME + ')', 'i');
const QUOTED_PRIVATE_URL_REGEX = new RegExp('(["\'])(' + PRIVATE_URL_SCHEME + '[^\\r\\n]*?)\\1', 'gi');
const URL_REFERENCE_REGEX = new RegExp(
    '(?:\\b(?:' + PRIVATE_URL_SCHEME + '|[a-z][a-z\\d+.-]{0,31}://)|\\.\\.?/|/)[^\\s"\'<>]+', 'gi'
);
const PRIVATE_URL_COMPONENTS = Object.freeze({
    host: 'unknown',
    hostname: 'unknown',
    port: null,
    pathname: MASK,
    search: '',
    searchParams: Object.freeze({})
});
const URL_VALUE_REGEX = /^(?:[a-z][a-z\d+.-]*:|\/|\.\.?\/|[?#])|^[^\s?#]+[?#][^#]*=/i;
const ENCODED_URL_SYNTAX_REGEX = /%(?:25)*(?:23|2f|3a|3d|3f|40)/i;
const ENCODED_EMAIL_SYNTAX_REGEX = /@[^@\s]*%/;
const MAX_URL_BYTES = 64 * 1024;
const MAX_NESTED_URL_DEPTH = 4;
const MAX_URL_DECODING_PASSES = 4;
const ACCOUNT_FIELD_REGEX = new RegExp(
    '^(?:(?:(?:account|recovery)[-_]?)?e[-_]?mail(?:[-_]?address)?|(?:account[-_]?)?user[-_]?name|' +
    '(?:first|last|full|given|family|display|profile)[-_]?name|' +
    '(?:(?:account|recovery)[-_]?)?(?:phone(?:[-_]?number)?|mobile[-_]?number)|' +
    'birth[-_]?(?:date|day)|date[-_]?of[-_]?birth)$', 'i'
);
// Start at a token boundary so a long ordinary value is scanned once.
const EMAIL_REGEX =
    /(?<![\p{L}\p{N}\p{M}._%+-])[\p{L}\p{N}\p{M}._%+-]+(?:@|%40)[\p{L}\p{N}\p{M}-]+(?:\.[\p{L}\p{N}\p{M}-]+)+/giu;
const LEGACY_PROFILE_REGEX = /\bGmail_[a-z\d._-]{1,80}?_(\d{13})(?:_(\d{1,8}))?(?![a-z\d_-])/gi;
const LEGACY_MASK_REGEX = /\[REDACTED:[a-f\d]{8}\]|%5BREDACTED%3A[a-f\d]{8}%5D/gi;
const PROXY_SCHEMES = new Set(['http', 'https', 'socks4', 'socks5', 'socks5h']);
const PROXY_HOST_PATTERN = String.raw`(\[[a-f\d:.]+\]|[^%/?#:@\\\s]+)`;
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
        const endpoint = parseProxyAddress(raw, { endpointOnly: true });
        if (!endpoint) return null;
        ({ ip: address, port: explicitPort, type: protocol } = endpoint);
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
        const isUrl = URL_VALUE_REGEX.test(value.trim());
        if (isUrl && depth > MAX_NESTED_URL_DEPTH) return MASK;

        const sanitized = isUrl ? redactUrl(value, depth) : redactDiagnosticIdentity(value);
        if (sanitized !== value) {
            try {
                let encoded = sanitized;
                for (let i = 0; i < decodingPass; i += 1) encoded = encodeURIComponent(encoded);
                return encoded;
            } catch {
                return MASK;
            }
        }
        if (isUrl && /[?#]/.test(value) && value.includes('=')) return raw;
        if (!ENCODED_URL_SYNTAX_REGEX.test(value) && !ENCODED_EMAIL_SYNTAX_REGEX.test(value)) return raw;
        if (exceedsUrlLimit(value)) return MASK;

        const decoded = decodeParameter(value);
        if (decoded === value) return MASK;
        value = decoded;
    }
    return MASK;
}

function redactParameters(parameters, depth) {
    if (!parameters.includes('=')) return parameters;
    const pairs = parameters.split('&').map((pair) => {
        const equals = pair.indexOf('=');
        const decodedName = equals > 0 ? decodeParameter(pair.slice(0, equals)).trim() : '';
        return { pair, equals, decodedName };
    });
    const hasCloudFrontKey = pairs.some(({ decodedName }) => decodedName.toLowerCase() === CLOUDFRONT_KEY_ID);
    return pairs.map(({ pair, equals, decodedName }) => {
        if (equals <= 0) return pair;
        const value = SENSITIVE_URL_PARAM_REGEX.test(decodedName) ||
            SENSITIVE_HEADER_REGEX.test(decodedName) || ACCOUNT_FIELD_REGEX.test(decodedName) ||
            (hasCloudFrontKey && /^policy$/i.test(decodedName))
            ? MASK
            : redactUrlValue(pair.slice(equals + 1), depth + 1);
        return pair.slice(0, equals + 1) + value;
    }).join('&');
}

function redactUrlPathIdentity(path) {
    if (!path.includes('%')) return redactDiagnosticIdentity(path);
    return path.split('/').map((segment) => {
        let decoded = segment;
        for (let pass = 0; pass < MAX_URL_DECODING_PASSES && decoded.includes('%'); pass += 1) {
            try {
                decoded = decodeURIComponent(decoded);
            } catch {
                break;
            }
            if (redactDiagnosticIdentity(decoded) !== decoded) return MASK;
        }
        return redactDiagnosticIdentity(segment);
    }).join('/');
}

function redactUrl(value, depth) {
    if (exceedsUrlLimit(value)) return MASK;
    const privateUrl = PRIVATE_URL_PREFIX_REGEX.exec(value);
    if (privateUrl) return privateUrl[1] + MASK;

    // Strip userinfo while preserving the original form of absolute and relative references.
    const url = value.replace(/^(\s*(?:[a-z][a-z\d+.-]*:)?\/\/)[^/?#]*@/i, '$1')
        .replace(LEGACY_MASK_REGEX, MASK);
    const fragmentStart = url.indexOf('#');
    const beforeFragment = fragmentStart < 0 ? url : url.slice(0, fragmentStart);
    const queryStart = beforeFragment.indexOf('?');
    const base = queryStart < 0
        ? redactUrlPathIdentity(beforeFragment)
        : redactUrlPathIdentity(beforeFragment.slice(0, queryStart)) + '?' +
            redactParameters(redactDiagnosticIdentity(beforeFragment.slice(queryStart + 1)), depth);
    if (fragmentStart < 0) return exceedsUrlLimit(base) ? MASK : base;

    const fragment = redactDiagnosticIdentity(url.slice(fragmentStart + 1));
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

function redactLinkHeader(value) {
    return value.replace(LINK_COMPONENT_REGEX, (component, reference, prefix, doubleQuoted, singleQuoted, token) => {
        if (reference !== undefined) return '<' + redactUrlSecrets(reference) + '>';

        const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : '';
        const parameter = quote ? (doubleQuoted ?? singleQuoted).replace(/\\([^\r\n])/g, '$1') : token;
        const projected = parameter.replace(/\S+/g, redactUrlSecrets);
        if (projected === parameter) return component;

        const formatted = quote ? projected.replace(/\\/g, '\\\\').replaceAll(quote, '\\' + quote) : projected;
        return prefix + quote + formatted + quote;
    });
}

function redactUrlReference(reference) {
    // Closing parentheses from surrounding prose can follow a URL with balanced parentheses of its own.
    let parenthesisEnd = reference.length;
    while (parenthesisEnd > 0 && '.,;:!?'.includes(reference[parenthesisEnd - 1])) parenthesisEnd -= 1;
    let parenthesisStart = parenthesisEnd;
    while (parenthesisStart > 0 && reference[parenthesisStart - 1] === ')') parenthesisStart -= 1;
    if (parenthesisStart === parenthesisEnd) return redactUrlSecrets(reference);

    let openParentheses = 0;
    for (let i = 0; i < parenthesisStart; i += 1) {
        if (reference[i] === '(') openParentheses += 1;
        else if (reference[i] === ')' && openParentheses > 0) openParentheses -= 1;
    }
    if (openParentheses >= parenthesisEnd - parenthesisStart) return redactUrlSecrets(reference);

    const end = parenthesisStart + openParentheses;
    return redactUrlSecrets(reference.slice(0, end)) + reference.slice(end);
}

export function redactDiagnosticText(rawText) {
    const cleaned = String(rawText ?? '')
        .replace(DIAGNOSTIC_CREDENTIAL_HEADER_REGEX,
            (_, indent, name, value) => indent + name + ': ' + redactCredentialHeader(name, value))
        .replace(/^([ \t]*)(:?[\w-]+)(:[ \t]*)([^\r\n]*(?:\r?\n(?![ \t]+:?[\w-]+:)[ \t]+[^\r\n]*)*)/gm,
            (line, indent, name, separator, value) => {
                if (LINK_HEADER_REGEX.test(name) || URL_HEADER_REGEX.test(name) || REFRESH_HEADER_REGEX.test(name)) {
                    return indent + name + separator + redactHeaderValue(name, value);
                }
                return line;
            })
        .replace(INLINE_AUTHORIZATION_REGEX,
            (_, prefix, name, value) => prefix + name + ': ' + redactCredentialHeader(name, value))
        .replace(DIAGNOSTIC_FILE_PATH_REGEX,
            (_, prefix, quote = '') => prefix + quote + MASK + quote)
        .replace(QUOTED_PRIVATE_URL_REGEX, (_, quote, url) => quote + redactUrlSecrets(url) + quote)
        .replace(URL_REFERENCE_REGEX, redactUrlReference)
        .replace(LEGACY_MASK_REGEX, MASK);
    return redactDiagnosticIdentity(cleaned);
}

function redactHeaderValue(rawName, rawValue) {
    const name = rawName.trim();
    const value = String(rawValue ?? '');
    if (SENSITIVE_HEADER_REGEX.test(name)) return redactCredentialHeader(name, value);
    if (LINK_HEADER_REGEX.test(name)) return redactLinkHeader(value);
    if (REFRESH_HEADER_REGEX.test(name)) {
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
        if (/^headers$/i.test(key) && typeof value === 'object' && !Array.isArray(value)) {
            return Object.freeze(redactSensitiveHeaders({ headers: value }).headers);
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
            (value.location === 'body' || SENSITIVE_URL_PARAM_REGEX.test(value.signatureName) ||
                SENSITIVE_HEADER_REGEX.test(value.signatureName));
        const url = value.url ?? value.targetUrl;
        const privateUrl = typeof url === 'string' && PRIVATE_URL_PREFIX_REGEX.test(url);
        const searchParams = /^searchParams$/i.test(key);
        const hasCloudFrontKey = searchParams && Object.keys(value)
            .some(name => name.trim().toLowerCase() === CLOUDFRONT_KEY_ID);
        const copyEntry = ([name, item]) => {
            if (privateUrl && Object.hasOwn(PRIVATE_URL_COMPONENTS, name)) {
                return [name, PRIVATE_URL_COMPONENTS[name]];
            }
            if (sensitiveSignature) {
                if (name === 'maskedPreview') return [name, MASK];
                if (/^(?:rawValue|value|valueLength|valueSha256)$/.test(name)) return [name, null];
            }
            if (searchParams) {
                const parameterName = name.trim();
                const sanitize = (param) => hasCloudFrontKey && /^policy$/i.test(parameterName)
                    ? MASK
                    : copy(typeof param === 'string' ? redactUrlValue(param, 1) : param, parameterName);
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
