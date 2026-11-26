import crypto from 'node:crypto';

export const SENSITIVE_HEADER_REGEX =
    /^(cookie2?|set-cookie2?|authorization|proxy-authorization|x-proxy-authorization|x-api-key|omocaptcha-key)$/i;

export const SENSITIVE_URL_PARAM_REGEX =
    /^(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|session[_-]?(?:id|token)|authorization[_-]?code|code|client[_-]?secret|password|passwd|pwd|secret|private[_-]?key)$/i;

const URL_HEADER_REGEX =
    /^(?::path|referer|referrer|origin|sec-websocket-origin|location|content-location|destination|.+[-_]ur[il])$/i;
const URL_METADATA_KEY_REGEX = /(?:url|uri|href|referrer|referer|location|origin|destination)$/i;
const AUTHORIZATION_HEADER_REGEX = /^(?:authorization|(?:x-)?proxy-authorization)$/i;
const MASK = '[REDACTED]';
const URL_REFERENCE_REGEX = /(?:[a-z][a-z\d+.-]{0,31}:\/\/|\/|\.\.?\/)[^\s"'<>()]+/gi;

function decodeParameter(raw) {
    try {
        return decodeURIComponent(raw.replace(/\+/g, '%20'));
    } catch {
        return raw;
    }
}

function redactParameters(parameters) {
    if (!parameters.includes('=')) return parameters;

    return parameters.split('&').map((pair) => {
        const equals = pair.indexOf('=');
        if (equals <= 0) return pair;
        const name = pair.slice(0, equals);
        if (!SENSITIVE_URL_PARAM_REGEX.test(decodeParameter(name))) return pair;

        const value = decodeParameter(pair.slice(equals + 1));
        const mask = /^\[REDACTED(?::[0-9a-f]{8})?\]$/i.test(value)
            ? value
            : `[REDACTED:${crypto.createHash('sha256').update(value).digest('hex').slice(0, 8)}]`;
        return `${name}=${mask}`;
    }).join('&');
}

export function redactUrlSecrets(rawUrl) {
    const value = String(rawUrl ?? '');
    const opaqueUrl = /^(\s*(?:data|javascript):)/i.exec(value);
    if (opaqueUrl) return `${opaqueUrl[1]}${MASK}`;

    // Strip userinfo while preserving the original form of absolute and relative references.
    const url = value.replace(/^(\s*(?:[a-z][a-z\d+.-]*:)?\/\/)[^/?#]*@/i, '$1');
    const fragmentStart = url.indexOf('#');
    const beforeFragment = fragmentStart < 0 ? url : url.slice(0, fragmentStart);
    const queryStart = beforeFragment.indexOf('?');
    const base = queryStart < 0
        ? beforeFragment
        : `${beforeFragment.slice(0, queryStart + 1)}${redactParameters(beforeFragment.slice(queryStart + 1))}`;
    if (fragmentStart < 0) return base;

    const fragment = url.slice(fragmentStart + 1);
    const fragmentQueryStart = fragment.indexOf('?');
    const sanitizedFragment = fragmentQueryStart < 0
        ? redactParameters(fragment)
        : `${fragment.slice(0, fragmentQueryStart + 1)}${redactParameters(fragment.slice(fragmentQueryStart + 1))}`;
    return `${base}#${sanitizedFragment}`;
}

function redactCredentialHeader(name, value) {
    // Keep only a recognized authentication scheme, never an arbitrary first word.
    const scheme = AUTHORIZATION_HEADER_REGEX.test(name)
        ? /^\s*(Basic|Bearer|Digest|Negotiate|NTLM|AWS4-HMAC-SHA256)(?:\s|$)/i.exec(value)?.[1]
        : null;
    return scheme ? `${scheme} ${MASK}` : MASK;
}

export function redactDiagnosticText(rawText) {
    return String(rawText ?? '')
        .replace(/^([ \t]*)([\w-]+):[ \t]*([^\r\n]*)(?:\r?\n[ \t][^\r\n]*)*/gm,
            (line, indent, name, value) => SENSITIVE_HEADER_REGEX.test(name)
                ? `${indent}${name}: ${redactCredentialHeader(name, value)}`
                : line)
        .replace(URL_REFERENCE_REGEX, redactUrlSecrets);
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
        if (SENSITIVE_HEADER_REGEX.test(key) || SENSITIVE_URL_PARAM_REGEX.test(key) || /^cookies$/i.test(key)) {
            return MASK;
        }
        if (/^headersArray$/i.test(key) && Array.isArray(value)) {
            return Object.freeze(redactSensitiveHeaders({ headersArray: value }).headersArray.map(Object.freeze));
        }
        if (typeof value === 'string') {
            return URL_METADATA_KEY_REGEX.test(key) ? redactUrlSecrets(value) : redactDiagnosticText(value);
        }
        if (typeof value !== 'object') return value;
        if (value instanceof Date) return value.toJSON();
        if (visited.has(value)) return null;

        visited.add(value);
        const sanitized = Array.isArray(value)
            ? value.map((item) => copy(item, key))
            : Object.fromEntries(Object.entries(value).map(([name, item]) => [name, copy(item, name)]));
        visited.delete(value);
        return Object.freeze(sanitized);
    };
    return metadata && typeof metadata === 'object' ? copy(metadata) : {};
}

export function redactTriggerAction(trigger) {
    if (!trigger) return null;
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
