const PROXY_SCHEME = /^([a-z][a-z0-9+.-]*):\/\//i;

export function formatProxyHost(value) {
    if (typeof value !== 'string') return null;
    const host = value.trim();
    if (!host || /[\s\u0000-\u001f\u007f\\/?#@%]/.test(host)) return null;
    const address = host.includes(':') && !host.startsWith('[') ? '[' + host + ']' : host;
    try {
        new URL('http://' + address);
        return address;
    } catch {
        return null;
    }
}

export function parseProxyPort(value) {
    const port = String(value ?? '').trim();
    const number = Number(port);
    return /^\d+$/.test(port) && number >= 1 && number <= 65535 ? String(number) : null;
}

function splitCompactAddress(input) {
    const hostEnd = input.startsWith('[') ? input.indexOf(']') + 1 : input.indexOf(':');
    if (hostEnd <= 0 || input[hostEnd] !== ':') return null;
    const ip = formatProxyHost(input.slice(0, hostEnd));
    const [rawPort, ...credentials] = input.slice(hostEnd + 1).split(':');
    const port = parseProxyPort(rawPort);
    return ip && port ? { ip, port, credentials } : null;
}

function parseAuthority(input) {
    const endpoint = splitCompactAddress(input);
    if (endpoint?.credentials.length === 0) return { ip: endpoint.ip, port: endpoint.port };
    const ip = formatProxyHost(input);
    return ip ? { ip, port: null } : null;
}

export function parseProxyAddress(value, { endpointOnly = false } = {}) {
    if (typeof value !== 'string') return null;
    const line = value.trim();
    if (!line || line.startsWith('#')) return null;

    const scheme = PROXY_SCHEME.exec(line);
    const type = scheme?.[1].toLowerCase() ?? 'http';
    const rest = scheme ? line.slice(scheme[0].length).trim() : line;
    const compact = splitCompactAddress(rest);
    const lastAt = rest.lastIndexOf('@');

    // A bracketed compact host cannot be unescaped URL userinfo.
    if (lastAt !== -1 && !compact?.ip.startsWith('[')) {
        const tail = rest.slice(lastAt + 1);
        const [authority] = tail.split(/[/?#\\]/, 1);
        const destination = parseAuthority(authority);
        if (destination && (destination.port || scheme || endpointOnly || !compact)) {
            // Find the competing authority before rejecting a URL suffix. A
            // path on an invalid configuration must not select the other host.
            if (compact) return null;
            if (endpointOnly) return { ...destination, type };
            if (!destination.port || tail.replace(/\/+$/, '') !== authority) return null;

            try {
                const [username, ...password] = rest.slice(0, lastAt).split(':');
                return {
                    ...destination,
                    username: decodeURIComponent(username).trim(),
                    password: decodeURIComponent(password.join(':')).trim(),
                    type,
                    raw: scheme ? line : 'http://' + line
                };
            } catch {
                return null;
            }
        }
    }

    const authority = endpointOnly ? rest.split(/[/?#\\]/, 1)[0] : rest.replace(/\/+$/, '');
    const endpoint = compact ?? (scheme || endpointOnly ? parseAuthority(authority) : null);
    if (!endpoint) return null;
    const { ip, port, credentials: [username = '', ...password] = [] } = endpoint;
    if (endpointOnly) return { ip, port, type };
    if (!port) return null;
    return { ip, port, username: username.trim(), password: password.join(':').trim(), type, raw: line };
}

export function requireProxyProtocol(proxy, supported, provider) {
    const protocols = new Set();
    for (const value of [proxy.type, proxy.protocol, proxy.mode]) {
        if (value == null || value === '') continue;
        if (typeof value !== 'string') throw new Error('Invalid proxy protocol');
        protocols.add(value.trim().toLowerCase());
    }
    if (protocols.size > 1) throw new Error('Conflicting proxy protocols');

    const [protocol = 'http'] = protocols;
    if (!supported.includes(protocol)) {
        const message = protocol === 'https' ? 'HTTPS proxies' : 'the configured proxy protocol';
        throw new Error(`${provider} does not support ${message}`);
    }
    return protocol;
}
