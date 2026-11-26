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
