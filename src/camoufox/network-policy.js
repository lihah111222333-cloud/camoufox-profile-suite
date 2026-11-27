import { loadApplicationEnvironment } from '../utils/private-env.js';

const managedBindings = new WeakSet();

function managedEgressError(message) {
    const error = new Error(message);
    error.code = 'ERR_CAMOUFOX_MANAGED_EGRESS_BINDING';
    return error;
}

export function resolveNetworkPolicyMode(...policies) {
    const modes = new Set(policies.map((policy) => policy?.mode).filter((mode) => mode !== undefined));
    for (const mode of modes) {
        if (mode !== 'url-only' && mode !== 'managed-proxy' && mode !== 'transport') {
            throw new TypeError("portScanProtection.mode must be 'url-only', 'managed-proxy', or 'transport'.");
        }
    }
    if (modes.has('transport')) {
        const error = new Error('Verified private-network isolation requires evidence of the destination IP policy.');
        error.code = 'ERR_CAMOUFOX_NETWORK_BOUNDARY_UNAVAILABLE';
        throw error;
    }
    if (modes.has('managed-proxy') && modes.has('url-only')) {
        throw managedEgressError('Conflicting Camoufox managed-proxy and URL-only policies.');
    }
    return modes.has('managed-proxy') ? 'managed-proxy' : 'url-only';
}

export function resolveConfiguredNetworkPolicyMode(...policies) {
    const { CAMOUFOX_PORT_SCAN_MODE: mode } = loadApplicationEnvironment();
    const configuredRestriction = mode !== undefined && mode !== 'url-only' ? { mode } : undefined;
    return resolveNetworkPolicyMode(configuredRestriction, ...policies);
}

function parseProxyOrigin(value) {
    if (typeof value !== 'string') return null;
    const match = /^(https?|socks5):\/\/(\[[0-9a-f:.]+\]|[a-z0-9.-]+):(\d+)\/?$/i.exec(value);
    if (!match) return null;
    const port = Number(match[3]);
    if (port < 1 || port > 65535) return null;
    try {
        const { protocol, hostname } = new URL(value);
        return protocol + '//' + hostname.toLowerCase() + ':' + port;
    } catch {
        return null;
    }
}

function hasProxyPreferenceOverride(preferences) {
    return Object.keys(preferences || {}).some(
        (key) => key.startsWith('network.proxy.') || key.startsWith('general.config.')
    );
}

function hasProxyEnvironmentOverride(env) {
    return Object.keys(env || {}).some((name) => /^(https?_proxy|all_proxy|no_proxy)$/i.test(name));
}

export function assertManagedProxyLaunchEnvironment(env) {
    if (hasProxyEnvironmentOverride(env)) {
        throw managedEgressError('Camoufox managed-proxy mode requires its original proxy configuration.');
    }
}

export function bindManagedProxy(proxy, options) {
    const expectedOrigin = parseProxyOrigin(process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN);
    if (!expectedOrigin) {
        throw managedEgressError('Set CAMOUFOX_MANAGED_EGRESS_ORIGIN to the managed proxy origin with an explicit port.');
    }
    if (!proxy || proxy.bypass || parseProxyOrigin(proxy.server) !== expectedOrigin) {
        throw managedEgressError('The Camoufox profile proxy must match the managed egress origin and use every destination.');
    }

    const portPolicies = [options.portScanProtection, options.securityPolicy?.portScanProtection];
    if (
        options.enablePortScanProtection === false ||
        options.allowedLocalPorts?.length ||
        options.allowSameOriginLocalDev ||
        portPolicies.some((policy) =>
            policy === false || (policy?.enabled !== undefined && !policy.enabled) ||
            policy?.allowedPorts?.length || policy?.allowSameOriginLocalDev
        )
    ) {
        throw managedEgressError('Camoufox managed-proxy mode requires the URL guard without local exceptions.');
    }
    const { launchOptions = {}, contextOptions = {} } = options;
    if (options.useSharedBrowser) {
        throw managedEgressError('Camoufox managed-proxy mode requires a dedicated browser.');
    }
    if (
        ['proxy', 'proxyOverride', 'from_options', 'executable_path', 'executablePath'].some(
            (key) => Object.hasOwn(launchOptions || {}, key)
        ) ||
        ['proxy', 'proxyOverride'].some((key) => Object.hasOwn(contextOptions || {}, key)) ||
        launchOptions?.args?.length || launchOptions?.persistent_context ||
        hasProxyPreferenceOverride(options.firefox_user_prefs) ||
        hasProxyPreferenceOverride(launchOptions?.firefox_user_prefs) ||
        hasProxyPreferenceOverride(launchOptions?.firefoxUserPrefs) ||
        hasProxyEnvironmentOverride(options.env) ||
        hasProxyEnvironmentOverride(launchOptions?.env) ||
        (expectedOrigin.startsWith('https://') && contextOptions?.ignoreHTTPSErrors)
    ) {
        throw managedEgressError('Camoufox managed-proxy mode requires its original launcher and proxy configuration.');
    }

    const binding = Object.freeze({ origin: expectedOrigin, proxy: Object.freeze(proxy) });
    managedBindings.add(binding);
    return binding;
}

export function assertManagedProxyBinding(binding) {
    if (!managedBindings.has(binding)) {
        throw managedEgressError('Camoufox managed-proxy policy must be bound before browser context setup.');
    }
}

export function assertManagedProxyReuse(existing, requested) {
    if (existing === requested) return;
    if (
        existing?.origin !== requested?.origin ||
        existing?.proxy.username !== requested?.proxy.username ||
        existing?.proxy.password !== requested?.proxy.password
    ) {
        throw managedEgressError('Restart the Camoufox profile to apply a different network policy or proxy.');
    }
}
