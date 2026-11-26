/**
 * Ziniao SuperBrowser V6 Absorbed Security, Per-Domain Canvas/WebGL Consistency Ledger,
 * Local Port-Scan Protection, Internal Scheme Guard & Deterministic Geo-Jitter Engine
 *
 * Absorbs and upgrades the core architectural strengths discovered by reverse-engineering
 * Ziniao Browser V6 (`entries/main.index.js`, `workbench/main2.js`, `envkit/env-kit`,
 * `envkit/ziniao-gateway`, and the `ziniaobrowser` Chromium 137 C++ kernel):
 *
 *   1. Active Localhost / Private-LAN Port-Scan Protection (`port_scan_protection` + `checkRDP`/`checkProxy`):
 *      Blocks and logs websites attempting to probe 127.0.0.1 / localhost / [::1] / RFC1918 LAN ports
 *      (RDP 3389, VNC 5900, TeamViewer 5938, AnyDesk 7070, CDP 9222, Marionette 2828, Clash/V2Ray 7890/10808).
 *   2. Per-Domain Canvas & WebGL Consistency Ledger with 64-Bit Hamming Distance (`hanming_distance` +
 *      `AddCanvasFingerprint`/`AddWebGlFingerprint` + `canvas_fingerprint_skip_hosts` + `is_skip_cpu_canvas_mask`):
 *      Persists per-profile, per-domain 64-bit Canvas/WebGL hashes, computes bitwise Hamming distance
 *      and similarity %, detects cross-session fingerprint drift, and skips pixel noise on Canvas productivity apps.
 *   3. Internal Browser Scheme & Extension Probing Guard (`defaultSpecialList` / `debugSpecialList`):
 *      Blocks web pages from probing `about:config`, `about:debugging`, `about:support`, `about:telemetry`,
 *      `chrome://`, `moz-extension://`, `resource://`, etc.
 *   4. OS & Hardware Release Generation vs Browser Version Floor Guard (`checkDarwinSystemAndKernelVersionMatch`):
 *      Prevents pairing 2024–2025 OS/SoC hardware (macOS 15/26, Win11 24H2, M3/M4/M5, Lunar Lake) with
 *      anachronistic older browser engine versions.
 *   5. Deterministic Metropolitan Geolocation Micro-Jitter Resolver (`followIP` / `base_on_ip` upgraded):
 *      Maps 40+ countries to real metropolitan coordinates with deterministic `MD5(profileId)` street-level
 *      jitter (±0.015° lat/lng, 18..65m accuracy), eliminating Ziniao's hardcoded Ningxia fallback bug.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * 1. Sensitive Local Ports Probed by E-Commerce & Anti-Bot Scripts
 *    (Amazon, eBay, Shopee, TikTok Shop, ThreatMetrix / LexisNexis, Arkose)
 */
export const SENSITIVE_LOCAL_PORT_CATALOG = Object.freeze({
    22: Object.freeze({ port: 22, service: 'SSH Server', category: 'remote-admin', severity: 'high' }),
    1080: Object.freeze({ port: 1080, service: 'SOCKS5 Proxy', category: 'local-proxy', severity: 'critical' }),
    10808: Object.freeze({ port: 10808, service: 'v2rayN SOCKS5 Proxy', category: 'local-proxy', severity: 'critical' }),
    10809: Object.freeze({ port: 10809, service: 'v2rayN HTTP Proxy', category: 'local-proxy', severity: 'critical' }),
    2828: Object.freeze({ port: 2828, service: 'Firefox Marionette Automation', category: 'automation-debugger', severity: 'critical' }),
    3128: Object.freeze({ port: 3128, service: 'Squid / HTTP Proxy', category: 'local-proxy', severity: 'high' }),
    3389: Object.freeze({ port: 3389, service: 'Windows Remote Desktop (RDP)', category: 'remote-desktop', severity: 'critical' }),
    4444: Object.freeze({ port: 4444, service: 'Selenium / WebDriver Server', category: 'automation-debugger', severity: 'critical' }),
    4723: Object.freeze({ port: 4723, service: 'Appium Automation Server', category: 'automation-debugger', severity: 'critical' }),
    5037: Object.freeze({ port: 5037, service: 'Android ADB Daemon', category: 'device-bridge', severity: 'critical' }),
    5900: Object.freeze({ port: 5900, service: 'VNC Remote Desktop (Display :0)', category: 'remote-desktop', severity: 'critical' }),
    5901: Object.freeze({ port: 5901, service: 'VNC Remote Desktop (Display :1)', category: 'remote-desktop', severity: 'critical' }),
    5938: Object.freeze({ port: 5938, service: 'TeamViewer Remote Control', category: 'remote-desktop', severity: 'critical' }),
    6379: Object.freeze({ port: 6379, service: 'Redis Local Instance', category: 'dev-service', severity: 'medium' }),
    7070: Object.freeze({ port: 7070, service: 'AnyDesk Remote Control', category: 'remote-desktop', severity: 'critical' }),
    7890: Object.freeze({ port: 7890, service: 'Clash Mixed Proxy', category: 'local-proxy', severity: 'critical' }),
    7891: Object.freeze({ port: 7891, service: 'Clash SOCKS Proxy', category: 'local-proxy', severity: 'critical' }),
    8080: Object.freeze({ port: 8080, service: 'Local HTTP Proxy / Mitmproxy', category: 'local-proxy', severity: 'high' }),
    8118: Object.freeze({ port: 8118, service: 'Privoxy HTTP Proxy', category: 'local-proxy', severity: 'high' }),
    8888: Object.freeze({ port: 8888, service: 'Charles / Fiddler HTTP Proxy', category: 'local-proxy', severity: 'critical' }),
    9050: Object.freeze({ port: 9050, service: 'Tor SOCKS5 Proxy', category: 'local-proxy', severity: 'critical' }),
    9150: Object.freeze({ port: 9150, service: 'Tor Browser SOCKS5', category: 'local-proxy', severity: 'critical' }),
    9222: Object.freeze({ port: 9222, service: 'Chrome DevTools Protocol (CDP)', category: 'automation-debugger', severity: 'critical' }),
    9229: Object.freeze({ port: 9229, service: 'Node.js V8 Inspector', category: 'automation-debugger', severity: 'critical' }),
    9515: Object.freeze({ port: 9515, service: 'ChromeDriver Server', category: 'automation-debugger', severity: 'critical' })
});

/**
 * Determine whether a hostname or IP address targets loopback (`localhost`, `127.0.0.0/8`, `[::1]`, `0.0.0.0`)
 * or private RFC1918 / link-local LAN ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`).
 *
 * @param {string} rawHost
 * @returns {{ isLocalOrPrivate: boolean, scope: 'loopback' | 'private-lan' | 'link-local' | 'public' }}
 */
export function isLocalOrPrivateTarget(rawHost) {
    if (!rawHost || typeof rawHost !== 'string') {
        return { isLocalOrPrivate: false, scope: 'public' };
    }
    let host = rawHost
        .replace(/^[\u0000-\u0020]+|[\u0000-\u0020]+$/g, '')
        .replace(/[\t\r\n]/g, '')
        .toLowerCase();

    if (!host) {
        return { isLocalOrPrivate: false, scope: 'public' };
    }

    // If a full URL, protocol-relative URL, userinfo@host, [ipv6]:port, or host:port was passed directly, extract the hostname
    if (host.includes('://') || host.startsWith('//')) {
        try {
            host = new URL(host.startsWith('//') ? `http:${host}` : host).hostname.toLowerCase();
        } catch {
            // Fall through to manual stripping
        }
    } else {
        host = host.split(/[/?#]/)[0];
        if (host.includes('@')) {
            host = host.slice(host.lastIndexOf('@') + 1);
        }
        if (host.startsWith('[') && host.includes(']')) {
            host = host.slice(1, host.indexOf(']'));
        } else if (host.indexOf(':') !== -1 && host.indexOf(':') === host.lastIndexOf(':')) {
            host = host.slice(0, host.indexOf(':'));
        }
    }

    host = host
        .replace(/^\[|\]$/g, '')
        .replace(/%.*$/, '')
        .replace(/\.+$/, '');

    if (!host) {
        return { isLocalOrPrivate: false, scope: 'public' };
    }

    // Normalize 1-to-4 segment hex / octal / integer IPv4 literals (e.g. "2130706433", "0x7f000001", "0177.0.0.1", "0x7f.1", "012.0.0.1")
    if (/^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$/i.test(host)) {
        try {
            host = new URL(`http://${host}`).hostname.toLowerCase().replace(/\.+$/, '');
        } catch {
            // Keep original host
        }
    } else if (host.includes(':')) {
        // Canonicalize compressed/expanded IPv6 literals via WHATWG URL parser (e.g. "0::1" -> "::1", "::0001" -> "::1", "::127.0.0.1" -> "::7f00:1")
        try {
            host = new URL(`http://[${host}]`).hostname.toLowerCase().replace(/^\[|\]$/g, '');
        } catch {
            // Keep original host
        }
    }

    // Check pure IPv6 loopback (::1) and unspecified (::) before IPv4-compatible unwrapping
    if (
        host === '::1' ||
        host === '::' ||
        /^(?:0+:){7}0*1$/.test(host) ||
        /^(?:0+:){7}0+$/.test(host)
    ) {
        return { isLocalOrPrivate: true, scope: 'loopback' };
    }

    // Unwrap IPv4-mapped (::ffff:w.x.y.z), SIIT (::ffff:0:w.x.y.z), IPv4-compatible (::w.x.y.z), and RFC 6052 NAT64 (64:ff9b::w.x.y.z) IPv6 addresses:
    // 1. Dotted-quad form: "::ffff:127.0.0.1", "::127.0.0.1", "64:ff9b::127.0.0.1"
    const mappedDottedMatch = host.match(
        /^(?:64:ff9b:(?:(?:0+:){0,3}0*:|:)|(?:(?:0+:){0,5}0*:|::)(?:ffff:(?:0+:)?|0+:)?)+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i
    );
    if (mappedDottedMatch) {
        host = mappedDottedMatch[1];
    } else {
        // 2. WHATWG URL canonical hex-pair form: "::ffff:7f00:1", "::7f00:1", "0:0:0:0:0:0:7f00:1", "64:ff9b::7f00:1"
        const mappedHexMatch = host.match(
            /^(?:64:ff9b:(?:(?:0+:){0,3}0*:|:)|(?:(?:0+:){0,5}0*:|::)(?:ffff:(?:0+:)?|0+:)?)+([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i
        );
        if (mappedHexMatch) {
            const hi = parseInt(mappedHexMatch[1], 16);
            const lo = parseInt(mappedHexMatch[2], 16);
            host = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        }
    }

    // Hostname / mDNS / local / DNS-rebinding domain checks
    if (
        host === 'localhost' ||
        host.endsWith('.localhost') ||
        host === 'localdomain' ||
        host.endsWith('.localdomain') ||
        host === 'localtest.me' ||
        host.endsWith('.localtest.me') ||
        host === 'lvh.me' ||
        host.endsWith('.lvh.me') ||
        host === 'vcap.me' ||
        host.endsWith('.vcap.me')
    ) {
        return { isLocalOrPrivate: true, scope: 'loopback' };
    }
    if (
        host === 'local' ||
        host === 'lan' ||
        host === 'internal' ||
        host === 'intranet' ||
        host === 'home.arpa' ||
        host.endsWith('.local') ||
        host.endsWith('.lan') ||
        host.endsWith('.internal') ||
        host.endsWith('.home.arpa') ||
        host.endsWith('.intranet') ||
        host.endsWith('.svc') ||
        host.endsWith('.nip.io') ||
        host.endsWith('.sslip.io') ||
        host.endsWith('.xip.io')
    ) {
        return { isLocalOrPrivate: true, scope: 'private-lan' };
    }

    // IPv6 link-local (fe80::/10) and ULA (fc00::/7)
    if (/^fe[89ab][0-9a-f]:/i.test(host)) {
        return { isLocalOrPrivate: true, scope: 'link-local' };
    }
    if (/^(?:fc|fd)[0-9a-f]{2}:/i.test(host)) {
        return { isLocalOrPrivate: true, scope: 'private-lan' };
    }

    // Strict IPv4 octet check (0..255)
    const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4Match) {
        const a = Number(ipv4Match[1]);
        const b = Number(ipv4Match[2]);
        const c = Number(ipv4Match[3]);
        const d = Number(ipv4Match[4]);
        if (a <= 255 && b <= 255 && c <= 255 && d <= 255) {
            if (a === 127 || a === 0) {
                return { isLocalOrPrivate: true, scope: 'loopback' };
            }
            if (a === 169 && b === 254) {
                return { isLocalOrPrivate: true, scope: 'link-local' };
            }
            if (
                a === 10 ||
                (a === 192 && b === 168) ||
                (a === 172 && b >= 16 && b <= 31) ||
                (a === 100 && b >= 64 && b <= 127) ||
                (a === 198 && (b === 18 || b === 19)) ||
                (a === 192 && b === 0 && c === 0)
            ) {
                return { isLocalOrPrivate: true, scope: 'private-lan' };
            }
        }
    }

    return { isLocalOrPrivate: false, scope: 'public' };
}

/**
 * Classify the risk of a scanned local/private TCP port.
 *
 * @param {number} port
 * @returns {{ port: number, service: string, category: string, severity: string }}
 */
export function classifyScannedPortRisk(port) {
    const numPort = Number(port);
    if (SENSITIVE_LOCAL_PORT_CATALOG[numPort]) {
        return SENSITIVE_LOCAL_PORT_CATALOG[numPort];
    }
    if (numPort >= 5900 && numPort <= 5910) {
        return {
            port: numPort,
            service: `VNC Remote Desktop (Display :${numPort - 5900})`,
            category: 'remote-desktop',
            severity: 'critical'
        };
    }
    return {
        port: numPort,
        service: `Local TCP Port ${numPort}`,
        category: 'local-port-probe',
        severity: 'high'
    };
}

/**
 * Evaluate whether a network request is a localhost / private-LAN port-scan probe
 * that must be blocked under Ziniao-absorbed `port_scan_protection`.
 *
 * @param {string} targetUrl
 * @param {{
 *   initiatorUrl?: string | null,
 *   enabled?: boolean,
 *   allowedPorts?: number[],
 *   allowSameOriginLocalDev?: boolean
 * }} [options]
 * @returns {{
 *   shouldBlock: boolean,
 *   isPortScanProbe: boolean,
 *   host: string | null,
 *   port: number | null,
 *   scope: string,
 *   service: string | null,
 *   category: string | null,
 *   severity: string | null,
 *   reason: string | null
 * }}
 */
export function evaluatePortScanRequest(targetUrl, options = {}) {
    const enabled = options.enabled !== undefined ? Boolean(options.enabled) : true;
    const allowedPorts = new Set((options.allowedPorts || []).map(Number));
    const allowSameOriginLocalDev =
        options.allowSameOriginLocalDev !== undefined ? Boolean(options.allowSameOriginLocalDev) : false;

    let normalizedTarget =
        typeof targetUrl === 'string'
            ? targetUrl.replace(/^[\u0000-\u0020]+|[\u0000-\u0020]+$/g, '').replace(/[\t\r\n]/g, '')
            : '';
    while (
        /^(?:blob|view-source|filesystem):/i.test(normalizedTarget) ||
        (/^jar:/i.test(normalizedTarget) && !/^jar:file:/i.test(normalizedTarget))
    ) {
        normalizedTarget = normalizedTarget
            .replace(/^(?:blob|view-source|filesystem|jar):/i, '')
            .replace(/^[\u0000-\u0020]+|[\u0000-\u0020]+$/g, '');
    }
    if (normalizedTarget.startsWith('//')) {
        normalizedTarget = `http:${normalizedTarget}`;
    }

    let parsed;
    try {
        parsed = new URL(normalizedTarget);
    } catch {
        return {
            shouldBlock: false,
            isPortScanProbe: false,
            host: null,
            port: null,
            scope: 'public',
            service: null,
            category: null,
            severity: null,
            reason: null
        };
    }

    const protocol = parsed.protocol.toLowerCase();
    if (!['http:', 'https:', 'ws:', 'wss:', 'ftp:'].includes(protocol)) {
        return {
            shouldBlock: false,
            isPortScanProbe: false,
            host: parsed.hostname,
            port: null,
            scope: 'public',
            service: null,
            category: null,
            severity: null,
            reason: null
        };
    }

    const hostCheck = isLocalOrPrivateTarget(parsed.hostname);
    if (!hostCheck.isLocalOrPrivate) {
        return {
            shouldBlock: false,
            isPortScanProbe: false,
            host: parsed.hostname,
            port: parsed.port ? Number(parsed.port) : null,
            scope: 'public',
            service: null,
            category: null,
            severity: null,
            reason: null
        };
    }

    const getDefaultPortForProtocol = (proto) =>
        proto === 'https:' || proto === 'wss:' ? 443 : proto === 'ftp:' ? 21 : 80;
    const defaultPort = getDefaultPortForProtocol(protocol);
    const port = parsed.port ? Number(parsed.port) : defaultPort;
    const risk = classifyScannedPortRisk(port);

    if (allowSameOriginLocalDev && options.initiatorUrl && !parsed.username && !parsed.password) {
        try {
            const initParsed = new URL(options.initiatorUrl);
            const initDefaultPort = getDefaultPortForProtocol(initParsed.protocol.toLowerCase());
            const initPort = initParsed.port ? Number(initParsed.port) : initDefaultPort;
            const normInitHost = initParsed.hostname.toLowerCase().replace(/\.+$/, '');
            const normTargetHost = parsed.hostname.toLowerCase().replace(/\.+$/, '');
            if (normInitHost === normTargetHost && initPort === port) {
                return {
                    shouldBlock: false,
                    isPortScanProbe: false,
                    host: parsed.hostname,
                    port,
                    scope: hostCheck.scope,
                    service: risk.service,
                    category: risk.category,
                    severity: 'low',
                    reason: 'Allowed same-origin local development request'
                };
            }
        } catch {
            // Ignore invalid initiatorUrl
        }
    }

    if (allowedPorts.has(port)) {
        return {
            shouldBlock: false,
            isPortScanProbe: true,
            host: parsed.hostname,
            port,
            scope: hostCheck.scope,
            service: risk.service,
            category: risk.category,
            severity: 'low',
            reason: `Permitted by port_scan_protection allowlist (port ${port})`
        };
    }

    return {
        shouldBlock: enabled,
        isPortScanProbe: true,
        host: parsed.hostname,
        port,
        scope: hostCheck.scope,
        service: risk.service,
        category: risk.category,
        severity: risk.severity,
        reason: `Blocked local/intranet port-scan probe to ${parsed.hostname}:${port} (${risk.service})`
    };
}

/**
 * 2. Internal Browser Scheme & Extension Probing Guard
 *    Absorbed from Ziniao `defaultSpecialList` / `debugSpecialList` (`main.index.js`).
 */
export const BLOCKED_INTERNAL_URL_PATTERNS = Object.freeze([
    /^about:(?:config|debugging|devtools|support|telemetry|networking|memory|cache|processes|profiles|serviceworkers|webrtc|addons|plugins|buildconfig|preferences|logins|policies|crashes|crashcontent|sync-log|url-classifier)\b/i,
    /^chrome:\/\//i,
    /^devtools:\/\//i,
    /^chrome-extension:\/\//i,
    /^moz-extension:\/\//i,
    /^resource:\/\//i,
    /^jar:file:\/\/\//i,
    /^file:\/\//i,
    /^view-source:about:/i
]);

/**
 * Check whether a URL targets a sensitive internal browser / extension scheme.
 *
 * @param {string} targetUrl
 * @param {{ allowedExtensionIds?: string[] }} [options]
 * @returns {{ shouldBlock: boolean, matchedScheme: string | null, reason: string | null }}
 */
export function evaluateInternalSchemeAccess(targetUrl, options = {}) {
    if (!targetUrl || typeof targetUrl !== 'string') {
        return { shouldBlock: false, matchedScheme: null, reason: null };
    }
    // Strip WHATWG leading/trailing C0 controls (\u0000-\u0020) and embedded ASCII tabs/newlines (\t, \r, \n)
    let cleaned = targetUrl
        .replace(/^[\u0000-\u0020]+|[\u0000-\u0020]+$/g, '')
        .replace(/[\t\r\n]/g, '');

    // Recursively unwrap nested wrapper schemes (blob:, filesystem:, view-source:, jar: except jar:file:)
    while (/^(?:blob|filesystem|view-source):/i.test(cleaned) || (/^jar:/i.test(cleaned) && !/^jar:file:/i.test(cleaned))) {
        cleaned = cleaned
            .replace(/^(?:blob|filesystem|view-source|jar):/i, '')
            .replace(/^[\u0000-\u0020]+|[\u0000-\u0020]+$/g, '');
    }

    // Normalize percent-encoded or slash-prefixed about: URLs (e.g. "about://%63onfig" -> "about:config")
    if (/^about:/i.test(cleaned)) {
        const rawAboutRest = cleaned.slice(6).replace(/^\/+/, '');
        let decodedAboutRest = rawAboutRest;
        try {
            decodedAboutRest = decodeURIComponent(rawAboutRest);
        } catch {
            // Keep rawAboutRest if malformed percent-encoding
        }
        cleaned = `about:${decodedAboutRest}`;
    }

    const allowedExt = new Set((options.allowedExtensionIds || []).map((s) => String(s).toLowerCase()));

    if (/^(?:moz-extension|chrome-extension):\/\//i.test(cleaned)) {
        try {
            const u = new URL(cleaned);
            if (allowedExt.has(u.hostname.toLowerCase())) {
                return { shouldBlock: false, matchedScheme: u.protocol, reason: null };
            }
        } catch {
            // Fall through to block
        }
    }

    for (const pattern of BLOCKED_INTERNAL_URL_PATTERNS) {
        if (pattern.test(cleaned)) {
            const scheme = cleaned.split(':')[0].toLowerCase();
            return {
                shouldBlock: true,
                matchedScheme: scheme,
                reason: `Blocked untrusted access to internal browser/extension resource "${targetUrl.trim()}"`
            };
        }
    }

    return { shouldBlock: false, matchedScheme: null, reason: null };
}

/**
 * 3. Per-Domain Canvas & WebGL Consistency Ledger + 64-Bit Hamming Distance Engine
 *    Absorbed from Ziniao `AddCanvasFingerprint` / `AddWebGlFingerprint`, `hanming_distance`,
 *    `canvas_fingerprint_keep_consistent_setting`, `canvas_fingerprint_skip_hosts`, and `is_skip_cpu_canvas_mask`.
 */
export const DEFAULT_CANVAS_SKIP_HOSTS = Object.freeze([
    'canva.com',
    'www.canva.com',
    'figma.com',
    'www.figma.com',
    'photopea.com',
    'www.photopea.com',
    'docs.google.com',
    'sheets.google.com',
    'slides.google.com',
    'excalidraw.com',
    'miro.com'
]);

const POPCOUNT_NIBBLE = Object.freeze([0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4]);

/**
 * Compute the exact bitwise Hamming distance between two hexadecimal fingerprint hashes
 * (e.g. 64-bit / 16-hex-char or 256-bit / 64-hex-char Canvas/WebGL hashes).
 *
 * @param {string} hexHashA
 * @param {string} hexHashB
 * @returns {number} Number of differing bits
 */
export function computeHexHammingDistance(hexHashA, hexHashB) {
    const cleanA = String(hexHashA ?? '').trim().toLowerCase().replace(/^0x/, '');
    const cleanB = String(hexHashB ?? '').trim().toLowerCase().replace(/^0x/, '');
    if (!cleanA || !cleanB || !/^[0-9a-f]+$/.test(cleanA) || !/^[0-9a-f]+$/.test(cleanB)) {
        throw new Error(`Invalid hexadecimal hash input for Hamming distance: "${hexHashA}" vs "${hexHashB}"`);
    }

    const maxLen = Math.max(cleanA.length, cleanB.length);
    const padA = cleanA.padStart(maxLen, '0');
    const padB = cleanB.padStart(maxLen, '0');

    let distance = 0;
    for (let i = 0; i < maxLen; i++) {
        const nibA = parseInt(padA[i], 16);
        const nibB = parseInt(padB[i], 16);
        distance += POPCOUNT_NIBBLE[nibA ^ nibB];
    }
    return distance;
}

/**
 * Compute bitwise similarity percentage (`0..100`) between two hex hashes.
 *
 * @param {string} hexHashA
 * @param {string} hexHashB
 * @returns {number}
 */
export function computeHashSimilarity(hexHashA, hexHashB) {
    const cleanA = String(hexHashA ?? '').trim().toLowerCase().replace(/^0x/, '');
    const cleanB = String(hexHashB ?? '').trim().toLowerCase().replace(/^0x/, '');
    const dist = computeHexHammingDistance(cleanA, cleanB);
    const totalBits = Math.max(cleanA.length, cleanB.length) * 4;
    return Number((((totalBits - dist) / totalBits) * 100).toFixed(2));
}

/**
 * Check whether Canvas 2D noise injection should be skipped for a given host/URL
 * (`canvas_fingerprint_skip_hosts` absorbed from Ziniao `main.index.js`).
 *
 * @param {string} urlOrHost
 * @param {string[]} [customSkipHosts]
 * @returns {boolean}
 */
export function shouldSkipCanvasNoiseForHost(urlOrHost, customSkipHosts = []) {
    if (!urlOrHost || typeof urlOrHost !== 'string') return false;
    let hostname = urlOrHost.trim().toLowerCase();
    if (hostname.includes('://')) {
        try {
            hostname = new URL(hostname).hostname.toLowerCase();
        } catch {
            // Keep raw string
        }
    } else {
        hostname = hostname.split('/')[0].split(':')[0];
    }
    hostname = hostname.replace(/\.+$/, '');

    const skipList = [...DEFAULT_CANVAS_SKIP_HOSTS, ...(customSkipHosts || [])].map((h) =>
        String(h).trim().toLowerCase().replace(/\.+$/, '')
    );

    return skipList.some((pattern) => hostname === pattern || hostname.endsWith(`.${pattern}`));
}

/**
 * Absorbed from Ziniao `is_skip_cpu_canvas_mask`:
 * Checks whether a WebGL renderer is a CPU software rasterizer (SwiftShader / llvmpipe / Basic Render Driver).
 *
 * @param {string} renderer
 * @returns {boolean}
 */
export function isSoftwareRasterizerRenderer(renderer) {
    if (!renderer || typeof renderer !== 'string') return false;
    return /\b(?:SwiftShader|llvmpipe|softpipe|Microsoft Basic Render Driver|Mesa OffScreen)\b/i.test(renderer);
}

/**
 * Per-Profile, Per-Domain Canvas & WebGL Fingerprint Consistency Ledger
 * (`CanvasWebglConsistencyLedger`).
 *
 * Ensures that for a given `profileId` and website `domain` (e.g. `accounts.google.com`),
 * every Canvas `(width, height, drewText)` and WebGL `(width, height)` probe produces a
 * consistent 64-bit hash within `maxHammingDistance`, detecting any cross-session GPU/font drift.
 */
export class CanvasWebglConsistencyLedger {
    /**
     * @param {{
     *   profileId: string,
     *   ledgerPath?: string | null,
     *   maxHammingDistance?: number,
     *   skipHosts?: string[]
     * }} options
     */
    constructor(options = {}) {
        this.profileId = String(options.profileId || 'default-profile');
        this.ledgerPath = options.ledgerPath || null;
        const parsedMax =
            options.maxHammingDistance !== undefined ? Number(options.maxHammingDistance) : 0;
        this.maxHammingDistance =
            Number.isFinite(parsedMax) && parsedMax >= 0 ? Math.floor(parsedMax) : 0;
        this.skipHosts = [...DEFAULT_CANVAS_SKIP_HOSTS, ...(options.skipHosts || [])];
        this.entries = new Map();
        this.driftAlerts = [];

        if (this.ledgerPath && fs.existsSync(this.ledgerPath)) {
            this.loadFromDisk();
        }
    }

    static extractDomain(urlOrDomain) {
        const raw = String(urlOrDomain || 'unknown').trim().toLowerCase();
        if (raw.includes('://')) {
            try {
                return new URL(raw).hostname.toLowerCase().replace(/\.+$/, '');
            } catch {
                return raw.replace(/\.+$/, '');
            }
        }
        return raw.split('/')[0].split(':')[0].replace(/\.+$/, '');
    }

    buildEntryKey({ kind = 'canvas', domain, width = 300, height = 150, drewText = '' }) {
        const normDomain = CanvasWebglConsistencyLedger.extractDomain(domain);
        const normKind = kind === 'webgl' ? 'webgl' : 'canvas';
        const textKey = drewText ? String(drewText).trim() : '*';
        return `${normKind}::${normDomain}::${Number(width)}x${Number(height)}::${textKey}`;
    }

    /**
     * Record or verify a Canvas / WebGL fingerprint observation for a domain.
     *
     * @param {{
     *   kind?: 'canvas' | 'webgl',
     *   url?: string,
     *   domain?: string,
     *   width?: number,
     *   height?: number,
     *   drewText?: string,
     *   hash: string,
     *   dataUrl?: string | null
     * }} observation
     * @returns {{
     *   status: 'recorded-initial' | 'consistent' | 'drift-detected' | 'skipped-host',
     *   key: string,
     *   domain: string,
     *   hammingDistance: number,
     *   similarityPct: number,
     *   canonicalHash: string,
     *   canonicalDataUrl: string | null,
     *   driftDetected: boolean
     * }}
     */
    recordOrVerify(observation = {}) {
        const domain = CanvasWebglConsistencyLedger.extractDomain(
            observation.domain || observation.url || 'unknown'
        );
        const kind = observation.kind === 'webgl' ? 'webgl' : 'canvas';
        const width = Number(observation.width ?? 300);
        const height = Number(observation.height ?? 150);
        const drewText = observation.drewText ? String(observation.drewText) : '';
        const observedHash = String(observation.hash ?? '')
            .trim()
            .toLowerCase()
            .replace(/^0x/, '');
        if (!observedHash || !/^[0-9a-f]+$/.test(observedHash)) {
            throw new Error(`Invalid hexadecimal fingerprint hash in recordOrVerify: "${observation.hash}"`);
        }

        if (kind === 'canvas' && shouldSkipCanvasNoiseForHost(domain, this.skipHosts)) {
            return {
                status: 'skipped-host',
                key: this.buildEntryKey({ kind, domain, width, height, drewText }),
                domain,
                hammingDistance: 0,
                similarityPct: 100,
                canonicalHash: observedHash,
                canonicalDataUrl: observation.dataUrl || null,
                driftDetected: false
            };
        }

        const key = this.buildEntryKey({ kind, domain, width, height, drewText });
        const existing = this.entries.get(key);

        if (!existing) {
            const entry = {
                key,
                kind,
                domain,
                width,
                height,
                drewText,
                hash: observedHash,
                dataUrl: observation.dataUrl || null,
                firstSeenAt: new Date().toISOString(),
                lastVerifiedAt: new Date().toISOString(),
                verificationCount: 1
            };
            this.entries.set(key, entry);
            this.saveToDisk();
            return {
                status: 'recorded-initial',
                key,
                domain,
                hammingDistance: 0,
                similarityPct: 100,
                canonicalHash: entry.hash,
                canonicalDataUrl: entry.dataUrl,
                driftDetected: false
            };
        }

        const hammingDistance = computeHexHammingDistance(existing.hash, observedHash);
        const similarityPct = computeHashSimilarity(existing.hash, observedHash);
        const driftDetected = hammingDistance > this.maxHammingDistance;

        existing.lastVerifiedAt = new Date().toISOString();
        existing.verificationCount += 1;

        if (driftDetected) {
            const alert = {
                timestamp: existing.lastVerifiedAt,
                profileId: this.profileId,
                key,
                kind,
                domain,
                expectedHash: existing.hash,
                observedHash,
                hammingDistance,
                similarityPct,
                maxAllowedDistance: this.maxHammingDistance
            };
            this.driftAlerts.push(alert);
        }

        this.saveToDisk();

        return {
            status: driftDetected ? 'drift-detected' : 'consistent',
            key,
            domain,
            hammingDistance,
            similarityPct,
            canonicalHash: existing.hash,
            canonicalDataUrl: existing.dataUrl,
            driftDetected
        };
    }

    loadFromDisk() {
        if (!this.ledgerPath || !fs.existsSync(this.ledgerPath)) return false;
        try {
            const raw = JSON.parse(fs.readFileSync(this.ledgerPath, 'utf8'));
            if (Array.isArray(raw.entries)) {
                this.entries.clear();
                for (const item of raw.entries) {
                    if (item && item.key) {
                        this.entries.set(item.key, item);
                    }
                }
            }
            if (Array.isArray(raw.driftAlerts)) {
                this.driftAlerts = raw.driftAlerts;
            }
            return true;
        } catch {
            return false;
        }
    }

    saveToDisk() {
        if (!this.ledgerPath) return false;
        try {
            fs.mkdirSync(path.dirname(this.ledgerPath), { recursive: true });
            const payload = {
                profileId: this.profileId,
                maxHammingDistance: this.maxHammingDistance,
                updatedAt: new Date().toISOString(),
                entries: Array.from(this.entries.values()),
                driftAlerts: this.driftAlerts
            };
            fs.writeFileSync(this.ledgerPath, JSON.stringify(payload, null, 2), 'utf8');
            return true;
        } catch {
            return false;
        }
    }
}

/**
 * 4. OS & Hardware Generation vs Browser Engine Version Floor Validator
 *    Absorbed and upgraded from Ziniao `checkDarwinSystemAndKernelVersionMatch` (`main.index.js`).
 *
 * @param {{
 *   os: 'windows' | 'macos' | 'linux' | 'win' | 'mac' | 'lin',
 *   osVersion?: string | null,
 *   browserVersion?: string | number | null,
 *   cpuModel?: string | null
 * }} params
 * @returns {{ passed: boolean, minRequiredBrowserMajor: number, actualBrowserMajor: number | null, issues: string[] }}
 */
export function validateOsAndBrowserVersionMatch(params = {}) {
    const issues = [];
    const rawOs = String(params.os || 'windows').toLowerCase();
    const normOs = rawOs.startsWith('mac') ? 'macos' : rawOs.startsWith('lin') ? 'linux' : 'windows';
    const osVersion = String(params.osVersion || '').trim();
    const cpuModel = String(params.cpuModel || '').trim();

    let actualMajor = null;
    if (params.browserVersion !== undefined && params.browserVersion !== null) {
        const rawVer = String(params.browserVersion);
        const m =
            rawVer.match(/\b(?:Firefox|FxiOS|Chrome|CriOS|Chromium|Edg|Version)\/(\d{2,3})\b/i) ||
            rawVer.match(/\brv:(\d{2,3})(?:\.\d+)?/i) ||
            rawVer.match(/(\d{2,3})/);
        if (m) actualMajor = Number(m[1]);
    }

    let minRequired = 115; // Baseline modern desktop Firefox ESR floor

    if (normOs === 'macos' && osVersion) {
        const verMatch = osVersion.match(/^(\d+)/);
        const macMajor = verMatch ? Number(verMatch[1]) : 0;
        // Ziniao rule: macOS 15 Sequoia (late 2024) requires >= 128; macOS 26 Tahoe (late 2025) requires >= 133
        if (macMajor >= 26) {
            minRequired = Math.max(minRequired, 133);
        } else if (macMajor >= 15) {
            minRequired = Math.max(minRequired, 128);
        } else if (macMajor >= 14) {
            minRequired = Math.max(minRequired, 118);
        }
    }

    if (normOs === 'windows' && osVersion) {
        // Windows 11 24H2 (Build 26100, late 2024) requires >= 128
        if (/26100|24H2/i.test(osVersion)) {
            minRequired = Math.max(minRequired, 128);
        }
    }

    // 2024-2025 Silicon generation floor
    if (/\bApple\s+M5\b/i.test(cpuModel)) {
        minRequired = Math.max(minRequired, 133);
    } else if (
        /\b(?:Apple\s+M4|Core\s+Ultra\s+[579]\s+2\d\d[VKU]|Ryzen\s+AI\s+9|Ryzen\s+[579]\s+9\d{3}X|Snapdragon\s+X)\b/i.test(
            cpuModel
        )
    ) {
        minRequired = Math.max(minRequired, 128);
    } else if (/\b(?:Apple\s+M3|Core\s+Ultra\s+[579]\s+1\d\d[HU])\b/i.test(cpuModel)) {
        minRequired = Math.max(minRequired, 120);
    }

    if (actualMajor !== null && actualMajor < minRequired) {
        issues.push(
            `Browser engine version floor violation: browser major version ${actualMajor} is too old for OS="${normOs} ${osVersion}" / CPU="${cpuModel || 'generic'}" (minimum required version: >= ${minRequired})`
        );
    }

    return {
        passed: issues.length === 0,
        minRequiredBrowserMajor: minRequired,
        actualBrowserMajor: actualMajor,
        issues
    };
}

/**
 * 5. Deterministic Metropolitan Geolocation Micro-Jitter Resolver
 *    Absorbed and upgraded from Ziniao `followIP` (`location_follow_ip` / `base_on_ip`),
 *    replacing Ziniao's hardcoded Ningxia (`37.2534, 105.9976`) fallback with 40+ authentic
 *    metropolitan business hubs and per-profile deterministic street-level micro-jitter.
 */
export const COUNTRY_METRO_COORDINATES_CATALOG = Object.freeze({
    US: Object.freeze({ city: 'New York', latitude: 40.7128, longitude: -74.006 }),
    CA: Object.freeze({ city: 'Toronto', latitude: 43.6532, longitude: -79.3832 }),
    GB: Object.freeze({ city: 'London', latitude: 51.5074, longitude: -0.1278 }),
    AU: Object.freeze({ city: 'Sydney', latitude: -33.8688, longitude: 151.2093 }),
    DE: Object.freeze({ city: 'Berlin', latitude: 52.52, longitude: 13.405 }),
    AT: Object.freeze({ city: 'Vienna', latitude: 48.2082, longitude: 16.3738 }),
    CH: Object.freeze({ city: 'Zurich', latitude: 47.3769, longitude: 8.5417 }),
    FR: Object.freeze({ city: 'Paris', latitude: 48.8566, longitude: 2.3522 }),
    NL: Object.freeze({ city: 'Amsterdam', latitude: 52.3676, longitude: 4.9041 }),
    ES: Object.freeze({ city: 'Madrid', latitude: 40.4168, longitude: -3.7038 }),
    IT: Object.freeze({ city: 'Milan', latitude: 45.4642, longitude: 9.19 }),
    PL: Object.freeze({ city: 'Warsaw', latitude: 52.2297, longitude: 21.0122 }),
    SE: Object.freeze({ city: 'Stockholm', latitude: 59.3293, longitude: 18.0686 }),
    NO: Object.freeze({ city: 'Oslo', latitude: 59.9139, longitude: 10.7522 }),
    FI: Object.freeze({ city: 'Helsinki', latitude: 60.1699, longitude: 24.9384 }),
    DK: Object.freeze({ city: 'Copenhagen', latitude: 55.6761, longitude: 12.5683 }),
    CZ: Object.freeze({ city: 'Prague', latitude: 50.0755, longitude: 14.4378 }),
    RO: Object.freeze({ city: 'Bucharest', latitude: 44.4268, longitude: 26.1025 }),
    HU: Object.freeze({ city: 'Budapest', latitude: 47.4979, longitude: 19.0402 }),
    GR: Object.freeze({ city: 'Athens', latitude: 37.9838, longitude: 23.7275 }),
    PT: Object.freeze({ city: 'Lisbon', latitude: 38.7223, longitude: -9.1393 }),
    TR: Object.freeze({ city: 'Istanbul', latitude: 41.0082, longitude: 28.9784 }),
    UA: Object.freeze({ city: 'Kyiv', latitude: 50.4501, longitude: 30.5234 }),
    RU: Object.freeze({ city: 'Moscow', latitude: 55.7558, longitude: 37.6173 }),
    JP: Object.freeze({ city: 'Tokyo', latitude: 35.6762, longitude: 139.6503 }),
    KR: Object.freeze({ city: 'Seoul', latitude: 37.5665, longitude: 126.978 }),
    CN: Object.freeze({ city: 'Shanghai', latitude: 31.2304, longitude: 121.4737 }),
    TW: Object.freeze({ city: 'Taipei', latitude: 25.033, longitude: 121.5654 }),
    HK: Object.freeze({ city: 'Hong Kong', latitude: 22.3193, longitude: 114.1694 }),
    SG: Object.freeze({ city: 'Singapore', latitude: 1.3521, longitude: 103.8198 }),
    MY: Object.freeze({ city: 'Kuala Lumpur', latitude: 3.139, longitude: 101.6869 }),
    TH: Object.freeze({ city: 'Bangkok', latitude: 13.7563, longitude: 100.5018 }),
    VN: Object.freeze({ city: 'Ho Chi Minh City', latitude: 10.8231, longitude: 106.6297 }),
    ID: Object.freeze({ city: 'Jakarta', latitude: -6.2088, longitude: 106.8456 }),
    PH: Object.freeze({ city: 'Manila', latitude: 14.5995, longitude: 120.9842 }),
    IN: Object.freeze({ city: 'Mumbai', latitude: 19.076, longitude: 72.8777 }),
    IL: Object.freeze({ city: 'Tel Aviv', latitude: 32.0853, longitude: 34.7818 }),
    AE: Object.freeze({ city: 'Dubai', latitude: 25.2048, longitude: 55.2708 }),
    SA: Object.freeze({ city: 'Riyadh', latitude: 24.7136, longitude: 46.6753 }),
    BR: Object.freeze({ city: 'Sao Paulo', latitude: -23.5505, longitude: -46.6333 }),
    MX: Object.freeze({ city: 'Mexico City', latitude: 19.4326, longitude: -99.1332 }),
    AR: Object.freeze({ city: 'Buenos Aires', latitude: -34.6037, longitude: -58.3816 }),
    CL: Object.freeze({ city: 'Santiago', latitude: -33.4489, longitude: -70.6693 }),
    CO: Object.freeze({ city: 'Bogota', latitude: 4.711, longitude: -74.0721 }),
    ZA: Object.freeze({ city: 'Johannesburg', latitude: -26.2041, longitude: 28.0473 })
});

/**
 * Resolve deterministic street-level geolocation coordinates for a `profileId` and `countryCode`.
 * Ensures two profiles in the same city never share identical 6-decimal GPS coordinates.
 *
 * @param {string} profileId
 * @param {string} [countryCode='US']
 * @param {{ baseLatitude?: number, baseLongitude?: number, radiusDegrees?: number }} [options]
 * @returns {{ country: string, city: string, latitude: number, longitude: number, accuracy: number }}
 */
export function resolveGeoCoordinatesWithDeterministicJitter(profileId = 'default-profile', countryCode = 'US', options = {}) {
    const code = String(countryCode || 'US').trim().toUpperCase();
    const metro = COUNTRY_METRO_COORDINATES_CATALOG[code] || COUNTRY_METRO_COORDINATES_CATALOG.US;
    const baseLat = Number.isFinite(options.baseLatitude) ? Number(options.baseLatitude) : metro.latitude;
    const baseLng = Number.isFinite(options.baseLongitude) ? Number(options.baseLongitude) : metro.longitude;
    const radius =
        Number.isFinite(options.radiusDegrees) && Number(options.radiusDegrees) >= 0
            ? Math.min(5, Number(options.radiusDegrees))
            : 0.015;

    const digest = crypto.createHash('md5').update(`${profileId}:geo:${code}`).digest();
    const u1 = digest.readUInt32BE(0) / 0xffffffff; // 0..1
    const u2 = digest.readUInt32BE(4) / 0xffffffff; // 0..1
    const u3 = digest.readUInt32BE(8) / 0xffffffff; // 0..1

    const latOffset = (u1 * 2 - 1) * radius;
    const lngOffset = (u2 * 2 - 1) * radius;
    const clampedLat = Math.max(-90, Math.min(90, baseLat + latOffset));
    let wrappedLng = baseLng + lngOffset;
    if (wrappedLng > 180 || wrappedLng < -180) {
        wrappedLng = ((((wrappedLng + 180) % 360) + 360) % 360) - 180;
    }
    const latitude = Number(clampedLat.toFixed(6));
    const longitude = Number(wrappedLng.toFixed(6));
    const accuracy = Math.round(18 + u3 * 47); // 18m .. 65m realistic Wi-Fi geolocation accuracy

    return {
        country: code,
        city: metro.city,
        latitude,
        longitude,
        accuracy
    };
}

/**
 * 6. Active Playwright BrowserContext Security Guard Attachment
 *    (`attachZiniaoSecurityGuardsToContext`)
 *
 * Attaches Ziniao-absorbed active network guards to a Playwright/Camoufox `BrowserContext`:
 *   - Blocks localhost / private-LAN port-scanning requests (`127.0.0.1`, `localhost`, `[::1]`, RFC1918)
 *   - Blocks untrusted navigation / subresource requests to internal browser schemes
 *   - Logs every blocked attempt for security auditing and pre-TLS traffic attribution
 *
 * @param {object} context Playwright BrowserContext
 * @param {{
 *   profileId?: string,
 *   portScanProtection?: { enabled?: boolean, allowedPorts?: number[], allowSameOriginLocalDev?: boolean },
 *   allowedExtensionIds?: string[],
 *   onBlockedAttempt?: (event: object) => void
 * }} [options]
 * @returns {Promise<{
 *   blockedPortScans: Array<object>,
 *   blockedInternalSchemes: Array<object>,
 *   detach: () => Promise<void>
 * }>}
 */
export async function attachZiniaoSecurityGuardsToContext(context, options = {}) {
    const blockedPortScans = [];
    const blockedInternalSchemes = [];
    const profileId = String(options.profileId || 'default-profile');
    const portProtOpts = options.portScanProtection || {};

    if (!context || typeof context.route !== 'function') {
        return {
            blockedPortScans,
            blockedInternalSchemes,
            detach: async () => {}
        };
    }

    const routeHandler = async (route, request) => {
        const req =
            request ||
            (typeof route?.request === 'function' ? route.request() : route?.request) ||
            {};
        const reqUrl = typeof req.url === 'function' ? req.url() : String(req.url || '');
        const method = typeof req.method === 'function' ? req.method() || 'GET' : String(req.method || 'GET');
        const resourceType =
            typeof req.resourceType === 'function'
                ? req.resourceType() || 'other'
                : String(req.resourceType || 'other');
        let initiatorUrl = null;
        try {
            const frame = typeof req.frame === 'function' ? req.frame() : null;
            if (frame && typeof frame.url === 'function') {
                initiatorUrl = frame.url() || null;
            }
        } catch {
            initiatorUrl = null;
        }

        // 1. Check internal browser scheme probing
        const schemeEval = evaluateInternalSchemeAccess(reqUrl, {
            allowedExtensionIds: options.allowedExtensionIds
        });
        if (schemeEval.shouldBlock) {
            const ev = {
                type: 'internal-scheme-probe',
                timestamp: new Date().toISOString(),
                profileId,
                initiatorUrl,
                targetUrl: reqUrl,
                method,
                resourceType,
                matchedScheme: schemeEval.matchedScheme,
                reason: schemeEval.reason
            };
            blockedInternalSchemes.push(ev);
            if (typeof options.onBlockedAttempt === 'function') {
                try {
                    options.onBlockedAttempt(ev);
                } catch {}
            }
            await route.abort('accessdenied');
            return;
        }

        // 2. Check localhost / private-LAN port-scan probe
        const portEval = evaluatePortScanRequest(reqUrl, {
            initiatorUrl,
            enabled: portProtOpts.enabled !== undefined ? portProtOpts.enabled : true,
            allowedPorts: portProtOpts.allowedPorts || [],
            allowSameOriginLocalDev: portProtOpts.allowSameOriginLocalDev ?? false
        });
        if (portEval.shouldBlock) {
            const ev = {
                type: 'local-port-scan-probe',
                timestamp: new Date().toISOString(),
                profileId,
                initiatorUrl,
                targetUrl: reqUrl,
                method,
                resourceType,
                host: portEval.host,
                port: portEval.port,
                scope: portEval.scope,
                service: portEval.service,
                category: portEval.category,
                severity: portEval.severity,
                reason: portEval.reason
            };
            blockedPortScans.push(ev);
            if (typeof options.onBlockedAttempt === 'function') {
                try {
                    options.onBlockedAttempt(ev);
                } catch {}
            }
            await route.abort('connectionrefused');
            return;
        }

        await route.continue();
    };

    await context.route('**/*', routeHandler);

    return {
        blockedPortScans,
        blockedInternalSchemes,
        detach: async () => {
            if (typeof context.unroute === 'function') {
                await context.unroute('**/*', routeHandler);
            }
        }
    };
}

export default {
    SENSITIVE_LOCAL_PORT_CATALOG,
    BLOCKED_INTERNAL_URL_PATTERNS,
    DEFAULT_CANVAS_SKIP_HOSTS,
    COUNTRY_METRO_COORDINATES_CATALOG,
    isLocalOrPrivateTarget,
    classifyScannedPortRisk,
    evaluatePortScanRequest,
    evaluateInternalSchemeAccess,
    computeHexHammingDistance,
    computeHashSimilarity,
    shouldSkipCanvasNoiseForHost,
    isSoftwareRasterizerRenderer,
    CanvasWebglConsistencyLedger,
    validateOsAndBrowserVersionMatch,
    resolveGeoCoordinatesWithDeterministicJitter,
    attachZiniaoSecurityGuardsToContext
};
