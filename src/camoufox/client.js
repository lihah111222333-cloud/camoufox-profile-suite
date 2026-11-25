/**
 * Camoufox Browser Profile Client
 * Open-source C++-patched Firefox antidetect replacement for Dolphin Anty & GPM Login
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import logger from '../utils/logger.js';
import { CamoufoxTrafficRecorder } from './traffic-recorder.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEFAULT_PROFILES_DIR = (process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR)
    ? path.resolve(process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR)
    : path.resolve(__dirname, '../../profiles');

const LOCAL_CAMOUFOX_DIST = '/Volumes/hello/wj/camoufox/typescript/dist/index.js';
const VALID_TARGET_OS = new Set(['windows', 'macos', 'linux']);
const VALID_PROXY_PROTOCOLS = new Set(['http', 'https', 'socks4', 'socks5', 'socks5h']);
const FORBIDDEN_UA_PATTERNS =
    /\b(Chrome|CriOS|Chromium|Safari|AppleWebKit|WebKit|Edg|Edge|EdgA|EdgiOS|OPR|Opera|Vivaldi|Brave|FxiOS|Android|iPhone|iPad|iPod|Mobile|Tablet|Touch|IEMobile|BlackBerry|SamsungBrowser|UCBrowser|Trident|MSIE)\b/i;

// Cached module reference, shared browser instance, and active profile sessions
let cachedCamoufoxModule = null;
let sharedBrowserInstance = null;
let sharedBrowserPromise = null;
let sharedBrowserConfigKey = null;
const sharedBrowserPool = new Set();
const activeProfiles = new Map();
const pendingProfileStarts = new Map();
let profileSeqCounter = 0;
let cleanupHooksRegistered = false;
let sigintCleanupHandler = null;
let sigtermCleanupHandler = null;

/**
 * Inject or reset a custom/mock Camoufox module implementation (used by isolation tests).
 */
export function setCamoufoxModule(mockModule = null) {
    cachedCamoufoxModule = mockModule || null;
    return cachedCamoufoxModule;
}

/**
 * Dynamically resolve the `camoufox` module.
 * Tries `import('camoufox')` first, falling back to `/Volumes/hello/wj/camoufox/typescript/dist/index.js`.
 */
export async function resolveCamoufoxModule() {
    if (cachedCamoufoxModule) {
        return cachedCamoufoxModule;
    }

    let primaryError = null;
    try {
        cachedCamoufoxModule = await import('camoufox');
        logger.debug('Resolved camoufox from installed npm package');
        return cachedCamoufoxModule;
    } catch (err) {
        primaryError = err;
        logger.debug('camoufox npm package not found in node_modules, trying local dist fallback', {
            fallbackPath: LOCAL_CAMOUFOX_DIST,
            reason: err.message
        });
    }

    try {
        const fallbackUrl = pathToFileURL(LOCAL_CAMOUFOX_DIST).href;
        cachedCamoufoxModule = await import(fallbackUrl);
        logger.info('Resolved camoufox from local TypeScript build', {
            path: LOCAL_CAMOUFOX_DIST
        });
        return cachedCamoufoxModule;
    } catch (fallbackErr) {
        const message =
            `Unable to load 'camoufox' package (primary: ${primaryError?.message || 'unknown'}) ` +
            `or local build at ${LOCAL_CAMOUFOX_DIST} (fallback: ${fallbackErr.message})`;
        logger.error('Failed to resolve Camoufox module', { error: message });
        throw new Error(message);
    }
}

/**
 * Determine default desktop OS name in Camoufox format ('windows' | 'macos' | 'linux').
 */
export function getHostTargetOs() {
    if (process.platform === 'win32') return 'windows';
    if (process.platform === 'darwin') return 'macos';
    return 'linux';
}

/**
 * Validate and normalize target OS ('windows', 'macos', 'linux').
 * Strictly enforces Desktop Firefox OS targets.
 */
export function normalizeTargetOs(osInput) {
    if (!osInput) {
        return process.env.CAMOUFOX_OS
            ? normalizeTargetOs(process.env.CAMOUFOX_OS)
            : getHostTargetOs();
    }

    if (Array.isArray(osInput)) {
        const normalizedList = osInput.map((item) => normalizeTargetOs(item));
        return normalizedList[Math.floor(Math.random() * normalizedList.length)];
    }

    const cleaned = String(osInput).trim().toLowerCase();
    const aliasMap = {
        win: 'windows',
        win32: 'windows',
        windows: 'windows',
        mac: 'macos',
        macos: 'macos',
        darwin: 'macos',
        osx: 'macos',
        lin: 'linux',
        linux: 'linux',
        ubuntu: 'linux'
    };

    const resolved = aliasMap[cleaned];
    if (!resolved || !VALID_TARGET_OS.has(resolved)) {
        throw new Error(
            `Invalid Camoufox target OS "${osInput}". Must be one of: windows, macos, linux (Desktop Firefox only).`
        );
    }

    return resolved;
}

/**
 * Validate a single candidate User-Agent string for Desktop Firefox coherence.
 */
function validateFirefoxUaString(candidateUa) {
    const uaString = String(candidateUa).trim();
    if (
        !uaString ||
        FORBIDDEN_UA_PATTERNS.test(uaString) ||
        !/\bFirefox\/\d+/i.test(uaString) ||
        !/\bGecko\b/i.test(uaString)
    ) {
        throw new Error(
            `Forbidden User-Agent override "${candidateUa}": Camoufox runs on C++-patched Gecko and must maintain Desktop Firefox User-Agent coherence.`
        );
    }
}

/**
 * Enforce strict Desktop Firefox User-Agent coherence.
 * Rejects any attempt to spoof Chrome, Safari, WebKit, Edge, or Mobile/Android/iPhone User-Agents on Gecko.
 */
export function assertFirefoxCoherence(options = {}) {
    if (typeof options === 'string') {
        validateFirefoxUaString(options);
        return true;
    }

    if (!options || typeof options !== 'object') {
        return true;
    }

    const candidates = [
        options.userAgent,
        options.user_agent,
        options.ua,
        options?.config?.['navigator.userAgent'],
        options?.firefox_user_prefs?.['general.useragent.override'],
        options?.contextOptions?.userAgent,
        options?.contextOptions?.user_agent,
        options?.launchOptions?.userAgent,
        options?.launchOptions?.user_agent,
        options?.launchOptions?.config?.['navigator.userAgent'],
        options?.launchOptions?.firefox_user_prefs?.['general.useragent.override']
    ];

    for (const candidateUa of candidates) {
        if (candidateUa !== undefined && candidateUa !== null) {
            validateFirefoxUaString(candidateUa);
        }
    }

    return true;
}

/**
 * Safely decode URI components in proxy credentials without throwing on raw '%' characters.
 */
function safeDecodeComponent(value) {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}

/**
 * Strictly parse and validate a TCP port (1..65535, digits only).
 */
function parseStrictPort(rawPort, sourceDescription = '') {
    if (rawPort === undefined || rawPort === null) {
        throw new Error(`Missing proxy port${sourceDescription ? ` in "${sourceDescription}"` : ''}`);
    }
    const portStr = String(rawPort).trim();
    if (!/^\d+$/.test(portStr)) {
        throw new Error(`Invalid proxy port "${rawPort}"${sourceDescription ? ` in "${sourceDescription}"` : ''}`);
    }
    const portNum = Number(portStr);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        throw new Error(`Out-of-range proxy port "${rawPort}"${sourceDescription ? ` in "${sourceDescription}"` : ''}`);
    }
    return portNum;
}

/**
 * Validate and format a proxy hostname or IPv4/IPv6 literal (wrapping bare IPv6 literals in brackets).
 */
function formatProxyHost(rawHost, sourceDescription = '') {
    const hostStr = String(rawHost ?? '').trim();
    if (!hostStr || /\s/.test(hostStr)) {
        throw new Error(`Invalid proxy host "${rawHost}"${sourceDescription ? ` in "${sourceDescription}"` : ''}`);
    }

    if (hostStr.startsWith('[') || hostStr.endsWith(']')) {
        if (!hostStr.startsWith('[') || !hostStr.endsWith(']')) {
            throw new Error(`Malformed IPv6 proxy host "${rawHost}"`);
        }
        const inner = hostStr.slice(1, -1).trim();
        if (!inner || !inner.includes(':') || !/^[0-9a-fA-F:.]+$/.test(inner)) {
            throw new Error(`Invalid IPv6 address "${rawHost}"`);
        }
        return `[${inner}]`;
    }

    if (hostStr.includes(':')) {
        if (!/^[0-9a-fA-F:.]+$/.test(hostStr)) {
            throw new Error(`Invalid proxy host "${rawHost}"`);
        }
        return `[${hostStr}]`;
    }

    return hostStr;
}

/**
 * Parse a URL-formatted proxy string (`protocol://[user[:pass]@]host:port` or `protocol://host:port:user:pass`).
 */
function parseUrlProxyString(urlString) {
    const schemeMatch = urlString.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.*)$/);
    if (!schemeMatch) {
        throw new Error(`Invalid proxy URL format: ${urlString}`);
    }

    const protocol = schemeMatch[1].toLowerCase();
    if (!VALID_PROXY_PROTOCOLS.has(protocol)) {
        throw new Error(`Unsupported proxy protocol "${protocol}" in "${urlString}"`);
    }

    let remainder = schemeMatch[2].trim().replace(/\/+$/, '');
    if (!remainder) {
        throw new Error(`Missing proxy host and port in "${urlString}"`);
    }

    // Check for protocol://[ipv6]:port:user:pass format
    if (remainder.startsWith('[')) {
        const ipv6ColonParts = remainder.match(/^(\[[^\]]+\]):(\d+):([^:]*)(?::(.*))?$/);
        if (ipv6ColonParts) {
            const host = formatProxyHost(ipv6ColonParts[1], urlString);
            const port = parseStrictPort(ipv6ColonParts[2], urlString);
            const result = { server: `${protocol}://${host}:${port}` };
            const username = (ipv6ColonParts[3] ?? '').trim();
            const password = (ipv6ColonParts[4] ?? '').trim();
            if (username) result.username = username;
            if (password) result.password = password;
            return result;
        }
    } else {
        // Check for protocol://host:port:user:pass (where password may contain ':' or '@')
        const parts = remainder.split(':');
        if (parts.length >= 3 && !parts[0].includes('@') && /^\d+$/.test(parts[1].trim())) {
            const [rawHost, rawPort, rawUsername, ...passwordParts] = parts;
            const host = formatProxyHost(rawHost, urlString);
            const port = parseStrictPort(rawPort, urlString);
            const result = { server: `${protocol}://${host}:${port}` };
            const username = (rawUsername ?? '').trim();
            const password = passwordParts.join(':').trim();
            if (username) result.username = username;
            if (password) result.password = password;
            return result;
        }
    }

    let username = '';
    let password = '';
    let hostPortPart = remainder;

    const lastAtIndex = remainder.lastIndexOf('@');
    if (lastAtIndex !== -1) {
        const authPart = remainder.slice(0, lastAtIndex);
        hostPortPart = remainder.slice(lastAtIndex + 1);
        const firstColon = authPart.indexOf(':');
        if (firstColon === -1) {
            username = safeDecodeComponent(authPart).trim();
        } else {
            username = safeDecodeComponent(authPart.slice(0, firstColon)).trim();
            password = safeDecodeComponent(authPart.slice(firstColon + 1)).trim();
        }
    }

    let host = '';
    let portStr = '';

    if (hostPortPart.startsWith('[')) {
        const ipv6Match = hostPortPart.match(/^(\[[^\]]*\])(?::(.*))?$/);
        if (!ipv6Match) {
            throw new Error(`Invalid IPv6 proxy URL: ${urlString}`);
        }
        host = formatProxyHost(ipv6Match[1], urlString);
        portStr = ipv6Match[2];
    } else {
        const colonIdx = hostPortPart.indexOf(':');
        if (colonIdx === -1) {
            throw new Error(`Missing proxy port in "${urlString}"`);
        }
        if (hostPortPart.indexOf(':', colonIdx + 1) !== -1) {
            throw new Error(`Invalid unbracketed IPv6 or extra colon in proxy URL "${urlString}"`);
        }
        host = formatProxyHost(hostPortPart.slice(0, colonIdx), urlString);
        portStr = hostPortPart.slice(colonIdx + 1);
    }

    const port = parseStrictPort(portStr, urlString);
    const result = {
        server: `${protocol}://${host}:${port}`
    };
    if (username) result.username = username;
    if (password) result.password = password;
    return result;
}

/**
 * Normalize proxy input into Playwright / Camoufox format:
 * `{ server: 'http://ip:port', username?: string, password?: string }`
 */
export function normalizeProxy(proxy) {
    if (!proxy) {
        return null;
    }

    if (typeof proxy === 'string') {
        const trimmed = proxy.trim();
        if (!trimmed) return null;

        // URL format: http://user:pass@host:port, socks5://user:pass@1.2.3.4:1080, http://[::1]:8080
        if (trimmed.includes('://')) {
            return parseUrlProxyString(trimmed);
        }

        // Unschemed bracketed IPv6: [::1]:8080 or [::1]:8080:user:p@ss:word
        if (trimmed.startsWith('[')) {
            const ipv6Match = trimmed.match(/^(\[[^\]]*\])(?::([^:]*)(?::([^:]*)(?::(.*))?)?)?$/);
            if (!ipv6Match) {
                throw new Error(`Invalid IPv6 proxy format: ${proxy}`);
            }
            const host = formatProxyHost(ipv6Match[1], trimmed);
            const port = parseStrictPort(ipv6Match[2], trimmed);
            const result = { server: `http://${host}:${port}` };
            const username = (ipv6Match[3] ?? '').trim();
            const password = (ipv6Match[4] ?? '').trim();
            if (username) result.username = username;
            if (password) result.password = password;
            return result;
        }

        // host:port or host:port:user:pass (where password may contain ':' and '@', e.g. host:port:user:p@ss:word)
        const parts = trimmed.split(':');
        if (parts.length >= 2) {
            // Check for unschemed user:pass@host:port where '@' appears before the host:port
            if (trimmed.includes('@') && (parts[0].includes('@') || !/^\d+$/.test(parts[1].trim()))) {
                const lastAt = trimmed.lastIndexOf('@');
                const afterAt = trimmed.slice(lastAt + 1);
                if (afterAt.includes(':')) {
                    return parseUrlProxyString(`http://${trimmed}`);
                }
            }

            const [rawHost, rawPort, rawUsername, ...passwordParts] = parts;
            const host = formatProxyHost(rawHost, trimmed);
            const port = parseStrictPort(rawPort, trimmed);
            const password = passwordParts.join(':').trim();
            const username = (rawUsername ?? '').trim();
            const result = { server: `http://${host}:${port}` };
            if (username) result.username = username;
            if (password) result.password = password;
            return result;
        }

        throw new Error(`Invalid proxy string format: ${proxy}`);
    }

    if (typeof proxy === 'object') {
        // Already in Playwright `{ server, username, password }` format
        if (proxy.server) {
            const rawServer = String(proxy.server).trim();
            const parsedServer = normalizeProxy(rawServer);
            if (!parsedServer) {
                throw new Error(`Invalid proxy server "${proxy.server}"`);
            }
            const normalized = { ...parsedServer };
            const username = (proxy.username || proxy.proxyUsername || '').toString().trim();
            const password = (proxy.password || proxy.proxyPassword || '').toString().trim();
            if (username) normalized.username = username;
            if (password) normalized.password = password;
            if (proxy.bypass) normalized.bypass = proxy.bypass;
            return normalized;
        }

        // Dolphin / GPM format `{ ip/host, port, username, password, type/protocol }`
        const rawHost = (proxy.ip || proxy.host || '').toString().trim();
        const host = formatProxyHost(rawHost);
        const port = parseStrictPort(proxy.port);

        const rawProtocol = (proxy.type || proxy.protocol || 'http').toString().trim().toLowerCase();
        const protocol = rawProtocol.replace(/:\/\/$/, '');
        if (!VALID_PROXY_PROTOCOLS.has(protocol)) {
            throw new Error(`Unsupported proxy protocol "${protocol}"`);
        }

        const normalized = {
            server: `${protocol}://${host}:${port}`
        };

        const username = (proxy.username || proxy.proxyUsername || '').toString().trim();
        const password = (proxy.password || proxy.proxyPassword || '').toString().trim();
        if (username) normalized.username = username;
        if (password) normalized.password = password;
        if (proxy.bypass) normalized.bypass = proxy.bypass;

        return normalized;
    }

    throw new Error(`Unsupported proxy configuration type: ${typeof proxy}`);
}

/**
 * Get the directory path for a given profile ID.
 */
export function getProfileDir(profileId, profilesDir = DEFAULT_PROFILES_DIR) {
    const safeId = String(profileId).replace(/[^a-zA-Z0-9._-]/g, '_');
    return path.join(profilesDir, safeId);
}

/**
 * Get the storage state file path (`profiles/<profileId>/storage-state.json`).
 */
export function getStorageStatePath(profileId, profilesDir = DEFAULT_PROFILES_DIR) {
    return path.join(getProfileDir(profileId, profilesDir), 'storage-state.json');
}

/**
 * Get the metadata file path (`profiles/<profileId>/profile.json`).
 */
export function getProfileMetadataPath(profileId, profilesDir = DEFAULT_PROFILES_DIR) {
    return path.join(getProfileDir(profileId, profilesDir), 'profile.json');
}

/**
 * Ensure profile storage directory exists and initialize an empty storage-state.json if missing.
 */
export function ensureProfileStorage(profileId, profilesDir = DEFAULT_PROFILES_DIR) {
    const profileDir = getProfileDir(profileId, profilesDir);
    const trafficDir = path.join(profileDir, 'traffic');
    const payloadsDir = path.join(trafficDir, 'payloads');
    fs.mkdirSync(profileDir, { recursive: true });
    fs.mkdirSync(trafficDir, { recursive: true });
    fs.mkdirSync(payloadsDir, { recursive: true });

    const storageStatePath = getStorageStatePath(profileId, profilesDir);
    if (!fs.existsSync(storageStatePath)) {
        const initialState = {
            cookies: [],
            origins: []
        };
        fs.writeFileSync(storageStatePath, JSON.stringify(initialState, null, 2), 'utf8');
    }

    return {
        profileDir,
        storageStatePath,
        metadataPath: getProfileMetadataPath(profileId, profilesDir),
        trafficDir,
        payloadsDir,
        sslKeyLogPath: path.join(trafficDir, 'sslkeylog.txt'),
        preTlsWireLogPath: path.join(trafficDir, 'pre-tls-wire.log'),
        neckoMozLogPath: path.join(trafficDir, 'necko-pre-tls.moz_log'),
        trafficNdjsonPath: path.join(trafficDir, 'traffic.ndjson'),
        attributionIndexPath: path.join(trafficDir, 'attribution-index.json'),
        harPath: path.join(trafficDir, 'trace.har')
    };
}

/**
 * Read saved storage state if present and valid.
 */
export function loadStorageState(profileId, profilesDir = DEFAULT_PROFILES_DIR) {
    const storageStatePath = getStorageStatePath(profileId, profilesDir);
    if (!fs.existsSync(storageStatePath)) {
        ensureProfileStorage(profileId, profilesDir);
        return storageStatePath;
    }

    try {
        const raw = fs.readFileSync(storageStatePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.cookies) && Array.isArray(parsed.origins)) {
            return storageStatePath;
        }
    } catch (error) {
        logger.warn('Corrupted storage-state.json encountered, re-initializing', {
            profileId,
            storageStatePath,
            error: error.message
        });
    }

    const initialState = { cookies: [], origins: [] };
    fs.mkdirSync(getProfileDir(profileId, profilesDir), { recursive: true });
    fs.writeFileSync(storageStatePath, JSON.stringify(initialState, null, 2), 'utf8');
    return storageStatePath;
}

/**
 * Persist cookies (`datr`, `ig_did`, `ttwid`, etc.) and `localStorage` from a BrowserContext
 * into `profiles/<profileId>/storage-state.json`.
 */
export async function saveProfileStorageState(profileId, context = null, profilesDir = null) {
    const active = activeProfiles.get(profileId);
    const targetContext = context || active?.context;
    if (!targetContext) {
        logger.debug('No active BrowserContext to save storageState for profile', { profileId });
        return null;
    }

    const resolvedProfilesDir = profilesDir || active?.profilesDir || DEFAULT_PROFILES_DIR;
    const { storageStatePath } = ensureProfileStorage(profileId, resolvedProfilesDir);
    const state = await targetContext.storageState({ path: storageStatePath });
    if (state && typeof state === 'object' && Array.isArray(state.cookies) && Array.isArray(state.origins)) {
        fs.writeFileSync(storageStatePath, JSON.stringify(state, null, 2), 'utf8');
    }
    logger.debug('Saved Camoufox profile storage state', {
        profileId,
        storageStatePath,
        cookiesCount: state?.cookies?.length ?? 0,
        originsCount: state?.origins?.length ?? 0
    });
    return storageStatePath;
}

/**
 * Check if Camoufox module and binary are available.
 */
export async function checkCamoufoxConnection() {
    try {
        const camoufoxMod = await resolveCamoufoxModule();
        if (typeof camoufoxMod.Camoufox !== 'function' && typeof camoufoxMod.AsyncCamoufox !== 'function') {
            throw new Error('Camoufox launcher function not exported by module');
        }
        logger.info('Camoufox module resolved and ready');
        return true;
    } catch (error) {
        logger.error('Camoufox availability check failed', { error: error.message });
        return false;
    }
}

/**
 * Synchronize NSS TLS secrets from a shared browser SSLKEYLOGFILE into a profile's sslkeylog.txt.
 */
function syncSharedSslKeyLog(sharedKeyLogPath, profileKeyLogPath) {
    if (!sharedKeyLogPath || !profileKeyLogPath || sharedKeyLogPath === profileKeyLogPath) {
        return false;
    }
    try {
        if (!fs.existsSync(sharedKeyLogPath) || !fs.statSync(sharedKeyLogPath).isFile()) {
            return false;
        }
        const sharedRaw = fs.readFileSync(sharedKeyLogPath, 'utf8');
        const sharedLines = sharedRaw
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter((l) => l && !l.startsWith('#'));
        if (sharedLines.length === 0) {
            return false;
        }

        fs.mkdirSync(path.dirname(profileKeyLogPath), { recursive: true });
        let existingContent = '';
        if (fs.existsSync(profileKeyLogPath)) {
            existingContent = fs.readFileSync(profileKeyLogPath, 'utf8');
        } else {
            existingContent = '# NSS SSL/TLS Secrets Log (Camoufox Pre-TLS Traffic Recorder)\n';
        }

        const existingSet = new Set(
            existingContent
                .split(/\r?\n/)
                .map((l) => l.trim())
                .filter((l) => l && !l.startsWith('#'))
        );

        const newLines = [];
        for (const line of sharedLines) {
            if (!existingSet.has(line)) {
                existingSet.add(line);
                newLines.push(line);
            }
        }

        if (newLines.length > 0) {
            const prefix = existingContent && !existingContent.endsWith('\n') ? '\n' : '';
            fs.writeFileSync(
                profileKeyLogPath,
                `${existingContent}${prefix}${newLines.join('\n')}\n`,
                'utf8'
            );
        } else if (!fs.existsSync(profileKeyLogPath)) {
            fs.writeFileSync(profileKeyLogPath, existingContent, 'utf8');
        }
        return true;
    } catch (error) {
        logger.debug('Could not sync shared SSLKEYLOGFILE into profile sslkeylog.txt', {
            sharedKeyLogPath,
            profileKeyLogPath,
            error: error.message
        });
        return false;
    }
}

/**
 * Obtain or launch a shared Camoufox browser instance for multi-context profiles.
 */
export async function getOrCreateSharedBrowser(options = {}) {
    assertFirefoxCoherence(options);
    const targetOs = normalizeTargetOs(options.os);
    const headless = options.headless ?? (process.env.CAMOUFOX_HEADLESS === 'true' ? true : false);
    const humanize = options.humanize !== undefined ? options.humanize : true;
    const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;
    const sslKeyLog = options.sslKeyLog !== undefined
        ? options.sslKeyLog !== false
        : process.env.CAMOUFOX_SSLKEYLOG !== 'false';
    const configKey = JSON.stringify({ headless, humanize: Boolean(humanize), sslKeyLog: Boolean(sslKeyLog) });

    if (sharedBrowserInstance && sharedBrowserInstance.isConnected?.() !== false && sharedBrowserConfigKey === configKey) {
        return sharedBrowserInstance;
    }

    if (sharedBrowserPromise && sharedBrowserConfigKey === configKey) {
        return sharedBrowserPromise;
    }

    sharedBrowserConfigKey = configKey;
    const currentPromise = (async () => {
        try {
            const camoufoxMod = await resolveCamoufoxModule();
            const launchFn = camoufoxMod.AsyncCamoufox || camoufoxMod.Camoufox;

            const sharedSslKeyLogPath = sslKeyLog
                ? path.join(profilesDir, '_shared_sslkeylog.txt')
                : null;
            if (sharedSslKeyLogPath) {
                fs.mkdirSync(profilesDir, { recursive: true });
                if (!fs.existsSync(sharedSslKeyLogPath)) {
                    fs.writeFileSync(
                        sharedSslKeyLogPath,
                        '# NSS Shared SSL/TLS Secrets Log (Camoufox Shared Browser)\n',
                        'utf8'
                    );
                }
            }

            const baseLaunchOptions = { ...(options.launchOptions || {}) };
            if (sharedSslKeyLogPath) {
                baseLaunchOptions.env = {
                    ...process.env,
                    ...(baseLaunchOptions.env || {}),
                    SSLKEYLOGFILE: sharedSslKeyLogPath
                };
            }

            logger.info('Launching shared Camoufox browser instance', {
                os: targetOs,
                headless,
                humanize: Boolean(humanize),
                sslKeyLog: Boolean(sslKeyLog)
            });

            const browser = await launchFn({
                os: targetOs,
                headless,
                humanize,
                canvas_noise: options.canvas_noise ?? true,
                ...baseLaunchOptions
            });

            if (sharedSslKeyLogPath && browser && typeof browser === 'object') {
                browser._sharedSslKeyLogPath = sharedSslKeyLogPath;
            }

            sharedBrowserPool.add(browser);
            sharedBrowserInstance = browser;
            if (typeof browser.on === 'function') {
                browser.on('disconnected', () => {
                    sharedBrowserPool.delete(browser);
                    if (sharedBrowserInstance === browser) {
                        sharedBrowserInstance = null;
                        sharedBrowserPromise = null;
                    }
                });
            }
            return browser;
        } catch (err) {
            if (sharedBrowserPromise === currentPromise) {
                sharedBrowserPromise = null;
                sharedBrowserInstance = null;
                sharedBrowserConfigKey = null;
            }
            throw err;
        }
    })();

    sharedBrowserPromise = currentPromise;
    return sharedBrowserPromise;
}

/**
 * Close the shared Camoufox browser instance(s) if running.
 */
export async function closeSharedBrowser() {
    const instancesToClose = new Set(sharedBrowserPool);
    if (sharedBrowserInstance) {
        instancesToClose.add(sharedBrowserInstance);
    }

    sharedBrowserPool.clear();
    sharedBrowserInstance = null;
    sharedBrowserPromise = null;
    sharedBrowserConfigKey = null;

    for (const instance of instancesToClose) {
        try {
            await instance.close();
            logger.info('Shared Camoufox browser closed');
        } catch (error) {
            logger.warn('Error closing shared Camoufox browser', { error: error.message });
        }
    }
    return true;
}

/**
 * Create a new isolated Camoufox profile and persist its metadata + initial storage-state.json.
 */
export async function createProfile(profileName, proxy = null, options = {}) {
    try {
        assertFirefoxCoherence(options);

        const timestamp = Date.now();
        const seq = (++profileSeqCounter) % 10000;
        const randomNum = Math.floor(Math.random() * 10000) * 10000 + seq;
        const rawBaseName = profileName && String(profileName).trim().length > 0
            ? String(profileName).trim()
            : `Gmail_${timestamp}_${randomNum}`;

        const cleanName = rawBaseName.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 60);
        const profileId = options.profileId
            ? String(options.profileId).replace(/[^a-zA-Z0-9._-]/g, '_')
            : `${cleanName}_${timestamp}_${randomNum}`;

        const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;
        const targetOs = normalizeTargetOs(options.os);
        const normalizedProxy = normalizeProxy(proxy || options.proxy || null);
        const geoip = options.geoip !== undefined ? Boolean(options.geoip) : Boolean(normalizedProxy);
        const humanize = options.humanize !== undefined ? options.humanize : true;
        const headless = options.headless ?? (process.env.CAMOUFOX_HEADLESS === 'true' ? true : false);
        const useSharedBrowser = Boolean(options.useSharedBrowser);

        const { profileDir, storageStatePath, metadataPath } = ensureProfileStorage(profileId, profilesDir);

        const metadata = {
            id: profileId,
            profileId,
            title: cleanName,
            os: targetOs,
            browserFamily: 'firefox',
            proxy: normalizedProxy,
            geoip,
            humanize,
            headless,
            useSharedBrowser,
            profileDir,
            storageStatePath,
            locale: options.locale || null,
            timezoneId: options.timezoneId || null,
            webrtc_ip: options.webrtc_ip || null,
            geolocation: options.geolocation || null,
            ff_version: options.ff_version || null,
            preset: options.preset || null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2), 'utf8');

        logger.info('Camoufox profile created', {
            profileId,
            title: cleanName,
            os: targetOs,
            hasProxy: Boolean(normalizedProxy),
            geoip,
            humanize: Boolean(humanize),
            storageStatePath
        });

        return metadata;
    } catch (error) {
        logger.error('Error creating Camoufox profile', { error: error.message });
        throw error;
    }
}

/**
 * Read profile metadata from disk (or synthesize defaults if starting an ad-hoc profileId).
 */
export async function getProfile(profileId, options = {}) {
    const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;
    const metadataPath = getProfileMetadataPath(profileId, profilesDir);

    if (fs.existsSync(metadataPath)) {
        const content = fs.readFileSync(metadataPath, 'utf8');
        return JSON.parse(content);
    }

    return null;
}

/**
 * List all saved Camoufox profiles on disk.
 */
export async function listProfiles(profilesDir = DEFAULT_PROFILES_DIR) {
    if (!fs.existsSync(profilesDir)) {
        return [];
    }

    const entries = fs.readdirSync(profilesDir, { withFileTypes: true });
    const profiles = [];

    for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const metaPath = path.join(profilesDir, entry.name, 'profile.json');
        if (fs.existsSync(metaPath)) {
            try {
                profiles.push(JSON.parse(fs.readFileSync(metaPath, 'utf8')));
            } catch (error) {
                logger.warn('Skipping unreadable profile metadata', {
                    metaPath,
                    error: error.message
                });
            }
        }
    }

    return profiles;
}

/**
 * Start a Camoufox profile by ID.
 * Supports both dedicated per-profile Camoufox browser instances and shared browser contexts,
 * loading and persisting `profiles/<profileId>/storage-state.json`.
 */
export async function startProfile(profileId, options = {}) {
    if (activeProfiles.has(profileId)) {
        const existing = activeProfiles.get(profileId);
        if (existing.context && existing.browser?.isConnected?.() !== false) {
            logger.info('Reusing active Camoufox profile session', { profileId });
            return existing;
        }
        activeProfiles.delete(profileId);
    }

    if (pendingProfileStarts.has(profileId)) {
        return pendingProfileStarts.get(profileId);
    }

    const startPromise = (async () => {
        try {
            const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;
            let metadata = await getProfile(profileId, { profilesDir });

            if (!metadata) {
                metadata = await createProfile(profileId, options.proxy || null, {
                    ...options,
                    profileId,
                    profilesDir
                });
            }

            const definedOptions = Object.fromEntries(
                Object.entries(options).filter(([, value]) => value !== undefined)
            );
            const mergedOptions = {
                ...metadata,
                ...definedOptions
            };

            assertFirefoxCoherence(mergedOptions);

            const targetOs = normalizeTargetOs(mergedOptions.os);
            const normalizedProxy = normalizeProxy(mergedOptions.proxy);
            const geoip = mergedOptions.geoip !== undefined
                ? Boolean(mergedOptions.geoip)
                : Boolean(normalizedProxy);
            const humanize = mergedOptions.humanize !== undefined
                ? mergedOptions.humanize
                : true;
            const headless = mergedOptions.headless ?? false;
            const useSharedBrowser = Boolean(mergedOptions.useSharedBrowser);

            const storageInfo = ensureProfileStorage(profileId, profilesDir);
            const storageStatePath = loadStorageState(profileId, profilesDir);
            const recordTraffic = mergedOptions.recordTraffic !== undefined
                ? mergedOptions.recordTraffic !== false
                : process.env.CAMOUFOX_RECORD_TRAFFIC !== 'false';
            const recordBodies = mergedOptions.recordBodies !== undefined
                ? mergedOptions.recordBodies !== false
                : process.env.CAMOUFOX_RECORD_BODIES !== 'false';
            const recordWireLog = options.recordWireLog !== undefined
                ? options.recordWireLog !== false
                : (mergedOptions.recordWireLog !== undefined
                    ? mergedOptions.recordWireLog !== false
                    : process.env.CAMOUFOX_RECORD_WIRE_LOG !== 'false');
            const sslKeyLog = mergedOptions.sslKeyLog !== undefined
                ? mergedOptions.sslKeyLog !== false
                : process.env.CAMOUFOX_SSLKEYLOG !== 'false';
            const neckoMozLog = Boolean(
                options.neckoMozLog ??
                mergedOptions.neckoMozLog ??
                (process.env.CAMOUFOX_NECKO_MOZ_LOG === 'true')
            );
            const neckoMozLogModules =
                options.neckoMozLogModules ||
                mergedOptions.neckoMozLogModules ||
                process.env.CAMOUFOX_NECKO_MOZ_LOG_MODULES ||
                'timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4';
            const recordHar = mergedOptions.recordHar !== undefined
                ? Boolean(mergedOptions.recordHar)
                : process.env.CAMOUFOX_RECORD_HAR === 'true';
            const maxBodyBytes = mergedOptions.maxBodyBytes !== undefined
                ? mergedOptions.maxBodyBytes
                : (process.env.CAMOUFOX_TRAFFIC_MAX_BODY_BYTES
                    ? parseInt(process.env.CAMOUFOX_TRAFFIC_MAX_BODY_BYTES, 10)
                    : 5242880);

            const trafficPaths = {
                trafficDir: storageInfo.trafficDir,
                payloadsDir: storageInfo.payloadsDir,
                sslKeyLogPath: storageInfo.sslKeyLogPath,
                preTlsWireLogPath: storageInfo.preTlsWireLogPath,
                neckoMozLogPath: storageInfo.neckoMozLogPath,
                trafficNdjsonPath: storageInfo.trafficNdjsonPath,
                attributionIndexPath: storageInfo.attributionIndexPath,
                harPath: storageInfo.harPath
            };

            const hasCustomLaunchEnv = Boolean(
                sslKeyLog ||
                neckoMozLog ||
                options.env ||
                mergedOptions.launchOptions?.env
            );
            const launchEnv = hasCustomLaunchEnv
                ? {
                      ...process.env,
                      ...(mergedOptions.launchOptions?.env || {}),
                      ...(options.env || {}),
                      ...(sslKeyLog ? { SSLKEYLOGFILE: storageInfo.sslKeyLogPath } : {}),
                      ...(neckoMozLog
                          ? {
                                MOZ_LOG: neckoMozLogModules,
                                MOZ_LOG_FILE: storageInfo.neckoMozLogPath
                            }
                          : {})
                  }
                : null;

            const camoufoxMod = await resolveCamoufoxModule();
            const launchFn = camoufoxMod.AsyncCamoufox || camoufoxMod.Camoufox;
            const newContextFn = camoufoxMod.AsyncNewContext || camoufoxMod.NewContext;

            let browser = null;
            let context = null;
            let ownsBrowser = false;

            if (useSharedBrowser) {
                browser = await getOrCreateSharedBrowser({
                    os: targetOs,
                    headless,
                    humanize,
                    sslKeyLog,
                    profilesDir,
                    canvas_noise: true,
                    launchOptions: {
                        ...(mergedOptions.launchOptions || {}),
                        ...(launchEnv ? { env: launchEnv } : {})
                    }
                });
                ownsBrowser = false;

                const contextOpts = {
                    os: targetOs,
                    storageState: storageStatePath,
                    ...(normalizedProxy ? { proxy: normalizedProxy } : {}),
                    ...(mergedOptions.webrtc_ip ? { webrtc_ip: mergedOptions.webrtc_ip } : {}),
                    ...(mergedOptions.geolocation ? { geolocation: mergedOptions.geolocation } : {}),
                    ...(mergedOptions.locale ? { locale: mergedOptions.locale } : {}),
                    ...(mergedOptions.timezoneId ? { timezoneId: mergedOptions.timezoneId } : {}),
                    ...(mergedOptions.ff_version ? { ff_version: mergedOptions.ff_version } : {}),
                    ...(mergedOptions.preset ? { preset: mergedOptions.preset } : {}),
                    ...(recordHar ? { recordHar: { path: storageInfo.harPath, content: 'attach' } } : {}),
                    ...(mergedOptions.contextOptions || {})
                };

                context = typeof newContextFn === 'function'
                    ? await newContextFn(browser, contextOpts)
                    : await browser.newContext(contextOpts);
            } else {
                const launchOpts = {
                    os: targetOs,
                    headless,
                    humanize,
                    geoip,
                    ...(normalizedProxy ? { proxy: normalizedProxy } : {}),
                    ...(mergedOptions.locale ? { locale: mergedOptions.locale } : {}),
                    ...(mergedOptions.ff_version ? { ff_version: mergedOptions.ff_version } : {}),
                    ...(mergedOptions.preset ? { preset: mergedOptions.preset } : {}),
                    ...(mergedOptions.addons ? { addons: mergedOptions.addons } : {}),
                    ...(mergedOptions.fonts ? { fonts: mergedOptions.fonts } : {}),
                    ...(mergedOptions.screen ? { screen: mergedOptions.screen } : {}),
                    ...(mergedOptions.window ? { window: mergedOptions.window } : {}),
                    ...(mergedOptions.config ? { config: mergedOptions.config } : {}),
                    ...(mergedOptions.firefox_user_prefs
                        ? { firefox_user_prefs: mergedOptions.firefox_user_prefs }
                        : {}),
                    ...(mergedOptions.launchOptions || {}),
                    ...(launchEnv ? { env: launchEnv } : {})
                };

                logger.info('Launching isolated Camoufox browser for profile', {
                    profileId,
                    os: targetOs,
                    hasProxy: Boolean(normalizedProxy),
                    geoip,
                    humanize: Boolean(humanize),
                    headless,
                    sslKeyLog
                });

                browser = await launchFn(launchOpts);
                ownsBrowser = true;

                const contextOpts = {
                    storageState: storageStatePath,
                    ...(mergedOptions.timezoneId ? { timezoneId: mergedOptions.timezoneId } : {}),
                    ...(mergedOptions.geolocation ? { geolocation: mergedOptions.geolocation } : {}),
                    ...(recordHar ? { recordHar: { path: storageInfo.harPath, content: 'attach' } } : {}),
                    ...(mergedOptions.contextOptions || {})
                };

                context = await browser.newContext(contextOpts);
            }

            const existingPages = context.pages();
            const page = existingPages.length > 0 ? existingPages[0] : await context.newPage();

            let trafficRecorder = null;
            if (recordTraffic) {
                trafficRecorder = new CamoufoxTrafficRecorder({
                    profileId,
                    trafficDir: storageInfo.trafficDir,
                    sslKeyLogPath: storageInfo.sslKeyLogPath,
                    preTlsWireLogPath: storageInfo.preTlsWireLogPath,
                    neckoMozLogPath: storageInfo.neckoMozLogPath,
                    harPath: recordHar ? storageInfo.harPath : null,
                    os: targetOs,
                    proxyServer: normalizedProxy?.server || null,
                    accountId: options.accountId ?? mergedOptions.accountId ?? null,
                    accountEmail: options.accountEmail ?? mergedOptions.accountEmail ?? null,
                    recordBodies: options.recordBodies !== undefined ? options.recordBodies !== false : recordBodies,
                    recordWireLog,
                    maxBodyBytes: options.maxBodyBytes ?? maxBodyBytes
                });
                await trafficRecorder.attachContext(context);
                await trafficRecorder.attachPage(page);
            }

            const session = {
                profileId,
                browser,
                context,
                page,
                ownsBrowser,
                profilesDir,
                storageStatePath,
                trafficRecorder,
                trafficPaths,
                metadata: {
                    ...metadata,
                    os: targetOs,
                    proxy: normalizedProxy,
                    geoip,
                    humanize,
                    trafficPaths
                }
            };

            activeProfiles.set(profileId, session);
            registerProcessCleanupHooks();

            logger.info('Camoufox profile started', {
                profileId,
                os: targetOs,
                storageStatePath,
                useSharedBrowser
            });

            return session;
        } catch (error) {
            logger.error('Error starting Camoufox profile', {
                profileId,
                error: error.message
            });
            throw error;
        } finally {
            pendingProfileStarts.delete(profileId);
        }
    })();

    pendingProfileStarts.set(profileId, startPromise);
    return startPromise;
}

/**
 * Stop an active Camoufox profile by ID, saving cookies and localStorage first.
 */
export async function stopProfile(profileId, options = {}) {
    if (pendingProfileStarts.has(profileId)) {
        try {
            await pendingProfileStarts.get(profileId);
        } catch {
            // Ignore start failure during stop
        }
    }

    const session = activeProfiles.get(profileId);
    if (!session) {
        logger.debug('Camoufox profile is not currently running', { profileId });
        return true;
    }

    const profilesDir = options.profilesDir || session.profilesDir || DEFAULT_PROFILES_DIR;

    try {
        if (session.browser?._sharedSslKeyLogPath && session.trafficPaths?.sslKeyLogPath) {
            syncSharedSslKeyLog(
                session.browser._sharedSslKeyLogPath,
                session.trafficPaths.sslKeyLogPath
            );
        }

        if (session.trafficRecorder) {
            try {
                await session.trafficRecorder.stop();
            } catch (trafficErr) {
                logger.warn('Could not flush traffic recorder before stopping profile', {
                    profileId,
                    error: trafficErr.message
                });
            }
        }

        if (session.context) {
            try {
                await saveProfileStorageState(profileId, session.context, profilesDir);
            } catch (saveErr) {
                logger.warn('Could not save storage state before stopping profile', {
                    profileId,
                    error: saveErr.message
                });
            }

            try {
                await session.context.close();
            } catch (closeCtxErr) {
                logger.debug('Error closing Camoufox context', {
                    profileId,
                    error: closeCtxErr.message
                });
            }
        }

        if (session.browser?._sharedSslKeyLogPath && session.trafficPaths?.sslKeyLogPath) {
            syncSharedSslKeyLog(
                session.browser._sharedSslKeyLogPath,
                session.trafficPaths.sslKeyLogPath
            );
        }

        if (session.ownsBrowser && session.browser) {
            try {
                await session.browser.close();
            } catch (closeBrowserErr) {
                logger.debug('Error closing Camoufox browser', {
                    profileId,
                    error: closeBrowserErr.message
                });
            }
        }

        activeProfiles.delete(profileId);
        logger.info('Camoufox profile stopped', { profileId });
        return true;
    } catch (error) {
        activeProfiles.delete(profileId);
        logger.warn('Error stopping Camoufox profile', {
            profileId,
            error: error.message
        });
        return false;
    }
}

/**
 * Delete a profile and remove its persistent storage directory (`profiles/<profileId>/`).
 */
export async function deleteProfile(profileId, options = {}) {
    const activeSession = activeProfiles.get(profileId);
    const profilesDir = options.profilesDir || activeSession?.profilesDir || DEFAULT_PROFILES_DIR;
    try {
        await stopProfile(profileId, { profilesDir });
        const profileDir = getProfileDir(profileId, profilesDir);
        if (fs.existsSync(profileDir)) {
            fs.rmSync(profileDir, { recursive: true, force: true });
        }
        logger.info('Camoufox profile deleted', { profileId, profileDir });
        return true;
    } catch (error) {
        logger.error('Error deleting Camoufox profile', {
            profileId,
            error: error.message
        });
        throw error;
    }
}

/**
 * Update proxy configuration for one or more profile IDs.
 */
export async function updateProfileProxy(profileIds, proxy, options = {}) {
    const ids = Array.isArray(profileIds) ? profileIds : [profileIds];
    const normalizedProxy = normalizeProxy(proxy);
    const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;

    for (const id of ids) {
        const metadataPath = getProfileMetadataPath(id, profilesDir);
        const existing = (await getProfile(id, { profilesDir })) || {
            id,
            profileId: id,
            title: id,
            os: getHostTargetOs(),
            browserFamily: 'firefox',
            humanize: true
        };

        const updated = {
            ...existing,
            proxy: normalizedProxy,
            geoip: normalizedProxy ? true : Boolean(existing.geoip),
            updatedAt: new Date().toISOString()
        };

        ensureProfileStorage(id, profilesDir);
        fs.writeFileSync(metadataPath, JSON.stringify(updated, null, 2), 'utf8');
    }

    logger.info('Updated Camoufox profile proxy configuration', {
        profileIds: ids,
        server: normalizedProxy?.server || null
    });

    return {
        success: true,
        profileIds: ids,
        proxy: normalizedProxy
    };
}

/**
 * Return an array of all currently active Camoufox profile IDs.
 */
export function getActiveProfileIds() {
    return Array.from(activeProfiles.keys());
}

/**
 * Gracefully stop all active Camoufox profiles concurrently, flushing each profile's
 * traffic recorder (`attribution-index.json`), syncing `_shared_sslkeylog.txt`,
 * persisting `storage-state.json`, and closing any shared Camoufox browser instance.
 */
export async function stopAllActiveProfiles(reason = 'shutdown') {
    if (pendingProfileStarts.size > 0) {
        await Promise.allSettled(Array.from(pendingProfileStarts.values()));
    }

    const profileIds = Array.from(activeProfiles.keys());
    if (profileIds.length > 0) {
        logger.info('Stopping all active Camoufox profiles', {
            reason,
            count: profileIds.length,
            profileIds
        });
    }

    const results = await Promise.allSettled(
        profileIds.map((profileId) => stopProfile(profileId))
    );
    const stoppedCount = results.filter(
        (res) => res.status === 'fulfilled' && res.value !== false
    ).length;

    await closeSharedBrowser();

    return {
        stoppedCount,
        profileIds,
        reason
    };
}

/**
 * Idempotently register process SIGINT and SIGTERM cleanup listeners to flush
 * active Camoufox profiles and shared browsers before termination.
 */
export function registerProcessCleanupHooks() {
    if (cleanupHooksRegistered) {
        return false;
    }

    sigintCleanupHandler = () => {
        if (activeProfiles.size > 0 || sharedBrowserPool.size > 0) {
            stopAllActiveProfiles('SIGINT').catch((error) => {
                logger.warn('Error flushing active Camoufox profiles on SIGINT', {
                    error: error.message
                });
            });
        }
    };

    sigtermCleanupHandler = () => {
        if (activeProfiles.size > 0 || sharedBrowserPool.size > 0) {
            stopAllActiveProfiles('SIGTERM').catch((error) => {
                logger.warn('Error flushing active Camoufox profiles on SIGTERM', {
                    error: error.message
                });
            });
        }
    };

    process.on('SIGINT', sigintCleanupHandler);
    process.on('SIGTERM', sigtermCleanupHandler);
    cleanupHooksRegistered = true;
    return true;
}

/**
 * Unregister process SIGINT and SIGTERM cleanup listeners (useful for test suites).
 */
export function unregisterProcessCleanupHooks() {
    if (!cleanupHooksRegistered) {
        return false;
    }

    if (sigintCleanupHandler) {
        process.off('SIGINT', sigintCleanupHandler);
        sigintCleanupHandler = null;
    }
    if (sigtermCleanupHandler) {
        process.off('SIGTERM', sigtermCleanupHandler);
        sigtermCleanupHandler = null;
    }

    cleanupHooksRegistered = false;
    return true;
}

export default {
    setCamoufoxModule,
    resolveCamoufoxModule,
    checkCamoufoxConnection,
    checkDolphinConnection: checkCamoufoxConnection,
    getHostTargetOs,
    normalizeTargetOs,
    assertFirefoxCoherence,
    normalizeProxy,
    getProfileDir,
    getStorageStatePath,
    getProfileMetadataPath,
    ensureProfileStorage,
    loadStorageState,
    saveProfileStorageState,
    getOrCreateSharedBrowser,
    closeSharedBrowser,
    createProfile,
    startProfile,
    stopProfile,
    deleteProfile,
    getProfile,
    listProfiles,
    updateProfileProxy,
    getActiveProfileIds,
    stopAllActiveProfiles,
    registerProcessCleanupHooks,
    unregisterProcessCleanupHooks
};
