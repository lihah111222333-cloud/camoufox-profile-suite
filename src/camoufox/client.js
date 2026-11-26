/**
 * Camoufox Browser Profile Client
 * Open-source C++-patched Firefox antidetect replacement for Dolphin Anty & GPM Login
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import logger from '../utils/logger.js';
import { ensurePrivateDirectory, writePrivateFile } from '../utils/private-storage.js';
import { assertManagedProxyReuse, bindManagedProxy, resolveNetworkPolicyMode } from './network-policy.js';
import {
    ensureProfileStorageAt,
    inspectProfileForDeletion,
    locateProfile,
    prepareNativeLogs,
    readProfileMetadata,
    readStorageState,
    resolveProfilesRoot,
    restrictLegacySharedKeyLog,
    restrictNativeLogs,
    validateProfileId
} from './profile-storage.js';
import { CamoufoxTrafficRecorder } from './traffic-recorder.js';
import { redactDiagnosticText, redactUrlSecrets } from './traffic-redaction.js';
import {
    USABLE_DEVICE_PRESET_CATALOG,
    listUsableDevicePresets,
    resolveDeterministicDeviceProfile,
    sanitizeAdsPowerProfileToCoherentPreset,
    sanitizeZiniaoProfileToCoherentPreset,
    CanvasWebglConsistencyLedger,
    attachZiniaoSecurityGuardsToContext,
    evaluatePortScanRequest,
    evaluateInternalSchemeAccess,
    computeHexHammingDistance,
    computeHashSimilarity,
    shouldSkipCanvasNoiseForHost,
    validateOsAndBrowserVersionMatch,
    resolveGeoCoordinatesWithDeterministicJitter,
    sanitizeRtcConfigurationIceServers,
    buildZiniaoWebRtcSecurityInitScript,
    GPU_PERFORMANCE_SPEC_CATALOG,
    lookupGpuPerformanceSpec,
    collectHostMacPerformanceBaseline,
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    buildGpuPerformanceInitScript,
    attachGpuPerformanceScalerToContext,
    validateGpuPerformanceScalingCoherence
} from './device-presets.js';

export {
    USABLE_DEVICE_PRESET_CATALOG,
    listUsableDevicePresets,
    resolveDeterministicDeviceProfile,
    sanitizeAdsPowerProfileToCoherentPreset,
    sanitizeZiniaoProfileToCoherentPreset,
    CanvasWebglConsistencyLedger,
    attachZiniaoSecurityGuardsToContext,
    evaluatePortScanRequest,
    evaluateInternalSchemeAccess,
    computeHexHammingDistance,
    computeHashSimilarity,
    shouldSkipCanvasNoiseForHost,
    validateOsAndBrowserVersionMatch,
    resolveGeoCoordinatesWithDeterministicJitter,
    sanitizeRtcConfigurationIceServers,
    buildZiniaoWebRtcSecurityInitScript,
    GPU_PERFORMANCE_SPEC_CATALOG,
    lookupGpuPerformanceSpec,
    collectHostMacPerformanceBaseline,
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    buildGpuPerformanceInitScript,
    attachGpuPerformanceScalerToContext,
    validateGpuPerformanceScalingCoherence
};

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

let cachedCamoufoxModule = null;
const sharedBrowsers = new Map();
const activeProfiles = new Map();
const pendingProfileStarts = new Map();
const pendingProfileSaves = new Map();
const pendingProfileStops = new Map();
const pendingProfileDeletes = new Map();
const profileContexts = new WeakMap();
let stoppingAllProfiles = null;
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
    return path.join(profilesDir, validateProfileId(profileId));
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
    return ensureProfileStorageAt(locateProfile(profileId, profilesDir, true));
}

/**
 * Read saved storage state if present and valid.
 */
export function loadStorageState(profileId, profilesDir = DEFAULT_PROFILES_DIR) {
    const { storageStatePath } = ensureProfileStorage(profileId, profilesDir);
    readStorageState(storageStatePath);
    return storageStatePath;
}

async function persistProfileStorageState(location, context) {
    const state = await context.storageState();
    if (!Array.isArray(state?.cookies) || !Array.isArray(state?.origins)) {
        throw new TypeError('Invalid Camoufox storage state');
    }

    const { storageStatePath } = ensureProfileStorageAt(location);
    writePrivateFile(storageStatePath, JSON.stringify(state, null, 2));
    logger.debug('Saved Camoufox profile storage state', {
        profileId: location.id,
        storageStatePath,
        cookiesCount: state.cookies.length,
        originsCount: state.origins.length
    });
    return storageStatePath;
}

/**
 * Persist cookies and localStorage from a BrowserContext to its profile store.
 */
export async function saveProfileStorageState(profileId, context = null, profilesDir = null) {
    const bound = context && profileContexts.get(context);
    const location = locateProfile(profileId, profilesDir || bound?.profilesDir || DEFAULT_PROFILES_DIR);
    const session = activeProfiles.get(location.key);
    if (bound && (bound.key !== location.key || session?.context !== context)) {
        throw new Error('Camoufox context does not belong to the active profile in this store');
    }
    if (context && session && session.context !== context) {
        throw new Error('Camoufox context does not match the active profile');
    }

    const targetContext = context || session?.context;
    if (!targetContext || pendingProfileStarts.has(location.key) ||
        pendingProfileStops.has(location.key) || pendingProfileDeletes.has(location.key)) {
        return null;
    }
    const saving = pendingProfileSaves.get(location.key);
    if (saving) {
        if (saving.context !== targetContext) {
            throw new Error('Another Camoufox context is saving this profile');
        }
        return saving.promise;
    }

    const savePromise = Promise.resolve()
        .then(() => persistProfileStorageState(location, targetContext))
        .finally(() => {
            pendingProfileSaves.delete(location.key);
        });
    pendingProfileSaves.set(location.key, { context: targetContext, promise: savePromise });
    return savePromise;
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

// Supply explicit empty values to override secrets-log settings inherited by the launcher.
function buildNativeLogEnvironment(env, { sslKeyLogPath, neckoMozLogPath, neckoMozLogModules } = {}) {
    return {
        ...process.env,
        ...env,
        SSLKEYLOGFILE: sslKeyLogPath || '',
        MOZ_LOG: neckoMozLogPath ? neckoMozLogModules : '',
        MOZ_LOG_FILE: neckoMozLogPath || '',
        NSPR_LOG_MODULES: '',
        NSPR_LOG_FILE: ''
    };
}

/**
 * Obtain or launch a shared Camoufox browser instance for multi-context profiles.
 */
async function getOrCreateSharedBrowser(options) {
    assertFirefoxCoherence(options);
    const targetOs = normalizeTargetOs(options.os);
    const headless = options.headless ?? (process.env.CAMOUFOX_HEADLESS === 'true');
    const humanize = options.humanize !== undefined ? options.humanize : true;
    const profilesDir = resolveProfilesRoot(options.profilesDir || DEFAULT_PROFILES_DIR);
    const configKey = JSON.stringify({ profilesDir, headless, humanize: Boolean(humanize) });

    const existing = sharedBrowsers.get(configKey);
    if (existing && existing.browser?.isConnected?.() !== false) return existing.promise;

    restrictLegacySharedKeyLog(profilesDir);
    const entry = { browser: null, promise: null };
    entry.promise = (async () => {
        const camoufoxMod = await resolveCamoufoxModule();
        const launchFn = camoufoxMod.AsyncCamoufox || camoufoxMod.Camoufox;
        const { recordHar: _ignored, ...baseLaunchOptions } = options.launchOptions || {};

        logger.info('Launching shared Camoufox browser instance', {
            os: targetOs,
            headless,
            humanize: Boolean(humanize)
        });

        const browser = await launchFn({
            os: targetOs,
            headless,
            humanize,
            canvas_noise: options.canvas_noise ?? true,
            ...baseLaunchOptions,
            env: buildNativeLogEnvironment(baseLaunchOptions.env)
        });

        entry.browser = browser;
        browser.on?.('disconnected', () => {
            if (sharedBrowsers.get(configKey) === entry) sharedBrowsers.delete(configKey);
        });
        return browser;
    })().catch((error) => {
        if (sharedBrowsers.get(configKey) === entry) sharedBrowsers.delete(configKey);
        throw error;
    });

    sharedBrowsers.set(configKey, entry);
    return entry.promise;
}

/**
 * Close the shared Camoufox browser instance(s) if running.
 */
export async function closeSharedBrowser() {
    const entries = [...sharedBrowsers.values()];
    sharedBrowsers.clear();
    const launches = await Promise.allSettled(entries.map((entry) => entry.promise));
    const instances = new Set(
        launches.filter((result) => result.status === 'fulfilled').map((result) => result.value)
    );
    for (const instance of instances) {
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
        resolveNetworkPolicyMode(options.portScanProtection, options.securityPolicy?.portScanProtection);
        assertFirefoxCoherence(options);

        const timestamp = Date.now();
        const seq = (++profileSeqCounter) % 10000;
        const randomNum = Math.floor(Math.random() * 10000) * 10000 + seq;
        const rawBaseName = profileName && String(profileName).trim().length > 0
            ? String(profileName).trim()
            : `Gmail_${timestamp}_${randomNum}`;

        const cleanName = rawBaseName.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 60);
        const profileId = validateProfileId(options.profileId ?? `${cleanName}_${timestamp}_${randomNum}`);

        const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;
        const targetOs = normalizeTargetOs(options.os);
        const location = locateProfile(profileId, profilesDir, true);
        const savedMetadata = readProfileMetadata(location);
        const requestedProxy = proxy || options.proxy || null;
        const managedProxyBinding = validateCamoufoxNetworkPolicy(options, requestedProxy, savedMetadata);
        const normalizedProxy = managedProxyBinding?.proxy ?? normalizeProxy(requestedProxy);
        const geoip = options.geoip !== undefined ? Boolean(options.geoip) : Boolean(normalizedProxy);
        const humanize = options.humanize !== undefined ? options.humanize : true;
        const headless = options.headless ?? (process.env.CAMOUFOX_HEADLESS === 'true' ? true : false);
        const useSharedBrowser = Boolean(options.useSharedBrowser);

        const { profileDir, storageStatePath, metadataPath } = ensureProfileStorageAt(location);
        const deviceProfile = resolveDeterministicDeviceProfile(profileId, {
            os: targetOs,
            presetId: options.presetId || options.preset || undefined,
            country: options.country || undefined,
            language: options.locale || undefined,
            timeZone: options.timezoneId || undefined,
            portScanProtection:
                options.portScanProtection !== undefined
                    ? Boolean(options.portScanProtection)
                    : options.enablePortScanProtection !== undefined
                      ? Boolean(options.enablePortScanProtection)
                      : true,
            allowedLocalPorts: options.allowedLocalPorts || undefined,
            canvasSkipHosts: options.canvasSkipHosts || undefined
        });

        if (managedProxyBinding) deviceProfile.securityPolicy.portScanProtection.mode = 'managed-proxy';

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
            presetId: deviceProfile.presetId,
            deviceModel: deviceProfile.hardwareProfile.deviceModel,
            deviceName: deviceProfile.deviceName,
            macAddress: deviceProfile.macAddress,
            resolvedLocale: deviceProfile.language,
            resolvedLanguages: deviceProfile.languages,
            acceptLanguage: deviceProfile.acceptLanguage,
            resolvedTimezoneId: deviceProfile.timeZone,
            resolvedGeolocation: deviceProfile.geolocation,
            securityPolicy: deviceProfile.securityPolicy,
            gpuPerformance: deviceProfile.gpuPerformance,
            hardwareProfile: deviceProfile.hardwareProfile,
            seeds: deviceProfile.seeds,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        writePrivateFile(metadataPath, JSON.stringify(metadata, null, 2));

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
    return readProfileMetadata(locateProfile(profileId, options.profilesDir || DEFAULT_PROFILES_DIR));
}

/**
 * List all saved Camoufox profiles on disk.
 */
export async function listProfiles(profilesDir = DEFAULT_PROFILES_DIR) {
    const root = resolveProfilesRoot(profilesDir);
    if (!fs.existsSync(root)) return [];

    const profiles = [];
    for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        try {
            const metadata = readProfileMetadata(locateProfile(entry.name, root));
            if (metadata) profiles.push(metadata);
        } catch (error) {
            logger.warn('Skipping unreadable profile metadata', {
                profileId: entry.name,
                error: error.message
            });
        }
    }
    return profiles;
}

export function validateCamoufoxNetworkPolicy(options, proxy, savedMetadata) {
    const storedMode = resolveNetworkPolicyMode(
        savedMetadata?.portScanProtection,
        savedMetadata?.securityPolicy?.portScanProtection
    );
    const mode = resolveNetworkPolicyMode(
        storedMode === 'managed-proxy' ? { mode: storedMode } : undefined,
        options.portScanProtection,
        options.securityPolicy?.portScanProtection
    );
    if (mode !== 'managed-proxy') return null;

    const definedOptions = Object.fromEntries(
        Object.entries(options).filter(([, value]) => value !== undefined)
    );
    let normalizedProxy;
    try {
        normalizedProxy = normalizeProxy(proxy);
    } catch {
        // Report a binding error without echoing the input proxy URL or credentials.
        normalizedProxy = null;
    }
    return bindManagedProxy(normalizedProxy, { ...savedMetadata, ...definedOptions });
}

function checkRecordingReuse(session, options) {
    if (options.recordBodies === false && session?.recording?.recordBodies) {
        throw new Error('Stop this Camoufox profile before disabling body recording');
    }
}

function removeHarTemporaryDir(directory) {
    try {
        fs.rmSync(directory, { recursive: true, force: true });
    } catch (error) {
        logger.warn('Could not remove temporary Camoufox HAR data', { error: error.message });
    }
}

/**
 * Start a Camoufox profile by ID.
 * Supports both dedicated per-profile Camoufox browser instances and shared browser contexts,
 * loading and persisting `profiles/<profileId>/storage-state.json`.
 */
export async function startProfile(requestedProfileId, options = {}) {
    resolveNetworkPolicyMode(options.portScanProtection, options.securityPolicy?.portScanProtection);
    if (stoppingAllProfiles) {
        throw new Error('Camoufox profile shutdown is in progress');
    }
    const location = locateProfile(requestedProfileId, options.profilesDir || DEFAULT_PROFILES_DIR, true);
    const { id: profileId, profilesDir, key } = location;

    if (pendingProfileDeletes.has(key)) {
        throw new Error('Camoufox profile is being deleted');
    }
    const stopping = pendingProfileStops.get(key);
    if (stopping) {
        await stopping;
        return startProfile(profileId, { ...options, profilesDir });
    }
    const savedMetadata = readProfileMetadata(location);
    const requestedProxy = options.proxy !== undefined ? options.proxy : savedMetadata?.proxy;
    const managedProxyBinding = validateCamoufoxNetworkPolicy(options, requestedProxy, savedMetadata);
    const existing = activeProfiles.get(key);
    if (existing) {
        if (existing.view.browser.isConnected()) {
            assertManagedProxyReuse(existing.managedProxyBinding, managedProxyBinding);
            checkRecordingReuse(existing, options);
            logger.info('Reusing active Camoufox profile session', { profileId });
            return existing.view;
        }
        if (!(await stopProfileAt(location))) {
            throw new Error('Previous Camoufox profile session could not be stopped');
        }
        return startProfile(profileId, { ...options, profilesDir });
    }

    const starting = pendingProfileStarts.get(key);
    if (starting) {
        assertManagedProxyReuse(starting.managedProxyBinding, managedProxyBinding);
        const view = await starting.promise;
        checkRecordingReuse(activeProfiles.get(key), options);
        return view;
    }
    const saving = pendingProfileSaves.get(key);
    if (saving) {
        await saving.promise;
        return startProfile(profileId, { ...options, profilesDir });
    }

    const startPromise = (async () => {
        let browser = null;
        let context = null;
        let ownsBrowser = false;
        let securityGuards = null;
        let trafficRecorder = null;
        let harTemporaryDir = null;
        try {
            let metadata = savedMetadata;

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
            const normalizedProxy = managedProxyBinding?.proxy ?? normalizeProxy(mergedOptions.proxy);
            const geoip = mergedOptions.geoip !== undefined
                ? Boolean(mergedOptions.geoip)
                : Boolean(normalizedProxy);
            const humanize = mergedOptions.humanize !== undefined
                ? mergedOptions.humanize
                : true;
            const headless = mergedOptions.headless ?? false;
            const useSharedBrowser = Boolean(mergedOptions.useSharedBrowser);

            const storageInfo = ensureProfileStorageAt(location);
            const { storageStatePath } = storageInfo;
            readStorageState(storageStatePath);
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
            const sslKeyLog = !useSharedBrowser && (
                mergedOptions.sslKeyLog ?? (process.env.CAMOUFOX_SSLKEYLOG === 'true')
            ) === true;
            const neckoMozLog = !useSharedBrowser && (
                mergedOptions.neckoMozLog ?? (process.env.CAMOUFOX_NECKO_MOZ_LOG === 'true')
            ) === true;
            const neckoMozLogModules =
                options.neckoMozLogModules ||
                mergedOptions.neckoMozLogModules ||
                process.env.CAMOUFOX_NECKO_MOZ_LOG_MODULES ||
                'timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4';
            const { recordHar: nativeHarOptions, ...contextOptions } = mergedOptions.contextOptions || {};
            const recordHar = Boolean(
                nativeHarOptions ?? mergedOptions.recordHar ?? (process.env.CAMOUFOX_RECORD_HAR === 'true')
            );
            if (nativeHarOptions?.urlFilter !== undefined ||
                (nativeHarOptions?.mode !== undefined && nativeHarOptions.mode !== 'full')) {
                throw new Error('Camoufox HAR export does not support native URL filters or minimal mode');
            }
            const harBodies = recordBodies && nativeHarOptions?.content !== 'omit' &&
                nativeHarOptions?.omitContent !== true;
            let harPath = recordHar ? storageInfo.harPath : null;
            if (nativeHarOptions?.path) {
                const requestedPath = path.resolve(nativeHarOptions.path);
                const requestedDir = resolveProfilesRoot(path.dirname(requestedPath));
                if (requestedDir !== storageInfo.trafficDir || path.extname(requestedPath).toLowerCase() !== '.har') {
                    throw new Error('Camoufox HAR path must be a .har file directly in its profile traffic directory');
                }
                harPath = path.join(requestedDir, path.basename(requestedPath));
            }

            restrictLegacySharedKeyLog(profilesDir);
            prepareNativeLogs(storageInfo, { sslKeyLog, neckoMozLog, harPath });
            const maxBodyBytes = mergedOptions.maxBodyBytes !== undefined
                ? mergedOptions.maxBodyBytes
                : (process.env.CAMOUFOX_TRAFFIC_MAX_BODY_BYTES
                    ? parseInt(process.env.CAMOUFOX_TRAFFIC_MAX_BODY_BYTES, 10)
                    : 5242880);

            const trafficPaths = {
                trafficDir: storageInfo.trafficDir,
                payloadsDir: storageInfo.payloadsDir,
                sslKeyLogPath: sslKeyLog ? storageInfo.sslKeyLogPath : null,
                preTlsWireLogPath: storageInfo.preTlsWireLogPath,
                neckoMozLogPath: neckoMozLog ? storageInfo.neckoMozLogPath : null,
                trafficNdjsonPath: storageInfo.trafficNdjsonPath,
                attributionIndexPath: storageInfo.attributionIndexPath,
                harPath: harPath || storageInfo.harPath
            };

            const { recordHar: _ignored, ...launchOptions } = mergedOptions.launchOptions || {};
            const profileEnv = { ...launchOptions.env, ...options.env };
            if (managedProxyBinding) {
                assertManagedProxyReuse(managedProxyBinding, bindManagedProxy(normalizedProxy, {
                    ...mergedOptions, launchOptions, contextOptions, env: profileEnv
                }));
            }

            const camoufoxMod = await resolveCamoufoxModule();
            const launchFn = camoufoxMod.AsyncCamoufox || camoufoxMod.Camoufox;
            const newContextFn = camoufoxMod.AsyncNewContext || camoufoxMod.NewContext;

            // Resolve deterministic metropolitan geolocation coordinates (with street-level micro-jitter)
            const rawGeoSource =
                mergedOptions.geolocation &&
                Number.isFinite(Number(mergedOptions.geolocation.latitude)) &&
                Number.isFinite(Number(mergedOptions.geolocation.longitude))
                    ? mergedOptions.geolocation
                    : options.country || mergedOptions.country
                      ? resolveGeoCoordinatesWithDeterministicJitter(
                            profileId,
                            options.country || mergedOptions.country
                        )
                      : mergedOptions.resolvedGeolocation || null;
            const hasExplicitGeolocation = Boolean(
                options.geolocation ||
                    options.country ||
                    (!geoip &&
                        rawGeoSource &&
                        Number.isFinite(Number(rawGeoSource.latitude)) &&
                        Number.isFinite(Number(rawGeoSource.longitude)))
            );
            const playwrightGeolocation =
                rawGeoSource &&
                Number.isFinite(Number(rawGeoSource.latitude)) &&
                Number.isFinite(Number(rawGeoSource.longitude))
                    ? {
                          latitude: Number(rawGeoSource.latitude),
                          longitude: Number(rawGeoSource.longitude),
                          ...(Number.isFinite(Number(rawGeoSource.accuracy))
                              ? { accuracy: Number(rawGeoSource.accuracy) }
                              : {})
                      }
                    : null;
            const effectiveLocale =
                mergedOptions.locale || (!geoip ? mergedOptions.resolvedLocale : null) || null;
            const effectiveTimezoneId =
                mergedOptions.timezoneId || (!geoip ? mergedOptions.resolvedTimezoneId : null) || null;
            const effectiveLaunchConfig =
                hasExplicitGeolocation && playwrightGeolocation
                    ? {
                          'geolocation:latitude': playwrightGeolocation.latitude,
                          'geolocation:longitude': playwrightGeolocation.longitude,
                          'geolocation:accuracy': playwrightGeolocation.accuracy ?? 35,
                          ...(mergedOptions.config || {})
                      }
                    : mergedOptions.config || null;

            if (useSharedBrowser) {
                browser = await getOrCreateSharedBrowser({
                    os: targetOs,
                    headless,
                    humanize,
                    profilesDir,
                    canvas_noise: true,
                    launchOptions: {
                        ...launchOptions,
                        env: profileEnv
                    }
                });
                ownsBrowser = false;

                const contextOpts = {
                    os: targetOs,
                    storageState: storageStatePath,
                    ...(normalizedProxy ? { proxy: normalizedProxy } : {}),
                    ...(mergedOptions.webrtc_ip ? { webrtc_ip: mergedOptions.webrtc_ip } : {}),
                    ...(hasExplicitGeolocation && playwrightGeolocation
                        ? { geolocation: playwrightGeolocation }
                        : {}),
                    ...(effectiveLocale ? { locale: effectiveLocale } : {}),
                    ...(effectiveTimezoneId ? { timezoneId: effectiveTimezoneId } : {}),
                    ...(mergedOptions.ff_version ? { ff_version: mergedOptions.ff_version } : {}),
                    ...(mergedOptions.preset ? { preset: mergedOptions.preset } : {}),
                    ...contextOptions
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
                    ...(effectiveLocale ? { locale: effectiveLocale } : {}),
                    ...(mergedOptions.ff_version ? { ff_version: mergedOptions.ff_version } : {}),
                    ...(mergedOptions.preset ? { preset: mergedOptions.preset } : {}),
                    ...(mergedOptions.addons ? { addons: mergedOptions.addons } : {}),
                    ...(mergedOptions.fonts ? { fonts: mergedOptions.fonts } : {}),
                    ...(mergedOptions.screen ? { screen: mergedOptions.screen } : {}),
                    ...(mergedOptions.window ? { window: mergedOptions.window } : {}),
                    ...(effectiveLaunchConfig ? { config: effectiveLaunchConfig } : {}),
                    ...(mergedOptions.firefox_user_prefs
                        ? { firefox_user_prefs: mergedOptions.firefox_user_prefs }
                        : {}),
                    ...launchOptions,
                    env: buildNativeLogEnvironment(profileEnv, {
                        sslKeyLogPath: trafficPaths.sslKeyLogPath,
                        neckoMozLogPath: trafficPaths.neckoMozLogPath,
                        neckoMozLogModules
                    })
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
                    ...(effectiveTimezoneId ? { timezoneId: effectiveTimezoneId } : {}),
                    ...(hasExplicitGeolocation && playwrightGeolocation
                        ? { geolocation: playwrightGeolocation }
                        : {}),
                    ...contextOptions
                };

                context = await browser.newContext(contextOpts);
            }

            const fingerprintLedger = new CanvasWebglConsistencyLedger({
                profileId,
                ledgerPath: path.join(storageInfo.profileDir, 'fingerprint-ledger.json'),
                maxHammingDistance:
                    options.maxHammingDistance ??
                    mergedOptions.maxHammingDistance ??
                    0,
                skipHosts: mergedOptions.securityPolicy?.canvasSkipHosts
            });

            const shouldAttachSecurityGuards =
                options.enablePortScanProtection !== false &&
                mergedOptions.enablePortScanProtection !== false &&
                mergedOptions.securityPolicy?.portScanProtection?.enabled !== false;
            if (shouldAttachSecurityGuards) {
                const customOnBlockedAttempt =
                    options.onBlockedAttempt ?? mergedOptions.onBlockedAttempt;
                const basePortProt = mergedOptions.securityPolicy?.portScanProtection || {};
                const runtimePortProt = options.portScanProtection || {};
                const effectivePortScanProtection = {
                    ...basePortProt,
                    ...runtimePortProt,
                    ...(managedProxyBinding ? { mode: 'managed-proxy' } : {}),
                    ...(Array.isArray(options.allowedLocalPorts)
                        ? { allowedPorts: options.allowedLocalPorts }
                        : {}),
                    ...(options.allowSameOriginLocalDev !== undefined
                        ? { allowSameOriginLocalDev: Boolean(options.allowSameOriginLocalDev) }
                        : {})
                };
                securityGuards = await attachZiniaoSecurityGuardsToContext(context, {
                    profileId,
                    managedProxyBinding,
                    portScanProtection: effectivePortScanProtection,
                    allowedExtensionIds: options.allowedExtensionIds ?? mergedOptions.allowedExtensionIds,
                    onBlockedAttempt: (blockedEvent) => {
                        logger.warn('Ziniao security guard blocked suspicious browser probe', {
                            profileId,
                            type: blockedEvent?.type,
                            targetUrl: redactUrlSecrets(blockedEvent?.targetUrl),
                            initiatorUrl: redactUrlSecrets(blockedEvent?.initiatorUrl),
                            reason: redactDiagnosticText(blockedEvent?.reason),
                            port: blockedEvent?.port ?? null,
                            service: blockedEvent?.service ?? null
                        });
                        if (trafficRecorder) {
                            try {
                                if (typeof trafficRecorder.recordSecurityBlock === 'function') {
                                    trafficRecorder.recordSecurityBlock(blockedEvent);
                                } else if (typeof trafficRecorder.recordTriggerAction === 'function') {
                                    trafficRecorder.recordTriggerAction(
                                        `security.${blockedEvent?.type || 'blocked-probe'}`,
                                        blockedEvent?.targetUrl || null,
                                        blockedEvent
                                    );
                                }
                            } catch {}
                        }
                        if (typeof customOnBlockedAttempt === 'function') {
                            customOnBlockedAttempt(blockedEvent);
                        }
                    }
                });
            }

            let gpuPerformanceScaler = null;
            if (
                options.enableGpuPerformanceScaling !== false &&
                mergedOptions.enableGpuPerformanceScaling !== false
            ) {
                gpuPerformanceScaler = await attachGpuPerformanceScalerToContext(
                    context,
                    mergedOptions.gpuPerformance ||
                        mergedOptions.hardwareProfile?.gpuModel ||
                        mergedOptions.deviceModel ||
                        targetOs,
                    { profileId }
                );
            }

            const existingPages = context.pages();
            const page = existingPages.length > 0 ? existingPages[0] : await context.newPage();

            if (recordTraffic || recordHar) {
                if (!recordTraffic) {
                    ensurePrivateDirectory(storageInfo.nativeDir);
                    harTemporaryDir = fs.mkdtempSync(path.join(storageInfo.nativeDir, 'har-'));
                }
                trafficRecorder = new CamoufoxTrafficRecorder({
                    profileId,
                    trafficDir: harTemporaryDir || storageInfo.trafficDir,
                    profileNativeDir: recordTraffic ? storageInfo.nativeDir : null,
                    trustedLocal: true,
                    sslKeyLog: recordTraffic && sslKeyLog,
                    sslKeyLogPath: trafficPaths.sslKeyLogPath,
                    preTlsWireLogPath: recordTraffic ? storageInfo.preTlsWireLogPath : null,
                    neckoMozLog: recordTraffic && neckoMozLog,
                    neckoMozLogPath: trafficPaths.neckoMozLogPath,
                    harPath,
                    os: targetOs,
                    proxyServer: normalizedProxy?.server || null,
                    accountId: options.accountId ?? mergedOptions.accountId ?? null,
                    accountEmail: options.accountEmail ?? mergedOptions.accountEmail ?? null,
                    recordBodies: recordTraffic ? recordBodies : harBodies,
                    recordWireLog: recordTraffic && recordWireLog,
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
                trafficRecorder: recordTraffic ? trafficRecorder : null,
                trafficPaths,
                fingerprintLedger,
                securityGuards,
                gpuPerformanceScaler,
                metadata: {
                    ...metadata,
                    os: targetOs,
                    proxy: normalizedProxy,
                    geoip,
                    humanize,
                    trafficPaths
                }
            };

            const { attachSessionCompatibility } = await import('./profile.js');
            const view = attachSessionCompatibility(session);
            profileContexts.set(context, location);
            activeProfiles.set(key, {
                ...session,
                location,
                view,
                managedProxyBinding,
                recording: trafficRecorder,
                harPath,
                harTemporaryDir,
                harBodies,
                storageInfo
            });
            registerProcessCleanupHooks();

            logger.info('Camoufox profile started', {
                profileId,
                os: targetOs,
                storageStatePath,
                useSharedBrowser
            });

            return view;
        } catch (error) {
            if (trafficRecorder && typeof trafficRecorder.stop === 'function') {
                await trafficRecorder.stop().catch(() => {});
            }
            if (harTemporaryDir) removeHarTemporaryDir(harTemporaryDir);
            if (securityGuards && typeof securityGuards.detach === 'function') {
                await securityGuards.detach().catch(() => {});
            }
            if (context && typeof context.close === 'function') {
                await context.close().catch(() => {});
            }
            if (ownsBrowser && browser && typeof browser.close === 'function') {
                await browser.close().catch(() => {});
            }
            logger.error('Error starting Camoufox profile', {
                profileId,
                error: error.message
            });
            throw error;
        }
    })().finally(() => {
        pendingProfileStarts.delete(key);
    });

    pendingProfileStarts.set(key, { promise: startPromise, managedProxyBinding });
    return startPromise;
}

/**
 * Stop an active Camoufox profile by ID, saving cookies and localStorage first.
 */
export async function stopProfile(profileId, options = {}) {
    return stopProfileAt(locateProfile(profileId, options.profilesDir || DEFAULT_PROFILES_DIR));
}

async function finalizeProfileRecording(session) {
    await session.recording.stop();
    if (session.harPath) {
        session.recording.exportHar(session.harPath, { recordBodies: session.harBodies });
    }
    session.recordingFinalized = true;
}

function stopProfileAt(location) {
    const { id: profileId, key } = location;
    const stopping = pendingProfileStops.get(key);
    if (stopping) return stopping;

    const stopPromise = (async () => {
        await Promise.allSettled([pendingProfileStarts.get(key)?.promise, pendingProfileSaves.get(key)?.promise]);
        const session = activeProfiles.get(key);
        if (!session) return true;

        let contextClosed = !session.context;
        let browserClosed = !session.ownsBrowser || !session.browser;
        try {
            if (session.recording && !session.recordingFinalized) {
                try {
                    await finalizeProfileRecording(session);
                } catch (error) {
                    logger.warn('Could not finalize Camoufox traffic recording', {
                        profileId,
                        error: error.message
                    });
                }
            }
            if (session.securityGuards) {
                try {
                    await session.securityGuards.detach?.();
                } catch (error) {
                    logger.debug('Error detaching Ziniao security guards', {
                        profileId,
                        error: error.message
                    });
                }
            }
            try {
                session.fingerprintLedger?.saveToDisk();
            } catch (error) {
                logger.debug('Could not save Camoufox fingerprint ledger', {
                    profileId,
                    error: error.message
                });
            }

            if (session.context) {
                try {
                    await persistProfileStorageState(session.location, session.context);
                } catch (error) {
                    logger.warn('Could not save storage state before stopping profile', {
                        profileId,
                        error: error.message
                    });
                }
                try {
                    await session.context.close();
                    contextClosed = true;
                } catch (error) {
                    contextClosed = !session.view.browser.isConnected();
                    logger.debug('Error closing Camoufox context', { profileId, error: error.message });
                }
            }

            if (session.ownsBrowser && session.browser) {
                try {
                    await session.browser.close();
                    contextClosed = true;
                    browserClosed = true;
                } catch (error) {
                    browserClosed = session.browser.isConnected?.() === false;
                    contextClosed ||= browserClosed;
                    logger.debug('Error closing Camoufox browser', { profileId, error: error.message });
                }
            }
            if (!contextClosed || !browserClosed) return false;

            restrictNativeLogs(session.storageInfo);
            const { sslKeyLogPath, neckoMozLogPath } = session.trafficPaths;
            if (session.trafficRecorder && (sslKeyLogPath || neckoMozLogPath)) {
                // The native process can append diagnostics until it closes.
                if (session.recordingFinalized) {
                    await session.trafficRecorder.flushSummary();
                } else {
                    await finalizeProfileRecording(session);
                }
            }
            logger.info('Camoufox profile stopped', { profileId });
            return !session.recording || session.recordingFinalized;
        } catch (error) {
            logger.warn('Error stopping Camoufox profile', { profileId, error: error.message });
            return false;
        } finally {
            if (session.harTemporaryDir && (session.recordingFinalized || (contextClosed && browserClosed))) {
                removeHarTemporaryDir(session.harTemporaryDir);
                session.harTemporaryDir = null;
            }
            if (contextClosed && browserClosed) activeProfiles.delete(key);
        }
    })().finally(() => {
        pendingProfileStops.delete(key);
    });
    pendingProfileStops.set(key, stopPromise);
    return stopPromise;
}

/**
 * Delete a profile and remove its persistent storage directory (`profiles/<profileId>/`).
 */
export async function deleteProfile(profileId, options = {}) {
    const location = locateProfile(profileId, options.profilesDir || DEFAULT_PROFILES_DIR);
    const { profileDir, key } = location;
    const deleting = pendingProfileDeletes.get(key);
    if (deleting) return deleting;

    const deletePromise = (async () => {
        await Promise.allSettled([pendingProfileStarts.get(key)?.promise, pendingProfileSaves.get(key)?.promise]);
        const checked = inspectProfileForDeletion(location);
        if (!checked) {
            if (activeProfiles.has(key)) {
                throw new Error('Active Camoufox profile directory is missing');
            }
            return true;
        }

        if (!(await stopProfileAt(location))) {
            throw new Error('Could not stop Camoufox profile before deletion');
        }
        const current = inspectProfileForDeletion(location);
        if (!current) return true;
        if (current.dev !== checked.dev || current.ino !== checked.ino) {
            throw new Error('Camoufox profile directory changed during deletion');
        }
        fs.rmSync(profileDir, { recursive: true });
        logger.info('Camoufox profile deleted', { profileId: location.id, profileDir });
        return true;
    })().finally(() => {
        pendingProfileDeletes.delete(key);
    });
    pendingProfileDeletes.set(key, deletePromise);
    return deletePromise;
}

/**
 * Update proxy configuration for one or more profile IDs.
 */
export async function updateProfileProxy(profileIds, proxy, options = {}) {
    const ids = (Array.isArray(profileIds) ? profileIds : [profileIds]).map(validateProfileId);
    const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;
    const profiles = ids.map((id) => {
        const location = locateProfile(id, profilesDir, true);
        const existing = readProfileMetadata(location) || {
            id,
            profileId: id,
            title: id,
            os: getHostTargetOs(),
            browserFamily: 'firefox',
            humanize: true
        };
        const binding = validateCamoufoxNetworkPolicy({}, proxy, existing);
        return { location, existing, binding };
    });
    const boundProxy = profiles.find(({ binding }) => binding)?.binding.proxy;
    const normalizedProxy = boundProxy ?? normalizeProxy(proxy);

    for (const { location, existing } of profiles) {
        const updated = {
            ...existing,
            proxy: normalizedProxy,
            geoip: normalizedProxy ? true : Boolean(existing.geoip),
            updatedAt: new Date().toISOString()
        };

        const { metadataPath } = ensureProfileStorageAt(location);
        writePrivateFile(metadataPath, JSON.stringify(updated, null, 2));
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
    return [...new Set([...activeProfiles.values()].map((session) => session.profileId))];
}

/**
 * Gracefully stop all active Camoufox profiles concurrently, flushing each profile's
 * traffic recorder, persisting storage state, and closing shared Camoufox browsers.
 */
export function stopAllActiveProfiles(reason = 'shutdown') {
    if (stoppingAllProfiles) return stoppingAllProfiles;
    stoppingAllProfiles = stopAllProfiles(reason).finally(() => {
        stoppingAllProfiles = null;
    });
    return stoppingAllProfiles;
}

async function stopAllProfiles(reason) {
    if (pendingProfileStarts.size > 0) {
        await Promise.allSettled([...pendingProfileStarts.values()].map((entry) => entry.promise));
    }

    const sessions = [...activeProfiles.values()];
    const profileIds = sessions.map((session) => session.profileId);
    if (profileIds.length > 0) {
        logger.info('Stopping all active Camoufox profiles', {
            reason,
            count: profileIds.length,
            profileIds
        });
    }

    const results = await Promise.allSettled(
        sessions.map((session) => stopProfileAt(session.location))
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
        if (activeProfiles.size || pendingProfileStarts.size || sharedBrowsers.size) {
            stopAllActiveProfiles('SIGINT').catch((error) => {
                logger.warn('Error flushing active Camoufox profiles on SIGINT', {
                    error: error.message
                });
            });
        }
    };

    sigtermCleanupHandler = () => {
        if (activeProfiles.size || pendingProfileStarts.size || sharedBrowsers.size) {
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
    unregisterProcessCleanupHooks,
    USABLE_DEVICE_PRESET_CATALOG,
    listUsableDevicePresets,
    resolveDeterministicDeviceProfile,
    sanitizeAdsPowerProfileToCoherentPreset,
    sanitizeZiniaoProfileToCoherentPreset,
    CanvasWebglConsistencyLedger,
    attachZiniaoSecurityGuardsToContext,
    evaluatePortScanRequest,
    evaluateInternalSchemeAccess,
    computeHexHammingDistance,
    computeHashSimilarity,
    shouldSkipCanvasNoiseForHost,
    validateOsAndBrowserVersionMatch,
    resolveGeoCoordinatesWithDeterministicJitter,
    sanitizeRtcConfigurationIceServers,
    buildZiniaoWebRtcSecurityInitScript,
    GPU_PERFORMANCE_SPEC_CATALOG,
    lookupGpuPerformanceSpec,
    collectHostMacPerformanceBaseline,
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    buildGpuPerformanceInitScript,
    attachGpuPerformanceScalerToContext,
    validateGpuPerformanceScalingCoherence
};
