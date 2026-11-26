/**
 * Camoufox Browser Profile Client
 * Open-source C++-patched Firefox antidetect replacement for Dolphin Anty & GPM Login
 */

import { randomUUID } from 'node:crypto';
import fs from 'fs';
import path from 'path';
import { isDeepStrictEqual } from 'node:util';
import logger from '../utils/logger.js';
import { getDefaultProfilesDirectory } from '../utils/state-paths.js';
import { ensurePrivateDirectory, writePrivateFile } from '../utils/private-storage.js';
import {
    assertManagedProxyLaunchEnvironment,
    assertManagedProxyReuse,
    bindManagedProxy,
    resolveConfiguredNetworkPolicyMode,
    resolveNetworkPolicyMode
} from './network-policy.js';
import { loadCamoufoxModule } from './sdk-resolution.js';
import {
    acquireProfileLease,
    archiveLegacyNativeLogs,
    assertProfileIdentity,
    assertProfileLease,
    ensureProfileStorageAt,
    initializeProfileStorageAt,
    inspectProfileForDeletion,
    locateProfile,
    prepareNativeLogs,
    PROFILE_LEASE_DIRECTORY,
    readProfileMetadata,
    readStorageState,
    releaseProfileLease,
    resolveProfilesRoot,
    restrictLegacySharedKeyLog,
    restrictNativeLogs,
    stampProfileIdentity,
    validateProfileId
} from './profile-storage.js';
import { CamoufoxTrafficRecorder, selectProfileNativeLogPaths } from './traffic-recorder.js';
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

const DEFAULT_PROFILES_DIR = getDefaultProfilesDirectory();

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
let closingSharedBrowsers = null;
let processCleanupEnabled = false;
let processCleanupAttached = false;

/**
 * Inject or reset a custom/mock Camoufox module implementation (used by isolation tests).
 */
export function setCamoufoxModule(mockModule = null) {
    cachedCamoufoxModule = mockModule || null;
    return cachedCamoufoxModule;
}

/**
 * Load the installed `camoufox` package.
 */
export async function resolveCamoufoxModule() {
    if (cachedCamoufoxModule) {
        return cachedCamoufoxModule;
    }

    try {
        cachedCamoufoxModule = await loadCamoufoxModule();
        return cachedCamoufoxModule;
    } catch (cause) {
        throw new Error("Unable to load the installed 'camoufox' package", { cause });
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

function defaultProfileMetadata(location) {
    return {
        id: location.id,
        profileId: location.id,
        title: location.id,
        os: getHostTargetOs(),
        browserFamily: 'firefox',
        humanize: true
    };
}

function assertProfileOwner(session) {
    assertProfileLease(session.lease);
    assertProfileIdentity(session.location, session.identity);
}

// Synchronous storage updates can use the lease of this process's active session.
function leaseForStorageUpdate(location) {
    const { key } = location;
    if (pendingProfileStarts.has(key) || pendingProfileStops.has(key) || pendingProfileDeletes.has(key)) {
        throw Object.assign(new Error('Camoufox profile lifecycle change is in progress'), {
            code: 'ERR_CAMOUFOX_PROFILE_BUSY'
        });
    }
    const session = activeProfiles.get(key);
    if (session) {
        assertProfileOwner(session);
        return null;
    }
    return acquireProfileLease(location);
}

/**
 * Prepare an owned profile store, reserving a new directory only if the ID is unused.
 */
export function ensureProfileStorage(profileId, profilesDir = DEFAULT_PROFILES_DIR) {
    const location = locateProfile(profileId, profilesDir, true);
    const lease = leaseForStorageUpdate(location);
    try {
        if (readProfileMetadata(location)) return ensureProfileStorageAt(location);
        return initializeProfileStorageAt(location, defaultProfileMetadata(location)).storage;
    } finally {
        if (lease) releaseProfileLease(lease);
    }
}

/**
 * Read saved storage state if present and valid.
 */
export function loadStorageState(profileId, profilesDir = DEFAULT_PROFILES_DIR) {
    const location = locateProfile(profileId, profilesDir);
    const storageStatePath = getStorageStatePath(location.id, location.profilesDir);
    if (readProfileMetadata(location)) {
        try {
            readStorageState(storageStatePath);
            return storageStatePath;
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
    }
    const storage = ensureProfileStorage(location.id, location.profilesDir);
    readStorageState(storage.storageStatePath);
    return storage.storageStatePath;
}

async function persistProfileStorageState(session) {
    const { location, context, storageStatePath } = session;
    assertProfileOwner(session);
    const state = await context.storageState();
    if (!Array.isArray(state?.cookies) || !Array.isArray(state?.origins)) {
        throw new TypeError('Invalid Camoufox storage state');
    }

    assertProfileOwner(session);
    try {
        readStorageState(storageStatePath);
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
    }
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
 * Persist cookies and localStorage from the BrowserContext registered to this store.
 */
export async function saveProfileStorageState(profileId, context = null, profilesDir = null) {
    const id = validateProfileId(profileId);
    const bound = profileContexts.get(context);
    const location = bound && !profilesDir
        ? bound
        : locateProfile(id, profilesDir || DEFAULT_PROFILES_DIR);
    const session = activeProfiles.get(location.key);
    if (context != null && (!bound || bound.id !== id || bound.key !== location.key || session?.context !== context)) {
        throw new Error('Camoufox context does not belong to the active profile in this store');
    }

    if (!session || pendingProfileStarts.has(location.key) ||
        pendingProfileStops.has(location.key) || pendingProfileDeletes.has(location.key)) {
        return null;
    }
    const saving = pendingProfileSaves.get(location.key);
    if (saving) return saving.promise;

    const savePromise = Promise.resolve()
        .then(() => persistProfileStorageState(session))
        .finally(() => {
            pendingProfileSaves.delete(location.key);
        });
    pendingProfileSaves.set(location.key, { promise: savePromise });
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

const BROWSER_ENV_KEYS = [
    'PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'TZ', 'LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE',
    'LC_COLLATE', 'LC_MESSAGES', 'LC_MONETARY', 'LC_NUMERIC', 'LC_TIME',
    'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'MOZ_ENABLE_WAYLAND', 'GDK_BACKEND',
    'XDG_SESSION_TYPE', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME',
    'XDG_DATA_HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
    'SystemRoot', 'SystemDrive', 'WINDIR', 'COMSPEC', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
    'ProgramFiles', 'ProgramFiles(x86)', 'PROGRAMDATA'
];

function buildBrowserEnvironment(overrides) {
    return Object.fromEntries(BROWSER_ENV_KEYS.flatMap((name) => {
        const value = overrides[name] ?? process.env[name];
        return typeof value === 'string' ? [[name, value]] : [];
    }));
}

// The launcher receives explicit empty native log values for disabled diagnostics.
function buildNativeLogEnvironment(env, { sslKeyLogPath, neckoMozLogPath, neckoMozLogModules } = {}) {
    return {
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
    if (closingSharedBrowsers) await closingSharedBrowsers;
    assertFirefoxCoherence(options);
    const targetOs = normalizeTargetOs(options.os);
    const headless = options.headless ?? (process.env.CAMOUFOX_HEADLESS === 'true');
    const humanize = options.humanize !== undefined ? options.humanize : true;
    const profilesDir = resolveProfilesRoot(options.profilesDir || DEFAULT_PROFILES_DIR);
    const env = buildNativeLogEnvironment(options.env);
    const configKey = JSON.stringify({ profilesDir, headless, humanize, env });

    const existing = sharedBrowsers.get(configKey);
    if (existing && existing.browser?.isConnected?.() !== false) return existing.promise;

    restrictLegacySharedKeyLog(profilesDir);
    const entry = { browser: null, promise: null };
    entry.promise = (async () => {
        const camoufoxMod = await resolveCamoufoxModule();
        const launchFn = camoufoxMod.AsyncCamoufox || camoufoxMod.Camoufox;
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
            env
        });

        entry.browser = browser;
        browser.on?.('disconnected', () => {
            if (sharedBrowsers.get(configKey) === entry) sharedBrowsers.delete(configKey);
            updateProcessCleanupHooks();
        });
        return browser;
    })().catch((error) => {
        if (sharedBrowsers.get(configKey) === entry) sharedBrowsers.delete(configKey);
        updateProcessCleanupHooks();
        throw error;
    });

    sharedBrowsers.set(configKey, entry);
    updateProcessCleanupHooks();
    return entry.promise;
}

/**
 * Close the shared Camoufox browser instance(s) if running.
 */
export function closeSharedBrowser() {
    if (closingSharedBrowsers) return closingSharedBrowsers;
    closingSharedBrowsers = closeSharedBrowsers().finally(() => {
        closingSharedBrowsers = null;
    });
    return closingSharedBrowsers;
}

async function closeSharedBrowsers() {
    const entries = [...sharedBrowsers.entries()];
    const launches = await Promise.allSettled(entries.map(([, entry]) => entry.promise));
    const instances = new Set(
        launches.filter((result) => result.status === 'fulfilled').map((result) => result.value)
    );
    const closed = new Set();
    for (const instance of instances) {
        if (instance.isConnected?.() !== false) {
            try {
                await instance.close();
            } catch (error) {
                if (instance.isConnected?.() !== false) {
                    logger.warn('Error closing shared Camoufox browser', {
                        error: redactDiagnosticText(error.message)
                    });
                    continue;
                }
            }
        }
        closed.add(instance);
        logger.info('Shared Camoufox browser closed');
    }
    for (const [key, entry] of entries) {
        if (closed.has(entry.browser) && sharedBrowsers.get(key) === entry) sharedBrowsers.delete(key);
    }

    const disconnected = [...activeProfiles.values()].filter((session) =>
        !session.ownsBrowser && closed.has(session.browser)
    );
    await Promise.allSettled(disconnected.map((session) => {
        session.contextClosed = true;
        return stopProfileAt(session.location);
    }));
    updateProcessCleanupHooks();
    return closed.size === instances.size;
}

/**
 * Create a new isolated Camoufox profile and persist its metadata + initial storage-state.json.
 */
export async function createProfile(profileName, proxy = null, options = {}) {
    try {
        resolveConfiguredNetworkPolicyMode(options.portScanProtection, options.securityPolicy?.portScanProtection);
        assertFirefoxCoherence(options);

        const profileId = validateProfileId(options.profileId ?? `profile-${randomUUID()}`);
        const rawBaseName = profileName && String(profileName).trim().length > 0
            ? String(profileName).trim()
            : profileId;
        const cleanName = rawBaseName.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 60);

        const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;
        const location = locateProfile(profileId, profilesDir, true);
        const requestedProxy = proxy || options.proxy || null;
        const savedMetadata = readProfileMetadata(location, { readOnly: true });
        const managedProxyBinding = validateCamoufoxNetworkPolicy(options, requestedProxy, savedMetadata);
        if (savedMetadata) {
            throw Object.assign(new Error('Camoufox profile ID already exists'), { code: 'EEXIST' });
        }
        const lease = acquireProfileLease(location);
        try {
            return createProfileAt(location, cleanName, requestedProxy, options, managedProxyBinding);
        } finally {
            releaseProfileLease(lease);
        }
    } catch (error) {
        logger.error('Error creating Camoufox profile', { error: error.message });
        throw error;
    }
}

function createProfileAt(location, cleanName, requestedProxy, options, managedProxyBinding) {
    const { id: profileId } = location;
    const targetOs = normalizeTargetOs(options.os);
    const normalizedProxy = managedProxyBinding?.proxy ?? normalizeProxy(requestedProxy);
    const geoip = options.geoip !== undefined ? Boolean(options.geoip) : Boolean(normalizedProxy);
    const humanize = options.humanize !== undefined ? options.humanize : true;
    const headless = options.headless ?? (process.env.CAMOUFOX_HEADLESS === 'true' ? true : false);
    const useSharedBrowser = Boolean(options.useSharedBrowser);

    const { profileDir, profilesDir } = location;
    const storageStatePath = getStorageStatePath(profileId, profilesDir);
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

    const { metadata } = initializeProfileStorageAt(location, {
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
    });

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
}

/**
 * Read profile metadata from disk.
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
        if (!entry.isDirectory() || entry.name === PROFILE_LEASE_DIRECTORY) continue;
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
    const mode = resolveConfiguredNetworkPolicyMode(
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

function resolveGuardSettings(options, managedProxyBinding) {
    const base = options.securityPolicy?.portScanProtection;
    const runtime = options.portScanProtection;
    const shouldAttach = options.enablePortScanProtection !== false && runtime !== false && (
        options.enablePortScanProtection === true || runtime === true || runtime?.enabled === true ||
        (base !== false && base?.enabled !== false)
    );
    const effective = { ...base, ...runtime };
    const allowedPorts = Array.isArray(options.allowedLocalPorts) ? options.allowedLocalPorts : effective.allowedPorts || [];
    const validPorts = allowedPorts.map(Number).filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
    const allowedLocalDev = options.allowSameOriginLocalDev !== undefined
        ? options.allowSameOriginLocalDev
        : effective.allowSameOriginLocalDev;
    const enabled = runtime?.enabled === undefined
        ? options.enablePortScanProtection === true || runtime === true || base?.enabled === undefined || Boolean(base.enabled)
        : Boolean(runtime.enabled);
    return {
        shouldAttach,
        portScanProtection: {
            mode: managedProxyBinding ? 'managed-proxy' : 'url-only',
            enabled: shouldAttach && enabled,
            allowedPorts: [...new Set(validPorts)].sort((a, b) => a - b),
            allowSameOriginLocalDev: Boolean(allowedLocalDev)
        },
        allowedExtensionIds: [...new Set((options.allowedExtensionIds || []).map((id) => String(id).toLowerCase()))].sort()
    };
}

function resolveRecordingSettings(options, useSharedBrowser, nativeHarOptions) {
    const recordTraffic = options.recordTraffic !== undefined
        ? options.recordTraffic !== false
        : process.env.CAMOUFOX_RECORD_TRAFFIC !== 'false';
    const bodyRecordingEnabled = options.recordBodies !== undefined
        ? options.recordBodies === true
        : process.env.CAMOUFOX_RECORD_BODIES === 'true';
    const wireRecordingEnabled = options.recordWireLog !== undefined
        ? options.recordWireLog !== false
        : process.env.CAMOUFOX_RECORD_WIRE_LOG !== 'false';
    const recordHar = options.recordHar !== false &&
        Boolean(nativeHarOptions ?? options.recordHar ?? (process.env.CAMOUFOX_RECORD_HAR === 'true'));
    const harBodies = recordHar && bodyRecordingEnabled && nativeHarOptions?.content !== 'omit' &&
        nativeHarOptions?.omitContent !== true;

    return {
        recordTraffic,
        recordBodies: recordTraffic ? bodyRecordingEnabled : harBodies,
        recordWireLog: recordTraffic && wireRecordingEnabled,
        recordHar,
        harBodies,
        sslKeyLog: !useSharedBrowser && (options.sslKeyLog ?? (process.env.CAMOUFOX_SSLKEYLOG === 'true')) === true,
        neckoMozLog: !useSharedBrowser && (options.neckoMozLog ?? (process.env.CAMOUFOX_NECKO_MOZ_LOG === 'true')) === true
    };
}

const RECORDING_OPTIONS = {
    recordTraffic: 'traffic recording',
    recordBodies: 'body recording',
    recordWireLog: 'wire logging',
    recordHar: 'HAR recording',
    harBodies: 'HAR body recording',
    sslKeyLog: 'TLS key logging',
    neckoMozLog: 'Necko logging'
};

function checkProfileReuse(existing, requested) {
    assertManagedProxyReuse(existing.managedProxyBinding, requested.managedProxyBinding);
    if (!isDeepStrictEqual(existing.networkSettings, requested.networkSettings)) {
        throw new Error('Stop this Camoufox profile before changing its network or URL guard settings');
    }
    for (const [key, label] of Object.entries(RECORDING_OPTIONS)) {
        if (existing.recordingSettings[key] && !requested.recordingSettings[key]) {
            throw new Error(`Stop this Camoufox profile before disabling ${label}`);
        }
    }
}

function copyOptionValues(options, keys) {
    return Object.fromEntries(keys.filter((key) => Object.hasOwn(options, key))
        .map((key) => [key, structuredClone(options[key])]));
}

function resolveSessionStartSettings(options, savedMetadata, managedProxyBinding) {
    const definedOptions = Object.fromEntries(
        Object.entries(options).filter(([, value]) => value !== undefined)
    );
    const startOptions = { ...savedMetadata, ...definedOptions };
    const normalizedProxy = managedProxyBinding?.proxy ?? normalizeProxy(startOptions.proxy);
    const useSharedBrowser = Boolean(startOptions.useSharedBrowser);
    const { recordHar: _launchHar, env: launchEnv, ...launchOptions } = startOptions.launchOptions || {};
    const { recordHar: nativeHarOptions, storageState: _storageState, ...contextOptions } =
        startOptions.contextOptions || {};
    const env = buildBrowserEnvironment({ ...launchEnv, ...startOptions.env });

    if (useSharedBrowser && (Object.keys(launchOptions).length ||
        ['addons', 'fonts', 'screen', 'window', 'config', 'firefox_user_prefs'].some((key) => startOptions[key]))) {
        throw new Error('Shared Camoufox profiles require default process launch settings and per-context proxies');
    }

    const guardSettings = resolveGuardSettings(startOptions, managedProxyBinding);
    const launchRouting = copyOptionValues(launchOptions, [
        'proxy', 'proxyOverride', 'args', 'firefox_user_prefs', 'firefoxUserPrefs', 'config',
        'from_options', 'executablePath', 'executable_path', 'persistent_context', 'user_data_dir'
    ]);
    Object.assign(launchOptions, structuredClone(launchRouting));
    const contextRouting = copyOptionValues(contextOptions, ['proxy', 'proxyOverride', 'ignoreHTTPSErrors']);
    Object.assign(contextOptions, structuredClone(contextRouting));
    const processRouting = copyOptionValues(startOptions, ['firefox_user_prefs', 'config']);

    const recordingSettings = resolveRecordingSettings(startOptions, useSharedBrowser, nativeHarOptions);
    const reuseSettings = {
        managedProxyBinding,
        networkSettings: {
            normalizedProxy: structuredClone(normalizedProxy),
            useSharedBrowser,
            env,
            guardSettings,
            launchRouting,
            contextRouting,
            processRouting
        },
        recordingSettings
    };
    return {
        definedOptions, normalizedProxy, useSharedBrowser, launchOptions, nativeHarOptions,
        contextOptions, env, guardSettings, processRouting, reuseSettings
    };
}

function removeHarTemporaryDir(directory) {
    try {
        fs.rmSync(directory, { recursive: true, force: true });
    } catch (error) {
        logger.warn('Could not remove temporary Camoufox HAR data', { error: error.message });
    }
}

function readStartSettings(location, options, expectedStorageGeneration) {
    const savedMetadata = readProfileMetadata(location);
    if (expectedStorageGeneration !== undefined && savedMetadata?._storageGeneration !== expectedStorageGeneration) {
        throw Object.assign(new Error('Camoufox profile changed before it could be started'), {
            code: 'ERR_CAMOUFOX_PROFILE_STALE'
        });
    }
    const requestedProxy = options.proxy !== undefined ? options.proxy : savedMetadata?.proxy;
    const managedProxyBinding = validateCamoufoxNetworkPolicy(options, requestedProxy, savedMetadata);
    return {
        savedMetadata,
        managedProxyBinding,
        ...resolveSessionStartSettings(options, savedMetadata, managedProxyBinding)
    };
}

/**
 * Start a Camoufox profile by ID.
 * Supports both dedicated per-profile Camoufox browser instances and shared browser contexts,
 * loading and persisting `profiles/<profileId>/storage-state.json`.
 */
export async function startProfile(requestedProfileId, options = {}, expectedStorageGeneration = undefined) {
    resolveConfiguredNetworkPolicyMode(options.portScanProtection, options.securityPolicy?.portScanProtection);
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
        return startProfile(profileId, { ...options, profilesDir }, expectedStorageGeneration);
    }
    let startSettings = readStartSettings(location, options, expectedStorageGeneration);
    const existing = activeProfiles.get(key);
    if (existing) {
        if (existing.view?.browser.isConnected()) {
            assertProfileOwner(existing);
            checkProfileReuse(existing, startSettings.reuseSettings);
            logger.info('Reusing active Camoufox profile session', { profileId });
            return existing.view;
        }
        if (!(await stopProfileAt(location))) {
            throw new Error('Previous Camoufox profile session could not be stopped');
        }
        return startProfile(profileId, { ...options, profilesDir }, expectedStorageGeneration);
    }

    const starting = pendingProfileStarts.get(key);
    if (starting) {
        checkProfileReuse(starting, startSettings.reuseSettings);
        return starting.promise;
    }
    const saving = pendingProfileSaves.get(key);
    if (saving) {
        await saving.promise;
        return startProfile(profileId, { ...options, profilesDir }, expectedStorageGeneration);
    }

    const lease = acquireProfileLease(location);
    try {
        // Another process could have updated the profile before this process acquired it.
        startSettings = readStartSettings(location, options, expectedStorageGeneration);
    } catch (error) {
        releaseProfileLease(lease);
        throw error;
    }
    const {
        savedMetadata, managedProxyBinding, definedOptions, normalizedProxy, useSharedBrowser, launchOptions, nativeHarOptions,
        contextOptions, env, guardSettings, processRouting, reuseSettings
    } = startSettings;

    const startPromise = (async () => {
        let identity = null;
        let browser = null;
        let context = null;
        let ownsBrowser = false;
        let securityGuards = null;
        let trafficRecorder = null;
        let harTemporaryDir = null;
        let initializedStorage = null;
        let hasClosedContext = () => browser?.isConnected?.() === false;
        try {
            const { attachSessionCompatibility, observeContextClosure } = await import('./profile.js');
            let metadata = savedMetadata;

            if (!metadata) {
                assertFirefoxCoherence(definedOptions);
                metadata = createProfileAt(
                    location, profileId.substring(0, 60), normalizedProxy, definedOptions, managedProxyBinding
                );
            }

            const mergedOptions = {
                ...metadata,
                ...definedOptions,
                ...structuredClone(processRouting)
            };

            assertFirefoxCoherence(mergedOptions);

            const targetOs = normalizeTargetOs(mergedOptions.os);
            const geoip = mergedOptions.geoip !== undefined
                ? Boolean(mergedOptions.geoip)
                : Boolean(normalizedProxy);
            const humanize = mergedOptions.humanize !== undefined
                ? mergedOptions.humanize
                : true;
            const headless = mergedOptions.headless ?? false;
            const storageInfo = ensureProfileStorageAt(location);
            const { storageStatePath } = storageInfo;
            const storageState = readStorageState(storageStatePath);
            identity = stampProfileIdentity(location, storageInfo.metadataPath, metadata);
            initializedStorage = storageInfo;
            const { recordTraffic, recordBodies, recordWireLog, sslKeyLog, neckoMozLog, recordHar, harBodies } =
                reuseSettings.recordingSettings;
            const neckoMozLogModules =
                options.neckoMozLogModules ||
                mergedOptions.neckoMozLogModules ||
                process.env.CAMOUFOX_NECKO_MOZ_LOG_MODULES ||
                'timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4';
            if (recordHar && (nativeHarOptions?.urlFilter !== undefined ||
                (nativeHarOptions?.mode !== undefined && nativeHarOptions.mode !== 'full'))) {
                throw new Error('Camoufox HAR export does not support native URL filters or minimal mode');
            }
            let harPath = recordHar ? storageInfo.harPath : null;
            if (recordHar && nativeHarOptions?.path) {
                const requestedPath = path.resolve(nativeHarOptions.path);
                const requestedDir = resolveProfilesRoot(path.dirname(requestedPath));
                if (requestedDir !== storageInfo.trafficDir || path.extname(requestedPath).toLowerCase() !== '.har') {
                    throw new Error('Camoufox HAR path must be a .har file directly in its profile traffic directory');
                }
                harPath = path.join(requestedDir, path.basename(requestedPath));
            }

            restrictLegacySharedKeyLog(profilesDir);
            archiveLegacyNativeLogs(storageInfo);
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

            if (sslKeyLog || neckoMozLog) {
                ensurePrivateDirectory(storageInfo.nativeDir);
                if (!recordTraffic) {
                    Object.assign(trafficPaths, selectProfileNativeLogPaths(
                        storageInfo.trafficDir, storageInfo.nativeDir, trafficPaths
                    ));
                }
            }
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
                if (recordTraffic) {
                    trafficPaths.sslKeyLogPath = trafficRecorder.sslKeyLogPath;
                    trafficPaths.neckoMozLogPath = trafficRecorder.neckoMozLogPath;
                }
            }
            prepareNativeLogs(storageInfo, {
                sslKeyLog, neckoMozLog, harPath,
                sslKeyLogPath: trafficPaths.sslKeyLogPath,
                neckoMozLogPath: trafficPaths.neckoMozLogPath
            });
            if (recordTraffic && (sslKeyLog || neckoMozLog)) {
                await trafficRecorder.flushSummary({ nativeLogsClosed: false });
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
                    env
                });
                ownsBrowser = false;

                const contextOpts = {
                    os: targetOs,
                    ...(normalizedProxy ? { proxy: normalizedProxy } : {}),
                    ...(mergedOptions.webrtc_ip ? { webrtc_ip: mergedOptions.webrtc_ip } : {}),
                    ...(hasExplicitGeolocation && playwrightGeolocation
                        ? { geolocation: playwrightGeolocation }
                        : {}),
                    ...(effectiveLocale ? { locale: effectiveLocale } : {}),
                    ...(effectiveTimezoneId ? { timezoneId: effectiveTimezoneId } : {}),
                    ...(mergedOptions.ff_version ? { ff_version: mergedOptions.ff_version } : {}),
                    ...(mergedOptions.preset ? { preset: mergedOptions.preset } : {}),
                    ...contextOptions,
                    storageState
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
                    env: buildNativeLogEnvironment(env, {
                        sslKeyLogPath: trafficPaths.sslKeyLogPath,
                        neckoMozLogPath: trafficPaths.neckoMozLogPath,
                        neckoMozLogModules
                    })
                };
                if (managedProxyBinding) assertManagedProxyLaunchEnvironment(launchOpts.env);

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
                    ...(effectiveTimezoneId ? { timezoneId: effectiveTimezoneId } : {}),
                    ...(hasExplicitGeolocation && playwrightGeolocation
                        ? { geolocation: playwrightGeolocation }
                        : {}),
                    ...contextOptions,
                    storageState
                };

                context = await browser.newContext(contextOpts);
            }

            hasClosedContext = observeContextClosure(context, browser);

            const fingerprintLedger = new CanvasWebglConsistencyLedger({
                profileId,
                ledgerPath: path.join(storageInfo.profileDir, 'fingerprint-ledger.json'),
                maxHammingDistance:
                    options.maxHammingDistance ??
                    mergedOptions.maxHammingDistance ??
                    0,
                skipHosts: mergedOptions.securityPolicy?.canvasSkipHosts
            });

            if (guardSettings.shouldAttach) {
                const customOnBlockedAttempt =
                    options.onBlockedAttempt ?? mergedOptions.onBlockedAttempt;
                securityGuards = await attachZiniaoSecurityGuardsToContext(context, {
                    profileId,
                    managedProxyBinding,
                    portScanProtection: guardSettings.portScanProtection,
                    allowedExtensionIds: guardSettings.allowedExtensionIds,
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

            if (trafficRecorder) {
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

            const active = {
                ...session,
                location,
                lease,
                identity,
                hasClosedContext,
                ...reuseSettings,
                recording: trafficRecorder,
                harPath,
                harTemporaryDir,
                harBodies,
                storageInfo
            };
            active.view = attachSessionCompatibility(session, {
                profilesDir,
                saveStorageState: () => saveProfileStorageState(profileId, context),
                stop: async () => ({
                    stopped: await stopProfileAt(location, active),
                    closed: Boolean(active.closed),
                    trafficAttribution: structuredClone(active.finalTrafficAttribution ?? null)
                }),
                delete: () => deleteProfileAt(location, active),
                async getTrafficAttribution() {
                    if (activeProfiles.get(key) === active) await pendingProfileStops.get(key);
                    if (active.closed || activeProfiles.get(key) !== active) {
                        return structuredClone(active.finalTrafficAttribution ?? null);
                    }
                    if (!active.trafficRecorder) return null;
                    assertProfileOwner(active);
                    return active.trafficRecorder.flushSummary({ nativeLogsClosed: false });
                }
            });
            profileContexts.set(context, location);
            activeProfiles.set(key, active);

            logger.info('Camoufox profile started', {
                profileId,
                os: targetOs,
                storageStatePath,
                useSharedBrowser
            });

            return active.view;
        } catch (error) {
            const failed = {
                profileId,
                location,
                browser,
                ownsBrowser,
                context,
                hasClosedContext,
                securityGuards,
                recording: trafficRecorder,
                harTemporaryDir,
                storageInfo: initializedStorage,
                lease,
                identity,
                startFailed: true
            };
            if (await closeNativeProfile(failed)) {
                try {
                    await cleanClosedProfile(failed);
                    releaseProfileLease(lease);
                } catch (cleanupError) {
                    activeProfiles.set(key, failed);
                    logger.warn('Could not finish failed Camoufox profile startup cleanup', {
                        profileId,
                        error: redactDiagnosticText(cleanupError.message)
                    });
                }
            } else {
                activeProfiles.set(key, failed);
            }
            logger.error('Error starting Camoufox profile', {
                profileId,
                error: error.message
            });
            throw error;
        }
    })().finally(() => {
        pendingProfileStarts.delete(key);
        updateProcessCleanupHooks();
    });

    pendingProfileStarts.set(key, { promise: startPromise, ...reuseSettings });
    updateProcessCleanupHooks();
    return startPromise;
}

/**
 * Stop an active Camoufox profile by ID, saving cookies and localStorage first.
 */
export async function stopProfile(profileId, options = {}) {
    return stopProfileAt(locateProfile(profileId, options.profilesDir || DEFAULT_PROFILES_DIR));
}

function hasNativeRecording(session) {
    return Boolean(session.recording?.sslKeyLogPath || session.recording?.neckoMozLogPath);
}

async function finalizeProfileRecording(session, nativeLogsClosed) {
    if (session.identity) assertProfileOwner(session);
    const summary = session.recordingFinalized
        ? await session.recording.flushSummary({ nativeLogsClosed })
        : await session.recording.stop({ nativeLogsClosed });
    if (!session.recordingFinalized && session.harPath) {
        session.recording.exportHar(session.harPath, { recordBodies: session.harBodies });
    }
    session.recordingFinalized = true;
    if (nativeLogsClosed) session.finalTrafficAttribution = structuredClone(summary);
}

async function closeNativeProfile(session) {
    const { profileId, context, browser } = session;
    session.contextClosed ||= !context || session.hasClosedContext();
    if (!session.contextClosed) {
        try {
            await context.close();
            session.contextClosed = true;
        } catch (error) {
            session.contextClosed = session.hasClosedContext();
            if (!session.contextClosed) {
                logger.warn('Could not close Camoufox context', {
                    profileId,
                    error: redactDiagnosticText(error.message)
                });
            }
        }
    }

    session.browserClosed ||= !session.ownsBrowser || !browser || browser.isConnected?.() === false;
    if (!session.browserClosed) {
        try {
            await browser.close();
            session.browserClosed = true;
        } catch (error) {
            session.browserClosed = browser.isConnected?.() === false;
            if (!session.browserClosed) {
                logger.warn('Could not close Camoufox browser', {
                    profileId,
                    error: redactDiagnosticText(error.message)
                });
            }
        }
        session.contextClosed ||= session.browserClosed;
    }
    return session.contextClosed && session.browserClosed;
}

async function cleanClosedProfile(session) {
    session.closed = true;
    const { profileId } = session;
    if (session.securityGuards) {
        try {
            await session.securityGuards.detach?.();
        } catch (error) {
            logger.debug('Error detaching Ziniao security guards', {
                profileId,
                error: redactDiagnosticText(error.message)
            });
        }
        session.securityGuards = null;
    }

    let finalized = true;
    try {
        if (session.storageInfo) {
            assertProfileOwner(session);
            restrictNativeLogs(session.storageInfo);
        }
        if (session.recording && (!session.recordingFinalized || hasNativeRecording(session))) {
            await finalizeProfileRecording(session, true);
        }
    } catch (error) {
        finalized = false;
        logger.warn('Could not finalize Camoufox profile files', {
            profileId,
            error: redactDiagnosticText(error.message)
        });
    }
    if (session.harTemporaryDir) {
        try {
            assertProfileOwner(session);
            removeHarTemporaryDir(session.harTemporaryDir);
            session.harTemporaryDir = null;
        } catch (error) {
            finalized = false;
            logger.warn('Could not verify temporary Camoufox HAR data ownership', {
                profileId,
                error: redactDiagnosticText(error.message)
            });
        }
    }
    return finalized;
}

function matchesProfileSession(session) {
    try {
        if (activeProfiles.get(session.location.key) === session) {
            assertProfileOwner(session);
        } else {
            assertProfileIdentity(session.location, session.identity);
        }
        return true;
    } catch (error) {
        logger.warn('Camoufox profile session no longer matches its storage', {
            profileId: session.profileId,
            error: redactDiagnosticText(error.message)
        });
        return false;
    }
}

function stopProfileAt(location, expected = null) {
    const { id: profileId, key } = location;
    if (expected) {
        const current = activeProfiles.get(key);
        if (current !== expected) {
            if (current || pendingProfileStarts.has(key)) return Promise.resolve(false);
            if (expected.deleted) return Promise.resolve(!inspectProfileForDeletion(location));
            return Promise.resolve(matchesProfileSession(expected) && expected.stopResult === true);
        }
    }
    const stopping = pendingProfileStops.get(key);
    if (stopping) {
        return expected && !matchesProfileSession(expected) ? Promise.resolve(false) : stopping;
    }

    const stopPromise = (async () => {
        await Promise.allSettled([pendingProfileStarts.get(key)?.promise, pendingProfileSaves.get(key)?.promise]);
        const session = activeProfiles.get(key);
        if (!session) return !expected;
        if (expected && (session !== expected || !matchesProfileSession(session))) return false;

        if (!session.startFailed && !session.contextClosed && !session.hasClosedContext()) {
            try {
                await persistProfileStorageState(session);
                session.storageSaved = true;
            } catch (error) {
                session.storageSaved = false;
                logger.warn('Could not save storage state before stopping profile', {
                    profileId,
                    error: redactDiagnosticText(error.message)
                });
            }
        }
        if (session.fingerprintLedger && !session.contextClosed) {
            try {
                assertProfileOwner(session);
                session.fingerprintLedger.saveToDisk();
            } catch (error) {
                logger.debug('Could not save Camoufox fingerprint ledger', {
                    profileId,
                    error: redactDiagnosticText(error.message)
                });
            }
        }
        if (session.recording && !session.recordingFinalized) {
            try {
                await finalizeProfileRecording(session, !hasNativeRecording(session));
            } catch (error) {
                logger.warn('Could not finalize Camoufox traffic recording', {
                    profileId,
                    error: redactDiagnosticText(error.message)
                });
            }
        }

        if (!(await closeNativeProfile(session))) return false;
        const finalized = await cleanClosedProfile(session);
        releaseProfileLease(session.lease);
        activeProfiles.delete(key);
        session.stopResult = session.storageSaved !== false && finalized;
        if (session.stopResult) logger.info('Camoufox profile stopped', { profileId });
        return session.stopResult;
    })().catch((error) => {
        logger.warn('Error stopping Camoufox profile', { profileId, error: redactDiagnosticText(error.message) });
        return false;
    }).finally(() => {
        pendingProfileStops.delete(key);
        updateProcessCleanupHooks();
    });
    pendingProfileStops.set(key, stopPromise);
    return stopPromise;
}

/**
 * Delete a profile and remove its persistent storage directory (`profiles/<profileId>/`).
 */
export async function deleteProfile(profileId, options = {}) {
    return deleteProfileAt(locateProfile(profileId, options.profilesDir || DEFAULT_PROFILES_DIR));
}

function deleteProfileAt(location, expected = null) {
    const { profileDir, key } = location;
    const deleting = pendingProfileDeletes.get(key);
    if (deleting) {
        if (expected && deleting.expected !== expected) {
            throw new Error('Another Camoufox profile deletion is in progress');
        }
        return deleting.promise;
    }
    const checkSession = () => {
        if (expected && (pendingProfileStarts.has(key) ||
            (activeProfiles.has(key) && activeProfiles.get(key) !== expected))) {
            throw new Error('Camoufox profile session is stale');
        }
    };
    checkSession();

    const deletePromise = (async () => {
        await Promise.allSettled([pendingProfileStarts.get(key)?.promise, pendingProfileSaves.get(key)?.promise]);
        checkSession();
        const checked = inspectProfileForDeletion(location);
        if (expected?.deleted && !checked) return true;
        if (expected) assertProfileIdentity(location, expected.identity);
        if (!checked && activeProfiles.has(key)) {
            throw new Error('Active Camoufox profile directory is missing');
        }
        if (!checked && !fs.existsSync(location.profilesDir)) return true;

        if (checked && !(await stopProfileAt(location, expected))) {
            throw new Error('Could not stop Camoufox profile before deletion');
        }
        const lease = acquireProfileLease(location);
        try {
            if (!checked) {
                if (inspectProfileForDeletion(location)) {
                    throw new Error('Camoufox profile directory changed during deletion');
                }
                return true;
            }
            assertProfileIdentity(location, expected?.identity ?? checked);
            fs.rmSync(profileDir, { recursive: true });
            if (expected) expected.deleted = true;
            logger.info('Camoufox profile deleted', { profileId: location.id, profileDir });
            return true;
        } finally {
            releaseProfileLease(lease);
        }
    })().finally(() => {
        pendingProfileDeletes.delete(key);
    });
    pendingProfileDeletes.set(key, { expected, promise: deletePromise });
    return deletePromise;
}

/**
 * Update proxy configuration for one or more profile IDs.
 */
export async function updateProfileProxy(profileIds, proxy, options = {}) {
    const ids = (Array.isArray(profileIds) ? profileIds : [profileIds]).map(validateProfileId);
    const profilesDir = options.profilesDir || DEFAULT_PROFILES_DIR;
    const leases = [];
    let normalizedProxy;
    try {
        const profiles = [...new Set(ids)].map((id) => {
            const location = locateProfile(id, profilesDir, true);
            const lease = leaseForStorageUpdate(location);
            if (lease) leases.push(lease);
            const existing = readProfileMetadata(location);
            const binding = validateCamoufoxNetworkPolicy({}, proxy, existing);
            return { location, existing, binding };
        });
        const boundProxy = profiles.find(({ binding }) => binding)?.binding.proxy;
        normalizedProxy = boundProxy ?? normalizeProxy(proxy);

        for (const { location, existing } of profiles) {
            const updated = {
                ...(existing || defaultProfileMetadata(location)),
                proxy: normalizedProxy,
                geoip: normalizedProxy ? true : Boolean(existing?.geoip),
                updatedAt: new Date().toISOString()
            };
            if (existing) {
                writePrivateFile(getProfileMetadataPath(location.id, location.profilesDir), JSON.stringify(updated, null, 2));
            } else {
                initializeProfileStorageAt(location, updated);
            }
        }
    } finally {
        for (const lease of leases) releaseProfileLease(lease);
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
        updateProcessCleanupHooks();
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

    await Promise.allSettled(sessions.map((session) => stopProfileAt(session.location)));
    const sharedBrowsersClosed = await closeSharedBrowser();
    const stoppedCount = sessions.filter((session) => session.stopResult === true).length;

    return {
        sharedBrowsersClosed,
        stoppedCount,
        profileIds,
        reason
    };
}

const processCleanupHandlers = Object.fromEntries(['SIGINT', 'SIGTERM'].map(signal => [
    signal,
    () => {
        stopAllActiveProfiles(signal).catch(() => {
            logger.warn('Could not flush active Camoufox profiles on signal', { signal });
        });
    }
]));

function updateProcessCleanupHooks() {
    const shouldAttach = processCleanupEnabled &&
        (activeProfiles.size > 0 || pendingProfileStarts.size > 0 || sharedBrowsers.size > 0);
    if (shouldAttach === processCleanupAttached) return;

    for (const [signal, handler] of Object.entries(processCleanupHandlers)) {
        if (shouldAttach) process.on(signal, handler);
        else process.off(signal, handler);
    }
    processCleanupAttached = shouldAttach;
}

/**
 * Opt in to process signal cleanup while this library owns browser resources.
 */
export function registerProcessCleanupHooks() {
    if (processCleanupEnabled) return false;
    processCleanupEnabled = true;
    updateProcessCleanupHooks();
    return true;
}

/**
 * Disable process signal cleanup and remove only this library's listeners.
 */
export function unregisterProcessCleanupHooks() {
    if (!processCleanupEnabled) return false;
    processCleanupEnabled = false;
    updateProcessCleanupHooks();
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
