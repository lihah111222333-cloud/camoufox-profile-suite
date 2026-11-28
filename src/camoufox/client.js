/**
 * Camoufox Browser Profile Client
 * Open-source C++-patched Firefox antidetect replacement for Dolphin Anty & GPM Login
 */

import { createHash, randomUUID } from 'node:crypto';
import fs from 'fs';
import path from 'path';
import { isDeepStrictEqual } from 'node:util';
import logger from '../utils/logger.js';
import { getConfiguredProfilesDirectory, resolveRecordingOptions } from '../utils/private-env.js';
import { formatProxyHost, parseProxyAddress, parseProxyPort, requireProxyProtocol } from '../utils/proxy-protocol.js';
import { getDefaultProfilesDirectory } from '../utils/state-paths.js';
import { ensurePrivateDirectory, syncDirectory, writePrivateFile } from '../utils/private-storage.js';
import { captureExportTargetVersion, listCaptureDirectory } from './capture-io.js';
import {
    assertManagedProxyLaunchEnvironment,
    assertManagedProxyReuse,
    bindManagedProxy,
    resolveConfiguredNetworkPolicyMode,
    resolveNetworkPolicyMode
} from './network-policy.js';
import { loadCamoufoxModule } from './sdk-resolution.js';
import {
    acquireProfileDeletionStaging,
    acquireProfileLease,
    acquireProfileTrafficDeletionLease,
    acquireTrafficDirectoryLease,
    archiveLegacyNativeLogs,
    assertProfileIdentity,
    assertProfileLease,
    assertProfileLeaseIdle,
    confirmProfileLeaseNativeExit,
    ensureProfileStorageAt,
    initializeProfileStorageAt,
    inspectProfileDirectory,
    inspectProfileForDeletion,
    locateProfile,
    nativeExitUnconfirmedError,
    prepareNativeLogs,
    PROFILE_LEASE_DIRECTORY,
    readProfileMetadata,
    readStorageState,
    writeProfileMetadata,
    writeStorageState,
    releaseProfileLease,
    removeStagedProfileDeletions,
    resolveExistingAncestors,
    resolveProfilesRoot,
    restrictLegacySharedKeyLog,
    restrictNativeLogs,
    retainProfileLeaseForNativeExit,
    stageProfileDeletion,
    stampProfileIdentity,
    validateProfileId
} from './profile-storage.js';
import {
    CamoufoxTrafficRecorder, buildBrowserEnvironment, buildNativeLogEnvironment,
    exportTrafficToHar, inspectHarScratch, selectProfileNativeLogPaths
} from './traffic-recorder.js';
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
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
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
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    validateGpuPerformanceScalingCoherence
};

const VALID_TARGET_OS = new Set(['windows', 'macos', 'linux']);
const VALID_PROXY_PROTOCOLS = ['http', 'https', 'socks4', 'socks5', 'socks5h'];
const FORBIDDEN_UA_PATTERNS =
    /\b(Chrome|CriOS|Chromium|Safari|AppleWebKit|WebKit|Edg|Edge|EdgA|EdgiOS|OPR|Opera|Vivaldi|Brave|FxiOS|Android|iPhone|iPad|iPod|Mobile|Tablet|Touch|IEMobile|BlackBerry|SamsungBrowser|UCBrowser|Trident|MSIE)\b/i;

let cachedCamoufoxModule = null;
const sharedBrowsers = new Map();
const activeProfiles = new Map();
const createdProfileOwners = new WeakMap();
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

export async function waitForCamoufoxStartup(pending, signal) {
    if (!signal) return pending;
    let abort;
    try {
        return await Promise.race([pending, new Promise((resolve, reject) => {
            abort = () => reject(signal.reason);
            signal.addEventListener('abort', abort, { once: true });
            if (signal.aborted) abort();
        })]);
    } finally {
        signal.removeEventListener('abort', abort);
    }
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

function camoufoxProxy({ type, ip, port, username, password }) {
    if (!VALID_PROXY_PROTOCOLS.includes(type)) throw new Error('Unsupported proxy protocol');
    return {
        server: type + '://' + ip + ':' + port,
        ...(username && { username }),
        ...(password && { password })
    };
}

function normalizeProxyProtocolSetting(value) {
    if (typeof value !== 'string') return value;
    return value.trim().replace(/:\/\/$/, '') || value;
}

/**
 * Normalize proxy input into Playwright / Camoufox format.
 */
export function normalizeProxy(proxy) {
    if (!proxy) return null;

    if (typeof proxy === 'string') {
        if (!proxy.trim()) return null;
        const address = parseProxyAddress(proxy);
        if (!address) throw new Error('Invalid or ambiguous proxy configuration');
        return camoufoxProxy(address);
    }

    if (typeof proxy !== 'object' || Array.isArray(proxy)) throw new Error('Invalid proxy configuration');
    const protocols = {
        type: normalizeProxyProtocolSetting(proxy.type),
        protocol: normalizeProxyProtocolSetting(proxy.protocol)
    };
    let normalized;
    if (proxy.server) {
        if (typeof proxy.server !== 'string') throw new Error('Invalid proxy server');
        normalized = normalizeProxy(proxy.server);
        if (!normalized) throw new Error('Invalid proxy server');
        const [scheme] = normalized.server.split(':', 1);
        requireProxyProtocol({ ...protocols, mode: scheme }, VALID_PROXY_PROTOCOLS, 'Camoufox');
    } else {
        const ip = formatProxyHost(proxy.ip || proxy.host);
        const port = parseProxyPort(proxy.port);
        if (!ip || !port) throw new Error('Invalid proxy host or port');
        const type = requireProxyProtocol(protocols, VALID_PROXY_PROTOCOLS, 'Camoufox');
        normalized = camoufoxProxy({ type, ip, port });
    }

    const username = String(proxy.username || proxy.proxyUsername || '').trim();
    const password = String(proxy.password || proxy.proxyPassword || '').trim();
    if (username) normalized.username = username;
    if (password) normalized.password = password;
    if (proxy.bypass) normalized.bypass = proxy.bypass;
    return normalized;
}

/**
 * Get the directory path for a given profile ID.
 */
export function getProfileDir(profileId, profilesDir = getConfiguredProfilesDirectory()) {
    return path.join(profilesDir, validateProfileId(profileId));
}

/**
 * Get the storage state file path (`profiles/<profileId>/storage-state.json`).
 */
export function getStorageStatePath(profileId, profilesDir = getConfiguredProfilesDirectory()) {
    return path.join(getProfileDir(profileId, profilesDir), 'storage-state.json');
}

/**
 * Get the metadata file path (`profiles/<profileId>/profile.json`).
 */
export function getProfileMetadataPath(profileId, profilesDir = getConfiguredProfilesDirectory()) {
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
        if (session.nativeExitUnconfirmed) throw nativeExitUnconfirmedError();
        assertProfileOwner(session);
        return null;
    }
    return acquireProfileLease(location);
}

/**
 * Prepare an owned profile store, reserving a new directory only if the ID is unused.
 */
export function ensureProfileStorage(profileId, profilesDir = getConfiguredProfilesDirectory()) {
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
 * Return a valid saved storage state path, or null if the profile or snapshot is absent.
 */
export function loadStorageState(profileId, profilesDir = getConfiguredProfilesDirectory()) {
    const location = locateProfile(profileId, profilesDir);
    if (!readProfileMetadata(location)) return null;
    const storageStatePath = getStorageStatePath(location.id, location.profilesDir);
    try {
        readStorageState(storageStatePath);
        return storageStatePath;
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
    }
}

async function captureProfileStorageState(session) {
    assertProfileOwner(session);
    const state = await session.context.storageState();
    if (!Array.isArray(state?.cookies) || !Array.isArray(state?.origins)) {
        throw new TypeError('Invalid Camoufox storage state');
    }
    return structuredClone(state);
}

function writeProfileStorageState(session, state) {
    const { location, storageStatePath } = session;
    assertProfileOwner(session);
    try {
        readStorageState(storageStatePath);
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
    }
    writeStorageState(storageStatePath, state);
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
        : locateProfile(id, profilesDir || getConfiguredProfilesDirectory());
    const session = activeProfiles.get(location.key);
    if (context != null && (!bound || bound.id !== id || bound.key !== location.key || session?.context !== context)) {
        throw new Error('Camoufox context does not belong to the active profile in this store');
    }

    if (!session || session.stopRequested || session.closingSnapshot || pendingProfileStarts.has(location.key) ||
        pendingProfileStops.has(location.key) || pendingProfileDeletes.has(location.key)) {
        return null;
    }
    if (pendingProfileSaves.has(location.key)) {
        throw Object.assign(new Error('A storage snapshot is already being saved for this profile'), {
            code: 'ERR_CAMOUFOX_PROFILE_BUSY'
        });
    }

    const savePromise = Promise.resolve()
        .then(async () => writeProfileStorageState(session, await captureProfileStorageState(session)))
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

/**
 * Obtain or launch a shared Camoufox browser instance for multi-context profiles.
 */
async function getOrCreateSharedBrowser(options) {
    assertFirefoxCoherence(options);
    const targetOs = normalizeTargetOs(options.os);
    const headless = options.headless ?? (process.env.CAMOUFOX_HEADLESS === 'true');
    const humanize = options.humanize !== undefined ? options.humanize : true;
    const profilesDir = resolveProfilesRoot(options.profilesDir || getDefaultProfilesDirectory());
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
    const starting = [...pendingProfileStarts.values()].filter(({ networkSettings }) => networkSettings.useSharedBrowser);
    await Promise.allSettled(starting.map(({ promise }) => promise));
    const entries = [...sharedBrowsers.entries()];
    const launches = await Promise.allSettled(entries.map(([, entry]) => entry.promise));
    const instances = new Set(
        launches.filter((result) => result.status === 'fulfilled').map((result) => result.value)
    );
    const sessions = [...activeProfiles.values()].filter((session) => !session.ownsBrowser && session.browser);
    const outcomes = await Promise.allSettled(sessions.map((session) => stopProfileAt(session.location, session)));
    const incomplete = new Set(sessions.filter((session) => !session.contextClosed && !session.hasClosedContext())
        .map((session) => session.browser));
    const closed = new Set();
    for (const instance of instances) {
        if (incomplete.has(instance)) continue;
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
    updateProcessCleanupHooks();
    return closed.size === instances.size && outcomes.every(({ status, value }) => status === 'fulfilled' && value);
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

        const profilesDir = options.profilesDir || getDefaultProfilesDirectory();
        const location = locateProfile(profileId, profilesDir, true);
        const requestedProxy = proxy || options.proxy || null;
        const savedMetadata = readProfileMetadata(location);
        const managedProxyBinding = validateCamoufoxNetworkPolicy(options, requestedProxy, savedMetadata);
        if (savedMetadata) {
            throw Object.assign(new Error('Camoufox profile ID already exists'), { code: 'EEXIST' });
        }
        const lease = acquireProfileLease(location);
        try {
            const created = createProfileAt(location, cleanName, requestedProxy, options, managedProxyBinding);
            createdProfileOwners.set(created, {
                location,
                identity: inspectProfileForDeletion(location),
                stopResult: true
            });
            return created;
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
    return readProfileMetadata(locateProfile(profileId, options.profilesDir || getConfiguredProfilesDirectory()));
}

/**
 * List all saved Camoufox profiles on disk. Reject incomplete listings.
 */
export async function listProfiles(profilesDir = getConfiguredProfilesDirectory()) {
    let root;
    let entries;
    try {
        root = resolveProfilesRoot(profilesDir);
        entries = fs.readdirSync(root, { withFileTypes: true });
    } catch (error) {
        if (error.code === 'ENOENT') return [];
        throw Object.assign(new Error('Could not list the Camoufox profiles directory'), {
            code: 'ERR_CAMOUFOX_PROFILE_LIST_FAILED'
        });
    }

    const profiles = [];
    let unreadableCount = 0;
    for (const entry of entries) {
        if (!entry.isDirectory() || entry.name === PROFILE_LEASE_DIRECTORY) continue;
        try {
            const metadata = readProfileMetadata(locateProfile(entry.name, root));
            if (metadata) profiles.push(metadata);
            else unreadableCount += 1;
        } catch {
            unreadableCount += 1;
        }
    }
    if (unreadableCount > 0) {
        throw Object.assign(new Error('Could not read all Camoufox profile metadata'), {
            code: 'ERR_CAMOUFOX_PROFILE_LIST_INCOMPLETE',
            unreadableCount
        });
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

function resolveRecordingSettings(options, useSharedBrowser, nativeHarOptions, location) {
    const recording = resolveRecordingOptions(options);
    const { recordTraffic } = recording;
    const recordHar = options.recordHar !== false && Boolean(nativeHarOptions ?? recording.recordHar);
    const harPath = recordHar ? resolveHarPath(location, nativeHarOptions) : null;
    const harBodies = recordHar && recording.recordBodies && nativeHarOptions?.content !== 'omit' &&
        nativeHarOptions?.omitContent !== true;
    const recordBodies = recordTraffic ? recording.recordBodies : harBodies;
    const neckoMozLog = !useSharedBrowser && recording.neckoMozLog;

    return {
        recordTraffic,
        recordBodies,
        maxBodyBytes: recordBodies ? recording.maxBodyBytes : undefined,
        recordWireLog: recordTraffic && recording.recordWireLog,
        recordHar,
        harPath,
        harBodies,
        sslKeyLog: !useSharedBrowser && recording.sslKeyLog,
        neckoMozLog,
        neckoMozLogModules: neckoMozLog
            ? options.neckoMozLogModules || process.env.CAMOUFOX_NECKO_MOZ_LOG_MODULES ||
                'timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4'
            : null
    };
}

function resolveHarPath(location, options) {
    if (options?.urlFilter !== undefined || (options?.mode !== undefined && options.mode !== 'full')) {
        throw new Error('Camoufox HAR export does not support native URL filters or minimal mode');
    }
    const trafficDir = path.join(location.profileDir, 'traffic');
    if (!options?.path) return path.join(trafficDir, 'trace.har');
    const requested = path.resolve(options.path);
    const requestedDir = resolveExistingAncestors(path.dirname(requested));
    if (requestedDir !== trafficDir || path.extname(requested).toLowerCase() !== '.har') {
        throw new Error('Camoufox HAR path must be a .har file directly in its profile traffic directory');
    }
    return path.join(trafficDir, path.basename(requested));
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
        throw new Error('Stop this Camoufox profile before changing its network or URL guard settings or context permissions');
    }
    for (const [key, label] of Object.entries(RECORDING_OPTIONS)) {
        const previous = existing.recordingSettings[key];
        const next = requested.recordingSettings[key];
        if (previous !== next && (previous || !requested.implicitRecordingDefaults[key])) {
            throw new Error(`Stop this Camoufox profile before ${next ? 'enabling' : 'disabling'} ${label}`);
        }
    }
    if (existing.recordingSettings.harPath !== requested.recordingSettings.harPath) {
        throw new Error('Stop this Camoufox profile before changing the HAR destination');
    }
    if (existing.recordingSettings.neckoMozLogModules !== requested.recordingSettings.neckoMozLogModules) {
        throw new Error('Stop this Camoufox profile before changing Necko logging modules');
    }
    if (existing.recordingSettings.maxBodyBytes !== requested.recordingSettings.maxBodyBytes) {
        throw new Error('Stop this Camoufox profile before changing the body recording limit');
    }
}

function copyOptionValues(options, keys) {
    return Object.fromEntries(keys.filter((key) => Object.hasOwn(options, key))
        .map((key) => [key, structuredClone(options[key])]));
}

function resolveSessionStartSettings(options, savedMetadata, managedProxyBinding, location) {
    const definedOptions = Object.fromEntries(
        Object.entries(options).filter(([, value]) => value !== undefined)
    );
    const startOptions = { ...savedMetadata, ...definedOptions };
    const normalizedProxy = managedProxyBinding?.proxy ?? normalizeProxy(startOptions.proxy);
    const useSharedBrowser = Boolean(startOptions.useSharedBrowser);
    const { recordHar: _launchHar, env: launchEnv, ...launchOptions } = startOptions.launchOptions || {};
    const { recordHar: nativeHarOptions, storageState: _storageState, ...contextOptions } =
        startOptions.contextOptions || {};
    const env = buildBrowserEnvironment({ ...launchEnv, ...startOptions.env }, process.env);

    if (useSharedBrowser && (Object.keys(launchOptions).length ||
        ['addons', 'fonts', 'screen', 'window', 'config', 'firefox_user_prefs'].some((key) => startOptions[key]))) {
        throw new Error('Shared Camoufox profiles require default process launch settings and per-context proxies');
    }

    for (const routing of [launchOptions, contextOptions]) {
        if (routing.proxyOverride !== undefined || (routing.proxy !== undefined &&
            !isDeepStrictEqual(normalizeProxy(routing.proxy), normalizedProxy))) {
            throw new Error('Conflicting Camoufox proxy settings');
        }
        delete routing.proxy;
        delete routing.proxyOverride;
    }

    const guardSettings = resolveGuardSettings(startOptions, managedProxyBinding);
    const launchRouting = copyOptionValues(launchOptions, [
        'args', 'firefox_user_prefs', 'firefoxUserPrefs', 'config',
        'from_options', 'executablePath', 'executable_path', 'persistent_context', 'user_data_dir'
    ]);
    Object.assign(launchOptions, structuredClone(launchRouting));
    const contextRouting = copyOptionValues(contextOptions, [
        'ignoreHTTPSErrors', 'acceptDownloads', 'permissions'
    ]);
    Object.assign(contextOptions, structuredClone(contextRouting));
    const processRouting = copyOptionValues(startOptions, ['firefox_user_prefs', 'config']);

    const recordingSettings = resolveRecordingSettings(startOptions, useSharedBrowser, nativeHarOptions, location);
    // Attaching by ID alone should preserve a session's deliberate choice to disable default recording.
    const implicitRecordingDefaults = {
        recordTraffic: startOptions.recordTraffic === undefined && process.env.CAMOUFOX_RECORD_TRAFFIC === undefined,
        recordWireLog: startOptions.recordWireLog === undefined && process.env.CAMOUFOX_RECORD_WIRE_LOG === undefined
    };
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
        recordingSettings,
        implicitRecordingDefaults
    };
    return {
        definedOptions, normalizedProxy, useSharedBrowser, launchOptions,
        contextOptions, env, guardSettings, processRouting, reuseSettings
    };
}

function removeHarTemporaryDir(directory, shouldRemove = () => true) {
    if (inspectProfileDirectory({ profileDir: directory })) {
        const lease = acquireTrafficDirectoryLease(directory);
        try {
            if (shouldRemove(directory)) fs.rmSync(directory, { recursive: true, force: true });
        } finally {
            releaseProfileLease(lease);
        }
    }
}

function hasHarScratchIndex(directory) {
    return Boolean(fs.lstatSync(path.join(directory, 'attribution-index.json'), { throwIfNoEntry: false }));
}

function pendingHarExportError(directory) {
    const error = new Error('Camoufox HAR cleanup is pending. Stop this profile to retry the export.');
    error.code = 'ERR_CAMOUFOX_HAR_EXPORT_PENDING';
    if (directory) error.recoveryDir = directory;
    return error;
}

function hasHarScratchData(directory) {
    for (const entry of listCaptureDirectory(directory, { trustedLocal: true })) {
        if (entry.isFile() && entry.name === 'attribution-index.json') continue;
        if (entry.isDirectory() && entry.name === 'payloads') {
            if (listCaptureDirectory(path.join(directory, entry.name), { trustedLocal: true }).length === 0) continue;
        }
        if (entry.isFile() && entry.name === 'traffic.ndjson' &&
            fs.lstatSync(path.join(directory, entry.name), { bigint: true }).size === 0n) continue;
        return true;
    }
    return false;
}

function cleanAbandonedHarScratch(storage, profileId, directory, generation) {
    removeHarTemporaryDir(directory, () => {
        if (hasHarScratchData(directory)) throw pendingHarExportError(directory);
        if (!hasHarScratchIndex(directory)) return true;
        const pending = inspectHarScratch(directory, profileId, storage.trafficDir, generation);
        if (pending?.phase === 'recording' || pending?.phase === 'unready') return true;
        throw pendingHarExportError(directory);
    });
}

function currentHarTargetVersion(harPath, expectedVersion) {
    const current = captureExportTargetVersion(harPath);
    if (current !== null && current !== expectedVersion) {
        throw new Error('Could not confirm the previous HAR publication. Target and capture were preserved.');
    }
    return current;
}

function publishHarScratch({ directory, index, harPath, storageGeneration }, writeArchive) {
    const recovery = index.harRecovery ?? { storageGeneration, ready: true, finalized: true };
    const publication = recovery.publication;
    const savePublication = (publication) => {
        const harRecovery = { ...recovery, publication };
        const updated = { ...index, harRecovery };
        writePrivateFile(path.join(directory, 'attribution-index.json'),
            `${JSON.stringify(updated, null, 2)}\n`, { durable: true });
        index.harRecovery = harRecovery;
    };

    if (publication?.published === true) {
        if (captureExportTargetVersion(harPath) === null) {
            throw new Error('Could not confirm the previous HAR publication. Target and capture were preserved.');
        }
        // A prior process may have stopped before syncing either directory.
        syncDirectory(path.dirname(harPath));
        savePublication(publication);
        return;
    }

    const previousTarget = currentHarTargetVersion(harPath, publication?.previousTarget);

    // Persist the old target's version before publishing so an interrupted rename
    // leaves enough evidence to refuse replacing a different archive on retry.
    savePublication({ previousTarget, published: false });
    writeArchive(previousTarget);
    savePublication({ previousTarget, published: true });
}

function recoverPendingHar(location, deletionIdentity) {
    const { profileDir, id: profileId } = location;
    const directory = path.join(profileDir, '.native', '~har-scratch');
    if (!inspectProfileDirectory({ profileDir: directory })) return true;

    let lease;
    let published = false;
    try {
        lease = acquireProfileLease(location);
        if (deletionIdentity) assertProfileIdentity(location, deletionIdentity);
        const identity = inspectProfileForDeletion(location);
        if (!identity) return false;
        const trafficDir = path.join(profileDir, 'traffic');
        removeHarTemporaryDir(directory, () => {
            const pending = inspectHarScratch(directory, profileId, trafficDir, identity.generation);
            if (!pending || pending.phase === 'unready') {
                if (!hasHarScratchData(directory) && (pending || !hasHarScratchIndex(directory))) return true;
                throw new Error('Could not validate the pending Camoufox HAR capture');
            }
            publishHarScratch({
                directory,
                harPath: pending.harPath,
                index: pending.index,
                storageGeneration: identity.generation
            }, (expectedTargetVersion) => exportTrafficToHar(directory, pending.harPath, { profileId }, {
                trustedLocal: true,
                recordBodies: pending.recordBodies,
                destinationTrafficDir: trafficDir,
                expectedTargetVersion
            }));
            published = true;
            return true;
        });
        return true;
    } catch (error) {
        if (error.code === 'ERR_CAMOUFOX_PROFILE_BUSY' ||
            (deletionIdentity && error.code === 'ERR_CAMOUFOX_PROFILE_STALE')) throw error;
        logger.warn(published ? 'Could not remove published Camoufox HAR scratch' :
            'Could not confirm Camoufox HAR publication. Capture preserved for retry.', {
            profileId,
            error: redactDiagnosticText(error.message)
        });
        return false;
    } finally {
        if (lease) releaseProfileLease(lease);
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
        ...resolveSessionStartSettings(options, savedMetadata, managedProxyBinding, location)
    };
}

function canReuseProfile(session) {
    return !session.stopRequested && !session.recording?.stopped && session.view?.browser.isConnected();
}

async function getPrimaryPage(session) {
    if (!canReuseProfile(session)) throw new Error('Camoufox profile closed while opening a page');
    if (session.page && session.page.isClosed?.() !== true) return session.page;

    session.openingPage ??= Promise.resolve().then(async () => {
        const { context } = session;
        const existing = context.pages().find((page) => page.isClosed?.() !== true);
        const page = existing ?? await context.newPage();
        if (!canReuseProfile(session) || page.isClosed?.() === true) {
            throw new Error('Camoufox profile closed while opening a page');
        }
        session.page = page;
        session.view.page = page;
        return page;
    }).finally(() => {
        session.openingPage = null;
    });
    return session.openingPage;
}

function profileLifecycle(session) {
    const { location, profileId, context } = session;
    return {
        profilesDir: location.profilesDir,
        canReuse: () => canReuseProfile(session),
        getPage: () => getPrimaryPage(session),
        saveStorageState: () => saveProfileStorageState(profileId, context),
        closeContext: (close) => closeProfileContext(session, close),
        stop: async () => ({
            stopped: await stopProfileAt(location, session),
            closed: Boolean(session.closed),
            trafficAttribution: structuredClone(session.finalTrafficAttribution ?? null)
        }),
        delete: (stop) => deleteProfileAt(location, session, stop),
        async getTrafficAttribution() {
            if (activeProfiles.get(location.key) === session) await pendingProfileStops.get(location.key);
            if (session.closed || activeProfiles.get(location.key) !== session) {
                return structuredClone(session.finalTrafficAttribution ?? null);
            }
            if (!session.trafficRecorder) return null;
            assertProfileOwner(session);
            return session.trafficRecorder.flushSummary({ nativeLogsClosed: false });
        }
    };
}

function takeIdleSharedBrowser(browser, failedKey) {
    if (!browser || [...activeProfiles.values()].some((session) => session.browser === browser) ||
        [...pendingProfileStarts].some(([key, start]) => key !== failedKey && start.networkSettings.useSharedBrowser)) {
        return false;
    }
    for (const [key, entry] of sharedBrowsers) {
        if (entry.browser === browser) {
            sharedBrowsers.delete(key);
            return true;
        }
    }
    return false;
}

/**
 * Start a Camoufox profile by ID.
 * Supports both dedicated per-profile Camoufox browser instances and shared browser contexts,
 * loading and persisting `profiles/<profileId>/storage-state.json`.
 */
export async function startProfile(requestedProfileId, options = {}, expectedStorageGeneration, attempt = {}) {
    const { signal } = options;
    signal?.throwIfAborted();
    resolveConfiguredNetworkPolicyMode(options.portScanProtection, options.securityPolicy?.portScanProtection);
    if (stoppingAllProfiles) {
        throw new Error('Camoufox profile shutdown is in progress');
    }
    const location = locateProfile(requestedProfileId, options.profilesDir || getDefaultProfilesDirectory(), true);
    const { id: profileId, profilesDir, key } = location;
    const creation = createdProfileOwners.get(attempt.createdProfile);
    if (creation && creation.location.key !== key) {
        throw new Error('Camoufox startup does not match its newly created profile');
    }

    if (pendingProfileDeletes.has(key)) {
        throw new Error('Camoufox profile is being deleted');
    }
    const stopping = pendingProfileStops.get(key);
    if (stopping) {
        const previous = activeProfiles.get(key);
        const stopped = await waitForCamoufoxStartup(stopping, signal);
        if (!stopped && !previous?.reopenFromSavedSnapshot) {
            if (previous?.nativeExitUnconfirmed) throw nativeExitUnconfirmedError();
            throw new Error('Previous Camoufox profile session could not be stopped');
        }
        return startProfile(profileId, { ...options, profilesDir }, expectedStorageGeneration, attempt);
    }
    let startSettings = readStartSettings(location, options, expectedStorageGeneration);
    if (closingSharedBrowsers && startSettings.useSharedBrowser) {
        await waitForCamoufoxStartup(closingSharedBrowsers, signal);
        return startProfile(profileId, { ...options, profilesDir }, expectedStorageGeneration, attempt);
    }
    const existing = activeProfiles.get(key);
    if (existing) {
        if (existing.nativeExitUnconfirmed) throw nativeExitUnconfirmedError();
        if (existing.harExportPending) throw pendingHarExportError(existing.harTemporaryDir);
        if (existing.view?.browser.isConnected()) {
            if (!canReuseProfile(existing)) {
                throw new Error('Finish stopping this Camoufox profile before starting it again');
            }
            assertProfileOwner(existing);
            checkProfileReuse(existing, startSettings.reuseSettings);
            await waitForCamoufoxStartup(getPrimaryPage(existing), signal);
            logger.info('Reusing active Camoufox profile session', { profileId });
            return existing.view;
        }
        const stopped = await waitForCamoufoxStartup(stopProfileAt(location), signal);
        if (!stopped && !existing.reopenFromSavedSnapshot) {
            if (existing.nativeExitUnconfirmed) throw nativeExitUnconfirmedError();
            throw new Error('Previous Camoufox profile session could not be stopped');
        }
        return startProfile(profileId, { ...options, profilesDir }, expectedStorageGeneration, attempt);
    }

    const starting = pendingProfileStarts.get(key);
    if (starting) {
        if (creation) throw new Error('Camoufox profile is already being started');
        checkProfileReuse(starting, startSettings.reuseSettings);
        return waitForCamoufoxStartup(starting.promise, signal);
    }
    const saving = pendingProfileSaves.get(key);
    if (saving) {
        await waitForCamoufoxStartup(saving.promise, signal);
        return startProfile(profileId, { ...options, profilesDir }, expectedStorageGeneration, attempt);
    }

    const lease = acquireProfileLease(location);
    try {
        // Another process could have updated the profile before this process acquired it.
        if (creation) assertProfileIdentity(location, creation.identity);
        startSettings = readStartSettings(location, options, expectedStorageGeneration);
    } catch (error) {
        releaseProfileLease(lease);
        throw error;
    }
    if (closingSharedBrowsers && startSettings.useSharedBrowser) {
        releaseProfileLease(lease);
        await waitForCamoufoxStartup(closingSharedBrowsers, signal);
        return startProfile(profileId, { ...options, profilesDir }, expectedStorageGeneration, attempt);
    }
    const {
        savedMetadata, managedProxyBinding, definedOptions, normalizedProxy, useSharedBrowser, launchOptions,
        contextOptions, env, guardSettings, processRouting, reuseSettings
    } = startSettings;

    const startPromise = (async () => {
        let identity = null;
        let browser = null;
        let context = null;
        let ownsBrowser = false;
        let nativeExitGuarded = false;
        let nativeLaunchAttempted = false;
        let securityGuards = null;
        let trafficRecorder = null;
        let nativeLogsClosed = false;
        const confirmRecordingClosed = (confirmed) => { nativeLogsClosed = confirmed ? true : null; };
        let harTemporaryDir = null;
        let harRecovery = null;
        let initializedStorage = null;
        let openedSession = null;
        let hasClosedContext = () => browser?.isConnected?.() === false;
        try {
            const { attachSessionCompatibility, observeContextClosure } = await import('./profile.js');
            signal?.throwIfAborted();
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
            const harScratch = path.join(storageInfo.nativeDir, '~har-scratch');
            cleanAbandonedHarScratch(storageInfo, profileId, harScratch, metadata._storageGeneration);
            identity = stampProfileIdentity(location, storageInfo.metadataPath, metadata);
            if (creation) creation.identity = identity;
            initializedStorage = storageInfo;
            const {
                recordTraffic, recordBodies, recordWireLog, sslKeyLog,
                neckoMozLog, neckoMozLogModules, recordHar, harPath, harBodies, maxBodyBytes
            } = reuseSettings.recordingSettings;

            restrictLegacySharedKeyLog(profilesDir);
            if (!recordTraffic) archiveLegacyNativeLogs(storageInfo);
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
                    fs.mkdirSync(harScratch, { mode: 0o700 });
                    harTemporaryDir = harScratch;
                    harRecovery = { storageGeneration: identity.generation, ready: false };
                }
                trafficRecorder = new CamoufoxTrafficRecorder({
                    profileId,
                    trafficDir: harTemporaryDir || storageInfo.trafficDir,
                    profileNativeDir: recordTraffic ? storageInfo.nativeDir : null,
                    trustedLocal: true,
                    nativeLogsAreClosed: () => nativeLogsClosed,
                    sslKeyLog: recordTraffic && sslKeyLog,
                    sslKeyLogPath: trafficPaths.sslKeyLogPath,
                    preTlsWireLogPath: recordTraffic ? storageInfo.preTlsWireLogPath : null,
                    neckoMozLog: recordTraffic && neckoMozLog,
                    neckoMozLogPath: trafficPaths.neckoMozLogPath,
                    harPath,
                    harRecovery,
                    os: targetOs,
                    proxyServer: normalizedProxy?.server || null,
                    accountId: options.accountId ?? mergedOptions.accountId ?? null,
                    accountEmail: options.accountEmail ?? mergedOptions.accountEmail ?? null,
                    recordBodies: recordTraffic ? recordBodies : harBodies,
                    recordWireLog: recordTraffic && recordWireLog,
                    maxBodyBytes
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
            signal?.throwIfAborted();
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
                signal?.throwIfAborted();

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

                if (typeof launchFn !== 'function') throw new TypeError('Camoufox dedicated launcher is unavailable');
                // Reserve the exit guard before the resource can outlive its controller.
                nativeExitGuarded = true;
                retainProfileLeaseForNativeExit(lease);
                nativeLaunchAttempted = true;
                browser = await launchFn(launchOpts);
                ownsBrowser = true;
                signal?.throwIfAborted();

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
            signal?.throwIfAborted();

            const fingerprintLedger = new CanvasWebglConsistencyLedger({
                profileId,
                ledgerPath: path.join(storageInfo.profileDir, 'fingerprint-ledger.json'),
                assertStorageOwner: () => {
                    if (openedSession?.stopRequested || hasClosedContext()) {
                        throw Object.assign(new Error('Camoufox fingerprint ledger session has closed'), {
                            code: 'ERR_CAMOUFOX_PROFILE_STALE'
                        });
                    }
                    assertProfileOwner({ location, lease, identity });
                },
                maxHammingDistance:
                    options.maxHammingDistance ??
                    mergedOptions.maxHammingDistance ??
                    0,
                skipHosts: mergedOptions.securityPolicy?.canvasSkipHosts
            });
            if (fingerprintLedger.loadFailed) {
                logger.warn('Could not load Camoufox fingerprint ledger', { profileId });
            }

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

            signal?.throwIfAborted();
            const existingPages = context.pages();
            const page = existingPages.length > 0 ? existingPages[0] : await context.newPage();
            signal?.throwIfAborted();

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
                metadata: {
                    ...metadata,
                    os: targetOs,
                    proxy: normalizedProxy,
                    geoip,
                    humanize,
                    trafficPaths
                }
            };

            const active = openedSession = {
                ...session,
                location,
                lease,
                identity,
                nativeExitGuarded,
                hasClosedContext,
                ...reuseSettings,
                recording: trafficRecorder,
                confirmRecordingClosed,
                harPath,
                harTemporaryDir,
                harBodies,
                storageInfo
            };
            const lifecycle = profileLifecycle(active);
            active.view = attachSessionCompatibility(session, lifecycle);
            signal?.throwIfAborted();
            if (attempt.beforeReady) await attempt.beforeReady(active.view);
            signal?.throwIfAborted();
            if (harPath) active.harPreviousTarget = captureExportTargetVersion(harPath);
            if (harRecovery) {
                harRecovery.publication = { previousTarget: active.harPreviousTarget, published: false };
                harRecovery.ready = true;
                await trafficRecorder.flushSummary({ nativeLogsClosed: false });
                signal?.throwIfAborted();
            }

            logger.info('Camoufox profile started', {
                profileId,
                os: targetOs,
                storageStatePath,
                useSharedBrowser
            });

            profileContexts.set(context, location);
            activeProfiles.set(key, active);
            attempt.lifecycle = lifecycle;
            if (creation) creation.session = active;
            return active.view;
        } catch (error) {
            const failed = openedSession ?? {
                profileId,
                location,
                browser,
                ownsBrowser,
                nativeExitGuarded,
                nativeExitUnconfirmed: nativeLaunchAttempted && !browser,
                context,
                hasClosedContext,
                securityGuards,
                recording: trafficRecorder,
                confirmRecordingClosed,
                harTemporaryDir,
                storageInfo: initializedStorage,
                lease,
                identity
            };
            failed.startFailed = true;
            if (harRecovery) harRecovery.ready = false;
            failed.stopRequested = true;
            failed.ownsBrowser ||= takeIdleSharedBrowser(browser, key);
            let released = false;
            try {
                if (await closeNativeProfile(failed)) {
                    const finalized = await cleanClosedProfile(failed);
                    if (!failed.nativeExitUnconfirmed && (finalized || failed.cleanupAbandoned)) {
                        releaseProfileLease(lease);
                        released = true;
                    }
                }
            } catch (cleanupError) {
                logger.warn('Could not finish failed Camoufox profile startup cleanup', {
                    profileId,
                    error: redactDiagnosticText(cleanupError.message)
                });
            }
            if (!released) {
                activeProfiles.set(key, failed);
                attempt.lifecycle = profileLifecycle(failed);
                if (creation) creation.session = failed;
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
    const location = locateProfile(profileId, options.profilesDir || getConfiguredProfilesDirectory());
    try {
        return await stopProfileAt(location);
    } catch (error) {
        if (error.code !== 'ERR_CAMOUFOX_PROFILE_BUSY' && error.code !== 'ERR_CAMOUFOX_NATIVE_EXIT_UNCONFIRMED') throw error;
        logger.warn(error.message, { profileId: location.id });
        return false;
    }
}

async function finalizeProfileRecording(session) {
    if (!session.closed) throw new Error('Camoufox has not confirmed browser closure');
    if (session.identity) assertProfileOwner(session);
    let summary = await session.recording.stop({ nativeLogsClosed: true });
    if (session.harPath && !session.startFailed) {
        try {
            if (session.harTemporaryDir) {
                const pending = inspectHarScratch(session.harTemporaryDir, session.profileId,
                    session.storageInfo.trafficDir, session.identity.generation);
                if (pending?.harPath !== session.harPath || pending.phase === 'unready') {
                    throw new Error('Could not validate the pending Camoufox HAR capture');
                }
                summary = pending.index;
                publishHarScratch({
                    directory: session.harTemporaryDir,
                    harPath: session.harPath,
                    index: summary,
                    storageGeneration: session.identity.generation
                }, (expectedTargetVersion) => session.recording.exportHar(session.harPath, {
                    recordBodies: session.harBodies,
                    destinationTrafficDir: session.storageInfo.trafficDir,
                    expectedTargetVersion
                }));
            } else {
                const expectedTargetVersion = currentHarTargetVersion(session.harPath, session.harPreviousTarget);
                session.recording.exportHar(session.harPath, { recordBodies: session.harBodies, expectedTargetVersion });
            }
        } catch (cause) {
            throw Object.assign(new Error('Camoufox HAR archive was not published. Capture preserved for retry.', {
                cause
            }), { code: 'ERR_CAMOUFOX_HAR_EXPORT_PENDING' });
        }
    }
    session.recordingFinalized = true;
    session.harExportPending = false;
    session.finalTrafficAttribution = structuredClone(summary);
}

function saveFinalProfileSnapshot(session) {
    if (session.startFailed) return;
    session.closingSnapshot ??= (async () => {
        await pendingProfileSaves.get(session.location.key)?.promise.catch(() => {});
        let contextAlreadyClosed = false;
        try {
            if (!session.pendingSnapshot) {
                contextAlreadyClosed = session.contextClosed || session.hasClosedContext();
                if (contextAlreadyClosed) {
                    throw new Error('Camoufox context closed before the final storage snapshot');
                }
                session.pendingSnapshot = await captureProfileStorageState(session);
            }
            writeProfileStorageState(session, session.pendingSnapshot);
            session.pendingSnapshot = null;
        } catch (error) {
            const message = session.pendingSnapshot
                ? 'Could not write final Camoufox storage state. Snapshot retained for retry.'
                : 'Could not save storage state before closing profile';
            logger.warn(message, {
                profileId: session.profileId,
                error: redactDiagnosticText(error?.message ?? String(error))
            });
            return { error, contextAlreadyClosed };
        }
    })();
    return session.closingSnapshot;
}

async function closeProfileContext(session, close) {
    const snapshot = await saveFinalProfileSnapshot(session);
    try {
        await close();
    } catch (error) {
        if (!session.hasClosedContext()) session.closingSnapshot = null;
        throw error;
    }
    if (snapshot) throw snapshot.error;
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

    if (session.ownsBrowser && !session.browserClosed && browser?.isConnected?.() === false) {
        session.nativeExitUnconfirmed = true;
    }
    session.browserClosed ||= !session.ownsBrowser || !browser || browser.isConnected?.() === false;
    if (!session.browserClosed) {
        if (!session.contextClosed) await saveFinalProfileSnapshot(session);
        try {
            await browser.close();
            session.browserClosed = true;
        } catch (error) {
            session.browserClosed = browser.isConnected?.() === false;
            if (session.browserClosed) session.nativeExitUnconfirmed = true;
            if (!session.browserClosed) {
                logger.warn('Could not close Camoufox browser', {
                    profileId,
                    error: redactDiagnosticText(error.message)
                });
            }
        }
        session.contextClosed ||= session.browserClosed;
    }
    if (!session.contextClosed) session.closingSnapshot = null;
    if (session.nativeExitUnconfirmed) {
        if (!session.nativeExitGuarded) retainProfileLeaseForNativeExit(session.lease);
    } else if (session.nativeExitGuarded && session.browserClosed) {
        confirmProfileLeaseNativeExit(session.lease);
        session.nativeExitGuarded = false;
    }
    return session.contextClosed && session.browserClosed;
}

async function cleanClosedProfile(session) {
    session.closed = true;
    session.harExportPending = Boolean(session.harPath && !session.recordingFinalized);
    session.confirmRecordingClosed?.(!session.nativeExitUnconfirmed);
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

    try {
        if (session.storageInfo) {
            assertProfileOwner(session);
            restrictNativeLogs(session.storageInfo);
        }
        if (session.recording && !session.recordingFinalized) {
            await finalizeProfileRecording(session);
        }
    } catch (error) {
        if (error.code === 'ERR_CAMOUFOX_PROFILE_STALE' ||
            session.recording?.ledgerWriteError || session.recording?.wireWriteError) {
            await session.recording?.abandon();
            session.cleanupAbandoned = true;
        }
        const message = error.code === 'ERR_CAMOUFOX_HAR_EXPORT_PENDING' ? error.message :
            'Could not finalize Camoufox profile files';
        logger.warn(message, {
            profileId,
            error: redactDiagnosticText(error.message)
        });
        return false;
    }
    if (session.harTemporaryDir) {
        try {
            assertProfileOwner(session);
            removeHarTemporaryDir(session.harTemporaryDir, (directory) => {
                if (session.startFailed && hasHarScratchData(directory)) {
                    session.harExportPending = true;
                    throw pendingHarExportError(directory);
                }
                return true;
            });
            session.harTemporaryDir = null;
        } catch (error) {
            logger.warn('Could not remove temporary Camoufox HAR data', {
                profileId,
                error: redactDiagnosticText(error.message)
            });
            return false;
        }
    }
    return true;
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

function stopProfileAt(location, expected = null, deletionIdentity) {
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
        if (deletionIdentity) assertProfileIdentity(location, deletionIdentity);
        const session = activeProfiles.get(key);
        if (!session) {
            if (expected) return false;
            assertProfileLeaseIdle(location);
            return recoverPendingHar(location, deletionIdentity);
        }
        if (expected && (session !== expected || !matchesProfileSession(session))) return false;

        session.stopRequested = true;
        if (session.pendingSnapshot && (session.contextClosed || session.hasClosedContext())) {
            session.closingSnapshot = null;
        }
        await saveFinalProfileSnapshot(session);
        if (!(await closeNativeProfile(session))) return false;
        const finalized = await cleanClosedProfile(session);
        session.cleanupConfirmed = finalized && !session.nativeExitUnconfirmed;
        if (session.nativeExitUnconfirmed) {
            logger.warn(nativeExitUnconfirmedError().message, { profileId });
            return false;
        }
        if (session.pendingSnapshot) return false;
        if (!finalized && !session.cleanupAbandoned) return false;
        const snapshotError = await session.closingSnapshot;
        releaseProfileLease(session.lease);
        activeProfiles.delete(key);
        session.stopResult = !snapshotError && session.cleanupConfirmed;
        session.reopenFromSavedSnapshot = session.cleanupConfirmed && snapshotError?.contextAlreadyClosed === true;
        if (session.stopResult) logger.info('Camoufox profile stopped', { profileId });
        return session.stopResult;
    })().catch((error) => {
        if (error.code === 'ERR_CAMOUFOX_PROFILE_BUSY' || error.code === 'ERR_CAMOUFOX_NATIVE_EXIT_UNCONFIRMED' ||
            (deletionIdentity && error.code === 'ERR_CAMOUFOX_PROFILE_STALE')) throw error;
        logger.warn('Error stopping Camoufox profile', { profileId, error: redactDiagnosticText(error.message) });
        return false;
    }).finally(() => {
        pendingProfileStops.delete(key);
        updateProcessCleanupHooks();
    });
    pendingProfileStops.set(key, stopPromise);
    return stopPromise;
}

function deletionTargetKey(location) {
    return createHash('sha256').update(location.key).digest('hex');
}

/**
 * Capture a JSON-serializable target for a local deletion that may need to be retried.
 */
export function getProfileDeletionTarget(profileId, options = {}) {
    const location = locateProfile(profileId, options.profilesDir || getConfiguredProfilesDirectory());
    const identity = inspectProfileForDeletion(location);
    if (!identity) return null;
    return Object.freeze({
        key: deletionTargetKey(location),
        dev: String(identity.dev),
        ino: String(identity.ino),
        generation: identity.generation
    });
}

/**
 * Delete a profile by ID, optionally restricting the request to a captured deletion target.
 */
export async function deleteProfile(profileId, options = {}) {
    const location = locateProfile(profileId, options.profilesDir || getConfiguredProfilesDirectory());
    if (!Object.hasOwn(options, 'deletionTarget')) return deleteProfileAt(location);

    const target = options.deletionTarget;
    if (target?.key !== deletionTargetKey(location) ||
        ![target.dev, target.ino].every((value) => typeof value === 'string' && /^-?\d{1,20}$/.test(value)) ||
        (target.generation != null && typeof target.generation !== 'string')) {
        throw Object.assign(new TypeError('Invalid Camoufox profile deletion target'), {
            code: 'ERR_CAMOUFOX_INVALID_DELETION_TARGET'
        });
    }
    const identity = { dev: BigInt(target.dev), ino: BigInt(target.ino), generation: target.generation };
    return deleteProfileAt(location, null, undefined, identity);
}

export async function rollbackCreatedProfile(created) {
    const owner = createdProfileOwners.get(created);
    if (!owner) return 'delete-unconfirmed';
    try {
        await deleteProfileAt(owner.location, owner.session ?? owner);
        return 'deleted';
    } catch {
        return owner.session && !owner.session.closed ? 'stop-unconfirmed' : 'delete-unconfirmed';
    }
}

function deleteProfileAt(location, expected = null, stop, deletionIdentity = null) {
    const { profileDir, key } = location;
    const deleting = pendingProfileDeletes.get(key);
    if (deleting) {
        if ((expected && deleting.expected !== expected) ||
            !isDeepStrictEqual(deletionIdentity, deleting.deletionIdentity)) {
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
    const deletePromise = (async () => {
        if (expected?.deleted) return true;
        if (!fs.lstatSync(location.profilesDir, { throwIfNoEntry: false })) {
            if (expected) throw new Error('Could not stop Camoufox profile before deletion');
            return true;
        }
        const staging = acquireProfileDeletionStaging(location);
        try {
            // A retry finishes the detached generation before considering the live ID.
            const stagedIdentity = deletionIdentity ?? expected?.identity;
            if ((!expected || stagedIdentity) && removeStagedProfileDeletions(staging, stagedIdentity)) {
                if (expected) expected.deleted = true;
                return true;
            }

            await Promise.allSettled([pendingProfileStarts.get(key)?.promise, pendingProfileSaves.get(key)?.promise]);
            if (stop && !(await stop())) {
                if (expected.nativeExitUnconfirmed) throw nativeExitUnconfirmedError();
                if (!expected.cleanupConfirmed || !matchesProfileSession(expected)) {
                    throw new Error('Could not stop Camoufox profile before deletion');
                }
            }
            checkSession();
            const checked = inspectProfileForDeletion(location);
            if (expected || (deletionIdentity && checked)) {
                assertProfileIdentity(location, expected?.identity ?? deletionIdentity);
            }
            if (!checked && activeProfiles.has(key)) {
                throw new Error('Active Camoufox profile directory is missing');
            }
            const session = activeProfiles.get(key) ?? expected;
            if (!stop && checked && (pendingProfileStops.has(key) || !session?.cleanupConfirmed)) {
                const stopped = await stopProfileAt(location, expected, deletionIdentity);
                if (session?.nativeExitUnconfirmed) throw nativeExitUnconfirmedError();
                if (!stopped && !session?.cleanupConfirmed) {
                    throw new Error('Could not stop Camoufox profile before deletion');
                }
            }

            // Explicit deletion can discard a pending snapshot after the live generation is detached.
            const retained = activeProfiles.get(key);
            const lease = retained?.lease ?? acquireProfileLease(location);
            let staged = false;
            try {
                if (retained) assertProfileOwner(retained);
                if (!checked) {
                    if (inspectProfileForDeletion(location)) {
                        throw new Error('Camoufox profile directory changed during deletion');
                    }
                    return true;
                }
                const identity = expected?.identity ?? deletionIdentity ?? checked;
                const deletion = acquireProfileTrafficDeletionLease(profileDir);
                try {
                    stageProfileDeletion(location, staging, identity, lease);
                    staged = true;
                } finally {
                    releaseProfileLease(deletion);
                }
            } finally {
                if (retained && staged) {
                    retained.pendingSnapshot = null;
                    activeProfiles.delete(key);
                }
                if (!retained || staged) releaseProfileLease(lease);
            }
            removeStagedProfileDeletions(staging, expected?.identity ?? deletionIdentity ?? checked);
            if (expected) expected.deleted = true;
            if (retained) retained.deleted = true;
            logger.info('Camoufox profile deleted', { profileId: location.id, profileDir });
            return true;
        } finally {
            releaseProfileLease(staging.lease);
        }
    })().finally(() => {
        pendingProfileDeletes.delete(key);
        updateProcessCleanupHooks();
    });
    pendingProfileDeletes.set(key, { expected, deletionIdentity, promise: deletePromise });
    return deletePromise;
}

/**
 * Update proxy configuration for one or more profile IDs.
 * A write failure reports which profile updates were confirmed.
 */
export async function updateProfileProxy(profileIds, proxy, options = {}) {
    const ids = (Array.isArray(profileIds) ? profileIds : [profileIds]).map(validateProfileId);
    if (ids.length === 0) throw new Error('At least one Camoufox profile ID is required');

    const profilesDir = options.profilesDir || getConfiguredProfilesDirectory();
    const leases = [];
    const updatedProfileIds = [];
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
                geoip: existing?.geoip === false ? false : Boolean(normalizedProxy || existing?.geoip),
                updatedAt: new Date().toISOString()
            };
            try {
                if (existing) {
                    writeProfileMetadata(getProfileMetadataPath(location.id, location.profilesDir), updated);
                } else {
                    initializeProfileStorageAt(location, updated);
                }
            } catch (error) {
                const remainingProfileIds = profiles.slice(updatedProfileIds.length).map(({ location }) => location.id);
                throw Object.assign(new Error('Could not complete the Camoufox proxy update'), {
                    code: 'ERR_CAMOUFOX_PROXY_UPDATE_FAILED',
                    updatedProfileIds,
                    failedProfileId: location.id,
                    remainingProfileIds,
                    ...(error?.cleanupPending === true && { cleanupPending: true })
                });
            }
            updatedProfileIds.push(location.id);
        }
    } finally {
        for (const lease of leases) releaseProfileLease(lease);
    }

    logger.info('Updated Camoufox profile proxy configuration', {
        profileIds: ids,
        hasProxy: Boolean(normalizedProxy)
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
    getProfileDeletionTarget,
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
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    validateGpuPerformanceScalingCoherence
};
