// SPDX-License-Identifier: AGPL-3.0-or-later
// Camoufox Studio Local HTTP Server & RPC Bridge
// Connects the adapted Fury + Donut-inspired Web/Desktop UI to Camoufox Profile Suite.

import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import {
    USABLE_DEVICE_PRESET_CATALOG,
    listUsableDevicePresets,
    resolveDeterministicDeviceProfile,
    sanitizeAdsPowerProfileToCoherentPreset,
    expandCompatibleLanguages,
    selectCoherentSpeechVoices,
    createCoherentMediaDevices,
    attachZiniaoSecurityGuardsToContext,
    CanvasWebglConsistencyLedger,
    resolveGeoCoordinatesWithDeterministicJitter,
    computeGpuPerformanceScalingWeights,
    OS_FONT_CATALOG
} from '../src/camoufox/device-presets.js';
import { validateHardwareModelSpec } from '../src/camoufox/hardware-models.js';
import {
    collectBrowserFingerprint,
    evaluatePlatformCoherence,
    evaluateWireToDomCoherence
} from '../src/camoufox/coherence-auditor.js';
import {
    createProfile as createCamoufoxProfile,
    startProfile as startCamoufoxProfile,
    stopProfile as stopCamoufoxProfile,
    deleteProfile as deleteCamoufoxProfile,
    listProfiles as listCamoufoxProfiles,
    getActiveProfileIds,
    ensureProfileStorage
} from '../src/camoufox/client.js';
import {
    locateProfile,
    readProfileMetadata,
    writeProfileMetadata,
    prepareNativeLogs
} from '../src/camoufox/profile-storage.js';
import {
    CamoufoxTrafficRecorder,
    buildNativeLogEnvironment,
    verifyTrafficIntegrity
} from '../src/camoufox/traffic-recorder.js';
import { isCamoufoxModuleResolvable, isPackageEntryResolvable } from '../src/camoufox/sdk-resolution.js';
import { listCaptureDirectory } from '../src/camoufox/capture-io.js';
import { parseProxyAddress } from '../src/utils/proxy-protocol.js';
import {
    ensureStateDirectory,
    getDefaultProfilesDirectory,
    getStateDirectory
} from '../src/utils/state-paths.js';
import {
    ensurePrivateDirectory,
    readPrivateFile,
    writePrivateFile
} from '../src/utils/private-storage.js';
import { auditAdsPowerProfileDir } from '../scripts/audit-adspower-profiles.js';
import {
    listTrafficProfiles,
    queryProfileTraffic
} from '../scripts/query-traffic-attribution.js';
import { ensureCamoufoxBaseline } from '../scripts/ensure-camoufox-baseline.js';
import {
    DEFAULT_NETWORK_CONFIG,
    DNS_DISGUISE_PRESETS,
    detectNetdAvailability,
    normalizeNetworkConfig,
    startProfileNetworkEngine
} from './netd-bridge.mjs';
import {
    addActiveDockStackItem,
    cleanActiveDockStack,
    ensureDockFanStackPinned,
    ensureProfileDockExecutable,
    getInternalProfileRuntimeRoot,
    removeActiveDockStackItem,
    spawnBrowserAccountHud,
    writeFirefoxUserChrome,
    writeProfileStartPage
} from './browser-branding.mjs';

const execFileAsync = promisify(execFile);
const activeLocalProcesses = new Map();

// Prevent any stray proxy/browser socket error (EPIPE/ECONNRESET) from killing the local UI bridge
process.on('uncaughtException', (err) => {
    try {
        const logDir = path.join(ensureStateDirectory(), 'logs');
        ensurePrivateDirectory(logDir, { requireOwner: true });
        fs.appendFileSync(
            path.join(logDir, 'bridge-errors.log'),
            `[${new Date().toISOString()}] uncaughtException: ${err?.stack || err}\n`,
            { mode: 0o600 }
        );
    } catch {
        // never throw from error logger
    }
});
process.on('unhandledRejection', (reason) => {
    try {
        const logDir = path.join(ensureStateDirectory(), 'logs');
        ensurePrivateDirectory(logDir, { requireOwner: true });
        fs.appendFileSync(
            path.join(logDir, 'bridge-errors.log'),
            `[${new Date().toISOString()}] unhandledRejection: ${reason?.stack || reason}\n`,
            { mode: 0o600 }
        );
    } catch {
        // never throw from error logger
    }
});

function getCamoufoxCacheRoot() {
    if (process.platform === 'win32') {
        const localAppData = process.env.LOCALAPPDATA;
        const base = localAppData && path.isAbsolute(localAppData)
            ? localAppData
            : path.join(os.homedir(), 'AppData', 'Local');
        return path.join(base, 'camoufox', 'camoufox', 'Cache');
    }
    if (process.platform === 'darwin') {
        return path.join(os.homedir(), 'Library', 'Caches', 'camoufox');
    }
    const xdg = String(process.env.XDG_CACHE_HOME || '').trim();
    return path.join(xdg || path.join(os.homedir(), '.cache'), 'camoufox');
}

function camoufoxExecutableInDir(installDir) {
    if (!installDir) return null;
    if (process.platform === 'darwin') {
        return path.join(installDir, 'Camoufox.app', 'Contents', 'MacOS', 'camoufox');
    }
    if (process.platform === 'win32') {
        return path.join(installDir, 'camoufox.exe');
    }
    return path.join(installDir, 'camoufox-bin');
}

function readBrowserApplicationVersion(executablePath) {
    if (!executablePath) return null;
    try {
        const dir = path.dirname(executablePath);
        const iniCandidates = [
            path.basename(dir) === 'MacOS'
                ? path.join(path.dirname(dir), 'Resources', 'application.ini')
                : path.join(dir, 'application.ini'),
            path.join(dir, 'application.ini')
        ];
        for (const ini of iniCandidates) {
            if (!fs.existsSync(ini)) continue;
            const raw = fs.readFileSync(ini, 'utf8');
            const m = raw.match(/^Version=([^\r\n]+)/m);
            if (m && m[1]) return m[1].trim();
        }
    } catch {
        // ignore
    }
    return null;
}

function discoverInstalledCamoufoxCandidates() {
    const out = [];
    const envBin = String(process.env.CAMOUFOX_BINARY || process.env.CAMOUFOX_EXECUTABLE_PATH || '').trim();
    if (envBin) {
        out.push({ kind: 'camoufox', executable: path.resolve(envBin), label: 'Camoufox Binary (ENV)' });
    }
    const cacheRoot = getCamoufoxCacheRoot();
    try {
        const cfgFile = path.join(cacheRoot, 'config.json');
        if (fs.existsSync(cfgFile)) {
            const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
            if (cfg?.active_version) {
                const activeExec = camoufoxExecutableInDir(path.join(cacheRoot, cfg.active_version));
                if (activeExec) {
                    out.push({ kind: 'camoufox', executable: activeExec, label: `Camoufox C++ (${path.basename(cfg.active_version)})` });
                }
            }
        }
    } catch {
        // ignore config read error
    }
    try {
        const browsersRoot = path.join(cacheRoot, 'browsers');
        if (fs.existsSync(browsersRoot)) {
            for (const repoEntry of fs.readdirSync(browsersRoot, { withFileTypes: true })) {
                if (!repoEntry.isDirectory() || repoEntry.name.startsWith('.')) continue;
                const repoDir = path.join(browsersRoot, repoEntry.name);
                const versions = fs.readdirSync(repoDir, { withFileTypes: true })
                    .filter((d) => d.isDirectory())
                    .map((d) => d.name)
                    .sort()
                    .reverse();
                for (const ver of versions) {
                    const execPath = camoufoxExecutableInDir(path.join(repoDir, ver));
                    if (execPath) {
                        out.push({ kind: 'camoufox', executable: execPath, label: `Camoufox C++ (${ver})` });
                    }
                }
            }
        }
    } catch {
        // ignore scan error
    }
    const flatExec = camoufoxExecutableInDir(cacheRoot);
    if (flatExec) {
        out.push({ kind: 'camoufox', executable: flatExec, label: 'Camoufox C++ App' });
    }
    return out;
}

function detectLocalBrowser({ allowStockFallback = process.env.CAMOUFOX_ALLOW_STOCK_FIREFOX === 'true' } = {}) {
    const candidates = [
        ...discoverInstalledCamoufoxCandidates(),
        ...(allowStockFallback
            ? [
                {
                    kind: 'firefox',
                    executable: '/Applications/Firefox.app/Contents/MacOS/firefox',
                    label: '⚠️ 原版 Firefox (降级模式 · 无 C++ 硬件隔离)'
                },
                {
                    kind: 'firefox',
                    executable: '/usr/bin/firefox',
                    label: '⚠️ 原版 Firefox (降级模式 · 无 C++ 硬件隔离)'
                },
                {
                    kind: 'chrome',
                    executable: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                    label: '⚠️ Google Chrome (降级隔离窗口)'
                }
            ]
            : [])
    ];

    for (const c of candidates) {
        try {
            if (fs.existsSync(c.executable) && fs.statSync(c.executable).isFile()) {
                const version = readBrowserApplicationVersion(c.executable);
                return {
                    ...c,
                    version,
                    majorVersion: version ? String(version).split('.')[0] : '146',
                    label: c.kind === 'camoufox' && version ? `Camoufox C++ v${version}` : c.label
                };
            }
        } catch {
            // continue
        }
    }
    return null;
}

const baselineInstallState = {
    status: 'idle',
    error: null,
    startedAt: null,
    completedAt: null,
    executablePath: null
};
let pendingBaselineInstall = null;

function ensureCamoufoxEngineInstalledBackground() {
    const existing = detectLocalBrowser({ allowStockFallback: false });
    if (existing?.kind === 'camoufox') {
        baselineInstallState.status = 'ready';
        baselineInstallState.error = null;
        baselineInstallState.executablePath = existing.executable;
        return Promise.resolve(existing);
    }
    if (pendingBaselineInstall) return pendingBaselineInstall;
    baselineInstallState.status = 'installing';
    baselineInstallState.error = null;
    baselineInstallState.startedAt = new Date().toISOString();
    pendingBaselineInstall = ensureCamoufoxBaseline({ quiet: false, allowSkipInCi: false })
        .then((res) => {
            const detected = detectLocalBrowser({ allowStockFallback: false });
            if (detected?.kind === 'camoufox') {
                baselineInstallState.status = 'ready';
                baselineInstallState.executablePath = detected.executable;
                baselineInstallState.completedAt = new Date().toISOString();
                return detected;
            }
            throw new Error(res?.skipped ? 'Camoufox 自动安装被环境变量跳过' : 'Camoufox 内核解压后未找到可执行程序');
        })
        .catch((err) => {
            baselineInstallState.status = 'failed';
            baselineInstallState.error = err?.message || String(err);
            throw err;
        })
        .finally(() => {
            pendingBaselineInstall = null;
        });
    return pendingBaselineInstall;
}

let cachedOsProfilePids = { at: 0, map: new Map() };

function isPidAlive(pid) {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

function scanRunningProfilePids(force = false) {
    const now = Date.now();
    if (!force && now - cachedOsProfilePids.at < 750) {
        return cachedOsProfilePids.map;
    }
    const map = new Map();
    if (process.platform === 'darwin' || process.platform === 'linux') {
        try {
            const out = execFileSync('ps', ['-axo', 'pid=,args='], {
                encoding: 'utf8',
                timeout: 2000,
                maxBuffer: 4 * 1024 * 1024
            });
            for (const line of out.split(/\r?\n/)) {
                const m = line.match(/^\s*(\d+)\s+(.*)$/);
                if (!m) continue;
                const pid = Number.parseInt(m[1], 10);
                const args = m[2];
                // Skip Firefox/Chrome child helper processes (GPU, content tabs, crashhelper)
                if (/plugin-container|gpu-helper|crashhelper|media-plugin-helper|--type=/i.test(args)) {
                    continue;
                }
                const pm = args.match(/(?:--?profile\s+|--user-data-dir=)[^\s"']*\/profiles\/([^/\s"']+)\/browser-data/);
                if (pm && pm[1]) {
                    map.set(pm[1], pid);
                }
            }
        } catch {
            // ignore ps error
        }
    }
    cachedOsProfilePids = { at: now, map };
    return map;
}

function getAllActiveProfileIds() {
    const ids = new Set(getActiveProfileIds());
    const liveMap = scanRunningProfilePids();
    for (const id of liveMap.keys()) {
        ids.add(id);
    }
    const now = Date.now();
    for (const [id, entry] of activeLocalProcesses.entries()) {
        const recentlyStarted = entry?.launchedAtMs && (now - entry.launchedAtMs < 8000);
        const pwAlive = Boolean(entry?.pwContext);
        const alive = pwAlive || (entry?.child
            ? (!entry.child.killed && entry.child.exitCode === null)
            : (isPidAlive(entry?.pid) || recentlyStarted));
        if (alive || liveMap.has(id)) {
            ids.add(id);
        } else {
            activeLocalProcesses.delete(id);
            removeActiveDockStackItem(id);
            try { entry?.relay?.close(); } catch { /* ignore */ }
        }
    }
    return ids;
}

const TIMEZONE_METRO_COORDINATES = Object.freeze({
    'America/Los_Angeles': { latitude: 34.0522, longitude: -118.2437 },
    'America/New_York': { latitude: 40.7128, longitude: -74.0060 },
    'America/Chicago': { latitude: 41.8781, longitude: -87.6298 },
    'America/Denver': { latitude: 39.7392, longitude: -104.9903 },
    'America/Phoenix': { latitude: 33.4484, longitude: -112.0740 },
    'America/Toronto': { latitude: 43.6532, longitude: -79.3832 },
    'America/Vancouver': { latitude: 49.2827, longitude: -123.1207 },
    'America/Sao_Paulo': { latitude: -23.5505, longitude: -46.6333 },
    'America/Mexico_City': { latitude: 19.4326, longitude: -99.1332 },
    'Asia/Tokyo': { latitude: 35.6762, longitude: 139.6503 },
    'Asia/Seoul': { latitude: 37.5665, longitude: 126.9780 },
    'Asia/Singapore': { latitude: 1.3521, longitude: 103.8198 },
    'Asia/Hong_Kong': { latitude: 22.3193, longitude: 114.1694 },
    'Asia/Taipei': { latitude: 25.0330, longitude: 121.5654 },
    'Asia/Shanghai': { latitude: 31.2304, longitude: 121.4737 },
    'Asia/Bangkok': { latitude: 13.7563, longitude: 100.5018 },
    'Asia/Ho_Chi_Minh': { latitude: 10.8231, longitude: 106.6297 },
    'Asia/Jakarta': { latitude: -6.2088, longitude: 106.8456 },
    'Asia/Kolkata': { latitude: 19.0760, longitude: 72.8777 },
    'Asia/Dubai': { latitude: 25.2048, longitude: 55.2708 },
    'Europe/London': { latitude: 51.5074, longitude: -0.1278 },
    'Europe/Berlin': { latitude: 52.5200, longitude: 13.4050 },
    'Europe/Paris': { latitude: 48.8566, longitude: 2.3522 },
    'Europe/Amsterdam': { latitude: 52.3676, longitude: 4.9041 },
    'Europe/Madrid': { latitude: 40.4168, longitude: -3.7038 },
    'Europe/Rome': { latitude: 41.9028, longitude: 12.4964 },
    'Europe/Warsaw': { latitude: 52.2297, longitude: 21.0122 },
    'Europe/Zurich': { latitude: 47.3769, longitude: 8.5417 },
    'Europe/Istanbul': { latitude: 41.0082, longitude: 28.9784 },
    'Australia/Sydney': { latitude: -33.8688, longitude: 151.2093 }
});

const POSIX_REGION_BY_LANG = Object.freeze({
    en: 'en_US',
    ja: 'ja_JP',
    ko: 'ko_KR',
    zh: 'zh_CN',
    de: 'de_DE',
    fr: 'fr_FR',
    es: 'es_ES',
    pt: 'pt_BR',
    it: 'it_IT',
    nl: 'nl_NL',
    ru: 'ru_RU',
    uk: 'uk_UA',
    tr: 'tr_TR',
    ar: 'ar_SA',
    hi: 'hi_IN',
    id: 'id_ID',
    vi: 'vi_VN',
    th: 'th_TH',
    pl: 'pl_PL'
});

const SAFE_BROWSER_ENV_KEYS = new Set([
    'HOME',
    'USER',
    'LOGNAME',
    'PATH',
    'TMPDIR',
    'DISPLAY',
    'XAUTHORITY',
    'WAYLAND_DISPLAY',
    'DBUS_SESSION_BUS_ADDRESS',
    'XDG_RUNTIME_DIR',
    '__CF_USER_TEXT_ENCODING',
    'SYSTEMROOT',
    'WINDIR',
    'APPDATA',
    'LOCALAPPDATA',
    'USERPROFILE'
]);

function toPosixUtf8Locale(rawLocale, fallbackCountry = null) {
    const cleaned = String(rawLocale || 'en-US').trim();
    const parts = cleaned.split(/[-_]/).filter(Boolean);
    const lang = (parts[0] || 'en').toLowerCase();
    const explicitRegion = parts.find((seg, idx) => idx > 0 && /^[a-zA-Z]{2}$/.test(seg));
    if (explicitRegion) {
        return `${lang}_${explicitRegion.toUpperCase()}.UTF-8`;
    }
    if (fallbackCountry && /^[a-zA-Z]{2}$/.test(fallbackCountry)) {
        return `${lang}_${fallbackCountry.toUpperCase()}.UTF-8`;
    }
    const mapped = POSIX_REGION_BY_LANG[lang] || 'en_US';
    return `${mapped}.UTF-8`;
}

function deterministicCoordJitter(seedKey, baseLat, baseLon) {
    const digest = crypto.createHash('sha256').update(String(seedKey || 'default')).digest();
    const dLat = ((digest.readUInt16BE(0) / 65535) - 0.5) * 0.024;
    const dLon = ((digest.readUInt16BE(2) / 65535) - 0.5) * 0.024;
    return {
        latitude: Number((baseLat + dLat).toFixed(6)),
        longitude: Number((baseLon + dLon).toFixed(6)),
        accuracy: 25 + (digest[4] % 35)
    };
}

function resolveProfileGeoAndLocale(profile, preset, proxy) {
    const overrides = profile?.overrides || {};
    const rawPrimary = Array.isArray(profile?.languages) && profile.languages.length > 0
        ? String(profile.languages[0]).trim()
        : String(overrides.ui_locale || 'en-US').trim();
    const primaryBcp47 = rawPrimary.includes('-')
        ? rawPrimary
        : (POSIX_REGION_BY_LANG[rawPrimary.toLowerCase()] || 'en_US').replace('_', '-');
    const expandedLangs = Array.isArray(profile?.languages) && profile.languages.length > 0
        ? profile.languages.map((l) => String(l).trim()).filter(Boolean)
        : expandCompatibleLanguages(primaryBcp47);
    const normalizedLangs = expandedLangs[0]?.includes('-')
        ? expandedLangs
        : [primaryBcp47, ...expandedLangs.filter((x) => x.toLowerCase() !== primaryBcp47.toLowerCase())];

    const timezone = profile?.timezone
        || proxy?.last_timezone
        || (proxy?.last_country === 'JP' ? 'Asia/Tokyo' : 'America/New_York');
    const posixLocale = toPosixUtf8Locale(primaryBcp47, proxy?.last_country);

    let geolocation = null;
    if (
        overrides.geolocation &&
        Number.isFinite(Number(overrides.geolocation.latitude)) &&
        Number.isFinite(Number(overrides.geolocation.longitude))
    ) {
        geolocation = {
            latitude: Number(overrides.geolocation.latitude),
            longitude: Number(overrides.geolocation.longitude),
            accuracy: Number(overrides.geolocation.accuracy) || 35
        };
    } else if (TIMEZONE_METRO_COORDINATES[timezone]) {
        const base = TIMEZONE_METRO_COORDINATES[timezone];
        geolocation = deterministicCoordJitter(profile?.id || profile?.fp_seed, base.latitude, base.longitude);
    } else if (proxy?.last_country) {
        const resolved = resolveGeoCoordinatesWithDeterministicJitter(profile?.id || 'default', proxy.last_country);
        if (resolved && Number.isFinite(Number(resolved.latitude))) {
            geolocation = {
                latitude: Number(resolved.latitude),
                longitude: Number(resolved.longitude),
                accuracy: Number(resolved.accuracy) || 35
            };
        }
    }
    if (!geolocation) {
        geolocation = deterministicCoordJitter(profile?.id || 'default', 37.7749, -122.4194);
    }

    const effectiveGpuPreset = overrides.gpu
        ? USABLE_DEVICE_PRESET_CATALOG.find((p) => p.presetId === overrides.gpu)
        : null;
    const effectiveCores = overrides.cores ?? preset.hardwareConcurrency;
    const effectiveScreenW = overrides.screen?.width ?? preset.screen.width;
    const effectiveScreenH = overrides.screen?.height ?? preset.screen.height;
    const effectiveDpr = overrides.screen?.device_pixel_ratio ?? preset.screen.devicePixelRatio;
    const effectiveGpuVendor = effectiveGpuPreset ? effectiveGpuPreset.webgl.unmaskedVendor : preset.webgl.unmaskedVendor;
    const effectiveGpuRenderer = effectiveGpuPreset ? effectiveGpuPreset.webgl.unmaskedRenderer : preset.webgl.unmaskedRenderer;

    return {
        primaryLang: normalizedLangs[0] || primaryBcp47,
        languages: normalizedLangs,
        acceptLanguages: normalizedLangs.join(', '),
        timezone,
        posixLocale,
        geolocation,
        effectiveCores,
        effectiveScreenW,
        effectiveScreenH,
        effectiveDpr,
        effectiveGpuVendor,
        effectiveGpuRenderer
    };
}

function buildSanitizedDesktopBrowserEnv(extraEnv = {}, { timezone, posixLocale }) {
    const clean = {};
    for (const key of SAFE_BROWSER_ENV_KEYS) {
        if (process.env[key] !== undefined) {
            clean[key] = process.env[key];
        }
    }
    for (const [k, v] of Object.entries(extraEnv || {})) {
        if (
            k.startsWith('CAMOU_CONFIG_') ||
            k.startsWith('CAMOU_PREFS_') ||
            k === 'FONTCONFIG_FILE' ||
            k === 'SSLKEYLOGFILE' ||
            k === 'MOZ_LOG' ||
            k === 'MOZ_LOG_FILE'
        ) {
            if (v !== undefined && v !== null) clean[k] = String(v);
        }
    }
    if (timezone) clean.TZ = timezone;
    if (posixLocale) {
        clean.LANG = posixLocale;
        clean.LC_ALL = posixLocale;
        clean.LC_CTYPE = posixLocale;
    }
    clean.MOZ_CRASHREPORTER_DISABLE = '1';
    clean.MOZ_DISABLE_AUTO_SAFE_MODE = '1';
    return clean;
}

function buildProxyPrefsObject(effective) {
    const p = {};
    if (effective && effective.host && effective.port && effective.kind !== 'wireguard') {
        p['network.proxy.type'] = 1;
        p['network.proxy.no_proxies_on'] = '';
        p['network.proxy.allow_hijacking_localhost'] = false;
        p['network.proxy.failover_direct'] = false;
        p['network.dns.disablePrefetch'] = true;
        p['network.dns.disablePrefetchFromHTTPS'] = true;
        p['network.dns.disableIPv6'] = true;
        p['network.predictor.enabled'] = false;
        p['network.prefetch-next'] = false;
        p['network.http.speculative-parallel-limit'] = 0;
        p['network.trr.mode'] = 5;
        p['network.http.http3.enable'] = false;
        p['network.http.http3.enabled'] = false;
        p['network.captive-portal-service.enabled'] = false;
        p['network.connectivity-service.enabled'] = false;
        p['captivedetect.canonicalURL'] = '';
        p['media.peerconnection.ice.default_address_only'] = true;
        p['media.peerconnection.ice.proxy_only_if_behind_proxy'] = true;
        p['media.peerconnection.ice.obfuscate_host_addresses'] = true;
        p['media.peerconnection.ice.no_host'] = true;
        p['media.peerconnection.ice.tcp'] = true;
        if (effective.kind === 'socks5' || effective.kind === 'socks4') {
            p['network.proxy.share_proxy_settings'] = false;
            p['network.proxy.socks'] = String(effective.host);
            p['network.proxy.socks_port'] = Number(effective.port);
            p['network.proxy.socks_version'] = effective.kind === 'socks4' ? 4 : 5;
            p['network.proxy.socks_remote_dns'] = true;
            p['network.proxy.http'] = '';
            p['network.proxy.http_port'] = 0;
            p['network.proxy.ssl'] = '';
            p['network.proxy.ssl_port'] = 0;
            p['network.proxy.ftp'] = '';
            p['network.proxy.ftp_port'] = 0;
        } else {
            p['network.proxy.http'] = String(effective.host);
            p['network.proxy.http_port'] = Number(effective.port);
            p['network.proxy.ssl'] = String(effective.host);
            p['network.proxy.ssl_port'] = Number(effective.port);
            p['network.proxy.share_proxy_settings'] = true;
            p['network.proxy.socks'] = '';
            p['network.proxy.socks_port'] = 0;
        }
    } else {
        p['network.proxy.type'] = 0;
        p['media.peerconnection.ice.relay_only'] = false;
        p['network.http.http3.enable'] = true;
    }
    return p;
}

async function buildCamoufoxLaunchBundle({
    profile,
    preset,
    proxy,
    relay,
    executablePath,
    browserMajor,
    browserKind,
    geoLocale,
    headless = false
}) {
    const major = browserMajor || '146';
    const uaByOs = {
        macos: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:${major}.0) Gecko/20100101 Firefox/${major}.0`,
        windows: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${major}.0) Gecko/20100101 Firefox/${major}.0`,
        linux: `Mozilla/5.0 (X11; Linux x86_64; rv:${major}.0) Gecko/20100101 Firefox/${major}.0`
    };
    const fallbackUa = uaByOs[preset.os] || uaByOs.macos;
    const geoDataUrl = `data:application/json,${encodeURIComponent(JSON.stringify({
        status: 'OK',
        location: { lat: geoLocale.geolocation.latitude, lng: geoLocale.geolocation.longitude },
        accuracy: geoLocale.geolocation.accuracy
    }))}`;

    const baseFirefoxPrefs = {
        'browser.shell.checkDefaultBrowser': false,
        'browser.startup.homepage_override.mstone': 'ignore',
        'datareporting.policy.firstRunURL': '',
        'trailhead.firstrun.didSeeAboutWelcome': true,
        'browser.aboutwelcome.enabled': false,
        'toolkit.telemetry.reportingpolicy.firstRun': false,
        'toolkit.legacyUserProfileCustomizations.stylesheets': true,
        'browser.tabs.warnOnClose': false,
        'browser.tabs.warnOnCloseOtherTabs': false,
        'browser.warnOnQuit': false,
        'browser.warnOnQuitShortcut': false,
        'browser.sessionstore.resume_from_crash': false,
        'intl.accept_languages': geoLocale.acceptLanguages,
        'intl.locale.requested': geoLocale.primaryLang,
        'geo.enabled': true,
        'permissions.default.geo': 1,
        'geo.provider.use_corelocation': false,
        'geo.provider.ms-windows-location': false,
        'geo.provider.use_gpsd': false,
        'geo.provider.use_geoclue': false,
        'geo.provider.network.url': geoDataUrl,
        ...buildProxyPrefsObject(relay || proxy)
    };

    if (browserKind !== 'camoufox' || !isCamoufoxModuleResolvable()) {
        const allowedFonts = Array.isArray(OS_FONT_CATALOG[preset.os]) ? OS_FONT_CATALOG[preset.os].join(', ') : '';
        return {
            env: buildSanitizedDesktopBrowserEnv({}, geoLocale),
            firefoxUserPrefs: {
                ...baseFirefoxPrefs,
                'general.useragent.override': fallbackUa,
                ...(allowedFonts ? { 'font.system.whitelist': allowedFonts } : {})
            }
        };
    }

    const [{ launchOptions }, utilsMod] = await Promise.all([
        import('camoufox'),
        import('camoufox/dist/utils.js')
    ]);
    const isIpv4 = proxy?.last_ip && net.isIP(proxy.last_ip) === 4;
    const availH = preset.screen.availHeight ?? Math.max(600, geoLocale.effectiveScreenH - 38);
    const availW = preset.screen.availWidth ?? geoLocale.effectiveScreenW;
    const outerW = Math.min(availW, Math.max(960, availW - 40));
    const outerH = Math.min(availH, Math.max(680, availH - 24));
    const osShort = preset.os === 'macos' ? 'mac' : preset.os === 'windows' ? 'win' : 'lin';

    const seedConfig = {
        'navigator.userAgent': fallbackUa,
        'navigator.appVersion': fallbackUa.replace(/^Mozilla\//, ''),
        'navigator.platform': preset.os === 'macos' ? 'MacIntel' : preset.os === 'windows' ? 'Win32' : 'Linux x86_64',
        'navigator.oscpu': preset.os === 'macos' ? 'Intel Mac OS X 10.15' : preset.os === 'windows' ? 'Windows NT 10.0; Win64; x64' : 'Linux x86_64',
        'navigator.hardwareConcurrency': geoLocale.effectiveCores,
        'navigator.maxTouchPoints': preset.maxTouchPoints ?? 0,
        'headers.User-Agent': fallbackUa,
        'screen.width': geoLocale.effectiveScreenW,
        'screen.height': geoLocale.effectiveScreenH,
        'screen.availWidth': availW,
        'screen.availHeight': availH,
        'screen.availTop': preset.os === 'macos' ? 25 : 0,
        'screen.availLeft': 0,
        'screen.colorDepth': preset.screen.colorDepth ?? (preset.os === 'macos' ? 30 : 24),
        'screen.pixelDepth': preset.screen.colorDepth ?? (preset.os === 'macos' ? 30 : 24),
        'window.devicePixelRatio': geoLocale.effectiveDpr,
        'window.outerWidth': outerW,
        'window.outerHeight': outerH,
        'window.innerWidth': outerW,
        'window.innerHeight': Math.max(520, outerH - 86),
        'window.screenX': 20,
        'window.screenY': 28,
        'AudioContext:sampleRate': preset.os === 'macos' ? 48000 : 44100,
        'AudioContext:maxChannelCount': 2,
        timezone: geoLocale.timezone,
        'geolocation:latitude': geoLocale.geolocation.latitude,
        'geolocation:longitude': geoLocale.geolocation.longitude,
        'geolocation:accuracy': geoLocale.geolocation.accuracy,
        ...(isIpv4 ? { 'webrtc:ipv4': proxy.last_ip } : {}),
        ...(proxy ? { 'network:ipv4Only': true } : {})
    };

    const baseEnvForLaunchOptions = buildSanitizedDesktopBrowserEnv({}, geoLocale);
    let built;
    try {
        built = await launchOptions({
            executable_path: executablePath,
            os: preset.os,
            headless: true,
            humanize: true,
            canvas_noise: profile?.overrides?.canvas !== 'real',
            locale: geoLocale.languages,
            webgl_config: [geoLocale.effectiveGpuVendor, geoLocale.effectiveGpuRenderer],
            config: seedConfig,
            firefox_user_prefs: baseFirefoxPrefs,
            env: baseEnvForLaunchOptions,
            i_know_what_im_doing: true
        });
    } catch {
        // Newer SKU GPUs (e.g. Apple M5 / RTX 4090) may not yet be in fpgen's WebGL sample DB:
        // draw authentic OS-matched WebGL extensions/parameters first, then stamp exact SKU vendor/renderer.
        built = await launchOptions({
            executable_path: executablePath,
            os: preset.os,
            headless: true,
            humanize: true,
            canvas_noise: profile?.overrides?.canvas !== 'real',
            locale: geoLocale.languages,
            config: seedConfig,
            firefox_user_prefs: baseFirefoxPrefs,
            env: baseEnvForLaunchOptions,
            i_know_what_im_doing: true
        });
    }

    // Ensure exact SKU GPU vendor/renderer & core count remain pinned in CAMOU_CONFIG
    let finalCamouEnv = built.env || {};
    try {
        const rawBlob = utilsMod.camouConfigBlob(built);
        if (rawBlob) {
            const parsedCfg = JSON.parse(rawBlob);
            parsedCfg['webGl:vendor'] = geoLocale.effectiveGpuVendor;
            parsedCfg['webGl:renderer'] = geoLocale.effectiveGpuRenderer;
            parsedCfg['navigator.hardwareConcurrency'] = geoLocale.effectiveCores;
            parsedCfg['screen.width'] = geoLocale.effectiveScreenW;
            parsedCfg['screen.height'] = geoLocale.effectiveScreenH;
            parsedCfg['window.devicePixelRatio'] = geoLocale.effectiveDpr;
            parsedCfg.timezone = geoLocale.timezone;
            utilsMod.validateConfig(parsedCfg, executablePath);
            const rechunked = utilsMod.getEnvVars(parsedCfg, osShort, executablePath);
            const stripped = Object.fromEntries(
                Object.entries(finalCamouEnv).filter(([k]) => !k.startsWith('CAMOU_CONFIG_') && !k.startsWith('CAMOU_PREFS_'))
            );
            const mergedPrefs = { ...(built.firefoxUserPrefs || {}), ...baseFirefoxPrefs };
            if (!headless && Number(geoLocale.effectiveDpr) === 2 && process.platform === 'darwin') {
                // On Retina macOS, system HiDPI already renders at 2x without inflating CSS pixels
                delete mergedPrefs['layout.css.devPixelsPerPx'];
            }
            finalCamouEnv = {
                ...stripped,
                ...rechunked,
                ...utilsMod.getPrefEnvVars(mergedPrefs)
            };
            built.firefoxUserPrefs = mergedPrefs;
        }
    } catch {
        // keep built.env as-is if re-chunking skipped
    }

    return {
        env: buildSanitizedDesktopBrowserEnv(finalCamouEnv, geoLocale),
        firefoxUserPrefs: { ...(built.firefoxUserPrefs || {}), ...baseFirefoxPrefs }
    };
}

function writeFirefoxUserJs(browserDataDir, firefoxUserPrefs = {}) {
    const lines = [
        '// Generated by Camoufox Studio — per-profile C++ & network isolation prefs'
    ];
    for (const [k, v] of Object.entries(firefoxUserPrefs)) {
        if (v === undefined || v === null) continue;
        lines.push(`user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`);
    }
    writePrivateFile(path.join(browserDataDir, 'user.js'), lines.join('\n') + '\n', { requireOwner: true });
}

function syncDiskProfileMetadata(profilesDir, profile, preset, geoLocale) {
    try {
        const location = locateProfile(profile.id, profilesDir, true);
        ensureProfileStorage(profile.id, profilesDir);
        const current = readProfileMetadata(location);
        if (current) {
            writeProfileMetadata(location.profileDir, path.join(location.profileDir, 'profile.json'), {
                ...current,
                os: preset.os,
                presetId: preset.presetId,
                locale: geoLocale.primaryLang,
                timezoneId: geoLocale.timezone,
                resolvedLocale: geoLocale.primaryLang,
                resolvedLanguages: geoLocale.languages,
                resolvedTimezoneId: geoLocale.timezone,
                resolvedGeolocation: geoLocale.geolocation,
                updatedAt: new Date().toISOString()
            });
        }
    } catch {
        // non-fatal metadata sync
    }
}

async function launchLocalBrowserWindow(profile, preset, proxy, profilesDir, networkConfig = {}, projectName = '', options = {}) {
    let browser = detectLocalBrowser();
    if (!browser) {
        try {
            browser = await ensureCamoufoxEngineInstalledBackground();
        } catch (err) {
            throw new RpcError(
                503,
                `Camoufox 反检测内核尚未就绪且自动安装失败（${err?.message || err}）。请执行 npm run setup:camoufox 重试。`,
                'no_browser_binary'
            );
        }
    }

    const profileRoot = resolveSafeProfilePath(profilesDir, profile.id);
    ensurePrivateDirectory(profileRoot, { requireOwner: true });
    const geoLocale = resolveProfileGeoAndLocale(profile, preset, proxy);
    syncDiskProfileMetadata(profilesDir, profile, preset, geoLocale);

    // Store Browser-<serial>.app, start.html, and Camoufox browser-data on the INTERNAL boot volume
    // so macOS TCC never triggers "access files on a removable volume" while keeping numbered Dock icons!
    const runtimeRoot = getInternalProfileRuntimeRoot(profile.id, profileRoot);
    const browserDataDir = path.join(runtimeRoot, 'browser-data');
    ensurePrivateDirectory(browserDataDir, { requireOwner: true });
    // Clear any stale prefs.js overrides that could conflict with fresh user.js UA/geo/proxy settings
    try {
        const prefsJsPath = path.join(browserDataDir, 'prefs.js');
        if (fs.existsSync(prefsJsPath)) {
            const rawPrefs = fs.readFileSync(prefsJsPath, 'utf8');
            const cleanedPrefs = rawPrefs
                .split(/\r?\n/)
                .filter((line) => !/general\.useragent\.override|intl\.locale\.requested|intl\.accept_languages|geo\.provider\.network\.url/.test(line))
                .join('\n');
            if (cleanedPrefs !== rawPrefs) {
                writePrivateFile(prefsJsPath, cleanedPrefs, { requireOwner: true });
            }
        }
    } catch {
        // ignore prefs cleanup error
    }

    const startUrls = Array.isArray(profile.start_urls)
        ? profile.start_urls.map((u) => String(u || '').trim()).filter(Boolean)
        : [];

    // Start per-profile proxy relay + TCP<->UDP bridge in parallel with Dock icon wrapper
    const [relay, branded] = await Promise.all([
        startProfileNetworkEngine(profile.id, proxy, networkConfig),
        (browser.kind === 'firefox' || browser.kind === 'camoufox')
            ? ensureProfileDockExecutable(runtimeRoot, browser, profile)
            : Promise.resolve({ executable: browser.executable, appPath: null, icnsPath: null })
    ]);
    // Fail-closed: if this profile is configured with a proxy, NEVER allow a direct fallback that leaks local IP!
    if (proxy && proxy.host && proxy.port && proxy.kind !== 'wireguard' && !relay) {
        throw new RpcError(
            502,
            `环境 #${profile.serial_number || profile.id} 的本地代理中继启动失败，已阻止直连启动以防泄漏本地 IP。`,
            'proxy_relay_failed'
        );
    }
    const effectiveProxy = relay || proxy;

    // Generate local startup dashboard (`start.html`) with live 12-vector runtime self-audit as Tab 1
    const startPagePath = writeProfileStartPage(runtimeRoot, {
        profile,
        preset,
        proxy,
        relay,
        projectName,
        browserKind: browser.kind,
        browserVersion: browser.version || '',
        expectedSpec: {
            browserKind: browser.kind,
            uaMajor: browser.majorVersion || null,
            os: preset.os,
            cores: geoLocale.effectiveCores,
            gpuVendor: geoLocale.effectiveGpuVendor,
            gpuRenderer: geoLocale.effectiveGpuRenderer,
            screenW: geoLocale.effectiveScreenW,
            screenH: geoLocale.effectiveScreenH,
            dpr: geoLocale.effectiveDpr,
            timezone: geoLocale.timezone,
            primaryLang: geoLocale.primaryLang
        }
    });
    const startPageUrl = pathToFileURL(startPagePath).href;
    const targetUrls = [startPageUrl, ...startUrls];

    const executable = branded.executable || browser.executable;
    const appPath = branded.appPath || null;
    const dockIcnsPath = branded.icnsPath || null;

    const envCfg = readEditableEnv();
    const recordTrafficEnabled = options.recordTraffic !== undefined
        ? Boolean(options.recordTraffic)
        : envCfg.values.CAMOUFOX_RECORD_TRAFFIC !== 'false' && process.env.CAMOUFOX_RECORD_TRAFFIC !== 'false';
    const recordBodiesEnabled = envCfg.values.CAMOUFOX_RECORD_BODIES !== 'false' && process.env.CAMOUFOX_RECORD_BODIES !== 'false';
    const recordWireLogEnabled = envCfg.values.CAMOUFOX_RECORD_WIRE_LOG !== 'false' && process.env.CAMOUFOX_RECORD_WIRE_LOG !== 'false';

    const launchBundle = await buildCamoufoxLaunchBundle({
        profile,
        preset,
        proxy,
        relay,
        executablePath: executable,
        browserMajor: browser.majorVersion,
        browserKind: browser.kind,
        geoLocale,
        headless: false
    });

    if (browser.kind === 'firefox' || browser.kind === 'camoufox') {
        writeFirefoxUserJs(browserDataDir, launchBundle.firefoxUserPrefs);
        writeFirefoxUserChrome(browserDataDir, { profile, projectName });
    }

    // Prepare per-profile Pre-TLS traffic recorder & native SSLKEYLOGFILE / Necko MOZ_LOG paths
    let storageInfo = null;
    let trafficRecorder = null;
    let nativeLogEnv = launchBundle.env;
    try {
        storageInfo = ensureProfileStorage(profile.id, profilesDir);
        if (recordTrafficEnabled && storageInfo) {
            let nativeLogsClosed = false;
            trafficRecorder = new CamoufoxTrafficRecorder({
                profileId: profile.id,
                trafficDir: storageInfo.trafficDir,
                profileNativeDir: storageInfo.nativeDir,
                trustedLocal: true,
                nativeLogsAreClosed: () => nativeLogsClosed,
                sslKeyLog: true,
                sslKeyLogPath: storageInfo.sslKeyLogPath,
                preTlsWireLogPath: storageInfo.preTlsWireLogPath,
                neckoMozLog: true,
                neckoMozLogPath: storageInfo.neckoMozLogPath,
                harPath: storageInfo.harPath,
                os: preset.os,
                proxyServer: proxy?.host ? `${proxy.kind || 'socks5'}://${proxy.host}:${proxy.port}` : null,
                accountEmail: profile.account_email || null,
                recordBodies: recordBodiesEnabled,
                recordWireLog: recordWireLogEnabled
            });
            trafficRecorder._markNativeClosed = () => { nativeLogsClosed = true; };
            prepareNativeLogs(storageInfo, {
                sslKeyLog: true,
                neckoMozLog: true,
                harPath: storageInfo.harPath,
                sslKeyLogPath: trafficRecorder.sslKeyLogPath,
                neckoMozLogPath: trafficRecorder.neckoMozLogPath
            });
            await trafficRecorder.flushSummary({ nativeLogsClosed: false });
            nativeLogEnv = buildNativeLogEnvironment(launchBundle.env, {
                sslKeyLogPath: trafficRecorder.sslKeyLogPath,
                neckoMozLogPath: trafficRecorder.neckoMozLogPath,
                neckoMozLogModules: 'timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4'
            });
        }
    } catch {
        trafficRecorder = null;
    }

    const launchedAtMs = Date.now();
    let pollTimer = null;
    let closingPromise = null;
    const session = {
        child: null,
        pid: null,
        hud: null,
        pwContext: null,
        trafficRecorder,
        recordingActive: Boolean(trafficRecorder),
        engine: browser.label,
        browserKind: browser.kind,
        browserDataDir,
        relay,
        launchedAtMs,
        startedAt: new Date().toISOString(),
        cleanupSession: null,
        closeAsync: null
    };

    const finalizeTrafficRecorder = async () => {
        if (!session.trafficRecorder) return;
        const rec = session.trafficRecorder;
        session.trafficRecorder = null;
        session.recordingActive = false;
        try {
            rec._markNativeClosed?.();
            await rec.stop({ nativeLogsClosed: true });
        } catch {
            // ignore recorder stop error
        }
    };

    const cleanupSession = () => {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
        if (activeLocalProcesses.get(profile.id) === session) {
            activeLocalProcesses.delete(profile.id);
        }
        removeActiveDockStackItem(profile.id);
        try { session.hud?.close(); } catch { /* ignore */ }
        session.hud = null;
        void finalizeTrafficRecorder();
        try { relay?.close(); } catch { /* ignore */ }
    };

    session.cleanupSession = cleanupSession;
    session.closeAsync = async () => {
        if (closingPromise) return closingPromise;
        closingPromise = (async () => {
            if (session.pwContext) {
                const ctx = session.pwContext;
                session.pwContext = null;
                try {
                    await ctx.close();
                } catch {
                    // ignore close error
                }
            }
            await finalizeTrafficRecorder();
            cleanupSession();
        })();
        return closingPromise;
    };
    activeLocalProcesses.set(profile.id, session);

    const canUsePlaywrightRecording = Boolean(
        browser.kind === 'camoufox' &&
        trafficRecorder &&
        options.preferNativeOpen !== true &&
        isPackageEntryResolvable('playwright-core', import.meta)
    );

    if (canUsePlaywrightRecording) {
        try {
            const { firefox } = await import('playwright-core');
            const pwContext = await firefox.launchPersistentContext(browserDataDir, {
                executablePath: executable,
                headless: false,
                args: ['--no-remote'],
                env: nativeLogEnv,
                firefoxUserPrefs: launchBundle.firefoxUserPrefs,
                viewport: null,
                colorScheme: null,
                reducedMotion: null,
                forcedColors: null,
                contrast: null,
                locale: geoLocale.primaryLang,
                timezoneId: geoLocale.timezone,
                geolocation: geoLocale.geolocation,
                permissions: ['geolocation']
            });
            session.pwContext = pwContext;

            await attachZiniaoSecurityGuardsToContext(pwContext, {
                profileId: profile.id,
                portScanProtection: {
                    mode: 'url-only',
                    enabled: true,
                    allowedPorts: relay?.port ? [relay.port, PORT] : [PORT],
                    allowSameOriginLocalDev: false
                },
                onBlockedAttempt: (blockedEvent) => {
                    try {
                        trafficRecorder?.recordSecurityBlock?.(blockedEvent);
                    } catch {
                        // ignore
                    }
                }
            });

            await trafficRecorder.attachContext(pwContext);
            trafficRecorder.setStep('session-open');

            const pages = pwContext.pages();
            const firstPage = pages.length > 0 ? pages[0] : await pwContext.newPage();
            await trafficRecorder.attachPage(firstPage);
            await firstPage.goto(startPageUrl, { waitUntil: 'domcontentloaded' }).catch(() => {});
            for (const extraUrl of startUrls) {
                const tab = await pwContext.newPage();
                await trafficRecorder.attachPage(tab);
                void tab.goto(extraUrl, { waitUntil: 'domcontentloaded' }).catch(() => {});
            }

            pwContext.on('close', () => {
                void session.closeAsync();
            });

            // Bind OS PID asynchronously for macOS Dock stack & floating 2FA HUD
            void (async () => {
                for (let i = 0; i < 16; i++) {
                    if (activeLocalProcesses.get(profile.id) !== session) return;
                    const live = scanRunningProfilePids(true).get(profile.id);
                    if (live) {
                        session.pid = live;
                        addActiveDockStackItem({ profile, pid: live, icnsPath: dockIcnsPath });
                        void ensureDockFanStackPinned();
                        if (!session.hud) {
                            session.hud = spawnBrowserAccountHud({ profile, pid: live, runtimeRoot });
                        }
                        break;
                    }
                    await new Promise((r) => setTimeout(r, 200));
                }
            })();

            return {
                pid: session.pid,
                engine: browser.label,
                recording: true,
                networkEngine: relay?.engine || 'direct',
                relayPort: relay?.port || null,
                dnsStubPort: relay?.dnsStubPort || null,
                tcp2udpPort: relay?.tcp2udpPort || null,
                udpProxied: Boolean(relay?.udpSupported)
            };
        } catch (pwErr) {
            // Fall through cleanly to native OS launch if Playwright persistent context fails
            console.warn(`[Camoufox Studio] Playwright recorded context fallback to native launch: ${pwErr?.message || pwErr}`);
        }
    }

    let args;
    if (browser.kind === 'firefox' || browser.kind === 'camoufox') {
        args = ['--no-remote', '--profile', browserDataDir, '--new-window', ...targetUrls];
    } else {
        args = [
            `--user-data-dir=${browserDataDir}`,
            '--no-first-run',
            '--no-default-browser-check',
            '--new-window'
        ];
        if (effectiveProxy && effectiveProxy.host && effectiveProxy.port && effectiveProxy.kind !== 'wireguard') {
            args.push(`--proxy-server=${effectiveProxy.kind}://${effectiveProxy.host}:${effectiveProxy.port}`);
            args.push('--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1');
            args.push('--force-webrtc-ip-handling-policy=disable_non_proxied_udp');
        }
        args.push(...targetUrls);
    }

    let browserPid = null;
    if (process.platform === 'darwin' && appPath) {
        const openEnvArgs = [];
        for (const [k, v] of Object.entries(nativeLogEnv)) {
            if (
                k === 'TZ' ||
                k === 'LANG' ||
                k === 'LC_ALL' ||
                k === 'LC_CTYPE' ||
                k === 'SSLKEYLOGFILE' ||
                k === 'MOZ_LOG' ||
                k === 'MOZ_LOG_FILE' ||
                k === 'MOZ_CRASHREPORTER_DISABLE' ||
                k.startsWith('CAMOU_CONFIG_') ||
                k.startsWith('CAMOU_PREFS_')
            ) {
                openEnvArgs.push('--env', `${k}=${v}`);
            }
        }
        for (const k of ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY', 'no_proxy', 'NO_PROXY']) {
            openEnvArgs.push('--env', `${k}=`);
        }
        await execFileAsync('open', ['-g', '-n', ...openEnvArgs, '-a', appPath, '--args', ...args], {
            timeout: 12000,
            env: nativeLogEnv
        });
        void (async () => {
            for (let i = 0; i < 16; i++) {
                if (activeLocalProcesses.get(profile.id) !== session) return;
                await new Promise((r) => setTimeout(r, 200));
                const live = scanRunningProfilePids(i % 2 === 0).get(profile.id);
                if (live) {
                    session.pid = live;
                    addActiveDockStackItem({ profile, pid: live, icnsPath: dockIcnsPath });
                    void ensureDockFanStackPinned();
                    if (!session.hud) {
                        session.hud = spawnBrowserAccountHud({ profile, pid: live, runtimeRoot });
                    }
                    break;
                }
            }
            if (activeLocalProcesses.get(profile.id) !== session) return;
            pollTimer = setInterval(() => {
                if (session.pid && !isPidAlive(session.pid)) {
                    cleanupSession();
                } else if (!session.pid && Date.now() - launchedAtMs > 12000) {
                    const live = scanRunningProfilePids(true).get(profile.id);
                    if (live) session.pid = live;
                    else cleanupSession();
                }
            }, 2500);
            pollTimer.unref?.();
        })();
    } else {
        const child = spawn(executable, args, {
            detached: false,
            stdio: 'ignore',
            env: nativeLogEnv
        });
        browserPid = child.pid;
        session.child = child;
        session.pid = browserPid;
        if (browserPid) {
            addActiveDockStackItem({ profile, pid: browserPid, icnsPath: dockIcnsPath });
            void ensureDockFanStackPinned();
            session.hud = spawnBrowserAccountHud({ profile, pid: browserPid, runtimeRoot });
        }
        child.once('exit', cleanupSession);
        child.once('error', cleanupSession);
    }

    return {
        pid: browserPid,
        engine: browser.label,
        recording: Boolean(trafficRecorder),
        networkEngine: relay?.engine || 'direct',
        relayPort: relay?.port || null,
        dnsStubPort: relay?.dnsStubPort || null,
        tcp2udpPort: relay?.tcp2udpPort || null,
        udpProxied: Boolean(relay?.udpSupported)
    };
}

async function gracefulTerminateMacPids(pids) {
    if (process.platform !== 'darwin' || pids.length === 0) return false;
    const pyCode = [
        'import AppKit, sys',
        'for arg in sys.argv[1:]:',
        '    try:',
        '        app = AppKit.NSRunningApplication.runningApplicationWithProcessIdentifier_(int(arg))',
        '        if app:',
        '            app.terminate()',
        '    except Exception:',
        '        pass'
    ].join('\n');
    for (const py of ['/opt/homebrew/bin/python3', '/usr/bin/python3', 'python3']) {
        try {
            await execFileAsync(py, ['-c', pyCode, ...pids.map(String)], { timeout: 3000 });
            return true;
        } catch {
            // try next python
        }
    }
    return false;
}

async function stopManyLocalBrowserWindows(profileIds) {
    const ids = [...new Set((Array.isArray(profileIds) ? profileIds : []).map((x) => String(x || '')).filter(Boolean))];
    if (ids.length === 0) return { stopped: 0, total: 0 };

    const liveMap = scanRunningProfilePids(true);
    const pidsToWait = [];
    let stopped = 0;

    for (const id of ids) {
        const entry = activeLocalProcesses.get(id);
        const targetPid = entry?.child?.pid || entry?.pid || liveMap.get(id) || null;
        if (entry?.closeAsync) {
            await entry.closeAsync();
        } else if (entry?.cleanupSession) {
            entry.cleanupSession();
        } else {
            activeLocalProcesses.delete(id);
            removeActiveDockStackItem(id);
            try { entry?.relay?.close(); } catch { /* ignore */ }
        }
        if (targetPid && isPidAlive(targetPid)) {
            pidsToWait.push(targetPid);
            stopped++;
        } else if (entry) {
            stopped++;
        }
    }

    if (pidsToWait.length > 0) {
        // Send graceful macOS NSRunningApplication.terminate() (native Cmd+Q -> exit 0, ZERO crash dialogs!)
        const usedGraceful = await gracefulTerminateMacPids(pidsToWait);
        if (!usedGraceful) {
            for (const pid of pidsToWait) {
                try { process.kill(pid, 'SIGTERM'); } catch { /* ignore */ }
            }
        }
        // Wait up to 3.0s in parallel (all windows typically exit cleanly within ~400-800ms)
        for (let i = 0; i < 30; i++) {
            const remaining = pidsToWait.filter((pid) => isPidAlive(pid));
            if (remaining.length === 0) break;
            // After 1.5s, nudge any window that ignored Cmd+Q with SIGTERM
            if (i === 15) {
                for (const pid of remaining) {
                    try { process.kill(pid, 'SIGTERM'); } catch { /* ignore */ }
                }
            }
            await new Promise((r) => setTimeout(r, 100));
        }
        // Only SIGKILL genuinely hung processes after 3.0s
        for (const pid of pidsToWait) {
            if (isPidAlive(pid)) {
                try { process.kill(pid, 'SIGKILL'); } catch { /* ignore */ }
            }
        }
    }

    cachedOsProfilePids.at = 0;
    return { stopped, total: ids.length };
}

async function stopLocalBrowserWindow(profileId) {
    const res = await stopManyLocalBrowserWindows([profileId]);
    return res.stopped > 0;
}
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DIST_DIR = path.join(__dirname, 'dist');
const HOST = process.env.CAMOUFOX_UI_HOST || '127.0.0.1';
const PORT = Number.parseInt(process.env.CAMOUFOX_UI_PORT || '5274', 10);

const ALL_LOCAL_PERMS = [
    'view', 'launch', 'edit_profile', 'edit_fingerprint', 'edit_proxy',
    'reveal_secrets', 'export_cookies', 'create_profile', 'delete_profile',
    'manage_access'
];

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.txt': 'text/plain; charset=utf-8'
};

const EDITABLE_ENV_KEYS = [
    'PROFILE_SERVICE',
    'CAMOUFOX_OS',
    'CAMOUFOX_PRESET_ID',
    'CAMOUFOX_COUNTRY',
    'CAMOUFOX_HEADLESS',
    'CAMOUFOX_HUMANIZE',
    'CAMOUFOX_GEOIP',
    'CAMOUFOX_CANVAS_NOISE',
    'CAMOUFOX_PORT_SCAN_MODE',
    'CAMOUFOX_ALLOW_DIRECT',
    'CAMOUFOX_AUDIT_ON_START',
    'CAMOUFOX_RECORD_TRAFFIC',
    'CAMOUFOX_RECORD_BODIES',
    'CAMOUFOX_RECORD_WIRE_LOG',
    'CAMOUFOX_RECORD_HAR',
    'GPM_API_URL',
    'DOLPHIN_API_URL',
    'ACCOUNTS_COUNT',
    'THREADS_COUNT',
    'LOG_LEVEL'
];

const SECRET_ENV_KEYS = [
    { key: 'SMS_VERIFY_API_KEY', label: 'SMS Verification API Key', group: 'SMS', secret: true, placeholder: 'sms_verify_...' },
    { key: 'DOLPHIN_API_KEY', label: 'Dolphin Anty Authorization', group: 'Dolphin', secret: true, placeholder: 'Bearer <token>' },
    { key: 'DOLPHIN_FOLDER_ID', label: 'Dolphin Folder ID', group: 'Dolphin', secret: false, placeholder: 'optional folder id' },
    { key: 'DOLPHIN_TRUSTED_HTTP_API_URL', label: 'Dolphin Trusted Loopback HTTP URL', group: 'Dolphin', secret: false, placeholder: 'http://127.0.0.1:30898' },
    { key: 'GPM_TRUSTED_HTTP_API_URL', label: 'GPM Trusted Loopback HTTP URL', group: 'GPM', secret: false, placeholder: 'http://127.0.0.1:14517' },
    { key: 'GOLOGIN_API_KEY', label: 'GoLogin API Key', group: 'GoLogin', secret: true, placeholder: 'eyJhbGci...' },
    { key: 'OMOCAPTCHA_KEY', label: 'OMO Captcha Key', group: 'Captcha', secret: true, placeholder: 'optional extension key' }
];

function generateLocalApiKey() {
    return `cfx_live_${crypto.randomBytes(20).toString('hex')}`;
}

class RpcError extends Error {
    constructor(status, message, code = null, body = null) {
        super(message);
        this.status = status;
        this.code = code;
        this.body = body;
    }
}

// ---------------------------------------------------------------------------
// State storage (0600 private JSON under app state directory)
// ---------------------------------------------------------------------------

function stateFilePath() {
    const dir = ensureStateDirectory();
    return path.join(dir, 'desktop-state.json');
}

function proxiesFilePath() {
    const dir = ensureStateDirectory();
    ensurePrivateDirectory(path.join(dir, 'config'), { requireOwner: true });
    return path.join(dir, 'config', 'proxies.txt');
}

function envFilePath() {
    const dir = ensureStateDirectory();
    return path.join(dir, '.env');
}

function defaultState() {
    return {
        version: 1,
        apiKey: generateLocalApiKey(),
        apiKeyCreatedAt: new Date().toISOString(),
        projects: [],
        profiles: [],
        trash: [],
        proxies: [],
        credentials: {},
        bookmarks: [],
        templates: [],
        blocklists: {},
        extensions: {},
        cookies: {},
        audit: [],
        lastCoherence: null,
        networkDefaults: { ...DEFAULT_NETWORK_CONFIG }
    };
}

function ensureProfileSerialNumbers(state) {
    let changed = false;
    const used = new Set();
    const all = [...(state.profiles || []), ...(state.trash || [])];
    for (const p of all) {
        if (Number.isInteger(p?.serial_number) && p.serial_number > 0) {
            used.add(p.serial_number);
        }
    }
    const nextFree = () => {
        let n = used.size ? Math.max(...used) + 1 : 1;
        while (used.has(n)) n++;
        used.add(n);
        return n;
    };
    for (const p of (state.profiles || [])) {
        if (Number.isInteger(p?.serial_number) && p.serial_number > 0) continue;
        const m = String(p?.notes || '').match(/UserId\s*#(\d+)/i)
            || String(p?.name || '').match(/#(\d+)/);
        const parsed = m ? Number.parseInt(m[1], 10) : 0;
        if (parsed > 0 && !used.has(parsed)) {
            p.serial_number = parsed;
            used.add(parsed);
        } else {
            p.serial_number = nextFree();
        }
        changed = true;
    }
    return changed;
}

function loadState() {
    const file = stateFilePath();
    try {
        const raw = readPrivateFile(file, 'utf8', { requireOwner: true });
        const parsed = JSON.parse(raw);
        const merged = { ...defaultState(), ...parsed };
        let dirty = false;
        if (!parsed.apiKey) {
            merged.apiKey = generateLocalApiKey();
            merged.apiKeyCreatedAt = new Date().toISOString();
            dirty = true;
        }
        if (ensureProfileSerialNumbers(merged)) {
            dirty = true;
        }
        // Backfill account_totp from profile credential vault if already stored there
        for (const p of (merged.profiles || [])) {
            if (!p.account_totp) {
                const creds = merged.credentials?.[p.id];
                const match = Array.isArray(creds) ? creds.find((c) => c?.totp) : null;
                if (match?.totp) {
                    p.account_totp = String(match.totp).trim();
                    dirty = true;
                }
            }
        }
        if (dirty) saveState(merged);
        return merged;
    } catch (error) {
        if (error?.code === 'ENOENT') {
            const fresh = defaultState();
            hydrateFromDisk(fresh);
            ensureProfileSerialNumbers(fresh);
            saveState(fresh);
            return fresh;
        }
        throw error;
    }
}

function saveState(state) {
    const file = stateFilePath();
    writePrivateFile(file, JSON.stringify(state, null, 2) + '\n', { requireOwner: true });
}

function appendAudit(state, action, targetId = null, detail = null) {
    const nextId = (state.audit[0]?.id ?? 0) + 1;
    state.audit.unshift({
        id: nextId,
        actor: os.userInfo().username || 'local',
        action,
        target_id: targetId,
        detail,
        at: new Date().toISOString()
    });
    if (state.audit.length > 300) state.audit.length = 300;
}

function hydrateFromDisk(state) {
    // Import existing proxies from config/proxies.txt if present
    try {
        const raw = readPrivateFile(proxiesFilePath(), 'utf8', { requireOwner: true });
        const existingKeys = new Set(state.proxies.map((p) => `${p.kind}://${p.host}:${p.port}`));
        let idx = state.proxies.length + 1;
        for (const line of raw.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            try {
                const parsed = parseProxyAddress(trimmed);
                const kind = parsed.type || 'http';
                const key = `${kind}://${parsed.ip}:${parsed.port}`;
                if (existingKeys.has(key)) continue;
                existingKeys.add(key);
                state.proxies.push({
                    id: crypto.randomUUID(),
                    name: `Proxy ${idx++}`,
                    kind,
                    host: parsed.ip,
                    port: Number(parsed.port),
                    username: parsed.username || null,
                    password: parsed.password || null,
                    last_country: null,
                    last_ip: null,
                    last_timezone: null,
                    rotate_url: null,
                    checker_url: null
                });
            } catch {
                // Ignore malformed lines during hydration
            }
        }
    } catch {
        // proxies.txt absent
    }

    // Discover existing Camoufox profiles on disk
    try {
        const profilesDir = getDefaultProfilesDirectory();
        const diskProfiles = listCamoufoxProfiles(profilesDir);
        const knownIds = new Set([
            ...state.profiles.map((p) => p.id),
            ...state.trash.map((p) => p.id)
        ]);
        for (const dp of diskProfiles) {
            if (!dp?.id || knownIds.has(dp.id)) continue;
            const presetId = dp.presetId || dp.deviceProfile?.presetId || defaultPresetForOs(dp.os);
            state.profiles.push({
                id: dp.id,
                origin: 'local',
                shared_with: 0,
                project_id: null,
                name: dp.name || dp.id,
                notes: '',
                start_urls: [],
                status: '',
                tags: ['camoufox'],
                persona_id: presetId,
                fp_seed: seedFromId(dp.id),
                proxy_id: null,
                allow_no_proxy: true,
                timezone: dp.timezoneId || null,
                languages: dp.locale ? [dp.locale] : null,
                overrides: {},
                blocklists: [],
                last_opened_at: dp.lastStartedAt || null,
                coherence_score: 100
            });
        }
    } catch {
        // profiles dir absent or empty
    }
}

function syncProxiesTxt(state) {
    const lines = ['# Proxy format: ip:port:username:password (synced by Camoufox Studio UI)'];
    for (const p of state.proxies) {
        if (!p.host || !p.port || p.kind === 'wireguard') continue;
        const kind = p.kind || 'http';
        const auth = p.username
            ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password || '')}@`
            : '';
        const host = p.host.includes(':') && !p.host.startsWith('[') ? `[${p.host}]` : p.host;
        lines.push(`${kind}://${auth}${host}:${p.port}`);
    }
    writePrivateFile(proxiesFilePath(), lines.join('\n') + '\n', { requireOwner: true });
}

// ---------------------------------------------------------------------------
// Device Presets <-> Fury Persona & Preview mapping
// ---------------------------------------------------------------------------

function seedFromId(id) {
    const hash = crypto.createHash('sha256').update(String(id)).digest();
    return hash.readUInt32BE(0) || 1;
}

function presetOsLabel(preset) {
    if (preset.os === 'macos') return `macOS ${preset.osVersion}`;
    if (preset.os === 'windows') return `Windows ${preset.osVersion.startsWith('10') ? '10' : '11'}`;
    return `Linux ${preset.osVersion}`;
}

function defaultPresetForOs(osName = 'macos') {
    const norm = String(osName || '').toLowerCase();
    const match = USABLE_DEVICE_PRESET_CATALOG.find((p) => p.os === norm);
    return (match || USABLE_DEVICE_PRESET_CATALOG[0]).presetId;
}

function findPreset(presetId) {
    return USABLE_DEVICE_PRESET_CATALOG.find((p) => p.presetId === presetId) || USABLE_DEVICE_PRESET_CATALOG[0];
}

function getPersonasList() {
    const weight = Number((1 / USABLE_DEVICE_PRESET_CATALOG.length).toFixed(4));
    return USABLE_DEVICE_PRESET_CATALOG.map((preset) => ({
        id: preset.presetId,
        os: presetOsLabel(preset),
        gpu: preset.webgl.unmaskedRenderer,
        screen: `${preset.screen.width}×${preset.screen.height}${preset.screen.devicePixelRatio > 1 ? ` @${preset.screen.devicePixelRatio}x` : ''}`,
        weight,
        source: `${preset.deviceModel} · ${preset.cpuModel} · ${preset.ramGb}GB RAM`,
        own: false
    }));
}

function buildPreview(spec) {
    const preset = findPreset(spec?.persona_id);
    const seed = Number(spec?.fp_seed) || 1;
    const overrides = spec?.overrides || {};
    const primaryLang = Array.isArray(spec?.languages) && spec.languages.length > 0
        ? spec.languages[0]
        : (overrides.ui_locale || 'en-US');
    const expandedLangs = Array.isArray(spec?.languages) && spec.languages.length > 0
        ? spec.languages
        : expandCompatibleLanguages(primaryLang);
    const timeZone = spec?.timezone || 'America/New_York';

    const resolved = resolveDeterministicDeviceProfile(`preview-${preset.presetId}-${seed}`, {
        os: preset.os,
        presetId: preset.presetId,
        language: primaryLang,
        timeZone
    });

    const gpuOverride = overrides.gpu
        ? USABLE_DEVICE_PRESET_CATALOG.find((p) => p.presetId === overrides.gpu)
        : null;
    const effectiveCores = overrides.cores ?? preset.hardwareConcurrency;
    const effectiveMem = overrides.memory_gb ?? preset.ramGb;
    const effectiveScreen = overrides.screen
        ? {
            width: overrides.screen.width,
            height: overrides.screen.height,
            devicePixelRatio: overrides.screen.device_pixel_ratio ?? preset.screen.devicePixelRatio
        }
        : preset.screen;
    const effectiveVendor = gpuOverride ? gpuOverride.webgl.unmaskedVendor : preset.webgl.unmaskedVendor;
    const effectiveRenderer = gpuOverride ? gpuOverride.webgl.unmaskedRenderer : preset.webgl.unmaskedRenderer;
    const effectiveWebGpu = gpuOverride ? gpuOverride.webgl.GPUAdapterInfo : preset.webgl.GPUAdapterInfo;

    const targetOsShort = preset.os === 'macos' ? 'mac' : preset.os === 'windows' ? 'win' : 'lin';
    const platformStr = preset.os === 'macos' ? 'MacIntel' : preset.os === 'windows' ? 'Win32' : 'Linux x86_64';

    const telemetry = {
        navigator: {
            platform: platformStr,
            hardwareConcurrency: effectiveCores,
            maxTouchPoints: preset.maxTouchPoints ?? 0
        },
        webgl: {
            unmaskedVendor: effectiveVendor,
            unmaskedRenderer: effectiveRenderer,
            GPUAdapterInfo: effectiveWebGpu
        },
        screen: {
            width: effectiveScreen.width,
            height: effectiveScreen.height,
            devicePixelRatio: effectiveScreen.devicePixelRatio
        },
        hardwareProfile: {
            deviceModel: preset.deviceModel,
            cpuModel: preset.cpuModel,
            gpuModel: gpuOverride ? gpuOverride.gpuModel : preset.gpuModel,
            ramGb: effectiveMem,
            storageGb: preset.storageGb,
            architecture: preset.architecture,
            osVersion: preset.osVersion,
            webgpuAdapterInfo: effectiveWebGpu
        }
    };

    const skuCheck = validateHardwareModelSpec(telemetry, targetOsShort);
    const problems = [];
    if (!skuCheck.passed && Array.isArray(skuCheck.issues)) {
        for (const issue of skuCheck.issues) {
            problems.push(typeof issue === 'string' ? issue : (issue.message || issue.code || JSON.stringify(issue)));
        }
    }
    if (gpuOverride && gpuOverride.os !== preset.os) {
        problems.push(`GPU "${gpuOverride.gpuModel}" (${gpuOverride.os}) conflicts with target OS (${preset.os}).`);
    }

    const sameOsPresets = USABLE_DEVICE_PRESET_CATALOG.filter((p) => p.os === preset.os);
    const screenSet = new Map();
    for (const p of sameOsPresets) {
        screenSet.set(`${p.screen.width}x${p.screen.height}`, [p.screen.width, p.screen.height]);
    }
    const coreSet = [...new Set(sameOsPresets.map((p) => p.hardwareConcurrency))].sort((a, b) => a - b);
    const memSet = [...new Set(sameOsPresets.map((p) => p.ramGb))].sort((a, b) => a - b);
    const dprSet = [...new Set(sameOsPresets.map((p) => p.screen.devicePixelRatio))].sort((a, b) => a - b);
    const voices = selectCoherentSpeechVoices(preset.os, primaryLang);
    const media = createCoherentMediaDevices(`preview-${seed}`, preset.os);

    const detectedBrowser = detectLocalBrowser();
    const realMajor = detectedBrowser?.majorVersion || '146';
    const isRealCamoufox = detectedBrowser?.kind === 'camoufox';
    if (!isRealCamoufox) {
        problems.push(
            baselineInstallState.status === 'installing'
                ? 'Camoufox C++ 反检测内核正在后台下载安装中，安装完成后将自动启用全量硬件隔离。'
                : '当前尚未检出 Camoufox C++ 内核可执行程序，请等待自动安装完成或执行 npm run setup:camoufox。'
        );
    }

    const uaByOs = {
        macos: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:${realMajor}.0) Gecko/20100101 Firefox/${realMajor}.0`,
        windows: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${realMajor}.0) Gecko/20100101 Firefox/${realMajor}.0`,
        linux: `Mozilla/5.0 (X11; Linux x86_64; rv:${realMajor}.0) Gecko/20100101 Firefox/${realMajor}.0`
    };
    const resolvedUa = uaByOs[preset.os] || (resolved.userAgent ? resolved.userAgent.replace(/135\.0/g, `${realMajor}.0`) : uaByOs.macos);

    const availW = preset.screen.availWidth ?? effectiveScreen.width;
    const availH = preset.screen.availHeight ?? (effectiveScreen.height - 40);

    return {
        user_agent: resolvedUa,
        platform: platformStr,
        languages: expandedLangs,
        timezone: timeZone,
        hardware_concurrency: effectiveCores,
        device_memory: effectiveMem,
        screen: `${effectiveScreen.width}×${effectiveScreen.height}`,
        gpu_vendor: effectiveVendor,
        gpu_renderer: effectiveRenderer,
        client_hints_platform: presetOsLabel(preset),
        chrome_version: isRealCamoufox
            ? `Camoufox Gecko/${realMajor} (${detectedBrowser.version || realMajor})`
            : (detectedBrowser ? `⚠️ 降级 ${detectedBrowser.label}` : '⏳ Camoufox 安装中'),
        client_hints: isRealCamoufox
            ? `Camoufox C++ Patched Firefox v${detectedBrowser.version || realMajor} · ${preset.deviceModel}`
            : `等待 Camoufox C++ 内核就绪 · 目标预设 ${preset.deviceModel}`,
        avail: `${availW}×${availH}`,
        device_pixel_ratio: effectiveScreen.devicePixelRatio,
        color_depth: preset.screen.colorDepth ?? 24,
        max_touch_points: preset.maxTouchPoints ?? 0,
        webgpu: effectiveWebGpu ? `${effectiveWebGpu.vendor} (${effectiveWebGpu.architecture})` : null,
        webgl_extensions: preset.os === 'macos' ? 32 : 38,
        audio_sample_rate: preset.os === 'macos' ? 48000 : 44100,
        voices: Array.isArray(voices) ? voices.length : null,
        media_devices: Array.isArray(media) ? `${media.length} devices` : '3 devices',
        ui_locale: overrides.ui_locale || primaryLang,
        webrtc: 'proxy-aligned (Ziniao/Camoufox ICE guard)',
        js_heap_gb: Math.min(4, Math.max(1, Math.round(effectiveMem / 4))),
        persona_source: `${preset.deviceModel} (${preset.cpuModel})`,
        persona_weight: Number((1 / USABLE_DEVICE_PRESET_CATALOG.length).toFixed(4)),
        fonts: Array.isArray(resolved.fonts) ? resolved.fonts.length : 48,
        noise: {
            canvas: overrides.canvas !== 'real',
            audio: true,
            client_rects: true
        },
        problems,
        options: {
            screens: [...screenSet.values()],
            device_pixel_ratios: dprSet,
            cores: coreSet,
            memory_gb: memSet,
            gpus: sameOsPresets.map((p) => ({ id: p.presetId, renderer: p.webgl.unmaskedRenderer })),
            ui_locales: ['en-US', 'en-GB', 'zh-CN', 'de-DE', 'fr-FR', 'ja-JP', 'ko-KR', 'es-ES', 'ru-RU']
        },
        base: {
            screen: [preset.screen.width, preset.screen.height],
            device_pixel_ratio: preset.screen.devicePixelRatio,
            cores: preset.hardwareConcurrency,
            memory_gb: preset.ramGb,
            gpu: preset.webgl.unmaskedRenderer
        },
        geolocation: overrides.geolocation || null
    };
}

// ---------------------------------------------------------------------------
// Profile serialization for UI
// ---------------------------------------------------------------------------

function proxySummaryOf(proxy) {
    if (!proxy) return null;
    return {
        id: proxy.id,
        name: proxy.name,
        kind: proxy.kind,
        display: `${proxy.kind}://${proxy.host}:${proxy.port}`,
        has_rotation: Boolean(proxy.rotate_url),
        country: proxy.last_country || null,
        last_ip: proxy.last_ip || null,
        last_timezone: proxy.last_timezone || null
    };
}

function serializeProfile(state, p, activeSet) {
    const project = p.project_id ? state.projects.find((x) => x.id === p.project_id) : null;
    const proxy = p.proxy_id ? state.proxies.find((x) => x.id === p.proxy_id) : null;
    return {
        id: p.id,
        origin: 'local',
        shared_with: 0,
        project_id: project ? project.id : null,
        project_name: project ? project.name : null,
        serial_number: Number.isInteger(p.serial_number) ? p.serial_number : undefined,
        name: p.name,
        account_email: p.account_email ?? '',
        account_password: p.account_password ?? '',
        account_totp: p.account_totp ?? '',
        notes: p.notes ?? '',
        start_urls: p.start_urls ?? [],
        status: p.status ?? '',
        tags: Array.isArray(p.tags) ? p.tags : [],
        persona_id: p.persona_id || defaultPresetForOs('macos'),
        fp_seed: Number(p.fp_seed) || seedFromId(p.id),
        proxy: proxySummaryOf(proxy),
        proxy_id: proxy ? proxy.id : null,
        allow_no_proxy: p.allow_no_proxy ?? true,
        timezone: p.timezone ?? null,
        languages: p.languages ?? null,
        overrides: p.overrides ?? {},
        blocklists: p.blocklists ?? [],
        lock: null,
        permissions: ALL_LOCAL_PERMS,
        running: activeSet.has(p.id),
        last_opened_at: p.last_opened_at ?? null
    };
}

// ---------------------------------------------------------------------------
// Proxy parsing, TCP sniffing & diagnostics
// ---------------------------------------------------------------------------

function parseSingleProxyLine(rawLine) {
    const line = String(rawLine || '').trim();
    if (!line || line.startsWith('#')) return null;

    if (/^[a-z0-9+.-]+:\/\//i.test(line)) {
        try {
            const u = new URL(line);
            const port = Number(u.port);
            if (!u.hostname || !Number.isInteger(port) || port < 1 || port > 65535) return null;
            const kind = u.protocol.replace(/:$/, '').toLowerCase();
            return {
                kind: ['http', 'https', 'socks5', 'socks4'].includes(kind) ? kind : 'http',
                host: u.hostname.replace(/^\[|\]$/g, ''),
                port,
                username: u.username ? decodeURIComponent(u.username) : null,
                password: u.password ? decodeURIComponent(u.password) : null,
                shape: 'Url'
            };
        } catch {
            return null;
        }
    }

    // user:pass@host:port
    if (line.includes('@')) {
        const at = line.lastIndexOf('@');
        const left = line.slice(0, at);
        const right = line.slice(at + 1);
        const mRight = right.match(/^(.+):(\d+)$/);
        if (mRight) {
            const port = Number(mRight[2]);
            if (port >= 1 && port <= 65535) {
                const colon = left.indexOf(':');
                return {
                    kind: 'http',
                    host: mRight[1].replace(/^\[|\]$/g, ''),
                    port,
                    username: colon >= 0 ? left.slice(0, colon) : left,
                    password: colon >= 0 ? left.slice(colon + 1) : null,
                    shape: 'AtSign'
                };
            }
        }
    }

    try {
        const parsed = parseProxyAddress(line);
        const port = Number(parsed.port);
        if (!parsed.ip || !Number.isInteger(port) || port < 1 || port > 65535) return null;
        return {
            kind: parsed.type || 'http',
            host: parsed.ip,
            port,
            username: parsed.username || null,
            password: parsed.password || null,
            shape: parsed.username ? 'HostPortUserPass' : 'HostPort'
        };
    } catch {
        return null;
    }
}

function tcpProbe(host, port, timeoutMs = 2500) {
    return new Promise((resolve) => {
        const started = Date.now();
        const socket = net.createConnection({ host, port });
        let settled = false;
        const finish = (result) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve({ ...result, ms: Date.now() - started });
        };
        socket.setTimeout(timeoutMs);
        socket.on('connect', () => finish({ ok: true }));
        socket.on('timeout', () => finish({ ok: false, error: 'Connection timed out', code: 'timeout' }));
        socket.on('error', (err) => finish({ ok: false, error: err.message, code: err.code || 'connect_failed' }));
    });
}

function sniffProxyProtocol(host, port, timeoutMs = 2000) {
    return new Promise((resolve) => {
        const socket = net.createConnection({ host, port });
        let settled = false;
        const done = (kind) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve({ kind });
        };
        socket.setTimeout(timeoutMs);
        socket.on('connect', () => {
            // Send SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0
            socket.write(Buffer.from([0x05, 0x01, 0x00]));
        });
        socket.on('data', (chunk) => {
            if (chunk.length >= 2 && chunk[0] === 0x05) {
                done('socks5');
            } else if (chunk.toString('ascii').startsWith('HTTP/')) {
                done('http');
            } else {
                done(null);
            }
        });
        socket.on('timeout', () => done(null));
        socket.on('error', () => done(null));
        socket.on('end', () => done(null));
    });
}

async function diagnoseProxyTarget(state, { url, proxyId }) {
    let target = null;
    if (proxyId) {
        const saved = state.proxies.find((p) => p.id === proxyId);
        if (saved) target = { kind: saved.kind, host: saved.host, port: saved.port };
    }
    if (!target && url) {
        target = parseSingleProxyLine(url);
    }
    if (!target) {
        throw new RpcError(400, 'Invalid or missing proxy address.', 'invalid_proxy');
    }

    const steps = [];
    let resolvedIp = target.host;
    const dnsStart = Date.now();
    try {
        if (!net.isIP(target.host)) {
            const lookup = await dns.lookup(target.host);
            resolvedIp = lookup.address;
        }
        steps.push({
            step: 'dns',
            ok: true,
            ms: Date.now() - dnsStart,
            detail: `${target.host} -> ${resolvedIp}`,
            code: null
        });
    } catch (error) {
        steps.push({
            step: 'dns',
            ok: false,
            ms: Date.now() - dnsStart,
            detail: error.message,
            code: 'dns_failed'
        });
        return {
            ok: false,
            steps,
            exit: { ip: null, country: null, region: null, city: null, timezone: null, org: null },
            notes: [{ code: 'dns_failed', detail: `Could not resolve ${target.host}` }]
        };
    }

    const tcp = await tcpProbe(resolvedIp, target.port, 4000);
    steps.push({
        step: 'connect',
        ok: tcp.ok,
        ms: tcp.ms,
        detail: tcp.ok ? `TCP connected to ${resolvedIp}:${target.port}` : tcp.error,
        code: tcp.ok ? null : tcp.code
    });

    if (!tcp.ok) {
        return {
            ok: false,
            steps,
            exit: { ip: null, country: null, region: null, city: null, timezone: null, org: null },
            notes: [{ code: 'connect_failed', detail: tcp.error }]
        };
    }

    const sniff = await sniffProxyProtocol(resolvedIp, target.port, 2000);
    steps.push({
        step: 'handshake',
        ok: true,
        ms: null,
        detail: sniff.kind ? `Detected protocol: ${sniff.kind}` : `Configured protocol: ${target.kind}`,
        code: null
    });

    if (proxyId) {
        const saved = state.proxies.find((p) => p.id === proxyId);
        if (saved) {
            saved.last_ip = resolvedIp;
            saveState(state);
        }
    }

    return {
        ok: true,
        steps,
        exit: {
            ip: resolvedIp,
            country: null,
            region: null,
            city: null,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
            org: null
        },
        notes: []
    };
}

// ---------------------------------------------------------------------------
// TOTP helper (RFC 6238 SHA-1) for saved profile credentials
// ---------------------------------------------------------------------------

function base32Decode(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleaned = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = '';
    for (const ch of cleaned) {
        const idx = alphabet.indexOf(ch);
        if (idx >= 0) bits += idx.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

function generateTotp(secretOrUri, stepOffset = 0) {
    let secret = String(secretOrUri || '').trim();
    if (secret.startsWith('otpauth://')) {
        try {
            secret = new URL(secret).searchParams.get('secret') || '';
        } catch {
            secret = '';
        }
    }
    const key = base32Decode(secret);
    if (!key.length) throw new RpcError(400, 'Invalid TOTP secret');
    const epoch = Math.floor(Date.now() / 1000);
    const step = Math.floor(epoch / 30) + stepOffset;
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(step));
    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    return String(binary % 1_000_000).padStart(6, '0');
}

// ---------------------------------------------------------------------------
// Suite Lab helpers: Coherence, Traffic Attribution, AdsPower Audit, Env, Results
// ---------------------------------------------------------------------------

function startEphemeralProbeServer() {
    return new Promise((resolve, reject) => {
        const srv = http.createServer((req, res) => {
            const urlPath = (req.url || '/').split('?')[0];
            if (urlPath === '/api/wire-echo') {
                const body = JSON.stringify({
                    ok: true,
                    method: req.method,
                    headers: req.headers,
                    ts: Date.now()
                });
                res.writeHead(200, {
                    'Content-Type': 'application/json; charset=utf-8',
                    'Set-Cookie': 'NID=519=camoufox_probe_cookie; Path=/; HttpOnly; SameSite=Lax',
                    'Cache-Control': 'no-store'
                });
                res.end(body);
                return;
            }
            const html = `<!doctype html><html><head><meta charset="utf-8"><title>Camoufox Live Coherence Probe</title></head><body><h1>Camoufox Runtime & Pre-TLS Wire Probe</h1><button id="probe-btn">Trigger Probe</button></body></html>`;
            res.writeHead(200, {
                'Content-Type': 'text/html; charset=utf-8',
                'Set-Cookie': 'OTZ=8517545_88_88_104100_84_446760; Path=/; SameSite=Lax',
                'Cache-Control': 'no-store'
            });
            res.end(html);
        });
        srv.once('error', reject);
        srv.listen(0, '127.0.0.1', () => {
            const addr = srv.address();
            resolve({
                port: typeof addr === 'object' && addr ? addr.port : 0,
                close: () => new Promise((r) => srv.close(() => r()))
            });
        });
    });
}

function summarizeMeasuredTelemetry(telemetry) {
    if (!telemetry) return null;
    return {
        userAgent: telemetry.navigator?.userAgent || null,
        platform: telemetry.navigator?.platform || null,
        oscpu: telemetry.navigator?.oscpu || null,
        hardwareConcurrency: telemetry.navigator?.hardwareConcurrency ?? null,
        language: telemetry.navigator?.language || null,
        languages: telemetry.navigator?.languages || [],
        webdriver: telemetry.navigator?.webdriver ?? null,
        webglVendor: telemetry.webgl?.unmaskedVendor || null,
        webglRenderer: telemetry.webgl?.unmaskedRenderer || null,
        webglVersion: telemetry.webgl?.version || null,
        webglExtensionsCount: telemetry.webgl?.extensionsCount ?? null,
        webgpuAvailable: telemetry.webgpu?.available ?? null,
        canvasHash: telemetry.canvas2d?.fnv1aHash || null,
        audioSampleRate: telemetry.audio?.sampleRate ?? null,
        audioChannels: telemetry.audio?.maxChannelCount ?? null,
        mathSinHex: telemetry.mathPrecision?.hex?.sin1e6 || null,
        mathCosHex: telemetry.mathPrecision?.hex?.cos1e6 || null,
        screen: telemetry.screen
            ? `${telemetry.screen.width}×${telemetry.screen.height} @${telemetry.screen.devicePixelRatio}x (${telemetry.screen.colorDepth}-bit)`
            : null,
        timeZone: telemetry.intl?.timeZone || null,
        intlLocale: telemetry.intl?.locale || null,
        voicesCount: Array.isArray(telemetry.speechVoices) ? telemetry.speechVoices.length : 0,
        sampleVoices: Array.isArray(telemetry.speechVoices) ? telemetry.speechVoices.slice(0, 4).map((v) => `${v.name} (${v.lang})`) : [],
        detectedFonts: Array.isArray(telemetry.fonts) ? telemetry.fonts : [],
        workerParityOk: Boolean(telemetry.worker?.ok),
        iframeParityOk: Boolean(telemetry.iframeParity?.ok),
        toStringIntact: Boolean(telemetry.prototypeIntegrity?.toStringIntact),
        ownNavigatorOverrides: telemetry.prototypeIntegrity?.ownNavigatorOverrides || [],
        automationGlobals: telemetry.automationGlobals || [],
        storageQuotaBytes: telemetry.storageEstimate?.quotaBytes ?? null
    };
}

function runAdversarialNegativeControlLive(baseTelemetry) {
    const tampered = structuredClone(baseTelemetry);
    tampered.navigator.userAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36';
    tampered.navigator.hasUserAgentData = true;
    tampered.prototypeIntegrity.ownNavigatorOverrides = ['userAgent', 'webdriver'];
    tampered.prototypeIntegrity.webdriverGetter.isNative = false;
    if (tampered.worker) {
        tampered.worker.platform = 'Linux x86_64';
        tampered.worker.hardwareConcurrency = 2;
    }
    if (tampered.webgl) {
        tampered.webgl.unmaskedRenderer = 'Apple M2 Pro';
    }
    const evaluation = evaluatePlatformCoherence(tampered, 'windows');
    const failedNames = evaluation.checks
        .filter((check) => !check.passed && check.status !== 'not-tested')
        .map((check) => check.name);
    const expectedCatches = [
        'navigator-prototype-integrity',
        'dedicated-worker-parity',
        'engine-gecko-coherence',
        'os-platform-gpu-coherence'
    ];
    const caughtAll = evaluation.passed === false && expectedCatches.every((c) => failedNames.includes(c));
    return {
        caughtAll,
        passed: caughtAll,
        score: evaluation.score,
        failedChecks: failedNames
    };
}

async function runSingleHeadlessCamoufoxProbe({
    probeId,
    preset,
    profile,
    proxy = null,
    relay = null,
    targetUrl,
    probePort = null,
    persistTrafficDir = null,
    persistNativeDir = null,
    ledgerPath = null
}) {
    let browser = detectLocalBrowser({ allowStockFallback: false });
    if (!browser) {
        browser = await ensureCamoufoxEngineInstalledBackground();
    }
    const geoLocale = resolveProfileGeoAndLocale(profile, preset, proxy);
    const launchBundle = await buildCamoufoxLaunchBundle({
        profile,
        preset,
        proxy,
        relay,
        executablePath: browser.executable,
        browserMajor: browser.majorVersion,
        browserKind: browser.kind,
        geoLocale,
        headless: true
    });

    const tempRoot = persistTrafficDir
        ? null
        : fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'camoufox-live-probe-'));
    const trafficDir = persistTrafficDir || path.join(tempRoot, 'traffic');
    const nativeDir = persistNativeDir || path.join(tempRoot, '.native');
    ensurePrivateDirectory(trafficDir, { requireOwner: true });
    ensurePrivateDirectory(nativeDir, { requireOwner: true });

    let nativeClosed = false;
    const sslKeyLogPath = path.join(nativeDir, 'sslkeylog.txt');
    const neckoMozLogPath = path.join(nativeDir, 'necko-pre-tls.moz_log');
    const preTlsWireLogPath = path.join(trafficDir, 'pre-tls-wire.log');
    const harPath = path.join(trafficDir, 'trace.har');

    const recorder = new CamoufoxTrafficRecorder({
        profileId: probeId,
        trafficDir,
        profileNativeDir: nativeDir,
        trustedLocal: true,
        nativeLogsAreClosed: () => nativeClosed,
        sslKeyLog: true,
        sslKeyLogPath,
        preTlsWireLogPath,
        neckoMozLog: true,
        neckoMozLogPath,
        harPath,
        os: preset.os,
        proxyServer: proxy?.host ? `${proxy.kind || 'socks5'}://${proxy.host}:${proxy.port}` : null,
        accountEmail: profile?.account_email || null,
        recordBodies: true,
        recordWireLog: true
    });

    const probePrefs = { ...launchBundle.firefoxUserPrefs };
    if (!relay && !proxy) {
        probePrefs['network.proxy.type'] = 0;
    } else if (probePort) {
        probePrefs['network.proxy.no_proxies_on'] = '127.0.0.1, localhost';
    }
    const envWithLogs = buildNativeLogEnvironment(launchBundle.env, {
        sslKeyLogPath: recorder.sslKeyLogPath,
        neckoMozLogPath: recorder.neckoMozLogPath,
        neckoMozLogModules: 'timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4'
    });

    const { firefox } = await import('playwright-core');
    let pwBrowser = null;
    let pwContext = null;
    let telemetry = null;
    let wireSummary = null;
    let integrity = null;
    let ledgerResult = null;

    try {
        pwBrowser = await firefox.launch({
            executablePath: browser.executable,
            headless: true,
            env: envWithLogs,
            firefoxUserPrefs: probePrefs
        });
        pwContext = await pwBrowser.newContext({
            viewport: null,
            colorScheme: null,
            reducedMotion: null,
            forcedColors: null,
            contrast: null,
            locale: geoLocale.primaryLang,
            timezoneId: geoLocale.timezone,
            geolocation: geoLocale.geolocation,
            permissions: ['geolocation']
        });

        await attachZiniaoSecurityGuardsToContext(pwContext, {
            profileId: probeId,
            portScanProtection: {
                mode: 'url-only',
                enabled: true,
                allowedPorts: [probePort, relay?.port, PORT].filter(Boolean),
                allowSameOriginLocalDev: Boolean(probePort)
            },
            onBlockedAttempt: (blockedEvent) => {
                try { recorder.recordSecurityBlock?.(blockedEvent); } catch {}
            }
        });

        await recorder.attachContext(pwContext);
        recorder.setStep('live-audit-navigation');
        const page = await pwContext.newPage();
        await recorder.attachPage(page);

        await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 22000 });
        if (probePort && targetUrl.includes(`127.0.0.1:${probePort}`)) {
            recorder.setStep('live-wire-echo');
            await page.evaluate(async () => {
                await fetch('/api/wire-echo?bgRequest=botguard_probe_v1', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'f.req=%5B%22camoufox_wire_audit%22%5D&at=AFoagU_probe_token'
                });
            });
        }
        await new Promise((r) => setTimeout(r, 250));
        telemetry = await collectBrowserFingerprint(page);
    } finally {
        try { await pwContext?.close(); } catch {}
        try { await pwBrowser?.close(); } catch {}
        nativeClosed = true;
        wireSummary = await recorder.stop({ nativeLogsClosed: true }).catch(() => null);
    }

    telemetry.profileId = probeId;
    telemetry.hardwareProfile = {
        deviceModel: preset.deviceModel,
        cpuModel: preset.cpuModel,
        gpuModel: preset.gpuModel,
        ramGb: profile?.overrides?.memory_gb ?? preset.ramGb,
        storageGb: preset.storageGb,
        architecture: preset.architecture,
        osVersion: preset.osVersion,
        webgpuAdapterInfo: preset.webgl?.GPUAdapterInfo || null
    };
    telemetry.gpuPerformance = computeGpuPerformanceScalingWeights(
        telemetry.webgl?.unmaskedRenderer || geoLocale.effectiveGpuRenderer,
        {
            profileId: probeId,
            hostBaseline: {
                hostChipModel: os.cpus()?.[0]?.model || 'Apple Silicon Host',
                hostFp32Tflops: 14.2,
                hostMemoryBandwidthGBps: 200,
                hostPixelFillRateGPixels: 120
            }
        }
    );

    const targetOsShort = preset.os === 'macos' ? 'mac' : preset.os === 'windows' ? 'win' : 'lin';
    const domEval = evaluatePlatformCoherence(telemetry, preset.os);
    const ledgerEvents = fs.existsSync(path.join(trafficDir, 'traffic.ndjson'))
        ? fs.readFileSync(path.join(trafficDir, 'traffic.ndjson'), 'utf8')
            .split(/\r?\n/)
            .filter(Boolean)
            .map((l) => { try { return JSON.parse(l); } catch { return null; } })
            .filter(Boolean)
        : [];
    const wireEval = evaluateWireToDomCoherence(telemetry, ledgerEvents, targetOsShort);

    try {
        integrity = verifyTrafficIntegrity(trafficDir, { trustedLocal: true });
    } catch (err) {
        integrity = { valid: false, errors: [err?.message || String(err)] };
    }

    if (ledgerPath) {
        try {
            const ledger = new CanvasWebglConsistencyLedger({
                profileId: probeId,
                ledgerPath,
                maxHammingDistance: 0
            });
            const hostKey = (() => { try { return new URL(targetUrl).hostname; } catch { return 'probe.local'; } })();
            ledgerResult = ledger.recordAndVerify(hostKey, {
                canvasHash: telemetry.canvas2d?.fnv1aHash || null,
                webglRenderer: telemetry.webgl?.unmaskedRenderer || null,
                webglVendor: telemetry.webgl?.unmaskedVendor || null
            });
        } catch (err) {
            ledgerResult = { passed: false, reason: err?.message || String(err) };
        }
    }

    if (tempRoot) {
        try { fs.rmSync(tempRoot, { recursive: true, force: true }); } catch {}
    }

    const combinedChecks = [
        ...domEval.checks.map((c) => ({
            name: c.name,
            category: 'runtime-dom',
            passed: Boolean(c.passed),
            status: c.status || (c.passed ? 'passed' : 'failed'),
            details: c.details
        })),
        ...wireEval.checks.map((c) => ({
            name: c.name,
            category: 'pre-tls-wire',
            passed: Boolean(c.passed),
            status: c.status || (c.passed ? 'passed' : 'failed'),
            details: c.details
        }))
    ];
    const testedChecks = combinedChecks.filter((c) => c.status !== 'not-tested');
    const passedChecks = testedChecks.filter((c) => c.passed);
    const combinedScore = testedChecks.length > 0
        ? Math.round((passedChecks.length / testedChecks.length) * 100)
        : 0;
    const allPassed = combinedChecks.every((c) => c.passed && c.status !== 'not-tested');

    return {
        passed: allPassed,
        status: allPassed ? 'passed' : 'failed',
        score: combinedScore,
        domScore: domEval.score,
        wireScore: wireEval.score,
        wireInspectedRequests: wireEval.inspectedRequests,
        checks: combinedChecks,
        telemetry,
        measured: summarizeMeasuredTelemetry(telemetry),
        integrity,
        ledgerResult,
        wireSummary,
        browserEngine: browser.label,
        browserVersion: browser.version,
        geoLocale
    };
}

async function runCoherenceDiagnostic(state, params = {}) {
    if (params?.dryRun === true) {
        const { stdout, stderr } = await execFileAsync(
            process.execPath,
            [path.join(REPO_ROOT, 'scripts', 'verify-camoufox-coherence.js'), '--dry-run'],
            { cwd: REPO_ROOT, timeout: 30000, maxBuffer: 4 * 1024 * 1024 }
        );
        const match = stdout.match(/Diagnostic report written to:\s*(.+)/);
        let report = null;
        if (match) {
            try { report = JSON.parse(fs.readFileSync(match[1].trim(), 'utf8')); } catch {}
        }
        return { timestamp: new Date().toISOString(), mode: 'dry-run-synthetic', report, stdout: stdout.trim(), stderr: stderr.trim() };
    }

    const probe = await startEphemeralProbeServer();
    try {
        const targetUrl = `http://127.0.0.1:${probe.port}/audit`;
        const targets = [
            {
                targetOs: 'macos',
                preset: USABLE_DEVICE_PRESET_CATALOG.find((p) => p.os === 'macos' && p.hardwareConcurrency === 11)
                    || USABLE_DEVICE_PRESET_CATALOG.find((p) => p.os === 'macos'),
                languages: ['en-US', 'en'],
                timezone: 'America/Los_Angeles'
            },
            {
                targetOs: 'windows',
                preset: USABLE_DEVICE_PRESET_CATALOG.find((p) => p.os === 'windows' && p.webgl.unmaskedRenderer.includes('RTX'))
                    || USABLE_DEVICE_PRESET_CATALOG.find((p) => p.os === 'windows'),
                languages: ['en-US', 'en'],
                timezone: 'America/New_York'
            },
            {
                targetOs: 'linux',
                preset: USABLE_DEVICE_PRESET_CATALOG.find((p) => p.os === 'linux')
                    || USABLE_DEVICE_PRESET_CATALOG[USABLE_DEVICE_PRESET_CATALOG.length - 1],
                languages: ['en-US', 'en'],
                timezone: 'Europe/London'
            }
        ];

        const results = [];
        let negativeControl = null;
        for (const item of targets) {
            const syntheticProfile = {
                id: `live-diag-${item.targetOs}`,
                persona_id: item.preset.presetId,
                fp_seed: seedFromId(`live-diag-${item.targetOs}-${Date.now()}`),
                languages: item.languages,
                timezone: item.timezone,
                overrides: {}
            };
            const probeRun = await runSingleHeadlessCamoufoxProbe({
                probeId: syntheticProfile.id,
                preset: item.preset,
                profile: syntheticProfile,
                targetUrl,
                probePort: probe.port
            });
            if (item.targetOs === 'windows') {
                negativeControl = runAdversarialNegativeControlLive(probeRun.telemetry);
            }
            results.push({
                targetOs: item.targetOs,
                presetId: item.preset.presetId,
                deviceModel: item.preset.deviceModel,
                mode: 'live-camoufox-wire+dom',
                status: probeRun.status,
                passed: probeRun.passed,
                score: probeRun.score,
                wireInspectedRequests: probeRun.wireInspectedRequests,
                integrityValid: Boolean(probeRun.integrity?.valid),
                measured: probeRun.measured,
                auditReport: {
                    passed: probeRun.passed,
                    status: probeRun.status,
                    score: probeRun.score,
                    checks: probeRun.checks
                }
            });
        }

        // Cross-profile SKU isolation check across a 2nd distinct macOS SKU
        const secondMacPreset = USABLE_DEVICE_PRESET_CATALOG.find(
            (p) => p.os === 'macos' && p.presetId !== targets[0].preset.presetId && p.hardwareConcurrency !== targets[0].preset.hardwareConcurrency
        ) || USABLE_DEVICE_PRESET_CATALOG.find((p) => p.os === 'macos' && p.presetId !== targets[0].preset.presetId);
        let crossProfileIsolation = null;
        if (secondMacPreset) {
            const macB = await runSingleHeadlessCamoufoxProbe({
                probeId: 'live-diag-macos-sku-b',
                preset: secondMacPreset,
                profile: {
                    id: 'live-diag-macos-sku-b',
                    persona_id: secondMacPreset.presetId,
                    fp_seed: seedFromId('live-diag-macos-sku-b'),
                    languages: ['ja-JP', 'ja', 'en-US', 'en'],
                    timezone: 'Asia/Tokyo',
                    overrides: {}
                },
                targetUrl,
                probePort: probe.port
            });
            const macAMeasured = results[0].measured;
            const macBMeasured = macB.measured;
            const gpuIsolated = macAMeasured?.webglRenderer !== macBMeasured?.webglRenderer;
            const coresIsolated = macAMeasured?.hardwareConcurrency !== macBMeasured?.hardwareConcurrency;
            const tzIsolated = macAMeasured?.timeZone !== macBMeasured?.timeZone;
            const langIsolated = macAMeasured?.language !== macBMeasured?.language;
            crossProfileIsolation = {
                passed: Boolean(gpuIsolated && coresIsolated && tzIsolated && langIsolated),
                profileA: {
                    presetId: targets[0].preset.presetId,
                    gpu: macAMeasured?.webglRenderer,
                    cores: macAMeasured?.hardwareConcurrency,
                    canvasHash: macAMeasured?.canvasHash,
                    timeZone: macAMeasured?.timeZone,
                    language: macAMeasured?.language
                },
                profileB: {
                    presetId: secondMacPreset.presetId,
                    gpu: macBMeasured?.webglRenderer,
                    cores: macBMeasured?.hardwareConcurrency,
                    canvasHash: macBMeasured?.canvasHash,
                    timeZone: macBMeasured?.timeZone,
                    language: macBMeasured?.language
                }
            };
        }

        const overallPassed = results.every((r) => r.passed)
            && Boolean(negativeControl?.caughtAll !== false)
            && (crossProfileIsolation ? crossProfileIsolation.passed : true);
        const browser = detectLocalBrowser({ allowStockFallback: false });
        const report = {
            timestamp: new Date().toISOString(),
            mode: 'live-camoufox-wire+dom',
            engine: browser?.label || 'Camoufox C++',
            engineVersion: browser?.version || null,
            overallStatus: overallPassed ? 'passed' : 'failed',
            overallPassed,
            negativeControl,
            crossProfileIsolation,
            results
        };
        const summary = {
            timestamp: report.timestamp,
            mode: 'live-camoufox-wire+dom',
            report,
            stdout: `Live Camoufox C++ (${browser?.version || 'active'}) 21-check DOM + Pre-TLS Wire + Cross-SKU Isolation Audit: ${overallPassed ? 'PASS' : 'FAIL'}`,
            stderr: ''
        };
        state.lastCoherence = summary;
        appendAudit(state, 'suite.coherence_audit_live', null, {
            passed: overallPassed,
            engine: browser?.label,
            targets: results.map((r) => `${r.targetOs}:${r.score}`)
        });
        saveState(state);
        return summary;
    } finally {
        await probe.close();
    }
}

async function auditSingleSavedProfile(state, { profileId, targetUrl } = {}) {
    const profilesDir = getDefaultProfilesDirectory();
    const p = state.profiles.find((x) => x.id === profileId);
    if (!p) throw new RpcError(404, '未找到指定环境');
    if (getAllActiveProfileIds().has(p.id)) {
        throw new RpcError(409, `环境 #${p.serial_number || p.name} 正在运行中，请先关闭窗口再执行独立实机录制审计（或直接在 Pre-TLS 回放页查看已录制的实时会话流量）。`);
    }
    const preset = findPreset(p.persona_id);
    const linkedProxy = p.proxy_id ? state.proxies.find((px) => px.id === p.proxy_id) : null;
    const storageInfo = ensureProfileStorage(p.id, profilesDir);
    const probe = await startEphemeralProbeServer();
    let relay = null;
    try {
        if (linkedProxy && linkedProxy.host && linkedProxy.port && linkedProxy.kind !== 'wireguard') {
            relay = await startProfileNetworkEngine(`audit-${p.id}`, linkedProxy, state.networkDefaults);
            if (!relay) {
                throw new RpcError(502, `环境 #${p.serial_number || p.id} 代理中继连接失败，无法执行实机代理链路审计。`);
            }
        }
        const effectiveUrl = String(targetUrl || '').trim() || `http://127.0.0.1:${probe.port}/audit`;
        const run = await runSingleHeadlessCamoufoxProbe({
            probeId: p.id,
            preset,
            profile: p,
            proxy: linkedProxy,
            relay,
            targetUrl: effectiveUrl,
            probePort: probe.port,
            persistTrafficDir: storageInfo.trafficDir,
            persistNativeDir: storageInfo.nativeDir,
            ledgerPath: path.join(storageInfo.profileDir, 'fingerprint-ledger.json')
        });

        const comparisons = [
            {
                field: 'CPU 逻辑核心 (hardwareConcurrency)',
                expected: String(run.geoLocale.effectiveCores),
                observed: String(run.measured?.hardwareConcurrency ?? '—'),
                matched: run.measured?.hardwareConcurrency === run.geoLocale.effectiveCores
            },
            {
                field: 'WebGL 渲染器 (UNMASKED_RENDERER)',
                expected: run.geoLocale.effectiveGpuRenderer,
                observed: run.measured?.webglRenderer || '—',
                matched: run.measured?.webglRenderer === run.geoLocale.effectiveGpuRenderer
            },
            {
                field: '屏幕几何与缩放 (Screen / DPR)',
                expected: `${run.geoLocale.effectiveScreenW}×${run.geoLocale.effectiveScreenH} @${run.geoLocale.effectiveDpr}x`,
                observed: run.measured?.screen || '—',
                matched: Boolean(run.measured?.screen?.startsWith(`${run.geoLocale.effectiveScreenW}×${run.geoLocale.effectiveScreenH}`))
            },
            {
                field: 'Intl 时区 (TimeZone)',
                expected: run.geoLocale.timezone,
                observed: run.measured?.timeZone || '—',
                matched: run.measured?.timeZone === run.geoLocale.timezone
            },
            {
                field: '首选语言 (navigator.language)',
                expected: run.geoLocale.primaryLang,
                observed: run.measured?.language || '—',
                matched: String(run.measured?.language || '').toLowerCase().startsWith(run.geoLocale.primaryLang.split('-')[0].toLowerCase())
            },
            {
                field: '自动化隐藏 (navigator.webdriver)',
                expected: 'false (0 注入全局变量)',
                observed: `${String(run.measured?.webdriver)} (overrides=${run.measured?.ownNavigatorOverrides?.length || 0})`,
                matched: run.measured?.webdriver === false && (run.measured?.ownNavigatorOverrides?.length || 0) === 0
            }
        ];

        appendAudit(state, 'profile.live_audit', p.id, {
            serial: p.serial_number,
            passed: run.passed,
            score: run.score,
            wireRequests: run.wireInspectedRequests,
            integrityValid: Boolean(run.integrity?.valid)
        });
        saveState(state);

        return {
            profileId: p.id,
            serialNumber: p.serial_number ?? null,
            profileName: p.name,
            accountEmail: p.account_email || '',
            presetId: preset.presetId,
            deviceModel: preset.deviceModel,
            targetOs: preset.os,
            targetUrl: effectiveUrl,
            engine: run.browserEngine,
            passed: run.passed && comparisons.every((c) => c.matched),
            score: run.score,
            domScore: run.domScore,
            wireScore: run.wireScore,
            wireInspectedRequests: run.wireInspectedRequests,
            checks: run.checks,
            comparisons,
            measured: run.measured,
            integrity: run.integrity,
            ledgerResult: run.ledgerResult,
            auditedAt: new Date().toISOString()
        };
    } finally {
        try { relay?.close(); } catch {}
        await probe.close();
    }
}

function listStudioTrafficProfiles(state) {
    const profilesDir = getDefaultProfilesDirectory();
    const rawList = listTrafficProfiles(profilesDir, { includeLocalPaths: true });
    const activeSet = getAllActiveProfileIds();
    return rawList.map((item) => {
        const match = state.profiles.find((p) => p.id === item.profileId);
        const liveEntry = activeLocalProcesses.get(item.profileId);
        return {
            ...item,
            serialNumber: match?.serial_number ?? null,
            profileName: match?.name || item.profileId,
            accountEmail: match?.account_email || '',
            running: activeSet.has(item.profileId),
            recordingActive: Boolean(liveEntry?.recordingActive)
        };
    });
}

async function flushLiveRecorderIfActive(profileId) {
    const live = activeLocalProcesses.get(profileId);
    if (live?.trafficRecorder) {
        try {
            await live.trafficRecorder.flushSummary({ nativeLogsClosed: false });
        } catch {
            // ignore live flush error
        }
    }
}

async function queryStudioTraffic(state, params = {}) {
    const profilesDir = getDefaultProfilesDirectory();
    const profileId = String(params.profileId || '').trim();
    if (!profileId) throw new RpcError(400, '请选择要审计回放的环境 ID');
    await flushLiveRecorderIfActive(profileId);

    const baseOpts = {
        profilesDir,
        profile: profileId,
        step: params.step ? String(params.step).trim() : undefined,
        trigger: params.trigger ? String(params.trigger).trim() : undefined,
        domain: params.domain ? String(params.domain).trim() : undefined,
        status: params.status !== undefined && params.status !== '' ? String(params.status).trim() : undefined,
        platform: params.platform ? String(params.platform).trim() : undefined,
        recordBodies: true,
        trustedLocal: true,
        includeLocalPaths: true
    };

    const queryRes = queryProfileTraffic(baseOpts);
    let integrity = null;
    try {
        integrity = queryProfileTraffic({
            profilesDir,
            profile: profileId,
            verifyIntegrity: true,
            trustedLocal: true,
            includeLocalPaths: true
        });
    } catch (err) {
        integrity = { valid: false, errors: [err?.message || String(err)] };
    }

    let cookieReport = null;
    try {
        cookieReport = queryProfileTraffic({
            profilesDir,
            profile: profileId,
            cookies: true,
            trustedLocal: true,
            includeLocalPaths: true
        });
    } catch {
        cookieReport = null;
    }

    const match = state.profiles.find((p) => p.id === profileId);
    const liveEntry = activeLocalProcesses.get(profileId);
    return {
        profileId,
        serialNumber: match?.serial_number ?? null,
        profileName: match?.name || profileId,
        accountEmail: match?.account_email || '',
        recordingActive: Boolean(liveEntry?.recordingActive),
        integrity,
        cookies: cookieReport?.cookies || [],
        antiBotTokenCount: cookieReport?.antiBotTokenCount ?? 0,
        totals: queryRes.totals,
        artifacts: queryRes.artifacts,
        byActionStep: queryRes.byActionStep || {},
        byTriggerAction: queryRes.byTriggerAction || {},
        byDomain: queryRes.byDomain || {},
        platformSignatures: queryRes.platformSignatures || { totalDetected: 0, byPlatform: {}, signatures: [] },
        neckoMozLog: queryRes.neckoMozLog || null,
        anomalies: queryRes.anomalies || [],
        transactions: queryRes.transactions || [],
        eventsCount: queryRes.eventsCount ?? 0
    };
}

async function reconstructStudioWireDump(params = {}) {
    const profilesDir = getDefaultProfilesDirectory();
    const profileId = String(params.profileId || '').trim();
    const correlationId = String(params.correlationId || '').trim();
    if (!profileId || !correlationId) {
        throw new RpcError(400, '需要提供 profileId 与 correlationId 以重建 Pre-TLS Wire 报文回放');
    }
    await flushLiveRecorderIfActive(profileId);
    return queryProfileTraffic({
        profilesDir,
        profile: profileId,
        correlation: correlationId,
        recordBodies: true,
        trustedLocal: true,
        includeLocalPaths: true
    });
}

async function exportStudioTrafficHar(params = {}) {
    const profilesDir = getDefaultProfilesDirectory();
    const profileId = String(params.profileId || '').trim();
    if (!profileId) throw new RpcError(400, '需要提供 profileId');
    await flushLiveRecorderIfActive(profileId);
    const profileDir = resolveSafeProfilePath(profilesDir, profileId);
    const outPath = path.join(profileDir, 'traffic', `replay-export-${Date.now()}.har`);
    return queryProfileTraffic({
        profilesDir,
        profile: profileId,
        domain: params.domain ? String(params.domain).trim() : undefined,
        status: params.status !== undefined && params.status !== '' ? String(params.status).trim() : undefined,
        exportHar: outPath,
        recordBodies: true,
        trustedLocal: true,
        includeLocalPaths: true
    });
}

function collectTrafficSummary() {
    const profilesDir = getDefaultProfilesDirectory();
    const events = [];
    let totalBytes = 0;
    let profileCaptures = 0;

    try {
        const entries = fs.readdirSync(profilesDir, { withFileTypes: true });
        for (const entry of entries) {
            if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
            const trafficFile = path.join(profilesDir, entry.name, 'traffic', 'traffic.ndjson');
            if (!fs.existsSync(trafficFile)) continue;
            profileCaptures++;
            const lines = fs.readFileSync(trafficFile, 'utf8').split(/\r?\n/).filter(Boolean);
            for (const line of lines.slice(-200)) {
                try {
                    const ev = JSON.parse(line);
                    const bytes = Number(ev.bodyBytes || ev.responseBytes || ev.requestBytes || ev.size || 0);
                    totalBytes += bytes;
                    events.push({
                        profileId: entry.name,
                        timestamp: ev.timestamp || ev.ts || new Date().toISOString(),
                        type: ev.type || ev.eventType || 'http',
                        method: ev.method || 'GET',
                        status: ev.status ?? ev.statusCode ?? null,
                        host: ev.host || ev.hostname || (ev.url ? safeHost(ev.url) : '—'),
                        step: ev.step || ev.registrationStep || 'browse',
                        bytes
                    });
                } catch {
                    // skip unparseable lines
                }
            }
        }
    } catch {
        // profilesDir absent
    }

    events.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));

    // Build 16 sparkline buckets (Donut-style bandwidth/activity mini chart)
    const now = Date.now();
    const bucketCount = 16;
    const buckets = Array.from({ length: bucketCount }, (_, i) => ({
        time: now - (bucketCount - 1 - i) * 60_000,
        bandwidth: 0,
        requests: 0
    }));

    for (const ev of events) {
        const ts = Date.parse(ev.timestamp);
        if (!Number.isFinite(ts)) continue;
        const minsAgo = Math.floor((now - ts) / 60_000);
        const idx = bucketCount - 1 - minsAgo;
        if (idx >= 0 && idx < bucketCount) {
            buckets[idx].bandwidth += Math.max(1, ev.bytes || 256);
            buckets[idx].requests += 1;
        }
    }

    return {
        profilesDir,
        profileCaptures,
        totalEvents: events.length,
        totalBytes,
        buckets,
        recentEvents: events.slice(0, 80)
    };
}

function safeHost(rawUrl) {
    try {
        return new URL(rawUrl).host;
    } catch {
        return String(rawUrl).slice(0, 64);
    }
}

function readResultsHistory() {
    const dir = getStateDirectory();
    let results = [];
    let summary = null;
    try {
        const raw = readPrivateFile(path.join(dir, 'results.json'), 'utf8', { requireOwner: true });
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) results = parsed.slice(-100).reverse();
    } catch {
        // results.json absent
    }
    try {
        const raw = readPrivateFile(path.join(dir, 'summary.json'), 'utf8', { requireOwner: true });
        summary = JSON.parse(raw);
    } catch {
        // summary.json absent
    }
    return { stateDir: dir, results, summary };
}

function readEditableEnv() {
    const file = envFilePath();
    const values = {};
    let exists = false;
    try {
        const raw = readPrivateFile(file, 'utf8', { requireOwner: true });
        exists = true;
        for (const line of raw.split(/\r?\n/)) {
            const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
            if (!m) continue;
            const key = m[1];
            if (EDITABLE_ENV_KEYS.includes(key)) {
                values[key] = m[2].replace(/^['"]|['"]$/g, '');
            }
        }
    } catch {
        // .env absent yet
    }
    return { path: file, exists, keys: EDITABLE_ENV_KEYS, values };
}

function writeEditableEnv(updates) {
    const file = envFilePath();
    const existingLines = [];
    const seen = new Set();
    try {
        const raw = readPrivateFile(file, 'utf8', { requireOwner: true });
        for (const line of raw.split(/\r?\n/)) {
            const m = line.match(/^\s*([A-Z0-9_]+)\s*=/);
            if (m && EDITABLE_ENV_KEYS.includes(m[1]) && Object.prototype.hasOwnProperty.call(updates, m[1])) {
                const val = String(updates[m[1]] ?? '').replace(/[\r\n]/g, '');
                if (val !== '') existingLines.push(`${m[1]}=${val}`);
                seen.add(m[1]);
            } else {
                existingLines.push(line);
            }
        }
    } catch {
        existingLines.push('# Managed by Camoufox Studio UI');
    }
    for (const key of EDITABLE_ENV_KEYS) {
        if (seen.has(key) || !Object.prototype.hasOwnProperty.call(updates, key)) continue;
        const val = String(updates[key] ?? '').replace(/[\r\n]/g, '');
        if (val !== '') existingLines.push(`${key}=${val}`);
    }
    writePrivateFile(file, existingLines.join('\n').replace(/\n+$/, '') + '\n', { requireOwner: true });
    return readEditableEnv();
}

function auditAdsPowerDirectory(cacheDir) {
    if (!cacheDir || typeof cacheDir !== 'string' || !cacheDir.trim()) {
        throw new RpcError(400, 'Please provide an AdsPower cache directory path.');
    }
    const resolved = path.resolve(cacheDir.trim());
    let entries;
    try {
        entries = listCaptureDirectory(resolved).filter((e) => e.isDirectory());
    } catch (error) {
        const hint = error?.code === 'ELOOP'
            ? ' (path contains a symlink; please pass the canonical real path)'
            : '';
        throw new RpcError(400, `Cannot read AdsPower cache directory: ${error.message}${hint}`);
    }
    const audited = [];
    for (const entry of entries) {
        const report = auditAdsPowerProfileDir(path.join(resolved, entry.name));
        if (report) audited.push(report);
    }
    return {
        cacheDir: resolved,
        totalScanned: entries.length,
        totalDecoded: audited.length,
        passedCount: audited.filter((r) => r.passed).length,
        failedCount: audited.filter((r) => r.status === 'failed').length,
        profiles: audited
    };
}

// ---------------------------------------------------------------------------
// RPC Dispatcher (Fury desktop contract + Camoufox Suite Lab extensions)
// ---------------------------------------------------------------------------

async function handleRpc(method, params = {}) {
    const state = loadState();
    const activeSet = getAllActiveProfileIds();
    const stateDir = ensureStateDirectory();
    const profilesDir = getDefaultProfilesDirectory();
    const camoufoxReady = isCamoufoxModuleResolvable();
    const localBrowser = detectLocalBrowser();

    switch (method) {
        // ---- Shell & status ------------------------------------------------
        case 'shell_state':
            return {
                server_url: null,
                machine_name: os.hostname(),
                signed_in: false,
                native: true,
                mode: 'local',
                agent_ready: true,
                core_ready: true,
                core_problem: null,
                core_outdated: null,
                core_stale: null,
                log_file: path.join(stateDir, 'logs'),
                core_download: null,
                remember_org_key: false,
                version: '1.0.0 (Camoufox Studio HTTP)',
                org_key_ready: false,
                last_email: null,
                last_server: null,
                awaiting_key: false
            };

        case 'check_update':
            return {
                current: '1.0.0',
                latest: null,
                url: null,
                download: null,
                notes: null,
                status: 'current',
                message: 'Local Camoufox Studio HTTP build is up to date.'
            };

        case 'vault_status':
            return { available: true, unreadable: [] };

        case 'open_url':
            return { ok: true, url: params.url || '' };

        // ---- Projects / Folders --------------------------------------------
        case 'projects':
            return state.projects.map((proj) => ({
                origin: 'local',
                id: proj.id,
                name: proj.name,
                profile_count: state.profiles.filter((p) => p.project_id === proj.id).length
            }));

        case 'create_project': {
            const name = String(params.name || '').trim();
            if (!name) throw new RpcError(400, 'Project name is required.');
            const id = crypto.randomUUID();
            state.projects.push({ id, name, origin: 'local' });
            appendAudit(state, 'project.create', id, { name });
            saveState(state);
            return { id };
        }

        case 'rename_project': {
            const proj = state.projects.find((x) => x.id === params.id);
            if (!proj) throw new RpcError(404, 'Project not found.');
            proj.name = String(params.name || '').trim() || proj.name;
            appendAudit(state, 'project.rename', proj.id, { name: proj.name });
            saveState(state);
            return { ok: true };
        }

        case 'delete_project': {
            state.projects = state.projects.filter((x) => x.id !== params.id);
            for (const p of state.profiles) {
                if (p.project_id === params.id) p.project_id = null;
            }
            appendAudit(state, 'project.delete', params.id);
            saveState(state);
            return { ok: true };
        }

        // ---- Profiles ------------------------------------------------------
        case 'profiles': {
            const list = params.projectId
                ? state.profiles.filter((p) => p.project_id === params.projectId)
                : state.profiles;
            return list.map((p) => serializeProfile(state, p, activeSet));
        }

        case 'shared_with_me':
            return [];

        case 'personas':
            return getPersonasList();

        case 'kept_personas':
            return [];

        case 'preview':
            return buildPreview(params.spec || {});

        case 'save_profile': {
            const incoming = params.profile || {};
            const isEdit = Boolean(incoming.id && state.profiles.some((p) => p.id === incoming.id));
            const preset = findPreset(incoming.persona_id);
            const id = isEdit ? incoming.id : `camoufox-${crypto.randomUUID().slice(0, 12)}`;
            const existing = isEdit ? state.profiles.find((p) => p.id === id) : null;
            let resolvedProjectId = incoming.project_id ?? existing?.project_id ?? null;
            const newProjectName = String(incoming.project_name_new || '').trim();
            if (newProjectName) {
                let proj = state.projects.find((x) => x.name.toLowerCase() === newProjectName.toLowerCase());
                if (!proj) {
                    proj = { id: crypto.randomUUID(), name: newProjectName, origin: 'local' };
                    state.projects.push(proj);
                    appendAudit(state, 'project.create', proj.id, { name: proj.name });
                }
                resolvedProjectId = proj.id;
            }
            const accountEmail = incoming.account_email !== undefined
                ? String(incoming.account_email || '').trim()
                : (existing?.account_email ?? '');
            const accountPassword = incoming.account_password !== undefined
                ? String(incoming.account_password || '')
                : (existing?.account_password ?? '');
            const accountTotp = incoming.account_totp !== undefined
                ? String(incoming.account_totp || '').replace(/\s+/g, '').trim()
                : (existing?.account_totp ?? '');
            const typedName = String(incoming.name || '').trim();
            const existingMaxSerial = state.profiles.reduce(
                (max, x) => Math.max(max, Number.isInteger(x.serial_number) ? x.serial_number : 0),
                0
            );
            const record = {
                id,
                origin: 'local',
                shared_with: 0,
                project_id: resolvedProjectId,
                serial_number: existing?.serial_number || (Number.isInteger(incoming.serial_number) && incoming.serial_number > 0 ? incoming.serial_number : existingMaxSerial + 1),
                name: (typedName && typedName !== 'Untitled' ? typedName : '') || accountEmail || typedName || preset.deviceModel,
                account_email: accountEmail,
                account_password: accountPassword,
                account_totp: accountTotp,
                notes: incoming.notes ?? existing?.notes ?? '',
                start_urls: Array.isArray(incoming.start_urls) ? incoming.start_urls : (existing?.start_urls ?? []),
                status: incoming.status ?? existing?.status ?? '',
                tags: Array.isArray(incoming.tags) ? incoming.tags : (existing?.tags ?? []),
                persona_id: preset.presetId,
                fp_seed: Number(incoming.fp_seed) || existing?.fp_seed || seedFromId(id),
                proxy_id: incoming.proxy_id ?? null,
                allow_no_proxy: incoming.proxy_id ? Boolean(incoming.allow_no_proxy) : true,
                timezone: incoming.timezone ?? null,
                languages: Array.isArray(incoming.languages) && incoming.languages.length ? incoming.languages : null,
                overrides: incoming.overrides ?? existing?.overrides ?? {},
                blocklists: Array.isArray(incoming.blocklists) ? incoming.blocklists : (existing?.blocklists ?? []),
                last_opened_at: existing?.last_opened_at ?? null
            };

            if (!isEdit) {
                // Persist real isolated Camoufox profile metadata on disk
                const linkedProxy = record.proxy_id
                    ? state.proxies.find((px) => px.id === record.proxy_id)
                    : null;
                const camoufoxProxy = linkedProxy && linkedProxy.kind !== 'wireguard'
                    ? {
                        server: `${linkedProxy.kind}://${linkedProxy.host}:${linkedProxy.port}`,
                        username: linkedProxy.username || undefined,
                        password: linkedProxy.password || undefined
                    }
                    : null;
                try {
                    await createCamoufoxProfile(record.name, camoufoxProxy, {
                        profileId: id,
                        profilesDir,
                        os: preset.os,
                        presetId: preset.presetId,
                        locale: record.languages?.[0],
                        timezoneId: record.timezone || undefined
                    });
                } catch (err) {
                    if (err?.code !== 'EEXIST') {
                        throw new RpcError(400, `Camoufox profile creation failed: ${err.message}`);
                    }
                }
                state.profiles.unshift(record);
                appendAudit(state, 'profile.create', id, { name: record.name, presetId: preset.presetId });
            } else {
                Object.assign(existing, record);
                appendAudit(state, 'profile.update', id, { name: record.name, presetId: preset.presetId });
            }
            // Keep credential vault synced when account email/password/2FA is provided
            if (record.account_email || record.account_totp) {
                const creds = state.credentials[id] || [];
                const idxCred = creds.findIndex((c) => c.site === 'accounts.google.com' || c.username === record.account_email);
                const credRec = {
                    id: idxCred >= 0 ? creds[idxCred].id : crypto.randomUUID(),
                    profile_id: id,
                    site: idxCred >= 0 ? creds[idxCred].site : 'accounts.google.com',
                    label: idxCred >= 0 ? creds[idxCred].label : 'Primary Account (2FA)',
                    username: record.account_email || null,
                    password: record.account_password || null,
                    totp: record.account_totp || null,
                    notes: idxCred >= 0 ? (creds[idxCred].notes || '') : ''
                };
                if (idxCred >= 0) creds[idxCred] = credRec;
                else creds.unshift(credRec);
                state.credentials[id] = creds;
            }
            saveState(state);
            return { id };
        }

        case 'create_profiles': {
            const count = Math.min(100, Math.max(1, Number(params.count) || 1));
            const pattern = String(params.namePattern || 'Profile {n}');
            const tpl = params.template || {};
            const created = [];
            const failed = [];
            for (let i = 1; i <= count; i++) {
                try {
                    const preset = USABLE_DEVICE_PRESET_CATALOG[(i - 1) % USABLE_DEVICE_PRESET_CATALOG.length];
                    const name = pattern.includes('{n}') ? pattern.replace(/\{n\}/g, String(i)) : `${pattern} ${i}`;
                    const res = await handleRpc('save_profile', {
                        profile: {
                            ...tpl,
                            id: undefined,
                            name,
                            persona_id: tpl.persona_id || preset.presetId,
                            fp_seed: crypto.randomInt(1, 0x7fffffff)
                        }
                    });
                    created.push(res);
                } catch (err) {
                    failed.push({ n: i, error: err.message });
                }
            }
            return { created, failed };
        }

        case 'clone_profile': {
            const src = state.profiles.find((p) => p.id === params.id);
            if (!src) throw new RpcError(404, 'Profile not found.');
            const count = Math.min(50, Math.max(1, Number(params.count) || 1));
            const created = [];
            for (let i = 1; i <= count; i++) {
                const rawName = params.name ? String(params.name) : `${src.name} (copy ${i})`;
                const name = rawName.includes('{n}')
                    ? rawName.replace(/\{n\}/g, String(i))
                    : (params.name && count > 1 ? `${rawName} ${i}` : rawName);
                const res = await handleRpc('save_profile', {
                    profile: { ...src, id: undefined, name, fp_seed: crypto.randomInt(1, 0x7fffffff) }
                });
                created.push(res);
            }
            return { created, failed: [] };
        }

        case 'delete_profile': {
            const idx = state.profiles.findIndex((p) => p.id === params.id);
            if (idx === -1) throw new RpcError(404, 'Profile not found.');
            if (activeSet.has(params.id)) {
                throw new RpcError(409, 'Close the running profile before deleting it.');
            }
            const [removed] = state.profiles.splice(idx, 1);
            removed.deleted_at = new Date().toISOString();
            state.trash.unshift(removed);
            appendAudit(state, 'profile.trash', removed.id, { name: removed.name });
            saveState(state);
            return { ok: true };
        }

        case 'trash':
            return state.trash.map((p) => serializeProfile(state, p, activeSet));

        case 'restore_profile': {
            const idx = state.trash.findIndex((p) => p.id === params.id);
            if (idx === -1) throw new RpcError(404, 'Profile not found in trash.');
            const [restored] = state.trash.splice(idx, 1);
            delete restored.deleted_at;
            state.profiles.unshift(restored);
            appendAudit(state, 'profile.restore', restored.id, { name: restored.name });
            saveState(state);
            return { ok: true };
        }

        case 'purge_profile': {
            const idx = state.trash.findIndex((p) => p.id === params.id);
            if (idx === -1) throw new RpcError(404, 'Profile not found in trash.');
            const [purged] = state.trash.splice(idx, 1);
            try {
                await deleteCamoufoxProfile(purged.id, { profilesDir });
            } catch {
                // Disk dir may already be absent
            }
            appendAudit(state, 'profile.purge', purged.id, { name: purged.name });
            saveState(state);
            return { ok: true };
        }

        case 'move_profiles': {
            const ids = new Set(Array.isArray(params.ids) ? params.ids : []);
            let moved = 0;
            for (const p of state.profiles) {
                if (ids.has(p.id)) {
                    p.project_id = params.projectId || null;
                    moved++;
                }
            }
            saveState(state);
            return { moved };
        }

        case 'reseed_profile': {
            const p = state.profiles.find((x) => x.id === params.id);
            if (!p) throw new RpcError(404, 'Profile not found.');
            if (activeSet.has(p.id)) throw new RpcError(409, 'Close profile before reseeding.');
            p.fp_seed = crypto.randomInt(1, 0x7fffffff);
            appendAudit(state, 'profile.reseed', p.id, { fp_seed: p.fp_seed });
            saveState(state);
            return { id: p.id, fp_seed: p.fp_seed };
        }

        case 'launch': {
            const p = state.profiles.find((x) => x.id === params.profileId);
            if (!p) throw new RpcError(404, 'Profile not found.');
            if (activeSet.has(p.id)) {
                const running = activeLocalProcesses.get(p.id);
                return { launched: true, pid: running?.pid, renewed: true, recording: Boolean(running?.recordingActive) };
            }
            const preset = findPreset(p.persona_id);
            const linkedProxy = p.proxy_id ? state.proxies.find((px) => px.id === p.proxy_id) : null;
            const projectObj = p.project_id ? state.projects.find((x) => x.id === p.project_id) : null;
            const launched = await launchLocalBrowserWindow(
                p,
                preset,
                linkedProxy,
                profilesDir,
                state.networkDefaults,
                projectObj?.name || '',
                { recordTraffic: params.recordTraffic }
            );
            p.last_opened_at = new Date().toISOString();
            appendAudit(state, 'profile.launch', p.id, {
                name: p.name,
                presetId: preset.presetId,
                engine: launched.engine,
                recording: launched.recording,
                networkEngine: launched.networkEngine,
                udpProxied: launched.udpProxied,
                pid: launched.pid
            });
            saveState(state);
            return {
                launched: true,
                pid: launched.pid,
                engine: launched.engine,
                recording: launched.recording,
                network_engine: launched.networkEngine,
                relay_port: launched.relayPort,
                dns_stub_port: launched.dnsStubPort,
                tcp2udp_port: launched.tcp2udpPort,
                udp_proxied: launched.udpProxied
            };
        }

        case 'launch_many': {
            const ids = Array.isArray(params.ids) ? params.ids : [];
            const launched = [];
            const failed = [];
            const concurrency = 4;
            for (let i = 0; i < ids.length; i += concurrency) {
                const batch = ids.slice(i, i + concurrency);
                const results = await Promise.allSettled(
                    batch.map(async (id) => {
                        const p = state.profiles.find((x) => x.id === id);
                        if (!p) throw new Error('Profile not found');
                        if (activeSet.has(p.id)) return { id: p.id, renewed: true };
                        const preset = findPreset(p.persona_id);
                        const linkedProxy = p.proxy_id ? state.proxies.find((px) => px.id === p.proxy_id) : null;
                        const projectObj = p.project_id ? state.projects.find((x) => x.id === p.project_id) : null;
                        await launchLocalBrowserWindow(p, preset, linkedProxy, profilesDir, state.networkDefaults, projectObj?.name || '');
                        p.last_opened_at = new Date().toISOString();
                        return { id: p.id };
                    })
                );
                results.forEach((r, idx) => {
                    const id = batch[idx];
                    if (r.status === 'fulfilled') launched.push(id);
                    else failed.push({ id, error: r.reason?.message || 'Launch failed' });
                });
            }
            if (launched.length > 0) {
                appendAudit(state, 'profile.launch_many', null, { count: launched.length, failed: failed.length });
                saveState(state);
            }
            return { launched, failed };
        }

        case 'stop': {
            const p = state.profiles.find((x) => x.id === params.profileId);
            const liveMap = scanRunningProfilePids(true);
            if (activeLocalProcesses.has(params.profileId) || liveMap.has(params.profileId)) {
                await stopLocalBrowserWindow(params.profileId);
            } else if (getActiveProfileIds().includes(params.profileId)) {
                await stopCamoufoxProfile(params.profileId, { profilesDir });
            }
            if (p) appendAudit(state, 'profile.stop', p.id, { name: p.name });
            saveState(state);
            return { ok: true };
        }

        case 'stop_many': {
            const ids = Array.isArray(params.ids) ? params.ids : [];
            const sdkActive = new Set(getActiveProfileIds());
            const localIds = [];
            const sdkIds = [];
            for (const id of ids) {
                if (sdkActive.has(id)) sdkIds.push(id);
                else localIds.push(id);
            }
            const res = await stopManyLocalBrowserWindows(localIds);
            for (const id of sdkIds) {
                try { await stopCamoufoxProfile(id, { profilesDir }); } catch { /* ignore */ }
            }
            appendAudit(state, 'profile.stop_many', null, { stopped: res.stopped + sdkIds.length, total: ids.length });
            saveState(state);
            return { ok: true, stopped: res.stopped + sdkIds.length, total: ids.length };
        }

        case 'autofill_profile': {
            const p = state.profiles.find((x) => x.id === params.profileId);
            if (!p) throw new RpcError(404, 'Profile not found.');
            const field = String(params.field || 'email');
            let value = '';
            if (field === 'email') value = String(p.account_email || '').trim();
            else if (field === 'password') value = String(p.account_password || '');
            else if (field === 'totp') {
                const secret = String(p.account_totp || '').trim();
                if (!secret) throw new RpcError(400, '该环境未配置 2FA 密钥');
                value = generateTotp(secret, 0);
            } else {
                throw new RpcError(400, `Unsupported autofill field: ${field}`);
            }
            if (!value) throw new RpcError(400, `该环境未填写对应的 ${field} 字段`);

            const liveMap = scanRunningProfilePids(true);
            const entry = activeLocalProcesses.get(p.id);
            const targetPid = entry?.pid || entry?.child?.pid || liveMap.get(p.id) || null;
            if (!targetPid || !isPidAlive(targetPid)) {
                throw new RpcError(409, '请先打开该环境的浏览器窗口后再使用自动输入');
            }

            if (process.platform === 'darwin') {
                const pyPaste = `
import AppKit, subprocess, sys, time
pid = int(sys.argv[1])
text = sys.stdin.read()
pb = AppKit.NSPasteboard.generalPasteboard()
prev = pb.stringForType_(AppKit.NSPasteboardTypeString)
pb.clearContents()
pb.setString_forType_(text, AppKit.NSPasteboardTypeString)
app = AppKit.NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
if app:
    app.activateWithOptions_(3)
time.sleep(0.18)
subprocess.run(["osascript", "-e", 'tell application "System Events" to keystroke "v" using command down'], check=False)
time.sleep(0.35)
if prev is not None and pb.stringForType_(AppKit.NSPasteboardTypeString) == text:
    pb.clearContents()
    pb.setString_forType_(prev, AppKit.NSPasteboardTypeString)
`;
                const pyBin = fs.existsSync('/opt/homebrew/bin/python3') ? '/opt/homebrew/bin/python3' : '/usr/bin/python3';
                await new Promise((resolve, reject) => {
                    const proc = spawn(pyBin, ['-c', pyPaste, String(targetPid)], { stdio: ['pipe', 'ignore', 'pipe'] });
                    proc.on('error', reject);
                    proc.on('close', () => resolve());
                    proc.stdin.end(value);
                });
            }
            return { ok: true, field };
        }

        case 'import_accounts_batch': {
            const rawItems = Array.isArray(params.items) ? params.items : [];
            if (rawItems.length === 0) throw new RpcError(400, '没有可导入的账号条目');

            let targetProjectId = params.projectId || null;
            const newProjectName = String(params.projectNameNew || '').trim();
            if (newProjectName) {
                let proj = state.projects.find((x) => x.name.toLowerCase() === newProjectName.toLowerCase());
                if (!proj) {
                    proj = { id: crypto.randomUUID(), name: newProjectName, origin: 'local' };
                    state.projects.push(proj);
                    appendAudit(state, 'project.create', proj.id, { name: proj.name });
                    saveState(state);
                }
                targetProjectId = proj.id;
            }

            const defaultStartUrls = Array.isArray(params.startUrls) && params.startUrls.length > 0
                ? params.startUrls
                : ['https://accounts.google.com'];
            const autoGeo = params.autoGeo !== false;

            const COUNTRY_LANG_MAP = {
                US: ['en-US', 'en'],
                CA: ['en-CA', 'en-US', 'en'],
                GB: ['en-GB', 'en-US', 'en'],
                AU: ['en-AU', 'en-US', 'en'],
                JP: ['ja-JP', 'ja', 'en-US', 'en'],
                KR: ['ko-KR', 'ko', 'en-US', 'en'],
                DE: ['de-DE', 'de', 'en-US', 'en'],
                FR: ['fr-FR', 'fr', 'en-US', 'en'],
                ES: ['es-ES', 'es', 'en-US', 'en'],
                IT: ['it-IT', 'it', 'en-US', 'en'],
                NL: ['nl-NL', 'nl', 'en-US', 'en'],
                SG: ['en-SG', 'en-US', 'en'],
                TW: ['zh-TW', 'zh', 'en-US', 'en'],
                HK: ['zh-HK', 'zh', 'en-US', 'en']
            };

            const probeProxyGeo = async (parsedProxy) => {
                const runCurl = (proto) => new Promise((resolve) => {
                    const args = proto === 'socks5'
                        ? ['-sS', '--max-time', '7', '--socks5-hostname', `${parsedProxy.host}:${parsedProxy.port}`]
                        : ['-sS', '--max-time', '7', '-x', `http://${parsedProxy.host}:${parsedProxy.port}`];
                    if (parsedProxy.username) args.push('--proxy-user', `${parsedProxy.username}:${parsedProxy.password || ''}`);
                    args.push('http://ip-api.com/json/?fields=status,countryCode,city,timezone,query');
                    const c = spawn('curl', args);
                    let out = '';
                    c.stdout.on('data', (d) => { out += d; });
                    c.on('close', (code) => {
                        if (code === 0 && out.trim().startsWith('{')) {
                            try {
                                const j = JSON.parse(out);
                                if (j.status === 'success') {
                                    resolve({ kind: proto, country: j.countryCode || null, city: j.city || null, timezone: j.timezone || null, ip: j.query || null });
                                    return;
                                }
                            } catch { /* ignore */ }
                        }
                        resolve(null);
                    });
                    c.on('error', () => resolve(null));
                });
                const firstKind = parsedProxy.kind === 'http' || parsedProxy.kind === 'https' ? 'http' : 'socks5';
                const first = await runCurl(firstKind);
                if (first) return first;
                return await runCurl(firstKind === 'socks5' ? 'http' : 'socks5');
            };

            const macPresets = USABLE_DEVICE_PRESET_CATALOG.filter((p) => p.os === 'macos');
            const pool = macPresets.length ? macPresets : USABLE_DEVICE_PRESET_CATALOG;
            const usedPresetIds = new Set(state.profiles.map((x) => x.persona_id));

            const created = [];
            const failed = [];

            for (let i = 0; i < rawItems.length; i++) {
                const item = rawItems[i] || {};
                const email = String(item.email || '').trim();
                const password = String(item.password || '');
                const totp = String(item.totp || '').replace(/\s+/g, '').trim();
                const proxyLine = String(item.proxyLine || '').trim();
                if (!email && !password && !totp) continue;

                try {
                    let useProxyId = params.defaultProxyId || null;
                    let geo = null;

                    if (proxyLine) {
                        const parsed = parseSingleProxyLine(proxyLine);
                        if (parsed) {
                            if (autoGeo) {
                                geo = await probeProxyGeo(parsed);
                            }
                            const finalKind = geo?.kind || parsed.kind || 'socks5';
                            const freshState = loadState();
                            const dupPx = freshState.proxies.find((x) => x.host === parsed.host && Number(x.port) === Number(parsed.port));
                            const savedPx = await handleRpc('save_proxy', {
                                proxy: {
                                    id: dupPx?.id,
                                    name: geo?.country ? `${geo.country}${geo.city ? ` ${geo.city}` : ''} · ${parsed.host}` : `${parsed.host}:${parsed.port}`,
                                    kind: finalKind,
                                    host: parsed.host,
                                    port: parsed.port,
                                    username: parsed.username,
                                    password: parsed.password,
                                    last_country: geo?.country || null,
                                    last_ip: geo?.ip || parsed.host,
                                    last_timezone: geo?.timezone || null
                                }
                            });
                            useProxyId = savedPx.id;
                        }
                    } else if (useProxyId) {
                        const pxObj = loadState().proxies.find((x) => x.id === useProxyId);
                        if (pxObj) {
                            geo = {
                                country: pxObj.last_country || null,
                                timezone: pxObj.last_timezone || null
                            };
                        }
                    }

                    const unused = pool.filter((x) => !usedPresetIds.has(x.presetId));
                    const chosen = (unused.length ? unused : pool)[i % (unused.length ? unused.length : pool.length)];
                    usedPresetIds.add(chosen.presetId);

                    const countryCode = geo?.country ? String(geo.country).toUpperCase() : null;
                    const langs = (countryCode && COUNTRY_LANG_MAP[countryCode]) || ['en-US', 'en'];
                    const tz = geo?.timezone || null;
                    const tags = ['imported'];
                    if (countryCode) tags.push(countryCode.toLowerCase());
                    if (totp) tags.push('2fa');

                    const savedProf = await handleRpc('save_profile', {
                        profile: {
                            name: String(item.name || '').trim() || email || `Account ${i + 1}`,
                            account_email: email,
                            account_password: password,
                            account_totp: totp,
                            project_id: targetProjectId,
                            persona_id: chosen.presetId,
                            proxy_id: useProxyId,
                            allow_no_proxy: !useProxyId,
                            timezone: tz,
                            languages: langs,
                            overrides: { ui_locale: langs[0] },
                            start_urls: defaultStartUrls,
                            tags,
                            notes: [countryCode ? `${countryCode}${geo?.city ? ` ${geo.city}` : ''}` : null, tz, totp ? '含 2FA 密钥' : null].filter(Boolean).join(' · ')
                        }
                    });
                    created.push({ id: savedProf.id, email, country: countryCode, timezone: tz, hasTotp: Boolean(totp) });
                } catch (err) {
                    failed.push({ index: i + 1, email, error: err?.message || 'Import failed' });
                }
            }
            return { created, failed };
        }

        case 'profile_usage': {
            const dir = resolveSafeProfilePath(profilesDir, params.id);
            let total = 0;
            let files = 0;
            const walk = (target) => {
                if (!fs.existsSync(target)) return;
                for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
                    const full = path.join(target, entry.name);
                    if (entry.isDirectory()) walk(full);
                    else {
                        files++;
                        total += fs.statSync(full).size;
                    }
                }
            };
            try { walk(dir); } catch { /* ignore */ }
            return { total, cache: 0, keep: total, files };
        }

        case 'trim_profile':
            return { bytes: 0, removed: [] };

        // ---- Proxies -------------------------------------------------------
        case 'proxies':
            return state.proxies;

        case 'save_proxy': {
            const incoming = params.proxy || {};
            const existing = incoming.id ? state.proxies.find((x) => x.id === incoming.id) : null;
            const id = existing ? existing.id : crypto.randomUUID();
            const record = {
                id,
                name: String(incoming.name || '').trim() || `${incoming.host}:${incoming.port}`,
                kind: incoming.kind || existing?.kind || 'http',
                host: String(incoming.host || '').trim(),
                port: Number(incoming.port) || 0,
                username: incoming.username ?? null,
                password: incoming.password ?? null,
                last_country: incoming.last_country ?? existing?.last_country ?? null,
                last_ip: incoming.last_ip ?? existing?.last_ip ?? null,
                last_timezone: incoming.last_timezone ?? existing?.last_timezone ?? null,
                rotate_url: incoming.rotate_url ?? existing?.rotate_url ?? null,
                checker_url: incoming.checker_url ?? existing?.checker_url ?? null
            };
            if (!record.host || !record.port) {
                throw new RpcError(400, 'Proxy host and port are required.');
            }
            if (existing) Object.assign(existing, record);
            else state.proxies.unshift(record);
            syncProxiesTxt(state);
            appendAudit(state, existing ? 'proxy.update' : 'proxy.create', id, { display: `${record.kind}://${record.host}:${record.port}` });
            saveState(state);
            return { id };
        }

        case 'delete_proxy': {
            state.proxies = state.proxies.filter((x) => x.id !== params.id);
            for (const p of state.profiles) {
                if (p.proxy_id === params.id) p.proxy_id = null;
            }
            syncProxiesTxt(state);
            appendAudit(state, 'proxy.delete', params.id);
            saveState(state);
            return { ok: true };
        }

        case 'parse_proxy_line':
            return parseSingleProxyLine(params.line);

        case 'sniff_proxy_kind':
            return sniffProxyProtocol(String(params.host || ''), Number(params.port) || 0);

        case 'import_proxies': {
            const lines = String(params.text || '').split(/\r?\n/);
            const prefix = String(params.namePrefix || 'Proxy').trim();
            const saved = [];
            const rejected = [];
            lines.forEach((raw, idx) => {
                const lineNum = idx + 1;
                const trimmed = raw.trim();
                if (!trimmed || trimmed.startsWith('#')) return;
                const parsed = parseSingleProxyLine(trimmed);
                if (!parsed) {
                    rejected.push({ line: lineNum, error: 'Unrecognized proxy format' });
                    return;
                }
                const id = crypto.randomUUID();
                state.proxies.push({
                    id,
                    name: `${prefix} ${saved.length + 1}`,
                    kind: parsed.kind,
                    host: parsed.host,
                    port: parsed.port,
                    username: parsed.username,
                    password: parsed.password,
                    last_country: null,
                    last_ip: null,
                    last_timezone: null,
                    rotate_url: null,
                    checker_url: null
                });
                saved.push({ id, line: lineNum, host: parsed.host, port: parsed.port, shape: parsed.shape });
            });
            if (saved.length > 0) {
                syncProxiesTxt(state);
                appendAudit(state, 'proxy.import', null, { count: saved.length });
                saveState(state);
            }
            return { saved, rejected };
        }

        case 'check_proxy': {
            const diag = await diagnoseProxyTarget(state, { url: params.url, proxyId: params.proxyId });
            const connectStep = diag.steps.find((s) => s.step === 'connect');
            return {
                ok: diag.ok,
                error: diag.ok ? undefined : (diag.notes[0]?.detail || 'Proxy check failed'),
                error_code: diag.ok ? null : (diag.notes[0]?.code || 'connect_failed'),
                ip: diag.exit.ip || undefined,
                country: diag.exit.country || undefined,
                city: diag.exit.city || undefined,
                timezone: diag.exit.timezone || undefined,
                ms: connectStep?.ms ?? undefined
            };
        }

        case 'diagnose_proxy':
            return diagnoseProxyTarget(state, { url: params.url, proxyId: params.proxyId });

        case 'rotate_proxy': {
            const px = state.proxies.find((x) => x.id === params.id);
            if (!px?.rotate_url) {
                return { ok: false, error: 'No rotation URL configured for this proxy.', error_code: 'no_rotate_url' };
            }
            try {
                const resp = await fetch(px.rotate_url, { signal: AbortSignal.timeout(8000) });
                return { ok: resp.ok, status: resp.status, error: resp.ok ? undefined : `HTTP ${resp.status}` };
            } catch (err) {
                return { ok: false, error: err.message, error_code: 'rotate_failed' };
            }
        }

        // ---- Credentials / Bookmarks / Templates / Blocklists / Cookies ----
        case 'credentials':
            return state.credentials[params.profileId] || [];

        case 'save_credential': {
            const c = params.credential || {};
            const list = state.credentials[c.profile_id] || [];
            const id = c.id || crypto.randomUUID();
            const existing = list.find((x) => x.id === id);
            const record = { ...c, id };
            if (existing) Object.assign(existing, record);
            else list.push(record);
            state.credentials[c.profile_id] = list;
            saveState(state);
            return { id };
        }

        case 'delete_credential': {
            const list = state.credentials[params.profileId] || [];
            state.credentials[params.profileId] = list.filter((x) => x.id !== params.id);
            saveState(state);
            return { ok: true };
        }

        case 'totp_code': {
            const list = state.credentials[params.profileId] || [];
            const cred = list.find((x) => x.id === params.id);
            if (!cred?.totp) throw new RpcError(404, 'TOTP seed not found');
            const seconds_remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
            return {
                code: generateTotp(cred.totp, 0),
                seconds_remaining,
                next: generateTotp(cred.totp, 1)
            };
        }

        case 'bookmarks_list':
            return { sets: state.bookmarks };

        case 'bookmarks_save': {
            const set = params.set || {};
            const id = set.id || crypto.randomUUID();
            const existing = state.bookmarks.find((x) => x.id === id);
            const record = { ...set, id };
            if (existing) Object.assign(existing, record);
            else state.bookmarks.push(record);
            saveState(state);
            return { id };
        }

        case 'bookmarks_delete':
            state.bookmarks = state.bookmarks.filter((x) => x.id !== params.id);
            saveState(state);
            return { ok: true };

        case 'templates':
            return state.templates;

        case 'save_template': {
            const tpl = params.template;
            state.templates = state.templates.filter((t) => t.name !== tpl.name);
            state.templates.push(tpl);
            saveState(state);
            return { saved: tpl.name };
        }

        case 'delete_template':
            state.templates = state.templates.filter((t) => t.name !== params.name);
            saveState(state);
            return { ok: true };

        case 'blocklists':
            return Object.entries(state.blocklists).map(([name, text]) => {
                const lines = String(text).split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
                return {
                    name,
                    domains: lines.filter((l) => !l.startsWith('@')).length,
                    allow_only: lines[0] === '@allow-only',
                    local: lines[0] === '@local'
                };
            });

        case 'read_blocklist':
            return { name: params.name, text: state.blocklists[params.name] || '' };

        case 'save_blocklist': {
            state.blocklists[params.name] = String(params.text || '');
            saveState(state);
            const all = await handleRpc('blocklists');
            return all.find((x) => x.name === params.name);
        }

        case 'delete_blocklist':
            delete state.blocklists[params.name];
            saveState(state);
            return { ok: true };

        case 'export_cookies': {
            const profileDir = resolveSafeProfilePath(profilesDir, params.id);
            const storagePath = path.join(profileDir, 'storage-state.json');
            try {
                const parsed = JSON.parse(readPrivateFile(storagePath, 'utf8', { requireOwner: true }));
                return { cookies: Array.isArray(parsed.cookies) ? parsed.cookies : [] };
            } catch {
                return { cookies: state.cookies[params.id] || [] };
            }
        }

        case 'import_cookies': {
            const cookies = Array.isArray(params.cookies) ? params.cookies : [];
            state.cookies[params.id] = cookies;
            saveState(state);
            return { imported: cookies.length, session_only: 0, skipped: 0 };
        }

        case 'extensions':
            return state.extensions[params.profileId] || [];

        case 'all_extensions':
        case 'all_extensions_with':
        case 'extension_catalogue':
            return [];

        // ---- Background status stubs for Fury UI polling -------------------
        case 'warm_status':
        case 'farm_due':
            return [];

        case 'warm_defaults':
            return { urls: ['https://example.com', 'https://news.ycombinator.com'] };

        case 'farm_list':
            return { now_ms: Date.now(), farms: [] };

        case 'mirror_status':
            return { active: false, typing: false, members: [], mirrored: 0 };

        case 'audit':
            return state.audit;

        case 'assistants_state':
            return {
                agent: null,
                agent_problem: null,
                clients: [],
                claude_code: null,
                snippet: null,
                skill_installed: false,
                skill_path: ''
            };

        // ---- Camoufox Suite Lab (Donut-inspired components) ----------------
        case 'suite_overview': {
            const traffic = collectTrafficSummary();
            const history = readResultsHistory();
            const envCfg = readEditableEnv();
            let recordingCount = 0;
            for (const entry of activeLocalProcesses.values()) {
                if (entry?.recordingActive) recordingCount++;
            }
            return {
                profileCount: state.profiles.length,
                runningCount: activeSet.size,
                recordingCount,
                projectCount: state.projects.length,
                proxyCount: state.proxies.length,
                presetCount: USABLE_DEVICE_PRESET_CATALOG.length,
                camoufoxSdkReady: Boolean(camoufoxReady && localBrowser?.kind === 'camoufox'),
                isAntidetectEngine: localBrowser?.kind === 'camoufox',
                baselineStatus: localBrowser?.kind === 'camoufox' ? 'ready' : baselineInstallState.status,
                baselineError: baselineInstallState.error,
                browserLauncher: localBrowser
                    ? { kind: localBrowser.kind, label: localBrowser.label, version: localBrowser.version || null }
                    : null,
                stateDir,
                profilesDir,
                profileService: envCfg.values.PROFILE_SERVICE || process.env.PROFILE_SERVICE || 'camoufox',
                lastCoherence: state.lastCoherence,
                traffic,
                recentResultsCount: history.results.length,
                summaryStats: history.summary?.stats || null
            };
        }

        case 'suite_ensure_baseline': {
            const installed = await ensureCamoufoxEngineInstalledBackground();
            return {
                ok: true,
                status: 'ready',
                browser: installed ? { kind: installed.kind, label: installed.label, version: installed.version || null } : null
            };
        }

        case 'suite_presets':
            return listUsableDevicePresets().map((p) => ({
                presetId: p.presetId,
                os: p.os,
                category: p.category,
                deviceModel: p.deviceModel,
                cpuModel: p.cpuModel,
                gpuModel: p.gpuModel,
                hardwareConcurrency: p.hardwareConcurrency,
                ramGb: p.ramGb,
                storageGb: p.storageGb,
                architecture: p.architecture,
                osVersion: p.osVersion,
                screen: p.screen,
                webgl: p.webgl
            }));

        case 'suite_run_coherence':
            return runCoherenceDiagnostic(state, params);

        case 'suite_audit_profile':
            return auditSingleSavedProfile(state, params);

        case 'suite_traffic_summary':
            return collectTrafficSummary();

        case 'suite_traffic_profiles':
            return listStudioTrafficProfiles(state);

        case 'suite_traffic_query':
            return queryStudioTraffic(state, params);

        case 'suite_traffic_wire_dump':
            return reconstructStudioWireDump(params);

        case 'suite_traffic_export_har':
            return exportStudioTrafficHar(params);

        case 'suite_audit_adspower':
            return auditAdsPowerDirectory(params.cacheDir);

        case 'suite_heal_adspower': {
            const report = auditAdsPowerDirectory(params.cacheDir);
            const selected = Array.isArray(params.fbccIds) && params.fbccIds.length
                ? report.profiles.filter((p) => params.fbccIds.includes(p.fbccId))
                : report.profiles;
            const imported = [];
            for (const item of selected) {
                const healed = item.healed || sanitizeAdsPowerProfileToCoherentPreset(item);
                const healedOs = healed?.healedProfile?.os || healed?.os || 'macos';
                const presetId = healed?.healedPresetId
                    || healed?.healedProfile?.presetId
                    || healed?.preset?.presetId
                    || defaultPresetForOs(healedOs);
                const created = await handleRpc('save_profile', {
                    profile: {
                        name: `Healed ${item.fbccId || item.profileDirName}`,
                        persona_id: presetId,
                        tags: ['adspower-healed', healedOs],
                        notes: `Healed from AdsPower (${item.profileDirName}) -> ${presetId}`,
                        allow_no_proxy: true
                    }
                });
                imported.push({ id: created.id, source: item.profileDirName, presetId });
            }
            return { imported };
        }

        case 'suite_results_history':
            return readResultsHistory();

        case 'suite_get_env':
            return readEditableEnv();

        case 'suite_save_env': {
            const updated = writeEditableEnv(params.values || {});
            appendAudit(state, 'suite.env_update', null, { keys: Object.keys(params.values || {}) });
            saveState(state);
            return updated;
        }

        case 'suite_cli_info': {
            const baseUrl = `http://${HOST}:${PORT}`;
            return {
                endpoint: baseUrl,
                apiBase: `${baseUrl}/api/v1`,
                apiKey: state.apiKey,
                apiKeyCreatedAt: state.apiKeyCreatedAt || null,
                desktopMode: process.env.CAMOUFOX_UI_DESKTOP === '1',
                repoRoot: REPO_ROOT,
                stateDir,
                endpoints: [
                    { method: 'GET', path: '/api/v1/health', desc: '服务健康与版本状态' },
                    { method: 'GET', path: '/api/v1/profiles', desc: '列出全部环境（含运行状态与预设）' },
                    { method: 'POST', path: '/api/v1/profiles', desc: '按预设/代理新建环境' },
                    { method: 'POST', path: '/api/v1/profiles/:id/launch', desc: '拉起指定环境的独立浏览器窗口' },
                    { method: 'POST', path: '/api/v1/profiles/:id/stop', desc: '关闭指定环境的运行中窗口' },
                    { method: 'DELETE', path: '/api/v1/profiles/:id', desc: '将环境移入回收站' },
                    { method: 'GET', path: '/api/v1/proxies', desc: '获取本地代理池列表' },
                    { method: 'GET', path: '/api/v1/presets', desc: '获取 37 套 SKU 硬件预设目录' },
                    { method: 'POST', path: '/api/v1/coherence/run', desc: '触发三端 17 项一致性审计' },
                    { method: 'POST', path: '/api/v1/rpc', desc: '调用任意本地 RPC 方法（{ method, params }）' }
                ],
                cliCommands: [
                    { id: 'coherence', label: '17 项跨平台硬件一致性审计', cmd: 'node scripts/verify-camoufox-coherence.js --dry-run' },
                    { id: 'presets', label: '列出 37 套 SKU 实机预设目录', cmd: 'node scripts/audit-adspower-profiles.js --list-presets' },
                    { id: 'cli-help', label: '查看主 CLI 帮助与参数', cmd: 'node bin/gmail-account-creator.js --help' },
                    { id: 'cli-version', label: '检查项目版本与节点环境', cmd: 'node bin/gmail-account-creator.js --version' }
                ]
            };
        }

        case 'suite_rotate_api_key': {
            state.apiKey = generateLocalApiKey();
            state.apiKeyCreatedAt = new Date().toISOString();
            appendAudit(state, 'suite.api_key_rotate', null, { createdAt: state.apiKeyCreatedAt });
            saveState(state);
            return { apiKey: state.apiKey, apiKeyCreatedAt: state.apiKeyCreatedAt };
        }

        case 'suite_get_keys':
            return readSecretEnvKeys();

        case 'suite_save_keys': {
            const updated = writeSecretEnvKeys(params.values || {});
            appendAudit(state, 'suite.keys_update', null, { keys: Object.keys(params.values || {}) });
            saveState(state);
            return updated;
        }

        case 'suite_run_cli':
            return runAllowlistedCli(params.commandId);

        case 'suite_network_status': {
            const netd = detectNetdAvailability();
            const defaults = normalizeNetworkConfig(state.networkDefaults);
            const activeRelays = [];
            for (const [profileId, entry] of activeLocalProcesses.entries()) {
                if (!entry?.relay) continue;
                const prof = state.profiles.find((p) => p.id === profileId);
                activeRelays.push({
                    profile_id: profileId,
                    profile_name: prof?.name || profileId,
                    engine: entry.relay.engine,
                    proxy_port: entry.relay.port,
                    dns_stub_port: entry.relay.dnsStubPort,
                    dns_disguise: entry.relay.dnsDisguise,
                    tcp2udp_port: entry.relay.tcp2udpPort,
                    udp_mode: entry.relay.udpMode,
                    udp_supported: entry.relay.udpSupported,
                    upstream_mode: entry.relay.upstreamMode
                });
            }
            return {
                netd,
                defaults,
                dns_presets: Object.values(DNS_DISGUISE_PRESETS),
                active_relays: activeRelays
            };
        }

        case 'suite_save_network_defaults': {
            state.networkDefaults = normalizeNetworkConfig({
                ...(state.networkDefaults || {}),
                ...(params.config || {})
            });
            appendAudit(state, 'suite.network_config', null, {
                engine: state.networkDefaults.engine,
                udp_mode: state.networkDefaults.udp_mode,
                dns_disguise: state.networkDefaults.dns_disguise,
                tcp2udp_enable: state.networkDefaults.tcp2udp_enable
            });
            saveState(state);
            return {
                ok: true,
                defaults: state.networkDefaults
            };
        }

        default:
            throw new RpcError(501, `Operation "${method}" is not enabled in local HTTP mode.`, 'not_supported_local');
    }
}

function readSecretEnvKeys() {
    const file = envFilePath();
    const rawValues = {};
    let exists = false;
    try {
        const raw = readPrivateFile(file, 'utf8', { requireOwner: true });
        exists = true;
        for (const line of raw.split(/\r?\n/)) {
            const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
            if (!m) continue;
            rawValues[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
        }
    } catch {
        // .env absent yet
    }
    return {
        path: file,
        exists,
        items: SECRET_ENV_KEYS.map((meta) => ({
            ...meta,
            configured: Boolean(rawValues[meta.key]),
            value: rawValues[meta.key] || ''
        }))
    };
}

function writeSecretEnvKeys(updates) {
    const allowed = new Set(SECRET_ENV_KEYS.map((k) => k.key));
    const file = envFilePath();
    const existingLines = [];
    const seen = new Set();
    try {
        const raw = readPrivateFile(file, 'utf8', { requireOwner: true });
        for (const line of raw.split(/\r?\n/)) {
            const m = line.match(/^\s*([A-Z0-9_]+)\s*=/);
            if (m && allowed.has(m[1]) && Object.prototype.hasOwnProperty.call(updates, m[1])) {
                const val = String(updates[m[1]] ?? '').replace(/[\r\n]/g, '').trim();
                if (val !== '') existingLines.push(`${m[1]}=${val}`);
                seen.add(m[1]);
            } else {
                existingLines.push(line);
            }
        }
    } catch {
        existingLines.push('# Managed by Camoufox Studio UI');
    }
    for (const meta of SECRET_ENV_KEYS) {
        if (seen.has(meta.key) || !Object.prototype.hasOwnProperty.call(updates, meta.key)) continue;
        const val = String(updates[meta.key] ?? '').replace(/[\r\n]/g, '').trim();
        if (val !== '') existingLines.push(`${meta.key}=${val}`);
    }
    writePrivateFile(file, existingLines.join('\n').replace(/\n+$/, '') + '\n', { requireOwner: true });
    return readSecretEnvKeys();
}

async function runAllowlistedCli(commandId) {
    const map = {
        coherence: {
            cmd: 'node scripts/verify-camoufox-coherence.js --dry-run',
            args: [path.join(REPO_ROOT, 'scripts', 'verify-camoufox-coherence.js'), '--dry-run']
        },
        presets: {
            cmd: 'node scripts/audit-adspower-profiles.js --list-presets',
            args: [path.join(REPO_ROOT, 'scripts', 'audit-adspower-profiles.js'), '--list-presets']
        },
        'cli-help': {
            cmd: 'node bin/gmail-account-creator.js --help',
            args: [path.join(REPO_ROOT, 'bin', 'gmail-account-creator.js'), '--help'],
            fallback: 'Usage: gmail-account-creator [--accounts=N] [--threads=N]\n       gmail-account-creator --help\n       gmail-account-creator --version\n\nCounts can also be set with -a=N and -t=N.'
        },
        'cli-version': {
            cmd: 'node bin/gmail-account-creator.js --version',
            args: [path.join(REPO_ROOT, 'bin', 'gmail-account-creator.js'), '--version'],
            fallback: `Camoufox Studio 1.0.0 (Node ${process.version})`
        }
    };
    const spec = map[commandId];
    if (!spec) throw new RpcError(400, `Unknown CLI command "${commandId}".`);
    const started = Date.now();
    if (!fs.existsSync(spec.args[0])) {
        return {
            commandId,
            cmd: spec.cmd,
            exitCode: 0,
            durationMs: Date.now() - started,
            stdout: spec.fallback || 'Script not included in standalone bundle.',
            stderr: ''
        };
    }
    try {
        const { stdout, stderr } = await execFileAsync(process.execPath, spec.args, {
            cwd: REPO_ROOT,
            timeout: 30000,
            maxBuffer: 4 * 1024 * 1024
        });
        return {
            commandId,
            cmd: spec.cmd,
            exitCode: 0,
            durationMs: Date.now() - started,
            stdout: stdout.trim(),
            stderr: stderr.trim()
        };
    } catch (err) {
        return {
            commandId,
            cmd: spec.cmd,
            exitCode: typeof err?.code === 'number' ? err.code : 1,
            durationMs: Date.now() - started,
            stdout: String(err?.stdout || '').trim(),
            stderr: String(err?.stderr || err?.message || '').trim()
        };
    }
}

function verifyApiKeyHeader(req) {
    const state = loadState();
    const expected = String(state.apiKey || '');
    if (!expected) return false;
    const headerKey = typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'].trim() : '';
    const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization.trim() : '';
    const bearer = /^Bearer\s+(.+)$/i.exec(authHeader)?.[1]?.trim() || '';
    const supplied = headerKey || bearer;
    if (!supplied) return false;
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(supplied, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

async function handleApiV1(req, res, pathname) {
    if (!verifyApiKeyHeader(req)) {
        sendJson(res, 401, {
            ok: false,
            error: 'Invalid or missing API key. Pass Authorization: Bearer <key> or X-API-Key: <key>.'
        });
        return;
    }

    try {
        if (pathname === '/api/v1/health' && req.method === 'GET') {
            sendJson(res, 200, {
                ok: true,
                service: 'camoufox-studio',
                version: '1.0.0',
                endpoint: `http://${HOST}:${PORT}`,
                node: process.version
            });
            return;
        }
        if (pathname === '/api/v1/profiles' && req.method === 'GET') {
            sendJson(res, 200, { ok: true, profiles: await handleRpc('profiles', {}) });
            return;
        }
        if (pathname === '/api/v1/profiles' && req.method === 'POST') {
            const body = await readJsonBody(req);
            sendJson(res, 201, { ok: true, ...(await handleRpc('save_profile', { profile: body })) });
            return;
        }
        const launchMatch = pathname.match(/^\/api\/v1\/profiles\/([^/]+)\/launch$/);
        if (launchMatch && req.method === 'POST') {
            const profileId = decodeURIComponent(launchMatch[1]);
            sendJson(res, 200, { ok: true, ...(await handleRpc('launch', { profileId })) });
            return;
        }
        const stopMatch = pathname.match(/^\/api\/v1\/profiles\/([^/]+)\/stop$/);
        if (stopMatch && req.method === 'POST') {
            const profileId = decodeURIComponent(stopMatch[1]);
            sendJson(res, 200, { ok: true, ...(await handleRpc('stop', { profileId })) });
            return;
        }
        const profileMatch = pathname.match(/^\/api\/v1\/profiles\/([^/]+)$/);
        if (profileMatch && req.method === 'DELETE') {
            const id = decodeURIComponent(profileMatch[1]);
            sendJson(res, 200, { ok: true, ...(await handleRpc('delete_profile', { id })) });
            return;
        }
        if (pathname === '/api/v1/proxies' && req.method === 'GET') {
            sendJson(res, 200, { ok: true, proxies: await handleRpc('proxies', {}) });
            return;
        }
        if (pathname === '/api/v1/presets' && req.method === 'GET') {
            sendJson(res, 200, { ok: true, presets: await handleRpc('suite_presets', {}) });
            return;
        }
        if (pathname === '/api/v1/network/status' && req.method === 'GET') {
            sendJson(res, 200, { ok: true, ...(await handleRpc('suite_network_status', {})) });
            return;
        }
        if (pathname === '/api/v1/coherence/run' && req.method === 'POST') {
            sendJson(res, 200, { ok: true, result: await handleRpc('suite_run_coherence', {}) });
            return;
        }
        if (pathname === '/api/v1/rpc' && req.method === 'POST') {
            const { method, params } = await readJsonBody(req);
            if (!method || typeof method !== 'string') throw new RpcError(400, 'Missing RPC method name.');
            sendJson(res, 200, { ok: true, result: await handleRpc(method, params || {}) });
            return;
        }
        sendJson(res, 404, { ok: false, error: `Unknown endpoint: ${req.method} ${pathname}` });
    } catch (err) {
        const status = typeof err?.status === 'number' ? err.status : 500;
        sendJson(res, status, { ok: false, status, code: err?.code || null, error: err?.message || 'Internal error' });
    }
}

// ---------------------------------------------------------------------------
// HTTP Server (Loopback-only static UI + same-origin /rpc)
// ---------------------------------------------------------------------------

function resolveSafeProfilePath(profilesDir, rawId) {
    const id = String(rawId || '').trim();
    if (!id || id.includes('/') || id.includes('\\') || id === '.' || id === '..') {
        throw new RpcError(400, 'Invalid profile ID.');
    }
    const base = path.resolve(profilesDir);
    const resolved = path.resolve(base, id);
    if (!resolved.startsWith(base + path.sep)) {
        throw new RpcError(400, 'Profile path escapes profiles directory.');
    }
    return resolved;
}

function isLoopbackHostname(hostname) {
    return ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(String(hostname || '').toLowerCase());
}

function isAllowedLoopbackRequest(req) {
    const hostHeader = req.headers.host;
    if (hostHeader) {
        try {
            const parsedHost = new URL(`http://${hostHeader}`);
            if (!isLoopbackHostname(parsedHost.hostname)) return false;
        } catch {
            return false;
        }
    }
    const origin = req.headers.origin;
    if (!origin) return true;
    try {
        const u = new URL(origin);
        return isLoopbackHostname(u.hostname);
    } catch {
        return false;
    }
}

function readJsonBody(req, maxBytes = 4 * 1024 * 1024) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > maxBytes) {
                reject(new RpcError(413, 'Request body too large'));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            try {
                const text = Buffer.concat(chunks).toString('utf8');
                resolve(text ? JSON.parse(text) : {});
            } catch {
                reject(new RpcError(400, 'Invalid JSON payload'));
            }
        });
        req.on('error', reject);
    });
}

function sendJson(res, status, payload) {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    });
    res.end(body);
}

function serveStatic(req, res) {
    const reqUrl = new URL(req.url || '/', `http://${HOST}:${PORT}`);
    let pathname = decodeURIComponent(reqUrl.pathname);
    if (pathname === '/') pathname = '/index.html';

    const resolved = path.resolve(DIST_DIR, '.' + pathname);
    if (!resolved.startsWith(DIST_DIR + path.sep) && resolved !== DIST_DIR) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
    }

    let filePath = resolved;
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        filePath = path.join(DIST_DIR, 'index.html');
    }

    if (!fs.existsSync(filePath)) {
        res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('UI build missing. Run: npm run ui:build');
        return;
    }

    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
        'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
        'X-Content-Type-Options': 'nosniff'
    });
    fs.createReadStream(filePath).pipe(res);
}

const server = http.createServer(async (req, res) => {
    if (!isAllowedLoopbackRequest(req)) {
        sendJson(res, 403, { status: 403, message: 'Non-loopback Host or cross-origin request forbidden.' });
        return;
    }
    const reqUrl = new URL(req.url || '/', `http://${HOST}:${PORT}`);

    if (reqUrl.pathname === '/api/health' && req.method === 'GET') {
        sendJson(res, 200, { ok: true, service: 'camoufox-studio-ui', port: PORT });
        return;
    }

    if (reqUrl.pathname.startsWith('/api/v1/')) {
        await handleApiV1(req, res, reqUrl.pathname);
        return;
    }

    if (reqUrl.pathname === '/rpc' && req.method === 'POST') {
        try {
            const { method, params } = await readJsonBody(req);
            if (!method || typeof method !== 'string') {
                throw new RpcError(400, 'Missing RPC method name.');
            }
            const result = await handleRpc(method, params || {});
            sendJson(res, 200, { ok: true, result });
        } catch (err) {
            const status = typeof err?.status === 'number' ? err.status : 500;
            sendJson(res, status, {
                ok: false,
                status,
                code: err?.code || null,
                message: err?.message || 'Internal bridge error',
                body: err?.body || null
            });
        }
        return;
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
        serveStatic(req, res);
        return;
    }

    res.writeHead(405);
    res.end('Method Not Allowed');
});

server.listen(PORT, HOST, () => {
    const stateDir = ensureStateDirectory();
    cleanActiveDockStack();
    const detected = detectLocalBrowser({ allowStockFallback: false });
    if (!detected && isCamoufoxModuleResolvable()) {
        void ensureCamoufoxEngineInstalledBackground().catch(() => {});
    }
    console.log('================================================================');
    console.log('  Camoufox Studio (HTTP Web UI Mode)');
    console.log(`  URL        : http://${HOST}:${PORT}`);
    console.log(`  State Dir  : ${stateDir}`);
    console.log(`  Presets    : ${USABLE_DEVICE_PRESET_CATALOG.length} SKU-verified hardware models`);
    console.log(`  Camoufox   : ${detected ? detected.label : 'Auto-installing baseline Camoufox engine in background...'}`);
    console.log('================================================================');
});
