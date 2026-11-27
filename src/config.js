/**
 * Application Configuration
 * إعدادات التطبيق
 */

import { parseAccountCount, parseThreadCount } from './utils/cli-counts.js';
import { configurationError, loadApplicationEnvironment, resolveRecordingOptions } from './utils/private-env.js';
import { getDefaultProfilesDirectory } from './utils/state-paths.js';

loadApplicationEnvironment();

const profileService = process.env.PROFILE_SERVICE?.trim() || 'gpm';
if (!['gpm', 'dolphin', 'camoufox'].includes(profileService)) {
    throw configurationError('PROFILE_SERVICE must be gpm, dolphin, or camoufox');
}

const configuredAccountsCount = process.env.ACCOUNTS_COUNT ?? '1';
const configuredThreadsCount = process.env.THREADS_COUNT ?? '1';

export const config = {
    profileService,
    gpmlogin: {
        apiUrl: process.env.GPM_API_URL || 'http://127.0.0.1:14517'
    },
    dolphin: {
        apiUrl: process.env.DOLPHIN_API_URL || 'http://127.0.0.1:30898',
        apiKey: process.env.DOLPHIN_API_KEY || '',
        folderId: process.env.DOLPHIN_FOLDER_ID || ''
    },
    camoufox: {
        os: process.env.CAMOUFOX_OS || 'windows', // 'windows', 'macos', 'linux'
        presetId: process.env.CAMOUFOX_PRESET_ID || process.env.CAMOUFOX_PRESET || null, // Optional exact SKU preset ID from USABLE_DEVICE_PRESET_CATALOG
        country: process.env.CAMOUFOX_COUNTRY || null, // Optional ISO-3166 country code (e.g. 'US', 'GB', 'DE', 'JP', 'SG')
        headless: process.env.CAMOUFOX_HEADLESS === 'true' ? true : (process.env.CAMOUFOX_HEADLESS === 'virtual' ? 'virtual' : false),
        humanize: process.env.CAMOUFOX_HUMANIZE !== 'false', // Default: true
        geoip: process.env.CAMOUFOX_GEOIP !== 'false', // Default: true when proxy is used
        canvasNoise: process.env.CAMOUFOX_CANVAS_NOISE !== 'false', // Default: true for cross-OS isolation
        enablePortScanProtection: process.env.CAMOUFOX_PORT_SCAN_PROTECTION !== 'false', // Default: true (Ziniao-absorbed localhost/RFC1918 LAN port-scan guard)
        portScanProtectionMode: process.env.CAMOUFOX_PORT_SCAN_MODE ?? 'url-only',
        allowedLocalPorts: process.env.CAMOUFOX_ALLOWED_LOCAL_PORTS
            ? process.env.CAMOUFOX_ALLOWED_LOCAL_PORTS.split(',')
                  .map((p) => parseInt(p.trim(), 10))
                  .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
            : [],
        canvasSkipHosts: process.env.CAMOUFOX_CANVAS_SKIP_HOSTS
            ? process.env.CAMOUFOX_CANVAS_SKIP_HOSTS.split(',')
                  .map((h) => h.trim())
                  .filter(Boolean)
            : undefined,
        maxHammingDistance: parseInt(process.env.CAMOUFOX_CANVAS_MAX_HAMMING_DISTANCE || '0', 10),
        storageDir: getDefaultProfilesDirectory(),
        ...resolveRecordingOptions(),
        neckoMozLogModules: process.env.CAMOUFOX_NECKO_MOZ_LOG_MODULES || 'timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4'
    },
    gologin: {
        apiKey: process.env.GOLOGIN_API_KEY || '',
        apiUrl: 'https://api.gologin.com'
    },
    omocaptcha: {
        extensionId: 'dfjghhjachoacpgpkmbpdlpppeagojhe',
        apiKey: process.env.OMOCAPTCHA_KEY || '',
        enabled: process.env.SETUP_OMO_CAPTCHA !== 'false' // Default: true, set SETUP_OMO_CAPTCHA=false to disable
    },
    smsVerify: {
        apiKey: process.env.SMS_VERIFY_API_KEY || '',
        lang: process.env.SMS_VERIFY_LANG || 'ru',
        service: 'go', // Google service code
        country: 16, // UK
        // SMS_VERIFY_COUNTRIES: Comma-separated country codes (e.g., "53,95" for Saudi Arabia and UAE)
        // If empty, defaults to Saudi Arabia (53) and UAE (95)
        // SMS_VERIFY_COUNTRIES: أكواد الدول مفصولة بفواصل (مثل: "53,95" للسعودية والإمارات)
        countries: process.env.SMS_VERIFY_COUNTRIES ? 
            process.env.SMS_VERIFY_COUNTRIES.split(',').map(c => parseInt(c.trim())).filter(c => !isNaN(c)) : 
            [53, 95] // Default: Saudi Arabia (53) and UAE (95)
    },
    app: {
        logLevel: process.env.LOG_LEVEL || 'info',
        maxRetries: parseInt(process.env.MAX_RETRIES || '3'),
        retryDelay: 5000,
        get accountsCount() { return parseAccountCount(configuredAccountsCount); },
        get threadsCount() { return parseThreadCount(configuredThreadsCount); },
        testProxy: process.env.TEST_PROXY !== 'false', // Controls the optional proxy preflight.
        allowDirectConnection: process.env.CAMOUFOX_ALLOW_DIRECT === 'true'
    }
};

// Validate required configuration
if (config.profileService === 'gpm') {
    if (!config.gpmlogin.apiUrl) {
        console.warn('⚠ GPM_API_URL is not set, using default: http://127.0.0.1:14517');
    }
} else if (config.profileService === 'dolphin') {
    if (!config.dolphin.apiKey) {
        console.warn('⚠ DOLPHIN_API_KEY is not set. Please set it in .env file');
    }
    if (!config.dolphin.apiUrl) {
        console.warn('⚠ DOLPHIN_API_URL is not set, using default: http://127.0.0.1:30898');
    }
    if (!config.dolphin.folderId) {
        console.warn('⚠ DOLPHIN_FOLDER_ID is not set. Profiles will be created in default folder');
    }
} else if (config.profileService === 'camoufox') {
    const validOs = ['windows', 'macos', 'linux'];
    if (!validOs.includes(String(config.camoufox.os).toLowerCase())) {
        console.warn('⚠ Unknown CAMOUFOX_OS. Using default: windows');
        config.camoufox.os = 'windows';
    } else {
        config.camoufox.os = String(config.camoufox.os).toLowerCase();
    }
}

if (!config.smsVerify.apiKey) {
    console.warn('⚠ SMS_VERIFY_API_KEY is not set');
}

export default config;

