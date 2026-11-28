import { parseAccountCount, parseThreadCount } from './cli-counts.js';
import { configurationError, loadApplicationEnvironment, resolveRecordingOptions } from './private-env.js';
import { getDefaultProfilesDirectory } from './state-paths.js';

function buildApplicationConfig(env) {
    const profileService = env.PROFILE_SERVICE?.trim() || 'gpm';
    if (!['gpm', 'dolphin', 'camoufox'].includes(profileService)) {
        throw configurationError('PROFILE_SERVICE must be gpm, dolphin, or camoufox');
    }

    const configuredAccountsCount = env.ACCOUNTS_COUNT ?? '1';
    const configuredThreadsCount = env.THREADS_COUNT ?? '1';
    let configuredGoLoginKey = env.GOLOGIN_API_KEY;

    const config = {
        profileService,
        gpmlogin: {
            apiUrl: env.GPM_API_URL || 'http://127.0.0.1:14517'
        },
        dolphin: {
            apiUrl: env.DOLPHIN_API_URL || 'http://127.0.0.1:30898',
            apiKey: env.DOLPHIN_API_KEY || '',
            folderId: env.DOLPHIN_FOLDER_ID || ''
        },
        camoufox: {
            os: env.CAMOUFOX_OS || 'windows', // 'windows', 'macos', 'linux'
            presetId: env.CAMOUFOX_PRESET_ID || env.CAMOUFOX_PRESET || null, // Optional exact SKU preset ID from USABLE_DEVICE_PRESET_CATALOG
            country: env.CAMOUFOX_COUNTRY || null, // Optional ISO-3166 country code (e.g. 'US', 'GB', 'DE', 'JP', 'SG')
            headless: env.CAMOUFOX_HEADLESS === 'true' ? true : (env.CAMOUFOX_HEADLESS === 'virtual' ? 'virtual' : false),
            humanize: env.CAMOUFOX_HUMANIZE !== 'false', // Default: true
            geoip: env.CAMOUFOX_GEOIP !== 'false', // Default: true when proxy is used
            canvasNoise: env.CAMOUFOX_CANVAS_NOISE !== 'false', // Default: true for cross-OS isolation
            enablePortScanProtection: env.CAMOUFOX_PORT_SCAN_PROTECTION !== 'false', // Default: true (Ziniao-absorbed localhost/RFC1918 LAN port-scan guard)
            portScanProtectionMode: env.CAMOUFOX_PORT_SCAN_MODE ?? 'url-only',
            allowedLocalPorts: env.CAMOUFOX_ALLOWED_LOCAL_PORTS
                ? env.CAMOUFOX_ALLOWED_LOCAL_PORTS.split(',')
                      .map((p) => parseInt(p.trim(), 10))
                      .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
                : [],
            canvasSkipHosts: env.CAMOUFOX_CANVAS_SKIP_HOSTS
                ? env.CAMOUFOX_CANVAS_SKIP_HOSTS.split(',')
                      .map((h) => h.trim())
                      .filter(Boolean)
                : undefined,
            maxHammingDistance: parseInt(env.CAMOUFOX_CANVAS_MAX_HAMMING_DISTANCE || '0', 10),
            storageDir: getDefaultProfilesDirectory(env),
            ...resolveRecordingOptions({}, env),
            neckoMozLogModules: env.CAMOUFOX_NECKO_MOZ_LOG_MODULES || 'timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4'
        },
        gologin: {
            get apiKey() {
                configuredGoLoginKey ??= loadApplicationEnvironment({
                    env: { ...process.env },
                    includeGoLoginFallback: true
                }).GOLOGIN_API_KEY;
                return configuredGoLoginKey ?? '';
            },
            apiUrl: 'https://api.gologin.com'
        },
        omocaptcha: {
            extensionId: 'dfjghhjachoacpgpkmbpdlpppeagojhe',
            apiKey: env.OMOCAPTCHA_KEY || '',
            enabled: env.SETUP_OMO_CAPTCHA !== 'false' // Default: true, set SETUP_OMO_CAPTCHA=false to disable
        },
        smsVerify: {
            apiKey: env.SMS_VERIFY_API_KEY || '',
            lang: env.SMS_VERIFY_LANG || 'ru',
            service: 'go', // Google service code
            country: 16, // UK
            // SMS_VERIFY_COUNTRIES: Comma-separated country codes (e.g., "53,95" for Saudi Arabia and UAE)
            // If empty, defaults to Saudi Arabia (53) and UAE (95)
            // SMS_VERIFY_COUNTRIES: أكواد الدول مفصولة بفواصل (مثل: "53,95" للسعودية والإمارات)
            countries: env.SMS_VERIFY_COUNTRIES ?
                env.SMS_VERIFY_COUNTRIES.split(',').map(c => parseInt(c.trim())).filter(c => !isNaN(c)) :
                [53, 95] // Default: Saudi Arabia (53) and UAE (95)
        },
        app: {
            logLevel: env.LOG_LEVEL || 'info',
            maxRetries: parseInt(env.MAX_RETRIES || '3'),
            retryDelay: 5000,
            get accountsCount() { return parseAccountCount(configuredAccountsCount); },
            get threadsCount() { return parseThreadCount(configuredThreadsCount); },
            testProxy: env.TEST_PROXY !== 'false', // Controls the optional proxy preflight.
            allowDirectConnection: env.CAMOUFOX_ALLOW_DIRECT === 'true'
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

    return config;
}

let applicationConfig;

export function loadApplicationConfig(validateEnvironment) {
    if (applicationConfig) {
        validateEnvironment?.(process.env);
        return applicationConfig;
    }

    let candidate;
    loadApplicationEnvironment({
        validate(env) {
            candidate = buildApplicationConfig(env);
            validateEnvironment?.(env);
        }
    });
    applicationConfig = candidate;
    return applicationConfig;
}
