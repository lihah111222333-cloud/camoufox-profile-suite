/**
 * Application Configuration
 * إعدادات التطبيق
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function loadEnvFileSafe(filePath) {
    try {
        if (!fs.existsSync(filePath)) return;
        if (typeof process.loadEnvFile === 'function') {
            process.loadEnvFile(filePath);
            return;
        }
        const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
        for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line || line.startsWith('#')) continue;
            const eqIdx = line.indexOf('=');
            if (eqIdx <= 0) continue;
            const key = line.slice(0, eqIdx).trim();
            const val = line.slice(eqIdx + 1).trim().replace(/^['"]|['"]$/g, '');
            if (!(key in process.env)) {
                process.env[key] = val;
            }
        }
    } catch {
        // Ignore missing/unreadable .env file
    }
}

// Load .env file first, then try .emv if .env doesn't exist
// تحميل ملف .env أولاً، ثم تجربة .emv إذا لم يوجد .env
loadEnvFileSafe(path.resolve(__dirname, '../.env'));
// Also try loading .emv if .env doesn't have required variables
// أيضاً جرب تحميل .emv إذا لم يكن .env يحتوي على المتغيرات المطلوبة
if (!process.env.PROFILE_SERVICE && !process.env.DOLPHIN_API_KEY) {
    loadEnvFileSafe(path.resolve(__dirname, '../.emv'));
}

export const config = {
    profileService: process.env.PROFILE_SERVICE || 'gpm', // 'gpm', 'dolphin', or 'camoufox'
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
        headless: process.env.CAMOUFOX_HEADLESS === 'true' ? true : (process.env.CAMOUFOX_HEADLESS === 'virtual' ? 'virtual' : false),
        humanize: process.env.CAMOUFOX_HUMANIZE !== 'false', // Default: true
        geoip: process.env.CAMOUFOX_GEOIP !== 'false', // Default: true when proxy is used
        canvasNoise: process.env.CAMOUFOX_CANVAS_NOISE !== 'false', // Default: true for cross-OS isolation
        storageDir: process.env.CAMOUFOX_STORAGE_DIR || path.resolve(__dirname, '../profiles'),
        recordTraffic: process.env.CAMOUFOX_RECORD_TRAFFIC !== 'false', // Default: true (pre-TLS Necko egress/ingress NDJSON + attribution)
        recordBodies: process.env.CAMOUFOX_RECORD_BODIES !== 'false', // Default: true (capture plaintext request/response payloads)
        sslKeyLog: process.env.CAMOUFOX_SSLKEYLOG !== 'false', // Default: true (export NSS pre-TLS secrets to sslkeylog.txt)
        recordHar: process.env.CAMOUFOX_RECORD_HAR === 'true', // Default: false (optional Playwright HAR 1.2 archive)
        maxBodyBytes: parseInt(process.env.CAMOUFOX_TRAFFIC_MAX_BODY_BYTES || '5242880', 10) // Default: 5MB
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
        accountsCount: parseInt(process.env.ACCOUNTS_COUNT || '1'),
        threadsCount: parseInt(process.env.THREADS_COUNT || '1'),
        testProxy: process.env.TEST_PROXY !== 'false' // Default: true, set TEST_PROXY=false to disable
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
        console.warn(`⚠ Unknown CAMOUFOX_OS: ${config.camoufox.os}. Using default: windows`);
        config.camoufox.os = 'windows';
    } else {
        config.camoufox.os = String(config.camoufox.os).toLowerCase();
    }
} else {
    console.warn(`⚠ Unknown PROFILE_SERVICE: ${config.profileService}. Using default: gpm`);
    config.profileService = 'gpm';
}

if (!config.omocaptcha.apiKey) {
    console.warn('⚠ OMOCAPTCHA_KEY is not set');
}

if (!config.smsVerify.apiKey) {
    console.warn('⚠ SMS_VERIFY_API_KEY is not set');
}

export default config;

