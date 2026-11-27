/**
 * GPM Login API Client
 * عميل GPM Login API
 */

import axios from 'axios';
import config from '../config.js';
import logger from '../utils/logger.js';
import {
    controllerApiUrl,
    controllerRequestOptions,
    parseControllerUrl,
    validateControllerEndpoint
} from '../utils/controller-url.js';
import { profileIdPathComponent } from '../utils/controller-id.js';
import {
    controllerAcknowledged,
    controllerErrorDetails,
    controllerRejected,
    parseControllerPayload,
    profileAllocationUnconfirmed,
    requireCreatedProfileId,
    sendControllerProfileCreate,
    sendControllerRequest
} from '../utils/controller-request.js';
import { requireProxyProtocol } from '../utils/proxy-protocol.js';

const GPM_API_URL = config.gpmlogin.apiUrl;
const controllerClient = axios.create(controllerRequestOptions);

function gpmApiUrl(path) {
    return controllerApiUrl(GPM_API_URL, path, 'GPM_TRUSTED_HTTP_API_URL');
}

function gpmMissingProfileCode(data) {
    const payload = parseControllerPayload(data);
    const message = payload?.message;
    if (payload?.success === false && typeof message === 'string' &&
        /^profile (?:is )?not found\.?$/i.test(message.trim())) {
        return 'PROFILE_NOT_FOUND';
    }
}

function gpmStopCode(data) {
    const payload = parseControllerPayload(data);
    const missing = gpmMissingProfileCode(payload);
    if (missing) return missing;
    const message = payload?.message;
    if (payload?.success !== true && typeof message === 'string' &&
        /^(?:(?:profile (?:is )?)?already stopped|profile (?:is )?not running)\.?$/i.test(message.trim())) {
        return 'PROFILE_ALREADY_STOPPED';
    }
}

/**
 * Generate realistic Android User-Agent with variations
 * توليد User-Agent واقعي لـ Android مع تنويعات
 */
export function generateAndroidUserAgent() {
    // Android versions (16 is latest, but include some variation)
    const androidVersions = ['16', '15', '14', '13', '12'];
    const androidVersion = androidVersions[Math.floor(Math.random() * androidVersions.length)];
    
    // Multiple device manufacturers for more variety
    const deviceProfiles = [
        // Samsung devices
        {
            models: ['SM-S938U', 'SM-S928U', 'SM-S918U', 'SM-S908U', 'SM-S998U', 'SM-S988U', 'SM-S978U'],
            buildPrefixes: ['BP2A', 'BP1A', 'AP3A', 'AP2A', 'AP1A'],
            buildSuffixes: ['250605', '250505', '250405', '250305', '250205'],
            buildNumbers: ['031', '030', '029', '028', '027'],
            buildLetters: ['A3', 'A2', 'A1', 'B1', 'B2']
        },
        // Google Pixel devices
        {
            models: ['Pixel 9 Pro', 'Pixel 9', 'Pixel 8 Pro', 'Pixel 8', 'Pixel 7 Pro', 'Pixel 7'],
            buildPrefixes: ['UP', 'TP', 'TQ'],
            buildSuffixes: ['1A', '2A', '3A', '1B', '2B'],
            buildNumbers: ['240805', '240705', '240605', '240505'],
            buildLetters: ['001', '002', '003']
        },
        // OnePlus devices
        {
            models: ['ONEPLUS A6013', 'ONEPLUS A5010', 'ONEPLUS A3000', 'ONEPLUS A6000'],
            buildPrefixes: ['OP', 'ONEPLUS'],
            buildSuffixes: ['28', '27', '26', '25'],
            buildNumbers: ['240805', '240705', '240605'],
            buildLetters: ['001', '002']
        },
        // Xiaomi devices
        {
            models: ['Mi 14', 'Mi 13', 'Redmi Note 13', 'Redmi Note 12', 'POCO F5'],
            buildPrefixes: ['V', 'MIUI'],
            buildSuffixes: ['14', '13', '12'],
            buildNumbers: ['240805', '240705', '240605'],
            buildLetters: ['001', '002']
        }
    ];
    
    const profile = deviceProfiles[Math.floor(Math.random() * deviceProfiles.length)];
    const deviceModel = profile.models[Math.floor(Math.random() * profile.models.length)];
    
    // Build numbers (realistic format based on manufacturer)
    const buildPrefix = profile.buildPrefixes[Math.floor(Math.random() * profile.buildPrefixes.length)];
    const buildSuffix = profile.buildSuffixes[Math.floor(Math.random() * profile.buildSuffixes.length)];
    const buildNumber = profile.buildNumbers[Math.floor(Math.random() * profile.buildNumbers.length)];
    const buildLetter = profile.buildLetters[Math.floor(Math.random() * profile.buildLetters.length)];
    
    // Different build formats for different manufacturers
    let buildString;
    if (deviceModel.includes('Pixel')) {
        buildString = `${buildPrefix}${buildSuffix}.${buildNumber}.${buildLetter}`;
    } else if (deviceModel.includes('ONEPLUS') || deviceModel.includes('OnePlus')) {
        buildString = `${buildPrefix}${buildSuffix}.${buildNumber}.${buildLetter}`;
    } else if (deviceModel.includes('Mi') || deviceModel.includes('Redmi') || deviceModel.includes('POCO')) {
        buildString = `${buildPrefix}${buildSuffix}.${buildNumber}.${buildLetter}`;
    } else {
        // Samsung format
        buildString = `${buildPrefix}.${buildSuffix}.${buildNumber}.${buildLetter}`;
    }
    
    // Chrome versions (141 is latest, include some variation)
    const chromeVersions = [
        '141.0.7390.54', '141.0.7390.53', '141.0.7390.52', 
        '140.0.7380.54', '140.0.7380.53', '140.0.7380.52',
        '139.0.7370.54', '139.0.7370.53'
    ];
    const chromeVersion = chromeVersions[Math.floor(Math.random() * chromeVersions.length)];
    
    // WebView version (usually 4.0 for Android)
    const webviewVersions = ['4.0', '4.1'];
    const webviewVersion = webviewVersions[Math.floor(Math.random() * webviewVersions.length)];
    
    // Construct User-Agent
    const userAgent = `Mozilla/5.0 (Linux; Android ${androidVersion}; ${deviceModel} Build/${buildString}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/${webviewVersion} Chrome/${chromeVersion} Safari/537.36`;
    
    return userAgent;
}

/**
 * Generate unique Android fingerprint for each profile
 * توليد بصمة Android فريدة لكل بروفايل
 */
export function generateAndroidFingerprint() {
    // Real Android device resolutions with device pixel ratio (DPR) from actual devices
    // مقاسات شاشة حقيقية للأندرويد من الأجهزة الفعلية مع نسبة البكسل
    const androidResolutions = [
        // Samsung Galaxy S24 Ultra
        { width: 1440, height: 3120, dpr: 3, screenSize: '6.8"', dpi: 501 },
        // Samsung Galaxy S23 Ultra
        { width: 1440, height: 3088, dpr: 3, screenSize: '6.8"', dpi: 500 },
        // Samsung Galaxy S22 Ultra
        { width: 1440, height: 3088, dpr: 3, screenSize: '6.8"', dpi: 500 },
        // Samsung Galaxy S21 Ultra
        { width: 1440, height: 3200, dpr: 3, screenSize: '6.8"', dpi: 515 },
        // Google Pixel 9 Pro
        { width: 1344, height: 2992, dpr: 3, screenSize: '6.3"', dpi: 514 },
        // Google Pixel 8 Pro
        { width: 1344, height: 2992, dpr: 3, screenSize: '6.7"', dpi: 489 },
        // Google Pixel 7 Pro
        { width: 1440, height: 3120, dpr: 3, screenSize: '6.7"', dpi: 512 },
        // OnePlus 12
        { width: 1440, height: 3168, dpr: 3, screenSize: '6.82"', dpi: 510 },
        // OnePlus 11
        { width: 1440, height: 3216, dpr: 3, screenSize: '6.7"', dpi: 525 },
        // Xiaomi 14 Pro
        { width: 1440, height: 3200, dpr: 3, screenSize: '6.73"', dpi: 522 },
        // Xiaomi 13 Pro
        { width: 1440, height: 3200, dpr: 3, screenSize: '6.73"', dpi: 522 },
        // Samsung Galaxy A54
        { width: 1080, height: 2340, dpr: 2.625, screenSize: '6.4"', dpi: 403 },
        // Samsung Galaxy A53
        { width: 1080, height: 2400, dpr: 2.625, screenSize: '6.5"', dpi: 405 },
        // Google Pixel 8
        { width: 1080, height: 2400, dpr: 2.625, screenSize: '6.2"', dpi: 428 },
        // Google Pixel 7
        { width: 1080, height: 2400, dpr: 2.625, screenSize: '6.3"', dpi: 416 },
        // OnePlus Nord 3
        { width: 1240, height: 2772, dpr: 3, screenSize: '6.74"', dpi: 451 },
        // Budget phones
        { width: 1080, height: 2340, dpr: 2, screenSize: '6.1"', dpi: 413 },
        { width: 720, height: 1600, dpr: 2, screenSize: '6.5"', dpi: 270 }
    ];
    const resolution = androidResolutions[Math.floor(Math.random() * androidResolutions.length)];
    
    // Languages (common Android languages)
    const languages = [
        'en-US,en;q=0.9',
        'en-GB,en;q=0.9',
        'ar-SA,ar;q=0.9,en;q=0.8',
        'es-ES,es;q=0.9',
        'fr-FR,fr;q=0.9',
        'de-DE,de;q=0.9'
    ];
    const language = languages[Math.floor(Math.random() * languages.length)];
    
    // Hardware specs (matched with resolution for realism)
    // مواصفات العتاد (مطابقة مع دقة الشاشة للحقيقة)
    let hardwareConcurrency, deviceMemory, maxTouchPoints;
    let hardwareConcurrencyOptions, deviceMemoryOptions;
    
    // Match hardware with resolution for realism
    if (resolution.width >= 1440) {
        // High-end devices - أجهزة عالية الجودة
        hardwareConcurrencyOptions = [8, 12];
        deviceMemoryOptions = [6, 8, 12];
        maxTouchPoints = 10;
    } else if (resolution.width >= 1240) {
        // Mid-high-end devices - أجهزة متوسطة-عالية
        hardwareConcurrencyOptions = [6, 8];
        deviceMemoryOptions = [4, 6, 8];
        maxTouchPoints = 10;
    } else if (resolution.width >= 1080) {
        // Mid-range devices - أجهزة متوسطة
        hardwareConcurrencyOptions = [4, 6, 8];
        deviceMemoryOptions = [3, 4, 6];
        maxTouchPoints = 5;
    } else {
        // Budget devices - أجهزة اقتصادية
        hardwareConcurrencyOptions = [4, 6];
        deviceMemoryOptions = [2, 3, 4];
        maxTouchPoints = 5;
    }
    
    hardwareConcurrency = hardwareConcurrencyOptions[Math.floor(Math.random() * hardwareConcurrencyOptions.length)];
    deviceMemory = deviceMemoryOptions[Math.floor(Math.random() * deviceMemoryOptions.length)];
    
    // Timezone (common timezones)
    const timezones = [
        'America/New_York',
        'America/Los_Angeles',
        'Europe/London',
        'Europe/Berlin',
        'Asia/Dubai',
        'Asia/Riyadh',
        'Asia/Kolkata',
        'Asia/Shanghai',
        'America/Sao_Paulo'
    ];
    const timezone = timezones[Math.floor(Math.random() * timezones.length)];
    
    // Platform (Android)
    const platform = 'Linux armv81';
    
    return {
        resolution: `${resolution.width}x${resolution.height}`,
        dpr: resolution.dpr, // Device Pixel Ratio
        screenSize: resolution.screenSize, // Screen size in inches
        dpi: resolution.dpi, // Dots per inch
        language,
        hardwareConcurrency,
        deviceMemory,
        maxTouchPoints,
        timezone,
        platform
    };
}

/**
 * Check if GPM API is available and responding
 * التحقق من أن GPM API متاح ويستجيب
 */
export async function checkGPMConnection() {
    try {
        const url = gpmApiUrl('/api/v3/profiles');
        const response = await sendControllerRequest('GPM API connection check', () =>
            controllerClient.get(url, { timeout: 5000 })
        );
        const payload = parseControllerPayload(response.data);
        if (payload?.success !== true || !Array.isArray(payload.data)) {
            throw new Error('GPM API did not return a successful profile list');
        }
        logger.info('GPM API is connected and responding');
        return true;
    } catch (error) {
        logger.error('GPM API connection check failed', controllerErrorDetails(error));
        return false;
    }
}

/**
 * Create a new profile in GPM
 * إنشاء بروفايل جديد في GPM
 */
export async function createProfile(profileName, proxy = null) {
    try {
        const timestamp = Date.now();
        const randomNum = Math.floor(Math.random() * 10000);
        let finalName = `Gmail_${timestamp}_${randomNum}`;
        
        // Clean name
        finalName = finalName.replace(/[^a-zA-Z0-9_]/g, '_');
        finalName = finalName.substring(0, 50);
        
        if (!finalName || finalName.trim().length === 0) {
            finalName = `Gmail_${timestamp}`;
        }
        
        // Generate realistic Android User-Agent
        const userAgent = generateAndroidUserAgent();
        
        // Generate unique Android fingerprint for this profile
        const fingerprint = generateAndroidFingerprint();
        
        logger.info('Generated Android fingerprint', {
            userAgent: userAgent.substring(0, 60) + '...',
            resolution: fingerprint.resolution,
            language: fingerprint.language,
            hardwareConcurrency: fingerprint.hardwareConcurrency,
            deviceMemory: fingerprint.deviceMemory,
            timezone: fingerprint.timezone
        });
        
        const requestBody = {
            profile_name: finalName,
            browser_core: "chromium",
            browser_name: "Chrome",
            user_agent: userAgent, // Set custom User-Agent
            is_masked_font: true,
            is_noise_webgl: false,
            is_noise_canvas: false,
            is_masked_webgl_data: true,
            is_masked_media_device: true,
            webrtc_mode: 2,
            // Add fingerprint parameters if GPM API supports them
            resolution: fingerprint.resolution,
            device_pixel_ratio: fingerprint.dpr, // Device Pixel Ratio for Android realism
            language: fingerprint.language,
            hardware_concurrency: fingerprint.hardwareConcurrency,
            device_memory: fingerprint.deviceMemory,
            max_touch_points: fingerprint.maxTouchPoints,
            timezone: fingerprint.timezone,
            platform: fingerprint.platform
        };
        
        logger.info('Using real Android device resolution', {
            resolution: fingerprint.resolution,
            dpr: fingerprint.dpr,
            screenSize: fingerprint.screenSize,
            dpi: fingerprint.dpi,
            hardware: {
                cores: fingerprint.hardwareConcurrency,
                ram: `${fingerprint.deviceMemory}GB`,
                touchPoints: fingerprint.maxTouchPoints
            }
        });
        
        if (config.omocaptcha.enabled) {
            requestBody.extension_ids = [config.omocaptcha.extensionId];
        }
        
        // GPM's raw proxy format here only represents HTTP and SOCKS5.
        if (proxy) {
            const proxyType = requireProxyProtocol(proxy, ['http', 'socks5', 'socks'], 'GPM Login');
            if (!proxy.ip || !proxy.port) {
                throw new Error('Proxy host and port are required');
            }
            let rawProxy = '';
            
            if (proxyType === 'socks5' || proxyType === 'socks') {
                if (proxy.username && proxy.password) {
                    rawProxy = `socks5://${proxy.ip}:${proxy.port}:${proxy.username}:${proxy.password}`;
                } else {
                    rawProxy = `socks5://${proxy.ip}:${proxy.port}`;
                }
            } else {
                if (proxy.username && proxy.password) {
                    rawProxy = `${proxy.ip}:${proxy.port}:${proxy.username}:${proxy.password}`;
                } else {
                    rawProxy = `${proxy.ip}:${proxy.port}`;
                }
            }
            
            requestBody.raw_proxy = rawProxy;
            logger.info('Creating profile with proxy', { protocol: proxyType });
        }
        
        logger.info('Creating GPM profile', { name: finalName, userAgent: userAgent.substring(0, 50) + '...' });
        
        const url = gpmApiUrl('/api/v3/profiles/create');
        const response = await sendControllerProfileCreate('GPM API create profile', () =>
            controllerClient.post(url, requestBody, {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                timeout: 10000
            })
        );

        const responseData = parseControllerPayload(response.data);
        if (typeof response.data === 'string' && responseData === undefined) {
            throw profileAllocationUnconfirmed(new Error('GPM API returned invalid JSON while creating a profile'));
        }

        if (controllerRejected(responseData)) {
            throw new Error('GPM API rejected profile creation');
        }

        const profile = responseData?.data ?? responseData;
        const id = requireCreatedProfileId(profile?.id);
        return { ...profile, id, userAgent };
    } catch (error) {
        logger.error('GPM API create profile failed', controllerErrorDetails(error));
        throw error;
    }
}

/**
 * Start a profile by ID
 * بدء بروفايل بالمعرف
 */
export async function startProfile(profileId, options = {}) {
    try {
        const params = new URLSearchParams();
        
        if (options.win_scale !== undefined && options.win_scale !== null) {
            params.append('win_scale', options.win_scale.toString());
        }
        
        if (options.win_pos) {
            params.append('win_pos', options.win_pos);
        }
        
        if (options.win_size) {
            params.append('win_size', options.win_size);
        }
        
        if (options.addination_args) {
            params.append('addination_args', options.addination_args);
        }
        
        let url = gpmApiUrl(`/api/v3/profiles/start/${profileIdPathComponent(profileId)}`);
        if (params.toString()) {
            url += `?${params.toString()}`;
        }
        
        const response = await sendControllerRequest('GPM API start profile', () =>
            controllerClient.get(url, { timeout: 30000 })
        );
        
        const payload = parseControllerPayload(response.data);
        const data = payload?.data ?? payload;
        if (controllerRejected(payload) || data?.success === false) {
            throw new Error('GPM API rejected profile startup');
        }
        if (data?.remote_debugging_address) {
            const endpoint = parseControllerUrl(data.remote_debugging_address, 'http:');
            validateControllerEndpoint(endpoint, parseControllerUrl(GPM_API_URL));
            return {
                driver_path: data.driver_path || '',
                remote_debugging_address: endpoint.href
            };
        }
        
        throw new Error('GPM API returned an invalid profile startup response');
    } catch (error) {
        logger.error('GPM API start profile failed', controllerErrorDetails(error));
        throw error;
    }
}

/**
 * Stop a profile by ID
 * إيقاف بروفايل بالمعرف
 */
export async function stopProfile(profileId, maxRetries = 3) {
    let url;
    try {
        url = gpmApiUrl(`/api/v3/profiles/stop/${profileIdPathComponent(profileId)}`);
    } catch (error) {
        logger.warn('GPM API stop profile failed', controllerErrorDetails(error));
        return false;
    }

    let lastError;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await sendControllerRequest('GPM API stop profile', () =>
                controllerClient.get(url, { timeout: 10000 }), gpmStopCode
            );
            if (controllerAcknowledged(response)) return true;
            break;
        } catch (error) {
            if (error.status === 404 && error.providerCode === 'PROFILE_NOT_FOUND') return true;
            if ((error.status === 400 || error.status === 409) && error.providerCode === 'PROFILE_ALREADY_STOPPED') return true;
            lastError = error;

            const retryable = ['ECONNREFUSED', 'ETIMEDOUT', 'ECONNRESET', 'ECONNABORTED'].includes(error.transportCode);
            if (!retryable || attempt === maxRetries) break;
            const delay = attempt * 1000;
            logger.warn('GPM API stop profile failed, retrying', {
                ...controllerErrorDetails(error), attempt, delay
            });
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    logger.error('GPM API stop profile failed', controllerErrorDetails(lastError));
    return false;
}

/**
 * Delete a profile
 * حذف بروفايل
 */
export async function deleteProfile(profileId, mode = 2) {
    try {
        const id = profileIdPathComponent(profileId);
        const query = new URLSearchParams({ mode });
        const url = gpmApiUrl(`/api/v3/profiles/delete/${id}?${query}`);
        const response = await sendControllerRequest('GPM API delete profile', () =>
            controllerClient.delete(url, {
                headers: { 'Accept': 'application/json' },
                timeout: 15000
            }), gpmMissingProfileCode
        );

        if (controllerAcknowledged(response)) {
            logger.info('GPM API profile deleted successfully', { profileId: id });
            return true;
        }
        throw new Error('GPM API did not confirm profile deletion');
    } catch (error) {
        if (error.status === 404 && error.providerCode === 'PROFILE_NOT_FOUND') return true;
        logger.error('GPM API delete profile failed', controllerErrorDetails(error));
        throw error;
    }
}

/**
 * Get profile by ID
 * الحصول على بروفايل بالمعرف
 */
export async function getProfile(profileId) {
    try {
        const url = gpmApiUrl(`/api/v3/profiles/${profileIdPathComponent(profileId)}`);
        const response = await sendControllerRequest('GPM API get profile', () =>
            controllerClient.get(url, { timeout: 10000 })
        );
        if (controllerRejected(response.data)) throw new Error('GPM API rejected the profile lookup');
        return response.data?.data || response.data;
    } catch (error) {
        logger.error('GPM API get profile failed', controllerErrorDetails(error));
        throw error;
    }
}

export default {
    checkGPMConnection,
    createProfile,
    startProfile,
    stopProfile,
    deleteProfile,
    getProfile,
    generateAndroidUserAgent,
    generateAndroidFingerprint
};

