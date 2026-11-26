/**
 * GoLogin API Client
 * عميل GoLogin API
 */

import dotenv from 'dotenv';
import axios from 'axios';
import net from 'node:net';
import logger from '../utils/logger.js';
import { profileIdPathComponent } from '../utils/controller-id.js';
import { controllerRequestOptions } from '../utils/controller-url.js';
import { loadPrivateEnvironment } from '../utils/private-env.js';
import { requireProxyProtocol } from '../utils/proxy-protocol.js';

loadPrivateEnvironment('.emv', '.env', () => !process.env.GOLOGIN_API_KEY, dotenv.parse, dotenv.decrypt);

const GOLOGIN_API_ORIGIN = 'https://api.gologin.com';

export function getGoLoginApiKey() {
    const apiKey = process.env.GOLOGIN_API_KEY;
    if (!apiKey) throw new Error('GOLOGIN_API_KEY is not set');
    return apiKey;
}

function goLoginApiUrl(endpoint) {
    if (typeof endpoint !== 'string' || !endpoint.startsWith('/') || endpoint.startsWith('//')
        || /[\\#\u0000-\u001f\u007f]/.test(endpoint)) {
        throw new Error('GoLogin API endpoint must be a root-relative path');
    }
    const url = new URL(endpoint, GOLOGIN_API_ORIGIN);
    if (url.origin !== GOLOGIN_API_ORIGIN) {
        throw new Error('GoLogin API endpoint must match the GoLogin API origin');
    }
    return url;
}

// The profile API's supported modes do not include HTTPS proxies.
function formatGoLoginProxy(proxy) {
    if (proxy == null) return proxy;
    const mode = requireProxyProtocol(proxy, ['http', 'socks4', 'socks5', 'none'], 'GoLogin');
    if (mode === 'none') return { mode };

    const host = (proxy.host || proxy.ip)?.trim();
    const port = Number(proxy.port);
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('Proxy host and a valid port are required');
    }
    return {
        mode,
        host,
        port,
        ...(proxy.username && { username: proxy.username.trim() }),
        ...(proxy.password && { password: proxy.password.trim() })
    };
}

/**
 * GoLogin API Client Class
 */
export class GoLoginClient {
    #apiKey;

    constructor(apiKey) {
        if (apiKey !== undefined && (typeof apiKey !== 'string' || !apiKey)) {
            throw new Error('A GoLogin API key is required');
        }
        this.#apiKey = apiKey;
    }

    /**
     * Make API request
     * إجراء طلب API
     */
    async request(method, endpoint, data = null, retries = 1) {
        const url = goLoginApiUrl(endpoint);
        const apiKey = this.#apiKey ?? getGoLoginApiKey();
        const config = {
            ...controllerRequestOptions,
            method,
            url: url.href,
            headers: {
                Authorization: `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            timeout: 30000,
            ...(data && { data })
        };

        let lastError;
        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                const response = await axios(config);
                return response.data;
            } catch (error) {
                lastError = error;
                const status = error.response?.status;
                const isServerError = status >= 500 && status < 600;
                const isRateLimit = status === 403 || status === 429;
                const isRetryable = isServerError || error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT';
                
                // Handle rate limit errors (403/429) with clear message
                if (isRateLimit) {
                    const errorData = error.response?.data;
                    const errorMessage = errorData?.error || errorData?.message || error.message;
                    const errorText = typeof errorData === 'string' ? errorData : errorMessage;
                    
                    // Extract more details from error if available
                    let detailedMessage = errorText;
                    if (status === 403) {
                        if (errorText.includes('free') || errorText.includes('limit') || errorText.includes('subscribe')) {
                            detailedMessage = 'You have reached your free API requests limit. Please subscribe to continue.';
                        }
                    }
                    
                    logger.error('GoLogin API rate limit reached', {
                        method,
                        endpoint,
                        status,
                        error: detailedMessage,
                        rawError: errorText,
                        suggestion: status === 403 
                            ? 'لقد وصلت إلى حد الطلبات المجانية لـ GoLogin API. الحلول:\n' +
                              '1. الاشتراك في خطة مدفوعة من https://app.gologin.com/\n' +
                              '2. الانتظار حتى يتم إعادة تعيين الحد (عادة شهرياً)\n' +
                              '3. استخدام حساب GoLogin آخر إذا كان متاحاً'
                            : 'تم تجاوز معدل الطلبات المسموح به. يرجى الانتظار قليلاً قبل إعادة المحاولة.'
                    });
                    // Don't retry on rate limit - throw immediately with clear message
                    const userMessage = status === 403 
                        ? `GoLogin API free limit reached: ${detailedMessage}. Please subscribe or wait for limit reset.`
                        : `GoLogin API rate limit exceeded: ${detailedMessage}. Please wait before retrying.`;
                    throw new Error(userMessage);
                }
                
                // Only retry on server errors or network issues
                if (isRetryable && attempt < retries) {
                    const waitTime = attempt * 1000; // 1s, 2s, 3s...
                    logger.warn(`API request failed, retrying... (${attempt}/${retries})`, {
                        method,
                        endpoint,
                        status,
                        waitTime: `${waitTime}ms`
                    });
                    await new Promise(resolve => setTimeout(resolve, waitTime));
                    continue;
                }
                
                // Log error only on final attempt or non-retryable errors
                if (!isRetryable || attempt === retries) {
                    logger.error('GoLogin API request failed', {
                        method,
                        endpoint,
                        status,
                        error: error.response?.data || error.message
                    });
                }
                throw error;
            }
        }
        throw lastError;
    }

    /**
     * Get all profiles
     * الحصول على جميع البروفايلات
     */
    async getProfiles(page = 1, limit = 50) {
        try {
            const response = await this.request(
                'GET',
                `/browser/v2?page=${page}&limit=${limit}&sorterField=createdAt&sorterOrder=descend`
            );
            return response;
        } catch (error) {
            throw new Error(`Failed to get profiles: ${error.message}`);
        }
    }

    /**
     * Create new profile
     * إنشاء بروفايل جديد
     * Uses /browser/custom endpoint as per GoLogin API documentation
     */
    /**
     * Generate unique Android fingerprint for each profile
     * توليد بصمة Android فريدة لكل بروفايل
     */
    generateAndroidFingerprint() {
        // Android versions
        const androidVersions = ['16', '15', '14', '13', '12'];
        const androidVersion = androidVersions[Math.floor(Math.random() * androidVersions.length)];
        
        // Multiple device manufacturers for more variety
        const deviceProfiles = [
            // Samsung devices
            {
                models: ['SM-S938U', 'SM-S928U', 'SM-S918U', 'SM-S908U', 'SM-S998U', 'SM-S988U'],
                buildPrefixes: ['BP2A', 'BP1A', 'AP3A', 'AP2A'],
                buildSuffixes: ['250605', '250505', '250405'],
                buildNumbers: ['031', '030', '029'],
                buildLetters: ['A3', 'A2', 'A1']
            },
            // Google Pixel devices
            {
                models: ['Pixel 9 Pro', 'Pixel 9', 'Pixel 8 Pro', 'Pixel 8', 'Pixel 7 Pro'],
                buildPrefixes: ['UP', 'TP'],
                buildSuffixes: ['1A', '2A', '3A'],
                buildNumbers: ['240805', '240705'],
                buildLetters: ['001', '002']
            },
            // OnePlus devices
            {
                models: ['ONEPLUS A6013', 'ONEPLUS A5010', 'ONEPLUS A3000'],
                buildPrefixes: ['OP'],
                buildSuffixes: ['28', '27'],
                buildNumbers: ['240805', '240705'],
                buildLetters: ['001']
            },
            // Xiaomi devices
            {
                models: ['Mi 14', 'Mi 13', 'Redmi Note 13', 'Redmi Note 12'],
                buildPrefixes: ['V', 'MIUI'],
                buildSuffixes: ['14', '13'],
                buildNumbers: ['240805', '240705'],
                buildLetters: ['001']
            }
        ];
        
        const profile = deviceProfiles[Math.floor(Math.random() * deviceProfiles.length)];
        const deviceModel = profile.models[Math.floor(Math.random() * profile.models.length)];
        
        // Build numbers
        const buildPrefix = profile.buildPrefixes[Math.floor(Math.random() * profile.buildPrefixes.length)];
        const buildSuffix = profile.buildSuffixes[Math.floor(Math.random() * profile.buildSuffixes.length)];
        const buildNumber = profile.buildNumbers[Math.floor(Math.random() * profile.buildNumbers.length)];
        const buildLetter = profile.buildLetters[Math.floor(Math.random() * profile.buildLetters.length)];
        
        let buildString;
        if (deviceModel.includes('Pixel')) {
            buildString = `${buildPrefix}${buildSuffix}.${buildNumber}.${buildLetter}`;
        } else {
            buildString = `${buildPrefix}.${buildSuffix}.${buildNumber}.${buildLetter}`;
        }
        
        // Chrome versions
        const chromeVersions = [
            '141.0.7390.54', '141.0.7390.53', '141.0.7390.52',
            '140.0.7380.54', '140.0.7380.53', '139.0.7370.54'
        ];
        const chromeVersion = chromeVersions[Math.floor(Math.random() * chromeVersions.length)];
        
        // WebView version
        const webviewVersion = Math.random() > 0.5 ? '4.0' : '4.1';
        
        // Generate User-Agent
        const userAgent = `Mozilla/5.0 (Linux; Android ${androidVersion}; ${deviceModel} Build/${buildString}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/${webviewVersion} Chrome/${chromeVersion} Safari/537.36`;
        
        // Screen resolutions (common Android phone resolutions)
        const resolutions = [
            { width: 1080, height: 2400 },
            { width: 1080, height: 2340 },
            { width: 1440, height: 3200 },
            { width: 1440, height: 3120 },
            { width: 1080, height: 2280 },
            { width: 1080, height: 2160 }
        ];
        const resolution = resolutions[Math.floor(Math.random() * resolutions.length)];
        
        // Language: Will be auto-detected based on proxy IP
        // اللغة: ستُحدد تلقائياً بناءً على IP البروكسي
        // Leave empty or use 'auto' to let GoLogin detect from proxy
        const language = ''; // Empty = auto-detect from proxy IP
        
        // Hardware specs (matched with resolution for realism)
        // مواصفات العتاد (مطابقة مع دقة الشاشة للحقيقة)
        let hardwareConcurrency, deviceMemory, maxTouchPoints;
        
        // Match hardware with resolution for realism
        if (resolution.width >= 1440) {
            // High-end devices
            hardwareConcurrencyOptions = [8, 12];
            deviceMemoryOptions = [6, 8, 12];
            maxTouchPoints = 10;
        } else if (resolution.width >= 1240) {
            // Mid-high-end devices
            hardwareConcurrencyOptions = [6, 8];
            deviceMemoryOptions = [4, 6, 8];
            maxTouchPoints = 10;
        } else if (resolution.width >= 1080) {
            // Mid-range devices
            hardwareConcurrencyOptions = [4, 6, 8];
            deviceMemoryOptions = [3, 4, 6];
            maxTouchPoints = 5;
        } else {
            // Budget devices
            hardwareConcurrencyOptions = [4, 6];
            deviceMemoryOptions = [2, 3, 4];
            maxTouchPoints = 5;
        }
        
        hardwareConcurrency = hardwareConcurrencyOptions[Math.floor(Math.random() * hardwareConcurrencyOptions.length)];
        deviceMemory = deviceMemoryOptions[Math.floor(Math.random() * deviceMemoryOptions.length)];
        
        // Additional Android-specific fingerprint parameters
        // معاملات البصمة الخاصة بالأندرويد
        const vendor = 'Google Inc. (Qualcomm)'; // Most Android devices use Qualcomm
        const renderer = 'Adreno (TM) 740'; // Common GPU for high-end Android
        
        // Timezone: Will be auto-detected based on proxy IP
        // المنطقة الزمنية: ستُحدد تلقائياً بناءً على IP البروكسي
        // Leave empty or use 'auto' to let GoLogin detect from proxy
        const timezone = ''; // Empty = auto-detect from proxy IP
        
        return {
            navigator: {
                userAgent,
                resolution: `${resolution.width}x${resolution.height}`,
                language,
                platform: 'Linux armv81',
                hardwareConcurrency,
                deviceMemory,
                maxTouchPoints
            },
            // Screen size and pixel ratio for realism
            // حجم الشاشة ونسبة البكسل للحقيقة
            devicePixelRatio: resolution.dpr,
            // Canvas fingerprinting with noise
            canvas: { 
                mode: 'noise',
                noise: Math.random() * 0.00001 // Random noise value
            },
            // WebGL fingerprinting with noise
            webGL: { 
                mode: 'noise',
                getClientRectsNoise: Math.random() * 10, // Random noise for client rects
                noise: Math.random() * 100 // Random noise value
            },
            // AudioContext fingerprinting with noise
            audioContext: { 
                mode: 'noise',
                noise: Math.random() * 0.000000001 // Random noise value
            },
            // WebGL Metadata with realistic vendor/renderer
            webGLMetadata: { 
                mode: 'mask',
                vendor: vendor,
                renderer: renderer
            },
            // Client rects noise
            clientRects: {
                mode: 'noise',
                noise: Math.random() * 10 // Random noise value
            },
            // Timezone
            timezone: {
                enabled: true,
                fillBasedOnIp: false,
                timezone
            },
            // Additional Android-specific settings
            // إعدادات إضافية خاصة بالأندرويد
            fonts: {
                families: [
                    'Roboto',
                    'Noto Sans',
                    'Roboto Condensed',
                    'Noto Sans Arabic',
                    'Noto Sans CJK',
                    'sans-serif'
                ],
                enableMasking: true,
                enableDomRect: true
            },
            // Media devices (cameras, microphones)
            mediaDevices: {
                enableMasking: true,
                videoInputs: 1, // Most phones have 1 front camera + 1-3 back cameras
                audioInputs: 1, // 1 microphone
                audioOutputs: 1 // 1 speaker/headphone jack
            },
            // Battery API (Android devices have batteries)
            battery: {
                charging: Math.random() > 0.3, // 70% chance of charging
                level: Math.random() * 0.5 + 0.5, // Battery level between 50-100%
                chargingTime: Math.random() > 0.3 ? Math.floor(Math.random() * 3600) : Infinity,
                dischargingTime: Math.random() > 0.3 ? Math.floor(Math.random() * 7200) : Infinity
            }
        };
    }

    async createProfile(profileData, testProxyConnection = false) {
        try {
            const proxy = formatGoLoginProxy(profileData.proxy);
            // Creation and the optional proxy update use the same credential.
            const client = this.#apiKey === undefined ? new GoLoginClient(getGoLoginApiKey()) : this;
            if (testProxyConnection && proxy?.mode === 'http') {
                const address = `${proxy.host}:${proxy.port}`;
                logger.info('Checking proxy TCP reachability before creating profile', { proxy: address });
                try {
                    const result = await this.testProxy(proxy);
                    if (!result.valid) {
                        logger.warn('Proxy preflight unsuccessful, continuing with profile creation', {
                            proxy: address,
                            error: result.error
                        });
                    }
                } catch (error) {
                    logger.warn('Proxy test failed, but continuing with profile creation', {
                        proxy: address,
                        error: error.message
                    });
                }
            }
            // Generate unique Android fingerprint for each profile
            // توليد بصمة Android فريدة لكل بروفايل
            const uniqueFingerprint = this.generateAndroidFingerprint();
            
            logger.info('Generated unique Android fingerprint', {
                userAgent: uniqueFingerprint.navigator.userAgent.substring(0, 60) + '...',
                resolution: uniqueFingerprint.navigator.resolution,
                language: uniqueFingerprint.navigator.language,
                hardwareConcurrency: uniqueFingerprint.navigator.hardwareConcurrency,
                deviceMemory: uniqueFingerprint.navigator.deviceMemory,
                timezone: uniqueFingerprint.timezone.timezone
            });

            // Base profile with required os parameter
            const defaultProfile = {
                os: 'android', // Required: win, mac, lin, android
                browserType: 'chrome', // Required for /browser/custom
                name: profileData.name || `Profile_${Date.now()}`,
                // Use unique Android fingerprint for each profile
                navigator: uniqueFingerprint.navigator,
                // Use unique fingerprint settings
                canvas: uniqueFingerprint.canvas,
                webGL: uniqueFingerprint.webGL,
                audioContext: uniqueFingerprint.audioContext,
                webGLMetadata: uniqueFingerprint.webGLMetadata,
                clientRects: uniqueFingerprint.clientRects,
                // Use unique timezone
                timezone: uniqueFingerprint.timezone,
                // Use unique fonts
                fonts: uniqueFingerprint.fonts,
                // Use unique media devices
                mediaDevices: uniqueFingerprint.mediaDevices,
                // Device pixel ratio
                devicePixelRatio: uniqueFingerprint.devicePixelRatio,
                // Optional: geolocation
                geolocation: {
                    mode: 'prompt',
                    enabled: true,
                    fillBasedOnIp: true
                },
                // Optional: webRTC
                webRTC: {
                    mode: 'alerted',
                    enabled: true,
                    fillBasedOnIp: true
                },
                // Merge with provided profileData (proxy, etc.) - this overrides defaults
                ...profileData,
                proxy
            };

            // Use /browser/custom endpoint with unique fingerprint for better authenticity
            // استخدام /browser/custom مع بصمة فريدة لمصداقية أفضل
            // Create profile using /browser/custom with unique Android fingerprint
            // Retry up to 2 times for server errors
            const response = await client.request('POST', '/browser/custom', defaultProfile, 2);
            logger.info('Profile created using /browser/custom with unique Android fingerprint', { 
                profileId: response.id,
                userAgent: uniqueFingerprint.navigator.userAgent.substring(0, 60) + '...'
            });
            
            // Update proxy separately if provided (uses dedicated PATCH endpoint - more efficient)
            // تحديث البروكسي بشكل منفصل إذا تم توفيره (استخدام PATCH endpoint مخصص - أكثر كفاءة)
            if (defaultProfile.proxy && defaultProfile.proxy.mode && defaultProfile.proxy.mode !== 'none') {
                try {
                    logger.info('Updating profile proxy', { 
                        profileId: response.id,
                        proxy: {
                            mode: defaultProfile.proxy.mode,
                            host: defaultProfile.proxy.host,
                            port: defaultProfile.proxy.port,
                            hasUsername: !!defaultProfile.proxy.username,
                            hasPassword: !!defaultProfile.proxy.password
                        }
                    });
                    await client.updateProfileProxy(response.id, defaultProfile.proxy);
                    logger.info('Proxy updated successfully', { profileId: response.id });
                    // Update response with proxy info for later use
                    response.proxy = defaultProfile.proxy;
                } catch (proxyError) {
                    logger.warn('Failed to update proxy, continuing anyway', { 
                        profileId: response.id,
                        error: proxyError.message
                    });
                }
            }
            
            // Profile already created with unique fingerprint, no need to update
            // البروفايل تم إنشاؤه بالفعل ببصمة فريدة، لا حاجة للتحديث
            
            logger.info('Profile created', { 
                profileId: response.id, 
                name: response.name,
                userAgent: response.navigator?.userAgent?.substring(0, 50) + '...'
            });
            return response;
        } catch (error) {
            throw new Error(`Failed to create profile: ${error.message}`);
        }
    }

    /**
     * Update profile
     * تحديث بروفايل
     */
    async updateProfile(profileId, updates) {
        // Retry up to 2 times for server errors
        const data = updates?.proxy ? { ...updates, proxy: formatGoLoginProxy(updates.proxy) } : updates;
        const response = await this.request('PUT', `/browser/${profileIdPathComponent(profileId)}`, data, 2);
        logger.info('Profile updated', { profileId });
        return response;
    }

    /**
     * Update profile proxy (dedicated endpoint - more efficient)
     * تحديث بروكسي البروفايل (endpoint مخصص - أكثر كفاءة)
     */
    async updateProfileProxy(profileId, proxyData) {
        // Use dedicated proxy endpoint (PATCH /browser/:id/proxy)
        // This only requires proxy data, not full profile update
        // Retry up to 2 times for server errors
        await this.request('PATCH', `/browser/${profileIdPathComponent(profileId)}/proxy`, formatGoLoginProxy(proxyData), 2);
        logger.info('Profile proxy updated', { profileId });
        return true;
    }

    /**
     * Delete profile
     * حذف بروفايل
     */
    async deleteProfile(profileId) {
        try {
            await this.request('DELETE', `/browser/${profileIdPathComponent(profileId)}`);
            logger.info('Profile deleted', { profileId });
            return true;
        } catch (error) {
            throw new Error(`Failed to delete profile: ${error.message}`);
        }
    }

    /**
     * Get profile by ID
     * الحصول على بروفايل بالمعرف
     */
    async getProfile(profileId) {
        try {
            const response = await this.request('GET', `/browser/${profileIdPathComponent(profileId)}`);
            return response;
        } catch (error) {
            throw new Error(`Failed to get profile: ${error.message}`);
        }
    }

    /**
     * Start profile (get browser connection details)
     * بدء البروفايل (الحصول على تفاصيل الاتصال)
     */
    async startProfile(profileId) {
        try {
            const response = await this.request('GET', `/browser/${profileIdPathComponent(profileId)}`);
            return response;
        } catch (error) {
            throw new Error(`Failed to start profile: ${error.message}`);
        }
    }

    /**
     * Stop profile
     * إيقاف البروفايل
     */
    async stopProfile(profileId) {
        const id = profileIdPathComponent(profileId);
        logger.warn('Stopping a GoLogin profile by ID is unsupported. Use the running session to stop it.', {
            profileId: id
        });
        return false;
    }

    /**
     * Check if an HTTP proxy endpoint accepts a TCP connection.
     */
    async testProxy(proxy) {
        const address = proxy?.host || proxy?.ip;
        const hostname = typeof address === 'string' ? address.trim() : '';
        if (!hostname || !proxy.port) {
            return { valid: false, error: 'Proxy data is missing' };
        }

        try {
            requireProxyProtocol(proxy, ['http'], 'GoLogin proxy preflight');
            if (proxy.username || proxy.password) {
                return { valid: false, error: 'Authenticated GoLogin proxy preflight requires HTTPS' };
            }

            const host = hostname.replace(/^\[([^\]]+)\]$/, '$1');
            const port = Number(proxy.port);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                return { valid: false, error: 'Invalid proxy port' };
            }

            return await new Promise(resolve => {
                const socket = net.createConnection({ host, port, timeout: 5000 });
                const finish = result => {
                    socket.destroy();
                    resolve(result);
                };
                socket.once('connect', () => finish({ valid: true, ip: hostname }));
                socket.once('error', error => finish({ valid: false, error: error.message }));
                socket.once('timeout', () => finish({ valid: false, error: 'Connection timeout' }));
            });
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }

    /**
     * Create profile with proxy
     * إنشاء بروفايل مع بروكسي
     */
    async createProfileWithProxy(name, proxy, testProxyConnection = true) {
        return this.createProfile({ name, proxy }, testProxyConnection);
    }
}

export default new GoLoginClient();

