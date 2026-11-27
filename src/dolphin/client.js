/**
 * Dolphin Anty API Client
 * عميل Dolphin Anty API
 */

import axios from 'axios';
import logger from '../utils/logger.js';
import { generateAndroidUserAgent } from '../gpmlogin/client.js';
import { generateAndroidFingerprint } from '../gpmlogin/client.js';
import config from '../config.js';
import {
    controllerApiUrl,
    controllerRequestOptions,
    parseControllerUrl,
    toWebSocketUrl,
    validateControllerEndpoint
} from '../utils/controller-url.js';
import { requireControllerProfileId } from '../utils/controller-id.js';
import {
    controllerAcknowledged,
    controllerErrorDetails,
    controllerRejected,
    parseControllerPayload,
    requireCreatedProfileId,
    sendControllerProfileCreate,
    sendControllerRequest
} from '../utils/controller-request.js';
import { requireProxyProtocol } from '../utils/proxy-protocol.js';

const DOLPHIN_API_URL = config.dolphin.apiUrl;
const DOLPHIN_API_KEY = config.dolphin.apiKey;
const controllerClient = axios.create(controllerRequestOptions);

function getAuthHeader() {
    if (!DOLPHIN_API_KEY.trim()) {
        throw new Error('DOLPHIN_API_KEY is required in .env');
    }
    return DOLPHIN_API_KEY;
}

function dolphinErrorCode(data) {
    if (typeof data === 'string') {
        try {
            data = JSON.parse(data);
        } catch {
            return undefined;
        }
    }
    // 12001 denotes a duplicate folder name. 50200 denotes insufficient permissions.
    const code = data?.code;
    if (code === 12001 || code === '12001') return '12001';
    if (code === 50200 || code === '50200') return '50200';
}

function dolphinPost(operation, path, body, timeout, { authorization, allocatesProfile = false } = {}) {
    const url = controllerApiUrl(DOLPHIN_API_URL, path, 'DOLPHIN_TRUSTED_HTTP_API_URL');
    const auth = authorization ?? getAuthHeader();
    const send = allocatesProfile ? sendControllerProfileCreate : sendControllerRequest;
    return send(operation, () => controllerClient.post(url, body, {
        headers: { Authorization: auth, 'Content-Type': 'application/json' },
        timeout
    }), dolphinErrorCode);
}

function readJsonResponse(data, operation) {
    if (typeof data !== 'string') return data;
    try {
        return JSON.parse(data);
    } catch {
        throw new Error(`${operation} returned invalid JSON`);
    }
}

/**
 * Check if Dolphin API is available and responding
 * التحقق من أن Dolphin API متاح ويستجيب
 */
export async function checkDolphinConnection() {
    try {
        const response = await dolphinPost('Dolphin Anty API connection check', '/api/profile/getProfiles',
            { page: 1, pageSize: 1 }, 5000);
        const data = parseControllerPayload(response.data);
        if (response.status !== 200 || data?.success === false || !Array.isArray(data?.list)) {
            logger.error('Dolphin Anty API connection check did not return a profile list');
            return false;
        }
        logger.info('Dolphin Anty API is connected and responding');
        return true;
    } catch (error) {
        logger.error('Dolphin Anty API connection check failed', controllerErrorDetails(error));
        return false;
    }
}

// The base-proxy API uses the same protocol and credential fields on create and update.
function formatBaseProxy(proxy) {
    if (!proxy) throw new Error('Proxy host and port are required');
    const protocol = requireProxyProtocol(proxy, ['http', 'https', 'socks4', 'socks5'], 'Dolphin Anty');
    const host = (proxy.host || proxy.ip)?.trim();
    const port = Number(proxy.port);
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('Proxy host and a valid port are required');
    }
    return {
        proxyMethod: 0,
        protocol,
        host,
        port,
        proxyUsername: proxy.username || proxy.proxyUsername || '',
        proxyPassword: proxy.password || proxy.proxyPassword || ''
    };
}

/**
 * Create a new profile in Dolphin Anty
 * إنشاء بروفايل جديد في Dolphin Anty
 */
export async function createProfile(profileName, proxy = null) {
    try {
        const proxyObj = proxy ? formatBaseProxy(proxy) : null;
        if (proxyObj) {
            proxyObj.proxyUsername = proxyObj.proxyUsername.trim();
            proxyObj.proxyPassword = proxyObj.proxyPassword.trim();
        }
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
        
        logger.info('Generated Android fingerprint for Dolphin', {
            userAgent: userAgent.substring(0, 60) + '...',
            resolution: fingerprint.resolution,
            language: fingerprint.language,
            hardwareConcurrency: fingerprint.hardwareConcurrency,
            deviceMemory: fingerprint.deviceMemory,
            timezone: fingerprint.timezone,
            dpr: fingerprint.dpr
        });
        
        // Extract device model from User-Agent for uamodel field
        const uaMatch = userAgent.match(/Android \d+; ([^)]+)/);
        const uamodel = uaMatch ? uaMatch[1] : null;
        
        // Parse resolution width and height
        const [width, height] = fingerprint.resolution.split('x').map(Number);
        
        // Generate random realistic WebGL configuration (Real hardware GPUs)
        // توليد إعدادات WebGL عشوائية واقعية (GPUs حقيقية)
        const webglConfigs = [
            { manufacturer: 'Qualcomm', renderer: 'Adreno (TM) 650' },
            { manufacturer: 'Qualcomm', renderer: 'Adreno (TM) 730' },
            { manufacturer: 'Qualcomm', renderer: 'Adreno (TM) 740' },
            { manufacturer: 'Qualcomm', renderer: 'Adreno (TM) 660' },
            { manufacturer: 'ARM', renderer: 'Mali-G78' },
            { manufacturer: 'ARM', renderer: 'Mali-G710' },
            { manufacturer: 'ARM', renderer: 'Mali-G77' },
            { manufacturer: 'Samsung', renderer: 'Xclipse 920' },
            { manufacturer: 'Samsung', renderer: 'Xclipse 930' },
        ];
        const selectedWebgl = webglConfigs[Math.floor(Math.random() * webglConfigs.length)];
        
        // Generate random resolution (common Android resolutions)
        // توليد دقة عشوائية (دقات Android شائعة)
        const resolutions = [
            { res: '360x720', dpr: 2.0 },
            { res: '360x740', dpr: 2.0 },
            { res: '360x780', dpr: 2.0 },
            { res: '360x800', dpr: 2.0 },
            { res: '412x732', dpr: 2.625 },
            { res: '412x869', dpr: 2.625 },
            { res: '412x892', dpr: 2.625 },
            { res: '393x873', dpr: 2.75 },
            { res: '384x854', dpr: 2.0 },
        ];
        const selectedResolution = resolutions[Math.floor(Math.random() * resolutions.length)];
        
        // Generate random Android device and User-Agent
        // توليد جهاز Android و User-Agent عشوائي
        const androidDevices = [
            { model: 'SM-S938U', build: 'BP2A.250605.031.A3', android: 16 },
            { model: 'SM-G998B', build: 'SP1A.210812.016', android: 14 },
            { model: 'SM-S928B', build: 'UP1A.231005.007', android: 14 },
            { model: 'Pixel 8 Pro', build: 'AP2A.240805.005', android: 15 },
            { model: 'Pixel 9', build: 'AP3A.241005.015', android: 15 },
            { model: 'SM-A546B', build: 'UP1A.231005.007', android: 14 },
            { model: 'OnePlus 12', build: 'TP1A.220624.014', android: 14 },
        ];
        const selectedDevice = androidDevices[Math.floor(Math.random() * androidDevices.length)];
        
        // Generate random Chrome version
        const chromeVersions = ['141.0.7390.54', '141.0.7390.111', '142.0.7444.138', '140.0.7259.132'];
        const selectedChromeVersion = chromeVersions[Math.floor(Math.random() * chromeVersions.length)];
        const chromeMajor = selectedChromeVersion.split('.')[0];
        
        // Build random User-Agent
        const randomUserAgent = `Mozilla/5.0 (Linux; Android ${selectedDevice.android}; ${selectedDevice.model} Build/${selectedDevice.build}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/${selectedChromeVersion} Safari/537.36`;
        
        // Generate random hardware concurrency (4-8 cores)
        const hardwareConcurrency = 4 + Math.floor(Math.random() * 5); // 4-8
        
        // Build fingerprint object for Dolphin API - with random realistic values
        // بناء كائن fingerprint لـ Dolphin API - بقيم عشوائية واقعية
        const fingerprintObj = {
            // OS and Browser Settings
            // إعدادات النظام والمتصفح
            os: 'Linux armv81', // Android
            osVersion: selectedDevice.android.toString(), // Random Android version
            product: 'chrome', // Browser product
            coreVersion: chromeMajor, // Chrome major version
            uaFullVersion: selectedChromeVersion, // Full UA version
            userAgent: randomUserAgent, // Random User-Agent
            
            // Profile Size: 500 x 950
            // حجم البروفايل: 500 x 950
            openWidth: 500,
            openHeight: 950,
            
            // Resolution: Random from common Android resolutions
            // الدقة: عشوائية من دقات Android الشائعة
            resolution: selectedResolution.res,
            devicePixelRatio: selectedResolution.dpr,
            
            // Language: Based on proxy IP
            // اللغة: بناءً على IP البروكسي
            languageFollowIp: true, // Generate language based on IP
            uiLanguageType: 2, // 2 = Follow system
            
            // Timezone: Based on proxy IP
            // المنطقة الزمنية: بناءً على IP البروكسي
            timeZoneFollowIp: true, // Generate timezone based on IP
            
            // Fonts: Random (masks font fingerprint)
            // الخطوط: عشوائية (تخفي بصمة الخط)
            randomFonts: true,
            
            // Hardware noise - all enabled for better anti-detection
            // ضوضاء الأجهزة - جميعها مفعلة لمكافحة الاكتشاف
            canvasNoise: true, // Prevents canvas fingerprinting
            webglNoise: true, // Prevents WebGL fingerprinting
            audioContextNoise: true, // Prevents audio fingerprinting
            clientRectsNoise: true, // Prevents element positioning fingerprinting
            mediaDeviceNoise: true, // Masks media device IDs
            speechVoiceNoise: true, // Masks speech synthesis voices
            
            // WebGL meta: Real hardware GPU (not SwiftShader!)
            // WebGL meta: GPU حقيقي (ليس SwiftShader!)
            webGLMeta: true,
            webGLManufacturer: selectedWebgl.manufacturer,
            webGLRender: selectedWebgl.renderer,
            
            // WebRTC: Replace (privacy mode - prevents IP leakage)
            // WebRTC: استبدال (وضع الخصوصية - يمنع تسريب IP)
            webRTC: 'replace', // replace = Replace mode
            
            // Geolocation: Based on proxy IP (better than Ask me!)
            // الموقع الجغرافي: بناءً على IP البروكسي (أفضل من Ask me!)
            geolocation: 2, // 2 = Based on proxy IP (not 1 = ask)
            geolocationFollowIp: true, // Generate geolocation based on IP
            
            // Hardware concurrency: Random (4-8 cores)
            // عدد المعالجات: عشوائي (4-8 أنوية)
            hardwareConcurrency: hardwareConcurrency,
            
            // Do not track: Disabled (more human-like)
            // عدم التتبع: معطل (أكثر شبهاً بالإنسان)
            doNotTrack: false,
            
            // Port Scan Protection: Enabled
            // حماية من مسح المنافذ: مفعل
            portScanProtection: true,
            
            // HTTPS certificate errors: Ignore (Disabled)
            // أخطاء شهادة HTTPS: تجاهل (معطل)
            ignoreHttpsErrors: false
        };
        
        logger.info('Generated random fingerprint for Dolphin', {
            device: selectedDevice.model,
            android: selectedDevice.android,
            chrome: chromeMajor,
            resolution: selectedResolution.res,
            webgl: `${selectedWebgl.manufacturer} - ${selectedWebgl.renderer}`,
            cores: hardwareConcurrency
        });
        
        const folderId = config.dolphin.folderId.trim() || await getOrCreateFolder('gmail-accounts');
        const requestBody = {
            title: finalName,
            folderId: String(folderId),
            fingerprint: fingerprintObj
        };
        if (proxyObj) requestBody.proxy = proxyObj;

        const operation = 'Dolphin Anty API create profile';
        logger.info('Creating Dolphin Anty profile', { name: finalName, hasProxy: !!proxyObj });
        const response = await dolphinPost(operation, '/api/profile/advancedCreateProfile', requestBody, 30000,
            { allocatesProfile: true });
        const data = parseControllerPayload(response.data);
        if (data === false || data?.success === false) throw new Error('Dolphin Anty API rejected profile creation');

        const id = requireCreatedProfileId(data?.id);
        logger.info('Dolphin Anty profile created successfully', { name: finalName });
        return { id, profileId: id, title: data.title || finalName, userAgent };
    } catch (error) {
        logger.error('Dolphin Anty API create profile failed', controllerErrorDetails(error));
        throw error;
    }
}

/**
 * Start a profile by ID
 * بدء بروفايل بالمعرف
 */
export async function startProfile(profileId) {
    try {
        const operation = 'Dolphin Anty API start profile';
        const id = requireControllerProfileId(profileId);
        const response = await dolphinPost(operation, '/api/browser/openBrowser', { profileId: id }, 60000);
        const data = readJsonResponse(response.data, operation);
        const address = data?.ws || data?.webSocketDebuggerUrl;
        if (address && data.success !== false) {
            const endpoint = toWebSocketUrl(parseControllerUrl(address, 'ws:'));
            validateControllerEndpoint(endpoint, parseControllerUrl(DOLPHIN_API_URL));
            logger.info('Dolphin Anty profile started successfully');
            return { ws: endpoint.href, webSocketDebuggerUrl: endpoint.href, port: data.port, pid: data.pid };
        }

        throw new Error('Dolphin Anty API returned an invalid profile startup response');
    } catch (error) {
        logger.error('Dolphin Anty API start profile failed', controllerErrorDetails(error));
        throw error;
    }
}

/**
 * Stop a profile by ID
 * إيقاف بروفايل بالمعرف
 */
export async function stopProfile(profileId) {
    try {
        const response = await dolphinPost('Dolphin Anty API stop profile', '/api/browser/closeProfiles',
            { profileIds: [requireControllerProfileId(profileId)] }, 10000);
        if (!controllerAcknowledged(response)) {
            logger.warn('Dolphin Anty API did not confirm profile closure');
            return false;
        }
        logger.info('Dolphin Anty profile stopped successfully');
        return true;
    } catch (error) {
        logger.warn('Dolphin Anty API stop profile failed', controllerErrorDetails(error));
        return false;
    }
}

/**
 * Move a profile to the recycle bin.
 */
export async function recycleProfile(profileId) {
    try {
        const id = String(requireControllerProfileId(profileId));
        const response = await dolphinPost('Dolphin Anty API recycle profile', '/api/profile/moveProfiletoRecycle',
            { ids: [id] }, 10000);
        if (response.status !== 200 || !controllerAcknowledged(response)) {
            throw new Error('Dolphin Anty API did not confirm profile recycling');
        }
        logger.info('Dolphin Anty profile moved to the recycle bin');
        return true;
    } catch (error) {
        logger.error('Dolphin Anty API recycle profile failed', controllerErrorDetails(error));
        throw error;
    }
}

export async function deleteProfile() {
    throw new Error('Permanent Dolphin Anty profile deletion is unavailable through the documented controller API');
}

/**
 * Get profile details by ID
 * الحصول على تفاصيل البروفايل بالمعرف
 */
export async function getProfile(profileId) {
    try {
        const id = requireControllerProfileId(profileId);
        const response = await dolphinPost('Dolphin Anty API get profile', '/api/profile/detail', { profileId: id }, 10000);
        if (controllerRejected(response.data)) throw new Error('Dolphin Anty API rejected the profile lookup');
        return response.data;
    } catch (error) {
        logger.error('Dolphin Anty API get profile failed', controllerErrorDetails(error));
        throw error;
    }
}

/**
 * Update profile's base proxy
 * تحديث البروكسي الأساسي للبروفايل
 * @param {string|string[]} profileIds - Profile ID or array of profile IDs
 * @param {Object} proxy - Proxy configuration object
 * @param {string} proxy.host - Proxy host/IP
 * @param {number} proxy.port - Proxy port
 * @param {string} proxy.protocol - Proxy protocol (http, https, socks4, socks5)
 * @param {string} proxy.username - Proxy username (optional)
 * @param {string} proxy.password - Proxy password (optional)
 */
export async function updateProfileProxy(profileIds, proxy) {
    try {
        const ids = Array.from(Array.isArray(profileIds) ? profileIds : [profileIds], requireControllerProfileId);
        if (ids.length === 0) throw new Error('At least one Dolphin Anty profile ID is required');
        const requestBody = { ...formatBaseProxy(proxy), ids };

        const response = await dolphinPost('Dolphin Anty API update profile proxy', '/api/profile/updateProfileBaseProxy',
            requestBody, 15000);
        if (controllerRejected(response.data)) throw new Error('Dolphin Anty API rejected the proxy update');
        logger.info('Dolphin Anty profile proxy updated successfully');
        return {
            success: true,
            profileIds: ids,
            proxy: {
                host: requestBody.host,
                port: requestBody.port,
                protocol: requestBody.protocol
            }
        };
    } catch (error) {
        logger.error('Dolphin Anty API update profile proxy failed', controllerErrorDetails(error));
        throw error;
    }
}

/**
 * Get folder list
 * الحصول على قائمة المجلدات
 */
export async function getFolderList(page = 1, pageSize = 100) {
    const operation = 'Dolphin Anty API list folders';
    const auth = getAuthHeader();
    const request = authorization => dolphinPost(operation, '/api/folder/list', { page, pageSize }, 10000, { authorization });
    let response;
    try {
        response = await request(auth);
    } catch (error) {
        if (error.status !== 401 || auth.startsWith('Bearer ')) throw error;
        response = await request(`Bearer ${auth}`);
    }
    const data = readJsonResponse(response.data, operation);
    if (controllerRejected(data)) throw new Error('Dolphin Anty API rejected the folder lookup');
    return data;
}

function folderListItems(data) {
    if (Array.isArray(data)) return data;
    const folders = [data?.list, data?.data, data?.folders].find(Array.isArray);
    if (!folders) {
        throw new Error('Dolphin Anty API returned an invalid folder list');
    }
    return folders;
}

function readFolderId(folder) {
    const id = folder?.id ?? folder?.folderId;
    if (Number.isSafeInteger(id) && id >= 0) return id;
    return typeof id === 'string' && id.trim() ? id : null;
}

/**
 * Get all folders (across all pages)
 * الحصول على جميع المجلدات (عبر جميع الصفحات)
 */
export async function getAllFolders() {
    const pageSize = 100;
    const allFolders = [];
    for (let page = 1; ; page++) {
        const data = await getFolderList(page, pageSize);
        const folders = folderListItems(data);
        allFolders.push(...folders);
        const total = Number(data.total);
        if (folders.length === 0 || !Number.isSafeInteger(total) || allFolders.length >= total) return allFolders;
    }
}

/**
 * Find a uniquely named folder
 * البحث عن مجلد بالاسم
 */
export async function findFolderByName(folderName) {
    if (typeof folderName !== 'string' || !folderName.trim()) throw new Error('Dolphin Anty folder name is required');
    const folders = await getAllFolders();
    const matches = folders.filter(folder => (folder?.folderName ?? folder?.name) === folderName);
    if (matches.length > 1) {
        throw new Error('Multiple Dolphin Anty folders match the desired name. Set DOLPHIN_FOLDER_ID explicitly.');
    }
    if (matches.length === 0) return null;

    const id = readFolderId(matches[0]);
    if (id === null) {
        throw new Error('The intended Dolphin Anty folder has no valid ID. Set DOLPHIN_FOLDER_ID explicitly.');
    }
    return id;
}

/**
 * Create a new folder
 * إنشاء مجلد جديد
 */
export async function createFolder(folderName, folderColor = '#3370FF', sortOrder = 0) {
    const operation = 'Dolphin Anty API create folder';
    try {
        const response = await dolphinPost(operation, '/api/folder/add', { folderName, folderColor, sortOrder }, 10000);
        const data = readJsonResponse(response.data, operation);
        const id = readFolderId(data);
        if (id !== null && data.success !== false) return id;
        throw new Error('Dolphin Anty API returned an invalid folder creation response');
    } catch (error) {
        if (error.providerCode === '12001') {
            // A concurrent creator may have created the same named folder.
            const existingFolderId = await findFolderByName(folderName).catch(() => null);
            if (existingFolderId !== null) return existingFolderId;
        }
        throw error;
    }
}

/**
 * Get the first visible folder on explicit request
 * الحصول على أول مجلد متاح من القائمة
 */
export async function getFirstAvailableFolder() {
    const [folder] = folderListItems(await getFolderList(1, 100));
    return readFolderId(folder);
}

/**
 * Get or create folder by name
 * الحصول على مجلد بالاسم أو إنشاؤه
 */
export async function getOrCreateFolder(folderName, folderColor = '#3370FF') {
    const existingFolderId = await findFolderByName(folderName);
    return existingFolderId ?? createFolder(folderName, folderColor);
}

export default {
    checkDolphinConnection,
    createProfile,
    startProfile,
    stopProfile,
    recycleProfile,
    deleteProfile,
    getProfile,
    updateProfileProxy,
    getFolderList,
    getAllFolders,
    findFolderByName,
    createFolder,
    getOrCreateFolder,
    getFirstAvailableFolder
};

