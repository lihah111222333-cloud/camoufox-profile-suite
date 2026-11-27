/**
 * GoLogin API Client
 * عميل GoLogin API
 */

import dotenv from 'dotenv';
import axios from 'axios';
import net from 'node:net';
import logger from '../utils/logger.js';
import { profileIdPathComponent, requireControllerProfileId } from '../utils/controller-id.js';
import { controllerRequestOptions } from '../utils/controller-url.js';
import {
    ControllerRequestError, controllerAcknowledged, controllerErrorDetails, controllerRejected,
    parseControllerPayload, profileAllocationUnconfirmed, sendControllerRequest
} from '../utils/controller-request.js';
import { loadPrivateEnvironment } from '../utils/private-env.js';
import { requireProxyProtocol } from '../utils/proxy-protocol.js';

loadPrivateEnvironment('.emv', '.env', env => !env.GOLOGIN_API_KEY, dotenv.parse, dotenv.decrypt);

const GOLOGIN_API_ORIGIN = 'https://api.gologin.com';
const supportedProfileOs = new Set(['lin', 'mac', 'win']);
const createProfileOptions = new Set(['name', 'os', 'browserType', 'proxy']);

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

function unconfirmedWrite(operation, cause) {
    const error = new Error(`GoLogin ${operation} could not be confirmed`, { cause });
    return operation === 'profile creation' ? profileAllocationUnconfirmed(error) : error;
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
        const response = await this.#request(method, endpoint, data, retries);
        return response.data;
    }

    async #request(method, endpoint, data, retries = 1) {
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

        const retryableMethod = typeof method === 'string' && ['GET', 'HEAD'].includes(method.toUpperCase());
        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                return await sendControllerRequest('GoLogin API request', () => axios(config));
            } catch (error) {
                const { status, transportCode } = error;
                const retryable = status >= 500
                    || (status === undefined && (transportCode === 'ECONNRESET' || transportCode === 'ETIMEDOUT'));
                if (retryableMethod && retryable && attempt < retries) {
                    const waitTime = attempt * 1000;
                    logger.warn('GoLogin API request failed, retrying', { ...controllerErrorDetails(error), attempt, waitTime });
                    await new Promise(resolve => setTimeout(resolve, waitTime));
                    continue;
                }
                logger.error('GoLogin API request failed', controllerErrorDetails(error));
                throw error;
            }
        }
        throw new Error('At least one GoLogin API request attempt is required');
    }

    async #write(method, endpoint, operation, data) {
        const response = await this.#request(method, endpoint, data).catch(error => {
            const status = error?.status;
            if (error instanceof ControllerRequestError && (status === undefined || status === 408 || status >= 500)) {
                throw unconfirmedWrite(operation, error);
            }
            throw error;
        });
        if (controllerRejected(response.data)) throw new Error(`GoLogin API rejected ${operation}`);
        return response;
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

    /** @deprecated GoLogin profiles use the provider's standard browser settings. */
    generateAndroidFingerprint() {
        throw new TypeError('GoLogin Android fingerprint generation has been removed');
    }

    async createProfile(profileData, testProxyConnection = false) {
        if (!profileData || typeof profileData !== 'object' || Array.isArray(profileData)) {
            throw new TypeError('GoLogin profile options must be an object');
        }
        if (Object.keys(profileData).some(option => !createProfileOptions.has(option))) {
            throw new TypeError('Unsupported GoLogin profile option');
        }
        const { name, os = 'lin', browserType = 'chrome', proxy: proxyData } = profileData;
        if (!supportedProfileOs.has(os) || browserType !== 'chrome') {
            throw new TypeError('Unsupported GoLogin profile OS or browser type');
        }
        if (name != null && typeof name !== 'string') {
            throw new TypeError('GoLogin profile name must be a string');
        }

        const proxy = formatGoLoginProxy(proxyData);
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

        // The partial-profile API requires an OS and accepts the proxy in the create request.
        const response = await client.#write('POST', '/browser/custom', 'profile creation', {
            os,
            name: name || `Profile_${Date.now()}`,
            ...(proxy && { proxy })
        });
        if (response.status !== 200 && response.status !== 201) throw unconfirmedWrite('profile creation');

        const created = parseControllerPayload(response.data);
        let profileId;
        try {
            profileId = requireControllerProfileId(created?.id);
        } catch (error) {
            throw unconfirmedWrite('profile creation', error);
        }
        logger.info('GoLogin profile created', { profileId });
        return created;
    }

    /**
     * Update profile
     * تحديث بروفايل
     */
    async updateProfile(profileId, updates) {
        const data = updates?.proxy ? { ...updates, proxy: formatGoLoginProxy(updates.proxy) } : updates;
        const response = await this.#write('PUT', `/browser/${profileIdPathComponent(profileId)}`, 'profile update', data);
        if (!controllerAcknowledged(response)) throw unconfirmedWrite('profile update');
        logger.info('Profile updated', { profileId });
        return response.data;
    }

    /**
     * Update profile proxy (dedicated endpoint - more efficient)
     * تحديث بروكسي البروفايل (endpoint مخصص - أكثر كفاءة)
     */
    async updateProfileProxy(profileId, proxyData) {
        const response = await this.#write(
            'PATCH', `/browser/${profileIdPathComponent(profileId)}/proxy`, 'profile proxy update', formatGoLoginProxy(proxyData)
        );
        if (!controllerAcknowledged(response)) throw unconfirmedWrite('profile proxy update');
        logger.info('Profile proxy updated', { profileId });
        return true;
    }

    /**
     * Delete profile
     * حذف بروفايل
     */
    async deleteProfile(profileId) {
        const response = await this.#write('DELETE', `/browser/${profileIdPathComponent(profileId)}`, 'profile deletion');
        if (!controllerAcknowledged(response)) throw unconfirmedWrite('profile deletion');
        logger.info('Profile deleted', { profileId });
        return true;
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

