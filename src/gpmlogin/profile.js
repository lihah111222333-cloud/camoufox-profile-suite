/**
 * GPM Login Profile Manager
 * إدارة بروفايلات GPM Login
 */

import puppeteer from 'puppeteer-core';
import axios from 'axios';
import logger from '../utils/logger.js';
import gpmClient from './client.js';
import ManagedProfile, { rollbackNewManagedProfile } from '../utils/managed-profile.js';
import { sendControllerRequest } from '../utils/controller-request.js';
import {
    ControllerConnectionError,
    ControllerUrlError,
    connectBrowser,
    controllerDelay,
    controllerRequestOptions,
    parseControllerUrl,
    toWebSocketUrl,
    validateControllerEndpoint
} from '../utils/controller-url.js';

const discoveryPaths = ['/json/version', '/json', '/json/list'];
const discoveryRetryCodes = new Set([
    'ECONNABORTED', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ERR_BAD_RESPONSE'
]);

async function discoverBrowserEndpoint(controller, paths, timeout, signal) {
    const originalPath = controller.pathname.replace(/\/$/, '');
    const webSocketController = toWebSocketUrl(controller);

    for (const path of paths) {
        signal.throwIfAborted();
        const url = new URL(controller);
        url.pathname = originalPath + path;
        let data;
        try {
            const response = await sendControllerRequest('GPM browser endpoint discovery', () =>
                axios.get(url.href, { ...controllerRequestOptions, timeout, signal })
            );
            data = response.data;
        } catch (error) {
            signal.throwIfAborted();
            if (error.status !== 404 && !discoveryRetryCodes.has(error.transportCode)) {
                throw error;
            }
            logger.debug('Could not discover GPM browser endpoint', { path });
            continue;
        }

        const page = path === '/json' && Array.isArray(data) ? data[0] : null;
        const target = path === '/json/version'
            ? data
            : Array.isArray(data) && (data.find(entry => entry?.type === 'browser') || page);
        if (!target?.webSocketDebuggerUrl) continue;

        const endpoint = parseControllerUrl(target.webSocketDebuggerUrl);
        validateControllerEndpoint(endpoint, webSocketController, true);
        if (target === page && target.type !== 'browser') {
            endpoint.pathname = endpoint.pathname.replace(/\/devtools\/page\/[^/]+$/, '/devtools/browser');
        }
        return endpoint;
    }
    return null;
}

class GPMLoginProfile extends ManagedProfile {
    constructor(profileId, remoteDebuggingAddress = null) {
        super(profileId, gpmClient, 'remoteDebuggingAddress', remoteDebuggingAddress,
            (startProfile, address, signal) => this.#startBrowser(startProfile, address, signal));
    }

    /**
     * Start profile and get browser instance
     * بدء البروفايل والحصول على متصفح
     */
    async #startBrowser(startProfile, address, signal) {
        try {
            logger.info('Starting GPM profile', { profileId: this.profileId });

            if (startProfile) {
                const startData = await startProfile();
                address = startData.remote_debugging_address;
            }

            signal.throwIfAborted();
            if (!address) {
                throw new Error('Failed to get remote debugging address from GPM');
            }

            this.remoteDebuggingAddress = address;
            const controller = parseControllerUrl(address, 'http:');
            const needsDiscovery = controller.protocol === 'http:' || controller.protocol === 'https:';

            // Wait a bit for browser to fully start
            await controllerDelay(2000, signal);

            let endpoint = toWebSocketUrl(controller);
            if (needsDiscovery) {
                endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + '/devtools/browser';
                endpoint = await discoverBrowserEndpoint(controller, discoveryPaths, 5000, signal) ?? endpoint;
            }

            let browser;
            let lastError;
            const retries = 8;
            for (let attempt = 1; attempt <= retries; attempt++) {
                if (needsDiscovery && attempt > 1 && attempt % 2 === 0) {
                    endpoint = await discoverBrowserEndpoint(controller, discoveryPaths.slice(0, 2), 3000, signal) ?? endpoint;
                }

                let connection;
                try {
                    logger.info(`GPM browser connection attempt ${attempt}/${retries}...`, { profileId: this.profileId });
                    connection = await connectBrowser(puppeteer, endpoint, { signal });
                    const pages = await connection.pages();
                    browser = connection;
                    logger.info('GPM browser connected successfully', {
                        profileId: this.profileId,
                        pagesCount: pages.length
                    });
                    break;
                } catch (error) {
                    if (connection) await connection.disconnect();
                    signal.throwIfAborted();
                    if (error instanceof ControllerUrlError || error instanceof ControllerConnectionError) throw error;
                    lastError = error;
                    logger.warn(`GPM browser connection attempt ${attempt} failed`, {
                        error: error.message,
                        profileId: this.profileId
                    });

                    if (attempt < retries) {
                        const waitTime = Math.min(2000 + (attempt * 1000), 8000);
                        logger.info(`Waiting ${waitTime / 1000}s before retry...`);
                        await controllerDelay(waitTime, signal);
                    }
                }
            }

            if (!browser) {
                throw new Error(`Failed to connect to browser: ${lastError?.message || 'Unknown error'}`);
            }

            this.browser = browser;
            signal.throwIfAborted();
            this.page = await this.createOwnedPage();
            signal.throwIfAborted();

            // Inject anti-detection scripts to hide automation traces
            // حقن نصوص إخفاء علامات automation
            await this.injectAntiDetectionScripts(this.page);

            logger.info('Profile started successfully', { profileId: this.profileId });
            return this;
        } catch (error) {
            logger.error('Failed to start profile', { 
                profileId: this.profileId, 
                error: error?.message
            });
            throw error;
        }
    }

    /**
     * Inject anti-detection scripts to hide automation traces
     * حقن نصوص إخفاء علامات automation
     */
    async injectAntiDetectionScripts(page) {
        try {
            await page.evaluateOnNewDocument(() => {
                // Hide webdriver property - only if not already defined
                try {
                    if (navigator.hasOwnProperty('webdriver')) {
                        delete navigator.webdriver;
                    }
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined,
                        configurable: true
                    });
                } catch (e) {
                    // If webdriver is already defined and not configurable, try to override differently
                    try {
                        Object.defineProperty(navigator, 'webdriver', {
                            value: undefined,
                            configurable: true
                        });
                    } catch (e2) {
                        // Ignore if we can't redefine it
                    }
                }

                // Override permissions API
                try {
                    const originalQuery = window.navigator.permissions?.query;
                    if (originalQuery) {
                        window.navigator.permissions.query = (parameters) => (
                            parameters.name === 'notifications' ?
                                Promise.resolve({ state: Notification.permission }) :
                                originalQuery(parameters)
                        );
                    }
                } catch (e) {
                    // Ignore if permissions API is not available
                }

                // Mock plugins
                try {
                    if (!navigator.plugins || navigator.plugins.length === 0) {
                        Object.defineProperty(navigator, 'plugins', {
                            get: () => [1, 2, 3, 4, 5],
                            configurable: true
                        });
                    }
                } catch (e) {
                    // Ignore if plugins can't be redefined
                }

                // Mock languages
                try {
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en'],
                        configurable: true
                    });
                } catch (e) {
                    // Ignore if languages can't be redefined
                }

                // Override Chrome runtime
                window.chrome = {
                    runtime: {}
                };

                // Remove automation indicators from window
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_JSON;
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_Object;
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_Proxy;

                // Override WebGL to prevent fingerprinting - only if WebGL exists
                try {
                    if (typeof WebGLRenderingContext !== 'undefined') {
                        const getParameter = WebGLRenderingContext.prototype.getParameter;
                        WebGLRenderingContext.prototype.getParameter = function(parameter) {
                            if (parameter === 37445) {
                                return 'Intel Inc.';
                            }
                            if (parameter === 37446) {
                                return 'Intel Iris OpenGL Engine';
                            }
                            return getParameter.call(this, parameter);
                        };
                    }
                } catch (e) {
                    // Ignore if WebGL is not available
                }

                // Add noise to canvas to prevent fingerprinting - only if Canvas exists
                try {
                    if (typeof HTMLCanvasElement !== 'undefined') {
                        const toBlob = HTMLCanvasElement.prototype.toBlob;
                        const toDataURL = HTMLCanvasElement.prototype.toDataURL;
                        
                        HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
                            try {
                                const canvas = this;
                                const context = canvas.getContext('2d');
                                if (context) {
                                    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                                    for (let i = 0; i < imageData.data.length; i += 4) {
                                        if (Math.random() < 0.01) {
                                            imageData.data[i] = Math.min(255, imageData.data[i] + Math.floor(Math.random() * 10) - 5);
                                        }
                                    }
                                    context.putImageData(imageData, 0, 0);
                                }
                            } catch (e) {
                                // Ignore canvas errors
                            }
                            return toBlob.call(this, callback, type, quality);
                        };

                        HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
                            try {
                                const canvas = this;
                                const context = canvas.getContext('2d');
                                if (context) {
                                    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                                    for (let i = 0; i < imageData.data.length; i += 4) {
                                        if (Math.random() < 0.01) {
                                            imageData.data[i] = Math.min(255, imageData.data[i] + Math.floor(Math.random() * 10) - 5);
                                        }
                                    }
                                    context.putImageData(imageData, 0, 0);
                                }
                            } catch (e) {
                                // Ignore canvas errors
                            }
                            return toDataURL.call(this, type, quality);
                        };
                    }
                } catch (e) {
                    // Ignore if Canvas is not available
                }

                // Mock battery API
                try {
                    if (navigator.getBattery) {
                        navigator.getBattery = () => Promise.resolve({
                            charging: true,
                            chargingTime: 0,
                            dischargingTime: Infinity,
                            level: 1
                        });
                    }
                } catch (e) {
                    // Ignore if battery API can't be overridden
                }
            });

            logger.info('Anti-detection scripts injected successfully');
        } catch (error) {
            logger.warn('Failed to inject anti-detection scripts', { error: error.message });
        }
    }
}

/**
 * Create and start a new profile
 * إنشاء وبدء بروفايل جديد
 */
export async function createAndStartProfile(name, proxy = null, { signal } = {}) {
    let profileManager;
    try {
        signal?.throwIfAborted();
        // Check GPM connection first
        const isConnected = await gpmClient.checkGPMConnection();
        signal?.throwIfAborted();
        if (!isConnected) {
            throw new Error('GPM API is not available. Please make sure GPM Login is running.');
        }

        // Create profile
        logger.info('Creating GPM profile...');
        const profile = await gpmClient.createProfile(name, proxy);
        
        profileManager = new GPMLoginProfile(profile?.id);

        logger.info('Profile created', { profileId: profile.id });

        // Wait a bit for profile to be ready
        logger.info('Waiting for profile initialization...');
        await controllerDelay(3000, signal);

        await profileManager.start({ signal });

        logger.info('Profile created and started', { profileId: profile.id });
        
        return profileManager;
    } catch (error) {
        if (profileManager) throw await rollbackNewManagedProfile(profileManager, error);
        logger.error('Failed to create and start profile', { error: error?.message });
        throw error;
    }
}

export default GPMLoginProfile;

