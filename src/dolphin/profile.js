/**
 * Dolphin Anty Profile Manager
 * إدارة بروفايلات Dolphin Anty
 */

import puppeteer from 'puppeteer-core';
import logger from '../utils/logger.js';
import dolphinClient from './client.js';
import ManagedProfile, { rollbackNewManagedProfile } from '../utils/managed-profile.js';
import {
    ControllerConnectionError,
    ControllerUrlError,
    connectBrowser,
    controllerDelay,
    parseControllerUrl,
    toWebSocketUrl,
    validateControllerEndpoint
} from '../utils/controller-url.js';

class DolphinProfile extends ManagedProfile {
    constructor(profileId, webSocketUrl = null) {
        super(profileId, dolphinClient, 'webSocketUrl', webSocketUrl,
            (client, address, signal) => this.#startBrowser(client, address, signal));
    }

    delete() {
        return dolphinClient.deleteProfile();
    }

    /**
     * Start profile and get browser instance
     * بدء البروفايل والحصول على متصفح
     */
    async #startBrowser(client, address, signal) {
        try {
            logger.info('Starting Dolphin Anty profile', { profileId: this.profileId });

            if (client) {
                // Let a dispatched launch return before cleanup can stop it by ID.
                const startData = await client.startProfile(this.profileId);
                address = startData.ws || startData.webSocketDebuggerUrl;
            }

            signal.throwIfAborted();
            if (!address) {
                throw new Error('Failed to get WebSocket URL from Dolphin Anty');
            }

            this.webSocketUrl = address;
            let endpoint = toWebSocketUrl(parseControllerUrl(address, 'ws:'));

            // Wait a bit for browser to fully start
            await controllerDelay(3000, signal);

            let browser;
            let lastError;
            const retries = 5;

            for (let attempt = 1; attempt <= retries; attempt++) {
                let connection;
                try {
                    logger.info(`Connecting to Dolphin Anty browser (attempt ${attempt}/${retries})...`, {
                        profileId: this.profileId,
                        controller: endpoint.origin
                    });
                    connection = await connectBrowser(puppeteer, endpoint, { signal });
                    const pages = await connection.pages();
                    browser = connection;
                    this.webSocketUrl = endpoint.href;
                    logger.info('Dolphin Anty browser connected successfully', {
                        profileId: this.profileId,
                        pagesCount: pages.length
                    });
                    break;
                } catch (error) {
                    if (connection) await connection.disconnect();
                    signal.throwIfAborted();
                    if (error instanceof ControllerUrlError || error instanceof ControllerConnectionError) throw error;
                    lastError = error;
                    logger.warn(`Dolphin Anty browser connection attempt ${attempt} failed`, {
                        error: error.message,
                        profileId: this.profileId
                    });

                    if (attempt < retries) {
                        const waitTime = Math.min(2000 + (attempt * 1000), 8000);
                        logger.info(`Waiting ${waitTime / 1000}s before retry...`);
                        await controllerDelay(waitTime, signal);

                        if (!client) continue;
                        signal.throwIfAborted();
                        let address;
                        try {
                            const startData = await client.startProfile(this.profileId);
                            address = startData.ws || startData.webSocketDebuggerUrl;
                        } catch (refreshError) {
                            signal.throwIfAborted();
                            if (refreshError instanceof ControllerUrlError) throw refreshError;
                            logger.debug('Could not refresh Dolphin Anty browser endpoint', { error: refreshError.message });
                        }
                        signal.throwIfAborted();
                        if (address) {
                            const refreshed = toWebSocketUrl(parseControllerUrl(address, 'ws:'));
                            endpoint = validateControllerEndpoint(refreshed, endpoint);
                        }
                    }
                }
            }

            if (!browser) {
                throw new Error(`Failed to connect to Dolphin Anty browser: ${lastError?.message || 'Unknown error'}`);
            }

            this.browser = browser;
            signal.throwIfAborted();
            
            // Always create a new clean page for stability
            // دائماً إنشاء صفحة نظيفة جديدة للاستقرار
            this.page = await this.createOwnedPage();
            signal.throwIfAborted();
            logger.info('Created new clean page');
            
            // Wait for page to be fully ready before proceeding
            // انتظار حتى تكون الصفحة جاهزة بالكامل قبل المتابعة
            await controllerDelay(3000, signal);
            
            // Ensure page is still accessible
            try {
                const pageUrl = await this.page.url();
                logger.info('Page is ready', { url: pageUrl || 'about:blank' });
            } catch (urlError) {
                logger.warn('Could not get page URL, but continuing', { error: urlError.message });
            }

            logger.info('Dolphin Anty profile started successfully', { profileId: this.profileId });
            return this;
        } catch (error) {
            logger.error('Failed to start Dolphin Anty profile', { 
                profileId: this.profileId, 
                error: error?.message
            });
            throw error;
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
        // Check Dolphin connection first
        const isConnected = await dolphinClient.checkDolphinConnection();
        signal?.throwIfAborted();
        if (!isConnected) {
            throw new Error('Dolphin Anty API is not available. Please make sure Dolphin Anty is running and DOLPHIN_API_KEY is set correctly.');
        }

        // Create profile
        logger.info('Creating Dolphin Anty profile...');
        const profile = await dolphinClient.createProfile(name, proxy);
        
        profileManager = new DolphinProfile(profile?.id);

        logger.info('Dolphin Anty profile created', { profileId: profile.id });

        // Wait a bit for profile to be ready
        logger.info('Waiting for profile initialization...');
        await controllerDelay(2000, signal);

        await profileManager.start({ signal });

        logger.info('Dolphin Anty profile created and started', { profileId: profile.id });
        
        return profileManager;
    } catch (error) {
        if (profileManager) throw await rollbackNewManagedProfile(profileManager, error, 'recycle');
        logger.error('Failed to create and start Dolphin Anty profile', { error: error?.message });
        throw error;
    }
}

export default DolphinProfile;

