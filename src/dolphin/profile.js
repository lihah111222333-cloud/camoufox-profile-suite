/**
 * Dolphin Anty Profile Manager
 * إدارة بروفايلات Dolphin Anty
 */

import puppeteer from 'puppeteer-core';
import logger from '../utils/logger.js';
import dolphinClient from './client.js';
import ManagedProfile, { rollbackNewManagedProfile } from '../utils/managed-profile.js';
import {
    ControllerUrlError,
    connectBrowser,
    parseControllerUrl,
    toWebSocketUrl,
    validateControllerEndpoint
} from '../utils/controller-url.js';

class DolphinProfile extends ManagedProfile {
    constructor(profileId, webSocketUrl = null) {
        super(profileId, dolphinClient, 'webSocketUrl', webSocketUrl, () => this.#startBrowser());
    }

    /**
     * Start profile and get browser instance
     * بدء البروفايل والحصول على متصفح
     */
    async #startBrowser() {
        try {
            logger.info('Starting Dolphin Anty profile', { profileId: this.profileId });

            if (!this.webSocketUrl) {
                // Start profile to get WebSocket URL
                const startData = await dolphinClient.startProfile(this.profileId);
                this.webSocketUrl = startData.ws || startData.webSocketDebuggerUrl;
            }

            if (!this.webSocketUrl) {
                throw new Error('Failed to get WebSocket URL from Dolphin Anty');
            }

            let endpoint = toWebSocketUrl(parseControllerUrl(this.webSocketUrl, 'ws:'));

            // Wait a bit for browser to fully start
            await new Promise(resolve => setTimeout(resolve, 3000));

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
                    connection = await connectBrowser(puppeteer, endpoint);
                    const pages = await connection.pages();
                    browser = connection;
                    this.webSocketUrl = endpoint.href;
                    logger.info('Dolphin Anty browser connected successfully', {
                        profileId: this.profileId,
                        pagesCount: pages.length
                    });
                    break;
                } catch (error) {
                    if (error instanceof ControllerUrlError) throw error;
                    if (connection) await connection.disconnect();
                    lastError = error;
                    logger.warn(`Dolphin Anty browser connection attempt ${attempt} failed`, {
                        error: error.message,
                        profileId: this.profileId
                    });

                    if (attempt < retries) {
                        const waitTime = Math.min(2000 + (attempt * 1000), 8000);
                        logger.info(`Waiting ${waitTime / 1000}s before retry...`);
                        await new Promise(resolve => setTimeout(resolve, waitTime));

                        let address;
                        try {
                            const startData = await dolphinClient.startProfile(this.profileId);
                            address = startData.ws || startData.webSocketDebuggerUrl;
                        } catch (refreshError) {
                            if (refreshError instanceof ControllerUrlError) throw refreshError;
                            logger.debug('Could not refresh Dolphin Anty browser endpoint', { error: refreshError.message });
                        }
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
            
            // Always create a new clean page for stability
            // دائماً إنشاء صفحة نظيفة جديدة للاستقرار
            this.page = await browser.newPage();
            logger.info('Created new clean page');
            
            // Wait for page to be fully ready before proceeding
            // انتظار حتى تكون الصفحة جاهزة بالكامل قبل المتابعة
            await new Promise(resolve => setTimeout(resolve, 3000));
            
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
                error: error.message 
            });
            throw error;
        }
    }
}

/**
 * Create and start a new profile
 * إنشاء وبدء بروفايل جديد
 */
export async function createAndStartProfile(name, proxy = null) {
    let profileManager;
    try {
        // Check Dolphin connection first
        const isConnected = await dolphinClient.checkDolphinConnection();
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
        await new Promise(resolve => setTimeout(resolve, 2000));

        await profileManager.start();

        logger.info('Dolphin Anty profile created and started', { profileId: profile.id });
        
        return profileManager;
    } catch (error) {
        if (profileManager) throw await rollbackNewManagedProfile(profileManager, error);
        logger.error('Failed to create and start Dolphin Anty profile', { error: error.message });
        throw error;
    }
}

export default DolphinProfile;

