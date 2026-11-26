/**
 * OMO Captcha Extension Handler
 * معالج OMO Captcha Extension (نسخة محسنة)
 */

import logger from '../utils/logger.js';
import config from '../config.js';

const OMOCAPTCHA_EXTENSION_ID = config.omocaptcha?.extensionId || 'dfjghhjachoacpgpkmbpdlpppeagojhe';
const OMO_CAPTCHA_ENABLED = config.omocaptcha?.enabled !== false; // Default: true

function isConfiguredExtensionUrl(address) {
    try {
        const url = new URL(address);
        return url.protocol === 'chrome-extension:' && url.host === OMOCAPTCHA_EXTENSION_ID &&
            !url.username && !url.password;
    } catch {
        return false;
    }
}

function requireManualExtensionSetup() {
    logger.warn('Configure OMO Captcha credentials manually in the installed extension settings.');
    return false;
}

/**
 * Detect whether the active profile/page runs on Camoufox (Firefox / Gecko),
 * where `chrome-extension://` CRX URLs are unsupported.
 */
function isFirefoxProfile(target) {
    return config.profileService === 'camoufox' || Boolean(
        target?._camoufoxCompatAttached || target?._camoufoxProfile ||
        target?._camoufoxContext || target?._camoufoxNewPageWrapped ||
        target?._camoufoxPagesWrapped || target?._camoufoxActiveProfile
    );
}

async function isFirefoxOrCamoufoxEngine(target) {
    if (isFirefoxProfile(target)) return true;
    if (target && typeof target.evaluate === 'function') {
        try {
            return await target.evaluate(() => {
                const ua = typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
                return /\bFirefox\/\d+/i.test(ua) && typeof chrome === 'undefined';
            });
        } catch {
            return false;
        }
    }
    return false;
}

/**
 * Check if reCAPTCHA extension is installed
 * التحقق من وجود extension
 */
export async function checkRecaptchaExtension(browser) {
    try {
        if (await isFirefoxOrCamoufoxEngine(browser)) {
            logger.info('Camoufox/Firefox engine detected — skipping Chrome CRX reCAPTCHA extension check');
            return { installed: false, enabled: false, skippedOnCamoufox: true, error: null };
        }
        logger.info('Checking reCAPTCHA Extension', { extensionId: OMOCAPTCHA_EXTENSION_ID });
        
        const tempPage = await browser.newPage();
        try {
            const extensionUrl = `chrome-extension://${OMOCAPTCHA_EXTENSION_ID}/index.html`;
            await tempPage.goto(extensionUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
            
            const currentUrl = tempPage.url();
            const isInstalled = isConfiguredExtensionUrl(currentUrl);
            
            await tempPage.close();
            
            if (isInstalled) {
                logger.info('reCAPTCHA extension is installed and accessible');
                return { installed: true, enabled: true, error: null };
            }
            
            return { installed: false, enabled: false, error: 'Extension URL mismatch' };
        } catch (navError) {
            await tempPage.close();
            return { installed: false, enabled: false, error: 'Could not check the configured extension.' };
        }
    } catch (error) {
        logger.error('Error checking reCAPTCHA extension', { error: error.message });
        return { installed: false, enabled: false, error: 'Could not check the configured extension.' };
    }
}

/**
 * Open OMO Captcha extension in new tab
 * فتح الإكستنشن في تبويب جديد
 */
export async function openOMOCaptchaExtension(page) {
    let newPage = null;
    try {
        if (await isFirefoxOrCamoufoxEngine(page)) {
            return { page: null, opened: false, skippedOnCamoufox: true };
        }
        logger.info('Opening OMO Captcha Extension in new tab');
        
        const browser = page.browser();
        if (!browser) {
            throw new Error('Browser context not available');
        }
        
        newPage = await browser.newPage();
        
        const possibleUrls = [
            `chrome-extension://${OMOCAPTCHA_EXTENSION_ID}/index.html`,
            `chrome-extension://${OMOCAPTCHA_EXTENSION_ID}/popup.html`,
            `chrome-extension://${OMOCAPTCHA_EXTENSION_ID}/options.html`,
            `chrome-extension://${OMOCAPTCHA_EXTENSION_ID}/options/index.html`,
            `chrome-extension://${OMOCAPTCHA_EXTENSION_ID}/`
        ];
        
        for (const extensionUrl of possibleUrls) {
            try {
                await newPage.goto(extensionUrl, { waitUntil: 'domcontentloaded', timeout: 6000 });
                await newPage.waitForTimeout(1000);
                
                const currentUrl = newPage.url();
                
                if (isConfiguredExtensionUrl(currentUrl)) {
                    logger.info('OMO Captcha extension opened successfully');
                    return { page: newPage, opened: true };
                }
            } catch (navError) {
                // Check if error is due to blocking
                const errorMsg = navError.message.toLowerCase();
                if (errorMsg.includes('blocked') || errorMsg.includes('net::err_blocked')) {
                    logger.warn('OMO Captcha extension access blocked', { 
                        error: navError.message,
                        hint: 'Extension may not be installed or is blocked by browser security'
                    });
                }
                continue;
            }
        }
        
        if (newPage) {
            await newPage.close().catch(() => {});
        }
        logger.warn('Failed to open OMO Captcha extension');
        return { page: null, opened: false };
    } catch (error) {
        logger.error('Error opening OMO Captcha extension', { error: error.message });
        if (newPage) {
            await newPage.close().catch(() => {});
        }
        return { page: null, opened: false };
    }
}

// Retain the legacy setup entry points for existing callers.
export async function setOMOCaptchaKeyViaAPI() {
    return requireManualExtensionSetup();
}

export async function enterOMOCaptchaKey() {
    return requireManualExtensionSetup();
}

/**
 * Click refresh button to activate extension
 * الضغط على زر التحديث لتفعيل الإكستنشن
 */
export async function clickRecaptchaRefreshButton(page) {
    try {
        logger.info('Clicking reCAPTCHA Refresh Button');
        
        const selectors = [
            'button.chakra-button',
            'button[type="button"]',
            'div.css-ls19pz button'
        ];
        
        for (const selector of selectors) {
            try {
                await page.waitForSelector(selector, { timeout: 5000 });
                const button = await page.$(selector);
                
                if (button) {
                    const isRefreshButton = await page.evaluate((btn) => {
                        const svg = btn.querySelector('svg');
                        if (!svg) return false;
                        return svg.getAttribute('viewBox') === '0 0 512 512' || 
                               svg.querySelector('path[d*="M400"]');
                    }, button);
                    
                    if (isRefreshButton) {
                        await page.evaluate((btn) => {
                            btn.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        }, button);
                        
                        await page.waitForTimeout(200);
                        await button.click();
                        logger.info('Refresh button clicked (first time)');
                        
                        await page.waitForTimeout(800);
                        await button.click();
                        logger.info('Refresh button clicked (second time)');
                        
                        await page.waitForTimeout(800);
                        return true;
                    }
                }
            } catch (e) {
                continue;
            }
        }
        
        // Try XPath
        try {
            const xpath = '//button[.//svg[@viewBox="0 0 512 512"]]';
            await page.waitForXPath(xpath, { timeout: 5000 });
            const buttonElements = await page.$x(xpath);
            
            if (buttonElements && buttonElements.length > 0) {
                const button = buttonElements[0];
                await page.evaluate((btn) => {
                    btn.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }, button);
                
                await page.waitForTimeout(200);
                await button.click();
                await page.waitForTimeout(500);
                await button.click();
                logger.info('Refresh button clicked using XPath');
                return true;
            }
        } catch (xpathError) {
            logger.debug('XPath method failed', { error: xpathError.message });
        }
        
        logger.warn('Could not find refresh button');
        return false;
    } catch (error) {
        logger.error('Error clicking refresh button', { error: error.message });
        return false;
    }
}

/**
 * Check whether setup is needed. Credentials are entered by the operator.
 */
export async function setupOMOCaptchaExtension(page) {
    if (!OMO_CAPTCHA_ENABLED) {
        logger.info('OMO Captcha extension setup is disabled');
        return true;
    }

    if (isFirefoxProfile(page)) {
        logger.info('Skipping Chromium extension setup on Camoufox');
        return true;
    }

    if (!config.omocaptcha?.apiKey) {
        logger.info('OMO Captcha extension setup skipped because its key is unconfigured');
        return true;
    }

    return requireManualExtensionSetup();
}
