/**
 * Gmail Account Creator
 * منشئ حسابات Gmail
 */

import logger from '../utils/logger.js';
import { detectGmailPage, waitForElement, elementExists } from './page-detector.js';
import { setupOMOCaptchaExtension } from '../captcha/omo-handler.js';
import {
    clickSignupConfirmation,
    FINAL_SIGNUP_STEPS,
    getSignupStage,
    isPostVerificationStage,
    ManualSignupRequiredError,
    requirePostUsernameStage,
    skipOptionalRecoveryEmail
} from './credential-handoff.js';
import humanBehavior from '../utils/human-behavior.js';

// Destructure human behavior functions for easier use
// استخراج دوال السلوك البشري لاستخدام أسهل
const {
    humanSleep,
    humanClick,
    humanMouseMove,
    humanScroll,
    humanScrollToElement,
    humanType,
    humanWait,
    explorePageRandomly,
    idleMouseMovement,
    simulateReading,
    performRandomAction,
    getHumanDelay,
    randomDelay
} = humanBehavior;

const GMAIL_URL = 'https://gmail.com';
const GMAIL_SIGNUP_URL = 'https://accounts.google.com/signup';

/**
 * Human-like typing with random delays, occasional mistakes, and natural pauses
 * كتابة شبيهة بالإنسان مع تأخير عشوائي، أخطاء محتملة، وتوقفات طبيعية
 * @param {Object} page - Puppeteer page object
 * @param {Object} input - Puppeteer element handle
 * @param {string} text - Text to type
 * @param {Object} options - Options for typing behavior
 * @param {number} options.minDelay - Minimum delay between characters (default: 30)
 * @param {number} options.maxDelay - Maximum delay between characters (default: 120)
 * @param {number} options.mistakeChance - Chance of making a mistake (0-1, default: 0.1)
 * @param {number} options.pauseChance - Chance of pausing mid-typing (0-1, default: 0.15)
 */
async function humanLikeType(page, input, text, options = {}) {
    const {
        minDelay = 30,
        maxDelay = 120,
        mistakeChance = 0.1,
        pauseChance = 0.15
    } = options;

    try {
        logger.debug('Starting human-like typing', { textLength: text.length });
        
        // Focus the input first
        await input.focus();
        await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 100));

        // Clear existing content - try multiple methods
        try {
            await input.click({ clickCount: 3 });
            await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 50));
            await page.keyboard.press('Delete');
            await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 50));
            
            // Also try clearing via JavaScript
            await input.evaluate(el => {
                el.value = '';
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
            });
            await new Promise(resolve => setTimeout(resolve, 50));
        } catch (clearError) {
            logger.debug('Error clearing input, continuing anyway', { error: clearError.message });
        }

        // Type each character with human-like behavior
        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            
            // Occasional mistake: type wrong character then delete and retype
            if (Math.random() < mistakeChance && i > 0 && i < text.length - 1) {
                // Type a wrong character
                const wrongChars = 'abcdefghijklmnopqrstuvwxyz0123456789';
                const wrongChar = wrongChars[Math.floor(Math.random() * wrongChars.length)];
                await input.type(wrongChar, { delay: 50 + Math.random() * 50 });
                await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 100));
                
                // Realize mistake and delete
                await page.keyboard.press('Backspace');
                await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 100));
            }
            
            // Type the correct character
            const delay = minDelay + Math.random() * (maxDelay - minDelay);
            await input.type(char, { delay: delay });
            
            // Occasional pause (like human thinking or looking at keyboard)
            if (Math.random() < pauseChance) {
                const pauseDuration = 200 + Math.random() * 300; // 200-500ms pause
                await new Promise(resolve => setTimeout(resolve, pauseDuration));
            }
            
            // Longer pause after space or special characters
            if (char === ' ' || char === '.' || char === '@') {
                await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 100));
            }
        }
        
        // Final small delay to simulate human finishing typing
        await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));
        
        // Verify the text was entered
        const enteredValue = await input.evaluate(el => el.value);
        logger.debug('Human-like typing completed', { match: enteredValue === text });
        
        // If text doesn't match, try to fix it
        if (enteredValue !== text) {
            logger.warn('Text mismatch after typing, attempting to fix');
            // Clear and retry once
            await input.click({ clickCount: 3 });
            await page.keyboard.press('Delete');
            await new Promise(resolve => setTimeout(resolve, 100));
            await input.type(text, { delay: minDelay });
        }
    } catch (error) {
        // Fallback to simple typing if human-like typing fails
        logger.warn('Human-like typing failed, falling back to simple typing', { 
            error: error.message,
            textLength: text.length 
        });
        try {
            await input.focus();
            await input.click({ clickCount: 3 });
            await new Promise(resolve => setTimeout(resolve, 100));
            await page.keyboard.press('Delete');
            await new Promise(resolve => setTimeout(resolve, 100));
            await input.type(text, { delay: 50 });
            
            // Verify fallback worked
            const enteredValue = await input.evaluate(el => el.value);
            if (enteredValue !== text) {
                logger.error('Fallback typing failed to enter correct text');
            }
        } catch (fallbackError) {
            logger.error('Fallback typing also failed', { error: fallbackError.message });
            throw fallbackError;
        }
    }
}

/**
 * Check if page is still open and throw error if closed
 * التحقق من أن الصفحة لا تزال مفتوحة
 */
function ensurePageOpen(page, operation = 'operation') {
    if (page.isClosed()) {
        throw new Error(`Page was closed during ${operation}. This may happen with Remote Mode if connection is lost.`);
    }
}

function setRegistrationStep(page, profile, stepName, metadata = {}) {
    try {
        const targetProfile = profile || page?._camoufoxProfile || null;
        if (typeof targetProfile?.setStep === 'function') {
            return targetProfile.setStep(stepName, metadata);
        }
        if (typeof targetProfile?.setTrafficStep === 'function') {
            return targetProfile.setTrafficStep(stepName, metadata);
        }
        if (typeof page?.setStep === 'function') {
            return page.setStep(stepName, metadata);
        }
        if (typeof page?.setTrafficStep === 'function') {
            return page.setTrafficStep(stepName, metadata);
        }
    } catch {
        // Never interrupt registration flow
    }
    return null;
}

/**
 * Create Gmail account
 * إنشاء حساب Gmail
 */
export async function createGmailAccount(page, accountData, options = {}) {
    const profile = options?.profile || page?._camoufoxProfile || null;
    try {
        logger.info('Starting Gmail account creation', { email: accountData.email });
        setRegistrationStep(page, profile, 'gmail:init', { email: accountData.email });

        // Human behavior: Initial page exploration before starting
        // سلوك بشري: استكشاف أولي للصفحة قبل البدء
        logger.info('Performing initial human-like behavior...');
        await humanSleep(1000, 30);
        await idleMouseMovement(page, { movements: 2 + Math.floor(Math.random() * 3) });

        // Step 1: Navigate to Gmail page and click "Create account" from dropdown
        // الخطوة 1: الانتقال إلى صفحة Gmail والنقر على "إنشاء حساب" من القائمة المنسدلة
        setRegistrationStep(page, profile, 'gmail:navigate-signup', { email: accountData.email });
        await navigateToSignUp(page);

        await page.waitForTimeout(1000);
        
        // Click on the dropdown button using XPath
        // النقر على زر القائمة المنسدلة باستخدام XPath
        const dropdownXPath = '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[3]/div/div[2]/div/div';
        try {
            await page.waitForXPath(dropdownXPath, { timeout: 10000 });
            const dropdownElements = await page.$x(dropdownXPath);
            if (dropdownElements.length > 0) {
                await dropdownElements[0].click();
                logger.info('Clicked on dropdown menu');
                await page.waitForTimeout(1000); // Wait for dropdown to open
            }
        } catch (e) {
            logger.warn('Could not find dropdown by XPath, trying CSS selector', { error: e.message });
            // Fallback to CSS selector
            try {
                const dropdown = await page.$('div[role="button"]');
                if (dropdown) {
                    await dropdown.click();
                    logger.info('Clicked on dropdown (CSS selector)');
                    await page.waitForTimeout(1000);
                }
            } catch (e2) {
                logger.warn('Could not click dropdown', { error: e2.message });
            }
        }
        
        await page.waitForTimeout(1000);
        
        // Click on "Create account" link (first option in dropdown menu)
        // النقر على رابط "إنشاء حساب" (الخيار الأول في القائمة المنسدلة)
        const createAccountXPath = '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[3]/div/div[2]/div/div/div[2]/div/ul/li[1]';
        try {
            await page.waitForXPath(createAccountXPath, { timeout: 5000 });
            const createAccountElements = await page.$x(createAccountXPath);
            if (createAccountElements.length > 0) {
                // Check if element is visible and clickable
                const isVisible = await createAccountElements[0].evaluate(el => {
                    return el.offsetParent !== null && window.getComputedStyle(el).display !== 'none';
                });
                
                if (isVisible) {
                    await createAccountElements[0].click();
                    logger.info('Clicked on Create account link');
                } else {
                    logger.warn('Create account link found but not visible');
                    // Try clicking the link inside the li element
                    const link = await createAccountElements[0].$('a');
                    if (link) {
                        await link.click();
                        logger.info('Clicked on Create account link (inside li)');
                    }
                }
            }
        } catch (e) {
            logger.warn('Could not find Create account link by XPath, trying alternatives', { error: e.message });
            // Fallback: try to find by text
            try {
                const createBtn = await page.evaluateHandle(() => {
                    // Try to find in the dropdown menu
                    const menu = document.querySelector('ul[role="menu"]');
                    if (menu) {
                        const items = Array.from(menu.querySelectorAll('li'));
                        return items.find(item => {
                            const text = item.textContent.toLowerCase();
                            return text.includes('create account') || text.includes('إنشاء حساب') || text.includes('create an account');
                        });
                    }
                    // Fallback: search all links
                    const links = Array.from(document.querySelectorAll('a'));
                    return links.find(link => {
                        const text = link.textContent.toLowerCase();
                        return text.includes('create account') || text.includes('إنشاء حساب') || text.includes('create an account');
                    });
                });
                if (createBtn && createBtn.asElement()) {
                    await createBtn.asElement().click();
                    logger.info('Clicked on Create account link (text search)');
                }
            } catch (e2) {
                logger.warn('Could not click Create account link', { error: e2.message });
            }
        }
        
        await page.waitForTimeout(2000);
        
        // Human behavior: Explore page after navigation
        // سلوك بشري: استكشاف الصفحة بعد التنقل
        await performRandomAction(page);

        // Step 2: Setup OMO Captcha extension
        setRegistrationStep(page, profile, 'gmail:setup-captcha');
        await setupOMOCaptchaExtension(page);

        // Note: We now navigate directly to signup page from gmail.com dropdown,
        // so we skip the "Create account" button and "Select account type" steps

        // Step 4: Fill sign up form (first name, last name)
        setRegistrationStep(page, profile, 'gmail:fill-name-form', {
            firstName: accountData.firstName,
            lastName: accountData.lastName
        });
        await fillSignUpForm(page, accountData);

        // Step 4.5: Detect current page and handle accordingly
        await page.waitForTimeout(2000);
        
        // Check for birthday/gender fields directly (more reliable than page detection)
        const hasBirthdayFields = await page.evaluate(() => {
            return !!(
                document.querySelector('input[name="day"], input[aria-label*="day" i]') &&
                (document.querySelector('div[jsname="O1htCb"]') || document.querySelector('#month, select[name="month"]')) &&
                document.querySelector('input[name="year"], input[aria-label*="year" i]') &&
                (document.querySelector('div[jsname="ZU2VHd"]') || document.querySelector('#gender, select[name="gender"]'))
            );
        });

        if (hasBirthdayFields) {
            logger.info('Birthday/Gender fields detected after name form, filling form...');
            await fillBirthdayAndGenderForm(page, accountData);
            await page.waitForTimeout(3000);
        }

        let pageAfterName = await detectGmailPage(page);
        if (pageAfterName) {
            logger.info('Page detected after name form', { 
                type: pageAfterName.type, 
                method: pageAfterName.method || 'unknown',
                url: page.url() 
            });

            // Handle birthday/gender page - MUST be filled before username/password
            if (pageAfterName.type === 'BIRTHDAY_GENDER') {
                logger.info('Birthday/Gender page detected, filling form...');
                await fillBirthdayAndGenderForm(page, accountData);
                // Re-detect page after filling birthday/gender
                await page.waitForTimeout(3000);
                pageAfterName = await detectGmailPage(page);
                if (pageAfterName) {
                    logger.info('Page after birthday/gender', { 
                        type: pageAfterName.type,
                        method: pageAfterName.method || 'unknown',
                        url: page.url()
                    });
                }
            }

            // Handle suggested emails page
            if (pageAfterName && pageAfterName.type === 'SUGGESTED_EMAILS') {
                logger.info('Suggested emails page detected');
                // fillUsernameForm will handle this
            }

            // Handle username input page
            if (pageAfterName && pageAfterName.type === 'USERNAME_INPUT') {
                logger.info('Username input page detected');
                // fillUsernameForm will handle this
            }
        }

        await fillUsernameForm(page, accountData);
        await requirePostUsernameStage(page);
        await completeAccountCreation(page);

        logger.info('Gmail account created successfully', { email: accountData.email });
        return {
            success: true,
            email: accountData.email,
            phone: null,
            orderId: null,
            firstName: accountData.firstName,
            lastName: accountData.lastName,
            fullName: accountData.fullName,
            username: accountData.username
        };
    } catch (error) {
        if (error instanceof ManualSignupRequiredError) {
            logger.warn(error.message, { stage: error.stage });
        } else {
            logger.error('Failed to create Gmail account', { error });
        }
        throw error;
    }
}

/**
 * Navigate to Gmail sign up page
 * الانتقال إلى صفحة إنشاء حساب Gmail عبر gmail.com
 */
async function navigateToSignUp(page) {
    try {
        logger.info('Navigating to Gmail signin page first');
        
        // Step 1: Navigate directly to Gmail signin page (where Create account button is)
        // Try with different wait strategies if proxy auth fails
        // محاولة باستراتيجيات انتظار مختلفة إذا فشلت مصادقة البروكسي
        try {
            await page.goto(GMAIL_URL, { 
                waitUntil: 'networkidle2', 
                timeout: 60000 
            });
        } catch (gotoError) {
            // If proxy auth error, try with domcontentloaded (faster, less strict)
            // إذا كان خطأ مصادقة البروكسي، جرب مع domcontentloaded (أسرع، أقل صرامة)
            if (gotoError.message.includes('ERR_UNEXPECTED_PROXY_AUTH') || 
                gotoError.message.includes('PROXY_AUTH')) {
                logger.warn('Proxy auth error detected, retrying with domcontentloaded', { 
                    error: gotoError.message 
                });
                await page.goto(GMAIL_URL, { 
                    waitUntil: 'domcontentloaded', 
                    timeout: 30000 
                });
                // Wait a bit for page to load
                await page.waitForTimeout(3000);
            } else {
                throw gotoError;
            }
        }
        
        logger.info('Navigated to Gmail signin page');
   
    } catch (error) {
        logger.error('Failed to navigate to sign up page', { 
            error: error.message,
            errorType: error.name,
            stack: error.stack?.substring(0, 500)
        });
        
        // If it's a proxy auth error, provide helpful message
        // إذا كان خطأ مصادقة البروكسي، قدم رسالة مفيدة
        if (error.message.includes('ERR_UNEXPECTED_PROXY_AUTH') || 
            error.message.includes('PROXY_AUTH')) {
            throw new Error(`Proxy authentication failed. Please check your proxy credentials in config/proxies.txt. Format: ip:port:username:password`);
        }
        
        throw error;
    }
}


/**
 * Fill sign up form
 * ملء نموذج التسجيل
 */
async function fillSignUpForm(page, accountData) {
    try {
        logger.info('Filling sign up form', { name: accountData.fullName });

        // Human behavior: Simulate reading the form before filling
        // سلوك بشري: محاكاة قراءة النموذج قبل الملء
        await humanSleep(1500, 40);
        await simulateReading(page, { duration: 1500 + Math.random() * 1000, scrollWhileReading: false });
        
        // Random mouse movement to look at form
        await idleMouseMovement(page, { movements: 1 + Math.floor(Math.random() * 2) });

        // Fill first name
        const firstNameSelectors = [
            'input[name="firstName"]',
            '#firstName',
            'input[aria-label*="First name" i]',
            'input[type="text"][autocomplete="given-name"]'
        ];

        let firstNameFilled = false;
        for (const selector of firstNameSelectors) {
            try {
                const input = await waitForElement(page, selector, 3000);
                if (input) {
                    logger.info('First name input field found', { selector });
                    
                    // Human behavior: Scroll to element and move mouse to it
                    // سلوك بشري: التمرير إلى العنصر وتحريك الماوس إليه
                    await humanScrollToElement(page, input);
                    await humanClick(page, input, { preClickDelay: true, postClickDelay: false });
                    
                    await humanType(page, input, accountData.firstName, {
                        minDelay: 40,
                        maxDelay: 150,
                        mistakeChance: 0.08,
                        pauseChance: 0.12
                    });
                    
                    // Verify that the text was entered
                    const enteredValue = await input.evaluate(el => el.value);
                    if (enteredValue && enteredValue.trim() === accountData.firstName.trim()) {
                        logger.info('First name entered and verified');
                        firstNameFilled = true;
                        break;
                    } else {
                        logger.warn('First name verification failed');
                    }
                }
            } catch (e) {
                logger.debug('Error filling first name', { selector, error: e.message });
                continue;
            }
        }
        
        if (!firstNameFilled) {
            logger.warn('Failed to fill first name with all selectors');
        }

        // Human behavior: Pause between fields (like looking at next field)
        // سلوك بشري: توقف بين الحقول (مثل النظر للحقل التالي)
        await humanSleep(getHumanDelay('betweenActions'));

        // Fill last name
        const lastNameSelectors = [
            'input[name="lastName"]',
            '#lastName',
            'input[aria-label*="Last name" i]',
            'input[type="text"][autocomplete="family-name"]'
        ];

        let lastNameFilled = false;
        for (const selector of lastNameSelectors) {
            try {
                const input = await waitForElement(page, selector, 3000);
                if (input) {
                    logger.info('Last name input field found', { selector });
                    
                    // Human behavior: Click on input with mouse movement
                    // سلوك بشري: النقر على الحقل مع حركة الماوس
                    await humanClick(page, input, { preClickDelay: true, postClickDelay: false });
                    
                    await humanType(page, input, accountData.lastName, {
                        minDelay: 40,
                        maxDelay: 150,
                        mistakeChance: 0.08,
                        pauseChance: 0.12
                    });
                    
                    // Verify that the text was entered
                    const enteredValue = await input.evaluate(el => el.value);
                    if (enteredValue && enteredValue.trim() === accountData.lastName.trim()) {
                        logger.info('Last name entered and verified');
                        lastNameFilled = true;
                        break;
                    } else {
                        logger.warn('Last name verification failed');
                    }
                }
            } catch (e) {
                logger.debug('Error filling last name', { selector, error: e.message });
                continue;
            }
        }
        
        if (!lastNameFilled) {
            logger.warn('Failed to fill last name with all selectors');
        }

        // Human behavior: Think before clicking Next (verify form)
        // سلوك بشري: التفكير قبل النقر على التالي (التحقق من النموذج)
        await humanSleep(getHumanDelay('thinking'));
        await performRandomAction(page);

        // Click Next button
        await clickNextButton(page);

        // Human behavior: Wait for page transition
        await humanSleep(getHumanDelay('pageLoad'));
    } catch (error) {
        logger.error('Failed to fill sign up form', { error: error.message });
        throw error;
    }
}

/**
 * Select a random suggested email option
 * اختيار أحد الاقتراحات عشوائياً
 */
async function selectRandomSuggestedEmail(page) {
    try {
        logger.info('Selecting a random suggested email option');
        await page.waitForTimeout(2000);

        // Find all suggested email radio buttons (excluding "Create your own" option)
        const suggestedEmails = await page.evaluate(() => {
            const radioButtons = Array.from(document.querySelectorAll('input[type="radio"][name="usernameRadio"]'));
            const suggestions = [];
            
            radioButtons.forEach(radio => {
                // Skip the "custom" option (Create your own Gmail address)
                if (radio.value !== 'custom' && radio.value) {
                    // Find the email text associated with this radio button
                    const radioId = radio.getAttribute('aria-labelledby');
                    if (radioId) {
                        const emailElement = document.getElementById(radioId);
                        if (emailElement) {
                            const emailText = emailElement.textContent.trim();
                            if (emailText && emailText.includes('@gmail.com')) {
                                suggestions.push({
                                    value: radio.value,
                                    email: emailText,
                                    element: radio
                                });
                            }
                        }
                    }
                }
            });
            
            return suggestions;
        });

        if (suggestedEmails.length === 0) {
            logger.warn('No suggested emails found, falling back to "Create your own"');
            return false;
        }

        // Select a random suggestion
        const randomIndex = Math.floor(Math.random() * suggestedEmails.length);
        const selectedEmail = suggestedEmails[randomIndex];
        
        logger.info('Selected random suggested email', { 
            email: selectedEmail.email, 
            value: selectedEmail.value,
            totalOptions: suggestedEmails.length
        });

        // Click on the selected radio button
        const radioXPath = `//input[@type="radio"][@name="usernameRadio"][@value="${selectedEmail.value}"]`;
        let clicked = false;

        try {
            await page.waitForXPath(radioXPath, { timeout: 5000 });
            const radioButtons = await page.$x(radioXPath);
            if (radioButtons.length > 0) {
                const radioButton = radioButtons[0];
                const isVisible = await page.evaluate(el => {
                    const style = window.getComputedStyle(el);
                    return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
                }, radioButton);

                if (isVisible) {
                    await radioButton.click();
                    logger.info('Selected suggested email radio button', { email: selectedEmail.email });
                    clicked = true;
                    await page.waitForTimeout(1000);
                }
            }
        } catch (e) {
            logger.debug('XPath method failed, trying alternative', { error: e.message });
        }

        // Fallback: try clicking by value using CSS selector
        if (!clicked) {
            try {
                const radioSelector = `input[type="radio"][name="usernameRadio"][value="${selectedEmail.value}"]`;
                const radioButton = await waitForElement(page, radioSelector, 3000);
                if (radioButton) {
                    await radioButton.click();
                    logger.info('Selected suggested email radio button (CSS)', { email: selectedEmail.email });
                    clicked = true;
                    await page.waitForTimeout(1000);
                }
            } catch (e) {
                logger.debug('CSS selector method failed', { error: e.message });
            }
        }

        // Return selected email info if successful
        if (clicked && selectedEmail.email) {
            return {
                success: true,
                email: selectedEmail.email,
                username: selectedEmail.email.split('@')[0]
            };
        }

        return { success: false };
    } catch (error) {
        logger.warn('Error selecting random suggested email', { error: error.message });
        return false;
    }
}

/**
 * Click "Create your own Gmail address" if suggested emails are shown
 * النقر على "إنشاء عنوان Gmail الخاص بك" إذا ظهرت اقتراحات البريد الإلكتروني
 */
async function clickCreateOwnGmailAddress(page) {
    try {
        logger.info('Checking for suggested emails page');
        await page.waitForTimeout(2000);

        // Check if we're on the suggested emails page by looking for the link/button
        const createOwnSelectors = [
            '//button[contains(text(), "Create your own Gmail address")]',
            '//a[contains(text(), "Create your own Gmail address")]',
            '//span[contains(text(), "Create your own Gmail address")]',
            'button:has-text("Create your own Gmail address")',
            'a:has-text("Create your own Gmail address")',
            '[aria-label*="Create your own Gmail address" i]'
        ];

        let clicked = false;
        for (const selector of createOwnSelectors) {
            try {
                if (selector.startsWith('//')) {
                    // XPath selector
                    const elements = await page.$x(selector);
                    if (elements.length > 0) {
                        const element = elements[0];
                        const isVisible = await page.evaluate(el => {
                            const style = window.getComputedStyle(el);
                            return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
                        }, element);
                        
                        if (isVisible) {
                            await element.click();
                            logger.info('Clicked "Create your own Gmail address" (XPath)');
                            clicked = true;
                            await page.waitForTimeout(2000);
                            break;
                        }
                    }
                } else {
                    // CSS selector
                    const element = await waitForElement(page, selector, 3000);
                    if (element) {
                        const isVisible = await page.evaluate(el => {
                            const style = window.getComputedStyle(el);
                            return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
                        }, element);
                        
                        if (isVisible) {
                            await element.click();
                            logger.info('Clicked "Create your own Gmail address" (CSS)');
                            clicked = true;
                            await page.waitForTimeout(2000);
                            break;
                        }
                    }
                }
            } catch (e) {
                logger.debug(`Create own Gmail selector failed: ${selector}`, { error: e.message });
                continue;
            }
        }

        // Try finding by text content as fallback
        if (!clicked) {
            try {
                const button = await page.evaluateHandle(() => {
                    const buttons = Array.from(document.querySelectorAll('button, a, span, div'));
                    return buttons.find(btn => {
                        const text = btn.textContent.toLowerCase();
                        return (text.includes('create your own') && text.includes('gmail address')) ||
                               (text.includes('create') && text.includes('own') && text.includes('email'));
                    });
                });

                if (button && button.asElement()) {
                    const isVisible = await page.evaluate(el => {
                        const style = window.getComputedStyle(el);
                        return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
                    }, button.asElement());
                    
                    if (isVisible) {
                        await button.asElement().click();
                        logger.info('Clicked "Create your own Gmail address" (text search)');
                        clicked = true;
                        await page.waitForTimeout(2000);
                    }
                }
            } catch (e) {
                logger.debug('Could not find "Create your own Gmail address" by text', { error: e.message });
            }
        }

        if (!clicked) {
            logger.info('No suggested emails page detected, proceeding to username input');
        }
    } catch (error) {
        logger.warn('Error checking for suggested emails page', { error: error.message });
        // Continue anyway - might already be on username input page
    }
}

/**
 * Fill the username (email)
 */
async function fillUsernameForm(page, accountData) {
    try {
        logger.info('Filling username');
        
        // Human behavior: Wait and explore page before filling
        // سلوك بشري: الانتظار واستكشاف الصفحة قبل الملء
        await humanSleep(getHumanDelay('pageLoad'));
        await idleMouseMovement(page, { movements: 2 });

        // A later signup step never needs a username fallback.
        const stage = getSignupStage(page.url());
        if (!stage) throw new ManualSignupRequiredError('untrusted-page');
        if (isPostVerificationStage(stage) || ['password', 'phone', 'verification'].includes(stage)) return;

        // Detect current page type - check multiple times to ensure we're on the right page
        let currentPage = await detectGmailPage(page);
        let retryCount = 0;
        const maxRetries = 3;
        
        while (retryCount < maxRetries) {
            if (currentPage) {
                if (['PASSWORD_INPUT', 'PHONE_VERIFICATION', 'VERIFICATION_CODE'].includes(currentPage.type)) return;

                logger.info('Page detected before username', {
                    type: currentPage.type,
                    method: currentPage.method || 'unknown',
                    url: page.url(),
                    retry: retryCount
                });

                // If we're on birthday/gender page, fill it first
                if (currentPage.type === 'BIRTHDAY_GENDER') {
                    logger.info('Detected Birthday/Gender page, filling form first...');
                    await fillBirthdayAndGenderForm(page, accountData);
                    // Wait and re-detect page after filling birthday/gender
                    await page.waitForTimeout(3000);
                    currentPage = await detectGmailPage(page);
                    retryCount++;
                    continue; // Check again after filling birthday/gender
                }

  

                // Check if we're actually on birthday/gender page (even if detected as SIGN_UP_FORM)
                const hasBirthdayFields = await page.evaluate(() => {
                    return !!(
                        document.querySelector('input[name="day"], input[aria-label*="day" i]') &&
                        (document.querySelector('div[jsname="O1htCb"]') || document.querySelector('#month, select[name="month"]')) &&
                        document.querySelector('input[name="year"], input[aria-label*="year" i]') &&
                        (document.querySelector('div[jsname="ZU2VHd"]') || document.querySelector('#gender, select[name="gender"]'))
                    );
                });

                if (hasBirthdayFields) {
                    logger.info('Birthday/Gender fields detected on page, filling form first...');
                    await fillBirthdayAndGenderForm(page, accountData);
                    await page.waitForTimeout(3000);
                    currentPage = await detectGmailPage(page);
                    retryCount++;
                    continue;
                }

                    // If we're on suggested emails page, select a random suggestion
                if (currentPage.type === 'SUGGESTED_EMAILS') {
                    logger.info('Detected suggested emails page, selecting a random suggestion');
                    const selected = await selectRandomSuggestedEmail(page);
                    if (selected && selected.success) {
                        // Update accountData with selected email
                        accountData.email = selected.email;
                        accountData.username = selected.username;
                        logger.info('Updated accountData with selected email', { 
                            email: selected.email, 
                            username: selected.username 
                        });
                        
                        // Click Next button after selecting
                        await page.waitForTimeout(1000);
                        await clickNextButton(page);
                        await page.waitForTimeout(2000);
                        currentPage = await detectGmailPage(page);
                        retryCount++;
                        continue; // Check again after selecting
                    } else {
                        // Fallback to "Create your own" if selection failed
                        logger.info('Failed to select suggested email, falling back to "Create your own"');
                        await clickCreateOwnGmailAddress(page);
                        await page.waitForTimeout(2000);
                        currentPage = await detectGmailPage(page);
                        retryCount++;
                        continue;
                    }
                }
                
                // If we're on username input page, break and proceed
                if (currentPage.type === 'USERNAME_INPUT') {
                    logger.info('On correct page for username input, proceeding...');
                    break;
                }

                // If detected as SIGN_UP_FORM but no birthday fields, might be username page
                if (currentPage.type === 'SIGN_UP_FORM' && !hasBirthdayFields) {
                    logger.info('SIGN_UP_FORM detected but no birthday fields, checking for username input...');
                    // Check if username input exists (more comprehensive check)
                    const hasUsernameInput = await page.evaluate(() => {
                        return !!(
                            document.querySelector('input[aria-label*="Gmail address" i]') ||
                            document.querySelector('input[aria-label*="email address" i]') ||
                            document.querySelector('input[aria-label*="username" i]') ||
                            document.querySelector('input[type="email"]') ||
                            document.querySelector('input[name="Username"]') ||
                            document.querySelector('input[name="username"]') ||
                            document.querySelector('input[autocomplete="username"]') ||
                            // Check for username input by placeholder or label
                            Array.from(document.querySelectorAll('input')).some(input => {
                                const label = input.getAttribute('aria-label') || input.getAttribute('placeholder') || '';
                                return label.toLowerCase().includes('gmail') || 
                                       label.toLowerCase().includes('email') ||
                                       label.toLowerCase().includes('username');
                            })
                        );
                    });
                    
                    // Also check if URL suggests we're past the name page
                    const currentUrl = page.url();
                    const isPastNamePage = currentUrl.includes('/username') || 
                                          currentUrl.includes('/email') ||
                                          (!currentUrl.includes('/name') && !currentUrl.includes('/signup/name'));
                    
                    if (hasUsernameInput || isPastNamePage) {
                        logger.info('Username input found or past name page, proceeding...', { 
                            hasUsernameInput, 
                            isPastNamePage,
                            url: currentUrl 
                        });
                        break;
                    }
                    
                    // If we're still on name page and no username input, wait more
                    if (currentUrl.includes('/name') || currentUrl.includes('/signup/name')) {
                        logger.info('Still on name page, waiting for navigation to username page...');
                        await page.waitForTimeout(3000);
                        currentPage = await detectGmailPage(page);
                        retryCount++;
                        continue;
                    }
                }

                // If page type is unknown or unexpected, wait and retry
                if (currentPage.type === 'UNKNOWN' || retryCount < maxRetries - 1) {
                    logger.info('Page type not ready yet, waiting and retrying...', { type: currentPage.type });
                    await page.waitForTimeout(2000);
                    currentPage = await detectGmailPage(page);
                    retryCount++;
                    continue;
                }
            } else {
                // If page detection failed, wait and retry
                if (retryCount < maxRetries - 1) {
                    logger.warn('Page detection failed, retrying...', { retry: retryCount });
                    await page.waitForTimeout(2000);
                    currentPage = await detectGmailPage(page);
                    retryCount++;
                    continue;
                }
            }
            break;
        }

        // Final check: if still on birthday/gender page, fill it
        const finalPageCheck = await detectGmailPage(page);
        if (finalPageCheck && finalPageCheck.type === 'BIRTHDAY_GENDER') {
            logger.warn('Still on Birthday/Gender page after retries, filling form now...');
            await fillBirthdayAndGenderForm(page, accountData);
            await page.waitForTimeout(3000);
        }

        // Always check for suggested emails page by checking for radio buttons directly
        // This is more reliable than page detection since the URL might contain /username
        logger.info('Checking for suggested emails page by looking for radio buttons...');
        const hasSuggestedEmails = await page.evaluate(() => {
            const radioButtons = document.querySelectorAll('input[type="radio"][name="usernameRadio"]');
            const hasCustomOption = Array.from(radioButtons).some(radio => radio.value === 'custom');
            const hasNonCustomOptions = Array.from(radioButtons).some(radio => radio.value !== 'custom' && radio.value);
            
            return radioButtons.length > 0 && hasCustomOption && hasNonCustomOptions;
        });
        
        if (hasSuggestedEmails) {
            logger.info('Detected suggested emails page by radio buttons, selecting random suggestion');
            const selected = await selectRandomSuggestedEmail(page);
            if (selected && selected.success) {
                // Update accountData with selected email
                accountData.email = selected.email;
                accountData.username = selected.username;
                logger.info('Updated accountData with selected email', { 
                    email: selected.email, 
                    username: selected.username 
                });
                
                // Click Next button after selecting
                await page.waitForTimeout(1000);
                await clickNextButton(page);
                await page.waitForTimeout(2000);
                
                // Re-check after clicking Next to see if we need to continue
                const pageAfterSelection = await detectGmailPage(page);
                if (pageAfterSelection && pageAfterSelection.type === 'USERNAME_INPUT') {
                    logger.info('Still on username input page after selecting suggested email, continuing...');
                    // Continue to fill username if needed
                } else {
                    logger.info('Navigated away from suggested emails page after selection');
                    // The selected email was accepted, we can skip username input
                    return;
                }
            } else {
                // Fallback to "Create your own" if selection failed
                logger.info('Failed to select suggested email, falling back to "Create your own"');
                await clickCreateOwnGmailAddress(page);
                await page.waitForTimeout(2000);
            }
        } else {
            // Check page detection as fallback
            const pageBeforeUsername = await detectGmailPage(page);
            if (pageBeforeUsername && pageBeforeUsername.type === 'SUGGESTED_EMAILS') {
                logger.info('Detected suggested emails page by page detection, selecting random suggestion');
                const selected = await selectRandomSuggestedEmail(page);
                if (selected && selected.success) {
                    accountData.email = selected.email;
                    accountData.username = selected.username;
                    logger.info('Updated accountData with selected email', { 
                        email: selected.email, 
                        username: selected.username 
                    });
                    
                    await page.waitForTimeout(1000);
                    await clickNextButton(page);
                    await page.waitForTimeout(2000);
                    
                    const pageAfterSelection = await detectGmailPage(page);
                    if (pageAfterSelection && pageAfterSelection.type === 'USERNAME_INPUT') {
                        logger.info('Still on username input page after selecting suggested email, continuing...');
                    } else {
                        logger.info('Navigated away from suggested emails page after selection');
                        return;
                    }
                } else {
                    logger.info('Failed to select suggested email, falling back to "Create your own"');
                    await clickCreateOwnGmailAddress(page);
                }
            } else if (!pageBeforeUsername || pageBeforeUsername.type !== 'USERNAME_INPUT') {
                // Fallback: try to click "Create your own Gmail address" anyway
                logger.info('Trying fallback: click "Create your own Gmail address"');
                await clickCreateOwnGmailAddress(page);
            }
        }

        // Wait for username input field to appear (after clicking "Create your own Gmail address")
        // Wait more if we're still on name page
        const currentUrlAfterClick = page.url();
        if (currentUrlAfterClick.includes('/name') || currentUrlAfterClick.includes('/signup/name')) {
            logger.info('Still on name page after clicking, waiting for navigation to username page...');
            for (let waitAttempt = 0; waitAttempt < 10; waitAttempt++) {
                await page.waitForTimeout(2000);
                const newUrl = page.url();
                logger.info('Waiting for navigation...', { attempt: waitAttempt + 1, url: newUrl });
                if (!newUrl.includes('/name') && !newUrl.includes('/signup/name')) {
                    logger.info('Navigation completed to username/email page');
                    break;
                }
            }
        } else {
            await page.waitForTimeout(2000);
        }

        // Generate a longer username by appending random characters
        const originalUsername = accountData.username;
        const makeLongUsername = (baseUsername) => {
            const randomChars = 'abcdefghijklmnopqrstuvwxyz0123456789';
            let longUsername = baseUsername;
            // Add 10-15 more random characters to make it longer
            const additionalLength = 10 + Math.floor(Math.random() * 6);
            for (let i = 0; i < additionalLength; i++) {
                longUsername += randomChars[Math.floor(Math.random() * randomChars.length)];
            }
            return longUsername;
        };

        const longUsername = makeLongUsername(originalUsername);
        // Update accountData to use the long username
        accountData.username = longUsername;
        accountData.email = `${longUsername}@gmail.com`;
        logger.info('Generated long username', { originalLength: originalUsername.length, newLength: longUsername.length, username: longUsername });

        // Fill username (email) - wait for field to be ready and visible
        logger.info('Waiting for username input field to appear and be visible...');
        let usernameFieldReady = false;
        for (let waitAttempt = 0; waitAttempt < 15; waitAttempt++) {
            const usernameFieldInfo = await page.evaluate(() => {
                const selectors = [
                    'input[aria-label*="Gmail address" i]',
                    'input[aria-label*="email address" i]',
                    'input[aria-label*="username" i]',
                    'input[type="email"]',
                    'input[name="Username"]',
                    'input[name="username"]',
                    'input[autocomplete="username"]'
                ];
                
                for (const selector of selectors) {
                    const input = document.querySelector(selector);
                    if (input) {
                        const style = window.getComputedStyle(input);
                        const isVisible = style.display !== 'none' && 
                                         style.visibility !== 'hidden' && 
                                         input.offsetParent !== null &&
                                         !input.disabled;
                        if (isVisible) {
                            return { found: true, selector };
                        }
                    }
                }
                return { found: false };
            });
            
            if (usernameFieldInfo.found) {
                logger.info('Username input field found and visible', { 
                    selector: usernameFieldInfo.selector
                });
                usernameFieldReady = true;
                break;
            }
            
            if (waitAttempt < 14) {
                logger.info('Username input field not found yet, waiting...', { attempt: waitAttempt + 1 });
                await page.waitForTimeout(2000);
            }
        }
        
        if (!usernameFieldReady) {
            logger.warn('Username input field not found after waiting, but will try to fill anyway');
        }

        const usernameSelectors = [
            '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[2]/div/div/div/form/span/section/div/div/div[2]/div[1]/div[1]/div[1]/div/div[1]/input', // User-provided XPath (after clicking "Create your own Gmail address")
            '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[2]/div/div/div/form/span/section/div/div/div/div[1]/div[1]/div[1]/div/div[1]/input', // Fallback XPath
            'input[name="Username"]',
            'input[aria-label="Create a Gmail address"]',
            'input[aria-label*="Gmail address" i]',
            '#username',
            'input[type="email"]',
            'input[aria-label*="username" i]'
        ];

        let usernameFilled = false;
        for (const selector of usernameSelectors) {
            try {
                let input;
                if (selector.startsWith('/html') || selector.startsWith('//')) {
                    // XPath selector
                    await page.waitForXPath(selector, { timeout: 5000 });
                    const elements = await page.$x(selector);
                    if (elements.length > 0) {
                        input = elements[0];
                    }
                } else {
                    // CSS selector
                    input = await waitForElement(page, selector, 3000);
                }

                if (input) {
                    await humanLikeType(page, input, longUsername, {
                        minDelay: 35,
                        maxDelay: 100,
                        mistakeChance: 0.12,
                        pauseChance: 0.18
                    });
                    logger.info('Long username entered', { username: longUsername, selector: selector.substring(0, 50) + '...' });
                    usernameFilled = true;
                    break;
                }
            } catch (e) {
                logger.debug(`Username selector failed: ${selector.substring(0, 50)}`, { error: e.message });
                continue;
            }
        }

        if (!usernameFilled) {
            logger.warn('Could not find username input field');
        }

        await page.waitForTimeout(500);
        await clickNextButton(page);
        await page.waitForTimeout(3000);

    } catch (error) {
        if (!(error instanceof ManualSignupRequiredError)) {
            logger.error('Failed to fill username form', { error });
        }
        throw error;
    }
}

/**
 * Fill birthday and gender form
 * ملء نموذج تاريخ الميلاد والجنس
 */
async function fillBirthdayAndGenderForm(page, accountData) {
    try {
        logger.info('Filling birthday and gender form');

        // Human behavior: Wait and read the form before filling
        // سلوك بشري: الانتظار وقراءة النموذج قبل الملء
        await humanSleep(getHumanDelay('pageLoad'));
        await simulateReading(page, { duration: 1000 + Math.random() * 500, scrollWhileReading: false });
        await idleMouseMovement(page, { movements: 1 + Math.floor(Math.random() * 2) });

        // Generate random birthday (age between 18-65)
        const currentYear = new Date().getFullYear();
        const age = 18 + Math.floor(Math.random() * 47); // 18-65 years old
        const birthYear = currentYear - age;
        const birthMonth = Math.floor(Math.random() * 12) + 1; // 1-12
        const birthDay = Math.floor(Math.random() * 28) + 1; // 1-28 (safe for all months)

        // Fill day
        const daySelectors = [
            'input[name="day"]',
            'input[aria-label*="day" i]',
            'input[type="number"][aria-label*="day" i]'
        ];

        let dayFilled = false;
        for (const selector of daySelectors) {
            try {
                const input = await waitForElement(page, selector, 3000);
                if (input) {
                    // Human behavior: Scroll to element and click naturally
                    // سلوك بشري: التمرير إلى العنصر والنقر بشكل طبيعي
                    await humanScrollToElement(page, input);
                    await humanClick(page, input, { preClickDelay: true, postClickDelay: false, doubleClick: true });
                    
                    await humanType(page, input, birthDay.toString(), {
                        minDelay: 60,
                        maxDelay: 120,
                        mistakeChance: 0.05,
                        pauseChance: 0.10
                    });
                    logger.info('Day entered', { day: birthDay });
                    dayFilled = true;
                    break;
                }
            } catch (e) {
                continue;
            }
        }

        if (!dayFilled) {
            logger.warn('Could not find day input field');
        }

        // Human behavior: Pause between fields
        await humanSleep(getHumanDelay('betweenActions'));

        // Fill month (custom dropdown - click to open, then select option)
        const monthXPath = '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[2]/div/div/div/form/span/section/div/div/div[1]/div[1]/div[2]/div/div[1]';
        let monthFilled = false;

        try {
            // Click on month dropdown to open it
            await page.waitForXPath(monthXPath, { timeout: 5000 });
            const monthDropdowns = await page.$x(monthXPath);
            if (monthDropdowns.length > 0) {
                await monthDropdowns[0].click();
                logger.info('Month dropdown opened');
                await page.waitForTimeout(1000); // Wait for dropdown menu to appear

                // Select month option by data-value (1-12)
                const monthOptionXPath = `//li[@role="option"][@data-value="${birthMonth}"]`;
                await page.waitForXPath(monthOptionXPath, { timeout: 3000 });
                const monthOptions = await page.$x(monthOptionXPath);
                if (monthOptions.length > 0) {
                    await monthOptions[0].click();
                    logger.info('Month selected', { month: birthMonth });
                    monthFilled = true;
                } else {
                    // Fallback: try to find by text
                    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                        'July', 'August', 'September', 'October', 'November', 'December'];
                    const monthName = monthNames[birthMonth - 1];
                    const monthTextXPath = `//li[@role="option"]//span[contains(text(), "${monthName}")]`;
                    const monthTextOptions = await page.$x(monthTextXPath);
                    if (monthTextOptions.length > 0) {
                        await monthTextOptions[0].click();
                        logger.info('Month selected by text', { month: monthName });
                        monthFilled = true;
                    }
                }
            }
        } catch (e) {
            logger.debug('Month XPath method failed, trying fallback', { error: e.message });
        }

        // Fallback to old method if XPath failed
        if (!monthFilled) {
            const monthSelectors = [
                '#month',
                'select[name="month"]',
                'select[aria-label*="month" i]'
            ];

            for (const selector of monthSelectors) {
                try {
                    const select = await waitForElement(page, selector, 3000);
                    if (select) {
                        const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                            'July', 'August', 'September', 'October', 'November', 'December'];
                        const monthName = monthNames[birthMonth - 1];
                        await select.select({ label: monthName });
                        logger.info('Month selected by fallback method', { month: monthName });
                        monthFilled = true;
                        break;
                    }
                } catch (e) {
                    continue;
                }
            }
        }

        if (!monthFilled) {
            logger.warn('Could not find month select field');
        }

        await page.waitForTimeout(500);

        // Fill year
        const yearSelectors = [
            'input[name="year"]',
            'input[aria-label*="year" i]',
            'input[type="number"][aria-label*="year" i]'
        ];

        let yearFilled = false;
        for (const selector of yearSelectors) {
            try {
                const input = await waitForElement(page, selector, 3000);
                if (input) {
                    await input.click({ clickCount: 3 });
                    await page.waitForTimeout(200);
                    await humanLikeType(page, input, birthYear.toString(), {
                        minDelay: 60,
                        maxDelay: 120,
                        mistakeChance: 0.05,
                        pauseChance: 0.10
                    });
                    logger.info('Year entered', { year: birthYear });
                    yearFilled = true;
                    break;
                }
            } catch (e) {
                continue;
            }
        }

        if (!yearFilled) {
            logger.warn('Could not find year input field');
        }

        await page.waitForTimeout(500);

        // Select gender (custom dropdown - click to open, then select option)
        const genderXPath = '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[2]/div/div/div/form/span/section/div/div/div[2]/div[1]/div[1]';
        
        // User-provided XPath selectors for gender options
        const genderOptionXPaths = {
            'male': '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[2]/div/div/div/form/span/section/div/div/div[2]/div[1]/div[1]/div/div[2]/ul/li[1]', // رجل
            'female': '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[2]/div/div/div/form/span/section/div/div/div[2]/div[1]/div[1]/div/div[2]/ul/li[2]' // بنت
        };

        const genderTextMap = {
            'male': 'Male',
            'female': 'Female'
        };
        const genderText = genderTextMap[accountData.gender] || 'Male'; // Default to Male
        const selectedGender = accountData.gender || 'male';

        let genderFilled = false;

        try {
            // Click on gender dropdown to open it
            await page.waitForXPath(genderXPath, { timeout: 5000 });
            const genderDropdowns = await page.$x(genderXPath);
            if (genderDropdowns.length > 0) {
                await genderDropdowns[0].click();
                logger.info('Gender dropdown opened');
                await page.waitForTimeout(1500); // Wait for dropdown menu to appear

                // Try user-provided XPath first (most reliable)
                const userProvidedXPath = genderOptionXPaths[selectedGender];
                if (userProvidedXPath) {
                    try {
                        await page.waitForXPath(userProvidedXPath, { timeout: 3000 });
                        const genderOptions = await page.$x(userProvidedXPath);
                        if (genderOptions.length > 0) {
                            // Check if element is visible
                            const isVisible = await page.evaluate(el => {
                                const style = window.getComputedStyle(el);
                                return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
                            }, genderOptions[0]);

                            if (isVisible) {
                                await genderOptions[0].click();
                                logger.info('Gender selected by user-provided XPath', { gender: genderText, xpath: userProvidedXPath });
                                genderFilled = true;
                            }
                        }
                    } catch (e) {
                        logger.debug('User-provided XPath failed, trying fallback methods', { error: e.message });
                    }
                }

                // Fallback: try by data-value if user-provided XPath failed
                if (!genderFilled) {
                    const genderValueMap = {
                        'male': '1',
                        'female': '2'
                    };
                    const genderDataValue = genderValueMap[selectedGender] || '1';
                    const genderOptionXPath = `//li[@role="option"][@data-value="${genderDataValue}"]`;
                    try {
                        await page.waitForXPath(genderOptionXPath, { timeout: 3000 });
                        const genderOptions = await page.$x(genderOptionXPath);
                        if (genderOptions.length > 0) {
                            await genderOptions[0].click();
                            logger.info('Gender selected by data-value', { gender: genderText, dataValue: genderDataValue });
                            genderFilled = true;
                        }
                    } catch (e) {
                        logger.debug('Data-value method failed, trying text search', { error: e.message });
                    }
                }

                // Fallback: try to find by text
                if (!genderFilled) {
                    const genderTextXPath = `//li[@role="option"]//span[contains(text(), "${genderText}")]`;
                    try {
                        const genderTextOptions = await page.$x(genderTextXPath);
                        if (genderTextOptions.length > 0) {
                            await genderTextOptions[0].click();
                            logger.info('Gender selected by text', { gender: genderText });
                            genderFilled = true;
                        }
                    } catch (e) {
                        logger.debug('Text search method failed', { error: e.message });
                    }
                }
            }
        } catch (e) {
            logger.debug('Gender dropdown click failed, trying fallback', { error: e.message });
        }

        // Final fallback: try CSS selectors
        if (!genderFilled) {
            const genderSelectors = [
                '#gender',
                'select[name="gender"]',
                'select[aria-label*="gender" i]'
            ];

            for (const selector of genderSelectors) {
                try {
                    const select = await waitForElement(page, selector, 3000);
                    if (select) {
                        await select.select(genderText);
                        logger.info('Gender selected by CSS selector fallback', { gender: genderText });
                        genderFilled = true;
                        break;
                    }
                } catch (e) {
                    continue;
                }
            }
        }

        if (!genderFilled) {
            logger.warn('Could not find gender select field');
            // Try one more time with a different approach
            try {
                // Try clicking the dropdown again and using the direct XPath
                const genderDropdownXPath = '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[2]/div/div/div/form/span/section/div/div/div[2]/div[1]/div[1]';
                const dropdowns = await page.$x(genderDropdownXPath);
                if (dropdowns.length > 0) {
                    await dropdowns[0].click();
                    await page.waitForTimeout(1500);
                    
                    const directGenderXPath = genderOptionXPaths[selectedGender];
                    if (directGenderXPath) {
                        const options = await page.$x(directGenderXPath);
                        if (options.length > 0) {
                            await options[0].click();
                            logger.info('Gender selected on retry', { gender: genderText });
                            genderFilled = true;
                        }
                    }
                }
            } catch (e) {
                logger.warn('Retry gender selection failed', { error: e.message });
            }
        }

        // Wait for gender dropdown to close after selection
        if (genderFilled) {
            await page.waitForTimeout(1000);
            logger.info('Gender selection completed, waiting for dropdown to close');
        }

        await page.waitForTimeout(500);

        // Verify all fields were filled before clicking Next
        const allFieldsFilled = dayFilled && monthFilled && yearFilled && genderFilled;
        if (!allFieldsFilled) {
            logger.warn('Not all birthday/gender fields were filled', {
                dayFilled,
                monthFilled,
                yearFilled,
                genderFilled
            });
            // Continue anyway - might still work
        } else {
            logger.info('All birthday/gender fields filled successfully');
        }

        // Click Next button - use specific XPath for birthday/gender page
        const birthdayNextButtonXPath = '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[3]/div/div/div/div/button';
        let nextClicked = false;

        // Try specific XPath for birthday/gender page first
        try {
            await page.waitForXPath(birthdayNextButtonXPath, { timeout: 5000 });
            const nextButtons = await page.$x(birthdayNextButtonXPath);
            if (nextButtons.length > 0) {
                const button = nextButtons[0];
                const isVisible = await page.evaluate(el => {
                    const style = window.getComputedStyle(el);
                    return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
                }, button);
                const isDisabled = await page.evaluate(el => el.disabled, button);

                if (isVisible && !isDisabled) {
                    await button.click();
                    logger.info('Next button clicked (Birthday/Gender page specific XPath)');
                    nextClicked = true;
                } else {
                    logger.debug('Next button found but not clickable', { isVisible, isDisabled });
                }
            }
        } catch (e) {
            logger.debug('Birthday/Gender specific XPath failed, trying general method', { error: e.message });
        }

        // Fallback to general clickNextButton function
        if (!nextClicked) {
            nextClicked = await clickNextButton(page);
        }

        if (!nextClicked) {
            throw new Error('Could not click Next button after filling birthday and gender');
        }

        // Wait for page to navigate after clicking Next
        await page.waitForTimeout(3000);

        // Verify we're no longer on the birthday/gender page
        const pageAfterNext = await detectGmailPage(page);
        if (pageAfterNext && pageAfterNext.type === 'BIRTHDAY_GENDER') {
            logger.warn('Still on Birthday/Gender page after clicking Next, waiting longer...');
            await page.waitForTimeout(3000);
            const pageAfterWait = await detectGmailPage(page);
            if (pageAfterWait) {
                logger.info('Page after additional wait', {
                    type: pageAfterWait.type,
                    method: pageAfterWait.method || 'unknown',
                    url: page.url()
                });
            }
        } else if (pageAfterNext) {
            logger.info('Successfully navigated away from Birthday/Gender page', {
                newPageType: pageAfterNext.type,
                method: pageAfterNext.method || 'unknown',
                url: page.url()
            });
        }

        logger.info('Birthday and gender form filled successfully');
    } catch (error) {
        logger.error('Failed to fill birthday and gender form', { error: error.message });
        throw error;
    }
}

/**
 * Complete account creation
 * إكمال إنشاء الحساب
 */
async function completeAccountCreation(page) {
    try {
        logger.info('Completing account creation');

        await page.waitForTimeout(2000);
        let stage = await skipOptionalRecoveryEmail(page);

        const confirmationXPath = '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[3]/div/div[1]/div/div/button';
        const identifierXPath = '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[3]/div/div/div/div/button';

        for (const expectedStage of FINAL_SIGNUP_STEPS) {
            if (stage !== expectedStage) continue;

            if (stage === 'termsofservice') {
                // Preserve scrolling within the terms page before reading the button.
                await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
                await page.waitForTimeout(1000);
                await page.evaluate(() => {
                    for (const scrollable of document.querySelectorAll('[style*="overflow"]')) {
                        scrollable.scrollTop = scrollable.scrollHeight;
                    }
                });
                await page.waitForTimeout(1000);
            }

            const xpath = stage === 'confirmidentifier' ? identifierXPath : confirmationXPath;
            let button;
            try {
                await page.waitForXPath(xpath, { timeout: 5000 });
                [button] = await page.$x(xpath);
            } catch (error) {
                logger.debug('Could not find the final signup control', { stage, error });
            }

            if (!(await clickSignupConfirmation(button, stage))) {
                throw new ManualSignupRequiredError('completion');
            }
            await page.waitForTimeout(stage === 'confirmation' ? 2000 : 3000);
            stage = await skipOptionalRecoveryEmail(page);
        }

        if (stage !== 'complete') throw new ManualSignupRequiredError('completion');
        logger.info('Account creation appears successful');
    } catch (error) {
        if (!(error instanceof ManualSignupRequiredError)) {
            logger.error('Failed to complete account creation', { error });
        }
        throw error;
    }
}

/**
 * Click Next button
 * الضغط على زر التالي
 */
async function clickNextButton(page) {
    if (getSignupStage(page.url()) === 'recovery-email') {
        throw new ManualSignupRequiredError('recovery-email');
    }
    try {
        // Human behavior: Wait a bit before clicking (like human deciding to click)
        // سلوك بشري: الانتظار قليلاً قبل النقر (مثل قرار الإنسان بالنقر)
        await humanSleep(getHumanDelay('beforeClick'));

        // Try XPath first (most reliable for Google forms)
        const xpathSelectors = [
            '/html/body/div[2]/div[1]/div[1]/div[2]/c-wiz/main/div[3]/div/div/div/div/button',
            '//button[contains(text(), "Next")]',
            '//button[contains(text(), "التالي")]',
            '//button[@jsname="OCpkoe"]',
            '//button[contains(@class, "VfPpkd-LgbsSe")]',
            '//button[contains(@aria-label, "Next")]'
        ];

        for (const xpath of xpathSelectors) {
            try {
                await page.waitForXPath(xpath, { timeout: 3000 });
                const buttons = await page.$x(xpath);
                if (buttons.length > 0) {
                    // Check if button is enabled
                    const isEnabled = await page.evaluate((btn) => {
                        return !btn.disabled && btn.offsetParent !== null;
                    }, buttons[0]);
                    
                    if (isEnabled) {
                        // Human behavior: Scroll to button and click with mouse movement
                        // سلوك بشري: التمرير إلى الزر والنقر مع حركة الماوس
                        await humanScrollToElement(page, buttons[0]);
                        await humanClick(page, buttons[0], { preClickDelay: true, postClickDelay: true });
                        logger.info('Next button clicked (XPath)', { xpath });
                        return true;
                    }
                }
            } catch (e) {
                continue;
            }
        }

        // Try CSS selectors
        const cssSelectors = [
            'button:has-text("Next")',
            'button:has-text("التالي")',
            '#next',
            'button[type="button"]:has-text("Next")',
            'button.VfPpkd-LgbsSe',
            'button[jsname="OCpkoe"]'
        ];

        for (const selector of cssSelectors) {
            try {
                const button = await waitForElement(page, selector, 2000);
                if (button) {
                    const isEnabled = await page.evaluate((btn) => {
                        return !btn.disabled && btn.offsetParent !== null;
                    }, button);
                    
                    if (isEnabled) {
                        // Human behavior: Click with mouse movement
                        // سلوك بشري: النقر مع حركة الماوس
                        await humanClick(page, button, { preClickDelay: true, postClickDelay: true });
                        logger.info('Next button clicked (CSS)', { selector });
                        return true;
                    }
                }
            } catch (e) {
                continue;
            }
        }

        // Try finding by text content and button attributes
        try {
            const button = await page.evaluateHandle(() => {
                const buttons = Array.from(document.querySelectorAll('button'));
                return buttons.find(btn => {
                    const text = btn.textContent.toLowerCase().trim();
                    const isNext = (text === 'next' || text === 'التالي' || text.includes('next'));
                    const isVisible = btn.offsetParent !== null;
                    const isEnabled = !btn.disabled;
                    return isNext && isVisible && isEnabled;
                });
            });

            if (button && button.asElement()) {
                // Human behavior: Click with mouse movement
                await humanClick(page, button.asElement(), { preClickDelay: true, postClickDelay: true });
                logger.info('Next button clicked (text search)');
                return true;
            }
        } catch (e) {
            logger.debug('Could not find Next button by text', { error: e.message });
        }

        // Try finding any enabled button that might be Next
        try {
            const button = await page.evaluateHandle(() => {
                // Look for button in the main form area
                const mainArea = document.querySelector('main') || document.body;
                const buttons = Array.from(mainArea.querySelectorAll('button'));
                return buttons.find(btn => {
                    const text = btn.textContent.toLowerCase().trim();
                    const isNext = text === 'next' || text === 'التالي';
                    const isVisible = btn.offsetParent !== null;
                    const isEnabled = !btn.disabled;
                    const hasNextClass = btn.className.includes('VfPpkd-LgbsSe');
                    return (isNext || hasNextClass) && isVisible && isEnabled;
                });
            });

            if (button && button.asElement()) {
                await button.asElement().click();
                logger.info('Next button clicked (fallback search)');
                await page.waitForTimeout(500);
                return true;
            }
        } catch (e) {
            logger.debug('Could not find Next button by fallback', { error: e.message });
        }

        logger.warn('Could not find Next button');
        return false;
    } catch (error) {
        logger.error('Error clicking Next button', { error: error.message });
        return false;
    }
}

export default {
    createGmailAccount
};

