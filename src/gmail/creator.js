/** Gmail signup with an explicit handoff for identity and consent. */

import logger from '../utils/logger.js';
import {
    getSignupStage,
    GOOGLE_ACCOUNTS_ORIGIN,
    ManualSignupRequiredError
} from './credential-handoff.js';

const GMAIL_URL = 'https://gmail.com';

function setRegistrationStep(page, profile, step, metadata = {}) {
    try {
        const target = profile || page?._camoufoxProfile;
        if (typeof target?.setStep === 'function') return target.setStep(step, metadata);
        if (typeof target?.setTrafficStep === 'function') return target.setTrafficStep(step, metadata);
        if (typeof page?.setStep === 'function') return page.setStep(step, metadata);
        if (typeof page?.setTrafficStep === 'function') return page.setTrafficStep(step, metadata);
    } catch {
        // Registration does not depend on telemetry.
    }
}

async function navigateToSignUp(page, signal) {
    try {
        logger.info('Navigating to Gmail signin page first');
        
        // Step 1: Navigate directly to Gmail signin page (where Create account button is)
        // Try with different wait strategies if proxy auth fails
        // محاولة باستراتيجيات انتظار مختلفة إذا فشلت مصادقة البروكسي
        try {
            signal?.throwIfAborted();
            await page.goto(GMAIL_URL, { 
                waitUntil: 'networkidle2', 
                timeout: 60000 
            });
        } catch (gotoError) {
            signal?.throwIfAborted();
            // If proxy auth error, try with domcontentloaded (faster, less strict)
            // إذا كان خطأ مصادقة البروكسي، جرب مع domcontentloaded (أسرع، أقل صرامة)
            if (gotoError.message.includes('ERR_UNEXPECTED_PROXY_AUTH') || 
                gotoError.message.includes('PROXY_AUTH')) {
                logger.warn('Proxy auth error detected, retrying with domcontentloaded', { 
                    error: gotoError.message 
                });
                signal?.throwIfAborted();
                await page.goto(GMAIL_URL, { 
                    waitUntil: 'domcontentloaded', 
                    timeout: 30000 
                });
                // Wait a bit for page to load
                signal?.throwIfAborted();
                await page.waitForTimeout(3000);
            } else {
                throw gotoError;
            }
        }
        
        signal?.throwIfAborted();
        logger.info('Navigated to Gmail signin page');
   
    } catch (error) {
        signal?.throwIfAborted();
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

const NAME_FIELDS = [
    { selector: 'input[name="firstName"]', dataKey: 'firstName' },
    { selector: 'input[name="lastName"]', dataKey: 'lastName' }
];
const USERNAME_FIELDS = [
    { selector: 'input[name="Username"]', dataKey: 'username' }
];

async function advanceSignupStep(page, address, stage, accountData, signal) {
    let handle;
    try {
        // Pin the transport to the observed main document before passing any candidate values.
        signal?.throwIfAborted();
        handle = await page.evaluateHandle(() => document);
        signal?.throwIfAborted();
        const current = await handle.evaluate(expectedDocument => ({
            address: location.href,
            origin: window.origin,
            sameDocument: window.top === window && document === expectedDocument
        }));
        if (current?.sameDocument !== true || current.origin !== GOOGLE_ACCOUNTS_ORIGIN ||
            current.address !== address || page.url() !== address) {
            throw new ManualSignupRequiredError('untrusted-page');
        }

        const fields = stage === 'name' ? NAME_FIELDS : USERNAME_FIELDS;
        const values = stage === 'sign-in' ? [] : fields.map(({ selector, dataKey }) => ({
            selector,
            value: accountData[dataKey]
        }));
        if (values.some(({ value }) => typeof value !== 'string' || value.trim() === '')) {
            throw new ManualSignupRequiredError('completion');
        }

        const interact = openMenu => handle.evaluate((expectedDocument, options) => {
            const { address, origin, stage, values, openMenu } = options;
            const correctDocument = () =>
                window.top === window && document === expectedDocument && window.origin === origin &&
                location.origin === origin && location.href === address;
            if (!correctDocument()) return 'changed';

            const visibleControl = element => {
                const style = window.getComputedStyle(element);
                return element.ownerDocument === document && element.isConnected &&
                    !element.matches(':disabled') && element.getAttribute('aria-disabled') !== 'true' &&
                    element.getClientRects().length > 0 && style.visibility === 'visible' &&
                    style.opacity !== '0';
            };

            const hasExactLabel = (element, allowedLabels) => {
                const text = element.textContent.trim().toLowerCase();
                const ariaLabel = (element.getAttribute('aria-label') || '').trim().toLowerCase();
                return allowedLabels.includes(text || ariaLabel) &&
                    (!text || !ariaLabel || allowedLabels.includes(ariaLabel));
            };

            if (stage === 'sign-in') {
                const identifiers = document.querySelectorAll('input[type="email"], input[name="identifier"], #identifierId');
                if (identifiers.length !== 1 || !visibleControl(identifiers[0]) || identifiers[0].value !== '') {
                    return 'manual';
                }

                const createLabels = ['create account', 'create an account', 'إنشاء حساب'];
                const links = [...document.querySelectorAll('a')].filter(link => {
                    if (!visibleControl(link) || !hasExactLabel(link, createLabels) ||
                        !['', '_self'].includes(link.target) || link.hasAttribute('download')) return false;
                    const target = new URL(link.href);
                    return target.protocol === 'https:' && target.origin === origin && !target.username &&
                        !target.password && /^\/(?:steps\/)?signup(?:\/name)?\/?$/.test(target.pathname);
                });
                if (links.length === 1) {
                    links[0].click();
                    return 'advanced';
                }
                if (!openMenu || links.length !== 0) return 'manual';

                const toggles = [...document.querySelectorAll('div[role="button"]')].filter(element =>
                    visibleControl(element) && hasExactLabel(element, createLabels));
                if (toggles.length !== 1) return 'manual';
                toggles[0].click();
                return 'opened-menu';
            }

            const inputs = values.map(({ selector }) => {
                const controls = [...document.querySelectorAll(selector)];
                return controls.length === 1 ? controls[0] : null;
            });
            if (inputs.some(input => !input || !visibleControl(input) || input.readOnly ||
                input.value !== '' || !['text', 'email'].includes(input.type))) return 'manual';
            if (stage === 'name' && inputs.some(input => input.type !== 'text')) return 'manual';

            const form = inputs[0].form;
            if (!form) return 'manual';
            const correctForm = () => {
                const target = new URL(form.action);
                return form.ownerDocument === document && form.isConnected &&
                    ['', '_self'].includes(form.target) && target.protocol === 'https:' &&
                    target.origin === origin && target.pathname === location.pathname &&
                    !target.username && !target.password &&
                    inputs.every((input, index) => input.form === form &&
                        document.querySelectorAll(values[index].selector).length === 1 &&
                        input.matches(values[index].selector));
            };
            if (!correctForm()) return 'manual';

            // Refuse mixed, unrecognized or already populated forms before input or submission.
            const otherFields = () => [...form.elements].some(element =>
                !inputs.includes(element) && (element.tagName === 'SELECT' || element.tagName === 'TEXTAREA' ||
                    (element.tagName === 'INPUT' && element.type !== 'hidden')));
            const nextControls = () => [...document.querySelectorAll('button')].filter(button =>
                button.form === form && visibleControl(button) &&
                ['button', 'submit'].includes(button.type) &&
                !button.hasAttribute('formaction') && !button.hasAttribute('formtarget') &&
                hasExactLabel(button, ['next', 'التالي']));
            const buttons = nextControls();
            if (otherFields() || buttons.length !== 1) return 'manual';

            for (const [index, input] of inputs.entries()) {
                if (!correctDocument()) return 'changed';
                if (!correctForm() || !visibleControl(input) || input.readOnly || input.value !== '' ||
                    !['text', 'email'].includes(input.type) || (stage === 'name' && input.type !== 'text') ||
                    otherFields()) return 'manual';
                input.value = values[index].value;
                input.dispatchEvent(new Event('input', { bubbles: true }));
            }

            // Input listeners can synchronously replace controls or advance the document.
            if (!correctDocument()) return 'changed';
            const finalButtons = nextControls();
            if (!correctForm() || otherFields() || finalButtons.length !== 1 || finalButtons[0] !== buttons[0] ||
                inputs.some((input, index) => input.form !== form || !visibleControl(input) ||
                    input.value !== values[index].value)) return 'manual';
            buttons[0].click();
            return 'advanced';
        }, { address, origin: GOOGLE_ACCOUNTS_ORIGIN, stage, values, openMenu });

        signal?.throwIfAborted();
        let result = await interact(true);
        if (result === 'opened-menu') {
            signal?.throwIfAborted();
            await page.waitForTimeout(1000);
            signal?.throwIfAborted();
            result = await interact(false);
        }
        if (result !== 'advanced') {
            throw new ManualSignupRequiredError(result === 'changed' ? 'untrusted-page' : 'completion');
        }
    } catch (error) {
        signal?.throwIfAborted();
        if (error instanceof ManualSignupRequiredError) throw error;
        throw new ManualSignupRequiredError('untrusted-page');
    } finally {
        if (handle) {
            try {
                await handle.dispose();
            } catch {
                // The document can disappear after navigation.
            }
        }
    }
}

export async function createGmailAccount(page, accountData, options = {}) {
    const profile = options?.profile;
    const signal = options?.signal;
    try {
        signal?.throwIfAborted();
        setRegistrationStep(page, profile, 'gmail:init');
        if (['about:blank', 'chrome://newtab/'].includes(page.url())) {
            setRegistrationStep(page, profile, 'gmail:navigate-signup');
            await navigateToSignUp(page, signal);

            // A username belongs to this attempt only after our own name step.
            let advancedName = false;
            const initialSteps = [
                ['sign-in', 'gmail:navigate-signup'],
                ['name', 'gmail:fill-name-form'],
                ['username', 'gmail:fill-username']
            ];
            for (const [step, telemetryStep] of initialSteps) {
                signal?.throwIfAborted();
                const address = page.url();
                if (getSignupStage(address) !== step) continue;
                if (step === 'username' && !advancedName) break;
                setRegistrationStep(page, profile, telemetryStep);
                await advanceSignupStep(page, address, step, accountData, signal);
                signal?.throwIfAborted();
                if (step === 'username') break;
                advancedName ||= step === 'name';
                const nextStage = getSignupStage(page.url());
                if (nextStage !== 'unknown' && !initialSteps.some(([initial]) => initial === nextStage)) break;
                await page.waitForTimeout(2000);
            }
        }

        // Handoff reads only the latest URL. The account holder decides how to handle optional prompts.
        signal?.throwIfAborted();
        const stage = getSignupStage(page.url());
        if (!stage) throw new ManualSignupRequiredError('untrusted-page');
        if (stage === 'phone' || stage === 'verification') throw new ManualSignupRequiredError('verification');
        if (stage === 'recovery-email' || stage === 'password') throw new ManualSignupRequiredError(stage);
        // Account home is also reached by existing sessions and proves no new account identity.
        throw new ManualSignupRequiredError('completion');
    } catch (error) {
        signal?.throwIfAborted();
        if (!(error instanceof ManualSignupRequiredError)) throw error;
        setRegistrationStep(page, profile, 'gmail:manual-signup', { stage: error.stage });
        logger.warn(error.message, { stage: error.stage });
        throw error;
    }
}

export default { createGmailAccount };
