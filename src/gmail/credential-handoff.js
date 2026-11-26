export const GOOGLE_ACCOUNTS_ORIGIN = 'https://accounts.google.com';
const GOOGLE_ACCOUNT_HOME_ORIGIN = 'https://myaccount.google.com';
export const FINAL_SIGNUP_STEPS = Object.freeze(['confirmation', 'termsofservice', 'confirmidentifier']);

const FORM_PATHS = {
    'sign-in': /^\/(?:v3\/)?signin\/identifier\/?$|^\/ServiceLogin\/?$/,
    name: /^\/(?:steps\/)?signup\/name\/?$/,
    username: /^\/(?:steps\/)?signup\/username\/?$/
};

const OPTIONAL_STEPS = {
    'recovery-email': /(?:^|\/)addrecoveryemail\/?$/,
    phone: /(?:^|\/)(?:collectemailphone|signup\/phone)\/?$/
};

const MANUAL_SIGNUP_MESSAGES = {
    password: 'Enter the password and continue signup manually on the Google Accounts site.',
    verification: 'Complete verification manually on the Google Accounts site.',
    'recovery-email': 'Skip recovery email or verify and set an address you control on the Google Accounts site.',
    'untrusted-page': 'Signup stopped because the current Google Accounts page could not be verified. Continue in a trusted browser.',
    completion: 'Review the intended account and any consent prompts, then complete or confirm signup manually on the Google Accounts site.'
};

export class ManualSignupRequiredError extends Error {
    constructor(stage) {
        super(MANUAL_SIGNUP_MESSAGES[stage]);
        this.code = 'MANUAL_SIGNUP_REQUIRED';
        this.stage = stage;
    }
}

export function getSignupStage(address) {
    try {
        const url = new URL(address);
        if (url.protocol !== 'https:' || url.username || url.password) return null;
        if (url.origin === GOOGLE_ACCOUNT_HOME_ORIGIN) return 'account-home';
        if (url.origin !== GOOGLE_ACCOUNTS_ORIGIN) return null;

        for (const [step, pattern] of Object.entries(FORM_PATHS)) {
            if (pattern.test(url.pathname)) return step;
        }
        for (const [step, pattern] of Object.entries(OPTIONAL_STEPS)) {
            if (pattern.test(url.pathname)) return step;
        }
        if (/(?:^|\/)(?:challenge|verification)\/(?:phone|sms)(?:\/|$)/.test(url.pathname)) return 'verification';
        if (/(?:^|\/)password(?:\/|$)/.test(url.pathname)) return 'password';
        const lastStep = url.pathname.split('/').filter(Boolean).pop();
        if (FINAL_SIGNUP_STEPS.includes(lastStep)) return lastStep;
        return 'unknown';
    } catch {
        return null;
    }
}

export function isPostVerificationStage(stage) {
    return stage === 'recovery-email' || FINAL_SIGNUP_STEPS.includes(stage);
}

function requireKnownOrigin(address) {
    const stage = getSignupStage(address);
    if (!stage) throw new ManualSignupRequiredError('untrusted-page');
    return stage;
}

async function clickExplicitSkip(page, stage, address) {
    try {
        return await page.evaluate(({ allowedOrigin, expectedUrl, stepPath, fieldSelector }) => {
            // Selection and the action use the same live top-level document.
            if (window.top !== window || window.origin !== allowedOrigin ||
                location.protocol !== 'https:' || location.origin !== allowedOrigin ||
                location.href !== expectedUrl || location.username || location.password ||
                !new RegExp(stepPath).test(location.pathname)) {
                return false;
            }

            if ([...document.querySelectorAll(fieldSelector)].some(input => input.value.trim() !== '')) {
                return false;
            }

            const skipLabels = ['skip', 'تخطي', 'تخطّي'];
            const buttons = [...document.querySelectorAll('button[type="button"]')].filter(button => {
                const label = button.textContent.trim() || button.getAttribute('aria-label') || '';
                const style = window.getComputedStyle(button);
                return skipLabels.includes(label.trim().toLowerCase()) && !button.matches(':disabled') &&
                    button.getAttribute('aria-disabled') !== 'true' && button.getClientRects().length > 0 &&
                    style.visibility === 'visible' && style.opacity !== '0';
            });
            if (buttons.length !== 1) return false;
            buttons[0].click();
            return true;
        }, {
            allowedOrigin: GOOGLE_ACCOUNTS_ORIGIN,
            expectedUrl: address,
            stepPath: OPTIONAL_STEPS[stage].source,
            fieldSelector: stage === 'recovery-email'
                ? 'input[type="email"], input[name="recoveryEmail"]'
                : 'input[type="tel"], input[name="phoneNumberId"]'
        });
    } catch {
        return false;
    }
}

export async function requirePostUsernameStage(page) {
    const address = page.url();
    let stage = requireKnownOrigin(address);
    if (stage === 'phone' && await clickExplicitSkip(page, stage, address)) {
        await page.waitForTimeout(2000);
        stage = requireKnownOrigin(page.url());
    }
    if (isPostVerificationStage(stage)) return;
    if (stage === 'phone' || stage === 'verification') throw new ManualSignupRequiredError('verification');
    throw new ManualSignupRequiredError(stage === 'password' ? 'password' : 'completion');
}

export async function skipOptionalRecoveryEmail(page) {
    const address = page.url();
    const stage = requireKnownOrigin(address);
    if (stage !== 'recovery-email') return stage;
    if (!(await clickExplicitSkip(page, stage, address))) throw new ManualSignupRequiredError(stage);

    await page.waitForTimeout(2000);
    const nextStage = requireKnownOrigin(page.url());
    if (nextStage === 'account-home') throw new ManualSignupRequiredError('completion');
    if (nextStage === stage || !isPostVerificationStage(nextStage)) throw new ManualSignupRequiredError(stage);
    return nextStage;
}
