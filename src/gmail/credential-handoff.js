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

export class ManualSignupRequiredError extends Error {
    constructor(stage) {
        super('Manual signup is required');
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
