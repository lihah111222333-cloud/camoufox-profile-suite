/**
 * SMS Provider Wrapper
 * اختيار مزود خدمة الأرقام من .env
 * 
 * Supported providers:
 * - 'sms-verification' (default) - SMS Verification API
 * - 'fivesim-legacy' and '5sim-legacy' are disabled
 */

import '../config.js';
import { rejectLegacyOperation } from './fivesim-api-legacy.js';

// Get provider from .env (default: 'sms-verification')
const SMS_PROVIDER = (process.env.SMS_PROVIDER || 'sms-verification').toLowerCase().trim();

// Lazy load providers
let smsProvider = null;
let providerLoaded = false;

async function loadProvider() {
    if (providerLoaded) return smsProvider;

    if (SMS_PROVIDER === 'fivesim-legacy' || SMS_PROVIDER === '5sim-legacy') {
        return rejectLegacyOperation();
    }

    const smsVerifyApi = await import('./sms-verification-api.js');
    smsProvider = {
        // Balance
        getBalance: smsVerifyApi.getSmsVerifyBalance,

        // Buy number
        buyNumber: smsVerifyApi.buySmsVerifyNumber,
        buyNumberAndGetSMS: smsVerifyApi.buyNumberAndGetSMS,

        // Order status
        getOrderStatus: smsVerifyApi.getSmsVerifyStatus,
        waitForSMS: smsVerifyApi.waitForSmsVerifyCode,

        // Order management
        cancelOrder: smsVerifyApi.cancelSmsVerifyOrder,
        finishOrder: smsVerifyApi.finishSmsVerifyOrder,
        requestResend: smsVerifyApi.resendSmsVerifyCode,
        reportNumberUsed: null, // Not available in SMS Verify API

        // Service name for compatibility
        serviceName: 'SMS Verification',
        providerType: 'sms-verification'
    };

    console.log('📱 Using SMS Provider: SMS Verification API');

    providerLoaded = true;
    return smsProvider;
}

// Export unified interface with lazy loading
export const getBalance = async (...args) => {
    const provider = await loadProvider();
    return provider.getBalance(...args);
};

export const buyNumber = async (...args) => {
    const provider = await loadProvider();
    return provider.buyNumber(...args);
};

export const buyNumberAndGetSMS = async (...args) => {
    const provider = await loadProvider();
    return provider.buyNumberAndGetSMS(...args);
};

export const getOrderStatus = async (...args) => {
    const provider = await loadProvider();
    return provider.getOrderStatus(...args);
};

export const waitForSMS = async (...args) => {
    const provider = await loadProvider();
    return provider.waitForSMS(...args);
};

export const cancelOrder = async (...args) => {
    const provider = await loadProvider();
    return provider.cancelOrder(...args);
};

export const finishOrder = async (...args) => {
    const provider = await loadProvider();
    return provider.finishOrder(...args);
};

export const requestResend = async (...args) => {
    const provider = await loadProvider();
    return provider.requestResend(...args);
};

export const reportNumberUsed = async (...args) => {
    const provider = await loadProvider();
    if (!provider.reportNumberUsed) return null;
    return provider.reportNumberUsed(...args);
};

export const setOrderStatus = async (...args) => {
    const provider = await loadProvider();
    return provider.setOrderStatus(...args);
};

export const getServiceName = async () => {
    const provider = await loadProvider();
    return provider.serviceName;
};

export const getProviderType = async () => {
    const provider = await loadProvider();
    return provider.providerType;
};

// Export provider info
export const SMS_PROVIDER_INFO = {
    current: SMS_PROVIDER
};

// For backward compatibility with existing code
export const buySmsVerifyNumber = buyNumber;
export const waitForSmsVerifyCode = waitForSMS;
export const cancelSmsVerifyOrder = cancelOrder;
export const finishSmsVerifyOrder = finishOrder;
export const getSmsVerifyStatus = getOrderStatus;
export const resendSmsVerifyCode = requestResend;

// Export country codes (from SMS Verify API for compatibility)
export { SMS_VERIFY_COUNTRIES } from './sms-verification-api.js';

export default smsProvider;

