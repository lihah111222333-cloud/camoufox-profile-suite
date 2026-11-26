/**
 * Compatibility exports for the retired 5SIM Legacy adapter.
 */

import '../config.js';

export async function rejectLegacyOperation() {
    throw new Error('5SIM Legacy is disabled because the adapter has no verified HTTPS endpoint');
}

export const getLegacyBalance = rejectLegacyOperation;
export const getLegacyNumbersStatus = rejectLegacyOperation;
export const buyLegacyNumber = rejectLegacyOperation;
export const getLegacyOrderStatus = rejectLegacyOperation;
export const setLegacyOrderStatus = rejectLegacyOperation;
export const cancelLegacyOrder = rejectLegacyOperation;
export const finishLegacyOrder = rejectLegacyOperation;
export const requestLegacyResend = rejectLegacyOperation;
export const reportLegacyNumberUsed = rejectLegacyOperation;
export const waitForLegacySMS = rejectLegacyOperation;
export const buyLegacyNumberAndGetSMS = rejectLegacyOperation;

export const LEGACY_DEFAULTS = {
    country: process.env.FIVESIM_COUNTRY || 'england',
    operator: process.env.FIVESIM_OPERATOR || 'any',
    service: process.env.FIVESIM_SERVICE || 'go',
    maxPrice: parseFloat(process.env.FIVESIM_MAX_PRICE) || 50
};

export default {
    getLegacyBalance,
    getLegacyNumbersStatus,
    buyLegacyNumber,
    getLegacyOrderStatus,
    setLegacyOrderStatus,
    cancelLegacyOrder,
    finishLegacyOrder,
    requestLegacyResend,
    reportLegacyNumberUsed,
    waitForLegacySMS,
    buyLegacyNumberAndGetSMS,
    LEGACY_DEFAULTS
};
