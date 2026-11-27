/**
 * SMS Verification Number API Integration
 * https://sms-verification-number.com/stubs/handler_api
 * Compatible API with sms-verification-number.com
 */

const SMS_VERIFY_API_URL = 'https://sms-verification-number.com/stubs/handler_api';

// Order status constants
const ORDER_STATUS = {
    WAIT_CODE: 'STATUS_WAIT_CODE',
    CANCEL: 'STATUS_CANCEL',
    OK: 'STATUS_OK'
};

class SmsVerifyKeyError extends Error {}
class SmsVerifyCanceledError extends Error {}

// A receipt can require reconciliation even if the provider never returned an order ID.
class SmsVerifyOrderError extends Error {
    constructor(message, orderId, status) {
        super(message);
        this.name = 'SmsVerifyOrderError';
        this.orderId = orderId;
        this.status = status;
        if (status === 'RECONCILIATION_REQUIRED') this.retryable = false;
    }
}

function unconfirmedPurchase(orderId = null) {
    return new SmsVerifyOrderError(
        'SMS Verification purchase is unconfirmed. Reconcile the order before ordering again.',
        orderId,
        'RECONCILIATION_REQUIRED'
    );
}

function isPriceRefusal(response) {
    return typeof response === 'string' && response.startsWith('WRONG_MAX_PRICE:');
}

function getApiKey() {
    const apiKey = process.env.SMS_VERIFY_API_KEY;
    if (!apiKey?.trim()) {
        throw new SmsVerifyKeyError('SMS Verification API key not configured. Set SMS_VERIFY_API_KEY in .env');
    }
    return apiKey;
}

/**
 * Get language/currency setting (ru = crystals, en = dollars)
 */
function getLang() {
    return process.env.SMS_VERIFY_LANG || 'ru';
}

/**
 * Make API request to SMS Verification service using built-in fetch (zero external dependency required)
 * @param {string} action - API action name
 * @param {Object} params - Additional parameters
 * @returns {Promise<any>} Response data
 */
async function makeRequest(action, params = {}) {
    const apiKey = getApiKey();
    const isPurchase = action === 'getNumber' || action === 'getNumberV2';
    let requestUrl;
    let signal;
    try {
        const queryParams = { ...params, api_key: apiKey, action, lang: getLang() };
        const url = new URL(SMS_VERIFY_API_URL);
        for (const [name, value] of Object.entries(queryParams)) {
            if (value !== undefined && value !== null) {
                url.searchParams.append(name, String(value));
            }
        }
        requestUrl = url.toString();
        signal = typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(30000) : undefined;
    } catch {
        throw new Error('SMS Verification API request could not be prepared');
    }

    let response;
    let data;
    try {
        response = await fetch(requestUrl, {
            method: 'GET',
            redirect: 'error',
            signal
        });
        data = await response.text();
    } catch {
        // Transport errors can contain the key-bearing request URL.
        if (isPurchase) throw unconfirmedPurchase();
        throw new Error('SMS Verification API request failed');
    }

    try {
        data = JSON.parse(data);
    } catch {
        // Keep string response format (e.g. ACCESS_NUMBER:..., BAD_KEY).
    }

    const clientError = response.status >= 400 && response.status < 500;
    if (data === 'BAD_KEY' && (!isPurchase || response.ok || clientError)) {
        throw new SmsVerifyKeyError('BAD_KEY');
    }

    if (!response.ok) {
        const availabilityRefusal = data === 'NO_NUMBERS' || data === 'NO_BALANCE';
        if (isPurchase && !(clientError && (availabilityRefusal || isPriceRefusal(data)))) {
            throw unconfirmedPurchase();
        }
        // Caller handling relies on these error codes. Discard other response text.
        const knownError = availabilityRefusal ? ` (${data})` : '';
        throw new Error(`SMS Verification API returned HTTP ${response.status}${knownError}`);
    }

    return data;
}

/**
 * Check balance
 * @returns {Promise<number>} Current balance
 */
export async function getSmsVerifyBalance() {
    const balance = await makeRequest('getBalance');
    return parseFloat(balance);
}

/**
 * Get available countries and operators
 * @returns {Promise<Array>} List of countries with operators
 */
export async function getSmsVerifyCountries() {
    return makeRequest('getCountryAndOperators');
}

/**
 * Get prices for a country
 * @param {number} country - Country ID
 * @param {string} operator - Operator code (optional)
 * @param {string} service - Service code (optional)
 * @returns {Promise<Object>} Prices data
 */
export async function getSmsVerifyPrices(country, operator, service) {
    const params = { country };
    if (operator) params.operator = operator;
    if (service) params.service = service;

    return makeRequest('getPrices', params);
}

/**
 * Get services with prices and quantities
 * @param {number} country - Country ID
 * @param {string} operator - Operator code (optional)
 * @param {string} service - Service code (optional)
 * @returns {Promise<Array>} Services with prices
 */
export async function getSmsVerifyServices(country, operator, service) {
    const params = { country };
    if (operator) params.operator = operator;
    if (service) params.service = service;

    return makeRequest('getServicesAndCost', params);
}

function numberOrderParams(service, country, operator, { maxPrice }) {
    if (maxPrice !== undefined && (!Number.isFinite(maxPrice) || maxPrice <= 0)) {
        throw new RangeError('maxPrice must be a positive finite number when supplied');
    }
    return { service, country, operator, maxPrice };
}

function parseOrderId(value) {
    const id = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
    return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function isPhoneNumber(value) {
    if (typeof value === 'string') return /^\+?\d+$/.test(value);
    return Number.isSafeInteger(value) && value > 0;
}

/**
 * Buy a number for SMS verification
 * @param {string} service - Service code (e.g., 'fu' for Snapchat)
 * @param {number} country - Country ID (default: 16 for UK)
 * @param {string} operator - Operator code (default: 'any')
 * @param {Object} options - Additional options
 * @param {number} [options.maxPrice] - Positive, finite spending cap
 * @returns {Promise<{id: number, phone: string, price?: number}>}
 * @throws {SmsVerifyOrderError} An unconfirmed purchase requires reconciliation before ordering again.
 */
export async function buySmsVerifyNumber(service = 'fu', country = 16, operator = 'any', options = {}) {
    const response = await makeRequest('getNumber', numberOrderParams(service, country, operator, options));

    // Parse response: ACCESS_NUMBER:ID:NUMBER
    if (typeof response === 'string') {
        if (response === 'NO_BALANCE') {
            throw new Error('Insufficient balance in your SMS Verification account');
        }
        if (response === 'NO_NUMBERS') {
            throw new Error('No phone numbers available for the requested service, country and operator');
        }
        if (isPriceRefusal(response)) {
            throw new Error('Price too low for the requested SMS number');
        }
        if (response.startsWith('ACCESS_NUMBER:')) {
            const parts = response.split(':');
            const id = parseOrderId(parts[1]);
            const phone = parts[2];
            if (id === null || parts.length !== 3 || !isPhoneNumber(phone)) throw unconfirmedPurchase(id);
            return { id, phone };
        }
    }

    throw unconfirmedPurchase();
}

/**
 * Buy number using V2 API (returns JSON)
 * @param {string} service - Service code
 * @param {number} country - Country ID
 * @param {string} operator - Operator code
 * @param {Object} options - Additional options
 * @param {number} [options.maxPrice] - Positive, finite spending cap
 * @returns {Promise<Object>} Order data
 * @throws {SmsVerifyOrderError} An unconfirmed purchase requires reconciliation before ordering again.
 */
export async function buySmsVerifyNumberV2(service = 'fu', country = 16, operator = 'any', options = {}) {
    const response = await makeRequest('getNumberV2', numberOrderParams(service, country, operator, options));

    if (typeof response === 'string') {
        if (response === 'NO_BALANCE') throw new Error('Insufficient balance');
        if (response === 'NO_NUMBERS') throw new Error('No numbers available');
        if (isPriceRefusal(response)) {
            throw new Error('Price too low for the requested SMS number');
        }
    }

    if (!response || typeof response !== 'object' || Array.isArray(response)) throw unconfirmedPurchase();
    const id = parseOrderId(response.activationId);
    if (id === null || !isPhoneNumber(response.phoneNumber)) throw unconfirmedPurchase(id);

    return {
        id: response.activationId,
        phone: response.phoneNumber,
        price: response.activationCost,
        currency: response.currency,
        countryCode: response.countryCode,
        operator: response.activationOperator,
        time: response.activationTime
    };
}

function classifyOrderStatus(response) {
    if (typeof response === 'string') {
        if (response === ORDER_STATUS.WAIT_CODE) return 'PENDING';
        if (response === ORDER_STATUS.CANCEL) return 'CANCELED';
        if (response.startsWith(`${ORDER_STATUS.OK}:`)) return 'RECEIVED';
    }
    return 'UNKNOWN';
}

/**
 * Check the status of an existing order for reconciliation.
 * @param {number} orderId - Order ID
 * @returns {Promise<{status: string}>}
 */
export async function getSmsVerifyOrderStatus(orderId) {
    const response = await makeRequest('getStatus', { id: orderId });
    return { status: classifyOrderStatus(response) };
}

/**
 * Check order status and get SMS code
 * @param {number} orderId - Order ID
 * @returns {Promise<{status: string, code?: string}>}
 */
export async function checkSmsVerifyOrder(orderId) {
    const response = await makeRequest('getStatus', { id: orderId });
    const status = classifyOrderStatus(response);
    const code = status === 'RECEIVED' ? response.split(':')[1] : null;
    return { status, code };
}

/**
 * Set order status
 * @param {number} orderId - Order ID
 * @param {number} status - Status code: 3=retry SMS, 6=finish, 8=cancel
 * @returns {Promise<string>} Response
 */
export async function setSmsVerifyStatus(orderId, status) {
    const response = await makeRequest('setStatus', { id: orderId, status });

    if (response === 'CANNOT_BEFORE_2_MIN') {
        throw new Error('Cannot cancel before 2 minutes after ordering');
    }

    return response;
}

/**
 * Cancel order (only if no SMS received)
 * @param {number} orderId - Order ID
 * @returns {Promise<boolean>} Success
 */
export async function cancelSmsVerifyOrder(orderId) {
    try {
        const response = await setSmsVerifyStatus(orderId, 8);
        return response === 'ACCESS_CANCEL';
    } catch (error) {
        if (error.message.includes('2 minutes')) {
            return false;
        }
        throw error;
    }
}

/**
 * Finish order (complete work with number)
 * @param {number} orderId - Order ID
 * @returns {Promise<boolean>} Success
 */
export async function finishSmsVerifyOrder(orderId) {
    const response = await setSmsVerifyStatus(orderId, 6);
    return response === 'ACCESS_ACTIVATION';
}

/**
 * Request another SMS
 * @param {number} orderId - Order ID
 * @returns {Promise<boolean>} Success
 */
export async function retrySmsVerifyOrder(orderId) {
    const response = await setSmsVerifyStatus(orderId, 3);
    return response === 'ACCESS_RETRY_GET';
}

/**
 * Get current activations list
 * @param {Object} options - Filter options
 * @param {number} options.status - Status filter (0=new, 1=finished, 2=canceled, 3=received, 4=waiting)
 * @param {number} options.limit - Limit results
 * @param {string} options.order - Order by field (id/number/date)
 * @param {string} options.orderBy - Sort direction (ASC/DESC)
 * @returns {Promise<Array>} List of activations
 */
export async function getSmsVerifyActivations(options = {}) {
    const params = {};
    if (options.status !== undefined) params.status = options.status;
    if (options.limit) params.limit = options.limit;
    if (options.order) params.order = options.order;
    if (options.orderBy) params.orderBy = options.orderBy;

    return makeRequest('getCurrentActivationsList', params);
}

/**
 * Wait for SMS code
 * @param {number} orderId - Order ID
 * @param {number} maxWaitTime - Max wait time in ms (default: 5 min)
 * @param {number} checkInterval - Check interval in ms (default: 3 sec)
 * @returns {Promise<string>} SMS code
 */
export async function waitForSmsVerifyCode(orderId, maxWaitTime = 300000, checkInterval = 3000) {
    const startTime = performance.now();
    let lastStatus = 'PENDING';

    console.log('Waiting for SMS...');

    while (performance.now() - startTime < maxWaitTime) {
        let result;
        try {
            result = await checkSmsVerifyOrder(orderId);
        } catch (error) {
            if (error instanceof SmsVerifyKeyError) throw error;
            console.log('Retrying SMS status request');
        }

        if (result) {
            if (result.status !== lastStatus) {
                console.log(`  Status: ${lastStatus} -> ${result.status}`);
                lastStatus = result.status;
            }

            if (result.code) return result.code;

            if (result.status === 'CANCELED') {
                throw new SmsVerifyCanceledError('Order was canceled');
            }
        }

        await new Promise(resolve => setTimeout(resolve, checkInterval));
    }

    throw new Error('Timeout waiting for SMS');
}

/**
 * Complete flow: Buy number, wait for SMS, finish order
 * @param {Object} options - Options
 * @param {string} options.service - Service code (default: 'fu' for Snapchat)
 * @param {number} options.country - Country ID (default: 16 for UK)
 * @param {string} options.operator - Operator code (default: 'any')
 * @param {number} options.maxWaitTime - Max wait time for SMS
 * @param {number} [options.maxPrice] - Positive, finite spending cap
 * @returns {Promise<{phone: string, code: string, orderId: number}>}
 * @throws {SmsVerifyOrderError} Includes status and an orderId when known. Reconciliation-required errors are not retryable.
 */
export async function buyNumberAndGetSMS({
    service = 'fu',
    country = 16,
    operator = 'any',
    maxWaitTime = 300000,
    maxPrice
} = {}) {
    const order = await buySmsVerifyNumber(service, country, operator, { maxPrice });
    let code;
    try {
        code = await waitForSmsVerifyCode(order.id, maxWaitTime);
    } catch (error) {
        const canceled = error instanceof SmsVerifyCanceledError ||
            await cancelSmsVerifyOrder(order.id).catch(() => false);
        if (canceled) {
            throw new SmsVerifyOrderError('SMS Verification order was canceled', order.id, 'CANCELED');
        }
        throw new SmsVerifyOrderError(
            'SMS Verification cancellation is unconfirmed. Reconcile the order before ordering again.',
            order.id,
            'RECONCILIATION_REQUIRED'
        );
    }

    // A finish request can succeed even if its response is lost. Preserve the order for reconciliation.
    const finished = await finishSmsVerifyOrder(order.id).catch(() => false);
    if (!finished) {
        throw new SmsVerifyOrderError(
            'SMS Verification completion is unconfirmed. Reconcile the order before ordering again.',
            order.id,
            'RECONCILIATION_REQUIRED'
        );
    }

    return { phone: order.phone, code, orderId: order.id };
}

// Country codes reference (commonly used)
export const SMS_VERIFY_COUNTRIES = {
    RUSSIA: 0,
    UKRAINE: 1,
    KAZAKHSTAN: 2,
    CHINA: 3,
    PHILIPPINES: 4,
    MYANMAR: 5,
    INDONESIA: 6,
    MALAYSIA: 7,
    KENYA: 8,
    TANZANIA: 9,
    VIETNAM: 10,
    KYRGYZSTAN: 11,
    USA_VIRTUAL: 12,
    ISRAEL: 13,
    HONG_KONG: 14,
    POLAND: 15,
    UK: 16,
    MADAGASCAR: 17,
    CONGO: 18,
    NIGERIA: 19,
    MACAU: 20,
    EGYPT: 21,
    INDIA: 22,
    IRELAND: 23,
    CAMBODIA: 24,
    LAOS: 25,
    HAITI: 26,
    IVORY_COAST: 27,
    GAMBIA: 28,
    SERBIA: 29,
    YEMEN: 30,
    SOUTH_AFRICA: 31,
    ROMANIA: 32,
    COLOMBIA: 33,
    ESTONIA: 34,
    AZERBAIJAN: 35,
    CANADA: 36,
    MOROCCO: 37,
    GHANA: 38,
    ARGENTINA: 39,
    UZBEKISTAN: 40,
    CAMEROON: 41,
    CHAD: 42,
    GERMANY: 43,
    LITHUANIA: 44,
    CROATIA: 45,
    SWEDEN: 46,
    IRAQ: 47,
    NETHERLANDS: 48,
    LATVIA: 49,
    AUSTRIA: 50,
    BELARUS: 51,
    THAILAND: 52,
    SAUDI_ARABIA: 53,
    MEXICO: 54,
    TAIWAN: 55,
    SPAIN: 56,
    IRAN: 57,
    ALGERIA: 58,
    SLOVENIA: 59,
    BANGLADESH: 60,
    SENEGAL: 61,
    TURKEY: 62,
    CZECH: 63,
    SRI_LANKA: 64,
    PERU: 65,
    PAKISTAN: 66,
    NEW_ZEALAND: 67,
    GUINEA: 68,
    MALI: 69,
    VENEZUELA: 70,
    ETHIOPIA: 71,
    MONGOLIA: 72,
    BRAZIL: 73,
    AFGHANISTAN: 74,
    UGANDA: 75,
    ANGOLA: 76,
    CYPRUS: 77,
    FRANCE: 78,
    GUINEA_BISSAU: 79,
    MOZAMBIQUE: 80,
    NEPAL: 81,
    BELGIUM: 82,
    BULGARIA: 83,
    HUNGARY: 84,
    MOLDOVA: 85,
    ITALY: 86,
    PARAGUAY: 87,
    HONDURAS: 88,
    TUNISIA: 89,
    NICARAGUA: 90,
    TIMOR_LESTE: 91,
    BOLIVIA: 92,
    COSTA_RICA: 93,
    GUATEMALA: 94,
    UAE: 95,
    ZIMBABWE: 96,
    PUERTO_RICO: 97,
    SUDAN: 98,
    TOGO: 99,
    KUWAIT: 100,
    EL_SALVADOR: 101,
    LIBYA: 102,
    JAMAICA: 103,
    TRINIDAD: 104,
    ECUADOR: 105,
    ESWATINI: 106,
    OMAN: 107,
    BOSNIA: 108,
    DOMINICAN_REP: 109,
    SYRIA: 110,
    QATAR: 111,
    PANAMA: 112,
    CUBA: 113,
    MAURITANIA: 114,
    SIERRA_LEONE: 115,
    JORDAN: 116,
    PORTUGAL: 117,
    BARBADOS: 118,
    BURUNDI: 119,
    BENIN: 120,
    BRUNEI: 121,
    BAHAMAS: 122,
    BOTSWANA: 123,
    BELIZE: 124,
    CAR: 125,
    DOMINICA: 126,
    GRENADA: 127,
    GEORGIA: 128,
    GREECE: 129,
    GUINEA_CONAKRY: 130,
    GUYANA: 131,
    ICELAND: 132,
    COMOROS: 133,
    ST_KITTS: 134,
    LIBERIA: 135,
    LESOTHO: 136,
    MALAWI: 137,
    NAMIBIA: 138,
    NIGER: 139,
    RWANDA: 140,
    SLOVAKIA: 141,
    SURINAME: 142,
    TAJIKISTAN: 143,
    MONACO: 144,
    BAHRAIN: 145,
    REUNION: 146,
    ZAMBIA: 147,
    ARMENIA: 148,
    SOMALIA: 149,
    CONGO_DRC: 150,
    CHILE: 151,
    BURKINA_FASO: 152,
    LEBANON: 153,
    GABON: 154,
    ALBANIA: 155,
    URUGUAY: 156,
    MAURITIUS: 157,
    BHUTAN: 158,
    MALDIVES: 159,
    GUADELOUPE: 160,
    TURKMENISTAN: 161,
    FRENCH_GUIANA: 162,
    FINLAND: 163,
    ST_LUCIA: 164,
    LUXEMBOURG: 165,
    ST_VINCENT: 166,
    EQUATORIAL_GUINEA: 167,
    DJIBOUTI: 168,
    ANTIGUA: 169,
    CAYMAN_ISLANDS: 170,
    MONTENEGRO: 171,
    DENMARK: 172,
    SWITZERLAND: 173,
    NORWAY: 174,
    AUSTRALIA: 175,
    ERITREA: 176,
    SOUTH_SUDAN: 177,
    SAO_TOME: 178,
    ARUBA: 179,
    MONTSERRAT: 180,
    ANGUILLA: 181,
    NORTH_MACEDONIA: 183,
    SEYCHELLES: 184,
    NEW_CALEDONIA: 185,
    CAPE_VERDE: 186,
    USA_REAL: 187,
    PALAU: 188,
    FIJI: 189,
    SOUTH_KOREA: 190,
    WESTERN_SAHARA: 192,
    SOLOMON_ISLANDS: 193,
    SINGAPORE: 196,
    TONGA: 197,
    AMERICAN_SAMOA: 198,
    MALTA: 199,
    JAPAN: 670
};

// Service codes reference (commonly used)
export const SMS_VERIFY_SERVICES = {
    SNAPCHAT: 'fu',
    WHATSAPP: 'wa',
    TELEGRAM: 'tg',
    INSTAGRAM: 'ig',
    FACEBOOK: 'fb',
    GOOGLE: 'go',
    TWITTER: 'tw',
    TIKTOK: 'lf',
    DISCORD: 'ds',
    VIBER: 'vi',
    WECHAT: 'wb',
    LINE: 'me',
    UBER: 'ub',
    MICROSOFT: 'mm',
    APPLE: 'wx',
    AMAZON: 'am',
    NETFLIX: 'nf',
    STEAM: 'mt',
    VK: 'vk',
    OK: 'ok'
};






