import { ControllerUrlError } from './controller-url.js';

const transportCodes = new Set([
    'ECONNABORTED', 'ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ETIMEDOUT',
    'EAI_AGAIN', 'ENOTFOUND',
    'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'DEPTH_ZERO_SELF_SIGNED_CERT',
    'ERR_TLS_CERT_ALTNAME_INVALID', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
]);

export class ControllerRequestError extends Error {
    constructor(operation, { status, transportCode, providerCode } = {}) {
        const details = [status && `HTTP ${status}`, transportCode, providerCode].filter(Boolean);
        super(`${operation} failed${details.length ? ` (${details.join(', ')})` : ''}`);
        this.name = 'ControllerRequestError';
        this.status = status;
        this.transportCode = transportCode;
        this.providerCode = providerCode;
    }
}

export async function sendControllerRequest(operation, send, getProviderCode) {
    try {
        return await send();
    } catch (error) {
        const status = error?.response?.status;
        const code = error?.code;
        throw new ControllerRequestError(operation, {
            status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : undefined,
            transportCode: transportCodes.has(code) ? code : undefined,
            providerCode: getProviderCode?.(error?.response?.data)
        });
    }
}

export function controllerErrorDetails(error) {
    if (error instanceof ControllerUrlError) return { hint: error.message };
    if (error instanceof ControllerRequestError) {
        return { status: error.status, transportCode: error.transportCode, providerCode: error.providerCode };
    }
}

export function controllerRejected(data) {
    if (typeof data === 'string') {
        try {
            data = JSON.parse(data);
        } catch {
            // Some controllers acknowledge with plain text or an empty body.
            return false;
        }
    }
    return data === false || data?.success === false;
}
