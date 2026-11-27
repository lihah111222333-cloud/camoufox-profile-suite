import { ControllerUrlError } from './controller-url.js';
import { requireControllerProfileId } from './controller-id.js';

const beforeConnectionCodes = new Set([
    'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EAI_AGAIN', 'ENOTFOUND',
    'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'DEPTH_ZERO_SELF_SIGNED_CERT',
    'ERR_TLS_CERT_ALTNAME_INVALID', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'
]);
const uncertainRequestCodes = new Set(['ECONNABORTED', 'ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'ERR_BAD_RESPONSE']);

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

function controllerRequestError(operation, error, getProviderCode) {
    const status = error?.response?.status;
    const code = error?.code;
    return new ControllerRequestError(operation, {
        status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : undefined,
        transportCode: beforeConnectionCodes.has(code) || uncertainRequestCodes.has(code) ? code : undefined,
        providerCode: getProviderCode?.(error?.response?.data)
    });
}

export async function sendControllerRequest(operation, send, getProviderCode) {
    try {
        return await send();
    } catch (error) {
        throw controllerRequestError(operation, error, getProviderCode);
    }
}

export function profileAllocationUnconfirmed(error) {
    return Object.assign(error, {
        code: 'PROFILE_ALLOCATION_UNCONFIRMED',
        profileCleanup: 'allocation-unconfirmed'
    });
}

export async function sendControllerProfileCreate(operation, send, getProviderCode) {
    try {
        return await send();
    } catch (error) {
        const failure = controllerRequestError(operation, error, getProviderCode);
        const { status } = failure;
        const rejected = (status >= 400 && status < 500 && status !== 408) || controllerRejected(error?.response?.data);
        const dispatched = error?.request || error?.response || uncertainRequestCodes.has(error?.code);
        if (dispatched && !rejected && !beforeConnectionCodes.has(error?.code)) {
            throw profileAllocationUnconfirmed(failure);
        }
        throw failure;
    }
}

export function requireCreatedProfileId(profileId) {
    try {
        return requireControllerProfileId(profileId);
    } catch (error) {
        throw profileAllocationUnconfirmed(error);
    }
}

export function controllerErrorDetails(error) {
    if (error instanceof ControllerUrlError) return { hint: error.message };
    if (error instanceof ControllerRequestError) {
        return { status: error.status, transportCode: error.transportCode, providerCode: error.providerCode };
    }
}

export function parseControllerPayload(data) {
    if (typeof data !== 'string') return data;
    try {
        return JSON.parse(data);
    } catch {
        return undefined;
    }
}

export function controllerRejected(data) {
    const payload = parseControllerPayload(data);
    return payload === false || payload?.success === false;
}

export function controllerAcknowledged({ status, data }) {
    if (status === 204) return data == null || data === '';
    if (status !== 200) return false;
    const payload = parseControllerPayload(data);
    return payload === true || payload?.success === true;
}
