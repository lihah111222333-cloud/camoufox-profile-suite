import { Agent as HttpAgent } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';
import { createRequire } from 'node:module';
import { isIPv4 } from 'node:net';
import { clearTimeout as clearConnectionTimeout, setTimeout as setConnectionTimeout } from 'node:timers';

export const controllerRequestOptions = {
    maxRedirects: 0,
    proxy: false,
    httpAgent: new HttpAgent(),
    httpsAgent: new HttpsAgent({ rejectUnauthorized: true })
};

const protocols = new Set(['http:', 'https:', 'ws:', 'wss:']);
const secureProtocols = new Set(['https:', 'wss:']);
const absoluteUrl = /^[a-z][a-z0-9+.-]*:\/\//i;
const require = createRequire(import.meta.url);
let WebSocket;

export class ControllerUrlError extends Error {
    name = 'ControllerUrlError';
}

export class ControllerConnectionError extends Error {
    name = 'ControllerConnectionError';

    constructor(code, message) {
        super(message);
        this.code = code;
    }
}

function isLoopback(hostname) {
    return hostname === 'localhost' || isLoopbackAddress(hostname);
}

function isLoopbackAddress(hostname) {
    return hostname === '[::1]' || (hostname.startsWith('127.') && isIPv4(hostname));
}

export function parseControllerUrl(address, defaultProtocol) {
    const value = typeof address === 'string' ? address.trim() : '';
    let url;
    try {
        url = new URL(!absoluteUrl.test(value) && defaultProtocol
            ? `${defaultProtocol}//${value}`
            : value);
    } catch {
        throw new ControllerUrlError('Invalid browser controller URL');
    }

    if (!protocols.has(url.protocol) || url.username || url.password || url.hash) {
        throw new ControllerUrlError('Invalid browser controller URL');
    }
    if (!secureProtocols.has(url.protocol) && !isLoopback(url.hostname)) {
        throw new ControllerUrlError('Remote browser controllers require HTTPS or WSS');
    }
    return url;
}

export function controllerApiUrl(address, path, trustedHttpSetting) {
    const url = parseControllerUrl(address);
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || /[?#]/.test(url.href)) {
        throw new ControllerUrlError('Invalid browser controller API URL');
    }
    const base = url.href.replace(/\/$/, '');
    if (url.protocol === 'http:') {
        let approved;
        try {
            approved = new URL(process.env[trustedHttpSetting]).href.replace(/\/$/, '');
        } catch {
            // A missing or malformed opt-in cannot approve a plaintext endpoint.
        }
        if (!isLoopbackAddress(url.hostname) || approved !== base) {
            throw new ControllerUrlError(`Browser controller API requires HTTPS or an explicit numeric loopback API URL in ${trustedHttpSetting}`);
        }
    }
    return `${base}${path}`;
}

export function validateControllerEndpoint(endpoint, controller, requireSameOrigin = false) {
    if (secureProtocols.has(controller.protocol) && !secureProtocols.has(endpoint.protocol)) {
        throw new ControllerUrlError('Browser controller endpoint downgraded a secure connection');
    }
    if (requireSameOrigin) {
        if (endpoint.origin !== controller.origin) {
            throw new ControllerUrlError('Browser endpoint does not match the discovery controller origin');
        }
    } else if (endpoint.hostname !== controller.hostname
        && !(isLoopback(endpoint.hostname) && isLoopback(controller.hostname))) {
        throw new ControllerUrlError('Browser endpoint does not match the configured controller host');
    }
    return endpoint;
}

export function toWebSocketUrl(url) {
    const endpoint = new URL(url);
    if (endpoint.protocol === 'http:') {
        endpoint.protocol = 'ws:';
    } else if (endpoint.protocol === 'https:') {
        endpoint.protocol = 'wss:';
    }
    return endpoint;
}

export async function controllerDelay(ms, signal) {
    signal?.throwIfAborted();
    await new Promise((resolve, reject) => {
        const abort = () => {
            clearTimeout(timer);
            reject(signal.reason);
        };
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', abort);
            resolve();
        }, ms);
        signal?.addEventListener('abort', abort, { once: true });
    });
}

export async function connectBrowser(puppeteer, endpoint, { signal, timeout = 10000 } = {}) {
    signal?.throwIfAborted();
    if (!WebSocket) {
        try {
            // Use the same WebSocket client installed for Puppeteer, including nested dependencies.
            WebSocket = createRequire(require.resolve('puppeteer-core'))('ws');
        } catch {
            throw new ControllerConnectionError('CONTROLLER_WEBSOCKET_UNAVAILABLE',
                'The installed Puppeteer does not provide a supported WebSocket client');
        }
    }

    const socket = new WebSocket(endpoint.href, {
        agent: endpoint.protocol === 'wss:' ? controllerRequestOptions.httpsAgent : controllerRequestOptions.httpAgent,
        followRedirects: false,
        rejectUnauthorized: true,
        perMessageDeflate: false,
        maxPayload: 256 * 1024 * 1024
    });
    const transport = {
        send: message => socket.send(message),
        close: () => socket.close()
    };
    let terminated = false;
    let rejectConnection;
    const terminate = () => {
        if (terminated) return;
        terminated = true;
        socket.terminate();
    };
    const abort = () => {
        rejectConnection?.(signal.reason);
        terminate();
    };
    socket.on('error', error => rejectConnection?.(error));
    socket.on('message', message => transport.onmessage?.(message.toString()));
    socket.once('close', () => {
        terminated = true;
        rejectConnection?.(new ControllerConnectionError('CONTROLLER_CONNECTION_CLOSED',
            'Browser controller connection closed before attachment'));
        transport.onclose?.();
    });

    let timer;
    try {
        return await new Promise((resolve, reject) => {
            rejectConnection = reject;
            socket.once('open', async () => {
                if (terminated) return;
                try {
                    resolve(await puppeteer.connect({ transport, ignoreHTTPSErrors: false, defaultViewport: null }));
                } catch (error) {
                    reject(error);
                }
            });
            timer = setConnectionTimeout(() => {
                reject(new ControllerConnectionError('CONTROLLER_CONNECTION_TIMEOUT',
                    'Browser controller connection timed out'));
            }, timeout);
            signal?.addEventListener('abort', abort, { once: true });
            if (signal?.aborted) abort();
        });
    } catch (error) {
        terminate();
        throw error;
    } finally {
        // After attachment, the profile manager can close its own pages before disconnecting.
        signal?.removeEventListener('abort', abort);
        clearConnectionTimeout(timer);
        rejectConnection = null;
    }
}
