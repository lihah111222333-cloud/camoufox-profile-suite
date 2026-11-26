import { Agent as HttpAgent } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';
import { createRequire } from 'node:module';
import { isIPv4 } from 'node:net';

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

export class ControllerUrlError extends Error {}

function isLoopback(hostname) {
    return hostname === 'localhost' || hostname === '[::1]'
        || (hostname.startsWith('127.') && isIPv4(hostname));
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

export function controllerApiUrl(address, path) {
    const url = parseControllerUrl(address);
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.search) {
        throw new ControllerUrlError('Invalid browser controller API URL');
    }
    return `${url.href.replace(/\/$/, '')}${path}`;
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

export async function connectBrowser(puppeteer, endpoint) {
    if (!WebSocket) {
        try {
            // Use the same WebSocket client installed for Puppeteer, including nested dependencies.
            WebSocket = createRequire(require.resolve('puppeteer-core'))('ws');
        } catch {
            throw new ControllerUrlError('The installed Puppeteer does not provide a supported WebSocket client');
        }
    }

    const socket = new WebSocket(endpoint.href, {
        agent: endpoint.protocol === 'wss:' ? controllerRequestOptions.httpsAgent : controllerRequestOptions.httpAgent,
        followRedirects: false,
        rejectUnauthorized: true,
        perMessageDeflate: false,
        maxPayload: 256 * 1024 * 1024
    });
    await new Promise((resolve, reject) => {
        socket.once('open', resolve);
        socket.on('error', reject);
    });

    const transport = {
        send: message => socket.send(message),
        close: () => socket.close()
    };
    socket.on('message', message => transport.onmessage?.(message.toString()));
    socket.on('close', () => transport.onclose?.());

    try {
        return await puppeteer.connect({ transport, ignoreHTTPSErrors: false, defaultViewport: null });
    } catch (error) {
        socket.close();
        throw error;
    }
}
