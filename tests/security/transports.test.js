import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

// Load the production modules with replacement dependencies in an isolated package.
const fixtureKey = Symbol.for('controller-transport-test');

async function loadAdapters(t) {
    const root = await mkdtemp(path.join(os.tmpdir(), 'controller-transport-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    await cp(new URL('../../src/', import.meta.url), path.join(root, 'src'), { recursive: true });
    await mkdir(path.join(root, 'config'));
    await writeFile(path.join(root, 'package.json'), '{"type":"module"}');

    const env = {
        GPM_API_URL: 'https://gpm-controller.invalid:7443',
        DOLPHIN_API_URL: 'https://dolphin-controller.invalid:7443',
        DOLPHIN_FOLDER_ID: 'fixture-folder',
        DOLPHIN_API_KEY: 'fixture-api-key',
        GOLOGIN_API_KEY: 'fixture-api-key',
        OMOCAPTCHA_KEY: 'fixture-omocaptcha-key',
        SMS_VERIFY_API_KEY: 'fixture-sms-key',
        PROFILE_SERVICE: 'gpm',
        LOG_LEVEL: 'silent'
    };
    for (const [key, value] of Object.entries(env)) {
        const previous = process.env[key];
        process.env[key] = value;
        t.after(() => {
            if (previous === undefined) delete process.env[key];
            else process.env[key] = previous;
        });
    }

    const requests = [];
    const sockets = [];
    const connections = [];
    const responses = [];
    const state = { connectionErrors: [], socketErrors: [] };
    const fakeBrowser = {
        async pages() { return []; },
        async newPage() {
            return {
                async evaluateOnNewDocument() {},
                async url() { return 'about:blank'; }
            };
        }
    };

    function send(method, url, data, options) {
        requests.push({ method, url, data, options });
        assert.ok(responses.length, 'Unexpected controller API or discovery request');
        const response = responses.shift();
        if (response instanceof Error) throw response;
        return { data: response };
    }
    function axiosMethods(defaults) {
        return {
            get: (url, options) => send('GET', url, undefined, { ...defaults, ...options }),
            post: (url, data, options) => send('POST', url, data, { ...defaults, ...options })
        };
    }
    const stubs = {
        axios: Object.assign(
            config => send(config.method, config.url, config.data, config),
            axiosMethods(),
            { create: axiosMethods }
        ),
        dotenv: { config() {} },
        'puppeteer-core': {
            async connect(options) {
                connections.push(options);
                if (state.connectionErrors.length) throw state.connectionErrors.shift();
                return fakeBrowser;
            }
        },
        ws: class extends EventEmitter {
            constructor(url, options) {
                super();
                sockets.push({ url: String(url), options });
                const error = state.socketErrors.shift();
                queueMicrotask(() => {
                    if (error) this.emit('error', error);
                    else this.emit('open');
                });
            }
            close() { this.emit('close'); }
        }
    };
    globalThis[fixtureKey] = stubs;
    t.after(() => { delete globalThis[fixtureKey]; });
    for (const name of Object.keys(stubs)) {
        const dir = path.join(root, 'node_modules', name);
        await mkdir(dir, { recursive: true });
        await writeFile(path.join(dir, 'package.json'), '{"main":"index.cjs"}');
        await writeFile(path.join(dir, 'index.cjs'),
            `module.exports = globalThis[Symbol.for('controller-transport-test')][${JSON.stringify(name)}];\n`);
    }

    const load = name => import(pathToFileURL(path.join(root, 'src', name)).href);
    const [gpm, dolphin, gologin, gpmProfile, dolphinProfile, proxyManager] = await Promise.all([
        load('gpmlogin/client.js'), load('dolphin/client.js'), load('gologin/client.js'),
        load('gpmlogin/profile.js'), load('dolphin/profile.js'), load('utils/proxy-manager.js')
    ]);
    return {
        requests,
        sockets,
        connections,
        responses,
        state,
        gpm,
        dolphin,
        gologin: gologin.default,
        proxyManager: proxyManager.default,
        GpmProfile: gpmProfile.default,
        DolphinProfile: dolphinProfile.default
    };
}

function assertSecureHttp(request) {
    assert.equal(new URL(request.url).protocol, 'https:');
    assert.equal(request.options.maxRedirects, 0);
    assert.equal(request.options.proxy, false);
    assert.equal(request.options.httpsAgent.options.rejectUnauthorized, true);
}

function assertWebSockets(sockets, connections, expected) {
    assert.deepEqual(sockets.map(socket => socket.url), expected);
    for (const { options } of sockets) {
        assert.equal(options.followRedirects, false);
        assert.equal(options.rejectUnauthorized, true);
    }
    assert.equal(connections.length, expected.length);
    for (const connection of connections) assert.equal(connection.ignoreHTTPSErrors, false);
}

test('GPM and Dolphin control and proxy transport policies', async t => {
    const {
        requests, sockets, connections, responses, state, gpm, dolphin, gologin,
        proxyManager, GpmProfile, DolphinProfile
    } = await loadAdapters(t);
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    let proxyRequests = 0;
    t.mock.method(http, 'request', () => {
        proxyRequests++;
        throw new Error('Unexpected proxy request');
    });

    async function run(name, body) {
        await t.test(name, async () => {
            requests.length = 0;
            sockets.length = 0;
            connections.length = 0;
            responses.length = 0;
            state.connectionErrors.length = 0;
            state.socketErrors.length = 0;
            proxyRequests = 0;
            await body();
            assert.equal(responses.length, 0);
            assert.equal(proxyRequests, 0);
        });
    }

    await run('GPM rediscovers a TLS endpoint after an attachment failure', async () => {
        const initial = 'wss://gpm-controller.invalid:9443/devtools/browser/initial';
        const refreshed = 'wss://gpm-controller.invalid:9443/devtools/browser/refreshed';
        responses.push(
            { data: { remote_debugging_address: 'https://gpm-controller.invalid:9443/cdp' } },
            { webSocketDebuggerUrl: initial },
            { webSocketDebuggerUrl: refreshed }
        );
        state.connectionErrors.push(new Error('Fixture attachment unavailable'));
        await new GpmProfile('fixture').start();

        assert.deepEqual(requests.map(request => new URL(request.url).pathname),
            ['/api/v3/profiles/start/fixture', '/cdp/json/version', '/cdp/json/version']);
        requests.forEach(assertSecureHttp);
        assertWebSockets(sockets, connections, [initial, refreshed]);
    });

    await run('GPM retains WSS in the discovery fallback and honors a direct WSS URL', async () => {
        responses.push({}, [], []);
        await new GpmProfile('fixture', 'https://gpm-controller.invalid:9443/cdp').start();
        const direct = 'wss://gpm-controller.invalid:9443/devtools/browser/direct';
        await new GpmProfile('fixture', direct).start();

        assert.equal(requests.length, 3);
        requests.forEach(assertSecureHttp);
        assertWebSockets(sockets, connections, ['wss://gpm-controller.invalid:9443/cdp/devtools/browser', direct]);
    });

    await run('GPM checks discovery certificates and binds endpoints to the controller origin', async () => {
        const address = 'https://gpm-controller.invalid:9443';
        responses.push({ webSocketDebuggerUrl: 'wss://gpm-controller.invalid:9444/devtools/browser/fixture' });
        await assert.rejects(new GpmProfile('fixture', address).start(), /controller origin/);
        const verificationError = new Error('Fixture certificate verification failed');
        verificationError.code = 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
        responses.push(verificationError);
        await assert.rejects(new GpmProfile('fixture', address).start(), /certificate verification failed/);
        assert.equal(requests.length, 2);
        assertWebSockets(sockets, connections, []);
    });

    await run('a redirect response never selects a GPM discovery endpoint', async () => {
        const error = new Error('Unexpected redirect response');
        error.response = { status: 302 };
        responses.push(error);
        await assert.rejects(new GpmProfile('fixture', 'https://gpm-controller.invalid:9443').start(),
            /redirect response/);
        assert.equal(requests.length, 1);
        assertSecureHttp(requests[0]);
        assertWebSockets(sockets, connections, []);
    });

    await run('GPM start rejects a debugger returned from a different configured host', async () => {
        responses.push({ data: { remote_debugging_address: 'https://other-controller.invalid:9443' } });
        await assert.rejects(gpm.startProfile('fixture'), /configured controller host/);
        assertSecureHttp(requests[0]);
        assertWebSockets(sockets, connections, []);
    });

    await run('a failed WSS handshake keeps Puppeteer detached', async () => {
        const endpoint = 'wss://gpm-controller.invalid:9443/devtools/browser/fixture';
        const error = Object.assign(new Error('Fixture certificate verification failed'), { code: 'CERT_HAS_EXPIRED' });
        state.socketErrors.push(...Array(8).fill(error));
        await assert.rejects(new GpmProfile('fixture', endpoint).start(), /certificate verification failed/);
        assert.equal(requests.length, 0);
        assert.equal(connections.length, 0);
        assert.equal(sockets.length, 8);
        for (const socket of sockets) {
            assert.equal(socket.url, endpoint);
            assert.equal(socket.options.followRedirects, false);
            assert.equal(socket.options.rejectUnauthorized, true);
        }
    });

    await run('Dolphin preserves HTTPS on initial and refreshed WebSocket URLs', async () => {
        const initial = 'https://dolphin-controller.invalid:9443/devtools/browser/initial';
        const refreshed = 'https://dolphin-controller.invalid:9444/devtools/browser/refreshed';
        responses.push({ ws: initial }, { ws: refreshed });
        state.connectionErrors.push(new Error('Fixture attachment unavailable'));
        await new DolphinProfile('fixture').start();

        assert.equal(requests.length, 2);
        requests.forEach(assertSecureHttp);
        assertWebSockets(sockets, connections, [initial.replace('https:', 'wss:'), refreshed.replace('https:', 'wss:')]);
    });

    await run('remote plaintext URLs and a Dolphin refresh downgrade fail before attachment', async () => {
        await assert.rejects(new GpmProfile('fixture', 'http://127.example.invalid:9222').start(), /require HTTPS or WSS/);
        await assert.rejects(new DolphinProfile('fixture', 'ws://dolphin-controller.invalid:9443/cdp').start(),
            /require HTTPS or WSS/);
        assert.equal(requests.length, 0);
        assert.equal(sockets.length, 0);

        const initial = 'wss://dolphin-controller.invalid:9443/devtools/browser/initial';
        responses.push({ ws: 'ws://127.0.0.1:9443/devtools/browser/fixture' });
        state.connectionErrors.push(new Error('Fixture attachment unavailable'));
        await assert.rejects(new DolphinProfile('fixture', initial).start(), /downgraded/);
        assertSecureHttp(requests[0]);
        assertWebSockets(sockets, connections, [initial]);
    });

    await run('legacy loopback HTTP discovery and local WebSocket endpoints still attach', async () => {
        const gpmEndpoint = 'ws://127.0.0.1:9222/devtools/browser/fixture';
        const dolphinEndpoint = 'ws://[::1]:9223/devtools/browser/fixture';
        responses.push({ webSocketDebuggerUrl: gpmEndpoint });
        await new GpmProfile('fixture', '127.0.0.1:9222').start();
        await new DolphinProfile('fixture', '[::1]:9223/devtools/browser/fixture').start();

        assert.equal(requests[0].url, 'http://127.0.0.1:9222/json/version');
        assertWebSockets(sockets, connections, [gpmEndpoint, dolphinEndpoint]);
    });

    const proxy = proxyManager.parseProxyLine('https://fixture-user:fixture-password@proxy.invalid:8443');

    await run('Dolphin retains parsed HTTPS through both proxy operations', async () => {
        responses.push({ id: 'fixture' }, {});
        await dolphin.createProfile('fixture', proxy);
        await dolphin.updateProfileProxy('fixture', proxy);
        const [create, update] = requests;
        [create, update].forEach(assertSecureHttp);
        for (const sent of [create.data.proxy, update.data]) {
            assert.equal(sent.protocol, 'https');
            assert.equal(sent.host, 'proxy.invalid');
            assert.equal(sent.port, 8443);
            assert.equal(sent.proxyUsername, 'fixture-user');
            assert.equal(sent.proxyPassword, 'fixture-password');
        }
        await assert.rejects(dolphin.createProfile('fixture', { ...proxy, protocol: 'http' }), /Conflicting proxy protocols/);
        assert.equal(requests.length, 2);
    });

    await run('GPM and GoLogin reject unsupported HTTPS proxies before API or preflight I/O', async () => {
        await assert.rejects(gpm.createProfile('fixture', proxy), /does not support HTTPS proxies/);
        await assert.rejects(gologin.createProfileWithProxy('fixture', proxy), /does not support HTTPS proxies/);
        const input = { mode: 'https', host: proxy.ip, port: proxy.port, username: proxy.username, password: proxy.password };
        await assert.rejects(gologin.createProfile({ name: 'fixture', proxy: input }), /does not support HTTPS proxies/);
        await assert.rejects(gologin.updateProfile('fixture', { proxy: input }), /does not support HTTPS proxies/);
        await assert.rejects(gologin.updateProfileProxy('fixture', input), /does not support HTTPS proxies/);
        const result = await gologin.testProxy(proxy);
        assert.equal(result.valid, false);
        assert.match(result.error, /does not support HTTPS proxies/);
        assert.equal(requests.length, 0);
    });
});
