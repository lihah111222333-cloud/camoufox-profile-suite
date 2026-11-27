import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { copyFile, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import dotenv from 'dotenv';

async function loadGoLogin(t, configure, entry = 'client.js') {
    const root = await mkdtemp(path.join(os.tmpdir(), 'gologin-boundary-'));
    const fixtureKey = Symbol.for('test-gologin-boundaries');
    const env = {
        GOLOGIN_API_KEY: process.env.GOLOGIN_API_KEY,
        DOTENV_KEY: process.env.DOTENV_KEY,
        GMAIL_CREATOR_STATE_DIR: process.env.GMAIL_CREATOR_STATE_DIR,
        GMAIL_CREATOR_LEGACY_DIR: process.env.GMAIL_CREATOR_LEGACY_DIR,
        LOG_LEVEL: process.env.LOG_LEVEL
    };
    const state = path.join(root, 'state');
    delete process.env.GOLOGIN_API_KEY;
    delete process.env.DOTENV_KEY;
    process.env.GMAIL_CREATOR_STATE_DIR = state;
    process.env.GMAIL_CREATOR_LEGACY_DIR = path.join(root, 'legacy');
    process.env.LOG_LEVEL = 'silent';
    t.after(async () => {
        delete globalThis[fixtureKey];
        for (const [key, previous] of Object.entries(env)) {
            if (previous === undefined) delete process.env[key];
            else process.env[key] = previous;
        }
        await rm(root, { recursive: true, force: true });
    });

    await mkdir(state, { mode: 0o700 });
    const envFile = path.join(state, '.emv');
    if (configure) {
        await configure(state);
    } else {
        await writeFile(envFile, 'GOLOGIN_API_KEY=fixture-import-key\n', { mode: 0o644 });
    }

    const source = new URL('../../src/', import.meta.url);
    for (const subdir of ['', 'gologin/', 'utils/']) {
        const dest = path.join(root, 'src', subdir);
        await mkdir(dest, { recursive: true });
        for (const file of await readdir(new URL(subdir, source), { withFileTypes: true })) {
            if (file.isFile() && file.name.endsWith('.js')) {
                await copyFile(new URL(subdir + file.name, source), path.join(dest, file.name));
            }
        }
    }
    await writeFile(path.join(root, 'package.json'), '{"type":"module"}');

    const requests = [];
    const responses = [];
    const launches = [];
    const stops = [];
    const browser = {
        async pages() { return []; },
        async newPage() { return {}; },
        async close() {}
    };
    const sdk = {
        initialize() {},
        async launch() { return { browser }; },
        async stop() {}
    };
    globalThis[fixtureKey] = {
        axios: async request => {
            requests.push(request);
            assert.ok(responses.length, 'Unexpected REST request');
            const response = responses.shift();
            if (response instanceof Error) throw response;
            return typeof response === 'function' ? response() : response;
        },
        dotenv,
        gologin: {
            GologinApi({ token }) {
                sdk.initialize();
                return {
                    async launch(options) {
                        launches.push({ token, options });
                        return sdk.launch(options);
                    },
                    async stop() {
                        stops.push(token);
                        return sdk.stop();
                    }
                };
            }
        }
    };
    for (const name of Object.keys(globalThis[fixtureKey])) {
        const dir = path.join(root, 'node_modules', name);
        await mkdir(dir, { recursive: true });
        await writeFile(path.join(dir, 'package.json'), '{"type":"module","main":"index.js"}');
        const fixture = `globalThis[Symbol.for('test-gologin-boundaries')][${JSON.stringify(name)}]`;
        const source = name === 'gologin'
            ? `export const { GologinApi } = ${fixture};\n`
            : `export default ${fixture};\n`;
        await writeFile(path.join(dir, 'index.js'), source);
    }

    const load = name => import(pathToFileURL(path.join(root, 'src/gologin', name)).href);
    await load(entry);
    const client = await load('client.js');
    if (!configure) {
        assert.equal(process.env.GOLOGIN_API_KEY, 'fixture-import-key');
        if (process.platform !== 'win32') assert.equal((await stat(envFile)).mode & 0o777, 0o600);
    }
    const profile = await load('profile.js');
    return {
        client: client.default, Profile: profile.default, createAndStartProfile: profile.createAndStartProfile,
        requests, responses, launches, stops, browser, sdk, state
    };
}

const proxy = { mode: 'http', host: 'proxy.invalid', port: 8080, username: 'fixture-user', password: 'fixture-password' };

function mockGoLoginTimers(t) {
    const deadlines = new Map();
    t.mock.method(globalThis, 'setTimeout', (callback, delay) => {
        const id = Symbol();
        if (delay === 5000) queueMicrotask(callback);
        else deadlines.set(id, { callback, delay });
        return id;
    });
    t.mock.method(globalThis, 'clearTimeout', id => { deadlines.delete(id); });
    return deadlines;
}

function reply(status, data) {
    return { status, data };
}

function deferred() {
    let resolve;
    const promise = new Promise(settle => { resolve = settle; });
    return { promise, resolve };
}

async function readLogs(state) {
    const dir = path.join(state, 'logs');
    return (await Promise.all((await readdir(dir)).map(file => readFile(path.join(dir, file), 'utf8')))).join('');
}

test('GoLogin credential and lifecycle boundaries', async t => {
    const { client, Profile, createAndStartProfile, requests, responses, launches, stops } = await loadGoLogin(t);
    const proxyConnections = [];
    let proxyCloseCount = 0;
    t.mock.method(http, 'request', () => assert.fail('Unexpected HTTP proxy request'));
    t.mock.method(net, 'createConnection', options => {
        const socket = new EventEmitter();
        socket.destroy = () => { proxyCloseCount++; };
        proxyConnections.push(options);
        queueMicrotask(() => socket.emit('connect'));
        return socket;
    });

    await t.test('only a root-relative vendor request receives the bearer', async () => {
        const redirect = new Error('Fixture redirect');
        redirect.response = { status: 302, headers: { location: 'https://outside.invalid/resource' } };
        responses.push(reply(200, { ok: true }), redirect);
        process.env.GOLOGIN_API_KEY = 'fixture-current-key';
        assert.deepEqual(await client.request('GET', '/browser/v2?page=2'), { ok: true });
        for (const endpoint of ['https://outside.invalid/resource', '//outside.invalid/resource', 'browser', '/resource#section']) {
            await assert.rejects(client.request('GET', endpoint), /root-relative path/);
        }
        await assert.rejects(client.request('GET', '/browser/v2'), { status: 302 });
        delete process.env.GOLOGIN_API_KEY;
        await assert.rejects(client.request('GET', '/browser/v2'), /GOLOGIN_API_KEY is not set/);
        assert.equal(requests.length, 2);
        assert.equal(requests[0].url, 'https://api.gologin.com/browser/v2?page=2');
        for (const request of requests.splice(0)) {
            assert.equal(new URL(request.url).origin, 'https://api.gologin.com');
            assert.equal(request.headers.Authorization, 'Bearer fixture-current-key');
            assert.equal(request.maxRedirects, 0);
            assert.equal(request.proxy, false);
            assert.equal(request.httpsAgent.options.rejectUnauthorized, true);
        }
    });

    await t.test('preflight rejects authenticated HTTP before any connection', async () => {
        const rejected = await client.testProxy(proxy);
        assert.equal(rejected.valid, false);
        assert.match(rejected.error, /preflight requires HTTPS/);
        assert.equal(proxyConnections.length, 0);

        const anonymous = { mode: 'http', host: 'proxy.invalid', port: 8080 };
        assert.deepEqual(await client.testProxy(anonymous), { valid: true, ip: 'proxy.invalid' });
        assert.deepEqual(proxyConnections.splice(0), [{ host: 'proxy.invalid', port: 8080, timeout: 5000 }]);
        assert.equal(proxyCloseCount, 1);
        const unsupported = await client.testProxy({ ...proxy, mode: 'https' });
        assert.equal(unsupported.valid, false);
        assert.match(unsupported.error, /does not support HTTPS proxies/);
        assert.equal(proxyConnections.length, 0);
    });

    await t.test('lifecycle helpers accept single IDs and stop cannot dispatch a delete', async () => {
        const id = 'fixture-profile_1';
        const operations = [
            ['PUT', `/browser/${id}`, id => client.updateProfile(id, { name: 'fixture' })],
            ['PATCH', `/browser/${id}/proxy`, id => client.updateProfileProxy(id, proxy)],
            ['GET', `/browser/${id}`, id => client.getProfile(id)],
            ['GET', `/browser/${id}`, id => client.startProfile(id)],
            ['DELETE', `/browser/${id}`, id => client.deleteProfile(id)]
        ];
        for (const [, , operation] of operations) {
            for (const id of ['', 'two/parts', 'encoded%20id', '.', {}]) {
                await assert.rejects(operation(id), /Invalid browser controller profile ID/);
            }
        }
        await assert.rejects(client.stopProfile('two/parts'), /Invalid browser controller profile ID/);
        assert.throws(() => new Profile('two/parts'), /Invalid browser controller profile ID/);
        assert.equal(new Profile(42).profileId, 42);
        assert.equal(await client.stopProfile('fixture-profile'), false);
        assert.equal(await new Profile('fixture-profile').stop(), false);
        assert.equal(requests.length, 0);

        process.env.GOLOGIN_API_KEY = 'fixture-lifecycle-key';
        for (const [method, route, operation] of operations) {
            responses.push(reply(200, { success: true }));
            await operation(id);
            const [request] = requests.splice(0);
            assert.equal(request.method, method);
            assert.equal(new URL(request.url).pathname, route);
        }
    });

    await t.test('create accepts ordinary profile options and retires the Android generator', async () => {
        assert.throws(() => client.generateAndroidFingerprint(), { name: 'TypeError' });
        for (const options of [{ os: 'android' }, { navigator: {} }, { browserType: 'unknown' }]) {
            await assert.rejects(client.createProfile(options), { name: 'TypeError' });
        }
        assert.equal(requests.length, 0);

        responses.push(reply(201, { id: 'fixture-profile' }));
        assert.deepEqual(await client.createProfile({ name: 'fixture', os: 'mac' }), { id: 'fixture-profile' });
        const [request] = requests.splice(0);
        assert.equal(request.method, 'POST');
        assert.deepEqual(request.data, { name: 'fixture', os: 'mac' });
    });

    await t.test('factory creation with a proxy, launch, and later deletion retain their tenant', async t => {
        const deadlines = mockGoLoginTimers(t);
        process.env.GOLOGIN_API_KEY = 'fixture-tenant-a';
        responses.push(() => {
            process.env.GOLOGIN_API_KEY = 'fixture-tenant-b';
            return reply(201, { id: 'fixture-profile' });
        }, reply(200, { id: 'fixture-profile' }));

        const profile = await createAndStartProfile('fixture', proxy);
        assert.equal(profile.profileId, 'fixture-profile');
        assert.equal(proxyConnections.length, 0);
        assert.deepEqual(launches, [{ token: 'fixture-tenant-a', options: { profileId: 'fixture-profile', cloud: true } }]);
        assert.deepEqual(requests.map(request => [request.method, new URL(request.url).pathname]), [
            ['POST', '/browser/custom'], ['GET', '/browser/fixture-profile']
        ]);
        assert.deepEqual(requests[0].data, { name: 'fixture', os: 'lin', proxy });

        process.env.GOLOGIN_API_KEY = 'fixture-tenant-c';
        assert.equal(await profile.stop(), true);
        assert.equal(profile.browser, null);
        assert.equal(profile.page, null);
        assert.deepEqual(stops, ['fixture-tenant-a']);
        assert.equal(requests.length, 2);

        responses.push(reply(204, ''));
        assert.equal(await profile.delete(), true);
        assert.equal(requests[2].method, 'DELETE');
        assert.equal(new URL(requests[2].url).pathname, '/browser/fixture-profile');
        assert.ok(requests.splice(0).every(request => request.headers.Authorization === 'Bearer fixture-tenant-a'));
        assert.equal(responses.length, 0);
        assert.equal(deadlines.size, 0);
    });

    await t.test('stop failure is observable and an external SDK cannot delete through an ambient tenant', async () => {
        const profile = new Profile('external-fixture', { async stop() { return false; } });
        assert.equal(await profile.stop(), false);
        await assert.rejects(profile.delete(), /requires a bound REST credential/);
        assert.equal(requests.length, 0);
    });
});

test('GoLogin REST failures expose safe status without request or response details', async t => {
    const { client, responses, state } = await loadGoLogin(t, async directory => {
        process.env.LOG_LEVEL = 'ERROR';
        await writeFile(path.join(directory, '.emv'), 'GOLOGIN_API_KEY=fixture-import-key\n', { mode: 0o600 });
    });
    const output = [];
    t.mock.method(console, 'log', value => output.push(value));
    const token = 'fixture-error-bearer';
    const diagnostic = 'fixture-response-secret';
    const query = 'fixture-private-cursor';
    process.env.GOLOGIN_API_KEY = token;
    const failures = [];
    for (const [status, data] of [[403, { error: { detail: diagnostic } }], [429, diagnostic], [502, { message: diagnostic }]]) {
        const failure = new Error(diagnostic);
        failure.response = { status, data };
        failure.config = { headers: { Authorization: `Bearer ${token}` } };
        responses.push(failure);
        failures.push([status, await client.request('GET', `/browser/v2?cursor=${query}`).catch(error => error)]);
    }
    for (const stream of [output.join('\n'), await readLogs(state)]) {
        assert.match(stream, /"status":429/);
        for (const value of [diagnostic, token, query]) assert.ok(!stream.includes(value));
    }
    for (const [status, error] of failures) {
        assert.equal(error.status, status);
        assert.match(error.message, new RegExp(`HTTP ${status}`));
        assert.equal(error.config, undefined);
        assert.equal(error.response, undefined);
        assert.equal(error.cause, undefined);
    }
});

test('GoLogin profile reads reject failure envelopes and non-JSON without exposing response text', async t => {
    const { client, responses } = await loadGoLogin(t);
    const privateDetail = 'fixture-private-read-response';
    const reads = [
        [() => client.getProfiles(), []],
        [() => client.getProfile('fixture'), { id: 'fixture' }],
        [() => client.startProfile('fixture'), { id: 'fixture' }]
    ];
    for (const [read, data] of reads) {
        responses.push(
            reply(200, { success: false, error: { detail: privateDetail } }),
            reply(200, 'invalid JSON ' + privateDetail),
            reply(200, data), reply(200, JSON.stringify(data))
        );
        for (const expected of [/API rejected the profile read/, /invalid profile response/]) {
            await assert.rejects(read(), error => {
                assert.match(error.message, expected);
                assert.doesNotMatch(error.stack, new RegExp(privateDetail));
                assert.equal(error.response, undefined);
                return true;
            });
        }
        assert.deepEqual(await read(), data);
        assert.deepEqual(await read(), data);
    }
});

test('GoLogin honors file log levels in both standalone import orders', async t => {
    for (const entry of ['client.js', 'profile.js']) {
        await t.test(entry, async t => {
            const { client, responses, state } = await loadGoLogin(t, async directory => {
                delete process.env.LOG_LEVEL;
                const file = entry === 'client.js' ? '.env' : '.emv';
                await writeFile(path.join(directory, file), 'GOLOGIN_API_KEY=fixture-file-key\nLOG_LEVEL=ERROR\n', { mode: 0o600 });
            }, entry);
            const output = [];
            t.mock.method(console, 'log', value => output.push(value));
            const failure = Object.assign(new Error('fixture'), { response: { status: 502 } });
            responses.push(reply(200, { success: true }), failure);
            await client.updateProfile('fixture', { name: 'fixture' });
            await assert.rejects(client.request('GET', '/browser/v2'));
            for (const stream of [output.join('\n'), await readLogs(state)]) {
                assert.match(stream, /\[ERROR\]/);
                assert.doesNotMatch(stream, /\[INFO\]/);
            }
        });
    }
});

test('GoLogin does not reissue an ambiguous create or compensate without an allocated ID', async t => {
    const { createAndStartProfile, requests, responses, launches, stops } = await loadGoLogin(t);
    const deadlines = mockGoLoginTimers(t);
    const timeout = Object.assign(new Error('fixture lost response'), { code: 'ECONNRESET' });
    responses.push(timeout, reply(201, { id: 'fixture-next-response' }));
    const result = createAndStartProfile('fixture').catch(error => error);
    await setImmediate();
    for (const { callback, delay } of deadlines.values()) {
        if (delay === 1000) callback();
    }
    await setImmediate();
    assert.equal(requests.length, 1);
    assert.equal(responses.length, 1);
    assert.equal(launches.length, 0);
    assert.equal(stops.length, 0);
    const error = await Promise.race([result, setImmediate('pending')]);
    assert.match(error.message, /creation could not be confirmed/);
    assert.equal(error.code, 'PROFILE_ALLOCATION_UNCONFIRMED');
    assert.equal(error.profileCleanup, 'allocation-unconfirmed');
    assert.equal(error.profileId, undefined);
});

test('GoLogin waits for a terminal creation receipt that identifies the allocated profile', async t => {
    const { createAndStartProfile, requests, responses, launches } = await loadGoLogin(t);
    for (const [response, rejected] of [
        [reply(201, { id: 'fixture-unallocated', success: false }), true],
        [reply(202, { id: 'fixture-pending', success: true }), false],
        [reply(201, {}), false],
        [reply(204, ''), false]
    ]) {
        responses.push(response);
        await assert.rejects(createAndStartProfile('fixture'), error => {
            const expected = rejected ? /API rejected profile creation/ : /profile creation could not be confirmed/;
            assert.match(error.message, expected);
            assert.equal(error.code, rejected ? undefined : 'PROFILE_ALLOCATION_UNCONFIRMED');
            assert.equal(error.profileId, undefined);
            return true;
        });
        assert.deepEqual(requests.splice(0).map(request => request.method), ['POST']);
    }
    assert.equal(launches.length, 0);
});

test('GoLogin update and deletion require an explicit acknowledgment and make one attempt', async t => {
    const { client, requests, responses } = await loadGoLogin(t);
    const fail = Object.assign(new Error('fixture transport error'), { code: 'ECONNRESET' });
    const operations = [
        ['PUT', () => client.updateProfile('fixture', { name: 'updated' })],
        ['PATCH', () => client.updateProfileProxy('fixture', proxy)],
        ['DELETE', () => client.deleteProfile('fixture')]
    ];
    for (const [method, operation] of operations) {
        for (const [response, expected] of [
            [reply(200, '{"success":false}'), /API rejected/],
            [reply(202, true), /could not be confirmed/],
            [reply(202, { success: false }), /could not be confirmed/],
            [reply(200, {}), /could not be confirmed/],
            [reply(200, ''), /could not be confirmed/],
            [fail, /could not be confirmed/]
        ]) {
            responses.push(response, reply(204, ''));
            await assert.rejects(operation(), expected);
            assert.deepEqual(requests.splice(0).map(request => request.method), [method]);
            assert.equal(responses.length, 1);
            await operation();
            assert.deepEqual(requests.splice(0).map(request => request.method), [method]);
        }
    }
});

test('GoLogin retains an unconfirmed deletion and does not reissue it or start the profile', async t => {
    const { Profile, requests, responses, launches } = await loadGoLogin(t);
    const deadlines = mockGoLoginTimers(t);
    const profile = new Profile('fixture-delete-pending');
    await profile.start();
    responses.push(reply(202, { success: true }));

    const deleting = profile.delete();
    assert.equal(profile.delete(), deleting);
    const expected = { profileId: 'fixture-delete-pending', profileCleanup: 'delete-unconfirmed' };
    await assert.rejects(deleting, expected);
    await assert.rejects(profile.delete(), expected);
    await assert.rejects(profile.start(), /deletion is unconfirmed/);
    assert.deepEqual(requests.map(request => request.method), ['DELETE']);
    assert.equal(launches.length, 1);
    assert.equal(deadlines.size, 0);
});

test('GoLogin direct start binds its credential before yielding', async t => {
    const { Profile, responses, requests, launches, stops } = await loadGoLogin(t);
    const deadlines = mockGoLoginTimers(t);
    process.env.GOLOGIN_API_KEY = 'fixture-start-owner';
    const profile = new Profile('fixture-existing');
    const starting = profile.start();
    process.env.GOLOGIN_API_KEY = 'fixture-other-tenant';
    await starting;
    responses.push(reply(204, ''));
    assert.equal(await profile.delete(), true);
    assert.equal(launches[0].token, 'fixture-start-owner');
    assert.deepEqual(stops, ['fixture-start-owner']);
    assert.deepEqual(requests.map(request => [request.method, request.headers.Authorization]), [
        ['DELETE', 'Bearer fixture-start-owner']
    ]);
    assert.equal(deadlines.size, 0);
});

test('GoLogin can explicitly delete a cold profile and recover from a known refusal', async t => {
    const { Profile, requests, responses, launches, stops } = await loadGoLogin(t);
    const refused = Object.assign(new Error('fixture private response'), { response: { status: 403 } });
    const notSent = Object.assign(new Error('fixture private diagnosis'), { code: 'ENOTFOUND' });
    responses.push(refused, reply(200, { success: false }), notSent, reply(204, ''));
    process.env.GOLOGIN_API_KEY = 'fixture-delete-owner';
    const profile = new Profile('fixture-existing');
    const first = profile.delete();
    process.env.GOLOGIN_API_KEY = 'fixture-other-tenant';
    await assert.rejects(first, { profileId: 'fixture-existing', profileCleanup: 'delete-rejected' });
    assert.equal(requests.length, 1);
    await assert.rejects(profile.delete(), { profileCleanup: 'delete-rejected' });
    assert.equal(requests.length, 2);
    await assert.rejects(profile.delete(), { profileCleanup: 'delete-rejected' });
    assert.equal(requests.length, 3);
    assert.equal(await profile.delete(), true);
    assert.equal(await profile.delete(), true);
    assert.equal(requests.length, 4);
    assert.ok(requests.every(request => request.method === 'DELETE' &&
        new URL(request.url).pathname === '/browser/fixture-existing' &&
        request.headers.Authorization === 'Bearer fixture-delete-owner'));
    assert.equal(launches.length, 0);
    assert.equal(stops.length, 0);
});

test('GoLogin wrappers close their borrowed SDK browser without stopping shared SDK resources', async t => {
    const { Profile, browser, requests } = await loadGoLogin(t);
    const deadlines = mockGoLoginTimers(t);
    let globalStops = 0;
    let closes = 0;
    browser.close = async () => { closes++; };
    const sharedSdk = {
        async launch() { return { browser }; },
        async stop() { globalStops++; }
    };
    const active = new Profile('fixture-active', sharedSdk);
    const other = new Profile('fixture-not-started', sharedSdk);
    await active.start();
    assert.equal(await other.stop(), false);
    assert.equal(active.browser, browser);
    assert.equal(closes, 0);
    assert.equal(globalStops, 0);
    assert.equal(await active.stop(), true);
    assert.equal(closes, 1);
    assert.equal(globalStops, 0);
    await assert.rejects(active.delete(), /requires a bound REST credential/);
    const providedSession = new Profile('fixture-provided-session', null, { createSdk: () => sharedSdk });
    await providedSession.start();
    assert.equal(await providedSession.stop(), true);
    assert.equal(closes, 2);
    assert.equal(globalStops, 0);
    assert.equal(requests.length, 0);
    assert.equal(deadlines.size, 0);
});

test('GoLogin factory compensates an SDK initialization failure using its allocation credential', async t => {
    const { createAndStartProfile, requests, responses, launches, sdk } = await loadGoLogin(t);
    const deadlines = mockGoLoginTimers(t);
    sdk.initialize = () => { throw new Error('fixture SDK initialization failure'); };
    process.env.GOLOGIN_API_KEY = 'fixture-allocate';
    responses.push(() => {
        process.env.GOLOGIN_API_KEY = 'fixture-other-tenant';
        return reply(201, { id: 'fixture-allocated' });
    }, reply(200, { id: 'fixture-allocated' }), reply(204, ''));

    await assert.rejects(createAndStartProfile('fixture'), {
        profileId: 'fixture-allocated', profileCleanup: 'deleted'
    });
    assert.deepEqual(requests.map(request => [request.method, new URL(request.url).pathname]), [
        ['POST', '/browser/custom'], ['GET', '/browser/fixture-allocated'], ['DELETE', '/browser/fixture-allocated']
    ]);
    assert.ok(requests.every(request => request.headers.Authorization === 'Bearer fixture-allocate'));
    assert.equal(launches.length, 0);
    assert.equal(deadlines.size, 0);
});

test('GoLogin factory compensates building a page only for its allocated profile', async t => {
    for (const [label, stopConfirmed, deleteResponse, cleanup] of [
        ['confirmed stop', true, { success: true }, 'deleted'],
        ['unconfirmed stop', false, { success: true }, 'stop-unconfirmed'],
        ['rejected deletion', true, { success: false }, 'delete-rejected'],
        ['unconfirmed deletion', true, {}, 'delete-unconfirmed']
    ]) {
        await t.test(label, async t => {
            const { createAndStartProfile, responses, requests, browser, sdk, stops } = await loadGoLogin(t);
            const deadlines = mockGoLoginTimers(t);
            browser.newPage = async () => { throw new Error('fixture-private-SDK-error'); };
            let closes = 0;
            browser.close = async () => { closes++; };
            sdk.stop = async () => stopConfirmed;
            process.env.GOLOGIN_API_KEY = 'fixture-owner';
            responses.push(() => {
                process.env.GOLOGIN_API_KEY = 'fixture-other-tenant';
                return reply(201, { id: 'fixture-owned' });
            }, reply(200, {}), reply(200, deleteResponse));
            await assert.rejects(createAndStartProfile('fixture'), error => {
                assert.equal(error.profileId, 'fixture-owned');
                assert.equal(error.profileCleanup, cleanup);
                assert.doesNotMatch(JSON.stringify(error) + error.stack, /fixture-private-SDK-error/);
                return true;
            });
            const deletes = requests.filter(({ method }) => method === 'DELETE');
            assert.deepEqual(deletes.map(request => new URL(request.url).pathname), stopConfirmed ? ['/browser/fixture-owned'] : []);
            assert.ok(requests.every(request => request.headers.Authorization === 'Bearer fixture-owner'));
            assert.deepEqual(stops, ['fixture-owner']);
            assert.equal(closes, 1);
            assert.equal(deadlines.size, 0);
        });
    }
});

test('GoLogin coalesces lifecycle calls and discards a page that resolves after deletion', async t => {
    const { Profile, browser, requests, responses, launches, stops } = await loadGoLogin(t);
    const deadlines = mockGoLoginTimers(t);
    const openingPage = deferred();
    const pageRequested = deferred();
    browser.newPage = () => {
        pageRequested.resolve();
        return openingPage.promise;
    };
    let closes = 0;
    browser.close = async () => { closes++; };
    const profile = new Profile('fixture-deleting');
    const starting = profile.start();
    assert.equal(profile.start(), starting);
    const failure = assert.rejects(starting, /startup interrupted by shutdown/);
    await pageRequested.promise;
    responses.push(reply(204, ''));

    const deleting = profile.delete();
    assert.equal(profile.delete(), deleting);
    assert.equal(profile.stop(), profile.stop());
    await failure;
    assert.equal(await deleting, true);
    openingPage.resolve({});
    await setImmediate();

    assert.equal(profile.browser, null);
    assert.equal(profile.page, null);
    assert.equal(closes, 1);
    assert.equal(launches.length, 1);
    assert.deepEqual(stops, ['fixture-import-key']);
    assert.deepEqual(requests.map(request => [request.method, new URL(request.url).pathname]), [
        ['DELETE', '/browser/fixture-deleting']
    ]);
    assert.equal(await profile.delete(), true);
    await assert.rejects(profile.start(), /was deleted/);
    assert.equal(requests.length, 1);
    assert.equal(deadlines.size, 0);
});

test('GoLogin stops or times out pending launches without adopting late browsers', async t => {
    for (const cancelled of ['stop', 'timeout']) {
        await t.test(cancelled, async t => {
            const { Profile, browser, sdk, launches, stops } = await loadGoLogin(t);
            const deadlines = mockGoLoginTimers(t);
            const pending = deferred();
            sdk.launch = () => pending.promise;
            let pageCreations = 0;
            let closes = 0;
            browser.newPage = async () => { pageCreations++; };
            browser.close = async () => { closes++; };
            const profile = new Profile('fixture-late');
            const start = profile.start().catch(error => error);
            await setImmediate();
            assert.equal(launches.length, 1);
            if (cancelled === 'stop') {
                assert.equal(await profile.stop(), false);
            } else {
                const [{ callback, delay }] = deadlines.values();
                assert.equal(delay, 120000);
                callback();
            }
            const error = await Promise.race([start, setImmediate('pending')]);
            assert.ok(error instanceof Error);
            await assert.rejects(profile.start(), /shutdown.*unconfirmed/);
            pending.resolve({ browser });
            await setImmediate();
            assert.equal(closes, 1);
            assert.deepEqual(stops, ['fixture-import-key']);
            assert.equal(pageCreations, 0);
            assert.equal(profile.browser, null);
            assert.equal(profile.page, null);
            assert.equal(launches.length, 1);
            assert.equal(await profile.stop(), true);
            assert.deepEqual(stops, ['fixture-import-key']);
            assert.equal(deadlines.size, 0);
        });
    }
});

test('GoLogin factory finishes late launch cleanup before its first deletion attempt', async t => {
    for (const [label, confirmed, deletion] of [
        ['confirmed stop and deletion', true, reply(204, '')],
        ['ambiguous deletion receipt', true, reply(202, { success: true })],
        ['unconfirmed stop', false, reply(204, '')]
    ]) {
        await t.test(label, async t => {
            const { createAndStartProfile, requests, responses, browser, sdk, launches, stops } = await loadGoLogin(t);
            const deadlines = mockGoLoginTimers(t);
            const output = [];
            process.env.LOG_LEVEL = 'INFO';
            t.mock.method(console, 'log', message => output.push(message));
            const pendingLaunch = deferred();
            const pendingStop = deferred();
            sdk.launch = () => pendingLaunch.promise;
            sdk.stop = () => pendingStop.promise;
            let closes = 0;
            browser.close = async () => { closes++; };
            process.env.GOLOGIN_API_KEY = 'fixture-allocation-owner';
            responses.push(reply(201, { id: 'fixture-late-owned' }), reply(200, {}), deletion);
            const attempt = createAndStartProfile('fixture');
            const failure = assert.rejects(attempt, {
                profileId: 'fixture-late-owned', profileCleanup: 'stop-unconfirmed'
            });
            await setImmediate();
            assert.equal(launches.length, 1);
            const [{ callback, delay }] = deadlines.values();
            assert.equal(delay, 120000);
            callback();
            await failure;
            assert.deepEqual(requests.map(request => request.method), ['POST', 'GET']);

            process.env.GOLOGIN_API_KEY = 'fixture-other-tenant';
            pendingLaunch.resolve({ browser });
            await setImmediate();
            assert.equal(closes, 1);
            assert.deepEqual(stops, ['fixture-allocation-owner']);
            assert.deepEqual(requests.map(request => request.method), ['POST', 'GET']);

            pendingStop.resolve(confirmed);
            await setImmediate();
            const deletes = requests.filter(request => request.method === 'DELETE');
            assert.deepEqual(deletes.map(request => new URL(request.url).pathname), confirmed ? ['/browser/fixture-late-owned'] : []);
            assert.ok(requests.every(request => request.headers.Authorization === 'Bearer fixture-allocation-owner'));
            assert.equal(output.some(message => message.includes('GoLogin profile deleted')), confirmed && deletion.status === 204);
            assert.equal(deadlines.size, 0);
        });
    }
});

function vaultKey(key) {
    return `dotenv://:key_${key.toString('hex')}@vault.invalid/vault/.env.vault?environment=production`;
}

async function writeVault(state, key) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const payload = Buffer.concat([
        nonce,
        cipher.update('GOLOGIN_API_KEY=fixture-vault-key\nLOG_LEVEL=debug\n'),
        cipher.final(),
        cipher.getAuthTag()
    ]).toString('base64');
    const file = path.join(state, '.env.vault');
    await writeFile(file, `DOTENV_VAULT_PRODUCTION="${payload}"\n`, { mode: 0o644 });
    return file;
}

test('GoLogin loads a private vault with key rotation and preserves exported settings', async t => {
    const key = Buffer.alloc(32, 1);
    let vault;
    const { client, requests, responses } = await loadGoLogin(t, async state => {
        process.env.DOTENV_KEY = `${vaultKey(Buffer.alloc(32, 2))},${vaultKey(key)}`;
        vault = await writeVault(state, key);
        await writeFile(path.join(state, '.env'), 'GOLOGIN_API_KEY=fixture-plaintext-key\n', { mode: 0o600 });
    });

    responses.push(reply(200, {}));
    await client.request('GET', '/browser/v2');
    assert.equal(requests[0].headers.Authorization, 'Bearer fixture-vault-key');
    assert.equal(process.env.LOG_LEVEL, 'silent');
    if (process.platform !== 'win32') assert.equal((await stat(vault)).mode & 0o777, 0o600);
});

test('GoLogin vault failures omit key material and decline plaintext fallback', async t => {
    const key = Buffer.alloc(32, 1);
    for (const [label, configured, message] of [
        ['malformed key', 'fixture-malformed-key', 'Invalid DOTENV_KEY'],
        ['key cannot decrypt vault', vaultKey(Buffer.alloc(32, 2)), 'Could not parse environment configuration in .env.vault']
    ]) {
        await t.test(label, async t => {
            await assert.rejects(loadGoLogin(t, async state => {
                process.env.DOTENV_KEY = configured;
                await writeVault(state, key);
                await writeFile(path.join(state, '.env'), 'GOLOGIN_API_KEY=fixture-plaintext-key\n', { mode: 0o600 });
            }), { message });
            assert.equal(process.env.GOLOGIN_API_KEY, undefined);
        });
    }
});
