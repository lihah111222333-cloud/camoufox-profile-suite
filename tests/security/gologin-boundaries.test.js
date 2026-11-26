import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { copyFile, mkdir, mkdtemp, readdir, rm, stat, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import dotenv from 'dotenv';

async function loadGoLogin(t, configure) {
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
    globalThis[fixtureKey] = {
        axios: async request => {
            requests.push(request);
            assert.ok(responses.length, 'Unexpected REST request');
            const response = responses.shift();
            if (response instanceof Error) throw response;
            return { data: typeof response === 'function' ? response() : response };
        },
        dotenv,
        gologin: {
            GologinApi({ token }) {
                return {
                    async launch(options) {
                        launches.push({ token, options });
                        return { browser };
                    },
                    async stop() { stops.push(token); }
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
    const client = await load('client.js');
    if (!configure) {
        assert.equal(process.env.GOLOGIN_API_KEY, 'fixture-import-key');
        if (process.platform !== 'win32') assert.equal((await stat(envFile)).mode & 0o777, 0o600);
    }
    const profile = await load('profile.js');
    return {
        client: client.default, Profile: profile.default, createAndStartProfile: profile.createAndStartProfile,
        requests, responses, launches, stops
    };
}

const proxy = { mode: 'http', host: 'proxy.invalid', port: 8080, username: 'fixture-user', password: 'fixture-password' };

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
        responses.push({ ok: true }, redirect);
        process.env.GOLOGIN_API_KEY = 'fixture-current-key';
        assert.deepEqual(await client.request('GET', '/browser/v2?page=2'), { ok: true });
        for (const endpoint of ['https://outside.invalid/resource', '//outside.invalid/resource', 'browser', '/resource#section']) {
            await assert.rejects(client.request('GET', endpoint), /root-relative path/);
        }
        await assert.rejects(client.request('GET', '/browser/v2'), /Fixture redirect/);
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
            responses.push({});
            await operation(id);
            const [request] = requests.splice(0);
            assert.equal(request.method, method);
            assert.equal(new URL(request.url).pathname, route);
        }
    });

    await t.test('factory creation, proxy update, launch, and later deletion retain their tenant', async t => {
        t.mock.method(globalThis, 'setTimeout', (callback, delay) => {
            if (delay === 5000) queueMicrotask(callback);
        });
        // Isolate credential routing from the existing fingerprint generator.
        t.mock.method(client.constructor.prototype, 'generateAndroidFingerprint', () => ({
            navigator: { userAgent: 'offline-fixture' },
            timezone: {}
        }));
        process.env.GOLOGIN_API_KEY = 'fixture-tenant-a';
        responses.push(() => {
            process.env.GOLOGIN_API_KEY = 'fixture-tenant-b';
            return { id: 'fixture-profile' };
        }, {}, { id: 'fixture-profile' });

        const profile = await createAndStartProfile('fixture', proxy);
        assert.equal(profile.profileId, 'fixture-profile');
        assert.equal(proxyConnections.length, 0);
        assert.deepEqual(launches, [{ token: 'fixture-tenant-a', options: { profileId: 'fixture-profile', cloud: true } }]);
        assert.deepEqual(requests.map(request => [request.method, new URL(request.url).pathname]), [
            ['POST', '/browser/custom'], ['PATCH', '/browser/fixture-profile/proxy'], ['GET', '/browser/fixture-profile']
        ]);

        process.env.GOLOGIN_API_KEY = 'fixture-tenant-c';
        assert.equal(await profile.stop(), true);
        assert.equal(profile.browser, null);
        assert.equal(profile.page, null);
        assert.deepEqual(stops, ['fixture-tenant-a']);
        assert.equal(requests.length, 3);

        responses.push({});
        assert.equal(await profile.delete(), true);
        assert.equal(requests[3].method, 'DELETE');
        assert.equal(new URL(requests[3].url).pathname, '/browser/fixture-profile');
        assert.ok(requests.splice(0).every(request => request.headers.Authorization === 'Bearer fixture-tenant-a'));
        assert.equal(responses.length, 0);
    });

    await t.test('stop failure is observable and an external SDK cannot delete through an ambient tenant', async () => {
        const profile = new Profile('external-fixture', { async stop() { return false; } });
        assert.equal(await profile.stop(), false);
        await assert.rejects(profile.delete(), /requires a bound REST credential/);
        assert.equal(requests.length, 0);
    });
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

    responses.push({});
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
