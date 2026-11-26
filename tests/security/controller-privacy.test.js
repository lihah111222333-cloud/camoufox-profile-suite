import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

const fixtureKey = Symbol.for('controller-privacy-test');
const syntheticKey = 'test-only-key';
const proxy = { ip: 'proxy.invalid', port: 8888, username: 'test-proxy-user', password: 'test-proxy-password' };

async function copySource(source, destination) {
    await mkdir(destination);
    const entries = await readdir(source, { withFileTypes: true });
    await Promise.all(entries.map(entry => {
        const from = new URL(entry.name, source);
        const to = path.join(destination, entry.name);
        return entry.isDirectory() ? copySource(new URL(entry.name + '/', source), to) : copyFile(from, to);
    }));
}

async function loadControllers(t, overrides = {}, stateEnvironment) {
    const root = await mkdtemp(path.join(os.tmpdir(), 'controller-privacy-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    await copySource(new URL('../../src/', import.meta.url), path.join(root, 'src'));
    await mkdir(path.join(root, 'scripts'));
    await copyFile(new URL('../../scripts/list-dolphin-folders.js', import.meta.url), path.join(root, 'scripts/list-dolphin-folders.js'));
    await writeFile(path.join(root, 'package.json'), '{"type":"module"}');

    const appStateDir = path.join(root, 'app-state');
    if (stateEnvironment) {
        await mkdir(appStateDir, { mode: 0o700 });
        await writeFile(path.join(appStateDir, '.env'), stateEnvironment, { mode: 0o600 });
    }
    const env = {
        GMAIL_CREATOR_STATE_DIR: appStateDir,
        PROFILE_SERVICE: 'gpm',
        GPM_API_URL: 'https://gpm-controller.invalid:7443',
        DOLPHIN_API_URL: 'https://dolphin-controller.invalid:7443',
        GPM_TRUSTED_HTTP_API_URL: undefined,
        DOLPHIN_TRUSTED_HTTP_API_URL: undefined,
        DOLPHIN_API_KEY: syntheticKey,
        DOLPHIN_FOLDER_ID: 'fixture-folder',
        OMOCAPTCHA_KEY: 'test-omo-key',
        SMS_VERIFY_API_KEY: 'test-sms-key',
        LOG_LEVEL: 'debug',
        ...overrides
    };
    for (const [key, value] of Object.entries(env)) {
        const previous = process.env[key];
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
        t.after(() => {
            if (previous === undefined) delete process.env[key];
            else process.env[key] = previous;
        });
    }
    const previousExitCode = process.exitCode;
    t.after(() => { process.exitCode = previousExitCode; });

    const output = [];
    t.mock.method(console, 'log', line => { output.push(String(line)); });
    t.mock.method(console, 'error', line => { output.push(String(line)); });
    const requests = [];
    const responses = [];
    function send(method, url, data, options) {
        requests.push({ method, url, data, options });
        assert.ok(responses.length, 'Unexpected controller request');
        const response = responses.shift();
        if (response instanceof Error) throw response;
        return response;
    }
    globalThis[fixtureKey] = {
        create(defaults) {
            return {
                get: (url, options) => send('GET', url, undefined, { ...defaults, ...options }),
                post: (url, data, options) => send('POST', url, data, { ...defaults, ...options }),
                delete: (url, options) => send('DELETE', url, undefined, { ...defaults, ...options })
            };
        }
    };
    t.after(() => { delete globalThis[fixtureKey]; });
    const axios = path.join(root, 'node_modules', 'axios');
    await mkdir(axios, { recursive: true });
    await writeFile(path.join(axios, 'package.json'), '{"main":"index.cjs"}');
    await writeFile(path.join(axios, 'index.cjs'), 'module.exports = globalThis[Symbol.for("controller-privacy-test")];');

    const load = name => import(pathToFileURL(path.join(root, name)).href);
    const [gpm, dolphin] = await Promise.all([load('src/gpmlogin/client.js'), load('src/dolphin/client.js')]);
    return { gpm, dolphin, requests, responses, output, load, root, appStateDir };
}

function rejectedResponse(status, data) {
    const error = new Error('controller diagnostic with a test-proxy-password');
    error.response = { status, data };
    error.config = { headers: { Authorization: syntheticKey } };
    return error;
}

test('plaintext controller calls need their own exact numeric loopback base', async t => {
    const { gpm, dolphin, requests, responses } = await loadControllers(t, {
        GPM_API_URL: 'http://127.0.0.1:14517/custom-base',
        DOLPHIN_API_URL: 'http://[::1]:30898'
    });

    assert.equal(await gpm.checkGPMConnection(), false);
    assert.equal(await dolphin.checkDolphinConnection(), false);
    await assert.rejects(gpm.createProfile('test profile', proxy), /GPM_TRUSTED_HTTP_API_URL/);
    await assert.rejects(dolphin.createProfile('test profile', proxy), /DOLPHIN_TRUSTED_HTTP_API_URL/);
    await assert.rejects(dolphin.getAllFolders(), /DOLPHIN_TRUSTED_HTTP_API_URL/);

    process.env.GPM_TRUSTED_HTTP_API_URL = 'http://127.0.0.1:14517';
    process.env.DOLPHIN_TRUSTED_HTTP_API_URL = 'http://[::1]:30899';
    await assert.rejects(gpm.createProfile('test profile', proxy), /requires HTTPS/);
    await assert.rejects(dolphin.updateProfileProxy('fixture', proxy), /requires HTTPS/);
    assert.equal(requests.length, 0);

    process.env.GPM_TRUSTED_HTTP_API_URL = 'http://127.0.0.1:14517/custom-base';
    process.env.DOLPHIN_TRUSTED_HTTP_API_URL = 'http://[::1]:30898';
    responses.push({ data: { id: 'gpm-test' } }, { data: { id: 'dolphin-test' } });
    assert.equal((await gpm.createProfile('test profile', proxy)).id, 'gpm-test');
    assert.equal((await dolphin.createProfile('test profile', proxy)).id, 'dolphin-test');
    assert.equal(requests[0].url, 'http://127.0.0.1:14517/custom-base/api/v3/profiles/create');
    assert.equal(requests[1].url, 'http://[::1]:30898/api/profile/advancedCreateProfile');
    assert.equal(requests[1].options.headers.Authorization, syntheticKey);
    assert.equal(requests[1].data.folderId, 'fixture-folder');
    assert.ok(requests.every(request => request.options.proxy === false && request.options.maxRedirects === 0));
});

test('plaintext trust cannot approve a hostname or a remote IP', async t => {
    const { gpm, dolphin, requests } = await loadControllers(t, {
        GPM_API_URL: 'http://localhost:14517',
        GPM_TRUSTED_HTTP_API_URL: 'http://localhost:14517',
        DOLPHIN_API_URL: 'http://192.0.2.10:30898',
        DOLPHIN_TRUSTED_HTTP_API_URL: 'http://192.0.2.10:30898'
    });
    await assert.rejects(gpm.createProfile('test profile', proxy), /numeric loopback/);
    await assert.rejects(dolphin.getAllFolders(), /require HTTPS or WSS/);
    assert.equal(requests.length, 0);
});

test('controller trust and authorization can load from private state configuration', async t => {
    const gpmBase = 'http://127.0.0.1:14517';
    const dolphinBase = 'http://[::1]:30898';
    const { gpm, dolphin, requests, responses } = await loadControllers(t, {
        GPM_API_URL: undefined,
        GPM_TRUSTED_HTTP_API_URL: undefined,
        DOLPHIN_API_URL: undefined,
        DOLPHIN_TRUSTED_HTTP_API_URL: undefined,
        DOLPHIN_API_KEY: undefined
    }, [
        'GPM_API_URL=' + gpmBase,
        'GPM_TRUSTED_HTTP_API_URL=' + gpmBase,
        'DOLPHIN_API_URL=' + dolphinBase,
        'DOLPHIN_TRUSTED_HTTP_API_URL=' + dolphinBase,
        'DOLPHIN_API_KEY=' + syntheticKey
    ].join('\n'));

    responses.push({ status: 200 }, { status: 200 });
    assert.equal(await gpm.checkGPMConnection(), true);
    assert.equal(await dolphin.checkDolphinConnection(), true);
    assert.deepEqual(requests.map(request => new URL(request.url).origin), [gpmBase, dolphinBase]);
    assert.equal(requests[1].options.headers.Authorization, syntheticKey);
});

test('all GPM profile routes take a single opaque identifier', async t => {
    const { gpm, requests, responses } = await loadControllers(t);
    for (const id of ['', 'embedded space', '.', 'line\nbreak', 'contains%sign']) {
        await assert.rejects(gpm.getProfile(id), /Invalid browser controller profile ID/);
        await assert.rejects(gpm.startProfile(id), /Invalid browser controller profile ID/);
        await assert.rejects(gpm.deleteProfile(id), /Invalid browser controller profile ID/);
        assert.equal(await gpm.stopProfile(id), false);
    }
    assert.equal(requests.length, 0);

    responses.push(
        { data: { data: { id: 'test-8_9' } } },
        { data: { data: { remote_debugging_address: 'https://gpm-controller.invalid:9443' } } },
        { status: 200 },
        { status: 204 }
    );
    assert.equal((await gpm.getProfile('test-8_9')).id, 'test-8_9');
    await gpm.startProfile('test-8_9');
    assert.equal(await gpm.stopProfile(123), true);
    assert.equal(await gpm.deleteProfile('test-8_9', 1), true);
    assert.deepEqual(requests.map(request => new URL(request.url).pathname), [
        '/api/v3/profiles/test-8_9',
        '/api/v3/profiles/start/test-8_9',
        '/api/v3/profiles/stop/123',
        '/api/v3/profiles/delete/test-8_9'
    ]);
    assert.equal(new URL(requests[3].url).searchParams.get('mode'), '1');
});

test('Dolphin profile operations require opaque IDs and preserve their type in JSON', async t => {
    const { dolphin, requests, responses } = await loadControllers(t);
    const invalid = { id: 'test-profile' };
    await assert.rejects(dolphin.startProfile(invalid), /Invalid browser controller profile ID/);
    await assert.rejects(dolphin.getProfile(invalid), /Invalid browser controller profile ID/);
    await assert.rejects(dolphin.deleteProfile(invalid), /Invalid browser controller profile ID/);
    await assert.rejects(dolphin.updateProfileProxy([invalid], proxy), /Invalid browser controller profile ID/);
    await assert.rejects(dolphin.updateProfileProxy([], proxy), /At least one/);
    assert.equal(await dolphin.stopProfile(invalid), false);
    assert.equal(requests.length, 0);

    responses.push({ status: 204 }, { status: 204 }, { status: 200 });
    assert.equal(await dolphin.stopProfile(123), true);
    assert.equal(await dolphin.deleteProfile('test-id_12'), true);
    await dolphin.updateProfileProxy([123, 'test-id_12'], proxy);
    assert.deepEqual(requests[0].data, { profileIds: [123] });
    assert.deepEqual(requests[1].data, { profileIds: ['test-id_12'] });
    assert.deepEqual(requests[2].data.ids, [123, 'test-id_12']);
});

test('profile creation supplies only a valid opaque ID to managed callers', async t => {
    const { gpm, dolphin, requests, responses } = await loadControllers(t);
    responses.push(
        { data: { success: true, data: { id: { id: 'test-profile' } } } },
        { data: { id: 'invalid ID' } },
        { data: { success: true, data: { id: 123 } } },
        { data: { id: 456 } }
    );
    await assert.rejects(gpm.createProfile('test profile'), /Invalid browser controller profile ID/);
    await assert.rejects(dolphin.createProfile('test profile'), /Invalid browser controller profile ID/);
    assert.equal((await gpm.createProfile('test profile')).id, 123);
    assert.equal((await dolphin.createProfile('test profile')).id, 456);
    assert.equal(requests.length, 4);
});

test('Dolphin only posts profile data to the selected destination', async t => {
    const { dolphin, requests, responses } = await loadControllers(t, { DOLPHIN_FOLDER_ID: '' });
    const unrelated = { id: 'unrelated-folder', name: 'Unrelated folder' };
    const named = { folderId: 'intended-folder', folderName: 'gmail-accounts' };
    const list = '/api/folder/list';
    const add = '/api/folder/add';
    const create = '/api/profile/advancedCreateProfile';
    const paths = () => requests.splice(0).map(request => new URL(request.url).pathname);

    responses.push(rejectedResponse(503, { message: proxy.password }));
    await assert.rejects(dolphin.createProfile('test profile', proxy), { status: 503 });
    assert.deepEqual(paths(), [list]);

    responses.push({ data: { data: [unrelated] } }, rejectedResponse(403, { code: 50200, message: proxy.password }));
    await assert.rejects(dolphin.createProfile('test profile', proxy), { status: 403, providerCode: '50200' });
    assert.deepEqual(paths(), [list, add]);

    responses.push({ data: { list: [unrelated, named, { ...named, folderId: 'another-folder' }] } });
    await assert.rejects(dolphin.createProfile('test profile', proxy), /DOLPHIN_FOLDER_ID explicitly/);
    assert.deepEqual(paths(), [list]);

    responses.push({ data: { data: [unrelated] } }, rejectedResponse(400, '{"code":12001}'),
        { data: { folders: [unrelated, named] } }, { data: { id: 'profile-one' } });
    assert.equal((await dolphin.createProfile('test profile', proxy)).id, 'profile-one');
    assert.equal(requests.at(-1).data.folderId, 'intended-folder');
    assert.deepEqual(paths(), [list, add, list, create]);
});

test('controller failures disclose only a safe operation, status and known codes', async t => {
    const { gpm, dolphin, responses, requests, output, root, appStateDir } = await loadControllers(t);
    const certificateError = new Error('certificate failure caused by ' + proxy.password);
    certificateError.code = 'CERT_HAS_EXPIRED';
    responses.push(
        rejectedResponse(502, 'plain-text echo ' + proxy.password),
        rejectedResponse(403, { other: syntheticKey, code: proxy.password }),
        { data: 'invalid JSON ' + proxy.password },
        certificateError
    );
    await assert.rejects(gpm.createProfile('test profile', proxy), error => {
        assert.match(error.message, /GPM API create profile failed \(HTTP 502\)/);
        assert.equal(error.response, undefined);
        assert.equal(error.config, undefined);
        return true;
    });
    await assert.rejects(dolphin.createProfile('test profile', proxy), /Dolphin Anty API create profile failed \(HTTP 403\)/);
    await assert.rejects(gpm.createProfile('test profile', proxy), /invalid JSON/);
    await assert.rejects(dolphin.updateProfileProxy('fixture', proxy), /CERT_HAS_EXPIRED/);
    assert.deepEqual(responses, []);
    assert.equal(requests.length, 4);
    for (const request of requests) {
        assert.equal(new URL(request.url).protocol, 'https:');
        assert.equal(request.options.httpsAgent.options.rejectUnauthorized, true);
        assert.equal(request.options.maxRedirects, 0);
        assert.equal(request.options.proxy, false);
    }

    const logDirs = [root, appStateDir].map(dir => path.join(dir, 'logs'));
    const snapshots = await Promise.all(logDirs.map(async dir => {
        const files = await readdir(dir).catch(error => {
            if (error.code === 'ENOENT') return [];
            throw error;
        });
        return Promise.all(files.map(file => readFile(path.join(dir, file), 'utf8')));
    }));
    const logs = snapshots.flat().join('\n');
    assert.match(logs, /GPM API create profile failed/);
    const diagnostics = output.join('\n') + logs;
    assert.match(diagnostics, /GPM API create profile failed/);
    assert.match(diagnostics, /"status":502/);
    assert.match(diagnostics, /CERT_HAS_EXPIRED/);
    for (const secret of [syntheticKey, proxy.username, proxy.password]) assert.ok(!diagnostics.includes(secret));
});

test('Dolphin folder command reports configured status and escapes folder fields', async t => {
    const { load, output, requests, responses } = await loadControllers(t);
    responses.push(rejectedResponse(401, { message: syntheticKey }), { data: { data: [{
        id: 'test-id\u0085tail',
        folderName: 'test-name\nline\x1b',
        folderColor: '#3370FF\u202e',
        resourceCount: '5\r6'
    }] } });
    await load('scripts/list-dolphin-folders.js');
    assert.deepEqual(requests.map(request => request.options.headers.Authorization),
        [syntheticKey, 'Bearer ' + syntheticKey]);
    const listing = output.join('\n');
    assert.match(listing, /DOLPHIN_API_KEY configured: true/);
    assert.ok(!listing.includes(syntheticKey));
    for (const escaped of ['test-id\\u{0085}tail', 'test-name\\u{000a}line\\u{001b}', '#3370FF\\u{202e}', '5\\u{000d}6']) {
        assert.ok(listing.includes(escaped), escaped);
    }
    assert.doesNotMatch(listing, /[\x1b\u0085\u202e\r]/);
});

test('Dolphin folder command reports a safe failure from the controller', async t => {
    const { load, output, responses } = await loadControllers(t, { LOG_LEVEL: 'silent' });
    responses.push(rejectedResponse(403, { message: syntheticKey, note: proxy.password }));
    await load('scripts/list-dolphin-folders.js');
    const listing = output.join('\n');
    assert.match(listing, /DOLPHIN_API_KEY configured: true/);
    assert.match(listing, /HTTP 403/);
    assert.ok(!listing.includes(syntheticKey));
    assert.ok(!listing.includes(proxy.password));
    assert.equal(process.exitCode, 1);
});

test('controller clients reject an explicit negative stop or delete acknowledgement', async t => {
    const { gpm, dolphin, responses } = await loadControllers(t);
    const rejected = { status: 200, data: '{"success":false,"message":"test-proxy-password"}' };
    const closed = { status: 204 };
    responses.push(rejected, rejected, rejected, rejected, { status: 200 }, closed, closed, closed,
        rejectedResponse(400, { message: 'Profile is not running' }), { status: 202 }, { status: 202 });
    assert.equal(await gpm.stopProfile('fixture'), false);
    await assert.rejects(gpm.deleteProfile('fixture'), /did not confirm profile deletion/);
    assert.equal(await dolphin.stopProfile('fixture'), false);
    await assert.rejects(dolphin.deleteProfile('fixture'), /did not confirm profile deletion/);
    assert.equal(await gpm.stopProfile('fixture'), true);
    assert.equal(await gpm.deleteProfile('fixture'), true);
    assert.equal(await dolphin.stopProfile('fixture'), true);
    assert.equal(await dolphin.deleteProfile('fixture'), true);
    assert.equal(await gpm.stopProfile('fixture'), true);
    assert.equal(await dolphin.stopProfile('fixture'), false);
    await assert.rejects(dolphin.deleteProfile('fixture'), /did not confirm profile deletion/);
    assert.deepEqual(responses, []);
});
