import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

async function fixture(t) {
    const root = await mkdtemp(path.join(tmpdir(), 'managed-lifecycle-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    // Keep all lifecycle and output code real, but replace the controller, CDP and consumer.
    for (const name of ['bin', 'src/utils', 'src/index.js', 'src/gpmlogin/profile.js', 'src/dolphin/profile.js']) {
        const destination = path.join(root, name);
        await mkdir(path.dirname(destination), { recursive: true });
        await cp(new URL('../../' + name, import.meta.url), destination, { recursive: true });
    }
    async function put(name, source) {
        const destination = path.join(root, name);
        await mkdir(path.dirname(destination), { recursive: true });
        await writeFile(destination, source);
    }
    await put('package.json', '{"type":"module"}');
    await put('src/fixture.cjs', `
        const fs = require('node:fs');
        const path = require('node:path');
        const state = {
            events: [],
            stops: [],
            starts: 0,
            stopOK: process.env.FIXTURE_STOP_OK !== 'false',
            deleteOK: true,
            pageError: process.env.FIXTURE_FAIL_PAGE ? new Error('Synthetic page failure') : null,
            trace(...event) {
                state.events.push(event);
                if (process.env.FIXTURE_TRACE) console.log(JSON.stringify(event));
            },
            client(service) {
                return {
                    checkGPMConnection: async () => true,
                    checkDolphinConnection: async () => true,
                    createProfile: async () => {
                        state.trace('allocate', service);
                        return { id: service + '-fixture' };
                    },
                    startProfile: async id => {
                        state.trace('start', id);
                        if (process.env.FIXTURE_START_SIGNAL) process.emit(process.env.FIXTURE_START_SIGNAL);
                        await state.startGate;
                        if (state.startError) throw state.startError;
                        const url = 'wss://controller.invalid/devtools/browser/' + ++state.starts;
                        return { remote_debugging_address: url, ws: url };
                    },
                    stopProfile: async id => {
                        state.trace('stop', id);
                        if (process.env.FIXTURE_CHECK_SAVED) {
                            const saved = JSON.parse(fs.readFileSync(path.join(
                                process.env.GMAIL_CREATOR_STATE_DIR, 'results.json'
                            )));
                            state.trace('saved-at-stop', saved[0].success, saved[0].profileCleanup);
                        }
                        return state.stops.length ? state.stops.shift() : state.stopOK;
                    },
                    deleteProfile: async id => {
                        state.trace('delete', id);
                        return state.deleteOK;
                    }
                };
            }
        };
        module.exports = state;
    `);
    for (const service of ['gpmlogin', 'dolphin']) {
        await put(`src/${service}/client.js`, `import fixture from '../fixture.cjs';
            export default fixture.client(${JSON.stringify(service)});`);
    }
    for (const dependency of ['axios', 'ws', 'puppeteer-core']) {
        await put(`node_modules/${dependency}/package.json`, '{"main":"fixture.cjs"}');
    }
    await put('node_modules/axios/fixture.cjs', 'module.exports = {};');
    await put('node_modules/ws/fixture.cjs', `
        const { EventEmitter } = require('node:events');
        const state = require('../../src/fixture.cjs');
        module.exports = class extends EventEmitter {
            constructor(address) {
                super();
                state.trace('attach', address);
                queueMicrotask(() => this.emit('open'));
            }
            close() { this.emit('close'); }
        };
    `);
    await put('node_modules/puppeteer-core/fixture.cjs', `
        const state = require('../../src/fixture.cjs');
        module.exports = {
            async connect({ transport }) {
                return {
                    pages: async () => [],
                    async newPage() {
                        if (state.pageError) throw state.pageError;
                        return { evaluateOnNewDocument: async () => {}, url: () => 'about:blank',
                                 evaluate: async () => null };
                    },
                    disconnect() {
                        state.trace('disconnect');
                        transport.close();
                        state.onDisconnect?.();
                    }
                };
            }
        };
    `);
    await put('src/config.js', `
        globalThis.setTimeout = callback => queueMicrotask(callback);
        export default { profileService: 'gpm' };
    `);
    await put('src/utils/logger.js', `
        import state from '../fixture.cjs';
        export default {
            debug() {}, info() {}, error() {},
            warn(message, details) { state.trace('warn', message, details); }
        };
    `);
    await put('src/utils/name-generator.js', `
        export default { generateAccountData: () => ({ username: 'fixture' }) };
    `);
    await put('src/utils/proxy-manager.js', `
        const proxy = { ip: 'proxy.invalid', port: 8443 };
        export default { proxies: [proxy], getNextProxy: () => proxy, getAvailableCount: () => 1 };
    `);
    await put('src/gmail/creator.js', `
        import state from '../fixture.cjs';
        export async function createGmailAccount() {
            state.trace('consume');
            if (process.env.FIXTURE_SIGNAL) {
                await new Promise(resolve => {
                    state.onDisconnect = resolve;
                    queueMicrotask(() => process.emit(process.env.FIXTURE_SIGNAL));
                });
                throw new Error('Fixture consumer disconnected');
            }
            return { email: 'account@example.invalid' };
        }
    `);

    return {
        root,
        load: name => import(pathToFileURL(path.join(root, name)).href),
        run: (args, env = {}) => spawnSync(process.execPath, args, {
            cwd: root,
            env: { ...process.env, GMAIL_CREATOR_STATE_DIR: root, FIXTURE_TRACE: '1', ...env },
            encoding: 'utf8',
            timeout: 5000
        })
    };
}

test('managed stop discards debug addresses and retries unconfirmed shutdown by ID', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    for (const [service, addressField] of [['gpmlogin', 'remoteDebuggingAddress'], ['dolphin', 'webSocketUrl']]) {
        const { default: Profile } = await sandbox.load(`src/${service}/profile.js`);
        const id = service + '-existing';
        const initial = 'wss://controller.invalid/devtools/browser/supplied';
        const profile = new Profile(id, initial);
        assert.throws(() => { profile.profileId = 'other-fixture'; }, TypeError);
        assert.throws(() => new Profile({ id }, initial), /invalid browser controller profile ID/i);
        const oldBrowser = await profile.getBrowser();
        state.events.length = 0;
        state.stops.push(false, true);
        assert.equal(await profile.stop(), false);
        assert.equal(profile.profileId, id);
        assert.equal(profile[addressField], null);
        assert.equal(profile.browser, null);
        assert.equal(profile.page, null);
        assert.equal(await profile.stop(), true);

        const freshBrowser = await profile.getBrowser();
        assert.notEqual(freshBrowser, oldBrowser);
        assert.deepEqual(state.events.filter(([action]) => action === 'start' || action === 'stop'), [
            ['stop', id], ['stop', id], ['start', id]
        ]);
        const attaches = state.events.filter(([action]) => action === 'attach');
        assert.deepEqual(attaches, [['attach', `wss://controller.invalid/devtools/browser/${state.starts}`]]);
        assert.equal(await profile.stop(), true);
    }
});

test('managed stop waits for an in-flight start and coalesces shutdown requests', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    const { default: Profile } = await sandbox.load('src/gpmlogin/profile.js');
    const profile = new Profile('shared-fixture');
    let resolveStart;
    state.startGate = new Promise(resolve => { resolveStart = resolve; });
    const starting = profile.start();
    const stopping = profile.stop();
    assert.equal(stopping, profile.stop());
    await Promise.resolve();
    assert.deepEqual(state.events, [['start', 'shared-fixture']]);
    resolveStart();
    assert.equal(await starting, profile);
    assert.equal(await stopping, true);
    assert.deepEqual(state.events.map(([action]) => action), ['start', 'attach', 'disconnect', 'stop']);
    assert.equal(profile.browser, null);
    assert.equal(profile.remoteDebuggingAddress, null);
});

test('managed factories compensate only the newly allocated profile and report unknown cleanup', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    const failure = new Error('synthetic initialization failure');
    for (const service of ['gpmlogin', 'dolphin']) {
        const id = service + '-fixture';
        const { createAndStartProfile } = await sandbox.load(`src/${service}/profile.js`);
        for (const [phase, stopOK, deleteOK, profileCleanup] of [
            ['startError', true, true, 'deleted'],
            ['pageError', false, true, 'stop-unconfirmed'],
            ['pageError', true, false, 'delete-unconfirmed']
        ]) {
            state.events.length = 0;
            state[phase] = failure;
            state.stopOK = stopOK;
            state.deleteOK = deleteOK;
            await assert.rejects(createAndStartProfile('fixture'), error => {
                assert.equal(error.cause, failure);
                assert.equal(error.profileId, id);
                assert.equal(error.profileCleanup, profileCleanup);
                return true;
            });
            assert.deepEqual(state.events.filter(([action]) => ['start', 'stop', 'delete'].includes(action)), [
                ['start', id], ['stop', id], ...(stopOK ? [['delete', id]] : [])
            ]);
            assert.equal(state.events.some(([action]) => action === 'disconnect'), phase === 'pageError');
            delete state[phase];
        }
    }
});

test('embedded main rejects invalid arguments without exiting or changing host signal listeners', async t => {
    const sandbox = await fixture(t);
    const completed = sandbox.run(['--input-type=module', '-e', `
        import assert from 'node:assert/strict';
        import app from './src/index.js';
        const listeners = () => [process.listeners('SIGINT'), process.listeners('SIGTERM')];
        process.on('SIGINT', () => {});
        process.on('SIGTERM', () => {});
        const before = listeners();
        process.argv.push('host', '--accounts=-1');
        await assert.rejects(app.main(), /account/i);
        assert.deepEqual(listeners(), before);
        assert.equal(process.exitCode, undefined);
        console.log('host reached completion');
    `]);
    assert.equal(completed.status, 0, completed.stderr);
    assert.match(completed.stdout, /host reached completion/);
});

test('both CLI entry points stop the owned browser and leave queued tasks undispatched on a signal', async t => {
    for (const [entry, signal, status, phase] of [
        ['src/index.js', 'SIGINT', 130, 'active'],
        ['bin/gmail-account-creator.js', 'SIGTERM', 143, 'active'],
        ['bin/gmail-account-creator.js', 'SIGTERM', 143, 'starting']
    ]) {
        const sandbox = await fixture(t);
        const signalSource = phase === 'starting' ? 'FIXTURE_START_SIGNAL' : 'FIXTURE_SIGNAL';
        const completed = sandbox.run([entry, '--accounts=3', '--threads=1'], { [signalSource]: signal });
        assert.equal(completed.status, status, completed.stderr);
        const events = completed.stdout.trim().split('\n').map(line => JSON.parse(line));
        assert.deepEqual(events.filter(([action]) => ['start', 'consume', 'disconnect', 'stop'].includes(action)), [
            ['start', 'gpmlogin-fixture'],
            ...(phase === 'active' ? [['consume']] : []),
            ['disconnect'],
            ['stop', 'gpmlogin-fixture']
        ]);
        const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
        assert.equal(summary.stats.total, 3);
        assert.equal(summary.stats.failed, 1);
        assert.equal(summary.stats.skipped, 2);
        assert.equal(summary.results.length, 1);
        assert.equal(summary.results[0].profileCleanup, 'stopped');
        assert.equal(summary.results[0].profileId, 'gpmlogin-fixture');
    }
});

test('CLI reports unconfirmed shutdown while preserving an already saved account outcome', async t => {
    const sandbox = await fixture(t);
    const completed = sandbox.run(['bin/gmail-account-creator.js'], {
        FIXTURE_STOP_OK: 'false',
        FIXTURE_CHECK_SAVED: '1'
    });
    assert.equal(completed.status, 1, completed.stderr);
    assert.match(completed.stderr, /profile cleanup is unconfirmed/);
    const events = completed.stdout.trim().split('\n').map(line => JSON.parse(line));
    assert.deepEqual(events.find(([event]) => event === 'saved-at-stop'), ['saved-at-stop', true, 'pending']);
    assert.ok(events.some(([event, message, details]) =>
        event === 'warn' && message.includes('Profile shutdown unconfirmed') &&
        details.profileId === 'gpmlogin-fixture' && details.profileType === 'GPM Login'
    ));
    const [result] = JSON.parse(await readFile(path.join(sandbox.root, 'results.json')));
    assert.equal(result.success, true);
    assert.equal(result.profileId, 'gpmlogin-fixture');
    assert.equal(result.profileCleanup, 'stop-unconfirmed');
    const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
    assert.equal(summary.results.length, 1);
    assert.equal(summary.results[0].profileCleanup, 'stop-unconfirmed');
    assert.equal(summary.results[0].profileId, result.profileId);
    assert.equal(summary.results[0].profileType, 'GPM Login');
});

test('CLI persists an allocated profile ID when initialization and shutdown are unconfirmed', async t => {
    const sandbox = await fixture(t);
    const completed = sandbox.run(['bin/gmail-account-creator.js'], {
        FIXTURE_FAIL_PAGE: '1',
        FIXTURE_STOP_OK: 'false'
    });
    assert.equal(completed.status, 1, completed.stderr);
    assert.match(completed.stderr, /profile cleanup is unconfirmed/);
    const events = completed.stdout.trim().split('\n').map(line => JSON.parse(line));
    assert.deepEqual(events.filter(([event]) => ['stop', 'delete', 'consume'].includes(event)), [
        ['stop', 'gpmlogin-fixture']
    ]);
    const [result] = JSON.parse(await readFile(path.join(sandbox.root, 'results.json')));
    assert.equal(result.success, false);
    assert.equal(result.profileId, 'gpmlogin-fixture');
    assert.equal(result.profileCleanup, 'stop-unconfirmed');
    const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
    assert.equal(summary.results.length, 1);
    assert.equal(summary.results[0].profileCleanup, 'stop-unconfirmed');
    assert.equal(summary.results[0].profileId, result.profileId);
});
