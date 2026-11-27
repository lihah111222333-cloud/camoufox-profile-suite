import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

async function fixture(t, { productionLogger = false } = {}) {
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
    await put('package.json', '{"type":"module","version":"1.2.3"}');
    await put('src/fixture.cjs', `
        const fs = require('node:fs');
        const path = require('node:path');
        const state = {
            events: [],
            stops: [],
            starts: 0,
            targets: 0,
            allocations: 0,
            consumers: 0,
            stopOK: process.env.FIXTURE_STOP_OK !== 'false',
            deleteOK: true,
            recycleOK: true,
            pageError: process.env.FIXTURE_FAIL_PAGE ? new Error('Synthetic page failure') : null,
            breakOutput(file) {
                const output = path.join(process.env.GMAIL_CREATOR_STATE_DIR, file);
                if (fs.existsSync(output)) fs.renameSync(output, output + '.fixture');
                fs.mkdirSync(output);
            },
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
                        if (process.env.FIXTURE_ALLOCATION_UNCONFIRMED) {
                            throw Object.assign(new Error('Synthetic controller allocation status unknown'), {
                                code: 'PROFILE_ALLOCATION_UNCONFIRMED',
                                profileCleanup: 'allocation-unconfirmed'
                            });
                        }
                        const suffix = process.env.FIXTURE_OUTPUT_FAILURE?.startsWith('concurrent')
                            ? '-' + ++state.allocations : '';
                        return { id: service + '-fixture' + suffix };
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
                        if (process.env.FIXTURE_OUTPUT_FAILURE === 'cleanup') state.breakOutput('results.json');
                        if (process.env.FIXTURE_OUTPUT_FAILURE === 'cleanup-replacement') {
                            const output = path.join(process.env.GMAIL_CREATOR_STATE_DIR, 'results.json');
                            fs.writeFileSync(output + '.before-cleanup', fs.readFileSync(output), { mode: 0o600 });
                            const rename = fs.renameSync;
                            fs.renameSync = (from, to) => {
                                if (to === output) {
                                    throw Object.assign(new Error('Fixture replacement failure'), { code: 'EIO' });
                                }
                                rename(from, to);
                            };
                        }
                        if (process.env.FIXTURE_OUTPUT_FAILURE === 'summary') state.breakOutput('summary.json');
                        return state.stops.length ? state.stops.shift() : state.stopOK;
                    },
                    deleteProfile: async id => {
                        if (service === 'dolphin') {
                            throw new Error('Permanent Dolphin Anty profile deletion is unavailable');
                        }
                        state.trace('delete', id);
                        return state.deleteOK;
                    },
                    recycleProfile: async id => {
                        state.trace('recycle', id);
                        return state.recycleOK;
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
                state.onAttach?.();
                if (!state.holdHandshake) queueMicrotask(() => this.emit('open'));
            }
            close() { this.emit('close'); }
            terminate() {
                state.trace('terminate');
                this.close();
            }
        };
    `);
    await put('node_modules/puppeteer-core/fixture.cjs', `
        const state = require('../../src/fixture.cjs');
        module.exports = {
            async connect({ transport }) {
                let attached = true;
                transport.onclose = () => { attached = false; };
                return {
                    isConnected: () => attached,
                    pages: async () => state.existingPages ?? [],
                    async newPage() {
                        if (process.env.FIXTURE_OUTPUT_FAILURE === 'initialization') state.breakOutput('results.json');
                        if (state.pageError) throw state.pageError;
                        let closed = false;
                        const targetId = (++state.targets).toString(16).padStart(32, '0');
                        const page = {
                            evaluateOnNewDocument: async () => {},
                            url: () => 'about:blank',
                            target: () => ({ _targetId: targetId }),
                            evaluate: async () => null,
                            isClosed: () => closed,
                            async close() {
                                if (!attached) throw new Error('Fixture transport disconnected before page closure');
                                closed = true;
                                state.trace('close-page');
                            }
                        };
                        state.onNewPage?.(page);
                        return page;
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
        import state from './fixture.cjs';
        state.trace('load-config');
        globalThis.setTimeout = callback => queueMicrotask(callback);
        export default { profileService: process.env.FIXTURE_PROFILE_SERVICE || 'gpm' };
    `);
    if (!productionLogger) {
        await put('src/utils/logger.js', `
            import state from '../fixture.cjs';
            export default {
                debug() {}, info() {}, error() {},
                warn(message, details) {
                    if (process.env.LOG_LEVEL !== 'ERROR') state.trace('warn', message, details);
                }
            };
        `);
    }
    await put('src/utils/name-generator.js', `
        export default { generateAccountData: () => ({ username: 'fixture' }) };
    `);
    await put('src/utils/proxy-manager.js', `
        const proxy = { ip: 'proxy.invalid', port: 8443 };
        export default {
            proxies: [proxy],
            getNextProxy: () => proxy,
            getAvailableCount: () => 1,
            getCamoufoxFormat: () => ({ server: 'http://proxy.invalid:8443' })
        };
    `);
    await put('src/camoufox/profile.js', `
        import state from '../fixture.cjs';
        export async function createAndStartProfile(_name, _proxy, options) {
            process.emit('SIGTERM');
            state.trace('camoufox-start', {
                aborted: options.signal?.aborted === true,
                hasAccountEmail: Object.hasOwn(options, 'accountEmail'),
                hasGpuToggle: Object.hasOwn(options, 'enableGpuPerformanceScaling')
            });
            throw Object.assign(new Error('Synthetic Camoufox startup cancelled'), {
                profileId: 'camoufox-fixture', profileCleanup: 'deleted'
            });
        }
    `);
    await put('src/gmail/creator.js', `
        import state from '../fixture.cjs';
        export async function createGmailAccount(_page, _accountData, { profile, signal } = {}) {
            state.trace('consume');
            if (process.env.FIXTURE_OUTPUT_FAILURE === 'result') state.breakOutput('results.json');
            if (process.env.FIXTURE_OUTPUT_FAILURE === 'concurrent') {
                if (++state.consumers === 1) {
                    await new Promise(resolve => { state.releaseFirstConsumer = resolve; });
                } else {
                    state.breakOutput('results.json');
                    state.releaseFirstConsumer();
                }
            }
            if (process.env.FIXTURE_OUTPUT_FAILURE === 'concurrent-persisted' && profile.profileId.endsWith('-2')) {
                state.breakOutput('results.json');
            }
            if (process.env.FIXTURE_SIGNAL) {
                await new Promise(resolve => {
                    state.onDisconnect = resolve;
                    queueMicrotask(() => process.emit(process.env.FIXTURE_SIGNAL));
                });
                state.trace('signal-forwarded', signal?.aborted === true);
                throw new Error('Fixture consumer disconnected');
            }
            if (process.env.FIXTURE_CONSUMER_OUTCOME === 'manual') {
                throw Object.assign(new Error('Manual signup is required'), {
                    code: 'MANUAL_SIGNUP_REQUIRED', stage: 'password'
                });
            }
            return { email: 'account@example.invalid' };
        }
    `);

    return {
        root,
        load: name => import(pathToFileURL(path.join(root, name)).href),
        run: (args, env = {}) => spawnSync(process.execPath, args, {
            cwd: root,
            env: {
                PATH: process.env.PATH,
                SystemRoot: process.env.SystemRoot,
                GMAIL_CREATOR_STATE_DIR: root,
                GMAIL_CREATOR_LEGACY_DIR: path.join(root, 'missing-legacy'),
                FIXTURE_TRACE: '1',
                ...env
            },
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
        const profile = new Profile(id);
        assert.throws(() => { profile.profileId = 'other-fixture'; }, TypeError);
        assert.throws(() => new Profile({ id }, initial), /invalid browser controller profile ID/i);
        profile[addressField] = initial;
        const oldBrowser = await profile.getBrowser();
        assert.notEqual(profile[addressField], initial);
        state.events.length = 0;
        state.stops.push(false, true);
        assert.equal(await profile.stop(), false);
        assert.equal(profile.profileId, id);
        assert.equal(profile[addressField], null);
        assert.equal(profile.browser, null);
        assert.equal(profile.page, null);
        const unresolved = { profileId: id, profileCleanup: 'stop-unconfirmed' };
        await assert.rejects(profile.start(), unresolved);
        await assert.rejects(profile.getBrowser(), unresolved);
        assert.deepEqual(state.events.filter(([, profileId]) => profileId === id), [['stop', id]]);
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

test('borrowed sessions close only manager-created pages before each disconnect', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    let closedExisting = false;
    const existing = {
        isClosed: () => closedExisting,
        async close() { closedExisting = true; }
    };
    state.existingPages = [existing];
    for (const [service, addressField] of [['gpmlogin', 'remoteDebuggingAddress'], ['dolphin', 'webSocketUrl']]) {
        const { default: Profile } = await sandbox.load(`src/${service}/profile.js`);
        const address = 'wss://borrowed-controller.invalid/devtools/browser/supplied';
        const profile = new Profile(service + '-existing', address);
        state.events.length = 0;

        await profile.start();
        if (service === 'dolphin') {
            await assert.rejects(profile.recycle(), /requires a bound REST controller/);
            await assert.rejects(profile.delete(), /Permanent Dolphin Anty profile deletion is unavailable/);
        } else {
            await assert.rejects(profile.delete(), /requires a bound REST controller/);
        }
        const owned = profile.page;
        profile.page = null;
        assert.equal(await profile.getPage(), existing);
        assert.equal(await profile.stop(), false);
        assert.equal(owned.isClosed(), true);
        assert.equal(existing.isClosed(), false);
        assert.equal(profile[addressField], null);
        assert.equal(profile.browser, null);
        await profile.start();
        const reattachedPage = profile.page;
        assert.equal(await profile.stop(), false);
        assert.equal(reattachedPage.isClosed(), true);
        assert.equal(existing.isClosed(), false);
        assert.deepEqual(state.events, [
            ['attach', address], ['close-page'], ['disconnect'],
            ['attach', address], ['close-page'], ['disconnect']
        ]);
    }
});

test('borrowed sessions retain the connection until a failed owned page close can be retried', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    state.existingPages = [{
        isClosed: () => false,
        async close() { assert.fail('An existing page must stay open'); }
    }];
    for (const service of ['gpmlogin', 'dolphin']) {
        const { default: Profile } = await sandbox.load(`src/${service}/profile.js`);
        const address = 'wss://borrowed-controller.invalid/devtools/browser/supplied';
        const profile = await new Profile(service + '-existing', address).start();
        const owned = profile.page;
        const close = owned.close.bind(owned);
        let attempts = 0;
        owned.close = async () => {
            if (++attempts === 1) throw new Error('Fixture page is temporarily busy');
            await close();
        };
        state.events.length = 0;

        assert.equal(await profile.stop(), false);
        assert.equal(owned.isClosed(), false);
        assert.deepEqual(state.events.map(([event]) => event), ['warn']);
        await assert.rejects(profile.start(), /Borrowed browser cleanup is incomplete/);

        assert.equal(await profile.stop(), false);
        assert.equal(attempts, 2);
        assert.equal(owned.isClosed(), true);
        assert.deepEqual(state.events.map(([event]) => event), ['warn', 'close-page', 'disconnect']);
    }
});

test('borrowed sessions reject a closed cached page without opening or adopting another tab', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    let existingCloses = 0;
    let createdPages = 0;
    state.existingPages = [{
        isClosed: () => false,
        async close() { existingCloses++; }
    }];
    state.onNewPage = () => { createdPages++; };
    for (const service of ['gpmlogin', 'dolphin']) {
        const { default: Profile } = await sandbox.load(`src/${service}/profile.js`);
        const profile = await new Profile(service + '-existing', 'wss://borrowed-controller.invalid/devtools/browser/supplied').start();
        const owned = await profile.getPage();
        const initialPageCount = createdPages;
        assert.equal(owned.isClosed(), false);
        await owned.close();

        await assert.rejects(profile.getPage(), /Managed page is unavailable because it has been closed/);
        assert.equal(createdPages, initialPageCount);
        assert.equal(await profile.stop(), false);
        assert.equal(existingCloses, 0);
    }
});

test('borrowed sessions reject an already disconnected browser without reconnecting', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    let existingCloses = 0;
    state.existingPages = [{
        isClosed: () => false,
        async close() { existingCloses++; }
    }];
    for (const service of ['gpmlogin', 'dolphin']) {
        const { default: Profile } = await sandbox.load(`src/${service}/profile.js`);
        const address = 'wss://borrowed-controller.invalid/devtools/browser/supplied?key=fixture-private';
        const profile = new Profile(service + '-existing', address);

        const browser = await profile.getBrowser();
        assert.equal(browser.isConnected(), true);
        assert.equal(await profile.getBrowser(), browser);
        const ownedPage = profile.page;
        const closedPage = await profile.createOwnedPage();
        await closedPage.close();
        let closeAttempts = 0;
        const close = ownedPage.close.bind(ownedPage);
        ownedPage.close = async () => {
            closeAttempts++;
            await close();
        };
        state.events.length = 0;
        await browser.disconnect();
        assert.equal(browser.isConnected(), false);

        const expected = { message: 'Borrowed browser connection is unavailable' };
        await assert.rejects(profile.getBrowser(), expected);
        await assert.rejects(profile.getPage(), expected);
        const unresolved = {
            profileId: profile.profileId,
            profileCleanup: 'stop-unconfirmed',
            targetIds: [ownedPage.target()._targetId],
            unresolvedPageCount: 1
        };
        await assert.rejects(profile.stop(), error => {
            assert.deepEqual({ ...error }, unresolved);
            assert.ok(!error.message.includes('fixture-private'));
            return true;
        });
        await assert.rejects(profile.stop(), unresolved);
        await assert.rejects(profile.start(), unresolved);
        assert.equal(ownedPage.isClosed(), false);
        assert.equal(closeAttempts, 0);
        assert.deepEqual(state.events, [['disconnect']]);
        assert.equal(existingCloses, 0);
    }
});

test('cancelling after page creation closes the owned borrowed page while still attached', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    for (const service of ['gpmlogin', 'dolphin']) {
        const { default: Profile } = await sandbox.load(`src/${service}/profile.js`);
        const address = 'wss://borrowed-controller.invalid/devtools/browser/supplied';
        const profile = new Profile(service + '-existing', address);
        const cancellation = new AbortController();
        const reason = new Error('fixture cancelled after creating the page');
        let allocated;
        state.events.length = 0;
        state.onNewPage = page => {
            allocated = page;
            cancellation.abort(reason);
        };

        await assert.rejects(profile.start({ signal: cancellation.signal }), error => error === reason);
        assert.equal(allocated.isClosed(), true);
        assert.deepEqual(state.events, [['attach', address], ['close-page'], ['disconnect']]);
        assert.equal(profile.page, null);
    }
});

test('queued startup needs a confirmed controller stop for owned profiles', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    for (const service of ['gpmlogin', 'dolphin']) {
        const { default: Profile } = await sandbox.load(`src/${service}/profile.js`);
        const id = service + '-queued';
        const profile = await new Profile(id).start();
        state.events.length = 0;
        state.stops.push(false, true);
        const unconfirmed = profile.stop();
        await assert.rejects(profile.start(), { profileId: id, profileCleanup: 'stop-unconfirmed' });
        assert.equal(await unconfirmed, false);
        assert.deepEqual(state.events.filter(([, profileId]) => profileId === id), [['stop', id]]);

        const confirmed = profile.stop();
        const restarted = profile.start();
        assert.equal(await confirmed, true);
        assert.equal(await restarted, profile);
        assert.deepEqual(state.events.filter(([, profileId]) => profileId === id), [
            ['stop', id], ['stop', id], ['start', id]
        ]);

        const borrowedId = service + '-borrowed-queued';
        const borrowed = await new Profile(borrowedId, 'wss://borrowed-controller.invalid/devtools/browser/fixture').start();
        const detached = borrowed.stop();
        const attached = borrowed.start();
        assert.equal(await detached, false);
        assert.equal(await attached, borrowed);
        assert.deepEqual(state.events.filter(([, profileId]) => profileId === borrowedId), []);
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
    const cancelled = assert.rejects(starting, /startup cancelled by stop/);
    await Promise.resolve();
    assert.deepEqual(state.events, [['start', 'shared-fixture']]);
    resolveStart();
    await cancelled;
    assert.equal(await stopping, true);
    assert.deepEqual(state.events, [['start', 'shared-fixture'], ['stop', 'shared-fixture']]);
    assert.equal(profile.browser, null);
    assert.equal(profile.remoteDebuggingAddress, null);
});

test('GPM preserves uncertain and confirmed deletion states before any restart', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    const { default: Profile } = await sandbox.load('src/gpmlogin/profile.js');
    const id = 'gpmlogin-retry';
    const profile = await new Profile(id).start();
    state.events.length = 0;
    state.deleteOK = false;
    await assert.rejects(profile.delete(), { profileCleanup: 'delete-unconfirmed' });
    state.deleteOK = true;
    const unresolved = { profileId: id, profileCleanup: 'delete-unconfirmed' };
    await assert.rejects(profile.start(), unresolved);
    await assert.rejects(profile.delete(), unresolved);
    assert.deepEqual(state.events.filter(([, profileId]) => profileId === id), [
        ['stop', id], ['delete', id]
    ]);

    const confirmed = await new Profile('gpmlogin-confirmed').start();
    assert.equal(await confirmed.delete(), true);
    assert.equal(await confirmed.delete(), true);
    assert.equal(await confirmed.stop(), true);
    await assert.rejects(confirmed.start(), /has been deleted/);
    assert.deepEqual(state.events.filter(([, id]) => id === confirmed.profileId), [
        ['start', confirmed.profileId], ['stop', confirmed.profileId], ['delete', confirmed.profileId]
    ]);

    const restarted = await new Profile('gpmlogin-restart').start();
    assert.equal(await restarted.stop(), true);
    await restarted.start();
    state.stops.push(false, true);
    await assert.rejects(restarted.delete(), { profileCleanup: 'stop-unconfirmed' });
    assert.equal(await restarted.delete(), true);
    assert.deepEqual(state.events.filter(([, id]) => id === restarted.profileId), [
        ['start', restarted.profileId], ['stop', restarted.profileId], ['start', restarted.profileId],
        ['stop', restarted.profileId], ['stop', restarted.profileId], ['delete', restarted.profileId]
    ]);
});

test('Dolphin recycling requires confirmed closure and only dispatches once per manager', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    const { default: Profile } = await sandbox.load('src/dolphin/profile.js');
    const id = 'dolphin-recycle';
    const profile = await new Profile(id).start();
    state.events.length = 0;
    state.stops.push(false, true);
    await assert.rejects(profile.recycle(), { profileId: id, profileCleanup: 'stop-unconfirmed' });
    state.recycleOK = false;
    const recycling = profile.recycle();
    assert.equal(profile.recycle(), recycling);
    await assert.rejects(recycling, { profileId: id, profileCleanup: 'recycle-unconfirmed' });
    assert.equal(profile.recycle(), recycling);
    await assert.rejects(profile.start(), /recycling has been requested/);
    await assert.rejects(profile.delete(), /Permanent Dolphin Anty profile deletion is unavailable/);
    assert.deepEqual(state.events.filter(([, affected]) => affected === id), [
        ['stop', id], ['stop', id], ['recycle', id]
    ]);

    state.recycleOK = true;
    const stopped = await new Profile('dolphin-stopped').start();
    assert.equal(await stopped.stop(), true);
    await assert.rejects(stopped.recycle(), { profileCleanup: 'stop-unconfirmed' });
    assert.deepEqual(state.events.filter(([, affected]) => affected === stopped.profileId), [
        ['start', stopped.profileId], ['stop', stopped.profileId]
    ]);
    await stopped.start();
    assert.equal(await stopped.recycle(), true);
    assert.equal(await stopped.recycle(), true);
    assert.deepEqual(state.events.filter(([, affected]) => affected === stopped.profileId), [
        ['start', stopped.profileId], ['stop', stopped.profileId],
        ['start', stopped.profileId], ['stop', stopped.profileId], ['recycle', stopped.profileId]
    ]);
});

test('managed startup cancellation terminates a pending handshake and cleans an allocated ID', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    state.holdHandshake = true;
    for (const service of ['gpmlogin', 'dolphin']) {
        const { default: Profile, createAndStartProfile } = await sandbox.load(`src/${service}/profile.js`);
        const cleanupAction = service === 'dolphin' ? 'recycle' : 'delete';
        const profileCleanup = service === 'dolphin' ? 'recycled' : 'deleted';
        const signal = new AbortController();
        const reason = new Error('fixture cancelled');
        state.events.length = 0;
        const attachedFactory = new Promise(resolve => { state.onAttach = resolve; });
        const creating = createAndStartProfile('fixture', null, { signal: signal.signal });
        const rejected = assert.rejects(creating, {
            cause: reason, profileId: service + '-fixture', profileCleanup
        });
        await attachedFactory;
        signal.abort(reason);
        await rejected;
        assert.deepEqual(state.events.map(([action]) => action).filter(action => action !== 'warn'),
            ['allocate', 'start', 'attach', 'terminate', 'stop', cleanupAction]);

        state.events.length = 0;
        const existing = new Profile(service + '-existing');
        const attachedExisting = new Promise(resolve => { state.onAttach = resolve; });
        const starting = assert.rejects(existing.start(), /startup cancelled by stop/);
        await attachedExisting;
        assert.equal(await existing.stop(), true);
        await starting;
        assert.deepEqual(state.events.map(([action]) => action), ['start', 'attach', 'terminate', 'stop']);
    }
});

test('cancelling a directly started managed profile reports its unresolved controller shutdown', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    state.holdHandshake = true;
    for (const service of ['gpmlogin', 'dolphin']) {
        const { default: Profile } = await sandbox.load(`src/${service}/profile.js`);
        const profileId = service + '-direct';
        const profile = new Profile(profileId);
        const reason = new Error('fixture cancelled the direct start');
        state.events.length = 0;
        await assert.rejects(profile.start({ signal: AbortSignal.abort(reason) }), error => error === reason);
        assert.deepEqual(state.events, []);

        const cancellation = new AbortController();
        const attaching = new Promise(resolve => { state.onAttach = resolve; });
        const unresolved = { profileId, profileCleanup: 'stop-unconfirmed' };
        const stoppingRequired = assert.rejects(profile.start({ signal: cancellation.signal }), {
            ...unresolved, cause: reason
        });
        await attaching;
        cancellation.abort(reason);
        await stoppingRequired;
        assert.equal(profile.browser, null);
        await assert.rejects(profile.getBrowser(), unresolved);
        assert.equal(await profile.stop(), true);
        assert.deepEqual(state.events.map(([action]) => action), ['start', 'attach', 'terminate', 'stop']);
    }
});

test('managed factories compensate only the newly allocated profile and report unknown cleanup', async t => {
    const sandbox = await fixture(t);
    const { default: state } = await sandbox.load('src/fixture.cjs');
    t.mock.method(globalThis, 'setTimeout', callback => queueMicrotask(callback));
    const failure = new Error('synthetic initialization failure');
    for (const service of ['gpmlogin', 'dolphin']) {
        const id = service + '-fixture';
        const cleanupAction = service === 'dolphin' ? 'recycle' : 'delete';
        const { createAndStartProfile } = await sandbox.load(`src/${service}/profile.js`);
        for (const [phase, stopOK, cleanupOK, profileCleanup] of [
            ['startError', true, true, service === 'dolphin' ? 'recycled' : 'deleted'],
            ['pageError', false, true, 'stop-unconfirmed'],
            ['pageError', true, false, cleanupAction + '-unconfirmed']
        ]) {
            state.events.length = 0;
            state[phase] = failure;
            state.stopOK = stopOK;
            state.deleteOK = cleanupOK;
            state.recycleOK = cleanupOK;
            await assert.rejects(createAndStartProfile('fixture'), error => {
                assert.equal(error.cause, failure);
                assert.equal(error.profileId, id);
                assert.equal(error.profileCleanup, profileCleanup);
                return true;
            });
            assert.deepEqual(state.events.filter(([action]) => ['start', 'stop', cleanupAction].includes(action)), [
                ['start', id], ['stop', id], ...(stopOK ? [[cleanupAction, id]] : [])
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

test('Both executable entry points handle help, version, and unknown arguments before state initialization', async t => {
    const sandbox = await fixture(t);
    const before = (await readdir(sandbox.root)).sort();
    for (const entry of ['src/index.js', 'bin/gmail-account-creator.js']) {
        for (const [args, status, pattern] of [
            [['--help'], 0, /Usage:/],
            [['-h'], 0, /Usage:/],
            [['--version'], 0, /^1\.2\.3\s*$/],
            [['-v'], 0, /^1\.2\.3\s*$/],
            [['--unexpected=fixture-private-value'], 1, /Unknown command-line argument/],
            [['positional'], 1, /Unknown command-line argument/],
            [['--help', '--unknown'], 1, /Unknown command-line argument/]
        ]) {
            for (const state of [sandbox.root, 'invalid-relative-state']) {
                const completed = sandbox.run([entry, ...args], { GMAIL_CREATOR_STATE_DIR: state });
                assert.equal(completed.status, status, completed.stderr);
                assert.match(status === 0 ? completed.stdout : completed.stderr, pattern);
                assert.doesNotMatch(completed.stdout, /load-config|allocate/);
                assert.doesNotMatch(completed.stderr, /fixture-private-value/);
                assert.deepEqual((await readdir(sandbox.root)).sort(), before);
            }
        }
    }
});

test('symbolic links to the source CLI preserve version output and invalid-count status', {
    skip: process.platform === 'win32'
}, async t => {
    const sandbox = await fixture(t);
    await symlink('src/index.js', path.join(sandbox.root, 'cli-link.js'), 'file');
    await symlink('.', path.join(sandbox.root, 'checkout-link'), 'dir');

    for (const entry of ['cli-link.js', 'checkout-link/src/index.js']) {
        const version = sandbox.run([entry, '--version']);
        assert.equal(version.status, 0, version.stderr);
        assert.equal(version.stdout.trim(), '1.2.3');
        const invalid = sandbox.run([entry, '--accounts=0']);
        assert.equal(invalid.status, 1, invalid.stderr);
        assert.match(invalid.stderr, /--accounts must be an integer/);
        assert.equal(invalid.stdout, '');
    }
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
        assert.deepEqual(events.filter(([action]) => ['start', 'consume', 'disconnect', 'stop', 'delete'].includes(action)), [
            ['start', 'gpmlogin-fixture'],
            ...(phase === 'active' ? [['consume'], ['disconnect']] : []),
            ['stop', 'gpmlogin-fixture'],
            ...(phase === 'starting' ? [['delete', 'gpmlogin-fixture']] : [])
        ]);
        if (phase === 'active') assert.deepEqual(events.find(([action]) => action === 'signal-forwarded'), ['signal-forwarded', true]);
        const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
        assert.equal(summary.stats.total, 3);
        assert.equal(summary.stats.failed, 1);
        assert.equal(summary.stats.skipped, 2);
        assert.equal(summary.results.length, 1);
        assert.equal(summary.results[0].profileCleanup, phase === 'starting' ? 'deleted' : 'stopped');
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
    assert.match(completed.stderr, /results\.json/);
    assert.ok(completed.stderr.includes('resultId ' + result.resultId + ' (stop-unconfirmed)'));
    const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
    assert.equal(summary.results.length, 1);
    assert.equal(summary.results[0].profileCleanup, 'stop-unconfirmed');
    assert.equal(summary.results[0].profileId, result.profileId);
    assert.equal(summary.results[0].profileType, 'GPM Login');
});

test('CLI warns about existing pending results with stable locations before replacing the summary', async t => {
    const sandbox = await fixture(t);
    const filename = path.join(sandbox.root, 'results.json');
    const pending = {
        success: true, resultId: '068fd614-aceb-46c0-90b9-8b329991e448',
        profileId: 'older-private-profile', profileCleanup: 'pending'
    };
    const legacy = { success: false, profileId: 'legacy-private-profile', profileCleanup: 'stop-unconfirmed' };
    await writeFile(filename, JSON.stringify([pending, legacy]));
    await writeFile(path.join(sandbox.root, 'summary.json'), JSON.stringify({ results: [pending, legacy] }));

    const completed = sandbox.run(['bin/gmail-account-creator.js'], { LOG_LEVEL: 'ERROR' });
    assert.equal(completed.status, 0, completed.stderr);
    assert.match(completed.stderr, /results\.json/);
    assert.ok(completed.stderr.includes('entry 1 (resultId ' + pending.resultId + ') (pending)'));
    assert.match(completed.stderr, /entry 2 \(stop-unconfirmed\)/);
    assert.doesNotMatch(completed.stderr, /older-private-profile|legacy-private-profile/);
    const [kept, keptLegacy, current] = JSON.parse(await readFile(filename));
    assert.deepEqual(kept, pending);
    assert.equal(keptLegacy.profileCleanup, 'stop-unconfirmed');
    assert.equal(current.profileCleanup, 'stopped');
    const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
    assert.equal(summary.results.length, 1);
    assert.equal(summary.results[0].profileCleanup, 'stopped');
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

test('CLI retains the profile ID when result writing and cleanup both fail', async t => {
    for (const phase of ['result', 'initialization', 'cleanup']) {
        const sandbox = await fixture(t);
        const completed = sandbox.run(['bin/gmail-account-creator.js'], {
            LOG_LEVEL: 'ERROR',
            FIXTURE_STOP_OK: 'false',
            FIXTURE_OUTPUT_FAILURE: phase,
            ...(phase === 'initialization' ? { FIXTURE_FAIL_PAGE: '1' } : {})
        });
        assert.equal(completed.status, 1, completed.stderr);
        assert.match(completed.stderr, /could not be saved|Could not save/);
        assert.match(completed.stderr, /profile cleanup is unconfirmed/i);
        assert.match(completed.stderr, /gpmlogin-fixture.*stop-unconfirmed/);
        assert.doesNotMatch(completed.stderr, /controller\.invalid|account@example\.invalid|proxy\.invalid/);
    }
});

test('CLI identifies the saved result when cleanup is unconfirmed and summary writing fails', async t => {
    const sandbox = await fixture(t);
    const completed = sandbox.run(['bin/gmail-account-creator.js'], {
        LOG_LEVEL: 'ERROR',
        FIXTURE_STOP_OK: 'false',
        FIXTURE_OUTPUT_FAILURE: 'summary'
    });
    assert.equal(completed.status, 1, completed.stderr);
    const [result] = JSON.parse(await readFile(path.join(sandbox.root, 'results.json')));
    assert.equal(result.profileCleanup, 'stop-unconfirmed');
    assert.equal(typeof result.resultId, 'string');
    assert.match(completed.stderr, /Run summary could not be saved safely in summary\.json/);
    assert.match(completed.stderr, /profile cleanup is unconfirmed.*results\.json/i);
    assert.ok(completed.stderr.includes('resultId ' + result.resultId + ' (stop-unconfirmed)'));
    assert.ok(!completed.stderr.includes(result.profileId), completed.stderr);
});

test('CLI locates the unchanged result when a cleanup update cannot replace it', async t => {
    for (const stopOK of [true, false]) {
        await t.test(stopOK ? 'confirmed stop' : 'unconfirmed stop', async t => {
            const sandbox = await fixture(t);
            const completed = sandbox.run(['bin/gmail-account-creator.js'], {
                LOG_LEVEL: 'ERROR',
                FIXTURE_CONSUMER_OUTCOME: 'manual',
                FIXTURE_STOP_OK: String(stopOK),
                FIXTURE_OUTPUT_FAILURE: 'cleanup-replacement'
            });
            assert.equal(completed.status, 1);
            const filename = path.join(sandbox.root, 'results.json');
            const bytes = await readFile(filename);
            assert.deepEqual(bytes, await readFile(filename + '.before-cleanup'));
            const [saved] = JSON.parse(bytes);
            assert.equal(saved.profileCleanup, 'pending');
            const diagnostic = completed.stderr;
            assert.equal(diagnostic.includes('Could not save profile cleanup in results.json.'), true);
            assert.equal(diagnostic.includes('resultId ' + saved.resultId), true);
            assert.equal(diagnostic.includes('recorded cleanup pending'), true);
            assert.equal(diagnostic.includes('observed cleanup ' + (stopOK ? 'stopped' : 'stop-unconfirmed')), true);
            assert.equal(diagnostic.includes(saved.profileId), false);
            assert.equal((await readdir(sandbox.root)).includes('results.json.lock'), false);
        });
    }
});

test('CLI retains every unconfirmed profile when one task prevents the run summary from being written', async t => {
    for (const phase of ['concurrent', 'concurrent-persisted']) {
        const sandbox = await fixture(t);
        const completed = sandbox.run([
            'bin/gmail-account-creator.js', '--accounts=2', phase === 'concurrent' ? '--threads=2' : '--threads=1'
        ], {
            LOG_LEVEL: 'ERROR',
            FIXTURE_STOP_OK: 'false',
            FIXTURE_OUTPUT_FAILURE: phase
        });
        assert.equal(completed.status, 1, completed.stderr);
        for (const id of [1, 2]) {
            assert.ok(completed.stderr.includes(`gpmlogin-fixture-${id} (stop-unconfirmed)`), completed.stderr);
        }
        assert.doesNotMatch(completed.stderr, /controller\.invalid|account@example\.invalid|proxy\.invalid/);
    }
});

test('CLI counts manual handoffs separately and gives continuation guidance only after confirmed shutdown', async t => {
    const guidance = 'Continue signup manually in a trusted browser you control.';
    for (const stopOK of [true, false]) {
        const sandbox = await fixture(t, { productionLogger: true });
        const completed = sandbox.run(['bin/gmail-account-creator.js'], {
            FIXTURE_CONSUMER_OUTCOME: 'manual',
            FIXTURE_STOP_OK: String(stopOK),
            LOG_LEVEL: 'ERROR'
        });
        assert.equal(completed.status, stopOK ? 0 : 1, completed.stderr);
        const lines = completed.stdout.trim().split('\n');
        const stopIndex = lines.findIndex(line => line.startsWith('["stop",'));
        const handoffIndex = lines.indexOf(guidance);
        assert.ok(stopIndex >= 0);
        if (stopOK) {
            assert.ok(handoffIndex > stopIndex);
        } else {
            assert.equal(handoffIndex, -1);
            assert.match(completed.stderr, /profile cleanup is unconfirmed.*before continuing/i);
        }
        const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
        assert.deepEqual(summary.stats, {
            total: 1, completed: 0, failed: 0, manual: 1, successRate: '0.00%'
        });
        assert.equal(summary.results[0].success, false);
        assert.equal(summary.results[0].errorCode, 'MANUAL_SIGNUP_REQUIRED');
        assert.equal(summary.results[0].errorStage, 'password');
        assert.equal(summary.results[0].profileCleanup, stopOK ? 'stopped' : 'stop-unconfirmed');
    }
});

test('programmatic manual handoff reports the persisted cleanup outcome', async t => {
    for (const stopOK of [true, false]) {
        const sandbox = await fixture(t);
        const expected = stopOK ? 'stopped' : 'stop-unconfirmed';
        const completed = sandbox.run(['--input-type=module', '-e', `
            import assert from 'node:assert/strict';
            import app from './src/index.js';
            await assert.rejects(app.createAccount(), {
                code: 'MANUAL_SIGNUP_REQUIRED',
                stage: 'password',
                profileCleanup: ${JSON.stringify(expected)}
            });
        `], { FIXTURE_CONSUMER_OUTCOME: 'manual', FIXTURE_STOP_OK: String(stopOK) });
        assert.equal(completed.status, 0, completed.stderr);
        const [result] = JSON.parse(await readFile(path.join(sandbox.root, 'results.json')));
        assert.equal(result.profileCleanup, expected);
        assert.equal(result.success, false);
    }
});

test('embedded main records failed attempts without changing the host exit status', async t => {
    const sandbox = await fixture(t);
    const completed = sandbox.run(['--input-type=module', '-e', `
        import assert from 'node:assert/strict';
        import app from './src/index.js';
        await app.main();
        assert.equal(process.exitCode, undefined);
    `], { FIXTURE_FAIL_PAGE: '1' });
    assert.equal(completed.status, 0, completed.stderr);
    const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
    assert.equal(summary.stats.failed, 1);
    assert.equal(summary.results[0].profileCleanup, 'deleted');
});

test('CLI reports an unconfirmed allocation with the provider type when the ID is unknown', async t => {
    const sandbox = await fixture(t);
    const completed = sandbox.run(['bin/gmail-account-creator.js'], {
        FIXTURE_ALLOCATION_UNCONFIRMED: '1'
    });
    assert.equal(completed.status, 1, completed.stderr);
    assert.match(completed.stderr, /profile cleanup is unconfirmed/i);
    const events = completed.stdout.trim().split('\n').map(line => JSON.parse(line));
    assert.equal(events.filter(([event]) => ['start', 'stop', 'delete'].includes(event)).length, 0);
    const records = JSON.parse(await readFile(path.join(sandbox.root, 'results.json')));
    const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
    for (const [result] of [records, summary.results]) {
        assert.equal(result.success, false);
        assert.equal(result.errorCode, 'PROFILE_ALLOCATION_UNCONFIRMED');
        assert.equal(result.profileId ?? null, null);
        assert.equal(result.profileType, 'GPM Login');
        assert.equal(result.profileCleanup, 'allocation-unconfirmed');
    }
});

test('CLI passes cancellation to Camoufox initialization without identity or GPU settings', async t => {
    const sandbox = await fixture(t);
    const completed = sandbox.run(['bin/gmail-account-creator.js', '--accounts=2'], {
        FIXTURE_PROFILE_SERVICE: 'camoufox'
    });
    assert.equal(completed.status, 143, completed.stderr);
    const events = completed.stdout.trim().split('\n').map(line => JSON.parse(line));
    assert.deepEqual(events.filter(([event]) => event === 'camoufox-start'), [[
        'camoufox-start', { aborted: true, hasAccountEmail: false, hasGpuToggle: false }
    ]]);
    assert.ok(!events.some(([event]) => event === 'consume'));
    const summary = JSON.parse(await readFile(path.join(sandbox.root, 'summary.json')));
    assert.equal(summary.stats.failed, 1);
    assert.equal(summary.stats.skipped, 1);
    assert.equal(summary.results[0].profileType, 'Camoufox');
    assert.equal(summary.results[0].profileCleanup, 'deleted');
});

test('routine logs redact identity and startup details in console and file output', async t => {
    const sandbox = await fixture(t, { productionLogger: true });
    const completed = sandbox.run(['--input-type=module', '-e', `
        import logger from './src/utils/logger.js';
        logger.info('Profile started', {
            profileType: 'GPM Login',
            profileId: 'fixture-controller-id',
            title: 'fixture-account-title',
            status: 'fixture-ready',
            attempt: 2,
            metadata: {
                fullName: 'Fixture Account Name',
                email: 'fixture-account@example.invalid',
                phone: 'Fixture Contact Phone',
                'phone-number': 'Fixture Alternate Phone',
                recoveryEmail: 'fixture-recovery@example.invalid',
                'date_of_birth': 'Fixture Birth Date',
                profileDir: '/fixture/private/profile',
                source: 'file:///fixture/private/source',
                gpuPerformance: { hostChipModel: 'Fixture Physical GPU' },
                cpuModel: 'Fixture Physical CPU'
            }
        });
    `]);
    assert.equal(completed.status, 0, completed.stderr);
    const logs = path.join(sandbox.root, 'logs');
    const [logFile] = await readdir(logs);
    for (const output of [completed.stdout, await readFile(path.join(logs, logFile), 'utf8')]) {
        assert.match(output, /Profile started.*GPM Login/);
        assert.match(output, /"status":"fixture-ready","attempt":2/);
        assert.doesNotMatch(output, /fixture-controller-id|fixture-account-title|Fixture Account Name|example\.invalid|\/fixture\/private|Fixture Physical/);
        assert.doesNotMatch(output, /Fixture (?:Contact Phone|Alternate Phone|Birth Date)/);
    }
});

test('GPM and Dolphin debugging logs show retries and results without controller endpoints', async t => {
    const sandbox = await fixture(t, { productionLogger: true });
    const completed = sandbox.run(['--input-type=module', '-e', `
        import assert from 'node:assert/strict';
        import state from './src/fixture.cjs';
        import GPMProfile from './src/gpmlogin/profile.js';
        import DolphinProfile from './src/dolphin/profile.js';

        globalThis.setTimeout = callback => queueMicrotask(callback);
        GPMProfile.prototype.injectAntiDetectionScripts = async () => {};
        const endpoint = 'wss://private-controller.invalid:37491/devtools/browser/fixture';
        for (const Profile of [GPMProfile, DolphinProfile]) {
            state.onAttach = () => {
                state.onAttach = null;
                throw new Error('Synthetic browser connection failure');
            };
            const profile = await new Profile('fixture-profile', endpoint).start();
            assert.equal(await profile.stop(), false);
            assert.equal(profile.browser, null);
        }
        assert.deepEqual(state.events.filter(([event]) => event === 'attach'),
            Array.from({ length: 4 }, () => ['attach', endpoint]));
    `], { FIXTURE_TRACE: '' });
    assert.equal(completed.status, 0, completed.stderr);
    assert.equal(completed.stderr, '');
    const logs = path.join(sandbox.root, 'logs');
    const [logFile] = await readdir(logs);
    const outputs = [completed.stdout, await readFile(path.join(logs, logFile), 'utf8')];
    for (const output of outputs) {
        assert.match(output, /Browser connection attempt 2\/8/i);
        assert.match(output, /Connecting to Dolphin Anty browser \(attempt 2\/5\)/);
        assert.match(output, /\[WARN\] (?:GPM )?Browser connection attempt 1 failed/i);
        assert.match(output, /Dolphin Anty browser connection attempt 1 failed/);
        assert.equal([...output.matchAll(/browser connected successfully/gi)].length, 2);
    }
    assert.deepEqual(outputs.map(output => /private-controller\.invalid|37491|\/devtools\/browser\//.test(output)),
        [false, false]);
});

test('log levels normalize padding and diagnose unknown values without echoing them', async t => {
    const sandbox = await fixture(t, { productionLogger: true });
    const defaultLevels = ['ERROR', 'WARN', 'INFO'];
    const source = `
        import logger from './src/utils/logger.js';
        for (const level of ['error', 'warn', 'info', 'debug']) {
            logger[level]('Logging level fixture');
        }
    `;
    for (const [label, level, expected, invalid] of [
        ['default', undefined, defaultLevels, false],
        ['empty', '', defaultLevels, false],
        ['padded-error', '  eRrOr  ', ['ERROR'], false],
        ['padded-silent', '  SiLeNt  ', [], false],
        ['invalid', 'fixture-private-invalid-level', defaultLevels, true],
        ['whitespace-only', ' \t ', defaultLevels, true]
    ]) {
        await t.test(label, async () => {
            const state = path.join(sandbox.root, label);
            const completed = sandbox.run(['--input-type=module', '-e', source], {
                GMAIL_CREATOR_STATE_DIR: state, LOG_LEVEL: level
            });
            assert.equal(completed.status, 0, completed.stderr);
            assert.equal(completed.stderr, invalid ? 'Invalid LOG_LEVEL. Using INFO.\n' : '');
            const loggedLevels = output => [...output.matchAll(/\[(ERROR|WARN|INFO|DEBUG)\] Logging level fixture/g)]
                .map(([, loggedLevel]) => loggedLevel);
            assert.deepEqual(loggedLevels(completed.stdout), expected);
            assert.doesNotMatch(completed.stdout, /fixture-private-invalid-level/);
            const logs = path.join(state, 'logs');
            if (expected.length === 0) {
                assert.equal(completed.stdout, '');
                await assert.rejects(readdir(logs), { code: 'ENOENT' });
                return;
            }
            const [file] = await readdir(logs);
            const contents = await readFile(path.join(logs, file), 'utf8');
            assert.deepEqual(loggedLevels(contents), expected);
            assert.doesNotMatch(contents, /fixture-private-invalid-level/);
        });
    }
});

test('a long-running logger writes each entry to its UTC date file', async t => {
    const sandbox = await fixture(t, { productionLogger: true });
    const completed = sandbox.run(['--input-type=module', '-e', `
        let now = '2026-01-01T23:59:59.990Z';
        const SystemDate = Date;
        globalThis.Date = class extends SystemDate {
            constructor(...args) { super(...(args.length ? args : [now])); }
        };
        const { default: logger } = await import('./src/utils/logger.js');
        logger.info('Before midnight');
        now = '2026-01-02T00:00:00.010Z';
        logger.info('After midnight');
    `]);
    assert.equal(completed.status, 0, completed.stderr);
    const logs = path.join(sandbox.root, 'logs');
    assert.deepEqual((await readdir(logs)).sort(), ['app-2026-01-01.log', 'app-2026-01-02.log']);
    assert.equal(await readFile(path.join(logs, 'app-2026-01-01.log'), 'utf8'),
        '[2026-01-01T23:59:59.990Z] [INFO] Before midnight\n');
    assert.equal(await readFile(path.join(logs, 'app-2026-01-02.log'), 'utf8'),
        '[2026-01-02T00:00:00.010Z] [INFO] After midnight\n');
});
