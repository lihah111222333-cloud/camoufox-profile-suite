import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    closeSharedBrowser,
    getActiveProfileIds,
    setCamoufoxModule,
    startProfile,
    stopAllActiveProfiles,
    stopProfile,
    unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import { CamoufoxProfile, createAndStartProfile } from '../../src/camoufox/profile.js';

function setup(t, configureContext = () => {}, beforeLaunch = () => {}) {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'profile-lifecycle-')));
    const contexts = [];
    const browsers = [];
    setCamoufoxModule({
        async Camoufox() {
            const ownContexts = [];
            let connected = true;
            const browser = Object.assign(new EventEmitter(), {
                isConnected: () => connected,
                async close() {
                    for (const fixture of ownContexts) {
                        if (fixture.closed) continue;
                        await fixture.beforeClose?.();
                        fixture.finishClose();
                    }
                    connected = false;
                    browser.emit('disconnected');
                },
                async newContext({ storageState } = {}) {
                    const fixture = {
                        routes: new Set(),
                        pages: [],
                        state: structuredClone(storageState ?? { cookies: [], origins: [] }),
                        closed: false,
                        finishClose() {
                            if (fixture.closed) return;
                            fixture.closed = true;
                            fixture.context.emit('close');
                        }
                    };
                    fixture.context = Object.assign(new EventEmitter(), {
                        browser: () => browser,
                        pages: () => fixture.pages.filter((page) => !page.isClosed()),
                        async newPage() {
                            await fixture.beforeNewPage?.();
                            let pageClosed = false;
                            const page = Object.assign(new EventEmitter(), {
                                context: () => fixture.context,
                                isClosed: () => fixture.closed || pageClosed,
                                async close() {
                                    pageClosed = true;
                                    page.emit('close');
                                },
                                url: () => 'about:blank',
                                evaluate: () => fixture.evaluate?.()
                            });
                            fixture.pages.push(page);
                            fixture.context.emit('page', page);
                            return page;
                        },
                        async storageState() {
                            await fixture.beforeSnapshot?.();
                            assert.equal(fixture.closed, false);
                            return fixture.state;
                        },
                        async route(pattern, handler) {
                            fixture.routes.add(handler);
                        },
                        async unroute(pattern, handler) {
                            assert.equal(fixture.closed, true);
                            fixture.routes.delete(handler);
                        },
                        async close() {
                            if (fixture.closed) return;
                            await fixture.beforeClose?.();
                            fixture.finishClose();
                        }
                    });
                    configureContext(fixture);
                    contexts.push(fixture);
                    ownContexts.push(fixture);
                    return fixture.context;
                }
            });
            browsers.push(browser);
            await beforeLaunch();
            return browser;
        }
    });
    t.after(async () => {
        for (const fixture of contexts) {
            fixture.beforeClose = null;
            fixture.beforeSnapshot = null;
        }
        try {
            await stopAllActiveProfiles();
        } finally {
            setCamoufoxModule();
            unregisterProcessCleanupHooks();
            fs.rmSync(root, { force: true, recursive: true });
        }
    });
    const options = {
        profilesDir: root,
        useSharedBrowser: true,
        enablePortScanProtection: true,
        enableGpuPerformanceScaling: false,
        recordTraffic: false,
        recordHar: false,
        recordWireLog: false,
        recordBodies: false,
        sslKeyLog: false,
        neckoMozLog: false
    };
    return { root, contexts, browsers, options };
}

test('profile close keeps filters installed through pending save and failed native close', async (t) => {
    const { contexts, options } = setup(t);
    const manager = await new CamoufoxProfile('filtered', options).start();
    const [fixture] = contexts;
    let startSnapshot;
    let finishSnapshot;
    const snapshotStarted = new Promise((resolve) => { startSnapshot = resolve; });
    const snapshotHeld = new Promise((resolve) => { finishSnapshot = resolve; });
    fixture.beforeSnapshot = async () => {
        startSnapshot();
        await snapshotHeld;
    };
    fixture.beforeClose = () => {
        assert.equal(fixture.routes.size, 1);
        throw new Error('Fixture close is unavailable');
    };
    const closing = manager.stop();
    await Promise.race([
        snapshotStarted,
        closing.then(() => { throw new Error('Profile stop finished before taking a snapshot'); })
    ]);
    try {
        assert.equal(fixture.routes.size, 1);
    } finally {
        finishSnapshot();
    }
    assert.equal(await closing, false);
    assert.equal(fixture.closed, false);
    assert.equal(fixture.routes.size, 1);
    assert.equal(manager.context, fixture.context);
    assert.equal(manager.browser.isConnected(), true);
    assert.deepEqual(getActiveProfileIds(), ['filtered']);
    await assert.rejects(manager.delete(), /Could not stop Camoufox profile before deletion/);
    assert.equal(fs.existsSync(manager.storageStatePath), true);
    assert.equal(fixture.routes.size, 1);

    fixture.beforeClose = () => {
        fixture.finishClose();
        throw new Error('Fixture driver threw after native close');
    };
    assert.equal(await manager.stop(), true);
    assert.equal(fixture.closed, true);
    assert.equal(fixture.routes.size, 0);
    assert.equal(manager.context, null);
    assert.deepEqual(getActiveProfileIds(), []);
});

test('shared-browser close retains the native process and context through a rejected close', async (t) => {
    const { contexts, options } = setup(t);
    await new CamoufoxProfile('shared', options).start();
    const [fixture] = contexts;
    fixture.beforeClose = () => { throw new Error('Fixture close unavailable'); };

    assert.equal(await closeSharedBrowser(), false);
    assert.equal(fixture.routes.size, 1);
    assert.deepEqual(getActiveProfileIds(), ['shared']);

    fixture.beforeClose = null;
    assert.equal(await closeSharedBrowser(), true);
    assert.equal(fixture.closed, true);
    assert.equal(fixture.routes.size, 0);
    assert.deepEqual(getActiveProfileIds(), []);
});

test('shared browser close saves both live and still-opening contexts before closing the browser', async (t) => {
    let openPage;
    let unblockPage;
    const pageOpening = new Promise((resolve) => { openPage = resolve; });
    const pageBlocked = new Promise((resolve) => { unblockPage = resolve; });
    const { contexts, options } = setup(t, (fixture) => {
        if (contexts.length === 1) {
            fixture.beforeNewPage = async () => { openPage(); await pageBlocked; };
        }
    });
    const active = await startProfile('active', options);
    const starting = startProfile('starting', options);
    await pageOpening;
    for (const [index, fixture] of contexts.entries()) {
        fixture.state.origins = [{ origin: 'https://fixture.invalid', localStorage: [{ name: 'sample', value: String(index) }] }];
    }

    const closing = closeSharedBrowser();
    unblockPage();
    const second = await starting;
    assert.equal(await closing, true);
    for (const [index, session] of [active, second].entries()) {
        assert.deepEqual(JSON.parse(fs.readFileSync(session.storageStatePath, 'utf8')), contexts[index].state);
        assert.equal(contexts[index].closed, true);
    }
    assert.deepEqual(getActiveProfileIds(), []);
});

test('closing the public context saves the final state before native close', async (t) => {
    const { contexts, options } = setup(t);
    const manager = await new CamoufoxProfile('context-close', options).start();
    const [fixture] = contexts;
    fixture.state.cookies = [{ name: 'fixture', value: 'final-context-state' }];
    let snapshots = 0;
    fixture.beforeSnapshot = () => { snapshots += 1; };
    const context = await manager.getContext();
    const [, stopped] = await Promise.all([context.close(), manager.stop()]);
    assert.equal(stopped, true);
    assert.equal(snapshots, 1);
    assert.deepEqual(JSON.parse(fs.readFileSync(manager.storageStatePath, 'utf8')), fixture.state);
    assert.equal(await manager.stop(), true);
});

test('shared browser shutdown reports a failed final snapshot after closing the native context', async (t) => {
    const { contexts, options } = setup(t);
    await startProfile('shared-save-failed', options);
    contexts[0].beforeSnapshot = () => { throw new Error('Fixture snapshot unavailable'); };
    assert.equal(await closeSharedBrowser(), false);
    assert.equal(contexts[0].closed, true);
    assert.deepEqual(getActiveProfileIds(), []);
});

test('public context closure reports a failed final snapshot and shutdown preserves the previous bytes', async (t) => {
    const { contexts, options } = setup(t);
    const manager = await new CamoufoxProfile('context-save-failed', options).start();
    const snapshot = fs.readFileSync(manager.storageStatePath, 'utf8');
    const [fixture] = contexts;
    fixture.beforeSnapshot = () => { throw new Error('Fixture snapshot unavailable'); };
    const context = await manager.getContext();
    await assert.rejects(context.close(), /Fixture snapshot unavailable/);
    assert.equal(fixture.closed, true);
    await assert.rejects(manager.getPage(), /Previous Camoufox profile session could not be stopped/);
    assert.equal(contexts.length, 1);
    assert.equal(await manager.stop(), false);
    assert.equal(fs.readFileSync(manager.storageStatePath, 'utf8'), snapshot);
});

test('a context that closes unexpectedly reports the unavailable final snapshot', async (t) => {
    const { contexts, options } = setup(t);
    const manager = await new CamoufoxProfile('unexpected-close', options).start();
    await manager.saveStorageState();
    contexts[0].finishClose();
    assert.equal(await manager.stop(), false);
    assert.deepEqual(getActiveProfileIds(), []);
});

test('getPage reopens a context closed externally from the last saved snapshot', async (t) => {
    const { contexts, options } = setup(t);
    const manager = await new CamoufoxProfile('externally-closed', options).start();
    const first = await manager.getPage();
    contexts[0].state.cookies = [{ name: 'fixture', value: 'saved-before-close' }];
    const savedPath = await manager.saveStorageState();
    const savedBytes = fs.readFileSync(savedPath);
    contexts[0].state.cookies[0].value = 'unsaved';
    contexts[0].finishClose();

    const reopened = await manager.getPage();
    assert.notEqual(reopened, first);
    assert.equal(reopened.isClosed(), false);
    assert.equal(contexts.length, 2);
    assert.equal(contexts[1].state.cookies[0].value, 'saved-before-close');
    assert.deepEqual(fs.readFileSync(savedPath), savedBytes);
});

test('all callers reuse one live primary page in a profile session', { timeout: 5000 }, async (t) => {
    const { contexts, options } = setup(t);
    const profileId = 'primary-page';
    const session = await startProfile(profileId, options);
    const manager = await new CamoufoxProfile(profileId, options).start();
    const otherManager = await new CamoufoxProfile(profileId, options).start();
    await session.page.close();

    let opened = 0;
    let announce;
    let resume;
    const opening = new Promise((resolve) => { announce = resolve; });
    const wait = new Promise((resolve) => { resume = resolve; });
    contexts[0].beforeNewPage = () => {
        opened += 1;
        announce();
        return wait;
    };
    const pages = Promise.all([
        manager.getPage(), otherManager.getPage(), manager.getPage(), startProfile(profileId, options)
    ]);
    await opening;
    resume();

    const [page, other, repeated, reused] = await pages;
    assert.equal(opened, 1);
    assert.equal(page, other);
    assert.equal(page, repeated);
    assert.equal(reused, session);
    assert.equal(session.page, page);
    assert.deepEqual(session.context.pages(), [page]);

    await page.close();
    const restarted = await startProfile(profileId, options);
    assert.equal(restarted, session);
    assert.notEqual(restarted.page, page);
    assert.equal(restarted.page.isClosed(), false);
    assert.equal(opened, 2);
});

test('a failed HAR scratch removal keeps cleanup retryable after the browser context closes', async (t) => {
    const { contexts, options } = setup(t);
    const settings = { ...options, recordHar: true };
    const session = await startProfile('har-cleanup', settings);
    const nativeDir = path.join(path.dirname(session.storageStatePath), '.native');
    const entry = fs.readdirSync(nativeDir).find((name) => fs.existsSync(path.join(nativeDir, name, 'payloads')));
    assert.ok(entry);
    const scratch = path.join(nativeDir, entry);
    const remove = fs.rmSync;
    const failRemoval = t.mock.method(fs, 'rmSync', (target, rmOptions) => {
        if (target === scratch) throw Object.assign(new Error('Fixture directory is busy'), { code: 'EBUSY' });
        return remove(target, rmOptions);
    });
    try {
        assert.equal(await stopProfile('har-cleanup', settings), false);
        assert.equal(contexts[0].closed, true);
        assert.equal(fs.existsSync(scratch), true);
    } finally {
        failRemoval.mock.restore();
    }
    await startProfile('har-cleanup', options);
    assert.equal(fs.existsSync(scratch), false);
    assert.equal(await stopProfile('har-cleanup', options), true);
    assert.deepEqual(fs.readdirSync(nativeDir), []);
});

test('failed startup keeps a still-live context tracked and filtered until cleanup can close it', async (t) => {
    const { contexts, options } = setup(t, (fixture) => {
        fixture.beforeNewPage = () => { throw new Error('Fixture page unavailable'); };
        fixture.beforeClose = () => { throw new Error('Fixture close unavailable'); };
    });
    await assert.rejects(
        new CamoufoxProfile('startup', options).start(),
        /Fixture page unavailable/
    );
    const [fixture] = contexts;
    assert.equal(fixture.closed, false);
    assert.equal(fixture.routes.size, 1);
    assert.deepEqual(getActiveProfileIds(), ['startup']);

    fixture.beforeClose = null;
    assert.equal(await stopProfile('startup', options), true);
    assert.equal(fixture.closed, true);
    assert.equal(fixture.routes.size, 0);
    assert.deepEqual(getActiveProfileIds(), []);
});

test('final snapshot failure is reported separately from confirmed native closure', async (t) => {
    const { contexts, options } = setup(t);
    const manager = await new CamoufoxProfile('save', options).start();
    const [fixture] = contexts;
    fixture.state.cookies = [{ name: 'fixture', value: 'previous-state' }];
    const savedFile = await manager.saveStorageState();
    const previousBytes = fs.readFileSync(savedFile, 'utf8');
    fixture.beforeSnapshot = () => { throw new Error('Fixture snapshot unavailable'); };

    assert.equal(await manager.stop(), false);
    assert.equal(fixture.closed, true);
    assert.equal(fixture.routes.size, 0);
    assert.equal(manager.context, null);
    assert.equal(fs.readFileSync(savedFile, 'utf8'), previousBytes);
});

test('an acquired manager lifecycle keeps its canonical storage when an alias changes', async (t) => {
    const { root, contexts, options } = setup(t);
    const firstRoot = path.join(root, 'first');
    const secondRoot = path.join(root, 'second');
    const alias = path.join(root, 'alias');
    const type = process.platform === 'win32' ? 'junction' : 'dir';
    fs.mkdirSync(firstRoot);
    fs.mkdirSync(secondRoot);
    fs.symlinkSync(firstRoot, alias, type);
    const first = await new CamoufoxProfile('same-id', { ...options, profilesDir: alias }).start();

    fs.unlinkSync(alias);
    fs.symlinkSync(secondRoot, alias, type);
    const second = await new CamoufoxProfile('same-id', { ...options, profilesDir: alias }).start();
    assert.equal(await first.saveStorageState(), path.join(firstRoot, 'same-id', 'storage-state.json'));
    assert.equal(await first.delete(), true);
    assert.equal(contexts[0].closed, true);
    assert.equal(contexts[1].closed, false);
    assert.equal(fs.existsSync(first.storageStatePath), false);
    assert.equal(fs.existsSync(second.storageStatePath), true);
});

test('old managers cannot stop or delete any later generation of the same profile', async (t) => {
    const { contexts, options } = setup(t);
    const old = await new CamoufoxProfile('generation', options).start();
    assert.equal(await stopProfile('generation', options), true);
    const current = await new CamoufoxProfile('generation', options).start();

    assert.equal(await old.stop(), false);
    await assert.rejects(old.delete(), /Could not stop Camoufox profile before deletion/);
    assert.equal(contexts[1].closed, false);
    assert.equal(await current.stop(), true);
    assert.equal(await old.stop(), false);
    await assert.rejects(old.delete(), /Could not stop Camoufox profile before deletion/);
    assert.equal(fs.existsSync(current.storageStatePath), true);
    assert.equal(await current.delete(), true);
});

test('manager cleanup requires the acquired directory identity even when metadata matches', async (t) => {
    const { contexts, options } = setup(t);
    const manager = await new CamoufoxProfile('directory', options).start();
    const dir = path.dirname(manager.storageStatePath);
    const held = dir + '-held';
    fs.renameSync(dir, held);
    try {
        fs.mkdirSync(dir);
        fs.copyFileSync(path.join(held, 'profile.json'), path.join(dir, 'profile.json'));
        assert.equal(await manager.stop(), false);
        await assert.rejects(manager.delete(), /Could not stop Camoufox profile before deletion/);
        assert.equal(contexts[0].closed, false);
        assert.equal(contexts[0].routes.size, 1);
        assert.equal(fs.existsSync(path.join(dir, 'profile.json')), true);
    } finally {
        fs.rmSync(dir, { force: true, recursive: true });
        fs.renameSync(held, dir);
    }
    assert.equal(await manager.delete(), true);
});

test('stopped manager attribution is an immutable snapshot of its session', async (t) => {
    const { options } = setup(t);
    const recordingOptions = { ...options, recordTraffic: true };
    const old = await new CamoufoxProfile('recording', recordingOptions).start();
    old.getTrafficRecorder().recordTriggerAction('fixture.first', 'inert');
    assert.equal(await stopProfile('recording', options), true);
    const oldSummary = await old.getTrafficAttribution();
    assert.ok(oldSummary.integrity.chainHeadHash);
    const original = structuredClone(oldSummary);

    const current = await new CamoufoxProfile('recording', recordingOptions).start();
    current.getTrafficRecorder().recordTriggerAction('fixture.second', 'inert');
    const currentSummary = await current.getTrafficAttribution();
    assert.notEqual(currentSummary.integrity.chainHeadHash, original.integrity.chainHeadHash);
    const index = current.trafficPaths.attributionIndexPath;
    const currentBytes = fs.readFileSync(index, 'utf8');

    oldSummary.integrity.chainHeadHash = 'caller-edit';
    assert.deepEqual(await old.getTrafficAttribution(), original);
    assert.equal(fs.readFileSync(index, 'utf8'), currentBytes);
});

test('stop during SDK launch waits for closure of the late browser', async (t) => {
    let enterLaunch;
    let releaseLaunch;
    const launchEntered = new Promise((resolve) => { enterLaunch = resolve; });
    const launchHeld = new Promise((resolve) => { releaseLaunch = resolve; });
    const { contexts, browsers, options } = setup(t, undefined, () => {
        enterLaunch();
        return launchHeld;
    });
    const manager = new CamoufoxProfile('starting-stop', { ...options, useSharedBrowser: false });
    const startupError = manager.start().then(() => null, (error) => error);
    await launchEntered;
    const stopping = manager.stop();
    try {
        assert.equal(await Promise.race([
            stopping.then(() => true),
            new Promise((resolve) => setImmediate(() => resolve(false)))
        ]), false);
    } finally {
        releaseLaunch();
    }
    assert.match((await startupError)?.message ?? '', /startup cancelled by stop/);
    assert.equal(await stopping, true);
    assert.equal(contexts.length, 0);
    assert.equal(browsers[0].isConnected(), false);
    assert.deepEqual(getActiveProfileIds(), []);
});

test('factory audit failure closes dedicated and idle shared browsers and rolls back the new profile', async (t) => {
    const { root, contexts, browsers, options } = setup(t, (fixture) => {
        fixture.evaluate = () => { throw new Error('Fixture diagnostic unavailable'); };
    });
    for (const useSharedBrowser of [false, true]) {
        const profileId = `audit-failure-${useSharedBrowser}`;
        await assert.rejects(createAndStartProfile('fixture', null, {
            ...options, useSharedBrowser, profileId, verifyCoherence: true
        }), (error) => error.profileId === profileId && error.profileCleanup === 'deleted' &&
            error.cause?.message === 'Fixture diagnostic unavailable');
        assert.equal(contexts.at(-1).closed, true);
        assert.equal(browsers.at(-1).isConnected(), false);
        assert.equal(fs.existsSync(path.join(root, profileId)), false);
        assert.deepEqual(getActiveProfileIds(), []);
    }
});

test('a shared startup rollback leaves another profile on the browser connected', async (t) => {
    const { root, contexts, browsers, options } = setup(t, (fixture) => {
        fixture.evaluate = () => { throw new Error('Fixture diagnostic unavailable'); };
    });
    const neighbor = await startProfile('running-neighbor', options);
    await assert.rejects(createAndStartProfile('fixture', null, {
        ...options, profileId: 'shared-audit-failure', verifyCoherence: true
    }), { profileId: 'shared-audit-failure', profileCleanup: 'deleted' });

    assert.equal(browsers.length, 1);
    assert.equal(browsers[0].isConnected(), true);
    assert.equal(neighbor.browser.isConnected(), true);
    assert.equal(contexts[1].closed, true);
    assert.equal(fs.existsSync(path.join(root, 'shared-audit-failure')), false);
    assert.deepEqual(getActiveProfileIds(), ['running-neighbor']);
});

test('a failed startup with an unconfirmed close reports the retained profile ID', async (t) => {
    const { root, contexts, options } = setup(t, (fixture) => {
        fixture.evaluate = () => { throw new Error('Fixture diagnostic unavailable'); };
        fixture.beforeClose = () => { throw new Error('Fixture close unavailable'); };
    });
    const profileId = 'unconfirmed-start';
    await assert.rejects(createAndStartProfile('fixture', null, {
        ...options, useSharedBrowser: false, profileId, verifyCoherence: true
    }), { profileId, profileCleanup: 'stop-unconfirmed' });

    assert.equal(fs.existsSync(path.join(root, profileId)), true);
    assert.deepEqual(getActiveProfileIds(), [profileId]);
    contexts[0].beforeClose = null;
    assert.equal(await stopProfile(profileId, options), true);
    assert.deepEqual(getActiveProfileIds(), []);
});

test('factory abort reports pending cleanup promptly and removes its profile when the SDK settles', async (t) => {
    let enterLaunch;
    let releaseLaunch;
    const launchEntered = new Promise((resolve) => { enterLaunch = resolve; });
    const launchHeld = new Promise((resolve) => { releaseLaunch = resolve; });
    const { root, contexts, browsers, options } = setup(t, undefined, () => {
        enterLaunch();
        return launchHeld;
    });
    const controller = new AbortController();
    const profileId = 'abort-factory';
    const attempt = createAndStartProfile('fixture', null, {
        ...options, useSharedBrowser: false, profileId, signal: controller.signal
    });
    await launchEntered;
    controller.abort(new Error('Fixture startup cancelled'));
    try {
        const outcome = await Promise.race([
            attempt.catch((error) => error),
            new Promise((resolve) => setImmediate(resolve))
        ]);
        assert.ok(outcome instanceof Error);
        assert.equal(outcome.name, 'AbortError');
        assert.equal(outcome.profileId, profileId);
        assert.equal(outcome.profileCleanup, 'stop-unconfirmed');
    } finally {
        releaseLaunch();
    }
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(contexts.length, 0);
    assert.equal(browsers[0].isConnected(), false);
    assert.equal(fs.existsSync(path.join(root, profileId)), false);
    assert.deepEqual(getActiveProfileIds(), []);
});

test('a failed native close preserves the recorder and prevents reattachment', async (t) => {
    const { contexts, options } = setup(t);
    const recording = { ...options, recordTraffic: true };
    const session = await startProfile('recording-close-failure', recording);
    const [fixture] = contexts;
    fixture.beforeClose = () => { throw new Error('Fixture close unavailable'); };

    assert.equal(await stopProfile('recording-close-failure', options), false);
    assert.equal(session.browser.isConnected(), true);
    assert.equal(session.trafficRecorder.stopped, false);
    await assert.rejects(startProfile('recording-close-failure', recording), /Finish stopping this Camoufox profile/);
    session.trafficRecorder.recordTriggerAction('fixture.retained-recorder');

    fixture.beforeClose = null;
    assert.equal(await stopProfile('recording-close-failure', options), true);
    assert.equal(session.trafficRecorder.stopped, true);
    assert.match(fs.readFileSync(session.trafficPaths.trafficNdjsonPath, 'utf8'), /fixture\.retained-recorder/);
});
