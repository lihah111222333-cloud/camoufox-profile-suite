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
    stopAllActiveProfiles,
    stopProfile,
    unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import { CamoufoxProfile } from '../../src/camoufox/profile.js';

function setup(t, configureContext = () => {}) {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'profile-lifecycle-')));
    const contexts = [];
    setCamoufoxModule({
        async Camoufox() {
            const ownContexts = [];
            let connected = true;
            const browser = Object.assign(new EventEmitter(), {
                isConnected: () => connected,
                async close() {
                    for (const fixture of ownContexts) await fixture.context.close();
                    connected = false;
                    browser.emit('disconnected');
                },
                async newContext() {
                    const fixture = {
                        routes: new Set(),
                        pages: [],
                        state: { cookies: [], origins: [] },
                        closed: false,
                        finishClose() {
                            if (fixture.closed) return;
                            fixture.closed = true;
                            fixture.context.emit('close');
                        }
                    };
                    fixture.context = Object.assign(new EventEmitter(), {
                        browser: () => browser,
                        pages: () => fixture.pages,
                        async newPage() {
                            await fixture.beforeNewPage?.();
                            const page = Object.assign(new EventEmitter(), {
                                context: () => fixture.context,
                                isClosed: () => fixture.closed,
                                url: () => 'about:blank'
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
    return { root, contexts, options };
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
