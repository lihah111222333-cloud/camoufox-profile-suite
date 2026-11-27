import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    createProfile,
    deleteProfile,
    ensureProfileStorage,
    getProfile,
    loadStorageState,
    saveProfileStorageState,
    setCamoufoxModule,
    startProfile,
    stopAllActiveProfiles,
    stopProfile,
    unregisterProcessCleanupHooks,
    updateProfileProxy
} from '../../src/camoufox/client.js';
import { createAndStartProfile } from '../../src/camoufox/profile.js';
import { CamoufoxTrafficRecorder } from '../../src/camoufox/traffic-recorder.js';

const OPTIONS = {
    enablePortScanProtection: false,
    enableGpuPerformanceScaling: false,
    recordTraffic: false,
    recordHar: false,
    sslKeyLog: false,
    neckoMozLog: false
};

function mockLauncher(onLaunch = () => {}) {
    return {
        async Camoufox() {
            onLaunch();
            let connected = true;
            const browser = {
                isConnected: () => connected,
                async close() { connected = false; },
                async newContext({ storageState }) {
                    const initialState = typeof storageState === 'string'
                        ? JSON.parse(fs.readFileSync(storageState, 'utf8'))
                        : structuredClone(storageState);
                    let closed = false;
                    const context = {
                        pages: () => [page],
                        isClosed: () => closed,
                        initialState,
                        nextState: structuredClone(initialState),
                        async close() { closed = true; },
                        async storageState() { return context.nextState; }
                    };
                    const page = {
                        context: () => context,
                        isClosed: () => closed,
                        url: () => 'about:blank'
                    };
                    return context;
                }
            };
            return browser;
        }
    };
}

function setup(t, onLaunch) {
    const profilesDir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-owner-test-')));
    setCamoufoxModule(mockLauncher(onLaunch));
    t.after(async () => {
        try {
            await stopAllActiveProfiles();
        } finally {
            unregisterProcessCleanupHooks();
            setCamoufoxModule();
            fs.rmSync(profilesDir, { recursive: true, force: true });
        }
    });
    return { ...OPTIONS, profilesDir };
}

function runOwnerProcess(operation, profilesDir) {
    const script = `
        import assert from 'node:assert/strict';
        import fs from 'node:fs';
        import {
            deleteProfile, saveProfileStorageState, setCamoufoxModule, startProfile, stopProfile
        } from ${JSON.stringify(new URL('../../src/camoufox/client.js', import.meta.url).href)};
        const makeLauncher = ${mockLauncher.toString()};
        setCamoufoxModule(makeLauncher());
        const [operation, profilesDir] = process.argv.slice(1);
        const options = { ...${JSON.stringify(OPTIONS)}, profilesDir };
        if (operation === 'check-exclusive') {
            const busy = { code: 'ERR_CAMOUFOX_PROFILE_BUSY' };
            await assert.rejects(startProfile('owner', options), busy);
            assert.equal(await stopProfile('owner', options), false);
            await assert.rejects(deleteProfile('owner', options), busy);
        } else if (operation === 'check-inactive') {
            assert.equal(await stopProfile('owner', options), true);
        } else if (operation === 'abandon-har') {
            await startProfile('owner', { ...options, recordHar: true });
        } else {
            const session = await startProfile('owner', options);
            session.context.nextState.origins = [{
                origin: 'https://fixture.invalid',
                localStorage: [{ name: 'sample', value: 'saved-before-process-exit' }]
            }];
            await saveProfileStorageState('owner', session.context);
        }
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', script, operation, profilesDir], {
        encoding: 'utf8',
        timeout: 10000
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr + result.stdout);
}

test('profile deletion preserves capture data while a standalone recorder owns it', async (t) => {
    const options = setup(t);
    for (const id of ['default-capture', 'nested-capture']) {
        await createProfile(id, null, { ...options, profileId: id });
        const profileDir = path.join(options.profilesDir, id);
        const override = id === 'nested-capture' ? { trafficDir: path.join(profileDir, 'copies', 'capture') } : {};
        const recorder = new CamoufoxTrafficRecorder({ ...options, profileId: id, ...override });
        try {
            await recorder.flushSummary();
            const metadata = fs.readFileSync(recorder.attributionIndexPath);
            const child = spawnSync(process.execPath, ['--input-type=module', '-e',
                `import assert from 'node:assert/strict';
                 import { deleteProfile } from ${JSON.stringify(new URL('../../src/camoufox/client.js', import.meta.url).href)};
                 await assert.rejects(deleteProfile(process.argv[1], { profilesDir: process.argv[2] }), {
                     code: 'ERR_CAMOUFOX_PROFILE_BUSY'
                 });`, id, options.profilesDir], { encoding: 'utf8', timeout: 10000 });
            assert.ifError(child.error);
            assert.equal(child.status, 0, child.stderr);
            assert.deepEqual(fs.readFileSync(recorder.attributionIndexPath), metadata);
        } finally {
            if (fs.existsSync(profileDir)) await recorder.stop();
        }
        assert.equal(await deleteProfile(id, options), true);
        assert.equal(fs.existsSync(profileDir), false);
    }
});

test('a standalone recorder cannot join a profile whose deletion has already started', async (t) => {
    const options = setup(t);
    const id = 'concurrent-capture';
    await createProfile(id, null, { ...options, profileId: id });
    const profileDir = path.join(options.profilesDir, id);
    const remove = fs.rmSync;
    let attempted = false;
    const hooked = t.mock.method(fs, 'rmSync', (target, flags) => {
        if (target === profileDir && !attempted) {
            attempted = true;
            assert.throws(() => new CamoufoxTrafficRecorder({ profilesDir: options.profilesDir, profileId: id }), {
                code: 'ERR_CAMOUFOX_PROFILE_BUSY'
            });
        }
        return remove(target, flags);
    });
    try {
        assert.equal(await deleteProfile(id, options), true);
        assert.equal(attempted, true);
    } finally {
        hooked.mock.restore();
    }
});

test('an existing directory needs matching metadata before profile operations can prepare it', async (t) => {
    const options = setup(t, () => assert.fail('must reject an unregistered directory before launch'));
    const directory = path.join(options.profilesDir, 'notes');
    fs.mkdirSync(directory);
    fs.writeFileSync(path.join(directory, 'notes.txt'), 'unrelated local fixture');

    await assert.rejects(createProfile('notes', null, { ...options, profileId: 'notes' }), { code: 'ENOENT' });
    await assert.rejects(startProfile('notes', options), { code: 'ENOENT' });
    await assert.rejects(updateProfileProxy('notes', null, options), { code: 'ENOENT' });
    assert.throws(() => ensureProfileStorage('notes', options.profilesDir), { code: 'ENOENT' });

    assert.deepEqual(fs.readdirSync(directory), ['notes.txt']);
    assert.equal(fs.readFileSync(path.join(directory, 'notes.txt'), 'utf8'), 'unrelated local fixture');
});

test('an interrupted storage initialization leaves the profile ID available for creation', async (t) => {
    const options = setup(t);
    const script = `
        import fs from 'node:fs';
        import path from 'node:path';
        import { ensureProfileStorage } from ${JSON.stringify(new URL('../../src/camoufox/client.js', import.meta.url).href)};
        const rename = fs.renameSync;
        fs.renameSync = (from, to) => {
            if (path.basename(to) === 'profile.json') process.exit(17);
            return rename(from, to);
        };
        ensureProfileStorage('interrupted', process.argv[1]);
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', script, options.profilesDir], {
        encoding: 'utf8', timeout: 10000
    });
    assert.ifError(result.error);
    assert.equal(result.status, 17, result.stderr + result.stdout);
    assert.equal(fs.existsSync(path.join(options.profilesDir, 'interrupted')), false);
    const created = await createProfile('fixture', null, { ...options, profileId: 'interrupted' });
    assert.deepEqual(await getProfile('interrupted', options), created);
    assert.deepEqual(JSON.parse(fs.readFileSync(created.storageStatePath, 'utf8')), { cookies: [], origins: [] });
});

test('new-profile factory rejects an occupied ID and inactive snapshots need a registered owner', async (t) => {
    let launches = 0;
    const options = setup(t, () => { launches += 1; });
    const created = await createProfile('fixture', null, { ...options, profileId: 'fixture' });
    const metadataPath = path.join(created.profileDir, 'profile.json');
    const initialState = fs.readFileSync(created.storageStatePath);
    await assert.rejects(
        saveProfileStorageState('fixture', { storageState: () => assert.fail('unexpected snapshot read') }, options.profilesDir),
        /does not belong/
    );
    assert.deepEqual(fs.readFileSync(created.storageStatePath), initialState);

    const session = await startProfile('fixture', options);
    const metadata = fs.readFileSync(metadataPath);
    await assert.rejects(createAndStartProfile('other name', null, { ...options, profileId: 'fixture' }), {
        code: 'EEXIST'
    });
    assert.deepEqual(fs.readFileSync(metadataPath), metadata);
    assert.equal(launches, 1);
    assert.equal(await startProfile('fixture', options), session);
});

test('loading a missing snapshot leaves the store untouched', async (t) => {
    const options = setup(t);
    const missingRoot = path.join(options.profilesDir, 'new-store');
    assert.equal(loadStorageState('fixture', missingRoot), null);
    assert.equal(fs.existsSync(missingRoot), false);

    assert.equal(loadStorageState('fixture', options.profilesDir), null);
    const created = await createProfile('fixture', null, { ...options, profileId: 'fixture' });
    assert.equal(loadStorageState('fixture', options.profilesDir), created.storageStatePath);

    fs.unlinkSync(created.storageStatePath);
    assert.equal(loadStorageState('fixture', options.profilesDir), null);
    assert.equal(fs.existsSync(created.storageStatePath), false);
});

test('a legacy profile can start after snapshot repair and routine reads preserve damaged bytes', async (t) => {
    let launches = 0;
    const options = setup(t, () => { launches += 1; });
    const profileDir = path.join(options.profilesDir, 'legacy');
    fs.mkdirSync(profileDir);
    fs.writeFileSync(path.join(profileDir, 'profile.json'), JSON.stringify({ profileId: 'legacy' }));
    const storageStatePath = path.join(profileDir, 'storage-state.json');
    const damaged = '{"cookies":[],"origins":';
    fs.writeFileSync(storageStatePath, damaged);

    const invalidState = { code: 'ERR_CAMOUFOX_STORAGE_STATE_INVALID' };
    assert.throws(() => loadStorageState('legacy', options.profilesDir), invalidState);
    await assert.rejects(startProfile('legacy', options), invalidState);
    assert.equal(fs.readFileSync(storageStatePath, 'utf8'), damaged);
    assert.equal(launches, 0);

    const recovered = { cookies: [{ name: 'fixture', value: 'recovered' }], origins: [] };
    fs.writeFileSync(storageStatePath, JSON.stringify(recovered));
    const session = await startProfile('legacy', options);
    assert.deepEqual(session.context.initialState, recovered);
    assert.equal(launches, 1);

    const malformed = '{"cookies":[],"origins":null}';
    fs.writeFileSync(storageStatePath, malformed);
    try {
        await assert.rejects(saveProfileStorageState('legacy', session.context), invalidState);
        assert.equal(fs.readFileSync(storageStatePath, 'utf8'), malformed);
    } finally {
        fs.writeFileSync(storageStatePath, JSON.stringify(recovered));
    }
});

test('another local process cannot start or delete an active profile and dead ownership can be recovered', async (t) => {
    const outer = setup(t);
    const firstRoot = path.join(outer.profilesDir, 'first');
    const secondRoot = path.join(outer.profilesDir, 'second');
    fs.mkdirSync(firstRoot);
    const alias = path.join(outer.profilesDir, 'alias');
    fs.symlinkSync(firstRoot, alias, process.platform === 'win32' ? 'junction' : 'dir');
    const first = { ...outer, profilesDir: firstRoot };
    const second = { ...outer, profilesDir: secondRoot };

    const active = await startProfile('owner', first);
    runOwnerProcess('check-exclusive', alias);
    assert.equal(active.browser.isConnected(), true);

    runOwnerProcess('persist-and-exit', secondRoot);
    const recovered = await startProfile('owner', second);
    assert.equal(recovered.context.initialState.origins[0].localStorage[0].value, 'saved-before-process-exit');
    assert.equal(active.browser.isConnected(), true);

    assert.equal(await stopProfile('owner', first), true);
    runOwnerProcess('check-inactive', alias);
    assert.equal(await deleteProfile('owner', first), true);
    assert.equal(await getProfile('owner', first), null);
    const replacement = await createProfile('replacement', null, { ...first, profileId: 'owner' });
    await assert.rejects(saveProfileStorageState('owner', active.context), /does not belong/);
    assert.deepEqual(JSON.parse(fs.readFileSync(replacement.storageStatePath, 'utf8')), { cookies: [], origins: [] });
});

test('a new process removes only the abandoned HAR scratch under the recovered lease', async (t) => {
    const options = setup(t);
    runOwnerProcess('abandon-har', options.profilesDir);
    const nativeDir = path.join(options.profilesDir, 'owner', '.native');
    const scratch = fs.readdirSync(nativeDir).find((name) => fs.existsSync(path.join(nativeDir, name, 'payloads')));
    assert.ok(scratch);
    const note = path.join(nativeDir, 'private-note.txt');
    fs.writeFileSync(note, 'Unrelated local fixture', { mode: 0o600 });

    await startProfile('owner', options);
    assert.equal(fs.existsSync(path.join(nativeDir, scratch)), false);
    assert.equal(fs.readFileSync(note, 'utf8'), 'Unrelated local fixture');
});
