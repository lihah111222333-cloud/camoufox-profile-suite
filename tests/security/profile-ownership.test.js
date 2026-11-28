import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    createProfile,
    deleteProfile,
    ensureProfileStorage,
    getProfile,
    getProfileDeletionTarget,
    loadStorageState,
    saveProfileStorageState,
    setCamoufoxModule,
    startProfile,
    stopAllActiveProfiles,
    stopProfile,
    unregisterProcessCleanupHooks,
    updateProfileProxy
} from '../../src/camoufox/client.js';
import { CamoufoxProfile, createAndStartProfile } from '../../src/camoufox/profile.js';
import { captureWriterLeaseDirectory, PROFILE_LEASE_DIRECTORY } from '../../src/camoufox/profile-storage.js';
import { CamoufoxTrafficRecorder } from '../../src/camoufox/traffic-recorder.js';
import { readProcessOwner } from '../../src/utils/process-owner.js';

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
            let connected = true;
            const browser = {
                isConnected: () => connected,
                disconnect() { connected = false; },
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
            onLaunch(browser);
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

function runOwnerProcess(operation, profilesDir, expectedExit = 0) {
    const script = `
        import assert from 'node:assert/strict';
        import fs from 'node:fs';
        import path from 'node:path';
        import {
            deleteProfile, ensureProfileStorage, saveProfileStorageState, setCamoufoxModule, startProfile, stopProfile
        } from ${JSON.stringify(new URL('../../src/camoufox/client.js', import.meta.url).href)};
        const makeLauncher = ${mockLauncher.toString()};
        let browser;
        const [operation, profilesDir] = process.argv.slice(1);
        setCamoufoxModule(makeLauncher((launched) => {
            browser = launched;
            if (operation === 'interrupt-launch') process.exit(74);
        }));
        const options = { ...${JSON.stringify(OPTIONS)}, profilesDir };
        if (operation === 'check-exclusive') {
            const busy = { code: 'ERR_CAMOUFOX_PROFILE_BUSY' };
            await assert.rejects(startProfile('owner', options), busy);
            assert.throws(() => ensureProfileStorage('owner', profilesDir), busy);
            assert.equal(await stopProfile('owner', options), false);
            await assert.rejects(deleteProfile('owner', options), busy);
        } else if (operation === 'check-inactive') {
            assert.equal(await stopProfile('owner', options), true);
        } else if (operation === 'abandon-har') {
            await startProfile('owner', { ...options, recordHar: true });
        } else if (operation === 'interrupt-launch') {
            await startProfile('owner', options);
        } else if (operation === 'disconnect-and-exit' || operation === 'disconnect-with-unwritable-guard') {
            await startProfile('owner', options);
            browser.disconnect();
            if (operation === 'disconnect-with-unwritable-guard') {
                const open = fs.openSync;
                fs.openSync = (file, ...args) => {
                    if (typeof file === 'string' && file.endsWith('~native-exit-unconfirmed') && args[0] === 'wx') {
                        throw Object.assign(new Error('fixture could not create exit guard'), { code: 'ENOSPC' });
                    }
                    return open(file, ...args);
                };
            }
            assert.equal(await stopProfile('owner', options), false);
        } else {
            const session = await startProfile('owner', options);
            session.context.nextState.origins = [{
                origin: 'https://fixture.invalid',
                localStorage: [{ name: 'sample', value: 'saved-before-process-exit' }]
            }];
            if (operation === 'interrupt-snapshot') {
                const rename = fs.renameSync;
                fs.renameSync = (source, target) => {
                    if (target === session.storageStatePath) process.exit(17);
                    return rename(source, target);
                };
            }
            await saveProfileStorageState('owner', session.context);
            if (operation === 'persist-and-exit') {
                const directory = path.join(profilesDir, ${JSON.stringify(PROFILE_LEASE_DIRECTORY)}, 'owner');
                const remove = fs.rmSync;
                fs.rmSync = (file, ...args) => {
                    if (typeof file === 'string' && path.dirname(file) === directory &&
                        path.basename(file).startsWith(String(process.pid) + '-')) {
                        assert.equal(browser.isConnected(), false);
                        assert.equal(fs.existsSync(path.join(directory, '~native-exit-unconfirmed')), false);
                        process.exit(76);
                    }
                    return remove(file, ...args);
                };
                await stopProfile('owner', options);
                assert.fail('expected interruption after confirmed dedicated close');
            }
        }
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', script, operation, profilesDir], {
        encoding: 'utf8',
        timeout: 10000
    });
    assert.ifError(result.error);
    assert.equal(result.status, expectedExit, result.stderr + result.stdout);
}

function archiveReviewedFixtureLease(t, profilesDir) {
    // The fixture controller has exited and its in-memory resource has no separate process.
    const archive = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-lease-archive-'));
    t.after(() => fs.rmSync(archive, { recursive: true, force: true }));
    fs.renameSync(path.join(profilesDir, PROFILE_LEASE_DIRECTORY, 'owner'), path.join(archive, 'owner'));
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
    const rename = fs.renameSync;
    let attempted = false;
    const hooked = t.mock.method(fs, 'renameSync', (from, to) => {
        if (from === profileDir && !attempted) {
            attempted = true;
            assert.throws(() => new CamoufoxTrafficRecorder({ profilesDir: options.profilesDir, profileId: id }), {
                code: 'ERR_CAMOUFOX_PROFILE_BUSY'
            });
        }
        return rename(from, to);
    });
    try {
        assert.equal(await deleteProfile(id, options), true);
        assert.equal(attempted, true);
    } finally {
        hooked.mock.restore();
    }
});

test('legacy migration waits for nested capture leases and excludes a new writer during the move', async (t) => {
    const options = setup(t);
    const profileId = 'archive';
    const { profileDir } = await createProfile(profileId, null, { ...options, profileId });
    const trafficDir = path.join(profileDir, 'traffic');
    const nativeLog = 'necko-pre-tls.moz_log';
    const legacyBytes = 'synthetic legacy log\n';
    fs.writeFileSync(path.join(trafficDir, nativeLog), legacyBytes);
    const childOptions = {
        profileId, trafficDir: path.join(trafficDir, 'copies', 'capture'),
        trustedLocal: true, recordWireLog: false
    };
    const nested = new CamoufoxTrafficRecorder(childOptions);
    nested.setStep('before migration attempt');
    const busy = { code: 'ERR_CAMOUFOX_PROFILE_BUSY' };
    await assert.rejects(startProfile(profileId, options), busy);
    assert.throws(() => new CamoufoxTrafficRecorder({ ...options, profileId }), busy);
    assert.equal(fs.readFileSync(path.join(trafficDir, nativeLog), 'utf8'), legacyBytes);
    nested.setStep('after refused migration');
    await nested.stop();
    const ledgerBytes = fs.readFileSync(nested.trafficNdjsonPath);

    const sibling = new CamoufoxTrafficRecorder({ ...childOptions, trafficDir: path.join(profileDir, 'other') });
    const rename = fs.renameSync;
    let attempted = false;
    const hooked = t.mock.method(fs, 'renameSync', (from, to) => {
        if (from === trafficDir) {
            assert.throws(() => new CamoufoxTrafficRecorder(childOptions), busy);
            attempted = true;
        }
        return rename(from, to);
    });
    try {
        await startProfile(profileId, options);
    } finally {
        hooked.mock.restore();
        await sibling.stop();
    }
    assert.equal(attempted, true);
    const nativeDir = path.join(profileDir, '.native');
    const [archived] = fs.readdirSync(nativeDir);
    const preserved = path.join(nativeDir, archived, 'traffic');
    assert.equal(fs.readFileSync(path.join(preserved, nativeLog), 'utf8'), legacyBytes);
    assert.deepEqual(fs.readFileSync(path.join(preserved, 'copies', 'capture', 'traffic.ndjson')), ledgerBytes);
    assert.equal(fs.existsSync(path.join(trafficDir, 'copies')), false);
    const reopened = new CamoufoxTrafficRecorder(childOptions);
    await reopened.stop();
});

test('a bound deletion can retry partial cleanup without stopping a replacement profile', async (t) => {
    const options = setup(t);
    const profileId = 'partial-delete';
    const original = await new CamoufoxProfile(profileId, options).start();
    const live = path.dirname(original.storageStatePath);
    let staged;
    const remove = fs.rmSync;
    const hooked = t.mock.method(fs, 'rmSync', (target, flags) => {
        const metadataPath = path.join(target, 'profile.json');
        if (flags?.recursive && fs.existsSync(metadataPath)) {
            staged = target;
            fs.unlinkSync(metadataPath);
            throw Object.assign(new Error('Fixture removal failed after unlinking metadata'), { code: 'EIO' });
        }
        return remove(target, flags);
    });
    try {
        await assert.rejects(original.delete(), { code: 'EIO' });
    } finally {
        hooked.mock.restore();
    }
    assert.ok(staged);
    assert.equal(fs.existsSync(live), false);
    assert.equal(fs.existsSync(path.join(staged, 'profile.json')), false);
    assert.equal(fs.existsSync(path.join(staged, 'storage-state.json')), true);
    assert.equal(original.context, null);

    const replacement = await new CamoufoxProfile(profileId, options).start();
    const replacementMetadata = fs.readFileSync(path.join(live, 'profile.json'));
    assert.equal(await original.delete(), true);
    assert.equal(fs.existsSync(staged), false);
    assert.deepEqual(fs.readFileSync(path.join(live, 'profile.json')), replacementMetadata);
    assert.equal(replacement.browser.isConnected(), true);
    assert.equal(await replacement.delete(), true);
    assert.equal(fs.existsSync(live), false);
});

test('an interrupted staged deletion can be retried by ID while a replacement is active', async (t) => {
    const options = setup(t);
    const profileId = 'interrupted-delete';
    const { profileDir } = await createProfile(profileId, null, { ...options, profileId });
    const script = `
        import fs from 'node:fs';
        import path from 'node:path';
        import { deleteProfile } from ${JSON.stringify(new URL('../../src/camoufox/client.js', import.meta.url).href)};
        const [id, profilesDir] = process.argv.slice(1);
        const rename = fs.renameSync;
        fs.renameSync = (from, to) => {
            rename(from, to);
            if (from === path.join(profilesDir, id)) {
                process.stdout.write(to + '\\n');
                process.exit(17);
            }
        };
        await deleteProfile(id, { profilesDir });
    `;
    const interrupted = spawnSync(process.execPath,
        ['--input-type=module', '-e', script, profileId, options.profilesDir],
        { encoding: 'utf8', timeout: 10000 });
    assert.ifError(interrupted.error);
    assert.equal(interrupted.status, 17, interrupted.stderr);
    const staged = interrupted.stdout.trim().split('\n').at(-1);
    assert.ok(staged && fs.existsSync(path.join(staged, 'storage-state.json')));
    assert.equal(fs.existsSync(profileDir), false);

    const replacement = await startProfile(profileId, { ...options, recordTraffic: true });
    const replacementMetadata = fs.readFileSync(path.join(profileDir, 'profile.json'));
    assert.equal(await deleteProfile(profileId, options), true);
    assert.equal(fs.existsSync(staged), false);
    assert.deepEqual(fs.readFileSync(path.join(profileDir, 'profile.json')), replacementMetadata);
    assert.equal(replacement.browser.isConnected(), true);
});

test('independent copies of a capture do not inherit its live writer lease', async (t) => {
    const options = setup(t);
    const stores = {};
    for (const profileId of ['source', 'migration-copy', 'deletion-copy', 'legacy-marker-copy']) {
        stores[profileId] = await createProfile(profileId, null, { ...options, profileId });
    }
    const sourceTraffic = path.join(stores.source.profileDir, 'traffic');
    const logName = 'necko-pre-tls.moz_log';
    fs.writeFileSync(path.join(sourceTraffic, logName), 'synthetic legacy log\n');
    const nestedPath = (trafficDir) => path.join(trafficDir, 'copies', 'capture');
    const makeRecorder = (profileId, trafficDir) => new CamoufoxTrafficRecorder({
        ...options, profileId, trafficDir, trustedLocal: true, recordWireLog: false
    });
    const source = makeRecorder('source', nestedPath(sourceTraffic));
    const busy = { code: 'ERR_CAMOUFOX_PROFILE_BUSY' };
    try {
        source.setStep('local fixture');
        const sourceLease = captureWriterLeaseDirectory(nestedPath(sourceTraffic));
        const [owner] = fs.readdirSync(sourceLease);
        if (!readProcessOwner(path.join(sourceLease, owner)).boot) {
            t.skip('Process scope unavailable for verifying a copied lease');
            return;
        }
        for (const profileId of ['migration-copy', 'deletion-copy', 'legacy-marker-copy']) {
            fs.cpSync(sourceTraffic, path.join(stores[profileId].profileDir, 'traffic'), { recursive: true });
        }
        const legacyTraffic = path.join(stores['legacy-marker-copy'].profileDir, 'traffic');
        const legacyLease = captureWriterLeaseDirectory(nestedPath(legacyTraffic));
        if (owner.includes('.')) {
            fs.renameSync(path.join(legacyLease, owner), path.join(legacyLease, owner.split('.')[0]));
        }
        assert.throws(() => makeRecorder('source', sourceTraffic), busy);
        assert.throws(() => makeRecorder('legacy-marker-copy', legacyTraffic), busy);

        const migration = makeRecorder('migration-copy', path.join(stores['migration-copy'].profileDir, 'traffic'));
        await migration.stop();
        const nativeDir = path.join(stores['migration-copy'].profileDir, '.native');
        const archived = fs.readdirSync(nativeDir).find((name) => name.startsWith('legacy-'));
        assert.equal(fs.readFileSync(path.join(nativeDir, archived, 'traffic', logName), 'utf8'), 'synthetic legacy log\n');
        assert.equal(await deleteProfile('deletion-copy', options), true);
        assert.equal(fs.existsSync(stores['deletion-copy'].profileDir), false);
        assert.equal(fs.existsSync(sourceLease), true);
        assert.equal(fs.readFileSync(path.join(sourceTraffic, logName), 'utf8'), 'synthetic legacy log\n');
        source.setStep('still owned by the original writer');
    } finally {
        await source.stop();
    }
});

test('staged deletion recovers its exact profile lease after a release error', async (t) => {
    const options = setup(t);
    const profileId = 'release-error';
    const { profileDir } = await createProfile(profileId, null, { ...options, profileId });
    const leaseDirectory = path.join(options.profilesDir, PROFILE_LEASE_DIRECTORY, profileId);
    const remove = fs.rmSync;
    const hook = t.mock.method(fs, 'rmSync', (target, flags) => {
        if (path.dirname(target) === leaseDirectory) {
            throw Object.assign(new Error('Fixture lease release failed'), { code: 'EIO' });
        }
        return remove(target, flags);
    });
    try {
        await assert.rejects(deleteProfile(profileId, options), { code: 'EIO' });
    } finally {
        hook.mock.restore();
    }
    assert.equal(fs.existsSync(profileDir), false);
    assert.equal(fs.readdirSync(leaseDirectory).length, 1);

    // The earlier caller is still alive, but its exact lease was relinquished
    // when it detached this generation under the deletion staging lease.
    const script = `
        import assert from 'node:assert/strict';
        import { deleteProfile } from ${JSON.stringify(new URL('../../src/camoufox/client.js', import.meta.url).href)};
        assert.equal(await deleteProfile(process.argv[1], { profilesDir: process.argv[2] }), true);
    `;
    const retry = spawnSync(process.execPath, ['--input-type=module', '-e', script, profileId, options.profilesDir],
        { encoding: 'utf8', timeout: 10000 });
    assert.ifError(retry.error);
    assert.equal(retry.status, 0, retry.stderr);
    assert.equal(fs.existsSync(leaseDirectory), false);
    await createProfile('replacement', null, { ...options, profileId });
    assert.equal(await deleteProfile(profileId, options), true);
});

test('a saved deletion target protects a same-ID replacement after a lost result', async (t) => {
    const options = setup(t);
    const script = `
        import fs from 'node:fs';
        import path from 'node:path';
        import { deleteProfile } from ${JSON.stringify(new URL('../../src/camoufox/client.js', import.meta.url).href)};
        const [profileId, profilesDir, target, phase] = process.argv.slice(1);
        const staging = path.join(profilesDir, '.camoufox-leases~', '~deleting');
        const remove = fs.rmSync;
        fs.rmSync = (entry, flags) => {
            const isStaged = flags?.recursive && path.dirname(entry) === staging;
            if (isStaged && phase === 'before') process.exit(73);
            const result = remove(entry, flags);
            if (isStaged && phase === 'after') process.exit(74);
            return result;
        };
        await deleteProfile(profileId, { profilesDir, deletionTarget: JSON.parse(target) });
    `;
    for (const phase of ['before', 'after']) {
        const profileId = 'lost-result-' + phase;
        const { profileDir } = await createProfile(profileId, null, { ...options, profileId });
        const saved = JSON.stringify(getProfileDeletionTarget(profileId, options));
        const deletionTarget = JSON.parse(saved);
        await assert.rejects(deleteProfile('different-id', { ...options, deletionTarget }),
            { code: 'ERR_CAMOUFOX_INVALID_DELETION_TARGET' });
        await assert.rejects(deleteProfile(profileId, { ...options, deletionTarget: null }),
            { code: 'ERR_CAMOUFOX_INVALID_DELETION_TARGET' });

        const interrupted = spawnSync(process.execPath, [
            '--input-type=module', '-e', script, profileId, options.profilesDir, saved, phase
        ], { encoding: 'utf8', timeout: 10000 });
        assert.ifError(interrupted.error);
        assert.equal(interrupted.status, phase === 'before' ? 73 : 74, interrupted.stderr);
        assert.equal(fs.existsSync(profileDir), false);

        const replacement = await startProfile(profileId, options);
        const metadataPath = path.join(profileDir, 'profile.json');
        const metadata = fs.readFileSync(metadataPath);
        if (phase === 'before') {
            assert.equal(await deleteProfile(profileId, { ...options, deletionTarget }), true);
        }
        await assert.rejects(deleteProfile(profileId, { ...options, deletionTarget }),
            { code: 'ERR_CAMOUFOX_PROFILE_STALE' });
        assert.deepEqual(fs.readFileSync(metadataPath), metadata);
        assert.equal(replacement.browser.isConnected(), true);

        assert.equal(await deleteProfile(profileId, options), true);
        assert.equal(fs.existsSync(profileDir), false);
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

test('reopening a profile discards a verified interrupted snapshot and preserves legacy staging', async (t) => {
    const options = setup(t);
    const storage = ensureProfileStorage('owner', options.profilesDir);
    const committed = JSON.stringify({ cookies: [{ name: 'fixture', value: 'last-good' }], origins: [] });
    fs.writeFileSync(storage.storageStatePath, committed);
    const legacy = path.join(storage.profileDir, '.storage-state.json.32bb47b8-dce1-4fa6-a565-1e87c924a984.tmp');
    fs.writeFileSync(legacy, committed, { mode: 0o600 });
    const unrelated = path.join(storage.profileDir, 'operator-notes.txt');
    fs.writeFileSync(unrelated, 'unrelated local fixture');

    const previousEntries = fs.readdirSync(storage.profileDir);
    runOwnerProcess('interrupt-snapshot', options.profilesDir, 17);
    const newEntries = fs.readdirSync(storage.profileDir).filter((name) => !previousEntries.includes(name));
    assert.equal(newEntries.length, 2);
    const temporary = path.join(storage.profileDir, newEntries.find((name) => name.endsWith('.tmp')));
    const staged = JSON.parse(fs.readFileSync(temporary, 'utf8'));
    assert.equal(staged.origins[0].localStorage[0].value, 'saved-before-process-exit');
    assert.equal(fs.readFileSync(storage.storageStatePath, 'utf8'), committed);
    await assert.rejects(startProfile('owner', options), { code: 'ERR_CAMOUFOX_NATIVE_EXIT_UNCONFIRMED' });
    archiveReviewedFixtureLease(t, options.profilesDir);

    const session = await startProfile('owner', options);
    assert.equal(session.context.initialState.cookies[0].value, 'last-good');
    assert.deepEqual(fs.readdirSync(storage.profileDir), previousEntries);
    assert.equal(fs.readFileSync(storage.storageStatePath, 'utf8'), committed);
    assert.equal(fs.readFileSync(legacy, 'utf8'), committed);
    assert.equal(fs.readFileSync(unrelated, 'utf8'), 'unrelated local fixture');

    session.context.nextState.cookies[0].value = 'new-state';
    await saveProfileStorageState('owner', session.context);
    assert.deepEqual(fs.readdirSync(storage.profileDir), previousEntries);
    assert.equal(JSON.parse(fs.readFileSync(storage.storageStatePath, 'utf8')).cookies[0].value, 'new-state');
    assert.equal(await stopProfile('owner', options), true);
});

test('snapshot recovery preserves a file that replaced the interrupted temporary inode', (t) => {
    const options = setup(t);
    const storage = ensureProfileStorage('owner', options.profilesDir);
    const before = fs.readdirSync(storage.profileDir);
    runOwnerProcess('interrupt-snapshot', options.profilesDir, 17);
    const added = fs.readdirSync(storage.profileDir).filter((name) => !before.includes(name));
    const temporary = path.join(storage.profileDir, added.find((name) => name.endsWith('.tmp')));
    const savedByOperator = path.join(storage.profileDir, 'operator-copy.json');
    fs.renameSync(temporary, savedByOperator);
    fs.writeFileSync(temporary, 'unrelated file at the same path', { mode: 0o600 });
    const saved = fs.readFileSync(savedByOperator);
    const entries = fs.readdirSync(storage.profileDir);

    assert.throws(() => ensureProfileStorage('owner', options.profilesDir), {
        code: 'ERR_CAMOUFOX_NATIVE_EXIT_UNCONFIRMED'
    });
    archiveReviewedFixtureLease(t, options.profilesDir);
    ensureProfileStorage('owner', options.profilesDir);
    assert.deepEqual(fs.readdirSync(storage.profileDir), entries);
    assert.deepEqual(fs.readFileSync(savedByOperator), saved);
    assert.equal(fs.readFileSync(temporary, 'utf8'), 'unrelated file at the same path');
});

test('the SDK refuses grant ACLs on existing macOS profile directories and snapshots', {
    skip: process.platform !== 'darwin'
}, async (t) => {
    const options = setup(t, () => assert.fail('storage ACL must be checked before launch'));
    const storage = ensureProfileStorage('owner', options.profilesDir);
    const committed = fs.readFileSync(storage.storageStatePath);
    const error = { code: 'PRIVATE_STORAGE_ACL_ERROR' };
    execFileSync('/bin/chmod', ['+a', 'group:everyone allow search,list', storage.profileDir]);
    assert.throws(() => ensureProfileStorage('owner', options.profilesDir), error);
    await assert.rejects(startProfile('owner', options), error);
    execFileSync('/bin/chmod', ['-N', storage.profileDir]);

    execFileSync('/bin/chmod', ['+a', 'group:everyone allow read', storage.storageStatePath]);
    assert.throws(() => loadStorageState('owner', options.profilesDir), error);
    await assert.rejects(startProfile('owner', options), error);
    assert.equal(fs.statSync(storage.storageStatePath).mode & 0o777, 0o600);
    assert.deepEqual(fs.readFileSync(storage.storageStatePath), committed);
});

test('macOS snapshot saves reject grant ACLs before writing a temporary file and preserve deny ACLs', {
    skip: process.platform !== 'darwin'
}, async (t) => {
    const options = setup(t);
    const session = await startProfile('owner', options);
    const { storageStatePath } = session;
    const committed = fs.readFileSync(storageStatePath);
    session.context.nextState.cookies = [{ name: 'fixture', value: 'updated' }];
    const error = { code: 'PRIVATE_STORAGE_ACL_ERROR' };
    const files = fs.readdirSync(path.dirname(storageStatePath));

    execFileSync('/bin/chmod', ['+a', 'group:everyone deny execute', storageStatePath]);
    await assert.rejects(saveProfileStorageState('owner', session.context), error);
    const listing = execFileSync('/bin/ls', ['-ledbn', storageStatePath], { encoding: 'utf8' });
    assert.match(listing, /deny execute/);
    execFileSync('/bin/chmod', ['-N', storageStatePath]);

    const open = fs.openSync;
    const tempFiles = [];
    const opened = t.mock.method(fs, 'openSync', (file, flags, mode) => {
        const fd = open(file, flags, mode);
        if (flags === 'wx' && typeof file === 'string' && file.endsWith('.tmp')) {
            tempFiles.push(file);
            execFileSync('/bin/chmod', ['+a', 'group:everyone allow read', file]);
        }
        return fd;
    });
    const writes = t.mock.method(fs, 'writeFileSync', fs.writeFileSync);
    try {
        await assert.rejects(saveProfileStorageState('owner', session.context), error);
        assert.equal(tempFiles.length, 1);
        assert.equal(writes.mock.callCount(), 0);
        assert.deepEqual(fs.readFileSync(storageStatePath), committed);
        assert.deepEqual(fs.readdirSync(path.dirname(storageStatePath)), files);
    } finally {
        opened.mock.restore();
        writes.mock.restore();
    }
    assert.equal(await stopProfile('owner', options), true);
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

    runOwnerProcess('persist-and-exit', secondRoot, 76);
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

test('an unconfirmed native exit remains blocked after the controller process exits', async (t) => {
    let launches = 0;
    const options = setup(t, () => { launches += 1; });
    const profileId = 'owner';
    runOwnerProcess('disconnect-and-exit', options.profilesDir);
    const unconfirmed = { code: 'ERR_CAMOUFOX_NATIVE_EXIT_UNCONFIRMED' };
    await assert.rejects(startProfile(profileId, options), unconfirmed);
    assert.equal(await stopProfile(profileId, options), false);
    await assert.rejects(deleteProfile(profileId, options), unconfirmed);
    assert.throws(() => ensureProfileStorage(profileId, options.profilesDir), unconfirmed);
    assert.equal(launches, 0);
    assert.ok(loadStorageState(profileId, options.profilesDir));

    archiveReviewedFixtureLease(t, options.profilesDir);
    await startProfile(profileId, options);
    assert.equal(launches, 1);
    assert.equal(await stopProfile(profileId, options), true);
});

test('dedicated resources retain the lease across controller interruption and guard write failure at stop', async (t) => {
    const { profilesDir } = setup(t);
    for (const [operation, exitCode] of [['interrupt-launch', 74], ['disconnect-with-unwritable-guard', 0]]) {
        await t.test(operation, () => {
            const root = path.join(profilesDir, operation);
            fs.mkdirSync(root, { mode: 0o700 });
            runOwnerProcess(operation, root, exitCode);
            const directory = path.join(root, PROFILE_LEASE_DIRECTORY, 'owner');
            const original = fs.readdirSync(directory).sort();
            assert.ok(original.includes('~native-exit-unconfirmed'));
            assert.throws(() => ensureProfileStorage('owner', root), {
                code: 'ERR_CAMOUFOX_NATIVE_EXIT_UNCONFIRMED'
            });
            assert.deepEqual(fs.readdirSync(directory).sort(), original);
        });
    }
});

test('a dedicated resource is refused until its exit guard can be stored', async (t) => {
    let launches = 0;
    const options = setup(t, () => { launches += 1; });
    const directory = path.join(options.profilesDir, PROFILE_LEASE_DIRECTORY, 'owner');
    const marker = path.join(directory, '~native-exit-unconfirmed');
    const open = fs.openSync;
    const full = t.mock.method(fs, 'openSync', (file, ...args) => {
        if (file === marker && args[0] === 'wx') {
            throw Object.assign(new Error('fixture could not create exit guard'), { code: 'ENOSPC' });
        }
        return open(file, ...args);
    });
    try {
        await assert.rejects(startProfile('owner', options), { code: 'ENOSPC' });
        assert.equal(launches, 0);
        assert.equal(fs.existsSync(directory), false);
    } finally {
        full.mock.restore();
    }
    await startProfile('owner', options);
    assert.equal(launches, 1);
    assert.ok(fs.existsSync(marker));
    assert.equal(await stopProfile('owner', options), true);
    assert.equal(fs.existsSync(directory), false);
});

test('a new process removes only the abandoned HAR scratch under the recovered lease', async (t) => {
    const options = setup(t);
    runOwnerProcess('abandon-har', options.profilesDir);
    const nativeDir = path.join(options.profilesDir, 'owner', '.native');
    const scratch = fs.readdirSync(nativeDir).find((name) => fs.existsSync(path.join(nativeDir, name, 'payloads')));
    assert.ok(scratch);
    const note = path.join(nativeDir, 'private-note.txt');
    fs.writeFileSync(note, 'Unrelated local fixture', { mode: 0o600 });

    await assert.rejects(startProfile('owner', options), { code: 'ERR_CAMOUFOX_NATIVE_EXIT_UNCONFIRMED' });
    assert.ok(fs.existsSync(path.join(nativeDir, scratch)));
    archiveReviewedFixtureLease(t, options.profilesDir);
    await startProfile('owner', options);
    assert.equal(fs.existsSync(path.join(nativeDir, scratch)), false);
    assert.equal(fs.readFileSync(note, 'utf8'), 'Unrelated local fixture');
});
