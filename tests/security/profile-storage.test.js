import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { formatCliReport, queryProfileTraffic } from '../../scripts/query-traffic-attribution.js';
import {
    createProfile,
    deleteProfile,
    getActiveProfileIds,
    getProfile,
    getProfileDir,
    saveProfileStorageState,
    setCamoufoxModule,
    startProfile,
    stopAllActiveProfiles,
    stopProfile,
    unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';

const OPTIONS = {
    enablePortScanProtection: false,
    enableGpuPerformanceScaling: false,
    neckoMozLog: false,
    recordHar: false,
    recordTraffic: false,
    sslKeyLog: false
};

function setup(t, beforeLaunch = async () => {}) {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'profile-storage-test-')));
    const launches = [];
    setCamoufoxModule({
        async Camoufox(options) {
            const launch = { options, contexts: [] };
            launches.push(launch);
            await beforeLaunch();
            let connected = true;
            const browser = Object.assign(new EventEmitter(), {
                isConnected: () => connected,
                async close() {
                    connected = false;
                    for (const context of launch.contexts) await context.close();
                    browser.emit('disconnected');
                },
                async newContext(contextOptions) {
                    const pages = [];
                    let closed = false;
                    const context = Object.assign(new EventEmitter(), {
                        options: contextOptions,
                        browser: () => browser,
                        pages: () => pages,
                        isClosed: () => closed,
                        state: { cookies: [], origins: [] },
                        async newPage() {
                            const page = Object.assign(new EventEmitter(), {
                                context: () => context,
                                isClosed: () => closed,
                                url: () => 'about:blank'
                            });
                            pages.push(page);
                            context.emit('page', page);
                            return page;
                        },
                        async storageState(...args) {
                            assert.equal(args.length, 0);
                            return context.state;
                        },
                        async close() {
                            if (closed) return;
                            closed = true;
                            context.emit('close');
                        }
                    });
                    launch.contexts.push(context);
                    return context;
                }
            });
            return browser;
        }
    });
    t.after(async () => {
        await stopAllActiveProfiles();
        unregisterProcessCleanupHooks();
        setCamoufoxModule();
        fs.rmSync(root, { force: true, recursive: true });
    });
    return { root, launches };
}

function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function assertMode(filePath, expected) {
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(filePath).mode & 0o777, expected, filePath);
    }
}

test('pending starts, active sessions and state persistence are scoped to canonical roots', async (t) => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const { root, launches } = setup(t, () => gate);
    const firstRoot = path.join(root, 'first');
    const secondRoot = path.join(root, 'second');
    const aliasRoot = path.join(root, 'alias');
    fs.mkdirSync(firstRoot);
    if (process.platform !== 'win32') fs.chmodSync(firstRoot, 0o751);
    fs.symlinkSync(firstRoot, aliasRoot, process.platform === 'win32' ? 'junction' : 'dir');

    const starts = [
        startProfile('same-id', { ...OPTIONS, profilesDir: firstRoot, useSharedBrowser: true }),
        startProfile('same-id', { ...OPTIONS, profilesDir: aliasRoot, useSharedBrowser: true }),
        startProfile('same-id', { ...OPTIONS, profilesDir: secondRoot, useSharedBrowser: true })
    ];
    release();
    const [first, alias, second] = await Promise.all(starts);
    assert.equal(launches.length, 2);
    assert.equal(first, alias);
    assert.notEqual(first.context, second.context);
    assert.equal(first.profilesDir, firstRoot);
    assert.equal(second.profilesDir, secondRoot);

    first.context.state.cookies = [{ name: 'fixture-root', value: 'first' }];
    second.context.state.cookies = [{ name: 'fixture-root', value: 'second' }];
    await assert.rejects(
        saveProfileStorageState('same-id', first.context, secondRoot),
        /does not belong/
    );
    await assert.rejects(saveProfileStorageState('other-id', first.context), /does not belong/);
    await saveProfileStorageState('same-id', null, aliasRoot);
    await saveProfileStorageState('same-id', second.context);
    assert.equal(readJson(first.storageStatePath).cookies[0].value, 'first');
    assert.equal(readJson(second.storageStatePath).cookies[0].value, 'second');

    await stopProfile('same-id', { profilesDir: path.join(root, 'unrelated') });
    assert.equal(first.browser.isConnected(), true);
    assert.equal(second.browser.isConnected(), true);
    await stopProfile('same-id', { profilesDir: aliasRoot });
    assert.equal(first.browser.isConnected(), false);
    assert.equal(second.browser.isConnected(), true);
    await assert.rejects(saveProfileStorageState('same-id', first.context), /does not belong/);
    assert.deepEqual(getActiveProfileIds(), ['same-id']);

    second.context.state.cookies[0].value = 'second-after-stop';
    const stopped = await stopAllActiveProfiles();
    assert.equal(stopped.stoppedCount, 1);
    assert.equal(second.browser.isConnected(), false);
    assert.equal(readJson(second.storageStatePath).cookies[0].value, 'second-after-stop');
    assertMode(firstRoot, 0o751);
});

test('managed proxy launch, native logs and deletion stay scoped to the selected profile store', async (t) => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const { root, launches } = setup(t, () => gate);
    const origin = 'https://controlled-egress.invalid:8443';
    const originalOrigin = process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN;
    process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN = origin;
    t.after(() => {
        if (originalOrigin === undefined) delete process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN;
        else process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN = originalOrigin;
    });

    const profileId = 'same-managed-id';
    const stores = ['first', 'second'].map((name) => ({
        name,
        options: {
            ...OPTIONS,
            profilesDir: path.join(root, name),
            portScanProtection: { mode: 'managed-proxy' },
            enablePortScanProtection: true,
            proxy: { server: origin, username: name, password: `synthetic-${name}` },
            recordTraffic: true,
            sslKeyLog: true,
            neckoMozLog: true
        }
    }));
    const firstOptions = stores[0].options;
    const secondOptions = stores[1].options;
    const firstStart = startProfile(profileId, firstOptions);
    const secondStart = startProfile(profileId, secondOptions);
    const rejectedReuse = assert.rejects(
        startProfile(profileId, { ...firstOptions, proxy: secondOptions.proxy }),
        { code: 'ERR_CAMOUFOX_MANAGED_EGRESS_BINDING' }
    );
    release();
    const [first, second] = await Promise.all([firstStart, secondStart, rejectedReuse]);
    await assert.rejects(
        startProfile(profileId, { ...firstOptions, portScanProtection: { mode: 'url-only' } }),
        { code: 'ERR_CAMOUFOX_MANAGED_EGRESS_BINDING' }
    );
    for (const [session, { name, options }] of [[first, stores[0]], [second, stores[1]]]) {
        const launch = launches.find(({ contexts }) => contexts.includes(session.context));
        assert.deepEqual(launch.options.proxy, options.proxy);
        const nativeDir = path.join(options.profilesDir, profileId, '.native');
        assert.equal(launch.options.env.SSLKEYLOGFILE, path.join(nativeDir, 'sslkeylog.txt'));
        assert.equal(launch.options.env.MOZ_LOG_FILE, path.join(nativeDir, 'necko-pre-tls.moz_log'));
        session.context.state.cookies = [{ name: 'fixture-root', value: name }];
        assert.equal(await saveProfileStorageState(profileId, session.context), session.storageStatePath);
        assert.equal(readJson(session.storageStatePath).cookies[0].value, name);
    }

    assert.equal(await deleteProfile(profileId, stores[0].options), true);
    assert.equal(first.browser.isConnected(), false);
    assert.equal(second.browser.isConnected(), true);
    assert.equal(fs.existsSync(first.storageStatePath), false);
    assert.equal(readJson(second.storageStatePath).cookies[0].value, 'second');
    assert.equal(await stopProfile(profileId, stores[1].options), true);
});

test('a body-off request cannot reuse a pending or active body-recording session', async (t) => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const { root } = setup(t, () => gate);
    const options = { ...OPTIONS, profilesDir: root, recordHar: true, recordBodies: true };

    const start = startProfile('profile', options);
    const cannotReuse = assert.rejects(
        startProfile('profile', { ...options, recordBodies: false }),
        /before disabling body recording/
    );
    release();
    await Promise.all([start, cannotReuse]);
    await assert.rejects(
        startProfile('profile', { ...options, recordBodies: false }),
        /before disabling body recording/
    );
    assert.equal(await stopProfile('profile', options), true);

    const restarted = await startProfile('profile', { ...options, recordBodies: false });
    assert.equal(restarted.browser.isConnected(), true);
});

test('invalid IDs fail validation and deletion requires matching direct-child metadata', async (t) => {
    const { root } = setup(t);
    for (const id of ['', '.', '..', 'two/names', 'ambiguous name', undefined]) {
        assert.throws(() => getProfileDir(id, root), /Invalid Camoufox profile ID/);
    }

    const options = { profilesDir: root };
    const first = await createProfile('first', null, { ...options, profileId: 'first' });
    const sibling = await createProfile('sibling', null, { ...options, profileId: 'sibling' });
    const unverified = path.join(root, 'unverified');
    fs.mkdirSync(unverified);
    await assert.rejects(deleteProfile('unverified', options), { code: 'ENOENT' });
    fs.writeFileSync(path.join(unverified, 'profile.json'), JSON.stringify({
        id: 'unverified',
        profileId: 'sibling'
    }));
    await assert.rejects(deleteProfile('unverified', options), /metadata does not match ID/);

    const alias = path.join(root, 'alias');
    fs.symlinkSync(sibling.profileDir, alias, process.platform === 'win32' ? 'junction' : 'dir');
    await assert.rejects(deleteProfile('alias', options), /direct Camoufox profile directory/);

    assert.equal(await deleteProfile('first', options), true);
    assert.equal(fs.existsSync(first.profileDir), false);
    assert.equal(fs.existsSync(unverified), true);
    assert.equal(fs.existsSync(sibling.profileDir), true);
    assert.equal((await getProfile('sibling', options)).id, 'sibling');
});

test('shared processes suppress inherited native diagnostics and isolate complete legacy captures', async (t) => {
    const { root, launches } = setup(t);
    const options = {
        ...OPTIONS,
        profilesDir: root,
        useSharedBrowser: true,
        sslKeyLog: true,
        neckoMozLog: true,
        recordTraffic: true
    };
    const legacyKeyPath = path.join(root, '_shared_sslkeylog.txt');
    fs.writeFileSync(legacyKeyPath, 'synthetic process-wide fixture\n');
    const legacyFiles = {
        '.private/sslkeylog.txt.1': 'synthetic legacy fixture\n',
        '.private/necko-pre-tls.moz_log.child-1': 'synthetic native fixture\n',
        'attribution-index.json': '{"fixture":"preserved manifest"}\n'
    };
    const { profileDir } = await createProfile('profile-a', null, { ...options, profileId: 'profile-a' });
    fs.mkdirSync(path.join(profileDir, 'traffic', '.private'));
    for (const [name, value] of Object.entries(legacyFiles)) {
        fs.writeFileSync(path.join(profileDir, 'traffic', name), value);
    }

    const inherited = {
        SSLKEYLOGFILE: legacyKeyPath,
        MOZ_LOG: 'nsHttp:5',
        MOZ_LOG_FILE: path.join(profileDir, 'traffic', 'necko-pre-tls.moz_log'),
        NSPR_LOG_MODULES: 'nsHttp:5',
        NSPR_LOG_FILE: path.join(profileDir, 'traffic', 'necko-fallback.log')
    };
    const original = Object.fromEntries(Object.keys(inherited).map((key) => [key, process.env[key]]));
    Object.assign(process.env, inherited);
    t.after(() => {
        for (const [key, value] of Object.entries(original)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
        }
    });

    const first = await startProfile('profile-a', { ...options, env: inherited });
    const second = await startProfile('profile-b', { ...options, launchOptions: { env: inherited } });
    assert.equal(launches.length, 1);
    for (const key of Object.keys(inherited)) assert.equal(launches[0].options.env[key], '');

    await stopAllActiveProfiles();
    for (const session of [first, second]) {
        assert.equal(session.trafficPaths.sslKeyLogPath, null);
        assert.equal(session.trafficPaths.neckoMozLogPath, null);
        const files = fs.readdirSync(session.trafficPaths.trafficDir);
        assert.equal(files.some((name) => name === '.private' || name.includes('sslkeylog') || name.includes('moz_log')), false);
        const index = readJson(session.trafficPaths.attributionIndexPath);
        assert.equal(index.artifacts.sslKeyLogPath, null);
        assert.equal(index.artifacts.neckoMozLogPath, null);
    }

    assertMode(legacyKeyPath, 0o600);
    assert.equal(fs.readFileSync(legacyKeyPath, 'utf8'), 'synthetic process-wide fixture\n');
    const nativeDir = path.join(profileDir, '.native');
    const [preserved] = fs.readdirSync(nativeDir);
    const preservedDir = path.join(nativeDir, preserved, 'traffic');
    assertMode(preservedDir, 0o700);
    for (const [name, value] of Object.entries(legacyFiles)) {
        assert.equal(fs.readFileSync(path.join(preservedDir, name), 'utf8'), value);
    }
});

test('profile state, metadata, ledger and dedicated native paths use owner-only modes', async (t) => {
    const { root, launches } = setup(t);
    const profilesDir = path.join(root, 'profiles');
    const options = { ...OPTIONS, profilesDir, sslKeyLog: true, neckoMozLog: true };
    const profile = await createProfile('local profile', null, { ...options, profileId: 'local' });
    const metadataPath = path.join(profile.profileDir, 'profile.json');
    const ledgerPath = path.join(profile.profileDir, 'fingerprint-ledger.json');
    const expectedDirectories = ['.', 'traffic', 'traffic/payloads']
        .map((suffix) => path.resolve(profile.profileDir, suffix));
    for (const dir of [profilesDir, ...expectedDirectories]) assertMode(dir, 0o700);
    for (const file of [metadataPath, profile.storageStatePath]) assertMode(file, 0o600);

    if (process.platform !== 'win32') {
        fs.chmodSync(profile.profileDir, 0o755);
        fs.chmodSync(metadataPath, 0o644);
        fs.chmodSync(profile.storageStatePath, 0o644);
    }
    fs.writeFileSync(ledgerPath, '{"entries":[]}', { mode: 0o644 });
    const session = await startProfile('local', options);
    const { sslKeyLogPath, neckoMozLogPath } = session.trafficPaths;
    assert.equal(sslKeyLogPath, path.join(profile.profileDir, '.native', 'sslkeylog.txt'));
    assert.equal(neckoMozLogPath, path.join(profile.profileDir, '.native', 'necko-pre-tls.moz_log'));
    assert.equal(launches[0].options.env.SSLKEYLOGFILE, sslKeyLogPath);
    assert.equal(launches[0].options.env.MOZ_LOG_FILE, neckoMozLogPath);

    assertMode(profile.profileDir, 0o700);
    assertMode(path.dirname(sslKeyLogPath), 0o700);
    for (const file of [metadataPath, profile.storageStatePath, ledgerPath, sslKeyLogPath, neckoMozLogPath]) {
        assertMode(file, 0o600);
    }
    const childLog = `${neckoMozLogPath}.child-1`;
    fs.writeFileSync(childLog, 'test-only native note', { mode: 0o644 });
    assert.equal(await stopProfile('local', options), true);
    assertMode(childLog, 0o600);
    assertMode(profile.storageStatePath, 0o600);
});

test('HAR-only capture uses the sanitized exporter and obeys body-off on both browser paths', async (t) => {
    const { root, launches } = setup(t);
    for (const useSharedBrowser of [false, true]) {
        const profileId = useSharedBrowser ? 'shared-har' : 'dedicated-har';
        const harPath = path.join(root, profileId, 'traffic', 'metadata.har');
        const legacyOptions = { path: harPath, content: 'attach' };
        const options = {
            ...OPTIONS,
            profilesDir: root,
            recordBodies: false,
            recordHar: true,
            useSharedBrowser,
            contextOptions: { recordHar: legacyOptions },
            launchOptions: { recordHar: legacyOptions }
        };
        const session = await startProfile(profileId, options);
        const launch = launches.at(-1);
        assert.equal(launch.options.recordHar, undefined);
        assert.equal(launch.contexts[0].options.recordHar, undefined);
        assert.equal(session.trafficRecorder, null);
        assert.equal(session.trafficPaths.harPath, harPath);

        let bodyReads = 0;
        const request = {
            method: () => 'POST',
            url: () => 'https://profile.invalid/action?access_token=fixture-query-secret',
            resourceType: () => 'fetch',
            headers: () => ({ cookie: 'session=fixture-cookie-secret' }),
            postDataBuffer: () => {
                bodyReads += 1;
                return Buffer.from('fixture-post-secret');
            }
        };
        const response = {
            request: () => request,
            url: request.url,
            status: () => 204,
            statusText: () => 'No Content',
            headers: () => ({ 'set-cookie': 'session=fixture-set-cookie-secret' }),
            async body() {
                bodyReads += 1;
                return Buffer.from('fixture-response-secret');
            }
        };
        session.context.emit('request', request);
        session.context.emit('response', response);
        session.context.emit('requestfinished', request);

        assert.equal(await stopProfile(profileId, options), true);
        assert.equal(bodyReads, 0);
        assertMode(harPath, 0o600);
        const serialized = fs.readFileSync(harPath, 'utf8');
        const [entry] = JSON.parse(serialized).log.entries;
        assert.equal(entry.request.method, 'POST');
        assert.equal(entry.response.status, 204);
        assert.doesNotMatch(serialized, /fixture-(?:query|cookie|set-cookie|post|response)-secret/);
        assert.deepEqual(fs.readdirSync(path.join(root, profileId, 'traffic')).sort(), ['metadata.har', 'payloads']);
        assert.deepEqual(fs.readdirSync(path.join(root, profileId, '.native')), []);
    }
});

test('dedicated profile integrity checks declared native logs after browser shutdown', async (t) => {
    const { root } = setup(t);
    const profile = 'native-integrity';
    const options = {
        ...OPTIONS,
        profilesDir: root,
        useSharedBrowser: false,
        recordTraffic: true,
        sslKeyLog: true,
        neckoMozLog: true
    };
    const session = await startProfile(profile, options);
    const { trafficDir, sslKeyLogPath, neckoMozLogPath, attributionIndexPath } = session.trafficPaths;
    session.context.on('close', () => {
        fs.appendFileSync(sslKeyLogPath, `CLIENT_RANDOM ${'a'.repeat(64)} ${'b'.repeat(96)}\n`);
        fs.appendFileSync(neckoMozLogPath, 'synthetic shutdown entry\n');
    });
    assert.equal(await stopProfile(profile, options), true);

    const index = readJson(attributionIndexPath);
    assert.equal(index.artifacts.sslKeyLogPath, null);
    assert.equal(index.artifacts.neckoMozLogPath, null);
    assert.equal(index.integrity.nativeArtifacts.sslKeyLog.bytes, fs.statSync(sslKeyLogPath).size);
    assert.equal(index.integrity.nativeArtifacts.neckoMozLog.bytes, fs.statSync(neckoMozLogPath).size);

    const verify = (name = profile) => queryProfileTraffic({
        profilesDir: root, profile: name, verifyIntegrity: true
    });
    const full = verify();
    assert.equal(full.scope, 'profile');
    assert.equal(full.valid, true);
    assert.equal(full.sslKeyLog.entryCount, 1);
    assert.equal(full.neckoMozLog.lineCount, 1);

    for (const filePath of [sslKeyLogPath, neckoMozLogPath]) {
        const bytes = fs.readFileSync(filePath);
        fs.unlinkSync(filePath);
        const missing = verify();
        assert.equal(missing.scope, 'profile');
        assert.equal(missing.valid, false);
        assert.ok(missing.errors.includes(`Missing ${path.basename(filePath)} on disk`));
        fs.writeFileSync(filePath, bytes, { mode: 0o600 });
    }
    const capture = queryProfileTraffic({ trafficDir, verifyIntegrity: true });
    assert.equal(capture.scope, 'capture');
    assert.equal(capture.valid, true);
    assert.deepEqual([...capture.unverifiedNativeArtifacts].sort(), ['necko-pre-tls.moz_log', 'sslkeylog.txt']);
    assert.match(formatCliReport(capture), /Unverified profile files/);

    const disabled = { ...options, sslKeyLog: false, neckoMozLog: false };
    const noLogs = await startProfile('native-disabled', disabled);
    assert.equal(await stopProfile('native-disabled', disabled), true);
    assert.equal(readJson(noLogs.trafficPaths.attributionIndexPath).integrity.nativeArtifacts, undefined);
    assert.equal(verify('native-disabled').scope, 'profile');
    assert.equal(verify('native-disabled').valid, true);
});
