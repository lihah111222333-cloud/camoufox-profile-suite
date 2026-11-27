import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    setCamoufoxModule, startProfile, stopAllActiveProfiles, stopProfile, unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import { CamoufoxTrafficRecorder, verifyTrafficIntegrity } from '../../src/camoufox/traffic-recorder.js';

function mockLauncher(launches = []) {
    return {
        async Camoufox(options) {
            launches.push(options);
            let connected = true;
            let context;
            const browser = Object.assign(new EventEmitter(), {
                isConnected: () => connected,
                async close() {
                    connected = false;
                    await context?.close();
                    browser.emit('disconnected');
                },
                async newContext() {
                    let closed = false;
                    const page = Object.assign(new EventEmitter(), {
                        context: () => context,
                        isClosed: () => closed,
                        url: () => 'about:blank'
                    });
                    context = Object.assign(new EventEmitter(), {
                        browser: () => browser,
                        pages: () => [page],
                        isClosed: () => closed,
                        storageState: async () => ({ cookies: [], origins: [] }),
                        async close() {
                            if (closed) return;
                            closed = true;
                            context.emit('close');
                        }
                    });
                    return context;
                }
            });
            return browser;
        }
    };
}

function managedFixture(t) {
    const profilesDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'native-generation-'));
    const launches = [];
    setCamoufoxModule(mockLauncher(launches));
    t.after(async () => {
        await stopAllActiveProfiles();
        unregisterProcessCleanupHooks();
        setCamoufoxModule();
        fs.rmSync(profilesDir, { recursive: true, force: true });
    });
    const profileId = 'native-fixture';
    const options = {
        profilesDir,
        enablePortScanProtection: false,
        enableGpuPerformanceScaling: false,
        useSharedBrowser: false,
        recordHar: false,
        recordTraffic: true,
        recordBodies: false,
        recordWireLog: false,
        sslKeyLog: false,
        neckoMozLog: true
    };
    const open = (overrides = {}) => startProfile(profileId, { ...options, ...overrides });
    const stop = () => stopProfile(profileId, options);
    return { open, stop, launches, options, profileId };
}

test('managed startup verifies closed native generations before browser launch and preserves them through rotation', async (t) => {
    const { open, stop, launches } = managedFixture(t);
    const first = await open();
    const { trafficDir, attributionIndexPath, neckoMozLogPath: firstPath } = first.trafficPaths;
    const nativeDir = path.dirname(firstPath);
    const verify = (authorized = true) => verifyTrafficIntegrity(trafficDir, authorized ? { nativeDir } : {});
    const readIndex = () => JSON.parse(fs.readFileSync(attributionIndexPath, 'utf8')).integrity;

    assert.equal((await first.trafficRecorder.flushSummary({ nativeLogsClosed: true }))
        .integrity.nativeArtifacts.neckoMozLog.closed, false);
    await first.trafficRecorder.stop();
    await first.trafficRecorder.flushSummary();
    assert.equal(readIndex().nativeArtifacts.neckoMozLog.closed, false);
    first.context.on('close', () => fs.appendFileSync(firstPath, 'synthetic first generation\n'));
    assert.equal(await stop(), true);
    const firstGeneration = readIndex().nativeArtifacts.neckoMozLog;
    assert.equal(firstGeneration.closed, true);
    assert.equal(verify().valid, true);
    const firstBytes = fs.readFileSync(firstPath);

    fs.appendFileSync(firstPath, 'invalid closed generation suffix\n');
    await assert.rejects(open(), /SHA-256 mismatch|byte length mismatch/);
    assert.equal(launches.length, 1);
    fs.writeFileSync(firstPath, firstBytes);

    fs.unlinkSync(firstPath);
    await assert.rejects(open({ recordTraffic: false }), /Missing necko-pre-tls\.moz_log on disk/);
    assert.equal(launches.length, 1);
    fs.writeFileSync(firstPath, firstBytes, { mode: 0o600 });

    const second = await open();
    const secondPath = second.trafficPaths.neckoMozLogPath;
    assert.equal(path.dirname(secondPath), nativeDir);
    assert.notEqual(secondPath, firstPath);
    assert.equal(launches[1].env.MOZ_LOG_FILE, secondPath);
    assert.deepEqual(readIndex().nativeArtifacts.neckoMozLog.previous, [firstGeneration]);
    const pending = fs.readFileSync(attributionIndexPath);
    assert.deepEqual((await first.trafficRecorder.flushSummary()).integrity.nativeArtifacts.neckoMozLog, firstGeneration);
    assert.deepEqual(fs.readFileSync(attributionIndexPath), pending);
    assert.deepEqual(verify().unverifiedNativeArtifacts, [path.basename(secondPath)]);
    second.context.on('close', () => fs.appendFileSync(secondPath, 'synthetic second generation\n'));
    assert.equal(await stop(), true);
    const secondGeneration = readIndex().nativeArtifacts.neckoMozLog;
    assert.equal(secondGeneration.closed, true);
    assert.deepEqual(verify().unverifiedNativeArtifacts, []);
    assert.equal(verify().valid, true);
    assert.deepEqual(fs.readFileSync(firstPath), firstBytes);

    const disabled = await open({ neckoMozLog: false });
    assert.equal(disabled.trafficPaths.neckoMozLogPath, null);
    assert.equal(await stop(), true);
    assert.deepEqual(readIndex().nativeArtifacts.neckoMozLog, secondGeneration);
    assert.deepEqual(verify(false).unverifiedNativeArtifacts.sort(), [path.basename(firstPath), path.basename(secondPath)].sort());

    const withoutRecording = await open({ recordTraffic: false });
    assert.notEqual(withoutRecording.trafficPaths.neckoMozLogPath, firstPath);
    assert.notEqual(withoutRecording.trafficPaths.neckoMozLogPath, secondPath);
    assert.equal(await stop(), true);
    assert.deepEqual(readIndex().nativeArtifacts.neckoMozLog, secondGeneration);
    assert.equal(verify().valid, true);

    fs.unlinkSync(firstPath);
    assert.equal(verify().valid, false);
    await assert.rejects(open({ neckoMozLog: false }), /Missing necko-pre-tls\.moz_log on disk/);
    assert.equal(launches.length, 4);
});

test('failed native permission and summary operations leave an owned, retryable cleanup', async (t) => {
    const { open, stop } = managedFixture(t);
    const first = await open();
    const { trafficDir, attributionIndexPath, neckoMozLogPath } = first.trafficPaths;
    const sidecar = `${neckoMozLogPath}.child-1`;
    fs.writeFileSync(sidecar, 'synthetic native fixture\n', { mode: 0o644 });

    const lstat = fs.lstatSync;
    fs.lstatSync = (target, ...args) => {
        if (target === sidecar) throw Object.assign(new Error('Fixture permission failure'), { code: 'EIO' });
        return lstat(target, ...args);
    };
    try {
        assert.equal(await stop(), false);
    } finally {
        fs.lstatSync = lstat;
    }
    assert.equal(first.browser.isConnected(), false);
    assert.throws(() => new CamoufoxTrafficRecorder({ trafficDir }), { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });

    const rename = fs.renameSync;
    fs.renameSync = (from, to) => {
        if (to === attributionIndexPath) throw Object.assign(new Error('Fixture summary failure'), { code: 'EIO' });
        return rename(from, to);
    };
    try {
        assert.equal(await stop(), false);
    } finally {
        fs.renameSync = rename;
    }
    assert.equal(await stop(), true);
    assert.equal(verifyTrafficIntegrity(trafficDir, { nativeDir: path.dirname(neckoMozLogPath) }).valid, true);
    await open();
    assert.equal(await stop(), true);
});

test('a terminal recorder write failure reports incomplete cleanup and releases the writer', async (t) => {
    const { open, stop } = managedFixture(t);
    const session = await open();
    const recorder = session.trafficRecorder;
    recorder.setStep('synthetic retained checkpoint');
    await recorder.flushSummary();

    const write = fs.writeFileSync;
    fs.writeFileSync = (target, data, ...args) => {
        if (typeof target === 'number' && typeof data === 'string' && data.includes('synthetic terminal fault')) {
            throw Object.assign(new Error('Fixture ledger write failed'), { code: 'EIO' });
        }
        return write(target, data, ...args);
    };
    try {
        recorder.setStep('synthetic terminal fault');
    } finally {
        fs.writeFileSync = write;
    }
    assert.equal(await stop(), false);
    assert.equal(session.browser.isConnected(), false);
    const next = await open();
    assert.notEqual(next, session);
    assert.equal(await stop(), true);
});

function observeSyntheticRequest(session) {
    const request = {
        method: () => 'GET',
        url: () => 'https://fixture.invalid/resource',
        resourceType: () => 'fetch',
        headers: () => ({})
    };
    session.context.emit('request', request);
    session.context.emit('response', {
        request: () => request,
        url: request.url,
        status: () => 204,
        statusText: () => 'No Content',
        headers: () => ({})
    });
    session.context.emit('requestfinished', request);
}

const HAR_ONLY = { recordTraffic: false, recordHar: true, neckoMozLog: false };

test('a failed HAR publication preserves the captured request and retries on stop', async (t) => {
    const { open, stop, options, profileId } = managedFixture(t);
    const session = await open(HAR_ONLY);
    observeSyntheticRequest(session);
    const { harPath } = session.trafficPaths;
    const scratch = path.join(options.profilesDir, profileId, '.native', '~har-scratch');
    fs.mkdirSync(harPath);

    assert.equal(await stop(), false);
    assert.equal(session.browser.isConnected(), false);
    assert.equal(fs.lstatSync(harPath).isDirectory(), true);
    assert.ok(fs.statSync(path.join(scratch, 'traffic.ndjson')).size > 0);
    assert.ok(fs.statSync(path.join(scratch, 'attribution-index.json')).size > 0);
    fs.rmdirSync(harPath);
    await assert.rejects(open({ ...HAR_ONLY, recordHar: false }), { code: 'ERR_CAMOUFOX_HAR_EXPORT_PENDING' });
    assert.equal(fs.existsSync(harPath), false);

    assert.equal(await stop(), true);
    const [entry] = JSON.parse(fs.readFileSync(harPath, 'utf8')).log.entries;
    assert.equal(entry.request.url, 'https://fixture.invalid/resource');
    assert.equal(entry.response.status, 204);
    assert.equal(fs.existsSync(scratch), false);
});

test('an explicit stop recovers a marked HAR after a process exits with publication pending', async (t) => {
    const { open, stop, options, profileId, launches } = managedFixture(t);
    const clientModule = new URL('../../src/camoufox/client.js', import.meta.url).href;
    const profileDir = path.join(options.profilesDir, profileId);
    const harPath = path.join(profileDir, 'traffic', 'selected.har');
    const scratch = path.join(profileDir, '.native', '~har-scratch');
    const child = `
        import assert from 'node:assert/strict';
        import { EventEmitter } from 'node:events';
        import fs from 'node:fs';
        import { setCamoufoxModule, startProfile, stopProfile } from ${JSON.stringify(clientModule)};
        const mockLauncher = ${mockLauncher.toString()};
        const observeSyntheticRequest = ${observeSyntheticRequest.toString()};
        const profileId = ${JSON.stringify(profileId)};
        const options = ${JSON.stringify({
            ...options, ...HAR_ONLY, contextOptions: { recordHar: { path: harPath } }
        })};
        setCamoufoxModule(mockLauncher());
        const session = await startProfile(profileId, options);
        observeSyntheticRequest(session);
        fs.mkdirSync(session.trafficPaths.harPath);
        assert.equal(await stopProfile(profileId, options), false);
    `;
    execFileSync(process.execPath, ['--input-type=module', '-e', child], { timeout: 10000 });
    const ledgerPath = path.join(scratch, 'traffic.ndjson');
    const original = fs.readFileSync(ledgerPath);
    fs.rmdirSync(harPath);

    await assert.rejects(open({ recordHar: false }), { code: 'ERR_CAMOUFOX_HAR_EXPORT_PENDING' });
    assert.equal(fs.existsSync(harPath), false);
    assert.deepEqual(fs.readFileSync(ledgerPath), original);
    assert.equal(launches.length, 0);

    assert.equal(await stop(), true);
    const [entry] = JSON.parse(fs.readFileSync(harPath, 'utf8')).log.entries;
    assert.equal(entry.request.url, 'https://fixture.invalid/resource');
    assert.equal(entry.response.status, 204);
    assert.equal(fs.existsSync(scratch), false);
});

test('only an owned legacy HAR scratch is removed on profile startup', async (t) => {
    const { open, stop, options, profileId } = managedFixture(t);
    const { trafficPaths } = await open({ ...HAR_ONLY, recordHar: false });
    assert.equal(await stop(), true);
    const nativeDir = path.join(options.profilesDir, profileId, '.native');
    fs.mkdirSync(nativeDir, { mode: 0o700, recursive: true });
    const owned = fs.mkdtempSync(path.join(nativeDir, 'har-'));
    const other = fs.mkdtempSync(path.join(nativeDir, 'har-'));
    const unknown = fs.mkdtempSync(path.join(nativeDir, 'har-'));
    fs.mkdirSync(path.join(unknown, 'payloads'), { mode: 0o700 });

    for (const [directory, id] of [[owned, profileId], [other, 'unrelated-profile']]) {
        const recorder = new CamoufoxTrafficRecorder({
            profileId: id,
            trafficDir: directory,
            trustedLocal: true,
            recordWireLog: false,
            harPath: trafficPaths.harPath
        });
        recorder.setStep('synthetic legacy HAR activity');
        await recorder.stop();
    }
    fs.unlinkSync(path.join(owned, 'attribution-index.json'));

    await open({ ...HAR_ONLY, recordHar: false });
    assert.equal(fs.existsSync(owned), false);
    assert.equal(fs.existsSync(other), true);
    assert.equal(fs.existsSync(unknown), true);
    assert.equal(await stop(), true);
});
