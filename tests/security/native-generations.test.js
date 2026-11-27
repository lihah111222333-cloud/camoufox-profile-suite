import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    createProfile, rollbackCreatedProfile, setCamoufoxModule, startProfile, stopAllActiveProfiles,
    stopProfile, unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import { CamoufoxTrafficRecorder, exportTrafficToHar, verifyTrafficIntegrity } from '../../src/camoufox/traffic-recorder.js';

function mockLauncher(launches = [], browsers = []) {
    return {
        async Camoufox(options) {
            launches.push(options);
            let connected = true;
            let context;
            const browser = Object.assign(new EventEmitter(), {
                isConnected: () => connected,
                disconnect() {
                    connected = false;
                    browser.emit('disconnected');
                },
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
            browsers.push(browser);
            return browser;
        }
    };
}

function managedFixture(t) {
    const profilesDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'native-generation-'));
    const launches = [];
    const browsers = [];
    setCamoufoxModule(mockLauncher(launches, browsers));
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
    return { open, stop, launches, browsers, options, profileId };
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

test('legacy HAR scratch stays intact when publication cannot be established', async (t) => {
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
    assert.equal(fs.existsSync(owned), true);
    assert.equal(fs.existsSync(other), true);
    assert.equal(fs.existsSync(unknown), true);
    assert.equal(await stop(), true);
});

test('a HAR-only checkpoint recovers recorded events from a previous process before its first stop', async (t) => {
    const { open, stop, options, profileId, launches } = managedFixture(t);
    const clientModule = new URL('../../src/camoufox/client.js', import.meta.url).href;
    const profileDir = path.join(options.profilesDir, profileId);
    const harPath = path.join(profileDir, 'traffic', 'interrupted.har');
    const scratch = path.join(profileDir, '.native', '~har-scratch');
    const ledgerPath = path.join(scratch, 'traffic.ndjson');
    const child = `
        import assert from 'node:assert/strict';
        import { EventEmitter } from 'node:events';
        import fs from 'node:fs';
        import { setCamoufoxModule, startProfile } from ${JSON.stringify(clientModule)};
        const mockLauncher = ${mockLauncher.toString()};
        const observeSyntheticRequest = ${observeSyntheticRequest.toString()};
        setCamoufoxModule(mockLauncher());
        const session = await startProfile(${JSON.stringify(profileId)}, ${JSON.stringify({
            ...options, ...HAR_ONLY, contextOptions: { recordHar: { path: harPath } }
        })});
        observeSyntheticRequest(session);
        const path = ${JSON.stringify(ledgerPath)};
        for (let attempt = 0; attempt < 50; attempt += 1) {
            if (fs.existsSync(path) && fs.readFileSync(path, 'utf8').trim().split('\\n').length === 3) break;
            await new Promise((resolve) => setTimeout(resolve, 10));
        }
        assert.equal(fs.readFileSync(path, 'utf8').trim().split('\\n').length, 3);
    `;
    execFileSync(process.execPath, ['--input-type=module', '-e', child], { timeout: 10000 });

    const indexPath = path.join(scratch, 'attribution-index.json');
    const originalIndex = fs.readFileSync(indexPath, 'utf8');
    const index = JSON.parse(originalIndex);
    assert.equal(index.harRecovery.ready, true);
    assert.equal(index.harRecovery.finalized, false);
    assert.equal(index.integrity.eventCount, 0);
    const original = fs.readFileSync(ledgerPath);
    await assert.rejects(open({ recordHar: false }), { code: 'ERR_CAMOUFOX_HAR_EXPORT_PENDING' });
    assert.deepEqual(fs.readFileSync(ledgerPath), original);
    assert.equal(launches.length, 0);

    index.harRecovery.storageGeneration = 'unrelated-generation';
    fs.writeFileSync(indexPath, JSON.stringify(index));
    assert.equal(await stop(), false);
    assert.equal(fs.existsSync(harPath), false);
    assert.deepEqual(fs.readFileSync(ledgerPath), original);

    fs.writeFileSync(indexPath, originalIndex);
    assert.equal(await stop(), true);
    const [entry] = JSON.parse(fs.readFileSync(harPath, 'utf8')).log.entries;
    assert.equal(entry.request.url, 'https://fixture.invalid/resource');
    assert.equal(entry.response.status, 204);
    assert.equal(fs.existsSync(scratch), false);
});

test('a nonempty pre-upgrade scratch without a checkpoint is retained for unknown ownership', async (t) => {
    const { open, stop, options, profileId } = managedFixture(t);
    await open({ ...HAR_ONLY, recordHar: false });
    assert.equal(await stop(), true);
    const scratch = path.join(options.profilesDir, profileId, '.native', '~har-scratch');
    const recorder = new CamoufoxTrafficRecorder({ profileId, trafficDir: scratch, recordWireLog: false });
    recorder.setStep('synthetic legacy HAR activity');
    await recorder.stop();
    fs.unlinkSync(path.join(scratch, 'attribution-index.json'));

    const ledger = path.join(scratch, 'traffic.ndjson');
    const original = fs.readFileSync(ledger);
    await assert.rejects(open(HAR_ONLY), { code: 'ERR_CAMOUFOX_HAR_EXPORT_PENDING' });
    assert.equal(await stop(), false);
    assert.deepEqual(fs.readFileSync(ledger), original);
});

test('failure before profile readiness leaves the previous HAR bytes intact', async (t) => {
    const { open, stop, options, profileId } = managedFixture(t);
    const session = await open(HAR_ONLY);
    observeSyntheticRequest(session);
    assert.equal(await stop(), true);
    const { harPath } = session.trafficPaths;
    const previous = fs.readFileSync(harPath);
    assert.equal(JSON.parse(previous).log.entries.length, 1);
    await assert.rejects(startProfile(profileId, { ...options, ...HAR_ONLY }, undefined, {
        beforeReady() { throw new Error('Synthetic startup check failed'); }
    }), /Synthetic startup check failed/);
    assert.deepEqual(fs.readFileSync(harPath), previous);
    await open(HAR_ONLY);
    assert.equal(await stop(), true);
});

test('active and pending profiles validate requested HAR destinations and formats before reuse', async (t) => {
    const { open, stop, options, profileId } = managedFixture(t);
    const harDir = path.join(options.profilesDir, profileId, 'traffic');
    const first = path.join(harDir, 'first.har');
    const second = path.join(harDir, 'second.har');
    const harSettings = (recordHar) => ({ ...HAR_ONLY, contextOptions: { recordHar } });
    const pending = open(harSettings({ path: first }));
    await assert.rejects(open(harSettings({ path: second })), /changing the HAR destination/);
    const session = await pending;
    assert.equal(await open(harSettings({ path: first, mode: 'full' })), session);
    await assert.rejects(open(harSettings({ path: second })), /changing the HAR destination/);
    await assert.rejects(open(harSettings({ path: first, mode: 'minimal' })), /minimal mode/);
    await assert.rejects(open(harSettings({ path: first, urlFilter: '*' })), /native URL filters/);
    observeSyntheticRequest(session);
    assert.equal(await stop(), true);
    assert.equal(JSON.parse(fs.readFileSync(first, 'utf8')).log.entries.length, 1);
    assert.equal(fs.existsSync(second), false);
});

test('a Necko log above the parsing limit stays private and does not block shutdown or restart', async (t) => {
    const { open, stop } = managedFixture(t);
    const session = await open();
    const { trafficDir, neckoMozLogPath, attributionIndexPath } = session.trafficPaths;
    const limit = 128 * 1024 * 1024;
    fs.truncateSync(neckoMozLogPath, limit + 1);

    assert.equal(await stop(), true);
    assert.equal(fs.statSync(neckoMozLogPath).size, limit + 1);
    const index = JSON.parse(fs.readFileSync(attributionIndexPath, 'utf8'));
    assert.equal(index.neckoMozLog.diagnosticsOmitted, 'size-limit');
    assert.equal(index.integrity.nativeArtifacts.neckoMozLog.hashedBytes, limit);
    const verified = verifyTrafficIntegrity(trafficDir, { nativeDir: path.dirname(neckoMozLogPath) });
    assert.equal(verified.valid, true);
    assert.deepEqual(verified.unverifiedNativeArtifacts, [path.basename(neckoMozLogPath)]);

    await open({ neckoMozLog: false });
    assert.equal(await stop(), true);
    assert.equal(fs.statSync(neckoMozLogPath).size, limit + 1);
});

test('Necko child files are included in the manifest and checked with the parent', async (t) => {
    const { open, stop } = managedFixture(t);
    const session = await open();
    const { trafficDir, neckoMozLogPath, attributionIndexPath } = session.trafficPaths;
    const child = neckoMozLogPath + '.child-1';
    const nativeDir = path.dirname(neckoMozLogPath);
    fs.writeFileSync(child, 'http request [\nGET /test HTTP/1.1\nHost: fixture.invalid\n]\n', { mode: 0o644 });
    assert.equal(await stop(), true);

    const index = JSON.parse(fs.readFileSync(attributionIndexPath, 'utf8'));
    assert.equal(index.neckoMozLog.requestBlockCount, 1);
    assert.equal(index.integrity.nativeArtifacts.neckoMozLog.children[0].file, path.basename(child));
    assert.equal(verifyTrafficIntegrity(trafficDir, { nativeDir }).valid, true);
    const extra = neckoMozLogPath + '.child-2';
    fs.writeFileSync(extra, 'independent synthetic child log\n', { mode: 0o600 });
    assert.deepEqual(verifyTrafficIntegrity(trafficDir, { nativeDir }).unverifiedNativeArtifacts, [path.basename(extra)]);
    fs.unlinkSync(child);
    const missing = verifyTrafficIntegrity(trafficDir, { nativeDir });
    assert.equal(missing.valid, false);
    assert.ok(missing.errors.includes(`Missing ${path.basename(child)} on disk`));
});

test('transport loss keeps the raw native generation unsealed and allows a fresh generation', async (t) => {
    const { open, stop, browsers } = managedFixture(t);
    const first = await open();
    const { neckoMozLogPath, trafficDir, attributionIndexPath } = first.trafficPaths;
    const nativeDir = path.dirname(neckoMozLogPath);
    fs.appendFileSync(neckoMozLogPath, 'native event before loss\n');
    browsers[0].disconnect();
    assert.equal(await stop(), false);
    const index = JSON.parse(fs.readFileSync(attributionIndexPath, 'utf8'));
    assert.equal(index.integrity.nativeArtifacts.neckoMozLog.closed, false);

    fs.appendFileSync(neckoMozLogPath, 'native event after transport loss\n');
    const evidence = verifyTrafficIntegrity(trafficDir, { nativeDir });
    assert.equal(evidence.valid, true);
    assert.deepEqual(evidence.unverifiedNativeArtifacts, [path.basename(neckoMozLogPath)]);
    const next = await open();
    assert.notEqual(next.trafficPaths.neckoMozLogPath, neckoMozLogPath);
    assert.equal(await stop(), true);
    assert.match(fs.readFileSync(neckoMozLogPath, 'utf8'), /after transport loss/);
});

test('startup rollback preserves native evidence when physical exit is unconfirmed', async (t) => {
    const { options, profileId, browsers } = managedFixture(t);
    const created = await createProfile('fixture', null, { ...options, profileId });
    const nativeFile = path.join(created.profileDir, '.native', 'necko-pre-tls.moz_log');
    await assert.rejects(startProfile(profileId, options, undefined, {
        createdProfile: created,
        beforeReady() {
            fs.appendFileSync(nativeFile, 'synthetic native data before startup disconnect\n');
            browsers[0].disconnect();
            throw new Error('Synthetic startup disconnected');
        }
    }), /Synthetic startup disconnected/);
    assert.equal(await rollbackCreatedProfile(created), 'delete-unconfirmed');
    assert.match(fs.readFileSync(nativeFile, 'utf8'), /before startup disconnect/);
});


test('HAR publication and cleanup keep their distinct states after a process exits', async (t) => {
    for (const failure of ['cleanup', 'partial-cleanup', 'receipt']) {
        await t.test(failure, async (t) => {
            const { stop, options, profileId } = managedFixture(t);
            const clientModule = new URL('../../src/camoufox/client.js', import.meta.url).href;
            const profileDir = path.join(options.profilesDir, profileId);
            const scratch = path.join(profileDir, '.native', '~har-scratch');
            const indexPath = path.join(scratch, 'attribution-index.json');
            const harPath = path.join(profileDir, 'traffic', 'trace.har');
            const child = `
                import assert from 'node:assert/strict';
                import { EventEmitter } from 'node:events';
                import fs from 'node:fs';
                import { setCamoufoxModule, startProfile, stopProfile, unregisterProcessCleanupHooks }
                    from ${JSON.stringify(clientModule)};
                const mockLauncher = ${mockLauncher.toString()};
                const observeSyntheticRequest = ${observeSyntheticRequest.toString()};
                const options = ${JSON.stringify({ ...options, ...HAR_ONLY })};
                const profileId = ${JSON.stringify(profileId)};
                setCamoufoxModule(mockLauncher());
                const session = await startProfile(profileId, options);
                observeSyntheticRequest(session);

                const mode = ${JSON.stringify(failure)};
                const remove = fs.rmSync;
                const rename = fs.renameSync;
                const fail = () => { throw Object.assign(new Error('Synthetic HAR phase failure'), { code: 'EACCES' }); };
                fs.rmSync = (file, ...args) => {
                    if (mode !== 'receipt' && file === ${JSON.stringify(scratch)}) {
                        if (mode === 'partial-cleanup') {
                            remove(${JSON.stringify(path.join(scratch, 'traffic.ndjson'))});
                        }
                        fail();
                    }
                    return remove(file, ...args);
                };
                fs.renameSync = (from, to) => {
                    if (mode === 'receipt' && to === ${JSON.stringify(indexPath)} &&
                        JSON.parse(fs.readFileSync(from)).harRecovery?.publication?.published === true) fail();
                    return rename(from, to);
                };
                try {
                    assert.equal(await stopProfile(profileId, options), false);
                } finally {
                    fs.rmSync = remove;
                    fs.renameSync = rename;
                    unregisterProcessCleanupHooks();
                }
            `;
            execFileSync(process.execPath, ['--input-type=module', '-e', child], { timeout: 10000 });
            const index = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
            assert.equal(index.harRecovery.publication?.published, failure !== 'receipt');

            const profileArchive = fs.readFileSync(harPath);
            assert.equal(JSON.parse(profileArchive).log.entries.length, 1);
            const independent = path.join(options.profilesDir, 'operator-capture');
            const recorder = new CamoufoxTrafficRecorder({ trafficDir: independent, recordWireLog: false, trustedLocal: true });
            const context = new EventEmitter();
            recorder.attachContext(context);
            context.emit('request', { method: () => 'GET', url: () => 'https://fixture.invalid/newer' });
            await recorder.stop();
            assert.equal(exportTrafficToHar(independent, harPath).entryCount, 1);
            const newer = fs.readFileSync(harPath);
            assert.notDeepEqual(newer, profileArchive);

            assert.equal(await stop(), failure !== 'receipt');
            assert.deepEqual(fs.readFileSync(harPath), newer);
            assert.equal(fs.existsSync(scratch), failure === 'receipt');

            if (failure === 'receipt') {
                const kept = path.join(profileDir, 'traffic', 'kept.har');
                fs.renameSync(harPath, kept);
                assert.equal(await stop(), true);
                assert.deepEqual(fs.readFileSync(kept), newer);
                assert.equal(JSON.parse(fs.readFileSync(harPath)).log.entries[0].request.url,
                    'https://fixture.invalid/resource');
                assert.equal(fs.existsSync(scratch), false);
            }
        });
    }
});
