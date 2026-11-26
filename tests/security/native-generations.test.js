import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    setCamoufoxModule, startProfile, stopAllActiveProfiles, stopProfile, unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import { verifyTrafficIntegrity } from '../../src/camoufox/traffic-recorder.js';

function managedFixture(t) {
    const profilesDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'native-generation-'));
    const launches = [];
    setCamoufoxModule({
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
    });
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
    return { open, stop, launches };
}

test('managed startup verifies closed native generations before browser launch and preserves them through rotation', async (t) => {
    const { open, stop, launches } = managedFixture(t);
    const first = await open();
    const { trafficDir, attributionIndexPath, neckoMozLogPath: firstPath } = first.trafficPaths;
    const nativeDir = path.dirname(firstPath);
    const verify = (authorized = true) => verifyTrafficIntegrity(trafficDir, authorized ? { nativeDir } : {});
    const readIndex = () => JSON.parse(fs.readFileSync(attributionIndexPath, 'utf8')).integrity;

    await first.trafficRecorder.stop({ nativeLogsClosed: false });
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
