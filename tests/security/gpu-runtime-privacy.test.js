import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

test('managed profiles use native GPU behavior and discard legacy host calibration', async (t) => {
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'gpu-runtime-privacy-'));
    const fixtureEnvironment = {
        GMAIL_CREATOR_STATE_DIR: path.join(root, 'state'),
        CAMOUFOX_AUDIT_ON_START: 'false'
    };
    const previousEnvironment = Object.keys(fixtureEnvironment).map((key) => [key, process.env[key]]);
    Object.assign(process.env, fixtureEnvironment);
    let client;
    t.after(async () => {
        try {
            if (client) {
                await client.stopAllActiveProfiles();
                client.unregisterProcessCleanupHooks();
                client.setCamoufoxModule();
            }
        } finally {
            for (const [key, value] of previousEnvironment) {
                if (value === undefined) delete process.env[key];
                else process.env[key] = value;
            }
            fs.rmSync(root, { recursive: true, force: true });
        }
    });

    const legacyBaseline = {
        hostChipModel: 'GPU privacy fixture host',
        hostFp32Tflops: 12,
        hostMemoryBandwidthGBps: 100,
        hostPixelFillRateGPixels: 90
    };
    let hostProbes = 0;
    t.mock.method(os, 'cpus', () => {
        hostProbes++;
        return [{ model: legacyBaseline.hostChipModel }];
    });
    t.mock.method(os, 'totalmem', () => {
        hostProbes++;
        return 4 * 1024 ** 3;
    });

    client = await import('../../src/camoufox/client.js');
    const { CamoufoxProfile } = await import('../../src/camoufox/profile.js');
    let initScripts = 0;
    client.setCamoufoxModule({
        async Camoufox() {
            let connected = true;
            let closed = false;
            const browser = Object.assign(new EventEmitter(), {
                isConnected: () => connected,
                newContext: async () => context,
                async close() {
                    if (!connected) return;
                    connected = false;
                    await context.close();
                    browser.emit('disconnected');
                }
            });
            const context = Object.assign(new EventEmitter(), {
                browser: () => browser,
                pages: () => [page],
                isClosed: () => closed,
                storageState: async () => ({ cookies: [], origins: [] }),
                async addInitScript() { initScripts++; },
                async close() {
                    if (closed) return;
                    closed = true;
                    context.emit('close');
                }
            });
            const page = Object.assign(new EventEmitter(), {
                context: () => context,
                isClosed: () => closed,
                url: () => 'about:blank'
            });
            return browser;
        }
    });
    const commonOptions = {
        profilesDir: path.join(root, 'profiles'),
        enablePortScanProtection: false,
        verifyCoherence: false,
        recordTraffic: false,
        sslKeyLog: false,
        neckoMozLog: false,
        recordHar: false
    };
    for (const [profileId, gpuOptions] of [
        ['default', {}],
        ['disabled', { enableGpuPerformanceScaling: false }],
        ['legacy', { enableGpuPerformanceScaling: true }]
    ]) {
        await t.test(profileId, async () => {
            const options = { ...commonOptions, ...gpuOptions, profileId };
            const metadata = await client.createProfile(profileId, null, options);
            const metadataFile = path.join(metadata.profileDir, 'profile.json');
            const readDiskMetadata = () => JSON.parse(fs.readFileSync(metadataFile, 'utf8'));
            const calibrationOnCreate = Object.hasOwn(readDiskMetadata(), 'gpuPerformance');
            const manager = new CamoufoxProfile(profileId, options);
            const previousScriptCount = initScripts;
            let exposedLegacyCalibration = false;

            if (profileId === 'legacy') {
                fs.writeFileSync(metadataFile, JSON.stringify({
                    ...readDiskMetadata(),
                    gpuPerformance: {
                        hostBaseline: legacyBaseline,
                        computeTimeMultiplier: 1,
                        targetGpuSpec: { model: 'Legacy GPU fixture' }
                    }
                }));
                exposedLegacyCalibration = Object.hasOwn(await client.getProfile(profileId, options), 'gpuPerformance');
            }

            await manager.start();
            try {
                const persisted = readDiskMetadata();
                assert.deepEqual({
                    calibrationOnCreate,
                    exposedLegacyCalibration,
                    injectedScripts: initScripts - previousScriptCount,
                    persistedCalibration: Object.hasOwn(persisted, 'gpuPerformance'),
                    summaryCalibration: Object.hasOwn(manager.getTelemetrySummary(), 'gpuPerformance')
                }, {
                    calibrationOnCreate: false,
                    exposedLegacyCalibration: false,
                    injectedScripts: 0,
                    persistedCalibration: false,
                    summaryCalibration: false
                });
                assert.equal(manager.getGpuPerformanceScaler(), null);
                assert.equal(persisted.presetId, metadata.presetId);
            } finally {
                assert.equal(await manager.stop(), true);
            }
        });
    }
    assert.equal(hostProbes, 0, 'profile creation or startup probed host hardware');
});
