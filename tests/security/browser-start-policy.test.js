import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import {
    createProfile,
    getProfileMetadataPath,
    setCamoufoxModule,
    startProfile,
    stopAllActiveProfiles,
    stopProfile,
    unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import { createAndStartProfile } from '../../src/camoufox/profile.js';

const proxy = { server: 'http://proxy.example.invalid:8080', bypass: 'example.invalid' };

function setup(t, beforeLaunch = async () => {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-start-policy-'));
    const launches = [];
    setCamoufoxModule({
        async Camoufox(options) {
            const launch = { options, contexts: [] };
            launches.push(launch);
            await beforeLaunch();
            let connected = true;
            return Object.assign(new EventEmitter(), {
                isConnected: () => connected,
                async newContext(contextOptions) {
                    launch.contexts.push(contextOptions);
                    let closed = false;
                    return Object.assign(new EventEmitter(), {
                        pages: () => [new EventEmitter()],
                        isClosed: () => closed,
                        route: async () => {},
                        storageState: async () => contextOptions.storageState,
                        async close() {
                            closed = true;
                            this.emit('close');
                        }
                    });
                },
                async close() {
                    connected = false;
                    this.emit('disconnected');
                }
            });
        }
    });
    t.after(async () => {
        await stopAllActiveProfiles();
        unregisterProcessCleanupHooks();
        setCamoufoxModule();
        fs.rmSync(root, { recursive: true, force: true });
    });
    return {
        root,
        launches,
        options: {
            profilesDir: root,
            enableGpuPerformanceScaling: false,
            recordTraffic: false,
            recordHar: false
        }
    };
}

function configureEnv(t, values) {
    const original = Object.fromEntries(Object.keys(values).map((name) => [name, process.env[name]]));
    Object.assign(process.env, values);
    t.after(() => {
        for (const [name, value] of Object.entries(original)) {
            if (value === undefined) delete process.env[name];
            else process.env[name] = value;
        }
    });
}

test('pending and active reuse require the same effective routing and normalized URL guard', async (t) => {
    let releaseLaunch;
    const gate = new Promise((resolve) => { releaseLaunch = resolve; });
    const { options, launches } = setup(t, () => gate);
    const requested = {
        ...options,
        proxy,
        allowedLocalPorts: [8300, 8100, 8300],
        allowSameOriginLocalDev: true,
        allowedExtensionIds: ['test-extension'],
        contextOptions: { acceptDownloads: false }
    };
    const incompatible = [
        { proxy: null },
        { proxy: { ...proxy, bypass: 'changed.invalid' } },
        { proxy: { server: 'http://changed.example.invalid:8080' } },
        { allowedLocalPorts: [8100] },
        { allowSameOriginLocalDev: false },
        { allowedExtensionIds: [] },
        { contextOptions: { acceptDownloads: true } }
    ];
    const pending = startProfile('routing', requested);
    let samePending;
    try {
        for (const change of incompatible) {
            await assert.rejects(startProfile('routing', { ...requested, ...change }), /network or URL guard/);
        }
        samePending = startProfile('routing', { ...requested, allowedLocalPorts: ['8100', '8300'] });
    } finally {
        releaseLaunch();
    }
    const active = await pending;
    assert.equal(await samePending, active);
    for (const change of incompatible) {
        await assert.rejects(startProfile('routing', { ...requested, ...change }), /network or URL guard/);
    }
    assert.equal(launches.length, 1);
    assert.equal(await stopProfile('routing', options), true);
    await startProfile('routing', { ...requested, proxy: null, allowedLocalPorts: [] });
    assert.equal(launches.length, 2);
});

test('nested proxy options cannot replace the selected profile proxy', async (t) => {
    const { launches, options } = setup(t);
    const settings = { ...options, proxy };

    for (const conflicting of [
        { launchOptions: { proxy: null } },
        { launchOptions: { proxy: { server: 'http://other.example.invalid:8080' } } },
        { contextOptions: { proxy: null } },
        { contextOptions: { proxyOverride: proxy } }
    ]) {
        await assert.rejects(startProfile('conflicting', { ...settings, ...conflicting }), /Conflicting Camoufox proxy/);
    }
    assert.equal(launches.length, 0);

    const session = await startProfile('consistent', {
        ...settings,
        launchOptions: { proxy: undefined },
        contextOptions: { proxy }
    });
    assert.deepEqual(session.metadata.proxy, proxy);
    assert.deepEqual(launches[0].options.proxy, proxy);
    assert.equal(Object.hasOwn(launches[0].contexts[0], 'proxy'), false);
});

test('all capture opt-outs reject pending and active reuse under the previous policy', async (t) => {
    let releaseLaunch;
    const gate = new Promise((resolve) => { releaseLaunch = resolve; });
    const { options, launches } = setup(t, () => gate);
    const verboseCapture = {
        ...options,
        recordTraffic: true,
        recordWireLog: true,
        recordHar: true,
        contextOptions: { recordHar: { content: 'attach' } },
        recordBodies: true,
        sslKeyLog: true,
        neckoMozLog: true
    };
    const optOuts = [
        [{ recordTraffic: false }, 'traffic recording'],
        [{ recordWireLog: false }, 'wire logging'],
        [{ recordHar: false }, 'HAR recording'],
        [{ contextOptions: { recordHar: { content: 'omit' } } }, 'HAR body recording'],
        [{ recordBodies: false }, 'body recording'],
        [{ sslKeyLog: false }, 'TLS key logging'],
        [{ neckoMozLog: false }, 'Necko logging']
    ];
    const pending = startProfile('capture', verboseCapture);
    try {
        for (const [change, label] of optOuts) {
            await assert.rejects(startProfile('capture', { ...verboseCapture, ...change }), new RegExp(label));
        }
    } finally {
        releaseLaunch();
    }
    await pending;
    for (const [change, label] of optOuts) {
        await assert.rejects(startProfile('capture', { ...verboseCapture, ...change }), new RegExp(label));
    }
    assert.equal(launches.length, 1);
});

test('pending and active reuse reject new capture or narrowed native logging settings', async (t) => {
    let releaseLaunch;
    const gate = new Promise((resolve) => { releaseLaunch = resolve; });
    const { options, launches } = setup(t, () => gate);
    const initial = {
        ...options,
        recordTraffic: true,
        recordBodies: true,
        maxBodyBytes: 4096,
        recordWireLog: false,
        neckoMozLog: true,
        neckoMozLogModules: 'timestamp,nsHttp:5,nsSocketTransport:5',
        contextOptions: { acceptDownloads: true }
    };
    const changed = [
        [{ recordHar: true }, /enabling HAR recording/],
        [{ recordWireLog: true }, /enabling wire logging/],
        [{ neckoMozLogModules: 'timestamp,nsHttp:3' }, /changing Necko logging modules/],
        [{ maxBodyBytes: 1024 }, /changing the body recording limit/],
        [{ contextOptions: { acceptDownloads: false } }, /context permissions/]
    ];
    const pending = startProfile('capture-options', initial);
    try {
        for (const [overrides, reason] of changed) {
            const rejected = startProfile('capture-options', { ...initial, ...overrides }).then(() => null, (error) => error);
            const outcome = await Promise.race([rejected, new Promise((resolve) => setImmediate(resolve))]);
            assert.match(outcome?.message ?? '', reason);
        }
    } finally {
        releaseLaunch();
    }
    const active = await pending;
    for (const [overrides, reason] of changed) {
        await assert.rejects(startProfile('capture-options', { ...initial, ...overrides }), reason);
    }
    assert.equal(await startProfile('capture-options', initial), active);
    assert.equal(launches.length, 1);
});

test('TLS and Necko opt-outs also apply to active native logging without traffic capture', async (t) => {
    const { options, launches } = setup(t);
    const logging = { ...options, sslKeyLog: true, neckoMozLog: true };
    await startProfile('native', logging);
    await assert.rejects(startProfile('native', { ...logging, sslKeyLog: false }), /TLS key logging/);
    await assert.rejects(startProfile('native', { ...logging, neckoMozLog: false }), /Necko logging/);
    assert.equal(await stopProfile('native', options), true);
    await startProfile('native', { ...logging, sslKeyLog: false, neckoMozLog: false });
    assert.equal(launches[1].options.env.SSLKEYLOGFILE, '');
    assert.equal(launches[1].options.env.MOZ_LOG, '');
});

test('deployment transport policy rejects SDK launch entry points before reading the launcher', async (t) => {
    const { root, options } = setup(t);
    configureEnv(t, { CAMOUFOX_PORT_SCAN_MODE: 'transport' });
    setCamoufoxModule({ get Camoufox() { assert.fail('Launcher lookup blocked by transport policy'); } });
    const unsupported = { code: 'ERR_CAMOUFOX_NETWORK_BOUNDARY_UNAVAILABLE' };
    await assert.rejects(startProfile('direct', options), unsupported);
    await assert.rejects(createProfile('direct', null, options), unsupported);
    await assert.rejects(createAndStartProfile('factory', null, options), unsupported);
    assert.deepEqual(fs.readdirSync(root), []);
});

test('deployment managed policy binds the proxy and forwards only browser runtime environment', async (t) => {
    const { launches, options } = setup(t);
    const origin = 'https://egress.example.invalid:8443';
    configureEnv(t, {
        CAMOUFOX_PORT_SCAN_MODE: 'managed-proxy',
        CAMOUFOX_MANAGED_EGRESS_ORIGIN: origin,
        HTTP_PROXY: 'http://unrelated.example.invalid:8080',
        SMS_VERIFY_API_KEY: 'synthetic-only-secret'
    });
    const incompatible = { code: 'ERR_CAMOUFOX_MANAGED_EGRESS_BINDING' };
    await assert.rejects(startProfile('unbound', options), incompatible);
    await assert.rejects(startProfile('conflict', { ...options, portScanProtection: { mode: 'url-only' } }), incompatible);
    const session = await startProfile('managed', {
        ...options,
        proxy: origin,
        launchOptions: { env: { DISPLAY: ':fixture', DOLPHIN_API_KEY: 'synthetic-only-secret' } }
    });
    assert.equal(session.securityGuards.getStats().portScanProtectionMode, 'managed-proxy');
    const launched = launches[0].options;
    assert.deepEqual(launched.proxy, { server: origin });
    assert.equal(launched.env.DISPLAY, ':fixture');
    assert.equal(launched.env.PATH, process.env.PATH);
    for (const name of ['SMS_VERIFY_API_KEY', 'DOLPHIN_API_KEY', 'HTTP_PROXY', 'NODE_OPTIONS']) {
        assert.equal(Object.hasOwn(launched.env, name), false);
    }
});

test('shared browsers have per-context routing and isolate explicit process environments', async (t) => {
    const { launches, options } = setup(t);
    const shared = { ...options, useSharedBrowser: true };
    for (const launchOptions of [{ proxy }, { addons: ['test-addon'] }]) {
        await assert.rejects(startProfile('custom', { ...shared, launchOptions }), /default process launch settings/);
    }
    await startProfile('proxied', { ...shared, proxy, env: { DISPLAY: ':fixture-a' } });
    await startProfile('direct', { ...shared, env: { DISPLAY: ':fixture-a' } });
    await startProfile('other-env', { ...shared, env: { DISPLAY: ':fixture-b' } });
    assert.equal(launches.length, 2);
    assert.equal(launches[0].options.env.DISPLAY, ':fixture-a');
    assert.equal(launches[1].options.env.DISPLAY, ':fixture-b');
    assert.equal(Object.hasOwn(launches[0].options, 'proxy'), false);
    assert.deepEqual(launches[0].contexts[0].proxy, proxy);
    assert.equal(Object.hasOwn(launches[0].contexts[1], 'proxy'), false);
});

test('both context constructors use only the selected profile’s validated state', async (t) => {
    const { root, launches, options } = setup(t);
    const states = [{ cookies: [{ name: 'first' }], origins: [] }, { cookies: [{ name: 'second' }], origins: [] }];
    const first = await createProfile('first', null, { ...options, profileId: 'first' });
    const second = await createProfile('second', null, { ...options, profileId: 'second', useSharedBrowser: true });
    fs.writeFileSync(first.storageStatePath, JSON.stringify(states[0]));
    fs.writeFileSync(second.storageStatePath, JSON.stringify(states[1]));
    fs.writeFileSync(getProfileMetadataPath('second', root), JSON.stringify({
        ...second,
        contextOptions: { storageState: first.storageStatePath, acceptDownloads: false }
    }));
    await startProfile('first', { ...options, contextOptions: { storageState: second.storageStatePath } });
    await startProfile('second', options);
    assert.deepEqual(launches.map(({ contexts }) => contexts[0].storageState), states);
    assert.equal(launches[1].contexts[0].acceptDownloads, false);
});

test('SDK availability resolves package metadata without evaluating the package', async (t) => {
    const { root } = setup(t);
    const probe = path.join(root, 'sdk-resolution.mjs');
    fs.copyFileSync(new URL('../../src/camoufox/sdk-resolution.js', import.meta.url), probe);
    const { isCamoufoxModuleResolvable } = await import(pathToFileURL(probe));
    const sdk = path.join(root, 'node_modules', 'camoufox');
    fs.mkdirSync(sdk, { recursive: true });
    fs.writeFileSync(path.join(sdk, 'package.json'), '{"exports":"./probe.js"}');
    assert.equal(isCamoufoxModuleResolvable(), false);
    fs.writeFileSync(path.join(sdk, 'probe.js'), 'throw new Error("Unexpected fixture SDK evaluation");');
    assert.equal(isCamoufoxModuleResolvable(), true);
});
