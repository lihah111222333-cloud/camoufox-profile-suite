import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    createProfile,
    setCamoufoxModule,
    startProfile,
    stopProfile,
    updateProfileProxy
} from '../../src/camoufox/client.js';
import { createAndStartProfile } from '../../src/camoufox/profile.js';
import {
    assertPrivateNetworkIsolationAvailable,
    attachZiniaoSecurityGuardsToContext
} from '../../src/camoufox/ziniao-security.js';

const isolationUnavailable = { code: 'ERR_CAMOUFOX_NETWORK_BOUNDARY_UNAVAILABLE' };
const transportPolicy = { mode: 'transport' };
const urlPolicy = { mode: 'url-only' };
const managedPolicy = { mode: 'managed-proxy' };
const bindingRejected = { code: 'ERR_CAMOUFOX_MANAGED_EGRESS_BINDING' };
const managedOrigin = 'https://egress.example.invalid:8443';

function configureManagedOrigin(testContext, origin) {
    const previous = process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN;
    if (origin === undefined) delete process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN;
    else process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN = origin;
    testContext.after(() => {
        if (previous === undefined) delete process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN;
        else process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN = previous;
    });
}

function makeProfilesDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-network-policy-'));
}

function writeProfilePolicy(profilesDir, id, portScanProtection) {
    const profileDir = path.join(profilesDir, id);
    fs.mkdirSync(profileDir, { mode: 0o700, recursive: true });
    fs.writeFileSync(
        path.join(profileDir, 'profile.json'),
        JSON.stringify({ id, securityPolicy: { portScanProtection } }),
        { mode: 0o600 }
    );
}

test('transport isolation requires enforcement before registering any context hooks', async () => {
    const context = {
        route: () => assert.fail('strict policy must reject before installing routes'),
        addInitScript: () => assert.fail('strict policy must reject before installing scripts')
    };

    await assert.rejects(
        attachZiniaoSecurityGuardsToContext(context, {
            portScanProtection: { ...transportPolicy, enabled: false, allowedPorts: [8100] }
        }),
        isolationUnavailable
    );
    assert.throws(() => assertPrivateNetworkIsolationAvailable({ mode: 'unrecognized' }), TypeError);
});

test('URL protection reports its scope and honors configured development ports', async () => {
    let handleRequest;
    const context = {
        async route(_pattern, handler) {
            handleRequest = handler;
        }
    };
    const url = 'http://127.0.0.1:8100/';
    const request = { url: () => url };
    const guard = await attachZiniaoSecurityGuardsToContext(context);
    const outcomes = [];
    const route = {
        abort: (error) => outcomes.push(error),
        continue: () => outcomes.push('continued')
    };

    await handleRequest(route, request);
    assert.equal(guard.getStats().portScanProtectionMode, 'url-only');
    assert.deepEqual(outcomes, ['connectionrefused']);

    const devGuard = await attachZiniaoSecurityGuardsToContext(context, {
        portScanProtection: { ...urlPolicy, allowedPorts: [8100] }
    });
    await handleRequest(route, request);
    assert.equal(devGuard.getStats().portScanProtectionMode, 'url-only');
    assert.deepEqual(outcomes, ['connectionrefused', 'continued']);
});

test('explicit strict policy rejects all launch entry points before side effects', async (t) => {
    const profilesDir = makeProfilesDir();
    t.after(() => {
        setCamoufoxModule();
        fs.rmSync(profilesDir, { force: true, recursive: true });
    });

    let launcherReads = 0;
    setCamoufoxModule({
        get Camoufox() {
            launcherReads += 1;
            assert.fail('strict mode must reject before inspecting the launcher');
        }
    });

    const options = { profilesDir, portScanProtection: transportPolicy };
    await assert.rejects(startProfile('direct', options), isolationUnavailable);
    await assert.rejects(createProfile('create-only', null, options), isolationUnavailable);
    await assert.rejects(createAndStartProfile('create-and-start', null, options), isolationUnavailable);
    await assert.rejects(
        startProfile('proxy', {
            profilesDir,
            useSharedBrowser: true,
            enablePortScanProtection: false,
            securityPolicy: { portScanProtection: transportPolicy },
            proxy: { server: 'https://egress.example.invalid:8443' }
        }),
        isolationUnavailable
    );

    assert.equal(launcherReads, 0);
    assert.deepEqual(fs.readdirSync(profilesDir), []);
});

test('stored transport policy prevents launch even with a runtime URL-only policy', async (t) => {
    const profilesDir = makeProfilesDir();
    t.after(() => {
        setCamoufoxModule();
        fs.rmSync(profilesDir, { force: true, recursive: true });
    });
    setCamoufoxModule({ Camoufox: () => assert.fail('stored strict policy must prevent launch') });

    writeProfilePolicy(profilesDir, 'stored', transportPolicy);
    await assert.rejects(
        createProfile('stored', null, { profilesDir, profileId: 'stored' }),
        isolationUnavailable
    );
    await assert.rejects(
        startProfile('stored', { profilesDir, portScanProtection: urlPolicy }),
        isolationUnavailable
    );
});

test('managed and transport policies cannot reuse a pending or active URL-only session', async (t) => {
    configureManagedOrigin(t, managedOrigin);
    const profilesDir = makeProfilesDir();
    const profileId = 'reuse';
    const context = {
        pages: () => [{}],
        storageState: async () => ({ cookies: [], origins: [] }),
        route: async () => {},
        close: async () => {}
    };
    const browser = {
        newContext: async () => context,
        close: async () => {}
    };
    let releaseLaunch;
    let notifyLaunchStarted;
    const blockedLaunch = new Promise((resolve) => { releaseLaunch = resolve; });
    const launchStarted = new Promise((resolve) => { notifyLaunchStarted = resolve; });

    setCamoufoxModule({
        Camoufox() {
            notifyLaunchStarted();
            return blockedLaunch;
        }
    });
    t.after(async () => {
        releaseLaunch(browser);
        await stopProfile(profileId, { profilesDir });
        setCamoufoxModule();
        fs.rmSync(profilesDir, { force: true, recursive: true });
    });

    writeProfilePolicy(profilesDir, profileId, urlPolicy);
    const pending = startProfile(profileId, {
        profilesDir,
        proxy: managedOrigin,
        recordTraffic: false,
        sslKeyLog: false,
        neckoMozLog: false,
        recordHar: false,
        enableGpuPerformanceScaling: false
    });
    await Promise.race([launchStarted, pending]);

    const strictOptions = { profilesDir, portScanProtection: transportPolicy };
    const managedOptions = { profilesDir, portScanProtection: managedPolicy, proxy: managedOrigin };
    const strictReuse = assert.rejects(startProfile(profileId, strictOptions), isolationUnavailable);
    const managedReuse = assert.rejects(startProfile(profileId, managedOptions), bindingRejected);
    releaseLaunch(browser);
    const [session] = await Promise.all([pending, strictReuse, managedReuse]);
    assert.equal(session.securityGuards.getStats().portScanProtectionMode, 'url-only');

    await assert.rejects(startProfile(profileId, strictOptions), isolationUnavailable);
    await assert.rejects(startProfile(profileId, managedOptions), bindingRejected);

    writeProfilePolicy(profilesDir, profileId, transportPolicy);
    await assert.rejects(startProfile(profileId, { profilesDir }), isolationUnavailable);
});

test('managed mode binds the launcher to the configured proxy and reports the unverified destination policy', async (t) => {
    configureManagedOrigin(t, managedOrigin);
    const profilesDir = makeProfilesDir();
    const proxy = { server: managedOrigin, username: 'fixture', password: 'fixture-password' };
    let launchedWith;
    let contextOptions;
    const context = {
        pages: () => [{}],
        storageState: async () => ({ cookies: [], origins: [] }),
        route: async () => {},
        close: async () => {}
    };
    setCamoufoxModule({
        Camoufox: async (options) => {
            launchedWith = options;
            return {
                newContext: async (options) => {
                    contextOptions = options;
                    return context;
                },
                close: async () => {}
            };
        }
    });
    t.after(async () => {
        await stopProfile('managed', { profilesDir });
        setCamoufoxModule();
        fs.rmSync(profilesDir, { force: true, recursive: true });
    });

    const profile = await createAndStartProfile('managed', proxy, {
        profileId: 'managed',
        profilesDir,
        portScanProtection: managedPolicy,
        recordTraffic: false,
        enableGpuPerformanceScaling: false
    });
    assert.deepEqual(launchedWith.proxy, proxy);
    assert.equal(Object.hasOwn(contextOptions, 'proxy'), false);
    assert.equal(profile.securityGuards.getStats().portScanProtectionMode, 'managed-proxy');
    assert.equal(profile.securityGuards.getStats().destinationIpPolicy, 'managed-proxy-unverified');
    assert.equal(profile.metadata.securityPolicy.portScanProtection.mode, 'managed-proxy');

    const existing = await startProfile('managed', { profilesDir });
    assert.equal(existing.page, profile.page);
    await assert.rejects(startProfile('managed', { profilesDir, proxy: null }), bindingRejected);
    await assert.rejects(
        startProfile('managed', { profilesDir, proxy: { ...proxy, username: 'other-fixture' } }),
        bindingRejected
    );
    await assert.rejects(startProfile('managed', { profilesDir, portScanProtection: urlPolicy }), bindingRejected);
    await assert.rejects(startProfile('managed', { profilesDir, portScanProtection: transportPolicy }), isolationUnavailable);
    await assert.rejects(updateProfileProxy('managed', 'https://other.example.invalid:8443', { profilesDir }), bindingRejected);
    await assert.rejects(updateProfileProxy('managed', null, { profilesDir }), bindingRejected);
    assert.equal((await startProfile('managed', { profilesDir })).page, profile.page);
});

test('managed mode rejects absent authority and incompatible routing before launcher lookup', async (t) => {
    configureManagedOrigin(t, undefined);
    const profilesDir = makeProfilesDir();
    t.after(() => {
        setCamoufoxModule();
        fs.rmSync(profilesDir, { force: true, recursive: true });
    });
    setCamoufoxModule({
        get Camoufox() {
            assert.fail('managed mode must reject invalid routing before inspecting the launcher');
        }
    });

    const options = { profilesDir, portScanProtection: managedPolicy, proxy: managedOrigin };
    await assert.rejects(createAndStartProfile('missing-authority', managedOrigin, {
        ...options,
        env: { CAMOUFOX_MANAGED_EGRESS_ORIGIN: managedOrigin }
    }), bindingRejected);

    process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN = 'https://fixture:secret@egress.example.invalid:8443';
    await assert.rejects(startProfile('credential-in-authority', options), bindingRejected);

    process.env.CAMOUFOX_MANAGED_EGRESS_ORIGIN = managedOrigin;
    for (const incompatible of [
        { proxy: null },
        { proxy: 'https://other.example.invalid:8443' },
        { proxy: 'http://egress.example.invalid:8443' },
        { proxy: { server: managedOrigin, bypass: 'example.invalid' } },
        { useSharedBrowser: true },
        { launchOptions: { proxy: undefined } },
        { launchOptions: { proxyOverride: { server: managedOrigin } } },
        { contextOptions: { proxy: { server: managedOrigin } } },
        { contextOptions: { ignoreHTTPSErrors: true } },
        { firefox_user_prefs: { 'network.proxy.type': 0 } },
        { env: { NO_PROXY: '*' } },
        { launchOptions: { persistent_context: true } },
        { enablePortScanProtection: false },
        { portScanProtection: { ...managedPolicy, enabled: null } },
        { allowedLocalPorts: [8100] },
        { allowSameOriginLocalDev: true }
    ]) {
        await assert.rejects(startProfile('incompatible', { ...options, ...incompatible }), bindingRejected);
    }
    await assert.rejects(
        attachZiniaoSecurityGuardsToContext({}, { portScanProtection: managedPolicy }),
        bindingRejected
    );
    assert.deepEqual(fs.readdirSync(profilesDir), []);
});
