import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { attachPageCompatibility } from '../../src/camoufox/profile.js';
import { CamoufoxTrafficRecorder } from '../../src/camoufox/traffic-recorder.js';
import { buildZiniaoWebRtcSecurityInitScript, sanitizeRtcConfigurationIceServers } from '../../src/camoufox/ziniao-security.js';
import { queryProfileTraffic } from '../../scripts/query-traffic-attribution.js';

function fixtureDirectory(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-page-scope-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    return directory;
}

test('page initializers use only the requested page and fail if page scope is unavailable', async () => {
    const context = { addInitScript: () => assert.fail('context initializer used') };
    function newPage() {
        return attachPageCompatibility({
            scripts: [],
            async addInitScript(fn, arg) { this.scripts.push([fn, arg]); }
        }, context);
    }
    const page = newPage();
    const sibling = newPage();
    await page.evaluateOnNewDocument((first, second) => first + second, 9, 4);
    const [[run, args]] = page.scripts;
    assert.equal(run(args), 13);
    assert.deepEqual(sibling.scripts, []);

    const unsupported = attachPageCompatibility({}, context);
    await assert.rejects(unsupported.evaluateOnNewDocument(() => {}), /page-scoped initializers/);
});

test('page cookie reads require at least one eligible HTTP(S) URL', async () => {
    const calls = [];
    const cookie = { name: 'fixture', domain: 'shop.example.test', path: '/' };
    const context = {
        async cookies(urls) {
            calls.push(urls);
            return [cookie];
        }
    };
    let url = 'about:blank';
    const page = attachPageCompatibility({ url: () => url }, context);
    for (const ineligible of ['about:blank', 'file:///fixture.txt', 'https://', undefined]) {
        url = ineligible;
        assert.deepEqual(await page.cookies(), []);
    }
    page.url = () => { throw new Error('unavailable'); };
    assert.deepEqual(await page.cookies(), []);
    assert.deepEqual(await page.cookies('about:blank', ''), []);
    assert.deepEqual(calls, []);
    assert.deepEqual(await page.cookies('https://shop.example.test/settings'), [cookie]);
    page.url = () => 'https://shop.example.test/settings';
    assert.deepEqual(await page.cookies(), [cookie]);
    assert.deepEqual(calls, Array(2).fill(['https://shop.example.test/settings']));
});

test('cookie deletion expires exact matches while concurrent and unrelated cookie identities survive', async () => {
    const firstPartition = 'https://one.example.test';
    const secondPartition = 'https://two.example.test';
    const methodCalls = [];
    const cookie = (domain, path, partitionKey) => ({ name: 'fixture', domain, path, partitionKey, value: 'sample' });
    const matchedHost = cookie('shop.example.test', '/settings');
    const matchedDomain = cookie('.example.test', '/');
    const first = cookie('shop.example.test', '/settings', firstPartition);
    const second = cookie('shop.example.test', '/settings', secondPartition);
    const unrelated = [
        cookie('different.test', '/'),
        cookie('example.test', '/'),
        cookie('shop.example.test', '/settings-old')
    ];
    const concurrent = cookie('another.test', '/');
    let jar = [matchedHost, matchedDomain, first, second, ...unrelated];
    const context = {
        async cookies() { return [...jar]; },
        async clearCookies() { assert.fail('jar-wide deletion used'); },
        async addCookies(entries) {
            methodCalls.push(entries);
            if (methodCalls.length === 1) jar.push(concurrent);
            for (const entry of entries) {
                assert.equal(entry.expires, 1);
                assert.equal(entry.value, '');
                jar = jar.filter((stored) =>
                    ['name', 'domain', 'path', 'partitionKey'].some((key) => stored[key] !== entry[key])
                );
            }
        }
    };
    let url = 'about:blank';
    const page = attachPageCompatibility({ url: () => url }, context);
    await page.deleteCookie({ name: 'fixture' });
    await page.deleteCookie({ name: 'fixture', url: 'file:///fixture.txt' });
    assert.deepEqual(methodCalls, []);

    url = 'https://shop.example.test/settings/account';
    await page.deleteCookie({ name: 'fixture' });
    assert.deepEqual(jar, [first, second, ...unrelated, concurrent]);
    await page.deleteCookie({ name: 'fixture', path: '/settings', partitionKey: firstPartition });
    assert.deepEqual(jar, [second, ...unrelated, concurrent]);
    await page.deleteCookie({ name: 'fixture', domain: 'shop.example.test', path: '/settings-old' });
    assert.deepEqual(jar, [second, ...unrelated.slice(0, 2), concurrent]);
});

test('page and handle press actions carry only approved controls into metadata-only diagnostics', async (t) => {
    const trafficDir = path.join(fixtureDirectory(t), 'traffic');
    const recorder = new CamoufoxTrafficRecorder({ trafficDir, recordBodies: false, sslKeyLog: false });
    const context = {};
    const handle = { async press(key) { return key; } };
    const page = attachPageCompatibility({
        url: () => 'https://fixture.example.test/keyboard',
        async press(_selector, key) { return key; },
        async $() { return handle; }
    }, context, { context, trafficRecorder: recorder });
    const decoratedHandle = await page.$('#fixture');

    assert.equal(await page.press('#fixture', '7'), '7');
    assert.equal(await decoratedHandle.press('Shift+KeyQ'), 'Shift+KeyQ');
    assert.equal(await page.press('#fixture', 'Enter'), 'Enter');
    assert.equal(await decoratedHandle.press('Tab'), 'Tab');
    recorder.recordTriggerAction('page.press', '#fixture', { key: 'Space' });
    await recorder.flushSummary();

    const events = fs.readFileSync(recorder.trafficNdjsonPath, 'utf8').trim().split('\n').map(JSON.parse);
    const keys = events.filter((event) => event.type === 'trigger-action').map((event) => event.metadata.key);
    assert.deepEqual(keys, [undefined, undefined, 'Enter', 'Tab', undefined]);
    const index = JSON.parse(fs.readFileSync(recorder.attributionIndexPath, 'utf8'));
    assert.deepEqual(Object.values(index.byTriggerAction).map((event) => event.metadata.key), keys);
});

test('diagnostic exports also omit printable keys from existing ledgers and indexes', (t) => {
    const outputDir = fixtureDirectory(t);
    const trafficDir = path.join(outputDir, 'profile', 'traffic');
    const recorder = new CamoufoxTrafficRecorder({ trafficDir, recordBodies: false, sslKeyLog: false });
    const press = {
        actionId: 'fixture-press', actionType: 'page.press', target: '#fixture',
        key: 'fixture-legacy-top-key', metadata: { key: 'fixture-legacy-metadata-key' }
    };
    const control = { actionId: 'fixture-control', actionType: 'elementHandle.press', metadata: { key: 'Escape' } };
    const url = 'https://fixture.example.test/items';
    const events = [
        { type: 'trigger-action', ...press, triggerAction: press },
        { type: 'trigger-action', ...control },
        { type: 'egress', method: 'GET', correlationId: 'corr-1', url, triggerAction: press },
        { type: 'ingress', correlationId: 'corr-1', url, status: 200, attribution: { triggerAction: press } }
    ];
    const ledger = events.map((event) => JSON.stringify(event)).join('\n');
    const ledgerPath = path.join(trafficDir, 'traffic.ndjson');
    fs.writeFileSync(ledgerPath, `${ledger}\n`);
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({
        session: { recordBodies: false }, byTriggerAction: { 'fixture-press': press, 'fixture-control': control }
    }));

    const report = queryProfileTraffic({ trafficDir });
    assert.equal(report.byTriggerAction['fixture-control'].metadata.key, 'Escape');
    assert.equal(report.events.find((event) => event.actionId === control.actionId).metadata.key, 'Escape');
    const wire = queryProfileTraffic({ trafficDir, correlationId: 'corr-1' });
    const har = recorder.buildHarArchive();
    for (const diagnostic of [report, wire, har]) {
        assert.doesNotMatch(JSON.stringify(diagnostic), /fixture-legacy-(?:top|metadata)-key/);
    }
    assert.equal(queryProfileTraffic({ trafficDir, trigger: 'fixture-legacy-top-key' }).events.length, 0);
    assert.equal(fs.readFileSync(ledgerPath, 'utf8'), `${ledger}\n`);
});

test('both RTC guards read the supplied configuration once and use captured URL primitives', () => {
    const primaryUrl = 'stun:one.example.test';
    const secondaryUrl = 'stun:two.example.test';
    function check(snapshotConfig) {
        let configReads = 0;
        let serverReads = 0;
        let legacyReads = 0;
        const urls = [primaryUrl];
        const config = {
            iceTransportPolicy: 'relay',
            get iceServers() {
                configReads += 1;
                return [{
                    get urls() { serverReads += 1; return urls; },
                    get url() { legacyReads += 1; return secondaryUrl; }
                }];
            }
        };
        const result = snapshotConfig(config);
        assert.deepEqual([configReads, serverReads, legacyReads], [1, 1, 1]);
        urls[0] = secondaryUrl;
        const [server] = result.iceServers;
        assert.deepEqual([...server.urls], [primaryUrl]);
        assert.equal(server.url, secondaryUrl);
        assert.equal(result.iceTransportPolicy, 'relay');
    }
    check(sanitizeRtcConfigurationIceServers);

    let received;
    function PeerConnection(config) { received = config; }
    PeerConnection.prototype.setConfiguration = function setConfiguration(config) { received = config; };
    const sandbox = { URL, RTCPeerConnection: PeerConnection };
    vm.runInNewContext(buildZiniaoWebRtcSecurityInitScript(), sandbox);
    check((config) => { new sandbox.RTCPeerConnection(config); return received; });
    const peer = new sandbox.RTCPeerConnection();
    check((config) => { peer.setConfiguration(config); return received; });

    const previous = received;
    assert.throws(() => peer.setConfiguration({ iceServers: {} }), /must be provided as an array/);
    assert.equal(received, previous);
    assert.throws(() => sanitizeRtcConfigurationIceServers({ iceServers: {} }), /must be provided as an array/);
});
