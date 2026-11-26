import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    CamoufoxTrafficRecorder, exportTrafficToHar, extractPlatformSignatures, redactProxyUrl, redactUrlSecrets
} from '../../src/camoufox/traffic-recorder.js';
import { createProfile } from '../../src/camoufox/client.js';
import { queryProfileTraffic, reconstructTransactionWireDump } from '../../scripts/query-traffic-attribution.js';

const mask = '[REDACTED]';
const fixtureEmail = 'diagnostic-fixture@person.invalid';
const legacyProfile = 'Gmail_diagnostic-fixture_1710000000000_1710000000001_42';
const publicProfile = 'profile-legacy-1710000000001-42';
const proxyAddress = 'socks5://proxy.example.test:1080';
const compactProxy = proxyAddress + ':fixture-proxy-user:fixture-proxy@password:tail';
const fixtureToken = 'fixture-session-field';
const nestedUrl = 'https://fixture.invalid/callback?access_token=' + fixtureToken + '&view=compact';
const requestUrl = 'https://fixture.invalid/outer?return_to=' +
    encodeURIComponent(encodeURIComponent(nestedUrl)) + '&scope=one&scope=two&code=1379&x-guest-token=' + fixtureToken;
const location = '/next?continue=' + encodeURIComponent(nestedUrl);

function expectReviewableUrls(url, redirect) {
    const parsed = new URL(url);
    assert.deepEqual(parsed.searchParams.getAll('scope'), ['one', 'two']);
    assert.equal(parsed.searchParams.get('code'), mask);
    assert.equal(parsed.searchParams.get('x-guest-token'), mask);
    const nested = new URL(decodeURIComponent(parsed.searchParams.get('return_to')));
    assert.equal(nested.pathname, '/callback');
    assert.equal(nested.searchParams.get('access_token'), mask);
    assert.equal(nested.searchParams.get('view'), 'compact');
    const target = new URL(new URL(redirect, url).searchParams.get('continue'));
    assert.equal(target.searchParams.get('access_token'), mask);
    assert.equal(target.searchParams.get('view'), 'compact');
}

test('URL masking is constant, recursive, bounded, and preserves ordinary parameters', () => {
    const digest = createHash('sha256').update('1379').digest('hex').slice(0, 8);
    const sanitized = redactUrlSecrets(requestUrl);
    expectReviewableUrls(sanitized, redactUrlSecrets(location));
    assert.equal(redactUrlSecrets(requestUrl.replace('1379', '9240')), sanitized);
    assert.equal(redactUrlSecrets(sanitized), sanitized);
    assert.equal(decodeURIComponent(redactUrlSecrets(encodeURIComponent(nestedUrl))), redactUrlSecrets(nestedUrl));
    assert.equal(redactUrlSecrets('/callback?code=[REDACTED:' + digest + ']'), '/callback?code=' + mask);
    assert.equal(redactUrlSecrets('/items?view=compact&title=One+Two&next=orders'),
        '/items?view=compact&title=One+Two&next=orders');
    assert.ok(!sanitized.includes(digest));

    let encoded = nestedUrl;
    for (let i = 0; i < 6; i += 1) encoded = encodeURIComponent(encoded);
    assert.equal(redactUrlSecrets('/next?return_to=' + encoded), '/next?return_to=' + mask);
    let recursive = nestedUrl;
    for (let i = 0; i < 7; i += 1) recursive = '/next?return_to=' + encodeURIComponent(recursive);
    assert.ok(!redactUrlSecrets(recursive).includes(fixtureToken));
    assert.equal(redactUrlSecrets('/next?return_to=' + 'a'.repeat(65_536)), mask);
});

test('proxy descriptors project only the recognized endpoint', () => {
    const fixtures = [
        [compactProxy, proxyAddress],
        ['proxy.example.test:8080:fixture-proxy-user:fixture-proxy@password:tail', 'http://proxy.example.test:8080'],
        ['[2001:db8::1]:8080:fixture-proxy-user:fixture-proxy-password', 'http://[2001:db8::1]:8080'],
        [{ server: compactProxy, username: 'fixture-proxy-user', password: 'fixture-proxy-password' }, proxyAddress],
        [{ host: '2001:db8::1', type: 'SOCKS5://', port: ' 1080 ' }, 'socks5://[2001:db8::1]:1080'],
        [{ host: 'proxy.example.test:8080', type: 'https' }, 'https://proxy.example.test:8080'],
        ['https://fixture-proxy-user:fixture-proxy-password@proxy.example.test:443/path?q=fixture-proxy-query',
            'https://proxy.example.test:443'],
        ['fixture-proxy-user:fixture-proxy-password@proxy.example.test:8080', 'http://proxy.example.test:8080'],
        ['proxy.example.test:invalid:fixture-proxy-unknown', null]
    ];
    for (const [raw, expected] of fixtures) assert.equal(redactProxyUrl(raw), expected);
});

function legacyFixtureRecords() {
    const attribution = {
        profileId: legacyProfile,
        accountId: 'fixture-personal-id',
        accountEmail: fixtureEmail,
        proxyServer: compactProxy,
        actionStep: 'browse'
    };
    const metadata = { email: fixtureEmail, firstName: 'fixture-first-name', lastName: 'fixture-last-name', step: 'browse' };
    const egress = {
        type: 'egress', correlationId: 'offline-fixture', method: 'GET', url: requestUrl, attribution, metadata,
        headers: { 'X-CSRF-Token': fixtureToken, 'X-Guest-Token': fixtureToken },
        headersArray: [
            { name: 'X-Guest-Token', value: fixtureToken },
            { name: 'Accept', value: 'text/plain' },
            { name: 'x-guest-token', value: fixtureToken }
        ],
        searchParams: { return_to: nestedUrl },
        platformSignatures: [{
            signatureName: 'x-guest-token', maskedPreview: fixtureToken, valueLength: 3, valueSha256: 'fixture-digest'
        }]
    };
    const ingress = {
        type: 'ingress', correlationId: egress.correlationId, status: 302, url: requestUrl, attribution,
        headers: { Location: location, 'X-Csrftoken': fixtureToken }
    };
    return { attribution, metadata, egress, ingress };
}

function assertShareable(report) {
    for (const identity of [fixtureEmail, 'diagnostic-fixture', 'fixture-first-name', 'fixture-last-name',
        'fixture-personal-id', 'fixture-proxy-user', 'fixture-proxy@password', fixtureToken, 'fixture-digest']) {
        assert.ok(!JSON.stringify(report).includes(identity), 'a synthetic private field survived the projection');
    }
}

test('legacy wire reconstruction projects nested token, proxy and identity fields', () => {
    const { egress, ingress } = legacyFixtureRecords();
    const wire = reconstructTransactionWireDump({
        profileId: legacyProfile, trafficDir: '/offline-fixture/' + legacyProfile + '/traffic',
        correlationId: egress.correlationId, events: [egress, ingress], recordBodies: false
    });
    assert.equal(wire.profileId, publicProfile);
    assert.equal(wire.egress.attribution.profileId, publicProfile);
    assert.equal(wire.egress.attribution.proxyServer, proxyAddress);
    assert.equal(wire.egress.attribution.accountEmail, null);
    assert.equal(wire.egress.metadata.step, 'browse');
    assert.equal(wire.egress.headers['X-CSRF-Token'], mask);
    assert.equal(wire.ingress.headers['X-Csrftoken'], mask);
    assert.deepEqual(wire.egress.headersArray.map(({ value }) => value), [mask, 'text/plain', mask]);
    assert.deepEqual(wire.egress.platformSignatures[0], {
        signatureName: 'x-guest-token', maskedPreview: mask, valueLength: null, valueSha256: null
    });
    expectReviewableUrls(wire.egress.url, wire.ingress.headers.Location);
    assert.match(wire.wireDump, /scope=one&scope=two/);
    assertShareable(wire);

    const signature = extractPlatformSignatures({ headers: { 'X-Guest-Token': fixtureToken } })[0];
    assert.equal(signature.signatureName, 'x-guest-token');
    assert.equal(signature.maskedPreview, mask);
    assert.equal(signature.valueSha256, null);
});

function directory(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'traffic-redaction-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

test('new default profile IDs are independent of the diagnostic title', async (t) => {
    const profilesDir = directory(t);
    const title = 'local-fixture-display-label';
    const generated = await createProfile(title, null, { profilesDir });
    assert.match(generated.profileId, /^profile-[a-f0-9-]{36}$/);
    assert.equal(path.basename(generated.profileDir), generated.profileId);
    assert.equal(generated.title, title);
    const explicit = await createProfile(title, null, { profilesDir, profileId: 'selected-profile' });
    assert.equal(explicit.profileId, 'selected-profile');
});

test('metadata-only recorder masks credentials consistently in the wire, ledger and HAR', async (t) => {
    const root = directory(t);
    const { egress, ingress, metadata } = legacyFixtureRecords();
    const recorder = new CamoufoxTrafficRecorder({
        profileDir: root, harPath: path.join(root, 'traffic.har'),
        sslKeyLog: false, neckoMozLog: false, recordBodies: false, proxyServer: compactProxy
    });
    recorder.setStep('browse', metadata);
    const transport = new EventEmitter();
    recorder.attachContext(transport);
    const request = {
        url: () => egress.url,
        method: () => 'GET',
        headers: () => egress.headers,
        headersArray: async () => egress.headersArray
    };
    transport.emit('request', request);
    transport.emit('response', {
        request: () => request,
        url: () => request.url(),
        status: () => ingress.status,
        headers: () => ingress.headers
    });
    await recorder.stop();
    const { log } = recorder.exportHar();
    assert.equal(log.entries.length, 1);
    const [entry] = log.entries;
    expectReviewableUrls(entry.request.url, entry.response.redirectURL);
    assert.deepEqual(entry.request.queryString, [...new URL(entry.request.url).searchParams.entries()]
        .map(([name, value]) => ({ name, value })));
    assert.deepEqual(entry.request.headers.map(({ value }) => value), [mask, 'text/plain', mask]);
    assert.equal(entry._attribution.proxyServer, proxyAddress);
    for (const file of [recorder.preTlsWireLogPath, recorder.trafficNdjsonPath, recorder.harPath]) {
        const capture = fs.readFileSync(file, 'utf8');
        assert.ok(capture.includes('scope=one&scope=two'));
        assertShareable(capture);
    }
});

test('legacy archive profile lookup, JSON and HAR use the anonymous profile label', (t) => {
    const root = directory(t);
    const trafficDir = path.join(root, legacyProfile, 'traffic');
    fs.mkdirSync(trafficDir, { recursive: true });
    const { egress, ingress, attribution } = legacyFixtureRecords();
    const ledgerPath = path.join(trafficDir, 'traffic.ndjson');
    fs.writeFileSync(ledgerPath, [egress, ingress].map(JSON.stringify).join('\n') + '\n');
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({
        session: { ...attribution, recordBodies: false }
    }));
    const initialLedger = fs.readFileSync(ledgerPath);

    const list = queryProfileTraffic({ profilesDir: root });
    assert.equal(list.profiles[0].profileId, publicProfile);
    assert.equal(list.profiles[0].proxyServer, proxyAddress);
    assertShareable(list);

    const report = queryProfileTraffic({ profilesDir: root, profile: publicProfile });
    assert.equal(report.transactions.length, 1);
    assert.equal(report.session.profileId, publicProfile);
    assert.equal(report.events[0].metadata.step, 'browse');
    assertShareable(report);

    const { log } = exportTrafficToHar(trafficDir, path.join(root, 'review.har'));
    assert.equal(log.entries[0]._attribution.profileId, publicProfile);
    assert.equal(log.entries[0]._attribution.accountEmail, null);
    assert.equal(log.entries[0]._attribution.proxyServer, proxyAddress);
    assertShareable(log);
    assert.deepEqual(fs.readFileSync(ledgerPath), initialLedger);
});
