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
import {
    redactDiagnosticMetadata, redactDiagnosticText, redactSensitiveHeaders, redactTriggerAction
} from '../../src/camoufox/traffic-redaction.js';
import { createProfile } from '../../src/camoufox/client.js';
import { queryProfileTraffic, reconstructTransactionWireDump } from '../../scripts/query-traffic-attribution.js';

const mask = '[REDACTED]';
const fixtureEmail = 'diagnostic-fixture@person.invalid';
const legacyProfile = 'Gmail_diagnostic-fixture_1710000000000_1710000000001_42';
const publicProfile = 'profile-legacy-1710000000001-42';
const proxyAddress = 'socks5://proxy.example.test:1080';
const compactProxy = proxyAddress + ':fixture-proxy-user:fixture-proxy@password:tail';
const fixtureToken = 'fixture-session-field';
const fixtureSignature = 'fixture-signing-material';
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

const privatePlatformFields = new Map([
    ['verifyFp', 'verifyFp'], ['s_v_web_id', 's_v_web_id'], ['msToken', 'msToken'], ['odin_tt', 'odin_tt'],
    ['ttwid', 'ttwid'], ['X-Ig-Www-Claim', 'x-ig-www-claim'],
    ['fc_token', 'fc-token'], ['cf-turnstile-response', 'cf-turnstile-response']
]);

test('known private platform fields hide values and stable digests across projections', () => {
    const parameters = [...privatePlatformFields.keys()].map(name => [name, fixtureToken]);
    const url = 'https://fixture.invalid/events?' + new URLSearchParams([...parameters, ['view', 'compact']]);
    const headers = Object.fromEntries([...parameters, ['Accept', 'text/plain'], ['CF-Ray', 'fixture-request-label']]);
    const safeUrl = redactUrlSecrets(url);
    const safeHeaders = redactSensitiveHeaders({ headers }).headers;
    for (const name of privatePlatformFields.keys()) {
        assert.equal(new URL(safeUrl).searchParams.get(name), mask, name);
        assert.equal(safeHeaders[name], mask, name);
    }
    assert.equal(new URL(safeUrl).searchParams.get('view'), 'compact');
    assert.equal(safeHeaders.Accept, 'text/plain');
    assert.equal(safeHeaders['CF-Ray'], 'fixture-request-label');

    const signatures = extractPlatformSignatures({ url, headers });
    for (const signatureName of privatePlatformFields.values()) {
        const matches = signatures.filter(signature => signature.signatureName === signatureName);
        assert.equal(matches.length, 2, signatureName);
        for (const signature of matches) {
            assert.equal(signature.maskedPreview, mask);
            assert.equal(signature.valueSha256, null);
            assert.equal(signature.valueLength, null);
        }
    }
    const archivedSignature = {
        signatureName: 'verifyFp', location: 'header', valueLength: 10,
        maskedPreview: 'fixture-preview-label', valueSha256: 'fixture-digest-label'
    };
    assert.deepEqual(redactDiagnosticMetadata(archivedSignature), {
        signatureName: 'verifyFp', location: 'header', valueLength: null, maskedPreview: mask, valueSha256: null
    });
});

const encodedQueryEmail = 'fixture.reader%40department%2einvalid';

test('URL identity masking inspects decoded free-text parameters and preserves ordinary context', () => {
    const url = 'https://fixture.invalid/find?q=Note+' + encodedQueryEmail + '&q=One%2eTwo&view=compact';
    const sanitized = redactUrlSecrets(url);
    assert.deepEqual([...new URL(sanitized).searchParams], [
        ['q', 'Note ' + mask], ['q', 'One.Two'], ['view', 'compact']
    ]);
    assert.ok(sanitized.includes('q=One%2eTwo'));
    assert.equal(redactUrlSecrets(sanitized), sanitized);
    const twiceEncoded = encodeURIComponent(encodedQueryEmail);
    const nested = new URL(redactUrlSecrets('https://fixture.invalid/find?q=' + twiceEncoded));
    assert.equal(decodeURIComponent(nested.searchParams.get('q')), mask);
    const encodedDomain = 'fixture.reader@département.invalid'.replace('é', '%C3%A9');
    assert.equal(new URL(redactUrlSecrets('https://fixture.invalid/find?q=' + encodedDomain)).searchParams.get('q'), mask);
});

test('percent-encoded identity is removed from URL paths without rewriting other segments', () => {
    const email = 'synthetic%2Ereader%40person%2Einvalid';
    const route = 'https://fixture.invalid/folder/' + email + '/notes%2Ejson?view=compact';
    const redacted = 'https://fixture.invalid/folder/' + mask + '/notes%2Ejson?view=compact';
    assert.equal(redactUrlSecrets(route), redacted);
    assert.equal(redactUrlSecrets(redacted), redacted);
    assert.equal(redactDiagnosticText('Failed to navigate to ' + route), 'Failed to navigate to ' + redacted);
});

test('inline authentication and absolute paths in file errors are removed from diagnostics', () => {
    const original = "Request failed (pRoXy-AuThOrIzAtIoN: Bearer synthetic-inline). " +
        "ENOENT: copyfile '/Users/fixture-operator/Two Words.json' -> 'C:\\Fixture\\Two Words.json'";
    const expected = "Request failed (pRoXy-AuThOrIzAtIoN: Bearer " + mask + "). " +
        "ENOENT: copyfile '" + mask + "' -> '" + mask + "'";
    assert.equal(redactDiagnosticText(original), expected);
    assert.equal(redactDiagnosticText(expected), expected);
    assert.equal(redactDiagnosticText('Could not open /opt/fixture-account/log.txt'), 'Could not open ' + mask);
    assert.equal(redactDiagnosticText('GET /notes/part%2Ejson'), 'GET /notes/part%2Ejson');
});

const diagnosticUrl = 'https://fixture.invalid/collection(review)?token=' + fixtureToken;
const localFileUrl = 'file:///Users/fixture-operator/Documents/fixture-local-document.pdf';

test('diagnostic URL redaction preserves legal path and surrounding punctuation', () => {
    assert.equal(redactDiagnosticText('Connection failed (' + diagnosticUrl + '). Try again.'),
        'Connection failed (https://fixture.invalid/collection(review)?token=' + mask + '). Try again.');
    assert.equal(redactDiagnosticText('Failure: redirect response\n  Location: next?token=' + fixtureToken + '&view=compact'),
        'Failure: redirect response\n  Location: next?token=' + mask + '&view=compact');
    assert.equal(redactDiagnosticText('Failure: request headers\n  Authorization: Bearer\r\n  fixture:' + fixtureToken),
        'Failure: request headers\n  Authorization: Bearer ' + mask);
});

test('local file references retain the scheme and omit the path', () => {
    assert.equal(redactUrlSecrets(localFileUrl), 'file:' + mask);
    assert.equal(redactUrlSecrets('jar:' + localFileUrl + '!/sample'), 'jar:file:' + mask);
    assert.equal(redactUrlSecrets('https://fixture.invalid/?next=' + encodeURIComponent(localFileUrl)),
        'https://fixture.invalid/?next=' + encodeURIComponent('file:' + mask));
    assert.equal(redactDiagnosticText('Blocked "' + localFileUrl + '"'), 'Blocked "file:' + mask + '"');
    assert.equal(redactDiagnosticText('Blocked "file:///Users/fixture-operator/Fixture Review.pdf".'),
        'Blocked "file:' + mask + '".');
    const trigger = redactTriggerAction({ actionType: 'page.goto', target: localFileUrl, metadata: { url: localFileUrl } });
    assert.equal(trigger.target, 'file:' + mask);
    assert.equal(trigger.metadata.url, trigger.target);

    const archived = {
        type: 'request-failed', correlationId: 'fixture-local-failure', url: localFileUrl,
        pathname: new URL(localFileUrl).pathname, method: 'GET', failureText: 'Denied "' + localFileUrl + '"'
    };
    const wire = reconstructTransactionWireDump({
        profileId: 'fixture', trafficDir: '/unused', correlationId: archived.correlationId,
        events: [archived], recordBodies: false
    });
    assert.equal(wire.failed.pathname, mask);
    assert.equal(wire.failed.method, 'GET');
    assert.ok(!JSON.stringify(wire).includes('fixture-operator'));
});

test('Signed URLs mask authentication material while retaining diagnostic parameters', () => {
    const fixtures = [
        ['X-Amz-Signature X-Amz-Credential X-Amz-Security-Token', 'X-Amz-Expires=3600'],
        ['X-Goog-Signature X-Goog-Credential', 'X-Goog-SignedHeaders=host'],
        ['Policy Signature Key-Pair-Id', 'download=inline'],
        ['sig', 'sv=2025-01-01&sp=r'],
        ['AWSAccessKeyId Signature', 'Expires=12345'],
        ['GoogleAccessId Signature', 'Expires=12345'],
        ['auth_key', 'view=compact']
    ];
    for (const [fields, publicQuery] of fixtures) {
        const query = value => fields.split(' ').map(field => `${field}=${value}`).join('&');
        const url = `//files.example.test/items/123?${query(fixtureSignature)}&${publicQuery}`;
        const expected = `//files.example.test/items/123?${query(mask)}&${publicQuery}`;
        assert.equal(redactUrlSecrets(url), expected);
        assert.equal(redactUrlSecrets(expected), expected);
    }
    const signedRelative = '/report?X%2dAmz%2dSignature=' + fixtureSignature + '&view=compact';
    const maskedRelative = '/report?X%2dAmz%2dSignature=' + mask + '&view=compact';
    assert.equal(redactUrlSecrets('/next?target=' + encodeURIComponent(signedRelative)),
        '/next?target=' + encodeURIComponent(maskedRelative));
    const publicPolicy = '/report?policy=organization&view=compact';
    assert.equal(redactUrlSecrets(publicPolicy), publicPolicy);
    const { searchParams } = redactDiagnosticMetadata({
        searchParams: { Policy: fixtureSignature, Signature: fixtureSignature, 'Key-Pair-Id': fixtureSignature }
    });
    assert.deepEqual(searchParams, { Policy: mask, Signature: mask, 'Key-Pair-Id': mask });
});

test('Authentication headers retain their names, order, and recognized schemes', () => {
    const credentialHeaders = {
        'X-Auth-Token': fixtureToken,
        'x-access-token': fixtureToken,
        'X-Goog-Api-Key': fixtureToken,
        'Private-Token': fixtureToken,
        'Authentication-Info': `nextnonce="${fixtureToken}"`,
        'X-Amz-Security-Token': fixtureToken,
        'X-Session-Id': fixtureToken,
        'X-Auth': fixtureToken,
        'X-Signature': fixtureToken
    };
    const ordinaryHeaders = {
        'X-Auth-Token-Status': 'accepted',
        Accept: 'text/plain'
    };
    const headers = { ...credentialHeaders, 'X-Authorization': `Bearer ${fixtureToken}`, ...ordinaryHeaders };
    const expected = {
        ...Object.fromEntries(Object.keys(credentialHeaders).map(name => [name, mask])),
        'X-Authorization': `Bearer ${mask}`,
        ...ordinaryHeaders
    };
    const headersArray = Object.entries(headers).map(([name, value]) => ({ name, value }));
    headersArray.push({ name: 'X-Auth-Token', value: fixtureSignature });
    const firstPass = redactSensitiveHeaders({ headers, headersArray });
    assert.deepEqual(firstPass, {
        headers: expected,
        headersArray: [...Object.entries(expected).map(([name, value]) => ({ name, value })),
            { name: 'X-Auth-Token', value: mask }]
    });
    assert.deepEqual(redactSensitiveHeaders(firstPass), firstPass);
    assert.equal(redactDiagnosticText(`X-Auth-Token: ${fixtureToken}\nAccept: text/plain`),
        `X-Auth-Token: ${mask}\nAccept: text/plain`);
});

test('Link masking covers URL-valued parameters and preserves ordinary attributes', () => {
    const link = value => `<https://files.example.test/doc?sig=${value}&view=compact>; rel="next"; ` +
        `anchor="related?X-Goog-Signature=${value}&page=2"; title="A, B; C", ` +
        `<../ordinary?page=1>; rel=prev; context='#/archive?token=${value}'`;
    const output = redactSensitiveHeaders({ headers: { Link: link(fixtureSignature) } });
    assert.equal(output.headers.Link, link(mask));
    assert.deepEqual(redactSensitiveHeaders(output), output);
    const escaped = String.raw`</doc>; anchor="relative?s\ig=${fixtureSignature}&view=compact"`;
    assert.equal(redactSensitiveHeaders({ headers: { Link: escaped } }).headers.Link,
        `</doc>; anchor="relative?sig=${mask}&view=compact"`);
    assert.equal(redactDiagnosticMetadata({ headers: { Link: link(fixtureSignature) } }).headers.Link, link(mask));
    const folded = value => 'Link:\t' + link(value).replace('; anchor=', ';\r\n anchor=');
    assert.equal(redactDiagnosticText(folded(fixtureSignature)), folded(mask));
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
        ['proxy.example.test:invalid:fixture-proxy-unknown', null],
        ['https://fixture-proxy-user:1234:fixture-proxy-password@proxy.example.test:8443/path', null]
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
        type: 'egress', correlationId: 'offline-fixture', method: 'GET',
        url: requestUrl + '&X-Amz-Signature=' + fixtureSignature, attribution, metadata,
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
        headers: {
            Location: location,
            'X-Csrftoken': fixtureToken,
            'X-Auth-Token': fixtureToken,
            Link: `</resource>; rel="help"; anchor="related?sig=${fixtureSignature}&view=compact"`
        }
    };
    return { attribution, metadata, egress, ingress };
}

function assertShareable(report) {
    for (const identity of [fixtureEmail, 'diagnostic-fixture', 'fixture-first-name', 'fixture-last-name',
        'fixture-personal-id', 'fixture-proxy-user', 'fixture-proxy@password', fixtureToken, fixtureSignature, 'fixture-digest']) {
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

test('stored and exported traffic omit private URL and signature metadata', async (t) => {
    const root = directory(t);
    const recorder = new CamoufoxTrafficRecorder({
        profileDir: root, harPath: path.join(root, 'traffic.har'), recordBodies: false
    });
    const transport = new EventEmitter();
    recorder.attachContext(transport);
    recorder.recordTriggerAction('page.goto', localFileUrl, { url: localFileUrl });
    const blocked = recorder.recordSecurityBlock({
        type: 'internal-scheme-probe', targetUrl: localFileUrl, matchedScheme: 'file',
        reason: 'Blocked "' + localFileUrl + '"'
    });
    const request = {
        url: () => 'https://fixture.invalid/find?q=' + encodedQueryEmail + '&view=compact',
        method: () => 'GET',
        headers: () => ({ Accept: 'text/plain', VerifyFp: fixtureSignature }),
        failure: () => ({ errorText: 'Connection failed (' + diagnosticUrl + ').' })
    };
    transport.emit('request', request);
    transport.emit('requestfailed', request);
    await recorder.stop();

    const { log } = recorder.exportHar();
    const requestEntry = log.entries.find(entry => entry.request.method === 'GET' && !entry._camoufoxSecurityBlock);
    const blockedEntry = log.entries.find(entry => entry._camoufoxSecurityBlock);
    assert.deepEqual(requestEntry.request.queryString, [{ name: 'q', value: mask }, { name: 'view', value: 'compact' }]);
    assert.equal(requestEntry.request.headers.find(({ name }) => name === 'VerifyFp').value, mask);
    assert.match(requestEntry._attribution.failureText, /collection\(review\)\?token=\[REDACTED\]/);
    assert.equal(blockedEntry.request.url, 'file:' + mask);
    assert.equal(blockedEntry._camoufoxSecurityBlock.matchedScheme, 'file');

    const signatures = queryProfileTraffic({ trafficDir: recorder.trafficDir, signatures: true });
    assert.equal(signatures.count, 1);
    assert.equal(signatures.signatures[0].valueSha256, null);
    const block = queryProfileTraffic({ trafficDir: recorder.trafficDir, correlation: blocked.correlationId });
    assert.equal(block.securityBlock.url, 'file:' + mask);
    const record = queryProfileTraffic({ trafficDir: recorder.trafficDir, correlation: requestEntry._attribution.correlationId });
    assert.match(record.wireDump, /collection\(review\)\?token=\[REDACTED\]/);

    for (const file of [recorder.trafficNdjsonPath, recorder.preTlsWireLogPath, recorder.harPath]) {
        const saved = fs.readFileSync(file, 'utf8');
        for (const marker of [encodedQueryEmail, 'fixture.reader@department.invalid', 'fixture-operator',
            'fixture-local-document', fixtureToken, fixtureSignature]) {
            assert.ok(!saved.includes(marker), path.basename(file));
        }
    }
});

test('new captures and shared reports omit private query, action and failure details', async (t) => {
    const root = directory(t);
    const recorder = new CamoufoxTrafficRecorder({
        profileDir: root, harPath: path.join(root, 'traffic.har'), recordBodies: false
    });
    const transport = new EventEmitter();
    recorder.attachContext(transport);
    const frame = { url: () => 'https://fixture.invalid/' };
    const fields = {
        ReCoVeRyPhOnE: ['+12025550149', '+12025550150'],
        birthdate: '1990-01-02',
        ClIeNt_AsSeRtIoN: 'synthetic-assertion',
        code_verifier: 'synthetic-verifier'
    };
    const params = new URLSearchParams();
    for (const [name, value] of Object.entries(fields)) {
        for (const item of [].concat(value)) params.append(name, item);
    }
    params.set('view', 'compact');
    recorder.recordTriggerAction('locator.click', '#fixture', { details: [fields] }, frame);
    const request = {
        frame: () => frame,
        url: () => 'https://fixture.invalid/contact/synthetic%40person%2Einvalid?' + params,
        method: () => 'GET',
        headers: () => ({}),
        failure: () => ({ errorText: "Request failed (Authorization: Bearer synthetic-inline). " +
            "ENOENT: open '/Users/fixture-operator/Two Words.json'" })
    };
    transport.emit('request', request);
    transport.emit('requestfailed', request);
    await recorder.stop();

    const { log } = recorder.exportHar();
    const [entry] = log.entries;
    assert.equal(new URL(entry.request.url).pathname, '/contact/' + mask);
    for (const name of Object.keys(fields)) {
        const expected = [].concat(fields[name]).map(() => mask);
        assert.deepEqual(new URL(entry.request.url).searchParams.getAll(name), expected);
        assert.equal(entry._attribution.triggerAction.metadata.details[0][name], mask);
    }
    assert.equal(new URL(entry.request.url).searchParams.get('view'), 'compact');
    const wire = queryProfileTraffic({ trafficDir: recorder.trafficDir, correlation: entry._attribution.correlationId });
    const profile = queryProfileTraffic({ trafficDir: recorder.trafficDir });
    assert.equal(wire.failed.failureText, "Request failed (Authorization: Bearer " + mask + "). ENOENT: open '" + mask + "'");
    for (const report of [log, wire, profile, fs.readFileSync(recorder.trafficNdjsonPath, 'utf8')]) {
        const output = JSON.stringify(report);
        for (const value of [...Object.values(fields).flat(), 'synthetic-inline', 'fixture-operator',
            'synthetic%40person%2Einvalid', 'synthetic@person.invalid']) {
            assert.ok(!output.includes(value), 'private fixture value survived projection');
        }
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
    const [entry] = log.entries;
    assert.equal(entry._attribution.profileId, publicProfile);
    assert.equal(entry._attribution.accountEmail, null);
    assert.equal(entry._attribution.proxyServer, proxyAddress);
    assert.ok(entry.request.queryString.some(({ name, value }) => name === 'X-Amz-Signature' && value === mask));
    assert.ok(entry.response.headers.some(({ name, value }) => name === 'X-Auth-Token' && value === mask));
    assert.equal(entry.response.headers.find(({ name }) => name === 'Link').value,
        `</resource>; rel="help"; anchor="related?sig=${mask}&view=compact"`);
    assertShareable(log);
    assert.deepEqual(fs.readFileSync(ledgerPath), initialLedger);
});
