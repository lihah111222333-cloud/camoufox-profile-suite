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

test('HTTP redirect targets and file operation destinations keep their separate privacy rules', () => {
    const diagnostic = 'Redirect failed: /previous -> /next?view=compact&token=' + fixtureToken + ' (HTTP 302)';
    assert.equal(redactDiagnosticText(diagnostic),
        'Redirect failed: /previous -> /next?view=compact&token=' + mask + ' (HTTP 302)');
    assert.equal(redactDiagnosticText("EXDEV: rename 'relative.txt' -> '/opt/fixture-private/destination.txt'"),
        "EXDEV: rename 'relative.txt' -> '" + mask + "'");
    assert.equal(redactDiagnosticText("EXDEV: copyfile '/opt/fixture-private/a -> b' -> '/opt/fixture-private/out'"),
        "EXDEV: copyfile '" + mask + "' -> '" + mask + "'");
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

test('the inventory proxy descriptor produces an endpoint-only value for logs', async () => {
    const { default: proxyManager } = await import('../../src/utils/proxy-manager.js');
    const proxy = proxyManager.parseProxyLine(compactProxy);
    assert.ok(proxy?.username && proxy?.password);
    assert.equal(redactProxyUrl(proxy), proxyAddress);
    assert.equal(redactProxyUrl(proxyManager.parseProxyLine('invalid proxy descriptor')), null);
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

const contactsByEmail = {
    [fixtureEmail]: { email: fixtureEmail, state: 'pending' },
    [mask + ' 1']: { state: 'literal' },
    'second%40person%2Einvalid': { state: 'ready' },
    ordinary: { state: 'queued' }
};
const projectedContacts = {
    [mask + ' 2']: { email: mask, state: 'pending' },
    [mask + ' 1']: { state: 'literal' },
    [mask + ' 3']: { state: 'ready' },
    ordinary: { state: 'queued' }
};

test('diagnostic metadata gives private identity keys distinct collision-free labels', () => {
    const raw = { details: [{ contacts: contactsByEmail }] };
    const expected = { details: [{ contacts: projectedContacts }] };
    assert.deepEqual(redactDiagnosticMetadata(raw), expected);
    assert.deepEqual(redactDiagnosticMetadata(expected), expected);
    assert.ok(Object.hasOwn(contactsByEmail, fixtureEmail));
});

test('metadata key privacy holds in new recordings and when projecting existing ledgers', async (t) => {
    const root = directory(t);
    const recorder = new CamoufoxTrafficRecorder({
        profileDir: root, harPath: path.join(root, 'traffic.har'), recordBodies: false
    });
    const transport = new EventEmitter();
    recorder.attachContext(transport);
    const frame = { url: () => 'https://fixture.invalid/' };
    const metadata = { contacts: contactsByEmail };
    const action = recorder.recordTriggerAction('locator.click', '#fixture', metadata, frame);
    const request = {
        frame: () => frame, url: () => 'https://fixture.invalid/items', method: () => 'GET', headers: () => ({})
    };
    transport.emit('request', request);
    await recorder.stop();

    const ledger = fs.readFileSync(recorder.trafficNdjsonPath, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(ledger.find(({ type }) => type === 'trigger-action').metadata.contacts, projectedContacts);
    const { log } = recorder.exportHar();
    assert.deepEqual(log.entries[0]._attribution.triggerAction.metadata.contacts, projectedContacts);
    const id = log.entries[0]._attribution.correlationId;
    const newWire = queryProfileTraffic({ trafficDir: recorder.trafficDir, correlation: id });
    assert.deepEqual(newWire.egress.triggerAction.metadata.contacts, projectedContacts);

    const legacyDir = path.join(root, 'legacy', 'traffic');
    fs.mkdirSync(legacyDir, { recursive: true });
    const legacy = {
        type: 'egress', timestamp: '2025-01-01T00:00:00.000Z', correlationId: 'legacy-contact-map',
        url: request.url(), method: 'GET', triggerAction: { ...action, metadata }
    };
    const legacyLedger = path.join(legacyDir, 'traffic.ndjson');
    const original = JSON.stringify(legacy) + '\n';
    fs.writeFileSync(legacyLedger, original, { mode: 0o600 });
    const legacyHar = exportTrafficToHar(legacyDir, path.join(root, 'legacy.har'));
    assert.deepEqual(legacyHar.log.entries[0]._attribution.triggerAction.metadata.contacts, projectedContacts);
    const legacyProfile = queryProfileTraffic({ trafficDir: legacyDir });
    assert.deepEqual(legacyProfile.transactions[0].egress.triggerAction.metadata.contacts, projectedContacts);
    assert.equal(fs.readFileSync(legacyLedger, 'utf8'), original);
});

test('URL parameter identity keys are projected consistently across capture and export', async (t) => {
    const root = directory(t);
    const recorder = new CamoufoxTrafficRecorder({
        profileDir: root, harPath: path.join(root, 'traffic.har'), recordBodies: false
    });
    const transport = new EventEmitter();
    recorder.attachContext(transport);
    const internationalEmail = 'fixture-reader@département.invalid';
    const literalLabel = mask + ' 1';
    const rawQuery = new URLSearchParams([
        [internationalEmail, 'first'], ['view', 'compact'], [internationalEmail, 'second'],
        [literalLabel, 'literal'], [fixtureEmail, 'third'], ['q', internationalEmail], ['access_token', fixtureToken]
    ]);
    const url = 'https://fixture.invalid/items?' + rawQuery + '&ordinary=%2B37&compact';
    const expected = [
        [mask + ' 2', 'first'], ['view', 'compact'], [mask + ' 2', 'second'],
        [literalLabel, 'literal'], [mask + ' 3', 'third'], ['q', mask], ['access_token', mask],
        ['ordinary', '+37'], ['compact', '']
    ];
    const sanitized = redactUrlSecrets(url);
    assert.deepEqual([...new URL(sanitized).searchParams], expected);
    assert.equal(redactUrlSecrets(sanitized), sanitized);
    assert.ok(sanitized.endsWith('&ordinary=%2B37&compact'));
    assert.deepEqual([...new URLSearchParams(redactUrlSecrets('/items#?' + rawQuery).split('#?')[1])],
        expected.slice(0, 7));

    transport.emit('request', { url: () => url, method: () => 'GET', headers: () => ({}) });
    await recorder.stop();
    const ledger = fs.readFileSync(recorder.trafficNdjsonPath, 'utf8').trim().split('\n').map(JSON.parse);
    const egress = ledger.find(({ type }) => type === 'egress');
    const har = recorder.exportHar().log.entries[0];
    const wire = queryProfileTraffic({ trafficDir: recorder.trafficDir, correlation: egress.correlationId });
    const profile = queryProfileTraffic({ trafficDir: recorder.trafficDir }).transactions[0];
    for (const recorded of [egress, wire.egress, profile.egress]) {
        assert.deepEqual([...new URL(recorded.url).searchParams], expected);
        assert.deepEqual(recorded.searchParams[mask + ' 2'], ['first', 'second']);
        assert.equal(recorded.searchParams[literalLabel], 'literal');
        assert.equal(recorded.searchParams[mask + ' 3'], 'third');
        assert.ok(!Object.hasOwn(recorded.searchParams, internationalEmail));
        assert.ok(!Object.hasOwn(recorded.searchParams, fixtureEmail));
    }
    assert.deepEqual(har.request.queryString, expected.map(([name, value]) => ({ name, value })));
});

test('OIDC hints are masked without rewriting ordinary query values', () => {
    const url = 'https://fixture.invalid/logout?id%5Ftoken_hint=fixture.id.token&login_hint=fixture-login' +
        '&logout_hint=fixture-logout&view=compact&view=full&state=ready';
    const expected = 'https://fixture.invalid/logout?id%5Ftoken_hint=' + mask + '&login_hint=' + mask +
        '&logout_hint=' + mask + '&view=compact&view=full&state=ready';
    assert.equal(redactUrlSecrets(url), expected);
    assert.equal(redactUrlSecrets(expected), expected);
});

test('Refresh and SourceMap project relative URL targets and preserve their header syntax', () => {
    const rawTarget = 'relative?access_token=fixture-refresh-token&view=compact';
    const safeTarget = 'relative?access_token=' + mask + '&view=compact';
    const pairs = [
        ['Refresh', '0; ' + rawTarget, '0; ' + safeTarget],
        ['Refresh', '2; url="' + rawTarget + '"', '2; url="' + safeTarget + '"'],
        ['Refresh', "3.5 , URL = '" + rawTarget + "'  ", "3.5 , URL = '" + safeTarget + "'  "],
        ['Refresh', '4 ' + rawTarget, '4 ' + safeTarget],
        ['Refresh', '5', '5'],
        ['Refresh', 'url="' + rawTarget + '"', 'url="' + safeTarget + '"'],
        ['Refresh', '6; relative?view=compact', '6; relative?view=compact'],
        ['SourceMap', rawTarget, safeTarget],
        ['X-SourceMap', 'bundle.js.map?view=compact', 'bundle.js.map?view=compact']
    ];
    const headersArray = pairs.map(([name, value]) => ({ name, value }));
    const expected = pairs.map(([name, , value]) => ({ name, value }));
    const projected = redactSensitiveHeaders({ headersArray });
    assert.deepEqual(projected.headersArray, expected);
    assert.deepEqual(redactSensitiveHeaders(projected), projected);
    assert.equal(redactDiagnosticText('SourceMap: ' + rawTarget), 'SourceMap: ' + safeTarget);
});

const routeEmail = 'fixture-route@département.invalid';
const encodedRouteEmail = encodeURIComponent(routeEmail);
const routePrefix = 'https://fixture.invalid/app#/inbox/';

test('fragment routes redact encoded identity and keep ordinary paths and queries', () => {
    const query = '?view=compact&format=a%2Bb';
    const ordinaryPath = routePrefix + 'quarter%2Ejson' + query;
    assert.equal(redactUrlSecrets(routePrefix + encodedRouteEmail + query), routePrefix + mask + query);
    assert.equal(redactUrlSecrets(ordinaryPath), ordinaryPath);
});

test('Content-Disposition projects plain and extended filename identity values', () => {
    const filename = 'attachment; filename="Report; ' + routeEmail + '.pdf"; ' +
        "filename*=UTF-8'en'" + encodedRouteEmail + '.pdf; size=12';
    const expected = 'attachment; filename="' + mask + '"; ' +
        "filename*=UTF-8'en'" + encodeURIComponent(mask) + '; size=12';
    const ordinary = 'inline; filename="Résumé; final.pdf"; ' +
        "filename*=UTF-8''R%C3%A9sum%C3%A9%20final.pdf";
    const project = value => redactSensitiveHeaders({ headers: { 'Content-Disposition': value } })
        .headers['Content-Disposition'];
    assert.equal(project(filename), expected);
    assert.equal(project(expected), expected);
    assert.equal(project(ordinary), ordinary);
    assert.equal(project("inline; filename*=ISO-8859-1''fixture%40d%E9partement.invalid.pdf"),
        "inline; filename*=ISO-8859-1''" + encodeURIComponent(mask));
    assert.equal(redactDiagnosticText('Content-Disposition: ' + filename), 'Content-Disposition: ' + expected);
});

test('external handler URLs retain scheme names in direct, linked, and nested projections', () => {
    const links = [
        ['MaIlTo:', 'fixture@contact.invalid?subject=fixture-subject&body=fixture-message'],
        ['sms:', '+12025550123?body=fixture-text'],
        ['tel:', '+12025550124'],
        ['geo:', '12.3456,76.5432']
    ];
    for (const [scheme, content] of links) {
        const url = scheme + content;
        const safeUrl = scheme + mask;
        assert.equal(redactUrlSecrets(url), safeUrl);
        assert.deepEqual(redactSensitiveHeaders({ headers: {
            Location: url, Link: '<' + url + '>; rel="author", </public?view=compact>; rel="next"'
        } }).headers, {
            Location: safeUrl, Link: '<' + safeUrl + '>; rel="author", </public?view=compact>; rel="next"'
        });
        assert.equal(redactUrlSecrets('/next?target=' + encodeURIComponent(url)),
            '/next?target=' + encodeURIComponent(safeUrl));
    }
});

test('new recordings and legacy exports share URL and response-header privacy', async (t) => {
    const root = directory(t);
    const recorder = new CamoufoxTrafficRecorder({
        profileDir: root, harPath: path.join(root, 'traffic.har')
    });
    const transport = new EventEmitter();
    recorder.attachContext(transport);

    const idHint = 'fixture-private-id-hint';
    const refreshToken = 'fixture-private-refresh';
    const mapToken = 'fixture-private-map';
    const message = 'fixture-private-subject';
    const frameUrl = routePrefix + encodedRouteEmail + '?view=compact';
    const safeFrameUrl = routePrefix + mask + '?view=compact';
    const sourceUrl = 'https://fixture.invalid/logout?id_token_hint=' + idHint + '&view=compact';
    const safeSourceUrl = 'https://fixture.invalid/logout?id_token_hint=' + mask + '&view=compact';
    const headers = {
        Refresh: '0; callback?access_token=' + refreshToken + '&view=compact',
        'X-SourceMap': 'bundle.js.map?token=' + mapToken + '&view=compact',
        Location: frameUrl,
        'Content-Disposition': "attachment; filename*=UTF-8''" + encodedRouteEmail + '.pdf',
        Link: '<mailto:fixture@contact.invalid?subject=' + message + '>; rel=author'
    };
    const safeHeaders = {
        Refresh: '0; callback?access_token=' + mask + '&view=compact',
        'X-SourceMap': 'bundle.js.map?token=' + mask + '&view=compact',
        Location: safeFrameUrl,
        'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(mask),
        Link: '<mailto:' + mask + '>; rel=author'
    };

    const headersArray = Object.entries(headers).map(([name, value]) => ({ name, value }));
    const safeHeadersArray = Object.entries(safeHeaders).map(([name, value]) => ({ name, value }));
    const req = { url: () => sourceUrl, method: () => 'GET', frame: () => ({ url: () => frameUrl }) };
    transport.emit('request', req);
    transport.emit('response', {
        request: () => req, url: req.url, status: () => 302,
        headers: () => headers, headersArray: async () => headersArray
    });
    await recorder.stop();

    const ledger = fs.readFileSync(recorder.trafficNdjsonPath, 'utf8').trim().split('\n').map(JSON.parse);
    const egress = ledger.find(({ type }) => type === 'egress');
    const ingress = ledger.find(({ type }) => type === 'ingress');
    assert.equal(egress.url, safeSourceUrl);
    assert.equal(egress.frameUrl, safeFrameUrl);
    assert.equal(egress.recordBodies, false);
    assert.deepEqual(ingress.headers, safeHeaders);
    assert.deepEqual(ingress.headersArray, safeHeadersArray);

    const legacyDir = path.join(root, 'legacy', 'traffic');
    fs.mkdirSync(legacyDir, { recursive: true, mode: 0o700 });
    const legacyLedger = path.join(legacyDir, 'traffic.ndjson');
    const archived = [
        { type: 'egress', timestamp: egress.timestamp, correlationId: 'legacy-url-fields',
            url: sourceUrl, frameUrl, method: 'GET', searchParams: { id_token_hint: idHint, view: 'compact' } },
        { type: 'ingress', timestamp: ingress.timestamp, correlationId: 'legacy-url-fields',
            url: sourceUrl, status: 302, headers, headersArray }
    ].map(JSON.stringify).join('\n') + '\n';
    fs.writeFileSync(legacyLedger, archived, { mode: 0o600 });

    const projected = [
        [recorder.trafficDir, egress.correlationId, recorder.exportHar().log.entries[0]],
        [legacyDir, 'legacy-url-fields', exportTrafficToHar(legacyDir, path.join(root, 'legacy.har')).log.entries[0]]
    ];
    const privateMarkers = [idHint, refreshToken, mapToken, routeEmail, encodedRouteEmail, message];
    const assertPrivateFieldsAbsent = (value) => {
        for (const marker of privateMarkers) assert.ok(!value.includes(marker), 'private field in traffic projection');
    };
    for (const [trafficDir, correlation, entry] of projected) {
        const wire = queryProfileTraffic({ trafficDir, correlation });
        assert.equal(wire.egress.url, safeSourceUrl);
        assert.equal(wire.egress.searchParams.id_token_hint, mask);
        assert.equal(wire.egress.frameUrl, safeFrameUrl);
        assert.deepEqual(wire.ingress.headers, safeHeaders);
        assert.deepEqual(wire.ingress.headersArray, safeHeadersArray);
        assert.deepEqual(entry.request.queryString, [
            { name: 'id_token_hint', value: mask }, { name: 'view', value: 'compact' }
        ]);
        assert.equal(entry.response.redirectURL, safeFrameUrl);
        assert.deepEqual(entry.response.headers, safeHeadersArray);
        assertPrivateFieldsAbsent(JSON.stringify([entry, wire]));
    }
    const wireLog = fs.readFileSync(recorder.preTlsWireLogPath, 'utf8');
    assert.ok(wireLog.includes('GET /logout?id_token_hint=' + mask + '&view=compact HTTP/1.1'));
    for (const [name, value] of Object.entries(safeHeaders)) assert.ok(wireLog.includes(name + ': ' + value));
    for (const file of [recorder.trafficNdjsonPath, recorder.preTlsWireLogPath, recorder.harPath]) {
        assertPrivateFieldsAbsent(fs.readFileSync(file, 'utf8'));
    }
    assert.equal(fs.readFileSync(legacyLedger, 'utf8'), archived);
});

test('legacy group projection retains a count for each colliding private step', (t) => {
    const trafficDir = path.join(directory(t), 'traffic');
    fs.mkdirSync(trafficDir, { mode: 0o700 });
    const steps = [fixtureEmail, 'another@fixture.invalid', mask, mask + ' 1', 'review'];
    const stepCounts = [1, 2, 1, 1, 1];
    const session = { profileId: 'legacy-group-fixture', traceId: 'legacy-group-trace', recordBodies: false };
    const records = steps.flatMap((actionStep, i) => Array.from({ length: stepCounts[i] }, (_, j) => ({
        type: 'egress', timestamp: '2025-01-01T00:00:00.000Z', correlationId: 'tx-' + i + '-' + j,
        url: 'https://fixture.invalid/items', method: 'GET', actionStep, stepIndex: i + 1,
        attribution: { ...session, actionStep, stepIndex: i + 1 }
    })));
    const byActionStep = Object.fromEntries(steps.map((name, i) => [name, { requests: stepCounts[i] }]));
    const ledgerPath = path.join(trafficDir, 'traffic.ndjson');
    const indexPath = path.join(trafficDir, 'attribution-index.json');
    const ledger = records.map(JSON.stringify).join('\n') + '\n';
    const index = JSON.stringify({ session, byActionStep });
    fs.writeFileSync(ledgerPath, ledger, { mode: 0o600 });
    fs.writeFileSync(indexPath, index, { mode: 0o600 });

    const report = queryProfileTraffic({ trafficDir });
    assert.equal(report.totals.totalRequests, 6);
    assert.equal(report.transactions.length, 6);
    assert.deepEqual(report.byActionStep, {
        [mask + ' 2']: { requests: 1 },
        [mask + ' 3']: { requests: 2 },
        [mask]: { requests: 1 },
        [mask + ' 1']: { requests: 1 },
        review: { requests: 1 }
    });
    assert.equal(fs.readFileSync(ledgerPath, 'utf8'), ledger);
    assert.equal(fs.readFileSync(indexPath, 'utf8'), index);
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
