import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    CamoufoxTrafficRecorder, parseNeckoMozLog, redactUrlSecrets
} from '../../src/camoufox/traffic-recorder.js';

function fixture(t, options = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'recorder-privacy-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const trafficDir = path.join(root, 'traffic');
    const recorderOptions = { trafficDir, harPath: path.join(trafficDir, 'traffic.har'), sslKeyLog: false, ...options };
    const recorder = new CamoufoxTrafficRecorder(recorderOptions);
    const context = new EventEmitter();
    const page = new EventEmitter();
    page.context = () => context;
    recorder.attachContext(context);
    recorder.attachPage(page);
    return { recorder, context, page, recorderOptions };
}

function request(url, headers = {}, extra = {}) {
    return {
        url: () => url,
        method: () => 'POST',
        headers: () => headers,
        headersArray: async () => Object.entries(headers).map(([name, value]) => ({ name, value })),
        ...extra
    };
}

function response(req, headers = {}, extra = {}) {
    return {
        request: () => req,
        url: () => req.url(),
        headers: () => headers,
        headersArray: async () => Object.entries(headers).map(([name, value]) => ({ name, value })),
        status: () => 200,
        statusText: () => 'OK',
        ...extra
    };
}

function events(recorder) {
    return fs.readFileSync(recorder.trafficNdjsonPath, 'utf8').trim().split('\n').map(JSON.parse);
}

function assertAbsent(recorder, markers) {
    for (const filePath of [
        recorder.trafficNdjsonPath, recorder.preTlsWireLogPath, recorder.attributionIndexPath, recorder.harPath
    ]) {
        if (!fs.existsSync(filePath)) continue;
        const content = fs.readFileSync(filePath, 'utf8');
        for (const marker of markers) {
            assert.equal(content.includes(marker), false, `unexpected marker in ${path.basename(filePath)}`);
        }
    }
}

const digest = (value) => createHash('sha256').update(value).digest('hex');

test('initial and updated account emails are omitted from recorded attribution', async (t) => {
    const initialEmail = 'initial-candidate@example.test';
    const updatedEmail = 'updated-candidate@example.test';
    const { recorder, context } = fixture(t, { accountId: 1, accountEmail: initialEmail });
    context.emit('request', request('https://fixture.invalid/first'));
    await recorder.flushSummary();

    const snapshot = recorder.updateAttribution({ accountId: 2, accountEmail: updatedEmail });
    assert.equal(snapshot.accountEmail, null);
    const second = request('https://fixture.invalid/second');
    context.emit('request', second);
    context.emit('response', response(second));

    const summary = await recorder.stop();
    assert.equal(summary.session.accountEmail, null);
    assert.equal(summary.session.accountId, 2);
    assert.deepEqual(events(recorder).map(({ attribution }) => [attribution.accountId, attribution.accountEmail]), [
        [1, null], [2, null], [2, null]
    ]);
    assertAbsent(recorder, [initialEmail, updatedEmail]);
});

test('credential headers are masked and cookie digests are recoverable from the ledger', async (t) => {
    const { recorder, context, recorderOptions } = fixture(t);
    const cookie = 'lineage-cookie-fixture-1234';
    const authorization = 'request-auth-fixture-2345';
    const apiKey = 'private-key-fixture-3456';
    const url = 'https://example.test/fixture';
    const firstRequest = request(url);
    context.emit('request', firstRequest);
    context.emit('response', response(firstRequest, {
        'Set-Cookie': `Fixture=${cookie}; Path=/store; Secure; HttpOnly; SameSite=Lax`
    }));
    await recorder.flushSummary();
    context.emit('request', request('https://example.test/store', {
        cookie: `Fixture=${cookie}`,
        Authorization: `Bearer ${authorization}`,
        'X-Api-Key': apiKey
    }));
    const summary = await recorder.stop();
    const { log } = recorder.exportHar();
    assert.equal(log.entries.length, 2);

    assertAbsent(recorder, [cookie, authorization, apiKey]);
    const ledger = events(recorder);
    const ingress = ledger.find(({ type }) => type === 'ingress');
    const egress = ledger.filter(({ type }) => type === 'egress').at(-1);
    assert.equal(ingress.headers['Set-Cookie'], '[REDACTED]');
    assert.deepEqual(ingress.headersArray, [{ name: 'Set-Cookie', value: '[REDACTED]' }]);
    assert.equal(egress.headers.cookie, '[REDACTED]');
    assert.equal(egress.headers.Authorization, 'Bearer [REDACTED]');
    assert.equal(egress.headers['X-Api-Key'], '[REDACTED]');
    assert.deepEqual(egress.cookieObservations, [{
        name: 'Fixture', valueSha256: digest(cookie), maskedValue: '[REDACTED]', isAntiBotToken: false
    }]);
    assert.equal(summary.cookieLineage.Fixture.lastValueSha256, digest(cookie));
    assert.equal(summary.cookieLineage.Fixture.lastMaskedValue, '[REDACTED]');
    assert.equal(summary.cookieLineage.Fixture.matchesLatestSetCookie, true);
    assert.equal(summary.cookieLineage.Fixture.path, '/store');

    fs.unlinkSync(recorder.attributionIndexPath);
    const resumed = new CamoufoxTrafficRecorder(recorderOptions);
    const rebuilt = await resumed.stop();
    assert.deepEqual(rebuilt.cookieLineage, summary.cookieLineage);
    assertAbsent(resumed, [cookie, authorization, apiKey]);
});

test('navigation and step metadata use the same URL masking as headers and HTTP events', async (t) => {
    const { recorder, context } = fixture(t);
    const targetToken = 'primary-navigation-fixture';
    const locationToken = 'redirect-navigation-fixture';
    const fragmentToken = 'fragment-navigation-fixture';
    const userInfo = 'userinfo-navigation-fixture';
    const authToken = 'header-authentication-fixture';
    const signedToken = 'signed-query-fixture';
    const linkToken = 'link-anchor-fixture';
    const url = `https://user:${userInfo}@example.test/go?ordinary=retained&access%5Ftoken=${targetToken}` +
        `&X-Amz-Signature=${signedToken}#id_token=${fragmentToken}`;
    const redirect = `/callback?refresh_token=${locationToken}`;
    const link = `<${redirect}>; rel="next"; anchor="related?sig=${linkToken}&page=2"`;
    const maskedLink = `<${redactUrlSecrets(redirect)}>; rel="next"; anchor="related?sig=[REDACTED]&page=2"`;
    const meta = { url, pageUrl: url, nested: { destination: [redirect] } };
    recorder.setStep('navigation', meta);
    const action = recorder.recordTriggerAction('page.goto', url, meta);
    assert.equal(action.target, redactUrlSecrets(url));
    assert.equal(action.metadata.url, action.target);
    assert.equal(action.metadata.pageUrl, action.target);
    assert.equal(meta.url, url);

    const req = request(url, { Referer: url, 'X-Original-URL': redirect, 'X-Auth-Token': authToken });
    context.emit('request', req);
    context.emit('response', response(req, {
        Location: redirect,
        Link: link,
        Refresh: `0; url="${url}"`
    }));
    const summary = await recorder.stop();
    const { log } = recorder.exportHar();
    const [step, trigger, egress, ingress] = events(recorder);
    assert.equal(step.metadata.nested.destination[0], redactUrlSecrets(redirect));
    assert.equal(trigger.target, egress.url);
    assert.equal(egress.headers.Referer, egress.url);
    assert.equal(egress.headers['X-Original-URL'], redactUrlSecrets(redirect));
    assert.equal(egress.headers['X-Auth-Token'], '[REDACTED]');
    assert.equal(egress.searchParams.ordinary, 'retained');
    assert.equal(egress.searchParams['X-Amz-Signature'], '[REDACTED]');
    assert.equal(ingress.headers.Location, redactUrlSecrets(redirect));
    assert.equal(ingress.headers.Link, maskedLink);
    assert.equal(ingress.headers.Refresh, `0; url="${egress.url}"`);
    assert.equal(log.entries[0].response.headers.find(({ name }) => name === 'Link').value, maskedLink);
    assert.equal(summary.byTriggerAction[action.actionId].target, egress.url);
    assert.equal(summary.byTriggerAction[action.actionId].metadata.url, egress.url);
    assertAbsent(recorder, [targetToken, locationToken, fragmentToken, userInfo, authToken, signedToken, linkToken]);
});

test('private Necko source keeps its format while the diagnostic index masks credentials and URLs', async (t) => {
    const { recorder, context } = fixture(t, { neckoMozLog: true });
    const secret = 'native-header-fixture-only';
    const urlKey = 'native-navigation-fixture-only';
    const source = [
        'http request [',
        `GET relative?token=${urlKey} HTTP/1.1`,
        'Host: example.test',
        `Cookie: NativeFixture=${secret}`,
        `Authorization: Basic ${secret}`,
        ']',
        'http response [',
        'HTTP/1.1 200 OK',
        `Set-Cookie: NativeFixture=${secret}; Path=/`,
        `Location: /fixture?password=${urlKey}`,
        ']'
    ].join('\n');
    recorder.recordNeckoMozLogBlock(source);
    context.emit('request', request('https://example.test/'));
    const summary = await recorder.stop();

    assert.equal(path.dirname(recorder.neckoMozLogPath), path.join(path.dirname(recorder.trafficDir), '.native'));
    assert.equal(fs.readFileSync(recorder.neckoMozLogPath, 'utf8'), `${source}\n`);
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(recorder.neckoMozLogPath).mode & 0o777, 0o600);
        assert.equal(fs.statSync(path.dirname(recorder.neckoMozLogPath)).mode & 0o777, 0o700);
    }
    const parsed = parseNeckoMozLog(recorder.neckoMozLogPath);
    assert.equal(parsed.parsedRequests[0].headers.cookie, '[REDACTED]');
    assert.equal(parsed.parsedRequests[0].headers.authorization, 'Basic [REDACTED]');
    assert.equal(parsed.parsedRequests[0].requestLine, `GET ${redactUrlSecrets(`relative?token=${urlKey}`)} HTTP/1.1`);
    assert.equal(parsed.parsedResponses[0].headers['set-cookie'], '[REDACTED]');
    assert.deepEqual(summary.neckoMozLog, { ...parsed, sha256: null });
    assertAbsent(recorder, [secret, urlKey]);
});

test('metadata-only mode skips request, response and WebSocket accessors by default', async (t) => {
    const { recorder, context, page } = fixture(t, { neckoMozLog: false });
    let reads = 0;
    const marker = 'metadata-only-content-fixture';
    const read = () => {
        reads += 1;
        return marker;
    };
    const req = request('https://example.test/post', {}, { postData: read, postDataBuffer: read });
    context.emit('request', req);
    context.emit('response', response(req, {}, { body: read, text: read }));
    const ws = new EventEmitter();
    ws.url = () => 'wss://example.test/socket';
    page.emit('websocket', ws);
    const frame = { get payload() { return read(); } };
    ws.emit('framesent', frame);
    ws.emit('framereceived', frame);
    const summary = await recorder.stop();
    const { log } = recorder.exportHar();

    assert.equal(log.entries.length, 1);
    assert.equal(log.entries[0].request.postData?.text || '', '');
    assert.deepEqual(log.entries[0].request.postData?.params || [], []);
    assert.equal(log.entries[0].response.content.text || '', '');
    assert.equal(reads, 0);
    assert.equal(summary.totals.totalRequests, 1);
    assert.equal(summary.totals.totalResponses, 1);
    assert.equal(summary.totals.wsFramesSent, 1);
    assert.equal(summary.totals.wsFramesReceived, 1);
    assert.equal(summary.neckoMozLog.exists, false);
    assert.equal(summary.sslKeyLog.exists, false);
    for (const event of events(recorder).filter(({ type }) => type !== 'ws-open')) {
        assert.equal(event.recordBodies, false);
        assert.equal(event.bodyOmittedReason, 'body-recording-disabled');
        assert.equal(event.bodyPreview, null);
        assert.equal(event.payloadFile, null);
        assert.equal(event.postDataSha256 ?? event.bodySha256 ?? event.payloadSha256 ?? null, null);
    }
    assert.deepEqual(fs.readdirSync(recorder.payloadsDir), []);
    assertAbsent(recorder, [marker, digest(marker)]);
});

test('an unbounded browser transport is never asked for decoded response bodies', async (t) => {
    const { recorder, context } = fixture(t, { recordBodies: true, maxBodyBytes: 32 });
    let requestedBodies = 0;
    const readUnbounded = async () => {
        requestedBodies += 1;
        return Buffer.from('response-body-fixture');
    };
    const headers = { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', 'Content-Length': '64' };
    for (let i = 0; i < 16; i += 1) {
        const req = request(`https://example.test/resource/${i}`, {}, {
            sizes: () => ({ requestBodySize: 0, responseBodySize: 64, responseHeadersSize: 120 })
        });
        context.emit('request', req);
        context.emit('response', response(req, i % 2 ? headers : {},
            i % 2 ? { body: readUnbounded } : { text: readUnbounded }));
        context.emit('requestfinished', req);
    }
    const summary = await recorder.stop();
    const ledger = events(recorder);
    const responses = ledger.filter(({ type }) => type === 'ingress');

    assert.equal(requestedBodies, 0);
    assert.equal(summary.totals.totalResponses, 16);
    assert.equal(responses.length, 16);
    assert.equal(responses.filter((record) => record.mimeType === 'application/json').length, 8);
    const finished = ledger.filter(({ type }) => type === 'request-finished');
    assert.equal(finished.length, 16);
    assert.ok(finished.every((record) => record.sizes.responseBodySize === 64));
    for (const event of responses) {
        assert.equal(event.status, 200);
        assert.equal(event.recordBodies, true);
        assert.equal(event.bodyOmittedReason, 'unbounded-response-reader');
        assert.equal(event.bodyBytes, 0);
        assert.equal(event.bodyPreview, null);
        assert.equal(event.payloadFile, null);
    }
    assert.deepEqual(fs.readdirSync(recorder.payloadsDir), []);
    assertAbsent(recorder, ['response-body-fixture']);
});

test('enabled request and WebSocket capture retain bounded payload files and content digests', async (t) => {
    const { recorder, context, page } = fixture(t, { recordBodies: true, maxBodyBytes: 24, maxInlinePreviewBytes: 20 });
    const body = 'fixture-content-'.repeat(10);
    context.emit('request', request('https://example.test/post', {}, { postData: () => body }));
    const ws = new EventEmitter();
    ws.url = () => 'wss://example.test/socket';
    page.emit('websocket', ws);
    ws.emit('framesent', { payload: Buffer.from(body) });
    await recorder.stop();

    const ledger = events(recorder);
    for (const event of ledger.filter(({ type }) => type === 'egress' || type === 'ws-egress')) {
        assert.equal(event.recordBodies, true);
        assert.equal(event.postDataSha256 ?? event.payloadSha256, digest(body));
        assert.equal(event.bodyPreview, null);
        assert.equal(event.payloadTruncated, true);
        const filePath = path.join(recorder.trafficDir, event.payloadFile);
        assert.equal(fs.readFileSync(filePath, 'utf8'), body.slice(0, 24));
        if (process.platform !== 'win32') assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
    }
});

test('opted-in requests project complete JSON and forms while authentication and WebSocket stay private', async (t) => {
    const { recorder, context, page } = fixture(t, { recordBodies: true, neckoMozLog: false });
    const jsonBody = '{"success":true,"label":"private-json-marker","data":{"count":2,"status":"succeeded"}}';
    const formBody = 'count=1&count=2&ok=true&label=private-form-marker';
    const reqs = [
        request('https://example.test/items', { 'Content-Type': 'application/fixture+json; charset=utf-8' }, {
            postData: () => jsonBody
        }),
        request('https://example.test/items', { 'Content-Type': 'application/x-www-form-urlencoded' }, {
            postData: () => formBody
        })
    ];
    for (const req of reqs) context.emit('request', req);
    let sensitiveBodyReads = 0;
    const readBody = () => {
        sensitiveBodyReads += 1;
        return 'private-auth-marker';
    };
    context.emit('request', request('https://example.test/v2/sign-in', { 'Content-Type': 'application/json' }, {
        postData: readBody, postDataBuffer: readBody
    }));

    const regularSocket = Object.assign(new EventEmitter(), { url: () => 'wss://example.test/events' });
    const authenticationSocket = Object.assign(new EventEmitter(), { url: () => 'wss://example.test/v2/auth/socket' });
    page.emit('websocket', regularSocket);
    page.emit('websocket', authenticationSocket);
    regularSocket.emit('framesent', { payload: 'private-ws-marker' });
    authenticationSocket.emit('framereceived', { get payload() { return readBody(); } });
    await recorder.stop();

    const ledger = events(recorder);
    const requests = ledger.filter(({ type }) => type === 'egress').sort((a, b) => a.seq - b.seq);
    const { log } = recorder.exportHar();
    const projections = ['{"success":true,"data":{"count":2,"status":"succeeded"}}', 'count=1&count=2&ok=true'];
    for (const [i, body] of [jsonBody, formBody].entries()) {
        const event = requests[i];
        assert.equal(event.bodyPreview, projections[i]);
        assert.ok(recorder.formatTransactionWireDump(event.correlationId).includes(projections[i]));
        assert.equal(log.entries[i].request.postData?.text, projections[i]);
        assert.equal(fs.readFileSync(path.join(recorder.trafficDir, event.payloadFile), 'utf8'), body);
    }
    const privateFrame = ledger.find(({ type }) => type === 'ws-egress');
    assert.equal(privateFrame.bodyPreview, null);
    assert.equal(fs.readFileSync(path.join(recorder.trafficDir, privateFrame.payloadFile), 'utf8'), 'private-ws-marker');
    assert.equal(ledger.find(({ type }) => type === 'ws-ingress').payloadFile, null);
    assert.equal(requests[2].payloadFile, null);
    assert.equal(log.entries[2].request.postData?.text ?? '', '');
    assert.equal(sensitiveBodyReads, 0);
    assertAbsent(recorder, ['private-json-marker', 'private-form-marker', 'private-auth-marker', 'private-ws-marker']);
});

test('reopened wire applies current header, URL, trigger and body rules to accepted legacy events', async (t) => {
    const traceId = 'legacy-wire-fixture';
    const archivedEmail = 'archived-candidate@example.test';
    const { recorder, recorderOptions } = fixture(t, { traceId, recordBodies: true, neckoMozLog: false });
    const common = {
        correlationId: 'legacy-transaction',
        timestamp: '2026-01-01T00:00:00.000Z',
        url: 'https://example.test/items',
        recordBodies: true,
        attribution: { traceId, accountEmail: archivedEmail }
    };
    const legacy = [
        {
            ...common,
            type: 'egress',
            method: 'POST',
            headers: {
                Authorization: 'Bearer legacy-request-marker',
                Cookie: 'session=legacy-cookie-marker',
                'Content-Type': 'application/json'
            },
            triggerAction: {
                actionId: 'legacy-action',
                actionType: 'goto',
                target: 'https://example.test/items?token=legacy-target-marker'
            },
            bodyPreview: '{"ok":true,"label":"legacy-body-marker"}',
            platformSignatures: [{
                signatureName: 'public_key',
                platform: 'arkose',
                location: 'body',
                valueSha256: digest('legacy-signature-marker'),
                valueLength: 'legacy-signature-marker'.length,
                maskedPreview: 'legacy-signature-marker'
            }]
        },
        {
            ...common,
            type: 'ingress',
            status: 200,
            headersArray: [
                { name: 'Set-Cookie', value: 'session=legacy-response-marker' },
                { name: 'Content-Type', value: 'application/json' },
                { name: 'Location', value: '/next?token=legacy-location-marker' }
            ],
            bodyPreview: '{"count":3,"label":"legacy-truncation-marker"',
            bodyPreviewTruncated: true
        },
        {
            ...common,
            correlationId: 'legacy-socket',
            type: 'ws-egress',
            url: 'wss://example.test/events',
            payloadBytes: 42,
            bodyPreview: '{"count":5,"label":"legacy-ws-marker"}'
        }
    ];
    let head = '0'.repeat(64);
    const lines = legacy.map((event, i) => {
        const record = { ...event, seq: i + 1, prevEventHash: head };
        head = digest(`${head}|${record.seq}|${JSON.stringify(record)}`);
        return JSON.stringify({ ...record, eventHash: head });
    });
    const archived = `${lines.join('\n')}\n`;
    await recorder.stop();
    const archivedIndex = JSON.parse(fs.readFileSync(recorder.attributionIndexPath, 'utf8'));
    archivedIndex.session.accountEmail = archivedEmail;
    fs.writeFileSync(recorder.attributionIndexPath, JSON.stringify(archivedIndex));
    fs.writeFileSync(recorder.trafficNdjsonPath, archived);
    const reopened = new CamoufoxTrafficRecorder(recorderOptions);
    const summary = await reopened.stop();

    const [signature] = summary.platformSignatures.signatures;
    assert.equal(signature.maskedPreview, '[REDACTED]');
    assert.equal(signature.valueSha256, null);
    assert.equal(signature.valueLength, null);
    assert.equal(summary.session.accountEmail, null);
    const rebuiltIndex = fs.readFileSync(recorder.attributionIndexPath, 'utf8');
    assert.doesNotMatch(rebuiltIndex, /legacy-signature-marker/);
    assert.equal(rebuiltIndex.includes(archivedEmail), false);
    const wire = reopened.formatTransactionWireDump('legacy-transaction');
    assert.match(wire, /Authorization: Bearer \[REDACTED\]/);
    assert.match(wire, /Cookie: \[REDACTED\]/);
    assert.match(wire, /Set-Cookie: \[REDACTED\]/);
    assert.match(wire, /"ok":true/);
    assert.match(wire, /legacy-action/);
    assert.doesNotMatch(wire, /legacy-(request|cookie|response|target|body|truncation|location)-marker/);
    assert.equal(wire.includes(archivedEmail), false);
    const socketWire = reopened.formatTransactionWireDump('legacy-socket');
    assert.match(socketWire, /WS-EGRESS.*bytes=42/);
    assert.doesNotMatch(socketWire, /legacy-ws-marker/);
    assert.equal(fs.readFileSync(recorder.trafficNdjsonPath, 'utf8'), archived);
});
