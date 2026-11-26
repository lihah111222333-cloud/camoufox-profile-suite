import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    CamoufoxTrafficRecorder, exportTrafficToHar, inferPayloadExtension, verifyTrafficIntegrity
} from '../../src/camoufox/traffic-recorder.js';
import { attachZiniaoSecurityGuardsToContext } from '../../src/camoufox/ziniao-security.js';

function fixture(t, options = {}) {
    const trafficDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'recorder-limits-'));
    t.after(() => fs.rmSync(trafficDir, { force: true, recursive: true }));
    const create = (overrides = {}) => new CamoufoxTrafficRecorder({
        trafficDir,
        traceId: 'fixed-fixture-trace',
        sslKeyLog: false,
        neckoMozLog: false,
        recordWireLog: false,
        recordBodies: false,
        ...options,
        ...overrides
    });
    return { trafficDir, create };
}

function events(recorder) {
    return fs.readFileSync(recorder.trafficNdjsonPath, 'utf8').trim().split('\n').map(JSON.parse);
}

function request(name, details = {}) {
    return {
        url: () => `https://example.test/${name}`,
        method: () => 'GET',
        ...details
    };
}

test('closed WebSocket wire dumps are recovered from the event-limited ledger without a wire log', async (t) => {
    const { trafficDir, create } = fixture(t, { maxCaptureEvents: 4 });
    const recorder = create();
    const page = new EventEmitter();
    const ws = Object.assign(new EventEmitter(), { url: () => 'wss://example.test/fixture' });
    recorder.attachPage(page);
    page.emit('websocket', ws);
    ws.emit('framesent', 'one frame');
    ws.emit('framereceived', 'one reply');
    ws.emit('close');
    const another = new EventEmitter();
    page.emit('websocket', another);

    assert.equal(ws.listenerCount('framesent'), 0);
    assert.equal(another.listenerCount('framesent'), 0);
    const { correlationId } = events(recorder)[0];
    const summary = await recorder.stop();
    assert.equal(summary.integrity.eventCount, 4);
    assert.equal(summary.totals.wsFramesSent, 1);
    assert.equal(summary.totals.wsFramesReceived, 1);
    assert.equal(summary.captureLimits.stoppedReason, 'event-limit');
    assert.equal(fs.existsSync(recorder.preTlsWireLogPath), false);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
    assert.match(recorder.formatTransactionWireDump(correlationId), /WS-EGRESS.*\n(?:.*\n)*.*WS-INGRESS/);
});

test('HTTP completion releases live transaction metadata while the ledger preserves wire and HAR output', async (t) => {
    const { create } = fixture(t);
    const recorder = create();
    const context = new EventEmitter();
    recorder.attachContext(context);
    const req = request('completed', {
        sizes: async () => ({ requestHeadersSize: 1024, responseHeadersSize: 2048 })
    });
    context.emit('request', req);
    await recorder.flushSummary();
    assert.equal(recorder.transactions.size, 1);

    context.emit('response', { request: () => req, url: () => req.url(), status: () => 200 });
    context.emit('requestfinished', req);
    const summary = await recorder.flushSummary();
    assert.equal(recorder.transactions.size, 0);
    assert.equal(summary.totals.totalEgressBytes, 1024);
    assert.equal(summary.totals.totalIngressBytes, 2048);
    const [out, incoming, finished] = events(recorder);
    assert.equal(out.correlationId, finished.correlationId);
    assert.equal(incoming.correlationId, finished.correlationId);
    assert.match(recorder.formatTransactionWireDump(out.correlationId), />>> EGRESS/);
    assert.match(recorder.formatTransactionWireDump(out.correlationId), /<<< INGRESS/);

    const failed = request('failed', { failure: () => ({ errorText: 'fixture cancellation' }) });
    context.emit('request', failed);
    context.emit('requestfailed', failed);
    await recorder.flushSummary();
    assert.equal(recorder.transactions.size, 0);
    await recorder.stop();
    assert.equal(recorder.buildHarArchive().log.entries.length, 2);
});

test('resume counts previous ledger, payload and wire storage toward the configured cap', async (t) => {
    const { trafficDir, create } = fixture(t, { recordWireLog: true, recordBodies: true });
    const recorder = create();
    recorder.recordSecurityBlock({ type: 'fixture-stopped', url: 'https://example.test/refused' });
    const context = new EventEmitter();
    recorder.attachContext(context);
    context.emit('request', request('retained-upload', {
        method: () => 'POST',
        headers: () => ({ 'content-type': 'text/plain' }),
        postDataBuffer: () => Buffer.from('fixture content')
    }));
    const initial = await recorder.stop();
    const before = fs.readFileSync(recorder.trafficNdjsonPath);
    const [attachment] = fs.readdirSync(recorder.payloadsDir);
    const attachmentBytes = fs.statSync(path.join(recorder.payloadsDir, attachment)).size;
    const knownBytes = before.byteLength + fs.statSync(recorder.preTlsWireLogPath).size + attachmentBytes;
    assert.equal(initial.captureLimits.bytes, knownBytes);

    const resumed = create({ maxCaptureBytes: knownBytes });
    assert.equal(resumed.recordSecurityBlock({ type: 'another-fixture' }), null);
    const summary = await resumed.stop();
    assert.equal(summary.captureLimits.stoppedReason, 'storage-limit');
    assert.equal(summary.captureLimits.bytes, knownBytes);
    assert.equal(summary.totals.failedRequests, 1);
    assert.deepEqual(fs.readFileSync(recorder.trafficNdjsonPath), before);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('attachment budget keeps an event when its payload and ledger entry exceed the combined limit', async (t) => {
    const { create } = fixture(t, { maxCaptureBytes: 1800, maxInlinePreviewBytes: 16, recordBodies: true });
    const recorder = create();
    const context = new EventEmitter();
    recorder.attachContext(context);
    const payload = Buffer.from('plain fixture text '.repeat(52));
    context.emit('request', request('upload', {
        method: () => 'POST',
        headers: () => ({ 'content-type': 'text/plain' }),
        postDataBuffer: () => payload
    }));
    const summary = await recorder.stop();
    const [event] = events(recorder);
    assert.equal(event.payloadFile, null);
    assert.equal(event.postDataBytes, payload.byteLength);
    assert.equal(event.postDataSha256, createHash('sha256').update(payload).digest('hex'));
    assert.deepEqual(event.payloadStorage, { status: 'omitted', reason: 'storage-limit' });
    assert.equal(summary.captureLimits.omittedPayloadFiles, 1);
    assert.equal(summary.captureLimits.bytes, fs.statSync(recorder.trafficNdjsonPath).size);
    assert.ok(summary.captureLimits.bytes <= 1800);
    assert.deepEqual(fs.readdirSync(recorder.payloadsDir), []);
    const resumed = create();
    assert.equal((await resumed.stop()).captureLimits.omittedPayloadFiles, 1);
});

test('page and context close release their listeners while the recorder is still active', async (t) => {
    const { create } = fixture(t);
    const recorder = create();
    const context = new EventEmitter();
    const page = Object.assign(new EventEmitter(), { context: () => context });
    recorder.attachContext(context);
    context.emit('page', page);
    recorder.attachPage(page);
    assert.equal(page.listenerCount('websocket'), 1);
    assert.equal(recorder.listenerDisposers.size, 2);

    page.emit('close');
    assert.equal(page.listenerCount('websocket'), 0);
    assert.equal(recorder.listenerDisposers.size, 1);
    context.emit('close');
    assert.equal(context.listenerCount('request'), 0);
    assert.equal(recorder.listenerDisposers.size, 0);
    await recorder.stop();
});

test('pending HTTP listeners drain accepted work at their configured limit', async (t) => {
    const { create } = fixture(t, { maxPendingEvents: 1 });
    const recorder = create();
    const context = new EventEmitter();
    recorder.attachContext(context);
    let resolveHeaders;
    const headers = new Promise((resolve) => { resolveHeaders = resolve; });
    context.emit('request', request('accepted', { headersArray: () => headers }));
    context.emit('request', request('unrecorded'));
    assert.equal(recorder.pendingTasks.size, 1);
    const stopping = recorder.stop();
    assert.equal(context.listenerCount('request'), 0);
    assert.equal(recorder.pendingTasks.size, 1);

    resolveHeaders([]);
    const summary = await stopping;
    assert.equal(summary.captureLimits.stoppedReason, 'pending-event-limit');
    assert.equal(summary.totals.totalRequests, 1);
    assert.equal(recorder.pendingTasks.size, 0);
    assert.equal(recorder.transactions.size, 0);
    assert.deepEqual(events(recorder).map(({ url }) => url), ['https://example.test/accepted']);
});

test('resume keeps historical HTTP entries separate with the same caller-supplied trace ID', async (t) => {
    const { trafficDir, create } = fixture(t);
    const context = new EventEmitter();
    const first = create();
    first.attachContext(context);
    context.emit('request', request('before'));
    await first.stop();

    const next = create();
    next.attachContext(context);
    context.emit('request', request('after'));
    await next.stop();
    const [before, after] = events(next);
    assert.equal(after.seq, before.seq + 1);
    assert.notEqual(after.correlationId.replace(/-\d+$/, ''), before.correlationId.replace(/-\d+$/, ''));
    const harEntries = ({ log }) => log.entries.map((entry) => [
        entry.request.url, entry._attribution.correlationId
    ]);
    assert.deepEqual(harEntries(first.buildHarArchive()), [
        ['https://example.test/before', before.correlationId]
    ]);
    assert.deepEqual(harEntries(next.buildHarArchive()), [
        ['https://example.test/after', after.correlationId]
    ]);

    const archivePath = path.join(trafficDir, 'complete.har');
    const archive = exportTrafficToHar(trafficDir, archivePath, {}, { recordBodies: false });
    assert.equal(archive.entryCount, 2);
    assert.deepEqual(harEntries(JSON.parse(fs.readFileSync(archivePath, 'utf8'))).sort(), [
        ['https://example.test/after', after.correlationId],
        ['https://example.test/before', before.correlationId]
    ]);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('resume rejects invalid and exhausted sequence numbers before changing the archive', (t) => {
    const { trafficDir, create } = fixture(t);
    const ledger = path.join(trafficDir, 'traffic.ndjson');
    for (const seq of [-1, 1.5, '2', Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1]) {
        const record = { seq, type: 'step-transition', actionStep: 'fixture', prevEventHash: '0'.repeat(64) };
        const preimage = `${record.prevEventHash}|${record.seq}|${JSON.stringify(record)}`;
        record.eventHash = createHash('sha256').update(preimage).digest('hex');
        const original = `${JSON.stringify(record)}\n`;
        fs.writeFileSync(ledger, original);
        assert.throws(() => create(), /Invalid or exhausted traffic event sequence/);
        assert.equal(fs.readFileSync(ledger, 'utf8'), original);
    }
});

test('payload classification reads a bounded prefix while honoring an explicit JSON MIME type', () => {
    const payload = Buffer.from(JSON.stringify({ sample: 'neutral fixture text '.repeat(36) }));
    payload.toString = () => assert.fail('classifier decoded the complete payload');
    assert.equal(inferPayloadExtension('application/octet-stream', payload), 'txt');
    assert.equal(inferPayloadExtension('application/json', payload), 'json');
    assert.equal(inferPayloadExtension(null, Buffer.from('{"sample":1}')), 'json');
});

test('guard caps recent diagnostic samples by count and bytes and still denies every blocked request', async () => {
    let handleRequest;
    const context = {
        async route(_pattern, handler) { handleRequest = handler; },
        async unroute(_pattern, handler) { assert.equal(handler, handleRequest); }
    };
    const notifications = [];
    const outcomes = [];
    const guard = await attachZiniaoSecurityGuardsToContext(context, {
        blockedHistoryMaxEntries: 2,
        blockedHistoryMaxBytes: 550,
        blockedNotificationsPerSecond: 1,
        onBlockedAttempt(event) { notifications.push(event); }
    });
    const route = {
        abort: (code) => outcomes.push(code),
        continue: () => outcomes.push('continued')
    };
    for (const url of ['http://localhost:8080/one', 'about:config', 'http://localhost:8080/two']) {
        await handleRequest(route, { url: () => url });
    }
    const stats = guard.getStats();
    assert.deepEqual(outcomes, ['connectionrefused', 'accessdenied', 'connectionrefused']);
    assert.equal(stats.blockedPortScanCount, 2);
    assert.equal(stats.blockedInternalSchemeCount, 1);
    assert.equal(stats.suppressedBlockedAttemptNotifications, 2);
    assert.equal(notifications.length, 1);
    assert.equal(stats.blockedPortScans.at(-1).targetUrl, 'http://localhost:8080/two');
    assert.equal(stats.blockedPortScans.length + stats.blockedInternalSchemes.length, 1);
    stats.blockedPortScans[0].targetUrl = 'altered fixture';
    assert.equal(guard.blockedPortScans[0].targetUrl, 'http://localhost:8080/two');

    await guard.detach();
    assert.deepEqual(guard.blockedPortScans, []);
    assert.deepEqual(guard.blockedInternalSchemes, []);
    assert.equal(guard.getStats().blockedPortScanCount, 2);
});
