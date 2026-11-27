import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
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
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'recorder-limits-'));
    const trafficDir = path.join(root, 'traffic');
    fs.mkdirSync(trafficDir);
    t.after(() => fs.rmSync(root, { force: true, recursive: true }));
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
    assert.equal(summary.totals.unknownWsFramesSent, 1);
    assert.equal(summary.totals.unknownWsFramesReceived, 1);
    const frames = events(recorder).filter(event => /^(?:ws-egress|ws-ingress)$/.test(event.type));
    assert.deepEqual(frames.map(({ payloadBytes }) => payloadBytes), [null, null]);
    assert.equal(summary.captureLimits.stoppedReason, 'event-limit');
    assert.equal(fs.existsSync(recorder.preTlsWireLogPath), false);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
    assert.match(recorder.formatTransactionWireDump(correlationId), /WS-EGRESS[^\n]*bytes=unknown.*\n(?:.*\n)*.*WS-INGRESS[^\n]*bytes=unknown/);
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

test('resume counts the wire file left by a writer that exited before its checkpoint', async (t) => {
    const { trafficDir, create } = fixture(t);
    const recorderModule = new URL('../../src/camoufox/traffic-recorder.js', import.meta.url).href;
    const child = `
        import { CamoufoxTrafficRecorder } from ${JSON.stringify(recorderModule)};
        const recorder = new CamoufoxTrafficRecorder({ trafficDir: process.argv[1], recordWireLog: true });
        recorder.recordSecurityBlock({ type: 'fixture', url: 'https://fixture.test/capture' });
    `;
    execFileSync(process.execPath, ['--input-type=module', '-e', child, trafficDir], { timeout: 5000 });
    const ledgerPath = path.join(trafficDir, 'traffic.ndjson');
    const ledger = fs.readFileSync(ledgerPath);
    const wire = fs.readFileSync(path.join(trafficDir, 'pre-tls-wire.log'));
    assert.ok(wire.length > 0);
    assert.equal(fs.existsSync(path.join(trafficDir, 'attribution-index.json')), false);

    const resumed = create({ maxCaptureBytes: ledger.length + wire.length, recordWireLog: false });
    assert.equal(resumed.recordSecurityBlock({ type: 'second-fixture' }), null);
    const summary = await resumed.stop();
    assert.equal(summary.captureLimits.stoppedReason, 'storage-limit');
    assert.equal(summary.captureLimits.bytes, ledger.length + wire.length);
    assert.deepEqual(fs.readFileSync(ledgerPath), ledger);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('replay retains measured byte totals when capture started after the request', async (t) => {
    const { create } = fixture(t);
    const recorder = create();
    const context = new EventEmitter();
    recorder.attachContext(context);
    const activeRequest = request('in-flight', {
        sizes: async () => ({
            requestHeadersSize: 80, requestBodySize: 20, responseHeadersSize: 50, responseBodySize: 90
        })
    });
    context.emit('response', { request: () => activeRequest, url: activeRequest.url, status: () => 200 });
    context.emit('requestfinished', activeRequest);
    const live = await recorder.stop();
    assert.equal(live.totals.totalRequests, 0);
    assert.equal(live.totals.totalResponses, 1);
    assert.equal(live.totals.totalEgressBytes, 100);
    assert.equal(live.totals.totalIngressBytes, 140);

    const replay = await create().stop();
    assert.deepEqual(replay.totals, live.totals);
    assert.deepEqual(replay.byActionStep, live.byActionStep);
    assert.deepEqual(replay.byDomain, live.byDomain);
});

test('attachment budget keeps an event when its payload and ledger entry exceed the combined limit', async (t) => {
    const { create } = fixture(t, { maxCaptureBytes: 1800, maxInlinePreviewBytes: 16, recordBodies: true });
    const recorder = create();
    const context = new EventEmitter();
    recorder.attachContext(context);
    const payload = Buffer.from('plain fixture text '.repeat(52));
    const write = fs.writeFileSync;
    let attachmentWrites = 0;
    let summary;
    fs.writeFileSync = (file, data, ...args) => {
        if (data === payload || (Buffer.isBuffer(data) && data.equals(payload))) attachmentWrites += 1;
        return write(file, data, ...args);
    };
    try {
        context.emit('request', request('upload', {
            method: () => 'POST',
            headers: () => ({ 'content-type': 'text/plain' }),
            postDataBuffer: () => payload
        }));
        summary = await recorder.stop();
    } finally {
        fs.writeFileSync = write;
    }
    assert.equal(attachmentWrites, 0);
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

test('attachment rollback keeps only files whose ledger event was fully written', async (t) => {
    for (const mode of ['partial', 'reader-failed', 'complete-without-newline']) {
        await t.test(mode, async (t) => {
            const { trafficDir, create } = fixture(t, { recordBodies: true });
            const recorder = create();
            const context = new EventEmitter();
            recorder.attachContext(context);
            recorder.setStep('before-append');
            await recorder.flushSummary();
            const originalLedger = fs.readFileSync(recorder.trafficNdjsonPath);
            const originalIndex = fs.readFileSync(recorder.attributionIndexPath);
            const body = Buffer.from('synthetic body under test');
            const write = fs.writeFileSync;
            const read = fs.readSync;
            const complete = mode === 'complete-without-newline';
            fs.writeFileSync = (file, data, ...args) => {
                if (typeof data === 'string' && data.startsWith('{"type":"egress"')) {
                    write(file, data.slice(0, complete ? -1 : 11), ...args);
                    if (mode === 'reader-failed') {
                        const ledger = fs.statSync(recorder.trafficNdjsonPath, { bigint: true });
                        fs.readSync = (fd, ...args) => {
                            const file = fs.fstatSync(fd, { bigint: true });
                            if (file.dev === ledger.dev && file.ino === ledger.ino) {
                                throw new Error('synthetic read fault');
                            }
                            return read(fd, ...args);
                        };
                    }
                    throw new Error('synthetic append fault');
                }
                return write(file, data, ...args);
            };
            try {
                context.emit('request', request('append-fault', { postDataBuffer: () => body }));
                await assert.rejects(recorder.stop(), /Could not append to traffic.ndjson/);
            } finally {
                fs.writeFileSync = write;
                fs.readSync = read;
            }
            assert.deepEqual(fs.readFileSync(recorder.attributionIndexPath), originalIndex);
            const pending = fs.readdirSync(recorder.payloadsDir);
            assert.equal(pending.some(name => name.startsWith('.pending-')), mode !== 'partial');
            if (mode === 'partial') assert.deepEqual(pending, []);

            const resumed = create();
            const summary = await resumed.stop();
            assert.equal(summary.integrity.eventCount, complete ? 2 : 1);
            assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
            if (complete) {
                const attachment = events(resumed)[1].payloadFile;
                assert.deepEqual(fs.readFileSync(path.join(trafficDir, attachment)), body);
                assert.deepEqual(fs.readdirSync(recorder.payloadsDir), [path.basename(attachment)]);
            } else {
                assert.deepEqual(fs.readFileSync(recorder.trafficNdjsonPath), originalLedger);
                assert.deepEqual(fs.readdirSync(recorder.payloadsDir), []);
            }
        });
    }
});

test('recovery removes an attachment abandoned by a recorder process before its event append', async (t) => {
    const { trafficDir, create } = fixture(t);
    const recorderModule = new URL('../../src/camoufox/traffic-recorder.js', import.meta.url).href;
    const child = `
        import fs from 'node:fs';
        import { EventEmitter } from 'node:events';
        import { CamoufoxTrafficRecorder } from ${JSON.stringify(recorderModule)};
        const recorder = new CamoufoxTrafficRecorder({
            trafficDir: process.argv[1], recordBodies: true, recordWireLog: false
        });
        const page = new EventEmitter();
        const socket = Object.assign(new EventEmitter(), { url: () => 'wss://example.test/local' });
        recorder.attachPage(page);
        page.emit('websocket', socket);
        const write = fs.writeFileSync;
        fs.writeFileSync = (file, data, ...args) => {
            if (typeof data === 'string' && data.startsWith('{"type":"ws-egress"')) process.exit(0);
            return write(file, data, ...args);
        };
        socket.emit('framesent', { payload: 'synthetic interrupted frame' });
        process.exitCode = 1;
    `;
    execFileSync(process.execPath, ['--input-type=module', '-e', child, trafficDir], { timeout: 5000 });
    const payloadsDir = path.join(trafficDir, 'payloads');
    assert.equal(fs.readdirSync(payloadsDir).length, 2);

    const resumed = create();
    const summary = await resumed.stop();
    assert.deepEqual(events(resumed).map(event => event.type), ['ws-open']);
    assert.deepEqual(fs.readdirSync(payloadsDir), []);
    assert.equal(summary.captureLimits.bytes, fs.statSync(resumed.trafficNdjsonPath).size);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('resume inventories older unindexed attachments without discarding their contents', async (t) => {
    const { trafficDir, create } = fixture(t);
    const recorder = create();
    recorder.setStep('earlier-recording');
    const first = await recorder.stop();
    const orphanPath = path.join(recorder.payloadsDir, 'prior-attachment.bin');
    const original = Buffer.from('local sample from an earlier recorder');
    fs.writeFileSync(orphanPath, original, { mode: 0o600 });

    const resumed = create({ maxCaptureBytes: first.captureLimits.bytes + original.byteLength });
    assert.equal(resumed.recordSecurityBlock({ type: 'later-recording' }), null);
    const summary = await resumed.stop();
    assert.equal(summary.captureLimits.stoppedReason, 'storage-limit');
    assert.equal(summary.captureLimits.bytes, first.captureLimits.bytes + original.byteLength);
    assert.deepEqual(fs.readFileSync(orphanPath), original);
    assert.match(verifyTrafficIntegrity(trafficDir).errors.join('\n'), /Orphan unindexed payload file/);
});

test('oversized request and WebSocket bodies use bounded processing and retain their byte prefix', async (t) => {
    const maxCaptureBytes = 16 * 1024;
    const maxBodyBytes = 32;
    const maxProcessingBytes = 4096;
    const { trafficDir, create } = fixture(t, { recordBodies: true, maxCaptureBytes, maxBodyBytes });
    const recorder = create();
    const context = new EventEmitter();
    const page = new EventEmitter();
    const ws = Object.assign(new EventEmitter(), { url: () => 'wss://example.test/body-limit' });
    recorder.attachContext(context);
    recorder.attachPage(page);
    page.emit('websocket', ws);

    const binary = Buffer.alloc(maxCaptureBytes * 2, 42);
    const text = 'a🌿'.repeat(maxCaptureBytes);
    const from = Buffer.from;
    const byteLength = Buffer.byteLength;
    const allocUnsafe = Buffer.allocUnsafe;
    const hashPrototype = Object.getPrototypeOf(createHash('sha256'));
    const update = hashPrototype.update;
    let maxMeasuredChars = 0;
    let maxAllocatedBytes = 0;
    let maxHashBytes = 0;
    Buffer.from = (value, ...args) => {
        const buffer = from(value, ...args);
        maxAllocatedBytes = Math.max(maxAllocatedBytes, buffer.byteLength);
        return buffer;
    };
    Buffer.allocUnsafe = (bytes) => {
        maxAllocatedBytes = Math.max(maxAllocatedBytes, bytes);
        return allocUnsafe(bytes);
    };
    Buffer.byteLength = (value, ...args) => {
        if (typeof value === 'string') maxMeasuredChars = Math.max(maxMeasuredChars, value.length);
        return byteLength(value, ...args);
    };
    hashPrototype.update = function (value, ...args) {
        maxHashBytes = Math.max(maxHashBytes, byteLength(value));
        return update.call(this, value, ...args);
    };
    let live;
    try {
        context.emit('request', request('buffer-upload', { postDataBuffer: () => binary }));
        context.emit('request', request('text-upload', { postData: () => text }));
        context.emit('request', request('empty-request', { postDataBuffer: () => null }));
        ws.emit('framesent', { payload: text });
        ws.emit('framereceived', { payload: '' });
        live = await recorder.stop();
    } finally {
        Buffer.from = from;
        Buffer.allocUnsafe = allocUnsafe;
        Buffer.byteLength = byteLength;
        hashPrototype.update = update;
    }
    assert.ok(maxMeasuredChars <= maxProcessingBytes + 1);
    assert.ok(maxAllocatedBytes <= maxProcessingBytes + 3);
    assert.ok(maxHashBytes <= maxProcessingBytes);
    const recorded = events(recorder);
    const sent = recorded.find(event => event.type === 'ws-egress');
    const empty = recorded.find(event => event.type === 'ws-ingress');
    const bufferUpload = recorded.find(event => event.type === 'egress' && event.url.endsWith('/buffer-upload'));
    const textUpload = recorded.find(event => event.type === 'egress' && event.url.endsWith('/text-upload'));
    const emptyRequest = recorded.find(event => event.type === 'egress' && event.url.endsWith('/empty-request'));
    assert.equal(bufferUpload.postDataBytes, binary.byteLength);
    assert.equal(textUpload.postDataBytes, null);
    assert.equal(emptyRequest.postDataBytes, 0);
    assert.equal(emptyRequest.payloadFile, null);
    assert.equal(sent.payloadBytes, null);
    assert.equal(empty.payloadBytes, 0);
    for (const [event, original] of [[sent, Buffer.from(text)], [bufferUpload, binary], [textUpload, Buffer.from(text)]]) {
        assert.equal(event.postDataSha256 ?? event.payloadSha256 ?? null, null);
        assert.equal(event.payloadTruncated, true);
        assert.deepEqual(fs.readFileSync(path.join(trafficDir, event.payloadFile)), original.subarray(0, maxBodyBytes));
    }
    assert.equal(live.totals.wsFramesSent, 1);
    assert.equal(live.totals.unknownWsFramesSent, 1);
    assert.equal(live.totals.wsFramesReceived, 1);
    assert.equal(live.totals.unknownWsFramesReceived, 0);
    assert.match(recorder.formatTransactionWireDump(sent.correlationId), /WS-EGRESS[^\n]*bytes=unknown/);
    assert.match(recorder.formatTransactionWireDump(empty.correlationId), /WS-INGRESS[^\n]*bytes=0/);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
    assert.deepEqual((await create().stop()).totals, live.totals);
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

test('context attachment replaces existing page HTTP handlers while retaining WebSockets', async (t) => {
    for (const first of ['page', 'context']) {
        const { create } = fixture(t);
        const recorder = create();
        const page = new EventEmitter();
        const context = Object.assign(new EventEmitter(), { pages: () => [page] });
        page.context = () => context;
        if (first === 'page') {
            recorder.attachPage(page);
            assert.equal(page.listenerCount('response'), 1);
            recorder.attachContext(context);
        } else {
            recorder.attachContext(context);
            recorder.attachPage(page);
        }

        assert.equal(page.listenerCount('response'), 0);
        assert.equal(page.listenerCount('websocket'), 1);
        const succeeded = request('succeeded');
        const failed = request('failed', { failure: () => ({ errorText: 'fixture error' }) });
        for (const emitter of [context, page]) {
            emitter.emit('request', succeeded);
            emitter.emit('request', failed);
            emitter.emit('response', { request: () => succeeded, url: succeeded.url, status: () => 200 });
            emitter.emit('requestfinished', succeeded);
            emitter.emit('requestfailed', failed);
        }
        const summary = await recorder.stop();
        assert.equal(summary.totals.totalRequests, 2);
        assert.equal(summary.totals.totalResponses, 1);
        assert.equal(summary.totals.failedRequests, 1);
        assert.equal(summary.integrity.eventCount, 5);
    }
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
