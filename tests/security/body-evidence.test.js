import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { queryProfileTraffic } from '../../scripts/query-traffic-attribution.js';
import {
    CamoufoxTrafficRecorder, exportTrafficToHar, MAX_HAR_RECORD_BYTES, verifyTrafficIntegrity
} from '../../src/camoufox/traffic-recorder.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';
const headers = { 'content-type': 'application/json' };
const traceId = 'operator-trace';
const profileId = 'body-fixture';

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'body-evidence-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const trafficDir = path.join(root, 'traffic');
    const output = path.join(root, 'trace.har');
    return {
        trafficDir,
        output,
        open: (options = {}) => new CamoufoxTrafficRecorder({
            trafficDir, traceId, profileId, recordWireLog: false, trustedLocal: true, ...options
        })
    };
}

function upload(recorder, url, content) {
    const context = new EventEmitter();
    recorder.attachContext(context);
    context.emit('request', {
        url: () => url,
        method: () => 'POST',
        headers: () => headers,
        postDataBuffer: () => Buffer.from(content)
    });
}

function events(recorder) {
    return fs.readFileSync(recorder.trafficNdjsonPath, 'utf8').trim().split('\n').map(JSON.parse);
}

function outlets(trafficDir, output, event, recordBodies) {
    const options = { trafficDir, recordBodies, trustedLocal: true };
    const archive = exportTrafficToHar(trafficDir, output, {}, options);
    const entry = archive.log.entries.find((entry) => entry.request.url === event.url);
    const wire = queryProfileTraffic({ ...options, correlationId: event.correlationId });
    const report = queryProfileTraffic(options);
    const row = report.events.find((record) => record.type === 'egress' && record.url === event.url);
    assert.ok(entry);
    assert.equal(wire.found, true);
    assert.ok(row);
    return { har: entry.request.postData.text, wire: wire.requestPayload, preview: row.bodyPreview };
}

function projection(text) {
    return { har: text, wire: text, preview: text };
}

function digest(content) {
    return createHash('sha256').update(content).digest('hex');
}

test('reusing a trace does not extend the recorded body export grant', { skip: !supported }, async (t) => {
    const { trafficDir, output, open } = fixture(t);
    const first = open({ recordBodies: true });
    const originalBody = '{"count":19,"message":"private fixture"}';
    upload(first, 'https://fixture.example/earlier', originalBody);
    await first.stop();
    const [original] = events(first);
    const originalPayload = path.join(trafficDir, original.payloadFile);
    assert.deepEqual(outlets(trafficDir, output, original), projection('{"count":19}'));

    const disabled = open({ recordBodies: false });
    upload(disabled, 'https://fixture.example/metadata', '{"count":0}');
    await disabled.stop();
    const withheld = { har: '', wire: null, preview: null };
    assert.deepEqual(outlets(trafficDir, output, original), withheld);
    const originalLedger = fs.readFileSync(first.trafficNdjsonPath);
    const empty = open({ recordBodies: true });
    await empty.stop();
    assert.equal(empty.buildHarArchive().log.entries.length, 0);
    assert.doesNotMatch(empty.formatTransactionWireDump(original.correlationId), /"count":19/);
    assert.deepEqual(outlets(trafficDir, output, original), withheld);
    assert.deepEqual(fs.readFileSync(first.trafficNdjsonPath), originalLedger);

    const current = open({ recordBodies: true });
    upload(current, 'https://fixture.example/current', '{"count":24}');
    await current.stop();
    const newlyRecorded = events(current).at(-1);
    assert.deepEqual(outlets(trafficDir, output, original), withheld);
    assert.deepEqual(outlets(trafficDir, output, newlyRecorded), projection('{"count":24}'));
    assert.deepEqual(outlets(trafficDir, output, newlyRecorded, false), withheld);
    assert.deepEqual(fs.readFileSync(first.trafficNdjsonPath).subarray(0, originalLedger.length), originalLedger);
    assert.equal(fs.readFileSync(originalPayload, 'utf8'), originalBody);
    assert.equal(verifyTrafficIntegrity(trafficDir, { trustedLocal: true }).valid, true);
});

test('reopening a verified legacy attachment does not supply missing body authorization', { skip: !supported }, async (t) => {
    const { trafficDir, output, open } = fixture(t);
    const directory = path.join(trafficDir, 'payloads');
    const payloadFile = 'payloads/legacy.json';
    const attachment = '{"count":57,"message":"archived fixture"}';
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(trafficDir, payloadFile), attachment);

    const genesisHash = '0'.repeat(64);
    const event = {
        type: 'egress',
        seq: 1,
        correlationId: 'legacy-transaction',
        timestamp: '2026-01-01T00:00:00.000Z',
        method: 'POST',
        url: 'https://fixture.example/archived',
        headers,
        attribution: { traceId, profileId },
        bodyPreview: null,
        payloadFile,
        postDataBytes: Buffer.byteLength(attachment),
        postDataSha256: digest(attachment),
        prevEventHash: genesisHash
    };
    event.eventHash = digest([event.prevEventHash, event.seq, JSON.stringify(event)].join('|'));
    const original = JSON.stringify(event) + '\n';
    const capturePath = path.join(trafficDir, 'traffic.ndjson');
    fs.writeFileSync(capturePath, original);
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({
        session: { profileId, traceId },
        integrity: {
            algorithm: 'sha256-chain',
            genesisHash,
            chainHeadHash: event.eventHash,
            eventCount: 1,
            payloadCount: 1,
            payloadManifest: {
                [payloadFile]: {
                    sha256: event.postDataSha256, bytes: event.postDataBytes, truncated: false
                }
            }
        }
    }));
    const withheld = { har: '', wire: null, preview: null };
    assert.deepEqual(outlets(trafficDir, output, event), withheld);
    const recorder = open({ recordBodies: true });
    await recorder.stop();
    assert.deepEqual(outlets(trafficDir, output, event), withheld);
    assert.equal(fs.readFileSync(capturePath, 'utf8'), original);
    assert.equal(fs.readFileSync(path.join(trafficDir, payloadFile), 'utf8'), attachment);
});

test('a checkpoint authorizes later events from its own recording only', { skip: !supported }, async (t) => {
    const { trafficDir, output, open } = fixture(t);
    const first = open({ recordBodies: true });
    const checkpoint = await first.flushSummary();
    assert.equal(checkpoint.integrity.eventCount, 0);
    upload(first, 'https://fixture.example/checkpoint-owner', '{"count":63}');
    await new Promise(setImmediate);
    const [owner] = events(first);
    assert.deepEqual(outlets(trafficDir, output, owner), projection('{"count":63}'));
    await first.stop();

    const next = open({ recordBodies: true });
    upload(next, 'https://fixture.example/checkpoint-successor', '{"count":72}');
    await new Promise(setImmediate);
    const successor = events(next).at(-1);
    assert.equal(successor.url, 'https://fixture.example/checkpoint-successor');
    assert.deepEqual(outlets(trafficDir, output, owner), projection('{"count":63}'));
    assert.deepEqual(outlets(trafficDir, output, successor), { har: '', wire: null, preview: null });
    await next.stop();
    assert.deepEqual(outlets(trafficDir, output, successor), projection('{"count":72}'));
    assert.deepEqual(outlets(trafficDir, output, owner), { har: '', wire: null, preview: null });
});

for (const [items, omitPreview] of [[90000, true], [75000, true], [74000, false]]) {
    test('optional body preview respects the serialized HAR ledger budget for ' + items + ' items', {
        skip: !supported
    }, async (t) => {
        const { trafficDir, output, open } = fixture(t);
        const body = JSON.stringify({ items: Array(items).fill({ count: 1 }) });
        const recorder = open({ recordBodies: true, maxInlinePreviewBytes: 1200000 });
        upload(recorder, 'https://fixture.example/items', body);
        const summary = await recorder.stop();
        const [event] = events(recorder);
        assert.equal(summary.integrity.eventCount, 1);
        assert.equal(summary.integrity.payloadCount, 1);
        assert.equal(summary.captureLimits.stoppedReason, null);
        assert.equal(verifyTrafficIntegrity(trafficDir, { trustedLocal: true }).valid, true);
        assert.ok(fs.statSync(recorder.trafficNdjsonPath).size - 1 <= MAX_HAR_RECORD_BYTES);
        const expectedPreview = omitPreview ? null : body;
        assert.equal(event.postData, expectedPreview);
        assert.equal(event.bodyPreview, expectedPreview);
        assert.equal(event.bodyPreviewTruncated, omitPreview);
        assert.equal(event.postDataSha256, digest(body));
        assert.equal(fs.readFileSync(path.join(trafficDir, event.payloadFile), 'utf8'), body);

        const contextual = recorder.buildHarArchive();
        assert.equal(contextual.log.entries[0].request.postData.text, body);
        const shared = exportTrafficToHar(trafficDir, output, {}, { trustedLocal: true, recordBodies: false });
        assert.equal(shared.log.entries[0].request.url, event.url);
        assert.equal(shared.log.entries[0].request.postData.text, '');
    });
}
