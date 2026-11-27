import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { formatCliReport, queryProfileTraffic } from '../../scripts/query-traffic-attribution.js';
import { CamoufoxTrafficRecorder, verifyTrafficIntegrity } from '../../src/camoufox/traffic-recorder.js';

function fixture(t, options = {}) {
    const trafficDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'attachment-verification-'));
    t.after(() => fs.rmSync(trafficDir, { recursive: true, force: true }));
    const open = (overrides = {}) => new CamoufoxTrafficRecorder({
        trafficDir,
        recordBodies: true,
        recordWireLog: false,
        sslKeyLog: false,
        neckoMozLog: false,
        ...options,
        ...overrides
    });
    const recorder = open();
    return { trafficDir, open, recorder, indexPath: recorder.attributionIndexPath, ledgerPath: recorder.trafficNdjsonPath };
}

function digest(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
}

function request(recorder, bytes) {
    const context = Object.assign(new EventEmitter(), { pages: () => [] });
    recorder.attachContext(context);
    context.emit('request', {
        url: () => 'https://fixture.invalid/upload',
        method: () => 'POST',
        headers: () => ({ 'content-type': 'text/plain' }),
        postDataBuffer: () => bytes
    });
}

function readEvents(ledgerPath) {
    return fs.readFileSync(ledgerPath, 'utf8').trimEnd().split('\n').map((line) => JSON.parse(line));
}

for (const [variant, maxBodyBytes] of [['complete', 1024], ['truncated', 4]]) {
    test(variant + ' attachments bind persisted bytes to the event during verification and resume', async (t) => {
        const { trafficDir, open, recorder, indexPath, ledgerPath } = fixture(t, { maxBodyBytes });
        const body = Buffer.from('synthetic payload');
        request(recorder, body);
        const summary = await recorder.stop();
        const [event] = readEvents(ledgerPath);
        const actual = body.subarray(0, maxBodyBytes);
        assert.equal(event.postDataSha256, digest(body));
        assert.deepEqual(event.payloadStorage, { status: 'stored', sha256: digest(actual), bytes: actual.length });
        const original = verifyTrafficIntegrity(trafficDir);
        assert.equal(original.valid, true);
        assert.equal(original.payloadManifestVerified, true);
        assert.equal(original.verifiedPayloads, 1);

        // Independent fixture declarations disagree with the event's captured bytes.
        const inconsistent = Buffer.alloc(actual.length, 0x61);
        fs.writeFileSync(path.join(trafficDir, event.payloadFile), inconsistent);
        summary.integrity.payloadManifest[event.payloadFile].sha256 = digest(inconsistent);
        fs.writeFileSync(indexPath, JSON.stringify(summary));
        const rejected = verifyTrafficIntegrity(trafficDir);
        assert.equal(rejected.valid, false);
        assert.equal(rejected.verifiedPayloads, 0);
        assert.equal(rejected.chainHeadHash, original.chainHeadHash);
        assert.match(rejected.errors.join('\n'), /Payload SHA-256 mismatch.*event/);
        assert.throws(open, /Payload SHA-256 mismatch.*event/);
    });
}

test('recovery restores a committed truncated attachment when no index checkpoint exists', async (t) => {
    const { trafficDir, open, recorder, indexPath } = fixture(t, { maxBodyBytes: 4 });
    request(recorder, Buffer.from('synthetic crash fixture'));
    await recorder.stop();
    fs.unlinkSync(indexPath);
    await open().stop();
    const restored = verifyTrafficIntegrity(trafficDir);
    assert.equal(restored.valid, true);
    assert.equal(restored.verifiedPayloads, 1);
});

test('legacy payload descriptors without proof remain explicitly unverified', async (t) => {
    const { trafficDir, open, recorder, indexPath } = fixture(t);
    request(recorder, Buffer.from('synthetic legacy descriptor'));
    const summary = await recorder.stop();
    const [relativePath] = Object.keys(summary.integrity.payloadManifest);
    delete summary.integrity.payloadManifest[relativePath].sha256;
    fs.writeFileSync(indexPath, JSON.stringify(summary));
    await open().stop();
    const report = queryProfileTraffic({ trafficDir, verifyIntegrity: true });
    assert.equal(report.valid, true);
    assert.equal(report.payloadManifestVerified, false);
    assert.equal(report.verifiedPayloads, 0);
    assert.deepEqual(report.unverifiedPayloads, [{ path: relativePath, reason: 'missing-manifest-digest-or-length' }]);
    assert.match(formatCliReport(report), /Status\s+: INCOMPLETE/);

    summary.integrity.payloadManifest[relativePath].sha256 = 'invalid';
    fs.writeFileSync(indexPath, JSON.stringify(summary));
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, false);
    assert.throws(open, /Payload SHA-256 digest is invalid/);
});

test('nested legacy payloads preserve manifest checks and the inventory finds extra files', async (t) => {
    const { trafficDir, recorder } = fixture(t);
    const body = Buffer.from('legacy payload');
    const prefix = body.subarray(0, 3);
    const relativePath = 'payloads/outer/inner/legitimate.txt';
    const fullPath = path.join(trafficDir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, prefix, { mode: 0o600 });
    recorder._appendNdjsonEvent({
        type: 'egress',
        seq: 1,
        payloadFile: relativePath,
        payloadTruncated: true,
        postDataSha256: digest(body),
        postDataBytes: body.length
    });
    recorder.payloadManifest[relativePath] = { sha256: digest(prefix), bytes: prefix.length, truncated: true };
    await recorder.stop();

    const legacy = verifyTrafficIntegrity(trafficDir);
    assert.equal(legacy.valid, true);
    assert.equal(legacy.verifiedPayloads, 0);
    assert.deepEqual(legacy.unverifiedPayloads, [{ path: relativePath, reason: 'missing-event-digest-or-length' }]);

    fs.writeFileSync(path.join(path.dirname(fullPath), 'extra.txt'), 'unindexed fixture');
    assert.match(verifyTrafficIntegrity(trafficDir).errors.join('\n'), /Orphan unindexed payload file.*outer\/inner\/extra.txt/);
});

test('an attachment write failure remains visible in the chain, HAR and strict verification after resume', async (t) => {
    const { trafficDir, open, recorder, ledgerPath } = fixture(t);
    const body = Buffer.from('synthetic write failure');
    const write = fs.writeFileSync;
    fs.writeFileSync = (file, bytes, ...args) => {
        if (typeof file === 'number' && Buffer.isBuffer(bytes) && bytes.equals(body)) {
            throw Object.assign(new Error('synthetic disk fault'), { code: 'ENOSPC' });
        }
        return write(file, bytes, ...args);
    };
    let summary;
    try {
        request(recorder, body);
        summary = await recorder.stop();
    } finally {
        fs.writeFileSync = write;
    }
    const [event] = readEvents(ledgerPath);
    assert.equal(event.payloadFile, null);
    assert.deepEqual(event.payloadStorage, { status: 'failed', reason: 'write-failed' });
    assert.deepEqual(summary.integrity.payloadCaptureIssues, { writeFailures: 1, storageOmissions: 0 });
    assert.deepEqual(fs.readdirSync(path.join(trafficDir, 'payloads')), []);

    const sessionHar = recorder.buildHarArchive().log;
    assert.deepEqual(sessionHar._payloadCaptureIssues, summary.integrity.payloadCaptureIssues);
    assert.equal(sessionHar.entries[0]._attribution.requestPayloadIssue, 'write-failed');
    assert.equal(sessionHar.entries[0]._attribution.requestPayloadFile, null);

    const resumed = open();
    const afterResume = await resumed.stop();
    const integrity = verifyTrafficIntegrity(trafficDir);
    assert.equal(integrity.valid, false);
    assert.equal(integrity.payloadManifestVerified, false);
    assert.match(integrity.errors.join('\n'), /1 payload attachment write/);
    assert.deepEqual(afterResume.integrity.payloadCaptureIssues, summary.integrity.payloadCaptureIssues);
    assert.equal(resumed.buildHarArchive().log.entries.length, 0);

    const archive = queryProfileTraffic({ trafficDir, exportHar: path.join(trafficDir, 'selected.har') }).log;
    assert.deepEqual(archive._payloadCaptureIssues, summary.integrity.payloadCaptureIssues);
    assert.equal(archive.entries[0]._attribution.requestPayloadIssue, 'write-failed');
    assert.equal(archive.entries[0]._attribution.requestPayloadFile, null);
    const wire = queryProfileTraffic({ trafficDir, correlationId: event.correlationId });
    assert.match(wire.wireDump, /Request attachment write failed/);
});

test('wire summaries skip disabled undeclared files and bound enabled file reads', async (t) => {
    const disabled = fixture(t);
    const wirePath = disabled.recorder.preTlsWireLogPath;
    await disabled.recorder.stop();
    fs.mkdirSync(wirePath);
    const resumed = disabled.open();
    assert.equal((await resumed.stop()).integrity.preTlsWireLogSha256, null);
    assert.equal(verifyTrafficIntegrity(disabled.trafficDir).valid, true);

    const enabled = fixture(t, { recordWireLog: true });
    const selected = enabled.recorder.preTlsWireLogPath;
    const initial = await enabled.recorder.flushSummary();
    const checkpoint = fs.readFileSync(enabled.indexPath);
    assert.equal(initial.integrity.preTlsWireLogSha256, digest(Buffer.alloc(0)));
    fs.truncateSync(selected, 128 * 1024 * 1024 + 1);
    await assert.rejects(enabled.recorder.stop(), { code: 'ERR_CAPTURE_TOO_LARGE' });
    assert.deepEqual(fs.readFileSync(enabled.indexPath), checkpoint);
});

test('disabling wire logging preserves a verified checkpoint with a recoverable appended suffix', async (t) => {
    const { trafficDir, open, recorder, indexPath } = fixture(t, { recordWireLog: true });
    recorder.recordSecurityBlock({ type: 'fixture' });
    await recorder.flushSummary();
    const checkpoint = fs.readFileSync(indexPath);
    recorder.recordSecurityBlock({ type: 'fixture', url: 'https://fixture.invalid' });
    await recorder.stop();
    fs.writeFileSync(indexPath, checkpoint);

    const resumed = open({ recordWireLog: false });
    await resumed.stop();
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});
