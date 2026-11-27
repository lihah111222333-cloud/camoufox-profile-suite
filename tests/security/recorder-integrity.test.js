import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';
import { CamoufoxTrafficRecorder, verifyTrafficIntegrity } from '../../src/camoufox/traffic-recorder.js';

function fixture(t, options = {}) {
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'recorder-integrity-'));
    t.after(() => fs.rmSync(root, { force: true, recursive: true }));
    const trafficDir = path.join(root, 'traffic');
    const create = (overrides = {}) => new CamoufoxTrafficRecorder({
        trafficDir,
        sslKeyLog: false,
        neckoMozLog: false,
        ...options,
        ...overrides
    });
    return {
        trafficDir,
        create,
        recorder: create(),
        ledgerPath: path.join(trafficDir, 'traffic.ndjson'),
        indexPath: path.join(trafficDir, 'attribution-index.json')
    };
}

function deferred() {
    let resolve;
    const promise = new Promise((finish) => {
        resolve = finish;
    });
    return { promise, resolve };
}

function readEvents(ledgerPath) {
    return fs.readFileSync(ledgerPath, 'utf8').trimEnd().split('\n').map((line) => JSON.parse(line));
}

test('the capture writer holds one lease through delayed finalization and can be reopened', async (t) => {
    const { trafficDir, recorder, create, ledgerPath, indexPath } = fixture(t, {
        recordWireLog: false, neckoMozLog: true
    });
    recorder.setStep('first writer');
    await recorder.flushSummary();
    const ledger = fs.readFileSync(ledgerPath);
    assert.throws(() => create({ resetTrafficOnStart: true }), { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });
    const recorderModule = new URL('../../src/camoufox/traffic-recorder.js', import.meta.url).href;
    const child = `
        import assert from 'node:assert/strict';
        import { CamoufoxTrafficRecorder } from ${JSON.stringify(recorderModule)};
        assert.throws(() => new CamoufoxTrafficRecorder({ trafficDir: process.argv[1] }),
            { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });
    `;
    execFileSync(process.execPath, ['--input-type=module', '-e', child, trafficDir], { timeout: 5000 });
    assert.deepEqual(fs.readFileSync(ledgerPath), ledger);

    await recorder.stop({ nativeLogsClosed: false });
    assert.throws(() => create(), { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });
    const final = await recorder.flushSummary({ nativeLogsClosed: true });
    const next = create({ neckoMozLog: false });
    next.setStep('next writer');
    await next.flushSummary();
    const nextIndex = fs.readFileSync(indexPath);
    assert.deepEqual(await recorder.stop(), final);
    assert.deepEqual(await recorder.flushSummary(), final);
    assert.deepEqual(fs.readFileSync(indexPath), nextIndex);
    await next.stop();
    assert.deepEqual(readEvents(ledgerPath).map((event) => event.actionStep), ['first writer', 'next writer']);

    const reset = create({ resetTrafficOnStart: true, neckoMozLog: false });
    reset.setStep('after reset');
    await reset.stop();
    assert.deepEqual(readEvents(ledgerPath).map((event) => event.actionStep), ['after reset']);
});

test('close and stop release recorder listeners and stop drains already accepted HTTP captures', async (t) => {
    const { trafficDir, recorder, ledgerPath } = fixture(t);
    const page = new EventEmitter();
    const context = Object.assign(new EventEmitter(), { pages: () => [page] });
    page.context = () => context;
    recorder.attachContext(context).attachPage(page);

    const closedSocket = Object.assign(new EventEmitter(), { url: () => 'wss://example.test/closed' });
    const activeSocket = Object.assign(new EventEmitter(), { url: () => 'wss://example.test/open' });
    const observer = () => {};
    closedSocket.on('framesent', observer);
    page.emit('websocket', closedSocket);
    closedSocket.emit('framesent', { payload: 'fixture frame' });
    const retainedClose = closedSocket.listeners('close')[0];
    closedSocket.emit('close');
    retainedClose();
    assert.deepEqual(closedSocket.listeners('framesent'), [observer]);
    for (const event of ['framereceived', 'socketerror', 'close']) {
        assert.equal(closedSocket.listenerCount(event), 0);
    }

    page.emit('websocket', activeSocket);
    const retainedFrame = activeSocket.listeners('framereceived')[0];
    const retainedRequest = context.listeners('request')[0];
    const headers = deferred();
    const sizes = deferred();
    const request = {
        url: () => 'https://example.test/form',
        method: () => 'POST',
        headersArray: () => headers.promise,
        sizes: () => sizes.promise,
        postDataBuffer: () => Buffer.from('fixture body')
    };
    context.emit('request', request);
    context.emit('requestfinished', request);

    let stopped = false;
    const stopping = recorder.stop().then((summary) => {
        stopped = true;
        return summary;
    });
    retainedFrame({ payload: 'late frame' });
    retainedRequest(request);
    recorder.setStep('late step');
    assert.equal(recorder.recordTriggerAction('late trigger'), null);
    assert.equal(recorder.recordSecurityBlock(), null);
    assert.equal(recorder.recordNeckoMozLogBlock('late line').appendedBytes, 0);
    recorder.attachPage(new EventEmitter()).attachContext(new EventEmitter());
    for (const event of ['framesent', 'framereceived', 'socketerror', 'close']) {
        assert.equal(activeSocket.listenerCount(event), 0);
    }
    assert.equal(context.listenerCount('request'), 0);
    assert.equal(page.listenerCount('websocket'), 0);

    headers.resolve([{ name: 'content-type', value: 'text/plain' }]);
    await setImmediate();
    assert.equal(stopped, false);
    assert.equal(recorder.endedAt, null);
    sizes.resolve({ requestBodySize: 12 });
    const summary = await stopping;
    assert.deepEqual(readEvents(ledgerPath).map(({ type }) => type), [
        'ws-open', 'ws-egress', 'ws-close', 'ws-open', 'egress', 'request-finished'
    ]);
    assert.equal(summary.totals.totalRequests, 1);
    assert.equal(summary.integrity.eventCount, 6);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
    assert.equal((await recorder.stop()).session.endedAt, summary.session.endedAt);
});

test('recovery drops only a torn append after a valid checkpoint and preserves the complete prefix', async (t) => {
    const { trafficDir, recorder, create, ledgerPath, indexPath } = fixture(t, { recordWireLog: false });
    recorder.setStep('checkpoint');
    await recorder.flushSummary();
    const checkpointIndex = fs.readFileSync(indexPath);
    recorder.setStep('complete event é');
    const prefix = fs.readFileSync(ledgerPath);
    recorder.setStep('interrupted event');
    await recorder.stop();
    fs.writeFileSync(indexPath, checkpointIndex);
    fs.truncateSync(ledgerPath, fs.statSync(ledgerPath).size - 9);

    const resumed = create();
    assert.deepEqual(fs.readFileSync(ledgerPath), prefix);
    assert.deepEqual(fs.readFileSync(indexPath), checkpointIndex);
    assert.equal(resumed.getAttributionSnapshot().stepIndex, 2);
    resumed.setStep('resumed');
    await resumed.stop();
    assert.deepEqual(readEvents(ledgerPath).map(({ actionStep }) => actionStep), [
        'checkpoint', 'complete event é', 'resumed'
    ]);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('recovery keeps a complete final record when only its newline is missing', async (t) => {
    const { trafficDir, recorder, create, ledgerPath } = fixture(t, { recordWireLog: false });
    recorder.setStep('complete event');
    await recorder.stop();
    const complete = fs.readFileSync(ledgerPath);
    fs.truncateSync(ledgerPath, complete.length - 1);
    const resumed = create();
    assert.deepEqual(fs.readFileSync(ledgerPath), complete.subarray(0, -1));
    resumed.setStep('next event');
    await resumed.stop();

    assert.deepEqual(fs.readFileSync(ledgerPath).subarray(0, complete.length), complete);
    assert.equal(readEvents(ledgerPath).length, 2);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('recovery preserves the ledger and index when recorded evidence is incomplete or corrupted', async (t) => {
    const { trafficDir, recorder, create, ledgerPath, indexPath } = fixture(t, { recordWireLog: false });
    recorder.setStep('first');
    recorder.setStep('second');
    recorder.setStep('third');
    await recorder.stop();
    const original = fs.readFileSync(ledgerPath);
    const index = fs.readFileSync(indexPath);
    const [first, second, third] = original.toString('utf8').trimEnd().split('\n');
    const cases = [
        [`${first}\n{"type":\n${third}\n`, /Line 2.*Invalid JSON/],
        [`${first}\n${second.replace('second', 'different')}\n${third}\n`, /Line 2.*eventHash mismatch/],
        [`${first}\n${second}\n${third.replace('third', 'different')}`, /Line 3.*eventHash mismatch/],
        [`${first}\n${second}\n{"type":}`, /Line 3.*Invalid JSON/],
        [`${first}\n${second}\n{"type":\n`, /Line 3.*Invalid JSON/],
        [original.subarray(0, -8), /Event count mismatch/]
    ];
    for (const [bytes, expectedError] of cases) {
        fs.writeFileSync(ledgerPath, bytes);
        assert.throws(() => create(), expectedError);
        assert.deepEqual(fs.readFileSync(ledgerPath), Buffer.from(bytes));
        assert.deepEqual(fs.readFileSync(indexPath), index);
        assert.equal(verifyTrafficIntegrity(trafficDir).valid, false);
    }
    fs.writeFileSync(ledgerPath, original);
    await create().stop();
});

test('a failed append does not advance the chain or overwrite the existing index', async (t) => {
    const { trafficDir, recorder, create, ledgerPath, indexPath } = fixture(t, { recordWireLog: false });
    recorder.setStep('before write fault');
    const checkpoint = await recorder.flushSummary();
    const original = fs.readFileSync(ledgerPath);
    const index = fs.readFileSync(indexPath);

    const write = fs.writeFileSync;
    fs.writeFileSync = (fd, data, ...args) => {
        if (typeof fd === 'number' && typeof data === 'string' && data.includes('interrupted write')) {
            write(fd, data.substring(0, Math.floor(data.length / 2)), ...args);
            throw new Error('simulated disk write fault');
        }
        return write(fd, data, ...args);
    };
    try {
        recorder.setStep('interrupted write');
    } finally {
        fs.writeFileSync = write;
    }
    const torn = fs.readFileSync(ledgerPath);
    assert.ok(torn.length > original.length);
    recorder.setStep('would follow partial append');
    await assert.rejects(recorder.stop(), /Could not append to traffic.ndjson/);
    assert.equal(recorder.chainHeadHash, checkpoint.integrity.chainHeadHash);
    assert.equal(recorder.chainedEventCount, checkpoint.integrity.eventCount);
    assert.deepEqual(fs.readFileSync(ledgerPath), torn);
    assert.deepEqual(fs.readFileSync(indexPath), index);

    const resumed = create();
    assert.deepEqual(fs.readFileSync(ledgerPath), original);
    await resumed.stop();
    const resumedIndex = fs.readFileSync(indexPath);
    await assert.rejects(recorder.flushSummary(), /Could not append to traffic.ndjson/);
    assert.deepEqual(fs.readFileSync(indexPath), resumedIndex);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('recovery and verification require recorded payloads to be present and unchanged', async (t) => {
    const { trafficDir, recorder, create, indexPath } = fixture(t, { maxInlinePreviewBytes: 0, recordBodies: true });
    const page = new EventEmitter();
    const socket = Object.assign(new EventEmitter(), { url: () => 'wss://example.test/fixture' });
    recorder.attachPage(page);
    page.emit('websocket', socket);
    socket.emit('framesent', { payload: 'fixture payload' });
    const summary = await recorder.stop();
    const [payloadFile] = Object.keys(summary.integrity.payloadManifest);
    const payloadPath = path.join(trafficDir, payloadFile);
    assert.equal(verifyTrafficIntegrity(trafficDir).verifiedPayloads, 1);
    const originalIndex = fs.readFileSync(indexPath);

    fs.writeFileSync(payloadPath, 'different data!');
    assert.match(verifyTrafficIntegrity(trafficDir).errors.join('\n'), /Payload SHA-256 mismatch/);
    assert.throws(() => create(), /Payload SHA-256 mismatch/);
    fs.unlinkSync(payloadPath);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, false);
    assert.throws(() => create(), { code: 'ENOENT' });
    assert.deepEqual(fs.readFileSync(indexPath), originalIndex);
});

test('recovery respects the previous wire checkpoint before trimming a torn append', async (t) => {
    const { trafficDir, recorder, create, ledgerPath, indexPath } = fixture(t);
    recorder.recordSecurityBlock({ type: 'fixture', url: 'https://example.test/one' });
    await recorder.flushSummary();
    const index = fs.readFileSync(indexPath);

    recorder.recordSecurityBlock({ type: 'fixture', url: 'https://example.test/two' });
    await recorder.stop();
    fs.writeFileSync(indexPath, index);
    const prefix = fs.readFileSync(ledgerPath);
    fs.appendFileSync(ledgerPath, '{"type":"step-transiti');
    const torn = fs.readFileSync(ledgerPath);

    const original = fs.readFileSync(recorder.preTlsWireLogPath);
    const altered = Buffer.from(original);
    altered[0] ^= 1;
    fs.writeFileSync(recorder.preTlsWireLogPath, altered);
    assert.throws(() => create(), /SHA-256 mismatch/);
    assert.deepEqual(fs.readFileSync(ledgerPath), torn);
    assert.deepEqual(fs.readFileSync(indexPath), index);
    fs.writeFileSync(recorder.preTlsWireLogPath, original);

    const resumed = create();
    assert.deepEqual(fs.readFileSync(ledgerPath), prefix);
    await resumed.stop();
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('verification checks legacy wire, NSS and Necko declarations even when only size is recorded', async (t) => {
    const { trafficDir, recorder, indexPath } = fixture(t);
    const summary = await recorder.stop();
    for (const [field, name, text] of [
        ['sslKeyLog', 'sslkeylog.txt', `CLIENT_RANDOM ${'a'.repeat(64)} ${'b'.repeat(96)}\n`],
        ['neckoMozLog', 'necko-pre-tls.moz_log', 'synthetic Necko fixture\n']
    ]) {
        fs.writeFileSync(path.join(trafficDir, name), text);
        summary.integrity[`${field}Sha256`] = createHash('sha256').update(text).digest('hex');
        summary.integrity[`${field}Bytes`] = Buffer.byteLength(text);
    }
    const writeIndex = (value) => fs.writeFileSync(indexPath, JSON.stringify(value));
    writeIndex(summary);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);

    const artifacts = [
        ['preTlsWireLog', 'pre-tls-wire.log'],
        ['sslKeyLog', 'sslkeylog.txt'],
        ['neckoMozLog', 'necko-pre-tls.moz_log']
    ];
    for (const [field, name] of artifacts) {
        const artifactPath = path.join(trafficDir, name);
        const bytes = fs.readFileSync(artifactPath);
        const sizeOnly = structuredClone(summary);
        delete sizeOnly.integrity[`${field}Sha256`];

        fs.unlinkSync(artifactPath);
        assert.ok(verifyTrafficIntegrity(trafficDir).errors.includes(`Missing ${name} on disk`));
        writeIndex(sizeOnly);
        assert.ok(verifyTrafficIntegrity(trafficDir).errors.includes(`Missing ${name} on disk`));
        fs.writeFileSync(artifactPath, Buffer.concat([bytes, Buffer.from('\n# fixture\n')]));
        assert.ok(verifyTrafficIntegrity(trafficDir).errors.includes(`${name} byte length mismatch`));
        writeIndex(summary);
        assert.ok(verifyTrafficIntegrity(trafficDir).errors.includes(`${name} SHA-256 mismatch`));
        fs.writeFileSync(artifactPath, bytes);
    }
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('verification accepts absent optional artifacts and checks newly recorded private native files', async (t) => {
    const absent = fixture(t, { recordWireLog: false });
    await absent.recorder.stop();
    const noLogs = verifyTrafficIntegrity(absent.trafficDir);
    assert.equal(noLogs.valid, true);
    assert.equal(noLogs.sslKeyLog.exists, false);
    assert.equal(noLogs.neckoMozLog.exists, false);

    const included = fixture(t, { sslKeyLog: true, neckoMozLog: true });
    const { trafficDir, recorder } = included;
    recorder.recordSslKeyLogSecret('CLIENT_RANDOM', 'c'.repeat(64), 'd'.repeat(96));
    recorder.recordNeckoMozLogBlock('synthetic Necko fixture');
    const summary = await recorder.stop();
    assert.equal(summary.integrity.sslKeyLogFile, undefined);
    assert.equal(summary.integrity.neckoMozLogFile, undefined);
    const portable = verifyTrafficIntegrity(trafficDir);
    assert.equal(portable.valid, true);
    assert.deepEqual(portable.unverifiedNativeArtifacts.sort(), ['necko-pre-tls.moz_log', 'sslkeylog.txt']);
    const profile = { nativeDir: recorder.profileNativeDir };
    assert.equal(verifyTrafficIntegrity(trafficDir, profile).valid, true);
    fs.unlinkSync(recorder.sslKeyLogPath);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
    assert.equal(verifyTrafficIntegrity(trafficDir, profile).valid, false);
});

test('a private native log outside the capture directory is outside the archive integrity scope', async (t) => {
    const nativeDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'recorder-native-'));
    t.after(() => fs.rmSync(nativeDir, { force: true, recursive: true }));
    const sslKeyLogPath = path.join(nativeDir, 'sslkeylog.txt');
    const { trafficDir, recorder } = fixture(t, { recordWireLog: false, sslKeyLog: true, sslKeyLogPath });
    recorder.recordSslKeyLogSecret('CLIENT_RANDOM', 'e'.repeat(64), 'f'.repeat(96));
    const summary = await recorder.stop();
    assert.equal(summary.sslKeyLog.entryCount, 1);
    assert.equal(summary.artifacts.sslKeyLogPath, null);
    assert.equal(summary.integrity.sslKeyLogSha256, null);
    assert.equal(summary.integrity.sslKeyLogBytes, 0);
    assert.equal(summary.integrity.sslKeyLogFile, undefined);
    fs.unlinkSync(sslKeyLogPath);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('legacy native archive migration keeps the new capture under its writer lease', async (t) => {
    const { trafficDir, recorder, create, ledgerPath } = fixture(t, { recordWireLog: false });
    recorder.setStep('legacy generation');
    await recorder.stop();
    const original = fs.readFileSync(ledgerPath);
    fs.writeFileSync(path.join(trafficDir, 'necko-pre-tls.moz_log'), 'synthetic legacy native file\n');

    const next = create();
    assert.throws(create, { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });
    const [archived] = fs.readdirSync(next.profileNativeDir);
    const preserved = path.join(next.profileNativeDir, archived, 'traffic', 'traffic.ndjson');
    assert.deepEqual(fs.readFileSync(preserved), original);
    next.setStep('new generation');
    await next.stop();

    const reopened = create();
    await reopened.stop();
    assert.deepEqual(fs.readFileSync(preserved), original);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});
