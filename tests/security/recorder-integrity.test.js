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

test('capture-relative custom wire logs verify and are reused on open', async (t) => {
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'recorder-wire-name-'));
    t.after(() => fs.rmSync(root, { force: true, recursive: true }));
    const trafficDir = path.join(root, 'traffic');
    const fileName = 'named wire.log';
    const preTlsWireLogPath = path.join(trafficDir, fileName);
    const recorder = new CamoufoxTrafficRecorder({ trafficDir, preTlsWireLogPath });
    recorder.recordSecurityBlock({ type: 'fixture', url: 'https://example.test/first' });
    const first = await recorder.stop();
    assert.equal(first.integrity.preTlsWireLogFile, fileName);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);

    const resumed = new CamoufoxTrafficRecorder({ trafficDir });
    resumed.recordSecurityBlock({ type: 'fixture', url: 'https://example.test/next' });
    const second = await resumed.stop();
    assert.equal(second.integrity.preTlsWireLogFile, fileName);
    assert.ok(second.integrity.preTlsWireLogBytes > first.integrity.preTlsWireLogBytes);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
    assert.equal(fs.existsSync(path.join(trafficDir, 'pre-tls-wire.log')), false);

    const indexPath = resumed.attributionIndexPath;
    second.integrity.preTlsWireLogFile = 'traffic.ndjson';
    fs.writeFileSync(indexPath, JSON.stringify(second));
    assert.match(verifyTrafficIntegrity(trafficDir).errors.join('\n'), /Invalid capture wire log file name/);
});

test('a reset failure aborts before starting a new chain over a retained ledger', async (t) => {
    const { trafficDir, recorder, create, ledgerPath, indexPath } = fixture(t);
    recorder.setStep('before reset');
    await recorder.stop();
    const ledger = fs.readFileSync(ledgerPath);
    const index = fs.readFileSync(indexPath);
    const remove = fs.rmSync;
    fs.rmSync = (filePath, ...args) => {
        if (filePath === ledgerPath) throw Object.assign(new Error('fixture reset failure'), { code: 'EACCES' });
        return remove(filePath, ...args);
    };
    try {
        assert.throws(() => create({ resetTrafficOnStart: true }), { code: 'EACCES' });
    } finally {
        fs.rmSync = remove;
    }
    assert.deepEqual(fs.readFileSync(ledgerPath), ledger);
    assert.deepEqual(fs.readFileSync(indexPath), index);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);

    const resumed = create();
    resumed.setStep('after reopening');
    assert.equal((await resumed.stop()).integrity.eventCount, 2);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('recovery preserves an unfinished wire block and refuses to seal it', async (t) => {
    for (const cutAt of ['opening separator', 'middle of request line']) {
        await t.test(cutAt, async (t) => {
            const { recorder, create, ledgerPath, indexPath } = fixture(t);
            recorder.recordSecurityBlock({ type: 'fixture', url: 'https://example.test/before' });
            await recorder.flushSummary();
            const index = fs.readFileSync(indexPath);
            const context = new EventEmitter();
            recorder.attachContext(context);
            const write = fs.writeFileSync;
            fs.writeFileSync = (file, data, ...args) => {
                if (typeof data === 'string' && data.includes('GET /wire-interrupted HTTP/1.1')) {
                    const count = cutAt === 'opening separator' ? data.indexOf('\n') + 1
                        : data.indexOf('GET /wire-interrupted') + 'GET /wire-inter'.length;
                    write(file, data.slice(0, count), ...args);
                    throw Object.assign(new Error('fixture wire short write'), { code: 'ENOSPC' });
                }
                return write(file, data, ...args);
            };
            try {
                context.emit('request', { method: () => 'GET', url: () => 'https://example.test/wire-interrupted' });
                await assert.rejects(recorder.stop(), /Could not append to pre-tls-wire.log/);
            } finally {
                fs.writeFileSync = write;
            }
            const wire = fs.readFileSync(recorder.preTlsWireLogPath);
            const ledger = fs.readFileSync(ledgerPath);
            assert.equal(readEvents(ledgerPath).length, 2);
            assert.throws(() => create(), { code: 'ERR_CAPTURE_INCOMPLETE_WIRE' });
            assert.deepEqual(fs.readFileSync(recorder.preTlsWireLogPath), wire);
            assert.deepEqual(fs.readFileSync(ledgerPath), ledger);
            assert.deepEqual(fs.readFileSync(indexPath), index);
        });
    }
});

test('a completion-only request contributes exact measured sizes before and after reopen', async (t) => {
    const { recorder, create, ledgerPath } = fixture(t, { recordWireLog: false });
    const context = new EventEmitter();
    recorder.attachContext(context);
    const request = {
        url: () => 'https://example.test/in-flight',
        sizes: async () => ({
            requestHeadersSize: 80,
            requestBodySize: 0,
            responseHeadersSize: 100,
            responseBodySize: 200
        })
    };
    context.emit('requestfinished', request);
    context.emit('requestfinished', request);
    const live = await recorder.stop();
    assert.deepEqual(readEvents(ledgerPath).map(({ type }) => type), ['request-finished']);
    assert.equal(live.totals.totalRequests, 0);
    assert.equal(live.totals.totalResponses, 0);
    assert.equal(live.totals.totalEgressBytes, 80);
    assert.equal(live.totals.totalIngressBytes, 300);
    const recovered = await create().stop();
    assert.deepEqual(recovered.totals, live.totals);
    assert.deepEqual(recovered.byDomain, live.byDomain);
    assert.deepEqual(recovered.byActionStep, live.byActionStep);
});

test('redirected requests retain the originating action after the first request completes', async (t) => {
    const { recorder, ledgerPath } = fixture(t, { recordWireLog: false });
    const context = new EventEmitter();
    const frame = { url: () => 'https://example.test/' };
    recorder.attachContext(context);
    const request = (pathname) => ({
        method: () => 'GET', url: () => 'https://example.test/' + pathname, frame: () => frame
    });
    const record = (req, status) => {
        context.emit('request', req);
        context.emit('response', { request: () => req, url: req.url, status: () => status });
        context.emit('requestfinished', req);
    };

    recorder.setStep('origin step');
    const initialAction = recorder.recordTriggerAction('page.click', '#initial', {}, frame);
    const initialRequest = request('initial');
    record(initialRequest, 302);
    await recorder.flushSummary();
    assert.equal(recorder.transactions.size, 0);

    recorder.setStep('other step');
    const otherAction = recorder.recordTriggerAction('page.click', '#other', {}, frame);
    const redirected = request('redirected');
    redirected.redirectedFrom = () => initialRequest;
    record(redirected, 200);
    record(request('unrelated'), 204);
    await recorder.stop();

    const egress = new Map(readEvents(ledgerPath).filter(event => event.type === 'egress').map(event => [event.url, event]));
    const parent = egress.get(initialRequest.url());
    const child = egress.get(redirected.url());
    const other = egress.get('https://example.test/unrelated');
    assert.equal(child.redirectedFromCorrelationId, parent.correlationId);
    assert.equal(child.triggerAction.actionId, initialAction.actionId);
    assert.equal(child.attribution.actionStep, 'origin step');
    assert.equal(other.triggerAction.actionId, otherAction.actionId);
    assert.equal(other.attribution.actionStep, 'other step');
});

test('closing a page releases its open socket listeners while other pages keep recording', async (t) => {
    const { recorder } = fixture(t, { recordWireLog: false });
    const closedPage = new EventEmitter();
    const activePage = new EventEmitter();
    const makeSocket = name => Object.assign(new EventEmitter(), { url: () => 'wss://example.test/' + name });
    const closedSocket = makeSocket('closed-page');
    const activeSocket = makeSocket('active-page');
    recorder.attachPage(closedPage);
    recorder.attachPage(activePage);
    closedPage.emit('websocket', closedSocket);
    activePage.emit('websocket', activeSocket);

    closedPage.emit('close');
    for (const event of ['framesent', 'framereceived', 'socketerror', 'close']) {
        assert.equal(closedSocket.listenerCount(event), 0);
        assert.equal(activeSocket.listenerCount(event), 1);
    }
    activeSocket.emit('framesent', { payload: 'fixture' });
    activeSocket.emit('close');
    assert.equal(recorder.webSocketDisposers.size, 0);
    assert.equal((await recorder.stop()).totals.wsFramesSent, 1);
});

test('reset removes the previous session’s verified custom wire log', async (t) => {
    const { trafficDir, recorder, create } = fixture(t, { recordWireLog: false });
    await recorder.stop();
    const wirePath = path.join(trafficDir, 'previous wire.log');
    const previous = create({ recordWireLog: true, preTlsWireLogPath: wirePath });
    previous.recordSecurityBlock({ type: 'fixture', url: 'https://example.test/previous' });
    const oldIndex = await previous.stop();
    assert.equal(oldIndex.integrity.preTlsWireLogFile, path.basename(wirePath));
    assert.ok(fs.statSync(wirePath).size > 0);

    const unrelatedPath = path.join(trafficDir, 'unrelated.log');
    fs.writeFileSync(unrelatedPath, 'unrelated fixture\n');
    const current = create({ resetTrafficOnStart: true });
    const summary = await current.stop();
    assert.equal(fs.existsSync(wirePath), false);
    assert.equal(fs.readFileSync(unrelatedPath, 'utf8'), 'unrelated fixture\n');
    assert.equal(summary.integrity.eventCount, 0);
    assert.equal(summary.captureLimits.bytes, 0);
    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
});

test('reset refuses an indexed custom wire whose bytes now differ', async (t) => {
    const { trafficDir, recorder, create, ledgerPath, indexPath } = fixture(t, { recordWireLog: false });
    await recorder.stop();
    const wirePath = path.join(trafficDir, 'previous wire.log');
    const previous = create({ recordWireLog: true, preTlsWireLogPath: wirePath });
    previous.recordSecurityBlock({ type: 'fixture', url: 'https://example.test/previous' });
    await previous.stop();
    const ledger = fs.readFileSync(ledgerPath);
    const index = fs.readFileSync(indexPath);
    const changed = fs.readFileSync(wirePath);
    changed[0] ^= 1;
    fs.writeFileSync(wirePath, changed);

    assert.throws(() => create({ resetTrafficOnStart: true }), /SHA-256 mismatch/);
    assert.deepEqual(fs.readFileSync(wirePath), changed);
    assert.deepEqual(fs.readFileSync(ledgerPath), ledger);
    assert.deepEqual(fs.readFileSync(indexPath), index);
});

test('stopped recorder launch environments cannot restore retired log files', async (t) => {
    const { recorder, create } = fixture(t, { neckoMozLog: true });
    const inherited = { PATH: '/synthetic/runtime', MOZ_LOG: 'nsHttp:5' };
    assert.equal(recorder.getLaunchEnv(inherited).MOZ_LOG_FILE, recorder.neckoMozLogPath);
    await recorder.stop();
    fs.unlinkSync(recorder.neckoMozLogPath);
    const current = create({ resetTrafficOnStart: true, neckoMozLog: false, recordWireLog: false });
    assert.equal(current.getLaunchEnv(inherited).MOZ_LOG_FILE, '');
    assert.equal(fs.existsSync(recorder.preTlsWireLogPath), false);

    const retired = recorder.getLaunchEnv(inherited);
    assert.equal(retired.PATH, inherited.PATH);
    assert.equal(retired.MOZ_LOG_FILE, '');
    assert.equal(retired.MOZ_LOG, '');
    assert.equal(retired.SSLKEYLOGFILE, '');
    assert.equal(fs.existsSync(recorder.neckoMozLogPath), false);
    assert.equal(fs.existsSync(recorder.preTlsWireLogPath), false);
    await current.stop();
});
