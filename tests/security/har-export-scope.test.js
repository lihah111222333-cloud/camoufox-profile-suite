import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { formatCliReport, queryProfileTraffic } from '../../scripts/query-traffic-attribution.js';
import { CamoufoxTrafficRecorder, exportTrafficToHar } from '../../src/camoufox/traffic-recorder.js';

const cliPath = fileURLToPath(new URL('../../scripts/query-traffic-attribution.js', import.meta.url));
const supported = process.platform === 'darwin' || process.platform === 'linux';

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'har-policy-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const trafficDir = path.join(root, 'fixture', 'traffic');
    const payloadsDir = path.join(trafficDir, 'payloads');
    fs.mkdirSync(payloadsDir, { recursive: true });
    return {
        root,
        trafficDir,
        ledgerPath: path.join(trafficDir, 'traffic.ndjson'),
        indexPath: path.join(trafficDir, 'attribution-index.json'),
        outputPath: path.join(root, 'export.har'),
        payloadsDir
    };
}

function writeLedger(file, events) {
    fs.writeFileSync(file, events.map((event) => JSON.stringify(event)).join('\n') + '\n');
}

function transaction(correlationId, { host = 'selected.example', actionStep = 'show', status = 409, target = '#show' } = {}) {
    const common = {
        correlationId,
        url: 'https://' + host + '/notes',
        attribution: { actionStep, traceId: 'fixture-trace' },
        triggerAction: { actionType: 'click', target }
    };
    return [{ ...common, type: 'egress', method: 'POST' }, { ...common, type: 'ingress', status }];
}

test('HAR CLI filters transactions before assembling pages and rejects unsupported combinations', { skip: !supported }, (t) => {
    const { root, ledgerPath, outputPath } = fixture(t);
    writeLedger(ledgerPath, [
        { type: 'step-transition', actionStep: 'other-page' },
        ...transaction('included'),
        ...transaction('wrong-domain', { host: 'unrelated.example' }),
        ...transaction('wrong-status', { status: 200 }),
        ...transaction('wrong-step', { actionStep: 'other-step' }),
        ...transaction('wrong-trigger', { target: '#other' })
    ]);
    const command = [cliPath, '--profiles-dir=' + root, '--profile=fixture', '--export-har=' + outputPath];
    const run = (...args) => spawnSync(process.execPath, [...command, ...args], { encoding: 'utf8' });

    for (const args of [['--platform=example'], ['--verify-integrity'], ['--domain=']]) {
        const rejected = run(...args);
        assert.notEqual(rejected.status, 0);
        assert.match(rejected.stderr, /HAR export/);
        assert.equal(fs.existsSync(outputPath), false);
    }

    const selected = run('--domain=selected.example', '--step=show', '--status=4xx', '--trigger=#show', '--json');
    assert.equal(selected.status, 0, selected.stderr);
    const result = JSON.parse(selected.stdout);
    const contents = fs.readFileSync(outputPath, 'utf8');
    const { log } = JSON.parse(contents);
    assert.equal(result.entryCount, 1);
    assert.equal(result.bytes, Buffer.byteLength(contents));
    assert.deepEqual(log.entries.map((entry) => entry._attribution.correlationId), ['included']);
    assert.equal(log.entries[0].response.status, 409);
    assert.deepEqual(log.pages.map((page) => page.title), ['show (step 0)']);
    assert.doesNotMatch(contents, /unrelated\.example|other-page|other-step|wrong-/);

    const invalidScopes = [
        [['--domian=selected.example'], /Unknown option --domian/],
        [['--since', '2024-01-01'], /Unknown option --since/],
        [['unexpected'], /Unexpected positional argument/]
    ];
    for (const [args, expected] of invalidScopes) {
        const rejected = run(...args);
        assert.equal(rejected.status, 1);
        assert.match(rejected.stderr, expected);
        assert.equal(rejected.stdout, '');
        assert.equal(fs.readFileSync(outputPath, 'utf8'), contents);
    }
});

test('HAR CLI selects a capture automatically only when it is unique', { skip: !supported }, (t) => {
    const { root, ledgerPath, outputPath } = fixture(t);
    writeLedger(ledgerPath, transaction('first'));
    const args = [cliPath, '--profiles-dir=' + root, '--export-har=' + outputPath, '--json'];
    const run = (...flags) => spawnSync(process.execPath, [...args, ...flags], { encoding: 'utf8' });

    const automatic = run();
    assert.equal(automatic.status, 0, automatic.stderr);
    assert.equal(JSON.parse(automatic.stdout).profileId, 'fixture');
    const original = fs.readFileSync(outputPath);

    const second = path.join(root, 'fixture-other', 'traffic');
    fs.mkdirSync(second, { recursive: true });
    writeLedger(path.join(second, 'traffic.ndjson'), transaction('second'));
    const ambiguous = run();
    assert.equal(ambiguous.status, 1);
    assert.match(ambiguous.stderr, /Multiple traffic captures.*--profile/);
    assert.deepEqual(fs.readFileSync(outputPath), original);

    const explicit = run('--profile=fixture-other');
    assert.equal(explicit.status, 0, explicit.stderr);
    const entries = JSON.parse(fs.readFileSync(outputPath, 'utf8')).log.entries;
    assert.deepEqual(entries.map((entry) => entry._attribution.correlationId), ['second']);
});

test('missing, malformed and unspecified index policy retain metadata and omit bodies', { skip: !supported }, (t) => {
    const { trafficDir, ledgerPath, indexPath, outputPath, payloadsDir } = fixture(t);
    const [egress, ingress] = transaction('policy-fixture');
    const stored = JSON.stringify({ count: 2030405, success: true });
    const payloadFile = 'payloads/note.json';
    fs.writeFileSync(path.join(payloadsDir, 'note.json'), stored);
    writeLedger(ledgerPath, [
        { ...egress, recordBodies: true, payloadFile, headers: { 'content-type': 'application/json' } },
        { ...ingress, recordBodies: true, bodyPreview: '{"message":"sample-withheld-reply"}', mimeType: 'application/json' }
    ]);

    for (const [reason, index] of [
        ['missing-index', null],
        ['invalid-index', '{"session":'],
        ['missing-session-policy', '{"session":{"recordBodies":"true"}}'],
        ['capture-disabled', '{"session":{"recordBodies":false}}']
    ]) {
        if (index !== null) fs.writeFileSync(indexPath, index);
        const archive = exportTrafficToHar(trafficDir, outputPath, {}, { recordBodies: true });
        const wire = queryProfileTraffic({ trafficDir, correlation: 'policy-fixture', recordBodies: true });
        assert.deepEqual(archive.log._bodyPolicy, { recordBodies: false, reason });
        assert.equal(archive.entryCount, 1);
        assert.equal(wire.found, true);
        assert.equal(wire.bodyPolicyReason, reason);
        assert.match(formatCliReport(wire), new RegExp(reason));
        assert.equal(wire.requestPayloadFile, null);
        assert.equal(wire.requestPayload, null);
        assert.equal(wire.responsePayload, null);
        assert.doesNotMatch(JSON.stringify({ archive, wire }), /2030405|sample-withheld-/);
    }

    fs.writeFileSync(indexPath, '{"session":{"recordBodies":true,"traceId":"another-session"}}');
    const olderArchive = exportTrafficToHar(trafficDir, outputPath);
    const olderWire = queryProfileTraffic({ trafficDir, correlation: 'policy-fixture' });
    assert.doesNotMatch(JSON.stringify({ olderArchive, olderWire }), /2030405|sample-withheld-/);

    fs.writeFileSync(indexPath, '{"session":{"recordBodies":true,"traceId":"fixture-trace"}}');
    const permitted = exportTrafficToHar(trafficDir, outputPath);
    assert.equal(permitted.log.entries[0].request.postData.text, stored);
    assert.equal(queryProfileTraffic({ trafficDir, correlation: 'policy-fixture' }).requestPayload, stored);
});

test('shared event and wire reports omit private body digests for withheld requests, responses and frames', { skip: !supported }, (t) => {
    const { trafficDir, ledgerPath, indexPath } = fixture(t);
    const [request, response] = transaction('digest-fixture');
    const digests = ['request', 'response', 'frame', 'chained-event', 'body-signature'].map((value) =>
        createHash('sha256').update(value).digest('hex'));
    const signature = {
        correlationId: 'digest-fixture', platform: 'example', signatureName: 'fixture-field',
        location: 'body', valueSha256: digests[4]
    };
    writeLedger(ledgerPath, [
        {
            ...request, recordBodies: true, postDataSha256: digests[0], eventHash: digests[3],
            platformSignatures: [signature],
            payloadStorage: { status: 'stored', sha256: digests[0], bytes: 9 }
        },
        { ...response, recordBodies: true, bodySha256: digests[1], prevEventHash: digests[3] },
        { ...request, type: 'ws-egress', recordBodies: true, payloadSha256: digests[2] }
    ]);
    fs.writeFileSync(indexPath, '{"session":{"recordBodies":false}}');

    const reports = [
        queryProfileTraffic({ trafficDir }),
        queryProfileTraffic({ trafficDir, correlation: 'digest-fixture' }),
        queryProfileTraffic({ trafficDir, signatures: true })
    ];
    const serialized = JSON.stringify(reports);
    assert.deepEqual(reports[0].events[0].payloadStorage, { status: 'stored', bytes: 9 });
    assert.deepEqual(reports[1].egress.payloadStorage, { status: 'stored', bytes: 9 });
    for (const digest of digests) {
        assert.equal(serialized.includes(digest), false);
        assert.equal(fs.readFileSync(ledgerPath, 'utf8').includes(digest), true);
    }
});

test('wire reports hide content-derived attachment names when a body is shareable', { skip: !supported }, (t) => {
    const { trafficDir, ledgerPath, indexPath, payloadsDir } = fixture(t);
    const [egress, ingress] = transaction('permitted-fixture');
    const body = '{"count":12,"message":"local fixture detail"}';
    const sha256 = createHash('sha256').update(body).digest('hex');
    const name = `req-1-${sha256.slice(0, 12)}.json`;
    const payloadFile = 'payloads/' + name;
    fs.writeFileSync(path.join(payloadsDir, name), body);
    writeLedger(ledgerPath, [{
        ...egress, recordBodies: true, payloadFile, headers: { 'content-type': 'application/json' },
        payloadStorage: { status: 'stored', sha256, bytes: Buffer.byteLength(body) }
    }, ingress]);
    fs.writeFileSync(indexPath, '{"session":{"recordBodies":true,"traceId":"fixture-trace"}}');

    const report = queryProfileTraffic({ trafficDir, correlationId: 'permitted-fixture' });
    assert.equal(report.requestPayload, '{"count":12}');
    assert.equal(report.requestPayloadExistsOnDisk, true);
    assert.equal(report.requestPayloadFile, null);
    assert.equal(report.egress.payloadFile, null);
    assert.equal(JSON.stringify(report).includes(sha256.slice(0, 12)), false);
    assert.equal(fs.readFileSync(path.join(payloadsDir, name), 'utf8'), body);
});

test('context HAR cuts off earlier sessions even if the same trace ID is reused', async (t) => {
    const { trafficDir, outputPath } = fixture(t);
    const options = {
        trafficDir,
        harPath: outputPath,
        traceId: 'fixture-trace',
        recordWireLog: false,
        recordBodies: false,
        sslKeyLog: false,
        trustedLocal: true
    };
    const record = async (step, url) => {
        const recorder = new CamoufoxTrafficRecorder(options);
        const context = new EventEmitter();
        await recorder.attachContext(context);
        recorder.setStep(step);
        context.emit('request', { method: () => 'GET', url: () => url, headers: () => ({}) });
        await recorder.stop();
        return recorder;
    };
    const previous = await record('previous-step', 'https://previous.example/notes');
    const current = await record('current-step', 'https://current.example/notes');
    assert.deepEqual(previous.buildHarArchive().log.entries.map((entry) => entry.request.url), [
        'https://previous.example/notes'
    ]);

    const currentArchive = current.buildHarArchive();
    assert.deepEqual(currentArchive.log.entries.map((entry) => entry.request.url), ['https://current.example/notes']);
    assert.doesNotMatch(JSON.stringify(currentArchive), /previous-(step|session)|previous\.example/);
    const written = current.exportHar();
    assert.deepEqual(JSON.parse(fs.readFileSync(outputPath)).log, written.log);
    assert.deepEqual(written.log.entries.map((entry) => entry.request.url), ['https://current.example/notes']);

    const full = exportTrafficToHar(trafficDir, outputPath, {}, { trustedLocal: true });
    assert.deepEqual(full.log.entries.map((entry) => entry.request.url), [
        'https://previous.example/notes', 'https://current.example/notes'
    ]);
});

test('HAR entry limit preserves an existing archive on failure', { skip: !supported }, (t) => {
    const { trafficDir, ledgerPath, outputPath } = fixture(t);
    writeLedger(ledgerPath, Array.from({ length: 10_001 }, (_, index) => transaction('entry-' + index)[0]));
    fs.writeFileSync(outputPath, 'previous archive');
    assert.throws(() => exportTrafficToHar(trafficDir, outputPath), {
        code: 'ERR_HAR_LIMIT', message: /transaction count/
    });
    assert.equal(fs.readFileSync(outputPath, 'utf8'), 'previous archive');
});

test('aggregate HAR attachment reads respect the body byte limit', { skip: !supported }, (t) => {
    const { trafficDir, ledgerPath, indexPath, outputPath, payloadsDir } = fixture(t);
    const body = JSON.stringify({ count: 2 });
    fs.writeFileSync(path.join(payloadsDir, 'note.json'), body + ' '.repeat(4 * 1024 * 1024));
    fs.writeFileSync(indexPath, '{"session":{"recordBodies":true,"traceId":"fixture-trace"}}');
    const sample = {
        payloadFile: 'payloads/note.json',
        recordBodies: true,
        headers: { 'content-type': 'application/json' }
    };
    const entries = Array.from({ length: 9 }, (_, index) => ({ ...transaction('body-' + index)[0], ...sample }));
    writeLedger(ledgerPath, entries.slice(0, 1));
    const smallArchive = exportTrafficToHar(trafficDir, outputPath);
    assert.deepEqual(JSON.parse(smallArchive.log.entries[0].request.postData.text), { count: 2 });
    const originalSize = fs.statSync(outputPath).size;

    writeLedger(ledgerPath, entries);
    assert.throws(() => exportTrafficToHar(trafficDir, outputPath), {
        code: 'ERR_HAR_LIMIT', message: /byte/
    });
    assert.equal(fs.statSync(outputPath).size, originalSize);
});

test('HAR charges repeated URL query values to the serialized byte limit', { skip: !supported }, (t) => {
    const { trafficDir, ledgerPath, outputPath } = fixture(t);
    const url = 'https://selected.example/notes?view=' + 'a'.repeat(32 * 1024);
    writeLedger(ledgerPath, Array.from({ length: 520 }, (_, index) => ({
        type: 'egress', correlationId: 'entry-' + index, url
    })));
    assert.throws(() => exportTrafficToHar(trafficDir, outputPath), {
        code: 'ERR_HAR_LIMIT', message: /serialized byte/
    });
    assert.equal(fs.existsSync(outputPath), false);
});


test('HAR verifies the indexed ledger before replacing a prior archive', { skip: !supported }, async (t) => {
    const { trafficDir, ledgerPath, indexPath, outputPath } = fixture(t);
    const recorder = new CamoufoxTrafficRecorder({
        trafficDir, trustedLocal: true, recordWireLog: false
    });
    const context = new EventEmitter();
    recorder.attachContext(context);
    await recorder.flushSummary();
    const initialIndex = fs.readFileSync(indexPath);
    for (const suffix of ['first', 'second']) {
        context.emit('request', { method: () => 'GET', url: () => 'https://fixture.example/' + suffix });
    }
    await recorder.stop();
    const completedIndex = fs.readFileSync(indexPath);
    const completedLedger = fs.readFileSync(ledgerPath, 'utf8');

    fs.writeFileSync(indexPath, initialIndex);
    fs.writeFileSync(ledgerPath, completedLedger + '{"type":');
    const recovered = exportTrafficToHar(trafficDir, outputPath);
    assert.equal(recovered.entryCount, 2);
    const previous = fs.readFileSync(outputPath);

    fs.writeFileSync(indexPath, completedIndex);
    fs.writeFileSync(ledgerPath, completedLedger.split('\n', 1)[0] + '\n');
    assert.throws(() => exportTrafficToHar(trafficDir, outputPath), {
        code: 'ERR_CAPTURE_INTEGRITY', message: /event count mismatch/i
    });
    assert.deepEqual(fs.readFileSync(outputPath), previous);

    fs.unlinkSync(ledgerPath);
    assert.throws(() => exportTrafficToHar(trafficDir, outputPath), { code: 'ERR_CAPTURE_INTEGRITY' });
    assert.deepEqual(fs.readFileSync(outputPath), previous);
});

test('length-only legacy attachment evidence is checked before HAR and wire projection', { skip: !supported }, (t) => {
    const { trafficDir, ledgerPath, indexPath, payloadsDir, outputPath } = fixture(t);
    const events = transaction('length-only');
    const payloadFile = 'payloads/body.json';
    const attachment = path.join(payloadsDir, 'body.json');
    const body = '{"count":1001}';
    Object.assign(events[0], {
        payloadFile, mimeType: 'application/json', recordBodies: true, postDataBytes: Buffer.byteLength(body)
    });
    fs.writeFileSync(indexPath, JSON.stringify({ session: { recordBodies: true, traceId: 'fixture-trace' } }));
    fs.writeFileSync(attachment, body);
    writeLedger(ledgerPath, events);
    assert.equal(exportTrafficToHar(trafficDir, outputPath).log.entries[0].request.postData.text, body);
    const previous = fs.readFileSync(outputPath);
    fs.writeFileSync(attachment, '{"count":7}');
    assert.throws(() => exportTrafficToHar(trafficDir, outputPath), { code: 'ERR_CAPTURE_INTEGRITY' });
    assert.deepEqual(fs.readFileSync(outputPath), previous);
    const wire = queryProfileTraffic({ trafficDir, correlationId: 'length-only' });
    assert.equal(wire.requestPayload, null);
    assert.equal(wire.requestPayloadOmittedReason, 'payload-integrity');

    fs.unlinkSync(attachment);
    assert.throws(() => exportTrafficToHar(trafficDir, outputPath), { code: 'ERR_CAPTURE_INTEGRITY' });
    assert.deepEqual(fs.readFileSync(outputPath), previous);
});

test('HAR separates identical steps across traces and reports a selected trace that reached its limit', {
    skip: !supported
}, async (t) => {
    const { trafficDir, outputPath } = fixture(t);
    const record = async (traceId, host) => {
        const recorder = new CamoufoxTrafficRecorder({
            trafficDir, traceId, trustedLocal: true, recordWireLog: false, maxCaptureEvents: 2
        });
        const context = new EventEmitter();
        recorder.attachContext(context);
        const request = { method: () => 'GET', url: () => 'https://' + host + '/notes' };
        context.emit('request', request);
        await recorder.flushSummary();
        if (traceId === 'later-trace') {
            context.emit('response', { request: () => request, url: request.url, status: () => 200 });
        }
        await recorder.stop();
        return recorder;
    };
    await record('earlier-trace', 'earlier.example');
    const later = await record('later-trace', 'later.example');
    const { log } = exportTrafficToHar(trafficDir, outputPath);
    assert.equal(log.entries.length, 2);
    assert.equal(log.pages.length, 2);
    assert.notEqual(log.entries[0].pageref, log.entries[1].pageref);
    for (const entry of log.entries) {
        assert.equal(log.pages.find((page) => page.id === entry.pageref).startedDateTime, entry.startedDateTime);
    }
    const limit = { stoppedReason: 'event-limit' };
    assert.deepEqual(log._captureLimits, limit);
    assert.deepEqual(later.buildHarArchive().log._captureLimits, limit);

    const filtered = (domain) => queryProfileTraffic({ trafficDir, domain, exportHar: outputPath }).log;
    assert.equal(filtered('earlier.example')._captureLimits, undefined);
    assert.deepEqual(filtered('later.example')._captureLimits, limit);
});

test('HAR represents measured zeros, unknown or compressed sizes, and observed receive time', {
    skip: !supported
}, async (t) => {
    const { trafficDir, outputPath } = fixture(t);
    const recorder = new CamoufoxTrafficRecorder({ trafficDir, trustedLocal: true, recordWireLog: false });
    const context = new EventEmitter();
    recorder.attachContext(context);
    const send = (suffix, status, headers, sizes, timing) => {
        const request = {
            method: () => 'POST', url: () => 'https://fixture.example/' + suffix,
            sizes: () => sizes, timing: () => timing
        };
        context.emit('request', request);
        context.emit('response', { request: () => request, url: request.url, status: () => status, headers: () => headers });
        context.emit('requestfinished', request);
    };
    send('unknown', 200, {});
    send('empty', 204, {}, { requestBodySize: 0, responseBodySize: 0 });
    send('compressed', 200, { 'Content-Encoding': 'gzip' }, { requestBodySize: 0, responseBodySize: 37 },
        { requestStart: 1, responseStart: 8, responseEnd: 13 });
    await recorder.stop();

    const { entries } = exportTrafficToHar(trafficDir, outputPath).log;
    const sizes = (entry) => [entry.request.bodySize, entry.response.bodySize, entry.response.content.size];
    assert.deepEqual(sizes(entries[0]), [-1, -1, -1]);
    assert.deepEqual(entries[0].timings._unmeasured, ['send', 'wait', 'receive']);
    assert.deepEqual(sizes(entries[1]), [0, 0, 0]);
    assert.deepEqual(sizes(entries[2]), [0, 37, -1]);
    assert.deepEqual([entries[2].time, entries[2].timings.wait, entries[2].timings.receive], [12, 7, 5]);
    assert.deepEqual(entries[2].timings._unmeasured, ['send']);
});

test('legacy response attribution supplies missing HAR step and trigger before filtering', { skip: !supported }, (t) => {
    const { trafficDir, ledgerPath, outputPath } = fixture(t);
    const [egress, ingress] = transaction('legacy-attribution', { status: 200 });
    egress.attribution = { traceId: 'fixture-trace' };
    egress.triggerAction = null;
    ingress.attribution = {
        traceId: 'fixture-trace', actionStep: 'observed-step', stepIndex: 4,
        triggerAction: { actionType: 'click', target: '#observed' }
    };
    ingress.triggerAction = null;
    writeLedger(ledgerPath, [egress, ingress]);
    const selected = queryProfileTraffic({ trafficDir, step: 'observed-step', trigger: '#observed', exportHar: outputPath });
    assert.equal(selected.entryCount, 1);
    const { _attribution: attribution, response } = selected.log.entries[0];
    assert.equal(response.status, 200);
    assert.equal(attribution.actionStep, 'observed-step');
    assert.equal(attribution.stepIndex, 4);
    assert.equal(attribution.triggerAction.target, '#observed');
    const full = queryProfileTraffic({ trafficDir, exportHar: outputPath });
    assert.deepEqual(full.log.entries[0]._attribution, attribution);
});


test('HAR checks retained hash-chain evidence even when an index is absent', { skip: !supported }, async (t) => {
    const { trafficDir, ledgerPath, indexPath, outputPath } = fixture(t);
    const recorder = new CamoufoxTrafficRecorder({ trafficDir, trustedLocal: true, recordWireLog: false });
    const context = new EventEmitter();
    recorder.attachContext(context);
    for (const suffix of ['first', 'second']) {
        context.emit('request', { method: () => 'GET', url: () => 'https://fixture.example/' + suffix });
    }
    await recorder.stop();
    const ledger = fs.readFileSync(ledgerPath, 'utf8').trimEnd().split('\n');
    fs.unlinkSync(indexPath);
    assert.equal(exportTrafficToHar(trafficDir, outputPath).entryCount, 2);
    const previous = fs.readFileSync(outputPath);

    fs.writeFileSync(ledgerPath, ledger[1] + '\n');
    assert.throws(() => exportTrafficToHar(trafficDir, outputPath), { code: 'ERR_CAPTURE_INTEGRITY' });
    assert.deepEqual(fs.readFileSync(outputPath), previous);

    writeLedger(ledgerPath, transaction('legacy-without-chain'));
    assert.equal(exportTrafficToHar(trafficDir, outputPath).entryCount, 1);
});

test('missing HAR correlation preserves the existing target for both scoped entry points', { skip: !supported }, (t) => {
    const { root, trafficDir, ledgerPath, outputPath } = fixture(t);
    writeLedger(ledgerPath, transaction('selected'));
    const command = [cliPath, '--profiles-dir=' + root, '--export-har=' + outputPath, '--json'];
    const run = (...args) => spawnSync(process.execPath, [...command, ...args], { encoding: 'utf8' });
    const selected = run('--profile=fixture', '--correlation=selected');
    assert.equal(selected.status, 0, selected.stderr);
    assert.equal(JSON.parse(selected.stdout).entryCount, 1);
    const previous = fs.readFileSync(outputPath);

    for (const scope of [[], ['--profile=fixture']]) {
        const missing = run(...scope, '--correlation=missing');
        assert.equal(missing.status, 1, missing.stderr);
        assert.match(missing.stderr, /Correlation ID .*not found/);
        assert.deepEqual(fs.readFileSync(outputPath), previous);
    }
    assert.throws(() => queryProfileTraffic({
        trafficDir, correlationId: 'missing', exportHar: outputPath
    }), { code: 'ERR_HAR_CORRELATION_NOT_FOUND' });
    assert.deepEqual(fs.readFileSync(outputPath), previous);

    const empty = run('--profile=fixture', '--status=2xx');
    assert.equal(empty.status, 0, empty.stderr);
    assert.equal(JSON.parse(empty.stdout).entryCount, 0);
});
