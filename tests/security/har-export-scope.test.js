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
