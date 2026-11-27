import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { readCaptureFile, readCapturePayload } from '../../src/camoufox/capture-io.js';
import { CamoufoxTrafficRecorder, exportTrafficToHar } from '../../src/camoufox/traffic-recorder.js';
import { queryProfileTraffic } from '../../scripts/query-traffic-attribution.js';

const cliPath = fileURLToPath(new URL('../../scripts/query-traffic-attribution.js', import.meta.url));
const supported = process.platform === 'darwin' || process.platform === 'linux';

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'capture-exports-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const profilesDir = path.join(root, 'received');
    const trafficDir = path.join(profilesDir, 'fixture', 'traffic');
    const operatorDir = path.join(root, 'operator');
    const payloadsDir = path.join(trafficDir, 'payloads');
    fs.mkdirSync(payloadsDir, { recursive: true });
    fs.mkdirSync(operatorDir);
    return { profilesDir, trafficDir, operatorDir, payloadsDir };
}

function writeEvents(directory, events) {
    fs.writeFileSync(path.join(directory, 'traffic.ndjson'), `${events.map((event) => JSON.stringify(event)).join('\n')}\n`);
}

function transaction(request = {}, response = {}) {
    const meta = { correlationId: 'transaction-1', url: 'https://fixture.example/v1/items?view=compact' };
    return [
        { ...meta, type: 'egress', method: 'POST', ...request },
        { ...meta, type: 'ingress', status: 200, ...response }
    ];
}

test('in-tree files survive HAR and wire export with credential fields filtered', { skip: !supported }, (t) => {
    const { trafficDir, payloadsDir, operatorDir } = fixture(t);
    fs.mkdirSync(path.join(payloadsDir, 'nested'));
    const responseFile = 'res-2-a123456789ab.json';
    fs.writeFileSync(path.join(payloadsDir, 'nested', 'request.json'), '{"count":2,"message":"legacy-body-value"}');
    fs.writeFileSync(path.join(payloadsDir, responseFile), '{"success":true,"password":"legacy-body-value"}');
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({ session: { recordBodies: true } }));
    writeEvents(trafficDir, transaction({
        payloadFile: 'payloads/nested/request.json',
        recordBodies: true,
        pathname: '/v1/items',
        searchParams: { view: 'compact' },
        headersArray: [
            { name: 'Content-Type', value: 'application/json' },
            { name: 'Cookie', value: 'session=legacy-cookie-value' },
            { name: 'Authorization', value: 'Bearer legacy-auth-value' },
            { name: 'Referer', value: 'https://fixture.example/start?access_token=legacy-referrer-value' }
        ],
        attribution: { proxyServer: 'http://person:legacy-proxy-value@fixture.example:8080' }
    }, {
        payloadFile: 'payloads/' + responseFile,
        recordBodies: true,
        headers: {
            'Set-Cookie': 'session=legacy-set-cookie; HttpOnly',
            'Content-Type': 'application/json',
            Location: '/v1/next?token=legacy-location-value'
        }
    }));

    const wire = queryProfileTraffic({ trafficDir, correlationId: 'transaction-1' });
    assert.equal(wire.requestPayload, '{"count":2}');
    assert.equal(wire.responsePayload, '{"success":true}');
    assert.equal(wire.requestPayloadExistsOnDisk, true);
    assert.equal(wire.responsePayloadExistsOnDisk, true);
    assert.equal(wire.responsePayloadFile, null);
    assert.match(wire.wireDump, /Cookie: \[REDACTED\]/);

    const outputPath = path.join(operatorDir, 'selected.har');
    const har = exportTrafficToHar(trafficDir, outputPath);
    const entry = har.log.entries[0];
    assert.equal(entry.request.postData.text, wire.requestPayload);
    assert.equal(entry.request.bodySize, fs.statSync(path.join(payloadsDir, 'nested', 'request.json')).size);
    assert.equal(entry.response.content.text, wire.responsePayload);
    assert.equal(entry.request.queryString[0].value, 'compact');
    assert.equal(entry.response.redirectURL, '/v1/next?token=[REDACTED]');
    assert.equal(entry._attribution.requestPayloadFile, 'payloads/nested/request.json');
    assert.equal(entry._attribution.responsePayloadFile, null);
    assert.doesNotMatch(JSON.stringify(wire), /a123456789ab/);
    assert.doesNotMatch(fs.readFileSync(outputPath, 'utf8'), /a123456789ab/);
    assert.doesNotMatch(JSON.stringify(wire), /legacy-(body|cookie|auth|referrer|proxy|set-cookie|location)/);
    assert.doesNotMatch(fs.readFileSync(outputPath, 'utf8'), /legacy-(body|cookie|auth|referrer|proxy|set-cookie|location)/);
});

test('capture reads reject linked paths, directories and oversize attachments', { skip: !supported }, (t) => {
    const { trafficDir, payloadsDir, operatorDir } = fixture(t);
    const fixturePath = path.join(payloadsDir, 'document.txt');
    fs.writeFileSync(fixturePath, '{"count":7}');
    fs.symlinkSync('document.txt', path.join(payloadsDir, 'alias.txt'));
    fs.mkdirSync(path.join(payloadsDir, 'nested'));
    fs.symlinkSync('nested', path.join(payloadsDir, 'folder-alias'), 'dir');
    fs.writeFileSync(path.join(payloadsDir, 'nested', 'note.txt'), 'ordinary nested note');

    assert.equal(readCapturePayload(trafficDir, 'payloads/document.txt').toString(), '{"count":7}');
    for (const reference of [fixturePath, 'document.txt', 'payloads/../missing.txt', 'payloads//document.txt',
        'payloads\\document.txt', 'payloads/alias.txt', 'payloads/folder-alias/note.txt', 'payloads/nested']) {
        assert.throws(() => readCapturePayload(trafficDir, reference));
    }
    assert.throws(() => readCapturePayload(trafficDir, 'payloads/document.txt', { maxBytes: 1 }), { code: 'ERR_CAPTURE_TOO_LARGE' });
    fs.linkSync(fixturePath, path.join(payloadsDir, 'other-name.txt'));
    assert.throws(() => readCapturePayload(trafficDir, 'payloads/document.txt'), { code: 'ERR_CAPTURE_UNSAFE' });

    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({ session: { recordBodies: true } }));
    const body = { recordBodies: true, mimeType: 'application/json' };
    writeEvents(trafficDir, transaction({
        ...body, payloadFile: 'payloads/alias.txt'
    }, {
        ...body, payloadFile: 'payloads/nested'
    }));
    const wire = queryProfileTraffic({ trafficDir, correlationId: 'transaction-1' });
    assert.equal(wire.requestPayload, null);
    assert.equal(wire.responsePayload, null);
    assert.equal(wire.requestPayloadFile, null);
    assert.equal(wire.responsePayloadFile, null);
    const har = exportTrafficToHar(trafficDir, path.join(operatorDir, 'regular-files-only.har'));
    assert.equal(har.log.entries[0].request.postData.text, '');
    assert.equal(har.log.entries[0].response.content.text, '');
});

test('metadata-only, disabled-body and known authentication transactions omit stored body bytes', { skip: !supported }, (t) => {
    const { trafficDir, payloadsDir, operatorDir } = fixture(t);
    fs.writeFileSync(path.join(payloadsDir, 'body.json'), '{"count":42,"label":"private-attachment-marker"}');
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({ session: { recordBodies: true } }));
    const headers = { 'Content-Type': 'application/json' };
    const payload = { payloadFile: 'payloads/body.json', bodyPreview: '{"count":42}', recordBodies: true, headers };
    writeEvents(trafficDir, transaction(payload, payload));
    const metadataOnly = exportTrafficToHar(trafficDir, path.join(operatorDir, 'metadata.har'), {}, { recordBodies: false });
    assert.equal(metadataOnly.log.entries[0].request.postData.text, '');
    assert.equal(metadataOnly.log.entries[0].response.content.text, '');

    writeEvents(trafficDir, transaction({ postData: '{"count":1}', headers }, {
        bodyPreview: '{"count":2}', headers, recordBodies: true
    }));
    const inline = queryProfileTraffic({ trafficDir, correlationId: 'transaction-1' });
    assert.equal(inline.requestPayload, null);
    assert.equal(inline.responsePayload, '{"count":2}');

    const url = 'https://fixture.example/sign-in?access_token=private-query-marker';
    // A legacy response can have a different URL while still belonging to the authentication transaction.
    writeEvents(trafficDir, transaction({ ...payload, url }, payload));
    const wire = queryProfileTraffic({ trafficDir, correlationId: 'transaction-1' });
    assert.equal(wire.requestPayload, null);
    assert.equal(wire.responsePayload, null);
    const report = queryProfileTraffic({ trafficDir });
    assert.equal(report.transactions[0].egress.bodyPreview, null);
    assert.equal(report.transactions[0].ingress.bodyPreview, null);
    assert.doesNotMatch(JSON.stringify(wire), /private-(attachment|query)-marker/);
    const har = exportTrafficToHar(trafficDir, path.join(operatorDir, 'authentication.har'));
    assert.equal(har.log.entries[0].request.postData.text, '');
    assert.equal(har.log.entries[0].response.content.text, '');
    assert.doesNotMatch(JSON.stringify(har.har), /private-(attachment|query)-marker/);
});

test('HAR and query wire omit unsupported, malformed and truncated legacy bodies', { skip: !supported }, (t) => {
    const { trafficDir, payloadsDir, operatorDir } = fixture(t);
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({ session: { recordBodies: true } }));
    const mimeTypes = {
        json: 'application/json',
        form: 'application/x-www-form-urlencoded',
        multipart: 'multipart/form-data; boundary=fixture',
        binary: 'application/octet-stream'
    };
    const cases = [
        { mimeType: mimeTypes.json, body: '{"count":7,"label":"private-test-marker"' },
        { mimeType: mimeTypes.json, body: '{"count":7}', payloadTruncated: true },
        { mimeType: mimeTypes.json, body: '{"count":7}', bodyPreviewTruncated: true, inlineOnly: true },
        { mimeType: mimeTypes.form, body: 'count=7&label=%invalid' },
        { mimeType: mimeTypes.multipart, body: '--fixture\r\nContent-Disposition: form-data; name="label"\r\n\r\nprivate-test-marker\r\n--fixture--\r\n' },
        { mimeType: mimeTypes.binary, body: 'private-test-marker' },
        { body: '{"count":7,"label":"private-test-marker"}' }
    ];
    const allEvents = [];
    for (const [n, { mimeType, body, inlineOnly, ...flags }] of cases.entries()) {
        const fileName = `legacy-${n}.txt`;
        if (!inlineOnly) fs.writeFileSync(path.join(payloadsDir, fileName), body);
        const data = {
            correlationId: `legacy-${n}`,
            recordBodies: true,
            mimeType,
            bodyPreview: body,
            ...(!inlineOnly && { payloadFile: `payloads/${fileName}` }),
            ...flags
        };
        allEvents.push(...transaction(data, data));
    }
    writeEvents(trafficDir, allEvents);

    const har = exportTrafficToHar(trafficDir, path.join(operatorDir, 'omitted.har'));
    assert.equal(har.log.entries.length, cases.length);
    for (const [n, entry] of har.log.entries.entries()) {
        assert.equal(entry.request.postData?.text ?? '', '');
        assert.equal(entry.response.content.text || '', '');
        assert.equal(entry._attribution.requestPayloadFile, null);
        const wire = queryProfileTraffic({ trafficDir, correlationId: `legacy-${n}` });
        assert.equal(wire.found, true);
        assert.equal(wire.requestPayload, null);
        assert.equal(wire.responsePayload, null);
        assert.equal(wire.egress.bodyPreview, null);
        assert.equal(wire.ingress.bodyPreview, null);
        assert.doesNotMatch(JSON.stringify(wire), /private-test-marker/);
    }
    assert.doesNotMatch(JSON.stringify(har.har), /private-test-marker/);
});

test('profile reports and CLI JSON project legacy event and index fields without changing the archive', { skip: !supported }, (t) => {
    const { profilesDir, trafficDir, payloadsDir, operatorDir } = fixture(t);
    const triggerAction = {
        actionId: 'action-1', type: 'goto', selector: '/continue?token=legacy-marker-selector',
        target: 'https://fixture.example/continue?access_token=legacy-marker-target',
        metadata: {
            password: 'legacy-marker-metadata',
            headersArray: [{ name: 'Authorization', value: 'Bearer legacy-marker-header-array' }]
        }
    };
    const payloadFile = 'payloads/reply.txt';
    fs.writeFileSync(path.join(payloadsDir, 'reply.txt'), 'legacy-marker-attachment');
    writeEvents(trafficDir, transaction({
        triggerAction,
        headers: { Cookie: 'session=legacy-marker-cookie' },
        postData: 'legacy-marker-request-preview'
    }, {
        headers: { 'Set-Cookie': 'session=legacy-marker-set-cookie; HttpOnly' },
        recordBodies: true,
        bodyPreview: 'legacy-marker-response-preview',
        payloadFile
    }));
    const indexPath = path.join(trafficDir, 'attribution-index.json');
    fs.writeFileSync(indexPath, JSON.stringify({
        session: { profileId: 'fixture', recordBodies: false },
        byTriggerAction: { 'action-1': triggerAction },
        anomaliesAndRiskSignals: [{
            correlationId: 'transaction-1', type: 'http-403', severity: 'high',
            triggerAction, url: '/v1/items?password=legacy-marker-anomaly'
        }],
        cookieLineage: { session: {
            name: 'session', lastMaskedValue: 'legacy-marker-fragment',
            valueHistory: [{ maskedValue: 'legacy-marker-history', value: 'legacy-marker-cookie-history' }]
        } },
        neckoMozLog: {
            exists: true,
            parsedRequests: [{ requestLine: 'GET /go?token=legacy-marker-necko HTTP/1.1', headers: {
                cookie: 'session=legacy-marker-native-cookie'
            } }]
        }
    }));
    const ledgerPath = path.join(trafficDir, 'traffic.ndjson');
    const original = [fs.readFileSync(ledgerPath), fs.readFileSync(indexPath)];

    const report = queryProfileTraffic({ trafficDir, trigger: 'legacy-marker-target' });
    assert.equal(report.mode, 'profile-query');
    assert.equal(report.transactions.length, 1);
    assert.equal(report.byTriggerAction['action-1'].metadata.password, '[REDACTED]');
    const cookieScopes = report.cookieLineage.session.instances;
    assert.equal(cookieScopes.find((entry) => entry.scopeStatus === 'set-cookie').lastMaskedValue, '[REDACTED]');
    assert.equal(cookieScopes.find((entry) => entry.scopeStatus === 'unmatched').sentCount, 1);
    // The operator-provided filter is returned for context, independent of projected capture data.
    const { filters, ...selected } = report;
    assert.doesNotMatch(JSON.stringify(selected), /legacy-marker/);

    const command = [cliPath, `--profiles-dir=${profilesDir}`, '--profile=fixture', '--json'];
    for (const extra of [[], ['--anomalies-only'], ['--cookies'], ['--dump-wire=transaction-1']]) {
        const serialized = execFileSync(process.execPath, [...command, ...extra], { cwd: operatorDir, encoding: 'utf8' });
        assert.doesNotMatch(serialized, /legacy-marker/);
        assert.ok(JSON.parse(serialized).mode);
    }
    const har = exportTrafficToHar(trafficDir, path.join(operatorDir, 'legacy-metadata.har'));
    assert.doesNotMatch(JSON.stringify(har.har), /legacy-marker/);
    assert.deepEqual([fs.readFileSync(ledgerPath), fs.readFileSync(indexPath)], original);
});

test('default CLI export is private and exclusive, and an explicit file may be atomically replaced', { skip: !supported }, (t) => {
    const { profilesDir, trafficDir, operatorDir } = fixture(t);
    writeEvents(trafficDir, transaction());
    const command = [cliPath, `--profiles-dir=${profilesDir}`, '--profile=fixture', '--export-har', '--json'];
    const result = JSON.parse(execFileSync(process.execPath, command, { cwd: operatorDir, encoding: 'utf8' }));
    const defaultOutput = path.join(operatorDir, 'traffic.har');
    assert.equal(result.harPath, path.basename(defaultOutput));
    assert.equal(fs.statSync(defaultOutput).mode & 0o777, 0o600);
    assert.equal(fs.existsSync(path.join(trafficDir, 'traffic.har')), false);
    const original = fs.readFileSync(defaultOutput);
    const conflict = spawnSync(process.execPath, command, { cwd: operatorDir, encoding: 'utf8' });
    assert.notEqual(conflict.status, 0);
    assert.match(conflict.stderr, /EEXIST/);
    assert.deepEqual(fs.readFileSync(defaultOutput), original);
    assert.deepEqual(fs.readdirSync(operatorDir), ['traffic.har']);

    const insideCapture = spawnSync(process.execPath, command, { cwd: trafficDir, encoding: 'utf8' });
    assert.notEqual(insideCapture.status, 0);
    assert.match(insideCapture.stderr, /Choose a HAR output path/);
    assert.equal(fs.existsSync(path.join(trafficDir, 'traffic.har')), false);

    const selectedOutput = path.join(operatorDir, 'selected.har');
    fs.writeFileSync(selectedOutput, 'previous archive');
    const previousNode = fs.statSync(selectedOutput).ino;
    const explicit = exportTrafficToHar(trafficDir, selectedOutput);
    assert.equal(explicit.log.entries.length, 1);
    assert.notEqual(fs.statSync(selectedOutput).ino, previousNode);
    assert.equal(fs.statSync(selectedOutput).mode & 0o777, 0o600);

    const aliasPath = path.join(operatorDir, 'alias.har');
    fs.symlinkSync('unused.har', aliasPath);
    assert.throws(() => exportTrafficToHar(trafficDir, aliasPath), { code: 'ERR_CAPTURE_UNSAFE' });
    assert.equal(fs.lstatSync(aliasPath).isSymbolicLink(), true);
    assert.equal(fs.existsSync(path.join(operatorDir, 'unused.har')), false);

    const ordinaryDirectory = path.join(operatorDir, 'ordinary');
    const linkedDirectory = path.join(operatorDir, 'linked');
    fs.mkdirSync(ordinaryDirectory);
    fs.symlinkSync('ordinary', linkedDirectory, 'dir');
    assert.throws(() => exportTrafficToHar(trafficDir, path.join(linkedDirectory, 'new.har')));
    assert.deepEqual(fs.readdirSync(ordinaryDirectory), []);
});

test('explicit HAR destinations preserve reserved source capture storage', { skip: !supported }, (t) => {
    const { trafficDir, payloadsDir } = fixture(t);
    writeEvents(trafficDir, transaction());
    const ledger = path.join(trafficDir, 'traffic.ndjson');
    const index = path.join(trafficDir, 'attribution-index.json');
    const attachment = path.join(payloadsDir, 'retained.json');
    fs.writeFileSync(index, JSON.stringify({ session: { recordBodies: false } }));
    fs.writeFileSync(attachment, '{}');

    const originals = new Map([ledger, index, attachment].map((file) => [file, fs.readFileSync(file)]));
    const caseAlias = path.join(trafficDir, 'Traffic.ndjson');
    if (fs.lstatSync(caseAlias, { throwIfNoEntry: false })?.ino === fs.lstatSync(ledger).ino) {
        assert.throws(() => exportTrafficToHar(trafficDir, caseAlias), { code: 'ERR_CAPTURE_UNSAFE' });
    }
    for (const file of originals.keys()) {
        assert.throws(() => exportTrafficToHar(trafficDir, file), { code: 'ERR_CAPTURE_UNSAFE' });
    }
    const absentParent = path.join(payloadsDir, 'absent');
    assert.throws(() => exportTrafficToHar(trafficDir, path.join(absentParent, 'new.har')), { code: 'ERR_CAPTURE_UNSAFE' });
    assert.equal(fs.existsSync(absentParent), false);
    const aliasDirectory = path.join(trafficDir, 'PAYLOADS');
    const aliasParent = path.join(aliasDirectory, 'absent');
    const aliasOutput = path.join(aliasParent, 'new.har');
    if (fs.existsSync(aliasDirectory)) {
        assert.throws(() => exportTrafficToHar(trafficDir, aliasOutput), { code: 'ERR_CAPTURE_UNSAFE' });
        assert.equal(fs.existsSync(aliasParent), false);
    } else {
        assert.equal(exportTrafficToHar(trafficDir, aliasOutput).entryCount, 1);
    }
    for (const [file, original] of originals) assert.deepEqual(fs.readFileSync(file), original);

    const independentOutput = path.join(trafficDir, 'selected.har');
    assert.equal(exportTrafficToHar(trafficDir, independentOutput).entryCount, 1);
    assert.equal(JSON.parse(fs.readFileSync(independentOutput)).log.entries.length, 1);
});

test('an optional absent ledger is distinguishable from an unsafe archive input', (t) => {
    const { trafficDir, operatorDir } = fixture(t);
    assert.equal(readCaptureFile(trafficDir, 'traffic.ndjson', { optional: true }), null);
    if (supported) assert.equal(exportTrafficToHar(trafficDir, path.join(operatorDir, 'empty.har')).entryCount, 0);
    writeEvents(trafficDir, transaction());
    assert.equal(readCaptureFile(trafficDir, 'traffic.ndjson', {
        trustedLocal: true, maxBytes: 129 * 1024 * 1024
    }).includes('transaction-1'), true);
});

test('HAR regression preserves historical attribution and explicit nulls under filters', { skip: !supported }, (t) => {
    const { trafficDir, operatorDir } = fixture(t);
    const [historyRequest, historyResponse] = transaction({
        attribution: { traceId: 'earlier', accountId: null, proxyServer: null }
    }, { traceId: 'earlier' });
    const [latestRequest, latestResponse] = transaction({
        correlationId: 'latest', attribution: { traceId: 'later', accountId: null, proxyServer: null }
    }, { correlationId: 'latest', traceId: 'later' });
    const [knownRequest, knownResponse] = transaction({ correlationId: 'known', traceId: 'later' }, {
        correlationId: 'known', traceId: 'later'
    });
    const [legacyRequest, legacyResponse] = transaction({ correlationId: 'legacy' }, { correlationId: 'legacy' });
    writeEvents(trafficDir, [historyRequest, historyResponse, latestRequest, latestResponse,
        knownRequest, knownResponse, legacyRequest, legacyResponse]);
    const proxyServer = 'http://proxy.example:8432';
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({
        session: { traceId: 'later', accountId: 37, proxyServer, recordBodies: false }
    }));

    for (const [correlationId, traceId, accountId, proxy] of [
        ['transaction-1', 'earlier', null, null], ['latest', 'later', null, null],
        ['known', 'later', 37, proxyServer], ['legacy', null, null, null]
    ]) {
        const result = queryProfileTraffic({
            trafficDir, correlationId, exportHar: path.join(operatorDir, 'selected.har')
        });
        assert.equal(result.entryCount, 1);
        const attribution = result.log.entries[0]._attribution;
        assert.deepEqual([attribution.traceId, attribution.accountId, attribution.proxyServer], [traceId, accountId, proxy]);
    }
});

test('HAR regression rejects a replaced ledger for an earlier recorder', { skip: !supported }, async (t) => {
    const { trafficDir, operatorDir } = fixture(t);
    const record = async (name, resetTrafficOnStart) => {
        const recorder = new CamoufoxTrafficRecorder({
            trafficDir, traceId: 'fixed-trace', recordWireLog: false, resetTrafficOnStart
        });
        const context = new EventEmitter();
        await recorder.attachContext(context);
        context.emit('request', { method: () => 'GET', url: () => `https://fixture.example/${name}`, headers: () => ({}) });
        await recorder.stop();
        return recorder;
    };
    const earlier = await record('earlier', false);
    const output = path.join(operatorDir, 'earlier.har');
    earlier.exportHar(output);
    const original = fs.readFileSync(output);
    const replacement = await record('replacement', true);
    assert.throws(() => earlier.exportHar(output), /session|ledger/i);
    assert.deepEqual(fs.readFileSync(output), original);
    assert.equal(replacement.buildHarArchive().log.entries[0].request.url, 'https://fixture.example/replacement');
});

test('HAR regression preserves local native and custom wire artifacts', { skip: !supported }, async (t) => {
    const { trafficDir, operatorDir } = fixture(t);
    const ledger = path.join(trafficDir, 'traffic.ndjson');
    const nativeDir = path.join(path.dirname(trafficDir), '.native');
    const nativeLog = path.join(nativeDir, 'necko-pre-tls.moz_log');
    const wireLog = path.join(operatorDir, 'local-wire.log');
    const recorder = new CamoufoxTrafficRecorder({ trafficDir, preTlsWireLogPath: wireLog });
    fs.mkdirSync(nativeDir, { recursive: true });
    fs.writeFileSync(nativeLog, 'Synthetic native diagnostics\n');
    const context = new EventEmitter();
    await recorder.attachContext(context);
    context.emit('request', { method: () => 'GET', url: () => 'https://fixture.example/notes', headers: () => ({}) });
    await recorder.stop();
    const index = JSON.parse(fs.readFileSync(recorder.attributionIndexPath, 'utf8'));
    assert.equal(index.artifacts.trafficNdjsonPath, path.relative(trafficDir, ledger));
    assert.equal(index.artifacts.preTlsWireLogPath, path.relative(trafficDir, wireLog));

    for (const target of [nativeLog, wireLog]) {
        const original = fs.readFileSync(target);
        assert.throws(() => exportTrafficToHar(trafficDir, target), { code: 'ERR_CAPTURE_UNSAFE' });
        assert.deepEqual(fs.readFileSync(target), original);
        assert.throws(() => recorder.exportHar(target), { code: 'ERR_CAPTURE_UNSAFE' });
        assert.deepEqual(fs.readFileSync(target), original);
    }
    assert.equal(exportTrafficToHar(trafficDir, path.join(operatorDir, 'ordinary.har')).entryCount, 1);
});

test('HAR regression preserves existing output when the source directory is missing', { skip: !supported }, (t) => {
    const { trafficDir, operatorDir } = fixture(t);
    const output = path.join(operatorDir, 'existing.har');
    fs.writeFileSync(output, 'Original synthetic archive\n');
    const original = fs.readFileSync(output);
    assert.throws(() => exportTrafficToHar(path.join(trafficDir, 'missing'), output), { code: 'ENOENT' });
    assert.deepEqual(fs.readFileSync(output), original);
    assert.equal(exportTrafficToHar(trafficDir, output).entryCount, 0);
});

test('HAR regression rejects corrupt ledger rows and retains a recoverable unfinished append', { skip: !supported }, (t) => {
    const { trafficDir, operatorDir } = fixture(t);
    const output = path.join(operatorDir, 'existing.har');
    const ledger = path.join(trafficDir, 'traffic.ndjson');
    const [egress, ingress] = transaction();
    fs.writeFileSync(output, 'Original synthetic archive\n');
    const original = fs.readFileSync(output);
    fs.writeFileSync(ledger, `${JSON.stringify(egress)}\n{"type":\n${JSON.stringify(ingress)}\n`);
    assert.throws(() => exportTrafficToHar(trafficDir, output), /Invalid JSON/);
    assert.deepEqual(fs.readFileSync(output), original);
    fs.writeFileSync(ledger, `${JSON.stringify(egress)}\n{"type":`);
    assert.equal(exportTrafficToHar(trafficDir, output).entryCount, 1);
});

test('HAR regression validates any recorded attachment digest before projecting it', { skip: !supported }, (t) => {
    const { trafficDir, payloadsDir, operatorDir } = fixture(t);
    const output = path.join(operatorDir, 'existing.har');
    const payloadFile = 'payloads/body.json';
    const attachment = path.join(payloadsDir, 'body.json');
    const body = '{"count":1}';
    const changed = '{"count":2}';
    const digest = createHash('sha256').update(body).digest('hex');
    const proof = { sha256: digest, bytes: Buffer.byteLength(body) };
    const session = { recordBodies: true };
    const index = path.join(trafficDir, 'attribution-index.json');
    for (const [eventEvidence, integrity] of [
        [{ postDataSha256: digest, postDataBytes: proof.bytes }, undefined],
        [{ payloadStorage: { status: 'stored', ...proof } }, undefined],
        [{}, { payloadManifest: { [payloadFile]: proof } }]
    ]) {
        fs.writeFileSync(index, JSON.stringify({ session, integrity }));
        writeEvents(trafficDir, transaction({ payloadFile, mimeType: 'application/json', recordBodies: true, ...eventEvidence }));
        fs.writeFileSync(attachment, body);
        assert.equal(exportTrafficToHar(trafficDir, output).log.entries[0].request.postData.text, body);
        const previous = fs.readFileSync(output);
        fs.writeFileSync(attachment, changed);
        assert.throws(() => exportTrafficToHar(trafficDir, output), /attachment.*evidence/i);
        assert.deepEqual(fs.readFileSync(output), previous);
        const report = queryProfileTraffic({ trafficDir, correlationId: 'transaction-1' });
        assert.equal(report.requestPayload, null);
        assert.equal(report.requestPayloadOmittedReason, 'payload-integrity');
        fs.unlinkSync(attachment);
        assert.throws(() => exportTrafficToHar(trafficDir, output), /attachment.*evidence/i);
        assert.deepEqual(fs.readFileSync(output), previous);
    }
});
