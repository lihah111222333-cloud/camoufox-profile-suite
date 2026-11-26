import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { readCaptureFile, readCapturePayload } from '../../src/camoufox/capture-io.js';
import { exportTrafficToHar } from '../../src/camoufox/traffic-recorder.js';
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
    fs.writeFileSync(path.join(payloadsDir, 'nested', 'request.json'), '{"count":2,"message":"legacy-body-value"}');
    fs.writeFileSync(path.join(payloadsDir, 'response.json'), '{"success":true,"password":"legacy-body-value"}');
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
        payloadFile: 'payloads/response.json',
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
    assert.match(wire.wireDump, /Cookie: \[REDACTED\]/);

    const outputPath = path.join(operatorDir, 'selected.har');
    const har = exportTrafficToHar(trafficDir, outputPath);
    const entry = har.log.entries[0];
    assert.equal(entry.request.postData.text, wire.requestPayload);
    assert.equal(entry.response.content.text, wire.responsePayload);
    assert.equal(entry.request.queryString[0].value, 'compact');
    assert.equal(entry.response.redirectURL, '/v1/next?token=[REDACTED]');
    assert.equal(entry._attribution.requestPayloadFile, 'payloads/nested/request.json');
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
        { mimeType: mimeTypes.json, body: '{"count":7}', postDataBytes: 200 },
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
    assert.equal(result.harPath, fs.realpathSync.native(defaultOutput));
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

test('an optional absent ledger is distinguishable from an unsafe archive input', (t) => {
    const { trafficDir, operatorDir } = fixture(t);
    assert.equal(readCaptureFile(trafficDir, 'traffic.ndjson', { optional: true }), null);
    if (supported) assert.equal(exportTrafficToHar(trafficDir, path.join(operatorDir, 'empty.har')).entryCount, 0);
    writeEvents(trafficDir, transaction());
    assert.equal(readCaptureFile(trafficDir, 'traffic.ndjson', {
        trustedLocal: true, maxBytes: 129 * 1024 * 1024
    }).includes('transaction-1'), true);
});
