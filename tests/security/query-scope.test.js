import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
    formatCliReport, listTrafficProfiles, parseCliArgs, queryProfileTraffic
} from '../../scripts/query-traffic-attribution.js';
import { CamoufoxTrafficRecorder } from '../../src/camoufox/traffic-recorder.js';

const cliPath = fileURLToPath(new URL('../../scripts/query-traffic-attribution.js', import.meta.url));
const supported = process.platform === 'darwin' || process.platform === 'linux';

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'query-scope-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const profilesDir = path.join(root, 'profiles');
    fs.mkdirSync(profilesDir);
    return { root, profilesDir };
}

function writeProfile(profilesDir, id, events, session = {}) {
    const trafficDir = path.join(profilesDir, id, 'traffic');
    fs.mkdirSync(trafficDir, { recursive: true });
    fs.writeFileSync(path.join(trafficDir, 'traffic.ndjson'),
        events.map((event) => JSON.stringify(event)).join('\n') + '\n');
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({ session }));
    return trafficDir;
}

function sample(correlationId, url) {
    return [
        { type: 'egress', correlationId, url, method: 'GET' },
        { type: 'ingress', correlationId, url, status: 403 }
    ];
}

test('queries, listing, and HAR export use the selected directory ID', { skip: !supported }, (t) => {
    const { root, profilesDir } = fixture(t);
    const events = sample('sample-1', 'https://reports.example/item');
    const trafficDir = writeProfile(profilesDir, 'fixture-west', events, { profileId: 'Old West Profile' });
    writeProfile(profilesDir, 'fixture-east', events, { profileId: 'fixture-west' });

    const profiles = listTrafficProfiles(profilesDir);
    assert.deepEqual(profiles.map((profile) => profile.profileId).sort(), ['fixture-east', 'fixture-west']);
    assert.equal(queryProfileTraffic({ profilesDir, profile: 'fixture-west', includeLocalPaths: true }).trafficDir, trafficDir);
    const byLabel = queryProfileTraffic({ profilesDir, profile: 'Old West Profile', includeLocalPaths: true });
    assert.equal(byLabel.trafficDir, trafficDir);
    assert.equal(byLabel.profileId, 'fixture-west');
    assert.equal(byLabel.session.profileId, 'fixture-west');

    const archivePath = path.join(root, 'audit.har');
    const archive = queryProfileTraffic({ profilesDir, profile: 'Old West Profile', exportHar: archivePath });
    assert.equal(archive.profileId, 'fixture-west');
    assert.equal(archive.entryCount, 1);

    const explicitDir = writeProfile(root, 'operator-capture', events);
    const explicit = queryProfileTraffic({ profilesDir, trafficDir: explicitDir, includeLocalPaths: true });
    assert.equal(explicit.profileDir, path.join(root, 'operator-capture'));
    assert.equal(explicit.transactionsCount, 1);

    writeProfile(profilesDir, 'fixture-north', events, { profileId: 'Old West Profile' });
    assert.throws(() => queryProfileTraffic({ profilesDir, profile: 'Old West Profile' }), /multiple directories/);
    for (const options of [{}, { verifyIntegrity: true }, { exportHar: archivePath }]) {
        assert.throws(() => queryProfileTraffic({ profilesDir, profile: '', ...options }), /Invalid Camoufox profile ID/);
    }
});

test('scoped query and recorder reject linked directories before touching a capture', { skip: !supported }, async (t) => {
    const { root, profilesDir } = fixture(t);
    const trafficDir = writeProfile(profilesDir, 'fixture', sample('sample-1', 'https://reports.example/item'));
    const ledgerPath = path.join(trafficDir, 'traffic.ndjson');
    const ledger = fs.readFileSync(ledgerPath);
    fs.symlinkSync(path.dirname(trafficDir), path.join(profilesDir, 'alternate'), 'dir');
    assert.equal(listTrafficProfiles(profilesDir).length, 1);
    assert.throws(() => queryProfileTraffic({ profilesDir, profile: 'alternate' }), /direct Camoufox profile directory/);

    const recorderOptions = { profilesDir, resetTrafficOnStart: true, sslKeyLog: false, neckoMozLog: false };
    assert.throws(() => new CamoufoxTrafficRecorder({ ...recorderOptions, profileId: 'alternate' }), /direct Camoufox profile directory/);
    assert.throws(() => new CamoufoxTrafficRecorder({ ...recorderOptions, profileId: '' }), /Invalid Camoufox profile ID/);
    assert.deepEqual(fs.readFileSync(ledgerPath), ledger);

    const recorder = new CamoufoxTrafficRecorder({ ...recorderOptions, profileId: 'standalone' });
    recorder.setStep('fixture step');
    await recorder.stop();
    assert.equal(path.dirname(recorder.trafficDir), path.join(profilesDir, 'standalone'));
    assert.equal(queryProfileTraffic({ profilesDir, profile: 'standalone' }).eventsCount, 1);

    const explicitDir = path.join(root, 'operator-traffic');
    const explicit = new CamoufoxTrafficRecorder({ ...recorderOptions, trafficDir: explicitDir });
    assert.equal(explicit.trafficDir, explicitDir);
    await explicit.stop();
});

test('domain filtering matches parsed hosts in events and anomaly reports', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    writeProfile(profilesDir, 'fixture', [
        ...sample('sample-matching', 'https://reports.example:7443/item'),
        ...sample('sample-other', 'https://calendar.example/reports.example:7443?q=reports.example:7443'),
        ...sample('sample-missing-host', 'Unstructured note about reports.example:7443'),
        ...sample('sample-stored-host', 'https://calendar.example/item').map((event) => ({
            ...event,
            host: 'reports.example:7443'
        }))
    ]);
    const report = queryProfileTraffic({ profilesDir, profile: 'fixture', domain: 'REPORTS.EXAMPLE:7443' });
    assert.equal(report.events.length, 2);
    assert.deepEqual(report.transactions.map((tx) => tx.correlationId), ['sample-matching']);
    assert.deepEqual(report.anomalies.map((anomaly) => anomaly.correlationId), ['sample-matching']);
});

test('filtered totals and groups describe selected traffic and omit the unscoped native log', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const transaction = (id, host, step, target, status) =>
        sample(id, `https://${host}/item`).map((event) => ({
            ...event,
            attribution: { actionStep: step },
            ...(event.type === 'egress'
                ? { triggerAction: { actionId: id + '-action', actionType: 'click', target } }
                : { status })
        }));
    const trafficDir = writeProfile(profilesDir, 'fixture', [
        ...transaction('selected', 'reports.example', 'show', '#show', '403'),
        ...transaction('wrong-status', 'reports.example', 'show', '#show', 200),
        ...transaction('wrong-domain', 'excluded.example', 'excluded-step', '#other', 500)
    ]);
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({
        session: {},
        totals: { totalRequests: 3, totalEgressBytes: 239 },
        byDomain: { 'reports.example': { requests: 2 }, 'excluded.example': { requests: 1 } },
        byActionStep: { show: { requests: 2 }, 'excluded-step': { requests: 1 } },
        byTriggerAction: { 'selected-action': { requests: 2 }, 'excluded-action': { requests: 1 } },
        neckoMozLog: {
            parsedRequests: [{ requestLine: 'GET /excluded HTTP/1.1', headers: { host: 'excluded.example' } }]
        }
    }));

    const options = {
        profilesDir, profile: 'fixture', domain: 'reports.example', step: 'show', trigger: '#show', status: '4xx'
    };
    const report = queryProfileTraffic(options);
    assert.equal(report.totals.totalRequests, 1);
    assert.equal(report.totals.totalResponses, 1);
    assert.equal(report.totals.totalEgressBytes, undefined);
    assert.deepEqual(Object.keys(report.byActionStep), ['show']);
    assert.deepEqual(Object.keys(report.byDomain), ['reports.example']);
    assert.deepEqual(Object.keys(report.byTriggerAction), ['selected-action']);
    assert.equal(report.byActionStep.show.requests, 1);
    assert.equal(report.byDomain['reports.example'].responses, 1);
    assert.deepEqual(report.byTriggerAction['selected-action'].statusCounts, { 403: 1 });
    assert.deepEqual(report.events.map(({ type }) => type), ['egress', 'ingress']);
    assert.equal(report.transactions.length, 1);
    assert.ok(report.transactions[0].egress);
    assert.ok(report.transactions[0].ingress);
    assert.equal(report.neckoMozLog, null);
    assert.doesNotMatch(JSON.stringify(report), /excluded|wrong-status/);
    assert.equal(queryProfileTraffic({ ...options, anomaliesOnly: true }).totals.totalRequests, 1);
    assert.equal(queryProfileTraffic({ profilesDir, profile: 'fixture' }).neckoMozLog.parsedRequests.length, 1);
});

test('explicit empty paths and unscoped filters do not fall back to a profile listing', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    assert.throws(() => queryProfileTraffic({ profilesDir: '' }), /Profiles root directory must be nonempty/);
    assert.throws(() => listTrafficProfiles(' '), /Profiles root directory must be nonempty/);
    assert.throws(() => queryProfileTraffic({ profilesDir, trafficDir: '' }), /Traffic directory must be nonempty/);
    assert.throws(() => queryProfileTraffic({ profilesDir, anomaliesOnly: true }), /Traffic directory not found/);
    assert.throws(() => queryProfileTraffic({ profilesDir, domain: '' }), /filter values must be nonempty/);

    writeProfile(profilesDir, 'first', sample('sample-1', 'https://reports.example/item'));
    const selected = queryProfileTraffic({ profilesDir, anomaliesOnly: true });
    assert.equal(selected.mode, 'anomalies');
    assert.equal(selected.profileId, 'first');
    assert.equal(selected.count, 1);

    writeProfile(profilesDir, 'second', sample('sample-2', 'https://other.example/item'));
    assert.equal(queryProfileTraffic({ profilesDir }).mode, 'list-profiles');
    for (const filters of [{ anomaliesOnly: true }, { domain: 'reports.example' }, { cookies: true }]) {
        assert.throws(() => queryProfileTraffic({ profilesDir, ...filters }), /Multiple traffic captures.*--profile/);
    }

    const rejected = spawnSync(process.execPath, [cliPath, '--profiles-dir', '--json'], { encoding: 'utf8' });
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /Profiles root directory must be nonempty/);
    assert.equal(rejected.stdout, '');
});

test('cookie lineage uses the selected events and the status of their transaction', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const withCookies = (id, host, step, target, status, name) =>
        sample(id, `https://${host}/item`).map((event) => ({
            ...event,
            attribution: { actionStep: step },
            ...(event.type === 'egress'
                ? { triggerAction: { actionType: 'click', target }, headers: { Cookie: `${name}Seen=sample` } }
                : { status, headers: { 'Set-Cookie': `${name}=sample; Path=/` } })
        }));
    writeProfile(profilesDir, 'fixture', [
        ...withCookies('chosen', 'reports.example', 'show', '#show', 200, 'Chosen'),
        ...withCookies('other-domain', 'other.example', 'show', '#show', 200, 'OtherDomain'),
        ...withCookies('other-step', 'reports.example', 'hide', '#show', 200, 'OtherStep'),
        ...withCookies('other-trigger', 'reports.example', 'show', '#hide', 200, 'OtherTrigger'),
        ...withCookies('other-status', 'reports.example', 'show', '#show', 403, 'OtherStatus')
    ]);
    const selection = {
        profilesDir, profile: 'fixture', domain: 'reports.example', step: 'show', trigger: '#show', status: '2xx'
    };
    const expected = ['Chosen', 'ChosenSeen'];
    const cookieReport = queryProfileTraffic({ ...selection, cookies: true });
    assert.deepEqual(Object.keys(cookieReport.cookieLineage).sort(), expected);
    assert.deepEqual(Object.keys(queryProfileTraffic(selection).cookieLineage).sort(), expected);
    assert.equal(queryProfileTraffic({ ...selection, cookie: 'OtherDomain' }).found, false);
    assert.equal(queryProfileTraffic({ ...selection, cookies: true, correlation: 'other-status' }).count, 0);
    assert.throws(() => queryProfileTraffic({ ...selection, cookies: true, anomaliesOnly: true }), /Choose one/);
});

test('ordinary query and wire omit cookie digests and keep explicit private lineage', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const value = 'fixture-cookie-value';
    const valueSha256 = createHash('sha256').update(value).digest('hex');
    const url = 'https://reports.example/item';
    writeProfile(profilesDir, 'fixture', [
        {
            type: 'ingress', correlationId: 'cookie-set', url, epochMs: 1,
            cookieObservations: [{ name: 'Sample', path: '/', valueSha256, value }]
        },
        {
            type: 'egress', correlationId: 'cookie-sent', url, epochMs: 2,
            cookieObservations: [{ name: 'Sample', valueSha256, rawValue: value }]
        }
    ]);

    const options = { profilesDir, profile: 'fixture' };
    const ordinary = queryProfileTraffic(options);
    const wire = queryProfileTraffic({ ...options, correlation: 'cookie-sent' });
    assert.equal(ordinary.cookieLineage.Sample.matchesLatestSetCookie, true);
    assert.equal(ordinary.cookieLineage.Sample.valueHistory.length, 1);
    assert.equal(wire.egress.cookieObservations[0].name, 'Sample');
    for (const report of [ordinary, wire]) {
        const json = JSON.stringify(report);
        assert.equal(json.includes(valueSha256), false);
        assert.equal(json.includes(value), false);
    }

    const privateReport = queryProfileTraffic({ ...options, cookie: 'Sample' });
    assert.equal(privateReport.privacy, 'private');
    assert.equal(privateReport.cookie.lastValueSha256, valueSha256);
    assert.equal(privateReport.cookie.valueHistory[0].valueSha256, valueSha256);
    assert.equal(JSON.stringify(privateReport).includes(value), false);
    assert.match(formatCliReport(privateReport), /Private report/);
});

test('wire and observed totals distinguish unknown WebSocket lengths from an empty frame', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const frame = (type, payloadBytes, extra = {}) => ({
        type, correlationId: 'frames', url: 'wss://reports.example/reports', payloadBytes, ...extra
    });
    writeProfile(profilesDir, 'fixture', [
        frame('ws-open', undefined),
        frame('ws-egress', null, { timestamp: 'new-unknown' }),
        frame('ws-ingress', 0, { timestamp: 'empty-frame' }),
        frame('ws-ingress', 0, { timestamp: 'legacy-unknown', bodyOmittedReason: 'body-recording-disabled' })
    ]);
    const options = { profilesDir, profile: 'fixture' };
    const wire = queryProfileTraffic({ ...options, correlation: 'frames' });
    assert.deepEqual(wire.wsEvents.map((event) => event.payloadBytes), [undefined, null, 0, null]);
    assert.match(wire.wireDump, /new-unknown bytes=unknown/);
    assert.match(wire.wireDump, /empty-frame bytes=0/);
    assert.match(wire.wireDump, /legacy-unknown bytes=unknown/);
    assert.doesNotMatch(wire.wireDump, /\[ws-open\][^\n]+bytes=/);

    const { totals } = queryProfileTraffic({ ...options, domain: 'reports.example' });
    assert.equal(totals.wsFramesSent, 1);
    assert.equal(totals.wsFramesReceived, 2);
    assert.equal(totals.unknownWsFramesSent, 1);
    assert.equal(totals.unknownWsFramesReceived, 1);
});

test('both CLI value forms agree and reject unknown options or unexpected arguments', () => {
    for (const [flag, value] of [
        ['--profile', 'fixture'],
        ['--status', '4xx'],
        ['--cookies', '0'],
        ['--anomalies-only', 'true'],
        ['--verify-integrity', 'false'],
        ['--json', 'false'],
        ['--export-har', 'false'],
        ['--export-har', 'fixture export.har']
    ]) {
        assert.deepEqual(parseCliArgs([flag, value]), parseCliArgs([flag + '=' + value]));
    }
    assert.equal(parseCliArgs(['--json', 'false']).json, false);
    assert.equal(parseCliArgs(['--export-har', 'false']).exportHar, false);
    assert.throws(() => parseCliArgs(['--cookies=unknown']), /requires a boolean value/);
    assert.throws(() => parseCliArgs(['--domian=reports.example']), /Unknown option --domian/);
    assert.throws(() => parseCliArgs(['unexpected']), /Unexpected positional argument/);
});

test('CLI and JS queries use the private application configuration and keeps help and explicit paths independent', { skip: !supported }, (t) => {
    const { root, profilesDir } = fixture(t);
    const trafficDir = writeProfile(profilesDir, 'configured', sample('sample-1', 'https://reports.example/item'));
    const stateDir = path.join(root, 'state');
    const defaultProfilesDir = path.join(stateDir, 'profiles');
    writeProfile(defaultProfilesDir, 'default', sample('sample-2', 'https://other.example/item'));
    const configPath = path.join(stateDir, '.env');
    const config = `CAMOUFOX_STORAGE_DIR="${profilesDir}"\n`;
    fs.writeFileSync(configPath, config, { mode: 0o644 });
    fs.chmodSync(configPath, 0o644);
    const env = {
        PATH: process.env.PATH,
        GMAIL_CREATOR_STATE_DIR: stateDir,
        GMAIL_CREATOR_LEGACY_DIR: path.join(root, 'legacy')
    };
    const run = (args, overrides = {}) =>
        spawnSync(process.execPath, [cliPath, ...args], { cwd: root, env: { ...env, ...overrides }, encoding: 'utf8' });

    const api = (expression) => spawnSync(process.execPath, ['--input-type=module', '--eval',
        'import { queryProfileTraffic, listTrafficProfiles } from ' +
        JSON.stringify(new URL('../../scripts/query-traffic-attribution.js', import.meta.url).href) +
        '; console.log(JSON.stringify(' + expression + '));'
    ], { cwd: root, env, encoding: 'utf8' });
    const audit = run(['--json']);
    assert.equal(audit.status, 0, audit.stderr);
    assert.deepEqual(JSON.parse(audit.stdout).profiles.map(({ profileId }) => profileId), ['configured']);
    assert.equal(fs.readFileSync(configPath, 'utf8'), config);
    assert.equal(fs.statSync(configPath).mode & 0o777, 0o644);

    for (const expression of ['queryProfileTraffic().profiles', 'listTrafficProfiles()']) {
        const report = api(expression);
        assert.equal(report.status, 0, report.stderr);
        assert.deepEqual(JSON.parse(report.stdout).map(({ profileId }) => profileId), ['configured']);
    }
    assert.equal(fs.statSync(configPath).mode & 0o777, 0o644);

    const override = run(['--json'], { CAMOUFOX_STORAGE_DIR: defaultProfilesDir });
    assert.equal(override.status, 0, override.stderr);
    assert.deepEqual(JSON.parse(override.stdout).profiles.map(({ profileId }) => profileId), ['default']);

    fs.rmSync(configPath);
    fs.mkdirSync(configPath);
    const help = run(['--help']);
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /Usage:/);
    const explicit = run(['--profiles-dir', profilesDir, '--json']);
    assert.equal(explicit.status, 0, explicit.stderr);
    assert.equal(JSON.parse(explicit.stdout).count, 1);
    const direct = api('queryProfileTraffic({ trafficDir: ' + JSON.stringify(trafficDir) + ' })');
    assert.equal(direct.status, 0, direct.stderr);
    assert.equal(JSON.parse(direct.stdout).eventsCount, 2);
    const invalidConfig = run(['--json']);
    assert.equal(invalidConfig.status, 1);
    assert.match(invalidConfig.stderr, /Could not read \.env as a private configuration file/);
    assert.deepEqual(fs.readdirSync(root).sort(), ['profiles', 'state']);
});

test('resumed capture counts and classifies new ledger events before an index refresh', { skip: !supported }, async (t) => {
    const { profilesDir } = fixture(t);
    const openRecorder = () => new CamoufoxTrafficRecorder({
        profilesDir, profileId: 'fixture', recordWireLog: false, sslKeyLog: false, neckoMozLog: false
    });
    const emitTransaction = (recorder, name, status) => {
        const context = new EventEmitter();
        const request = { url: () => `https://reports.example/${name}`, method: () => 'GET' };
        recorder.attachContext(context);
        context.emit('request', request);
        context.emit('response', { request: () => request, url: request.url, status: () => status });
    };

    const initial = openRecorder();
    emitTransaction(initial, 'initial', 200);
    await initial.stop();
    const indexPath = initial.attributionIndexPath;
    const priorIndex = fs.readFileSync(indexPath);

    const resumed = openRecorder();
    emitTransaction(resumed, 'warning', 401);
    emitTransaction(resumed, 'error', 500);
    const page = new EventEmitter();
    const socket = Object.assign(new EventEmitter(), { url: () => 'wss://reports.example/socket' });
    resumed.attachPage(page);
    page.emit('websocket', socket);
    socket.emit('socketerror', 'fixture socket closed');
    socket.emit('socketerror', 'fixture socket closed');
    await Promise.all([...resumed.pendingTasks]);

    const select = () => queryProfileTraffic({ profilesDir, profile: 'fixture' });
    const anomalies = (report) => report.anomalies.map(({ type, severity }) => [type, severity]).sort();
    const stale = select();
    const [staleList] = listTrafficProfiles(profilesDir);
    assert.equal(stale.totals.totalRequests, 3);
    assert.equal(staleList.totals.totalResponses, 3);
    assert.equal(stale.totals.totalEgressBytes, undefined);
    assert.equal(stale.byDomain['reports.example'].requests, 3);
    assert.equal(stale.byActionStep.init.responses, 3);
    assert.deepEqual(anomalies(stale), [
        ['http-401-unauthorized', 'medium'], ['http-500-server-error', 'high'], ['websocket-error', 'medium']
    ]);
    assert.equal(staleList.anomalyCount, 3);
    assert.match(stale.indexWarnings[0], /out of sync/);
    assert.deepEqual(fs.readFileSync(indexPath), priorIndex);

    await resumed.stop();
    const fresh = select();
    assert.deepEqual(fresh.indexWarnings, []);
    assert.deepEqual(anomalies(fresh), anomalies(stale));

    const partial = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
    partial.totals = { totalRequests: 3 };
    delete partial.anomaliesAndRiskSignals;
    fs.writeFileSync(indexPath, JSON.stringify(partial));
    assert.equal(select().totals.totalResponses, 3);
    assert.equal(listTrafficProfiles(profilesDir)[0].anomalyCount, 3);
    assert.deepEqual(anomalies(select()), anomalies(fresh));
});

test('correlation queries require a directory when multiple captures claim one ID', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    writeProfile(profilesDir, 'fixture-west', [
        ...sample('shared', 'https://reports.example/west'),
        ...sample('unique', 'https://reports.example/unique')
    ], { profileId: 'label' });
    writeProfile(profilesDir, 'fixture-east', sample('shared', 'https://reports.example/east'), { profileId: 'label' });

    const unique = queryProfileTraffic({ profilesDir, correlationId: 'unique' });
    assert.equal(unique.profileId, 'fixture-west');
    assert.equal(unique.egress.url, 'https://reports.example/unique');
    assert.throws(() => queryProfileTraffic({ profilesDir, correlationId: 'shared' }), /multiple profiles.*--profile/);
    const qualified = queryProfileTraffic({ profilesDir, profile: 'fixture-east', correlationId: 'shared' });
    assert.equal(qualified.profileId, 'fixture-east');
    assert.equal(qualified.egress.url, 'https://reports.example/east');
});

test('a missing correlation has a failing CLI status with or without a profile', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    writeProfile(profilesDir, 'fixture', sample('sample-1', 'https://reports.example/item'));
    const argv = [cliPath, `--profiles-dir=${profilesDir}`, '--correlation=missing'];
    const run = (...flags) => spawnSync(process.execPath, [...argv, ...flags], { encoding: 'utf8' });

    const one = run('--profile=fixture');
    assert.equal(one.status, 1);
    assert.match(one.stdout, /Correlation ID "missing" not found in profile "fixture"/);
    const json = run('--profile=fixture', '--json');
    assert.equal(json.status, 1);
    assert.equal(JSON.parse(json.stdout).found, false);
    const all = run();
    assert.equal(all.status, 1);
    assert.match(all.stderr, /Correlation ID "missing" not found/);
});

test('integrity failure returns the full JSON report through a pipe', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const trafficDir = writeProfile(profilesDir, 'fixture', []);
    const payloadsDir = path.join(trafficDir, 'payloads');
    fs.mkdirSync(payloadsDir);
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({
        integrity: { eventCount: 0, chainHeadHash: '0'.repeat(64), payloadManifest: {} }
    }));
    const orphanCount = 512;
    for (let i = 0; i < orphanCount; i += 1) {
        fs.writeFileSync(path.join(payloadsDir, `fixture-${'attachment-'.repeat(14)}${i}.txt`), '');
    }

    const result = spawnSync(process.execPath,
        [cliPath, `--profiles-dir=${profilesDir}`, '--profile=fixture', '--verify-integrity', '--json'],
        { encoding: 'utf8' });
    assert.equal(result.status, 1, result.stderr);
    assert.ok(Buffer.byteLength(result.stdout) > 64 * 1024);
    const report = JSON.parse(result.stdout);
    assert.equal(report.valid, false);
    assert.equal(report.errors.length, orphanCount);
});

test('the CLI escapes display controls while preserving generated report lines', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const events = sample('sample-1', 'https://reports.example/item');
    events[0].actionStep = 'phase one\nphase two';
    events[1].statusText = 'sample\u0085message';
    writeProfile(profilesDir, 'fixture', [...events, {
        type: 'ws-ingress',
        correlationId: 'sample-1',
        url: 'wss://reports.example/socket',
        timestamp: 'capture\rclock'
    }], { os: 'test\u2028platform' });

    const run = (...options) => execFileSync(process.execPath,
        [cliPath, `--profiles-dir=${profilesDir}`, ...options], { encoding: 'utf8' });
    const list = run();
    assert.match(list, /fixture \| OS=test\\u2028platform/);
    const report = run('--profile=fixture');
    assert.match(report, /step=phase one\\u000aphase two/);
    const wire = run('--profile=fixture', '--correlation=sample-1');
    assert.match(wire, /Profile ID +: fixture\nCorrelation ID/);
    assert.match(wire, /Action Step +: phase one\\u000aphase two/);
    assert.match(wire, /sample\\u0085message/);
    assert.match(wire, /\[ws-ingress\] capture\\u000dclock/);
    for (const output of [list, report, wire]) {
        assert.doesNotMatch(output, /[\x00-\x09\x0b-\x1f\x7f-\x9f\u2028]/);
    }
    const machine = JSON.parse(run('--profile=fixture', '--correlation=sample-1', '--json'));
    assert.equal(machine.actionStep, 'phase one\nphase two');
});

test('query filters match archived values and mask them in JSON reports', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const step = 'Review fixture.operator@example.test';
    const events = sample('fixture', 'https://reports.example/item').map((event) => ({ ...event, actionStep: step }));
    writeProfile(profilesDir, 'fixture', events);
    const run = (...flags) => spawnSync(process.execPath,
        [cliPath, '--profiles-dir=' + profilesDir, '--profile=fixture', '--step=' + step, '--json', ...flags],
        { encoding: 'utf8' });

    const ordinary = run();
    assert.equal(ordinary.status, 0, ordinary.stderr);
    assert.equal(JSON.parse(ordinary.stdout).eventsCount, 2);
    assert.equal(JSON.parse(ordinary.stdout).filters.step, 'Review [REDACTED]');
    assert.doesNotMatch(ordinary.stdout, /fixture\.operator@example\.test/);
    const anomalyReport = run('--anomalies-only');
    assert.equal(anomalyReport.status, 0, anomalyReport.stderr);
    assert.equal(JSON.parse(anomalyReport.stdout).count, 1);
    assert.doesNotMatch(anomalyReport.stdout, /fixture\.operator@example\.test/);
});

test('wire queries reject damaged ledger records and accept a complete final record without a newline', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const events = sample('fixture-item', 'https://reports.example/item');
    const trafficDir = writeProfile(profilesDir, 'fixture', events);
    const ledger = path.join(trafficDir, 'traffic.ndjson');
    const rows = events.map((event) => JSON.stringify(event));
    const args = [cliPath, '--profiles-dir=' + profilesDir, '--profile=fixture', '--correlation=fixture-item', '--json'];
    const run = () => spawnSync(process.execPath, args, { encoding: 'utf8' });
    for (const [badRow, explanation] of [['{"type":', 'Invalid JSON'], ['null', 'Expected an event object']]) {
        fs.writeFileSync(ledger, [rows[0], badRow, rows[1], ''].join('\n'));
        const result = run();
        assert.equal(result.status, 1);
        assert.equal(result.stdout, '');
        assert.ok(result.stderr.includes('Line 2 of traffic.ndjson: ' + explanation));
    }

    fs.writeFileSync(ledger, rows.join('\n'));
    const complete = run();
    assert.equal(complete.status, 0, complete.stderr);
    assert.equal(JSON.parse(complete.stdout).ingress.status, 403);
});

test('an invalid status filter leaves an existing HAR intact', { skip: !supported }, (t) => {
    const { root, profilesDir } = fixture(t);
    writeProfile(profilesDir, 'fixture', sample('fixture-item', 'https://reports.example/item'));
    const target = path.join(root, 'existing.har');
    const options = { profilesDir, profile: 'fixture', exportHar: target };
    assert.equal(queryProfileTraffic(options).entryCount, 1);
    const before = fs.readFileSync(target);
    const result = spawnSync(process.execPath, [
        cliPath, '--profiles-dir=' + profilesDir, '--profile=fixture', '--export-har=' + target, '--status=4x', '--json'
    ], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /status filter/i);
    assert.equal(result.stdout, '');
    assert.deepEqual(fs.readFileSync(target), before);
});

test('a literal profile directory takes precedence over a colliding legacy alias', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const alias = 'profile-legacy-1710000000000';
    const legacy = 'Gmail_fixture_1710000000000';
    writeProfile(profilesDir, alias, sample('direct', 'https://reports.example/direct'));
    writeProfile(profilesDir, legacy, sample('legacy', 'https://reports.example/legacy'));
    const select = (profile) => queryProfileTraffic({ profilesDir, profile }).transactions[0].correlationId;
    assert.equal(select(alias), 'direct');
    assert.equal(select(legacy), 'legacy');
    fs.rmSync(path.join(profilesDir, alias), { recursive: true });
    assert.equal(select(alias), 'legacy');
});

test('wire reports an integrity omission for a legacy attachment with a length mismatch', { skip: !supported }, (t) => {
    const { profilesDir } = fixture(t);
    const [egress] = sample('fixture-item', 'https://reports.example/item');
    const body = '{"count":27}';
    const payloadFile = 'payloads/note.json';
    const trafficDir = writeProfile(profilesDir, 'fixture', [{
        ...egress,
        headers: { 'Content-Type': 'application/json' },
        recordBodies: true,
        payloadFile,
        postDataBytes: Buffer.byteLength(body)
    }], { recordBodies: true });
    const payload = path.join(trafficDir, payloadFile);
    fs.mkdirSync(path.dirname(payload));
    fs.writeFileSync(payload, body);
    const read = () => queryProfileTraffic({ profilesDir, profile: 'fixture', correlationId: 'fixture-item' });
    assert.equal(read().requestPayload, body);

    fs.writeFileSync(payload, '{"count":2}');
    const broken = read();
    assert.equal(broken.requestPayload, null);
    assert.equal(broken.requestPayloadOmittedReason, 'payload-integrity');
    assert.match(formatCliReport(broken), /Request attachment failed integrity verification/);
});

test('wire reports when a recording stopped at its event limit', { skip: !supported }, async (t) => {
    const { profilesDir } = fixture(t);
    const recorder = new CamoufoxTrafficRecorder({
        profilesDir, profileId: 'fixture', maxCaptureEvents: 1,
        recordWireLog: false, sslKeyLog: false, neckoMozLog: false
    });
    const context = new EventEmitter();
    recorder.attachContext(context);
    const request = { url: () => 'https://reports.example/item', method: () => 'GET' };
    context.emit('request', request);
    await Promise.all([...recorder.pendingTasks]);
    context.emit('response', { request: () => request, url: request.url, status: () => 200 });
    const summary = await recorder.stop();
    assert.equal(summary.captureLimits.stoppedReason, 'event-limit');
    const options = { profilesDir, profile: 'fixture' };
    const [egress] = queryProfileTraffic(options).events;
    const wire = queryProfileTraffic({ ...options, correlation: egress.correlationId });
    assert.equal(wire.ingress, null);
    assert.deepEqual(wire.captureLimits, { stoppedReason: 'event-limit' });
    assert.match(formatCliReport(wire), /Capture stopped.*event-limit/);
});

test('query reports the wire name from integrity metadata and supports the old default', { skip: !supported }, (t) => {
    const { root, profilesDir } = fixture(t);
    const trafficDir = writeProfile(profilesDir, 'fixture', sample('fixture-item', 'https://reports.example/item'));
    const legacy = path.join(trafficDir, 'pre-tls-wire.log');
    const custom = path.join(trafficDir, 'custom-wire.log');
    fs.writeFileSync(legacy, 'default artifact');
    fs.writeFileSync(custom, 'custom artifact');
    const name = () => path.basename(queryProfileTraffic({ profilesDir, profile: 'fixture' }).artifacts.preTlsWireLogPath);
    assert.equal(name(), 'pre-tls-wire.log');

    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify({
        integrity: { preTlsWireLogFile: 'custom-wire.log' },
        artifacts: { preTlsWireLogPath: path.join(root, 'unrelated.log') }
    }));
    assert.equal(name(), 'custom-wire.log');
    assert.equal(path.basename(listTrafficProfiles(profilesDir)[0].artifacts.preTlsWireLogPath), 'custom-wire.log');
});
