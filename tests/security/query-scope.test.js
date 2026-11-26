import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
    listTrafficProfiles, queryProfileTraffic
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
    assert.equal(queryProfileTraffic({ profilesDir, profile: 'fixture-west' }).trafficDir, trafficDir);
    const byLabel = queryProfileTraffic({ profilesDir, profile: 'Old West Profile' });
    assert.equal(byLabel.trafficDir, trafficDir);
    assert.equal(byLabel.profileId, 'fixture-west');
    assert.equal(byLabel.session.profileId, 'fixture-west');

    const archivePath = path.join(root, 'audit.har');
    const archive = queryProfileTraffic({ profilesDir, profile: 'Old West Profile', exportHar: archivePath });
    assert.equal(archive.profileId, 'fixture-west');
    assert.equal(archive.entryCount, 1);

    const explicitDir = writeProfile(root, 'operator-capture', events);
    const explicit = queryProfileTraffic({ profilesDir, trafficDir: explicitDir });
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
