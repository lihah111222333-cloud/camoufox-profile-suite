import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { listTrafficProfiles, queryProfileTraffic } from '../../scripts/query-traffic-attribution.js';
import { CamoufoxTrafficRecorder, exportTrafficToHar } from '../../src/camoufox/traffic-recorder.js';

const cliPath = fileURLToPath(new URL('../../scripts/query-traffic-attribution.js', import.meta.url));

function fixture(t) {
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'private-query-fixture-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const profilesDir = path.join(root, 'profiles');
    const env = {
        GMAIL_CREATOR_STATE_DIR: path.join(root, 'state'),
        GMAIL_CREATOR_LEGACY_DIR: path.join(root, 'legacy')
    };
    const cli = (...args) => spawnSync(process.execPath, [
        cliPath, '--profiles-dir=' + profilesDir, ...args
    ], { encoding: 'utf8', cwd: root, env });
    return { root, profilesDir, cli };
}

async function record(profilesDir, profileId, options = {}, observations = [{}]) {
    const recorder = new CamoufoxTrafficRecorder({
        profilesDir, profileId, recordWireLog: false, sslKeyLog: false, neckoMozLog: false, ...options
    });
    for (const observation of observations) {
        assert.ok(recorder.recordSecurityBlock({
            targetUrl: 'https://fixture.example/item', reason: 'Synthetic observation', ...observation
        }));
    }
    await recorder.stop();
    return recorder;
}

test('ordinary audit outputs omit local roots while callers can explicitly open the artifacts', async (t) => {
    const { root, profilesDir, cli } = fixture(t);
    const recorder = await record(profilesDir, 'fixture-profile');
    for (const args of [
        [],
        ['--profile=fixture-profile'],
        ['--profile=fixture-profile', '--verify-integrity'],
        ['--profile=fixture-profile', '--export-har']
    ]) {
        const run = cli(...args, '--json');
        assert.equal(run.status, 0, run.stderr);
        assert.ok(!run.stdout.includes(root));
    }
    const plain = cli();
    assert.equal(plain.status, 0, plain.stderr);
    assert.ok(!plain.stdout.includes(root));

    const missing = cli('--profile=missing');
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /Traffic directory not found/);
    assert.ok(!missing.stderr.includes(root));

    const [profile] = listTrafficProfiles(profilesDir);
    assert.equal(profile.trafficDir, undefined);
    assert.equal(profile.artifacts.trafficNdjsonPath, 'traffic.ndjson');
    const privateReport = queryProfileTraffic({ profilesDir, profile: 'fixture-profile', includeLocalPaths: true });
    assert.equal(privateReport.trafficDir, recorder.trafficDir);
    assert.equal(privateReport.artifacts.trafficNdjsonPath, recorder.trafficNdjsonPath);
    assert.ok(fs.existsSync(privateReport.artifacts.trafficNdjsonPath));
});

test('new recording projects legacy profile IDs without renaming storage', async (t) => {
    const { root, profilesDir } = fixture(t);
    const profileId = 'Gmail_synthetic_candidate_1700000000000';
    const displayId = 'profile-legacy-1700000000000';
    const recorder = await record(profilesDir, profileId);
    assert.equal(path.dirname(recorder.trafficDir), path.join(profilesDir, profileId));
    for (const file of [recorder.trafficNdjsonPath, recorder.attributionIndexPath]) {
        const output = fs.readFileSync(file, 'utf8');
        assert.ok(output.includes(displayId));
        assert.ok(!output.includes(profileId));
        assert.ok(!output.includes(root));
    }
    const query = queryProfileTraffic({ profilesDir, profile: profileId });
    assert.equal(query.session.profileId, displayId);
    assert.equal(query.events.length, 1);
    const har = exportTrafficToHar(recorder.trafficDir, path.join(root, 'fixture.har'));
    assert.equal(har.log.entries[0]._attribution.profileId, displayId);
});

test('transactions and wire reconstruction keep distinct traces apart', async (t) => {
    const { profilesDir, cli } = fixture(t);
    const profile = 'fixture-profile';
    const correlationId = 'fixture-observation';
    const shared = { correlationId };
    const first = await record(profilesDir, profile, { traceId: 'first-trace', accountId: 1 }, [
        { ...shared, targetUrl: 'https://first.example/item' },
        { correlationId: 'fixture-unique', targetUrl: 'https://first.example/other' }
    ]);
    const latest = await record(profilesDir, profile, { traceId: 'second-trace', accountId: 2 }, [
        { ...shared, targetUrl: 'https://second.example/item' }
    ]);
    const report = queryProfileTraffic({ profilesDir, profile });
    const matches = report.transactions.filter((item) => item.correlationId === correlationId);
    assert.deepEqual(matches.map((item) => [item.host, item.securityBlock.attribution.accountId]), [
        ['first.example', 1], ['second.example', 2]
    ]);
    const wire = cli('--profile=' + profile, '--correlation=' + correlationId, '--json');
    assert.equal(wire.status, 1);
    assert.match(wire.stderr, /multiple recording sessions/i);
    assert.doesNotMatch(wire.stderr, /first\.example|second\.example/);
    assert.match(latest.formatTransactionWireDump(correlationId), /multiple recording sessions/i);

    const unique = queryProfileTraffic({ profilesDir, profile, correlation: 'fixture-unique' });
    assert.equal(unique.securityBlock.attribution.traceId, 'first-trace');
    assert.equal(unique.anomalies.length, 1);
    assert.match(first.formatTransactionWireDump('fixture-unique'), /first\.example/);
});

test('direct traffic paths cannot be relabeled with an unrelated profile selector', async (t) => {
    const { root, profilesDir } = fixture(t);
    const first = await record(profilesDir, 'fixture-first');
    await record(profilesDir, 'fixture-second');
    const options = { profilesDir, trafficDir: first.trafficDir };
    assert.equal(queryProfileTraffic(options).profileId, 'fixture-first');
    assert.equal(queryProfileTraffic({ ...options, profile: 'fixture-first' }).profileId, 'fixture-first');
    assert.equal(queryProfileTraffic({ profilesDir, profile: 'fixture-second' }).profileId, 'fixture-second');

    const output = path.join(root, 'existing.har');
    fs.writeFileSync(output, 'original');
    for (const mode of [{}, { exportHar: output }]) {
        assert.throws(() => queryProfileTraffic({ ...options, profileId: 'fixture-second', ...mode }),
            /Selected profile ID does not match/);
    }
    assert.equal(fs.readFileSync(output, 'utf8'), 'original');
});

test('standalone captures validate a claimed profile against their recorded identity', async (t) => {
    const { root, profilesDir } = fixture(t);
    const trafficDir = path.join(root, 'independent', 'traffic');
    const options = { profilesDir, trafficDir };
    await record(profilesDir, 'recorded-profile', { trafficDir });
    assert.equal(queryProfileTraffic(options).profileId, 'recorded-profile');
    assert.equal(queryProfileTraffic({ ...options, profile: 'recorded-profile' }).eventsCount, 1);

    const output = path.join(root, 'existing.har');
    fs.writeFileSync(output, 'original');
    assert.throws(() => queryProfileTraffic({ ...options, profile: 'independent', exportHar: output }),
        /Selected profile ID does not match/);
    fs.unlinkSync(path.join(trafficDir, 'attribution-index.json'));
    assert.throws(() => queryProfileTraffic({ ...options, profile: 'recorded-profile', exportHar: output }),
        /Selected profile ID does not match/);
    assert.equal(queryProfileTraffic(options).profileId, 'standalone-capture');
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'),
        JSON.stringify({ session: { profileId: path.join(root, 'private-identity') } }));
    const unverified = queryProfileTraffic(options);
    assert.equal(unverified.profileId, 'standalone-capture');
    assert.equal(unverified.session.profileId, unverified.profileId);
    assert.ok(!JSON.stringify(unverified).includes(root));
    assert.equal(fs.readFileSync(output, 'utf8'), 'original');
});
