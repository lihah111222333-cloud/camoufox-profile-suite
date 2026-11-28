import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    listTrafficProfiles, queryProfileTraffic
} from '../../scripts/query-traffic-attribution.js';
import { CamoufoxTrafficRecorder } from '../../src/camoufox/traffic-recorder.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

function fixture(t) {
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'capture-attribution-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

function writeArchive(trafficDir, events, index) {
    fs.mkdirSync(trafficDir, { recursive: true });
    const ledger = events.map((event) => JSON.stringify(event)).join('\n') + '\n';
    fs.writeFileSync(path.join(trafficDir, 'traffic.ndjson'), ledger);
    fs.writeFileSync(path.join(trafficDir, 'attribution-index.json'), JSON.stringify(index));
}

function observations({ correlationId, url, accountId, traceId, profileId, status, target }) {
    const request = {
        type: 'egress', correlationId, url, method: 'GET',
        attribution: { accountId, traceId, profileId, actionStep: 'review' },
        ...(target && { triggerAction: { actionType: 'click', target } })
    };
    const { triggerAction, ...response } = request;
    return [request, { ...response, type: 'ingress', status }];
}

test('R7-05 keeps a reused correlation separate when the recorded account changes', { skip: !supported }, async (t) => {
    const root = fixture(t);
    const profilesDir = path.join(root, 'profiles');
    const profile = 'audit-profile';
    const recorder = new CamoufoxTrafficRecorder({
        profilesDir, profileId: profile, traceId: 'same-trace', accountId: 11,
        recordWireLog: false, sslKeyLog: false, neckoMozLog: false
    });
    const repeated = 'shared-observation';
    try {
        for (const [accountId, host] of [[11, 'first.example.test'], [12, 'second.example.test']]) {
            recorder.updateAttribution({ accountId });
            assert.ok(recorder.recordSecurityBlock({ correlationId: repeated, targetUrl: 'https://' + host + '/item' }));
            assert.ok(recorder.recordSecurityBlock({
                correlationId: 'control-' + accountId, targetUrl: 'https://' + host + '/control'
            }));
        }
    } finally {
        await recorder.stop();
    }
    const options = { profilesDir, profile };
    const ledgerBefore = fs.readFileSync(recorder.trafficNdjsonPath);
    const indexBefore = fs.readFileSync(recorder.attributionIndexPath);
    const report = queryProfileTraffic(options);
    assert.equal(report.eventsCount, 4);
    assert.equal(report.transactionsCount, 4);
    const matches = report.transactions.filter((event) => event.correlationId === repeated);
    assert.deepEqual(matches.map((event) => [
        event.host, event.failed.attribution.accountId, event.securityBlock.attribution.accountId
    ]), [['first.example.test', 11, 11], ['second.example.test', 12, 12]]);
    assert.equal(queryProfileTraffic({ ...options, domain: 'second.example.test' }).session.accountId, 12);
    assert.equal(queryProfileTraffic({ ...options, correlation: 'control-11' }).securityBlock.attribution.accountId, 11);
    assert.throws(() => queryProfileTraffic({ ...options, correlation: repeated }), /multiple recorded accounts/);
    assert.match(recorder.formatTransactionWireDump(repeated), /multiple recorded accounts/);

    const output = path.join(root, 'summary.har');
    const fullHar = queryProfileTraffic({ ...options, exportHar: output });
    assert.equal(fullHar.entryCount, 4);
    assert.deepEqual(fullHar.log.entries.map((event) => event._attribution.accountId), [11, 11, 12, 12]);
    const previous = fs.readFileSync(output);
    assert.throws(() => queryProfileTraffic({ ...options, correlation: repeated, exportHar: output }),
        /multiple transactions/);
    assert.deepEqual(fs.readFileSync(output), previous);
    const scopedHar = queryProfileTraffic({
        ...options, correlation: repeated, domain: 'second.example.test', exportHar: path.join(root, 'scoped.har')
    });
    assert.equal(scopedHar.entryCount, 1);
    assert.equal(scopedHar.log.entries[0]._attribution.accountId, 12);
    assert.equal(queryProfileTraffic({ ...options, verifyIntegrity: true }).valid, true);
    assert.deepEqual(fs.readFileSync(recorder.trafficNdjsonPath), ledgerBefore);
    assert.deepEqual(fs.readFileSync(recorder.attributionIndexPath), indexBefore);
});

test('R7-16 an unrelated profile does not split a verified legacy alias pair', { skip: !supported }, (t) => {
    const root = fixture(t);
    const trafficDir = path.join(root, 'archive');
    const rawProfileId = 'Gmail_fixture_audit_1710000000000';
    const displayProfile = 'profile-legacy-1710000000000';
    const traceId = 'legacy-trace';
    const [request, response] = observations({
        accountId: 21, correlationId: 'legacy-match', traceId, profileId: rawProfileId,
        url: 'https://legacy.example.test/item', status: 403, target: '#review'
    });
    response.attribution = { ...response.attribution, profileId: displayProfile };
    const unrelated = observations({
        accountId: 22, correlationId: 'other-match', traceId: 'other-trace', profileId: 'other-profile',
        url: 'https://other.example.test/item', status: 200, target: '#other'
    });
    writeArchive(trafficDir, [request, response, ...unrelated], {
        session: { profileId: displayProfile, traceId, recordBodies: false }
    });
    const filters = { domain: 'legacy.example.test', status: 403, trigger: '#review' };
    const report = queryProfileTraffic({ trafficDir, ...filters });
    assert.equal(report.profileIdentity, 'mixed');
    assert.equal(report.totals.totalRequests, 1);
    assert.equal(report.totals.totalResponses, 1);
    assert.equal(report.transactionsCount, 1);
    assert.ok(report.transactions[0].egress && report.transactions[0].ingress);
    assert.equal(report.anomalies[0].triggerAction.target, '#review');
    assert.equal(report.session.accountId, 21);
    const wire = queryProfileTraffic({ trafficDir, correlation: 'legacy-match' });
    assert.ok(wire.egress);
    assert.equal(wire.ingress.status, 403);
    const har = queryProfileTraffic({ trafficDir, ...filters, exportHar: path.join(root, 'legacy.har') });
    assert.equal(har.entryCount, 1);
    assert.equal(har.log.entries[0].response.status, 403);
});

test('R7-16 a shared legacy alias cannot select between distinct raw profiles', { skip: !supported }, (t) => {
    const root = fixture(t);
    const trafficDir = path.join(root, 'archive');
    const first = 'Gmail_fixture_first_1710000000000';
    const second = 'Gmail_fixture_second_1710000000000';
    const [request, response] = observations({
        correlationId: 'ambiguous-item', traceId: 'shared-trace', profileId: first,
        url: 'https://first.example.test/item', status: 403, target: '#first'
    });
    response.attribution = { ...response.attribution, profileId: 'profile-legacy-1710000000000' };
    const unrelated = observations({
        correlationId: 'named-other-item', traceId: 'shared-trace', profileId: second,
        url: 'https://second.example.test/item', status: 200
    });
    writeArchive(trafficDir, [request, response, ...unrelated], {});
    const report = queryProfileTraffic({ trafficDir, domain: 'first.example.test', status: 403 });
    assert.deepEqual(report.events.map(({ type }) => type), ['ingress']);
    assert.equal(report.transactions[0].egress, null);
    assert.equal(queryProfileTraffic({ trafficDir, trigger: '#first', status: 403 }).transactionsCount, 0);
    assert.throws(() => queryProfileTraffic({ trafficDir, correlation: 'ambiguous-item' }), /ambiguous recorded profile/);
    assert.throws(() => queryProfileTraffic({ trafficDir, exportHar: path.join(root, 'ambiguous.har') }), /ambiguous recorded profile/);
});

test('R7-17 resolves a legacy index anomaly by its evidence and retains unresolved rows', { skip: !supported }, (t) => {
    const root = fixture(t);
    const profilesDir = path.join(root, 'profiles');
    const profileId = 'archive-profile';
    const trafficDir = path.join(profilesDir, profileId, 'traffic');
    const correlationId = 'archived-item';
    const firstUrl = 'https://first.example.test/item';
    const first = observations({
        accountId: 31, correlationId, traceId: 'first-trace', profileId,
        url: firstUrl, status: 200, target: '#first'
    });
    const second = observations({
        accountId: 32, correlationId, traceId: 'second-trace', profileId,
        url: 'https://second.example.test/item', status: 200, target: '#second'
    });
    const anomaly = {
        correlationId, type: 'proxy-anonymity-leak', severity: 'high',
        url: firstUrl, method: 'GET', status: 200, failureText: 'Synthetic diagnostic'
    };
    const index = { session: { profileId, traceId: 'second-trace' }, anomaliesAndRiskSignals: [anomaly] };
    writeArchive(trafficDir, [...first, ...second], index);
    const firstOnly = queryProfileTraffic({
        trafficDir, anomaliesOnly: true, domain: 'first.example.test', status: 200, trigger: '#first'
    });
    assert.equal(firstOnly.count, 1);
    assert.equal(firstOnly.anomalies[0].traceId, 'first-trace');
    assert.equal(firstOnly.session.accountId, 31);
    assert.equal(listTrafficProfiles(profilesDir)[0].anomalyCount, firstOnly.count);

    const ambiguous = [...first, ...second.map((event) => ({ ...event, url: firstUrl }))];
    writeArchive(trafficDir, ambiguous, index);
    const unresolved = queryProfileTraffic({ trafficDir, anomaliesOnly: true, domain: 'first.example.test' });
    assert.equal(unresolved.count, 1);
    assert.equal(unresolved.anomalies[0].attributionStatus, 'unresolved');
    assert.equal(unresolved.anomalies[0].traceId, undefined);
    assert.equal(unresolved.anomalies[0].triggerAction, undefined);
    assert.equal(listTrafficProfiles(profilesDir)[0].anomalyCount, unresolved.count);
    assert.equal(queryProfileTraffic({ trafficDir, anomaliesOnly: true, trigger: '#first' }).count, 0);

    writeArchive(trafficDir, ambiguous, {
        ...index, anomaliesAndRiskSignals: [{ ...anomaly, traceId: 'first-trace' }]
    });
    assert.equal(queryProfileTraffic({ trafficDir, anomaliesOnly: true, trigger: '#first' }).anomalies[0].traceId, 'first-trace');
});
