import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { queryProfileTraffic, formatCliReport } from '../../scripts/query-traffic-attribution.js';
import { attachPageCompatibility } from '../../src/camoufox/profile.js';
import { CamoufoxTrafficRecorder, verifyTrafficIntegrity } from '../../src/camoufox/traffic-recorder.js';

const cliPath = fileURLToPath(new URL('../../scripts/query-traffic-attribution.js', import.meta.url));
const digest = (value) => createHash('sha256').update(value).digest('hex');

function fixture(t) {
    const profilesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'recorder-attribution-'));
    t.after(() => fs.rmSync(profilesDir, { recursive: true, force: true }));
    const trafficDir = path.join(profilesDir, 'fixture', 'traffic');
    const options = { profileId: 'fixture', trafficDir, sslKeyLog: false, recordBodies: false, recordWireLog: false };
    const recorder = new CamoufoxTrafficRecorder(options);
    const context = new EventEmitter();
    recorder.attachContext(context);
    return { recorder, context, trafficDir, profilesDir, options };
}

function request(url, headers = {}, frame = null) {
    return {
        method: () => 'GET',
        url: () => url,
        frame: () => frame,
        headers: () => headers,
        async headersArray() {
            return Object.entries(headers).map(([name, value]) => ({ name, value }));
        }
    };
}

function setCookie(context, url, values, headers) {
    const req = request(url, headers);
    context.emit('request', req);
    context.emit('response', {
        request: () => req,
        url: req.url,
        status: () => 200,
        headersArray: async () => values.map((value) => ({ name: 'Set-Cookie', value }))
    });
}

function emitCookie(context, url, header) {
    context.emit('request', request(url, { Cookie: header }));
}

function events(recorder) {
    return fs.readFileSync(recorder.trafficNdjsonPath, 'utf8').trim().split('\n').map(JSON.parse);
}

test('cookie instances use effective scope and keep uncertain observations separate in live and offline reports', async (t) => {
    const { recorder, context, trafficDir, profilesDir, options } = fixture(t);
    setCookie(context, 'https://alpha.test/store/setup', [
        'Sample=blue; Secure; HttpOnly', 'Ordinary=gray; Path=/', '__proto__=pink; Path=/',
        'Shared=ivory; Domain=.ALPHA.TEST; Path=/', 'Shared=ivory; Path=/store',
        'PartitionSample=gray; Partitioned; Secure; Path=/'
    ]);
    setCookie(context, 'https://beta.test/update', [
        'Sample=green; Domain=.BETA.TEST; Path=/', 'Sample=gray; Domain=alpha.test; Path=/store'
    ]);
    await recorder.flushSummary();

    emitCookie(context, 'https://alpha.test/store/view', 'Sample=blue; Shared=ivory; __proto__=pink; PartitionSample=gray');
    emitCookie(context, 'https://alpha.test/storehouse', 'Sample=blue');
    emitCookie(context, 'https://cdn.alpha.test/store/view', 'Sample=blue; Shared=ivory');
    emitCookie(context, 'https://cdn.beta.test/', 'Sample=green');
    emitCookie(context, 'http://alpha.test/store/view', 'Sample=blue');
    const summary = await recorder.stop();

    const { Sample, Shared, PartitionSample } = summary.cookieLineage;
    assert.equal(Sample.instances.length, 5);
    const [alpha, beta, unrelatedDomain, unknownPath, unknownSubdomain] = Sample.instances;
    assert.equal(alpha.domain, 'alpha.test');
    assert.equal(alpha.hostOnly, true);
    assert.equal(alpha.path, '/store');
    assert.equal(alpha.secure, true);
    assert.equal(alpha.httpOnly, true);
    assert.equal(alpha.lastValueSha256, digest('blue'));
    assert.equal(alpha.sentCount, 1);
    assert.equal(beta.hostOnly, false);
    assert.equal(beta.domain, 'beta.test');
    assert.equal(beta.lastValueSha256, digest('green'));
    assert.equal(beta.sentCount, 1);
    assert.equal(unrelatedDomain.scopeStatus, 'unknown');
    assert.equal(unrelatedDomain.sentCount, 0);
    assert.equal(unknownPath.scopeStatus, 'unmatched');
    assert.equal(unknownPath.path, null);
    assert.equal(unknownPath.sentCount, 2);
    assert.equal(unknownSubdomain.domain, 'cdn.alpha.test');
    assert.equal(unknownSubdomain.sentCount, 1);
    assert.equal(Shared.instances.find((entry) => !entry.hostOnly).sentCount, 1);
    assert.equal(Shared.instances.find((entry) => entry.hostOnly).sentCount, 0);
    assert.equal(Shared.instances.find((entry) => entry.scopeStatus === 'ambiguous').sentCount, 1);
    assert.equal(PartitionSample.instances.find((entry) => entry.partitioned).sentCount, 0);
    assert.equal(PartitionSample.instances.find((entry) => entry.scopeStatus === 'ambiguous').sentCount, 1);

    const rawIndex = JSON.parse(fs.readFileSync(recorder.attributionIndexPath, 'utf8'));
    assert.ok(Object.hasOwn(rawIndex.cookieLineage, '__proto__'));
    const report = queryProfileTraffic({ trafficDir, cookie: '__proto__' });
    assert.deepEqual(Object.keys(report.cookieLineage), ['__proto__']);
    assert.equal(report.cookie.sentCount, 1);
    assert.deepEqual(queryProfileTraffic({ trafficDir, cookies: true }).cookieLineage, summary.cookieLineage);

    for (const cookie of ['Sample', 'missing', '']) {
        const result = JSON.parse(execFileSync(process.execPath, [
            cliPath, `--profiles-dir=${profilesDir}`, '--profile=fixture', `--cookie=${cookie}`, '--json'
        ], { encoding: 'utf8' }));
        assert.deepEqual(Object.keys(result.cookieLineage), cookie === 'Sample' ? ['Sample'] : []);
        assert.equal(result.found, cookie === 'Sample');
        assert.equal(Object.hasOwn(result, 'allCookieLineage'), false);
        assert.doesNotMatch(JSON.stringify(result), /Ordinary|PartitionSample|__proto__/);
        if (cookie === 'Sample') assert.match(formatCliReport(result), /scope=unmatched/);
    }

    const resumed = new CamoufoxTrafficRecorder(options);
    assert.deepEqual((await resumed.stop()).cookieLineage, summary.cookieLineage);
});

test('recorder bounds repeated cookie history while the ledger keeps the complete lineage', async (t) => {
    const { recorder, context, trafficDir, options } = fixture(t);
    const url = 'https://repeat.test/';
    setCookie(context, url, ['Repeated=blue']);
    await recorder.flushSummary();
    const repeats = 270;
    for (let i = 0; i < repeats; i++) {
        setCookie(context, url, ['Repeated=blue', 'Repeated=blue'], { Cookie: 'Repeated=blue' });
        // Settle captures in batches so the fixture measures history retention.
        if ((i + 1) % 64 === 0) await recorder.flushSummary();
    }
    const summary = await recorder.stop();
    const ledger = events(recorder);
    const sent = ledger.filter((event) => event.type === 'egress' && event.cookieObservations.length > 0);
    const received = ledger.filter((event) => event.type === 'ingress');
    assert.equal(sent.length, repeats);
    assert.equal(received.length, repeats + 1);
    const recent = summary.cookieLineage.Repeated;
    assert.equal(recent.mutationsCount, 1);
    assert.equal(recent.sentCount, repeats);
    assert.equal(recent.valueHistory.length, 256);
    assert.equal(recent.valueHistoryOmittedCount, repeats + 1 - 256);
    assert.equal(recent.sentInCorrelationIds.length, 256);
    const complete = queryProfileTraffic({ trafficDir, cookie: 'Repeated' }).cookie;
    assert.equal(complete.valueHistory.length, repeats + 1);
    assert.equal(complete.valueHistoryOmittedCount, 0);
    assert.equal(complete.sentCount, repeats);
    assert.deepEqual(complete.sentInCorrelationIds, sent.map((event) => event.correlationId));
    assert.deepEqual(complete.valueHistory.map((entry) => entry.correlationId),
        received.map((event) => event.correlationId));
    assert.deepEqual(complete.valueHistory.slice(-256), recent.valueHistory);
    assert.deepEqual(complete.sentInCorrelationIds.slice(-256), recent.sentInCorrelationIds);
    assert.deepEqual((await new CamoufoxTrafficRecorder(options).stop()).cookieLineage.Repeated, recent);
});

test('security blocks, cookies, and platform correlations are projected from intact events', async (t) => {
    const { recorder, context, trafficDir } = fixture(t);
    const block = recorder.recordSecurityBlock({
        targetUrl: 'https://diagnostic.test/block', type: 'synthetic', reason: 'Fixture decision'
    });
    setCookie(context, 'https://diagnostic.test/signed', ['Tracked=blue'], {
        'X-Client-Transaction-Id': 'synthetic-observation'
    });
    context.emit('request', request('https://diagnostic.test/regular'));
    await recorder.stop();

    const before = queryProfileTraffic({ trafficDir, anomaliesOnly: true, status: 0 });
    assert.deepEqual(before.indexWarnings, []);
    assert.deepEqual(before.anomalies.map((anomaly) => anomaly.correlationId), [block.correlationId]);
    const [signed, regular] = events(recorder).filter((event) => event.type === 'egress');
    const baselineSignatures = queryProfileTraffic({ trafficDir, signatures: true, platform: 'twitter' });
    assert.equal(baselineSignatures.count, 1);
    assert.equal(baselineSignatures.signatures[0].correlationId, signed.correlationId);

    const index = JSON.parse(fs.readFileSync(recorder.attributionIndexPath, 'utf8'));
    index.anomaliesAndRiskSignals = [];
    index.cookieLineage = { CachedOnly: { name: 'CachedOnly', valueHistory: [] } };
    index.platformSignatures.signatures[0].correlationId = regular.correlationId;
    fs.writeFileSync(recorder.attributionIndexPath, JSON.stringify(index));

    assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);
    const anomalies = queryProfileTraffic({ trafficDir, anomaliesOnly: true, status: 0 });
    assert.deepEqual(anomalies.anomalies, before.anomalies);
    assert.match(formatCliReport(anomalies), /differs? from the traffic ledger/);
    const wire = queryProfileTraffic({ trafficDir, correlation: block.correlationId });
    assert.deepEqual(wire.anomalies, before.anomalies);
    assert.equal(wire.indexWarnings.length, 1);

    const report = queryProfileTraffic({ trafficDir, platform: 'twitter' });
    assert.deepEqual(report.transactions.map((transaction) => transaction.correlationId), [signed.correlationId]);
    assert.deepEqual(report.platformSignatures.signatures, baselineSignatures.signatures);
    assert.deepEqual(Object.keys(queryProfileTraffic({ trafficDir, cookies: true }).cookieLineage), ['Tracked']);
});

test('only the originating live frame can get an inferred trigger and its request keeps that snapshot', async (t) => {
    const { context, recorder, trafficDir } = fixture(t);
    const profileBinding = { context, trafficRecorder: recorder };
    function pageWithFrame(url, subframes = []) {
        const frame = { url: () => url };
        const page = Object.assign(new EventEmitter(), {
            context: () => context,
            mainFrame: () => frame,
            frames: () => [frame, ...subframes],
            url: frame.url,
            click: async () => {}
        });
        context.emit('page', page);
        return attachPageCompatibility(page, context, profileBinding);
    }
    const child = { url: () => 'https://child.test/' };
    const source = pageWithFrame('https://frontend.test/', [child]);
    const other = pageWithFrame('https://other.test/');
    const mainFrame = source.mainFrame();
    recorder.setStep('step-one');
    await source.click('#fixture-control');

    const pending = request('https://frontend.test/init', {}, mainFrame);
    let releaseHeaders;
    pending.headersArray = () => new Promise((resolve) => { releaseHeaders = resolve; });
    context.emit('request', pending);
    context.emit('request', request('https://other.test/background', {}, other.mainFrame()));
    context.emit('request', request('https://child.test/background', {}, child));
    context.emit('request', request('https://worker.test/background'));
    source.emit('framenavigated', mainFrame);
    context.emit('request', request('https://frontend.test/after-navigation', {}, mainFrame));

    recorder.setStep('step-two');
    await other.click('#other-control');
    context.emit('response', {
        request: () => pending, url: pending.url, status: () => 200, headersArray: async () => []
    });
    context.emit('requestfinished', pending);
    releaseHeaders([]);
    const scopedChild = recorder.recordTriggerAction('frame.click', '#child-control', {}, child);
    assert.ok(scopedChild.actionId);
    context.emit('request', request('https://child.test/with-action', {}, child));
    source.emit('framedetached', child);
    context.emit('request', request('https://child.test/after-detach', {}, child));
    const timed = other.recordTrafficTrigger('page.click', '#late-control');
    assert.equal(recorder.getActiveTriggerSnapshot(timed.epochMs + 31_000, other.mainFrame()), null);
    other.emit('close');
    context.emit('request', request('https://other.test/after-close', {}, other.mainFrame()));
    await recorder.stop();

    const records = events(recorder).filter((event) => event.correlationId);
    const attributed = records.filter((event) => event.triggerAction);
    assert.deepEqual(attributed.map((event) => event.triggerAction.target).sort(), [
        '#child-control', '#fixture-control', '#fixture-control', '#fixture-control'
    ].sort());
    assert.ok(attributed.every((event) => event.triggerAction.association === 'inferred'));
    assert.ok(attributed.filter((event) => event.triggerAction.target === '#fixture-control')
        .every((event) => event.attribution.actionStep === 'step-one'));
    assert.equal(queryProfileTraffic({ trafficDir, trigger: '#fixture-control' }).transactions.length, 1);
});
