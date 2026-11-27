import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CamoufoxTrafficRecorder, verifyTrafficIntegrity } from '../../src/camoufox/traffic-recorder.js';

const nativeRequest = 'http request [\nGET /synthetic HTTP/1.1\nHost: fixture.invalid\n]\n';
const nativeName = 'necko-pre-tls.moz_log';

function fixture(t, options = {}) {
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'native-evidence-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const trafficDir = path.join(root, 'traffic');
    const nativeDir = path.join(root, '.native');
    return {
        root,
        nativeDir,
        trafficDir,
        indexPath: path.join(trafficDir, 'attribution-index.json'),
        create: (overrides = {}) => new CamoufoxTrafficRecorder({
            trafficDir,
            profileNativeDir: nativeDir,
            recordWireLog: false,
            neckoMozLog: true,
            trustedLocal: true,
            ...options,
            ...overrides
        }),
        verify: () => verifyTrafficIntegrity(trafficDir, { nativeDir, trustedLocal: true })
    };
}

test('a checkpointed Necko child that is missing before stop remains in the incomplete index', async (t) => {
    const { create, indexPath, verify } = fixture(t);
    const recorder = create();
    const child = recorder.neckoMozLogPath + '.child-1';
    fs.writeFileSync(child, nativeRequest, { mode: 0o600 });
    const recorded = await recorder.flushSummary();
    assert.equal(recorded.neckoMozLog.requestBlockCount, 1);
    assert.equal(recorded.integrity.nativeArtifacts.neckoMozLog.children[0].file, path.basename(child));
    const checkpoint = fs.readFileSync(indexPath);

    fs.unlinkSync(child);
    await assert.rejects(recorder.flushSummary(), /Missing necko-pre-tls\.moz_log\.child-1 on disk/);
    await assert.rejects(recorder.stop(), /Missing necko-pre-tls\.moz_log\.child-1 on disk/);
    assert.deepEqual(fs.readFileSync(indexPath), checkpoint);
    const incomplete = verify();
    assert.equal(incomplete.valid, false);
    assert.ok(incomplete.errors.some((error) => error.includes('Missing')));

    fs.writeFileSync(child, nativeRequest, { mode: 0o600 });
    const reopened = create();
    assert.notEqual(reopened.neckoMozLogPath, recorder.neckoMozLogPath);
    const final = await reopened.stop();
    assert.equal(final.integrity.nativeArtifacts.neckoMozLog.previous[0].children[0].file, path.basename(child));
    assert.equal(verify().valid, true);
});

test('unconfirmed exit retains the latest native checkpoint instead of the initial empty one', async (t) => {
    let nativeExit = false;
    const { create, verify } = fixture(t, { nativeLogsAreClosed: () => nativeExit });
    const recorder = create();
    await recorder.flushSummary();
    const child = recorder.neckoMozLogPath + '.child-1';
    fs.writeFileSync(child, nativeRequest, { mode: 0o600 });
    await recorder.flushSummary();

    fs.unlinkSync(child);
    nativeExit = null;
    const stopped = await recorder.stop();
    const artifact = stopped.integrity.nativeArtifacts.neckoMozLog;
    assert.equal(artifact.closed, false);
    assert.equal(artifact.children[0].file, path.basename(child));
    assert.equal(verify().valid, false);
});

test('unsupported native names are rejected before writing and historical unknown files remain unverified', async (t) => {
    const { create, nativeDir, trafficDir, indexPath, verify } = fixture(t);
    fs.mkdirSync(nativeDir, { mode: 0o700 });
    const custom = path.join(nativeDir, 'historical-private-note.log');
    fs.writeFileSync(custom, nativeRequest, { mode: 0o600 });

    assert.throws(() => create({ neckoMozLogPath: custom }), /supported filename directly/);
    assert.throws(() => create({
        sslKeyLog: true, sslKeyLogPath: path.join(nativeDir, 'custom-tls.log')
    }), /supported filename directly/);
    assert.equal(fs.existsSync(trafficDir), false);
    assert.equal(fs.readFileSync(custom, 'utf8'), nativeRequest);

    const supported = path.join(nativeDir, nativeName);
    const first = create({ neckoMozLogPath: supported });
    first.recordNeckoMozLogBlock(nativeRequest);
    await first.stop();
    const second = create({ neckoMozLogPath: supported });
    second.recordNeckoMozLogBlock(nativeRequest);
    const final = await second.stop();
    assert.notEqual(second.neckoMozLogPath, first.neckoMozLogPath);
    assert.equal(final.neckoMozLog.requestBlockCount, 1);
    assert.equal(final.integrity.nativeArtifacts.neckoMozLog.previous.length, 1);
    assert.deepEqual(verify().unverifiedNativeArtifacts, ['unclassified file in profile native directory']);
    assert.equal(fs.readFileSync(custom, 'utf8'), nativeRequest);

    const legacy = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
    delete legacy.integrity.nativeArtifacts;
    fs.writeFileSync(indexPath, JSON.stringify(legacy));
    assert.deepEqual(verifyTrafficIntegrity(trafficDir).unverifiedNativeArtifacts,
        ['necko-pre-tls.moz_log (untracked historical log)']);
});

test('an explicitly selected external native log is visible as unverified beside verified generations', async (t) => {
    const { create, root, verify } = fixture(t);
    const owned = create();
    await owned.stop();

    const external = path.join(root, 'separate-private-directory', 'external-diagnostic.log');
    const recorder = create({ neckoMozLogPath: external });
    recorder.recordNeckoMozLogBlock(nativeRequest);
    const final = await recorder.stop();
    assert.equal(final.neckoMozLog.requestBlockCount, 1);
    assert.equal(final.neckoMozLog.scope, 'external-file');
    assert.equal(final.artifacts.neckoMozLogPath, null);
    assert.equal(final.integrity.nativeArtifacts.neckoMozLog.file, path.basename(owned.neckoMozLogPath));

    const verdict = verify();
    assert.equal(verdict.valid, true);
    assert.deepEqual(verdict.unverifiedNativeArtifacts, ['necko-pre-tls.moz_log (external log)']);
    assert.equal(fs.readFileSync(external, 'utf8'), nativeRequest);
});
