import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    CamoufoxTrafficRecorder, selectProfileNativeLogPaths, verifyTrafficIntegrity
} from '../../src/camoufox/traffic-recorder.js';

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

test('Necko generation selection preserves previously unassigned child logs', async (t) => {
    const cases = [
        { label: 'retained child without parent', name: nativeName, child: '.child-1' },
        {
            label: 'retained child at a supported rotated path',
            name: nativeName + '.generation-00000000-0000-4000-8000-000000000001',
            child: '.child-2.0'
        },
        { label: 'retained empty parent and child', name: nativeName, child: '.child-1', hasParent: true },
        { label: 'first recording with no historical logs', name: nativeName }
    ];

    for (const { label, name, child, hasParent } of cases) {
        await t.test(label, async (t) => {
            const { nativeDir, trafficDir, indexPath, create, verify } = fixture(t);
            const selectedPath = path.join(nativeDir, name);
            const historicalChild = selectedPath + (child ?? '');
            const historicalRequest = nativeRequest.replace('/synthetic', '/historical');
            if (child) {
                fs.mkdirSync(nativeDir, { mode: 0o700 });
                fs.writeFileSync(historicalChild, historicalRequest, { mode: 0o600 });
            }
            if (hasParent) fs.writeFileSync(selectedPath, '', { mode: 0o600 });

            const nativeOnly = selectProfileNativeLogPaths(trafficDir, nativeDir, { neckoMozLogPath: selectedPath });
            assert.equal(nativeOnly.neckoMozLogPath !== selectedPath, Boolean(child));
            assert.equal(fs.existsSync(indexPath), false);
            const recorder = create({ neckoMozLogPath: selectedPath });
            assert.equal(recorder.neckoMozLogPath !== selectedPath, Boolean(child));
            assert.equal((await recorder.flushSummary()).neckoMozLog.requestBlockCount, 0);

            const currentChild = recorder.neckoMozLogPath + '.child-1';
            fs.writeFileSync(currentChild, nativeRequest, { mode: 0o600 });
            const final = await recorder.stop();
            const artifact = final.integrity.nativeArtifacts.neckoMozLog;
            assert.equal(final.neckoMozLog.requestBlockCount, 1);
            assert.equal(artifact.closed, true);
            assert.deepEqual(artifact.children.map(({ file }) => file), [path.basename(currentChild)]);

            const verdict = verify();
            assert.equal(verdict.valid, true);
            assert.deepEqual(verdict.unverifiedNativeArtifacts, child
                ? [...(hasParent ? [name] : []), path.basename(historicalChild)] : []);
            if (child) assert.equal(fs.readFileSync(historicalChild, 'utf8'), historicalRequest);
        });
    }
});

test('native capture rejects grant ACLs on its directory and on newly created children', {
    skip: process.platform !== 'darwin'
}, async (t) => {
    const { nativeDir, create, indexPath, verify } = fixture(t);
    fs.mkdirSync(nativeDir, { mode: 0o700 });
    execFileSync('/bin/chmod', ['+a', 'group:everyone allow list,search,file_inherit', nativeDir]);
    assert.throws(() => create(), { code: 'PRIVATE_STORAGE_ACL_ERROR' });
    assert.deepEqual(fs.readdirSync(nativeDir), []);

    execFileSync('/bin/chmod', ['-N', nativeDir]);
    const recorder = create();
    await recorder.flushSummary();
    const checkpoint = fs.readFileSync(indexPath);
    const child = recorder.neckoMozLogPath + '.child-1';
    fs.writeFileSync(child, nativeRequest, { mode: 0o600 });
    execFileSync('/bin/chmod', ['+a', 'group:everyone allow read', child]);

    await assert.rejects(recorder.flushSummary(), { code: 'PRIVATE_STORAGE_ACL_ERROR' });
    assert.deepEqual(fs.readFileSync(indexPath), checkpoint);
    assert.equal(fs.readFileSync(child, 'utf8'), nativeRequest);

    execFileSync('/bin/chmod', ['-N', child]);
    execFileSync('/bin/chmod', ['+a', 'group:everyone deny delete', child]);
    try {
        const closed = await recorder.stop();
        assert.equal(closed.integrity.nativeArtifacts.neckoMozLog.closed, true);
        assert.equal(closed.neckoMozLog.requestBlockCount, 1);
        assert.equal(verify().valid, true);
        assert.match(execFileSync('/bin/ls', ['-led', child], { encoding: 'utf8' }), /everyone deny delete/);
    } finally {
        execFileSync('/bin/chmod', ['-N', child]);
    }
});

test('an archived malformed NSS generation remains invalid after recording a new generation', async (t) => {
    const { create, verify } = fixture(t, { sslKeyLog: true, neckoMozLog: false });
    const first = create();
    fs.appendFileSync(first.sslKeyLogPath, 'synthetic-incomplete-line');
    await first.stop();
    assert.equal(verify().valid, false);
    const retained = fs.readFileSync(first.sslKeyLogPath);

    const second = create();
    assert.notEqual(second.sslKeyLogPath, first.sslKeyLogPath);
    await second.stop();
    assert.deepEqual(fs.readFileSync(first.sslKeyLogPath), retained);

    const verdict = verify();
    assert.equal(verdict.valid, false);
    assert.equal(verdict.sslKeyLog.malformedLineCount, 0);
    assert.deepEqual(verdict.unverifiedNativeArtifacts, []);
    assert.deepEqual(verdict.errors, ['Archived NSS key log sslkeylog.txt contains 1 malformed line(s)']);
});

test('oversized external native logs stay unverified without blocking a final summary', async (t) => {
    const { create, root, verify } = fixture(t);
    const externalDir = path.join(root, 'external');
    const neckoMozLogPath = path.join(externalDir, 'necko.log');
    const sslKeyLogPath = path.join(externalDir, 'nss.log');
    const recorder = create({ neckoMozLogPath, sslKeyLogPath });
    recorder.recordNeckoMozLogBlock(nativeRequest);
    assert.equal((await recorder.flushSummary()).neckoMozLog.requestBlockCount, 1);

    const bytes = 128 * 1024 * 1024 + 1;
    for (const log of [neckoMozLogPath, sslKeyLogPath]) fs.truncateSync(log, bytes);
    const final = await recorder.stop();

    assert.ok(final.session.endedAt);
    assert.equal(final.integrity.nativeArtifacts, undefined);
    for (const [kind, log] of [['neckoMozLog', neckoMozLogPath], ['sslKeyLog', sslKeyLogPath]]) {
        assert.equal(final[kind].exists, true);
        assert.equal(final[kind].bytes, bytes);
        assert.equal(final[kind].scope, 'external-file');
        assert.equal(final[kind].diagnosticsOmitted, 'size-limit');
        assert.equal(final[kind].sha256, null);
        assert.equal(final.artifacts[kind + 'Path'], null);
        assert.equal(fs.statSync(log).size, bytes);
    }
    assert.deepEqual(verify().unverifiedNativeArtifacts, [
        'sslkeylog.txt (external log)',
        'necko-pre-tls.moz_log (external log)'
    ]);
});
