import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
    evaluateWireToDomCoherence, readCoherenceCaptureEvents
} from '../../src/camoufox/coherence-auditor.js';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const supportsCaptureReads = process.platform === 'darwin' || process.platform === 'linux';

function fixture(t) {
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'diagnostic-io-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

test('only explicitly selected local capture roots supply coherence ledger files', { skip: !supportsCaptureReads }, (t) => {
    const root = fixture(t);
    const ledger = path.join(root, 'traffic.ndjson');
    const dom = { navigator: { userAgent: 'fixture user agent', language: 'en-US' } };
    const event = { type: 'egress', headers: { 'User-Agent': 'fixture user agent' } };
    fs.writeFileSync(ledger, JSON.stringify(event) + '\n');

    for (const imported of [{ trafficNdjsonPath: ledger }, { paths: { trafficNdjsonPath: ledger } }]) {
        assert.equal(evaluateWireToDomCoherence(dom, imported).inspectedRequests, 0);
    }
    assert.equal(evaluateWireToDomCoherence(dom, { events: [event] }).inspectedRequests, 1);
    assert.equal(evaluateWireToDomCoherence(dom, readCoherenceCaptureEvents(root)).inspectedRequests, 1);

    fs.truncateSync(ledger, 128 * 1024 * 1024 + 1);
    assert.throws(() => readCoherenceCaptureEvents(root), { code: 'ERR_CAPTURE_TOO_LARGE' });
    fs.renameSync(ledger, path.join(root, 'other.ndjson'));
    fs.symlinkSync('other.ndjson', ledger);
    assert.throws(() => readCoherenceCaptureEvents(root));
});

test('AdsPower audits valid caches alongside rejected entries and escapes every terminal row', { skip: !supportsCaptureReads }, (t) => {
    const root = fixture(t);
    const cache = path.join(root, 'cache');
    fs.mkdirSync(cache);
    const filename = (profile, kind) => createHash('md5').update(profile + '_' + kind).digest('hex');
    function makeEntry(profile, kind = 'static', parent = cache) {
        const dir = path.join(parent, profile + '_fixture');
        fs.mkdirSync(dir, { recursive: true });
        return path.join(dir, filename(profile, kind));
    }
    const config = JSON.stringify({
        Platform: 'MacIntel',
        DeviceName: 'Fixture\u001b[31m\r\nrow text\u2028unicode text',
        HardwareConcurrency: 10,
        DeviceMemory: 16,
        UserAgentMetadata: { architecture: 'arm\u0085separator', platformVersion: '13.6' }
    });
    const valid = makeEntry('valid');
    fs.writeFileSync(valid, config);
    fs.writeFileSync(makeEntry('valid', 'webgl'), JSON.stringify({ UNMASKED_RENDERER_WEBGL: 'Apple M2 Pro' }));
    fs.symlinkSync(valid, makeEntry('linkedfile'));
    const hardlinkTarget = path.join(root, 'fixture-original');
    fs.writeFileSync(hardlinkTarget, config);
    fs.linkSync(hardlinkTarget, makeEntry('hardlink'));
    const oversized = makeEntry('oversized');
    fs.writeFileSync(oversized, '');
    fs.truncateSync(oversized, 4 * 1024 * 1024 + 1);
    execFileSync('mkfifo', [makeEntry('pipe')]);
    const elsewhere = makeEntry('linkedprofile', 'static', root);
    fs.writeFileSync(elsewhere, config);
    fs.symlinkSync(path.dirname(elsewhere), path.join(cache, 'linkedprofile_fixture'), 'dir');

    const cli = path.join(repo, 'scripts', 'audit-adspower-profiles.js');
    const result = spawnSync(process.execPath, [cli, '--cache-dir=' + cache, '--heal'], {
        encoding: 'utf8',
        timeout: 5000
    });
    assert.equal(result.status, 0, result.error?.message || result.stderr);
    assert.match(result.stdout, /Audited Profiles: 1\b/);
    assert.match(result.stdout, /Unreadable or unsupported profile directories: 4\b/);
    assert.equal(result.stdout.split('\n').filter((row) => /^(?:✅ PASS|❌ FAIL)/.test(row)).length, 1);
    assert.match(result.stdout, /Fixture\\u\{1b\}\[31m\\u\{d\}\\u\{a\}row text\\u\{2028\}unicode text/);
    assert.match(result.stdout, /arm\\u\{85\}separator/);
    assert.doesNotMatch(result.stdout, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]/u);
    assert.doesNotMatch(result.stdout, /(?:valid|hardlink)_fixture/);
    const noRoot = spawnSync(process.execPath, [cli], { encoding: 'utf8', timeout: 5000 });
    assert.equal(noRoot.status, 1);
    assert.match(noRoot.stderr, /--cache-dir=/);
});

test('standalone native logging opts in, excludes inherited destinations and rejects capture aliases', async (t) => {
    const { CamoufoxTrafficRecorder } = await import('../../src/camoufox/traffic-recorder.js');
    const root = fixture(t);
    const trafficDir = path.join(root, 'standalone');
    const settings = { trafficDir, recordWireLog: false, trustedLocal: true };
    const disabled = new CamoufoxTrafficRecorder(settings);
    const capturePath = path.join(trafficDir, 'raw.log');
    const inherited = {
        SSLKEYLOGFILE: capturePath,
        MOZ_LOG: 'nsHttp:5',
        MOZ_LOG_FILE: capturePath,
        NSPR_LOG_MODULES: 'nsHttp:5',
        NSPR_LOG_FILE: capturePath
    };
    assert.equal(disabled.sslKeyLogPath, null);
    assert.equal(disabled.neckoMozLogPath, null);
    const safeEnv = disabled.getLaunchEnv(inherited);
    for (const key of Object.keys(inherited)) assert.equal(safeEnv[key], '');
    assert.equal(fs.existsSync(disabled.profileNativeDir), false);
    await disabled.stop();

    const enabled = new CamoufoxTrafficRecorder({ ...settings, sslKeyLog: true, neckoMozLog: true });
    assert.equal(path.dirname(enabled.sslKeyLogPath), enabled.profileNativeDir);
    assert.equal(path.dirname(enabled.neckoMozLogPath), enabled.profileNativeDir);
    assert.equal(path.dirname(enabled.profileNativeDir), root);
    assert.equal(enabled.getLaunchEnv(inherited).MOZ_LOG_FILE, enabled.neckoMozLogPath);
    assert.equal(enabled.getLaunchEnv(inherited).SSLKEYLOGFILE, enabled.sslKeyLogPath);
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(enabled.profileNativeDir).mode & 0o777, 0o700);
        assert.equal(fs.statSync(enabled.neckoMozLogPath).mode & 0o777, 0o600);
    }
    await enabled.stop();
    assert.throws(() => new CamoufoxTrafficRecorder({ ...settings, sslKeyLogPath: capturePath }), /outside/);
    if (supportsCaptureReads) {
        const alias = path.join(root, 'alias');
        fs.symlinkSync(trafficDir, alias, 'dir');
        assert.throws(() => new CamoufoxTrafficRecorder({
            ...settings, neckoMozLogPath: path.join(alias, 'raw.log')
        }), /outside/);
    }
    assert.equal(fs.existsSync(capturePath), false);
});

test('Camoufox diagnostic separates temporary reports and publishes persistent reports privately', (t) => {
    const root = fixture(t);
    const stateDir = path.join(root, 'state');
    const temporaryDir = path.join(root, 'temporary');
    fs.mkdirSync(stateDir);
    fs.mkdirSync(temporaryDir);
    const reportName = 'camoufox-audit-report.json';
    const existingReports = [path.join(root, reportName), path.join(stateDir, reportName)];
    for (const report of existingReports) fs.writeFileSync(report, 'original diagnostic fixture');

    const script = path.join('scripts', 'verify-camoufox-coherence.js');
    const sources = [
        script,
        'src/camoufox/capture-io.js',
        'src/camoufox/coherence-auditor.js',
        'src/camoufox/device-presets.js',
        'src/camoufox/gpu-performance-scaler.js',
        'src/camoufox/hardware-models.js',
        'src/camoufox/network-policy.js',
        'src/camoufox/sdk-resolution.js',
        'src/camoufox/traffic-redaction.js',
        'src/camoufox/ziniao-security.js',
        'src/utils/logger.js',
        'src/utils/private-storage.js',
        'src/utils/state-paths.js'
    ];
    for (const source of sources) {
        const origin = path.join(repo, source);
        const target = path.join(root, source);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(origin, target);
    }
    fs.writeFileSync(path.join(root, 'package.json'), '{"type":"module"}');
    const sdk = path.join(root, 'node_modules', 'camoufox');
    fs.mkdirSync(sdk, { recursive: true });
    fs.writeFileSync(path.join(sdk, 'package.json'), '{"type":"module","exports":"./index.js"}');
    fs.writeFileSync(path.join(sdk, 'index.js'), 'throw new Error("Unexpected SDK evaluation");');
    for (const module of ['src/config.js', 'src/camoufox/profile.js']) {
        fs.writeFileSync(path.join(root, module), 'throw new Error("Unexpected live module import");');
    }

    const runDiagnostic = (...options) => spawnSync(process.execPath, [path.join(root, script), '--os=windows', ...options], {
        encoding: 'utf8',
        timeout: 5000,
        env: {
            ...process.env,
            TMPDIR: temporaryDir,
            TMP: temporaryDir,
            TEMP: temporaryDir,
            GMAIL_CREATOR_STATE_DIR: stateDir
        }
    });
    const run = runDiagnostic('--dry-run');
    assert.equal(run.status, 0, run.error?.message || run.stderr + run.stdout);
    for (const report of existingReports) assert.equal(fs.readFileSync(report, 'utf8'), 'original diagnostic fixture');
    const [directory] = fs.readdirSync(temporaryDir);
    assert.match(directory, /^camoufox-audit-/);
    const reportFile = path.join(temporaryDir, directory, reportName);
    const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    assert.equal(report.results[0].mode, 'dry-run-synthetic');
    assert.equal(report.environment.camoufoxSdkInstalled, true);
    assert.equal(report.results[0].auditReport.telemetry.gpuPerformance.hostBaseline.hostChipModel, 'Synthetic fixture');
    assert.equal(Object.hasOwn(report.environment, 'camoufoxConfig'), false);
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(path.dirname(reportFile)).mode & 0o777, 0o700);
        assert.equal(fs.statSync(reportFile).mode & 0o777, 0o600);
    }
    const check = runDiagnostic('--check-env');
    assert.equal(check.status, 0, check.error?.message || check.stderr + check.stdout);
    assert.equal(fs.readdirSync(temporaryDir).length, 2);
    for (const persistent of existingReports) assert.equal(fs.readFileSync(persistent, 'utf8'), 'original diagnostic fixture');

    // Supply a synthetic browser session to exercise the persistent report path.
    fs.writeFileSync(path.join(root, 'src', 'config.js'), 'export {};');
    const telemetry = JSON.stringify(report.results[0].auditReport.telemetry);
    fs.writeFileSync(path.join(root, 'src', 'camoufox', 'profile.js'),
        `export async function createAndStartProfile() {
            return { getPage: () => ({ evaluate: () => (${telemetry}) }), stop: async () => {} };
        }`);

    const simulated = runDiagnostic();
    assert.equal(simulated.status, 0, simulated.error?.message || simulated.stderr + simulated.stdout);
    const persistentReport = path.join(stateDir, reportName);
    const persisted = fs.readFileSync(persistentReport, 'utf8');
    assert.equal(JSON.parse(persisted).results[0].mode, 'live-browser');
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(persistentReport).mode & 0o777, 0o600);
        const other = path.join(root, 'synthetic-report-target');
        fs.renameSync(persistentReport, other);
        fs.symlinkSync(other, persistentReport);
        const rejected = runDiagnostic();
        assert.equal(rejected.status, 1);
        assert.match(rejected.stderr, /Capture export destination must be an ordinary file/);
        assert.equal(fs.readFileSync(other, 'utf8'), persisted);
        assert.ok(fs.lstatSync(persistentReport).isSymbolicLink());
    }
});
