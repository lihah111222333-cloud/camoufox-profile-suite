import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
    evaluatePlatformCoherence, evaluateWireToDomCoherence, readCoherenceCaptureEvents
} from '../../src/camoufox/coherence-auditor.js';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const supportsCaptureReads = process.platform === 'darwin' || process.platform === 'linux';

function fixture(t) {
    const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'diagnostic-io-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

test('WebRTC and wire coherence require observations', () => {
    const dom = { navigator: { userAgent: 'fixture user agent', language: 'en-US' } };
    for (const webrtc of [undefined, { available: true }, { available: false }, {
        available: true, candidateIps: [], candidatePorts: [], privateIpLeaked: false
    }, { candidateIps: ['203.0.113.45'] }]) {
        const result = evaluatePlatformCoherence({ ...dom, webrtc }, 'windows');
        const check = result.checks.find(({ name }) => name === 'webrtc-network-coherence');
        assert.equal(check.passed, false);
        assert.equal(check.status, 'not-tested');
    }

    for (const events of [[], [{ type: 'egress', headers: {} }], [{ type: 'ingress', headers: { Accept: '*/*' } }]]) {
        const result = evaluateWireToDomCoherence(dom, events);
        assert.equal(result.status, 'not-tested');
        assert.equal(result.passed, false);
        assert.equal(result.score, null);
        assert.equal(result.inspectedRequests, 0);
        assert.ok(result.checks.every(({ status }) => status === 'not-tested'));
    }

    const event = { type: 'egress', headers: { 'User-Agent': dom.navigator.userAgent } };
    const partial = evaluateWireToDomCoherence(dom, [event]);
    assert.equal(partial.status, 'incomplete');
    assert.equal(partial.passed, false);
    assert.equal(partial.inspectedRequests, 1);
    assert.equal(partial.checks.find(({ name }) => name === 'wire-accept-language-matches-dom').status, 'not-tested');

    event.headers['Accept-Language'] = dom.navigator.language;
    const measured = evaluateWireToDomCoherence(dom, [event]);
    assert.equal(measured.status, 'passed');
    assert.equal(measured.score, 100);
    const missingHeaders = evaluateWireToDomCoherence(dom, [event, { type: 'egress' }]);
    assert.equal(missingHeaders.passed, false);
    assert.equal(missingHeaders.inspectedRequests, 1);
});

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
    const safeEnv = disabled.getLaunchEnv({
        ...inherited,
        PATH: '/synthetic/browser/runtime',
        GOOGLE_APPLICATION_CREDENTIALS: '/synthetic/private/application.json',
        SMS_VERIFY_API_KEY: 'synthetic-local-key',
        HTTP_PROXY: 'http://synthetic-proxy.invalid:8080'
    });
    for (const key of Object.keys(inherited)) assert.equal(safeEnv[key], '');
    assert.equal(safeEnv.PATH, '/synthetic/browser/runtime');
    for (const key of ['GOOGLE_APPLICATION_CREDENTIALS', 'SMS_VERIFY_API_KEY', 'HTTP_PROXY']) {
        assert.equal(Object.hasOwn(safeEnv, key), false);
    }
    const parentKey = 'CAMOUFOX_DIAGNOSTIC_TEST_PRIVATE_TOKEN';
    const previous = process.env[parentKey];
    process.env[parentKey] = 'synthetic-parent-token';
    try {
        assert.equal(Object.hasOwn(disabled.getLaunchEnv(), parentKey), false);
        assert.equal(disabled.getLaunchEnv().PATH, process.env.PATH);
    } finally {
        if (previous === undefined) delete process.env[parentKey];
        else process.env[parentKey] = previous;
    }
    assert.equal(fs.existsSync(disabled.profileNativeDir), false);
    await disabled.stop();

    const enabled = new CamoufoxTrafficRecorder({ ...settings, sslKeyLog: true, neckoMozLog: true });
    assert.equal(path.dirname(enabled.sslKeyLogPath), enabled.profileNativeDir);
    assert.equal(path.dirname(enabled.neckoMozLogPath), enabled.profileNativeDir);
    assert.equal(path.dirname(enabled.profileNativeDir), root);
    assert.equal(enabled.getLaunchEnv(inherited).MOZ_LOG_FILE, enabled.neckoMozLogPath);
    assert.equal(enabled.getLaunchEnv(inherited).SSLKEYLOGFILE, enabled.sslKeyLogPath);
    assert.equal(enabled.getLaunchEnv(inherited).MOZ_LOG, inherited.MOZ_LOG);
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

test('Camoufox diagnostic separates live evidence, unavailable data, and synthetic reports', (t) => {
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
    for (const module of ['src/config.js', 'src/camoufox/profile.js']) {
        fs.writeFileSync(path.join(root, module), 'throw new Error("Unexpected live module import");');
    }

    const runDiagnostic = (...options) => spawnSync(process.execPath, [path.join(root, script), '--os=windows', ...options], {
        cwd: root,
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
    function runWithTemporaryReport(...options) {
        const existing = new Set(fs.readdirSync(temporaryDir));
        const run = runDiagnostic(...options);
        const [directory, ...other] = fs.readdirSync(temporaryDir).filter((name) => !existing.has(name));
        assert.match(directory ?? '', /^camoufox-audit-/, run.error?.message || run.stderr + run.stdout);
        assert.equal(other.length, 0);
        const reportFile = path.join(temporaryDir, directory, reportName);
        return { run, reportFile, report: JSON.parse(fs.readFileSync(reportFile, 'utf8')) };
    }

    const missingSdk = runWithTemporaryReport();
    assert.equal(missingSdk.run.status, 1);
    assert.match(missingSdk.run.stdout, /Live browser audit: NOT TESTED/);
    assert.equal(missingSdk.report.environment.camoufoxSdkInstalled, false);
    assert.equal(missingSdk.report.overallStatus, 'not-tested');
    assert.equal(missingSdk.report.overallPassed, false);
    assert.equal(missingSdk.report.negativeControl, null);
    assert.deepEqual(missingSdk.report.results[0], {
        targetOs: 'windows', mode: 'live-browser-unavailable', status: 'not-tested', passed: false,
        unavailableReason: 'Camoufox SDK is unavailable', auditReport: null
    });

    const sdk = path.join(root, 'node_modules', 'camoufox');
    fs.mkdirSync(sdk, { recursive: true });
    fs.writeFileSync(path.join(sdk, 'package.json'), '{"type":"module","exports":"./index.js"}');
    fs.writeFileSync(path.join(sdk, 'index.js'), 'throw new Error("Unexpected SDK evaluation");');
    const { run, reportFile, report } = runWithTemporaryReport('--dry-run');
    assert.equal(run.status, 0, run.error?.message || run.stderr + run.stdout);
    assert.match(run.stdout, /Synthetic rule verification: PASS/);
    assert.equal(report.overallStatus, 'passed');
    assert.equal(report.results[0].mode, 'dry-run-synthetic');
    assert.equal(report.environment.camoufoxSdkInstalled, true);
    assert.equal(report.results[0].auditReport.telemetry.gpuPerformance.hostBaseline.hostChipModel, 'Synthetic fixture');
    assert.equal(Object.hasOwn(report.environment, 'camoufoxConfig'), false);
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(path.dirname(reportFile)).mode & 0o777, 0o700);
        assert.equal(fs.statSync(reportFile).mode & 0o777, 0o600);
    }
    const check = runWithTemporaryReport('--check-env');
    assert.equal(check.run.status, 0, check.run.error?.message || check.run.stderr + check.run.stdout);
    assert.equal(check.report.results[0].mode, 'dry-run-synthetic');

    fs.writeFileSync(path.join(root, 'src', 'config.js'), 'export {};');
    const profile = path.join(root, 'src', 'camoufox', 'profile.js');
    fs.writeFileSync(profile, 'export async function createAndStartProfile() { throw new Error("Startup unavailable"); }');
    const startupFailure = runWithTemporaryReport();
    assert.equal(startupFailure.run.status, 1);
    assert.equal(startupFailure.report.overallStatus, 'not-tested');
    assert.equal(startupFailure.report.results[0].auditReport, null);

    function useMockPage(evaluate) {
        fs.writeFileSync(profile, `export async function createAndStartProfile() {
            return { getPage: () => ({ evaluate: ${evaluate} }), stop: async () => {} };
        }`);
    }
    useMockPage('() => { throw new Error("No evidence collected"); }');
    const collectionFailure = runWithTemporaryReport();
    assert.equal(collectionFailure.run.status, 1);
    assert.equal(collectionFailure.report.overallStatus, 'not-tested');
    assert.equal(collectionFailure.report.results[0].auditReport, null);

    useMockPage('() => ({})');
    const noEvidence = runWithTemporaryReport();
    assert.equal(noEvidence.run.status, 1);
    assert.equal(noEvidence.report.overallStatus, 'not-tested');
    assert.equal(noEvidence.report.results[0].auditReport.score, null);
    assert.equal(noEvidence.report.results[0].auditReport.telemetry, null);
    for (const persistent of existingReports) assert.equal(fs.readFileSync(persistent, 'utf8'), 'original diagnostic fixture');

    // Mock browser output so no SDK or browser code runs in this test.
    const telemetry = report.results[0].auditReport.telemetry;
    const persistentReport = path.join(stateDir, reportName);
    useMockPage(`() => (${JSON.stringify({ ...telemetry, webrtc: { available: true } })})`);
    const incomplete = runDiagnostic();
    assert.equal(incomplete.status, 1);
    assert.match(incomplete.stdout, /Not tested: webrtc-network-coherence/);
    const incompleteReport = JSON.parse(fs.readFileSync(persistentReport, 'utf8'));
    assert.equal(incompleteReport.overallStatus, 'incomplete');
    assert.equal(incompleteReport.results[0].mode, 'live-browser');

    useMockPage(`() => (${JSON.stringify(telemetry)})`);
    const simulated = runDiagnostic();
    assert.equal(simulated.status, 0, simulated.error?.message || simulated.stderr + simulated.stdout);
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
