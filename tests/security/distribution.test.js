import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
    appendAccountResult, migrateExistingAccountOutputs, writeRunSummary
} from '../../src/utils/account-results.js';
import {
    appendPrivateFile, ensurePrivateDirectory, readPrivateFile, restrictPrivateFile, writePrivateFile
} from '../../src/utils/private-storage.js';

const PROJECT = fileURLToPath(new URL('../../', import.meta.url));
const FAKE_PASSWORD = 'fake-account-password';
const FAKE_PROXY = 'http://fake-proxy-user:fake-proxy-password@192.0.2.1:8080';
const FAKE_CODE = '000000';
const FAKE_MESSAGE = 'fake provider response with confidential data';
const GPU_TELEMETRY = { targetGpuModel: 'fixture target GPU', antiPenetrationActive: true };
const LEGACY_GPU_TELEMETRY = {
    ...GPU_TELEMETRY,
    hostChipModel: 'fixture host CPU',
    computeTimeMultiplier: 1.25,
    throughputSpeedupRatio: 0.8,
    hostBaseline: { cpuBenchmark: 12345 }
};

function temporaryDirectory(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-distribution-test-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    return directory;
}

function visibleMode(filePath) {
    return fs.statSync(filePath).mode & 0o777;
}

function copyProjectFile(directory, relativeFile) {
    const destination = path.join(directory, relativeFile);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(PROJECT, relativeFile), destination);
}

function assertNoFakeCredentials(text) {
    for (const value of [FAKE_PASSWORD, 'fake-proxy-user', 'fake-proxy-password', FAKE_CODE, FAKE_MESSAGE]) {
        assert.ok(!text.includes(value));
    }
}

test('account result rewrites project historical and new results and tighten file permissions', (t) => {
    const output = path.join(temporaryDirectory(t), 'results.json');
    fs.writeFileSync(output, JSON.stringify([
        {
            success: true,
            email: 'old@example.test',
            timestamp: '2026-01-01T00:00:00.000Z',
            password: FAKE_PASSWORD,
            proxy: FAKE_PROXY,
            phoneCode: FAKE_CODE,
            proxyIP: '192.0.2.1',
            trafficAttribution: {
                trafficNdjsonPath: '/fixture/traffic.ndjson',
                sslKeyLogPath: '/fixture/.native/sslkeylog.txt',
                neckoMozLogPath: '/fixture/.native/necko-pre-tls.moz_log',
                rawProxy: FAKE_PROXY
            },
            camoufoxTelemetry: {
                gpuPerformance: LEGACY_GPU_TELEMETRY,
                securityGuards: {
                    blockedPortScanCount: 1,
                    blockedPortScans: [{ details: FAKE_PROXY }]
                }
            }
        },
        {
            success: false,
            profileType: 'GPM Login',
            profileCleanup: 'allocation-unconfirmed',
            error: FAKE_MESSAGE,
            errorCode: 'PROFILE_ALLOCATION_UNCONFIRMED'
        }
    ]));
    if (process.platform !== 'win32') {
        fs.chmodSync(output, 0o644);
    }

    const oldFile = fs.openSync(output, 'r');
    try {
        appendAccountResult(output, {
            success: true,
            email: 'new@example.test',
            password: FAKE_PASSWORD,
            proxy: FAKE_PROXY,
            proxyIP: '[2001:db8::8]',
            profileIP: '2001:db8::9',
            phoneCode: FAKE_CODE,
            camoufoxTelemetry: { gpuPerformance: LEGACY_GPU_TELEMETRY }
        });
        if (process.platform !== 'win32') {
            assert.equal(fs.fstatSync(oldFile).mode & 0o777, 0o600);
            assert.equal(visibleMode(output), 0o600);
        }
    } finally {
        fs.closeSync(oldFile);
    }

    const saved = fs.readFileSync(output, 'utf8');
    assertNoFakeCredentials(saved);
    const [old, failure, current] = JSON.parse(saved);
    assert.equal(old.email, 'old@example.test');
    assert.equal(old.timestamp, '2026-01-01T00:00:00.000Z');
    assert.equal(old.proxyIP, '192.0.2.1');
    assert.deepEqual(old.trafficAttribution, { trafficNdjsonPath: '/fixture/traffic.ndjson' });
    assert.deepEqual(old.camoufoxTelemetry.gpuPerformance, GPU_TELEMETRY);
    assert.deepEqual(old.camoufoxTelemetry.securityGuards, { blockedPortScanCount: 1 });
    assert.deepEqual(failure, {
        success: false,
        profileType: 'GPM Login',
        profileCleanup: 'allocation-unconfirmed',
        error: 'Managed profile allocation is unconfirmed',
        errorCode: 'PROFILE_ALLOCATION_UNCONFIRMED'
    });
    assert.equal(current.email, 'new@example.test');
    assert.equal(current.proxyIP, '[2001:db8::8]');
    assert.equal(current.profileIP, '2001:db8::9');
    assert.deepEqual(current.camoufoxTelemetry.gpuPerformance, GPU_TELEMETRY);
    assert.ok(Number.isFinite(Date.parse(current.createdAt)));
});

test('invalid history is retained privately and its contents stay out of errors', (t) => {
    const output = path.join(temporaryDirectory(t), 'results.json');
    const invalid = `{ ${FAKE_PASSWORD}`;
    fs.writeFileSync(output, invalid);
    if (process.platform !== 'win32') {
        fs.chmodSync(output, 0o644);
    }
    assert.throws(() => appendAccountResult(output, { success: true }), {
        message: 'Account results file contains invalid JSON'
    });
    assert.equal(fs.readFileSync(output, 'utf8'), invalid);
    if (process.platform !== 'win32') {
        assert.equal(visibleMode(output), 0o600);
    }
});

test('startup projects existing results and summary without creating missing files', (t) => {
    const directory = temporaryDirectory(t);
    const results = path.join(directory, 'results.json');
    const summary = path.join(directory, 'summary.json');
    migrateExistingAccountOutputs(results, summary);
    assert.deepEqual(fs.readdirSync(directory), []);

    const oldRecord = {
        success: true,
        email: 'existing@example.test',
        profileId: 'existing-profile',
        password: FAKE_PASSWORD,
        proxy: FAKE_PROXY,
        proxyIP: 'proxy.example.test',
        phoneCode: FAKE_CODE,
        camoufoxTelemetry: { gpuPerformance: LEGACY_GPU_TELEMETRY },
        trafficAttribution: { sslKeyLogPath: '/fixture/.native/sslkeylog.txt' }
    };
    fs.writeFileSync(results, JSON.stringify([oldRecord]));
    fs.writeFileSync(summary, JSON.stringify({
        stats: { completed: 1 },
        results: [oldRecord]
    }));
    if (process.platform !== 'win32') {
        fs.chmodSync(results, 0o644);
        fs.chmodSync(summary, 0o644);
    }

    migrateExistingAccountOutputs(results, summary);
    assert.deepEqual(JSON.parse(fs.readFileSync(results, 'utf8'))[0].camoufoxTelemetry.gpuPerformance, GPU_TELEMETRY);
    for (const file of [results, summary]) {
        const content = fs.readFileSync(file, 'utf8');
        assertNoFakeCredentials(content);
        assert.ok(!content.includes('sslkeylog.txt'));
        assert.match(content, /existing-profile/);
        if (process.platform !== 'win32') {
            assert.equal(visibleMode(file), 0o600);
        }
    }
    const priorInodes = [results, summary].map((file) => fs.statSync(file).ino);
    migrateExistingAccountOutputs(results, summary);
    assert.deepEqual([results, summary].map((file) => fs.statSync(file).ino), priorInodes);
});

test('startup protects an invalid original and also migrates the other output', (t) => {
    const directory = temporaryDirectory(t);
    const results = path.join(directory, 'results.json');
    const summary = path.join(directory, 'summary.json');
    const invalid = `{ ${FAKE_PASSWORD}`;
    fs.writeFileSync(results, JSON.stringify([{ success: true, password: FAKE_PASSWORD }]));
    fs.writeFileSync(summary, invalid);
    assert.throws(() => migrateExistingAccountOutputs(results, summary), {
        name: 'AggregateError',
        message: 'Run summary file contains invalid JSON'
    });
    assertNoFakeCredentials(fs.readFileSync(results, 'utf8'));
    assert.equal(fs.readFileSync(summary, 'utf8'), invalid);
    if (process.platform !== 'win32') {
        assert.equal(visibleMode(results), 0o600);
        assert.equal(visibleMode(summary), 0o600);
    }
});

test('run summary writes account and failure metadata without credentials', (t) => {
    const output = path.join(temporaryDirectory(t), 'summary.json');
    fs.writeFileSync(output, JSON.stringify({ password: FAKE_PASSWORD, proxy: FAKE_PROXY }));
    const stats = { total: 4, completed: 1, failed: 2, manual: 1, successRate: '25.00%' };
    writeRunSummary(output, {
        timestamp: '2026-01-01T00:00:00.000Z',
        configuration: { accountsCount: 3, threadsCount: 1, smsProvider: 'sms-verification' },
        stats,
        duration: '0.25s',
        results: [
            {
                success: true,
                email: 'account@example.test',
                password: FAKE_PASSWORD,
                proxy: FAKE_PROXY,
                proxyIP: FAKE_PROXY,
                profileId: 'test-profile',
                phoneCode: FAKE_CODE
            },
            {
                success: false,
                error: FAKE_MESSAGE,
                errorCode: 'MANUAL_SIGNUP_REQUIRED',
                errorStage: 'verification',
                profileId: 'recycled-profile',
                profileType: 'Dolphin Anty',
                profileCleanup: 'recycled'
            },
            {
                success: false,
                profileType: 'GPM Login',
                profileCleanup: 'allocation-unconfirmed',
                error: FAKE_MESSAGE,
                errorCode: 'PROFILE_ALLOCATION_UNCONFIRMED'
            },
            {
                success: false,
                profileId: 'needs-recycle',
                profileType: 'Dolphin Anty',
                profileCleanup: 'recycle-unconfirmed',
                error: FAKE_MESSAGE
            }
        ]
    });

    const saved = fs.readFileSync(output, 'utf8');
    assertNoFakeCredentials(saved);
    const summary = JSON.parse(saved);
    assert.deepEqual(summary.stats, stats);
    assert.equal(summary.results[0].profileId, 'test-profile');
    assert.equal(summary.results[0].proxyIP, null);
    assert.deepEqual(summary.results[1], {
        success: false,
        email: null,
        profileId: 'recycled-profile',
        profileType: 'Dolphin Anty',
        profileCleanup: 'recycled',
        error: 'Manual signup is required',
        errorCode: 'MANUAL_SIGNUP_REQUIRED',
        errorStage: 'verification'
    });
    assert.deepEqual(summary.results[2], {
        success: false,
        email: null,
        profileType: 'GPM Login',
        profileCleanup: 'allocation-unconfirmed',
        error: 'Managed profile allocation is unconfirmed',
        errorCode: 'PROFILE_ALLOCATION_UNCONFIRMED'
    });
    assert.deepEqual(summary.results[3], {
        success: false,
        email: null,
        profileId: 'needs-recycle',
        profileType: 'Dolphin Anty',
        profileCleanup: 'recycle-unconfirmed',
        error: 'Account creation failed'
    });
    if (process.platform !== 'win32') {
        assert.equal(visibleMode(output), 0o600);
    }
});

test('private storage restricts existing paths and leaves original data if replacement fails', (t) => {
    const outputDirectory = path.join(temporaryDirectory(t), 'private');
    fs.mkdirSync(outputDirectory);
    ensurePrivateDirectory(outputDirectory);
    const output = path.join(outputDirectory, 'example.txt');
    writePrivateFile(output, 'first');
    appendPrivateFile(output, ' append');
    assert.throws(() => writePrivateFile(output, undefined), { code: 'ERR_INVALID_ARG_TYPE' });
    assert.equal(readPrivateFile(output), 'first append');
    assert.deepEqual(fs.readdirSync(outputDirectory), ['example.txt']);
    if (process.platform !== 'win32') {
        assert.equal(visibleMode(outputDirectory), 0o700);
        assert.equal(visibleMode(output), 0o600);
    }
});

test('private storage accepts only regular files', { skip: process.platform === 'win32' }, (t) => {
    const directory = temporaryDirectory(t);
    const output = path.join(directory, 'output');
    const target = path.join(directory, 'fixture.txt');
    fs.writeFileSync(target, 'fixture');
    fs.symlinkSync(target, output);
    assert.throws(() => readPrivateFile(output), /Expected a regular file/);
    assert.throws(() => appendPrivateFile(output, 'additional'), /Expected a regular file/);
    assert.throws(() => writePrivateFile(output, 'replacement'), /Expected a regular file/);
    assert.equal(fs.readFileSync(target, 'utf8'), 'fixture');
});

test('private storage rejects shared directory entries before chmod or access', {
    skip: process.platform === 'win32'
}, (t) => {
    const directory = temporaryDirectory(t);
    const fixture = path.join(directory, 'fixture.txt');
    const extraDirectory = path.join(directory, 'second');
    const secondEntry = path.join(extraDirectory, 'linked.txt');
    fs.mkdirSync(extraDirectory);
    fs.writeFileSync(fixture, 'synthetic test data');
    fs.chmodSync(fixture, 0o644);
    fs.linkSync(fixture, secondEntry);

    assert.throws(() => restrictPrivateFile(secondEntry), /one directory entry/);
    assert.throws(() => readPrivateFile(secondEntry), /one directory entry/);
    assert.throws(() => appendPrivateFile(secondEntry, 'append'), /one directory entry/);
    assert.throws(() => writePrivateFile(secondEntry, 'replace'), /one directory entry/);
    assert.equal(visibleMode(fixture), 0o644);
    assert.equal(fs.readFileSync(fixture, 'utf8'), 'synthetic test data');
});

test('Win32 compatibility uses existing filesystem permissions for ordinary file operations', {
    skip: process.platform === 'win32'
}, (t) => {
    const directory = temporaryDirectory(t);
    const output = path.join(directory, 'example.txt');
    fs.writeFileSync(output, 'fixture');
    fs.chmodSync(directory, 0o755);
    fs.chmodSync(output, 0o644);

    // Exercise the JavaScript platform branch on an isolated POSIX fixture.
    const simulateWindows = `
        import assert from 'node:assert/strict';
        Object.defineProperty(process, 'platform', { value: 'win32' });
        const storage = await import(process.argv[1]);
        storage.ensurePrivateDirectory(process.argv[2]);
        storage.restrictPrivateFile(process.argv[3]);
        assert.equal(storage.readPrivateFile(process.argv[3]), 'fixture');
        storage.appendPrivateFile(process.argv[3], ' appended');
    `;
    const storageModule = new URL('../../src/utils/private-storage.js', import.meta.url).href;
    const run = spawnSync(process.execPath, [
        '--input-type=module', '--eval', simulateWindows, storageModule, directory, output
    ], { env: { PATH: process.env.PATH }, encoding: 'utf8' });
    assert.equal(run.status, 0, run.error?.message || run.stderr);
    assert.equal(visibleMode(directory), 0o755);
    assert.equal(visibleMode(output), 0o644);
    assert.equal(fs.readFileSync(output, 'utf8'), 'fixture appended');
});

const npmScript = /[/\\]npm-cli\.js$/.test(process.env.npm_execpath || '') ? process.env.npm_execpath : null;
const manifest = JSON.parse(fs.readFileSync(path.join(PROJECT, 'package.json'), 'utf8'));
const publicFiles = manifest.files.map((file) => file.replace(/^\//, ''));

test('npm tarball contains exactly the public files from a checkout with local state', {
    skip: process.platform === 'win32' && !npmScript
}, (t) => {
    const directory = temporaryDirectory(t);
    const packageRoot = path.join(directory, 'package');
    const expected = ['package.json', ...publicFiles];
    for (const file of [...expected, '.gitignore', 'tests/security/distribution.test.js']) {
        copyProjectFile(packageRoot, file);
    }
    const privateFiles = [
        'config/proxies.txt', 'config/operator-local.json', '.env', '.emv', 'traffic.har',
        'src/.env.example', 'src/USAGE.md',
        'bin/operator-copy.txt', 'src/custom store/profile/profile.json',
        'src/custom store/profile/storage-state.json', 'src/custom store/profile/traffic/payloads/part.bin',
        'src/custom store/profile/.native/sslkeylog.txt', 'scripts/archived-capture.har',
        'docs/local-export.json', 'assets/operator-copy.jpeg'
    ];
    for (const file of privateFiles) {
        const destination = path.join(packageRoot, file);
        fs.mkdirSync(path.dirname(destination), { recursive: true });
        fs.writeFileSync(destination, FAKE_PASSWORD);
    }
    const stateDirectory = path.join(directory, 'state');
    fs.mkdirSync(stateDirectory, { mode: 0o700 });
    const envFile = path.join(stateDirectory, '.env');
    const customStore = 'CAMOUFOX_STORAGE_DIR="./src/custom store"\n';
    fs.writeFileSync(envFile, customStore, { mode: 0o600 });
    const userConfig = path.join(directory, 'empty-user-npmrc');
    const globalConfig = path.join(directory, 'empty-global-npmrc');
    fs.writeFileSync(userConfig, '');
    fs.writeFileSync(globalConfig, '');

    const npm = npmScript ? process.execPath : 'npm';
    const argv = npmScript ? [npmScript] : [];
    const pack = () => spawnSync(npm, [
        ...argv, 'pack', '--offline', '--json',
        '--cache', path.join(directory, 'cache'), '--userconfig', userConfig, '--globalconfig', globalConfig
    ], {
        cwd: packageRoot,
        env: {
            PATH: process.env.PATH,
            SystemRoot: process.env.SystemRoot,
            NODE_OPTIONS: process.env.NODE_OPTIONS,
            GMAIL_CREATOR_STATE_DIR: stateDirectory
        },
        encoding: 'utf8'
    });
    const packed = pack();
    assert.equal(packed.status, 0, packed.error?.message || packed.stderr);
    const [{ files: packedFiles, filename }] = JSON.parse(packed.stdout);
    assert.deepEqual(packedFiles.map((file) => file.path).sort(), expected.sort());
    for (const file of ['bin/gmail-account-creator.js', 'src/index.js', 'config/names.json', '.env.example',
        'docs/openapi-default.json', 'src/utils/account-results.js', 'src/utils/private-storage.js']) {
        assert.ok(expected.includes(file), file);
    }

    if (process.platform !== 'win32') {
        const archive = spawnSync('tar', ['-tzf', path.join(packageRoot, filename)], {
            env: { PATH: process.env.PATH }, encoding: 'utf8'
        });
        assert.equal(archive.status, 0, archive.error?.message || archive.stderr);
        assert.deepEqual(archive.stdout.trim().split('\n').sort(), expected.map((file) => `package/${file}`).sort());
    }

    const verifyArchive = (input) => spawnSync(process.execPath, ['scripts/check-distribution.mjs', 'archive'], {
        cwd: packageRoot, env: { PATH: process.env.PATH }, input, encoding: 'utf8'
    });
    const verified = verifyArchive(packed.stdout);
    assert.equal(verified.status, 0, verified.stderr);
    assert.equal(verified.stdout.trim(), filename);

    fs.appendFileSync(path.join(packageRoot, filename), 'fixture');
    const changed = verifyArchive(packed.stdout);
    assert.notEqual(changed.status, 0);
    assert.match(changed.stderr, /npm archive does not match its pack report/);

    const aliases = fs.existsSync(path.join(packageRoot, 'SRC')) ? ['src', 'SRC'] : ['src'];
    for (const sourceDir of aliases) {
        fs.writeFileSync(envFile, `CAMOUFOX_STORAGE_DIR=./${sourceDir}\n`);
        const overlappingStore = pack();
        assert.notEqual(overlappingStore.status, 0);
        assert.match(overlappingStore.stderr, /Expected an allowed public file for packaging/);
    }
    fs.writeFileSync(envFile, customStore);

    // npm can also add the manifest's browser entry independently of its files list.
    const manifestPath = path.join(packageRoot, 'package.json');
    const browserEntry = 'assets/operator-copy.jpeg';
    fs.writeFileSync(manifestPath, JSON.stringify({ ...manifest, browser: browserEntry }));
    const extraArchive = pack();
    assert.equal(extraArchive.status, 0, extraArchive.stderr);
    const unexpected = verifyArchive(extraArchive.stdout);
    assert.notEqual(unexpected.status, 0);
    assert.match(unexpected.stderr, /Unexpected npm archive member/);
    assert.ok(unexpected.stderr.includes(browserEntry));
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));

    // npm implicitly includes root README variants even with an explicit files list.
    fs.writeFileSync(path.join(packageRoot, 'README.local-copy'), FAKE_PASSWORD);
    const blocked = pack();
    assert.notEqual(blocked.status, 0);
    assert.match(blocked.stderr, /additional file that npm would include/);
    assert.ok(!blocked.stderr.includes(FAKE_PASSWORD));
    fs.unlinkSync(path.join(packageRoot, 'README.local-copy'));

    const specPath = path.join(packageRoot, 'docs', 'openapi-default.json');
    const specification = JSON.parse(fs.readFileSync(specPath, 'utf8'));
    const profile = specification.paths['/api/profile/detail'].post.responses['200'].content['application/json'].example;
    profile.fingerprint.computerName = 'FIXTURE-NONPLACEHOLDER-HOST';
    fs.writeFileSync(specPath, JSON.stringify(specification));
    const identifyingExample = pack();
    assert.notEqual(identifyingExample.status, 0);
    assert.match(identifyingExample.stderr, /Use synthetic identifiers and credential placeholders/);
    assert.doesNotMatch(identifyingExample.stderr, /FIXTURE-NONPLACEHOLDER-HOST/);
});

test('release checker blocks the historical tag and requires the new package version', (t) => {
    const directory = temporaryDirectory(t);
    copyProjectFile(directory, 'scripts/check-distribution.mjs');
    const manifestPath = path.join(directory, 'package.json');
    fs.writeFileSync(manifestPath, JSON.stringify({ ...manifest, version: '1.0.0' }));
    const checkTag = (candidate) => spawnSync(process.execPath, ['scripts/check-distribution.mjs', 'tag', candidate], {
        cwd: directory, env: { PATH: process.env.PATH }, encoding: 'utf8'
    });
    const historical = checkTag('v1.0.0');
    assert.notEqual(historical.status, 0);
    assert.match(historical.stderr, /v1\.0\.0 retains historical OpenAPI example data/);

    const tag = 'v9.9.9';
    fs.writeFileSync(manifestPath, JSON.stringify({ ...manifest, version: tag.slice(1) }));
    const valid = checkTag(tag);
    assert.equal(valid.status, 0, valid.stderr);
    const invalid = checkTag(`${tag}-fixture`);
    assert.notEqual(invalid.status, 0);
    assert.ok(invalid.stderr.includes(`Release tag must be ${tag}`));
});

const commitFixtureFiles = ['PUSH_TO_GITHUB.sh', 'scripts/check-distribution.mjs', 'package.json',
    ...publicFiles.filter((file) => file.startsWith('src/'))];

function temporaryRepository(t, includeIgnore = true) {
    const directory = temporaryDirectory(t);
    const root = path.join(directory, 'repository');
    for (const file of commitFixtureFiles) {
        copyProjectFile(root, file);
    }
    if (includeIgnore) {
        copyProjectFile(root, '.gitignore');
    }
    const globalConfig = path.join(directory, 'empty-gitconfig');
    fs.writeFileSync(globalConfig, '');
    const env = {
        PATH: process.env.PATH,
        NODE_OPTIONS: process.env.NODE_OPTIONS,
        GMAIL_CREATOR_STATE_DIR: path.join(directory, 'state'),
        GIT_CONFIG_GLOBAL: globalConfig,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_TERMINAL_PROMPT: '0'
    };
    const git = (...args) => spawnSync('git', args, { cwd: root, env, encoding: 'utf8' });
    const initialize = git('init', '-q');
    assert.equal(initialize.status, 0, initialize.error?.message || initialize.stderr);
    const prepareCommit = (input, stateDirectory = env.GMAIL_CREATOR_STATE_DIR) => spawnSync('bash', ['PUSH_TO_GITHUB.sh'], {
        cwd: root, env: { ...env, GMAIL_CREATOR_STATE_DIR: stateDirectory }, input, encoding: 'utf8'
    });
    return { root, git, prepareCommit, env };
}

test('source guard checks the selected commit used by a real Git archive', { skip: process.platform === 'win32' }, (t) => {
    const { root, git, env } = temporaryRepository(t);
    const sourceCheck = () => spawnSync(process.execPath, ['scripts/check-distribution.mjs', 'source', 'HEAD'], {
        cwd: root, env, encoding: 'utf8'
    });
    const commit = (message) => {
        const result = git('-c', 'user.name=Local Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-m', message);
        assert.equal(result.status, 0, result.stderr);
    };
    copyProjectFile(root, 'docs/openapi-default.json');
    assert.equal(git('add', '.').status, 0);
    commit('Sanitized code and docs');
    const clean = sourceCheck();
    assert.equal(clean.status, 0, clean.stderr);

    const file = 'local-fixture.log';
    fs.writeFileSync(path.join(root, file), FAKE_PASSWORD);
    assert.equal(git('add', '--force', '--', file).status, 0);
    commit('Record a synthetic sensitive file');
    assert.equal(git('rm', '--', file).status, 0);
    const rejected = sourceCheck();
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /Sensitive file in the source archive.*local-fixture\.log/);
    assert.ok(!rejected.stderr.includes(FAKE_PASSWORD));

    const archivePath = path.join(path.dirname(root), 'source.tar');
    const archive = git('archive', '--format=tar', `--output=${archivePath}`, 'HEAD');
    assert.equal(archive.status, 0, archive.stderr);
    const list = spawnSync('tar', ['-tf', archivePath], { env, encoding: 'utf8' });
    assert.equal(list.status, 0, list.stderr);
    assert.ok(list.stdout.split('\n').includes(file));
    assert.ok(!publicFiles.includes(file));
});

test('the first push helper rejects a clean tree with earlier identifying examples in its history', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, env, prepareCommit } = temporaryRepository(t);
    const api = 'docs/openapi-default.json';
    copyProjectFile(root, api);
    const original = fs.readFileSync(path.join(root, api), 'utf8');
    const specification = JSON.parse(original);
    const profile = specification.paths['/api/profile/detail'].post.responses['200'].content['application/json'].example;
    profile.sk = FAKE_PASSWORD;
    const commitFixture = (contents) => {
        fs.writeFileSync(path.join(root, api), contents);
        assert.equal(git('add', '.').status, 0);
        const commit = git('-c', 'user.name=Local Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-m', 'Fixture');
        assert.equal(commit.status, 0, commit.stderr);
    };
    commitFixture(JSON.stringify(specification));
    commitFixture(original);

    const sanitized = spawnSync(process.execPath, ['scripts/check-distribution.mjs', 'source', 'HEAD'], {
        cwd: root, env, encoding: 'utf8'
    });
    assert.equal(sanitized.status, 0, sanitized.stderr);
    const blocked = prepareCommit('y\n');
    assert.notEqual(blocked.status, 0);
    assert.match(blocked.stderr, /The branch retains earlier OpenAPI examples/);
    assert.ok(!blocked.stderr.includes(FAKE_PASSWORD));
    assert.equal(git('status', '--porcelain').stdout, '');
});

test('commit helper rejects credential files already in its index', { skip: process.platform === 'win32' }, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t);
    for (const file of [
        '.env.production', '.emv', 'config/proxies.txt', 'results.json', 'traffic.har',
        'custom/profile/profile.json', 'custom/profile/storage-state.json', 'custom/profile/.native/sslkeylog.txt'
    ]) {
        const fullPath = path.join(root, file);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, FAKE_PASSWORD);
        assert.equal(git('add', '--force', '--', file).status, 0);
        const blocked = prepareCommit('y\n');
        assert.equal(blocked.status, 1);
        assert.ok(blocked.stderr.includes('Sensitive file would be included in the commit'));
        assert.ok(blocked.stderr.includes(file));
        assert.ok(!blocked.stderr.includes(FAKE_PASSWORD));
        assert.equal(git('rm', '--cached', '--', file).status, 0);
        fs.unlinkSync(fullPath);
    }
});

test('commit helper rejects an unignored secret before staging', { skip: process.platform === 'win32' }, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t, false);
    fs.writeFileSync(path.join(root, '.emv'), FAKE_PASSWORD);
    const blocked = prepareCommit('y\n');
    assert.equal(blocked.status, 1);
    assert.ok(blocked.stderr.includes('Sensitive file would be included in the commit'));
    assert.equal(git('ls-files').stdout, '');
});

test('commit helper excludes resolved storage roots and rejects existing index entries there', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t);
    const store = 'src/runtime [store]';
    const privateFile = `${store}/unrecognized-output.bin`;
    const sourceFile = `${store}-helper.js`;
    const stateDir = 'operator state';
    const stateFile = `${stateDir}/unrecognized-output.bin`;
    fs.mkdirSync(path.join(root, store));
    fs.mkdirSync(path.join(root, stateDir));
    const link = spawnSync('ln', ['-s', store, 'active-store'], {
        cwd: root, env: { PATH: process.env.PATH }, encoding: 'utf8'
    });
    assert.equal(link.status, 0, link.error?.message || link.stderr);
    fs.writeFileSync(path.join(root, '.env'), 'CAMOUFOX_STORAGE_DIR=./active-store\n', { mode: 0o600 });
    fs.writeFileSync(path.join(root, privateFile), FAKE_PASSWORD);
    fs.writeFileSync(path.join(root, stateFile), FAKE_PASSWORD);
    fs.writeFileSync(path.join(root, sourceFile), '// public source fixture\n');
    const stateDirectory = path.join(root, stateDir);
    const cancelled = prepareCommit('n\n', stateDirectory);
    assert.match(cancelled.stdout, /Cancelled/);
    const staged = git('ls-files', '-z').stdout.split('\0');
    assert.ok(staged.includes(sourceFile));
    assert.ok(!staged.includes(privateFile));
    assert.ok(!staged.includes(stateFile));
    assert.ok(!staged.includes('active-store'));

    for (const file of [privateFile, stateFile]) {
        assert.equal(git('add', '--', file).status, 0);
        const blocked = prepareCommit('y\n', stateDirectory);
        assert.equal(blocked.status, 1);
        assert.match(blocked.stderr, /Sensitive file would be included in the commit/);
        assert.ok(blocked.stderr.includes(file));
        assert.equal(git('rm', '--cached', '--', file).status, 0);
    }
});

test('commit helper excludes state directory aliases on a case-insensitive volume', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t);
    const store = 'src/OperatorVault';
    const alias = 'src/operatorvault';
    fs.mkdirSync(path.join(root, store));
    if (!fs.existsSync(path.join(root, alias))) {
        t.skip('The fixture volume is case-sensitive');
        return;
    }
    const privateFile = `${store}/unrecognized.fixture`;
    fs.writeFileSync(path.join(root, privateFile), FAKE_PASSWORD);
    fs.writeFileSync(path.join(root, '.env'), `CAMOUFOX_STORAGE_DIR=./${alias}\n`, { mode: 0o600 });
    const cancelled = prepareCommit('n\n');
    assert.match(cancelled.stdout, /Cancelled/);
    assert.equal(git('ls-files', '--', privateFile).stdout, '');

    assert.equal(git('add', '--', privateFile).status, 0);
    const blocked = prepareCommit('y\n');
    assert.equal(blocked.status, 1);
    assert.match(blocked.stderr, /Sensitive file would be included in the commit/);
    assert.ok(blocked.stderr.includes(privateFile));
});

test('the GitHub setup command stops after a failed preflight or an existing origin', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, env } = temporaryRepository(t);
    const instructions = fs.readFileSync(path.join(PROJECT, 'GITHUB_SETUP.md'), 'utf8');
    const block = Array.from(instructions.matchAll(/```bash\n([\s\S]*?)\n```/g), ([, code]) => code)
        .find((code) => code.includes('bash PUSH_TO_GITHUB.sh'));
    assert.ok(block);
    const setup = `git() {
        if [ "$1" = push ]; then
            echo "fixture push attempted"
            return 90
        fi
        command git "$@"
    }
    ${block}`;
    const run = () => spawnSync('bash', ['-c', setup], {
        cwd: root, env: { ...env, GIT_ALLOW_PROTOCOL: 'file' }, input: 'y\n', encoding: 'utf8'
    });
    const priorOrigin = 'https://other.example.test/fixture.git';
    assert.equal(git('remote', 'add', 'origin', priorOrigin).status, 0);
    fs.writeFileSync(path.join(root, '.env.local'), FAKE_PASSWORD);
    assert.equal(git('add', '--force', '--', '.env.local').status, 0);
    const rejectedFiles = run();
    assert.notEqual(rejectedFiles.status, 0);
    assert.match(rejectedFiles.stderr, /Sensitive file would be included in the commit/);
    assert.doesNotMatch(rejectedFiles.stdout, /fixture push attempted/);

    assert.equal(git('rm', '--cached', '--', '.env.local').status, 0);
    assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);
    assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
    const rejectedOrigin = run();
    assert.notEqual(rejectedOrigin.status, 0);
    assert.match(rejectedOrigin.stderr, /origin already exists/);
    assert.doesNotMatch(rejectedOrigin.stdout, /fixture push attempted/);
    assert.equal(git('remote', 'get-url', '--push', 'origin').stdout.trim(), priorOrigin);
});

test('commit helper checks .npmrc in both the worktree and index and accepts environment references', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t, false);
    const config = path.join(root, '.npmrc');
    const inline = `//registry.example.test/:_authToken = "${FAKE_PASSWORD}"\n`;
    const environment = '//registry.example.test/:_authToken=${GITHUB_PACKAGES_TOKEN}\n';
    fs.writeFileSync(config, inline);
    const unstaged = prepareCommit('y\n');
    assert.equal(unstaged.status, 1);
    assert.match(unstaged.stderr, /Sensitive file would be included in the commit.*\.npmrc/);
    assert.ok(!unstaged.stderr.includes(FAKE_PASSWORD));
    assert.equal(git('ls-files').stdout, '');

    assert.equal(git('add', '--', '.npmrc').status, 0);
    fs.writeFileSync(config, environment);
    const staged = prepareCommit('y\n');
    assert.equal(staged.status, 1);
    assert.match(staged.stderr, /Sensitive file would be included in the commit.*\.npmrc/);
    assert.ok(!staged.stderr.includes(FAKE_PASSWORD));

    assert.equal(git('add', '--', '.npmrc').status, 0);
    const cancelled = prepareCommit('n\n');
    assert.match(cancelled.stdout, /Cancelled/);
});

test('environment template can be staged while local variants are ignored', { skip: process.platform === 'win32' }, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t);
    copyProjectFile(root, '.env.example');
    for (const file of ['.env', '.env.production', '.emv', '.emv.local', 'traffic.har', '.npmrc']) {
        fs.writeFileSync(path.join(root, file), `FIXTURE=${FAKE_PASSWORD}\n`, { mode: 0o600 });
    }
    const cancelled = prepareCommit('n\n');
    assert.equal(cancelled.status, 1);
    assert.ok(cancelled.stdout.includes('Cancelled'));
    const staged = git('ls-files');
    assert.equal(staged.status, 0, staged.stderr);
    assert.deepEqual(staged.stdout.trim().split('\n'), ['.env.example', '.gitignore', ...commitFixtureFiles].sort());
});

test('OpenAPI includes placeholders in profile, proxy and token examples', () => {
    const specification = JSON.parse(fs.readFileSync(path.join(PROJECT, 'docs/openapi-default.json'), 'utf8'));
    assert.match(specification.info.description, /generate -i docs\/openapi-default\.json/);
    assert.match(specification.info.description, /readFileSync\('docs\/openapi-default\.json'/);
    assert.match(specification.info.description, /verify the exact API origin/);
    assert.doesNotMatch(specification.info.description, /http:\/\/[^\s]+\/openapi/);
    const profile = specification.paths['/api/profile/detail'].post.responses['200'].content['application/json'].example;
    assert.ok(profile.sk === 'REPLACE_WITH_SECRET_KEY');
    assert.equal(profile.fingerprint.computerName, 'REPLACE_WITH_COMPUTER_NAME');
    assert.equal(profile.fingerprint.macAddr, '00:00:00:00:00:00');
    assert.match(profile.id, /^REPLACE_WITH_PROFILE_ID_\d+$/);
    for (const cookie of JSON.parse(profile.cookie)) {
        assert.equal(cookie.domain, 'example.invalid');
        assert.ok(cookie.value === 'REPLACE_WITH_COOKIE_VALUE');
    }
    const requestExample = (endpoint) => specification.paths[endpoint].post.requestBody.content['application/json'].example;
    for (const proxy of [
        profile.proxy,
        requestExample('/api/profile/advancedCreateProfile').proxy,
        requestExample('/api/profile/updateProfileBaseProxy'),
        requestExample('/api/proxy/proxyDetect'),
        requestExample('/api/proxy/createBaseProxy')
    ]) {
        assert.ok(proxy.proxyUsername === 'REPLACE_WITH_PROXY_USERNAME');
        assert.ok(proxy.proxyPassword === 'REPLACE_WITH_PROXY_PASSWORD');
        assert.equal(proxy.host, '192.0.2.10');
    }
    const login = specification.components.schemas.login_with_token;
    assert.ok(login.properties.token.example === 'REPLACE_WITH_API_TOKEN');
    const browser = specification.paths['/api/browser/openBrowser'].post.responses['200'].content['application/json'].example;
    assert.equal(new URL(browser.ws).hostname, 'example.invalid');
    assert.equal(browser.pid, 0);
});
