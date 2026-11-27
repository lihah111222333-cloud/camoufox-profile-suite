import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
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
    for (const name of ['local_storage_import', 'cookies_import', 'cookie_robot_start', 'browser_profile_start']) {
        const password = specification.components.schemas[name].properties.browserProfilePassword;
        assert.equal(password.example, 'REPLACE_WITH_BROWSER_PROFILE_PASSWORD');
        password.example = FAKE_PASSWORD;
        fs.writeFileSync(specPath, JSON.stringify(specification));
        const prepack = spawnSync(process.execPath, ['scripts/check-distribution.mjs', 'pack'], {
            cwd: packageRoot,
            env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, GMAIL_CREATOR_STATE_DIR: stateDirectory },
            encoding: 'utf8'
        });
        assert.equal(prepack.status, 1, name);
        assert.match(prepack.stderr, /Use synthetic identifiers and credential placeholders/);
        assert.ok(!prepack.stderr.includes(FAKE_PASSWORD));
        password.example = 'REPLACE_WITH_BROWSER_PROFILE_PASSWORD';
    }

    const profile = specification.paths['/api/profile/detail'].post.responses['200'].content['application/json'].example;
    profile.fingerprint.computerName = 'FIXTURE-NONPLACEHOLDER-HOST';
    fs.writeFileSync(specPath, JSON.stringify(specification));
    const identifyingExample = pack();
    assert.notEqual(identifyingExample.status, 0);
    assert.match(identifyingExample.stderr, /Use synthetic identifiers and credential placeholders/);
    assert.doesNotMatch(identifyingExample.stderr, /FIXTURE-NONPLACEHOLDER-HOST/);
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

test('release checker uses the exact tagged commit, version and source files', { skip: process.platform === 'win32' }, (t) => {
    const { root, git, env } = temporaryRepository(t);
    const checkTag = (...args) => spawnSync(process.execPath, ['scripts/check-distribution.mjs', 'tag', ...args], {
        cwd: root, env, encoding: 'utf8'
    });
    const historical = checkTag('v1.0.0');
    assert.equal(historical.status, 1);
    assert.match(historical.stderr, /v1\.0\.0 retains historical OpenAPI example data/);

    const writeVersion = (version) => fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ ...manifest, version }));
    const identity = ['-c', 'user.name=Local Fixture', '-c', 'user.email=fixture@example.test'];
    const commit = (message) => {
        assert.equal(git('add', '.').status, 0);
        const result = git(...identity, 'commit', '-m', message);
        assert.equal(result.status, 0, result.stderr);
        return git('rev-parse', 'HEAD').stdout.trim();
    };

    copyProjectFile(root, 'docs/openapi-default.json');
    const tag = 'v9.9.9';
    writeVersion(tag.slice(1));
    const reviewedCommit = commit('Reviewed release fixture');
    const annotated = git(...identity, 'tag', '-a', tag, '-m', 'Fixture release', reviewedCommit);
    assert.equal(annotated.status, 0, annotated.stderr);
    const tagObject = git('rev-parse', `refs/tags/${tag}`).stdout.trim();
    assert.notEqual(tagObject, reviewedCommit);

    const unsafeTag = 'v9.9.8';
    writeVersion(unsafeTag.slice(1));
    const privateFile = 'local-fixture.log';
    fs.writeFileSync(path.join(root, privateFile), FAKE_PASSWORD);
    assert.equal(git('add', '-f', '--', privateFile).status, 0);
    const unsafeCommit = commit('Different version with a private fixture');
    assert.equal(git('tag', unsafeTag, unsafeCommit).status, 0);

    const checked = checkTag(tag, reviewedCommit);
    assert.equal(checked.status, 0, checked.stderr);
    assert.equal(checked.stdout.trim(), tagObject);
    const changedTarget = checkTag(tag, unsafeCommit);
    assert.equal(changedTarget.status, 1);
    assert.match(changedTarget.stderr, /does not point to the expected commit/);
    assert.equal(changedTarget.stdout, '');

    assert.equal(git('checkout', '--detach', reviewedCommit).status, 0);
    const rejected = checkTag(unsafeTag);
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /Sensitive file in the source archive.*local-fixture\.log/);
    assert.ok(!rejected.stderr.includes(FAKE_PASSWORD));
    assert.equal(rejected.stdout, '');

    const wrongVersion = `${tag}-fixture`;
    assert.equal(git('tag', wrongVersion, reviewedCommit).status, 0);
    const invalid = checkTag(wrongVersion);
    assert.equal(invalid.status, 1);
    assert.ok(invalid.stderr.includes(`Release tag must be ${tag}.`));

    assert.equal(git('branch', 'v9.9.7', reviewedCommit).status, 0);
    assert.equal(checkTag('v9.9.7').status, 1);
});

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

test('first push rejects private paths and registry credentials in removed historical files', {
    skip: process.platform === 'win32'
}, (t) => {
    const fixtures = [
        ['.env', `FIXTURE=${FAKE_PASSWORD}\n`],
        ['config/proxies.txt', FAKE_PROXY],
        ['.npmrc', `//registry.example.test/:_authToken=${FAKE_PASSWORD}\n`]
    ];
    for (const [file, contents] of fixtures) {
        const { root, git, prepareCommit } = temporaryRepository(t);
        const fullPath = path.join(root, file);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, contents, { mode: 0o600 });
        assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);
        assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
        assert.equal(git('add', '.').status, 0);
        assert.equal(git('add', '--force', '--', file).status, 0);
        assert.equal(git('commit', '-qm', 'Fixture with private output').status, 0);
        assert.equal(git('rm', '--', file).status, 0);
        assert.equal(git('commit', '-qm', 'Remove private output').status, 0);
        const head = git('rev-parse', 'HEAD').stdout;

        const blocked = prepareCommit('y\n');
        assert.equal(blocked.status, 1);
        assert.ok(blocked.stderr.includes(`Sensitive file in the first-push history: ${JSON.stringify(file)}`), blocked.stderr);
        assert.ok(!blocked.stderr.includes(contents));
        assert.doesNotMatch(blocked.stdout, /expected_origin=/);
        assert.equal(git('rev-parse', 'HEAD').stdout, head);
        assert.equal(git('status', '--porcelain').stdout, '');
    }
});

test('first push preserves a pending merge and checks a completed merge through all parents', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t);
    assert.equal(git('symbolic-ref', 'HEAD', 'refs/heads/reviewed').status, 0);
    assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);
    assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
    assert.equal(git('add', '.').status, 0);
    assert.equal(git('commit', '-qm', 'Reviewed base').status, 0);
    const reviewed = git('rev-parse', 'HEAD').stdout;

    assert.equal(git('checkout', '-qb', 'topic').status, 0);
    fs.writeFileSync(path.join(root, 'local-fixture.log'), FAKE_PASSWORD);
    assert.equal(git('add', '--force', '--', 'local-fixture.log').status, 0);
    assert.equal(git('commit', '-qm', 'Local diagnostics fixture').status, 0);
    assert.equal(git('rm', '--', 'local-fixture.log').status, 0);
    fs.writeFileSync(path.join(root, 'merge-note.txt'), 'Public topic fixture');
    assert.equal(git('add', '--', 'merge-note.txt').status, 0);
    assert.equal(git('commit', '-qm', 'Clean topic tree').status, 0);
    const topic = git('rev-parse', 'HEAD').stdout;

    assert.equal(git('checkout', '-q', 'reviewed').status, 0);
    const clean = prepareCommit('y\n');
    assert.equal(clean.status, 0, clean.stderr);
    const merge = git('merge', '--no-commit', '--no-ff', 'topic');
    assert.equal(merge.status, 0, merge.stderr);

    const pending = prepareCommit('y\n');
    assert.equal(pending.status, 1);
    assert.match(pending.stderr, /Finish or abort the pending merge/);
    assert.doesNotMatch(pending.stdout, /expected_origin=/);
    assert.equal(git('rev-parse', 'HEAD').stdout, reviewed);
    assert.equal(git('rev-parse', 'MERGE_HEAD').stdout, topic);
    assert.equal(git('diff', '--cached', '--name-only').stdout.trim(), 'merge-note.txt');

    assert.equal(git('commit', '-qm', 'Completed topic merge').status, 0);
    assert.equal(git('rev-parse', 'HEAD^2').stdout, topic);
    const blocked = prepareCommit('y\n');
    assert.equal(blocked.status, 1);
    assert.match(blocked.stderr, /Sensitive file in the first-push history: "local-fixture\.log"/);
    assert.ok(!blocked.stderr.includes(FAKE_PASSWORD));
    assert.doesNotMatch(blocked.stdout, /expected_origin=/);
    assert.equal(git('status', '--porcelain').stdout, '');
});

test('custom captures keep recorder attachments out of staging and source delivery', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, env, prepareCommit } = temporaryRepository(t);
    const metadata = 'custom capture/traffic.ndjson';
    const generated = 'custom capture/payloads/res-1-0123456789ab.bin';
    const nested = 'another/traffic/payloads/local-body.bin';
    const source = 'fixtures/payloads/example.json';
    const writeFile = (file, contents) => {
        const fullPath = path.join(root, file);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, contents);
    };
    writeFile(metadata, '{}\n');
    writeFile(generated, FAKE_PASSWORD);
    writeFile(nested, FAKE_PASSWORD);
    writeFile(source, '{}\n');
    for (const file of [metadata, generated, nested]) {
        assert.equal(git('check-ignore', '--', file).status, 0, file);
    }
    assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);
    assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
    const normal = prepareCommit('y\n');
    assert.equal(normal.status, 0, normal.stderr);
    assert.equal(git('ls-files', '--', source).stdout.trim(), source);
    assert.equal(git('ls-files', '--', metadata, generated, nested).stdout, '');

    const imported = 'custom capture/payloads/nested/imported-body.txt';
    writeFile(imported, FAKE_PASSWORD);
    const blocked = prepareCommit('y\n');
    assert.equal(blocked.status, 1);
    assert.ok(blocked.stderr.includes(`Sensitive file would be included in the commit: ${JSON.stringify(imported)}`));
    assert.ok(!blocked.stderr.includes(FAKE_PASSWORD));
    assert.equal(git('ls-files', '--', imported).stdout, '');
    fs.unlinkSync(path.join(root, imported));
    fs.unlinkSync(path.join(root, metadata));

    assert.equal(git('add', '--force', '--', generated).status, 0);
    const blockedIndex = prepareCommit('y\n');
    assert.equal(blockedIndex.status, 1);
    assert.ok(blockedIndex.stderr.includes(`Sensitive file would be included in the commit: ${JSON.stringify(generated)}`));
    assert.equal(git('commit', '-qm', 'Source tree fixture with attachment').status, 0);
    const blockedSource = spawnSync(process.execPath, ['scripts/check-distribution.mjs', 'source', 'HEAD'], {
        cwd: root, env, encoding: 'utf8'
    });
    assert.equal(blockedSource.status, 1);
    assert.ok(blockedSource.stderr.includes(`Sensitive file in the source archive: ${JSON.stringify(generated)}`));
    assert.ok(!blockedSource.stderr.includes(FAKE_PASSWORD));
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

test('commit helper prepares a clean branch without creating a new commit', {
    skip: process.platform === 'win32'
}, (t) => {
    const { git, prepareCommit } = temporaryRepository(t);
    assert.equal(git('add', '.').status, 0);
    const initial = git(
        '-c', 'user.name=Local Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'Reviewed source'
    );
    assert.equal(initial.status, 0, initial.stderr);
    const head = git('rev-parse', 'HEAD').stdout;

    const prepared = prepareCommit('y\n');
    assert.equal(prepared.status, 0, prepared.stderr || prepared.stdout);
    assert.match(prepared.stdout, /No staged changes/);
    assert.match(prepared.stdout, /expected_origin=/);
    assert.equal(git('rev-parse', 'HEAD').stdout, head);
    assert.equal(git('status', '--porcelain').stdout, '');
    assert.equal(git('remote').stdout, '');
});

test('commit helper requires explicit Git identity for a new commit', {
    skip: process.platform === 'win32'
}, (t) => {
    const { git, prepareCommit, env } = temporaryRepository(t);
    env.EMAIL = 'fixture@local-host.invalid';
    assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);

    const rejected = prepareCommit('y\n');
    assert.equal(rejected.status, 1, rejected.stderr || rejected.stdout);
    assert.match(rejected.stderr, /auto-detection is disabled/);
    assert.doesNotMatch(rejected.stderr, /fixture@local-host\.invalid/);
    assert.notEqual(git('rev-parse', '--verify', '--quiet', 'HEAD').status, 0);

    assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
    const committed = prepareCommit('y\n');
    assert.equal(committed.status, 0, committed.stderr || committed.stdout);
    const identities = git('show', '-s', '--format=%ae%n%ce');
    assert.equal(identities.stdout.trim(), 'fixture@example.test\nfixture@example.test');
    assert.equal(git('config', '--get', 'user.useConfigOnly').status, 1);
});

function githubSetupBlock() {
    const instructions = fs.readFileSync(path.join(PROJECT, 'GITHUB_SETUP.md'), 'utf8');
    const block = Array.from(instructions.matchAll(/```bash\n([\s\S]*?)\n```/g), ([, code]) => code)
        .find((code) => code.includes('bash PUSH_TO_GITHUB.sh'));
    assert.ok(block);
    return block;
}

function fixtureGithubSetup(block) {
    return `git() {
        if [ "$1" = push ]; then
            local refspec="\${@: -1}"
            echo "fixture push attempted $refspec"
            command git update-ref refs/remotes/origin/main "\${refspec%%:*}"
            return $?
        fi
        command git "$@"
    }
    ${block.replace(/^\s*expected_origin=.*$/m, 'expected_origin=file:///fixture-remote.git')}`;
}

function printedGithubSetup(prepared) {
    assert.equal(prepared.status, 0, prepared.stderr);
    const handoff = /^ {3}expected_origin=[\s\S]*?(?=\n\n)/m.exec(prepared.stdout)?.[0];
    assert.ok(handoff);
    return handoff;
}

function runGithubSetup(root, env, block) {
    return spawnSync('bash', ['-c', fixtureGithubSetup(block)], {
        cwd: root, env: { ...env, GIT_ALLOW_PROTOCOL: 'file' }, input: 'y\n', encoding: 'utf8'
    });
}

test('documented and printed first-push commands send only the reviewed branch with followTags enabled', {
    skip: process.platform === 'win32'
}, (t) => {
    for (const printed of [false, true]) {
        const { root, git, env, prepareCommit } = temporaryRepository(t);
        assert.equal(git('symbolic-ref', 'HEAD', 'refs/heads/reviewed').status, 0);
        assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);
        assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
        assert.equal(git('config', 'push.followTags', 'true').status, 0);
        assert.equal(git('add', '.').status, 0);
        assert.equal(git('commit', '-qm', 'Reviewed branch fixture').status, 0);
        assert.equal(git('tag', '-a', 'v9.9.9', '-m', 'Local release fixture').status, 0);
        const head = git('rev-parse', 'HEAD').stdout.trim();
        const destination = path.join(path.dirname(root), 'destination.git');
        assert.equal(git('init', '-q', '--bare', destination).status, 0);

        const block = printed ? printedGithubSetup(prepareCommit('y\n')) : githubSetupBlock();
        const localBlock = block.replace(/^\s*expected_origin=.*$/m, `expected_origin=${pathToFileURL(destination).href}`);
        const pushed = spawnSync('bash', ['-c', localBlock], {
            cwd: root, env: { ...env, GIT_ALLOW_PROTOCOL: 'file' }, input: 'y\n', encoding: 'utf8'
        });
        assert.equal(pushed.status, 0, pushed.stderr || pushed.stdout);
        const delivered = git('--git-dir', destination, 'for-each-ref', '--format=%(objectname) %(refname)');
        assert.equal(delivered.status, 0, delivered.stderr);
        assert.equal(delivered.stdout.trim(), `${head} refs/heads/main`);
        assert.equal(git('tag', '--list').stdout.trim(), 'v9.9.9');
    }
});

test('the GitHub setup command stops after a failed preflight or an existing origin', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, env } = temporaryRepository(t);
    const block = githubSetupBlock();
    const run = () => runGithubSetup(root, env, block);
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

test('first-push commands preserve a separate main and require a named branch before adding origin', {
    skip: process.platform === 'win32'
}, (t) => {
    const { root, git, prepareCommit, env } = temporaryRepository(t);
    assert.equal(git('symbolic-ref', 'HEAD', 'refs/heads/reviewed').status, 0);
    assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);
    assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
    assert.equal(git('add', '.').status, 0);
    assert.equal(git('commit', '-qm', 'Shared fixture').status, 0);
    const handoff = printedGithubSetup(prepareCommit('y\n'));
    const documented = githubSetupBlock();

    assert.equal(git('checkout', '-qb', 'main').status, 0);
    fs.writeFileSync(path.join(root, 'main.txt'), 'Local main fixture');
    assert.equal(git('add', 'main.txt').status, 0);
    assert.equal(git('commit', '-qm', 'Independent main fixture').status, 0);
    const existingMain = git('rev-parse', 'refs/heads/main').stdout;
    assert.equal(git('checkout', '-q', 'reviewed').status, 0);
    fs.writeFileSync(path.join(root, 'reviewed.txt'), 'Reviewed branch fixture');
    assert.equal(git('add', 'reviewed.txt').status, 0);
    assert.equal(git('commit', '-qm', 'Independent reviewed fixture').status, 0);
    const review = git('rev-parse', 'HEAD').stdout;

    for (const checkout of ['reviewed', '--detach']) {
        assert.equal(git('checkout', '-q', checkout).status, 0);
        for (const block of [documented, handoff]) {
            const rejected = runGithubSetup(root, env, block);
            assert.notEqual(rejected.status, 0, rejected.stdout);
            assert.match(rejected.stderr, /Check out local main/);
            assert.doesNotMatch(rejected.stdout, /fixture push attempted/);
            assert.equal(git('rev-parse', 'refs/heads/main').stdout, existingMain);
            assert.equal(git('rev-parse', 'refs/heads/reviewed').stdout, review);
            assert.equal(git('rev-parse', 'HEAD').stdout, review);
            assert.equal(git('remote').stdout, '');
        }
    }

    assert.equal(git('checkout', '-q', 'reviewed').status, 0);
    assert.equal(git('branch', '-m', 'main', 'prior-main').status, 0);
    const normal = runGithubSetup(root, env, documented);
    assert.equal(normal.status, 0, normal.stderr);
    assert.match(normal.stdout, /fixture push attempted/);
    assert.equal(git('symbolic-ref', 'HEAD').stdout.trim(), 'refs/heads/main');
    assert.equal(git('rev-parse', 'HEAD').stdout, review);
    assert.equal(git('rev-parse', 'refs/heads/prior-main').stdout, existingMain);

    assert.equal(git('remote', 'remove', 'origin').status, 0);
    const obsolete = runGithubSetup(root, env, handoff);
    assert.notEqual(obsolete.status, 0);
    assert.match(obsolete.stderr, /The prepared branch or commit changed/);
    assert.doesNotMatch(obsolete.stdout, /fixture push attempted/);
    assert.equal(git('remote').stdout, '');

    const onMain = runGithubSetup(root, env, printedGithubSetup(prepareCommit('y\n')));
    assert.equal(onMain.status, 0, onMain.stderr);
    assert.match(onMain.stdout, /fixture push attempted/);
    assert.equal(git('rev-parse', 'refs/heads/main').stdout, review);
});

test('first-push confirmation stops before committing when the checked out branch changes', {
    skip: process.platform === 'win32', timeout: 10000
}, async (t) => {
    const { root, git, env } = temporaryRepository(t);
    assert.equal(git('symbolic-ref', 'HEAD', 'refs/heads/reviewed').status, 0);
    assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);
    assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
    assert.equal(git('add', '.').status, 0);
    assert.equal(git('commit', '-qm', 'Shared fixture').status, 0);
    const reviewed = git('rev-parse', 'HEAD').stdout;
    assert.equal(git('checkout', '-qb', 'alternate').status, 0);
    fs.writeFileSync(path.join(root, 'alternate.txt'), 'Alternate branch fixture');
    assert.equal(git('add', 'alternate.txt').status, 0);
    assert.equal(git('commit', '-qm', 'Alternate fixture').status, 0);
    const alternate = git('rev-parse', 'HEAD').stdout;
    assert.equal(git('checkout', '-q', 'reviewed').status, 0);
    fs.writeFileSync(path.join(root, 'release-note.txt'), 'Release note fixture');

    const block = githubSetupBlock();
    const rejected = await new Promise((resolve, reject) => {
        const child = spawn('bash', ['-c', fixtureGithubSetup(block)], {
            cwd: root, env: { ...env, GIT_ALLOW_PROTOCOL: 'file' }
        });
        t.after(() => child.kill());
        let stdout = '';
        let stderr = '';
        let confirmed = false;
        const confirm = () => {
            if (confirmed || !(stdout + stderr).includes('Make sure sensitive files are NOT in the list above!')) return;
            confirmed = true;
            try {
                assert.equal(git('checkout', '-q', 'alternate').status, 0);
                child.stdin.end('y\n');
            } catch (error) {
                child.kill();
                reject(error);
            }
        };
        child.stdout.setEncoding('utf8').on('data', (chunk) => {
            stdout += chunk;
            confirm();
        });
        child.stderr.setEncoding('utf8').on('data', (chunk) => {
            stderr += chunk;
            confirm();
        });
        child.once('error', reject);
        child.once('close', (status) => {
            if (confirmed) resolve({ status, stdout, stderr });
            else reject(new Error('The first-push helper exited before confirmation'));
        });
    });
    assert.notEqual(rejected.status, 0, rejected.stdout);
    assert.match(rejected.stderr, /The selected branch or commit changed during confirmation/);
    assert.doesNotMatch(rejected.stdout, /fixture push attempted/);
    assert.equal(git('rev-parse', 'refs/heads/reviewed').stdout, reviewed);
    assert.equal(git('rev-parse', 'refs/heads/alternate').stdout, alternate);
    assert.equal(git('rev-parse', 'HEAD').stdout, alternate);
    assert.equal(git('diff', '--cached', '--name-only').stdout.trim(), 'release-note.txt');
    assert.equal(git('remote').stdout, '');

    assert.equal(git('checkout', '-q', 'reviewed').status, 0);
    const delivered = runGithubSetup(root, env, block);
    assert.equal(delivered.status, 0, delivered.stderr);
    const prepared = git('rev-parse', 'refs/heads/main').stdout.trim();
    assert.ok(delivered.stdout.includes(`fixture push attempted ${prepared}:refs/heads/main`));
    assert.equal(git('show', 'refs/heads/main:release-note.txt').stdout, 'Release note fixture');
    assert.equal(git('rev-parse', '--abbrev-ref', '@{upstream}').stdout.trim(), 'origin/main');
});

test('first-push handoff verifies the resulting tree and parent after Git commits', {
    skip: process.platform === 'win32'
}, (t) => {
    for (const hook of ['pre-commit', 'post-commit']) {
        const { root, git, env } = temporaryRepository(t);
        assert.equal(git('symbolic-ref', 'HEAD', 'refs/heads/reviewed').status, 0);
        assert.equal(git('config', 'user.name', 'Local Fixture').status, 0);
        assert.equal(git('config', 'user.email', 'fixture@example.test').status, 0);
        assert.equal(git('add', '.').status, 0);
        assert.equal(git('commit', '-qm', 'Reviewed base').status, 0);
        const reviewed = git('rev-parse', 'HEAD').stdout;
        fs.writeFileSync(path.join(root, 'release-note.txt'), 'Reviewed release note');

        const action = hook === 'pre-commit'
            ? "printf 'generated note' > generated-note.txt\ngit add -- generated-note.txt"
            : "git -c core.hooksPath=.git/empty-hooks commit --allow-empty -qm 'Separate Git commit'";
        fs.writeFileSync(path.join(root, '.git', 'hooks', hook), `#!/bin/sh\nset -e\n${action}\n`, { mode: 0o700 });

        const outcome = runGithubSetup(root, env, githubSetupBlock());
        assert.notEqual(outcome.status, 0, outcome.stdout);
        assert.match(outcome.stderr, /The resulting commit differs from the reviewed tree or parent/);
        assert.doesNotMatch(outcome.stdout, /fixture push attempted/);
        assert.equal(git('remote').stdout, '');
        assert.equal(git('symbolic-ref', 'HEAD').stdout.trim(), 'refs/heads/reviewed');
        assert.equal(git('show', 'HEAD:release-note.txt').stdout, 'Reviewed release note');

        if (hook === 'pre-commit') {
            assert.equal(git('rev-parse', 'HEAD^1').stdout, reviewed);
            assert.equal(git('show', 'HEAD:generated-note.txt').stdout, 'generated note');
        } else {
            assert.equal(git('rev-parse', 'HEAD^^').stdout, reviewed);
            assert.equal(git('rev-parse', 'HEAD^{tree}').stdout, git('rev-parse', 'HEAD^1^{tree}').stdout);
        }
    }
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
    assert.match(specification.info.description, /axiosConfigDefaults: \{ maxRedirects: 0, proxy: false \}/);
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
