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
                securityGuards: {
                    blockedPortScanCount: 1,
                    blockedPortScans: [{ details: FAKE_PROXY }]
                }
            }
        },
        { success: false, profileId: 'existing-profile', error: FAKE_MESSAGE }
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
            phoneCode: FAKE_CODE
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
    assert.deepEqual(old.camoufoxTelemetry.securityGuards, { blockedPortScanCount: 1 });
    assert.deepEqual(failure, {
        success: false, profileId: 'existing-profile', error: 'Account creation failed'
    });
    assert.equal(current.email, 'new@example.test');
    assert.equal(current.proxyIP, '[2001:db8::8]');
    assert.equal(current.profileIP, '2001:db8::9');
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
    const stats = { total: 3, completed: 1, failed: 2, successRate: '33.33%' };
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
                errorStage: 'verification'
            },
            { success: false, error: FAKE_MESSAGE }
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
        error: 'Manual signup is required',
        errorCode: 'MANUAL_SIGNUP_REQUIRED',
        errorStage: 'verification'
    });
    assert.equal(summary.results[2].error, 'Account creation failed');
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

test('npm package includes public config but excludes operator files', {
    skip: process.platform === 'win32' && !npmScript
}, (t) => {
    const directory = temporaryDirectory(t);
    const packageRoot = path.join(directory, 'package');
    for (const file of [
        'package.json', '.gitignore', '.env.example', 'config/names.json', 'docs/openapi-default.json',
        'src/index.js', 'src/utils/account-results.js', 'src/utils/private-storage.js'
    ]) {
        copyProjectFile(packageRoot, file);
    }
    const privateFiles = ['config/proxies.txt', 'config/operator-local.json', '.env', '.emv'];
    for (const file of privateFiles) {
        fs.writeFileSync(path.join(packageRoot, file), FAKE_PASSWORD);
    }
    const userConfig = path.join(directory, 'empty-user-npmrc');
    const globalConfig = path.join(directory, 'empty-global-npmrc');
    fs.writeFileSync(userConfig, '');
    fs.writeFileSync(globalConfig, '');

    const npm = npmScript ? process.execPath : 'npm';
    const argv = npmScript ? [npmScript] : [];
    const packed = spawnSync(npm, [
        ...argv, 'pack', '--dry-run', '--ignore-scripts', '--offline', '--json',
        '--cache', path.join(directory, 'cache'), '--userconfig', userConfig, '--globalconfig', globalConfig
    ], {
        cwd: packageRoot,
        env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
        encoding: 'utf8'
    });
    assert.equal(packed.status, 0, packed.error?.message || packed.stderr);
    const [{ files }] = JSON.parse(packed.stdout);
    const packaged = new Set(files.map((file) => file.path));
    assert.ok(packaged.has('config/names.json'));
    assert.ok(packaged.has('.env.example'));
    assert.ok(packaged.has('docs/openapi-default.json'));
    assert.ok(packaged.has('src/utils/account-results.js'));
    assert.ok(packaged.has('src/utils/private-storage.js'));
    for (const file of privateFiles) {
        assert.ok(!packaged.has(file), file);
    }
});

function temporaryRepository(t, includeIgnore = true) {
    const directory = temporaryDirectory(t);
    const root = path.join(directory, 'repository');
    copyProjectFile(root, 'PUSH_TO_GITHUB.sh');
    if (includeIgnore) {
        copyProjectFile(root, '.gitignore');
    }
    const globalConfig = path.join(directory, 'empty-gitconfig');
    fs.writeFileSync(globalConfig, '');
    const env = {
        PATH: process.env.PATH,
        GIT_CONFIG_GLOBAL: globalConfig,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_TERMINAL_PROMPT: '0'
    };
    const git = (...args) => spawnSync('git', args, { cwd: root, env, encoding: 'utf8' });
    const initialize = git('init', '-q');
    assert.equal(initialize.status, 0, initialize.error?.message || initialize.stderr);
    const prepareCommit = (input) => spawnSync('bash', ['PUSH_TO_GITHUB.sh'], {
        cwd: root, env, input, encoding: 'utf8'
    });
    return { root, git, prepareCommit };
}

test('commit helper rejects credential files already in its index', { skip: process.platform === 'win32' }, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t);
    for (const file of ['.env.production', '.emv', 'config/proxies.txt', 'results.json']) {
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

test('environment template can be staged while local variants are ignored', { skip: process.platform === 'win32' }, (t) => {
    const { root, git, prepareCommit } = temporaryRepository(t);
    copyProjectFile(root, '.env.example');
    for (const file of ['.env', '.env.production', '.emv', '.emv.local']) {
        fs.writeFileSync(path.join(root, file), FAKE_PASSWORD);
    }
    const cancelled = prepareCommit('n\n');
    assert.equal(cancelled.status, 1);
    assert.ok(cancelled.stdout.includes('Cancelled'));
    const staged = git('ls-files');
    assert.equal(staged.status, 0, staged.stderr);
    assert.deepEqual(staged.stdout.trim().split('\n'), ['.env.example', '.gitignore', 'PUSH_TO_GITHUB.sh']);
});

test('OpenAPI includes placeholders in profile, proxy and token examples', () => {
    const specification = JSON.parse(fs.readFileSync(path.join(PROJECT, 'docs/openapi-default.json'), 'utf8'));
    const profile = specification.paths['/api/profile/detail'].post.responses['200'].content['application/json'].example;
    assert.ok(profile.sk === 'REPLACE_WITH_SECRET_KEY');
    for (const cookie of JSON.parse(profile.cookie)) {
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
});
