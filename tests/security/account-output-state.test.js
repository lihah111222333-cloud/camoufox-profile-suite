import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess, { execFile, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
    appendAccountResult, migrateExistingAccountOutputs, writeRunSummary
} from '../../src/utils/account-results.js';
import { describeProcessOwner, readProcessOwner } from '../../src/utils/process-owner.js';

const runFile = promisify(execFile);
const source = fileURLToPath(new URL('../../', import.meta.url));
const outputsModule = new URL('../../src/utils/account-results.js', import.meta.url).href;
const lockModule = new URL('../../src/utils/account-output-lock.js', import.meta.url).href;

function temporaryDirectory(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-account-output-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

function readJson(file) {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

test('concurrent writer processes preserve every result while migrating shared history', async (t) => {
    const state = temporaryDirectory(t);
    const legacy = temporaryDirectory(t);
    const results = path.join(state, 'results.json');
    const summary = path.join(state, 'summary.json');
    const original = '[{"success":true,"profileId":"previous","password":"fixture-only"}]';
    const legacyResults = path.join(legacy, 'results.json');
    fs.writeFileSync(legacyResults, original, { mode: 0o644 });

    const writeFixtureResults = [
        'const [module, results, summary, legacyDirectory, writer] = process.argv.slice(1);',
        'const { appendAccountResult, migrateExistingAccountOutputs, writeRunSummary } = await import(module);',
        'for (let i = 0; i < 6; i++) {',
        '    migrateExistingAccountOutputs(results, summary, { legacyDirectory });',
        '    appendAccountResult(results, { success: true, profileId: writer + "-" + i });',
        '}',
        'writeRunSummary(summary, { results: [{ success: true, profileId: writer }] });'
    ].join('\n');

    const writers = ['one', 'two', 'three', 'four'];
    await Promise.all(writers.map((writer) => runFile(process.execPath, [
        '--input-type=module', '--eval', writeFixtureResults, outputsModule, results, summary, legacy, writer
    ], { timeout: 12_000 })));

    const expectedIds = writers.flatMap((writer) => Array.from({ length: 6 }, (_, i) => writer + '-' + i));
    assert.deepEqual(readJson(results).map((record) => record.profileId).sort(), ['previous', ...expectedIds].sort());
    assert.ok(writers.includes(readJson(summary).results[0].profileId));
    assert.doesNotMatch(fs.readFileSync(results, 'utf8'), /fixture-only/);
    assert.equal(fs.readFileSync(legacyResults, 'utf8'), original);
    assert.deepEqual(fs.readdirSync(state).sort(), ['results.json', 'summary.json']);
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(results).mode & 0o777, 0o600);
        assert.equal(fs.statSync(legacyResults).mode & 0o777, 0o644 & ~process.umask());
    }
});

test('output locks recover a dead owner and preserve an unknown lock', (t) => {
    const root = temporaryDirectory(t);
    const output = path.join(root, 'results.json');
    const lock = output + '.lock';
    const exited = spawnSync(process.execPath, ['-e', '']);
    assert.equal(exited.status, 0);
    assert.ok(Number.isInteger(exited.pid));
    fs.mkdirSync(lock, { mode: 0o700 });
    fs.writeFileSync(path.join(lock, 'owner-' + exited.pid + '-068fd614-aceb-46c0-90b9-8b329991e448'), '');

    appendAccountResult(output, { success: true, profileId: 'after-exit' });
    assert.equal(readJson(output)[0].profileId, 'after-exit');
    assert.equal(fs.existsSync(lock), false);

    fs.mkdirSync(lock, { mode: 0o700 });
    const unexpectedFile = path.join(lock, 'unexpected');
    fs.writeFileSync(unexpectedFile, 'fixture contents');
    assert.throws(
        () => appendAccountResult(output, { success: true, profileId: 'during-unknown-lock' }),
        /Invalid results\.json writer lock/
    );
    assert.equal(fs.readFileSync(unexpectedFile, 'utf8'), 'fixture contents');
    assert.equal(readJson(output).length, 1);
    assert.deepEqual(fs.readdirSync(root).sort(), ['results.json', 'results.json.lock']);
});

test('a waiting writer retries when the incumbent removes an open marker', {
    skip: process.platform === 'win32'
}, (t) => {
    const root = temporaryDirectory(t);
    const output = path.join(root, 'results.json');
    const lock = output + '.lock';
    const owner = `owner-${process.pid}-068fd614-aceb-46c0-90b9-8b329991e448`;
    const marker = path.join(lock, owner);
    const detached = path.join(root, 'released-lock');
    const first = appendAccountResult(output, { success: true, profileId: 'incumbent' });
    fs.mkdirSync(lock, { mode: 0o700 });
    fs.writeFileSync(marker, describeProcessOwner(), { mode: 0o600 });

    const open = fs.openSync;
    t.mock.method(fs, 'openSync', (filePath, ...options) => {
        const fd = open(filePath, ...options);
        if (filePath === marker) {
            fs.renameSync(lock, detached);
            fs.unlinkSync(path.join(detached, owner));
            fs.rmdirSync(detached);
        }
        return fd;
    });

    const second = appendAccountResult(output, { success: false, profileId: 'waiting-writer' });
    assert.deepEqual(readJson(output), [first, second]);
    assert.deepEqual(fs.readdirSync(root), ['results.json']);
});

test('a marker must still name the opened file after it has been read', {
    skip: process.platform === 'win32'
}, async (t) => {
    for (const replace of [false, true]) {
        await t.test(replace ? 'rejects a replacement' : 'reports a detached marker as missing', (t) => {
            const root = temporaryDirectory(t);
            const lock = path.join(root, 'results.json.lock');
            const owner = `owner-${process.pid}-068fd614-aceb-46c0-90b9-8b329991e448`;
            const marker = path.join(lock, owner);
            const detached = path.join(root, 'released-lock');
            const metadata = describeProcessOwner();
            fs.mkdirSync(lock, { mode: 0o700 });
            fs.writeFileSync(marker, metadata, { mode: 0o600 });

            const readFile = fs.readFileSync;
            t.mock.method(fs, 'readFileSync', (file, ...options) => {
                const data = readFile(file, ...options);
                if (typeof file === 'number') {
                    fs.renameSync(lock, detached);
                    if (replace) {
                        fs.mkdirSync(lock, { mode: 0o700 });
                        fs.writeFileSync(marker, metadata, { mode: 0o600 });
                    }
                }
                return data;
            });

            if (replace) {
                assert.throws(() => readProcessOwner(marker), /File changed while reading/);
                assert.equal(fs.readFileSync(marker, 'utf8'), metadata);
            } else {
                assert.throws(() => readProcessOwner(marker), { code: 'ENOENT' });
            }
        });
    }
});

test('committed writes return their result ID when removing the detached owner fails', (t) => {
    const root = temporaryDirectory(t);
    const output = path.join(root, 'results.json');
    const lock = output + '.lock';
    const unlink = fs.unlinkSync;
    let injectFailure = true;
    const cleanupWarning = t.mock.method(process, 'emitWarning', () => {});
    t.mock.method(fs, 'unlinkSync', (file) => {
        const name = path.basename(file);
        if (injectFailure && name.startsWith('owner-') && !name.endsWith('.snapshot') && fs.existsSync(output)) {
            injectFailure = false;
            throw Object.assign(new Error('fixture unlock failure'), { code: 'EIO' });
        }
        return unlink(file);
    });

    const committed = appendAccountResult(output, { success: true, profileId: 'first' });
    assert.ok(committed.resultId);
    assert.equal(readJson(output)[0].resultId, committed.resultId);
    assert.equal(cleanupWarning.mock.callCount(), 1);
    const [, options] = cleanupWarning.mock.calls[0].arguments;
    assert.equal(options.code, 'ACCOUNT_OUTPUT_LOCK_CLEANUP_FAILED');
    assert.equal(fs.existsSync(lock), false);
    const next = appendAccountResult(output, { success: true, profileId: 'separate-attempt' });
    assert.deepEqual(readJson(output).map((record) => record.resultId), [committed.resultId, next.resultId]);

    const rename = fs.renameSync;
    const writeFailure = Object.assign(new Error('fixture replacement failure'), { code: 'EACCES' });
    t.mock.method(fs, 'renameSync', (from, to) => {
        if (to === output) throw writeFailure;
        rename(from, to);
    });
    injectFailure = true;
    assert.throws(() => appendAccountResult(output, { success: true }), (error) => error === writeFailure);
    assert.equal(cleanupWarning.mock.callCount(), 2);
    assert.equal(fs.existsSync(lock), false);
    assert.deepEqual(readJson(output).map((record) => record.resultId), [committed.resultId, next.resultId]);
});

test('finishing a write preserves unexpected content in the lock directory', (t) => {
    const root = temporaryDirectory(t);
    const output = path.join(root, 'results.json');
    const foreign = path.join(output + '.lock', 'unexpected');
    const rename = fs.renameSync;
    const cleanupWarning = t.mock.method(process, 'emitWarning', () => {});
    t.mock.method(fs, 'renameSync', (from, to) => {
        rename(from, to);
        if (to === output) fs.writeFileSync(foreign, 'fixture contents');
    });

    const saved = appendAccountResult(output, { success: true, profileId: 'committed' });
    assert.equal(readJson(output)[0].resultId, saved.resultId);
    assert.equal(cleanupWarning.mock.callCount(), 1);
    assert.equal(fs.readFileSync(foreign, 'utf8'), 'fixture contents');
    assert.throws(() => appendAccountResult(output, { success: true }), /Invalid results\.json writer lock/);
    assert.equal(fs.readFileSync(foreign, 'utf8'), 'fixture contents');
    assert.deepEqual(readJson(output), [saved]);
});

test('output locks and profile leases distinguish a reused PID from an active owner', {
    skip: !['linux', 'darwin', 'freebsd', 'win32'].includes(process.platform)
}, async (t) => {
    const root = temporaryDirectory(t);
    const output = path.join(root, 'results.json');
    const lock = output + '.lock';
    const active = childProcess.spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
    await once(active, 'spawn');
    t.after(async () => {
        if (active.exitCode === null && active.signalCode === null) {
            const exited = once(active, 'exit');
            active.kill();
            await exited;
        }
    });

    if (process.platform === 'darwin' || process.platform === 'freebsd') {
        // The desktop sandbox can deny ps. Inject only the OS query, with production lock handling intact.
        const query = ['-p', String(process.pid), '-o', 'lstart='];
        const env = { LC_ALL: 'C', TZ: 'UTC0' };
        if (spawnSync('/bin/ps', query, { env }).status !== 0) {
            t.mock.method(childProcess, 'execFileSync', (program, args, options) => {
                assert.equal(program, '/bin/ps');
                assert.ok([String(process.pid), String(active.pid)].includes(args[1]));
                assert.deepEqual(args, ['-p', args[1], '-o', 'lstart=']);
                assert.deepEqual(options.env, env);
                return 'Thu Nov 26 07:00:00 2026\n';
            });
        }
    } else if (process.platform === 'win32') {
        if (!/^[a-z]:[\\/]windows[\\/]?$/i.test(process.env.SystemRoot || '')) return t.skip('SystemRoot is unavailable');
        t.mock.method(childProcess, 'execFileSync', () => '639313996000000000\n');
    }

    const { withAccountOutputLock } = await import(lockModule + '?pid-reuse');
    let owner;
    let metadata;
    withAccountOutputLock(output, () => {
        [owner] = fs.readdirSync(lock);
        metadata = fs.readFileSync(path.join(lock, owner), 'utf8');
    });
    const [host, generation] = metadata.trim().split(' ');
    assert.match(generation, /^(?:[0-9a-f]{64}|-)$/);
    fs.mkdirSync(lock, { mode: 0o700 });
    const marker = path.join(lock, owner);
    const wait = new Error('fixture would wait for this owner');
    const waitMethod = t.mock.method(Atomics, 'wait', () => { throw wait; });
    const otherHost = (host[0] === '0' ? '1' : '0') + host.slice(1);
    for (const protectedMetadata of ['', metadata, `${host} -\n`, `${otherHost} ${generation}\n`, 'unknown owner metadata']) {
        fs.writeFileSync(marker, protectedMetadata);
        assert.throws(() => withAccountOutputLock(output, () => assert.fail('protected owner overwritten')),
            protectedMetadata === 'unknown owner metadata' ? /Invalid results\.json writer lock/ : (error) => error === wait);
        assert.equal(fs.readFileSync(marker, 'utf8'), protectedMetadata);
    }
    waitMethod.mock.restore();
    const olderGeneration = '0'.repeat(64);
    const reusedMarker = path.join(lock, owner.replace(/^owner-[0-9]+-/, `owner-${active.pid}-`));
    fs.renameSync(marker, reusedMarker);
    fs.writeFileSync(reusedMarker, `${host} ${olderGeneration}\n`);
    assert.equal(withAccountOutputLock(output, () => 'acquired'), 'acquired');
    assert.equal(fs.existsSync(lock), false);
    assert.doesNotThrow(() => process.kill(active.pid, 0));

    await t.test('legacy, foreign, and newer profile leases use the same ownership rules', async () => {
        const { acquireProfileLease, assertProfileLease, releaseProfileLease } =
            await import('../../src/camoufox/profile-storage.js');
        const location = { id: 'fixture-profile', profilesDir: fs.realpathSync.native(root) };
        const liveLease = acquireProfileLease(location);
        assert.doesNotThrow(() => assertProfileLease(liveLease));
        assert.throws(() => acquireProfileLease(location), { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });
        releaseProfileLease(liveLease);

        const installMarker = (pid, marker) => {
            const name = `${pid}-068fd614-aceb-46c0-90b9-8b329991e448`;
            fs.mkdirSync(liveLease.directory, { mode: 0o700 });
            const target = path.join(liveLease.directory, name);
            fs.writeFileSync(target, marker, { mode: 0o600 });
            return target;
        };
        const exited = spawnSync(process.execPath, ['-e', '']);
        assert.equal(exited.status, 0);
        const legacy = installMarker(exited.pid, '');
        const recoveredLegacy = acquireProfileLease(location);
        assert.equal(fs.existsSync(legacy), false);
        releaseProfileLease(recoveredLegacy);

        const foreign = installMarker(exited.pid, `${otherHost} ${generation}\n`);
        assert.throws(() => acquireProfileLease(location), { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });
        assert.equal(fs.readFileSync(foreign, 'utf8'), `${otherHost} ${generation}\n`);
        fs.unlinkSync(foreign);
        fs.rmdirSync(liveLease.directory);

        const replaced = installMarker(active.pid, `${host} ${olderGeneration}\n`);
        const recovered = acquireProfileLease(location);
        assert.equal(fs.existsSync(replaced), false);
        assert.doesNotThrow(() => assertProfileLease(recovered));
        releaseProfileLease(recovered);
        assert.equal(fs.existsSync(liveLease.directory), false);
    });
});

test('a writer recovers the interrupted replacement snapshot and preserves unrelated files', (t) => {
    const root = temporaryDirectory(t);
    const output = path.join(root, 'results.json');
    const lock = output + '.lock';
    const extra = path.join(root, '.results.json.068fd614-aceb-46c0-90b9-8b329991e448.tmp');
    fs.writeFileSync(extra, 'unverified fixture');
    const first = appendAccountResult(output, { success: true, profileId: 'first' });
    const code = [
        'import fs from "node:fs";',
        'const [module, output] = process.argv.slice(1);',
        'const { appendAccountResult } = await import(module);',
        'const rename = fs.renameSync;',
        'fs.renameSync = (from, to) => to === output ? process.exit(73) : rename(from, to);',
        'appendAccountResult(output, { success: true, profileId: "interrupted" });'
    ].join('\n');
    const interrupted = spawnSync(process.execPath, ['--input-type=module', '--eval', code, outputsModule, output], {
        encoding: 'utf8', timeout: 12_000
    });
    assert.equal(interrupted.status, 73, interrupted.stderr);
    assert.deepEqual(readJson(output), [first]);
    const snapshotName = fs.readdirSync(lock).find((entry) => entry.endsWith('.snapshot'));
    assert.ok(snapshotName);
    const snapshot = path.join(lock, snapshotName);
    assert.equal(readJson(snapshot).length, 2);
    if (process.platform !== 'win32') assert.equal(fs.statSync(snapshot).mode & 0o777, 0o600);

    const recovered = appendAccountResult(output, { success: true, profileId: 'recovered' });
    assert.deepEqual(readJson(output), [first, recovered]);
    assert.equal(fs.existsSync(snapshot), false);
    assert.equal(fs.existsSync(lock), false);
    assert.deepEqual(fs.readdirSync(root).sort(), [path.basename(extra), 'results.json']);
    assert.equal(fs.readFileSync(extra, 'utf8'), 'unverified fixture');
});

test('legacy import preserves the original on failure and gives existing state precedence', (t) => {
    const legacy = temporaryDirectory(t);
    const state = temporaryDirectory(t);
    const results = path.join(state, 'results.json');
    const summary = path.join(state, 'summary.json');
    const original = '{"bad fixture';
    const legacyResults = path.join(legacy, 'results.json');
    fs.writeFileSync(legacyResults, original);
    fs.writeFileSync(path.join(legacy, 'summary.json'), '{"results":[{"success":true,"profileId":"earlier"}]}');

    assert.throws(
        () => migrateExistingAccountOutputs(results, summary, { legacyDirectory: legacy }),
        /Account results file contains invalid JSON/
    );
    assert.equal(fs.existsSync(results), false);
    assert.equal(fs.readFileSync(legacyResults, 'utf8'), original);
    assert.equal(readJson(summary).results[0].profileId, 'earlier');

    appendAccountResult(results, {
        success: false, profileId: 'current', profileType: 'GPM Login', profileCleanup: 'stop-unconfirmed'
    });
    writeRunSummary(summary, { stats: { skipped: 2 }, results: readJson(results) });
    assert.equal(readJson(summary).results[0].profileId, 'current');
    assert.equal(readJson(summary).results[0].profileType, 'GPM Login');
    assert.equal(readJson(summary).results[0].profileCleanup, 'stop-unconfirmed');
    assert.equal(readJson(summary).stats.skipped, 2);
    migrateExistingAccountOutputs(results, summary, { legacyDirectory: legacy });
    assert.equal(readJson(results)[0].profileId, 'current');
});

test('migration and append preserve invalid UTF-8 in current or legacy results', (t) => {
    const state = temporaryDirectory(t);
    const legacy = temporaryDirectory(t);
    const results = path.join(state, 'results.json');
    const summary = path.join(state, 'summary.json');
    const legacyResults = path.join(legacy, 'results.json');
    const bytes = Buffer.concat([
        Buffer.from('[{"success":true,"profileId":"fixture-'), Buffer.from([0xff]), Buffer.from('"}]')
    ]);
    fs.writeFileSync(legacyResults, bytes, { mode: 0o600 });
    fs.writeFileSync(path.join(legacy, 'summary.json'), '{"results":[{"success":true,"profileId":"valid-summary"}]}');
    assert.throws(() => migrateExistingAccountOutputs(results, summary, { legacyDirectory: legacy }),
        /Account results file contains invalid UTF-8/);
    assert.equal(fs.existsSync(results), false);
    assert.deepEqual(fs.readFileSync(legacyResults), bytes);
    assert.equal(readJson(summary).results[0].profileId, 'valid-summary');

    fs.writeFileSync(results, bytes, { mode: 0o600 });
    assert.throws(() => migrateExistingAccountOutputs(results, summary), /Account results file contains invalid UTF-8/);
    assert.throws(() => appendAccountResult(results, { success: true }), { code: 'ACCOUNT_OUTPUT_INVALID_DATA' });
    assert.deepEqual(fs.readFileSync(results), bytes);
});

function installedCli(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-installed-cli-'));
    const install = path.join(root, 'install');
    t.after(() => {
        if (process.platform !== 'win32' && fs.existsSync(install)) fs.chmodSync(install, 0o755);
        fs.rmSync(root, { recursive: true, force: true });
    });
    const workingDirectory = path.join(root, 'other');
    const xdg = path.join(root, 'state-home');
    const home = path.join(root, 'home');
    fs.mkdirSync(install);
    fs.mkdirSync(workingDirectory);
    fs.mkdirSync(home);
    const files = [
        'bin/gmail-account-creator.js', 'src/index.js', 'src/config.js', 'config/names.json',
        ...['account-output-lock', 'account-results', 'cli-counts', 'controller-id', 'logger',
            'name-generator', 'private-storage', 'process-owner', 'state-paths']
            .map((name) => 'src/utils/' + name + '.js')
    ];
    if (fs.existsSync(path.join(source, 'src/utils/private-env.js'))) files.push('src/utils/private-env.js');
    for (const file of files) {
        const target = path.join(install, file);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(path.join(source, file), target);
    }
    fs.writeFileSync(path.join(install, 'package.json'), '{"type":"module"}');
    fs.writeFileSync(path.join(install, 'src', 'utils', 'proxy-manager.js'), [
        'const proxy = process.env.FIXTURE_NO_PROXY ? null : { ip: "proxy.invalid", port: 8080 };',
        'const proxies = proxy ? [proxy] : [];',
        'export default { proxies, getAvailableCount: () => proxies.length, getNextProxy: () => proxy };'
    ].join('\n'));
    fs.mkdirSync(path.join(install, 'src', 'gpmlogin'));
    fs.writeFileSync(path.join(install, 'src', 'gpmlogin', 'profile.js'),
        "export async function createAndStartProfile() { throw new Error('Fixture profile allocation failed'); }");
    fs.mkdirSync(path.join(install, 'src', 'gmail'));
    fs.writeFileSync(path.join(install, 'src', 'gmail', 'creator.js'),
        "export async function createGmailAccount() { throw new Error('Unexpected browser call'); }");
    if (process.platform !== 'win32') fs.chmodSync(install, 0o555);
    const run = (args, overrides = {}) => spawnSync(process.execPath, [
        path.join(install, 'bin', 'gmail-account-creator.js'), ...args
    ], {
        cwd: workingDirectory,
        env: {
            PATH: process.env.PATH,
            NODE_OPTIONS: process.env.NODE_OPTIONS,
            HOME: home,
            USERPROFILE: home,
            XDG_STATE_HOME: xdg,
            PROFILE_SERVICE: 'gpm',
            LOG_LEVEL: 'info',
            ...overrides
        },
        encoding: 'utf8',
        timeout: 12_000
    });
    return { run, install, workingDirectory, state: path.join(xdg, 'gmail-account-creator') };
}

test('installed CLI rejects malformed counts without altering history or starting runtime', (t) => {
    const { run, state } = installedCli(t);
    const original = '[{"success":true,"profileId":"kept-verbatim"}]\n';
    fs.mkdirSync(state, { recursive: true });
    const results = path.join(state, 'results.json');
    fs.writeFileSync(results, original);
    const invalidInputs = [
        [[], { ACCOUNTS_COUNT: '1.5' }, 'ACCOUNTS_COUNT'],
        [[], { THREADS_COUNT: 'Infinity' }, 'THREADS_COUNT'],
        [[], { THREADS_COUNT: '' }, 'THREADS_COUNT'],
        [[], { THREADS_COUNT: '3junk' }, 'THREADS_COUNT'],
        [['--threads=1=2'], {}, '--threads'],
        [['--threads'], {}, '--threads'],
        [['--accounts=0'], {}, '--accounts'],
        [['-a=9007199254740992'], {}, '-a'],
        [['-t=9007199254740992'], {}, '-t']
    ];
    for (const [args, env, option] of invalidInputs) {
        const result = run(args, env);
        assert.equal(result.status, 1, result.stderr);
        assert.ok(result.stderr.includes(option + ' must be an integer'), result.stderr);
        assert.equal(fs.readFileSync(results, 'utf8'), original);
        assert.deepEqual(fs.readdirSync(state), ['results.json']);
    }
});

test('installed CLI rejects an empty proxy inventory before scheduling account attempts', (t) => {
    const { run, state } = installedCli(t);
    const result = run(['--accounts=2'], { FIXTURE_NO_PROXY: '1' });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /No proxies available/);
    assert.equal(fs.existsSync(path.join(state, 'results.json')), false);
    assert.equal(fs.existsSync(path.join(state, 'summary.json')), false);
});

test('installed CLI reports failed attempts and writes state outside its installation and caller directories', (t) => {
    const { run, install, state, workingDirectory } = installedCli(t);
    const result = run(['-a=2', '--threads=3'], { ACCOUNTS_COUNT: '4', THREADS_COUNT: '1' });
    assert.equal(result.status, 1, result.stderr);
    const results = readJson(path.join(state, 'results.json'));
    const summary = readJson(path.join(state, 'summary.json'));
    assert.deepEqual(results.map((record) => record.success), [false, false]);
    assert.equal(summary.configuration.accountsCount, 2);
    assert.equal(summary.configuration.threadsCount, 2);
    assert.equal(summary.stats.failed, 2);
    assert.equal(fs.readdirSync(path.join(state, 'logs')).length, 1);
    assert.deepEqual(fs.readdirSync(install).sort(), ['bin', 'config', 'package.json', 'src']);
    assert.deepEqual(fs.readdirSync(workingDirectory), []);
});
