import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
    appendAccountResult, migrateExistingAccountOutputs, writeRunSummary
} from '../../src/utils/account-results.js';

const runFile = promisify(execFile);
const source = fileURLToPath(new URL('../../', import.meta.url));
const outputsModule = new URL('../../src/utils/account-results.js', import.meta.url).href;

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
        ...['account-output-lock', 'account-results', 'cli-counts', 'logger', 'name-generator', 'private-storage', 'state-paths']
            .map((name) => 'src/utils/' + name + '.js')
    ];
    if (fs.existsSync(path.join(source, 'src/utils/private-env.js'))) files.push('src/utils/private-env.js');
    for (const file of files) {
        const target = path.join(install, file);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(path.join(source, file), target);
    }
    fs.writeFileSync(path.join(install, 'package.json'), '{"type":"module"}');
    // With a simulated empty pool, each attempt stops before any profile service or browser call.
    fs.writeFileSync(path.join(install, 'src', 'utils', 'proxy-manager.js'), [
        'export default { proxies: [], getAvailableCount: () => 0, getNextProxy: () => null };'
    ].join('\n'));
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

test('installed CLI writes state outside its installation and caller directories', (t) => {
    const { run, install, state, workingDirectory } = installedCli(t);
    const result = run(['-a=2', '--threads=3'], { ACCOUNTS_COUNT: '4', THREADS_COUNT: '1' });
    assert.equal(result.status, 0, result.stderr);
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
