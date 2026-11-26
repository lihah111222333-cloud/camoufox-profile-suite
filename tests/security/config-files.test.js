import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const posix = process.platform !== 'win32';
const proxyFile = 'config/proxies.txt';
const fixtureUser = 'fixture-proxy-user';
const fixturePassword = 'fixture-proxy-password';
const fixtureProxyHost = 'fixture-proxy.invalid';

async function copySources(source, destination) {
    await mkdir(destination, { recursive: true });
    for (const entry of await readdir(source, { withFileTypes: true })) {
        const childSource = path.join(source, entry.name);
        const childDestination = path.join(destination, entry.name);
        if (entry.isDirectory()) {
            await copySources(childSource, childDestination);
        } else if (entry.isFile()) {
            await copyFile(childSource, childDestination);
        }
    }
}

async function makeFixture(t) {
    const root = await mkdtemp(path.join(tmpdir(), 'gmail-config-files-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    await writeFile(path.join(root, 'package.json'), '{"type":"module"}');
    await copySources(fileURLToPath(new URL('../../src/', import.meta.url)), path.join(root, 'src'));
    for (const file of ['bin/gmail-account-creator.js', 'config/names.json']) {
        await mkdir(path.dirname(path.join(root, file)), { recursive: true });
        await copyFile(new URL('../../' + file, import.meta.url), path.join(root, file));
    }
    await writeFile(path.join(root, 'src/camoufox/profile.js'), `
        import assert from 'node:assert/strict';
        export async function createAndStartProfile(_name, proxy) {
            assert.equal(proxy, null);
            throw Object.assign(new Error('Simulated browser boundary reached'), { code: 'FIXTURE_PROFILE_REACHED' });
        }
    `);
    return root;
}

function runNode(root, args, extraEnv = {}) {
    return spawnSync(process.execPath, args, {
        cwd: root,
        env: {
            PATH: process.env.PATH,
            SystemRoot: process.env.SystemRoot,
            NODE_OPTIONS: process.env.NODE_OPTIONS,
            GMAIL_CREATOR_STATE_DIR: root,
            ...extraEnv
        },
        encoding: 'utf8'
    });
}

function runModule(root, source, env) {
    return runNode(root, ['--input-type=module', '-e', source], env);
}

async function permissions(root, file) {
    return (await stat(path.join(root, file))).mode & 0o777;
}

test('Invalid proxy entries stop CLI startup and only their physical line numbers appear in diagnostics', async t => {
    const root = await makeFixture(t);
    const inventory = [
        '# Example inventory',
        '',
        [fixtureProxyHost, '8080', fixtureUser, fixturePassword].join(':'),
        'https://' + fixtureUser + ':' + fixturePassword + '%@' + fixtureProxyHost + ':8443',
        [fixtureProxyHost, 'invalid-port', fixtureUser, fixturePassword].join(':')
    ].join('\r\n');
    await writeFile(path.join(root, proxyFile), inventory, { mode: 0o600 });

    const result = runNode(root, ['bin/gmail-account-creator.js'], {
        PROFILE_SERVICE: 'camoufox',
        TEST_PROXY: 'false'
    });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Invalid proxy configuration in config\/proxies\.txt/);
    assert.doesNotMatch(result.stdout, /Starting Gmail Account Creation|proceeding with direct connection/);
    const [logName] = await readdir(path.join(root, 'logs'));
    const log = await readFile(path.join(root, 'logs', logName), 'utf8');
    for (const output of [result.stdout, log]) {
        assert.match(output, /"lineNumber":4/);
        assert.match(output, /"lineNumber":5/);
    }
    for (const output of [result.stdout, result.stderr, log]) {
        for (const value of [fixtureUser, fixturePassword, fixtureProxyHost]) {
            assert.ok(!output.includes(value));
        }
    }
});

test('A missing inventory is created privately and an empty inventory preserves intentional direct use', async t => {
    const root = await makeFixture(t);
    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import app from './src/index.js';
        await assert.rejects(app.createAccount(), { code: 'FIXTURE_PROFILE_REACHED' });
    `, { PROFILE_SERVICE: 'camoufox', TEST_PROXY: 'false' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /proceeding with direct connection \(TEST_PROXY=false\)/);
    const content = await readFile(path.join(root, proxyFile), 'utf8');
    assert.match(content, /^# Proxy format/);
    if (posix) assert.equal(await permissions(root, proxyFile), 0o600);

    const denied = runModule(root, `
        import assert from 'node:assert/strict';
        import app from './src/index.js';
        await assert.rejects(app.createAccount(), /No proxies available/);
    `, { PROFILE_SERVICE: 'camoufox' });
    assert.equal(denied.status, 0, denied.stderr);
});

test('Existing proxy files become private and a failed reload cannot reuse a stale or empty pool', async t => {
    const root = await makeFixture(t);
    await writeFile(path.join(root, proxyFile), [
        'https://fixture-user:safe%3Afixture@[2001:db8::1]:8443',
        'proxy.invalid:1080:fixture-user:safe:fixture'
    ].join('\n'));
    if (posix) await chmod(path.join(root, proxyFile), 0o644);

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import { writeFileSync } from 'node:fs';
        import manager from './src/utils/proxy-manager.js';

        assert.equal(manager.getAvailableCount(), 2);
        assert.equal(manager.proxies[0].ip, '[2001:db8::1]');
        assert.equal(manager.proxies[0].type, 'https');
        for (const proxy of manager.proxies) assert.equal(proxy.password, 'safe:fixture');
        assert.ok(manager.getNextProxy());

        writeFileSync('config/proxies.txt', 'bad-inventory-entry');
        assert.throws(() => manager.loadProxies(), /Invalid proxy configuration/);
        assert.throws(() => manager.getNextProxy(), /Invalid proxy configuration/);
        writeFileSync('config/proxies.txt', 'replacement-proxy.invalid:1080');
        assert.equal(manager.getNextProxy().ip, 'replacement-proxy.invalid');
    `);
    assert.equal(result.status, 0, result.stderr);
    if (posix) assert.equal(await permissions(root, proxyFile), 0o600);
});

test('Unsafe proxy and dotenv paths are rejected before their targets are read or changed', { skip: !posix }, async t => {
    const root = await makeFixture(t);
    const target = path.join(root, 'operator-fixture.txt');
    const contents = 'PROFILE_SERVICE=camoufox\n# harmless fixture\n';
    await writeFile(target, contents);
    await chmod(target, 0o644);
    await symlink(target, path.join(root, proxyFile));
    await symlink(target, path.join(root, '.env'));

    const env = { PROFILE_SERVICE: 'camoufox', TEST_PROXY: 'false' };
    const badEnv = runNode(root, ['bin/gmail-account-creator.js'], env);
    assert.equal(badEnv.status, 1, badEnv.stderr);
    assert.match(badEnv.stderr, /Could not read \.env as a private configuration file/);

    await rm(path.join(root, '.env'));
    const badProxy = runNode(root, ['bin/gmail-account-creator.js'], env);
    assert.equal(badProxy.status, 1, badProxy.stderr);
    assert.match(badProxy.stderr, /Could not safely read or create config\/proxies\.txt/);
    assert.doesNotMatch(badProxy.stdout, /proceeding with direct connection/);
    assert.equal(await readFile(target, 'utf8'), contents);
    assert.equal(await permissions(root, 'operator-fixture.txt'), 0o644);
});

test('The common dotenv loader protects both files and preserves exported environment precedence', async t => {
    const root = await makeFixture(t);
    await writeFile(path.join(root, '.env'), 'GPM_API_URL="http://127.0.0.1:12345"\nSMS_VERIFY_API_KEY=fixture-from-file\n');
    await writeFile(path.join(root, '.emv'), 'PROFILE_SERVICE=camoufox\nDOLPHIN_API_KEY=fixture-from-fallback\n');
    if (posix) {
        await chmod(path.join(root, '.env'), 0o755);
        await chmod(path.join(root, '.emv'), 0o644);
    }

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import config from './src/config.js';

        assert.equal(config.profileService, 'camoufox');
        assert.equal(config.gpmlogin.apiUrl, 'http://127.0.0.1:12345');
        assert.equal(config.dolphin.apiKey, 'fixture-from-fallback');
        assert.equal(config.smsVerify.apiKey, 'fixture-from-environment');
    `, { SMS_VERIFY_API_KEY: 'fixture-from-environment' });
    assert.equal(result.status, 0, result.stderr);
    if (posix) {
        assert.equal(await permissions(root, '.env'), 0o600);
        assert.equal(await permissions(root, '.emv'), 0o600);
    }
});

test('A previously configured installation inventory requires explicit adoption before direct use', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'operator-state');
    await mkdir(state, { mode: 0o700 });
    await writeFile(path.join(root, proxyFile), 'fixture-proxy.invalid:1080\n', { mode: 0o600 });

    const env = { GMAIL_CREATOR_STATE_DIR: state, PROFILE_SERVICE: 'camoufox', TEST_PROXY: 'false' };
    const result = runNode(root, ['bin/gmail-account-creator.js'], env);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /An installation proxy inventory exists.*GMAIL_CREATOR_LEGACY_DIR/);
    assert.doesNotMatch(result.stdout, /proceeding with direct connection/);

    const adopted = runModule(root, `
        import assert from 'node:assert/strict';
        import manager from './src/utils/proxy-manager.js';
        assert.equal(manager.getNextProxy().ip, 'fixture-proxy.invalid');
    `, { ...env, GMAIL_CREATOR_LEGACY_DIR: root });
    assert.equal(adopted.status, 0, adopted.stderr);
});

test('Private environment loading does not combine state and legacy tenant files', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'operator-state');
    await mkdir(state, { mode: 0o700 });
    await writeFile(path.join(state, '.env'), 'SMS_VERIFY_API_KEY=fixture-current-tenant\n', { mode: 0o600 });
    await writeFile(path.join(root, '.emv'), 'DOLPHIN_API_KEY=fixture-old-tenant\n', { mode: 0o600 });

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import config from './src/config.js';
        assert.equal(config.smsVerify.apiKey, 'fixture-current-tenant');
        assert.equal(config.dolphin.apiKey, '');
    `, { GMAIL_CREATOR_STATE_DIR: state, GMAIL_CREATOR_LEGACY_DIR: root });
    assert.equal(result.status, 0, result.stderr);
});

test('Standalone GoLogin startup reads its key from the private state source', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'operator-state');
    await mkdir(state, { mode: 0o700 });
    for (const [name, content] of Object.entries({
        dotenv: "module.exports = { parse: require('node:util').parseEnv };",
        axios: 'function request() { throw new Error("Unexpected transport call"); } request.create = () => request; module.exports = request;'
    })) {
        const directory = path.join(root, 'node_modules', name);
        await mkdir(directory, { recursive: true });
        await writeFile(path.join(directory, 'index.js'), content);
    }
    await writeFile(path.join(state, '.env'), 'GOLOGIN_API_KEY=fixture-state-key\n');
    await writeFile(path.join(root, '.emv'), 'GOLOGIN_API_KEY=fixture-legacy-key\n', { mode: 0o600 });

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        await import('./src/gologin/client.js');
        assert.equal(process.env.GOLOGIN_API_KEY, 'fixture-state-key');
    `, { GMAIL_CREATOR_STATE_DIR: state, GMAIL_CREATOR_LEGACY_DIR: root });
    assert.equal(result.status, 0, result.stderr);
    if (posix) assert.equal(await permissions(state, '.env'), 0o600);
});
