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
            assert.equal(proxy?.server ?? null, process.env.FIXTURE_PROXY_SERVER ?? null);
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
        [fixtureProxyHost, 'invalid-port', fixtureUser, fixturePassword].join(':'),
        [fixtureProxyHost, '8080', fixtureUser, fixturePassword + '@other-proxy.invalid:8443'].join(':')
    ].join('\r\n');
    await writeFile(path.join(root, proxyFile), inventory, { mode: 0o600 });

    const result = runNode(root, ['bin/gmail-account-creator.js'], {
        PROFILE_SERVICE: 'camoufox',
        CAMOUFOX_ALLOW_DIRECT: 'true'
    });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Invalid proxy configuration in config\/proxies\.txt/);
    assert.match(result.stderr, /Keep the configured scheme and percent-encode credential delimiters/);
    assert.match(result.stderr, /http:\/\/user:pass%40word%3Aend@proxy\.example:8080/);
    assert.doesNotMatch(result.stdout, /Starting Gmail Account Creation|proceeding with direct connection/);
    const [logName] = await readdir(path.join(root, 'logs'));
    const log = await readFile(path.join(root, 'logs', logName), 'utf8');
    for (const output of [result.stdout, log]) {
        assert.match(output, /"lineNumber":4/);
        assert.match(output, /"lineNumber":5/);
        assert.match(output, /"lineNumber":6/);
    }
    for (const output of [result.stdout, result.stderr, log]) {
        for (const value of [fixtureUser, fixturePassword, fixtureProxyHost, 'other-proxy.invalid']) {
            assert.ok(!output.includes(value));
        }
    }
});

test('Camoufox requires explicit direct connection permission when its inventory is empty', async t => {
    const root = await makeFixture(t);
    const env = { PROFILE_SERVICE: 'camoufox' };
    for (const settings of [
        {},
        { TEST_PROXY: 'false', CAMOUFOX_ALLOW_DIRECT: 'false' },
        { CAMOUFOX_ALLOW_DIRECT: 'true', CAMOUFOX_PORT_SCAN_MODE: 'managed-proxy' },
        { CAMOUFOX_ALLOW_DIRECT: 'true', PROFILE_SERVICE: 'gpm' }
    ]) {
        const denied = runNode(root, ['bin/gmail-account-creator.js'], { ...env, ...settings });
        assert.equal(denied.status, 1, denied.stderr);
        assert.match(denied.stderr, /No proxies available/);
        assert.doesNotMatch(denied.stdout, /Starting Gmail Account Creation|allowed direct connection/);
    }
    const content = await readFile(path.join(root, proxyFile), 'utf8');
    assert.match(content, /^# Proxy format/);
    if (posix) assert.equal(await permissions(root, proxyFile), 0o600);

    const direct = { ...env, CAMOUFOX_ALLOW_DIRECT: 'true' };
    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import app from './src/index.js';
        await assert.rejects(app.createAccount(), { code: 'FIXTURE_PROFILE_REACHED' });
    `, direct);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /explicitly allowed direct connection/);

    await writeFile(path.join(root, proxyFile), 'fixture-proxy.invalid:8080\n', { mode: 0o600 });
    const proxied = runModule(root, `
        import assert from 'node:assert/strict';
        import app from './src/index.js';
        await assert.rejects(app.createAccount(), { code: 'FIXTURE_PROFILE_REACHED' });
    `, { ...direct, FIXTURE_PROXY_SERVER: 'http://fixture-proxy.invalid:8080' });
    assert.equal(proxied.status, 0, proxied.stderr);
    assert.doesNotMatch(proxied.stdout, /allowed direct connection/);
});

test('Proxy parsing preserves unambiguous legacy and URL credentials', async t => {
    const root = await makeFixture(t);
    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import manager from './src/utils/proxy-manager.js';
        import { normalizeProxy } from './src/camoufox/client.js';

        for (const [input, expected] of [
            ['proxy.invalid:8080:user:part@word:end', ['http', 'proxy.invalid', '8080', 'user', 'part@word:end']],
            ['user:part%3Aend@proxy.invalid:8080', ['http', 'proxy.invalid', '8080', 'user', 'part:end']],
            ['https://user:part%40word%3Aend@proxy.invalid:443/', ['https', 'proxy.invalid', '443', 'user', 'part@word:end']],
            ['socks5://[2001:db8::1]:1080:user:part:end', ['socks5', '[2001:db8::1]', '1080', 'user', 'part:end']]
        ]) {
            const { type, ip, port, username, password } = manager.parseProxyLine(input);
            assert.deepEqual([type, ip, port, username, password], expected);
        }
        for (const invalid of [
            'https://user:123:fixture-marker@proxy.invalid:443',
            'https://user:123:fixture-marker@proxy.invalid:443/unexpected-path',
            'https://user:fixture-marker@proxy.invalid'
        ]) {
            assert.equal(manager.parseProxyLine(invalid), null);
            assert.throws(() => normalizeProxy(invalid), error =>
                /Invalid or ambiguous proxy configuration/.test(error.message) &&
                !error.message.includes('fixture-marker'));
        }
    `);
    assert.equal(result.status, 0, result.stderr);
});

test('successful proxy updates log status without the endpoint or credentials', async t => {
    const root = await makeFixture(t);
    const result = runModule(root, `
        import { createProfile, updateProfileProxy } from './src/camoufox/client.js';
        const proxy = {
            server: 'https://fixture-proxy.invalid:8443',
            username: 'fixture-proxy-user',
            password: 'fixture-proxy-password'
        };
        await createProfile('fixture', proxy, { profileId: 'fixture' });
        await updateProfileProxy('fixture', proxy);
    `);
    assert.equal(result.status, 0, result.stderr);
    const [name] = await readdir(path.join(root, 'logs'));
    const logs = await readFile(path.join(root, 'logs', name), 'utf8');
    for (const output of [result.stdout, logs]) {
        assert.match(output, /Updated Camoufox profile proxy configuration.*"hasProxy":true/);
        assert.ok(!output.includes(fixtureProxyHost));
        assert.ok(!output.includes(fixtureUser));
        assert.ok(!output.includes(fixturePassword));
    }
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

    const env = { PROFILE_SERVICE: 'camoufox', CAMOUFOX_ALLOW_DIRECT: 'true' };
    const badEnv = runNode(root, ['bin/gmail-account-creator.js'], env);
    assert.equal(badEnv.status, 1, badEnv.stderr);
    assert.match(badEnv.stderr, /Could not read \.env as a private configuration file/);

    await rm(path.join(root, '.env'));
    const badProxy = runNode(root, ['bin/gmail-account-creator.js'], env);
    assert.equal(badProxy.status, 1, badProxy.stderr);
    assert.match(badProxy.stderr, /Could not safely read or create config\/proxies\.txt/);
    assert.doesNotMatch(badProxy.stdout, /allowed direct connection/);
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

test('The application interprets commented dotenv settings consistently across Node versions', async t => {
    const root = await makeFixture(t);
    const escaped = String.raw`fixture \"quoted\" label`;
    await writeFile(path.join(root, '.env'), [
        '# Synthetic settings',
        'ACCOUNTS_COUNT=1',
        'ACCOUNTS_COUNT=2      # accounts',
        'export THREADS_COUNT=3 # threads',
        'FIXTURE_EMPTY=    ',
        'CAMOUFOX_STORAGE_DIR="./fixture # store" # storage directory',
        "SMS_VERIFY_API_KEY='fixture#literal' # only this part is a comment",
        'FIXTURE_COMMENTED_EMPTY= # empty',
        'FIXTURE_COLON: fixture-value',
        'FIXTURE_ESCAPED="' + escaped + '"',
        'FIXTURE_CARRIAGE_RETURN="first\\rsecond"',
        'FIXTURE_LINES="first\\nsecond"',
        'FIXTURE_MULTILINE="first',
        'second"'
    ].join('\r\n'), { mode: 0o600 });

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import path from 'node:path';
        import config from './src/config.js';
        assert.equal(config.app.accountsCount, 2);
        assert.equal(config.app.threadsCount, 3);
        assert.equal(config.camoufox.storageDir, path.join(process.cwd(), 'fixture # store'));
        assert.equal(config.smsVerify.apiKey, 'fixture#literal');
        assert.equal(process.env.FIXTURE_EMPTY, '');
        assert.equal(process.env.FIXTURE_COMMENTED_EMPTY, '');
        assert.equal(process.env.FIXTURE_COLON, 'fixture-value');
        assert.equal(process.env.FIXTURE_ESCAPED, ${JSON.stringify(escaped)});
        assert.equal(process.env.FIXTURE_CARRIAGE_RETURN, 'first\\rsecond');
        assert.equal(process.env.FIXTURE_LINES, 'first\\nsecond');
        assert.equal(process.env.FIXTURE_MULTILINE, 'first\\nsecond');
    `);
    assert.equal(result.status, 0, result.stderr);
});

test('Private dotenv accepts quoted Windows directories ending in a separator', async t => {
    const root = await makeFixture(t);
    const directory = 'C:\\Fixture\\Profiles\\';
    await writeFile(path.join(root, '.env'), [
        'CAMOUFOX_STORAGE_DIR="' + directory + '"',
        "FIXTURE_SINGLE='" + directory + "'",
        'FIXTURE_BACKTICK=`' + directory + '`',
        'FIXTURE_AFTER="still parsed"'
    ].join('\n'), { mode: 0o600 });

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import { win32 } from 'node:path';
        import { loadApplicationEnvironment } from './src/utils/private-env.js';
        const env = loadApplicationEnvironment({ env: {}, readOnly: true });
        const expected = ${JSON.stringify(directory)};
        assert.equal(env.CAMOUFOX_STORAGE_DIR, expected);
        assert.equal(env.FIXTURE_SINGLE, expected);
        assert.equal(env.FIXTURE_BACKTICK, expected);
        assert.equal(env.FIXTURE_AFTER, 'still parsed');
        assert.equal(win32.isAbsolute(env.CAMOUFOX_STORAGE_DIR), true);
    `);
    assert.equal(result.status, 0, result.stderr);
});

test('A vault key is validated only for a selected vault and an invalid active key stops plaintext fallback', async t => {
    const root = await makeFixture(t);
    await writeFile(path.join(root, '.env'), 'PROFILE_SERVICE=camoufox\nCAMOUFOX_STORAGE_DIR=fixture-primary\n', { mode: 0o600 });
    const env = { DOTENV_KEY: 'fixture-unrelated-label' };
    const plaintext = runModule(root, `
        import assert from 'node:assert/strict';
        import path from 'node:path';
        import { getConfiguredProfilesDirectory } from './src/utils/private-env.js';
        assert.equal(getConfiguredProfilesDirectory(), path.join(process.cwd(), 'fixture-primary'));
    `, env);
    assert.equal(plaintext.status, 0, plaintext.stderr);

    await writeFile(path.join(root, '.env.vault'), 'DOTENV_VAULT_PRODUCTION=fixture-encrypted-data\n', { mode: 0o600 });
    const selected = runModule(root, `
        import assert from 'node:assert/strict';
        import { getConfiguredProfilesDirectory } from './src/utils/private-env.js';
        assert.throws(getConfiguredProfilesDirectory, { code: 'PRIVATE_ENV_CONFIGURATION_ERROR', message: 'Invalid DOTENV_KEY' });
        assert.equal(process.env.CAMOUFOX_STORAGE_DIR, undefined);
    `, env);
    assert.equal(selected.status, 0, selected.stderr);
});

test('A vault-only state source does not fall back to legacy plaintext without a key', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'operator-state');
    await mkdir(state, { mode: 0o700 });
    await writeFile(path.join(root, '.env'), 'PROFILE_SERVICE=dolphin\nCAMOUFOX_STORAGE_DIR=legacy-profiles\n', { mode: 0o600 });
    const env = { GMAIL_CREATOR_STATE_DIR: state, GMAIL_CREATOR_LEGACY_DIR: root };

    for (const name of ['.env', '.emv']) {
        const vault = path.join(state, name + '.vault');
        await writeFile(vault, 'DOTENV_VAULT_PRODUCTION=fixture-encrypted-data\n', { mode: 0o600 });

        const missingKey = runModule(root, `
            import assert from 'node:assert/strict';
            import { getConfiguredProfilesDirectory } from './src/utils/private-env.js';
            const error = {
                code: 'PRIVATE_ENV_CONFIGURATION_ERROR',
                message: ${JSON.stringify('DOTENV_KEY is required to read ' + name + '.vault')}
            };
            assert.throws(getConfiguredProfilesDirectory, error);
            await assert.rejects(import('./src/config.js'), error);
            assert.equal(process.env.CAMOUFOX_STORAGE_DIR, undefined);
        `, env);
        assert.equal(missingKey.status, 0, missingKey.stderr);

        const readPlaintext = `
            import assert from 'node:assert/strict';
            import path from 'node:path';
            import { getConfiguredProfilesDirectory } from './src/utils/private-env.js';
            const profilesDir = path.join(process.cwd(), 'state-profiles');
            assert.equal(getConfiguredProfilesDirectory(), profilesDir);
            assert.equal(process.env.CAMOUFOX_STORAGE_DIR, undefined);
            const { default: config } = await import('./src/config.js');
            assert.equal(config.profileService, 'camoufox');
            assert.equal(config.camoufox.storageDir, profilesDir);
        `;
        for (const plaintextName of name === '.env' ? ['.env', '.emv'] : ['.emv']) {
            const plaintext = path.join(state, plaintextName);
            await writeFile(plaintext, 'PROFILE_SERVICE=camoufox\nCAMOUFOX_STORAGE_DIR=state-profiles\n', { mode: 0o600 });
            const sameSourcePlaintext = runModule(root, readPlaintext, env);
            assert.equal(sameSourcePlaintext.status, 0, sameSourcePlaintext.stderr);
            await rm(plaintext);
        }

        await rm(vault);
    }
});

test('SDK configuration retries use the corrected files after a fallback read fails', async t => {
    const root = await makeFixture(t);
    await writeFile(path.join(root, '.env'), 'CAMOUFOX_STORAGE_DIR=initial-profiles\nFIXTURE_LABEL=initial\n', { mode: 0o600 });
    await mkdir(path.join(root, '.emv'));

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import { rmdirSync, writeFileSync } from 'node:fs';
        import path from 'node:path';
        import { getProfileDir, validateCamoufoxNetworkPolicy } from './src/camoufox/client.js';

        assert.throws(() => validateCamoufoxNetworkPolicy({}, null), {
            code: 'PRIVATE_ENV_CONFIGURATION_ERROR',
            message: 'Could not read .emv as a private configuration file'
        });
        assert.equal(process.env.CAMOUFOX_STORAGE_DIR, undefined);
        assert.equal(process.env.FIXTURE_LABEL, undefined);

        rmdirSync('.emv');
        writeFileSync('.env', 'CAMOUFOX_STORAGE_DIR=corrected-profiles\\nFIXTURE_LABEL=corrected\\n');
        writeFileSync('.emv', 'PROFILE_SERVICE=camoufox\\nFIXTURE_LABEL=fallback\\n', { mode: 0o600 });
        assert.equal(validateCamoufoxNetworkPolicy({}, null), null);
        assert.equal(process.env.PROFILE_SERVICE, 'camoufox');
        assert.equal(process.env.FIXTURE_LABEL, 'corrected');
        assert.equal(getProfileDir('fixture'), path.join(process.cwd(), 'corrected-profiles', 'fixture'));
    `);
    assert.equal(result.status, 0, result.stderr);
});

test('The GoLogin fallback is read only by callers that need its key', async t => {
    const root = await makeFixture(t);
    const primary = path.join(root, '.env');
    await writeFile(primary, 'PROFILE_SERVICE=camoufox\nCAMOUFOX_STORAGE_DIR=fixture-primary\n', { mode: 0o600 });
    await mkdir(path.join(root, '.emv'));

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import path from 'node:path';
        import { getConfiguredProfilesDirectory } from './src/utils/private-env.js';
        assert.equal(getConfiguredProfilesDirectory(), path.join(process.cwd(), 'fixture-primary'));
        const { default: config } = await import('./src/config.js');
        assert.equal(config.camoufox.storageDir, path.join(process.cwd(), 'fixture-primary'));
        assert.throws(() => config.gologin.apiKey, {
            code: 'PRIVATE_ENV_CONFIGURATION_ERROR',
            message: 'Could not read .emv as a private configuration file'
        });
    `);
    assert.equal(result.status, 0, result.stderr);
});

test('A symlink state directory is rejected before loading configuration or inventory', { skip: !posix }, async t => {
    const root = await makeFixture(t);
    const target = path.join(root, 'other-state');
    const linked = path.join(root, 'linked-state');
    const contents = 'FIXTURE_LINKED_STATE=kept-out\n';
    await mkdir(target);
    await writeFile(path.join(target, '.env'), contents);
    await chmod(path.join(target, '.env'), 0o644);
    await mkdir(path.join(target, 'config'));
    const inventory = 'fixture-proxy.invalid:1080\n';
    await writeFile(path.join(target, proxyFile), inventory);
    await chmod(path.join(target, proxyFile), 0o644);
    await symlink(target, linked, 'dir');

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import manager from './src/utils/proxy-manager.js';
        await assert.rejects(import('./src/config.js'), { code: 'PRIVATE_ENV_CONFIGURATION_ERROR' });
        assert.equal(process.env.FIXTURE_LINKED_STATE, undefined);
        assert.throws(() => manager.loadProxies(), { code: 'PROXY_CONFIGURATION_ERROR' });
    `, { GMAIL_CREATOR_STATE_DIR: linked });
    assert.equal(await permissions(target, '.env'), 0o644);
    assert.equal(await readFile(path.join(target, '.env'), 'utf8'), contents);
    assert.equal(await permissions(target, proxyFile), 0o644);
    assert.equal(await readFile(path.join(target, proxyFile), 'utf8'), inventory);
    assert.equal(result.status, 0, result.stderr);
});

test('Reading configuration does not create a missing state directory', async t => {
    const root = await makeFixture(t);
    const missing = path.join(root, 'new-state');
    const result = runModule(root, `await import('./src/config.js');`, { GMAIL_CREATOR_STATE_DIR: missing });
    assert.equal(result.status, 0, result.stderr);
    await assert.rejects(stat(missing), { code: 'ENOENT' });
});

test('Reading an explicit Camoufox profile does not initialize application logs', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'missing-log-state');
    const profilesDir = path.join(root, 'explicit-profiles');
    const profile = path.join(profilesDir, 'fixture');
    await mkdir(profile, { recursive: true });
    await writeFile(path.join(profile, 'profile.json'), '{"id":"fixture"}', { mode: 0o600 });

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import { existsSync } from 'node:fs';
        import { getProfile } from './src/camoufox/client.js';
        import logger from './src/utils/logger.js';
        const state = process.env.GMAIL_CREATOR_STATE_DIR;
        assert.equal(existsSync(state), false);
        assert.deepEqual(await getProfile('fixture', { profilesDir: 'explicit-profiles' }), { id: 'fixture' });
        logger.debug('Filtered fixture message');
        assert.equal(existsSync(state), false);
    `, { GMAIL_CREATOR_STATE_DIR: state, LOG_LEVEL: 'INFO' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
    await assert.rejects(stat(state), { code: 'ENOENT' });
});

test('An unavailable application log directory affects only file logging and can recover', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'blocked-log-state');
    const profile = path.join(root, 'explicit-profiles', 'fixture');
    await writeFile(state, 'unrelated fixture', { mode: 0o600 });
    await mkdir(profile, { recursive: true });
    await writeFile(path.join(profile, 'profile.json'), '{"id":"fixture"}', { mode: 0o600 });

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import { readFileSync, unlinkSync } from 'node:fs';
        import { getProfile } from './src/camoufox/client.js';
        import logger from './src/utils/logger.js';
        const state = process.env.GMAIL_CREATOR_STATE_DIR;
        assert.deepEqual(await getProfile('fixture', { profilesDir: 'explicit-profiles' }), { id: 'fixture' });
        logger.info('Fixture with unavailable log directory');
        assert.equal(readFileSync(state, 'utf8'), 'unrelated fixture');
        unlinkSync(state);
        logger.info('Fixture after log directory recovery');
    `, { GMAIL_CREATOR_STATE_DIR: state, LOG_LEVEL: 'INFO' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Fixture with unavailable log directory/);
    assert.match(result.stdout, /Fixture after log directory recovery/);
    assert.equal(result.stderr.trim(), 'Failed to write to the application log file');

    const logDir = path.join(state, 'logs');
    const [name] = await readdir(logDir);
    const log = await readFile(path.join(logDir, name), 'utf8');
    assert.match(name, /^app-\d{4}-\d{2}-\d{2}\.log$/);
    assert.match(log, /\[INFO\] Fixture after log directory recovery\n$/);
    assert.doesNotMatch(log, /unavailable log directory/);
    if (posix) {
        assert.equal(await permissions(state, 'logs'), 0o700);
        assert.equal(await permissions(logDir, name), 0o600);
    }
});

test('The state directory cannot be an alias of the user home', { skip: !posix }, async t => {
    const root = await makeFixture(t);
    const home = path.join(root, 'fixture-home');
    const parentAlias = path.join(root, 'parent-alias');
    await mkdir(home);
    await chmod(home, 0o755);
    await writeFile(path.join(home, '.env'), 'FIXTURE_HOME_ENV=keep-private\n');
    await chmod(path.join(home, '.env'), 0o644);
    await symlink(root, parentAlias, 'dir');
    const aliases = [path.join(parentAlias, path.basename(home))];
    const caseAlias = path.join(root, 'FIXTURE-HOME');
    if (await stat(caseAlias).catch(error => {
        if (error.code !== 'ENOENT') throw error;
        return undefined;
    })) aliases.push(caseAlias);

    for (const alias of aliases) {
        const result = runModule(root, `
            import assert from 'node:assert/strict';
            const { ensureStateDirectory } = await import('./src/utils/state-paths.js');
            assert.throws(ensureStateDirectory, /must name a dedicated directory/);
            await assert.rejects(import('./src/config.js'), { code: 'PRIVATE_ENV_CONFIGURATION_ERROR' });
            assert.equal(process.env.FIXTURE_HOME_ENV, undefined);
        `, { HOME: home, GMAIL_CREATOR_STATE_DIR: alias });
        assert.equal(result.status, 0, result.stderr);
    }
    assert.equal(await permissions(root, 'fixture-home'), 0o755);
    assert.equal(await permissions(home, '.env'), 0o644);
});

test('A previously configured installation inventory requires explicit adoption before direct use', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'operator-state');
    await mkdir(state, { mode: 0o700 });
    await writeFile(path.join(root, proxyFile), 'fixture-proxy.invalid:1080\n', { mode: 0o600 });

    const env = { GMAIL_CREATOR_STATE_DIR: state, PROFILE_SERVICE: 'camoufox', CAMOUFOX_ALLOW_DIRECT: 'true' };
    const result = runNode(root, ['bin/gmail-account-creator.js'], env);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /An installation proxy inventory exists.*GMAIL_CREATOR_LEGACY_DIR/);
    assert.doesNotMatch(result.stdout, /allowed direct connection/);

    const adopted = runModule(root, `
        import assert from 'node:assert/strict';
        import manager from './src/utils/proxy-manager.js';
        assert.equal(manager.getNextProxy().ip, 'fixture-proxy.invalid');
    `, { ...env, GMAIL_CREATOR_LEGACY_DIR: root });
    assert.equal(adopted.status, 0, adopted.stderr);
});

test('An explicitly selected installation inventory accepts a path through an aliased parent', {
    skip: !posix
}, async t => {
    const root = await makeFixture(t);
    const alias = path.join(root, 'parent-alias');
    await symlink(path.dirname(root), alias, 'dir');
    const installationAlias = path.join(alias, path.basename(root));
    await writeFile(path.join(root, proxyFile), '# Intentionally empty\n', { mode: 0o600 });
    const separateState = path.join(root, 'operator-state');

    for (const env of [
        { GMAIL_CREATOR_STATE_DIR: installationAlias },
        { GMAIL_CREATOR_STATE_DIR: separateState, GMAIL_CREATOR_LEGACY_DIR: installationAlias }
    ]) {
        const result = runModule(root, `
            import assert from 'node:assert/strict';
            import manager from './src/utils/proxy-manager.js';
            assert.equal(manager.getAvailableCount(), 0);
            manager.rejectUnselectedLegacyInventory();
        `, env);
        assert.equal(result.status, 0, result.stderr);
    }
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

test('Skipping a state fallback file does not allow legacy configuration to take over', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'operator-state');
    await mkdir(state, { mode: 0o700 });
    await writeFile(path.join(state, '.emv'), 'LOG_LEVEL=debug\n', { mode: 0o600 });
    await writeFile(path.join(root, '.env'), 'DOLPHIN_API_KEY=fixture-legacy-key\n', { mode: 0o600 });
    const env = { GMAIL_CREATOR_STATE_DIR: state, GMAIL_CREATOR_LEGACY_DIR: root, PROFILE_SERVICE: 'camoufox' };

    const current = runModule(root, `
        import assert from 'node:assert/strict';
        import config from './src/config.js';
        assert.equal(config.profileService, 'camoufox');
        assert.equal(config.dolphin.apiKey, '');
        assert.equal(process.env.LOG_LEVEL, undefined);
    `, env);
    assert.equal(current.status, 0, current.stderr);

    await rm(path.join(state, '.emv'));
    const legacy = runModule(root, `
        import assert from 'node:assert/strict';
        import config from './src/config.js';
        assert.equal(config.profileService, 'camoufox');
        assert.equal(config.dolphin.apiKey, 'fixture-legacy-key');
    `, env);
    assert.equal(legacy.status, 0, legacy.stderr);
});

async function stubGoLoginModules(root, source = 'module.exports = () => { throw new Error("Unexpected transport call"); };') {
    const directory = path.join(root, 'node_modules', 'axios');
    await mkdir(directory, { recursive: true });
    await writeFile(path.join(directory, 'index.js'), source);
}

test('A GoLogin client with an explicit key ignores an unreadable default fallback', async t => {
    const root = await makeFixture(t);
    await writeFile(path.join(root, '.env'), 'PROFILE_SERVICE=camoufox\n', { mode: 0o600 });
    await mkdir(path.join(root, '.emv'));
    await stubGoLoginModules(root, `
        module.exports = async ({ headers }) => ({
            status: 200,
            data: headers.Authorization === 'Bearer fixture-explicit-key'
        });
    `);

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import { rmdirSync, writeFileSync } from 'node:fs';
        import defaultClient, { GoLoginClient, getGoLoginApiKey } from './src/gologin/client.js';

        const client = new GoLoginClient('fixture-explicit-key');
        assert.equal(await client.request('GET', '/browser/v2'), true);
        assert.equal(process.env.PROFILE_SERVICE, undefined);
        assert.equal(process.env.GOLOGIN_API_KEY, undefined);
        await assert.rejects(defaultClient.request('GET', '/browser/v2'), {
            code: 'PRIVATE_ENV_CONFIGURATION_ERROR',
            message: 'Could not read .emv as a private configuration file'
        });
        assert.equal(process.env.PROFILE_SERVICE, undefined);
        rmdirSync('.emv');
        writeFileSync('.emv', 'GOLOGIN_API_KEY=fixture-fallback-key\\n', { mode: 0o600 });
        assert.equal(getGoLoginApiKey(), 'fixture-fallback-key');
    `);
    assert.equal(result.status, 0, result.stderr);
});

test('Standalone GoLogin resolves its default key from the private state source on first use', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'operator-state');
    await mkdir(state, { mode: 0o700 });
    await stubGoLoginModules(root);
    await writeFile(path.join(state, '.env'), 'GOLOGIN_API_KEY=fixture-state-key\n');
    await writeFile(path.join(root, '.emv'), 'GOLOGIN_API_KEY=fixture-legacy-key\n', { mode: 0o600 });

    const result = runModule(root, `
        import assert from 'node:assert/strict';
        const { getGoLoginApiKey } = await import('./src/gologin/client.js');
        assert.equal(process.env.GOLOGIN_API_KEY, undefined);
        assert.equal(getGoLoginApiKey(), 'fixture-state-key');
        assert.equal(process.env.GOLOGIN_API_KEY, 'fixture-state-key');
    `, { GMAIL_CREATOR_STATE_DIR: state, GMAIL_CREATOR_LEGACY_DIR: root });
    assert.equal(result.status, 0, result.stderr);
    if (posix) assert.equal(await permissions(state, '.env'), 0o600);
});

test('Application and standalone GoLogin imports resolve the same configuration source and key', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'operator-state');
    await mkdir(state, { mode: 0o700 });
    await stubGoLoginModules(root);
    const primary = path.join(state, '.env');
    await writeFile(primary, 'PROFILE_SERVICE=camoufox\nGOLOGIN_API_KEY=fixture-primary-key\n', { mode: 0o600 });
    await writeFile(path.join(state, '.emv'), 'PROFILE_SERVICE=dolphin\nGOLOGIN_API_KEY=fixture-fallback-key\nLOG_LEVEL=debug\n', { mode: 0o600 });
    await writeFile(path.join(root, '.env'), 'DOLPHIN_API_KEY=fixture-legacy-key\n', { mode: 0o600 });
    const env = { GMAIL_CREATOR_STATE_DIR: state, GMAIL_CREATOR_LEGACY_DIR: root };

    const check = (first, expected, overrides) => {
        const result = runModule(root, `
            import assert from 'node:assert/strict';
            const firstModule = await import('./src/' + ${JSON.stringify(first)});
            firstModule.getGoLoginApiKey?.();
            const { default: config } = await import('./src/config.js');
            assert.equal(config.gologin.apiKey, ${JSON.stringify(expected)});
            const { getGoLoginApiKey } = await import('./src/gologin/client.js');
            assert.equal(config.gologin.apiKey, getGoLoginApiKey());
            assert.equal(config.profileService, 'camoufox');
            assert.equal(process.env.LOG_LEVEL, undefined);
            assert.equal(process.env.DOLPHIN_API_KEY, undefined);
        `, { ...env, ...overrides });
        assert.equal(result.status, 0, result.stderr);
    };

    for (const first of ['config.js', 'gologin/client.js']) {
        check(first, 'fixture-primary-key');
        check(first, 'fixture-exported', { GOLOGIN_API_KEY: 'fixture-exported' });
    }
    await writeFile(primary, 'PROFILE_SERVICE=camoufox\n');
    for (const first of ['config.js', 'gologin/client.js']) {
        check(first, 'fixture-fallback-key');
    }
});


test('An independent state directory works when HOME cannot be traversed', {
    skip: !posix || process.geteuid() === 0
}, async t => {
    const root = await makeFixture(t);
    const parent = path.join(root, 'home-parent');
    const home = path.join(parent, 'home');
    await mkdir(home, { recursive: true });
    await writeFile(path.join(root, '.env'), 'PROFILE_SERVICE=camoufox\n', { mode: 0o600 });
    await chmod(parent, 0o000);
    try {
        const result = runModule(root, `
            import assert from 'node:assert/strict';
            import { statSync } from 'node:fs';
            assert.throws(() => statSync(process.env.HOME), { code: 'EACCES' });
            const { default: config } = await import('./src/config.js');
            assert.equal(config.profileService, 'camoufox');
        `, { HOME: home });
        assert.equal(result.status, 0, result.stderr);
    } finally {
        await chmod(parent, 0o700);
    }
});

test('An unrelated launch setting and an empty override preserve a configured profile service', async t => {
    const root = await makeFixture(t);
    await writeFile(path.join(root, '.emv'), 'PROFILE_SERVICE=camoufox\n', { mode: 0o600 });
    const readService = `
        const { default: config } = await import('./src/config.js');
        console.log(config.profileService);
    `;
    const fallback = runModule(root, readService, { DOLPHIN_API_KEY: 'fixture-unused' });
    assert.equal(fallback.status, 0, fallback.stderr);
    assert.equal(fallback.stdout.trim(), 'camoufox');

    await writeFile(path.join(root, '.env'), 'PROFILE_SERVICE=dolphin\n', { mode: 0o600 });
    const empty = runModule(root, readService, { PROFILE_SERVICE: '' });
    assert.equal(empty.status, 0, empty.stderr);
    assert.equal(empty.stdout.trim(), 'dolphin');
    const override = runModule(root, readService, { PROFILE_SERVICE: 'camoufox' });
    assert.equal(override.status, 0, override.stderr);
    assert.equal(override.stdout.trim(), 'camoufox');

    const invalid = runNode(root, ['bin/gmail-account-creator.js'], { PROFILE_SERVICE: 'fixture-unknown' });
    assert.equal(invalid.status, 1, invalid.stderr);
    assert.match(invalid.stderr, /PROFILE_SERVICE must be gpm, dolphin, or camoufox/);
});

test('Invalid recording settings are rejected before startup and valid limits are exact', async t => {
    const root = await makeFixture(t);
    for (const [key, value] of [
        ['CAMOUFOX_RECORD_TRAFFIC', 'False'],
        ['CAMOUFOX_RECORD_WIRE_LOG', ''],
        ['CAMOUFOX_RECORD_BODIES', 'yes'],
        ['CAMOUFOX_TRAFFIC_MAX_BODY_BYTES', '0'],
        ['CAMOUFOX_TRAFFIC_MAX_BODY_BYTES', '-8'],
        ['CAMOUFOX_TRAFFIC_MAX_BODY_BYTES', '8.75'],
        ['CAMOUFOX_TRAFFIC_MAX_BODY_BYTES', '8 bytes'],
        ['CAMOUFOX_TRAFFIC_MAX_BODY_BYTES', ''],
        ['CAMOUFOX_TRAFFIC_MAX_BODY_BYTES', '9007199254740992']
    ]) {
        await writeFile(path.join(root, '.env'), 'PROFILE_SERVICE=camoufox\n' + key + '=' + value + '\n', { mode: 0o600 });
        const result = runNode(root, ['bin/gmail-account-creator.js']);
        assert.equal(result.status, 1, result.stderr);
        assert.match(result.stderr, new RegExp(key + ' must be'));
    }
    const call = runModule(root, `
        import assert from 'node:assert/strict';
        import { startProfile } from './src/camoufox/client.js';
        await assert.rejects(startProfile('invalid', { maxBodyBytes: 0 }), /maxBodyBytes must be a positive safe integer/);
        await assert.rejects(startProfile('invalid', { recordTraffic: 'false' }), /recordTraffic must be a boolean/);
    `);
    assert.equal(call.status, 0, call.stderr);

    const valid = runModule(root, `
        import assert from 'node:assert/strict';
        import config from './src/config.js';
        assert.equal(config.camoufox.recordTraffic, false);
        assert.equal(config.camoufox.recordWireLog, false);
        assert.equal(config.camoufox.maxBodyBytes, 8);
    `, { CAMOUFOX_RECORD_TRAFFIC: 'false', CAMOUFOX_RECORD_WIRE_LOG: 'false', CAMOUFOX_TRAFFIC_MAX_BODY_BYTES: '8' });
    assert.equal(valid.status, 0, valid.stderr);
});

test('Standalone Camoufox uses the deployment profiles directory and managed policy', async t => {
    const root = await makeFixture(t);
    await writeFile(path.join(root, '.env'), [
        'PROFILE_SERVICE=camoufox',
        'CAMOUFOX_STORAGE_DIR=fixture-profiles',
        'CAMOUFOX_PORT_SCAN_MODE=managed-proxy',
        'CAMOUFOX_MANAGED_EGRESS_ORIGIN=http://proxy.invalid:8080'
    ].join('\n'), { mode: 0o600 });
    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import path from 'node:path';
        import {
            getProfileDir, setCamoufoxModule, startProfile, validateCamoufoxNetworkPolicy
        } from './src/camoufox/client.js';
        import { CamoufoxTrafficRecorder } from './src/camoufox/traffic-recorder.js';

        const profiles = path.join(process.cwd(), 'fixture-profiles');
        assert.equal(getProfileDir('fixture'), path.join(profiles, 'fixture'));
        assert.equal(new CamoufoxTrafficRecorder({ profileId: 'recorder-fixture' }).profilesDir, profiles);
        setCamoufoxModule({ Camoufox: () => assert.fail('Unexpected launch without proxy authorization') });
        await assert.rejects(startProfile('fixture', { recordTraffic: false }), {
            code: 'ERR_CAMOUFOX_MANAGED_EGRESS_BINDING'
        });
        const authorized = validateCamoufoxNetworkPolicy({}, { server: 'http://proxy.invalid:8080' });
        assert.equal(authorized.origin, 'http://proxy.invalid:8080');
    `);
    assert.equal(result.status, 0, result.stderr);
});

test('Published state-directory constants preserve the valid launch-time paths', async t => {
    const root = await makeFixture(t);
    const state = path.join(root, 'state');
    const legacy = path.join(root, 'legacy');
    const result = runModule(root, `
        import assert from 'node:assert/strict';
        import { STATE_DIRECTORY, LEGACY_DIRECTORY, getStateDirectory, getLegacyDirectory } from './src/utils/state-paths.js';
        assert.equal(STATE_DIRECTORY, process.env.GMAIL_CREATOR_STATE_DIR);
        assert.equal(LEGACY_DIRECTORY, process.env.GMAIL_CREATOR_LEGACY_DIR);
        process.env.GMAIL_CREATOR_STATE_DIR = 'later-configuration';
        process.env.GMAIL_CREATOR_LEGACY_DIR = 'later-configuration';
        assert.equal(getStateDirectory(), STATE_DIRECTORY);
        assert.equal(getLegacyDirectory(), LEGACY_DIRECTORY);
    `, {
        HOME: path.join(root, 'separate-home'),
        GMAIL_CREATOR_STATE_DIR: state,
        GMAIL_CREATOR_LEGACY_DIR: legacy
    });
    assert.equal(result.status, 0, result.stderr);
    await assert.rejects(stat(state), { code: 'ENOENT' });
});

test('Audit help and explicit reads do not depend on unused state path overrides', async t => {
    const root = await makeFixture(t);
    const profilesDir = path.join(root, 'explicit-profiles');
    const profileDir = path.join(profilesDir, 'fixture');
    const trafficDir = path.join(profileDir, 'traffic');
    const auditCLI = fileURLToPath(new URL('../../scripts/query-traffic-attribution.js', import.meta.url));
    await mkdir(trafficDir, { recursive: true });
    await writeFile(path.join(profileDir, 'profile.json'), '{"id":"fixture"}\n', { mode: 0o600 });
    await writeFile(path.join(trafficDir, 'traffic.ndjson'),
        '{"type":"egress","correlationId":"fixture","url":"https://example.invalid/","method":"GET"}\n',
        { mode: 0o600 });
    const env = {
        HOME: path.join(root, 'separate-home'),
        GMAIL_CREATOR_LEGACY_DIR: path.join(root, 'legacy')
    };

    for (const [field, value] of [
        ['GMAIL_CREATOR_STATE_DIR', ''],
        ['GMAIL_CREATOR_LEGACY_DIR', ''],
        ['GMAIL_CREATOR_LEGACY_DIR', 'fixture-relative-path']
    ]) {
        const overrides = { ...env, [field]: value };
        const help = runNode(root, [auditCLI, '--help'], overrides);
        assert.equal(help.status, 0, help.stderr);
        assert.match(help.stdout, /^Usage:/);
        const explicit = runNode(root, [auditCLI, '--profiles-dir', profilesDir, '--json'], overrides);
        assert.equal(explicit.status, 0, explicit.stderr);
        assert.deepEqual(JSON.parse(explicit.stdout).profiles.map(profile => profile.profileId), ['fixture']);

        const read = runModule(root, `
            import assert from 'node:assert/strict';
            import { getProfile } from './src/camoufox/client.js';
            const profile = await getProfile('fixture', { profilesDir: ${JSON.stringify(profilesDir)} });
            assert.equal(profile.id, 'fixture');
        `, overrides);
        assert.equal(read.status, 0, read.stderr);

        const defaults = runNode(root, [auditCLI, '--json'], overrides);
        assert.equal(defaults.status, 1, defaults.stderr);
        assert.equal(defaults.stdout, '');
        assert.equal(defaults.stderr.trim(), 'Error: ' + field + ' must be an absolute path');

        const application = runNode(root, ['bin/gmail-account-creator.js'], overrides);
        assert.equal(application.status, 1, application.stderr);
        assert.equal(application.stderr.trim(), field + ' must be an absolute path');
    }
    await assert.rejects(stat(path.join(root, 'logs')), { code: 'ENOENT' });
});

test('Whitespace-only configured profile roots report errors without changing empty and relative roots', async t => {
    const root = await makeFixture(t);
    const profilesDir = path.join(root, 'fixture-profiles');
    const trafficDir = path.join(profilesDir, 'fixture', 'traffic');
    const auditCLI = fileURLToPath(new URL('../../scripts/query-traffic-attribution.js', import.meta.url));
    await mkdir(trafficDir, { recursive: true });
    await writeFile(path.join(trafficDir, 'traffic.ndjson'),
        '{"type":"egress","correlationId":"fixture","url":"https://example.invalid/","method":"GET"}\n',
        { mode: 0o600 });
    const env = {
        HOME: path.join(root, 'separate-home'),
        GMAIL_CREATOR_LEGACY_DIR: path.join(root, 'legacy')
    };
    for (const field of ['CAMOUFOX_STORAGE_DIR', 'CAMOUFOX_PROFILES_DIR']) {
        const invalid = runNode(root, [auditCLI, '--json'], { ...env, [field]: ' \t ' });
        assert.equal(invalid.status, 1, invalid.stderr);
        assert.equal(invalid.stdout, '');
        assert.match(invalid.stderr, new RegExp('^Error: ' + field + ' .*directory'));
    }

    const relative = runNode(root, [auditCLI, '--json'], {
        ...env, CAMOUFOX_STORAGE_DIR: '', CAMOUFOX_PROFILES_DIR: 'fixture-profiles'
    });
    assert.equal(relative.status, 0, relative.stderr);
    assert.deepEqual(JSON.parse(relative.stdout).profiles.map(profile => profile.profileId), ['fixture']);
});
