import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const invalidUtf8 = Buffer.from([0xc3]);

function corruptText(before, after) {
    return Buffer.concat([Buffer.from(before), invalidUtf8, Buffer.from(after)]);
}

function writeFixture(filePath, data) {
    fs.writeFileSync(filePath, data, { mode: 0o600 });
}

function listIncomplete(unreadableCount) {
    return error => {
        assert.equal(error.code, 'ERR_CAMOUFOX_PROFILE_LIST_INCOMPLETE');
        assert.equal(error.message, 'Could not read all Camoufox profile metadata');
        assert.equal(error.unreadableCount, unreadableCount);
        assert.equal(error.cause, undefined);
        assert.equal(error.path, undefined);
        return true;
    };
}

test('local configuration and profile inventories', async (t) => {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'local-inventory-test-')));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const state = path.join(root, 'state');
    const legacy = path.join(root, 'legacy');
    const profilesDir = path.join(root, 'profiles');
    for (const directory of [state, legacy, profilesDir]) fs.mkdirSync(directory, { mode: 0o700 });
    const launchSettings = { GMAIL_CREATOR_STATE_DIR: state, GMAIL_CREATOR_LEGACY_DIR: legacy };
    const oldSettings = Object.fromEntries(Object.keys(launchSettings).map(key => [key, process.env[key]]));
    Object.assign(process.env, launchSettings);
    t.after(() => {
        for (const [key, value] of Object.entries(oldSettings)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
        }
    });

    const { getProfile, listProfiles } = await import('../../src/camoufox/client.js');
    const { locateProfile, readProfileMetadata, resolveProfileNativeDirectory } =
        await import('../../src/camoufox/profile-storage.js');
    const { loadApplicationEnvironment } = await import('../../src/utils/private-env.js');
    const { default: proxyManager } = await import('../../src/utils/proxy-manager.js');

    function profileFile(id, data) {
        const directory = path.join(profilesDir, id);
        const file = path.join(directory, 'profile.json');
        fs.mkdirSync(directory, { mode: 0o700 });
        writeFixture(file, data);
        return file;
    }

    await t.test('the saved-profile list distinguishes partial and full read failure from an empty store', async () => {
        assert.deepEqual(await listProfiles(profilesDir), []);
        assert.deepEqual(await listProfiles(path.join(root, 'absent-profiles')), []);
        const goodRecord = { id: 'first', title: 'Fixture first' };
        const otherRecord = { profileId: 'second', title: 'Fixture second' };
        const first = profileFile('first', JSON.stringify(goodRecord));
        const second = profileFile('second', JSON.stringify(otherRecord));
        const originalBytes = [fs.readFileSync(first), fs.readFileSync(second)];
        const firstInode = fs.statSync(first).ino;
        const secondInode = fs.statSync(second).ino;
        const faultedInodes = new Set([secondInode]);
        const originalReads = { readFileSync: fs.readFileSync, readSync: fs.readSync };
        let faults = 0;
        for (const [method, read] of Object.entries(originalReads)) {
            fs[method] = (fileOrFd, ...args) => {
                if (typeof fileOrFd === 'number' && faultedInodes.has(fs.fstatSync(fileOrFd).ino)) {
                    faults++;
                    throw Object.assign(new Error('Synthetic I/O error ' + second), {
                        code: 'EIO',
                        path: second
                    });
                }
                return read(fileOrFd, ...args);
            };
        }
        try {
            await assert.rejects(listProfiles(profilesDir), listIncomplete(1));
            assert.deepEqual(await getProfile('first', { profilesDir }), goodRecord);
            faultedInodes.add(firstInode);
            await assert.rejects(listProfiles(profilesDir), listIncomplete(2));
            assert.equal(faults, 3);
        } finally {
            Object.assign(fs, originalReads);
        }
        const recovered = await listProfiles(profilesDir);
        assert.ok(Array.isArray(recovered));
        assert.deepEqual(recovered.sort((a, b) => (a.id ?? a.profileId).localeCompare(b.id ?? b.profileId)),
            [goodRecord, otherRecord]);
        assert.deepEqual([fs.readFileSync(first), fs.readFileSync(second)], originalBytes);
    });

    await t.test('a profiles root that cannot be enumerated has a safe, typed error', async () => {
        const file = path.join(root, 'not-a-directory');
        writeFixture(file, '');
        await assert.rejects(listProfiles(file), error => {
            assert.equal(error.code, 'ERR_CAMOUFOX_PROFILE_LIST_FAILED');
            assert.equal(error.message, 'Could not list the Camoufox profiles directory');
            assert.equal(error.cause, undefined);
            assert.equal(error.path, undefined);
            return true;
        });
    });

    await t.test('all profile metadata reads reject invalid UTF-8 and retain valid legacy data', async () => {
        const file = profileFile('historical', corruptText(
            '{"id":"historical","title":"synthetic private label', '"}'
        ));
        const location = locateProfile('historical', profilesDir);
        const invalidEncoding = {
            code: 'ERR_CAMOUFOX_PROFILE_METADATA_INVALID',
            message: 'Invalid UTF-8 in Camoufox profile metadata'
        };
        await assert.rejects(getProfile('historical', { profilesDir }), invalidEncoding);
        assert.throws(() => readProfileMetadata(location, { readOnly: true }), invalidEncoding);
        assert.throws(() => resolveProfileNativeDirectory('historical', profilesDir, { trustedLocal: true }),
            invalidEncoding);
        await assert.rejects(listProfiles(profilesDir), listIncomplete(1));

        const valid = { id: 'historical', title: '合法标题\uFFFD' };
        writeFixture(file, JSON.stringify(valid));
        assert.deepEqual(await getProfile('historical', { profilesDir }), valid);
        assert.deepEqual(readProfileMetadata(location, { readOnly: true }), valid);
        writeFixture(file, '\uFEFF' + JSON.stringify(valid));
        await assert.rejects(getProfile('historical', { profilesDir }), {
            code: 'ERR_CAMOUFOX_PROFILE_METADATA_INVALID',
            message: 'Invalid Camoufox profile metadata JSON'
        });
        fs.rmSync(path.dirname(file), { recursive: true });
    });

    await t.test('configuration rejects corrupted plaintext without applying staged values', () => {
        const primary = path.join(state, '.env');
        const fallback = path.join(state, '.emv');
        const legacyConfig = path.join(legacy, '.env');
        writeFixture(legacyConfig, 'PROFILE_SERVICE=dolphin\n');
        const env = {};
        writeFixture(primary, corruptText('PROFILE_SERVICE=camoufox\nFIXTURE_LABEL=private-value', '\n'));
        assert.throws(() => loadApplicationEnvironment({ env, readOnly: true }), {
            code: 'PRIVATE_ENV_CONFIGURATION_ERROR',
            message: 'Invalid UTF-8 in private configuration file .env'
        });
        assert.deepEqual(env, {});

        writeFixture(primary, '\uFEFFFIXTURE_LABEL=正常\uFFFD\n');
        writeFixture(fallback, corruptText('PROFILE_SERVICE=camoufox\nFIXTURE_FALLBACK=private-value', '\n'));
        assert.throws(() => loadApplicationEnvironment({ env, readOnly: true }), {
            code: 'PRIVATE_ENV_CONFIGURATION_ERROR',
            message: 'Invalid UTF-8 in private configuration file .emv'
        });
        assert.deepEqual(env, {});
        writeFixture(fallback, '\uFEFFPROFILE_SERVICE=camoufox\n');
        assert.deepEqual(loadApplicationEnvironment({ env, readOnly: true }), {
            FIXTURE_LABEL: '正常\uFFFD',
            PROFILE_SERVICE: 'camoufox'
        });
    });

    await t.test('a vault rejects damaged authenticated text and accepts valid BOM text', () => {
        const vaultFile = path.join(state, '.env.vault');
        const key = randomBytes(32);
        const env = { DOTENV_KEY: 'dotenv://:' + key.toString('hex') + '@vault.invalid?environment=test' };
        function writeVault(plaintext) {
            const nonce = randomBytes(12);
            const cipher = createCipheriv('aes-256-gcm', key, nonce);
            const encrypted = Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
            writeFixture(vaultFile, 'DOTENV_VAULT_TEST=' + encrypted.toString('base64') + '\n');
        }
        writeVault(corruptText('PROFILE_SERVICE=camoufox\nFIXTURE_VAULT=private-value', '\n'));
        assert.throws(() => loadApplicationEnvironment({ env, readOnly: true }), {
            code: 'PRIVATE_ENV_CONFIGURATION_ERROR',
            message: 'Could not parse environment configuration in .env.vault'
        });
        assert.equal(env.PROFILE_SERVICE, undefined);
        assert.equal(env.FIXTURE_VAULT, undefined);

        writeVault('\uFEFFPROFILE_SERVICE=camoufox\nFIXTURE_VAULT=正常\uFFFD\n');
        const loaded = loadApplicationEnvironment({ env, readOnly: true });
        assert.equal(loaded.PROFILE_SERVICE, 'camoufox');
        assert.equal(loaded.FIXTURE_VAULT, '正常\uFFFD');
    });

    await t.test('a corrupt proxy inventory fails closed and reloads the corrected current file', () => {
        const currentDirectory = path.join(state, 'config');
        const legacyDirectory = path.join(legacy, 'config');
        for (const directory of [currentDirectory, legacyDirectory]) fs.mkdirSync(directory, { mode: 0o700 });
        const file = path.join(currentDirectory, 'proxies.txt');
        const legacyFile = path.join(legacyDirectory, 'proxies.txt');
        writeFixture(legacyFile, 'legacy.invalid:8080\n');
        writeFixture(file, 'initial.invalid:8080\n');
        proxyManager.loadProxies();
        assert.equal(proxyManager.proxies[0].ip, 'initial.invalid');

        const invalid = corruptText('current.invalid:8080:fixture-user:fixture-private-value', '\n');
        writeFixture(file, invalid);
        const safeError = { code: 'PROXY_CONFIGURATION_ERROR', message: 'Invalid UTF-8 in config/proxies.txt' };
        assert.throws(() => proxyManager.loadProxies(), safeError);
        assert.throws(() => proxyManager.getAvailableCount(), safeError);
        assert.deepEqual(fs.readFileSync(file), invalid);

        writeFixture(file, '\uFEFFcurrent.invalid:8080:fixture-user:合法\uFFFD\n');
        assert.equal(proxyManager.getAvailableCount(), 1);
        assert.equal(proxyManager.proxies[0].ip, 'current.invalid');
        assert.equal(proxyManager.proxies[0].password, '合法\uFFFD');
    });
});
