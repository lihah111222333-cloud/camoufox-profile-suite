import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    createProfile, getProfile, getProfileMetadataPath, normalizeProxy, updateProfileProxy
} from '../../src/camoufox/client.js';
import { resolveProfileNativeDirectory } from '../../src/camoufox/profile-storage.js';

function profileOptions(t) {
    const profilesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-proxy-updates-'));
    t.after(() => fs.rmSync(profilesDir, { recursive: true, force: true }));
    return { profilesDir };
}

test('Camoufox rejects conflicting proxy protocols before persisting an archive', async (t) => {
    const options = profileOptions(t);
    const server = 'https://proxy.example.invalid:8443';
    const hostAndPort = { host: 'proxy.example.invalid', port: 8443 };
    for (const proxy of [
        { ...hostAndPort, type: 'http', protocol: 'HTTPS://' },
        { server, protocol: 'http' },
        { server: 'https://fixture-user:fixture-password@proxy.example.invalid:8443', type: 'http' }
    ]) {
        await assert.rejects(createProfile('conflict', proxy, { ...options, profileId: 'conflict' }), {
            message: 'Conflicting proxy protocols'
        });
    }
    assert.equal(await getProfile('conflict', options), null);

    for (const proxy of [
        { ...hostAndPort, protocol: 'https' },
        { ...hostAndPort, type: 'HTTPS://', protocol: 'https' },
        { server, type: 'HTTPS://', protocol: 'https' }
    ]) {
        assert.deepEqual(normalizeProxy(proxy), { server });
    }
});

test('a Camoufox proxy update requires at least one profile', async (t) => {
    const options = profileOptions(t);
    await assert.rejects(updateProfileProxy([], { server: 'http://proxy.example.invalid:8080' }, options),
        /At least one Camoufox profile ID/);
    assert.deepEqual(fs.readdirSync(options.profilesDir), []);
});

test('a partial Camoufox proxy update identifies committed and remaining profiles', {
    skip: process.platform === 'win32' || process.geteuid?.() === 0
}, async (t) => {
    const options = profileOptions(t);
    const ids = ['first', 'second', 'third'];
    const oldProxy = { server: 'https://old-proxy.example.invalid:8443' };
    const newProxy = {
        server: 'https://new-proxy.example.invalid:8443',
        username: 'fixture-user',
        password: 'fixture-password'
    };
    for (const profileId of ids) await createProfile(profileId, oldProxy, { ...options, profileId });

    const unwritable = path.join(options.profilesDir, 'second');
    fs.chmodSync(unwritable, 0o500);
    try {
        await assert.rejects(updateProfileProxy(ids, newProxy, options), (error) => {
            assert.equal(error.code, 'ERR_CAMOUFOX_PROXY_UPDATE_FAILED');
            assert.equal(error.message, 'Could not complete the Camoufox proxy update');
            assert.deepEqual(error.updatedProfileIds, ['first']);
            assert.equal(error.failedProfileId, 'second');
            assert.deepEqual(error.remainingProfileIds, ['second', 'third']);
            assert.equal(error.cause, undefined);
            for (const value of Object.values(newProxy)) {
                assert.ok(!JSON.stringify(error).includes(value));
            }
            return true;
        });
    } finally {
        fs.chmodSync(unwritable, 0o700);
    }

    assert.deepEqual((await getProfile('first', options)).proxy, newProxy);
    assert.deepEqual((await getProfile('second', options)).proxy, oldProxy);
    assert.deepEqual((await getProfile('third', options)).proxy, oldProxy);
    const completed = await updateProfileProxy(ids, newProxy, options);
    assert.equal(completed.success, true);
    for (const id of ids) assert.deepEqual((await getProfile(id, options)).proxy, newProxy);
});

test('invalid private profile JSON is rejected without returning the contents', async (t) => {
    const options = profileOptions(t);
    const proxy = { server: 'https://old-proxy.example.invalid:8443' };
    const replacement = { server: 'https://new-proxy.example.invalid:8443' };
    await createProfile('first', proxy, { ...options, profileId: 'first' });
    await createProfile('damaged', proxy, { ...options, profileId: 'damaged' });
    const firstPath = getProfileMetadataPath('first', options.profilesDir);
    const originalFirst = fs.readFileSync(firstPath);
    const metadataPath = getProfileMetadataPath('damaged', options.profilesDir);
    const password = 'synthp9';
    const damaged = JSON.stringify({ id: 'damaged', proxy: { ...proxy, password } }).replace(
        JSON.stringify(password), password
    );
    fs.writeFileSync(metadataPath, damaged, 'utf8');

    function safeError(error) {
        assert.equal(error.name, 'SyntaxError');
        assert.equal(error.code, 'ERR_CAMOUFOX_PROFILE_METADATA_INVALID');
        assert.equal(error.message, 'Invalid Camoufox profile metadata JSON');
        assert.equal(error.cause, undefined);
        assert.ok(!error.stack.includes(password));
        return true;
    }
    await assert.rejects(updateProfileProxy(['first', 'damaged'], replacement, options), safeError);
    await assert.rejects(getProfile('damaged', options), safeError);
    await assert.rejects(createProfile('damaged', proxy, { ...options, profileId: 'damaged' }), safeError);
    assert.throws(() => resolveProfileNativeDirectory('damaged', options.profilesDir), safeError);
    assert.deepEqual((await getProfile('first', options)).proxy, proxy);
    assert.deepEqual(fs.readFileSync(firstPath), originalFirst);
    assert.equal(fs.readFileSync(metadataPath, 'utf8'), damaged);
});

test('proxy updates preserve a disabled GeoIP setting and the defaults for missing settings', async (t) => {
    const options = profileOptions(t);
    const proxy = { server: 'https://old-proxy.example.invalid:8443' };
    const replacement = { server: 'https://new-proxy.example.invalid:8443' };
    await createProfile('disabled', proxy, { ...options, profileId: 'disabled', geoip: false });
    await createProfile('legacy', null, { ...options, profileId: 'legacy' });
    const legacyPath = getProfileMetadataPath('legacy', options.profilesDir);
    const legacy = JSON.parse(fs.readFileSync(legacyPath, 'utf8'));
    delete legacy.geoip;
    fs.writeFileSync(legacyPath, JSON.stringify(legacy), 'utf8');

    await updateProfileProxy(['disabled', 'legacy', 'fresh'], replacement, options);
    const disabled = await getProfile('disabled', options);
    assert.deepEqual(disabled.proxy, replacement);
    assert.equal(disabled.geoip, false);
    assert.equal((await getProfile('legacy', options)).geoip, true);
    assert.equal((await getProfile('fresh', options)).geoip, true);
});
