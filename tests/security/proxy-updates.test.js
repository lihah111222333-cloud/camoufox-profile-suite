import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createProfile, getProfile, normalizeProxy, updateProfileProxy } from '../../src/camoufox/client.js';

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
