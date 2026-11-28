import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    ensureProfileStorage, getProfile, listProfiles, loadStorageState, updateProfileProxy
} from '../../src/camoufox/client.js';
import { appendPrivateFile } from '../../src/utils/private-storage.js';

process.env.LOG_LEVEL = 'SILENT';

function privateDirectory(t) {
    const directory = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'profile-private-io-')));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    return directory;
}

function profileFixture(t, id = 'fixture') {
    const profilesDir = privateDirectory(t);
    const storage = ensureProfileStorage(id, profilesDir);
    return { id, ...storage, profilesDir };
}

function mode(file) {
    return fs.statSync(file).mode & 0o777;
}

function addAcl(file, entry) {
    execFileSync('/bin/chmod', ['+a', entry, file]);
}

function acl(file) {
    return execFileSync('/bin/ls', ['-ledbn', file], { encoding: 'utf8' }).trimEnd().split('\n').slice(1);
}

test('the app logger preserves its existing file when an extra read ACL is present', {
    skip: process.platform !== 'darwin'
}, (t) => {
    const state = privateDirectory(t);
    const loggerModule = new URL('../../src/utils/logger.js', import.meta.url).href;
    const writeLog = (message) => {
        const result = spawnSync(process.execPath, [
            '--input-type=module', '--eval',
            'const { logger } = await import(process.argv[1]); logger.info(process.argv[2]);',
            loggerModule, message
        ], { env: { ...process.env, GMAIL_CREATOR_STATE_DIR: state, LOG_LEVEL: 'INFO' }, encoding: 'utf8' });
        assert.equal(result.status, 0, result.error?.message || result.stderr);
        return result;
    };
    assert.equal(writeLog('prior event fixture').stderr, '');
    const logDir = path.join(state, 'logs');
    const [name] = fs.readdirSync(logDir);
    const log = path.join(logDir, name);
    addAcl(log, 'group:everyone allow read');
    const original = fs.readFileSync(log);
    assert.match(writeLog('later event fixture').stderr, /Failed to write to the application log file/);
    assert.deepEqual(fs.readFileSync(log), original);
    assert.ok(acl(log).some((entry) => entry.includes('allow read')));
    assert.equal(mode(log), 0o600);

    execFileSync('/bin/chmod', ['-N', log]);
    assert.equal(writeLog('recovered event fixture').stderr, '');
    assert.match(fs.readFileSync(log, 'utf8'), /recovered event fixture/);
});

test('private append refuses an inherited grant before the first bytes and removes the empty file', {
    skip: process.platform !== 'darwin'
}, (t) => {
    const directory = privateDirectory(t);
    addAcl(directory, 'group:everyone allow list,search,file_inherit,directory_inherit');
    const log = path.join(directory, 'fresh.log');
    assert.throws(() => appendPrivateFile(log, 'temporary fixture', { requireOwner: true, checkAcl: true }), {
        code: 'PRIVATE_STORAGE_ACL_ERROR'
    });
    assert.deepEqual(fs.readdirSync(directory), []);

    execFileSync('/bin/chmod', ['-N', directory]);
    appendPrivateFile(log, 'first event fixture', { requireOwner: true });
    appendPrivateFile(log, ' and next', { requireOwner: true });
    assert.equal(fs.readFileSync(log, 'utf8'), 'first event fixture and next');
    assert.equal(mode(log), 0o600);
});

test('proxy updates cannot discard existing restrictive metadata ACLs', {
    skip: process.platform !== 'darwin'
}, async (t) => {
    const { id, profilesDir, profileDir, metadataPath } = profileFixture(t);
    const original = fs.readFileSync(metadataPath);
    const entries = fs.readdirSync(profileDir);
    addAcl(metadataPath, 'group:everyone deny writeextattr');
    const restrictions = acl(metadataPath);
    const replacement = { server: 'http://proxy.fixture.invalid:8443' };
    assert.ok(restrictions.some((entry) => entry.includes('deny writeextattr')));

    await assert.rejects(updateProfileProxy(id, replacement, { profilesDir }), {
        code: 'ERR_CAMOUFOX_PROXY_UPDATE_FAILED'
    });
    assert.deepEqual(fs.readdirSync(profileDir), entries);
    assert.deepEqual(fs.readFileSync(metadataPath), original);
    assert.deepEqual(acl(metadataPath), restrictions);

    execFileSync('/bin/chmod', ['-N', metadataPath]);
    assert.equal((await updateProfileProxy(id, replacement, { profilesDir })).success, true);
    assert.deepEqual((await getProfile(id, { profilesDir })).proxy, replacement);
    assert.equal(mode(metadataPath), 0o600);
});

function storageReadOnly() {
    return Object.assign(new Error('fixture filesystem became read-only'), { code: 'EROFS' });
}

async function failUpdate(t, { id, profilesDir, metadataPath }, replacement, { preventCleanup = true } = {}) {
    const rename = fs.renameSync;
    const rm = fs.rmSync;
    let staged;
    const renameMock = t.mock.method(fs, 'renameSync', (source, destination) => {
        if (destination === metadataPath) {
            staged = source;
            throw storageReadOnly();
        }
        rename(source, destination);
    });
    const rmMock = t.mock.method(fs, 'rmSync', (file, options) => {
        if (preventCleanup && file === staged) throw storageReadOnly();
        rm(file, options);
    });
    let result;
    try {
        await assert.rejects(updateProfileProxy(id, replacement, { profilesDir }), (error) => {
            assert.equal(error.code, 'ERR_CAMOUFOX_PROXY_UPDATE_FAILED');
            result = error;
            return true;
        });
    } finally {
        rmMock.mock.restore();
        renameMock.mock.restore();
    }
    assert.ok(staged);
    return { staged, result };
}

test('retries recover owned metadata staging after a read-only storage fault', {
    skip: process.platform === 'win32'
}, async (t) => {
    const storage = profileFixture(t);
    const { id, profilesDir, profileDir, metadataPath } = storage;
    const before = fs.readFileSync(metadataPath);
    const operatorCopy = path.join(profileDir, '.profile.json.operator-copy.tmp');
    const operatorBytes = Buffer.from('operator archive fixture');
    fs.writeFileSync(operatorCopy, operatorBytes, { mode: 0o600 });
    const entries = fs.readdirSync(profileDir);
    const replacement = { server: 'http://next.fixture.invalid:8080' };
    const { staged, result } = await failUpdate(t, storage, replacement);
    assert.deepEqual(fs.readFileSync(metadataPath), before);
    assert.equal(mode(staged), 0o600);
    assert.deepEqual(JSON.parse(fs.readFileSync(staged)).proxy, replacement);
    assert.equal(result.cleanupPending, true);

    assert.equal((await updateProfileProxy(id, replacement, { profilesDir })).success, true);
    assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath)).proxy, replacement);
    assert.deepEqual(fs.readdirSync(profileDir), entries);
    assert.deepEqual(fs.readFileSync(operatorCopy), operatorBytes);

    const noResidue = await failUpdate(t, storage, replacement, { preventCleanup: false });
    assert.equal(noResidue.result.cleanupPending, undefined);
    assert.deepEqual(fs.readdirSync(profileDir), entries);
});

test('metadata staging recovery preserves an operator copy and a file with changed permissions', {
    skip: process.platform === 'win32'
}, async (t) => {
    const storage = profileFixture(t);
    const { id, profilesDir, profileDir } = storage;
    const replacement = { server: 'http://next.fixture.invalid:8080' };
    const first = await failUpdate(t, storage, replacement);
    const operatorCopy = path.join(profileDir, 'operator-copy.json');
    fs.renameSync(first.staged, operatorCopy);
    fs.writeFileSync(first.staged, 'operator notes fixture', { mode: 0o600 });

    const second = await failUpdate(t, storage, replacement);
    fs.chmodSync(second.staged, 0o640);
    const retained = fs.readFileSync(second.staged);
    assert.equal((await updateProfileProxy(id, replacement, { profilesDir })).success, true);
    assert.equal(fs.readFileSync(first.staged, 'utf8'), 'operator notes fixture');
    assert.deepEqual(JSON.parse(fs.readFileSync(operatorCopy)).proxy, replacement);
    assert.deepEqual(fs.readFileSync(second.staged), retained);
    assert.equal(mode(second.staged), 0o640);
});

test('getProfile rejects a misplaced profile without rewriting its mode or contents', {
    skip: process.platform === 'win32'
}, async (t) => {
    const { id, profilesDir, metadataPath } = profileFixture(t);
    const misplaced = Buffer.from(JSON.stringify({ id: 'another-profile', title: 'fixture' }));
    fs.writeFileSync(metadataPath, misplaced);
    fs.chmodSync(metadataPath, 0o640);
    await assert.rejects(getProfile(id, { profilesDir }), /metadata does not match ID/);
    assert.equal(mode(metadataPath), 0o640);
    assert.deepEqual(fs.readFileSync(metadataPath), misplaced);
});

test('valid metadata and snapshot queries are read-only, storage preparation still restricts owner modes', {
    skip: process.platform === 'win32'
}, async (t) => {
    const { id, profilesDir, metadataPath, storageStatePath } = profileFixture(t);
    fs.chmodSync(metadataPath, 0o640);
    fs.chmodSync(storageStatePath, 0o640);
    assert.equal((await getProfile(id, { profilesDir })).id, id);
    assert.deepEqual((await listProfiles(profilesDir)).map((profile) => profile.id), [id]);
    assert.equal(loadStorageState(id, profilesDir), storageStatePath);
    assert.equal(mode(metadataPath), 0o640);
    assert.equal(mode(storageStatePath), 0o640);

    ensureProfileStorage(id, profilesDir);
    assert.equal(mode(metadataPath), 0o600);
    assert.equal(mode(storageStatePath), 0o600);
});
