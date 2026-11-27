import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    CanvasWebglConsistencyLedger, setCamoufoxModule, stopAllActiveProfiles, unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import { acquireDirectoryLease, releaseProfileLease } from '../../src/camoufox/profile-storage.js';
import { CamoufoxProfile } from '../../src/camoufox/profile.js';

const BASE_OBSERVATION = { domain: 'ledger-fixture.invalid', hash: 'abcd1234' };
const LATE_OBSERVATION = { domain: 'late-fixture.invalid', hash: 'abcd2345' };
const NEW_OBSERVATION = { domain: 'new-fixture.invalid', hash: 'abcd3456' };
const STALE = { code: 'ERR_CAMOUFOX_PROFILE_STALE' };
const UNREADABLE = { code: 'ERR_CAMOUFOX_FINGERPRINT_LEDGER_UNREADABLE' };
const CONFLICT = { code: 'ERR_CAMOUFOX_FINGERPRINT_LEDGER_CONFLICT' };

function fixture(t, beforeContext = () => {}) {
    const profilesDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'fingerprint-ledger-test-'));
    const profileId = 'profile-fixture';
    const profileDir = path.join(profilesDir, profileId);
    const ledgerPath = path.join(profileDir, 'fingerprint-ledger.json');
    setCamoufoxModule({
        async Camoufox() {
            let connected = true;
            let closed = false;
            const browser = Object.assign(new EventEmitter(), {
                isConnected: () => connected,
                async newContext() {
                    beforeContext();
                    return context;
                },
                async close() {
                    if (!connected) return;
                    connected = false;
                    await context.close();
                    browser.emit('disconnected');
                }
            });
            const context = Object.assign(new EventEmitter(), {
                browser: () => browser,
                pages: () => [page],
                isClosed: () => closed,
                storageState: async () => ({ cookies: [], origins: [] }),
                async close() {
                    if (closed) return;
                    closed = true;
                    context.emit('close');
                }
            });
            const page = Object.assign(new EventEmitter(), {
                context: () => context,
                isClosed: () => closed,
                url: () => 'about:blank'
            });
            return browser;
        }
    });
    t.after(async () => {
        await stopAllActiveProfiles();
        unregisterProcessCleanupHooks();
        setCamoufoxModule();
        fs.rmSync(profilesDir, { recursive: true, force: true });
    });
    async function open() {
        const profile = new CamoufoxProfile(profileId, {
            profilesDir,
            enablePortScanProtection: false,
            recordTraffic: false,
            recordHar: false,
            sslKeyLog: false,
            neckoMozLog: false
        });
        await profile.start();
        return profile;
    }
    return { ledgerPath, profileDir, open };
}

function standaloneFixture(t) {
    const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'standalone-fingerprint-ledger-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const ledgerPath = path.join(directory, 'ledger.json');
    const open = () => new CanvasWebglConsistencyLedger({ profileId: 'fixture', ledgerPath });
    return { ledgerPath, open };
}

test('retired fingerprint ledgers cannot restore deleted storage or touch the same ID after reuse', async (t) => {
    const { ledgerPath, profileDir, open } = fixture(t);
    const original = await open();
    const ledger = original.getFingerprintLedger();
    assert.equal(original.recordOrVerifyFingerprint(BASE_OBSERVATION).status, 'recorded-initial');
    const committed = fs.readFileSync(ledgerPath);
    assert.equal(await original.stop(), true);
    assert.throws(() => original.recordOrVerifyFingerprint(LATE_OBSERVATION), STALE);
    assert.throws(() => ledger.recordOrVerify(LATE_OBSERVATION), STALE);
    assert.equal(ledger.saveToDisk(), false);
    assert.deepEqual(fs.readFileSync(ledgerPath), committed);

    assert.equal(await original.delete(), true);
    assert.equal(fs.existsSync(profileDir), false);
    assert.throws(() => original.recordOrVerifyFingerprint(LATE_OBSERVATION), STALE);
    assert.equal(ledger.saveToDisk(), false);
    assert.equal(fs.existsSync(profileDir), false);

    const replacement = await open();
    assert.equal(replacement.recordOrVerifyFingerprint(NEW_OBSERVATION).status, 'recorded-initial');
    const updated = fs.readFileSync(ledgerPath);
    assert.deepEqual(JSON.parse(updated).entries.map(({ domain }) => domain), [NEW_OBSERVATION.domain]);
    assert.equal(ledger.loadFromDisk(), false);
    assert.throws(() => original.recordOrVerifyFingerprint(LATE_OBSERVATION), STALE);
    assert.equal(ledger.saveToDisk(), false);
    assert.deepEqual(fs.readFileSync(ledgerPath), updated);
    assert.equal(await replacement.stop(), true);
    assert.throws(() => ledger.recordOrVerify(LATE_OBSERVATION), STALE);
    assert.equal(ledger.saveToDisk(), false);
    assert.deepEqual(fs.readFileSync(ledgerPath), updated);
});

test('fingerprint ledger parse and read failures preserve the original evidence through stop', async (t) => {
    const { ledgerPath, open } = fixture(t);
    const original = await open();
    assert.equal(original.recordOrVerifyFingerprint(BASE_OBSERVATION).status, 'recorded-initial');
    assert.equal(await original.stop(), true);
    const intact = fs.readFileSync(ledgerPath);
    for (const damaged of [intact.subarray(0, -1), Buffer.from('{"entries":null}')]) {
        fs.writeFileSync(ledgerPath, damaged);
        const restarted = await open();
        const unreadable = restarted.getFingerprintLedger();
        const { loadFailed, totalEntries, driftAlertCount } = unreadable.getSummary();
        assert.deepEqual({ loadFailed, totalEntries, driftAlertCount }, {
            loadFailed: true, totalEntries: null, driftAlertCount: null
        });
        assert.throws(() => restarted.recordOrVerifyFingerprint(LATE_OBSERVATION), UNREADABLE);
        assert.equal(unreadable.saveToDisk(), false);
        assert.equal(await restarted.stop(), true);
        assert.deepEqual(fs.readFileSync(ledgerPath), damaged);
    }

    fs.writeFileSync(ledgerPath, intact);
    const openSync = fs.openSync;
    const simulatedFailure = t.mock.method(fs, 'openSync', (file, ...args) => {
        if (file === ledgerPath) throw Object.assign(new Error('Fixture read failed'), { code: 'EIO' });
        return openSync(file, ...args);
    });
    const temporarilyUnavailable = await open();
    simulatedFailure.mock.restore();
    const ledger = temporarilyUnavailable.getFingerprintLedger();
    assert.equal(ledger.loadFailed, true);
    assert.throws(() => ledger.recordOrVerify(LATE_OBSERVATION), UNREADABLE);
    assert.equal(ledger.saveToDisk(), false);
    assert.deepEqual(fs.readFileSync(ledgerPath), intact);

    assert.equal(ledger.loadFromDisk(), true);
    assert.equal(ledger.loadFailed, false);
    assert.equal(temporarilyUnavailable.recordOrVerifyFingerprint(BASE_OBSERVATION).status, 'consistent');
    assert.equal(await temporarilyUnavailable.stop(), true);
    assert.equal(JSON.parse(fs.readFileSync(ledgerPath)).entries[0].verificationCount, 2);
});

test('a transient ownership read failure blocks fingerprint writes until the existing ledger loads', async (t) => {
    let injectOwnershipError = false;
    let metadataReadPending = false;
    let failures = 0;
    const { ledgerPath, profileDir, open } = fixture(t, () => {
        metadataReadPending = injectOwnershipError;
    });
    const original = await open();
    assert.equal(original.recordOrVerifyFingerprint(BASE_OBSERVATION).status, 'recorded-initial');
    assert.equal(await original.stop(), true);
    const intact = fs.readFileSync(ledgerPath);
    const metadataPath = path.join(profileDir, 'profile.json');
    const openSync = fs.openSync;
    const fault = t.mock.method(fs, 'openSync', (file, ...args) => {
        if (metadataReadPending && file === metadataPath) {
            metadataReadPending = false;
            failures++;
            throw Object.assign(new Error('Fixture ownership read failed'), { code: 'EIO' });
        }
        return openSync(file, ...args);
    });
    injectOwnershipError = true;
    const restarted = await open();
    fault.mock.restore();
    assert.equal(failures, 1);
    const ledger = restarted.getFingerprintLedger();
    assert.equal(ledger.getSummary().loadFailed, true);
    assert.equal(ledger.getSummary().totalEntries, null);
    assert.equal(ledger.saveToDisk(), false);
    assert.throws(() => restarted.recordOrVerifyFingerprint(NEW_OBSERVATION), UNREADABLE);
    assert.deepEqual(fs.readFileSync(ledgerPath), intact);

    assert.equal(ledger.loadFromDisk(), true);
    assert.equal(restarted.recordOrVerifyFingerprint(NEW_OBSERVATION).status, 'recorded-initial');
    assert.equal(await restarted.stop(), true);
    assert.deepEqual(JSON.parse(fs.readFileSync(ledgerPath)).entries.map(({ domain }) => domain), [
        BASE_OBSERVATION.domain, NEW_OBSERVATION.domain
    ]);
});

test('standalone fingerprint ledgers reject a stale snapshot and support a fresh reload', (t) => {
    const { ledgerPath, open } = standaloneFixture(t);
    const writer = open();
    const unopened = open();
    assert.equal(writer.recordOrVerify(BASE_OBSERVATION).status, 'recorded-initial');
    assert.throws(() => unopened.recordOrVerify(LATE_OBSERVATION), CONFLICT);
    assert.equal(unopened.getSummary().totalEntries, 0);

    const stale = open();
    const pending = acquireDirectoryLease(ledgerPath + '.ledger-lock');
    try {
        assert.throws(() => writer.recordOrVerify(NEW_OBSERVATION), { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });
        assert.equal(writer.getSummary().totalEntries, 1);
    } finally {
        releaseProfileLease(pending);
    }
    assert.equal(writer.recordOrVerify(NEW_OBSERVATION).status, 'recorded-initial');
    const written = fs.readFileSync(ledgerPath);
    assert.equal(stale.saveToDisk(), false);
    assert.throws(() => stale.recordOrVerify(LATE_OBSERVATION), CONFLICT);
    assert.deepEqual(fs.readFileSync(ledgerPath), written);
    assert.equal(stale.getSummary().totalEntries, 1);

    assert.equal(stale.loadFromDisk(), true);
    assert.equal(stale.recordOrVerify(LATE_OBSERVATION).status, 'recorded-initial');
    assert.deepEqual(JSON.parse(fs.readFileSync(ledgerPath)).entries.map(({ domain }) => domain), [
        BASE_OBSERVATION.domain, NEW_OBSERVATION.domain, LATE_OBSERVATION.domain
    ]);
});

test('fingerprint ledgers preserve invalid UTF-8 and still load legacy and valid Unicode data', (t) => {
    const { ledgerPath, open } = standaloneFixture(t);
    fs.writeFileSync(ledgerPath, '{"entries":[]}');
    const legacy = open();
    assert.equal(legacy.loadFromDisk(), true);
    assert.equal(legacy.getSummary().totalEntries, 0);

    const observation = { ...BASE_OBSERVATION, drewText: '合成观测记录' };
    assert.equal(legacy.recordOrVerify(observation).status, 'recorded-initial');
    const intact = fs.readFileSync(ledgerPath);
    assert.equal(JSON.parse(intact).entries[0].drewText, observation.drewText);

    const damaged = Buffer.from(intact);
    const field = Buffer.from('"drewText": "');
    const fieldOffset = damaged.indexOf(field);
    assert.notEqual(fieldOffset, -1);
    damaged[fieldOffset + field.length] = 0xff;
    fs.writeFileSync(ledgerPath, damaged);

    const restarted = open();
    assert.equal(restarted.loadFromDisk(), false);
    assert.equal(restarted.getSummary().totalEntries, null);
    assert.equal(restarted.saveToDisk(), false);
    assert.throws(() => restarted.recordOrVerify(LATE_OBSERVATION), UNREADABLE);
    assert.deepEqual(fs.readFileSync(ledgerPath), damaged);

    fs.writeFileSync(ledgerPath, intact);
    assert.equal(restarted.loadFromDisk(), true);
    assert.equal(restarted.recordOrVerify(observation).status, 'consistent');
    assert.equal(JSON.parse(fs.readFileSync(ledgerPath)).entries[0].drewText, observation.drewText);
});

test('fingerprint ledger cleanup failures preserve the actual publication outcome', (t) => {
    const { ledgerPath, open } = standaloneFixture(t);
    const ledger = open();
    assert.equal(ledger.recordOrVerify(BASE_OBSERVATION).status, 'recorded-initial');

    const warning = t.mock.method(process, 'emitWarning', () => {});
    const rmdirSync = fs.rmdirSync;
    let cleanupFailure = true;
    t.mock.method(fs, 'rmdirSync', (directory, ...args) => {
        if (cleanupFailure && directory === ledgerPath + '.ledger-lock') {
            cleanupFailure = false;
            throw Object.assign(new Error('Fixture cleanup failed'), { code: 'EIO' });
        }
        return rmdirSync(directory, ...args);
    });

    assert.equal(ledger.recordOrVerify(NEW_OBSERVATION).status, 'recorded-initial');
    assert.equal(ledger.getSummary().totalEntries, 2);
    assert.equal(JSON.parse(fs.readFileSync(ledgerPath)).entries.length, 2);
    assert.equal(warning.mock.calls[0]?.arguments[1].code, 'CAMOUFOX_FINGERPRINT_LEDGER_LEASE_CLEANUP_FAILED');

    cleanupFailure = true;
    assert.equal(ledger.saveToDisk(), true);
    assert.equal(warning.mock.callCount(), 2);
    const written = fs.readFileSync(ledgerPath);

    const renameSync = fs.renameSync;
    t.mock.method(fs, 'renameSync', (source, target) => {
        if (target === ledgerPath) {
            throw Object.assign(new Error('Fixture publication failed'), { code: 'ENOSPC' });
        }
        return renameSync(source, target);
    });
    cleanupFailure = true;
    assert.throws(() => ledger.recordOrVerify(LATE_OBSERVATION), { code: 'ENOSPC' });
    assert.equal(warning.mock.callCount(), 3);
    assert.equal(ledger.getSummary().totalEntries, 2);
    assert.deepEqual(fs.readFileSync(ledgerPath), written);
});
