import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    setCamoufoxModule, stopAllActiveProfiles, unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import { CamoufoxProfile } from '../../src/camoufox/profile.js';

const BASE_OBSERVATION = { domain: 'ledger-fixture.invalid', hash: 'abcd1234' };
const LATE_OBSERVATION = { domain: 'late-fixture.invalid', hash: 'abcd2345' };
const NEW_OBSERVATION = { domain: 'new-fixture.invalid', hash: 'abcd3456' };
const STALE = { code: 'ERR_CAMOUFOX_PROFILE_STALE' };
const UNREADABLE = { code: 'ERR_CAMOUFOX_FINGERPRINT_LEDGER_UNREADABLE' };

function fixture(t) {
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
                newContext: async () => context,
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
