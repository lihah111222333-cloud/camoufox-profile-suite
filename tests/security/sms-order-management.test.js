import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import {
    buyNumberAndGetSMS,
    buySmsVerifyNumber,
    buySmsVerifyNumberV2
} from '../../src/providers/sms-verification-api.js';

const API_KEY = 'fixture-api-key';
const PRIVATE_DATA = 'fixture-private-provider-data';
const ORDER_ID = 71234;
const ORDER_REPLY = `ACCESS_NUMBER:${ORDER_ID}:${PRIVATE_DATA}`;

function setEnv(t, name, value) {
    const original = process.env[name];
    process.env[name] = value;
    t.after(() => {
        if (original === undefined) delete process.env[name];
        else process.env[name] = original;
    });
}

async function importWrapper(t, selection, label) {
    setEnv(t, 'SMS_PROVIDER', selection);
    const envPaths = ['.env', '.emv'].map(name => fileURLToPath(new URL(`../../${name}`, import.meta.url)));
    const existsSync = fs.existsSync;
    t.mock.method(fs, 'existsSync', path => !envPaths.includes(path) && existsSync(path));
    return import(`../../src/providers/sms-provider.js?${label}`);
}

function mockTransport(t, ...responses) {
    setEnv(t, 'SMS_VERIFY_API_KEY', API_KEY);
    const requests = [];
    t.mock.method(globalThis, 'fetch', async url => {
        const { searchParams } = new URL(url);
        requests.push({
            action: searchParams.get('action'),
            id: searchParams.get('id'),
            status: searchParams.get('status'),
            maxPrice: searchParams.get('maxPrice')
        });
        const response = responses.shift();
        if (response instanceof Error) throw response;
        if (response === undefined) throw new Error('Unexpected fixture request');
        return new Response(response);
    });
    return requests;
}

function expectOrderError(status) {
    return error => {
        assert.equal(error.orderId, ORDER_ID);
        assert.equal(error.status, status);
        const details = inspect(error, { showHidden: true });
        assert.equal(details.includes(PRIVATE_DATA), false);
        assert.equal(details.includes(API_KEY), false);
        return true;
    };
}

test('SMS order entry points reject zero, nonfinite and invalid caps locally', async t => {
    const requests = mockTransport(t);
    for (const maxPrice of [0, -0, -1, NaN, Infinity, -Infinity, null, false, '', '0', '0.25', {}]) {
        await assert.rejects(buySmsVerifyNumber(undefined, undefined, undefined, { maxPrice }), RangeError);
        await assert.rejects(buySmsVerifyNumberV2(undefined, undefined, undefined, { maxPrice }), RangeError);
        await assert.rejects(buyNumberAndGetSMS({ maxPrice }), RangeError);
    }
    assert.deepEqual(requests, []);
});

test('SMS order requests retain positive caps and preserve omitted caps', async t => {
    const requests = mockTransport(t, 'NO_NUMBERS', 'NO_NUMBERS', 'NO_NUMBERS', 'NO_NUMBERS');
    for (const buy of [buySmsVerifyNumber, buySmsVerifyNumberV2]) {
        await assert.rejects(buy(undefined, undefined, undefined, { maxPrice: 0.25 }), /No (?:phone )?numbers available/);
        await assert.rejects(buy(), /No (?:phone )?numbers available/);
    }
    assert.deepEqual(requests.map(({ action, maxPrice }) => [action, maxPrice]), [
        ['getNumber', '0.25'], ['getNumber', null], ['getNumberV2', '0.25'], ['getNumberV2', null]
    ]);
});

test('SMS order wrapper rejects an unknown provider before requesting anything', async t => {
    const requests = mockTransport(t);
    const wrapper = await importWrapper(t, PRIVATE_DATA, 'unknown-provider');
    for (const request of [wrapper.buyNumber, wrapper.buyNumberAndGetSMS, wrapper.getOrderStatus]) {
        await assert.rejects(request(), error => {
            assert.match(error.message, /Unsupported SMS_PROVIDER/);
            assert.equal(error.message.includes(PRIVATE_DATA), false);
            return true;
        });
    }
    assert.deepEqual(requests, []);
});

test('SMS order wrapper exposes only status when checking preexisting orders', async t => {
    const requests = mockTransport(t, 'STATUS_WAIT_CODE', 'STATUS_CANCEL', `STATUS_OK:${PRIVATE_DATA}`, PRIVATE_DATA);
    const wrapper = await importWrapper(t, ' SMS-Verification ', 'reconcile-status');
    for (const status of ['PENDING', 'CANCELED', 'RECEIVED', 'UNKNOWN']) {
        assert.deepEqual(await wrapper.getOrderStatus(ORDER_ID), { status });
    }
    assert.equal(requests.length, 4);
    assert.ok(requests.every(request => request.action === 'getStatus' && request.id === String(ORDER_ID)));
});

test('SMS order wrapper distinguishes confirmed and unconfirmed finish and cancel actions', async t => {
    const requests = mockTransport(t, 'ACCESS_ACTIVATION', 'ACCESS_CANCEL', 'CANNOT_BEFORE_2_MIN', PRIVATE_DATA);
    const wrapper = await importWrapper(t, 'sms-verification', 'reconcile-actions');
    assert.equal(await wrapper.setOrderStatus(ORDER_ID, 6), true);
    assert.equal(await wrapper.setOrderStatus(ORDER_ID, 8), true);
    assert.equal(await wrapper.cancelOrder(ORDER_ID), false);
    assert.equal(await wrapper.finishOrder(ORDER_ID), false);
    await assert.rejects(wrapper.setOrderStatus(ORDER_ID, 3), RangeError);
    assert.deepEqual(requests.map(({ action, id, status }) => [action, id, status]), [
        ['setStatus', String(ORDER_ID), '6'],
        ['setStatus', String(ORDER_ID), '8'],
        ['setStatus', String(ORDER_ID), '8'],
        ['setStatus', String(ORDER_ID), '6']
    ]);
});

test('SMS order receipts distinguish cancellation confirmation from reconciliation needed', async t => {
    const cancelReplies = [
        ['CANNOT_BEFORE_2_MIN', 'RECONCILIATION_REQUIRED'],
        [PRIVATE_DATA, 'RECONCILIATION_REQUIRED'],
        [new Error(`${API_KEY} ${PRIVATE_DATA}`), 'RECONCILIATION_REQUIRED'],
        ['ACCESS_CANCEL', 'CANCELED']
    ];
    const requests = mockTransport(t, ...cancelReplies.flatMap(([reply]) => [ORDER_REPLY, reply]));
    for (const [, status] of cancelReplies) {
        await assert.rejects(buyNumberAndGetSMS({ maxWaitTime: 0, maxPrice: 0.25 }), expectOrderError(status));
    }
    assert.deepEqual(requests.map(({ action, id, status }) => [action, id, status]), cancelReplies.flatMap(() => [
        ['getNumber', null, null], ['setStatus', String(ORDER_ID), '8']
    ]));
});

test('SMS order receipts preserve cancellation observed during status lookup', async t => {
    const requests = mockTransport(t, ORDER_REPLY, 'STATUS_CANCEL');
    await assert.rejects(buyNumberAndGetSMS({ maxWaitTime: 1000, maxPrice: 0.25 }), expectOrderError('CANCELED'));
    assert.deepEqual(requests.map(({ action, id }) => [action, id]), [['getNumber', null], ['getStatus', String(ORDER_ID)]]);
});
