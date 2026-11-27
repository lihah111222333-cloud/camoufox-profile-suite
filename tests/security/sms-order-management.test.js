import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import {
    buyNumberAndGetSMS,
    buySmsVerifyNumber,
    buySmsVerifyNumberV2,
    getSmsVerifyBalance,
    setSmsVerifyStatus,
    waitForSmsVerifyCode
} from '../../src/providers/sms-verification-api.js';

const API_KEY = 'fixture-api-key';
const PRIVATE_DATA = 'fixture-private-provider-data';
const PHONE_NUMBER = '+12025550123';
const SMS_CODE = '042691';
const ORDER_ID = 71234;
const ORDER_REPLY = `ACCESS_NUMBER:${ORDER_ID}:${PHONE_NUMBER}`;

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
        return response instanceof Response ? response : new Response(response);
    });
    return requests;
}

function expectOrderError(status, orderId = ORDER_ID) {
    return error => {
        assert.equal(error.name, 'SmsVerifyOrderError');
        assert.equal(error.orderId, orderId);
        assert.equal(error.status, status);
        if (status === 'RECONCILIATION_REQUIRED') assert.equal(error.retryable, false);
        const details = inspect(error, { showHidden: true });
        for (const privateValue of [PRIVATE_DATA, API_KEY, PHONE_NUMBER, SMS_CODE]) {
            assert.equal(details.includes(privateValue), false);
        }
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

test('SMS purchase uncertainty requires reconciliation without another request', async t => {
    const privateError = new Error(`${API_KEY} ${PHONE_NUMBER} ${SMS_CODE}`, { cause: PRIVATE_DATA });
    const interruptedBody = new Response(new ReadableStream({
        start(controller) { controller.error(privateError); }
    }));
    const requests = mockTransport(t, privateError, interruptedBody,
        new Response(PRIVATE_DATA, { status: 504 }), new Response('NO_BALANCE', { status: 503 }),
        new Response(PRIVATE_DATA, { status: 409 }));
    const wrapper = await importWrapper(t, 'sms-verification', 'uncertain-purchase');
    const uncertain = expectOrderError('RECONCILIATION_REQUIRED', null);
    await assert.rejects(buySmsVerifyNumber(), uncertain);
    await assert.rejects(buySmsVerifyNumberV2(), uncertain);
    await assert.rejects(buyNumberAndGetSMS({ maxWaitTime: 0 }), uncertain);
    await assert.rejects(wrapper.buyNumber(), uncertain);
    await assert.rejects(wrapper.buyNumberAndGetSMS({ maxWaitTime: 0 }), uncertain);
    assert.deepEqual(requests.map(({ action }) => action), [
        'getNumber', 'getNumberV2', 'getNumber', 'getNumber', 'getNumber'
    ]);
});

test('SMS purchase preserves explicit refusals and errors before dispatch', async t => {
    const requests = mockTransport(t, new Response('NO_BALANCE', { status: 400 }),
        new Response('BAD_KEY', { status: 403 }));
    const invalidService = { toString() { throw new Error(API_KEY); } };
    await assert.rejects(buySmsVerifyNumber(invalidService), error => {
        assert.match(error.message, /could not be prepared/);
        assert.equal(error.status, undefined);
        assert.equal(inspect(error, { showHidden: true }).includes(API_KEY), false);
        return true;
    });
    assert.deepEqual(requests, []);
    await assert.rejects(buySmsVerifyNumber(), /HTTP 400 \(NO_BALANCE\)/);
    await assert.rejects(buySmsVerifyNumberV2(), /BAD_KEY/);
    assert.equal(requests.length, 2);
});

test('SMS purchases require a valid order ID and phone in each receipt format', async t => {
    const invalidV1 = [
        [PRIVATE_DATA, null],
        [`ACCESS_NUMBER:0:${PHONE_NUMBER}`, null],
        [`ACCESS_NUMBER:${ORDER_ID}x:${PHONE_NUMBER}`, null],
        [`ACCESS_NUMBER:9007199254740992:${PHONE_NUMBER}`, null],
        [`ACCESS_NUMBER:${ORDER_ID}:`, ORDER_ID],
        [`ACCESS_NUMBER:${ORDER_ID}:0`, ORDER_ID],
        [`ACCESS_NUMBER:${ORDER_ID}:+00000`, ORDER_ID],
        [`${ORDER_REPLY}:${SMS_CODE}`, ORDER_ID]
    ];
    const invalidV2 = [
        [null, null],
        [[], null],
        [PRIVATE_DATA, null],
        [{ error: PRIVATE_DATA }, null],
        [{ activationId: -1, phoneNumber: PHONE_NUMBER }, null],
        [{ activationId: 12.5, phoneNumber: PHONE_NUMBER }, null],
        [{ activationId: '9007199254740992', phoneNumber: PHONE_NUMBER }, null],
        [{ activationId: ORDER_ID }, ORDER_ID],
        [{ activationId: ORDER_ID, phoneNumber: '0', activationCost: 0.25 }, ORDER_ID],
        [{ activationId: ORDER_ID, phoneNumber: PHONE_NUMBER, activationCost: 0.25, error: 'NO_BALANCE' }, null],
        [{ activationId: ORDER_ID, phoneNumber: PHONE_NUMBER, activationCost: 0.25, success: false }, null],
        [{ activationId: ORDER_ID, phoneNumber: PHONE_NUMBER, activationCost: 0.25, status: 'failed' }, null],
        [{ activationId: ORDER_ID, phoneNumber: { key: API_KEY, code: SMS_CODE } }, ORDER_ID]
    ];
    const requests = mockTransport(t, ...invalidV1.map(([body]) => body),
        ...invalidV2.map(([body]) => JSON.stringify(body)), `ACCESS_NUMBER:${ORDER_ID}:${PRIVATE_DATA}`);

    for (const [, orderId] of invalidV1) {
        await assert.rejects(buySmsVerifyNumber(), expectOrderError('RECONCILIATION_REQUIRED', orderId));
    }
    for (const [, orderId] of invalidV2) {
        await assert.rejects(buySmsVerifyNumberV2(), expectOrderError('RECONCILIATION_REQUIRED', orderId));
    }
    await assert.rejects(buyNumberAndGetSMS({ maxWaitTime: 0 }), expectOrderError('RECONCILIATION_REQUIRED'));
    assert.equal(requests.length, invalidV1.length + invalidV2.length + 1);
    assert.ok(requests.every(({ action, id }) => ['getNumber', 'getNumberV2'].includes(action) && id === null));
});

test('SMS purchases preserve valid V1 and V2 receipt fields', async t => {
    const v2Receipt = {
        activationId: String(ORDER_ID),
        phoneNumber: PHONE_NUMBER,
        activationCost: 0.25
    };
    const requests = mockTransport(t, ORDER_REPLY, JSON.stringify(v2Receipt));
    assert.deepEqual(await buySmsVerifyNumber(), { id: ORDER_ID, phone: PHONE_NUMBER });
    const receipt = await buySmsVerifyNumberV2();
    assert.equal(receipt.id, v2Receipt.activationId);
    assert.equal(receipt.phone, PHONE_NUMBER);
    assert.equal(receipt.price, v2Receipt.activationCost);
    assert.deepEqual(requests.map(({ action }) => action), ['getNumber', 'getNumberV2']);
});

test('SMS balance must be a finite numeric amount', async t => {
    const requests = mockTransport(t, ' 12.50 ', '-2.50', '12.50 incomplete', '[12.5,"incomplete"]', '1e309', 'null');
    assert.equal(await getSmsVerifyBalance(), 12.5);
    assert.equal(await getSmsVerifyBalance(), -2.5);
    for (let i = 0; i < 4; i++) {
        await assert.rejects(getSmsVerifyBalance(), /invalid balance/);
    }
    assert.equal(requests.length, 6);
});

test('SMS V2 receipts with unusable billing or an amount above the cap require reconciliation', async t => {
    const valid = {
        activationId: String(ORDER_ID), phoneNumber: PHONE_NUMBER, activationCost: '0.2500', currency: 'USD'
    };
    const invalid = [
        { activationCost: '0.70' }, { activationCost: '0.25000000000000000001' },
        { activationCost: '-0.25' }, { activationCost: '0.10 extra' },
        { activationCost: '1e309' }, { activationCost: null }, { activationCost: undefined },
        { currency: { amount: PRIVATE_DATA } }, { currency: '' }, { currency: null }
    ];
    const requests = mockTransport(t, JSON.stringify(valid),
        ...invalid.map(fields => JSON.stringify({ ...valid, ...fields })), 'WRONG_MAX_PRICE:');
    const buy = () => buySmsVerifyNumberV2(undefined, undefined, undefined, { maxPrice: 0.25 });
    const receipt = await buy();
    assert.equal(receipt.price, valid.activationCost);
    assert.equal(receipt.currency, valid.currency);
    for (const fields of invalid) {
        await assert.rejects(buy(), expectOrderError('RECONCILIATION_REQUIRED'), JSON.stringify(fields));
    }
    await assert.rejects(buy(), expectOrderError('RECONCILIATION_REQUIRED', null));
    assert.equal(requests.length, invalid.length + 2);
    assert.ok(requests.every(({ action, maxPrice }) => action === 'getNumberV2' && maxPrice === '0.25'));
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
    const requests = mockTransport(t, 'ACCESS_ACTIVATION', 'ACCESS_CANCEL', 'CANNOT_BEFORE_2_MIN',
        new Response('CANNOT_BEFORE_2_MIN', { status: 400 }), PRIVATE_DATA,
        new Error(API_KEY), new Response('ACCESS_CANCEL', { status: 202 }),
        new Response('CANNOT_BEFORE_2_MIN', { status: 408 }));
    const wrapper = await importWrapper(t, 'sms-verification', 'reconcile-actions');
    assert.equal(await wrapper.setOrderStatus(ORDER_ID, 6), true);
    assert.equal(await wrapper.setOrderStatus(ORDER_ID, 8), true);
    assert.equal(await wrapper.cancelOrder(ORDER_ID), false);
    assert.equal(await wrapper.cancelOrder(ORDER_ID), false);
    const unconfirmed = expectOrderError('RECONCILIATION_REQUIRED');
    await assert.rejects(wrapper.finishOrder(ORDER_ID), unconfirmed);
    await assert.rejects(wrapper.finishOrder(ORDER_ID), unconfirmed);
    await assert.rejects(wrapper.cancelOrder(ORDER_ID), unconfirmed);
    await assert.rejects(wrapper.cancelOrder(ORDER_ID), unconfirmed);
    await assert.rejects(wrapper.setOrderStatus(ORDER_ID, 3), RangeError);
    assert.deepEqual(requests.map(({ action, id, status }) => [action, id, status]),
        ['6', '8', '8', '8', '6', '6', '8', '8'].map(status => ['setStatus', String(ORDER_ID), status]));
});

test('SMS order mutations reject invalid targets before dispatch', async t => {
    const requests = mockTransport(t, 'ACCESS_CANCEL', 'ACCESS_ACTIVATION');
    const wrapper = await importWrapper(t, 'sms-verification', 'invalid-order-target');
    for (const id of [undefined, null, '', ' ', NaN, 0, -1, '12x', '9007199254740992']) {
        await assert.rejects(wrapper.cancelOrder(id), /Order ID must/);
        await assert.rejects(wrapper.setOrderStatus(id, 6), /Order ID must/);
        await assert.rejects(setSmsVerifyStatus(id, '8'), /Order ID must/);
    }
    assert.deepEqual(requests, []);
    const stringId = `00${ORDER_ID}`;
    assert.equal(await wrapper.cancelOrder(stringId), true);
    assert.equal(await setSmsVerifyStatus(ORDER_ID, '6'), 'ACCESS_ACTIVATION');
    assert.deepEqual(requests.map(({ id, status }) => [id, status]), [[stringId, '8'], [String(ORDER_ID), '6']]);
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

test('SMS status polling sleep is limited to the remaining wait budget', async t => {
    let now = 0;
    const sleeps = [];
    const response = new Response('STATUS_WAIT_CODE');
    t.mock.method(response, 'text', async () => {
        now += 5;
        return 'STATUS_WAIT_CODE';
    });
    const requests = mockTransport(t, response);
    t.mock.method(performance, 'now', () => now);
    t.mock.method(globalThis, 'setTimeout', (resolve, delay) => {
        sleeps.push(delay);
        now += delay;
        queueMicrotask(resolve);
    });
    await assert.rejects(waitForSmsVerifyCode(ORDER_ID, 50), /Timeout waiting/);
    assert.deepEqual(sleeps, [45]);
    assert.equal(requests.length, 1);
    assert.equal(now, 50);
});

test('SMS pending status request is aborted at the wait deadline', async t => {
    let now = 0;
    const timeouts = [];
    const controller = new AbortController();
    setEnv(t, 'SMS_VERIFY_API_KEY', API_KEY);
    t.mock.method(performance, 'now', () => now);
    t.mock.method(AbortSignal, 'timeout', milliseconds => {
        timeouts.push(milliseconds);
        return controller.signal;
    });
    const fetch = t.mock.method(globalThis, 'fetch', async (url, { signal }) => {
        assert.equal(new URL(url).searchParams.get('action'), 'getStatus');
        return new Promise((resolve, reject) => {
            signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        });
    });
    const waiting = waitForSmsVerifyCode(ORDER_ID, 50);
    now += 50;
    controller.abort();
    await assert.rejects(waiting, /Timeout waiting/);
    assert.deepEqual(timeouts, [50]);
    assert.equal(fetch.mock.callCount(), 1);
});
