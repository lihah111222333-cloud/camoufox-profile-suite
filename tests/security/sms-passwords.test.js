import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import * as smsVerify from '../../src/providers/sms-verification-api.js';

const SMS_KEY = 'fixture-sms-key+&/';
const LEGACY_KEY = 'fixture-legacy-key';
const SMS_CODE = '042691';

function replaceForTest(t, target, name, replacement) {
    const existed = Object.hasOwn(target, name);
    const original = target[name];
    target[name] = replacement;
    t.after(() => {
        if (existed) target[name] = original;
        else delete target[name];
    });
}

function assertNoSmsSecrets(value) {
    const serialized = inspect(value, { depth: null, showHidden: true });
    for (const secret of [SMS_KEY, encodeURIComponent(SMS_KEY), LEGACY_KEY, SMS_CODE]) {
        assert.ok(!serialized.includes(secret), 'Diagnostic output contains an SMS secret');
    }
}

function hideLocalEnv(t) {
    const localEnvFiles = ['.env', '.emv'].map(name => fileURLToPath(new URL(`../../${name}`, import.meta.url)));
    const existsSync = fs.existsSync;
    replaceForTest(t, fs, 'existsSync', path => !localEnvFiles.includes(path) && existsSync(path));
}

function captureLogs(t) {
    const logs = [];
    for (const method of ['log', 'error', 'warn']) {
        replaceForTest(t, console, method, (...args) => logs.push(args));
    }
    return logs;
}

test('5SIM Legacy rejects each operation before any network request', async (t) => {
    hideLocalEnv(t);
    replaceForTest(t, process.env, 'SMS_VERIFY_API_KEY', SMS_KEY);
    replaceForTest(t, process.env, 'FIVESIM_API_KEY', '');
    replaceForTest(t, process.env, 'SMS_PROVIDER', 'fivesim-legacy');
    let requests = 0;
    replaceForTest(t, globalThis, 'fetch', async () => {
        requests++;
        throw new Error('Unexpected network request');
    });

    const wrapper = await import('../../src/providers/sms-provider.js?legacy');
    const disabled = /5SIM Legacy is disabled.*HTTPS/;
    await assert.rejects(wrapper.getBalance(), disabled);
    await assert.rejects(wrapper.buyNumber(), disabled);

    process.env.FIVESIM_API_KEY = LEGACY_KEY;
    process.env.SMS_PROVIDER = '5sim-legacy';
    const alias = await import('../../src/providers/sms-provider.js?legacy-alias');
    await assert.rejects(alias.getBalance(), disabled);

    const direct = await import('../../src/providers/fivesim-api-legacy.js');
    const operations = [
        'getLegacyBalance', 'getLegacyNumbersStatus', 'buyLegacyNumber', 'getLegacyOrderStatus',
        'setLegacyOrderStatus', 'cancelLegacyOrder', 'finishLegacyOrder', 'requestLegacyResend',
        'reportLegacyNumberUsed', 'waitForLegacySMS', 'buyLegacyNumberAndGetSMS'
    ];
    for (const name of operations) {
        assert.equal(direct.default[name], direct[name]);
        await assert.rejects(direct[name](), disabled);
    }
    assert.equal(requests, 0);
});

test('SMS Verify requires a nonblank dedicated key before sending or polling', async (t) => {
    replaceForTest(t, process.env, 'SMS_VERIFY_API_KEY', '');
    replaceForTest(t, process.env, 'FIVESIM_API_KEY', LEGACY_KEY);
    let requests = 0;
    replaceForTest(t, globalThis, 'fetch', async () => {
        requests++;
        throw new Error('Unexpected network request');
    });

    await assert.rejects(smsVerify.getSmsVerifyBalance(), /Set SMS_VERIFY_API_KEY/);
    process.env.SMS_VERIFY_API_KEY = '   ';
    await assert.rejects(smsVerify.waitForSmsVerifyCode(1, 1000, 1), /Set SMS_VERIFY_API_KEY/);
    assert.equal(requests, 0);
});

test('SMS Verify uses its dedicated key over HTTPS with redirects disabled', async (t) => {
    hideLocalEnv(t);
    replaceForTest(t, process.env, 'SMS_PROVIDER', '');
    replaceForTest(t, process.env, 'SMS_VERIFY_API_KEY', SMS_KEY);
    replaceForTest(t, process.env, 'FIVESIM_API_KEY', LEGACY_KEY);
    const requests = [];
    replaceForTest(t, globalThis, 'fetch', async (url, options) => {
        requests.push({ url: new URL(url), options });
        return new Response('12.50');
    });

    const provider = await import('../../src/providers/sms-provider.js?default');
    assert.equal(await provider.getBalance(), 12.5);
    assert.equal(requests.length, 1);
    const [{ url, options }] = requests;
    assert.equal(url.protocol, 'https:');
    assert.equal(url.host, 'sms-verification-number.com');
    assert.equal(url.pathname, '/stubs/handler_api');
    assert.deepEqual(url.searchParams.getAll('api_key'), [SMS_KEY]);
    assert.equal(options.redirect, 'error');
});

test('SMS Verify drops provider bodies and transport details from errors', async (t) => {
    replaceForTest(t, process.env, 'SMS_VERIFY_API_KEY', SMS_KEY);
    const logs = captureLogs(t);
    const sensitiveData = { apiKey: SMS_KEY, code: SMS_CODE };
    const responses = [
        () => new Response(JSON.stringify(sensitiveData), { status: 503 }),
        () => new Response(`WRONG_MAX_PRICE:${SMS_CODE}`),
        () => new Response(`WRONG_MAX_PRICE:${SMS_CODE}`),
        () => new Response(JSON.stringify(sensitiveData)),
        () => { throw new Error(SMS_KEY, { cause: sensitiveData }); }
    ];
    replaceForTest(t, globalThis, 'fetch', async () => responses.shift()());

    for (const [operation, message] of [
        [smsVerify.getSmsVerifyBalance, /HTTP 503/],
        [smsVerify.buySmsVerifyNumber, /Price too low/],
        [smsVerify.buySmsVerifyNumberV2, /Price too low/],
        [smsVerify.buySmsVerifyNumber, /purchase is unconfirmed/],
        [smsVerify.getSmsVerifyBalance, /request failed/]
    ]) {
        await assert.rejects(operation(), error => {
            assert.match(error.message, message);
            assertNoSmsSecrets(error);
            return true;
        });
    }
    assertNoSmsSecrets(logs);
});

test('SMS Verify polling returns the code while keeping diagnostics free of provider data', async (t) => {
    replaceForTest(t, process.env, 'SMS_VERIFY_API_KEY', SMS_KEY);
    const logs = captureLogs(t);
    const responses = [
        new Response(`Provider failure ${SMS_KEY} ${SMS_CODE}`, { status: 503 }),
        new Response(`STATUS_WAIT_RETRY:${SMS_CODE}`),
        new Response(`STATUS_OK:${SMS_CODE}`),
        new Response('BAD_KEY', { status: 403 }),
        new Response(`STATUS_WAIT_RETRY:${SMS_CODE}`),
        new Response('STATUS_CANCEL')
    ];
    replaceForTest(t, globalThis, 'fetch', async () => responses.shift());

    assert.equal(await smsVerify.waitForSmsVerifyCode(1, 1000, 1), SMS_CODE);
    await assert.rejects(smsVerify.waitForSmsVerifyCode(1, 1000, 1), /BAD_KEY/);
    assert.deepEqual(await smsVerify.checkSmsVerifyOrder(1), { status: 'UNKNOWN', code: null });
    await assert.rejects(smsVerify.waitForSmsVerifyCode(1, 1000, 1), /Order was canceled/);
    assert.equal(responses.length, 0);
    assertNoSmsSecrets(logs);
});

test('password generation uses a cryptographic RNG and keeps the established character rules', async (t) => {
    const logsDir = fileURLToPath(new URL('../../logs', import.meta.url));
    const existsSync = fs.existsSync;
    replaceForTest(t, fs, 'existsSync', path => path === logsDir || existsSync(path));
    replaceForTest(t, process.env, 'LOG_LEVEL', 'ERROR');
    const { default: nameGenerator } = await import('../../src/utils/name-generator.js');

    replaceForTest(t, Math, 'random', () => {
        throw new Error('Password generation used Math.random');
    });

    for (const [length, expectedLength] of [[undefined, 16], [3, 4], [4, 4], [24, 24]]) {
        const password = nameGenerator.generatePassword(length);
        assert.equal(password.length, expectedLength);
        assert.match(password, /^[A-Za-z0-9!@#$%^&*]+$/);
        assert.match(password, /[A-Z]/);
        assert.match(password, /[a-z]/);
        assert.match(password, /[0-9]/);
        assert.match(password, /[!@#$%^&*]/);
    }
});
