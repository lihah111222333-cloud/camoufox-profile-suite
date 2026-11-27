import assert from 'node:assert/strict';
import test from 'node:test';
import { attachPageCompatibility } from '../../src/camoufox/profile.js';
import logger from '../../src/utils/logger.js';

test('User-Agent decisions omit the supplied value from logs, errors and page state', async (t) => {
    const messages = [];
    for (const level of ['warn', 'debug']) {
        t.mock.method(logger, level, (...args) => messages.push(args));
    }
    const page = attachPageCompatibility({});
    const marker = 'synthetic-private-ua';
    const blocked = await page.setUserAgent('Chrome/1 ' + marker);
    assert.equal(blocked.blocked, true);
    await assert.rejects(page.setUserAgent('Chrome/1 ' + marker, { strict: true }), (error) =>
        error.message.includes('Refusing to set') && !error.message.includes(marker));
    const managed = await page.setUserAgent('Firefox/1 ' + marker);
    assert.equal(managed.blocked, false);
    assert.equal(managed.applied, false);
    assert.equal(messages.length, 3);
    assert.ok(!JSON.stringify([messages, page, blocked, managed]).includes(marker));
});

test('page and frame queries preserve native strict selection and its error', async () => {
    const ambiguity = new Error('fixture matched two elements');
    const firstMatch = { id: 'first' };
    async function query(selector, options) {
        assert.equal(selector, '.fixture');
        if (options?.strict) throw ambiguity;
        return firstMatch;
    }

    const frame = { $: query };
    const page = attachPageCompatibility({ $: query, mainFrame: () => frame });
    for (const target of [page, page.mainFrame()]) {
        await assert.rejects(target.$('.fixture', { strict: true }), (error) => error === ambiguity);
        assert.equal(await target.$('.fixture', { strict: false }), firstMatch);
    }
});

test('navigation rejects multiple wait conditions before invoking the backend', async () => {
    const calls = [];
    const page = attachPageCompatibility({
        async goto(url, options) { calls.push([url, options]); },
        async waitForNavigation(options) { calls.push(options); }
    });

    const url = 'https://fixture.example.test/';
    const compound = { waitUntil: ['domcontentloaded', 'load'] };
    await assert.rejects(page.goto(url, compound), /only one waitUntil condition/);
    await assert.rejects(page.waitForNavigation(compound), /only one waitUntil condition/);
    assert.deepEqual(calls, []);
    await page.goto(url, { waitUntil: ['load'], timeout: 123 });
    await page.waitForNavigation({ waitUntil: 'networkidle2' });
    assert.deepEqual(calls, [[url, { waitUntil: 'load', timeout: 123 }], { waitUntil: 'networkidle' }]);
});

test('viewport only reflects confirmed successful resizes', async () => {
    const nativeFailure = new Error('fixture resize unavailable');
    const page = attachPageCompatibility({
        viewportSize: () => null,
        async setViewportSize({ width }) {
            if (width === 1200) throw nativeFailure;
        }
    });
    assert.equal(page.viewport(), null);
    const earlier = { width: 960, height: 600, deviceScaleFactor: 2 };
    await page.setViewport(earlier);
    await assert.rejects(
        page.setViewport({ width: 1200, height: 800, deviceScaleFactor: 1 }),
        (error) => error === nativeFailure
    );
    assert.deepEqual(page.viewport(), earlier);
    await assert.rejects(page.setViewport({ width: -1, height: 500 }), /positive integer viewport/);
    assert.deepEqual(page.viewport(), earlier);
});

test('unsupported evaluation callbacks fail before dispatch or initializer registration', async () => {
    const calls = [];
    const initialized = [];
    const element = {
        async evaluate(fn, argument) { calls.push('element value'); return fn(10, argument); },
        async evaluateHandle(fn, argument) { calls.push('element handle'); return { value: fn(10, argument) }; }
    };
    const frame = {
        async evaluateHandle(fn, argument) { calls.push('frame handle'); return { value: fn(argument) }; }
    };
    const page = attachPageCompatibility({
        async $() { return element; },
        mainFrame: () => frame,
        async evaluate(fn, argument) { calls.push('page value'); return fn(argument); },
        async addInitScript(fn, argument) { initialized.push([fn, argument]); }
    });
    const handle = await page.$('.fixture');
    const { add } = { add(a, b = 0) { return a + b; } };
    const serializationError = { name: 'TypeError', message: /serializable standalone function/ };
    await assert.rejects(page.evaluate(add, 3, 4), serializationError);
    await assert.rejects(page.mainFrame().evaluateHandle(add, 3, 4), serializationError);
    await assert.rejects(handle.evaluate(add, 3, 4), serializationError);
    await assert.rejects(handle.evaluateHandle(add, 3, 4), serializationError);
    await assert.rejects(page.evaluate('1 + 2', 3, 4), serializationError);
    await assert.rejects(page.evaluateOnNewDocument(add, 3, 4), serializationError);
    await assert.rejects(page.evaluateOnNewDocument(add, 3), serializationError);
    await assert.rejects(page.evaluateOnNewDocument(add.bind(null, 3), 4), serializationError);
    await assert.rejects(page.evaluateOnNewDocument(class Fixture {}, 3, 4), serializationError);
    assert.deepEqual(calls, []);
    assert.deepEqual(initialized, []);

    assert.equal(await page.evaluate(add, 3), 3);
    assert.equal(await page.evaluate((a, b) => a + b, 3, 4), 7);
    assert.equal(await page.evaluate(class$ => class$, 3, 4), 3);
    assert.equal((await page.mainFrame().evaluateHandle((a, b) => a + b, 3, 4)).value, 7);
    assert.equal(await handle.evaluate((base, a, b) => base + a + b, 3, 4), 17);
    assert.equal((await handle.evaluateHandle((base, a, b) => base + a + b, 3, 4)).value, 17);
    await page.evaluateOnNewDocument((a, b) => a + b, 3, 4);
    assert.equal(initialized.length, 1);
    const [[invoke, args]] = initialized;
    assert.equal(invoke(args), 7);
});
