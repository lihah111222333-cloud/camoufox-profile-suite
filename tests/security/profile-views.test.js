import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import camoufoxClient, * as camoufoxExports from '../../src/camoufox/client.js';
import {
    setCamoufoxModule,
    startProfile,
    stopAllActiveProfiles,
    stopProfile,
    unregisterProcessCleanupHooks
} from '../../src/camoufox/client.js';
import {
    attachBrowserCompatibility,
    attachElementHandleCompatibility,
    CamoufoxProfile
} from '../../src/camoufox/profile.js';

function createMockBrowser() {
    const contexts = [];
    let connected = true;
    const browser = {
        contexts: () => contexts.map(({ context }) => context),
        isConnected: () => connected,
        async close() {
            connected = false;
            await Promise.all(contexts.map(({ context }) => context.close()));
        },
        async newContext() {
            const context = new EventEmitter();
            const pages = [];
            const clicks = [];
            const navigations = [];
            let closed = false;
            const openPage = () => {
                let url = 'about:blank';
                const newHandle = async (selector) => ({
                    async click() {
                        clicks.push(selector);
                    }
                });
                const frame = { $: newHandle };
                const page = Object.assign(new EventEmitter(), {
                    context: () => context,
                    url: () => url,
                    async goto(nextUrl, options) {
                        navigations.push({ url: nextUrl, options });
                        url = nextUrl;
                    },
                    async click(selector) {
                        clicks.push(selector);
                    },
                    $: newHandle,
                    mainFrame: () => frame,
                    frames: () => [frame]
                });
                pages.push(page);
                context.emit('page', page);
                return page;
            };
            Object.assign(context, {
                browser: () => browser,
                pages: () => [...pages],
                newPage: async () => openPage(),
                async storageState() {
                    return { cookies: [], origins: [] };
                },
                async close() {
                    if (closed) return;
                    closed = true;
                    await new Promise((resolve) => setImmediate(resolve));
                    context.emit('close');
                }
            });
            contexts.push({ context, openPage, clicks, navigations });
            return context;
        }
    };
    return { browser, contexts };
}

async function setupProfiles(t, recordTraffic = false) {
    const profilesDir = await fs.mkdtemp(path.join(os.tmpdir(), 'camoufox-profile-views-'));
    const engine = createMockBrowser();
    let launchCount = 0;
    setCamoufoxModule({
        async Camoufox() {
            launchCount += 1;
            return engine.browser;
        }
    });
    t.after(async () => {
        try {
            await stopAllActiveProfiles();
        } finally {
            unregisterProcessCleanupHooks();
            setCamoufoxModule();
            await fs.rm(profilesDir, { recursive: true, force: true });
        }
    });
    const options = {
        profilesDir,
        useSharedBrowser: true,
        enablePortScanProtection: false,
        enableGpuPerformanceScaling: false,
        sslKeyLog: false,
        neckoMozLog: false,
        recordHar: false,
        recordWireLog: false
    };
    const first = await startProfile('profile-a', { ...options, recordTraffic });
    const second = await new CamoufoxProfile('profile-b', {
        ...options,
        recordTraffic: false
    }).start();
    assert.equal(launchCount, 1);
    return { ...engine, first, second, profilesDir };
}

test('client, profile, context and page APIs return the owning browser view', async (t) => {
    const { browser: nativeBrowser, contexts, first, second, profilesDir } = await setupProfiles(t);
    const secondBrowser = await second.getBrowser();
    const secondContext = await second.getContext();
    const secondPage = await second.getPage();
    assert.notEqual(first.browser, secondBrowser);
    assert.equal('getOrCreateSharedBrowser' in camoufoxClient, false);
    assert.equal('getOrCreateSharedBrowser' in camoufoxExports, false);
    for (const [browser, context, page] of [
        [first.browser, first.context, first.page],
        [secondBrowser, secondContext, secondPage]
    ]) {
        assert.notEqual(browser, nativeBrowser);
        assert.equal(browser.contexts, undefined);
        assert.equal(browser.newContext, undefined);
        assert.equal(browser.close, undefined);
        assert.equal(browser._camoufoxRawBrowser, undefined);
        assert.equal(page.browser(), browser);
        assert.equal(page.context().browser(), browser);
        assert.equal(context.browser(), browser);
        assert.deepEqual(await browser.pages(), [page]);
    }

    const newPage = await first.browser.newPage();
    const contextPage = await secondContext.newPage();
    const popup = contexts[1].openPage();
    assert.equal(newPage.context(), first.context);
    assert.equal(popup.browser(), secondBrowser);
    assert.equal(contextPage.browser(), secondBrowser);
    assert.deepEqual(await first.browser.pages(), [first.page, newPage]);
    assert.deepEqual(await secondBrowser.pages(), [secondPage, contextPage, popup]);
    assert.equal(contexts.length, 2);

    const reused = await startProfile('profile-a', { profilesDir });
    assert.equal(reused.browser, first.browser);
    await first.browser.disconnect();
    assert.equal(first.browser.isConnected(), true);

    await stopProfile('profile-a', { profilesDir });
    assert.equal(nativeBrowser.isConnected(), true);
    assert.equal(first.browser.isConnected(), false);
    assert.deepEqual(await first.browser.pages(), []);
    await assert.rejects(first.browser.newPage(), /No active Playwright context/);
    assert.deepEqual(await secondBrowser.pages(), [secondPage, contextPage, popup]);

    const unavailable = attachBrowserCompatibility(nativeBrowser, { context: null });
    assert.equal(unavailable.isConnected(), false);
    assert.deepEqual(await unavailable.pages(), []);
    await assert.rejects(unavailable.newPage(), /No active Playwright context/);

    const closing = secondContext.close();
    assert.equal(secondBrowser.isConnected(), false);
    assert.deepEqual(await secondBrowser.pages(), []);
    await closing;
});

test('recording follows context ownership and sanitizes navigation metadata', async (t) => {
    const { first, second, contexts } = await setupProfiles(t, true);
    const secondPage = await second.getPage();
    const recorder = first.page.getTrafficRecorder();
    assert.equal(recorder, first.trafficRecorder);
    assert.equal(secondPage.getTrafficRecorder(), null);

    const sampleUrl = 'https://profile.invalid/view?access_token=fixture-credential&view=compact';
    await first.page.goto(sampleUrl, { waitUntil: 'networkidle2' });
    assert.deepEqual(contexts[0].navigations, [
        { url: sampleUrl, options: { waitUntil: 'networkidle' } }
    ]);
    await first.page.click('button[data-action=save]');
    await (await first.page.mainFrame().$('button[data-action=preview]')).click();

    const recorded = await fs.readFile(recorder.trafficNdjsonPath, 'utf8');
    const actions = recorded.trim().split('\n').map(JSON.parse)
        .filter(({ type }) => type === 'trigger-action');
    assert.deepEqual(actions.map(({ actionType }) => actionType), [
        'page.goto',
        'page.click',
        'elementHandle.click'
    ]);
    assert.match(actions[0].target, /access_token=\[REDACTED\]/);
    assert.match(actions[0].metadata.url, /view=compact/);
    assert.match(actions[1].metadata.pageUrl, /access_token=\[REDACTED\]/);
    assert.doesNotMatch(recorded, /fixture-credential/);
    await recorder.flushSummary();
    const summary = await fs.readFile(recorder.attributionIndexPath, 'utf8');
    assert.doesNotMatch(summary, /fixture-credential/);

    await secondPage.click('button[data-action=save]');
    await (await secondPage.mainFrame().$('button[data-action=preview]')).click();
    const ownerless = attachElementHandleCompatibility({ async click() {} });
    await ownerless.click();
    assert.equal(contexts[1].clicks.length, 2);
    assert.equal(await fs.readFile(recorder.trafficNdjsonPath, 'utf8'), recorded);
});

test('locally rejected navigation leaves later request attribution on the prior action', async (t) => {
    const { first, contexts: [fixture] } = await setupProfiles(t, true);
    const { page, trafficRecorder: recorder } = first;
    const origin = 'https://profile.invalid';
    const frame = page.mainFrame();
    function emitRequest(name) {
        fixture.context.emit('request', {
            method: () => 'GET',
            url: () => origin + '/' + name,
            frame: () => frame,
            headers: () => ({}),
            headersArray: async () => []
        });
    }

    await page.click('button[data-action=refresh]');
    emitRequest('before-poll');
    await assert.rejects(page.goto(origin + '/rejected', {
        waitUntil: ['domcontentloaded', 'load']
    }), /only one waitUntil condition/);
    assert.deepEqual(fixture.navigations, []);
    emitRequest('after-poll');
    await page.goto(origin + '/accepted', { waitUntil: ['load'] });
    assert.deepEqual(fixture.navigations, [
        { url: origin + '/accepted', options: { waitUntil: 'load' } }
    ]);
    emitRequest('accepted-poll');
    await recorder.flushSummary();

    const ledger = (await fs.readFile(recorder.trafficNdjsonPath, 'utf8')).trim().split('\n').map(JSON.parse);
    const actions = ledger.filter(({ type }) => type === 'trigger-action');
    const egress = new Map(ledger.filter(({ type }) => type === 'egress')
        .map(({ url, triggerAction }) => [url, triggerAction?.actionId]));
    assert.equal(egress.size, 3);
    assert.equal(egress.get(origin + '/before-poll'), actions[0].actionId);
    assert.equal(egress.get(origin + '/after-poll'), actions[0].actionId);
    assert.deepEqual(actions.map(({ actionType }) => actionType), ['page.click', 'page.goto']);
    assert.equal(egress.get(origin + '/accepted-poll'), actions[1].actionId);
});
