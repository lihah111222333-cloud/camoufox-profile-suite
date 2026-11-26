/**
 * Isolated Playwright-to-Puppeteer Compatibility Test Suite
 * Verifies all compatibility shims in `src/camoufox/profile.js` against
 * mock Playwright Browser, BrowserContext, Page, Frame, and ElementHandle objects,
 * as well as `src/utils/human-behavior.js` and `src/gmail/page-detector.js`.
 */

import assert from 'node:assert/strict';
import {
    attachPageCompatibility,
    attachBrowserCompatibility,
    attachFrameCompatibility,
    attachElementHandleCompatibility,
    normalizeNavigationOptions,
    normalizeWaitForOptions
} from '../src/camoufox/profile.js';
import {
    humanMouseMove,
    humanClick,
    humanClickAt,
    humanScroll,
    humanScrollToElement,
    humanType
} from '../src/utils/human-behavior.js';
import { detectGmailPage, waitForElement, elementExists, waitForPageLoad } from '../src/gmail/page-detector.js';

function createMockElementHandle(tagName = 'button', initialValue = '') {
    const calls = {
        clicks: [],
        types: [],
        focused: 0,
        queries: [],
        waitSelectors: []
    };

    const handle = {
        tagName,
        value: initialValue,
        calls,
        async boundingBox() {
            return { x: 100, y: 200, width: 80, height: 36 };
        },
        async click(options = {}) {
            calls.clicks.push(options);
        },
        async focus() {
            calls.focused += 1;
        },
        async type(text, options = {}) {
            calls.types.push({ text, options });
            if (text === 'Backspace' || text === 'Delete') {
                return;
            }
            handle.value += text;
        },
        async $(selector) {
            calls.queries.push({ type: '$', selector });
            return createMockElementHandle('span');
        },
        async $$(selector) {
            calls.queries.push({ type: '$$', selector });
            return [createMockElementHandle('span')];
        },
        async waitForSelector(selector, options = {}) {
            calls.waitSelectors.push({ selector, options });
            return createMockElementHandle('span');
        },
        async evaluate(fn, arg) {
            const domMock = {
                tagName,
                get value() {
                    return handle.value;
                },
                set value(v) {
                    handle.value = v;
                },
                textContent: 'Mock Button',
                disabled: false,
                dispatchEvent() {
                    return true;
                },
                scrollIntoView() {}
            };
            return fn(domMock, arg);
        },
        async evaluateHandle(fn, arg) {
            const res = await handle.evaluate(fn, arg);
            return createMockElementHandle(res?.tagName || 'div');
        }
    };

    return handle;
}

function createMockFrame(name = 'main', initialUrl = 'https://accounts.google.com/signup') {
    const calls = {
        queries: [],
        waitSelectors: [],
        gotos: [],
        navigations: [],
        evaluations: []
    };

    const frame = {
        name,
        _url: initialUrl,
        calls,
        url() {
            return frame._url;
        },
        async $(selector) {
            calls.queries.push({ type: '$', selector });
            return createMockElementHandle('input');
        },
        async $$(selector) {
            calls.queries.push({ type: '$$', selector });
            return [createMockElementHandle('button')];
        },
        async waitForSelector(selector, options = {}) {
            calls.waitSelectors.push({ selector, options });
            return createMockElementHandle('div');
        },
        async goto(url, options = {}) {
            frame._url = url;
            calls.gotos.push({ url, options });
            return { ok: true, url };
        },
        async waitForNavigation(options = {}) {
            calls.navigations.push({ options });
            return { ok: true };
        },
        async evaluate(pageFunction, arg) {
            calls.evaluations.push({ pageFunction, arg });
            if (typeof pageFunction === 'function') {
                const prevWindow = globalThis.window;
                const prevDocument = globalThis.document;
                const prevEvent = globalThis.Event;
                try {
                    globalThis.window = globalThis.window || {
                        mouseX: 0,
                        mouseY: 0,
                        scrollY: 0,
                        innerWidth: 1280,
                        innerHeight: 800,
                        scrollBy() {},
                        dispatchEvent() {}
                    };
                    globalThis.document = globalThis.document || {
                        documentElement: { scrollHeight: 2000 },
                        body: {},
                        querySelector() {
                            return null;
                        },
                        querySelectorAll() {
                            return [];
                        },
                        dispatchEvent() {}
                    };
                    globalThis.Event =
                        globalThis.Event ||
                        class MockEvent {
                            constructor(type, opts) {
                                this.type = type;
                                this.opts = opts;
                            }
                        };
                    return await pageFunction(arg);
                } finally {
                    globalThis.window = prevWindow;
                    globalThis.document = prevDocument;
                    globalThis.Event = prevEvent;
                }
            }
            return null;
        },
        async evaluateHandle(pageFunction, arg) {
            await frame.evaluate(pageFunction, arg);
            return createMockElementHandle('button');
        }
    };

    return frame;
}

function createMockPlaywrightStack() {
    const state = {
        cookies: [],
        initScripts: [],
        pages: [],
        savedStorageCount: 0,
        viewportSize: { width: 1280, height: 800 }
    };

    let browser;
    const context = {
        browser() {
            return browser;
        },
        pages() {
            return state.pages;
        },
        async newPage() {
            const p = createMockPage(context);
            state.pages.push(p);
            return p;
        },
        async addInitScript(fn, arg) {
            state.initScripts.push({ fn, arg });
        },
        async cookies(urls) {
            if (!urls || urls.length === 0) {
                return [...state.cookies];
            }
            return state.cookies.filter((c) =>
                urls.some((u) => u.includes((c.domain || '').replace(/^\./, '')))
            );
        },
        async addCookies(newCookies) {
            for (const cookie of newCookies) {
                const idx = state.cookies.findIndex(
                    (c) => c.name === cookie.name && c.domain === cookie.domain
                );
                if (idx >= 0) {
                    state.cookies[idx] = { ...state.cookies[idx], ...cookie };
                } else {
                    state.cookies.push({ ...cookie });
                }
            }
        },
        async clearCookies() {
            state.cookies = [];
        }
    };

    function createMockPage(ownerContext) {
        const baseFrame = createMockFrame('main', 'https://accounts.google.com/signup/name');
        const childFrame = createMockFrame('recaptcha-iframe', 'https://www.google.com/recaptcha/api2/anchor');
        const mouseMoves = [];
        const mouseClicks = [];
        const keyPresses = [];

        const page = {
            ...baseFrame,
            mouseMoves,
            mouseClicks,
            keyPresses,
            context() {
                return ownerContext;
            },
            frames() {
                return [baseFrame, childFrame];
            },
            mainFrame() {
                return baseFrame;
            },
            async setViewportSize({ width, height }) {
                state.viewportSize = { width, height };
            },
            viewportSize() {
                return state.viewportSize;
            },
            mouse: {
                async move(x, y) {
                    mouseMoves.push({ x, y });
                },
                async click(x, y, options = {}) {
                    mouseClicks.push({ x, y, options });
                }
            },
            keyboard: {
                async press(key) {
                    keyPresses.push({ action: 'press', key });
                    if ((key === 'Backspace' || key === 'Delete') && page._activeInput) {
                        if (key === 'Delete') {
                            page._activeInput.value = '';
                        } else {
                            page._activeInput.value = page._activeInput.value.slice(0, -1);
                        }
                    }
                },
                async down(key) {
                    keyPresses.push({ action: 'down', key });
                },
                async up(key) {
                    keyPresses.push({ action: 'up', key });
                }
            }
        };
        return page;
    }

    browser = {
        contexts() {
            return [context];
        },
        isConnected() {
            return true;
        }
    };

    const profile = {
        context,
        browser,
        async saveStorageState() {
            state.savedStorageCount += 1;
            return '/tmp/mock-storage-state.json';
        }
    };

    const initialPage = createMockPage(context);
    state.pages.push(initialPage);

    attachBrowserCompatibility(browser, profile);
    attachPageCompatibility(initialPage, context, browser);

    return { browser, context, page: initialPage, profile, state };
}

async function runTests() {
    console.log('Running Playwright-Puppeteer Compatibility Test Suite...');

    const { browser, page, state } = createMockPlaywrightStack();

    // 1. Test normalizeNavigationOptions & normalizeWaitForOptions
    assert.deepEqual(normalizeNavigationOptions({ waitUntil: 'networkidle2', timeout: 5000 }), {
        waitUntil: 'networkidle',
        timeout: 5000
    });
    assert.deepEqual(normalizeNavigationOptions({ waitUntil: ['networkidle0', 'load'] }), {
        waitUntil: 'networkidle'
    });
    assert.deepEqual(normalizeWaitForOptions({ visible: true, timeout: 3000 }), {
        state: 'visible',
        timeout: 3000
    });
    assert.deepEqual(normalizeWaitForOptions({ hidden: true }), {
        state: 'hidden'
    });
    console.log('  [PASS] Navigation and waitFor options normalization');

    // 2. Test page.$x, page.waitForXPath, and ElementHandle.$x
    const xpathResults = await page.$x('//button[contains(text(), "Next")]');
    assert.equal(xpathResults.length, 1);
    assert.equal(page.calls.queries.at(-1).selector, 'xpath=//button[contains(text(), "Next")]');

    const childXpathResults = await xpathResults[0].$x('.//span');
    assert.equal(childXpathResults.length, 1);
    assert.equal(xpathResults[0].calls.queries.at(-1).selector, 'xpath=.//span');

    const waitedEl = await page.waitForXPath('//input[@name="firstName"]', {
        visible: true,
        timeout: 4000
    });
    assert.ok(waitedEl);
    assert.deepEqual(page.calls.waitSelectors.at(-1), {
        selector: 'xpath=//input[@name="firstName"]',
        options: { state: 'visible', timeout: 4000 }
    });
    console.log('  [PASS] page.$x, ElementHandle.$x, and page.waitForXPath');

    // 3. Test frames() and mainFrame() compatibility
    const mainFrame = page.mainFrame();
    assert.equal(typeof mainFrame.$x, 'function');
    assert.equal(typeof mainFrame.waitForXPath, 'function');
    const frames = page.frames();
    assert.equal(frames.length, 2);
    const frameXpathEls = await frames[1].$x('//div[@id="recaptcha-accessible-status"]');
    assert.equal(frameXpathEls.length, 1);
    assert.equal(
        frames[1].calls.queries.at(-1).selector,
        'xpath=//div[@id="recaptcha-accessible-status"]'
    );
    console.log('  [PASS] page.frames(), page.mainFrame(), and frame.$x / frame.waitForXPath');

    // 4. Test evaluateOnNewDocument (single and multi-arg)
    await page.evaluateOnNewDocument((a, b) => a + b, 10, 20);
    assert.equal(state.initScripts.length, 1);
    assert.deepEqual(state.initScripts[0].arg[1], [10, 20]);
    console.log('  [PASS] page.evaluateOnNewDocument');

    // 5. Test setViewport and viewport()
    await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 2 });
    assert.deepEqual(page.viewport(), { width: 1440, height: 900, deviceScaleFactor: 2 });
    console.log('  [PASS] page.setViewport and page.viewport()');

    // 6. Test setUserAgent coherence guard
    const chromeUaResult = await page.setUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36'
    );
    assert.equal(chromeUaResult.blocked, true);
    assert.equal(chromeUaResult.applied, false);
    await assert.rejects(
        () =>
            page.setUserAgent(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36',
                { strict: true }
            ),
        /Refusing to set non-Firefox User-Agent on Camoufox/
    );
    const firefoxUaResult = await page.setUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0'
    );
    assert.equal(firefoxUaResult.blocked, false);
    assert.equal(firefoxUaResult.applied, false);
    console.log('  [PASS] page.setUserAgent Firefox coherence guard');

    // 7. Test cookies(), setCookie(), and deleteCookie()
    await page.setCookie(
        { name: 'SID', value: 'abc123', domain: '.google.com' },
        { name: 'HSID', value: 'xyz789', domain: '.google.com' }
    );
    const allCookies = await page.cookies('https://accounts.google.com');
    assert.equal(allCookies.length, 2);
    assert.equal(allCookies[0].path, '/');

    await page.deleteCookie({ name: 'SID', domain: '.google.com' });
    const remainingCookies = await page.cookies();
    assert.equal(remainingCookies.length, 1);
    assert.equal(remainingCookies[0].name, 'HSID');
    console.log('  [PASS] page.cookies(), page.setCookie(), and page.deleteCookie()');

    // 8. Test multi-arg page.evaluate, page.evaluateHandle (.asElement()), and ElementHandle.evaluate
    const sum = await page.evaluate((a, b, c) => a + b + c, 5, 10, 15);
    assert.equal(sum, 30);

    const handleResult = await page.evaluateHandle((x, y) => ({ tagName: x + y }), 'but', 'ton');
    assert.ok(handleResult.asElement());
    assert.equal(typeof handleResult.asElement().$x, 'function');

    const elMultiEval = await waitedEl.evaluate(
        (el, prefix, suffix) => `${prefix}:${el.tagName}:${suffix}`,
        'start',
        'end'
    );
    assert.equal(elMultiEval, 'start:div:end');
    console.log('  [PASS] Multi-argument page.evaluate, page.evaluateHandle, and ElementHandle.evaluate');

    // 9. Test goto & waitForNavigation with networkidle2, and waitForTimeout
    await page.goto('https://accounts.google.com/signup/name', {
        waitUntil: 'networkidle2',
        timeout: 10000
    });
    assert.equal(page.calls.gotos.at(-1).options.waitUntil, 'networkidle');

    await waitForPageLoad(page, 1000);
    assert.equal(page.calls.navigations.at(-1).options.waitUntil, 'networkidle');
    console.log('  [PASS] page.goto, page.waitForNavigation (networkidle2 -> networkidle), and waitForPageLoad');

    // 10. Test page.browser(), browser.pages(), browser.newPage(), browser.disconnect(), browser.isConnected()
    assert.equal(page.browser(), browser);
    assert.equal(browser.isConnected(), true);
    const newTab = await browser.newPage();
    assert.equal(typeof newTab.$x, 'function');
    assert.equal(typeof newTab.waitForXPath, 'function');
    const openPages = await browser.pages();
    assert.equal(openPages.length, 2);
    await browser.disconnect();
    assert.equal(state.savedStorageCount, 1);
    console.log('  [PASS] page.browser(), browser.pages(), browser.newPage(), and browser.disconnect()');

    // 11. Test human-behavior.js & page-detector.js integration against the shimmed Page & ElementHandle
    await humanMouseMove(page, 250, 300, { steps: 3, baseDelay: 1 });
    assert.ok(page.mouseMoves.length >= 3);

    const mockBtn = attachElementHandleCompatibility(createMockElementHandle('button'));
    const clicked = await humanClick(page, mockBtn, {
        moveFirst: true,
        preClickDelay: false,
        postClickDelay: false
    });
    assert.equal(clicked, true);
    assert.equal(mockBtn.calls.clicks.length, 1);

    const clickedAt = await humanClickAt(page, 150, 220, {
        moveFirst: false,
        preClickDelay: false,
        postClickDelay: false
    });
    assert.equal(clickedAt, true);
    assert.equal(page.mouseClicks.length, 1);

    await humanScroll(page, { direction: 'down', distance: 120, steps: 2, pauseChance: 0 });
    await humanScrollToElement(page, mockBtn, { addRandomOffset: false });

    const mockInput = attachElementHandleCompatibility(createMockElementHandle('input', 'old'));
    page._activeInput = mockInput;
    const typed = await humanType(page, mockInput, 'testuser', {
        minDelay: 1,
        maxDelay: 2,
        mistakeChance: 0,
        pauseChance: 0,
        burstTypingChance: 0,
        clearFirst: true
    });
    assert.equal(typed, true);
    assert.equal(mockInput.value, 'testuser');

    const detected = await detectGmailPage(page);
    assert.equal(detected.type, 'SIGN_UP_FORM');
    const foundEl = await waitForElement(page, 'input[name="firstName"]', 1000);
    assert.ok(foundEl);
    assert.equal(await elementExists(page, 'input[name="firstName"]'), true);
    console.log('  [PASS] human-behavior.js and page-detector.js integration');

    // 12. Test Round-5 Page/Frame compatibility decoupling, userAgent(), lowercase sameSite, and URL-scoped deleteCookie
    const { context: ctx12, profile: prof12 } = createMockPlaywrightStack();
    const rawFrameFirstPage = createMockFrame('raw-frame-first', 'https://accounts.google.com/signup');
    rawFrameFirstPage.context = () => ctx12;
    rawFrameFirstPage.frames = () => [rawFrameFirstPage];
    rawFrameFirstPage.mainFrame = () => rawFrameFirstPage;
    attachFrameCompatibility(rawFrameFirstPage);
    assert.equal(rawFrameFirstPage._camoufoxFrameCompatAttached, true);
    assert.equal(Boolean(rawFrameFirstPage._camoufoxPageCompatAttached), false);
    attachPageCompatibility(rawFrameFirstPage, ctx12, prof12);
    assert.equal(rawFrameFirstPage._camoufoxPageCompatAttached, true);
    assert.equal(typeof rawFrameFirstPage.setViewport, 'function');
    assert.equal(typeof rawFrameFirstPage.evaluateOnNewDocument, 'function');
    assert.equal(typeof rawFrameFirstPage.cookies, 'function');
    assert.equal(typeof rawFrameFirstPage.setCookie, 'function');
    assert.equal(typeof rawFrameFirstPage.deleteCookie, 'function');
    assert.equal(typeof rawFrameFirstPage.userAgent, 'function');

    const pageUa = await page.userAgent();
    const browserUa = await browser.userAgent();
    assert.match(pageUa, /Firefox\/\d+/);
    assert.match(browserUa, /Firefox\/\d+/);

    await page.setCookie(
        { name: 'PREF', value: '1', domain: '.google.com', sameSite: 'lax' },
        {
            name: 'NID',
            value: '2',
            url: 'https://accounts.google.com/signup',
            path: '/signup',
            sameSite: 'none'
        },
        { name: 'SHARED', value: 'goog', domain: '.google.com', sameSite: 'strict' },
        { name: 'SHARED', value: 'example', domain: '.example.com', sameSite: 'unspecified' }
    );
    const allStoredCookies = await ctx12.cookies();
    const storedOnMain = await page.cookies();
    const prefCookie = storedOnMain.find((c) => c.name === 'PREF');
    assert.equal(prefCookie.sameSite, 'Lax');
    assert.equal(prefCookie.path, '/');

    await page.deleteCookie({ name: 'SHARED', url: 'https://accounts.google.com/signup' });
    const afterUrlScopedDelete = await page.cookies('https://accounts.google.com', 'https://example.com');
    assert.equal(
        afterUrlScopedDelete.some((c) => c.name === 'SHARED' && c.domain === '.google.com'),
        false
    );
    assert.equal(
        afterUrlScopedDelete.some((c) => c.name === 'SHARED' && c.domain === '.example.com'),
        true
    );
    assert.equal(Array.isArray(allStoredCookies), true);
    console.log(
        '  [PASS] Round-5 Frame/Page flag decoupling, page/browser.userAgent(), lowercase sameSite normalization, and URL-scoped deleteCookie'
    );

    console.log('\nAll Playwright-Puppeteer compatibility tests passed!');
}

runTests().catch((err) => {
    console.error('Compatibility test failed:', err);
    process.exit(1);
});
