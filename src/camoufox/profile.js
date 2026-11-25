/**
 * Camoufox Profile Manager
 * Drop-in replacement for Dolphin Anty (`src/dolphin/profile.js`) and GPM Login (`src/gpmlogin/profile.js`)
 */

import logger from '../utils/logger.js';
import camoufoxClient from './client.js';
import { auditProfileCoherence } from './coherence-auditor.js';

const WAIT_UNTIL_MAP = {
    networkidle0: 'networkidle',
    networkidle2: 'networkidle',
    domcontentloaded: 'domcontentloaded',
    load: 'load',
    commit: 'commit'
};

/**
 * Normalize Puppeteer-style navigation options (`networkidle2` / `networkidle0`) for Playwright.
 */
export function normalizeNavigationOptions(options) {
    if (!options || typeof options !== 'object') {
        return options;
    }
    const normalized = { ...options };
    if (typeof normalized.waitUntil === 'string') {
        normalized.waitUntil = WAIT_UNTIL_MAP[normalized.waitUntil] || normalized.waitUntil;
    } else if (Array.isArray(normalized.waitUntil)) {
        normalized.waitUntil = normalized.waitUntil[0]
            ? WAIT_UNTIL_MAP[normalized.waitUntil[0]] || normalized.waitUntil[0]
            : 'load';
    }
    return normalized;
}

/**
 * Normalize Puppeteer-style waitForSelector / waitForXPath options (`visible`, `hidden`)
 * into Playwright's `{ state: 'visible' | 'hidden' }`.
 */
export function normalizeWaitForOptions(options) {
    if (!options || typeof options !== 'object') {
        return options;
    }
    const normalized = { ...options };
    if (!normalized.state) {
        if (normalized.visible === true) {
            normalized.state = 'visible';
        } else if (normalized.hidden === true) {
            normalized.state = 'hidden';
        }
    }
    delete normalized.visible;
    delete normalized.hidden;
    return normalized;
}

function normalizeXPathSelector(expression) {
    const raw = String(expression ?? '');
    return raw.startsWith('xpath=') ? raw : `xpath=${raw}`;
}

function normalizeCookieDomain(domain) {
    return typeof domain === 'string' ? domain.replace(/^\./, '').toLowerCase() : '';
}

function wrapMultiArgEvaluate(originalEvaluate, decorateResult = null) {
    return async (pageFunction, ...args) => {
        let result;
        if (args.length <= 1 || typeof pageFunction !== 'function') {
            result = await originalEvaluate(pageFunction, args[0]);
        } else {
            const fnSource = pageFunction.toString();
            result = await originalEvaluate(
                ([serializedFn, serializedArgs]) => {
                    // eslint-disable-next-line no-new-func
                    const hydratedFn = new Function(`return (${serializedFn})`)();
                    return hydratedFn(...serializedArgs);
                },
                [fnSource, args]
            );
        }
        return decorateResult ? decorateResult(result) : result;
    };
}

let lastActiveTrafficRecorder = null;

function resolveFrameRecorder(frame) {
    if (!frame || typeof frame !== 'object') {
        return lastActiveTrafficRecorder || null;
    }
    if (typeof frame.getTrafficRecorder === 'function') {
        const rec = frame.getTrafficRecorder();
        if (rec) return rec;
    }
    if (frame._camoufoxProfile?.trafficRecorder) {
        return frame._camoufoxProfile.trafficRecorder;
    }
    if (frame._camoufoxContext?._camoufoxTrafficRecorder) {
        return frame._camoufoxContext._camoufoxTrafficRecorder;
    }
    if (typeof frame.page === 'function') {
        try {
            const page = frame.page();
            if (page) {
                const rec =
                    page.getTrafficRecorder?.() ||
                    page._camoufoxProfile?.trafficRecorder ||
                    page.context?.()?._camoufoxTrafficRecorder;
                if (rec) return rec;
            }
        } catch {
            // Ignore frame.page() resolution error
        }
    }
    if (typeof frame.context === 'function') {
        try {
            const ctx = frame.context();
            if (ctx?._camoufoxTrafficRecorder) {
                return ctx._camoufoxTrafficRecorder;
            }
        } catch {
            // Ignore frame.context() resolution error
        }
    }
    return lastActiveTrafficRecorder || null;
}

function resolveHandleRecorder(handle) {
    if (!handle || typeof handle !== 'object') {
        return lastActiveTrafficRecorder || null;
    }
    const owner = handle._camoufoxOwner;
    if (owner) {
        if (typeof owner.recordTriggerAction === 'function') {
            return owner;
        }
        const rec = resolveFrameRecorder(owner);
        if (rec) return rec;
    }
    if (typeof handle.getTrafficRecorder === 'function') {
        const rec = handle.getTrafficRecorder();
        if (rec) return rec;
    }
    const internalPage = handle._page || (typeof handle._frame?.page === 'function' ? handle._frame.page() : null);
    if (internalPage) {
        const rec = resolveFrameRecorder(internalPage);
        if (rec) return rec;
    }
    if (handle._context?._camoufoxTrafficRecorder) {
        return handle._context._camoufoxTrafficRecorder;
    }
    return lastActiveTrafficRecorder || null;
}

/**
 * Decorate a Playwright ElementHandle / JSHandle with Puppeteer compatibility helpers
 * (`$x`, `waitForXPath`, `asElement`, and multi-arg `evaluate` / `evaluateHandle`)
 * as well as automatic pre-TLS causal action trigger hooks (`click`, `fill`, `type`, `press`).
 */
export function attachElementHandleCompatibility(handle, owner = null, targetHint = null) {
    if (!handle || typeof handle !== 'object') {
        return handle;
    }

    if (owner && !handle._camoufoxOwner) {
        Object.defineProperty(handle, '_camoufoxOwner', {
            value: owner,
            enumerable: false,
            configurable: true,
            writable: true
        });
    }

    if (targetHint && !handle._camoufoxTargetHint) {
        Object.defineProperty(handle, '_camoufoxTargetHint', {
            value: String(targetHint),
            enumerable: false,
            configurable: true,
            writable: true
        });
    }

    if (handle._camoufoxCompatAttached) {
        return handle;
    }

    Object.defineProperty(handle, '_camoufoxCompatAttached', {
        value: true,
        enumerable: false,
        configurable: true
    });

    if (typeof handle.$ === 'function') {
        const originalQuery = handle.$.bind(handle);
        handle.$ = async (selector) =>
            attachElementHandleCompatibility(
                await originalQuery(selector),
                handle._camoufoxOwner || handle,
                selector
            );
    }

    if (typeof handle.$$ === 'function') {
        const originalQueryAll = handle.$$.bind(handle);
        handle.$$ = async (selector) => {
            const elements = await originalQueryAll(selector);
            return Array.isArray(elements)
                ? elements.map((el) =>
                      attachElementHandleCompatibility(el, handle._camoufoxOwner || handle, selector)
                  )
                : elements;
        };
    }

    if (typeof handle.$x !== 'function' && typeof handle.$$ === 'function') {
        handle.$x = async (expression) => handle.$$(normalizeXPathSelector(expression));
    }

    if (typeof handle.waitForSelector === 'function') {
        const originalWaitForSelector = handle.waitForSelector.bind(handle);
        handle.waitForSelector = async (selector, options) =>
            attachElementHandleCompatibility(
                await originalWaitForSelector(selector, normalizeWaitForOptions(options)),
                handle._camoufoxOwner || handle,
                selector
            );
    }

    if (typeof handle.waitForXPath !== 'function' && typeof handle.waitForSelector === 'function') {
        handle.waitForXPath = async (expression, options) =>
            handle.waitForSelector(normalizeXPathSelector(expression), options);
    }

    if (typeof handle.evaluate === 'function') {
        const originalEvaluate = handle.evaluate.bind(handle);
        handle.evaluate = async (pageFunction, ...args) => {
            if (args.length <= 1 || typeof pageFunction !== 'function') {
                return originalEvaluate(pageFunction, args[0]);
            }
            const fnSource = pageFunction.toString();
            return originalEvaluate(
                (el, [serializedFn, serializedArgs]) => {
                    // eslint-disable-next-line no-new-func
                    const hydratedFn = new Function(`return (${serializedFn})`)();
                    return hydratedFn(el, ...serializedArgs);
                },
                [fnSource, args]
            );
        };
    }

    if (typeof handle.evaluateHandle === 'function') {
        const originalEvaluateHandle = handle.evaluateHandle.bind(handle);
        handle.evaluateHandle = async (pageFunction, ...args) => {
            let res;
            if (args.length <= 1 || typeof pageFunction !== 'function') {
                res = await originalEvaluateHandle(pageFunction, args[0]);
            } else {
                const fnSource = pageFunction.toString();
                res = await originalEvaluateHandle(
                    (el, [serializedFn, serializedArgs]) => {
                        // eslint-disable-next-line no-new-func
                        const hydratedFn = new Function(`return (${serializedFn})`)();
                        return hydratedFn(el, ...serializedArgs);
                    },
                    [fnSource, args]
                );
            }
            return attachElementHandleCompatibility(res, handle._camoufoxOwner || handle);
        };
    }

    for (const methodName of ['click', 'fill', 'type', 'press']) {
        if (typeof handle[methodName] === 'function') {
            const originalMethod = handle[methodName].bind(handle);
            handle[methodName] = async (...args) => {
                try {
                    const recorder = resolveHandleRecorder(handle);
                    const target = handle._camoufoxTargetHint || 'ElementHandle';
                    const meta = {};
                    if (methodName === 'press' && typeof args[0] === 'string') {
                        meta.key = args[0];
                    } else if (
                        (methodName === 'fill' || methodName === 'type') &&
                        typeof args[0] === 'string'
                    ) {
                        meta.valueLength = args[0].length;
                    }
                    recorder?.recordTriggerAction?.(`elementHandle.${methodName}`, target, meta);
                } catch {
                    // Never allow instrumentation to interfere with ElementHandle actions
                }
                return originalMethod(...args);
            };
        }
    }

    if (typeof handle.asElement === 'function') {
        const originalAsElement = handle.asElement.bind(handle);
        handle.asElement = () =>
            attachElementHandleCompatibility(
                originalAsElement(),
                handle._camoufoxOwner || handle,
                handle._camoufoxTargetHint || null
            );
    } else {
        handle.asElement = () => handle;
    }

    return handle;
}

/**
 * Decorate a Playwright Frame with Puppeteer compatibility shims
 * (`$x`, `waitForXPath`, `waitForTimeout`, multi-arg `evaluate`, `networkidle2`).
 */
export function attachFrameCompatibility(frame) {
    if (!frame || typeof frame !== 'object' || frame._camoufoxCompatAttached) {
        return frame;
    }

    Object.defineProperty(frame, '_camoufoxCompatAttached', {
        value: true,
        enumerable: false,
        configurable: true
    });

    if (typeof frame.$ === 'function') {
        const originalQuery = frame.$.bind(frame);
        frame.$ = async (selector) =>
            attachElementHandleCompatibility(await originalQuery(selector), frame, selector);
    }

    if (typeof frame.$$ === 'function') {
        const originalQueryAll = frame.$$.bind(frame);
        frame.$$ = async (selector) => {
            const elements = await originalQueryAll(selector);
            return Array.isArray(elements)
                ? elements.map((el) => attachElementHandleCompatibility(el, frame, selector))
                : elements;
        };
    }

    if (typeof frame.$x !== 'function' && typeof frame.$$ === 'function') {
        frame.$x = async (expression) => frame.$$(normalizeXPathSelector(expression));
    }

    if (typeof frame.waitForSelector === 'function') {
        const originalWaitForSelector = frame.waitForSelector.bind(frame);
        frame.waitForSelector = async (selector, options) =>
            attachElementHandleCompatibility(
                await originalWaitForSelector(selector, normalizeWaitForOptions(options)),
                frame,
                selector
            );
    }

    if (typeof frame.waitForXPath !== 'function' && typeof frame.waitForSelector === 'function') {
        frame.waitForXPath = async (expression, options) =>
            frame.waitForSelector(normalizeXPathSelector(expression), options);
    }

    if (typeof frame.waitForTimeout !== 'function') {
        frame.waitForTimeout = async (ms) =>
            new Promise((resolve) => setTimeout(resolve, Math.max(0, Number(ms) || 0)));
    }

    if (typeof frame.goto === 'function') {
        const originalGoto = frame.goto.bind(frame);
        frame.goto = async (url, options) => originalGoto(url, normalizeNavigationOptions(options));
    }

    if (typeof frame.waitForNavigation === 'function') {
        const originalWaitForNavigation = frame.waitForNavigation.bind(frame);
        frame.waitForNavigation = async (options) =>
            originalWaitForNavigation(normalizeNavigationOptions(options));
    }

    if (typeof frame.evaluate === 'function') {
        const originalEvaluate = frame.evaluate.bind(frame);
        frame.evaluate = wrapMultiArgEvaluate(originalEvaluate);
    }

    if (typeof frame.evaluateHandle === 'function') {
        const originalEvaluateHandle = frame.evaluateHandle.bind(frame);
        frame.evaluateHandle = wrapMultiArgEvaluate(originalEvaluateHandle, (res) =>
            attachElementHandleCompatibility(res, frame)
        );
    }

    return frame;
}

/**
 * Decorate a Playwright Page with non-intrusive compatibility shims for callers
 * that use Puppeteer helpers (`$x`, `waitForXPath`, `evaluateOnNewDocument`,
 * `setViewport`/`viewport`, `cookies`/`setCookie`/`deleteCookie`, `setUserAgent`,
 * `frames`/`mainFrame`, `browser()`, multi-arg `evaluate`, `networkidle2`)
 * and automatic pre-TLS causal action attribution hooks.
 */
export function attachPageCompatibility(page, context = null, profile = null) {
    if (!page || typeof page !== 'object') {
        return page;
    }

    if (context && !page._camoufoxContext) {
        Object.defineProperty(page, '_camoufoxContext', {
            value: context,
            enumerable: false,
            configurable: true,
            writable: true
        });
    }

    if (profile && !page._camoufoxProfile) {
        Object.defineProperty(page, '_camoufoxProfile', {
            value: profile,
            enumerable: false,
            configurable: true,
            writable: true
        });
    }

    const resolveContext = () =>
        page._camoufoxContext ||
        context ||
        page._camoufoxProfile?.context ||
        (typeof page.context === 'function' ? page.context() : null);

    const resolveBrowser = () => {
        const p = page._camoufoxProfile || profile;
        if (p) {
            if (p.browser) {
                return p.browser;
            }
            if (
                typeof p.contexts === 'function' ||
                typeof p.newContext === 'function' ||
                typeof p.isConnected === 'function'
            ) {
                return p;
            }
        }
        const ctx = resolveContext();
        return ctx && typeof ctx.browser === 'function' ? ctx.browser() : null;
    };

    // Traffic attribution helpers directly on page
    page.getTrafficRecorder = () =>
        (page._camoufoxProfile || profile)?.trafficRecorder ||
        resolveContext()?._camoufoxTrafficRecorder ||
        null;

    page.setTrafficStep = (stepName, meta = {}) =>
        page.getTrafficRecorder()?.setStep(stepName, meta) || null;

    page.recordTrafficTrigger = (actionType, target = null, meta = {}) =>
        page.getTrafficRecorder()?.recordTriggerAction?.(actionType, target, meta) || null;

    if (page._camoufoxCompatAttached) {
        return page;
    }

    // Apply all Frame-level shims ($x, waitForXPath, waitForSelector, goto, waitForNavigation, evaluate, evaluateHandle, waitForTimeout)
    attachFrameCompatibility(page);

    // Instrument page.goto with causal trigger attribution
    if (typeof page.goto === 'function') {
        const normalizedGoto = page.goto.bind(page);
        page.goto = async (url, options) => {
            try {
                const recorder = page.getTrafficRecorder?.();
                const targetUrl = typeof url === 'string' ? url : String(url ?? '');
                recorder?.recordTriggerAction?.('page.goto', targetUrl, {
                    url: targetUrl,
                    pageUrl: typeof page.url === 'function' ? page.url() : null
                });
            } catch {
                // Never allow instrumentation to interfere with navigation
            }
            return normalizedGoto(url, options);
        };
    }

    // Instrument UI action drivers on page: click, fill, type, press, tap
    for (const methodName of ['click', 'fill', 'type', 'press', 'tap']) {
        if (typeof page[methodName] === 'function') {
            const originalMethod = page[methodName].bind(page);
            page[methodName] = async (selector, ...rest) => {
                try {
                    const recorder = page.getTrafficRecorder?.();
                    const targetSelector =
                        typeof selector === 'string' ? selector : String(selector ?? '');
                    const meta = {
                        pageUrl: typeof page.url === 'function' ? page.url() : null
                    };
                    if (methodName === 'press' && typeof rest[0] === 'string') {
                        meta.key = rest[0];
                    } else if (
                        (methodName === 'fill' || methodName === 'type') &&
                        typeof rest[0] === 'string'
                    ) {
                        meta.valueLength = rest[0].length;
                    }
                    recorder?.recordTriggerAction?.(`page.${methodName}`, targetSelector, meta);
                } catch {
                    // Never allow instrumentation to interfere with page execution
                }
                return originalMethod(selector, ...rest);
            };
        }
    }

    // Puppeteer page.evaluateOnNewDocument(fn, ...args) -> Playwright context.addInitScript
    if (typeof page.evaluateOnNewDocument !== 'function') {
        page.evaluateOnNewDocument = async (pageFunction, ...args) => {
            const targetContext = resolveContext();
            const addScript =
                targetContext && typeof targetContext.addInitScript === 'function'
                    ? targetContext.addInitScript.bind(targetContext)
                    : typeof page.addInitScript === 'function'
                      ? page.addInitScript.bind(page)
                      : null;

            if (!addScript) {
                return undefined;
            }

            if (args.length <= 1 || typeof pageFunction !== 'function') {
                return addScript(pageFunction, args[0]);
            }

            const fnSource = pageFunction.toString();
            return addScript(
                ([serializedFn, serializedArgs]) => {
                    // eslint-disable-next-line no-new-func
                    const hydratedFn = new Function(`return (${serializedFn})`)();
                    return hydratedFn(...serializedArgs);
                },
                [fnSource, args]
            );
        };
    }

    // Puppeteer page.setViewport({ width, height }) & page.viewport()
    if (typeof page.setViewport !== 'function') {
        page.setViewport = async (viewport) => {
            if (!viewport || typeof viewport !== 'object') {
                return;
            }
            const { width, height } = viewport;
            page._camoufoxViewport = { ...viewport };
            if (typeof page.setViewportSize === 'function' && width && height) {
                await page.setViewportSize({ width, height });
            }
        };
    }

    if (typeof page.viewport !== 'function') {
        page.viewport = () => {
            if (typeof page.viewportSize === 'function') {
                const size = page.viewportSize();
                if (size) {
                    return page._camoufoxViewport ? { ...page._camoufoxViewport, ...size } : size;
                }
            }
            return page._camoufoxViewport || null;
        };
    }

    // Puppeteer page.setUserAgent(ua) -> guard against non-Firefox UA overrides on Camoufox
    if (typeof page.setUserAgent !== 'function') {
        page.setUserAgent = async (userAgent, options = {}) => {
            const uaString = String(userAgent ?? '');
            const isFirefoxCoherent =
                /Firefox\/\d+|Gecko\/\d+/i.test(uaString) &&
                !/Chrome\/\d+|Chromium\/\d+|Edg\/\d+/i.test(uaString);

            if (!isFirefoxCoherent) {
                page._lastBlockedUserAgent = uaString;
                logger.warn(
                    'Blocked non-Firefox page.setUserAgent() on Camoufox to preserve Firefox C++ fingerprint coherence',
                    { userAgent: uaString }
                );
                if (options?.strict === true) {
                    throw new Error(
                        `Refusing to set non-Firefox User-Agent on Camoufox: ${uaString}`
                    );
                }
                return {
                    applied: false,
                    blocked: true,
                    reason: 'non_firefox_ua_blocked'
                };
            }

            logger.debug(
                'Ignoring runtime page.setUserAgent() on Camoufox; User-Agent is managed at the C++ BrowserForge layer',
                { userAgent: uaString }
            );
            return {
                applied: false,
                blocked: false,
                reason: 'managed_by_camoufox_cpp'
            };
        };
    }

    // Puppeteer page.cookies(...urls) -> Playwright context.cookies(urls)
    if (typeof page.cookies !== 'function') {
        page.cookies = async (...urls) => {
            const targetContext = resolveContext();
            if (!targetContext || typeof targetContext.cookies !== 'function') {
                return [];
            }
            if (urls.length > 0) {
                return targetContext.cookies(urls);
            }
            const currentUrl = typeof page.url === 'function' ? page.url() : '';
            if (currentUrl && /^https?:\/\//i.test(currentUrl)) {
                return targetContext.cookies([currentUrl]);
            }
            return targetContext.cookies();
        };
    }

    // Puppeteer page.setCookie(...cookies) -> Playwright context.addCookies(cookies)
    if (typeof page.setCookie !== 'function') {
        page.setCookie = async (...cookies) => {
            const targetContext = resolveContext();
            if (!targetContext || typeof targetContext.addCookies !== 'function') {
                return;
            }
            const currentUrl = typeof page.url === 'function' ? page.url() : '';
            const normalized = cookies
                .flat()
                .filter((c) => c && typeof c === 'object' && c.name)
                .map((cookie) => {
                    const copy = { ...cookie };
                    if (!copy.url && !copy.domain && currentUrl && /^https?:\/\//i.test(currentUrl)) {
                        copy.url = currentUrl;
                    } else if (copy.domain && !copy.path) {
                        copy.path = '/';
                    }
                    return copy;
                });

            if (normalized.length > 0) {
                await targetContext.addCookies(normalized);
            }
        };
    }

    // Puppeteer page.deleteCookie(...cookies) -> filter & restore on Playwright context
    if (typeof page.deleteCookie !== 'function') {
        page.deleteCookie = async (...cookiesToDelete) => {
            const targetContext = resolveContext();
            if (!targetContext) {
                return;
            }
            const targets = cookiesToDelete
                .flat()
                .filter((c) => c && typeof c === 'object' && c.name);
            if (targets.length === 0) {
                return;
            }

            const matchesTarget = (cookie, target) => {
                if (cookie.name !== target.name) {
                    return false;
                }
                if (
                    target.domain &&
                    normalizeCookieDomain(cookie.domain) !== normalizeCookieDomain(target.domain)
                ) {
                    return false;
                }
                if (target.path && cookie.path && cookie.path !== target.path) {
                    return false;
                }
                return true;
            };

            if (
                typeof targetContext.cookies === 'function' &&
                typeof targetContext.clearCookies === 'function'
            ) {
                const existing = await targetContext.cookies();
                const remaining = existing.filter(
                    (cookie) => !targets.some((target) => matchesTarget(cookie, target))
                );
                await targetContext.clearCookies();
                if (remaining.length > 0 && typeof targetContext.addCookies === 'function') {
                    await targetContext.addCookies(remaining);
                }
                return;
            }

            if (typeof targetContext.addCookies === 'function') {
                const currentUrl = typeof page.url === 'function' ? page.url() : '';
                const expired = targets.map((target) => ({
                    ...target,
                    value: '',
                    expires: 0,
                    ...(!target.url && !target.domain && currentUrl && /^https?:\/\//i.test(currentUrl)
                        ? { url: currentUrl }
                        : {}),
                    ...(target.domain && !target.path ? { path: '/' } : {})
                }));
                await targetContext.addCookies(expired);
            }
        };
    }

    // Wrap page.frames() and page.mainFrame() so all frames have $x / waitForXPath
    if (typeof page.frames === 'function') {
        const originalFrames = page.frames.bind(page);
        page.frames = () => {
            const frames = originalFrames();
            return Array.isArray(frames)
                ? frames.map((f) => attachFrameCompatibility(f))
                : frames;
        };
    }

    if (typeof page.mainFrame === 'function') {
        const originalMainFrame = page.mainFrame.bind(page);
        page.mainFrame = () => attachFrameCompatibility(originalMainFrame());
    }

    // Puppeteer page.browser() -> returns compatibility-decorated Browser instance
    if (typeof page.browser !== 'function') {
        page.browser = () => {
            const targetBrowser = resolveBrowser();
            const targetContext = resolveContext();
            return targetBrowser
                ? attachBrowserCompatibility(targetBrowser, page._camoufoxProfile || { context: targetContext })
                : null;
        };
    }

    return page;
}

/**
 * Decorate a Playwright Browser with `pages()`, `newPage()`, `disconnect()`, and `isConnected()`
 * convenience methods so callers expecting Puppeteer's `Browser` API work transparently.
 */
export function attachBrowserCompatibility(browser, profile = null) {
    if (!browser) {
        return browser;
    }

    const resolvePrimaryContext = () => {
        if (profile?.context) {
            return profile.context;
        }
        if (
            profile &&
            typeof profile.pages === 'function' &&
            typeof profile.newPage === 'function'
        ) {
            return profile;
        }
        const contexts = typeof browser.contexts === 'function' ? browser.contexts() : [];
        return contexts[0] || null;
    };

    if (!browser._camoufoxPagesWrapped) {
        browser.pages = async () => {
            const primaryContext = resolvePrimaryContext();
            if (primaryContext && typeof primaryContext.pages === 'function') {
                return primaryContext
                    .pages()
                    .map((p) => attachPageCompatibility(p, primaryContext, profile || browser));
            }
            const contexts = typeof browser.contexts === 'function' ? browser.contexts() : [];
            return contexts.flatMap((ctx) =>
                ctx.pages().map((p) => attachPageCompatibility(p, ctx, profile || browser))
            );
        };
        Object.defineProperty(browser, '_camoufoxPagesWrapped', {
            value: true,
            enumerable: false,
            configurable: true
        });
    }

    if (!browser._camoufoxNewPageWrapped) {
        const originalBrowserNewPage =
            typeof browser.newPage === 'function' ? browser.newPage.bind(browser) : null;

        browser.newPage = async (...args) => {
            const primaryContext = resolvePrimaryContext();
            if (primaryContext && typeof primaryContext.newPage === 'function') {
                const page = await primaryContext.newPage(...args);
                return attachPageCompatibility(page, primaryContext, profile || browser);
            }
            if (originalBrowserNewPage) {
                const page = await originalBrowserNewPage(...args);
                return attachPageCompatibility(page, page?.context?.() || null, profile || browser);
            }
            throw new Error('No active Playwright context available to create a new page');
        };
        Object.defineProperty(browser, '_camoufoxNewPageWrapped', {
            value: true,
            enumerable: false,
            configurable: true
        });
    }

    if (typeof browser.disconnect !== 'function') {
        browser.disconnect = async () => {
            if (profile && typeof profile.saveStorageState === 'function') {
                await profile.saveStorageState();
            }
        };
    }

    if (typeof browser.isConnected !== 'function') {
        browser.isConnected = () => true;
    }

    return browser;
}

export class CamoufoxProfile {
    constructor(profileId, options = {}) {
        this.profileId = profileId;
        this.options = options;
        this.browser = null;
        this.context = null;
        this.page = null;
        this.storageStatePath = null;
        this.metadata = null;
        this.coherenceReport = null;
        this.trafficRecorder = null;
        this.trafficPaths = null;
        this.lastTrafficAttribution = null;
    }

    /**
     * Set active workflow step for pre-TLS traffic attribution
     */
    setTrafficStep(stepName, metadata = {}) {
        return this.trafficRecorder?.setStep(stepName, metadata);
    }

    /**
     * Update account/profile attribution metadata on the active traffic recorder
     */
    updateTrafficAttribution(partial = {}) {
        return this.trafficRecorder?.updateAttribution(partial);
    }

    /**
     * Get the underlying CamoufoxTrafficRecorder instance
     */
    getTrafficRecorder() {
        return this.trafficRecorder;
    }

    /**
     * Flush and return the latest pre-TLS traffic attribution summary report
     */
    async getTrafficAttribution() {
        if (this.trafficRecorder) {
            if (typeof this.trafficRecorder.flushSummary === 'function') {
                return await this.trafficRecorder.flushSummary();
            }
            if (typeof this.trafficRecorder.getSummary === 'function') {
                return this.trafficRecorder.getSummary();
            }
        }
        return this.lastTrafficAttribution || null;
    }

    /**
     * Audit in-browser C++ fingerprint coherence on the active profile page
     */
    async auditCoherence(expectedOs = null) {
        const page = await this.getPage();
        const targetOs = expectedOs || this.metadata?.os || this.options?.os || 'windows';
        this.coherenceReport = await auditProfileCoherence(page, targetOs);
        return this.coherenceReport;
    }

    /**
     * Start profile and initialize Camoufox Browser, BrowserContext, and Page
     */
    async start() {
        try {
            logger.info('Starting Camoufox profile', { profileId: this.profileId });

            const session = await camoufoxClient.startProfile(this.profileId, this.options);
            this.context = session.context;
            this.storageStatePath = session.storageStatePath;
            this.metadata = session.metadata;
            this.trafficRecorder = session.trafficRecorder || null;
            this.trafficPaths = session.trafficPaths || null;

            if (this.context) {
                this.context._camoufoxTrafficRecorder = this.trafficRecorder;
            }
            if (this.trafficRecorder) {
                lastActiveTrafficRecorder = this.trafficRecorder;
            }

            this.browser = attachBrowserCompatibility(session.browser, this);
            this.page = attachPageCompatibility(session.page, this.context, this);

            // Wrap context.newPage so any additional pages also receive compatibility helpers
            if (this.context && !this.context._camoufoxNewPageWrapped) {
                const originalNewPage = this.context.newPage.bind(this.context);
                this.context.newPage = async (...args) => {
                    const newPage = await originalNewPage(...args);
                    if (this.trafficRecorder && typeof this.trafficRecorder.attachPage === 'function') {
                        await this.trafficRecorder.attachPage(newPage);
                    }
                    return attachPageCompatibility(newPage, this.context, this);
                };
                Object.defineProperty(this.context, '_camoufoxNewPageWrapped', {
                    value: true,
                    enumerable: false,
                    configurable: true
                });
            }

            if (this.options?.verifyCoherence || process.env.CAMOUFOX_AUDIT_ON_START === 'true') {
                await this.auditCoherence(this.metadata?.os);
            }

            logger.info('Camoufox profile started successfully', {
                profileId: this.profileId,
                os: this.metadata?.os,
                storageStatePath: this.storageStatePath
            });

            return this;
        } catch (error) {
            logger.error('Failed to start Camoufox profile', {
                profileId: this.profileId,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Get browser instance (starts profile if needed)
     */
    async getBrowser() {
        if (!this.browser) {
            await this.start();
        }
        return this.browser;
    }

    /**
     * Get isolated Playwright BrowserContext instance (starts profile if needed)
     */
    async getContext() {
        if (!this.context) {
            await this.start();
        }
        return this.context;
    }

    /**
     * Get primary Page instance (creates one in the profile context if needed)
     */
    async getPage() {
        if (!this.page || (typeof this.page.isClosed === 'function' && this.page.isClosed())) {
            const context = await this.getContext();
            const pages = context.pages();
            this.page = attachPageCompatibility(
                pages[0] || (await context.newPage()),
                context,
                this
            );
        }
        return this.page;
    }

    /**
     * Persist cookies (`datr`, `ig_did`, `ttwid`, etc.) and `localStorage`
     * to `profiles/<profileId>/storage-state.json`
     */
    async saveStorageState() {
        if (!this.context) {
            return null;
        }
        const savedPath = await camoufoxClient.saveProfileStorageState(
            this.profileId,
            this.context,
            this.options?.profilesDir
        );
        if (savedPath) {
            this.storageStatePath = savedPath;
        }
        return savedPath;
    }

    /**
     * Stop profile (automatically saves storageState and flushes traffic attribution before closing)
     */
    async stop() {
        try {
            await this.saveStorageState();
        } catch (error) {
            logger.warn('Failed to save Camoufox storageState during stop()', {
                profileId: this.profileId,
                error: error.message
            });
        }

        if (this.trafficRecorder && typeof this.trafficRecorder.stop === 'function') {
            try {
                this.lastTrafficAttribution = await this.trafficRecorder.stop();
            } catch (error) {
                logger.warn('Failed to stop Camoufox trafficRecorder during stop()', {
                    profileId: this.profileId,
                    error: error.message
                });
            }
        }

        try {
            const stopped = await camoufoxClient.stopProfile(this.profileId, this.options);
            this.browser = null;
            this.context = null;
            this.page = null;
            logger.info('Camoufox profile stopped', { profileId: this.profileId });
            return stopped;
        } catch (error) {
            logger.warn('Error stopping Camoufox profile', {
                profileId: this.profileId,
                error: error.message
            });
            this.browser = null;
            this.context = null;
            this.page = null;
            return false;
        }
    }

    /**
     * Delete profile and its persistent storage directory
     */
    async delete() {
        try {
            await this.stop();
            await camoufoxClient.deleteProfile(this.profileId, this.options);
            logger.info('Camoufox profile deleted', { profileId: this.profileId });
            return true;
        } catch (error) {
            logger.error('Failed to delete Camoufox profile', {
                profileId: this.profileId,
                error: error.message
            });
            throw error;
        }
    }
}

/**
 * Create and start a new Camoufox profile
 */
export async function createAndStartProfile(profileName, proxy = null, options = {}) {
    try {
        const isAvailable = await camoufoxClient.checkCamoufoxConnection();
        if (!isAvailable) {
            throw new Error(
                'Camoufox module is not available. Ensure the camoufox package or /Volumes/hello/wj/camoufox/typescript/dist/index.js is built.'
            );
        }

        logger.info('Creating Camoufox profile...', { name: profileName });
        const profileData = await camoufoxClient.createProfile(profileName, proxy, options);

        if (!profileData || !profileData.id) {
            throw new Error('Failed to create Camoufox profile: No profile ID returned');
        }

        const profileManager = new CamoufoxProfile(profileData.id, {
            ...options,
            proxy: profileData.proxy,
            os: profileData.os,
            geoip: profileData.geoip,
            humanize: profileData.humanize
        });

        await profileManager.start();

        logger.info('Camoufox profile created and started', {
            profileId: profileData.id,
            name: profileData.title || profileName,
            os: profileData.os,
            storageStatePath: profileManager.storageStatePath
        });

        return profileManager;
    } catch (error) {
        logger.error('Failed to create and start Camoufox profile', { error: error.message });
        throw error;
    }
}

export default CamoufoxProfile;
