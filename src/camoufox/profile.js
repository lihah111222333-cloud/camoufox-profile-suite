/**
 * Camoufox Profile Manager
 * Drop-in replacement for Dolphin Anty (`src/dolphin/profile.js`) and GPM Login (`src/gpmlogin/profile.js`)
 */

import logger from '../utils/logger.js';
import camoufoxClient, { validateCamoufoxNetworkPolicy } from './client.js';
import { auditProfileCoherence, evaluateWireToDomCoherence } from './coherence-auditor.js';

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

const contextBindings = new WeakMap();
const pageContexts = new WeakMap();
const framePages = new WeakMap();
const handleOwners = new WeakMap();

function bindContext(context, profile) {
    let binding = contextBindings.get(context);
    if (!binding) {
        binding = { closed: false };
        contextBindings.set(context, binding);
        context.once?.('close', () => {
            binding.closed = true;
        });
    }
    if (profile?.context === context) {
        binding.profile ??= profile;
        if (binding.trafficRecorder === undefined && profile.trafficRecorder !== undefined) {
            binding.trafficRecorder = profile.trafficRecorder;
        }
        if (profile instanceof CamoufoxProfile) {
            binding.manager ??= profile;
        }
    }
    return binding;
}

function isContextUsable(context) {
    if (!context || (typeof context.isClosed === 'function' && context.isClosed())) {
        return false;
    }
    const binding = contextBindings.get(context);
    return !binding?.closed && binding?.isBrowserConnected?.() !== false;
}

function resolvePageContext(page) {
    return pageContexts.get(page) || page?.context?.() || null;
}

function resolveContextRecorder(context) {
    if (!isContextUsable(context)) return null;
    const recorder = contextBindings.get(context)?.trafficRecorder;
    return recorder && !recorder.stopped ? recorder : null;
}

function resolveFrameRecorder(frame) {
    const page = framePages.get(frame) || frame?.page?.() || frame;
    return resolveContextRecorder(resolvePageContext(page));
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

    if (owner && !handleOwners.has(handle)) handleOwners.set(handle, owner);

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
                handleOwners.get(handle),
                selector
            );
    }

    if (typeof handle.$$ === 'function') {
        const originalQueryAll = handle.$$.bind(handle);
        handle.$$ = async (selector) => {
            const elements = await originalQueryAll(selector);
            return Array.isArray(elements)
                ? elements.map((el) =>
                      attachElementHandleCompatibility(el, handleOwners.get(handle), selector)
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
                handleOwners.get(handle),
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
            return attachElementHandleCompatibility(res, handleOwners.get(handle));
        };
    }

    for (const methodName of ['click', 'fill', 'type', 'press']) {
        if (typeof handle[methodName] === 'function') {
            const originalMethod = handle[methodName].bind(handle);
            handle[methodName] = async (...args) => {
                try {
                    const recorder = resolveFrameRecorder(handleOwners.get(handle));
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
                handleOwners.get(handle),
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
export function attachFrameCompatibility(frame, page = null) {
    if (!frame || typeof frame !== 'object') {
        return frame;
    }
    if (page && !framePages.has(frame)) framePages.set(frame, page);
    if (frame._camoufoxFrameCompatAttached) return frame;

    Object.defineProperty(frame, '_camoufoxFrameCompatAttached', {
        value: true,
        enumerable: false,
        configurable: true
    });
    if (!frame._camoufoxCompatAttached) {
        Object.defineProperty(frame, '_camoufoxCompatAttached', {
            value: true,
            enumerable: false,
            configurable: true
        });
    }

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

    const owningContext = resolvePageContext(page) || context;
    if (owningContext && !pageContexts.has(page)) {
        pageContexts.set(page, owningContext);
        Object.defineProperty(page, '_camoufoxContext', {
            value: owningContext
        });
    }

    if (owningContext) {
        const binding = bindContext(owningContext, profile);
        if (!binding.browserView) {
            const owningProfile = profile?.context === owningContext ? profile : null;
            const browser = owningContext.browser?.() || owningProfile?.browser;
            if (browser) {
                attachBrowserCompatibility(browser, owningProfile || { context: owningContext });
            }
        }
    }

    if (page._camoufoxPageCompatAttached) {
        return page;
    }

    const resolveContext = () => resolvePageContext(page);
    const resolveRecorder = () => resolveContextRecorder(resolveContext());
    page.getTrafficRecorder = resolveRecorder;
    page.setTrafficStep = (stepName, meta = {}) => resolveRecorder()?.setStep(stepName, meta) || null;
    page.setStep = page.setTrafficStep;
    page.recordTrafficTrigger = (actionType, target = null, meta = {}) =>
        resolveRecorder()?.recordTriggerAction?.(actionType, target, meta) || null;

    Object.defineProperty(page, '_camoufoxProfile', {
        get() {
            const ctx = resolveContext();
            const manager = contextBindings.get(ctx)?.manager;
            return manager?.context === ctx ? manager : null;
        }
    });

    Object.defineProperty(page, '_camoufoxPageCompatAttached', {
        value: true,
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(page, '_camoufoxCompatAttached', {
        value: true,
        enumerable: false,
        configurable: true
    });

    // Apply all Frame-level shims ($x, waitForXPath, waitForSelector, goto, waitForNavigation, evaluate, evaluateHandle, waitForTimeout)
    attachFrameCompatibility(page);

    // Instrument page.goto with causal trigger attribution
    if (typeof page.goto === 'function') {
        const normalizedGoto = page.goto.bind(page);
        page.goto = async (url, options) => {
            try {
                const recorder = resolveRecorder();
                if (recorder) {
                    const targetUrl = typeof url === 'string' ? url : String(url ?? '');
                    recorder.recordTriggerAction?.('page.goto', targetUrl, {
                        url: targetUrl,
                        pageUrl: typeof page.url === 'function' ? page.url() : null
                    });
                }
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
                    const recorder = resolveRecorder();
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

    // Puppeteer page.userAgent() -> return active browser/profile Firefox User-Agent
    if (typeof page.userAgent !== 'function') {
        page.userAgent = async () => {
            if (typeof page.evaluate === 'function') {
                try {
                    const domUa = await page.evaluate(() =>
                        typeof window !== 'undefined' && window.navigator?.userAgent
                            ? window.navigator.userAgent
                            : typeof navigator !== 'undefined' &&
                                navigator.userAgent &&
                                !/^Node\.js\//i.test(navigator.userAgent)
                              ? navigator.userAgent
                              : null
                    );
                    if (typeof domUa === 'string' && domUa.trim().length > 0) {
                        return domUa;
                    }
                } catch {
                    // Fallback to profile metadata or OS-coherent Firefox User-Agent
                }
            }
            return profileUserAgent(page._camoufoxProfile || contextBindings.get(resolveContext())?.profile);
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
                    if (typeof copy.sameSite === 'string') {
                        const lowerSameSite = copy.sameSite.trim().toLowerCase();
                        if (lowerSameSite === 'lax') {
                            copy.sameSite = 'Lax';
                        } else if (lowerSameSite === 'strict') {
                            copy.sameSite = 'Strict';
                        } else if (lowerSameSite === 'none' || lowerSameSite === 'no_restriction') {
                            copy.sameSite = 'None';
                        } else if (
                            lowerSameSite === 'unspecified' ||
                            lowerSameSite === 'default' ||
                            lowerSameSite === ''
                        ) {
                            delete copy.sameSite;
                        }
                    }
                    if (copy.domain) {
                        delete copy.url;
                        if (!copy.path) {
                            copy.path = '/';
                        }
                    } else {
                        if (!copy.url && currentUrl && /^https?:\/\//i.test(currentUrl)) {
                            copy.url = currentUrl;
                        }
                        if (copy.url) {
                            delete copy.path;
                        }
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

            const extractCookieHostname = (rawDomain, rawUrl) => {
                const normDom = normalizeCookieDomain(rawDomain);
                if (normDom) return normDom;
                if (typeof rawUrl === 'string' && rawUrl.trim()) {
                    try {
                        return normalizeCookieDomain(new URL(rawUrl).hostname);
                    } catch {
                        return normalizeCookieDomain(rawUrl);
                    }
                }
                return '';
            };

            const matchesTarget = (cookie, target) => {
                if (cookie.name !== target.name) {
                    return false;
                }
                const cookieDomain = extractCookieHostname(cookie.domain, cookie.url);
                if (target.domain) {
                    if (cookieDomain !== normalizeCookieDomain(target.domain)) {
                        return false;
                    }
                } else if (target.url) {
                    const targetHost = extractCookieHostname(null, target.url);
                    if (
                        targetHost &&
                        cookieDomain &&
                        cookieDomain !== targetHost &&
                        !targetHost.endsWith(`.${cookieDomain}`)
                    ) {
                        return false;
                    }
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
                ? frames.map((f) => attachFrameCompatibility(f, page))
                : frames;
        };
    }

    if (typeof page.mainFrame === 'function') {
        const originalMainFrame = page.mainFrame.bind(page);
        page.mainFrame = () => attachFrameCompatibility(originalMainFrame(), page);
    }

    page.browser = () => contextBindings.get(resolveContext())?.browserView || null;

    return page;
}

function profileUserAgent(profile) {
    const metaUa =
        profile?.metadata?.userAgent ||
        profile?.metadata?.hardwareProfile?.userAgent ||
        profile?.options?.userAgent ||
        null;
    if (typeof metaUa === 'string' && metaUa.trim().length > 0) {
        return metaUa;
    }
    const os = String(profile?.metadata?.os || profile?.options?.os || 'windows').toLowerCase();
    if (os === 'macos' || os === 'mac' || os === 'darwin') {
        return 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0';
    }
    if (os === 'linux') {
        return 'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0';
    }
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0';
}

/**
 * Expose the Puppeteer browser operations that can be fulfilled by one Playwright context.
 */
export function attachBrowserCompatibility(browser, profile = null) {
    if (!browser || !profile || browser === profile) return null;

    const context =
        profile.context ||
        (typeof profile.pages === 'function' &&
        typeof profile.newPage === 'function' &&
        typeof profile.contexts !== 'function'
            ? profile
            : null);
    const binding = context ? bindContext(context, profile) : null;
    if (binding?.browserView) return binding.browserView;

    const getPages = context?.pages?.bind(context);
    const createPage = context?.newPage?.bind(context);
    const closeContext = context?.close?.bind(context);
    const decoratePage = (page) => attachPageCompatibility(page, context);
    const listPages = () => (isContextUsable(context) && getPages ? getPages().map(decoratePage) : []);
    const newPage = async (...args) => {
        if (!isContextUsable(context) || !createPage) {
            throw new Error('No active Playwright context available to create a new page');
        }
        const page = await createPage(...args);
        await resolveContextRecorder(context)?.attachPage?.(page);
        return decoratePage(page);
    };

    const view = Object.freeze({
        pages: async () => listPages(),
        newPage,
        isConnected: () => isContextUsable(context),
        async disconnect() {
            if (isContextUsable(context)) await profile.saveStorageState?.();
        },
        async userAgent() {
            const [page] = listPages();
            return page ? page.userAgent() : profileUserAgent(profile);
        }
    });

    if (binding) {
        binding.browserView = view;
        binding.isBrowserConnected = () =>
            (profile === context || profile.context === context) && browser.isConnected?.() !== false;
        context.browser = () => view;
        if (getPages) context.pages = listPages;
        if (createPage) context.newPage = newPage;
        if (closeContext) {
            context.close = (...args) => {
                binding.closed = true;
                return closeContext(...args);
            };
        }
        context.on?.('page', decoratePage);
    }
    return view;
}

/**
 * Keep the native browser with the client lifecycle and return the profile-scoped view.
 */
export function attachSessionCompatibility(session) {
    const { browser, context, page, profileId, profilesDir, metadata, trafficRecorder } = session;
    const view = attachBrowserCompatibility(browser, {
        context,
        metadata,
        trafficRecorder: trafficRecorder ?? null,
        saveStorageState: () => camoufoxClient.saveProfileStorageState(profileId, context, profilesDir)
    });
    return {
        ...session,
        browser: view,
        page: attachPageCompatibility(page, context)
    };
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
        this.fingerprintLedger = null;
        this.securityGuards = null;
        this.gpuPerformanceScaler = null;
    }

    /**
     * Get the Per-Domain Canvas & WebGL Fingerprint Consistency Ledger for this profile
     */
    getFingerprintLedger() {
        return this.fingerprintLedger;
    }

    /**
     * Record or verify a Canvas / WebGL observation in the profile's consistency ledger
     */
    recordOrVerifyFingerprint(observation = {}) {
        return this.fingerprintLedger ? this.fingerprintLedger.recordOrVerify(observation) : null;
    }

    /**
     * Get the active Ziniao-absorbed port-scan & internal-scheme security guard handle
     */
    getSecurityGuards() {
        return this.securityGuards;
    }

    /**
     * Get the Host-Mac-Calibrated GPU Performance Scaler attached to this profile
     */
    getGpuPerformanceScaler() {
        return this.gpuPerformanceScaler;
    }

    /**
     * Set active workflow step for pre-TLS traffic attribution
     */
    setTrafficStep(stepName, metadata = {}) {
        return this.trafficRecorder?.setStep(stepName, metadata);
    }

    /**
     * Alias for setTrafficStep
     */
    setStep(stepName, metadata = {}) {
        return this.setTrafficStep(stepName, metadata);
    }

    /**
     * Return a consolidated summary of Camoufox hardware preset, GPU performance scaling,
     * active security guard statistics, fingerprint consistency ledger, and coherence report.
     */
    getTelemetrySummary() {
        const gpuWeights =
            this.gpuPerformanceScaler?.scalingWeights ||
            this.lastGpuPerformanceSummary ||
            this.metadata?.gpuPerformance ||
            null;
        return {
            profileId: this.profileId,
            presetId: this.metadata?.presetId || null,
            deviceModel: this.metadata?.deviceModel || this.metadata?.hardwareProfile?.deviceModel || null,
            os: this.metadata?.os || null,
            gpuPerformance: gpuWeights
                ? {
                      targetGpuModel: gpuWeights.targetGpuSpec?.model || gpuWeights.targetGpuModel || null,
                      hostChipModel: gpuWeights.hostBaseline?.hostChipModel || null,
                      computeTimeMultiplier: gpuWeights.computeTimeMultiplier ?? null,
                      throughputSpeedupRatio: gpuWeights.throughputSpeedupRatio ?? null,
                      antiPenetrationActive: gpuWeights.antiPenetrationActive ?? true
                  }
                : null,
            securityGuards:
                this.securityGuards?.getStats?.() || this.lastSecurityGuardStats || null,
            fingerprintLedger:
                this.fingerprintLedger?.getSummary?.() || null,
            coherenceScore: this.coherenceReport?.score ?? null,
            coherencePassed: this.coherenceReport?.passed ?? null
        };
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
    async auditCoherence(expectedOs = null, options = {}) {
        const page = await this.getPage();
        const targetOs = expectedOs || this.metadata?.os || this.options?.os || 'windows';
        this.coherenceReport = await auditProfileCoherence(page, targetOs, {
            profileId: this.profileId,
            hardwareProfile: this.metadata?.hardwareProfile || undefined,
            gpuPerformance:
                this.gpuPerformanceScaler?.scalingWeights ||
                this.metadata?.gpuPerformance ||
                undefined,
            ...options
        });
        if (
            this.fingerprintLedger &&
            typeof this.fingerprintLedger.recordOrVerify === 'function'
        ) {
            const pageUrl =
                typeof page?.url === 'function' ? page.url() : 'about:blank';
            if (this.coherenceReport?.telemetry?.canvas2d?.fnv1aHash) {
                try {
                    this.coherenceReport.canvasConsistency = this.fingerprintLedger.recordOrVerify({
                        kind: 'canvas',
                        url: pageUrl || 'about:blank',
                        width: 240,
                        height: 60,
                        drewText: 'Camoufox Coherence 🦊 123.45',
                        hash: this.coherenceReport.telemetry.canvas2d.fnv1aHash
                    });
                } catch (ledgerErr) {
                    logger.debug('Could not record canvas2d hash in fingerprintLedger during auditCoherence', {
                        profileId: this.profileId,
                        error: ledgerErr.message
                    });
                }
            }
            const webglInfo = this.coherenceReport?.telemetry?.webgl;
            if (webglInfo && (webglInfo.fnv1aHash || webglInfo.unmaskedRenderer || webglInfo.renderer)) {
                try {
                    let webglHash = webglInfo.fnv1aHash;
                    if (!webglHash || !/^[0-9a-f]+$/i.test(String(webglHash))) {
                        const sig = [
                            webglInfo.unmaskedVendor || webglInfo.vendor || '',
                            webglInfo.unmaskedRenderer || webglInfo.renderer || '',
                            webglInfo.version || '',
                            webglInfo.shadingLanguageVersion || '',
                            webglInfo.maxTextureSize ?? '',
                            webglInfo.extensionsCount ?? ''
                        ].join('|');
                        let hHigh = 0x811c9dc5;
                        let hLow = 0xcbf29ce4;
                        for (let i = 0; i < sig.length; i++) {
                            const b = sig.charCodeAt(i) & 0xff;
                            hHigh ^= b;
                            hHigh = Math.imul(hHigh, 0x01000193) >>> 0;
                            if ((i & 1) === 1) {
                                hLow ^= b;
                                hLow = Math.imul(hLow, 0x01000193) >>> 0;
                            }
                        }
                        webglHash =
                            hHigh.toString(16).padStart(8, '0') +
                            hLow.toString(16).padStart(8, '0');
                    }
                    this.coherenceReport.webglConsistency = this.fingerprintLedger.recordOrVerify({
                        kind: 'webgl',
                        url: pageUrl || 'about:blank',
                        width: 64,
                        height: 64,
                        drewText: webglInfo.unmaskedRenderer || webglInfo.renderer || '',
                        hash: webglHash
                    });
                } catch (ledgerErr) {
                    logger.debug('Could not record webgl hash in fingerprintLedger during auditCoherence', {
                        profileId: this.profileId,
                        error: ledgerErr.message
                    });
                }
            }
        }
        if (this.trafficRecorder && this.coherenceReport?.telemetry) {
            this.coherenceReport.wireToDomCoherence = evaluateWireToDomCoherence(
                this.coherenceReport.telemetry,
                this.trafficRecorder,
                targetOs
            );
        }
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
            this.fingerprintLedger = session.fingerprintLedger || null;
            this.securityGuards = session.securityGuards || null;
            this.gpuPerformanceScaler = session.gpuPerformanceScaler || null;

            this.browser = session.browser;
            this.page = attachPageCompatibility(session.page, this.context, this);

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

        if (this.securityGuards && typeof this.securityGuards.getStats === 'function') {
            try {
                this.lastSecurityGuardStats = this.securityGuards.getStats();
            } catch {}
        }
        if (this.gpuPerformanceScaler?.scalingWeights || this.metadata?.gpuPerformance) {
            this.lastGpuPerformanceSummary =
                this.gpuPerformanceScaler?.scalingWeights || this.metadata?.gpuPerformance;
        }

        try {
            const stopped = await camoufoxClient.stopProfile(this.profileId, this.options);
            if (this.trafficRecorder && typeof this.trafficRecorder.stop === 'function') {
                try {
                    this.lastTrafficAttribution = await this.trafficRecorder.stop();
                } catch {}
            }
            this.browser = null;
            this.context = null;
            this.page = null;
            this.securityGuards = null;
            this.gpuPerformanceScaler = null;
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
            this.securityGuards = null;
            this.gpuPerformanceScaler = null;
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
        validateCamoufoxNetworkPolicy(options, proxy || options.proxy || null);
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
