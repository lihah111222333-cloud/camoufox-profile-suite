/**
 * Camoufox Profile Manager
 * Drop-in replacement for Dolphin Anty (`src/dolphin/profile.js`) and GPM Login (`src/gpmlogin/profile.js`)
 */

import path from 'node:path';
import { Script } from 'node:vm';
import logger from '../utils/logger.js';
import camoufoxClient, {
    rollbackCreatedProfile, validateCamoufoxNetworkPolicy, waitForCamoufoxStartup
} from './client.js';
import {
    auditProfileCoherence, evaluateWireToDomCoherence, readCoherenceCaptureEvents, summarizeCoherenceChecks
} from './coherence-auditor.js';
import { recordedControlKey } from './traffic-redaction.js';

const WAIT_UNTIL_MAP = {
    networkidle0: 'networkidle',
    networkidle2: 'networkidle',
    domcontentloaded: 'domcontentloaded',
    load: 'load',
    commit: 'commit'
};

/**
 * Normalize Puppeteer-style navigation options (`networkidle2` / `networkidle0`) for Playwright.
 * Playwright accepts a single lifecycle condition, so reject waits requiring multiple conditions.
 */
export function normalizeNavigationOptions(options) {
    if (!options || typeof options !== 'object') {
        return options;
    }
    const normalized = { ...options };
    if (Array.isArray(normalized.waitUntil)) {
        if (normalized.waitUntil.length > 1) {
            throw new TypeError('Camoufox navigation supports only one waitUntil condition');
        }
        normalized.waitUntil = normalized.waitUntil[0] || 'load';
    }
    if (typeof normalized.waitUntil === 'string') {
        normalized.waitUntil = WAIT_UNTIL_MAP[normalized.waitUntil] || normalized.waitUntil;
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

function parseCookieUrl(value) {
    if (typeof value !== 'string') return null;
    try {
        const url = new URL(value);
        return url.protocol === 'http:' || url.protocol === 'https:' ? url : null;
    } catch {
        return null;
    }
}

function currentCookieUrl(page) {
    try {
        return parseCookieUrl(page.url?.());
    } catch {
        return null;
    }
}

function cookieMatchesScope(cookie, { name, domain, url, path, partitionKey, _crHasCrossSiteAncestor }) {
    if (cookie.name !== name || (cookie.partitionKey ?? null) !== partitionKey) return false;
    if (_crHasCrossSiteAncestor !== undefined && cookie._crHasCrossSiteAncestor !== _crHasCrossSiteAncestor) return false;
    if (typeof cookie.domain !== 'string' || !cookie.domain) return false;
    if (typeof cookie.path !== 'string' || !cookie.path.startsWith('/')) return false;

    const cookieDomain = cookie.domain.toLowerCase();
    if (domain) {
        if (cookieDomain !== domain) return false;
    } else {
        const host = url.hostname.toLowerCase();
        const hostMatches = cookieDomain.startsWith('.')
            ? `.${host}`.endsWith(cookieDomain)
            : host === cookieDomain;
        if (!hostMatches || (cookie.secure && url.protocol !== 'https:')) return false;
    }

    if (path !== undefined) return cookie.path === path;
    if (!url || url.pathname === cookie.path) return true;
    return url.pathname.startsWith(cookie.path.endsWith('/') ? cookie.path : `${cookie.path}/`);
}

/**
 * The adapter serializes standalone functions and arrows. Check the same expression
 * used by the backend without running the callback or registering an initializer.
 */
function evaluationFunctionSource(pageFunction) {
    const message = 'Camoufox evaluation requires a serializable standalone function or arrow function';
    if (typeof pageFunction !== 'function') throw new TypeError(message);
    const source = Function.prototype.toString.call(pageFunction);
    if (/^class(?=\s|\{|\/)/.test(source)) throw new TypeError(message);
    try {
        new Script(`(${source})`);
    } catch {
        throw new TypeError(message);
    }
    return source;
}

function wrapMultiArgEvaluate(originalEvaluate, decorateResult = null) {
    return async (pageFunction, ...args) => {
        let result;
        if (args.length <= 1) {
            result = await originalEvaluate(pageFunction, args[0]);
        } else {
            const fnSource = evaluationFunctionSource(pageFunction);
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
const sessionLifecycles = new WeakMap();
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
    return !binding?.closed && !binding?.closing && binding?.isBrowserConnected?.() !== false;
}

export function observeContextClosure(context, browser) {
    const binding = bindContext(context);
    return () => binding.closed || context.isClosed?.() === true || browser.isConnected?.() === false;
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
            if (args.length <= 1) {
                return originalEvaluate(pageFunction, args[0]);
            }
            const fnSource = evaluationFunctionSource(pageFunction);
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
            if (args.length <= 1) {
                res = await originalEvaluateHandle(pageFunction, args[0]);
            } else {
                const fnSource = evaluationFunctionSource(pageFunction);
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
                    if (methodName === 'press') {
                        const key = recordedControlKey(args[0]);
                        if (key !== undefined) meta.key = key;
                    } else if (
                        (methodName === 'fill' || methodName === 'type') &&
                        typeof args[0] === 'string'
                    ) {
                        meta.valueLength = args[0].length;
                    }
                    recorder?.recordTriggerAction?.(`elementHandle.${methodName}`, target, meta, handleOwners.get(handle));
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
        frame.$ = async (selector, options) =>
            attachElementHandleCompatibility(await originalQuery(selector, options), frame, selector);
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
        frame.goto = async (url, options) => {
            const normalized = normalizeNavigationOptions(options);
            try {
                const recorder = frame._camoufoxPageCompatAttached
                    ? resolveContextRecorder(resolvePageContext(frame))
                    : null;
                if (recorder) {
                    const targetUrl = typeof url === 'string' ? url : String(url ?? '');
                    recorder.recordTriggerAction?.('page.goto', targetUrl, {
                        url: targetUrl,
                        pageUrl: typeof frame.url === 'function' ? frame.url() : null
                    }, frame);
                }
            } catch {
                // Never allow instrumentation to interfere with navigation
            }
            return originalGoto(url, normalized);
        };
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
        resolveRecorder()?.recordTriggerAction?.(actionType, target, meta, page) || null;

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
                    if (methodName === 'press') {
                        const key = recordedControlKey(rest[0]);
                        if (key !== undefined) meta.key = key;
                    } else if (
                        (methodName === 'fill' || methodName === 'type') &&
                        typeof rest[0] === 'string'
                    ) {
                        meta.valueLength = rest[0].length;
                    }
                    recorder?.recordTriggerAction?.(`page.${methodName}`, targetSelector, meta, page);
                } catch {
                    // Never allow instrumentation to interfere with page execution
                }
                return originalMethod(selector, ...rest);
            };
        }
    }

    // Puppeteer page.evaluateOnNewDocument(fn, ...args) -> Playwright page.addInitScript
    if (typeof page.evaluateOnNewDocument !== 'function') {
        page.evaluateOnNewDocument = async (pageFunction, ...args) => {
            if (typeof page.addInitScript !== 'function') {
                throw new Error('The browser backend does not support page-scoped initializers');
            }

            if (typeof pageFunction === 'function' && args.length <= 1) {
                evaluationFunctionSource(pageFunction);
            }
            return wrapMultiArgEvaluate(page.addInitScript.bind(page))(pageFunction, ...args);
        };
    }

    // Puppeteer page.setViewport({ width, height }) & page.viewport()
    if (typeof page.setViewport !== 'function') {
        page.setViewport = async (viewport) => {
            const { width, height } = viewport ?? {};
            if (!Number.isInteger(width) || width <= 0 || !Number.isInteger(height) || height <= 0) {
                throw new TypeError('Camoufox requires positive integer viewport width and height');
            }
            if (typeof page.setViewportSize !== 'function') {
                throw new Error('The browser backend does not support viewport resizing');
            }
            const requestedViewport = { ...viewport, width, height };
            await page.setViewportSize({ width, height });
            page._camoufoxViewport = requestedViewport;
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
                logger.warn('Blocked non-Firefox page.setUserAgent() on Camoufox');
                if (options?.strict === true) {
                    throw new Error('Refusing to set non-Firefox User-Agent on Camoufox');
                }
                return {
                    applied: false,
                    blocked: true,
                    reason: 'non_firefox_ua_blocked'
                };
            }

            logger.debug('Ignored page.setUserAgent() because Camoufox manages the User-Agent');
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
            const scope = urls.length ? urls.map(parseCookieUrl) : [currentCookieUrl(page)];
            const cookieUrls = scope.filter(Boolean).map((url) => url.href);
            return cookieUrls.length ? targetContext.cookies(cookieUrls) : [];
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
                    if (copy.path != null && (typeof copy.path !== 'string' || !copy.path.startsWith('/'))) {
                        throw new TypeError('Cookie path must begin with /');
                    }
                    if (copy.domain) {
                        delete copy.url;
                        if (!copy.path) {
                            copy.path = '/';
                        }
                    } else if (copy.path != null) {
                        const scopedUrl = parseCookieUrl(copy.url || currentUrl);
                        if (!scopedUrl) throw new TypeError('Cookie path requires an HTTP(S) URL or a domain');
                        copy.domain = scopedUrl.hostname;
                        if (scopedUrl.protocol === 'https:') copy.secure = true;
                        delete copy.url;
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

    // Expire only the matching cookie identities through Playwright's cookie API.
    if (typeof page.deleteCookie !== 'function') {
        page.deleteCookie = async (...cookiesToDelete) => {
            const targetContext = resolveContext();
            const targets = cookiesToDelete
                .flat()
                .filter((cookie) => typeof cookie?.name === 'string' && cookie.name);
            if (targets.length === 0) return;

            const pageUrl = currentCookieUrl(page);
            const scopes = targets.map(({ name, domain, url, path, partitionKey, _crHasCrossSiteAncestor }) => {
                if (domain != null && typeof domain !== 'string') return null;
                const scopedDomain = typeof domain === 'string' && domain ? domain.toLowerCase() : null;
                return {
                    name,
                    domain: scopedDomain,
                    url: scopedDomain ? null : url == null ? pageUrl : parseCookieUrl(url),
                    path,
                    partitionKey: partitionKey ?? null,
                    _crHasCrossSiteAncestor
                };
            }).filter((scope) => scope && (scope.domain || scope.url));
            if (scopes.length === 0) return;

            if (typeof targetContext?.cookies !== 'function' || typeof targetContext.addCookies !== 'function') {
                throw new Error('The browser backend does not support scoped cookie deletion');
            }
            const existing = await targetContext.cookies();
            const expired = existing.filter((cookie) => scopes.some((scope) => cookieMatchesScope(cookie, scope)))
                .map(({ name, domain, path, secure, httpOnly, sameSite, partitionKey, _crHasCrossSiteAncestor }) => ({
                    name,
                    domain,
                    path,
                    secure,
                    httpOnly,
                    sameSite,
                    ...(partitionKey != null ? { partitionKey } : {}),
                    ...(_crHasCrossSiteAncestor !== undefined ? { _crHasCrossSiteAncestor } : {}),
                    value: '',
                    expires: 1
                }));
            if (expired.length > 0) {
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
                if (!binding.closing) {
                    const close = async () => {
                        await closeContext(...args);
                        binding.closed = true;
                    };
                    binding.closing = Promise.resolve().then(() => (
                        profile.closeContext ? profile.closeContext(close) : close()
                    )).finally(() => {
                        binding.closing = null;
                    });
                }
                return binding.closing;
            };
        }
        context.on?.('page', decoratePage);
    }
    return view;
}

/**
 * Keep the native browser with the client lifecycle and return the profile-scoped view.
 */
export function attachSessionCompatibility(session, lifecycle) {
    const { browser, context, page, metadata, trafficRecorder } = session;
    const view = {
        ...session,
        browser: attachBrowserCompatibility(browser, {
            context,
            metadata,
            trafficRecorder: trafficRecorder ?? null,
            saveStorageState: lifecycle.saveStorageState,
            closeContext: lifecycle.closeContext
        }),
        page: attachPageCompatibility(page, context)
    };
    sessionLifecycles.set(view, lifecycle);
    return view;
}

export class CamoufoxProfile {
    #lifecycle = null;
    #profilesDir;
    #starting = null;
    #startCancellation = null;
    #stopping = null;

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

    /** Legacy accessor for callers checking for a scaler. */
    getGpuPerformanceScaler() {
        return null;
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
     * Return a summary of the preset, security guards, consistency ledger, and coherence report.
     */
    getTelemetrySummary() {
        return {
            profileId: this.profileId,
            presetId: this.metadata?.presetId || null,
            deviceModel: this.metadata?.deviceModel || this.metadata?.hardwareProfile?.deviceModel || null,
            os: this.metadata?.os || null,
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
        return this.#lifecycle?.getTrafficAttribution() ?? null;
    }

    /**
     * Audit the active page. The overall verdict and score include its wire checks when recording is enabled.
     */
    async auditCoherence(expectedOs = null, options = {}) {
        const page = await this.getPage();
        this.coherenceReport = await this.#auditSession({ ...this, page }, expectedOs, options);
        return this.coherenceReport;
    }

    async #auditSession(session, expectedOs = null, options = {}, signal) {
        const { page, browser, metadata, trafficRecorder, trafficPaths } = session;
        const targetOs = expectedOs || metadata?.os || this.options?.os || 'windows';
        const includeTelemetry = options?.includeTelemetry === true;
        const { telemetry, ...report } = await waitForCamoufoxStartup(auditProfileCoherence(page, targetOs, {
            profileId: this.profileId,
            hardwareProfile: metadata?.hardwareProfile || undefined,
            ...options,
            includeTelemetry: includeTelemetry || Boolean(trafficRecorder)
        }), signal);
        signal?.throwIfAborted();
        if (browser?.isConnected() === false) throw new Error('Camoufox profile closed during its audit');

        if (trafficRecorder && telemetry) {
            const traceId = trafficRecorder.traceId;
            let events = [];
            let captureIssue = null;
            if (typeof traceId === 'string' && traceId.trim()) {
                try {
                    events = trafficPaths?.trafficDir
                        ? readCoherenceCaptureEvents(trafficPaths.trafficDir, { trustedLocal: true })
                        : trafficRecorder;
                } catch (error) {
                    captureIssue = error.code === 'ERR_COHERENCE_CAPTURE_INVALID' ? 'invalid-capture-record' : 'unreadable-capture';
                }
            } else {
                captureIssue = 'unknown-active-trace';
            }
            const wireToDomCoherence = evaluateWireToDomCoherence(telemetry, events, targetOs, { traceId });
            if (captureIssue) wireToDomCoherence.captureIssue = captureIssue;
            const { passed, status, score } = summarizeCoherenceChecks([...report.checks, ...wireToDomCoherence.checks]);
            Object.assign(report, { wireToDomCoherence, passed, status, score });
        }
        return { ...report, telemetry: includeTelemetry ? telemetry : null };
    }

    /**
     * Start profile and initialize Camoufox Browser, BrowserContext, and Page
     */
    async start(expectedStorageGeneration, createdProfile) {
        const signal = this.options?.signal;
        signal?.throwIfAborted();
        while (this.#stopping) await waitForCamoufoxStartup(this.#stopping, signal);
        signal?.throwIfAborted();
        if (this.#starting) return this.#starting;

        const controller = new AbortController();
        const abort = () => controller.abort(signal.reason);
        signal?.addEventListener('abort', abort, { once: true });
        this.#startCancellation = controller;
        this.#starting = this.#startSession(expectedStorageGeneration, createdProfile, controller.signal).finally(() => {
            signal?.removeEventListener('abort', abort);
            this.#startCancellation = null;
            this.#starting = null;
        });
        return this.#starting;
    }

    async #startSession(expectedStorageGeneration, createdProfile, signal) {
        const shouldAudit = this.options?.verifyCoherence || process.env.CAMOUFOX_AUDIT_ON_START === 'true';
        let report = null;
        const audit = async (session) => {
            signal.throwIfAborted();
            report = await this.#auditSession(session, session.metadata?.os, {}, signal);
        };
        const attempt = { createdProfile, beforeReady: shouldAudit ? audit : undefined };
        try {
            logger.info('Starting Camoufox profile', { profileId: this.profileId });

            const session = await camoufoxClient.startProfile(
                this.profileId,
                { ...this.options, profilesDir: this.#profilesDir ?? this.options?.profilesDir, signal },
                expectedStorageGeneration,
                attempt
            );
            const lifecycle = sessionLifecycles.get(session);
            if (shouldAudit && !report) await audit(session);
            signal.throwIfAborted();
            if (!lifecycle.canReuse()) throw new Error('Camoufox profile closed during startup');
            if (report || this.#lifecycle !== lifecycle) this.coherenceReport = report;
            this.#lifecycle = lifecycle;
            this.#profilesDir = lifecycle.profilesDir;
            this.context = session.context;
            this.lastTrafficAttribution = null;
            this.storageStatePath = session.storageStatePath;
            this.metadata = session.metadata;
            this.trafficRecorder = session.trafficRecorder || null;
            this.trafficPaths = session.trafficPaths || null;
            this.fingerprintLedger = session.fingerprintLedger || null;
            this.securityGuards = session.securityGuards || null;

            this.browser = session.browser;
            this.page = attachPageCompatibility(session.page, this.context, this);

            logger.info('Camoufox profile started successfully', {
                profileId: this.profileId,
                os: this.metadata?.os,
                storageStatePath: this.storageStatePath
            });

            return this;
        } catch (error) {
            if (attempt.lifecycle) {
                this.#lifecycle = attempt.lifecycle;
                this.#profilesDir = attempt.lifecycle.profilesDir;
                if (attempt.lifecycle.canReuse()) await this.#stopSession();
            }
            logger.error('Failed to start Camoufox profile', {
                profileId: this.profileId,
                error: error?.message
            });
            throw error;
        }
    }

    /**
     * Get browser instance (starts profile if needed)
     */
    async getBrowser() {
        if (this.#starting || this.#stopping || !this.#lifecycle?.canReuse()) {
            await this.start();
        }
        return this.browser;
    }

    /**
     * Get isolated Playwright BrowserContext instance (starts profile if needed)
     */
    async getContext() {
        await this.getBrowser();
        return this.context;
    }

    /**
     * Get primary Page instance (creates one in the profile context if needed)
     */
    async getPage() {
        const context = await this.getContext();
        const lifecycle = this.#lifecycle;
        if (!context || !lifecycle?.canReuse()) throw new Error('Camoufox profile closed while opening a page');
        const page = await lifecycle.getPage();
        if (this.context !== context || this.#lifecycle !== lifecycle || !lifecycle.canReuse()) {
            throw new Error('Camoufox profile closed while opening a page');
        }
        this.page = attachPageCompatibility(page, context, this);
        return this.page;
    }

    /**
     * Persist cookies (`datr`, `ig_did`, `ttwid`, etc.) and `localStorage`
     * to `profiles/<profileId>/storage-state.json`
     */
    async saveStorageState() {
        if (!this.context || !this.#lifecycle) return null;
        const savedPath = await this.#lifecycle.saveStorageState();
        if (savedPath) {
            this.storageStatePath = savedPath;
        }
        return savedPath;
    }

    /**
     * Stop profile, saving storage state and finalizing capture after native closure.
     */
    stop() {
        if (this.#stopping) return this.#stopping;
        const starting = this.#starting;
        this.#stopping = Promise.resolve().then(async () => {
            await starting?.catch(() => {});
            return this.#stopSession();
        }).finally(() => {
            this.#stopping = null;
        });
        this.#startCancellation?.abort(new Error('Camoufox profile startup cancelled by stop'));
        return this.#stopping;
    }

    async #stopSession() {
        const lifecycle = this.#lifecycle;
        if (!lifecycle) return true;

        try {
            const { stopped, closed, trafficAttribution } = await lifecycle.stop();
            if (closed && this.#lifecycle === lifecycle) {
                if (typeof this.securityGuards?.getStats === 'function') {
                    try {
                        this.lastSecurityGuardStats = this.securityGuards.getStats();
                    } catch {}
                }
                this.lastTrafficAttribution = trafficAttribution;
                this.browser = null;
                this.context = null;
                this.page = null;
                this.securityGuards = null;
            }
            return stopped;
        } catch (error) {
            logger.warn('Error stopping Camoufox profile', {
                profileId: this.profileId,
                error: error.message
            });
            return false;
        }
    }

    /**
     * Delete profile and its persistent storage directory
     */
    async delete() {
        try {
            const lifecycle = this.#lifecycle;
            if (!lifecycle) throw new Error('Camoufox manager has no acquired profile session');
            if (!(await this.stop())) throw new Error('Could not stop Camoufox profile before deletion');
            await lifecycle.delete();
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
    const { signal } = options;
    signal?.throwIfAborted();
    let profileData;
    const opening = open();
    try {
        return await waitForCamoufoxStartup(opening, signal);
    } catch (error) {
        if (signal?.aborted && error === signal.reason && profileData) {
            // If completion and cancellation coincide, the owned operation may still have returned a session.
            opening.then(() => rollback()).catch(() => {});
            throw startupError(error, 'stop-unconfirmed');
        }
        throw error;
    }

    async function rollback() {
        const profileCleanup = await rollbackCreatedProfile(profileData);
        logger.info('Finished Camoufox startup rollback', { profileId: profileData.id, profileCleanup });
        return profileCleanup;
    }

    function startupError(cause, profileCleanup) {
        const error = new Error('Camoufox profile initialization failed', { cause });
        if (cause?.name === 'AbortError' || (signal?.aborted && cause === signal.reason)) error.name = 'AbortError';
        return Object.assign(error, { code: cause?.code, profileId: profileData.id, profileCleanup });
    }

    async function open() {
        try {
            validateCamoufoxNetworkPolicy(options, proxy || options.proxy || null);
            const isAvailable = await camoufoxClient.checkCamoufoxConnection();
            signal?.throwIfAborted();
            if (!isAvailable) {
                throw new Error(
                    'Camoufox module is not available. Ensure the trusted camoufox package is installed.'
                );
            }

            logger.info('Creating Camoufox profile...', { name: profileName });
            profileData = await camoufoxClient.createProfile(profileName, proxy, options);
            const profileManager = new CamoufoxProfile(profileData.id, {
                ...options,
                profilesDir: path.dirname(profileData.profileDir),
                proxy: profileData.proxy,
                os: profileData.os,
                geoip: profileData.geoip,
                humanize: profileData.humanize
            });

            await profileManager.start(profileData._storageGeneration, profileData);
            signal?.throwIfAborted();

            logger.info('Camoufox profile created and started', {
                profileId: profileData.id,
                name: profileData.title || profileName,
                os: profileData.os,
                storageStatePath: profileManager.storageStatePath
            });

            return profileManager;
        } catch (error) {
            logger.error('Failed to create and start Camoufox profile', { error: error?.message });
            if (!profileData) throw error;
            throw startupError(error, await rollback());
        }
    }
}

export default CamoufoxProfile;
