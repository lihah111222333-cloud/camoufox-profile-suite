/**
 * In-Browser Fingerprint & Anti-Bot Environment Coherence Auditor for Camoufox
 *
 * Implements defensive runtime probes and cross-field hardware/OS invariant checks
 * modeled on Camoufox's `coherence.py` / `coherence.ts` and the environmental signals
 * inspected by Google BotGuard, Arkose BDA, Meta Device Graph, and ByteDance JSVMP.
 */

import logger from '../utils/logger.js';

/**
 * Hardware & OS coherence constants synchronized with Camoufox `launcher-constants.json`
 * and `coherence.ts`.
 */
export const CAMOUFOX_COHERENCE_CONSTANTS = Object.freeze({
    appleSiliconCores: new Set([8, 10, 11, 12, 14, 16, 20, 24, 28, 32]),
    intelMacIgpCores: new Set([2, 4, 6, 8, 12, 16]),
    intelMacDgpuCores: new Set([2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24, 28, 32, 36, 48, 56]),
    intelOnlyCoreCounts: new Set([10, 14, 18, 22, 28]),
    intelIgpus: Object.freeze([
        'Intel(R) HD Graphics, or similar',
        'Intel(R) HD Graphics 400, or similar',
        'Intel(R) HD Graphics Direct3D11',
        'Intel(R) HD Graphics 400 Direct3D11'
    ]),
    amdApuGpus: Object.freeze([
        'Radeon HD 3200 Graphics',
        'AMD Radeon(TM) Graphics',
        'Radeon(TM) Graphics',
        'Radeon Vega',
        'Radeon(TM) Vega',
        'Radeon 680M',
        'Radeon 780M',
        'Radeon 890M',
        'AMD APU'
    ]),
    appleSiliconPanels: new Set([
        '1024x665', '1280x832', '1470x956', '1710x1112',
        '1280x828', '1440x932', '1710x1107',
        '1147x745', '1352x878', '1512x982', '1800x1169',
        '1312x848', '1496x967', '1728x1117', '2056x1329',
        '2240x1260'
    ]),
    plausibleDpr: Object.freeze({
        win: [1, 1.25, 1.5, 1.75, 2, 2.5, 3],
        mac: [1, 2],
        lin: [1, 1.25, 1.5, 1.75, 2]
    }),
    plausibleColorDepth: new Set([24, 30]),
    maxPlausibleTouchPoints: 10,
    browserChromeHeight: 86,
    notAMacGpu: ['ANGLE', 'llvmpipe']
});

/**
 * Normalize an OS identifier ('win', 'windows', 'win32', 'mac', 'macos', 'darwin', 'lin', 'linux')
 * into Camoufox's canonical short OS key: 'win' | 'mac' | 'lin'.
 *
 * @param {string} [osInput]
 * @returns {'win' | 'mac' | 'lin' | null}
 */
export function normalizeTargetOs(osInput) {
    if (!osInput || typeof osInput !== 'string') {
        return null;
    }
    const cleaned = osInput.trim().toLowerCase();
    if (cleaned.startsWith('win')) return 'win';
    if (cleaned.startsWith('mac') || cleaned === 'darwin' || cleaned === 'osx') return 'mac';
    if (cleaned.startsWith('lin') || cleaned === 'ubuntu' || cleaned === 'debian') return 'lin';
    return null;
}

/**
 * Check whether a WebGL renderer string fits the target OS according to Camoufox's `gpuFitsOs`.
 *
 * @param {string | null | undefined} rendererString
 * @param {'win' | 'mac' | 'lin'} targetOs
 * @returns {boolean}
 */
export function gpuFitsOs(rendererString, targetOs) {
    const r = typeof rendererString === 'string' ? rendererString.trim() : '';
    if (!r) return false;
    if (targetOs === 'mac') {
        return !CAMOUFOX_COHERENCE_CONSTANTS.notAMacGpu.some((bad) => r.includes(bad));
    }
    if (targetOs === 'win') {
        return r.startsWith('ANGLE');
    }
    if (targetOs === 'lin') {
        return !r.includes('ANGLE') && !r.includes('Apple M');
    }
    return true;
}

/**
 * Collect comprehensive in-browser fingerprint telemetry from a Playwright/Puppeteer page.
 *
 * @param {import('playwright').Page | import('puppeteer-core').Page} page
 * @returns {Promise<object>} Collected telemetry payload
 */
export async function collectBrowserFingerprint(page) {
    if (!page || typeof page.evaluate !== 'function') {
        throw new TypeError('collectBrowserFingerprint requires a valid browser Page instance with .evaluate()');
    }

    return await page.evaluate(async () => {
        const fnToString = Function.prototype.toString;
        const nativeCodeRegex = /^function\s+(?:get\s+|set\s+)?[\w$]*\(\)\s*\{\s*\[native code\]\s*\}$/s;

        const inspectGetter = (proto, prop) => {
            try {
                const desc = Object.getOwnPropertyDescriptor(proto, prop);
                if (!desc || typeof desc.get !== 'function') {
                    return { exists: Boolean(desc), isGetter: false, source: null, isNative: false };
                }
                const source = fnToString.call(desc.get);
                const hasOwnName = desc.get.name === `get ${prop}` || desc.get.name === prop;
                const hasPrototype = 'prototype' in desc.get;
                return {
                    exists: true,
                    isGetter: true,
                    source,
                    isNative: nativeCodeRegex.test(source) && hasOwnName && !hasPrototype
                };
            } catch (err) {
                return { exists: false, isGetter: false, source: String(err), isNative: false };
            }
        };

        const inspectMethod = (proto, prop) => {
            try {
                const desc = Object.getOwnPropertyDescriptor(proto, prop);
                if (!desc || typeof desc.value !== 'function') {
                    return { exists: Boolean(desc), isMethod: false, source: null, isNative: false };
                }
                const source = fnToString.call(desc.value);
                return {
                    exists: true,
                    isMethod: true,
                    source,
                    isNative: nativeCodeRegex.test(source) && desc.value.name === prop
                };
            } catch (err) {
                return { exists: false, isMethod: false, source: String(err), isNative: false };
            }
        };

        // 1. Navigator & Prototype Integrity
        const navProto = Object.getPrototypeOf(navigator);
        const ownNavigatorOverrides = [
            'userAgent',
            'platform',
            'oscpu',
            'hardwareConcurrency',
            'languages',
            'language',
            'webdriver',
            'maxTouchPoints'
        ].filter((prop) => Object.prototype.hasOwnProperty.call(navigator, prop));

        const toStringSelfSource = fnToString.call(fnToString);
        const toStringIntact = nativeCodeRegex.test(toStringSelfSource);

        const prototypeIntegrity = {
            toStringIntact,
            ownNavigatorOverrides,
            userAgentGetter: inspectGetter(navProto, 'userAgent'),
            webdriverGetter: inspectGetter(navProto, 'webdriver'),
            platformGetter: inspectGetter(navProto, 'platform'),
            hardwareConcurrencyGetter: inspectGetter(navProto, 'hardwareConcurrency'),
            webglGetParameter:
                typeof WebGLRenderingContext !== 'undefined'
                    ? inspectMethod(WebGLRenderingContext.prototype, 'getParameter')
                    : { exists: false, isMethod: false, source: null, isNative: false },
            webgl2GetParameter:
                typeof WebGL2RenderingContext !== 'undefined'
                    ? inspectMethod(WebGL2RenderingContext.prototype, 'getParameter')
                    : { exists: false, isMethod: false, source: null, isNative: false }
        };

        const navigatorInfo = {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            oscpu: 'oscpu' in navigator ? navigator.oscpu : null,
            hardwareConcurrency: navigator.hardwareConcurrency,
            languages: Array.isArray(navigator.languages) ? [...navigator.languages] : [],
            language: navigator.language,
            webdriver: navigator.webdriver,
            maxTouchPoints: typeof navigator.maxTouchPoints === 'number' ? navigator.maxTouchPoints : 0,
            hasUserAgentData: 'userAgentData' in navigator && Boolean(navigator.userAgentData),
            hasWindowChrome: typeof window.chrome !== 'undefined' && Boolean(window.chrome),
            vendor: navigator.vendor || '',
            buildID: 'buildID' in navigator ? navigator.buildID : null
        };

        // 2. Dedicated Worker Parity via inline Blob Worker
        const collectWorkerTelemetry = () =>
            new Promise((resolve) => {
                if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined') {
                    resolve({ supported: false, error: 'Worker or Blob API unavailable' });
                    return;
                }
                let workerUrl = null;
                let worker = null;
                const timer = setTimeout(() => {
                    try {
                        if (worker) worker.terminate();
                        if (workerUrl) URL.revokeObjectURL(workerUrl);
                    } catch {}
                    resolve({ supported: true, timedOut: true, error: 'Worker probe timed out after 2500ms' });
                }, 2500);

                try {
                    const workerScript = `
                        self.onmessage = function () {
                            try {
                                const nav = self.navigator || {};
                                self.postMessage({
                                    ok: true,
                                    userAgent: nav.userAgent,
                                    platform: nav.platform,
                                    hardwareConcurrency: nav.hardwareConcurrency,
                                    languages: Array.isArray(nav.languages) ? Array.from(nav.languages) : [],
                                    language: nav.language,
                                    webdriver: nav.webdriver,
                                    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                                    math: {
                                        sin1e6: Math.sin(1e6),
                                        cos1e6: Math.cos(1e6),
                                        tan1e6: Math.tan(1e6),
                                        powPi: Math.pow(3.141592653589793, -7.3)
                                    }
                                });
                            } catch (e) {
                                self.postMessage({ ok: false, error: String(e) });
                            }
                        };
                    `;
                    const blob = new Blob([workerScript], { type: 'application/javascript' });
                    workerUrl = URL.createObjectURL(blob);
                    worker = new Worker(workerUrl);
                    worker.onmessage = (event) => {
                        clearTimeout(timer);
                        try {
                            worker.terminate();
                            URL.revokeObjectURL(workerUrl);
                        } catch {}
                        resolve({ supported: true, ...event.data });
                    };
                    worker.onerror = (err) => {
                        clearTimeout(timer);
                        try {
                            worker.terminate();
                            URL.revokeObjectURL(workerUrl);
                        } catch {}
                        resolve({
                            supported: true,
                            ok: false,
                            error: err?.message || 'Worker execution blocked (possibly by CSP)'
                        });
                    };
                    worker.postMessage('probe');
                } catch (err) {
                    clearTimeout(timer);
                    try {
                        if (worker) worker.terminate();
                        if (workerUrl) URL.revokeObjectURL(workerUrl);
                    } catch {}
                    resolve({ supported: true, ok: false, error: String(err) });
                }
            });

        const workerInfo = await collectWorkerTelemetry();

        // 3. WebGL & Deterministic Canvas 2D
        const collectWebGlAndCanvas = () => {
            const result = {
                webgl: {
                    available: false,
                    vendor: null,
                    renderer: null,
                    version: null,
                    shadingLanguageVersion: null,
                    unmaskedVendor: null,
                    unmaskedRenderer: null,
                    extensionsCount: 0
                },
                canvas2d: {
                    available: false,
                    fnv1aHash: null,
                    pixelSampleSum: 0,
                    dataUrlLength: 0
                }
            };

            try {
                const glCanvas = document.createElement('canvas');
                glCanvas.width = 64;
                glCanvas.height = 64;
                const gl =
                    glCanvas.getContext('webgl') ||
                    glCanvas.getContext('experimental-webgl') ||
                    glCanvas.getContext('webgl2');

                if (gl) {
                    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
                    const exts = gl.getSupportedExtensions() || [];
                    result.webgl = {
                        available: true,
                        vendor: gl.getParameter(gl.VENDOR),
                        renderer: gl.getParameter(gl.RENDERER),
                        version: gl.getParameter(gl.VERSION),
                        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                        unmaskedVendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
                        unmaskedRenderer: dbg
                            ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
                            : gl.getParameter(gl.RENDERER),
                        extensionsCount: exts.length
                    };
                }
            } catch (err) {
                result.webgl.error = String(err);
            }

            try {
                const c2d = document.createElement('canvas');
                c2d.width = 240;
                c2d.height = 60;
                const ctx = c2d.getContext('2d');
                if (ctx) {
                    ctx.textBaseline = 'alphabetic';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(100, 2, 62, 20);

                    const grad = ctx.createLinearGradient(0, 0, 240, 0);
                    grad.addColorStop(0, '#1a73e8');
                    grad.addColorStop(0.5, '#34a853');
                    grad.addColorStop(1, '#ea4335');
                    ctx.fillStyle = grad;
                    ctx.font = '15px sans-serif';
                    ctx.fillText('Camoufox Coherence 🦊 123.45', 4, 18);

                    ctx.strokeStyle = 'rgba(120, 186, 176, 0.75)';
                    ctx.beginPath();
                    ctx.arc(60, 38, 16, 0, Math.PI * 1.65, false);
                    ctx.stroke();

                    const imgData = ctx.getImageData(0, 0, c2d.width, c2d.height).data;
                    let hashHigh = 0x811c9dc5;
                    let hashLow = 0xcbf29ce4;
                    let nonZeroSum = 0;
                    for (let i = 0; i < imgData.length; i++) {
                        const byte = imgData[i];
                        nonZeroSum += byte;
                        hashHigh ^= byte;
                        hashHigh = Math.imul(hashHigh, 0x01000193) >>> 0;
                        if ((i & 1) === 1) {
                            hashLow ^= byte;
                            hashLow = Math.imul(hashLow, 0x01000193) >>> 0;
                        }
                    }
                    const dataUrl = c2d.toDataURL('image/png');
                    result.canvas2d = {
                        available: true,
                        fnv1aHash:
                            hashHigh.toString(16).padStart(8, '0') + hashLow.toString(16).padStart(8, '0'),
                        pixelSampleSum: nonZeroSum,
                        dataUrlLength: dataUrl.length
                    };
                }
            } catch (err) {
                result.canvas2d.error = String(err);
            }

            return result;
        };

        const graphicsInfo = collectWebGlAndCanvas();

        // 4. AudioContext & CPU Math Precision
        const float64ToHex = (val) => {
            const buf = new ArrayBuffer(8);
            const view = new DataView(buf);
            view.setFloat64(0, val, false);
            const hi = view.getUint32(0, false).toString(16).padStart(8, '0');
            const lo = view.getUint32(4, false).toString(16).padStart(8, '0');
            return `0x${hi}${lo}`;
        };

        const sin1e6 = Math.sin(1e6);
        const cos1e6 = Math.cos(1e6);
        const tan1e6 = Math.tan(1e6);
        const powPi = Math.pow(3.141592653589793, -7.3);

        const mathPrecision = {
            sin1e6,
            cos1e6,
            tan1e6,
            powPi,
            hex: {
                sin1e6: float64ToHex(sin1e6),
                cos1e6: float64ToHex(cos1e6),
                tan1e6: float64ToHex(tan1e6),
                powPi: float64ToHex(powPi)
            }
        };

        const collectAudioInfo = () => {
            const audio = {
                available: false,
                sampleRate: null,
                maxChannelCount: null,
                channelCount: null,
                state: null
            };
            try {
                const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
                const AudioCtx = window.AudioContext || window.webkitAudioContext;
                if (AudioCtx) {
                    const ctx = new AudioCtx();
                    audio.available = true;
                    audio.sampleRate = ctx.sampleRate;
                    audio.maxChannelCount = ctx.destination?.maxChannelCount ?? null;
                    audio.channelCount = ctx.destination?.channelCount ?? null;
                    audio.state = ctx.state;
                    if (typeof ctx.close === 'function') {
                        ctx.close().catch(() => {});
                    }
                } else if (OfflineCtx) {
                    const offCtx = new OfflineCtx(1, 44100, 44100);
                    audio.available = true;
                    audio.sampleRate = offCtx.sampleRate;
                    audio.maxChannelCount = offCtx.destination?.maxChannelCount ?? 1;
                    audio.channelCount = offCtx.destination?.channelCount ?? 1;
                    audio.state = offCtx.state;
                }
            } catch (err) {
                audio.error = String(err);
            }
            return audio;
        };

        const audioInfo = collectAudioInfo();

        // 5. Screen & CSS Media Query Parity
        const scr = window.screen;
        const dpr = window.devicePixelRatio;
        const mm = (query) => {
            try {
                return window.matchMedia(query).matches;
            } catch {
                return false;
            }
        };

        const screenInfo = {
            width: scr.width,
            height: scr.height,
            availWidth: scr.availWidth,
            availHeight: scr.availHeight,
            colorDepth: scr.colorDepth,
            pixelDepth: scr.pixelDepth,
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight,
            outerWidth: window.outerWidth,
            outerHeight: window.outerHeight,
            devicePixelRatio: dpr,
            mediaQueries: {
                deviceWidthMatches: mm(`(device-width: ${scr.width}px)`),
                deviceHeightMatches: mm(`(device-height: ${scr.height}px)`),
                innerWidthMatches: mm(`(width: ${window.innerWidth}px)`),
                innerHeightMatches: mm(`(height: ${window.innerHeight}px)`),
                dprResolutionMatches:
                    mm(`(resolution: ${dpr}dppx)`) ||
                    mm(`(min-resolution: ${Math.max(0.5, dpr - 0.01)}dppx) and (max-resolution: ${dpr + 0.01}dppx)`),
                orientationLandscape: mm('(orientation: landscape)'),
                orientationPortrait: mm('(orientation: portrait)'),
                colorBitsAtLeast8: mm('(min-color: 8)')
            }
        };

        // 6. Timezone & Intl Coherence
        let intlOptions = {};
        try {
            intlOptions = Intl.DateTimeFormat().resolvedOptions();
        } catch {}

        const intlInfo = {
            timeZone: intlOptions.timeZone || null,
            locale: intlOptions.locale || null,
            calendar: intlOptions.calendar || null,
            numberingSystem: intlOptions.numberingSystem || null,
            timezoneOffsetMinutes: new Date().getTimezoneOffset()
        };

        return {
            navigator: navigatorInfo,
            prototypeIntegrity,
            worker: workerInfo,
            webgl: graphicsInfo.webgl,
            canvas2d: graphicsInfo.canvas2d,
            audio: audioInfo,
            mathPrecision,
            screen: screenInfo,
            intl: intlInfo
        };
    });
}

/**
 * Evaluate whether collected browser telemetry satisfies strict coherence requirements
 * across Google BotGuard, Arkose BDA, Meta Device Graph, ByteDance JSVMP, and Camoufox's
 * hardware/OS invariants.
 *
 * @param {object} telemetry Output of `collectBrowserFingerprint(page)`
 * @param {string} [expectedOs] Expected target OS ('win'/'windows', 'mac'/'macos', 'lin'/'linux')
 * @returns {{ passed: boolean, score: number, checks: Array<{ name: string, passed: boolean, details: string }> }}
 */
export function evaluatePlatformCoherence(telemetry, expectedOs) {
    if (!telemetry || typeof telemetry !== 'object') {
        throw new TypeError('evaluatePlatformCoherence requires a telemetry object');
    }

    const checks = [];
    const nav = telemetry.navigator || {};
    const proto = telemetry.prototypeIntegrity || {};
    const worker = telemetry.worker || {};
    const webgl = telemetry.webgl || {};
    const canvas2d = telemetry.canvas2d || {};
    const audio = telemetry.audio || {};
    const math = telemetry.mathPrecision || {};
    const scr = telemetry.screen || {};
    const mq = scr.mediaQueries || {};
    const intl = telemetry.intl || {};

    // Infer target OS if not explicitly provided
    let targetOs = normalizeTargetOs(expectedOs);
    if (!targetOs) {
        const p = String(nav.platform || '').toLowerCase();
        if (p.includes('win')) targetOs = 'win';
        else if (p.includes('mac')) targetOs = 'mac';
        else if (p.includes('linux')) targetOs = 'lin';
    }

    // Check 1: Webdriver Stealth & Native Prototype Integrity
    {
        const webdriverClean = nav.webdriver === false;
        const noOwnOverrides =
            Array.isArray(proto.ownNavigatorOverrides) && proto.ownNavigatorOverrides.length === 0;
        const platformGetterOk = proto.platformGetter ? Boolean(proto.platformGetter.isNative) : true;
        const hcGetterOk = proto.hardwareConcurrencyGetter
            ? Boolean(proto.hardwareConcurrencyGetter.isNative)
            : true;
        const webgl2GetterOk =
            proto.webgl2GetParameter && proto.webgl2GetParameter.exists !== false
                ? Boolean(proto.webgl2GetParameter.isNative)
                : true;
        const gettersNative =
            Boolean(proto.toStringIntact) &&
            Boolean(proto.userAgentGetter?.isNative) &&
            Boolean(proto.webdriverGetter?.isNative) &&
            platformGetterOk &&
            hcGetterOk &&
            Boolean(proto.webglGetParameter?.isNative) &&
            webgl2GetterOk;

        const issues = [];
        if (!webdriverClean) issues.push(`navigator.webdriver=${String(nav.webdriver)}`);
        if (!noOwnOverrides) {
            issues.push(
                `navigator own-property overrides detected: [${(proto.ownNavigatorOverrides || []).join(', ')}]`
            );
        }
        if (!proto.toStringIntact) issues.push('Function.prototype.toString tampered');
        if (!proto.userAgentGetter?.isNative) issues.push('Navigator.prototype.userAgent getter is not [native code]');
        if (!proto.webdriverGetter?.isNative) issues.push('Navigator.prototype.webdriver getter is not [native code]');
        if (!platformGetterOk) issues.push('Navigator.prototype.platform getter is not [native code]');
        if (!hcGetterOk) issues.push('Navigator.prototype.hardwareConcurrency getter is not [native code]');
        if (!proto.webglGetParameter?.isNative) {
            issues.push('WebGLRenderingContext.prototype.getParameter is not [native code]');
        }
        if (!webgl2GetterOk) {
            issues.push('WebGL2RenderingContext.prototype.getParameter is not [native code]');
        }

        const passed = webdriverClean && noOwnOverrides && gettersNative;
        checks.push({
            name: 'navigator-prototype-integrity',
            passed,
            details: passed
                ? 'navigator.webdriver is false and C++ WebIDL [native code] getters/methods are intact'
                : issues.join('; ')
        });
    }

    // Check 2: Main Thread vs. Dedicated Web Worker Parity
    {
        if (worker.ok) {
            const mismatches = [];
            if (worker.userAgent !== nav.userAgent) {
                mismatches.push(`userAgent mismatch (main=${nav.userAgent} vs worker=${worker.userAgent})`);
            }
            if (worker.platform !== nav.platform) {
                mismatches.push(`platform mismatch (main=${nav.platform} vs worker=${worker.platform})`);
            }
            if (worker.hardwareConcurrency !== nav.hardwareConcurrency) {
                mismatches.push(
                    `hardwareConcurrency mismatch (main=${nav.hardwareConcurrency} vs worker=${worker.hardwareConcurrency})`
                );
            }
            if ((worker.language || nav.language) && worker.language !== nav.language) {
                mismatches.push(`language mismatch (main=${nav.language} vs worker=${worker.language})`);
            }
            if (JSON.stringify(worker.languages) !== JSON.stringify(nav.languages)) {
                mismatches.push(
                    `languages mismatch (main=${JSON.stringify(nav.languages)} vs worker=${JSON.stringify(worker.languages)})`
                );
            }
            if (Boolean(worker.webdriver) !== Boolean(nav.webdriver)) {
                mismatches.push(`webdriver mismatch (main=${nav.webdriver} vs worker=${worker.webdriver})`);
            }
            if ((worker.timeZone || intl.timeZone) && worker.timeZone !== intl.timeZone) {
                mismatches.push(`timeZone mismatch (main=${intl.timeZone} vs worker=${worker.timeZone})`);
            }
            const mathKeys = ['sin1e6', 'cos1e6', 'tan1e6', 'powPi'];
            if (!worker.math || typeof worker.math !== 'object') {
                mismatches.push('IEEE-754 Math results missing from Dedicated Worker telemetry');
            } else {
                const divergentKeys = mathKeys.filter(
                    (k) =>
                        typeof worker.math[k] !== 'number' ||
                        !Number.isFinite(worker.math[k]) ||
                        !Object.is(worker.math[k], math[k])
                );
                if (divergentKeys.length > 0) {
                    mismatches.push(
                        `IEEE-754 Math results differ between main thread and Web Worker (${divergentKeys.join(', ')})`
                    );
                }
            }

            const passed = mismatches.length === 0;
            checks.push({
                name: 'dedicated-worker-parity',
                passed,
                details: passed
                    ? 'WorkerNavigator, Intl timezone, and IEEE-754 math match main thread 100%'
                    : mismatches.join('; ')
            });
        } else {
            checks.push({
                name: 'dedicated-worker-parity',
                passed: false,
                details: `Dedicated Worker probe failed: ${worker.error || 'unknown error'}`
            });
        }
    }

    // Check 3: Firefox/Gecko Engine Coherence
    {
        const ua = String(nav.userAgent || '');
        const isGeckoFirefox =
            /^Mozilla\/5\.0\s+\([^)]+\)\s+Gecko\/20100101\s+Firefox\/\d+\.\d+/.test(ua) &&
            !ua.includes('Chrome/') &&
            !ua.includes('Safari/') &&
            !ua.includes('AppleWebKit/');
        const noClientHintsLeak = !nav.hasUserAgentData;
        const noWindowChromeLeak = !Boolean(
            nav.hasWindowChrome ||
                nav.chrome ||
                telemetry.hasWindowChrome ||
                telemetry.chrome ||
                telemetry.window?.chrome
        );
        const emptyVendor = !nav.vendor;

        const issues = [];
        if (!isGeckoFirefox) issues.push(`User-Agent is not authentic Firefox/Gecko: "${ua}"`);
        if (!noClientHintsLeak) issues.push('Chromium navigator.userAgentData leaked in Gecko context');
        if (!noWindowChromeLeak) issues.push('Chromium window.chrome object leaked in Gecko context');
        if (!emptyVendor) issues.push(`navigator.vendor should be empty in Firefox, got "${nav.vendor}"`);

        const passed = isGeckoFirefox && noClientHintsLeak && noWindowChromeLeak && emptyVendor;
        checks.push({
            name: 'engine-gecko-coherence',
            passed,
            details: passed
                ? `Authentic Gecko/Firefox engine signature verified (${ua})`
                : issues.join('; ')
        });
    }

    // Check 4: OS-to-Platform, Architecture & GPU Hardware Coherence (Camoufox rules)
    {
        const ua = String(nav.userAgent || '');
        const platform = String(nav.platform || '');
        const oscpu = String(nav.oscpu || '');
        const renderer = String(webgl.unmaskedRenderer || webgl.renderer || '');
        const cores = Number(nav.hardwareConcurrency);
        const issues = [];

        if (!Number.isInteger(cores) || cores < 1) {
            issues.push(`Invalid navigator.hardwareConcurrency=${String(nav.hardwareConcurrency)}`);
        }

        // Apple Silicon GPU vs core count coherence (applies whenever an Apple M-series GPU is claimed)
        if (renderer.includes('Apple M')) {
            if (!CAMOUFOX_COHERENCE_CONSTANTS.appleSiliconCores.has(cores)) {
                issues.push(
                    `Apple Silicon GPU "${renderer}" with hardwareConcurrency=${cores}; valid counts are [${[...CAMOUFOX_COHERENCE_CONSTANTS.appleSiliconCores].join(', ')}]`
                );
            }
        }

        if (!targetOs) {
            issues.push(`Unable to determine target OS from expectedOs="${expectedOs}" or platform="${platform}"`);
        } else if (targetOs === 'win') {
            if (platform !== 'Win32') issues.push(`Windows platform must be "Win32", got "${platform}"`);
            if (!ua.includes('Windows NT')) issues.push(`Windows UA missing "Windows NT": "${ua}"`);
            if (oscpu && !oscpu.includes('Windows NT')) {
                issues.push(`Windows navigator.oscpu mismatch: "${oscpu}"`);
            }
            if (!gpuFitsOs(renderer, 'win')) {
                issues.push(`Windows WebGL renderer must render through ANGLE, got "${renderer}"`);
            }
        } else if (targetOs === 'mac') {
            if (platform !== 'MacIntel') issues.push(`macOS platform must be "MacIntel", got "${platform}"`);
            if (!ua.includes('Macintosh; Intel Mac OS X')) {
                issues.push(`macOS UA missing "Macintosh; Intel Mac OS X": "${ua}"`);
            }
            if (oscpu && !oscpu.includes('Intel Mac OS X')) {
                issues.push(`macOS navigator.oscpu mismatch: "${oscpu}"`);
            }
            if (!gpuFitsOs(renderer, 'mac')) {
                issues.push(`macOS identity reports incompatible GPU renderer "${renderer}"`);
            }
            if (renderer && !renderer.includes('Apple M')) {
                const allowedCores = renderer.includes('Intel')
                    ? CAMOUFOX_COHERENCE_CONSTANTS.intelMacIgpCores
                    : CAMOUFOX_COHERENCE_CONSTANTS.intelMacDgpuCores;
                if (Number.isInteger(cores) && !allowedCores.has(cores)) {
                    issues.push(`Intel Mac GPU "${renderer}" with implausible hardwareConcurrency=${cores}`);
                }
                const panelKey = `${scr.width}x${scr.height}`;
                if (CAMOUFOX_COHERENCE_CONSTANTS.appleSiliconPanels.has(panelKey)) {
                    issues.push(
                        `Intel Mac GPU "${renderer}" behind notched Apple Silicon panel ${panelKey}`
                    );
                }
            }
        } else if (targetOs === 'lin') {
            if (!platform.startsWith('Linux')) {
                issues.push(`Linux platform must start with "Linux", got "${platform}"`);
            }
            if (!ua.includes('Linux')) issues.push(`Linux UA missing "Linux": "${ua}"`);
            if (oscpu && !oscpu.includes('Linux')) {
                issues.push(`Linux navigator.oscpu mismatch: "${oscpu}"`);
            }
            if (!gpuFitsOs(renderer, 'lin')) {
                issues.push(`Linux identity reports incompatible GPU renderer "${renderer}"`);
            }
        }

        // Cross-check x86 Intel-only hybrid core counts (10, 14, 18, 22, 28) vs AMD CPU/APU renderer contradictions
        if ((targetOs === 'win' || targetOs === 'lin') && !renderer.includes('Apple M')) {
            const isAmdApuRenderer = CAMOUFOX_COHERENCE_CONSTANTS.amdApuGpus.some((sig) =>
                renderer.includes(sig)
            );
            const isIntelIgpuRenderer =
                CAMOUFOX_COHERENCE_CONSTANTS.intelIgpus.some((sig) => renderer.includes(sig)) ||
                renderer.includes('Intel(R) UHD Graphics') ||
                renderer.includes('Intel(R) Iris');
            const claimedCpuMaker = String(telemetry.cpu?.manufacturer || nav.cpuManufacturer || '').toLowerCase();

            if (CAMOUFOX_COHERENCE_CONSTANTS.intelOnlyCoreCounts.has(cores)) {
                if (isAmdApuRenderer) {
                    issues.push(
                        `Intel-only hardwareConcurrency=${cores} contradicts AMD APU/iGPU renderer "${renderer}"`
                    );
                }
                if (claimedCpuMaker === 'amd') {
                    issues.push(
                        `Intel-only hardwareConcurrency=${cores} contradicts claimed AMD CPU manufacturer`
                    );
                }
            }
            if (claimedCpuMaker === 'amd' && isIntelIgpuRenderer) {
                issues.push(`Claimed AMD CPU manufacturer contradicts Intel integrated GPU "${renderer}"`);
            }
            if (claimedCpuMaker === 'intel' && isAmdApuRenderer) {
                issues.push(`Claimed Intel CPU manufacturer contradicts AMD APU/iGPU renderer "${renderer}"`);
            }
        }

        // Cross-check arch-agreement rule from Camoufox coherence.ts
        if (
            ua.includes('x86_64') &&
            (platform.includes('armv') ||
                oscpu.includes('armv') ||
                platform.includes('aarch64') ||
                oscpu.includes('aarch64'))
        ) {
            issues.push(`UA claims x86_64 while platform/oscpu say "${platform}" / "${oscpu}"`);
        }

        // Touch points check from Camoufox coherence.ts
        const touch = Number(nav.maxTouchPoints ?? 0);
        if (!Number.isInteger(touch) || touch < 0 || touch > CAMOUFOX_COHERENCE_CONSTANTS.maxPlausibleTouchPoints) {
            issues.push(
                `navigator.maxTouchPoints=${touch} exceeds consumer digitiser limit (${CAMOUFOX_COHERENCE_CONSTANTS.maxPlausibleTouchPoints})`
            );
        } else if (targetOs === 'mac' && touch > 0) {
            issues.push(`macOS identity reports maxTouchPoints=${touch}; no Mac has a touchscreen`);
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'os-platform-gpu-coherence',
            passed,
            details: passed
                ? `OS (${targetOs}), platform (${platform}), CPU cores (${cores}), and GPU (${renderer}) are coherent`
                : issues.join('; ')
        });
    }

    // Check 5: Screen Geometry, Color Depth, DPR & CSS Media Query Parity
    {
        const issues = [];
        const width = Number(scr.width);
        const height = Number(scr.height);
        const availW = Number(scr.availWidth);
        const availH = Number(scr.availHeight);
        const colorDepth = Number(scr.colorDepth);
        const pixelDepth = Number(scr.pixelDepth);
        const dpr = Number(scr.devicePixelRatio);

        if (!(width >= 1024 && height > 0 && width >= height)) {
            issues.push(`Implausible desktop screen shape ${width}x${height} (must be landscape and >= 1024px wide)`);
        }
        if (!(availW > 0 && availH > 0) || availW > width || availH > height) {
            issues.push(`availBounds ${availW}x${availH} exceed screen bounds ${width}x${height}`);
        }
        if (
            Number.isFinite(scr.outerWidth) &&
            Number.isFinite(scr.innerWidth) &&
            scr.outerWidth > 0 &&
            scr.innerWidth > scr.outerWidth
        ) {
            issues.push(`window.innerWidth (${scr.innerWidth}) exceeds window.outerWidth (${scr.outerWidth})`);
        }
        if (
            Number.isFinite(scr.outerHeight) &&
            Number.isFinite(scr.innerHeight) &&
            scr.outerHeight > 0 &&
            scr.innerHeight > scr.outerHeight
        ) {
            issues.push(`window.innerHeight (${scr.innerHeight}) exceeds window.outerHeight (${scr.outerHeight})`);
        }
        if (!CAMOUFOX_COHERENCE_CONSTANTS.plausibleColorDepth.has(colorDepth)) {
            issues.push(`screen.colorDepth=${colorDepth} is not a valid Firefox value (24 or 30)`);
        }
        if (targetOs === 'mac' && colorDepth !== 30) {
            issues.push(`macOS identity has colorDepth=${colorDepth}; macOS Firefox defaults to 30`);
        }
        if (pixelDepth !== colorDepth) {
            issues.push(`screen.pixelDepth (${pixelDepth}) differs from screen.colorDepth (${colorDepth})`);
        }
        if (targetOs && CAMOUFOX_COHERENCE_CONSTANTS.plausibleDpr[targetOs]) {
            const allowedDprs = CAMOUFOX_COHERENCE_CONSTANTS.plausibleDpr[targetOs];
            if (!allowedDprs.includes(dpr)) {
                issues.push(
                    `devicePixelRatio=${dpr} is not a standard ${targetOs} scaling step ([${allowedDprs.join(', ')}])`
                );
            }
        }
        if (!mq.deviceWidthMatches || !mq.deviceHeightMatches) {
            issues.push(`screen ${width}x${height} does not match CSS (device-width)/(device-height) matchMedia`);
        }
        if (!mq.innerWidthMatches || !mq.innerHeightMatches) {
            issues.push(
                `viewport ${scr.innerWidth}x${scr.innerHeight} does not match CSS (width)/(height) matchMedia`
            );
        }
        if (!mq.dprResolutionMatches) {
            issues.push(`devicePixelRatio=${dpr} does not match CSS (resolution) matchMedia`);
        }
        if (!mq.orientationLandscape || mq.orientationPortrait === true) {
            issues.push('CSS matchMedia("(orientation: landscape)") evaluated to false on desktop profile');
        }
        if (mq.colorBitsAtLeast8 === false) {
            issues.push('CSS matchMedia("(min-color: 8)") evaluated to false');
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'screen-media-query-parity',
            passed,
            details: passed
                ? `Screen ${width}x${height} @ ${dpr}x (${colorDepth}-bit) matches all CSS matchMedia queries`
                : issues.join('; ')
        });
    }

    // Check 6: WebGL, Canvas 2D, AudioContext & CPU Math Precision Integrity
    {
        const issues = [];
        if (!webgl.available || !webgl.unmaskedRenderer || !(webgl.extensionsCount > 0)) {
            issues.push(
                `WebGL context incomplete (available=${webgl.available}, renderer=${webgl.unmaskedRenderer}, extensions=${webgl.extensionsCount})`
            );
        }
        if (!canvas2d.available || !canvas2d.fnv1aHash || !(canvas2d.pixelSampleSum > 0)) {
            issues.push('Canvas 2D rendering failed or returned blank zero-filled buffer');
        }
        if (!audio.available || !(audio.sampleRate >= 8000 && audio.sampleRate <= 192000)) {
            issues.push(`AudioContext invalid or unavailable (sampleRate=${audio.sampleRate})`);
        }
        const mathValues = [math.sin1e6, math.cos1e6, math.tan1e6, math.powPi];
        const mathFinite = mathValues.every((v) => typeof v === 'number' && Number.isFinite(v));
        if (!mathFinite) {
            issues.push('CPU IEEE-754 floating-point math probe produced non-finite values');
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'graphics-audio-math-integrity',
            passed,
            details: passed
                ? `WebGL (${webgl.extensionsCount} exts), Canvas 2D (${canvas2d.fnv1aHash}), Audio (${audio.sampleRate}Hz), and IEEE-754 Math (${math.hex?.sin1e6}) verified`
                : issues.join('; ')
        });
    }

    // Check 7: Intl & Timezone Coherence
    {
        const issues = [];
        if (!intl.timeZone || typeof intl.timeZone !== 'string' || intl.timeZone.length < 2) {
            issues.push(`Invalid Intl timeZone: "${intl.timeZone}"`);
        }
        if (!intl.locale || typeof intl.locale !== 'string') {
            issues.push(`Invalid Intl locale: "${intl.locale}"`);
        }
        if (!Array.isArray(nav.languages) || nav.languages.length === 0) {
            issues.push('navigator.languages is empty');
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'timezone-intl-coherence',
            passed,
            details: passed
                ? `Intl timeZone="${intl.timeZone}", locale="${intl.locale}", languages=[${(nav.languages || []).join(', ')}]`
                : issues.join('; ')
        });
    }

    const passedCount = checks.filter((c) => c.passed).length;
    const score = checks.length > 0 ? Math.round((passedCount / checks.length) * 100) : 0;
    const passed = passedCount === checks.length;

    return {
        passed,
        score,
        checks
    };
}

/**
 * Execute an end-to-end in-browser fingerprint collection and platform coherence audit
 * on a live Camoufox page, logging and returning the full diagnostic report.
 *
 * @param {import('playwright').Page | import('puppeteer-core').Page} page
 * @param {string} [expectedOs] Expected OS ('win' | 'mac' | 'lin')
 * @returns {Promise<{
 *   passed: boolean,
 *   score: number,
 *   expectedOs: string | null,
 *   checks: Array<{ name: string, passed: boolean, details: string }>,
 *   telemetry: object,
 *   timestamp: string
 * }>}
 */
export async function auditProfileCoherence(page, expectedOs) {
    const normalizedOs = normalizeTargetOs(expectedOs);
    logger.info('Running Camoufox in-browser fingerprint coherence audit...', {
        expectedOs: normalizedOs || expectedOs || 'auto'
    });

    const telemetry = await collectBrowserFingerprint(page);
    const evaluation = evaluatePlatformCoherence(telemetry, normalizedOs || expectedOs);
    const report = {
        passed: evaluation.passed,
        score: evaluation.score,
        expectedOs: normalizedOs || expectedOs || null,
        checks: evaluation.checks,
        telemetry,
        timestamp: new Date().toISOString()
    };

    if (report.passed) {
        logger.info(`Camoufox profile coherence audit PASSED (${report.score}/100)`, {
            expectedOs: report.expectedOs,
            renderer: telemetry.webgl?.unmaskedRenderer,
            canvasHash: telemetry.canvas2d?.fnv1aHash,
            timeZone: telemetry.intl?.timeZone
        });
    } else {
        const failedChecks = report.checks.filter((c) => !c.passed);
        logger.warn(`Camoufox profile coherence audit FAILED (${report.score}/100)`, {
            expectedOs: report.expectedOs,
            failedChecks
        });
    }

    return report;
}

export default {
    CAMOUFOX_COHERENCE_CONSTANTS,
    normalizeTargetOs,
    gpuFitsOs,
    collectBrowserFingerprint,
    evaluatePlatformCoherence,
    auditProfileCoherence
};
