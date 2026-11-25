/**
 * In-Browser Fingerprint & Anti-Bot Environment Coherence Auditor for Camoufox
 *
 * Implements defensive runtime probes and cross-field hardware/OS invariant checks
 * modeled on Camoufox's `coherence.py` / `coherence.ts` and the environmental signals
 * inspected by Google BotGuard, Arkose BDA, Meta Device Graph, and ByteDance JSVMP.
 */

import fs from 'fs';
import logger from '../utils/logger.js';
import {
    APPLE_SILICON_SKU_CATALOG,
    INTEL_MAC_SKU_CATALOG,
    QUALCOMM_SNAPDRAGON_SKU_CATALOG,
    OEM_DEVICE_MODEL_CATALOG,
    PC_CPU_SKU_CATALOG,
    PC_GPU_SKU_CATALOG,
    PCI_DEVICE_ID_CATALOG,
    PCI_VENDOR_ID_BY_GPU_VENDOR,
    parseAppleSiliconSkuName,
    lookupIntelMacSku,
    lookupSnapdragonSku,
    lookupOemDeviceSku,
    lookupPcCpuSku,
    lookupPcGpuSku,
    validateHardwareModelSpec
} from './hardware-models.js';
import {
    OS_FONT_CATALOG,
    LOCALE_FALLBACK_CHAINS,
    COUNTRY_GEO_PROFILE_CATALOG,
    OS_SPEECH_VOICES_CATALOG,
    OS_MEDIA_DEVICES_CATALOG,
    USABLE_DEVICE_PRESET_CATALOG,
    normalizePresetOs,
    listUsableDevicePresets,
    expandCompatibleLanguages,
    buildAcceptLanguageHeader,
    resolveCountryGeoProfile,
    selectCoherentSpeechVoices,
    createCoherentMediaDevices,
    resolveDeterministicDeviceProfile,
    sanitizeAdsPowerProfileToCoherentPreset,
    sanitizeZiniaoProfileToCoherentPreset,
    SENSITIVE_LOCAL_PORT_CATALOG,
    BLOCKED_INTERNAL_URL_PATTERNS,
    DEFAULT_CANVAS_SKIP_HOSTS,
    COUNTRY_METRO_COORDINATES_CATALOG,
    isLocalOrPrivateTarget,
    classifyScannedPortRisk,
    evaluatePortScanRequest,
    evaluateInternalSchemeAccess,
    computeHexHammingDistance,
    computeHashSimilarity,
    shouldSkipCanvasNoiseForHost,
    isSoftwareRasterizerRenderer,
    CanvasWebglConsistencyLedger,
    validateOsAndBrowserVersionMatch,
    resolveGeoCoordinatesWithDeterministicJitter,
    attachZiniaoSecurityGuardsToContext
} from './device-presets.js';

export {
    APPLE_SILICON_SKU_CATALOG,
    INTEL_MAC_SKU_CATALOG,
    QUALCOMM_SNAPDRAGON_SKU_CATALOG,
    OEM_DEVICE_MODEL_CATALOG,
    PC_CPU_SKU_CATALOG,
    PC_GPU_SKU_CATALOG,
    PCI_DEVICE_ID_CATALOG,
    PCI_VENDOR_ID_BY_GPU_VENDOR,
    parseAppleSiliconSkuName,
    lookupIntelMacSku,
    lookupSnapdragonSku,
    lookupOemDeviceSku,
    lookupPcCpuSku,
    lookupPcGpuSku,
    validateHardwareModelSpec,
    OS_FONT_CATALOG,
    LOCALE_FALLBACK_CHAINS,
    COUNTRY_GEO_PROFILE_CATALOG,
    OS_SPEECH_VOICES_CATALOG,
    OS_MEDIA_DEVICES_CATALOG,
    USABLE_DEVICE_PRESET_CATALOG,
    normalizePresetOs,
    listUsableDevicePresets,
    expandCompatibleLanguages,
    buildAcceptLanguageHeader,
    resolveCountryGeoProfile,
    selectCoherentSpeechVoices,
    createCoherentMediaDevices,
    resolveDeterministicDeviceProfile,
    sanitizeAdsPowerProfileToCoherentPreset,
    sanitizeZiniaoProfileToCoherentPreset,
    SENSITIVE_LOCAL_PORT_CATALOG,
    BLOCKED_INTERNAL_URL_PATTERNS,
    DEFAULT_CANVAS_SKIP_HOSTS,
    COUNTRY_METRO_COORDINATES_CATALOG,
    isLocalOrPrivateTarget,
    classifyScannedPortRisk,
    evaluatePortScanRequest,
    evaluateInternalSchemeAccess,
    computeHexHammingDistance,
    computeHashSimilarity,
    shouldSkipCanvasNoiseForHost,
    isSoftwareRasterizerRenderer,
    CanvasWebglConsistencyLedger,
    validateOsAndBrowserVersionMatch,
    resolveGeoCoordinatesWithDeterministicJitter,
    attachZiniaoSecurityGuardsToContext
};

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
    notAMacGpu: ['ANGLE', 'llvmpipe'],
    ephemeralPortRanges: Object.freeze({
        win: [49152, 65535],
        mac: [49152, 65535],
        lin: [32768, 60999]
    }),
    forbiddenAutomationGlobals: Object.freeze([
        '__playwright',
        '__pw_manual',
        '__puppeteer_evaluation_script__',
        '_selenium',
        'callPhantom',
        '_phantom',
        'domAutomation',
        'domAutomationController',
        '_WEBDRIVER_ELEM_CACHE'
    ]),
    windowsExclusiveFonts: Object.freeze([
        'Segoe UI',
        'Consolas',
        'Calibri',
        'Cambria',
        'Candara',
        'Gabriola',
        'Ebrima'
    ]),
    macosExclusiveFonts: Object.freeze([
        'SF Pro',
        'SF Pro Text',
        'SF Pro Display',
        'Helvetica Neue',
        'Menlo',
        'Apple Color Emoji',
        'Geneva',
        'Monaco',
        'PingFang SC'
    ]),
    linuxExclusiveFonts: Object.freeze([
        'Ubuntu',
        'Ubuntu Mono',
        'Cantarell',
        'Liberation Sans',
        'Noto Color Emoji'
    ]),
    forbiddenChromiumApisOnGecko: Object.freeze([
        'deviceMemory',
        'getBattery',
        'bluetooth',
        'usb',
        'serial',
        'hid',
        'openDatabase'
    ]),
    forbiddenStackMarkers: Object.freeze([
        '__puppeteer_evaluation_script__',
        '__playwright',
        'UtilityScript',
        'pptr:',
        'evaluateOnNewDocument',
        'juggler://',
        'webdriver'
    ])
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
            pdfViewerEnabled: 'pdfViewerEnabled' in navigator ? navigator.pdfViewerEnabled : true,
            cookieEnabled: 'cookieEnabled' in navigator ? navigator.cookieEnabled : true,
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
                    const rawViewportDims = gl.getParameter(gl.MAX_VIEWPORT_DIMS);
                    const rawLineWidthRange = gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE);
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
                        extensionsCount: exts.length,
                        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
                        maxCubeMapTextureSize: gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
                        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
                        maxViewportDims: rawViewportDims ? Array.from(rawViewportDims) : null,
                        maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
                        aliasedLineWidthRange: rawLineWidthRange ? Array.from(rawLineWidthRange) : null
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
                colorBitsAtLeast8: mm('(min-color: 8)'),
                colorGamutSrgb: mm('(color-gamut: srgb)'),
                colorGamutP3: mm('(color-gamut: p3)'),
                dynamicRangeHigh: mm('(dynamic-range: high)'),
                pointerFine: mm('(pointer: fine)'),
                pointerCoarse: mm('(pointer: coarse)'),
                hoverSupported: mm('(hover: hover)')
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

        // 7. Automation Globals, SpeechSynthesis Voices & WebRTC Surface
        const forbiddenGlobalsSet = new Set([
            '__playwright',
            '__pw_manual',
            '__puppeteer_evaluation_script__',
            '_selenium',
            'callPhantom',
            '_phantom',
            'domAutomation',
            'domAutomationController',
            '_WEBDRIVER_ELEM_CACHE'
        ]);
        const forbiddenGlobalRegex = /^(\$?cdc_|__webdriver|__selenium|__fxdriver|__playwright)/i;
        const isForbiddenGlobal = (key) => forbiddenGlobalsSet.has(key) || forbiddenGlobalRegex.test(key);
        let automationGlobals = [];
        try {
            const winProps =
                typeof window !== 'undefined' ? Object.getOwnPropertyNames(window).filter(isForbiddenGlobal) : [];
            const docProps =
                typeof document !== 'undefined' ? Object.getOwnPropertyNames(document).filter(isForbiddenGlobal) : [];
            automationGlobals = Array.from(new Set([...winProps, ...docProps]));
        } catch {}

        let speechVoices = [];
        try {
            speechVoices =
                typeof speechSynthesis !== 'undefined' && typeof speechSynthesis.getVoices === 'function'
                    ? speechSynthesis.getVoices().map((v) => ({
                          name: v.name,
                          lang: v.lang,
                          voiceURI: v.voiceURI
                      }))
                    : [];
        } catch {}

        const webrtcInfo = {
            available: typeof RTCPeerConnection !== 'undefined',
            candidatePorts: [],
            candidateIps: [],
            privateIpLeaked: false
        };

        let fonts = [];
        try {
            const probeFonts = [
                'Segoe UI',
                'Consolas',
                'Calibri',
                'SF Pro',
                'Helvetica Neue',
                'Menlo',
                'Monaco',
                'Ubuntu',
                'Liberation Sans',
                'DejaVu Sans',
                'Arial',
                'Times New Roman'
            ];
            const probeText = 'mmmmmmmmmmlliWW1234567890';
            const baseFamilies = ['monospace', 'sans-serif', 'serif'];
            const fontCanvas =
                typeof document !== 'undefined' && typeof document.createElement === 'function'
                    ? document.createElement('canvas')
                    : null;
            const fontCtx =
                fontCanvas && typeof fontCanvas.getContext === 'function'
                    ? fontCanvas.getContext('2d')
                    : null;

            if (fontCtx) {
                const baseWidths = {};
                for (const base of baseFamilies) {
                    fontCtx.font = `72px ${base}`;
                    baseWidths[base] = fontCtx.measureText(probeText).width;
                }
                for (const fontName of probeFonts) {
                    let detected = false;
                    for (const base of baseFamilies) {
                        fontCtx.font = `72px "${fontName}", ${base}`;
                        const width = fontCtx.measureText(probeText).width;
                        if (width !== baseWidths[base]) {
                            detected = true;
                            break;
                        }
                    }
                    if (detected) {
                        fonts.push(fontName);
                    }
                }
            } else if (
                typeof document !== 'undefined' &&
                document.fonts &&
                typeof document.fonts.check === 'function'
            ) {
                const bogusAvailable = document.fonts.check('16px "__camoufox_nonexistent_font__"');
                if (!bogusAvailable) {
                    fonts = probeFonts.filter((fontName) => document.fonts.check(`16px "${fontName}"`));
                }
            }
        } catch {}

        // 8. Dynamic Same-Origin iframe (contentWindow) Parity Probe
        const collectIframeParity = () => {
            if (typeof document === 'undefined' || typeof document.createElement !== 'function') {
                return { ok: false, error: 'document.createElement unavailable' };
            }
            let ifr = null;
            try {
                ifr = document.createElement('iframe');
                ifr.style.display = 'none';
                const host = document.body || document.documentElement;
                if (!host) {
                    return { ok: false, error: 'document.body and document.documentElement unavailable' };
                }
                host.appendChild(ifr);
                const cw = ifr.contentWindow;
                if (!cw || !cw.navigator || !cw.screen) {
                    return { ok: false, error: 'iframe.contentWindow or navigator/screen unavailable' };
                }
                const ifrNav = cw.navigator;
                const ifrScr = cw.screen;
                const ifrNavProto = Object.getPrototypeOf(ifrNav);
                const uaGetterDesc = ifrNavProto
                    ? Object.getOwnPropertyDescriptor(ifrNavProto, 'userAgent')
                    : null;
                const wdGetterDesc = ifrNavProto
                    ? Object.getOwnPropertyDescriptor(ifrNavProto, 'webdriver')
                    : null;
                const userAgentGetterNative = Boolean(
                    uaGetterDesc &&
                        typeof uaGetterDesc.get === 'function' &&
                        nativeCodeRegex.test(fnToString.call(uaGetterDesc.get))
                );
                const webdriverGetterNative = Boolean(
                    wdGetterDesc &&
                        typeof wdGetterDesc.get === 'function' &&
                        nativeCodeRegex.test(fnToString.call(wdGetterDesc.get))
                );
                return {
                    ok: true,
                    userAgent: ifrNav.userAgent,
                    platform: ifrNav.platform,
                    oscpu: 'oscpu' in ifrNav ? ifrNav.oscpu : null,
                    hardwareConcurrency: ifrNav.hardwareConcurrency,
                    webdriver: ifrNav.webdriver,
                    language: ifrNav.language,
                    languages: Array.isArray(ifrNav.languages) ? [...ifrNav.languages] : [],
                    width: ifrScr.width,
                    height: ifrScr.height,
                    colorDepth: ifrScr.colorDepth,
                    pixelDepth: ifrScr.pixelDepth,
                    userAgentGetterNative,
                    webdriverGetterNative
                };
            } catch (err) {
                return { ok: false, error: String(err) };
            } finally {
                try {
                    if (ifr && ifr.parentNode) {
                        ifr.parentNode.removeChild(ifr);
                    } else if (ifr && typeof ifr.remove === 'function') {
                        ifr.remove();
                    }
                } catch {}
            }
        };

        const iframeParity = collectIframeParity();

        // 9. Gecko API Surface & High-Precision Timer Probe
        let performanceNowMonotonic = false;
        try {
            if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
                const t1 = performance.now();
                const t2 = performance.now();
                performanceNowMonotonic = Number.isFinite(t1) && Number.isFinite(t2) && t2 >= t1;
            }
        } catch {}

        const geckoApiSurface = {
            hasDeviceMemory: 'deviceMemory' in navigator,
            hasGetBattery: 'getBattery' in navigator,
            hasBluetooth: 'bluetooth' in navigator,
            hasUsb: 'usb' in navigator,
            hasSerial: 'serial' in navigator,
            hasHid: 'hid' in navigator,
            hasOpenDatabase: typeof window !== 'undefined' && 'openDatabase' in window,
            hasMozInnerScreenX: typeof window !== 'undefined' && 'mozInnerScreenX' in window,
            performanceNowMonotonic
        };

        // 10. WebGPU Availability & Native Method Probe
        const hasWebGpu = typeof navigator !== 'undefined' && 'gpu' in navigator && Boolean(navigator.gpu);
        let requestAdapterNative = true;
        if (hasWebGpu) {
            try {
                const reqAdapter = navigator.gpu.requestAdapter;
                requestAdapterNative =
                    typeof reqAdapter === 'function' &&
                    nativeCodeRegex.test(fnToString.call(reqAdapter));
            } catch {
                requestAdapterNative = false;
            }
        }
        const webgpu = {
            available: hasWebGpu,
            requestAdapterNative
        };

        // 11. Error Stack Trace & MediaDevices Hygiene Probe
        const stackMarkerList = [
            '__puppeteer_evaluation_script__',
            '__playwright',
            'UtilityScript',
            'pptr:',
            'evaluateOnNewDocument',
            'juggler://',
            'webdriver'
        ];
        let rawStack = '';
        try {
            rawStack = String(new Error('probe').stack || '');
        } catch {}
        const hasAtSignFormat = /@/.test(rawStack) && !/^\s+at\s+/m.test(rawStack);
        const leakedStackMarkers = stackMarkerList.filter((marker) =>
            rawStack.toLowerCase().includes(marker.toLowerCase())
        );

        const mediaDevicesAvailable =
            typeof navigator !== 'undefined' &&
            typeof navigator.mediaDevices !== 'undefined' &&
            typeof navigator.mediaDevices?.enumerateDevices === 'function';
        let enumerateDevicesNative = true;
        if (typeof MediaDevices !== 'undefined' && MediaDevices.prototype) {
            enumerateDevicesNative = inspectMethod(MediaDevices.prototype, 'enumerateDevices').isNative;
        } else if (mediaDevicesAvailable) {
            try {
                enumerateDevicesNative = nativeCodeRegex.test(
                    fnToString.call(navigator.mediaDevices.enumerateDevices)
                );
            } catch {
                enumerateDevicesNative = false;
            }
        }

        let unpermittedLabelsLeaked = false;
        if (mediaDevicesAvailable) {
            try {
                const devices = await Promise.race([
                    navigator.mediaDevices.enumerateDevices(),
                    new Promise((resolve) => setTimeout(() => resolve([]), 500))
                ]);
                if (Array.isArray(devices)) {
                    unpermittedLabelsLeaked = devices.some(
                        (d) => d && typeof d.label === 'string' && d.label.trim().length > 0
                    );
                }
            } catch {
                unpermittedLabelsLeaked = false;
            }
        }

        const stackAndMediaHygiene = {
            hasAtSignFormat,
            leakedStackMarkers,
            enumerateDevicesNative,
            unpermittedLabelsLeaked,
            mediaDevices: {
                available: mediaDevicesAvailable,
                enumerateDevicesNative,
                unpermittedLabelsLeaked
            }
        };

        // 12. Browser StorageManager Quota Probe (for Disk Size vs Storage Quota Coherence)
        let storageEstimate = null;
        if (
            typeof navigator !== 'undefined' &&
            navigator.storage &&
            typeof navigator.storage.estimate === 'function'
        ) {
            try {
                const est = await Promise.race([
                    navigator.storage.estimate(),
                    new Promise((resolve) => setTimeout(() => resolve(null), 500))
                ]);
                if (est && typeof est === 'object') {
                    storageEstimate = {
                        quotaBytes: typeof est.quota === 'number' ? est.quota : null,
                        usageBytes: typeof est.usage === 'number' ? est.usage : null
                    };
                }
            } catch {
                storageEstimate = null;
            }
        }

        return {
            navigator: navigatorInfo,
            prototypeIntegrity,
            worker: workerInfo,
            webgl: graphicsInfo.webgl,
            canvas2d: graphicsInfo.canvas2d,
            audio: audioInfo,
            mathPrecision,
            screen: screenInfo,
            intl: intlInfo,
            automationGlobals,
            speechVoices,
            webrtc: webrtcInfo,
            fonts,
            iframeParity,
            geckoApiSurface,
            webgpu,
            stackAndMediaHygiene,
            storageEstimate
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

    // Check 8: Automation Globals Absence ($cdc_, __playwright, __puppeteer, _selenium, domAutomation)
    {
        const rawGlobals = telemetry.automationGlobals;
        const collected = [];
        if (Array.isArray(rawGlobals)) {
            collected.push(...rawGlobals);
        } else if (rawGlobals && typeof rawGlobals === 'object') {
            for (const key of ['window', 'document', 'windowGlobals', 'documentGlobals', 'detected', 'leaked']) {
                if (Array.isArray(rawGlobals[key])) {
                    collected.push(...rawGlobals[key]);
                }
            }
        }

        const forbiddenSet = new Set(CAMOUFOX_COHERENCE_CONSTANTS.forbiddenAutomationGlobals);
        const forbiddenRegex =
            /^(\$?cdc_|__webdriver|__selenium|__fxdriver|__playwright|__pw_manual|__puppeteer|_selenium|callPhantom|_phantom|domAutomation|_WEBDRIVER_ELEM_CACHE)/i;
        const leaked = Array.from(
            new Set(
                collected
                    .map((g) => String(g || '').trim())
                    .filter((g) => g.length > 0 && (forbiddenSet.has(g) || forbiddenRegex.test(g) || g.length > 0))
            )
        );

        const passed = leaked.length === 0;
        checks.push({
            name: 'automation-globals-absence',
            passed,
            details: passed
                ? 'Zero CDP/WebDriver/Playwright/Puppeteer automation globals detected on window or document'
                : `Leaked automation globals detected on window/document: [${leaked.join(', ')}]`
        });
    }

    // Check 9: WebRTC Network & Ephemeral Port Coherence
    {
        const webrtc = telemetry.webrtc;
        const issues = [];

        const isRfc1918PrivateIpv4 = (ip) => {
            if (typeof ip !== 'string') return false;
            const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
            if (!match) return false;
            const a = Number(match[1]);
            const b = Number(match[2]);
            const c = Number(match[3]);
            const d = Number(match[4]);
            if (a > 255 || b > 255 || c > 255 || d > 255) return false;
            return (
                a === 10 ||
                (a === 192 && b === 168) ||
                (a === 172 && b >= 16 && b <= 31) ||
                a === 127 ||
                (a === 169 && b === 254)
            );
        };

        if (webrtc && typeof webrtc === 'object') {
            if (webrtc.privateIpLeaked === true) {
                issues.push('WebRTC private LAN IP leak detected (privateIpLeaked=true)');
            }

            if (
                Array.isArray(webrtc.candidateIps) &&
                (Boolean(webrtc.expectedPublicIp) || webrtc.blockPrivateIp !== false)
            ) {
                for (const ip of webrtc.candidateIps) {
                    if (isRfc1918PrivateIpv4(ip)) {
                        issues.push(`WebRTC leaked RFC1918 private LAN IP "${ip}" in ICE candidates`);
                    } else if (webrtc.expectedPublicIp && ip !== webrtc.expectedPublicIp) {
                        issues.push(
                            `WebRTC candidate IP "${ip}" does not match expected proxy public IP "${webrtc.expectedPublicIp}"`
                        );
                    }
                }
            }

            if (Array.isArray(webrtc.candidatePorts) && webrtc.candidatePorts.length > 0) {
                const range = targetOs ? CAMOUFOX_COHERENCE_CONSTANTS.ephemeralPortRanges[targetOs] : null;
                if (range) {
                    const [minPort, maxPort] = range;
                    for (const port of webrtc.candidatePorts) {
                        const portNum = Number(port);
                        if (!Number.isInteger(portNum) || portNum < minPort || portNum > maxPort) {
                            issues.push(
                                `WebRTC ICE candidate UDP port ${port} falls outside ${targetOs} ephemeral range [${minPort}–${maxPort}]`
                            );
                        }
                    }
                }
            }
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'webrtc-network-coherence',
            passed,
            details: passed
                ? 'WebRTC ICE candidates respect RFC1918 private IP protection and OS ephemeral UDP port range'
                : issues.join('; ')
        });
    }

    // Check 10: SpeechSynthesis OS Voice Coherence
    {
        const voices = telemetry.speechVoices;
        const issues = [];

        if (Array.isArray(voices) && voices.length > 0 && targetOs) {
            for (const v of voices) {
                const name = typeof v === 'string' ? v : String(v?.name || '');
                const uri = typeof v === 'string' ? v : String(v?.voiceURI || '');
                const combined = `${name} ${uri}`;
                const label = name || uri || JSON.stringify(v);

                if (targetOs === 'win') {
                    if (/com\.apple\.speech|\bapple\b|\bsamantha\b|\bvictoria\b|\balex\b/i.test(combined)) {
                        issues.push(
                            `Windows identity leaked macOS/Apple SpeechSynthesis voice "${label}"`
                        );
                    }
                } else if (targetOs === 'mac') {
                    if (/microsoft\s+(david|zira|mark|hazel)|\bespeak\b/i.test(combined)) {
                        issues.push(
                            `macOS identity leaked Windows/Linux SpeechSynthesis voice "${label}"`
                        );
                    }
                } else if (targetOs === 'lin') {
                    if (/com\.apple\.speech|\bapple\b|microsoft\s+(david|zira|mark|hazel)/i.test(combined)) {
                        issues.push(
                            `Linux identity leaked macOS/Windows SpeechSynthesis voice "${label}"`
                        );
                    }
                }
            }
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'speech-voices-coherence',
            passed,
            details: passed
                ? 'SpeechSynthesis voices match target OS speech engine catalog'
                : issues.join('; ')
        });
    }

    // Check 11: Storage, PDF Viewer & OS Font Exclusive Signature Coherence
    {
        const issues = [];
        if (nav.pdfViewerEnabled === false) {
            issues.push(
                'navigator.pdfViewerEnabled=false (stock Desktop Firefox always reports pdfViewerEnabled=true)'
            );
        }
        if (nav.cookieEnabled === false) {
            issues.push('navigator.cookieEnabled=false (cookies must be enabled in Desktop Firefox)');
        }

        const rawFonts = Array.isArray(telemetry.fonts)
            ? telemetry.fonts
            : Array.isArray(telemetry.fonts?.available)
              ? telemetry.fonts.available
              : [];

        if (rawFonts.length > 0 && targetOs) {
            const winFontSet = new Set(
                CAMOUFOX_COHERENCE_CONSTANTS.windowsExclusiveFonts.map((f) => f.toLowerCase())
            );
            const macFontSet = new Set(
                CAMOUFOX_COHERENCE_CONSTANTS.macosExclusiveFonts.map((f) => f.toLowerCase())
            );
            const linFontSet = new Set(
                CAMOUFOX_COHERENCE_CONSTANTS.linuxExclusiveFonts.map((f) => f.toLowerCase())
            );

            for (const rawFont of rawFonts) {
                const fontName = String(rawFont || '').trim();
                const lowerFont = fontName.toLowerCase();
                if (!lowerFont) continue;

                if (targetOs === 'win') {
                    if (macFontSet.has(lowerFont)) {
                        issues.push(`Windows identity leaked macOS-exclusive font "${fontName}"`);
                    } else if (linFontSet.has(lowerFont)) {
                        issues.push(`Windows identity leaked Linux-exclusive font "${fontName}"`);
                    }
                } else if (targetOs === 'mac') {
                    if (winFontSet.has(lowerFont)) {
                        issues.push(`macOS identity leaked Windows-exclusive font "${fontName}"`);
                    } else if (linFontSet.has(lowerFont)) {
                        issues.push(`macOS identity leaked Linux-exclusive font "${fontName}"`);
                    }
                } else if (targetOs === 'lin') {
                    if (winFontSet.has(lowerFont)) {
                        issues.push(`Linux identity leaked Windows-exclusive font "${fontName}"`);
                    } else if (macFontSet.has(lowerFont)) {
                        issues.push(`Linux identity leaked macOS-exclusive font "${fontName}"`);
                    }
                }
            }
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'storage-pdf-fonts-coherence',
            passed,
            details: passed
                ? 'navigator.pdfViewerEnabled, navigator.cookieEnabled, and OS system font catalog are coherent'
                : issues.join('; ')
        });
    }

    // Check 12: Dynamic Same-Origin iframe (contentWindow) Parity
    {
        const iframeParity = telemetry.iframeParity;
        const issues = [];

        if (iframeParity && typeof iframeParity === 'object') {
            if (iframeParity.ok === false) {
                issues.push(`Dynamic iframe probe failed: ${iframeParity.error || 'unknown error'}`);
            } else {
                if (iframeParity.userAgent !== nav.userAgent) {
                    issues.push(
                        `iframe navigator.userAgent mismatch (main="${nav.userAgent}" vs iframe="${iframeParity.userAgent}")`
                    );
                }
                if (iframeParity.platform !== nav.platform) {
                    issues.push(
                        `iframe navigator.platform mismatch (main="${nav.platform}" vs iframe="${iframeParity.platform}")`
                    );
                }
                if (
                    iframeParity.oscpu !== undefined &&
                    nav.oscpu !== undefined &&
                    iframeParity.oscpu !== nav.oscpu
                ) {
                    issues.push(
                        `iframe navigator.oscpu mismatch (main="${nav.oscpu}" vs iframe="${iframeParity.oscpu}")`
                    );
                }
                if (iframeParity.hardwareConcurrency !== nav.hardwareConcurrency) {
                    issues.push(
                        `iframe navigator.hardwareConcurrency mismatch (main=${nav.hardwareConcurrency} vs iframe=${iframeParity.hardwareConcurrency})`
                    );
                }
                if (Boolean(iframeParity.webdriver) !== Boolean(nav.webdriver)) {
                    issues.push(
                        `iframe navigator.webdriver mismatch (main=${nav.webdriver} vs iframe=${iframeParity.webdriver})`
                    );
                }
                if (
                    iframeParity.language !== undefined &&
                    nav.language !== undefined &&
                    iframeParity.language !== nav.language
                ) {
                    issues.push(
                        `iframe navigator.language mismatch (main="${nav.language}" vs iframe="${iframeParity.language}")`
                    );
                }
                if (
                    Array.isArray(iframeParity.languages) &&
                    Array.isArray(nav.languages) &&
                    JSON.stringify(iframeParity.languages) !== JSON.stringify(nav.languages)
                ) {
                    issues.push(
                        `iframe navigator.languages mismatch (main=${JSON.stringify(nav.languages)} vs iframe=${JSON.stringify(iframeParity.languages)})`
                    );
                }
                if (iframeParity.width !== scr.width) {
                    issues.push(
                        `iframe screen.width mismatch (main=${scr.width} vs iframe=${iframeParity.width})`
                    );
                }
                if (iframeParity.height !== scr.height) {
                    issues.push(
                        `iframe screen.height mismatch (main=${scr.height} vs iframe=${iframeParity.height})`
                    );
                }
                if (iframeParity.colorDepth !== scr.colorDepth) {
                    issues.push(
                        `iframe screen.colorDepth mismatch (main=${scr.colorDepth} vs iframe=${iframeParity.colorDepth})`
                    );
                }
                if (
                    iframeParity.pixelDepth !== undefined &&
                    scr.pixelDepth !== undefined &&
                    iframeParity.pixelDepth !== scr.pixelDepth
                ) {
                    issues.push(
                        `iframe screen.pixelDepth mismatch (main=${scr.pixelDepth} vs iframe=${iframeParity.pixelDepth})`
                    );
                }
                if (iframeParity.userAgentGetterNative === false) {
                    issues.push('iframe Navigator.prototype.userAgent getter is not [native code]');
                }
                if (iframeParity.webdriverGetterNative === false) {
                    issues.push('iframe Navigator.prototype.webdriver getter is not [native code]');
                }
            }
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'iframe-contentwindow-parity',
            passed,
            details: passed
                ? 'Dynamic same-origin iframe.contentWindow navigator, screen, and C++ WebIDL getters match top-level window 100%'
                : issues.join('; ')
        });
    }

    // Check 13: Gecko API Surface & High-Precision Timer Coherence
    {
        const geckoApiSurface = telemetry.geckoApiSurface;
        const issues = [];

        if (geckoApiSurface && typeof geckoApiSurface === 'object') {
            if (geckoApiSurface.hasDeviceMemory) {
                issues.push('Chromium navigator.deviceMemory leaked on Gecko');
            }
            if (geckoApiSurface.hasGetBattery) {
                issues.push('Chromium navigator.getBattery leaked on Gecko');
            }
            if (geckoApiSurface.hasBluetooth) {
                issues.push('Chromium navigator.bluetooth leaked on Gecko');
            }
            if (geckoApiSurface.hasUsb) {
                issues.push('Chromium navigator.usb leaked on Gecko');
            }
            if (geckoApiSurface.hasSerial) {
                issues.push('Chromium navigator.serial leaked on Gecko');
            }
            if (geckoApiSurface.hasHid) {
                issues.push('Chromium navigator.hid leaked on Gecko');
            }
            if (geckoApiSurface.hasOpenDatabase) {
                issues.push('Chromium window.openDatabase WebSQL API leaked on Gecko');
            }
            if (geckoApiSurface.hasMozInnerScreenX === false) {
                issues.push('Firefox window.mozInnerScreenX property missing');
            }
            if (geckoApiSurface.performanceNowMonotonic === false) {
                issues.push('performance.now() high-precision timer is non-monotonic or invalid');
            }
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'gecko-api-surface-coherence',
            passed,
            details: passed
                ? 'Zero Chromium-only APIs leaked on Gecko, window.mozInnerScreenX present, and performance.now() is monotonic'
                : issues.join('; ')
        });
    }

    // Check 14: WebGPU OS & GPU Architecture Coherence
    {
        const webgpu = telemetry.webgpu;
        const renderer = String(webgl.unmaskedRenderer || webgl.renderer || '');
        const issues = [];

        if (webgpu && typeof webgpu === 'object') {
            if (targetOs === 'lin' && webgpu.available === true) {
                issues.push(
                    'Linux identity exposes navigator.gpu (WebGPU is disabled by default on Linux Desktop Firefox/Camoufox)'
                );
            }
            if (webgpu.requestAdapterNative === false) {
                issues.push('navigator.gpu.requestAdapter is not [native code]');
            }
            if (targetOs === 'mac' && webgpu.available === true && renderer && !renderer.includes('Apple M')) {
                issues.push(
                    `macOS identity exposes navigator.gpu (WebGPU) on non-Apple-Silicon renderer "${renderer}" (Camoufox only enables WebGPU on Apple Silicon Macs)`
                );
            }
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'webgpu-os-coherence',
            passed,
            details: passed
                ? 'navigator.gpu (WebGPU) availability and native requestAdapter signature match OS and GPU architecture rules'
                : issues.join('; ')
        });
    }

    // Check 15: Error Stack Trace & MediaDevices Hygiene
    {
        const hygiene = telemetry.stackAndMediaHygiene;
        const issues = [];

        if (hygiene && typeof hygiene === 'object') {
            let hasAtSignFormat = hygiene.hasAtSignFormat !== false;
            const markerSet = new Set(
                Array.isArray(hygiene.leakedStackMarkers) ? hygiene.leakedStackMarkers : []
            );

            if (typeof hygiene.stack === 'string' && hygiene.stack.length > 0) {
                if (!/@/.test(hygiene.stack) || /^\s+at\s+/m.test(hygiene.stack)) {
                    hasAtSignFormat = false;
                }
                for (const marker of CAMOUFOX_COHERENCE_CONSTANTS.forbiddenStackMarkers) {
                    if (hygiene.stack.toLowerCase().includes(marker.toLowerCase())) {
                        markerSet.add(marker);
                    }
                }
            }

            if (!hasAtSignFormat) {
                issues.push(
                    'Error.prototype.stack uses V8/Chromium "    at " format instead of SpiderMonkey/Firefox "fn@url:line:col" format'
                );
            }

            const leakedMarkers = Array.from(markerSet);
            if (leakedMarkers.length > 0) {
                issues.push(
                    `Error.prototype.stack leaked automation evaluation markers: [${leakedMarkers.join(', ')}]`
                );
            }

            const enumerateDevicesNative =
                hygiene.enumerateDevicesNative !== false &&
                hygiene.mediaDevices?.enumerateDevicesNative !== false;
            if (!enumerateDevicesNative) {
                issues.push('MediaDevices.prototype.enumerateDevices is not [native code]');
            }

            const unpermittedLabelsLeaked =
                hygiene.unpermittedLabelsLeaked === true ||
                hygiene.mediaDevices?.unpermittedLabelsLeaked === true;
            if (unpermittedLabelsLeaked) {
                issues.push(
                    'navigator.mediaDevices.enumerateDevices() leaked non-empty hardware device labels without active media permission'
                );
            }
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'stack-trace-and-mediadevices-hygiene',
            passed,
            details: passed
                ? 'SpiderMonkey Error.prototype.stack format is clean and MediaDevices.prototype.enumerateDevices is native without unpermitted label leaks'
                : issues.join('; ')
        });
    }

    // Check 16: Exact Hardware SKU & Device Model Parameter Coherence
    // Validates exact CPU SKU, GPU SKU, Unified/System RAM capacity, SSD/Disk capacity,
    // StorageManager quota vs physical disk size, laptop notched/non-notched display panel
    // vs SoC SKU, Windows ANGLE vendor/shader model lockstep, and WebGL hardware limits.
    {
        const skuValidation = validateHardwareModelSpec(telemetry, targetOs);
        const passed = skuValidation.passed;
        const skuDesc = skuValidation.matchedSku ? ` [${skuValidation.matchedSku}]` : '';
        checks.push({
            name: 'exact-hardware-sku-model-coherence',
            passed,
            details: passed
                ? `Exact hardware model parameters${skuDesc} (CPU cores/threads, GPU SKU, RAM capacity, SSD storage tier, panel form-factor, and WebGL hardware limits) are 100% coherent`
                : skuValidation.issues.join('; ')
        });
    }

    // Check 17: Display Gamut/HDR, Touchscreen/Pointer & Audio Hardware Limits Coherence
    {
        const issues = [];
        const renderer = String(webgl.unmaskedRenderer || '').trim();

        // 1. Display Color Gamut (sRGB / Display-P3) vs ColorDepth & Hardware Panel Coherence
        if (mq.colorGamutSrgb === false) {
            issues.push('CSS (color-gamut: srgb) matchMedia returned false on a desktop/laptop display');
        }
        if (targetOs === 'mac' && /^Apple M\d/i.test(renderer) && scr.colorDepth === 30) {
            if (mq.colorGamutP3 === false) {
                issues.push(
                    'macOS 30-bit Apple Silicon Liquid/Retina display reports CSS (color-gamut: p3) === false'
                );
            }
        }
        if (mq.colorGamutP3 === true && Number.isFinite(scr.colorDepth) && scr.colorDepth < 24) {
            issues.push(`Display reports CSS (color-gamut: p3) === true with low colorDepth=${scr.colorDepth}`);
        }

        // 2. Touchscreen (navigator.maxTouchPoints) vs CSS Pointer/Hover & OS Coherence
        if (targetOs === 'mac' && Number(nav.maxTouchPoints) > 0) {
            issues.push(
                `macOS desktop/MacBook identity reports navigator.maxTouchPoints=${nav.maxTouchPoints} (macOS hardware has 0 touch points)`
            );
        }
        if (Number(nav.maxTouchPoints) === 0 && mq.pointerCoarse === true && mq.pointerFine === false) {
            issues.push(
                'navigator.maxTouchPoints is 0 but CSS matchMedia reports (pointer: coarse) without (pointer: fine)'
            );
        }
        if (Number(nav.maxTouchPoints) === 0 && mq.hoverSupported === false) {
            issues.push(
                'Desktop mouse/trackpad profile (maxTouchPoints=0) reports CSS (hover: hover) === false'
            );
        }

        // 3. AudioContext Hardware SampleRate & Channel Limits Coherence
        if (audio && audio.available) {
            const validDesktopSampleRates = [44100, 48000, 88200, 96000, 192000];
            if (
                audio.sampleRate !== null &&
                audio.sampleRate !== undefined &&
                !validDesktopSampleRates.includes(Number(audio.sampleRate))
            ) {
                issues.push(
                    `AudioContext sampleRate=${audio.sampleRate}Hz is non-standard for desktop OS audio hardware (expected 44100Hz or 48000Hz)`
                );
            }
            if (audio.maxChannelCount !== null && audio.maxChannelCount !== undefined) {
                const maxCh = Number(audio.maxChannelCount);
                if (!Number.isFinite(maxCh) || maxCh < 2 || maxCh > 64) {
                    issues.push(
                        `AudioContext destination.maxChannelCount=${audio.maxChannelCount} is invalid for desktop audio output (expected 2..64 channels)`
                    );
                }
            }
            if (
                Number.isFinite(audio.channelCount) &&
                Number.isFinite(audio.maxChannelCount) &&
                audio.channelCount > audio.maxChannelCount
            ) {
                issues.push(
                    `AudioContext destination.channelCount (${audio.channelCount}) exceeds maxChannelCount (${audio.maxChannelCount})`
                );
            }
        }

        const passed = issues.length === 0;
        checks.push({
            name: 'display-gamut-touch-and-audio-coherence',
            passed,
            details: passed
                ? 'Display color gamut (sRGB/P3), pointer/hover/maxTouchPoints, and AudioContext hardware sampleRate/channels are 100% coherent'
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
 * Extract pre-TLS egress HTTP request events from an array of events, a summary object
 * (`{ egressEvents }`), or a live/stopped `CamoufoxTrafficRecorder` instance.
 *
 * @param {Array<object> | object | null | undefined} trafficEventsOrSummary
 * @returns {Array<object>}
 */
function extractEgressRequestEvents(trafficEventsOrSummary) {
    if (!trafficEventsOrSummary) {
        return [];
    }

    const isEgressEvent = (ev) => {
        if (!ev || typeof ev !== 'object') return false;
        const type = ev.type || ev.eventType || ev.direction || null;
        if (!type) {
            return Boolean(ev.headers || ev.headersArray || ev.requestHeaders || ev.egressWireBlock);
        }
        return type === 'egress' || type === 'request' || ev.direction === 'egress';
    };

    if (Array.isArray(trafficEventsOrSummary)) {
        return trafficEventsOrSummary.filter(isEgressEvent);
    }

    if (typeof trafficEventsOrSummary === 'object') {
        if (Array.isArray(trafficEventsOrSummary.egressEvents)) {
            return trafficEventsOrSummary.egressEvents.filter((ev) => ev && typeof ev === 'object');
        }
        if (Array.isArray(trafficEventsOrSummary.events)) {
            return trafficEventsOrSummary.events.filter(isEgressEvent);
        }
        if (Array.isArray(trafficEventsOrSummary.requests)) {
            return trafficEventsOrSummary.requests.filter((ev) => ev && typeof ev === 'object');
        }

        const ndjsonPath =
            trafficEventsOrSummary.paths?.trafficNdjsonPath ||
            trafficEventsOrSummary.trafficNdjsonPath ||
            null;

        if (typeof ndjsonPath === 'string' && ndjsonPath.length > 0) {
            try {
                if (fs.existsSync(ndjsonPath)) {
                    const content = fs.readFileSync(ndjsonPath, 'utf8');
                    const parsedEvents = [];
                    for (const line of content.split(/\r?\n/)) {
                        const trimmed = line.trim();
                        if (!trimmed) continue;
                        try {
                            const ev = JSON.parse(trimmed);
                            if (isEgressEvent(ev)) {
                                parsedEvents.push(ev);
                            }
                        } catch {
                            // Ignore malformed NDJSON line
                        }
                    }
                    if (parsedEvents.length > 0) {
                        return parsedEvents;
                    }
                }
            } catch {
                // Fall back to in-memory transactions if reading traffic.ndjson fails
            }
        }

        if (trafficEventsOrSummary.transactions) {
            const txIterable =
                trafficEventsOrSummary.transactions instanceof Map
                    ? Array.from(trafficEventsOrSummary.transactions.values())
                    : Array.isArray(trafficEventsOrSummary.transactions)
                      ? trafficEventsOrSummary.transactions
                      : typeof trafficEventsOrSummary.transactions === 'object'
                        ? Object.values(trafficEventsOrSummary.transactions)
                        : [];
            return txIterable.filter(
                (tx) =>
                    tx &&
                    typeof tx === 'object' &&
                    Boolean(tx.headers || tx.headersArray || tx.requestHeaders || tx.egressWireBlock)
            );
        }
    }

    return [];
}

/**
 * Normalize headers from an egress event (`headers`, `headersArray`, `requestHeaders`, or `egressWireBlock`)
 * into a uniform list of `{ name, lowerName, value }`.
 *
 * @param {object} event
 * @returns {Array<{ name: string, lowerName: string, value: string }>}
 */
function normalizeEgressHeaders(event) {
    if (!event || typeof event !== 'object') {
        return [];
    }

    const result = [];
    const seen = new Set();

    const pushHeader = (rawName, rawValue) => {
        const name = String(rawName ?? '').trim();
        if (!name) return;
        const lowerName = name.toLowerCase();
        const value = String(rawValue ?? '').trim();
        const dedupKey = `${lowerName}\u0000${value}`;
        if (seen.has(dedupKey)) return;
        seen.add(dedupKey);
        result.push({ name, lowerName, value });
    };

    if (Array.isArray(event.headersArray)) {
        for (const entry of event.headersArray) {
            if (entry && typeof entry === 'object') {
                pushHeader(entry.name, entry.value);
            }
        }
    }

    const headerObjs = [event.headers, event.requestHeaders];
    for (const hdrObj of headerObjs) {
        if (hdrObj && typeof hdrObj === 'object' && !Array.isArray(hdrObj)) {
            for (const [k, v] of Object.entries(hdrObj)) {
                pushHeader(k, v);
            }
        } else if (Array.isArray(hdrObj)) {
            for (const entry of hdrObj) {
                if (entry && typeof entry === 'object') {
                    pushHeader(entry.name, entry.value);
                }
            }
        }
    }

    if (result.length === 0 && typeof event.egressWireBlock === 'string') {
        const lines = event.egressWireBlock.split(/\r?\n/);
        let inHeaders = false;
        for (const line of lines) {
            const trimmed = line.trim();
            if (!inHeaders) {
                if (/^[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?$/i.test(trimmed)) {
                    inHeaders = true;
                }
                continue;
            }
            if (!trimmed || trimmed.startsWith('====')) {
                break;
            }
            const colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                const hName = line.slice(0, colonIdx).trim();
                const hVal = line.slice(colonIdx + 1).trim();
                pushHeader(hName, hVal);
            }
        }
    }

    return result;
}

/**
 * Cross-check in-browser DOM telemetry (`domTelemetry.navigator`) against recorded pre-TLS
 * egress HTTP request events (`traffic.ndjson` / `CamoufoxTrafficRecorder` / array of egress events).
 *
 * @param {object} domTelemetry Output of `collectBrowserFingerprint(page)` (or object containing `.navigator`)
 * @param {Array<object> | object} trafficEventsOrSummary Array of egress events, `{ egressEvents }`, or `CamoufoxTrafficRecorder`
 * @param {string | null} [expectedOs=null] Optional expected OS ('win' | 'mac' | 'lin')
 * @returns {{
 *   passed: boolean,
 *   score: number,
 *   inspectedRequests: number,
 *   checks: Array<{ name: string, passed: boolean, details: string }>
 * }}
 */
export function evaluateWireToDomCoherence(domTelemetry, trafficEventsOrSummary, expectedOs = null) {
    if (!domTelemetry || typeof domTelemetry !== 'object') {
        throw new TypeError('evaluateWireToDomCoherence requires a domTelemetry object');
    }

    const nav = domTelemetry.navigator || domTelemetry.telemetry?.navigator || domTelemetry || {};
    const domUa = String(nav.userAgent || '').trim();
    const domPrimaryLang = String(
        nav.language || (Array.isArray(nav.languages) && nav.languages[0]) || ''
    ).trim();
    const targetOs = normalizeTargetOs(expectedOs);

    const egressEvents = extractEgressRequestEvents(trafficEventsOrSummary);
    const inspectedRequests = egressEvents.length;

    const uaMismatches = [];
    const langMismatches = [];
    const clientHintsLeaks = [];
    const proxyHeaderLeaks = [];

    if (!domUa) {
        uaMismatches.push('DOM navigator.userAgent is missing or empty');
    }
    if (!domPrimaryLang) {
        langMismatches.push('DOM navigator.language / navigator.languages[0] is missing or empty');
    }

    const proxyLeakRegex = /^(x-forwarded-for|via|x-real-ip|forwarded)$/i;

    for (let idx = 0; idx < egressEvents.length; idx += 1) {
        const ev = egressEvents[idx];
        const reqLabel = ev.url || ev.correlationId || `req#${idx + 1}`;
        const headers = normalizeEgressHeaders(ev);

        for (const h of headers) {
            if (h.lowerName === 'user-agent') {
                if (domUa && h.value !== domUa) {
                    uaMismatches.push(
                        `Wire User-Agent "${h.value}" on ${reqLabel} does not match DOM navigator.userAgent "${domUa}"`
                    );
                }
                if (targetOs === 'win' && !h.value.includes('Windows NT')) {
                    uaMismatches.push(
                        `Wire User-Agent "${h.value}" on ${reqLabel} contradicts expected Windows OS`
                    );
                } else if (targetOs === 'mac' && !h.value.includes('Macintosh')) {
                    uaMismatches.push(
                        `Wire User-Agent "${h.value}" on ${reqLabel} contradicts expected macOS`
                    );
                } else if (targetOs === 'lin' && !h.value.includes('Linux')) {
                    uaMismatches.push(
                        `Wire User-Agent "${h.value}" on ${reqLabel} contradicts expected Linux OS`
                    );
                }
            } else if (h.lowerName === 'accept-language') {
                if (domPrimaryLang) {
                    const wireValueLower = h.value.toLowerCase();
                    const domLangLower = domPrimaryLang.toLowerCase();
                    const wirePrimaryTag = wireValueLower.split(',')[0].split(';')[0].trim();
                    if (!wireValueLower.startsWith(domLangLower) || wirePrimaryTag !== domLangLower) {
                        langMismatches.push(
                            `Wire Accept-Language "${h.value}" on ${reqLabel} does not start with DOM primary language "${domPrimaryLang}"`
                        );
                    }
                }
            } else if (h.lowerName.startsWith('sec-ch-ua')) {
                clientHintsLeaks.push(
                    `Chromium Client Hint header "${h.name}: ${h.value}" leaked on Gecko egress request (${reqLabel})`
                );
            } else if (proxyLeakRegex.test(h.lowerName)) {
                proxyHeaderLeaks.push(
                    `Proxy leak header "${h.name}: ${h.value}" detected on egress request (${reqLabel})`
                );
            }
        }
    }

    const checks = [
        {
            name: 'wire-ua-matches-dom-ua',
            passed: uaMismatches.length === 0,
            details:
                uaMismatches.length === 0
                    ? `All ${inspectedRequests} pre-TLS egress requests match DOM navigator.userAgent`
                    : uaMismatches.join('; ')
        },
        {
            name: 'wire-accept-language-matches-dom',
            passed: langMismatches.length === 0,
            details:
                langMismatches.length === 0
                    ? `All ${inspectedRequests} pre-TLS egress requests start with DOM primary language "${domPrimaryLang}"`
                    : langMismatches.join('; ')
        },
        {
            name: 'wire-no-chromium-client-hints',
            passed: clientHintsLeaks.length === 0,
            details:
                clientHintsLeaks.length === 0
                    ? 'Zero Sec-CH-UA* Chromium Client Hints headers present on pre-TLS Gecko egress traffic'
                    : clientHintsLeaks.join('; ')
        },
        {
            name: 'wire-no-proxy-leak-headers',
            passed: proxyHeaderLeaks.length === 0,
            details:
                proxyHeaderLeaks.length === 0
                    ? 'Zero proxy attribution headers (X-Forwarded-For, Via, X-Real-IP, Forwarded) present on egress traffic'
                    : proxyHeaderLeaks.join('; ')
        }
    ];

    const passedCount = checks.filter((c) => c.passed).length;
    const score = checks.length > 0 ? Math.round((passedCount / checks.length) * 100) : 0;
    const passed = passedCount === checks.length;

    return {
        passed,
        score,
        inspectedRequests,
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
    APPLE_SILICON_SKU_CATALOG,
    INTEL_MAC_SKU_CATALOG,
    QUALCOMM_SNAPDRAGON_SKU_CATALOG,
    OEM_DEVICE_MODEL_CATALOG,
    PC_CPU_SKU_CATALOG,
    PC_GPU_SKU_CATALOG,
    PCI_DEVICE_ID_CATALOG,
    PCI_VENDOR_ID_BY_GPU_VENDOR,
    parseAppleSiliconSkuName,
    lookupIntelMacSku,
    lookupSnapdragonSku,
    lookupOemDeviceSku,
    lookupPcCpuSku,
    lookupPcGpuSku,
    validateHardwareModelSpec,
    normalizeTargetOs,
    gpuFitsOs,
    collectBrowserFingerprint,
    evaluatePlatformCoherence,
    evaluateWireToDomCoherence,
    auditProfileCoherence
};
