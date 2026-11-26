/**
 * Exhaustive Isolation Unit Test Suite for Camoufox Coherence Auditor
 *
 * Verifies all cross-field hardware/OS invariants, Worker thread parity (including
 * IEEE-754 floating-point math & timezone), prototype native-code integrity,
 * engine coherence, GPU-to-OS/CPU rules, and CSS media-query parity.
 *
 * Run:
 *   node scripts/test-coherence-auditor.js
 */

import assert from 'node:assert/strict';
import {
    CAMOUFOX_COHERENCE_CONSTANTS,
    APPLE_SILICON_SKU_CATALOG,
    INTEL_MAC_SKU_CATALOG,
    QUALCOMM_SNAPDRAGON_SKU_CATALOG,
    OEM_DEVICE_MODEL_CATALOG,
    PC_CPU_SKU_CATALOG,
    PC_GPU_SKU_CATALOG,
    PCI_DEVICE_ID_CATALOG,
    OS_FONT_CATALOG,
    LOCALE_FALLBACK_CHAINS,
    COUNTRY_GEO_PROFILE_CATALOG,
    OS_SPEECH_VOICES_CATALOG,
    OS_MEDIA_DEVICES_CATALOG,
    USABLE_DEVICE_PRESET_CATALOG,
    parseAppleSiliconSkuName,
    lookupIntelMacSku,
    lookupSnapdragonSku,
    lookupOemDeviceSku,
    lookupPcCpuSku,
    lookupPcGpuSku,
    validateHardwareModelSpec,
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
    attachZiniaoSecurityGuardsToContext,
    GPU_PERFORMANCE_SPEC_CATALOG,
    lookupGpuPerformanceSpec,
    collectHostMacPerformanceBaseline,
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    buildGpuPerformanceInitScript,
    attachGpuPerformanceScalerToContext,
    validateGpuPerformanceScalingCoherence,
    normalizeTargetOs,
    gpuFitsOs,
    evaluatePlatformCoherence,
    evaluateWireToDomCoherence,
    auditProfileCoherence
} from '../src/camoufox/coherence-auditor.js';
import { CamoufoxProfile } from '../src/camoufox/profile.js';

function float64ToHex(val) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setFloat64(0, val, false);
    const hi = view.getUint32(0, false).toString(16).padStart(8, '0');
    const lo = view.getUint32(4, false).toString(16).padStart(8, '0');
    return `0x${hi}${lo}`;
}

/**
 * Build a baseline 100/100 coherent telemetry fixture for 'windows' | 'macos' | 'linux'.
 *
 * @param {'windows' | 'macos' | 'linux'} os
 * @returns {object}
 */
function buildCoherentTelemetry(os = 'windows') {
    const presets = {
        windows: {
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
            platform: 'Win32',
            oscpu: 'Windows NT 10.0; Win64; x64',
            hardwareConcurrency: 8,
            colorDepth: 24,
            devicePixelRatio: 1,
            width: 1920,
            height: 1080,
            availWidth: 1920,
            availHeight: 1040,
            unmaskedVendor: 'Google Inc. (NVIDIA)',
            unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
            candidatePorts: [54321, 61042],
            speechVoices: [
                {
                    name: 'Microsoft David Desktop - English (United States)',
                    lang: 'en-US',
                    voiceURI: 'urn:moz-tts:sapi:Microsoft David Desktop - English (United States)?en-US'
                },
                {
                    name: 'Microsoft Zira Desktop - English (United States)',
                    lang: 'en-US',
                    voiceURI: 'urn:moz-tts:sapi:Microsoft Zira Desktop - English (United States)?en-US'
                }
            ],
            fonts: ['Segoe UI', 'Consolas', 'Calibri', 'Arial', 'Times New Roman']
        },
        macos: {
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0',
            platform: 'MacIntel',
            oscpu: 'Intel Mac OS X 10.15',
            hardwareConcurrency: 10,
            colorDepth: 30,
            devicePixelRatio: 2,
            width: 1512,
            height: 982,
            availWidth: 1512,
            availHeight: 944,
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M2 Pro',
            candidatePorts: [51234, 59876],
            speechVoices: [
                {
                    name: 'Samantha',
                    lang: 'en-US',
                    voiceURI: 'com.apple.speech.synthesis.voice.samantha'
                },
                {
                    name: 'Alex',
                    lang: 'en-US',
                    voiceURI: 'com.apple.speech.synthesis.voice.Alex'
                }
            ],
            fonts: ['SF Pro', 'Helvetica Neue', 'Menlo', 'Monaco', 'Arial', 'Times New Roman']
        },
        linux: {
            userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
            platform: 'Linux x86_64',
            oscpu: 'Linux x86_64',
            hardwareConcurrency: 8,
            colorDepth: 24,
            devicePixelRatio: 1,
            width: 1920,
            height: 1080,
            availWidth: 1920,
            availHeight: 1052,
            unmaskedVendor: 'Intel',
            unmaskedRenderer: 'Mesa Intel(R) UHD Graphics 620 (KBL GT2)',
            candidatePorts: [42100, 55120],
            speechVoices: [
                {
                    name: 'English (America)',
                    lang: 'en-US',
                    voiceURI: 'urn:moz-tts:speechd:English%20(America)?en'
                }
            ],
            fonts: ['Ubuntu', 'Liberation Sans', 'DejaVu Sans', 'Arial', 'Times New Roman']
        }
    };

    const p = presets[os] || presets.windows;
    const sin1e6 = Math.sin(1e6);
    const cos1e6 = Math.cos(1e6);
    const tan1e6 = Math.tan(1e6);
    const powPi = Math.pow(3.141592653589793, -7.3);

    return {
        navigator: {
            userAgent: p.userAgent,
            platform: p.platform,
            oscpu: p.oscpu,
            hardwareConcurrency: p.hardwareConcurrency,
            languages: ['en-US', 'en'],
            language: 'en-US',
            webdriver: false,
            maxTouchPoints: 0,
            pdfViewerEnabled: true,
            cookieEnabled: true,
            hasUserAgentData: false,
            hasWindowChrome: false,
            vendor: '',
            buildID: '20181001000000'
        },
        prototypeIntegrity: {
            toStringIntact: true,
            ownNavigatorOverrides: [],
            userAgentGetter: {
                exists: true,
                isGetter: true,
                source: 'function get userAgent() {\n    [native code]\n}',
                isNative: true
            },
            webdriverGetter: {
                exists: true,
                isGetter: true,
                source: 'function get webdriver() {\n    [native code]\n}',
                isNative: true
            },
            platformGetter: {
                exists: true,
                isGetter: true,
                source: 'function get platform() {\n    [native code]\n}',
                isNative: true
            },
            hardwareConcurrencyGetter: {
                exists: true,
                isGetter: true,
                source: 'function get hardwareConcurrency() {\n    [native code]\n}',
                isNative: true
            },
            webglGetParameter: {
                exists: true,
                isMethod: true,
                source: 'function getParameter() {\n    [native code]\n}',
                isNative: true
            },
            webgl2GetParameter: {
                exists: true,
                isMethod: true,
                source: 'function getParameter() {\n    [native code]\n}',
                isNative: true
            }
        },
        worker: {
            supported: true,
            ok: true,
            userAgent: p.userAgent,
            platform: p.platform,
            hardwareConcurrency: p.hardwareConcurrency,
            languages: ['en-US', 'en'],
            language: 'en-US',
            webdriver: false,
            timeZone: 'America/New_York',
            math: { sin1e6, cos1e6, tan1e6, powPi }
        },
        webgl: {
            available: true,
            vendor: 'Mozilla',
            renderer: 'Mozilla',
            version: 'WebGL 2.0',
            shadingLanguageVersion: 'WebGL GLSL ES 3.00',
            unmaskedVendor: p.unmaskedVendor,
            unmaskedRenderer: p.unmaskedRenderer,
            extensionsCount: 28,
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: os === 'windows' ? [32768, 32768] : [16384, 16384],
            maxVertexAttribs: 16,
            aliasedLineWidthRange: [1, 1]
        },
        canvas2d: {
            available: true,
            fnv1aHash: 'a94f3c1e8b204d71',
            pixelSampleSum: 482910,
            dataUrlLength: 3420
        },
        audio: {
            available: true,
            sampleRate: 48000,
            maxChannelCount: 2,
            channelCount: 2,
            state: 'running'
        },
        mathPrecision: {
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
        },
        screen: {
            width: p.width,
            height: p.height,
            availWidth: p.availWidth,
            availHeight: p.availHeight,
            colorDepth: p.colorDepth,
            pixelDepth: p.colorDepth,
            innerWidth: p.availWidth,
            innerHeight: p.availHeight - 86,
            outerWidth: p.availWidth,
            outerHeight: p.availHeight,
            devicePixelRatio: p.devicePixelRatio,
            mediaQueries: {
                deviceWidthMatches: true,
                deviceHeightMatches: true,
                innerWidthMatches: true,
                innerHeightMatches: true,
                dprResolutionMatches: true,
                orientationLandscape: true,
                orientationPortrait: false,
                colorBitsAtLeast8: true,
                colorGamutSrgb: true,
                colorGamutP3: os === 'macos',
                dynamicRangeHigh: os === 'macos',
                pointerFine: true,
                pointerCoarse: false,
                hoverSupported: true
            }
        },
        intl: {
            timeZone: 'America/New_York',
            locale: 'en-US',
            calendar: 'gregory',
            numberingSystem: 'latn',
            timezoneOffsetMinutes: 300
        },
        automationGlobals: [],
        webrtc: {
            available: true,
            candidatePorts: p.candidatePorts,
            candidateIps: ['203.0.113.45'],
            privateIpLeaked: false
        },
        speechVoices: p.speechVoices,
        fonts: p.fonts,
        iframeParity: {
            ok: true,
            userAgent: p.userAgent,
            platform: p.platform,
            oscpu: p.oscpu,
            hardwareConcurrency: p.hardwareConcurrency,
            webdriver: false,
            language: 'en-US',
            languages: ['en-US', 'en'],
            width: p.width,
            height: p.height,
            colorDepth: p.colorDepth,
            pixelDepth: p.colorDepth,
            userAgentGetterNative: true,
            webdriverGetterNative: true
        },
        geckoApiSurface: {
            hasDeviceMemory: false,
            hasGetBattery: false,
            hasBluetooth: false,
            hasUsb: false,
            hasSerial: false,
            hasHid: false,
            hasOpenDatabase: false,
            hasMozInnerScreenX: true,
            performanceNowMonotonic: true
        },
        webgpu: {
            available: os !== 'linux',
            requestAdapterNative: true
        },
        stackAndMediaHygiene: {
            hasAtSignFormat: true,
            leakedStackMarkers: [],
            enumerateDevicesNative: true,
            unpermittedLabelsLeaked: false,
            mediaDevices: {
                available: true,
                enumerateDevicesNative: true,
                unpermittedLabelsLeaked: false
            }
        },
        hardwareProfile: {
            ramGb: 16,
            storageGb: 512
        },
        storageEstimate: {
            quotaBytes: 21474836480,
            usageBytes: 4096
        }
    };
}

function findCheck(result, checkName) {
    const check = result.checks.find((c) => c.name === checkName);
    assert.ok(check, `Expected check "${checkName}" to be present in evaluation result`);
    return check;
}

const tests = [
    {
        name: '1. Valid Windows (NVIDIA ANGLE) profile passes 100/100',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, true);
            assert.equal(res.score, 100);
            assert.equal(res.checks.length, 17);
            assert.ok(res.checks.every((c) => c.passed));
        }
    },
    {
        name: '2. Valid macOS (Apple M2 Pro, colorDepth=30) profile passes 100/100',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, true);
            assert.equal(res.score, 100);
            assert.ok(res.checks.every((c) => c.passed));
        }
    },
    {
        name: '3. Valid Linux (Mesa Intel) profile passes 100/100',
        fn: () => {
            const telemetry = buildCoherentTelemetry('linux');
            const res = evaluatePlatformCoherence(telemetry, 'linux');
            assert.equal(res.passed, true);
            assert.equal(res.score, 100);
            assert.ok(res.checks.every((c) => c.passed));
        }
    },
    {
        name: '4. Detects navigator.webdriver === true automation leak',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.navigator.webdriver = true;
            telemetry.worker.webdriver = true;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'navigator-prototype-integrity');
            assert.equal(check.passed, false);
            assert.match(check.details, /navigator\.webdriver=true/);
        }
    },
    {
        name: '5. Detects non-native Function.prototype.toString and JS getter tampering',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.prototypeIntegrity.toStringIntact = false;
            telemetry.prototypeIntegrity.userAgentGetter.isNative = false;
            telemetry.prototypeIntegrity.ownNavigatorOverrides = ['userAgent'];
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'navigator-prototype-integrity');
            assert.equal(check.passed, false);
            assert.match(check.details, /Function\.prototype\.toString tampered/);
            assert.match(check.details, /Navigator\.prototype\.userAgent getter is not \[native code\]/);
            assert.match(check.details, /navigator own-property overrides detected/);
        }
    },
    {
        name: '6. Detects Dedicated Worker userAgent & platform divergence from main thread',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.worker.userAgent =
                'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0';
            telemetry.worker.platform = 'Linux x86_64';
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'dedicated-worker-parity');
            assert.equal(check.passed, false);
            assert.match(check.details, /userAgent mismatch/);
            assert.match(check.details, /platform mismatch/);
        }
    },
    {
        name: '7. Detects Dedicated Worker hardwareConcurrency & timeZone divergence',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.worker.hardwareConcurrency = 4;
            telemetry.worker.timeZone = 'Europe/London';
            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'dedicated-worker-parity');
            assert.equal(check.passed, false);
            assert.match(check.details, /hardwareConcurrency mismatch/);
            assert.match(check.details, /timeZone mismatch/);
        }
    },
    {
        name: '8. Detects Dedicated Worker IEEE-754 floating-point math divergence',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            // Simulate main-thread JS math override or missing worker FDLIBM/CRT patch parity
            telemetry.worker.math.sin1e6 = telemetry.mathPrecision.sin1e6 + 1e-15;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'dedicated-worker-parity');
            assert.equal(check.passed, false);
            assert.match(check.details, /IEEE-754 Math results differ between main thread and Web Worker/);
            assert.match(check.details, /sin1e6/);
        }
    },
    {
        name: '9. Detects Chromium navigator.userAgentData leak on Gecko engine',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.navigator.hasUserAgentData = true;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'engine-gecko-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /navigator\.userAgentData leaked/);
        }
    },
    {
        name: '10. Detects Chrome User-Agent spoofed on Gecko engine',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            const chromeUa =
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36';
            telemetry.navigator.userAgent = chromeUa;
            telemetry.worker.userAgent = chromeUa;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'engine-gecko-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /User-Agent is not authentic Firefox\/Gecko/);
        }
    },
    {
        name: '11. Detects window.chrome object leaked on Gecko engine',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.navigator.hasWindowChrome = true;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'engine-gecko-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /window\.chrome object leaked/);
        }
    },
    {
        name: '12. Detects Windows non-ANGLE WebGL GPU renderer',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.webgl.unmaskedRenderer = 'Mesa Intel(R) UHD Graphics 620 (KBL GT2)';
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'os-platform-gpu-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Windows WebGL renderer must render through ANGLE/);
        }
    },
    {
        name: '13. Detects macOS ANGLE and llvmpipe WebGL GPU renderers',
        fn: () => {
            const telemetryAngle = buildCoherentTelemetry('macos');
            telemetryAngle.webgl.unmaskedRenderer =
                'ANGLE (Apple, ANGLE Metal Renderer: Apple M2 Pro, Unspecified Version)';
            const resAngle = evaluatePlatformCoherence(telemetryAngle, 'macos');
            assert.equal(resAngle.passed, false);
            assert.equal(findCheck(resAngle, 'os-platform-gpu-coherence').passed, false);

            const telemetryLlvmpipe = buildCoherentTelemetry('macos');
            telemetryLlvmpipe.webgl.unmaskedRenderer = 'llvmpipe (LLVM 15.0.7, 256 bits)';
            const resLlvmpipe = evaluatePlatformCoherence(telemetryLlvmpipe, 'macos');
            assert.equal(resLlvmpipe.passed, false);
            assert.equal(findCheck(resLlvmpipe, 'os-platform-gpu-coherence').passed, false);
        }
    },
    {
        name: '14. Detects Linux Apple Silicon WebGL GPU renderer contradiction',
        fn: () => {
            const telemetry = buildCoherentTelemetry('linux');
            telemetry.webgl.unmaskedRenderer = 'Apple M2 Max';
            const res = evaluatePlatformCoherence(telemetry, 'linux');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'os-platform-gpu-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Linux identity reports incompatible GPU renderer/);
        }
    },
    {
        name: '15. Detects Apple Silicon impossible core counts (6 cores on Apple M2)',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.webgl.unmaskedRenderer = 'Apple M2';
            telemetry.navigator.hardwareConcurrency = 6;
            telemetry.worker.hardwareConcurrency = 6;
            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'os-platform-gpu-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Apple Silicon GPU "Apple M2" with hardwareConcurrency=6/);
        }
    },
    {
        name: '16. Detects Windows Intel-only hybrid core counts (14 cores) vs AMD APU renderer contradiction',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.navigator.hardwareConcurrency = 14;
            telemetry.worker.hardwareConcurrency = 14;
            telemetry.webgl.unmaskedRenderer =
                'ANGLE (AMD, Radeon HD 3200 Graphics Direct3D11 vs_5_0 ps_5_0)';
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'os-platform-gpu-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Intel-only hardwareConcurrency=14 contradicts AMD APU\/iGPU renderer/);
        }
    },
    {
        name: '17. Detects Intel Mac GPU behind notched Apple Silicon panel resolution (1512x982)',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.webgl.unmaskedRenderer = 'Intel(R) Iris(TM) Plus Graphics 655';
            telemetry.navigator.hardwareConcurrency = 8;
            telemetry.worker.hardwareConcurrency = 8;
            telemetry.screen.width = 1512;
            telemetry.screen.height = 982;
            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'os-platform-gpu-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /behind notched Apple Silicon panel 1512x982/);
        }
    },
    {
        name: '18. Detects screen.availHeight > screen.height and pixelDepth !== colorDepth',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.screen.availHeight = telemetry.screen.height + 40;
            telemetry.screen.pixelDepth = 30; // colorDepth is 24
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'screen-media-query-parity');
            assert.equal(check.passed, false);
            assert.match(check.details, /availBounds .* exceed screen bounds/);
            assert.match(check.details, /screen\.pixelDepth \(30\) differs from screen\.colorDepth \(24\)/);
        }
    },
    {
        name: '19. Detects macOS colorDepth=24 violation (macOS Firefox requires 30-bit deep color)',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.screen.colorDepth = 24;
            telemetry.screen.pixelDepth = 24;
            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'screen-media-query-parity');
            assert.equal(check.passed, false);
            assert.match(check.details, /macOS identity has colorDepth=24; macOS Firefox defaults to 30/);
        }
    },
    {
        name: '20. Detects CSS matchMedia device-width, viewport, and resolution DPR mismatches',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.screen.mediaQueries.deviceWidthMatches = false;
            telemetry.screen.mediaQueries.innerHeightMatches = false;
            telemetry.screen.mediaQueries.dprResolutionMatches = false;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'screen-media-query-parity');
            assert.equal(check.passed, false);
            assert.match(check.details, /does not match CSS \(device-width\)\/\(device-height\) matchMedia/);
            assert.match(check.details, /does not match CSS \(width\)\/\(height\) matchMedia/);
            assert.match(check.details, /does not match CSS \(resolution\) matchMedia/);
        }
    },
    {
        name: '21. Verifies normalizeTargetOs, gpuFitsOs, and CAMOUFOX_COHERENCE_CONSTANTS exports',
        fn: () => {
            assert.equal(normalizeTargetOs('Windows 11'), 'win');
            assert.equal(normalizeTargetOs('darwin'), 'mac');
            assert.equal(normalizeTargetOs('Ubuntu'), 'lin');
            assert.equal(normalizeTargetOs('unknown'), null);

            assert.equal(gpuFitsOs('ANGLE (NVIDIA, RTX 4070 Direct3D11)', 'win'), true);
            assert.equal(gpuFitsOs('Apple M3 Max', 'win'), false);
            assert.equal(gpuFitsOs('Apple M3 Max', 'mac'), true);
            assert.equal(gpuFitsOs('ANGLE (Apple, Metal)', 'mac'), false);
            assert.equal(gpuFitsOs('Mesa Intel(R) Arc(TM) A770', 'lin'), true);
            assert.equal(gpuFitsOs('Apple M2', 'lin'), false);
            assert.ok(CAMOUFOX_COHERENCE_CONSTANTS.appleSiliconCores.has(11));
            assert.ok(CAMOUFOX_COHERENCE_CONSTANTS.intelOnlyCoreCounts.has(14));
        }
    },
    {
        name: '22. Verifies auditProfileCoherence end-to-end with mock Page instance',
        fn: async () => {
            const mockPage = {
                async evaluate() {
                    return buildCoherentTelemetry('macos');
                }
            };
            const report = await auditProfileCoherence(mockPage, 'macos');
            assert.equal(report.passed, true);
            assert.equal(report.score, 100);
            assert.equal(report.expectedOs, 'mac');
            assert.equal(report.checks.length, 17);
        }
    },
    {
        name: '23. Detects leaked $cdc_asdjflasutopfhvcZLmcfl_ / __playwright automation globals on window/document',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.automationGlobals = ['$cdc_asdjflasutopfhvcZLmcfl_', '__playwright'];
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'automation-globals-absence');
            assert.equal(check.passed, false);
            assert.match(check.details, /\$cdc_asdjflasutopfhvcZLmcfl_/);
            assert.match(check.details, /__playwright/);
        }
    },
    {
        name: '24. Detects WebRTC RFC1918 private LAN IP (192.168.1.45) leak when proxy/WebRTC protection is active',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.webrtc = {
                available: true,
                candidatePorts: [54321],
                candidateIps: ['192.168.1.45'],
                privateIpLeaked: false,
                blockPrivateIp: true
            };
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'webrtc-network-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /192\.168\.1\.45/);
        }
    },
    {
        name: '25. Detects WebRTC Linux ephemeral UDP port (38120) leaked on a Windows (49152–65535) identity',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.webrtc = {
                available: true,
                candidatePorts: [52100, 38120],
                candidateIps: ['203.0.113.45'],
                privateIpLeaked: false
            };
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'webrtc-network-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /38120/);
            assert.match(check.details, /49152–65535/);
        }
    },
    {
        name: '26. Detects Windows identity leaking macOS Apple com.apple.speech.synthesis.voice.samantha speech voice',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.speechVoices = [
                {
                    name: 'Samantha',
                    lang: 'en-US',
                    voiceURI: 'com.apple.speech.synthesis.voice.samantha'
                }
            ];
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'speech-voices-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Windows identity leaked macOS\/Apple SpeechSynthesis voice/);
        }
    },
    {
        name: '27. Detects macOS identity leaking Windows Microsoft Zira Desktop speech voice',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.speechVoices = [
                {
                    name: 'Microsoft Zira Desktop - English (United States)',
                    lang: 'en-US',
                    voiceURI: 'urn:moz-tts:sapi:Microsoft Zira Desktop - English (United States)?en-US'
                }
            ];
            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'speech-voices-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /macOS identity leaked Windows\/Linux SpeechSynthesis voice/);
        }
    },
    {
        name: '28. Valid Windows, macOS, and Linux profiles with coherent webrtc ephemeral ports, OS-matched speechVoices, and empty automationGlobals pass 11/11 checks (100/100)',
        fn: () => {
            for (const os of ['windows', 'macos', 'linux']) {
                const telemetry = buildCoherentTelemetry(os);
                const res = evaluatePlatformCoherence(telemetry, os);
                assert.equal(res.passed, true, `Expected ${os} profile to pass`);
                assert.equal(res.score, 100, `Expected ${os} score to be 100`);
                assert.equal(res.checks.length, 17, `Expected 17 checks for ${os}`);
                assert.ok(res.checks.every((c) => c.passed));

                // Also verify backward compatibility when older synthetic fixtures omit the optional fields
                const legacyTelemetry = buildCoherentTelemetry(os);
                delete legacyTelemetry.automationGlobals;
                delete legacyTelemetry.webrtc;
                delete legacyTelemetry.speechVoices;
                delete legacyTelemetry.fonts;
                delete legacyTelemetry.iframeParity;
                delete legacyTelemetry.geckoApiSurface;
                delete legacyTelemetry.webgpu;
                delete legacyTelemetry.stackAndMediaHygiene;
                delete legacyTelemetry.hardwareProfile;
                delete legacyTelemetry.storageEstimate;
                const legacyRes = evaluatePlatformCoherence(legacyTelemetry, os);
                assert.equal(legacyRes.passed, true);
                assert.equal(legacyRes.score, 100);
                assert.equal(legacyRes.checks.length, 17);
            }
        }
    },
    {
        name: '29. Detects navigator.pdfViewerEnabled === false and navigator.cookieEnabled === false anomalies',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.navigator.pdfViewerEnabled = false;
            telemetry.navigator.cookieEnabled = false;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'storage-pdf-fonts-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /navigator\.pdfViewerEnabled=false/);
            assert.match(check.details, /navigator\.cookieEnabled=false/);
        }
    },
    {
        name: '30. Detects Windows identity leaking macOS Helvetica Neue and Menlo system fonts',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.fonts = ['Segoe UI', 'Helvetica Neue', 'Menlo', 'Arial'];
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'storage-pdf-fonts-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Windows identity leaked macOS-exclusive font "Helvetica Neue"/);
            assert.match(check.details, /Windows identity leaked macOS-exclusive font "Menlo"/);
        }
    },
    {
        name: '31. Detects macOS identity leaking Windows Segoe UI and Consolas system fonts',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.fonts = ['SF Pro', 'Segoe UI', 'Consolas', 'Arial'];
            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'storage-pdf-fonts-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /macOS identity leaked Windows-exclusive font "Segoe UI"/);
            assert.match(check.details, /macOS identity leaked Windows-exclusive font "Consolas"/);
        }
    },
    {
        name: '32. evaluateWireToDomCoherence passes 100/100 when pre-TLS egress wire User-Agent and Accept-Language match DOM navigator',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            const egressEvents = [
                {
                    type: 'egress',
                    url: 'https://accounts.google.com/signup/v2/webcreateaccount',
                    headers: {
                        'User-Agent': telemetry.navigator.userAgent,
                        'Accept-Language': 'en-US,en;q=0.5',
                        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                },
                {
                    type: 'egress',
                    url: 'https://accounts.google.com/_/signup/validatepersonaldetails',
                    headersArray: [
                        { name: 'User-Agent', value: telemetry.navigator.userAgent },
                        { name: 'Accept-Language', value: 'en-US,en;q=0.5' }
                    ]
                }
            ];
            const res = evaluateWireToDomCoherence(telemetry, egressEvents, 'windows');
            assert.equal(res.passed, true);
            assert.equal(res.score, 100);
            assert.equal(res.inspectedRequests, 2);
            assert.equal(res.checks.length, 4);
            assert.ok(res.checks.every((c) => c.passed));
        }
    },
    {
        name: '33. evaluateWireToDomCoherence detects wire User-Agent vs DOM navigator.userAgent mismatch and Accept-Language vs navigator.language mismatch',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            const egressEvents = [
                {
                    type: 'egress',
                    url: 'https://accounts.google.com/signup',
                    headers: {
                        'User-Agent':
                            'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
                        'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.5'
                    }
                }
            ];
            const res = evaluateWireToDomCoherence(telemetry, { egressEvents }, 'windows');
            assert.equal(res.passed, false);
            assert.equal(res.inspectedRequests, 1);

            const uaCheck = findCheck(res, 'wire-ua-matches-dom-ua');
            assert.equal(uaCheck.passed, false);
            assert.match(uaCheck.details, /does not match DOM navigator\.userAgent/);

            const langCheck = findCheck(res, 'wire-accept-language-matches-dom');
            assert.equal(langCheck.passed, false);
            assert.match(langCheck.details, /does not start with DOM primary language "en-US"/);
        }
    },
    {
        name: '34. evaluateWireToDomCoherence detects Sec-CH-UA Client Hints and X-Forwarded-For proxy leak headers on pre-TLS egress traffic',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            const mockRecorder = {
                transactions: new Map([
                    [
                        'corr-1',
                        {
                            correlationId: 'corr-1',
                            url: 'https://accounts.google.com/v3/signin',
                            headers: {
                                'User-Agent': telemetry.navigator.userAgent,
                                'Accept-Language': 'en-US,en;q=0.5',
                                'Sec-CH-UA': '"Chromium";v="135", "Not-A.Brand";v="8"',
                                'Sec-CH-UA-Platform': '"Windows"',
                                'X-Forwarded-For': '198.51.100.24',
                                Via: '1.1 squid-proxy'
                            }
                        }
                    ]
                ])
            };
            const res = evaluateWireToDomCoherence(telemetry, mockRecorder, 'windows');
            assert.equal(res.passed, false);
            assert.equal(res.inspectedRequests, 1);

            const chCheck = findCheck(res, 'wire-no-chromium-client-hints');
            assert.equal(chCheck.passed, false);
            assert.match(chCheck.details, /Sec-CH-UA/);

            const proxyCheck = findCheck(res, 'wire-no-proxy-leak-headers');
            assert.equal(proxyCheck.passed, false);
            assert.match(proxyCheck.details, /X-Forwarded-For/);
            assert.match(proxyCheck.details, /Via/);
        }
    },
    {
        name: '35. Detects iframe.contentWindow.navigator (userAgent / platform / webdriver) divergence from top-level window.navigator',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.iframeParity.userAgent =
                'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0';
            telemetry.iframeParity.platform = 'Linux x86_64';
            telemetry.iframeParity.webdriver = true;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'iframe-contentwindow-parity');
            assert.equal(check.passed, false);
            assert.match(check.details, /iframe navigator\.userAgent mismatch/);
            assert.match(check.details, /iframe navigator\.platform mismatch/);
            assert.match(check.details, /iframe navigator\.webdriver mismatch/);
        }
    },
    {
        name: '36. Detects iframe.contentWindow.screen (width / colorDepth) or non-native getter divergence in dynamic iframe',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.iframeParity.width = 1920;
            telemetry.iframeParity.colorDepth = 24;
            telemetry.iframeParity.userAgentGetterNative = false;
            telemetry.iframeParity.webdriverGetterNative = false;
            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'iframe-contentwindow-parity');
            assert.equal(check.passed, false);
            assert.match(check.details, /iframe screen\.width mismatch/);
            assert.match(check.details, /iframe screen\.colorDepth mismatch/);
            assert.match(check.details, /iframe Navigator\.prototype\.userAgent getter is not \[native code\]/);
            assert.match(check.details, /iframe Navigator\.prototype\.webdriver getter is not \[native code\]/);
        }
    },
    {
        name: '37. Detects Chromium navigator.deviceMemory and navigator.getBattery leaked on Gecko',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.geckoApiSurface.hasDeviceMemory = true;
            telemetry.geckoApiSurface.hasGetBattery = true;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'gecko-api-surface-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Chromium navigator\.deviceMemory leaked on Gecko/);
            assert.match(check.details, /Chromium navigator\.getBattery leaked on Gecko/);
        }
    },
    {
        name: '38. Detects Chromium navigator.bluetooth, navigator.usb, navigator.serial, navigator.hid, or window.openDatabase leaked on Gecko',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.geckoApiSurface.hasBluetooth = true;
            telemetry.geckoApiSurface.hasUsb = true;
            telemetry.geckoApiSurface.hasSerial = true;
            telemetry.geckoApiSurface.hasHid = true;
            telemetry.geckoApiSurface.hasOpenDatabase = true;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'gecko-api-surface-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Chromium navigator\.bluetooth leaked on Gecko/);
            assert.match(check.details, /Chromium navigator\.usb leaked on Gecko/);
            assert.match(check.details, /Chromium navigator\.serial leaked on Gecko/);
            assert.match(check.details, /Chromium navigator\.hid leaked on Gecko/);
            assert.match(check.details, /Chromium window\.openDatabase WebSQL API leaked on Gecko/);
        }
    },
    {
        name: '39. Detects missing Firefox window.mozInnerScreenX or non-monotonic performance.now()',
        fn: () => {
            const telemetry = buildCoherentTelemetry('linux');
            telemetry.geckoApiSurface.hasMozInnerScreenX = false;
            telemetry.geckoApiSurface.performanceNowMonotonic = false;
            const res = evaluatePlatformCoherence(telemetry, 'linux');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'gecko-api-surface-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /Firefox window\.mozInnerScreenX property missing/);
            assert.match(check.details, /performance\.now\(\) high-precision timer is non-monotonic or invalid/);
        }
    },
    {
        name: '40. Valid Windows, macOS, and Linux profiles with full 13/13 checks (iframeParity + geckoApiSurface included) pass 100/100',
        fn: () => {
            assert.deepEqual(CAMOUFOX_COHERENCE_CONSTANTS.forbiddenChromiumApisOnGecko, [
                'deviceMemory',
                'getBattery',
                'bluetooth',
                'usb',
                'serial',
                'hid',
                'openDatabase'
            ]);
            for (const os of ['windows', 'macos', 'linux']) {
                const telemetry = buildCoherentTelemetry(os);
                const res = evaluatePlatformCoherence(telemetry, os);
                assert.equal(res.passed, true, `Expected ${os} profile to pass`);
                assert.equal(res.score, 100, `Expected ${os} score to be 100`);
                assert.equal(res.checks.length, 17, `Expected 17 checks for ${os}`);
                assert.ok(res.checks.every((c) => c.passed));
                assert.equal(findCheck(res, 'iframe-contentwindow-parity').passed, true);
                assert.equal(findCheck(res, 'gecko-api-surface-coherence').passed, true);
            }
        }
    },
    {
        name: '41. Detects navigator.gpu (WebGPU) exposed on a Linux Firefox profile or non-native requestAdapter',
        fn: () => {
            const linuxTelemetry = buildCoherentTelemetry('linux');
            linuxTelemetry.webgpu = {
                available: true,
                requestAdapterNative: true
            };
            const linuxRes = evaluatePlatformCoherence(linuxTelemetry, 'linux');
            assert.equal(linuxRes.passed, false);
            const linuxCheck = findCheck(linuxRes, 'webgpu-os-coherence');
            assert.equal(linuxCheck.passed, false);
            assert.match(linuxCheck.details, /Linux identity exposes navigator\.gpu/);

            const winTelemetry = buildCoherentTelemetry('windows');
            winTelemetry.webgpu = {
                available: true,
                requestAdapterNative: false
            };
            const winRes = evaluatePlatformCoherence(winTelemetry, 'windows');
            assert.equal(winRes.passed, false);
            const winCheck = findCheck(winRes, 'webgpu-os-coherence');
            assert.equal(winCheck.passed, false);
            assert.match(winCheck.details, /navigator\.gpu\.requestAdapter is not \[native code\]/);
        }
    },
    {
        name: '42. Detects navigator.gpu (WebGPU) exposed on an Intel Mac (non-Apple-Silicon) profile',
        fn: () => {
            const macTelemetry = buildCoherentTelemetry('macos');
            macTelemetry.webgl.unmaskedRenderer = 'Intel(R) Iris(TM) Plus Graphics 655';
            macTelemetry.navigator.hardwareConcurrency = 8;
            macTelemetry.worker.hardwareConcurrency = 8;
            macTelemetry.iframeParity.hardwareConcurrency = 8;
            macTelemetry.screen.width = 1440;
            macTelemetry.screen.height = 900;
            macTelemetry.screen.availWidth = 1440;
            macTelemetry.screen.availHeight = 860;
            macTelemetry.iframeParity.width = 1440;
            macTelemetry.iframeParity.height = 900;
            macTelemetry.webgpu = {
                available: true,
                requestAdapterNative: true
            };
            const res = evaluatePlatformCoherence(macTelemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'webgpu-os-coherence');
            assert.equal(check.passed, false);
            assert.match(check.details, /macOS identity exposes navigator\.gpu \(WebGPU\) on non-Apple-Silicon renderer/);
        }
    },
    {
        name: '43. Detects V8 "    at " Error.stack format or leaked __puppeteer_evaluation_script__ / __playwright stack frames',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.stackAndMediaHygiene.hasAtSignFormat = false;
            telemetry.stackAndMediaHygiene.leakedStackMarkers = [
                '__puppeteer_evaluation_script__',
                '__playwright'
            ];
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'stack-trace-and-mediadevices-hygiene');
            assert.equal(check.passed, false);
            assert.match(check.details, /Error\.prototype\.stack uses V8\/Chromium/);
            assert.match(check.details, /__puppeteer_evaluation_script__/);
            assert.match(check.details, /__playwright/);
        }
    },
    {
        name: '44. Detects non-native MediaDevices.prototype.enumerateDevices or unpermitted device hardware labels leaked before permission grant',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.stackAndMediaHygiene.enumerateDevicesNative = false;
            telemetry.stackAndMediaHygiene.unpermittedLabelsLeaked = true;
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'stack-trace-and-mediadevices-hygiene');
            assert.equal(check.passed, false);
            assert.match(check.details, /MediaDevices\.prototype\.enumerateDevices is not \[native code\]/);
            assert.match(check.details, /leaked non-empty hardware device labels without active media permission/);
        }
    },
    {
        name: '45. Full 17/17 coherence check validation across Windows, macOS, and Linux profiles (100/100)',
        fn: () => {
            assert.deepEqual(CAMOUFOX_COHERENCE_CONSTANTS.forbiddenStackMarkers, [
                '__puppeteer_evaluation_script__',
                '__playwright',
                'UtilityScript',
                'pptr:',
                'evaluateOnNewDocument',
                'juggler://',
                'webdriver'
            ]);
            for (const os of ['windows', 'macos', 'linux']) {
                const telemetry = buildCoherentTelemetry(os);
                const res = evaluatePlatformCoherence(telemetry, os);
                assert.equal(res.passed, true, `Expected ${os} profile to pass all 17 checks`);
                assert.equal(res.score, 100, `Expected ${os} score to be 100`);
                assert.equal(res.checks.length, 17, `Expected 17 checks for ${os}`);
                assert.ok(res.checks.every((c) => c.passed));
                assert.equal(findCheck(res, 'webgpu-os-coherence').passed, true);
                assert.equal(findCheck(res, 'stack-trace-and-mediadevices-hygiene').passed, true);
                assert.equal(findCheck(res, 'exact-hardware-sku-model-coherence').passed, true);
                assert.equal(findCheck(res, 'display-gamut-touch-and-audio-coherence').passed, true);
            }
        }
    },
    {
        name: '46. End-to-end CamoufoxProfile.auditCoherence() integration with evaluateWireToDomCoherence on an active profile',
        fn: async () => {
            const telemetry = buildCoherentTelemetry('windows');
            const profile = new CamoufoxProfile('unit-test-profile-win', { os: 'windows' });
            profile.metadata = { os: 'windows' };
            profile.page = {
                isClosed: () => false,
                async evaluate() {
                    return telemetry;
                }
            };
            profile.trafficRecorder = {
                transactions: new Map([
                    [
                        'tx-1',
                        {
                            correlationId: 'tx-1',
                            url: 'https://accounts.google.com/v3/signin',
                            headers: {
                                'User-Agent': telemetry.navigator.userAgent,
                                'Accept-Language': 'en-US,en;q=0.5'
                            }
                        }
                    ]
                ])
            };

            const report = await profile.auditCoherence();
            assert.equal(report.passed, true);
            assert.equal(report.score, 100);
            assert.equal(report.expectedOs, 'win');
            assert.equal(report.checks.length, 17);
            assert.ok(report.wireToDomCoherence, 'Expected wireToDomCoherence report to be attached');
            assert.equal(report.wireToDomCoherence.passed, true);
            assert.equal(report.wireToDomCoherence.score, 100);
            assert.equal(report.wireToDomCoherence.inspectedRequests, 1);
            assert.equal(report.wireToDomCoherence.checks.length, 4);
        }
    },
    {
        name: '47. Exact SKU Audit: Rejects Apple M1 CPU paired with Apple M2 GPU (Unified SoC die cannot mix different Apple M chips)',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.hardwareProfile = {
                cpuModel: 'Apple M1',
                gpuModel: 'Apple M2',
                ramGb: 16,
                storageGb: 512
            };
            telemetry.webgl.unmaskedRenderer = 'Apple M2';
            telemetry.navigator.hardwareConcurrency = 8;
            telemetry.worker.hardwareConcurrency = 8;
            telemetry.iframeParity.hardwareConcurrency = 8;
            telemetry.screen.width = 1440;
            telemetry.screen.height = 900;
            telemetry.screen.availWidth = 1440;
            telemetry.screen.availHeight = 860;
            telemetry.iframeParity.width = 1440;
            telemetry.iframeParity.height = 900;

            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'exact-hardware-sku-model-coherence');
            assert.equal(check.passed, false);
            assert.match(
                check.details,
                /Apple Silicon SoC CPU\/GPU model mismatch: CPU is "Apple M1" but WebGL GPU renderer is "Apple M2"/
            );
        }
    },
    {
        name: '48. Exact SKU Audit: Rejects base Apple M1 with 32GB/64GB/128GB RAM (M1 maxes out at 16GB) or 10/12 cores (M1 is 8-core only)',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.webgl.unmaskedRenderer = 'Apple M1';
            telemetry.hardwareProfile = {
                cpuModel: 'Apple M1',
                gpuModel: 'Apple M1',
                ramGb: 128,
                storageGb: 512
            };
            telemetry.navigator.hardwareConcurrency = 12;
            telemetry.worker.hardwareConcurrency = 12;
            telemetry.iframeParity.hardwareConcurrency = 12;
            telemetry.screen.width = 1440;
            telemetry.screen.height = 900;
            telemetry.screen.availWidth = 1440;
            telemetry.screen.availHeight = 860;
            telemetry.iframeParity.width = 1440;
            telemetry.iframeParity.height = 900;

            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'exact-hardware-sku-model-coherence');
            assert.equal(check.passed, false);
            assert.match(
                check.details,
                /Apple M1 exact core count violation: navigator\.hardwareConcurrency=12 is invalid for Apple M1 \(physical options: \[8\] cores\)/
            );
            assert.match(
                check.details,
                /Apple M1 exact Unified Memory \(RAM\) violation: ramGb=128GB does not exist on Apple M1 \(factory RAM tiers: \[8GB, 16GB\]\)/
            );
        }
    },
    {
        name: '49. Exact SKU Audit: Rejects Apple M1 Max with 128GB RAM (M1 Max ceiling is 64GB) or 8 cores (M1 Max is 10-core only)',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.webgl.unmaskedRenderer = 'Apple M1 Max';
            telemetry.hardwareProfile = {
                cpuModel: 'Apple M1 Max',
                gpuModel: 'Apple M1 Max',
                ramGb: 128,
                storageGb: 1024
            };
            telemetry.navigator.hardwareConcurrency = 8;
            telemetry.worker.hardwareConcurrency = 8;
            telemetry.iframeParity.hardwareConcurrency = 8;

            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'exact-hardware-sku-model-coherence');
            assert.equal(check.passed, false);
            assert.match(
                check.details,
                /Apple M1 Max exact core count violation: navigator\.hardwareConcurrency=8 is invalid for Apple M1 Max \(physical options: \[10\] cores\)/
            );
            assert.match(
                check.details,
                /Apple M1 Max exact Unified Memory \(RAM\) violation: ramGb=128GB does not exist on Apple M1 Max \(factory RAM tiers: \[32GB, 64GB\]\)/
            );
        }
    },
    {
        name: '50. Exact SKU Audit: Rejects Apple M3 Pro with 16GB or 32GB RAM (192-bit bus only supports 18GB/36GB) and 14-core M3 Max with 128GB RAM',
        fn: () => {
            const m3Pro = buildCoherentTelemetry('macos');
            m3Pro.webgl.unmaskedRenderer = 'Apple M3 Pro';
            m3Pro.hardwareProfile = {
                cpuModel: 'Apple M3 Pro',
                gpuModel: 'Apple M3 Pro',
                ramGb: 32,
                storageGb: 512
            };
            m3Pro.navigator.hardwareConcurrency = 12;
            m3Pro.worker.hardwareConcurrency = 12;
            m3Pro.iframeParity.hardwareConcurrency = 12;

            const resPro = evaluatePlatformCoherence(m3Pro, 'macos');
            assert.equal(resPro.passed, false);
            const checkPro = findCheck(resPro, 'exact-hardware-sku-model-coherence');
            assert.equal(checkPro.passed, false);
            assert.match(
                checkPro.details,
                /Apple M3 Pro exact Unified Memory \(RAM\) violation: ramGb=32GB does not exist on Apple M3 Pro \(factory RAM tiers: \[18GB, 36GB\]\)/
            );

            // 14-core M3 Max only supports 36GB or 96GB (128GB requires 16-core M3 Max 512-bit bus)
            const m3Max14 = buildCoherentTelemetry('macos');
            m3Max14.webgl.unmaskedRenderer = 'Apple M3 Max';
            m3Max14.hardwareProfile = {
                cpuModel: 'Apple M3 Max',
                gpuModel: 'Apple M3 Max',
                ramGb: 128,
                storageGb: 1024
            };
            m3Max14.navigator.hardwareConcurrency = 14;
            m3Max14.worker.hardwareConcurrency = 14;
            m3Max14.iframeParity.hardwareConcurrency = 14;

            const resMax = evaluatePlatformCoherence(m3Max14, 'macos');
            assert.equal(resMax.passed, false);
            const checkMax = findCheck(resMax, 'exact-hardware-sku-model-coherence');
            assert.equal(checkMax.passed, false);
            assert.match(
                checkMax.details,
                /Apple M3 Max \(14-core die\) cannot be configured with 128GB Unified Memory \(allowed RAM for 14-core Apple M3 Max: \[36GB, 96GB\]\)/
            );
        }
    },
    {
        name: '51. Exact SKU Audit: Rejects base Apple M1 behind notched 14" Pro panel (1512x982) and desktop-only Apple M2 Ultra behind laptop notched panel',
        fn: () => {
            const m1Notched = buildCoherentTelemetry('macos');
            m1Notched.webgl.unmaskedRenderer = 'Apple M1';
            m1Notched.hardwareProfile = {
                cpuModel: 'Apple M1',
                gpuModel: 'Apple M1',
                ramGb: 16,
                storageGb: 512
            };
            m1Notched.navigator.hardwareConcurrency = 8;
            m1Notched.worker.hardwareConcurrency = 8;
            m1Notched.iframeParity.hardwareConcurrency = 8;
            // Keep 1512x982 notched 14" MacBook Pro screen resolution
            const resM1 = evaluatePlatformCoherence(m1Notched, 'macos');
            assert.equal(resM1.passed, false);
            const checkM1 = findCheck(resM1, 'exact-hardware-sku-model-coherence');
            assert.equal(checkM1.passed, false);
            assert.match(
                checkM1.details,
                /Apple M1 \(2020 13\.3" MacBook Air\/Pro\) did not ship with a notched Liquid Retina display panel \(1512x982\)/
            );

            const m2UltraLaptop = buildCoherentTelemetry('macos');
            m2UltraLaptop.webgl.unmaskedRenderer = 'Apple M2 Ultra';
            m2UltraLaptop.hardwareProfile = {
                cpuModel: 'Apple M2 Ultra',
                gpuModel: 'Apple M2 Ultra',
                ramGb: 128,
                storageGb: 2048
            };
            m2UltraLaptop.navigator.hardwareConcurrency = 24;
            m2UltraLaptop.worker.hardwareConcurrency = 24;
            m2UltraLaptop.iframeParity.hardwareConcurrency = 24;
            // 1512x982 is a laptop notched panel, impossible on Mac Studio / Mac Pro
            const resUltra = evaluatePlatformCoherence(m2UltraLaptop, 'macos');
            assert.equal(resUltra.passed, false);
            const checkUltra = findCheck(resUltra, 'exact-hardware-sku-model-coherence');
            assert.equal(checkUltra.passed, false);
            assert.match(
                checkUltra.details,
                /Apple M2 Ultra is a desktop-only SoC \(Mac Studio \/ Mac Pro\) and cannot be paired with built-in MacBook laptop display panel 1512x982/
            );
        }
    },
    {
        name: '52. Exact SKU Audit: Rejects impossible SSD storage capacities (Apple M1 with 4096GB SSD) and StorageManager quota exceeding physical disk size',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.webgl.unmaskedRenderer = 'Apple M1';
            telemetry.navigator.hardwareConcurrency = 8;
            telemetry.worker.hardwareConcurrency = 8;
            telemetry.iframeParity.hardwareConcurrency = 8;
            telemetry.screen.width = 1440;
            telemetry.screen.height = 900;
            telemetry.screen.availWidth = 1440;
            telemetry.screen.availHeight = 860;
            telemetry.iframeParity.width = 1440;
            telemetry.iframeParity.height = 900;
            telemetry.hardwareProfile = {
                cpuModel: 'Apple M1',
                gpuModel: 'Apple M1',
                ramGb: 16,
                storageGb: 4096 // M1 maxes out at 2048GB (2TB)
            };
            telemetry.storageEstimate = {
                quotaBytes: 5000 * 1024 ** 3, // 5000 GiB quota > 4096 GiB physical disk
                usageBytes: 1024
            };

            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'exact-hardware-sku-model-coherence');
            assert.equal(check.passed, false);
            assert.match(
                check.details,
                /Apple M1 exact SSD storage capacity violation: storageGb=4096GB is not a valid factory SSD tier for Apple M1/
            );
            assert.match(
                check.details,
                /Browser StorageManager quotaBytes .* exceeds physical disk capacity storageGb/
            );
        }
    },
    {
        name: '53. Exact SKU Audit: Rejects PC CPU model thread count mismatch, RAM ceiling overflow, and Intel CPU + AMD APU iGPU mismatch',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.hardwareProfile = {
                cpuModel: 'Intel Core i7-13700K', // 16C/24T, max 192GB RAM
                gpuModel: 'NVIDIA GeForce RTX 3060',
                ramGb: 256, // exceeds 192GB ceiling
                storageGb: 1024
            };
            // Leave hardwareConcurrency at 8 (mismatch against i7-13700K allowed [16, 24])
            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'exact-hardware-sku-model-coherence');
            assert.equal(check.passed, false);
            assert.match(
                check.details,
                /CPU SKU "Intel Core i7-13700K" thread count violation: navigator\.hardwareConcurrency=8 does not match Intel Core i7-13700K \(16C\/24T, allowed: \[16, 24\]\)/
            );
            assert.match(
                check.details,
                /CPU SKU "Intel Core i7-13700K" RAM capacity violation: ramGb=256GB exceeds 192GB hardware ceiling/
            );

            // Also verify Intel CPU paired with AMD Radeon integrated APU is rejected
            const igpuMismatch = buildCoherentTelemetry('windows');
            igpuMismatch.hardwareProfile = {
                cpuModel: 'Intel Core i5-12400',
                ramGb: 16,
                storageGb: 512
            };
            igpuMismatch.navigator.hardwareConcurrency = 12;
            igpuMismatch.worker.hardwareConcurrency = 12;
            igpuMismatch.iframeParity.hardwareConcurrency = 12;
            igpuMismatch.webgl.unmaskedVendor = 'Google Inc. (AMD)';
            igpuMismatch.webgl.unmaskedRenderer =
                'ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';

            const resIgpu = evaluatePlatformCoherence(igpuMismatch, 'windows');
            assert.equal(resIgpu.passed, false);
            const checkIgpu = findCheck(resIgpu, 'exact-hardware-sku-model-coherence');
            assert.equal(checkIgpu.passed, false);
            assert.match(
                checkIgpu.details,
                /CPU SKU "Intel Core i5-12400" \(INTEL\) cannot pair with integrated AMD iGPU/
            );
        }
    },
    {
        name: '54. Exact SKU Audit: Rejects Windows ANGLE unmaskedVendor vs unmaskedRenderer inner vendor mismatch and D3D11 vs_3_0 shader model contradiction',
        fn: () => {
            const telemetry = buildCoherentTelemetry('windows');
            telemetry.webgl.unmaskedVendor = 'Google Inc. (Intel)';
            telemetry.webgl.unmaskedRenderer =
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_3_0 ps_3_0, D3D11)';

            const res = evaluatePlatformCoherence(telemetry, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'exact-hardware-sku-model-coherence');
            assert.equal(check.passed, false);
            assert.match(
                check.details,
                /Windows ANGLE vendor mismatch: unmaskedVendor is "Google Inc\. \(Intel\)" .* but unmaskedRenderer is "ANGLE \(NVIDIA/
            );
            assert.match(
                check.details,
                /Windows ANGLE Direct3D11 renderer .* reports legacy Direct3D9 shader model/
            );
        }
    },
    {
        name: '55. Exact SKU Audit: Rejects WebGL hardware limit tampering (MAX_TEXTURE_SIZE=4096 or ALIASED_LINE_WIDTH_RANGE=[1, 10] on ANGLE/Metal)',
        fn: () => {
            const telemetry = buildCoherentTelemetry('macos');
            telemetry.webgl.maxTextureSize = 4096;
            telemetry.webgl.aliasedLineWidthRange = [1, 10];

            const res = evaluatePlatformCoherence(telemetry, 'macos');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'exact-hardware-sku-model-coherence');
            assert.equal(check.passed, false);
            assert.match(
                check.details,
                /WebGL MAX_TEXTURE_SIZE=4096 contradicts GPU SKU "Apple M2 Pro" hardware specification \(expected 16384\)/
            );
            assert.match(
                check.details,
                /WebGL ALIASED_LINE_WIDTH_RANGE=\[1, 10\] is invalid for macOS Metal \(must be \[1, 1\]\)/
            );
        }
    },
    {
        name: '56. Exact SKU Audit: Valid exact device SKU profiles (Apple M3 Pro 12C/18GB/512GB, Intel i7-13700K 24T/32GB/1TB + RTX 3060, AMD Ryzen 7 7800X3D 16T/32GB/2TB) pass 16/16 checks (100/100)',
        fn: () => {
            assert.equal(parseAppleSiliconSkuName('Apple M3 Pro'), 'Apple M3 Pro');
            assert.ok(APPLE_SILICON_SKU_CATALOG['Apple M1 Max'].allowedRamGb.includes(64));
            assert.equal(APPLE_SILICON_SKU_CATALOG['Apple M1 Max'].allowedRamGb.includes(128), false);
            assert.ok(PC_CPU_SKU_CATALOG['Intel Core i7-13700K']);
            assert.ok(PC_GPU_SKU_CATALOG.length >= 10);

            // 1. Apple M3 Pro (12-core, 18GB Unified Memory, 512GB SSD, 1512x982 14" Pro panel)
            const macM3Pro = buildCoherentTelemetry('macos');
            macM3Pro.webgl.unmaskedRenderer = 'Apple M3 Pro';
            macM3Pro.navigator.hardwareConcurrency = 12;
            macM3Pro.worker.hardwareConcurrency = 12;
            macM3Pro.iframeParity.hardwareConcurrency = 12;
            macM3Pro.hardwareProfile = {
                cpuModel: 'Apple M3 Pro',
                gpuModel: 'Apple M3 Pro',
                ramGb: 18,
                storageGb: 512
            };
            const resMac = evaluatePlatformCoherence(macM3Pro, 'macos');
            assert.equal(resMac.passed, true);
            assert.equal(resMac.score, 100);
            assert.equal(resMac.checks.length, 17);

            // 2. Windows Intel Core i7-13700K (24 threads, 32GB DDR5, 1024GB NVMe, RTX 3060)
            const win13700k = buildCoherentTelemetry('windows');
            win13700k.navigator.hardwareConcurrency = 24;
            win13700k.worker.hardwareConcurrency = 24;
            win13700k.iframeParity.hardwareConcurrency = 24;
            win13700k.hardwareProfile = {
                cpuModel: 'Intel Core i7-13700K',
                gpuModel: 'NVIDIA GeForce RTX 3060',
                ramGb: 32,
                storageGb: 1024
            };
            const resWin = evaluatePlatformCoherence(win13700k, 'windows');
            assert.equal(resWin.passed, true);
            assert.equal(resWin.score, 100);
            assert.equal(resWin.checks.length, 17);

            // 3. Linux AMD Ryzen 7 7800X3D (16 threads, 32GB DDR5, 2048GB NVMe, Radeon RX 7800 XT)
            const lin7800x3d = buildCoherentTelemetry('linux');
            lin7800x3d.navigator.hardwareConcurrency = 16;
            lin7800x3d.worker.hardwareConcurrency = 16;
            lin7800x3d.iframeParity.hardwareConcurrency = 16;
            lin7800x3d.webgl.unmaskedVendor = 'AMD';
            lin7800x3d.webgl.unmaskedRenderer = 'AMD Radeon RX 7800 XT (radeonsi, navi32, LLVM 17.0.6)';
            lin7800x3d.hardwareProfile = {
                cpuModel: 'AMD Ryzen 7 7800X3D',
                gpuModel: 'AMD Radeon RX 7800 XT',
                ramGb: 32,
                storageGb: 2048
            };
            const resLin = evaluatePlatformCoherence(lin7800x3d, 'linux');
            assert.equal(resLin.passed, true);
            assert.equal(resLin.score, 100);
            assert.equal(resLin.checks.length, 17);
        }
    },
    {
        name: '57. Intel-based Apple Mac SKUs: Rejects 13" Intel MacBook Pro (Iris Plus 655) with 64GB RAM or 16 cores, and rejects desktop iMac 5K (Radeon Pro 580X) on a laptop 1440x900 panel',
        fn: () => {
            assert.ok(INTEL_MAC_SKU_CATALOG['MacBook Pro 13-inch (Intel 2018-2020)']);
            assert.ok(INTEL_MAC_SKU_CATALOG['iMac 27-inch 5K / iMac Pro (Intel)']);
            assert.ok(INTEL_MAC_SKU_CATALOG['Mac Pro (Intel Xeon W 2019)']);

            const intelMbp13 = buildCoherentTelemetry('macos');
            intelMbp13.webgl.unmaskedVendor = 'Intel Inc.';
            intelMbp13.webgl.unmaskedRenderer = 'Intel(R) Iris(TM) Plus Graphics 655';
            intelMbp13.webgpu.available = false;
            intelMbp13.screen.width = 1440;
            intelMbp13.screen.height = 900;
            intelMbp13.screen.availWidth = 1440;
            intelMbp13.screen.availHeight = 860;
            intelMbp13.iframeParity.width = 1440;
            intelMbp13.iframeParity.height = 900;
            intelMbp13.navigator.hardwareConcurrency = 16; // Invalid for 13" Intel MBP (4 or 8 threads only)
            intelMbp13.worker.hardwareConcurrency = 16;
            intelMbp13.iframeParity.hardwareConcurrency = 16;
            intelMbp13.hardwareProfile = {
                deviceModel: 'MacBook Pro 13-inch (Intel 2018-2020)',
                ramGb: 64, // Max on 13" Intel MBP was 32GB
                storageGb: 512
            };

            const resMbp13 = evaluatePlatformCoherence(intelMbp13, 'macos');
            assert.equal(resMbp13.passed, false);
            const checkMbp13 = findCheck(resMbp13, 'exact-hardware-sku-model-coherence');
            assert.equal(checkMbp13.passed, false);
            assert.match(checkMbp13.details, /Intel Mac SKU "MacBook Pro 13-inch \(Intel 2018-2020\)" core count violation/);
            assert.match(checkMbp13.details, /Intel Mac SKU "MacBook Pro 13-inch \(Intel 2018-2020\)" RAM capacity violation: ramGb=64GB/);

            // Desktop Intel iMac 27" 5K (AMD Radeon Pro 580X) on laptop 1440x900 screen is rejected
            const intelImac = buildCoherentTelemetry('macos');
            intelImac.webgl.unmaskedVendor = 'ATI Technologies Inc.';
            intelImac.webgl.unmaskedRenderer = 'AMD Radeon Pro 580X OpenGL Engine';
            intelImac.webgpu.available = false;
            intelImac.navigator.hardwareConcurrency = 16;
            intelImac.worker.hardwareConcurrency = 16;
            intelImac.iframeParity.hardwareConcurrency = 16;
            intelImac.screen.width = 1440;
            intelImac.screen.height = 900;
            intelImac.screen.availWidth = 1440;
            intelImac.screen.availHeight = 860;
            intelImac.iframeParity.width = 1440;
            intelImac.iframeParity.height = 900;
            intelImac.hardwareProfile = {
                ramGb: 32,
                storageGb: 1024
            };
            const resImac = evaluatePlatformCoherence(intelImac, 'macos');
            assert.equal(resImac.passed, false);
            const checkImac = findCheck(resImac, 'exact-hardware-sku-model-coherence');
            assert.equal(checkImac.passed, false);
            assert.match(
                checkImac.details,
                /Intel Mac SKU "iMac 27-inch 5K \/ iMac Pro \(Intel\)" display panel violation: resolution 1440x900/
            );
        }
    },
    {
        name: '58. Lenovo ThinkPad OEM SKUs: Rejects ThinkPad X1 Carbon Gen 10 with discrete RTX GPU or 64GB RAM, and rejects ThinkPad T14 AMD with Intel CPU/iGPU',
        fn: () => {
            assert.ok(lookupOemDeviceSku('Lenovo ThinkPad X1 Carbon Gen 10'));
            assert.ok(lookupOemDeviceSku('Lenovo ThinkPad T14 Gen 4 (AMD)'));

            const x1Carbon = buildCoherentTelemetry('windows');
            x1Carbon.navigator.hardwareConcurrency = 16;
            x1Carbon.worker.hardwareConcurrency = 16;
            x1Carbon.iframeParity.hardwareConcurrency = 16;
            // X1 Carbon Gen 10 is Intel Iris Xe iGPU-only and max 32GB soldered LPDDR5
            x1Carbon.hardwareProfile = {
                deviceModel: 'Lenovo ThinkPad X1 Carbon Gen 10',
                cpuModel: 'Intel Core i7-1260P',
                ramGb: 64,
                storageGb: 1024
            };
            // Keep default RTX 3060 discrete GPU to trigger iGPU-only violation
            const resX1 = evaluatePlatformCoherence(x1Carbon, 'windows');
            assert.equal(resX1.passed, false);
            const checkX1 = findCheck(resX1, 'exact-hardware-sku-model-coherence');
            assert.equal(checkX1.passed, false);
            assert.match(
                checkX1.details,
                /OEM Ultrabook "Lenovo ThinkPad X1 Carbon Gen 10" is integrated-GPU only and cannot house discrete GPU/
            );
            assert.match(
                checkX1.details,
                /OEM device model "Lenovo ThinkPad X1 Carbon Gen 10" RAM capacity violation: ramGb=64GB/
            );

            // ThinkPad T14 Gen 4 (AMD) paired with Intel CPU is rejected
            const t14Amd = buildCoherentTelemetry('linux');
            t14Amd.navigator.hardwareConcurrency = 16;
            t14Amd.worker.hardwareConcurrency = 16;
            t14Amd.iframeParity.hardwareConcurrency = 16;
            t14Amd.hardwareProfile = {
                deviceModel: 'Lenovo ThinkPad T14 Gen 4 (AMD)',
                cpuModel: 'Intel Core i7-13700H',
                ramGb: 32,
                storageGb: 512
            };
            const resT14 = evaluatePlatformCoherence(t14Amd, 'linux');
            assert.equal(resT14.passed, false);
            const checkT14 = findCheck(resT14, 'exact-hardware-sku-model-coherence');
            assert.equal(checkT14.passed, false);
            assert.match(
                checkT14.details,
                /OEM device model "Lenovo ThinkPad T14 Gen 4 \(AMD\)" CPU vendor violation: requires AMD CPU/
            );
        }
    },
    {
        name: '59. Dell XPS OEM SKUs: Rejects Dell XPS 13 9320 with discrete RTX GPU or 64GB RAM, and rejects Dell XPS 15 9530 with desktop RTX 4090',
        fn: () => {
            const xps13 = buildCoherentTelemetry('windows');
            xps13.navigator.hardwareConcurrency = 16;
            xps13.worker.hardwareConcurrency = 16;
            xps13.iframeParity.hardwareConcurrency = 16;
            xps13.hardwareProfile = {
                deviceModel: 'Dell XPS 13 9320',
                cpuModel: 'Intel Core i7-1260P',
                ramGb: 64,
                storageGb: 512
            };
            const resXps13 = evaluatePlatformCoherence(xps13, 'windows');
            assert.equal(resXps13.passed, false);
            const checkXps13 = findCheck(resXps13, 'exact-hardware-sku-model-coherence');
            assert.equal(checkXps13.passed, false);
            assert.match(checkXps13.details, /OEM Ultrabook "Dell XPS 13 9320" is integrated-GPU only/);
            assert.match(checkXps13.details, /OEM device model "Dell XPS 13 9320" RAM capacity violation: ramGb=64GB/);

            const xps15 = buildCoherentTelemetry('windows');
            xps15.navigator.hardwareConcurrency = 20;
            xps15.worker.hardwareConcurrency = 20;
            xps15.iframeParity.hardwareConcurrency = 20;
            xps15.webgl.unmaskedRenderer =
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            xps15.hardwareProfile = {
                deviceModel: 'Dell XPS 15 9530',
                cpuModel: 'Intel Core i7-13700H',
                ramGb: 32,
                storageGb: 1024
            };
            const resXps15 = evaluatePlatformCoherence(xps15, 'windows');
            assert.equal(resXps15.passed, false);
            const checkXps15 = findCheck(resXps15, 'exact-hardware-sku-model-coherence');
            assert.equal(checkXps15.passed, false);
            assert.match(checkXps15.details, /OEM device model "Dell XPS 15 9530" GPU mismatch/);
        }
    },
    {
        name: '60. Microsoft Surface SKUs: Rejects Surface Pro 9 with 16:9 1920x1080 display, maxTouchPoints=0, or 2TB SSD, and passes 3:2 touchscreen Surface Pro 9',
        fn: () => {
            const surfaceBad = buildCoherentTelemetry('windows');
            surfaceBad.navigator.hardwareConcurrency = 12;
            surfaceBad.worker.hardwareConcurrency = 12;
            surfaceBad.iframeParity.hardwareConcurrency = 12;
            surfaceBad.webgl.unmaskedVendor = 'Google Inc. (Intel)';
            surfaceBad.webgl.unmaskedRenderer =
                'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';
            surfaceBad.hardwareProfile = {
                deviceModel: 'Microsoft Surface Pro 9',
                cpuModel: 'Intel Core i7-1255U',
                ramGb: 16,
                storageGb: 2048 // Surface Pro 9 maxes out at 1024GB
            };
            // Keep 1920x1080 (16:9) and maxTouchPoints=0
            const resBad = evaluatePlatformCoherence(surfaceBad, 'windows');
            assert.equal(resBad.passed, false);
            const checkBad = findCheck(resBad, 'exact-hardware-sku-model-coherence');
            assert.equal(checkBad.passed, false);
            assert.match(checkBad.details, /OEM device model "Microsoft Surface Pro 9" SSD storage violation: storageGb=2048GB/);
            assert.match(checkBad.details, /OEM device "Microsoft Surface Pro 9" has a 3:2 PixelSense display/);
            assert.match(checkBad.details, /OEM 2-in-1 tablet "Microsoft Surface Pro 9" requires touchscreen support/);

            // Valid Surface Pro 9 (3:2 1440x960 logical / 2880x1920 physical, maxTouchPoints=10, 512GB SSD)
            const surfaceOk = buildCoherentTelemetry('windows');
            surfaceOk.navigator.hardwareConcurrency = 12;
            surfaceOk.worker.hardwareConcurrency = 12;
            surfaceOk.iframeParity.hardwareConcurrency = 12;
            surfaceOk.navigator.maxTouchPoints = 10;
            surfaceOk.screen.width = 1440;
            surfaceOk.screen.height = 960;
            surfaceOk.screen.availWidth = 1440;
            surfaceOk.screen.availHeight = 920;
            surfaceOk.screen.devicePixelRatio = 2;
            surfaceOk.iframeParity.width = 1440;
            surfaceOk.iframeParity.height = 960;
            surfaceOk.webgl.unmaskedVendor = 'Google Inc. (Intel)';
            surfaceOk.webgl.unmaskedRenderer =
                'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';
            surfaceOk.hardwareProfile = {
                deviceModel: 'Microsoft Surface Pro 9',
                cpuModel: 'Intel Core i7-1255U',
                ramGb: 16,
                storageGb: 512
            };
            const resOk = evaluatePlatformCoherence(surfaceOk, 'windows');
            assert.equal(resOk.passed, true);
            assert.equal(resOk.score, 100);
        }
    },
    {
        name: '61. Gaming Laptop OEM SKUs: Rejects ASUS ROG Zephyrus G14 (2024) with Intel CPU or 64GB RAM, and passes Razer Blade 16 (i9-14900HX + RTX 4090 Laptop GPU)',
        fn: () => {
            const g14Bad = buildCoherentTelemetry('windows');
            g14Bad.navigator.hardwareConcurrency = 20;
            g14Bad.worker.hardwareConcurrency = 20;
            g14Bad.iframeParity.hardwareConcurrency = 20;
            g14Bad.webgl.unmaskedRenderer =
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)';
            g14Bad.hardwareProfile = {
                deviceModel: 'ASUS ROG Zephyrus G14 (2024)',
                cpuModel: 'Intel Core i7-13700H', // G14 2024 is AMD Ryzen 8000HS only!
                ramGb: 64, // G14 2024 soldered max is 32GB
                storageGb: 1024
            };
            const resG14 = evaluatePlatformCoherence(g14Bad, 'windows');
            assert.equal(resG14.passed, false);
            const checkG14 = findCheck(resG14, 'exact-hardware-sku-model-coherence');
            assert.equal(checkG14.passed, false);
            assert.match(checkG14.details, /OEM device model "ASUS ROG Zephyrus G14 \(2024\)" CPU vendor violation: requires AMD CPU/);
            assert.match(checkG14.details, /OEM device model "ASUS ROG Zephyrus G14 \(2024\)" RAM capacity violation: ramGb=64GB/);

            // Valid Razer Blade 16 (i9-14900HX 32T + RTX 4090 Laptop GPU 16GB VRAM + 64GB DDR5 + 2TB SSD)
            const razerOk = buildCoherentTelemetry('windows');
            razerOk.navigator.hardwareConcurrency = 32;
            razerOk.worker.hardwareConcurrency = 32;
            razerOk.iframeParity.hardwareConcurrency = 32;
            razerOk.webgl.unmaskedRenderer =
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)';
            razerOk.hardwareProfile = {
                deviceModel: 'Razer Blade 16',
                cpuModel: 'Intel Core i9-14900HX',
                ramGb: 64,
                vramGb: 16,
                storageGb: 2048
            };
            const resRazer = evaluatePlatformCoherence(razerOk, 'windows');
            assert.equal(resRazer.passed, true);
            assert.equal(resRazer.score, 100);
        }
    },
    {
        name: '62. Linux & Modular OEM Laptops: Rejects Samsung Galaxy Book4 Pro on Linux, and passes Framework Laptop 13 (AMD Ryzen 7 7840U + Radeon 780M) on Linux',
        fn: () => {
            const galaxyLinux = buildCoherentTelemetry('linux');
            galaxyLinux.navigator.hardwareConcurrency = 22;
            galaxyLinux.worker.hardwareConcurrency = 22;
            galaxyLinux.iframeParity.hardwareConcurrency = 22;
            galaxyLinux.webgl.unmaskedRenderer = 'Mesa Intel(R) Arc(TM) Graphics (MTL)';
            galaxyLinux.hardwareProfile = {
                deviceModel: 'Samsung Galaxy Book4 Pro',
                cpuModel: 'Intel Core Ultra 7 155H',
                ramGb: 32,
                storageGb: 1024
            };
            const resGalaxy = evaluatePlatformCoherence(galaxyLinux, 'linux');
            assert.equal(resGalaxy.passed, false);
            const checkGalaxy = findCheck(resGalaxy, 'exact-hardware-sku-model-coherence');
            assert.equal(checkGalaxy.passed, false);
            assert.match(
                checkGalaxy.details,
                /OEM device model "Samsung Galaxy Book4 Pro" OS violation: cannot run targetOs="lin"/
            );

            const frameworkLinux = buildCoherentTelemetry('linux');
            frameworkLinux.navigator.hardwareConcurrency = 16;
            frameworkLinux.worker.hardwareConcurrency = 16;
            frameworkLinux.iframeParity.hardwareConcurrency = 16;
            frameworkLinux.webgl.unmaskedVendor = 'AMD';
            frameworkLinux.webgl.unmaskedRenderer = 'AMD Radeon 780M (radeonsi, phoenix, LLVM 17.0.6)';
            frameworkLinux.hardwareProfile = {
                deviceModel: 'Framework Laptop 13',
                cpuModel: 'AMD Ryzen 7 7840U',
                ramGb: 32,
                storageGb: 1024
            };
            const resFw = evaluatePlatformCoherence(frameworkLinux, 'linux');
            assert.equal(resFw.passed, true);
            assert.equal(resFw.score, 100);
        }
    },
    {
        name: '63. Qualcomm Snapdragon X (Windows 11 ARM64 Copilot+ PC): Rejects Snapdragon X Elite paired with NVIDIA GPU or 16 cores, and passes valid Snapdragon X Elite + Adreno X1-85',
        fn: () => {
            assert.ok(QUALCOMM_SNAPDRAGON_SKU_CATALOG['Snapdragon X Elite X1E-84-100']);
            assert.ok(lookupSnapdragonSku('Snapdragon X Plus X1P-64-100'));

            const snapBad = buildCoherentTelemetry('windows');
            snapBad.navigator.hardwareConcurrency = 16; // X Elite is 12-core Oryon only
            snapBad.worker.hardwareConcurrency = 16;
            snapBad.iframeParity.hardwareConcurrency = 16;
            snapBad.hardwareProfile = {
                cpuModel: 'Snapdragon X Elite X1E-84-100',
                ramGb: 128, // Max 64GB LPDDR5x
                storageGb: 1024
            };
            // Keep default RTX 3060 GPU to trigger unified SoC GPU mismatch
            const resBad = evaluatePlatformCoherence(snapBad, 'windows');
            assert.equal(resBad.passed, false);
            const checkBad = findCheck(resBad, 'exact-hardware-sku-model-coherence');
            assert.equal(checkBad.passed, false);
            assert.match(
                checkBad.details,
                /Qualcomm Unified SoC "Snapdragon X Elite X1E-84-100" CPU\/GPU mismatch: cannot pair with non-Adreno WebGL renderer/
            );
            assert.match(
                checkBad.details,
                /Qualcomm SoC "Snapdragon X Elite X1E-84-100" core count violation: navigator\.hardwareConcurrency=16 \(expected \[12\] cores\)/
            );
            assert.match(
                checkBad.details,
                /Qualcomm SoC "Snapdragon X Elite X1E-84-100" LPDDR5x RAM violation: ramGb=128GB/
            );

            // Valid Snapdragon X Elite X1E-84-100 (12 cores, Adreno X1-85, 32GB LPDDR5x, 1TB SSD)
            const snapOk = buildCoherentTelemetry('windows');
            snapOk.navigator.hardwareConcurrency = 12;
            snapOk.worker.hardwareConcurrency = 12;
            snapOk.iframeParity.hardwareConcurrency = 12;
            snapOk.webgl.unmaskedVendor = 'Google Inc. (Qualcomm)';
            snapOk.webgl.unmaskedRenderer =
                'ANGLE (Qualcomm, Qualcomm(R) Adreno(TM) X1-85 GPU Direct3D11 vs_5_0 ps_5_0, D3D11)';
            snapOk.hardwareProfile = {
                cpuModel: 'Snapdragon X Elite X1E-84-100',
                ramGb: 32,
                storageGb: 1024
            };
            const resOk = evaluatePlatformCoherence(snapOk, 'windows');
            assert.equal(resOk.passed, true);
            assert.equal(resOk.score, 100);
        }
    },
    {
        name: '64. Intel Lunar Lake On-Package Memory (MoP) & Arrow Lake No-Hyper-Threading Lockstep: Rejects Core Ultra 7 256V with 32GB RAM or 16 threads, and rejects Core Ultra 9 285K with 32 threads',
        fn: () => {
            // Lunar Lake Core Ultra 7 256V has 16GB soldered MoP RAM and 8C/8T (no HT)
            const lunarBad = buildCoherentTelemetry('windows');
            lunarBad.navigator.hardwareConcurrency = 16;
            lunarBad.worker.hardwareConcurrency = 16;
            lunarBad.iframeParity.hardwareConcurrency = 16;
            lunarBad.webgl.unmaskedVendor = 'Google Inc. (Intel)';
            lunarBad.webgl.unmaskedRenderer =
                'ANGLE (Intel, Intel(R) Arc(TM) 140V Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';
            lunarBad.hardwareProfile = {
                cpuModel: 'Intel Core Ultra 7 256V',
                ramGb: 32, // 32GB is only on 258V/288V!
                storageGb: 1024
            };
            const resLunar = evaluatePlatformCoherence(lunarBad, 'windows');
            assert.equal(resLunar.passed, false);
            const checkLunar = findCheck(resLunar, 'exact-hardware-sku-model-coherence');
            assert.equal(checkLunar.passed, false);
            assert.match(
                checkLunar.details,
                /CPU SKU "Intel Core Ultra 7 256V" thread count violation: navigator\.hardwareConcurrency=16 does not match Intel Core Ultra 7 256V \(8C\/8T, allowed: \[8\]\)/
            );
            assert.match(
                checkLunar.details,
                /CPU SKU "Intel Core Ultra 7 256V" on-package memory \(MoP\) violation: ramGb=32GB is impossible on Intel Core Ultra 7 256V \(soldered on-package RAM options: \[16GB\]\)/
            );

            // Arrow Lake Core Ultra 9 285K removed Hyper-Threading (24C/24T, never 32 threads)
            const arrowBad = buildCoherentTelemetry('windows');
            arrowBad.navigator.hardwareConcurrency = 32;
            arrowBad.worker.hardwareConcurrency = 32;
            arrowBad.iframeParity.hardwareConcurrency = 32;
            arrowBad.hardwareProfile = {
                cpuModel: 'Intel Core Ultra 9 285K',
                ramGb: 64,
                storageGb: 2048
            };
            const resArrow = evaluatePlatformCoherence(arrowBad, 'windows');
            assert.equal(resArrow.passed, false);
            const checkArrow = findCheck(resArrow, 'exact-hardware-sku-model-coherence');
            assert.equal(checkArrow.passed, false);
            assert.match(
                checkArrow.details,
                /CPU SKU "Intel Core Ultra 9 285K" thread count violation: navigator\.hardwareConcurrency=32 does not match Intel Core Ultra 9 285K \(24C\/24T, allowed: \[24\]\)/
            );
        }
    },
    {
        name: '65. CPUs Without Integrated Graphics (hasIntegratedGpu=false): Rejects AMD Ryzen 5 5600X / Ryzen 7 5800X3D and Intel Core i7-13700KF paired with an integrated GPU',
        fn: () => {
            const ryzenNoIgpu = buildCoherentTelemetry('windows');
            ryzenNoIgpu.navigator.hardwareConcurrency = 12;
            ryzenNoIgpu.worker.hardwareConcurrency = 12;
            ryzenNoIgpu.iframeParity.hardwareConcurrency = 12;
            ryzenNoIgpu.webgl.unmaskedVendor = 'Google Inc. (AMD)';
            ryzenNoIgpu.webgl.unmaskedRenderer =
                'ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';
            ryzenNoIgpu.hardwareProfile = {
                cpuModel: 'AMD Ryzen 5 5600X', // Vermeer desktop CPU has NO integrated GPU
                ramGb: 32,
                storageGb: 1024
            };
            const resRyzen = evaluatePlatformCoherence(ryzenNoIgpu, 'windows');
            assert.equal(resRyzen.passed, false);
            const checkRyzen = findCheck(resRyzen, 'exact-hardware-sku-model-coherence');
            assert.equal(checkRyzen.passed, false);
            assert.match(
                checkRyzen.details,
                /CPU SKU "AMD Ryzen 5 5600X" physically lacks an integrated GPU \(hasIntegratedGpu=false\)/
            );

            const intelKfNoIgpu = buildCoherentTelemetry('windows');
            intelKfNoIgpu.navigator.hardwareConcurrency = 24;
            intelKfNoIgpu.worker.hardwareConcurrency = 24;
            intelKfNoIgpu.iframeParity.hardwareConcurrency = 24;
            intelKfNoIgpu.webgl.unmaskedVendor = 'Google Inc. (Intel)';
            intelKfNoIgpu.webgl.unmaskedRenderer =
                'ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            intelKfNoIgpu.hardwareProfile = {
                cpuModel: 'Intel Core i7-13700KF', // -KF suffix disables integrated UHD 770
                ramGb: 32,
                storageGb: 1024
            };
            const resKf = evaluatePlatformCoherence(intelKfNoIgpu, 'windows');
            assert.equal(resKf.passed, false);
            const checkKf = findCheck(resKf, 'exact-hardware-sku-model-coherence');
            assert.equal(checkKf.passed, false);
            assert.match(
                checkKf.details,
                /CPU SKU "Intel Core i7-13700KF" physically lacks an integrated GPU \(hasIntegratedGpu=false\)/
            );
        }
    },
    {
        name: '66. CPU Generation vs Integrated GPU Model Lockstep: Rejects Intel i7-13700K claiming 8th-Gen UHD 620 and AMD Ryzen 7 6800U claiming Radeon 780M',
        fn: () => {
            const intelGenMismatch = buildCoherentTelemetry('linux');
            intelGenMismatch.navigator.hardwareConcurrency = 24;
            intelGenMismatch.worker.hardwareConcurrency = 24;
            intelGenMismatch.iframeParity.hardwareConcurrency = 24;
            // Default linux renderer is UHD Graphics 620 (8th Gen Kaby Lake), impossible on 13th Gen i7-13700K (UHD 770)
            intelGenMismatch.hardwareProfile = {
                cpuModel: 'Intel Core i7-13700K',
                ramGb: 32,
                storageGb: 1024
            };
            const resIntel = evaluatePlatformCoherence(intelGenMismatch, 'linux');
            assert.equal(resIntel.passed, false);
            const checkIntel = findCheck(resIntel, 'exact-hardware-sku-model-coherence');
            assert.equal(checkIntel.passed, false);
            assert.match(
                checkIntel.details,
                /CPU SKU "Intel Core i7-13700K" integrated GPU generation mismatch: WebGL renderer "Mesa Intel\(R\) UHD Graphics 620 \(KBL GT2\)" does not match Intel Core i7-13700K's built-in iGPU/
            );

            const amdGenMismatch = buildCoherentTelemetry('linux');
            amdGenMismatch.navigator.hardwareConcurrency = 16;
            amdGenMismatch.worker.hardwareConcurrency = 16;
            amdGenMismatch.iframeParity.hardwareConcurrency = 16;
            amdGenMismatch.webgl.unmaskedVendor = 'AMD';
            amdGenMismatch.webgl.unmaskedRenderer = 'AMD Radeon 780M (radeonsi, phoenix, LLVM 17.0.6)';
            amdGenMismatch.hardwareProfile = {
                cpuModel: 'AMD Ryzen 7 6800U', // Rembrandt 6800U has Radeon 680M, not Phoenix 780M!
                ramGb: 16,
                storageGb: 512
            };
            const resAmd = evaluatePlatformCoherence(amdGenMismatch, 'linux');
            assert.equal(resAmd.passed, false);
            const checkAmd = findCheck(resAmd, 'exact-hardware-sku-model-coherence');
            assert.equal(checkAmd.passed, false);
            assert.match(
                checkAmd.details,
                /CPU SKU "AMD Ryzen 7 6800U" integrated GPU generation mismatch/
            );
        }
    },
    {
        name: '67. Desktop CPU vs Mobile-Only GPU & Ultrabook CPU vs Desktop-Only GPU Form-Factor Cross-Check',
        fn: () => {
            // Desktop i9-14900K paired with mobile "RTX 4070 Laptop GPU"
            const desktopWithLaptopGpu = buildCoherentTelemetry('windows');
            desktopWithLaptopGpu.navigator.hardwareConcurrency = 32;
            desktopWithLaptopGpu.worker.hardwareConcurrency = 32;
            desktopWithLaptopGpu.iframeParity.hardwareConcurrency = 32;
            desktopWithLaptopGpu.webgl.unmaskedRenderer =
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)';
            desktopWithLaptopGpu.hardwareProfile = {
                cpuModel: 'Intel Core i9-14900K',
                ramGb: 64,
                storageGb: 2048
            };
            const res1 = evaluatePlatformCoherence(desktopWithLaptopGpu, 'windows');
            assert.equal(res1.passed, false);
            const check1 = findCheck(res1, 'exact-hardware-sku-model-coherence');
            assert.equal(check1.passed, false);
            assert.match(
                check1.details,
                /Desktop CPU SKU "Intel Core i9-14900K" cannot be paired with laptop\/mobile-only GPU/
            );

            // Ultrabook 15W i7-1355U paired with 450W desktop RTX 4090
            const ultrabookWithDesktopGpu = buildCoherentTelemetry('windows');
            ultrabookWithDesktopGpu.navigator.hardwareConcurrency = 12;
            ultrabookWithDesktopGpu.worker.hardwareConcurrency = 12;
            ultrabookWithDesktopGpu.iframeParity.hardwareConcurrency = 12;
            ultrabookWithDesktopGpu.webgl.unmaskedRenderer =
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            ultrabookWithDesktopGpu.hardwareProfile = {
                cpuModel: 'Intel Core i7-1355U',
                ramGb: 16,
                storageGb: 512
            };
            const res2 = evaluatePlatformCoherence(ultrabookWithDesktopGpu, 'windows');
            assert.equal(res2.passed, false);
            const check2 = findCheck(res2, 'exact-hardware-sku-model-coherence');
            assert.equal(check2.passed, false);
            assert.match(
                check2.details,
                /Low-power Ultrabook CPU SKU "Intel Core i7-1355U" cannot be paired with full-size desktop discrete GPU/
            );
        }
    },
    {
        name: '68. GPU VRAM Capacity & PCI Vendor/Device ID Spoofing Detection: Rejects RTX 3060 with 24GB VRAM, RTX 4090 Laptop GPU with 24GB VRAM, and RTX 4090 claiming Intel UHD 620 PCI ID (0x00005917)',
        fn: () => {
            assert.ok(PCI_DEVICE_ID_CATALOG['0x5917']);
            assert.ok(PCI_DEVICE_ID_CATALOG['0x2684']);

            const spoofedGpu = buildCoherentTelemetry('windows');
            // Claim RTX 4090 in renderer string, but leave Intel UHD 620 PCI Device ID (0x00005917) and wrong VRAM (12GB) + Intel PCI vendor ID
            spoofedGpu.webgl.unmaskedRenderer =
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 (0x00005917) Direct3D11 vs_5_0 ps_5_0, D3D11)';
            spoofedGpu.hardwareProfile = {
                vramGb: 12, // Desktop RTX 4090 is 24GB only
                pciVendorId: '0x8086', // Intel PCI vendor ID on NVIDIA GPU
                ramGb: 32,
                storageGb: 1024
            };

            const res = evaluatePlatformCoherence(spoofedGpu, 'windows');
            assert.equal(res.passed, false);
            const check = findCheck(res, 'exact-hardware-sku-model-coherence');
            assert.equal(check.passed, false);
            assert.match(
                check.details,
                /GPU SKU "NVIDIA GeForce RTX 4090" VRAM capacity violation: vramGb=12GB does not match factory VRAM configuration \(allowed: \[24GB\]\)/
            );
            assert.match(
                check.details,
                /GPU PCI Vendor ID mismatch: hardwareProfile\.pciVendorId="0x8086" contradicts NVIDIA GPU/
            );
            assert.match(
                check.details,
                /GPU PCI Device ID spoofing detected: PCI ID 0x5917 belongs to "Intel\(R\) UHD Graphics 620" \(INTEL\)/
            );
        }
    },
    {
        name: '69. Check 17 (display-gamut-touch-and-audio-coherence): Detects Apple Silicon P3 gamut mismatch, macOS touch points > 0, pointer:coarse on non-touch desktop, and abnormal AudioContext sampleRate/channels',
        fn: () => {
            const macTampered = buildCoherentTelemetry('macos');
            macTampered.screen.mediaQueries.colorGamutP3 = false;
            macTampered.navigator.maxTouchPoints = 5;
            macTampered.audio.sampleRate = 8000;
            macTampered.audio.maxChannelCount = 1;

            const resMac = evaluatePlatformCoherence(macTampered, 'macos');
            assert.equal(resMac.passed, false);
            const checkMac = findCheck(resMac, 'display-gamut-touch-and-audio-coherence');
            assert.equal(checkMac.passed, false);
            assert.match(checkMac.details, /macOS 30-bit Apple Silicon Liquid\/Retina display reports CSS \(color-gamut: p3\) === false/);
            assert.match(checkMac.details, /macOS desktop\/MacBook identity reports navigator\.maxTouchPoints=5/);
            assert.match(checkMac.details, /AudioContext sampleRate=8000Hz is non-standard/);
            assert.match(checkMac.details, /AudioContext destination\.maxChannelCount=1 is invalid/);

            const winPointerTampered = buildCoherentTelemetry('windows');
            winPointerTampered.screen.mediaQueries.pointerCoarse = true;
            winPointerTampered.screen.mediaQueries.pointerFine = false;
            winPointerTampered.screen.mediaQueries.hoverSupported = false;

            const resWin = evaluatePlatformCoherence(winPointerTampered, 'windows');
            assert.equal(resWin.passed, false);
            const checkWin = findCheck(resWin, 'display-gamut-touch-and-audio-coherence');
            assert.equal(checkWin.passed, false);
            assert.match(checkWin.details, /navigator\.maxTouchPoints is 0 but CSS matchMedia reports \(pointer: coarse\)/);
            assert.match(checkWin.details, /Desktop mouse\/trackpad profile \(maxTouchPoints=0\) reports CSS \(hover: hover\) === false/);
        }
    },
    {
        name: '70. Multi-Vendor Device Matrix: End-to-end 17/17 (100/100) coherence pass across ThinkPad X1 Carbon Gen 12, Dell XPS 16 9640, Intel Mac Pro Xeon W, Lunar Lake Core Ultra 7 258V, and AMD Ryzen AI 9 HX 370',
        fn: () => {
            // 1. Lenovo ThinkPad X1 Carbon Gen 12 (Core Ultra 7 155H 22T, Intel Arc Graphics, 32GB LPDDR5x, 1TB SSD)
            const x1Gen12 = buildCoherentTelemetry('windows');
            x1Gen12.navigator.hardwareConcurrency = 22;
            x1Gen12.worker.hardwareConcurrency = 22;
            x1Gen12.iframeParity.hardwareConcurrency = 22;
            x1Gen12.webgl.unmaskedVendor = 'Google Inc. (Intel)';
            x1Gen12.webgl.unmaskedRenderer =
                'ANGLE (Intel, Intel(R) Arc(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';
            x1Gen12.hardwareProfile = {
                deviceModel: 'Lenovo ThinkPad X1 Carbon Gen 12',
                cpuModel: 'Intel Core Ultra 7 155H',
                ramGb: 32,
                storageGb: 1024
            };
            const resX1 = evaluatePlatformCoherence(x1Gen12, 'windows');
            assert.equal(resX1.passed, true);
            assert.equal(resX1.score, 100);
            assert.equal(resX1.checks.length, 17);

            // 2. Intel Mac Pro (2019 Xeon W 32 threads, AMD Radeon Pro W6800X, 96GB RAM, 2TB SSD, 2560x1440 display)
            const macProIntel = buildCoherentTelemetry('macos');
            macProIntel.navigator.hardwareConcurrency = 32;
            macProIntel.worker.hardwareConcurrency = 32;
            macProIntel.iframeParity.hardwareConcurrency = 32;
            macProIntel.webgl.unmaskedVendor = 'ATI Technologies Inc.';
            macProIntel.webgl.unmaskedRenderer = 'AMD Radeon Pro W6800X OpenGL Engine';
            macProIntel.webgpu.available = false;
            macProIntel.screen.width = 2560;
            macProIntel.screen.height = 1440;
            macProIntel.screen.availWidth = 2560;
            macProIntel.screen.availHeight = 1400;
            macProIntel.iframeParity.width = 2560;
            macProIntel.iframeParity.height = 1440;
            macProIntel.hardwareProfile = {
                deviceModel: 'Mac Pro (Intel Xeon W 2019)',
                ramGb: 96,
                storageGb: 2048
            };
            const resMacPro = evaluatePlatformCoherence(macProIntel, 'macos');
            assert.equal(resMacPro.passed, true);
            assert.equal(resMacPro.score, 100);
            assert.equal(resMacPro.checks.length, 17);

            // 3. Intel Lunar Lake Core Ultra 7 258V (8C/8T, 32GB MoP RAM, Intel Arc 140V Graphics, 1TB SSD)
            const lunarOk = buildCoherentTelemetry('windows');
            lunarOk.navigator.hardwareConcurrency = 8;
            lunarOk.worker.hardwareConcurrency = 8;
            lunarOk.iframeParity.hardwareConcurrency = 8;
            lunarOk.webgl.unmaskedVendor = 'Google Inc. (Intel)';
            lunarOk.webgl.unmaskedRenderer =
                'ANGLE (Intel, Intel(R) Arc(TM) 140V Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';
            lunarOk.hardwareProfile = {
                cpuModel: 'Intel Core Ultra 7 258V',
                ramGb: 32,
                storageGb: 1024
            };
            const resLunar = evaluatePlatformCoherence(lunarOk, 'windows');
            assert.equal(resLunar.passed, true);
            assert.equal(resLunar.score, 100);
            assert.equal(resLunar.checks.length, 17);

            // 4. AMD Ryzen AI 9 HX 370 (12C/24T, AMD Radeon 890M, 32GB LPDDR5x, 1TB SSD)
            const strixPointOk = buildCoherentTelemetry('linux');
            strixPointOk.navigator.hardwareConcurrency = 24;
            strixPointOk.worker.hardwareConcurrency = 24;
            strixPointOk.iframeParity.hardwareConcurrency = 24;
            strixPointOk.webgl.unmaskedVendor = 'AMD';
            strixPointOk.webgl.unmaskedRenderer = 'AMD Radeon 890M (radeonsi, strix, LLVM 18.1.8)';
            strixPointOk.hardwareProfile = {
                cpuModel: 'AMD Ryzen AI 9 HX 370',
                ramGb: 32,
                storageGb: 1024
            };
            const resStrix = evaluatePlatformCoherence(strixPointOk, 'linux');
            assert.equal(resStrix.passed, true);
            assert.equal(resStrix.score, 100);
            assert.equal(resStrix.checks.length, 17);
        }
    },
    {
        name: '71. Absorbed Usable Device Preset Catalog (31 Presets across macOS/Windows/Linux): Every preset in USABLE_DEVICE_PRESET_CATALOG passes 17/17 checks (100/100 score)',
        fn: () => {
            const allPresets = listUsableDevicePresets();
            assert.ok(allPresets.length >= 31, `Expected >= 31 presets, got ${allPresets.length}`);

            const macPresets = listUsableDevicePresets({ os: 'macos' });
            const winPresets = listUsableDevicePresets({ os: 'windows' });
            const linPresets = listUsableDevicePresets({ os: 'linux' });
            assert.ok(macPresets.length >= 13);
            assert.ok(winPresets.length >= 13);
            assert.ok(linPresets.length >= 5);

            for (const preset of allPresets) {
                const resolved = resolveDeterministicDeviceProfile(`test-preset-${preset.presetId}`, {
                    presetId: preset.presetId,
                    country: 'US'
                });
                assert.equal(resolved.presetId, preset.presetId);
                assert.equal(resolved.os, preset.os);

                const skuRes = validateHardwareModelSpec(resolved.telemetry, preset.os);
                assert.equal(
                    skuRes.passed,
                    true,
                    `Preset ${preset.presetId} failed validateHardwareModelSpec: ${skuRes.issues.join(' | ')}`
                );

                const platformRes = evaluatePlatformCoherence(resolved.telemetry, preset.os);
                assert.equal(
                    platformRes.passed,
                    true,
                    `Preset ${preset.presetId} failed evaluatePlatformCoherence: ${platformRes.checks
                        .filter((c) => !c.passed)
                        .map((c) => `${c.name}: ${c.details}`)
                        .join(' | ')}`
                );
                assert.equal(platformRes.score, 100);
                assert.equal(platformRes.checks.length, 17);
            }
        }
    },
    {
        name: '72. AdsPower-Absorbed Deterministic Profile Seeding, OS Font Isolation, OS Speech Voice URI Isolation & Media Device Hygiene',
        fn: () => {
            // 1. Same profileId yields identical deterministic preset, seeds, MAC address, hostname, and USB device IDs
            const p1 = resolveDeterministicDeviceProfile('acct_seed_998877', { os: 'macos', country: 'JP' });
            const p2 = resolveDeterministicDeviceProfile('acct_seed_998877', { os: 'macos', country: 'JP' });
            assert.equal(p1.presetId, p2.presetId);
            assert.equal(p1.deviceName, p2.deviceName);
            assert.equal(p1.macAddress, p2.macAddress);
            assert.deepEqual(p1.seeds, p2.seeds);
            assert.deepEqual(p1.telemetry.media.devices, p2.telemetry.media.devices);
            assert.match(p1.deviceName, /MacBook|iMac|Mac mini|Mac Studio/);
            assert.equal(p1.language, 'ja-JP');
            assert.equal(p1.timeZone, 'Asia/Tokyo');

            // 2. Strict OS font catalog isolation (zero Windows/Linux signature fonts in macOS catalog and vice-versa)
            const macFonts = new Set(OS_FONT_CATALOG.macos);
            const winFonts = new Set(OS_FONT_CATALOG.windows);
            const linFonts = new Set(OS_FONT_CATALOG.linux);
            assert.equal(macFonts.has('Segoe UI'), false);
            assert.equal(macFonts.has('Ubuntu'), false);
            assert.equal(winFonts.has('Helvetica Neue'), false);
            assert.equal(winFonts.has('PingFang SC'), false);
            assert.equal(linFonts.has('Segoe UI'), false);
            assert.equal(linFonts.has('Helvetica Neue'), false);

            // 3. SpeechVoices OS & language lockstep
            const winZhVoices = selectCoherentSpeechVoices('windows', 'zh-CN');
            assert.ok(winZhVoices.every((v) => v.name.includes('Microsoft')));
            assert.equal(winZhVoices[0].default, true);
            assert.ok(winZhVoices[0].lang.toLowerCase().startsWith('zh'));

            const macJaVoices = selectCoherentSpeechVoices('macos', 'ja-JP');
            assert.ok(macJaVoices.every((v) => v.voiceURI.startsWith('com.apple.')));
            assert.equal(macJaVoices[0].default, true);
            assert.equal(macJaVoices[0].lang, 'ja-JP');

            // 4. Pre-permission media devices hygiene (empty label unless includeLabels=true)
            const anonDevices = createCoherentMediaDevices('seed_1', 'windows');
            assert.equal(anonDevices.length, 3);
            assert.ok(anonDevices.every((d) => d.label === ''));
            const labeledDevices = createCoherentMediaDevices('seed_1', 'windows', { includeLabels: true });
            assert.ok(labeledDevices.every((d) => d.label.length > 0));
            const videoDev = labeledDevices.find((d) => d.kind === 'videoinput');
            assert.ok(videoDev.label.includes('Camera') || videoDev.label.includes('Webcam') || videoDev.label.includes('HD'));
        }
    },
    {
        name: '73. AdsPower-Absorbed 50+ Locale Fallback Chains, RFC-9110 Accept-Language q-Factor Builder & 40+ Country Geo Profiles (Wire-to-DOM Coherence)',
        fn: () => {
            assert.ok(Object.keys(LOCALE_FALLBACK_CHAINS).length >= 50);
            assert.ok(Object.keys(COUNTRY_GEO_PROFILE_CATALOG).length >= 40);

            const zhChain = expandCompatibleLanguages('zh-CN');
            assert.deepEqual(zhChain, ['zh-CN', 'zh']);
            const zhHeader = buildAcceptLanguageHeader(zhChain);
            assert.equal(zhHeader, 'zh-CN,zh;q=0.9');

            const deProfile = resolveDeterministicDeviceProfile('berlin_user_01', {
                os: 'windows',
                country: 'DE'
            });
            assert.equal(deProfile.language, 'de-DE');
            assert.equal(deProfile.timeZone, 'Europe/Berlin');
            assert.equal(deProfile.acceptLanguage, 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7');

            const wireToDom = evaluateWireToDomCoherence(
                deProfile.telemetry,
                [
                    {
                        type: 'egress',
                        url: 'https://accounts.google.com/',
                        headers: deProfile.headers
                    }
                ],
                'windows'
            );
            assert.equal(wireToDom.passed, true);
            assert.equal(wireToDom.score, 100);
        }
    },
    {
        name: '74. Rule M / Rule N / Rule O (AdsPower Real-World Broken Profile Detection): Rejects 4-Core M1 Max on Mac mini, x86 Intel Iris Mac Studio, M5 Pro on MacBook Air with macOS 11, and AMD GPU with gen-12lp WebGPU',
        fn: () => {
            // 1. AdsPower broken profile pattern #1: Mac mini + 4-core Apple M1 Max + macOS 11.7.1
            const brokenM1MaxMini = buildCoherentTelemetry('macos');
            brokenM1MaxMini.navigator.hardwareConcurrency = 4;
            brokenM1MaxMini.worker.hardwareConcurrency = 4;
            brokenM1MaxMini.iframeParity.hardwareConcurrency = 4;
            brokenM1MaxMini.webgl.unmaskedRenderer = 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1 Max, Unspecified Version)';
            brokenM1MaxMini.hardwareProfile = {
                deviceName: 'Mac-mini.local',
                architecture: 'arm',
                osVersion: '11.7.1',
                ramGb: 8
            };
            const res1 = validateHardwareModelSpec(brokenM1MaxMini, 'macos');
            assert.equal(res1.passed, false);
            assert.ok(res1.issues.some((i) => i.includes('navigator.hardwareConcurrency=4 is invalid for Apple M1 Max')));
            assert.ok(res1.issues.some((i) => i.includes('ramGb=8GB does not exist on Apple M1 Max')));
            assert.ok(res1.issues.some((i) => i.includes('(Mac mini) only ships with base or Pro Apple Silicon SoCs')));

            // 2. AdsPower broken profile pattern #2: Mac Studio + x86 + Intel Iris Plus Graphics 645
            const brokenMacStudio = buildCoherentTelemetry('macos');
            brokenMacStudio.navigator.hardwareConcurrency = 4;
            brokenMacStudio.worker.hardwareConcurrency = 4;
            brokenMacStudio.iframeParity.hardwareConcurrency = 4;
            brokenMacStudio.webgl.unmaskedVendor = 'Intel Inc.';
            brokenMacStudio.webgl.unmaskedRenderer = 'ANGLE (Intel Inc., Intel(R) Iris(TM) Plus Graphics 645, OpenGL 4.1)';
            brokenMacStudio.hardwareProfile = {
                deviceName: 'Mac-Studio.local',
                architecture: 'x86',
                osVersion: '12.6.8',
                ramGb: 8,
                webgpuAdapterInfo: { vendor: 'intel', architecture: 'gen-9' }
            };
            const res2 = validateHardwareModelSpec(brokenMacStudio, 'macos');
            assert.equal(res2.passed, false);
            assert.ok(res2.issues.some((i) => i.includes('is Apple Silicon Max/Ultra exclusive and never existed with x86 Intel/AMD hardware')));

            // 3. AdsPower broken profile pattern #3: MacBook Air + Apple M5 Pro + macOS 11.7.6 Big Sur
            const brokenM5Air = buildCoherentTelemetry('macos');
            brokenM5Air.navigator.hardwareConcurrency = 4;
            brokenM5Air.worker.hardwareConcurrency = 4;
            brokenM5Air.iframeParity.hardwareConcurrency = 4;
            brokenM5Air.webgl.unmaskedRenderer = 'ANGLE (Apple, ANGLE Metal Renderer: Apple M5 Pro, Unspecified Version)';
            brokenM5Air.hardwareProfile = {
                deviceName: 'MacBook-Air.local',
                architecture: 'arm',
                osVersion: '11.7.6',
                ramGb: 8
            };
            const res3 = validateHardwareModelSpec(brokenM5Air, 'macos');
            assert.equal(res3.passed, false);
            assert.ok(res3.issues.some((i) => i.includes('(MacBook Air) only ships with base Apple M-series SoCs')));
            assert.ok(res3.issues.some((i) => i.includes("minimum bootable macOS violation: osVersion=\"11.7.6\" is older than Apple M5 Pro's factory minimum macOS")));

            // 4. AdsPower broken profile pattern #4: AMD Radeon Pro 5700 XT with Intel WebGPU architecture "gen-12lp"
            const brokenWebGpuArch = buildCoherentTelemetry('macos');
            brokenWebGpuArch.navigator.hardwareConcurrency = 16;
            brokenWebGpuArch.worker.hardwareConcurrency = 16;
            brokenWebGpuArch.iframeParity.hardwareConcurrency = 16;
            brokenWebGpuArch.webgl.unmaskedVendor = 'ATI Technologies Inc.';
            brokenWebGpuArch.webgl.unmaskedRenderer = 'ANGLE (AMD, ANGLE Metal Renderer: AMD Radeon Pro 5700 XT, Unspecified Version)';
            brokenWebGpuArch.hardwareProfile = {
                deviceName: 'iMac.local',
                architecture: 'x86',
                osVersion: '14.7.0',
                ramGb: 32,
                webgpuAdapterInfo: { vendor: 'intel', architecture: 'gen-12lp' }
            };
            const res4 = validateHardwareModelSpec(brokenWebGpuArch, 'macos');
            assert.equal(res4.passed, false);
            assert.ok(res4.issues.some((i) => i.includes('WebGPU GPUAdapterInfo.architecture="gen-12lp" (Intel/Apple architecture) contradicts AMD WebGL renderer')));
        }
    },
    {
        name: '75. Auto-Healer (sanitizeAdsPowerProfileToCoherentPreset): Repairs broken AdsPower profiles into 100/100 SKU-coherent profiles',
        fn: () => {
            const brokenRawProfiles = [
                {
                    fbccId: 'k1a953b8',
                    Platform: 'MacIntel',
                    DeviceName: 'Mac-mini.local',
                    HardwareConcurrency: 4,
                    DeviceMemory: 8,
                    UNMASKED_RENDERER_WEBGL: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1 Max, Unspecified Version)',
                    UserAgentMetadata: { architecture: 'arm', platformVersion: '11.7.1' }
                },
                {
                    fbccId: 'k1a95b31',
                    Platform: 'MacIntel',
                    DeviceName: 'Mac-Studio.local',
                    HardwareConcurrency: 4,
                    DeviceMemory: 8,
                    UNMASKED_RENDERER_WEBGL: 'ANGLE (Intel Inc., Intel(R) Iris(TM) Plus Graphics 645, OpenGL 4.1)',
                    UserAgentMetadata: { architecture: 'x86', platformVersion: '12.6.8' }
                },
                {
                    fbccId: 'k18yt91c',
                    Platform: 'MacIntel',
                    DeviceName: 'MacBook-Air.local',
                    HardwareConcurrency: 4,
                    DeviceMemory: 8,
                    UNMASKED_RENDERER_WEBGL: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M5 Pro, Unspecified Version)',
                    UserAgentMetadata: { architecture: 'arm', platformVersion: '11.7.6' }
                },
                {
                    fbccId: 'win_broken_kf',
                    Platform: 'Win32',
                    DeviceName: 'DESKTOP-BAD1234',
                    HardwareConcurrency: 4,
                    DeviceMemory: 8,
                    UNMASKED_RENDERER_WEBGL: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)',
                    UserAgentMetadata: { architecture: 'x86', platformVersion: '15.0.0' }
                }
            ];

            for (const raw of brokenRawProfiles) {
                const healed = sanitizeAdsPowerProfileToCoherentPreset(raw);
                assert.equal(
                    healed.validation.passed,
                    true,
                    `Healed profile for ${raw.fbccId} failed SKU validation: ${healed.validation.issues.join(' | ')}`
                );
                const fullAudit = evaluatePlatformCoherence(
                    healed.healedProfile.telemetry,
                    healed.healedProfile.os
                );
                assert.equal(fullAudit.passed, true);
                assert.equal(fullAudit.score, 100);
            }
        }
    },
    {
        name: '76. Rule P & Ziniao SuperBrowser V6 Reverse-Engineered Flaw Detection & Auto-Healer: Rejects 3-core concurrency, 6GB W3C deviceMemory violation, DESKTOP-XXXXXX on macOS, Locally-Administered MAC (bit 1=1), and 1024x1366 portrait headless screen, and auto-heals via sanitizeZiniaoProfileToCoherentPreset',
        fn: () => {
            const brokenZiniaoMac = buildCoherentTelemetry('macos');
            brokenZiniaoMac.navigator.hardwareConcurrency = 3; // Ziniao kwn dropdown offers "3" cores!
            brokenZiniaoMac.worker.hardwareConcurrency = 3;
            brokenZiniaoMac.iframeParity.hardwareConcurrency = 3;
            brokenZiniaoMac.screen.width = 1024; // Ziniao headless fallback 1024x1366 portrait!
            brokenZiniaoMac.screen.height = 1366;
            brokenZiniaoMac.hardwareProfile = {
                deviceName: 'DESKTOP-8F3A1B', // Ziniao h1a() always generates DESKTOP-XXXXXX even on macOS
                macAddress: '52-A4-1C-99-01-FE', // Ziniao m1a() sets bit 1 = 1 (0x52 & 0x02 === 2, Locally Administered)
                deviceMemory: 6, // Ziniao zwn dropdown offers "6GB" (violates W3C power-of-2 spec)
                ramGb: 6
            };

            const skuCheck = validateHardwareModelSpec(brokenZiniaoMac, 'macos');
            assert.equal(skuCheck.passed, false);
            assert.ok(skuCheck.issues.some((i) => i.includes('Cross-OS DeviceName violation: Windows hostname pattern "DESKTOP-8F3A1B"')));
            assert.ok(skuCheck.issues.some((i) => i.includes('has Locally Administered bit set')));
            assert.ok(skuCheck.issues.some((i) => i.includes('W3C Device Memory specification violation: deviceMemory=6GB')));
            assert.ok(skuCheck.issues.some((i) => i.includes('portrait 1024x1366 (Ziniao headless window fallback)')));

            // Auto-heal raw Ziniao V6 config while absorbing its port_scan_protection and canvas_fingerprint_skip_hosts
            const healedZiniao = sanitizeZiniaoProfileToCoherentPreset({
                ContainerId: 'SB9901234',
                system_value: 2, // MacOS
                concurrent_hardware_num: 3,
                device_memory: 6,
                device_info_str: 'DESKTOP-8F3A1B',
                mac_address_str: '52-A4-1C-99-01-FE',
                webgl_metadata: 1, // --disable-gpu
                webgl_renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M3 Pro, Unspecified Version)',
                port_protection: 1,
                port_protection_msg: '9222, 5900',
                canvas_fingerprint_skip_hosts: 'sellercentral.amazon.com|www.ebay.com'
            });

            assert.equal(healedZiniao.validation.passed, true);
            assert.ok(healedZiniao.repairsApplied.length >= 5);
            assert.equal(healedZiniao.absorbedSecurityPolicy.portScanProtection.enabled, true);
            assert.deepEqual(healedZiniao.absorbedSecurityPolicy.portScanProtection.allowedPorts, [9222, 5900]);
            assert.deepEqual(healedZiniao.absorbedSecurityPolicy.canvasSkipHosts, [
                'sellercentral.amazon.com',
                'www.ebay.com'
            ]);

            const platformAudit = evaluatePlatformCoherence(
                healedZiniao.healedTelemetry,
                healedZiniao.healedProfile.os
            );
            assert.equal(platformAudit.passed, true);
            assert.equal(platformAudit.score, 100);
        }
    },
    {
        name: '77. Ziniao-Absorbed Active Localhost / Private-LAN Port-Scan Protection (evaluatePortScanRequest & attachZiniaoSecurityGuardsToContext): Blocks RDP (3389), VNC (5900), CDP (9222), Marionette (2828), Clash (7890), v2rayN ([::1]:10808) & LAN Router (192.168.1.1)',
        fn: async () => {
            assert.ok(SENSITIVE_LOCAL_PORT_CATALOG[3389]);
            assert.ok(SENSITIVE_LOCAL_PORT_CATALOG[9222]);
            assert.ok(SENSITIVE_LOCAL_PORT_CATALOG[2828]);

            // 1. Blocks localhost/loopback/LAN probes
            const rdpProbe = evaluatePortScanRequest('http://127.0.0.1:3389/probe', {
                initiatorUrl: 'https://www.ebay.com/'
            });
            assert.equal(rdpProbe.shouldBlock, true);
            assert.equal(rdpProbe.isPortScanProbe, true);
            assert.equal(rdpProbe.scope, 'loopback');
            assert.equal(rdpProbe.port, 3389);
            assert.match(rdpProbe.service, /Windows Remote Desktop \(RDP\)/);

            const cdpProbe = evaluatePortScanRequest('ws://localhost:9222/devtools/browser', {
                initiatorUrl: 'https://sellercentral.amazon.com/'
            });
            assert.equal(cdpProbe.shouldBlock, true);
            assert.equal(cdpProbe.port, 9222);
            assert.match(cdpProbe.service, /Chrome DevTools Protocol/);

            const ipv6V2rayProbe = evaluatePortScanRequest('http://[::1]:10808/', {
                initiatorUrl: 'https://www.tiktok.com/'
            });
            assert.equal(ipv6V2rayProbe.shouldBlock, true);
            assert.equal(ipv6V2rayProbe.port, 10808);

            const lanProbe = evaluatePortScanRequest('http://192.168.1.1/login.htm', {
                initiatorUrl: 'https://www.shopee.com/'
            });
            assert.equal(lanProbe.shouldBlock, true);
            assert.equal(lanProbe.scope, 'private-lan');

            // 2. Allows whitelisted port and public URLs
            const allowedWhitelisted = evaluatePortScanRequest('http://127.0.0.1:8080/api', {
                allowedPorts: [8080]
            });
            assert.equal(allowedWhitelisted.shouldBlock, false);

            const publicUrl = evaluatePortScanRequest('https://accounts.google.com/v3/signin');
            assert.equal(publicUrl.shouldBlock, false);
            assert.equal(publicUrl.isPortScanProbe, false);

            // 3. Test live Playwright BrowserContext route interception mock
            let registeredHandler = null;
            const mockContext = {
                route: async (_pattern, handler) => {
                    registeredHandler = handler;
                },
                unroute: async () => {
                    registeredHandler = null;
                }
            };

            const guard = await attachZiniaoSecurityGuardsToContext(mockContext, {
                profileId: 'ziniao_guard_test_1',
                portScanProtection: { enabled: true, allowedPorts: [3000] }
            });
            assert.ok(typeof registeredHandler === 'function');

            let abortedCode = null;
            let continued = false;
            await registeredHandler(
                {
                    abort: async (code) => {
                        abortedCode = code;
                    },
                    continue: async () => {
                        continued = true;
                    }
                },
                {
                    url: () => 'http://127.0.0.1:5900/',
                    frame: () => ({ url: () => 'https://www.ebay.com/' })
                }
            );
            assert.equal(abortedCode, 'connectionrefused');
            assert.equal(continued, false);
            assert.equal(guard.blockedPortScans.length, 1);
            assert.equal(guard.blockedPortScans[0].port, 5900);
            assert.match(guard.blockedPortScans[0].service, /VNC Remote Desktop/);
        }
    },
    {
        name: '78. Ziniao-Absorbed Per-Domain Canvas & WebGL Consistency Ledger + 64-Bit Hamming Distance Engine (CanvasWebglConsistencyLedger, computeHexHammingDistance, shouldSkipCanvasNoiseForHost)',
        fn: () => {
            // 1. Exact 64-bit bitwise Hamming distance & similarity %
            assert.equal(computeHexHammingDistance('a94f3c1e8b204d71', 'a94f3c1e8b204d71'), 0);
            assert.equal(computeHashSimilarity('a94f3c1e8b204d71', 'a94f3c1e8b204d71'), 100);
            // Flip 2 bits in last nibble (0x1 -> 0x7: 0001 -> 0111 = 2 bits difference)
            assert.equal(computeHexHammingDistance('a94f3c1e8b204d71', 'a94f3c1e8b204d77'), 2);
            assert.equal(computeHashSimilarity('a94f3c1e8b204d71', 'a94f3c1e8b204d77'), 96.88);

            // 2. Canvas productivity app noise-skip hosts (Canva, Figma, Photopea, Google Docs)
            assert.ok(DEFAULT_CANVAS_SKIP_HOSTS.includes('canva.com'));
            assert.equal(shouldSkipCanvasNoiseForHost('https://www.canva.com/design/123'), true);
            assert.equal(shouldSkipCanvasNoiseForHost('https://www.figma.com/file/abc'), true);
            assert.equal(shouldSkipCanvasNoiseForHost('https://docs.google.com/document/d/1'), true);
            assert.equal(shouldSkipCanvasNoiseForHost('https://accounts.google.com/signin'), false);
            assert.equal(isSoftwareRasterizerRenderer('Google SwiftShader'), true);
            assert.equal(isSoftwareRasterizerRenderer('Apple M3 Pro'), false);

            // 3. Per-domain ledger recording, consistency check, and drift alert detection
            const ledger = new CanvasWebglConsistencyLedger({
                profileId: 'acct_amz_01',
                maxHammingDistance: 2
            });

            // Initial visit to sellercentral.amazon.com
            const firstVisit = ledger.recordOrVerify({
                kind: 'canvas',
                url: 'https://sellercentral.amazon.com/home',
                width: 280,
                height: 60,
                drewText: 'AmazonSellerFpCheck',
                hash: 'a94f3c1e8b204d71'
            });
            assert.equal(firstVisit.status, 'recorded-initial');
            assert.equal(firstVisit.driftDetected, false);

            // Second visit with minor 1-bit difference (within maxHammingDistance=2)
            const secondVisit = ledger.recordOrVerify({
                kind: 'canvas',
                url: 'https://sellercentral.amazon.com/orders',
                width: 280,
                height: 60,
                drewText: 'AmazonSellerFpCheck',
                hash: 'a94f3c1e8b204d73' // 0x1 ^ 0x3 = 1 bit
            });
            assert.equal(secondVisit.status, 'consistent');
            assert.equal(secondVisit.hammingDistance, 1);
            assert.equal(secondVisit.driftDetected, false);
            assert.equal(secondVisit.canonicalHash, 'a94f3c1e8b204d71');

            // Third visit after GPU/font change causing a 28-bit hash jump -> Drift detected!
            const driftVisit = ledger.recordOrVerify({
                kind: 'canvas',
                url: 'https://sellercentral.amazon.com/inventory',
                width: 280,
                height: 60,
                drewText: 'AmazonSellerFpCheck',
                hash: 'f0129b8c3d410a2e'
            });
            assert.equal(driftVisit.status, 'drift-detected');
            assert.equal(driftVisit.driftDetected, true);
            assert.ok(driftVisit.hammingDistance > 10);
            assert.equal(driftVisit.canonicalHash, 'a94f3c1e8b204d71');
            assert.equal(ledger.driftAlerts.length, 1);

            // Skipped host (Canva)
            const canvaVisit = ledger.recordOrVerify({
                kind: 'canvas',
                url: 'https://www.canva.com/design',
                width: 1920,
                height: 1080,
                hash: '1122334455667788'
            });
            assert.equal(canvaVisit.status, 'skipped-host');
        }
    },
    {
        name: '79. Ziniao-Absorbed Internal Browser Scheme Guard (evaluateInternalSchemeAccess) & OS/Hardware Release vs Browser Engine Version Floor Guard (validateOsAndBrowserVersionMatch)',
        fn: () => {
            // 1. Internal scheme probing blocked
            assert.equal(evaluateInternalSchemeAccess('about:config').shouldBlock, true);
            assert.equal(evaluateInternalSchemeAccess('about:debugging#/runtime/this-firefox').shouldBlock, true);
            assert.equal(evaluateInternalSchemeAccess('about:support').shouldBlock, true);
            assert.equal(evaluateInternalSchemeAccess('chrome://gpu').shouldBlock, true);
            assert.equal(evaluateInternalSchemeAccess('moz-extension://12345678-90ab-cdef/manifest.json').shouldBlock, true);
            assert.equal(
                evaluateInternalSchemeAccess('moz-extension://allowed-uuid/index.html', {
                    allowedExtensionIds: ['allowed-uuid']
                }).shouldBlock,
                false
            );
            assert.equal(evaluateInternalSchemeAccess('https://www.google.com/').shouldBlock, false);

            // 2. OS & Silicon Generation vs Browser Engine Version Floor
            const oldBrowserOnM4Sequoia = validateOsAndBrowserVersionMatch({
                os: 'macos',
                osVersion: '15.3.2',
                cpuModel: 'Apple M4 Pro',
                browserVersion: '115.0'
            });
            assert.equal(oldBrowserOnM4Sequoia.passed, false);
            assert.equal(oldBrowserOnM4Sequoia.minRequiredBrowserMajor, 128);
            assert.match(oldBrowserOnM4Sequoia.issues[0], /browser major version 115 is too old/);

            const oldBrowserOnM5Tahoe = validateOsAndBrowserVersionMatch({
                os: 'macos',
                osVersion: '26.1.0',
                cpuModel: 'Apple M5',
                browserVersion: '128.0'
            });
            assert.equal(oldBrowserOnM5Tahoe.passed, false);
            assert.equal(oldBrowserOnM5Tahoe.minRequiredBrowserMajor, 133);

            const validModernFirefox = validateOsAndBrowserVersionMatch({
                os: 'macos',
                osVersion: '26.1.0',
                cpuModel: 'Apple M5',
                browserVersion: '135.0'
            });
            assert.equal(validModernFirefox.passed, true);
        }
    },
    {
        name: '80. Ziniao-Absorbed Deterministic Metropolitan Geolocation Micro-Jitter (resolveGeoCoordinatesWithDeterministicJitter): 40+ Countries with Street-Level Jitter & Zero Hardcoded Ningxia Fallback',
        fn: () => {
            assert.ok(Object.keys(COUNTRY_METRO_COORDINATES_CATALOG).length >= 40);

            const us1 = resolveGeoCoordinatesWithDeterministicJitter('profile_ny_1', 'US');
            const us1Repeat = resolveGeoCoordinatesWithDeterministicJitter('profile_ny_1', 'US');
            const us2 = resolveGeoCoordinatesWithDeterministicJitter('profile_ny_2', 'US');

            // Deterministic for the same profileId
            assert.deepEqual(us1, us1Repeat);
            assert.equal(us1.city, 'New York');
            // Distinct street-level coordinates for two different profileIds in New York
            assert.notEqual(us1.latitude, us2.latitude);
            assert.notEqual(us1.longitude, us2.longitude);
            // Within ±0.015° (~1.5km) of Manhattan (40.7128, -74.0060)
            assert.ok(Math.abs(us1.latitude - 40.7128) <= 0.016);
            assert.ok(Math.abs(us1.longitude - -74.006) <= 0.016);
            assert.ok(us1.accuracy >= 18 && us1.accuracy <= 65);

            // Never leaks Ziniao's hardcoded Ningxia coordinates (37.2534, 105.9976) on JP/DE/GB profiles
            const jp = resolveGeoCoordinatesWithDeterministicJitter('profile_tokyo_1', 'JP');
            assert.equal(jp.city, 'Tokyo');
            assert.notEqual(jp.latitude, 37.2534);
            assert.notEqual(jp.longitude, 105.9976);
            assert.ok(Math.abs(jp.latitude - 35.6762) <= 0.016);
        }
    },
    {
        name: '81. Host Mac GPU Performance Baseline Collector (collectHostMacPerformanceBaseline) & 45+ GPU Physical Performance Catalog (GPU_PERFORMANCE_SPEC_CATALOG)',
        fn: () => {
            const hostBase = collectHostMacPerformanceBaseline({ forceRefresh: true });
            assert.ok(hostBase.hostChipModel && hostBase.hostChipModel.length > 0);
            assert.ok(hostBase.hostCpuCores >= 4);
            assert.ok(hostBase.hostGpuCores >= 8);
            assert.ok(hostBase.hostRamGb >= 8);
            assert.ok(hostBase.hostFp32Tflops > 0);
            assert.ok(hostBase.hostMemoryBandwidthGBps > 0);
            assert.ok(hostBase.hostPixelFillRateGPixels > 0);
            assert.ok(hostBase.hostMeasuredMatrixOpsPerMs > 10000);

            // Verify key GPUs in GPU_PERFORMANCE_SPEC_CATALOG
            const rtx4090 = lookupGpuPerformanceSpec(
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)'
            );
            assert.equal(rtx4090.model, 'NVIDIA GeForce RTX 4090');
            assert.equal(rtx4090.fp32Tflops, 82.58);
            assert.equal(rtx4090.memoryBandwidthGBps, 1008);

            const rtx4090Laptop = lookupGpuPerformanceSpec(
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)'
            );
            assert.equal(rtx4090Laptop.model, 'NVIDIA GeForce RTX 4090 Laptop GPU');
            assert.equal(rtx4090Laptop.fp32Tflops, 32.95);

            const uhd620 = lookupGpuPerformanceSpec('Mesa Intel(R) UHD Graphics 620 (KBL GT2)');
            assert.equal(uhd620.model, 'Intel(R) UHD Graphics 620');
            assert.equal(uhd620.fp32Tflops, 0.44);

            const m5Pro = lookupGpuPerformanceSpec('Apple M5 Pro');
            assert.equal(m5Pro.model, 'Apple M5 Pro');
            assert.equal(m5Pro.fp32Tflops, 11.5);
        }
    },
    {
        name: '82. Host-to-Target GPU Performance Weighting (computeGpuPerformanceScalingWeights & scaleGpuExecutionDurationMs): Weights RTX 4090 ~7.18x faster and Intel UHD 620 ~26.1x slower than Host Apple M5 Pro without leaking host timing',
        fn: () => {
            const hostBase = collectHostMacPerformanceBaseline();

            // 1. Target = NVIDIA GeForce RTX 4090 (82.58 TFLOPS vs Host Apple M5 Pro 11.5 TFLOPS)
            const rtx4090Weights = computeGpuPerformanceScalingWeights(
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)',
                { profileId: 'perf_rtx4090_01', hostBaseline: hostBase }
            );
            assert.equal(rtx4090Weights.targetGpuSpec.model, 'NVIDIA GeForce RTX 4090');
            // computeTimeMultiplier = 11.5 / 82.58 ≈ 0.139259 (< 1.0, i.e., 7.18x faster than host Mac!)
            assert.ok(rtx4090Weights.computeTimeMultiplier < 0.25);
            assert.ok(rtx4090Weights.throughputSpeedupRatio > 4.0);
            assert.ok(rtx4090Weights.memoryTransferMultiplier < 0.45);

            // A 10.0ms shader benchmark on the host Mac is weighted down to ~1.5-2.5ms for RTX 4090
            const rtxSample1 = scaleGpuExecutionDurationMs(10.0, rtx4090Weights, {
                operationType: 'compute',
                sampleIndex: 1
            });
            const rtxSample2 = scaleGpuExecutionDurationMs(10.0, rtx4090Weights, {
                operationType: 'compute',
                sampleIndex: 2
            });
            assert.ok(rtxSample1.weightedTargetElapsedMs < 2.5);
            assert.notEqual(rtxSample1.weightedTargetElapsedMs, 10.0); // Never leaks raw 10.0ms host Mac timing!
            assert.notEqual(rtxSample1.weightedTargetElapsedMs, rtxSample2.weightedTargetElapsedMs); // Has realistic thermal micro-jitter

            // 2. Target = Intel(R) UHD Graphics 620 (0.44 TFLOPS vs Host Apple M5 Pro 11.5 TFLOPS)
            const uhd620Weights = computeGpuPerformanceScalingWeights(
                'Mesa Intel(R) UHD Graphics 620 (KBL GT2)',
                { profileId: 'perf_uhd620_01', hostBaseline: hostBase }
            );
            assert.equal(uhd620Weights.targetGpuSpec.model, 'Intel(R) UHD Graphics 620');
            assert.ok(uhd620Weights.computeTimeMultiplier > 15.0);
            const uhdSample = scaleGpuExecutionDurationMs(10.0, uhd620Weights, {
                operationType: 'compute',
                sampleIndex: 1
            });
            assert.ok(uhdSample.weightedTargetElapsedMs > 150.0);
        }
    },
    {
        name: '83. In-Browser Anti-Penetration GPU Performance Init Script (buildGpuPerformanceInitScript): Compresses RTX 4090 & Dilates UHD 620 WebGL/Timer-Query/WebGPU Benchmarks while Preserving Monotonic performance.now() and [native code]',
        fn: async () => {
            const vm = await import('node:vm');

            const runSimulatedBrowserBenchmark = (targetGpuRenderer, realHostElapsedMs = 20.0) => {
                const weights = computeGpuPerformanceScalingWeights(targetGpuRenderer, {
                    profileId: 'vm_test_profile'
                });
                const scriptCode = buildGpuPerformanceInitScript(weights);

                let simulatedRealClockMs = 1000.0;
                function now() {
                    return simulatedRealClockMs;
                }
                function Performance() {}
                Performance.prototype.now = now;
                const perfInstance = new Performance();

                function WebGL2RenderingContext() {}
                WebGL2RenderingContext.prototype.drawArrays = function drawArrays() {};
                WebGL2RenderingContext.prototype.finish = function finish() {};
                WebGL2RenderingContext.prototype.readPixels = function readPixels() {};
                WebGL2RenderingContext.prototype.getQueryParameter = function getQueryParameter(_q, pname) {
                    // Simulate raw host Mac returning 20,000,000 ns (20ms) for QUERY_RESULT (0x8866)
                    return pname === 0x8866 ? realHostElapsedMs * 1e6 : 1;
                };

                const sandbox = {
                    Performance,
                    performance: perfInstance,
                    Date: {
                        now: function now() {
                            return Math.round(1700000000000 + simulatedRealClockMs);
                        }
                    },
                    WebGLRenderingContext: WebGL2RenderingContext,
                    WebGL2RenderingContext
                };

                vm.createContext(sandbox);
                vm.runInContext(scriptCode, sandbox);

                const gl = new sandbox.WebGL2RenderingContext();

                // Check [native code] preservation
                const perfNowStr = vm.runInContext(
                    'Function.prototype.toString.call(Performance.prototype.now)',
                    sandbox
                );
                const readPixelsStr = vm.runInContext(
                    'Function.prototype.toString.call(WebGL2RenderingContext.prototype.readPixels)',
                    sandbox
                );

                // Simulate WebGL drawArrays -> 20ms host GPU work -> gl.finish() benchmark
                const t0 = sandbox.Performance.prototype.now.call(sandbox.performance);
                gl.drawArrays(4, 0, 10000);
                simulatedRealClockMs += realHostElapsedMs;
                gl.finish();
                const t1 = sandbox.Performance.prototype.now.call(sandbox.performance);

                // Check strict monotonicity across 10 consecutive calls
                let prev = t1;
                let monotonic = true;
                for (let i = 0; i < 10; i++) {
                    simulatedRealClockMs += 0.5;
                    const curr = sandbox.Performance.prototype.now.call(sandbox.performance);
                    if (curr < prev) monotonic = false;
                    prev = curr;
                }

                // Hardware timer query (TIME_ELAPSED_EXT / QUERY_RESULT = 0x8866)
                const queryNs = gl.getQueryParameter({}, 0x8866);

                return {
                    perceivedElapsedMs: Number((t1 - t0).toFixed(4)),
                    queryNs,
                    monotonic,
                    perfNowStr,
                    readPixelsStr
                };
            };

            const rtx4090Run = runSimulatedBrowserBenchmark('NVIDIA GeForce RTX 4090', 20.0);
            const m5ProHostRun = runSimulatedBrowserBenchmark('Apple M5 Pro', 20.0);
            const uhd620Run = runSimulatedBrowserBenchmark('Intel(R) UHD Graphics 620', 20.0);

            // RTX 4090 must perceive much faster execution than the 20ms host Mac baseline (~3.5-4.5ms)
            assert.ok(
                rtx4090Run.perceivedElapsedMs < 6.0,
                `Expected RTX 4090 perceived time < 6ms, got ${rtx4090Run.perceivedElapsedMs}ms`
            );
            // Host Apple M5 Pro should perceive ~20ms
            assert.ok(
                m5ProHostRun.perceivedElapsedMs > 18.0 && m5ProHostRun.perceivedElapsedMs < 22.0,
                `Expected M5 Pro perceived time ~20ms, got ${m5ProHostRun.perceivedElapsedMs}ms`
            );
            // Intel UHD 620 must perceive much slower execution than the 20ms host Mac baseline (> 350ms)
            assert.ok(
                uhd620Run.perceivedElapsedMs > 350.0,
                `Expected UHD 620 perceived time > 350ms, got ${uhd620Run.perceivedElapsedMs}ms`
            );

            // Hardware timer query (0x8866) in nanoseconds must also be weighted per GPU SKU
            assert.ok(rtx4090Run.queryNs < 5_000_000); // ~2.78ms in ns
            assert.ok(uhd620Run.queryNs > 350_000_000); // ~522ms in ns

            // Strict monotonicity & Function.prototype.toString cloaking
            assert.equal(rtx4090Run.monotonic, true);
            assert.equal(uhd620Run.monotonic, true);
            assert.match(rtx4090Run.perfNowStr, /function now\(\)/);
            assert.match(rtx4090Run.readPixelsStr, /function readPixels\(\)/);
        }
    },
    {
        name: '84. Check 16 GPU Performance Anti-Penetration Audit (validateGpuPerformanceScalingCoherence): Rejects RTX 4090 or UHD 620 profile leaking unscaled Host Mac GPU timing',
        fn: () => {
            // 1. Valid weighted RTX 4090 preset passes 17/17 checks (100/100)
            const rtxProfile = resolveDeterministicDeviceProfile('rtx4090_audit_ok', {
                presetId: 'win-desktop-i9-14900k-rtx4090'
            });
            const resOk = evaluatePlatformCoherence(rtxProfile.telemetry, 'windows');
            assert.equal(resOk.passed, true);
            assert.equal(resOk.score, 100);

            // 2. Tamper gpuPerformance to leak raw unscaled host Mac timing (computeTimeMultiplier = 1.0, measured10msHostShaderMs = 10.0)
            const leakedRtxTelemetry = structuredClone(rtxProfile.telemetry);
            leakedRtxTelemetry.gpuPerformance = {
                ...leakedRtxTelemetry.gpuPerformance,
                computeTimeMultiplier: 1.0,
                measured10msHostShaderMs: 10.0
            };
            const resLeaked = evaluatePlatformCoherence(leakedRtxTelemetry, 'windows');
            assert.equal(resLeaked.passed, false);
            const skuCheck = findCheck(resLeaked, 'exact-hardware-sku-model-coherence');
            assert.equal(skuCheck.passed, false);
            assert.match(skuCheck.details, /Host Mac GPU performance penetration detected/);
            assert.match(skuCheck.details, /Host Mac GPU timing leak detected/);
        }
    },
    {
        name: '85. Subagent 2 Security Audit Hardening: IPv4-Mapped IPv6, Trailing-Dot FQDN, Integer/Hex IPv4, Nested Scheme Wrappers, C0 Controls & Full-UA Version Floor',
        fn: () => {
            // 1. IPv4-mapped IPv6 & WHATWG hex-pair form
            assert.equal(isLocalOrPrivateTarget('[::ffff:127.0.0.1]').isLocalOrPrivate, true);
            assert.equal(isLocalOrPrivateTarget('[::ffff:7f00:1]').isLocalOrPrivate, true);
            assert.equal(isLocalOrPrivateTarget('[0:0:0:0:0:ffff:192.168.1.1]').scope, 'private-lan');
            assert.equal(evaluatePortScanRequest('http://[::ffff:127.0.0.1]:3389/').shouldBlock, true);
            assert.equal(evaluatePortScanRequest('http://[0:0:0:0:0:ffff:192.168.1.1]:8080/').shouldBlock, true);

            // 2. Trailing-dot FQDN, integer/hex IPv4, ULA fd12::, link-local fe80::%en0, unspecified [::]
            assert.equal(evaluatePortScanRequest('http://localhost.:9222/json').shouldBlock, true);
            assert.equal(evaluatePortScanRequest('http://router.local.:80/').shouldBlock, true);
            assert.equal(isLocalOrPrivateTarget('2130706433').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('0x7f000001').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('::').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('fd12:3456:789a::1').scope, 'private-lan');
            assert.equal(isLocalOrPrivateTarget('fe80::1%25en0').scope, 'link-local');
            assert.equal(evaluatePortScanRequest('blob:http://127.0.0.1:9222/abc').shouldBlock, true);
            assert.equal(evaluatePortScanRequest('//127.0.0.1:3389/probe').shouldBlock, true);

            // 3. Internal scheme access with C0 controls, embedded tabs, nested wrappers, and percent-encoded about:
            assert.equal(evaluateInternalSchemeAccess('\u0001about:config').shouldBlock, true);
            assert.equal(evaluateInternalSchemeAccess('ab\tout:config').shouldBlock, true);
            assert.equal(evaluateInternalSchemeAccess('about://%63onfig').shouldBlock, true);
            assert.equal(evaluateInternalSchemeAccess('view-source:chrome://gpu').shouldBlock, true);
            assert.equal(
                evaluateInternalSchemeAccess('blob:moz-extension://untrusted-id/page.html').shouldBlock,
                true
            );
            assert.equal(
                evaluateInternalSchemeAccess('blob:moz-extension://trusted-id/page.html', {
                    allowedExtensionIds: ['trusted-id']
                }).shouldBlock,
                false
            );
            assert.equal(
                evaluateInternalSchemeAccess('filesystem:chrome-extension://untrusted-id/temp/a.txt').shouldBlock,
                true
            );

            // 4. CanvasWebglConsistencyLedger negative maxHammingDistance guard & invalid hash rejection
            const ledger = new CanvasWebglConsistencyLedger({
                profileId: 'neg_dist_test',
                maxHammingDistance: -5
            });
            assert.equal(ledger.maxHammingDistance, 0);
            const firstObs = ledger.recordOrVerify({
                kind: 'canvas',
                domain: 'accounts.google.com',
                hash: '0x8f4a2c910b3e7d12'
            });
            assert.equal(firstObs.status, 'recorded-initial');
            const secondObs = ledger.recordOrVerify({
                kind: 'canvas',
                domain: 'accounts.google.com',
                hash: '8f4a2c910b3e7d12'
            });
            assert.equal(secondObs.status, 'consistent');
            assert.equal(secondObs.driftDetected, false);
            assert.throws(
                () => ledger.recordOrVerify({ kind: 'canvas', domain: 'accounts.google.com', hash: '' }),
                /Invalid hexadecimal fingerprint hash/
            );

            // 5. validateOsAndBrowserVersionMatch with full User-Agent string containing "Windows NT 10.0" or "Mac OS X 10.15"
            const uaCheck = validateOsAndBrowserVersionMatch({
                os: 'macos',
                osVersion: '15.4.0',
                cpuModel: 'Apple M4 Max',
                browserVersion:
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0'
            });
            assert.equal(uaCheck.actualBrowserMajor, 135);
            assert.equal(uaCheck.passed, true);
        }
    },
    {
        name: '86. Subagent 1 Hardware SKU Edge-Case Hardening: Apple M4 Ultra, Multi-Digit macOS Minor Version (13.10), MacBook Pro + Ultra Rejection, X1P-42 Adreno X1-85 Rejection & Arc A770 Ultrabook Rejection',
        fn: () => {
            // 1. Apple M4 Ultra SKU is recognized and rejects laptop panel
            assert.equal(parseAppleSiliconSkuName('Apple M4 Ultra'), 'Apple M4 Ultra');
            const m4UltraLaptop = buildCoherentTelemetry('macos');
            m4UltraLaptop.navigator.hardwareConcurrency = 32;
            m4UltraLaptop.worker.hardwareConcurrency = 32;
            m4UltraLaptop.iframeParity.hardwareConcurrency = 32;
            m4UltraLaptop.webgl.unmaskedRenderer = 'Apple M4 Ultra';
            m4UltraLaptop.screen.width = 1728;
            m4UltraLaptop.screen.height = 1117;
            const resM4U = validateHardwareModelSpec(m4UltraLaptop, 'macos');
            assert.equal(resM4U.passed, false);
            assert.ok(resM4U.issues.some((i) => i.includes('desktop-only SoC')));

            // 2. Multi-digit minor macOS version "13.10" must NOT satisfy Apple M3's macOS 14.0 floor
            const m3Mac1310 = buildCoherentTelemetry('macos');
            m3Mac1310.navigator.hardwareConcurrency = 8;
            m3Mac1310.webgl.unmaskedRenderer = 'Apple M3';
            m3Mac1310.hardwareProfile = {
                cpuModel: 'Apple M3',
                gpuModel: 'Apple M3',
                osVersion: '13.10.2',
                ramGb: 16
            };
            const res1310 = validateHardwareModelSpec(m3Mac1310, 'macos');
            assert.equal(res1310.passed, false);
            assert.ok(res1310.issues.some((i) => i.includes('minimum bootable macOS violation')));

            // 3. MacBook Pro paired with M3 Ultra & iMac Pro paired with Apple M1 are rejected
            const mbpUltra = buildCoherentTelemetry('macos');
            mbpUltra.navigator.hardwareConcurrency = 28;
            mbpUltra.webgl.unmaskedRenderer = 'Apple M3 Ultra';
            mbpUltra.screen.width = 2560;
            mbpUltra.screen.height = 1440;
            mbpUltra.hardwareProfile = {
                deviceModel: 'MacBook Pro 16"',
                cpuModel: 'Apple M3 Ultra',
                ramGb: 96
            };
            const resMbpUltra = validateHardwareModelSpec(mbpUltra, 'macos');
            assert.equal(resMbpUltra.passed, false);
            assert.ok(resMbpUltra.issues.some((i) => i.includes('(MacBook Pro) never ships with desktop-only Ultra-tier SoC')));

            // 4. Snapdragon X Plus X1P-42-100 (Adreno X1-45 only) rejects Adreno X1-85
            const x1p42 = buildCoherentTelemetry('windows');
            x1p42.navigator.hardwareConcurrency = 8;
            x1p42.webgl.unmaskedVendor = 'Google Inc. (Qualcomm)';
            x1p42.webgl.unmaskedRenderer =
                'ANGLE (Qualcomm, Qualcomm(R) Adreno(TM) X1-85 GPU Direct3D11 vs_5_0 ps_5_0, D3D11)';
            x1p42.hardwareProfile = {
                cpuModel: 'Snapdragon X Plus X1P-42-100',
                ramGb: 16
            };
            const resX1p = validateHardwareModelSpec(x1p42, 'windows');
            assert.equal(resX1p.passed, false);
            assert.ok(resX1p.issues.some((i) => i.includes('Qualcomm Unified SoC "Snapdragon X Plus X1P-42-100" CPU/GPU mismatch')));

            // 5. ThinkPad X1 Carbon Gen 12 rejects discrete Intel Arc A770 Graphics
            const x1c12ArcA770 = buildCoherentTelemetry('windows');
            x1c12ArcA770.navigator.hardwareConcurrency = 14;
            x1c12ArcA770.webgl.unmaskedVendor = 'Google Inc. (Intel)';
            x1c12ArcA770.webgl.unmaskedRenderer =
                'ANGLE (Intel, Intel(R) Arc(TM) A770 Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)';
            x1c12ArcA770.hardwareProfile = {
                deviceModel: 'Lenovo ThinkPad X1 Carbon Gen 12',
                cpuModel: 'Intel Core Ultra 7 155U',
                ramGb: 32
            };
            const resX1c = validateHardwareModelSpec(x1c12ArcA770, 'windows');
            assert.equal(resX1c.passed, false);
            assert.ok(resX1c.issues.some((i) => i.includes('is integrated-GPU only') || i.includes('GPU mismatch')));
        }
    },
    {
        name: '87. Subagent 1 Auto-Healer Hardening: Apple M1 Non-Notch 1440x900 Healing, Leaked LAPTOP- Hostname on macOS, Windows RTX 4090 Preset Resolution & Ziniao Skip-Hosts Preservation',
        fn: () => {
            // 1. Apple M1 profile heals to non-notched 1440x900 and passes 17/17 checks
            const healedM1 = sanitizeAdsPowerProfileToCoherentPreset({
                fbccId: 'm1_heal_test',
                Platform: 'MacIntel',
                DeviceName: 'LAPTOP-WINLEAK99',
                HardwareConcurrency: 4,
                DeviceMemory: 64,
                UNMASKED_RENDERER_WEBGL: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
                osVersion: '11.6.0'
            });
            assert.equal(healedM1.validation.passed, true, `Issues: ${healedM1.validation.issues.join('; ')}`);
            assert.equal(healedM1.healedTelemetry.screen.width, 1440);
            assert.equal(healedM1.healedTelemetry.screen.height, 900);
            assert.doesNotMatch(healedM1.healedProfile.deviceName, /^LAPTOP-/i);
            const m1Eval = evaluatePlatformCoherence(healedM1.healedTelemetry, 'macos');
            assert.equal(m1Eval.passed, true);
            assert.equal(m1Eval.score, 100);

            // 2. Windows RTX 4090 profile heals directly to win-desktop-i9-14900k-rtx4090-64g
            const healedWin4090 = sanitizeAdsPowerProfileToCoherentPreset({
                fbccId: 'win_4090_heal',
                Platform: 'Win32',
                UNMASKED_RENDERER_WEBGL:
                    'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)'
            });
            assert.equal(healedWin4090.healedPresetId, 'win-desktop-i9-14900k-rtx4090-64g');
            assert.equal(healedWin4090.validation.passed, true);

            // 3. Ziniao string os: "macos" + LAPTOP- hostname + preserved DEFAULT_CANVAS_SKIP_HOSTS
            const healedZiniao = sanitizeZiniaoProfileToCoherentPreset({
                ContainerId: 'ziniao_mac_str_os',
                os: 'macos',
                device_info_str: 'LAPTOP-ZINIAO1',
                concurrent_hardware_num: 3,
                device_memory: 6,
                webgl_renderer: 'Apple M3 Pro'
            });
            assert.equal(healedZiniao.validation.passed, true);
            assert.equal(healedZiniao.healedProfile.os, 'macos');
            assert.ok(healedZiniao.absorbedSecurityPolicy.canvasSkipHosts.includes('figma.com'));
        }
    },
    {
        name: '88. Subagent 1 & 2 GPU Performance Init Script Hardening: Bounded Virtual-Clock Burst Window, Flush+Finish Preservation, Idempotent Timer Query Cache, GPUBuffer.mapAsync & __camoufoxGpuPerformanceState',
        fn: async () => {
            const vm = await import('node:vm');
            const weights = computeGpuPerformanceScalingWeights('Intel(R) UHD Graphics 620', {
                profileId: 'gpu_hardening_test'
            });
            const scriptSource = buildGpuPerformanceInitScript(weights);

            let mockRealNow = 1000.0;
            function MockPerformance() {}
            MockPerformance.prototype.now = function now() {
                return mockRealNow;
            };
            const perfInstance = new MockPerformance();
            const MockDate = {
                now: function now() {
                    return Math.round(1700000000000 + mockRealNow);
                }
            };
            function MockWebGL2() {}
            MockWebGL2.prototype.drawArrays = function drawArrays() {};
            MockWebGL2.prototype.flush = function flush() {
                mockRealNow += 2.0;
            };
            MockWebGL2.prototype.finish = function finish() {
                mockRealNow += 8.0;
            };
            MockWebGL2.prototype.clientWaitSync = function clientWaitSync() {
                mockRealNow += 5.0;
                return 0x911a;
            };
            MockWebGL2.prototype.beginQuery = function beginQuery() {};
            MockWebGL2.prototype.getQueryParameter = function getQueryParameter() {
                return 10_000_000;
            };
            function MockGPUBuffer() {}
            MockGPUBuffer.prototype.mapAsync = function mapAsync() {
                mockRealNow += 4.0;
                return Promise.resolve();
            };

            const sandbox = {
                Function,
                Object,
                Math,
                WeakMap,
                WeakSet,
                Promise,
                Performance: MockPerformance,
                performance: perfInstance,
                Date: MockDate,
                WebGL2RenderingContext: MockWebGL2,
                GPUBuffer: MockGPUBuffer
            };
            sandbox.globalThis = sandbox;
            vm.createContext(sandbox);
            vm.runInContext(scriptSource, sandbox);

            // 1. __camoufoxGpuPerformanceState is exposed and non-enumerable
            assert.ok(sandbox.__camoufoxGpuPerformanceState);
            assert.equal(sandbox.__camoufoxGpuPerformanceState.targetGpuModel, 'Intel(R) UHD Graphics 620');
            assert.equal(
                Object.prototype.propertyIsEnumerable.call(sandbox, '__camoufoxGpuPerformanceState'),
                false
            );

            // 2. gl.drawArrays -> gl.flush -> gl.finish preserves burst scaling across flush+finish
            const gl = new MockWebGL2();
            const t0 = perfInstance.now();
            gl.drawArrays(4, 0, 3000);
            gl.flush();
            gl.finish();
            const t1 = perfInstance.now();
            // 10ms real elapsed on UHD 620 (~26x slower) must scale to > 150ms
            assert.ok(t1 - t0 > 150, `Expected flush+finish scaled duration > 150ms, got ${t1 - t0}ms`);

            // 3. Unsynchronized drawArrays followed by 5000ms idle time is capped by MAX_GPU_BURST_WINDOW_MS (100ms)
            const tBeforeIdle = perfInstance.now();
            gl.drawArrays(4, 0, 3000); // No finish() or readPixels() called!
            mockRealNow += 5000.0; // 5 seconds of idle page time
            const tAfterIdle = perfInstance.now();
            const idleDelta = tAfterIdle - tBeforeIdle;
            // Only the 100ms burst window is scaled (~2600ms) + 4900ms idle = ~7500ms, NOT 5000 * 26 = 130,000ms!
            assert.ok(
                idleDelta < 10000,
                `Expected bounded burst window delta < 10000ms, got ${idleDelta}ms`
            );

            // 4. Repeated getQueryParameter(query, 0x8866) on the same query object returns identical cached value
            const queryObj = {};
            gl.beginQuery(0x88bf, queryObj);
            const q1 = gl.getQueryParameter(queryObj, 0x8866);
            const q2 = gl.getQueryParameter(queryObj, 0x8866);
            assert.equal(q1, q2);

            // 5. GPUBuffer.prototype.mapAsync is hooked and cloaked
            const buf = new MockGPUBuffer();
            const tBeforeMap = perfInstance.now();
            await buf.mapAsync(1);
            const tAfterMap = perfInstance.now();
            assert.ok(tAfterMap - tBeforeMap > 20);
            assert.match(Function.prototype.toString.call(MockGPUBuffer.prototype.mapAsync), /function mapAsync\(\)/);
        }
    },
    {
        name: '89. 3-Subagent Deep Audit Hardening (Part 1): Function .name & .length Descriptor Preservation, Zero Extension Property Leak, Non-Timer Query Bypass, HTMLCanvasElement.toBlob & Check 1 GPU Hook Integrity',
        fn: async () => {
            const vm = await import('node:vm');
            const weights = computeGpuPerformanceScalingWeights('Intel(R) UHD Graphics 620', {
                profileId: 'deep_audit_gpu_descriptors'
            });
            const scriptSource = buildGpuPerformanceInitScript(weights);

            let mockRealNow = 5000.0;
            function MockPerformance() {}
            MockPerformance.prototype.now = function now() {
                return mockRealNow;
            };
            const perfInstance = new MockPerformance();
            const MockDate = {
                now: function now() {
                    return Math.round(1700000000000 + mockRealNow);
                }
            };
            const extObj = {
                beginQueryEXT: function beginQueryEXT(target, query) {},
                getQueryObjectEXT: function getQueryObjectEXT(query, pname) {
                    return 10_000_000;
                }
            };
            function MockWebGL2() {}
            MockWebGL2.prototype.drawArrays = function drawArrays(mode, first, count) {};
            MockWebGL2.prototype.readPixels = function readPixels(x, y, width, height, format, type, pixels) {};
            MockWebGL2.prototype.beginQuery = function beginQuery(target, query) {};
            MockWebGL2.prototype.getQueryParameter = function getQueryParameter(query, pname) {
                return query && query._rawResult !== undefined ? query._rawResult : 10_000_000;
            };
            MockWebGL2.prototype.getExtension = function getExtension(name) {
                return extObj;
            };
            function MockHTMLCanvasElement() {}
            MockHTMLCanvasElement.prototype.toDataURL = function toDataURL(type, quality) {
                mockRealNow += 3.0;
                return 'data:image/png;base64,AA==';
            };
            MockHTMLCanvasElement.prototype.toBlob = function toBlob(callback, type, quality) {
                mockRealNow += 3.0;
                callback({ size: 128 });
            };

            const sandbox = {
                Function,
                Object,
                Math,
                WeakMap,
                WeakSet,
                Promise,
                Performance: MockPerformance,
                performance: perfInstance,
                Date: MockDate,
                WebGL2RenderingContext: MockWebGL2,
                HTMLCanvasElement: MockHTMLCanvasElement
            };
            sandbox.globalThis = sandbox;
            vm.createContext(sandbox);
            vm.runInContext(scriptSource, sandbox);

            // 1. Exact .name and .length preservation on hooked prototype methods
            assert.equal(MockPerformance.prototype.now.name, 'now');
            assert.equal(MockPerformance.prototype.now.length, 0);
            assert.equal(MockWebGL2.prototype.drawArrays.name, 'drawArrays');
            assert.equal(MockWebGL2.prototype.drawArrays.length, 3);
            assert.equal(MockWebGL2.prototype.readPixels.name, 'readPixels');
            assert.equal(MockWebGL2.prototype.readPixels.length, 7);
            assert.equal(MockWebGL2.prototype.getQueryParameter.name, 'getQueryParameter');
            assert.equal(MockWebGL2.prototype.getQueryParameter.length, 2);
            assert.equal(MockHTMLCanvasElement.prototype.toBlob.name, 'toBlob');
            assert.equal(MockHTMLCanvasElement.prototype.toBlob.length, 3);

            // 2. Zero leaked internal properties (_camoufoxScaled / _camoufoxBeginScaled) on EXT_disjoint_timer_query object
            const gl = new MockWebGL2();
            const ext = gl.getExtension('EXT_disjoint_timer_query');
            assert.deepEqual(Object.getOwnPropertyNames(ext).sort(), ['beginQueryEXT', 'getQueryObjectEXT']);
            assert.equal(ext.getQueryObjectEXT.name, 'getQueryObjectEXT');
            assert.equal(ext.getQueryObjectEXT.length, 2);

            // 3. Non-timer WebGL2 occlusion query (ANY_SAMPLES_PASSED = 0x8C2F) is NOT scaled by getQueryParameter
            const occlusionQuery = { _rawResult: 1 };
            gl.beginQuery(0x8c2f, occlusionQuery);
            assert.equal(gl.getQueryParameter(occlusionQuery, 0x8866), 1);

            // Whereas TIME_ELAPSED_EXT (0x88BF) query IS scaled
            const timerQuery = { _rawResult: 10_000_000 };
            gl.beginQuery(0x88bf, timerQuery);
            assert.ok(gl.getQueryParameter(timerQuery, 0x8866) > 150_000_000);

            // 4. HTMLCanvasElement.prototype.toBlob scales pending draw burst
            const canvas = new MockHTMLCanvasElement();
            const t0 = perfInstance.now();
            gl.drawArrays(4, 0, 1000);
            let blobSize = 0;
            canvas.toBlob((b) => {
                blobSize = b.size;
            });
            const t1 = perfInstance.now();
            assert.equal(blobSize, 128);
            assert.ok(t1 - t0 > 30);

            // 5. Check 1 (navigator-prototype-integrity) catches tampered performanceNow or webglReadPixels
            const tamperedProto = buildCoherentTelemetry('windows');
            tamperedProto.prototypeIntegrity.performanceNow = {
                exists: true,
                isMethod: true,
                source: 'function () { return 0; }',
                name: '',
                length: 0,
                isNative: false
            };
            const resTampered = evaluatePlatformCoherence(tamperedProto, 'windows');
            assert.equal(resTampered.passed, false);
            const check1 = findCheck(resTampered, 'navigator-prototype-integrity');
            assert.equal(check1.passed, false);
            assert.match(check1.details, /Performance\.prototype\.now is not \[native code\]/);
        }
    },
    {
        name: '90. 3-Subagent Deep Audit Hardening (Part 2): Full OEM Preset Catalog Backing, Cross-OS Rule G/H Enforcement, Check 16 Browser Version Floor, Octal IPv4 / Compressed IPv6 & Traffic Recorder Security Block',
        fn: async () => {
            const fs = await import('node:fs');
            const os = await import('node:os');
            const path = await import('node:path');
            const { CamoufoxTrafficRecorder, verifyTrafficIntegrity } = await import(
                '../src/camoufox/traffic-recorder.js'
            );
            const { queryProfileTraffic } = await import('../scripts/query-traffic-attribution.js');

            // 1. Newly registered OEM device models in USABLE_DEVICE_PRESET_CATALOG match lookupOemDeviceSku
            assert.ok(lookupOemDeviceSku('Surface Laptop 7th Edition (Snapdragon X Elite)'));
            assert.ok(lookupOemDeviceSku('ASUS Zenbook S 14 (Lunar Lake)'));
            assert.ok(lookupOemDeviceSku('ThinkPad T480 (Intel i5-8250U)'));

            // Surface Laptop 7th Edition (Qualcomm only) rejects Intel CPU
            const badSurface7 = buildCoherentTelemetry('windows');
            badSurface7.navigator.hardwareConcurrency = 12;
            badSurface7.hardwareProfile = {
                deviceModel: 'Surface Laptop 7th Edition (Snapdragon X Elite)',
                cpuModel: 'Intel Core i7-13700K',
                ramGb: 16
            };
            const resSurface7 = validateHardwareModelSpec(badSurface7, 'windows');
            assert.equal(resSurface7.passed, false);
            assert.ok(resSurface7.issues.some((i) => i.includes('CPU vendor violation') || i.includes('cannot house desktop socket CPU')));

            // 2. Rule G cross-OS renderer leak & Rule H MAX_VIEWPORT_DIMS tampering
            const macWithD3d = buildCoherentTelemetry('macos');
            macWithD3d.webgl.unmaskedRenderer =
                'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            const resMacD3d = validateHardwareModelSpec(macWithD3d, 'macos');
            assert.equal(resMacD3d.passed, false);
            assert.ok(resMacD3d.issues.some((i) => i.includes('cannot use Windows Direct3D ANGLE renderer')));

            const macBadViewport = buildCoherentTelemetry('macos');
            macBadViewport.webgl.maxViewportDims = [32768, 32768]; // Apple Silicon Metal limit is [16384, 16384]
            const resMacVp = validateHardwareModelSpec(macBadViewport, 'macos');
            assert.equal(resMacVp.passed, false);
            assert.ok(resMacVp.issues.some((i) => i.includes('MAX_VIEWPORT_DIMS=[32768, 32768] contradicts Apple Silicon Metal limit')));

            // 3. Check 16 invokes validateOsAndBrowserVersionMatch (rejects Apple M5 Pro + macOS 26.1 with Firefox 115)
            const m5OldFf = resolveDeterministicDeviceProfile('m5_old_ff_test', {
                presetId: 'mac-mbp16-m5-pro-18c-64g',
                firefoxVersion: '115.0'
            });
            const resM5OldFf = evaluatePlatformCoherence(m5OldFf.telemetry, 'macos');
            assert.equal(resM5OldFf.passed, false);
            const skuCheck = findCheck(resM5OldFf, 'exact-hardware-sku-model-coherence');
            assert.equal(skuCheck.passed, false);
            assert.match(skuCheck.details, /Browser engine version floor violation/);

            // 4. 4-part octal/hex IPv4 ("0177.0.0.1", "012.0.0.1", "0x7f.0.0.1") & compressed IPv6 ("0::1", "::0001")
            assert.equal(isLocalOrPrivateTarget('0177.0.0.1').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('012.0.0.1').scope, 'private-lan');
            assert.equal(isLocalOrPrivateTarget('0x7f.0.0.1').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('0::1').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('::0001').scope, 'loopback');
            assert.equal(shouldSkipCanvasNoiseForHost('https://www.figma.com./file/abc'), true);

            // 5. CamoufoxTrafficRecorder.recordSecurityBlock & queryProfileTraffic wire dump integration
            const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-sec-block-'));
            try {
                const recorder = new CamoufoxTrafficRecorder({
                    profileId: 'sec-block-profile',
                    trafficDir: tmpDir
                });
                recorder.setStep('port-scan-defense-step');
                const secRec = recorder.recordSecurityBlock({
                    type: 'local-port-scan-probe',
                    targetUrl: 'http://127.0.0.1:9222/json/version',
                    host: '127.0.0.1',
                    port: 9222,
                    scope: 'loopback',
                    service: 'Chrome DevTools Protocol (CDP)',
                    category: 'automation-debugger',
                    severity: 'critical',
                    reason: 'Blocked local/intranet port-scan probe to 127.0.0.1:9222 (Chrome DevTools Protocol (CDP))'
                });
                assert.ok(secRec && secRec.correlationId);
                await recorder.stop();

                const integrity = verifyTrafficIntegrity(tmpDir);
                assert.equal(integrity.valid, true);

                const wireDumpRes = queryProfileTraffic({
                    profileId: 'sec-block-profile',
                    trafficDir: tmpDir,
                    correlationId: secRec.correlationId
                });
                assert.equal(wireDumpRes.found, true);
                assert.ok(wireDumpRes.securityBlock);
                assert.match(wireDumpRes.wireDump, /SECURITY BLOCK \[ZINIAO ACTIVE GUARD\]/);
            } finally {
                fs.rmSync(tmpDir, { recursive: true, force: true });
            }
        }
    },
    {
        name: '91. Round-2 Adversarial Audit (Part 1): Non-Constructor GPU Wrapper Stealth ("prototype" in fn === false, WebIDL Receiver Brand Check, requestAnimationFrame Synchronization, ANGLE_instanced_arrays & 100% PC_GPU_SKU_CATALOG Coverage)',
        fn: async () => {
            const vm = await import('node:vm');
            const baseline = collectHostMacPerformanceBaseline();
            const rtx4090Weights = computeGpuPerformanceScalingWeights('NVIDIA GeForce RTX 4090', {
                profileId: 'round2-rtx4090',
                hostBaseline: baseline
            });

            let realClock = 1000;
            const sandbox = {
                performance: {
                    now() {
                        return realClock;
                    }
                },
                Performance: function Performance() {},
                Date: {
                    now() {
                        return 1700000000000 + Math.round(realClock);
                    }
                },
                requestAnimationFrame(cb) {
                    return cb(realClock);
                },
                WebGLRenderingContext: function WebGLRenderingContext() {},
                WebGL2RenderingContext: function WebGL2RenderingContext() {}
            };
            // Ensure native-like non-constructor methods on mock prototypes
            sandbox.Performance.prototype = {
                now() {
                    if (this !== sandbox.performance) {
                        throw new TypeError("'now' called on an object that does not implement interface Performance.");
                    }
                    return realClock;
                }
            };
            const extObj = {
                drawArraysInstancedANGLE() {}
            };
            sandbox.WebGLRenderingContext.prototype = {
                drawArrays() {},
                finish() {},
                readPixels() {},
                getExtension(name) {
                    return /ANGLE_instanced_arrays/i.test(name) ? extObj : null;
                }
            };
            sandbox.WebGL2RenderingContext.prototype = {
                drawRangeElements() {}
            };
            sandbox.globalThis = sandbox;

            const script = buildGpuPerformanceInitScript(rtx4090Weights);
            vm.runInNewContext(script, sandbox);

            // 1. Every hooked method must have 'prototype' in fn === false and throw on `new fn()`
            for (const fn of [
                sandbox.Performance.prototype.now,
                sandbox.Date.now,
                sandbox.requestAnimationFrame,
                sandbox.WebGLRenderingContext.prototype.drawArrays,
                sandbox.WebGLRenderingContext.prototype.finish,
                sandbox.WebGL2RenderingContext.prototype.drawRangeElements
            ]) {
                assert.equal('prototype' in fn, false, `Expected no .prototype on ${fn.name}`);
                assert.equal(Object.getOwnPropertyDescriptor(fn, 'prototype'), undefined);
                assert.throws(() => new fn());
            }

            // 2. WebIDL receiver brand check on Performance.prototype.now.call({})
            assert.throws(() => sandbox.Performance.prototype.now.call({}));

            // 3. requestAnimationFrame callback timestamp stays synchronized <= performance.now() after RTX 4090 burst
            const gl = Object.create(sandbox.WebGLRenderingContext.prototype);
            const angleExt = gl.getExtension('ANGLE_instanced_arrays');
            angleExt.drawArraysInstancedANGLE(4, 0, 6, 100);
            realClock += 50; // 50ms real host Mac burst compressed to ~7ms virtual RTX 4090 time
            gl.finish();
            let rafTs = 0;
            sandbox.requestAnimationFrame((ts) => {
                rafTs = ts;
            });
            const currentVirtualNow = sandbox.Performance.prototype.now.call(sandbox.performance);
            assert.ok(
                rafTs <= currentVirtualNow,
                `Expected requestAnimationFrame ts (${rafTs}) <= virtual performance.now() (${currentVirtualNow})`
            );

            // 4. Every PC_GPU_SKU_CATALOG entry resolves to its own vendor (never falls through to Apple M5 Pro)
            for (const gpuSku of Object.values(PC_GPU_SKU_CATALOG)) {
                const gpuId = gpuSku.id || gpuSku.model;
                const perfSpec = lookupGpuPerformanceSpec(gpuId);
                assert.equal(
                    perfSpec.vendor,
                    gpuSku.vendor,
                    `PC_GPU_SKU_CATALOG["${gpuId}"] resolved to wrong vendor "${perfSpec.vendor}" (${perfSpec.model})`
                );
            }
            assert.equal(
                lookupGpuPerformanceSpec('NVIDIA GeForce RTX 3060 Laptop GPU').model,
                'NVIDIA GeForce RTX 3060 Laptop GPU'
            );
            assert.equal(lookupGpuPerformanceSpec('NVIDIA GeForce RTX 3050').model, 'NVIDIA GeForce RTX 3050');
            assert.equal(lookupGpuPerformanceSpec('NVIDIA GeForce RTX 2060').model, 'NVIDIA GeForce RTX 2060');
            assert.equal(lookupGpuPerformanceSpec('NVIDIA GeForce GTX 1660').model, 'NVIDIA GeForce GTX 1660');

            // 5. Desktop vs Laptop RTX 4090 / 4070 auto-healing distinction
            const desktop4090Healed = sanitizeAdsPowerProfileToCoherentPreset({
                ProfileId: 'test-desktop-4090',
                Platform: 'Win32',
                WebGLRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)'
            });
            assert.equal(desktop4090Healed.healedPresetId, 'win-desktop-i9-14900k-rtx4090-64g');

            const laptop4090Healed = sanitizeAdsPowerProfileToCoherentPreset({
                ProfileId: 'test-laptop-4090',
                Platform: 'Win32',
                WebGLRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)'
            });
            assert.equal(laptop4090Healed.healedPresetId, 'win-razer-blade16-i9-rtx4090');
        }
    },
    {
        name: '92. Round-2 Adversarial Audit (Part 2): IPv4-Compatible IPv6 (::127.0.0.1), NAT64 (64:ff9b::), Gecko jar:http:// Unwrapping, Check 16 In-Browser GPU State Cross-Verification & Resumed Security-Block Anomaly Recovery',
        fn: async () => {
            const fs = await import('node:fs');
            const os = await import('node:os');
            const path = await import('node:path');
            const { CamoufoxTrafficRecorder } = await import('../src/camoufox/traffic-recorder.js');

            // 1. IPv4-compatible IPv6, NAT64, Fake-IP 198.18.0.0/15, userinfo@ confusion & jar:http:// port scan protection
            assert.equal(isLocalOrPrivateTarget('::127.0.0.1').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('::7f00:1').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('64:ff9b::127.0.0.1').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('198.18.0.1').scope, 'private-lan');
            assert.equal(isLocalOrPrivateTarget('http://www.google.com@127.0.0.1:9222/json').scope, 'loopback');
            assert.equal(isLocalOrPrivateTarget('kubernetes.default.svc').scope, 'private-lan');

            const jarProbe = evaluatePortScanRequest('jar:http://127.0.0.1:9222/probe.jar!/entry');
            assert.equal(jarProbe.shouldBlock, true);
            assert.equal(jarProbe.port, 9222);

            // 2. Check 1 detects tampered functionToString & Check 16 detects in-browser gpuPerformanceState divergence
            const baseProfile = resolveDeterministicDeviceProfile('round2-check16', {
                os: 'windows',
                presetId: 'win-desktop-i9-14900k-rtx4090-64g'
            });
            const tamperedStateTelemetry = structuredClone(baseProfile.telemetry);
            tamperedStateTelemetry.gpuPerformanceState = {
                targetGpuModel: 'Apple M5 Pro',
                computeTimeMultiplier: 1.0,
                antiPenetrationActive: true
            };
            const evalRes = evaluatePlatformCoherence(tamperedStateTelemetry, 'windows');
            assert.equal(evalRes.passed, false);
            const check16 = findCheck(evalRes, 'exact-hardware-sku-model-coherence');
            assert.equal(check16.passed, false);
            assert.match(check16.details, /In-browser GPU/);

            // 3. Resuming CamoufoxTrafficRecorder from unflushed traffic.ndjson preserves stepIndex & security-block anomaly
            const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-resume-sec-'));
            try {
                const rec1 = new CamoufoxTrafficRecorder({
                    profileId: 'resume-sec-profile',
                    trafficDir: tmpDir
                });
                rec1.setStep('step-1-login');
                rec1.setStep('step-2-probe');
                const secEv = rec1.recordSecurityBlock({
                    type: 'local-port-scan-probe',
                    targetUrl: 'http://127.0.0.1:3389/',
                    host: '127.0.0.1',
                    port: 3389,
                    reason: 'Blocked RDP probe'
                });
                // Simulate process crash before flushSummary() by opening rec2 directly on traffic.ndjson
                const rec2 = new CamoufoxTrafficRecorder({
                    profileId: 'resume-sec-profile',
                    trafficDir: tmpDir
                });
                assert.equal(rec2.attribution.stepIndex, 2);
                assert.equal(rec2.anomaliesAndRiskSignals.length, 1);
                assert.equal(rec2.anomaliesAndRiskSignals[0].correlationId, secEv.correlationId);
                assert.match(
                    rec2.formatTransactionWireDump(secEv.correlationId),
                    /SECURITY-BLOCK \[ZINIAO ACTIVE GUARD\]/
                );
                await rec2.stop();
            } finally {
                fs.rmSync(tmpDir, { recursive: true, force: true });
            }
        }
    }
];

async function runTests() {
    console.log('================================================================================');
    console.log('🧪 Running Camoufox Coherence Auditor Isolation Unit Tests');
    console.log('================================================================================\n');

    let passed = 0;
    for (const t of tests) {
        try {
            await t.fn();
            passed++;
            console.log(`✅ PASS: ${t.name}`);
        } catch (err) {
            console.error(`❌ FAIL: ${t.name}`);
            console.error(err);
            process.exit(1);
        }
    }

    console.log('\n================================================================================');
    console.log(`🏁 All ${passed}/${tests.length} coherence auditor unit tests passed!`);
    console.log('================================================================================');
}

runTests();
