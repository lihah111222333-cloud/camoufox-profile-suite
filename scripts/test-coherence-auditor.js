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
    PC_CPU_SKU_CATALOG,
    PC_GPU_SKU_CATALOG,
    parseAppleSiliconSkuName,
    validateHardwareModelSpec,
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
                colorBitsAtLeast8: true
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
            assert.equal(res.checks.length, 16);
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
            assert.equal(report.checks.length, 16);
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
                assert.equal(res.checks.length, 16, `Expected 16 checks for ${os}`);
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
                assert.equal(legacyRes.checks.length, 16);
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
                assert.equal(res.checks.length, 16, `Expected 16 checks for ${os}`);
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
        name: '45. Full 16/16 coherence check validation across Windows, macOS, and Linux profiles (100/100)',
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
                assert.equal(res.passed, true, `Expected ${os} profile to pass all 16 checks`);
                assert.equal(res.score, 100, `Expected ${os} score to be 100`);
                assert.equal(res.checks.length, 16, `Expected 16 checks for ${os}`);
                assert.ok(res.checks.every((c) => c.passed));
                assert.equal(findCheck(res, 'webgpu-os-coherence').passed, true);
                assert.equal(findCheck(res, 'stack-trace-and-mediadevices-hygiene').passed, true);
                assert.equal(findCheck(res, 'exact-hardware-sku-model-coherence').passed, true);
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
            assert.equal(report.checks.length, 16);
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
            assert.equal(resMac.checks.length, 16);

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
            assert.equal(resWin.checks.length, 16);

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
            assert.equal(resLin.checks.length, 16);
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
