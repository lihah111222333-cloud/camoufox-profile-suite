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
    normalizeTargetOs,
    gpuFitsOs,
    evaluatePlatformCoherence,
    auditProfileCoherence
} from '../src/camoufox/coherence-auditor.js';

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
            ]
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
            ]
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
            ]
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
            extensionsCount: 28
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
        speechVoices: p.speechVoices
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
            assert.equal(res.checks.length, 10);
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
            assert.equal(report.checks.length, 10);
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
        name: '28. Valid Windows, macOS, and Linux profiles with coherent webrtc ephemeral ports, OS-matched speechVoices, and empty automationGlobals pass 10/10 checks (100/100)',
        fn: () => {
            for (const os of ['windows', 'macos', 'linux']) {
                const telemetry = buildCoherentTelemetry(os);
                const res = evaluatePlatformCoherence(telemetry, os);
                assert.equal(res.passed, true, `Expected ${os} profile to pass`);
                assert.equal(res.score, 100, `Expected ${os} score to be 100`);
                assert.equal(res.checks.length, 10, `Expected 10 checks for ${os}`);
                assert.ok(res.checks.every((c) => c.passed));

                // Also verify backward compatibility when older synthetic fixtures omit the 3 new fields
                const legacyTelemetry = buildCoherentTelemetry(os);
                delete legacyTelemetry.automationGlobals;
                delete legacyTelemetry.webrtc;
                delete legacyTelemetry.speechVoices;
                const legacyRes = evaluatePlatformCoherence(legacyTelemetry, os);
                assert.equal(legacyRes.passed, true);
                assert.equal(legacyRes.score, 100);
                assert.equal(legacyRes.checks.length, 10);
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
