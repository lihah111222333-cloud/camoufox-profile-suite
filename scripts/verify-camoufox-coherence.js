/**
 * Camoufox Fingerprint Coherence Diagnostic CLI
 * أداة تشخيص وفحص تناسق البصمة الرقمية لمحرك Camoufox
 *
 * Run with --help for usage.
 * Normal invocation requires live evidence. The dry-run and check-env modes evaluate fixtures.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

const USAGE = 'Usage: node scripts/verify-camoufox-coherence.js [--help | -h] [--dry-run | --check-env] [--os=windows|macos|linux]';
const REPORT_NAME = 'camoufox-audit-report.json';
const SUPPORTED_OS_TARGETS = ['windows', 'macos', 'linux'];
const SYNTHETIC_GPU_BASELINE = {
    hostChipModel: 'Synthetic fixture',
    hostFp32Tflops: 10,
    hostMemoryBandwidthGBps: 100,
    hostPixelFillRateGPixels: 100
};

function float64ToHex(val) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setFloat64(0, val, false);
    const hi = view.getUint32(0, false).toString(16).padStart(8, '0');
    const lo = view.getUint32(4, false).toString(16).padStart(8, '0');
    return `0x${hi}${lo}`;
}

/**
 * Build realistic C++-level Camoufox browser telemetry for dry-run / pre-binary coherence auditing
 */
function getSyntheticCamoufoxTelemetry(targetOs, computeGpuPerformanceScalingWeights) {
    const profiles = {
        windows: {
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
            platform: 'Win32',
            oscpu: 'Windows NT 10.0; Win64; x64',
            hardwareConcurrency: 8,
            colorDepth: 24,
            devicePixelRatio: 1,
            screenWidth: 1920,
            screenHeight: 1080,
            availWidth: 1920,
            availHeight: 1040,
            webglVendor: 'Google Inc. (NVIDIA)',
            webglRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
            hardwareProfile: {
                cpuModel: 'Intel Core i7-10700K',
                gpuModel: 'NVIDIA GeForce RTX 3060',
                ramGb: 32,
                storageGb: 1024
            },
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
            screenWidth: 1512,
            screenHeight: 982,
            availWidth: 1512,
            availHeight: 944,
            webglVendor: 'Apple',
            webglRenderer: 'Apple M2 Pro',
            hardwareProfile: {
                cpuModel: 'Apple M2 Pro',
                gpuModel: 'Apple M2 Pro',
                ramGb: 16,
                storageGb: 512
            },
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
            screenWidth: 1920,
            screenHeight: 1080,
            availWidth: 1920,
            availHeight: 1052,
            webglVendor: 'Intel',
            webglRenderer: 'Mesa Intel(R) UHD Graphics 620 (KBL GT2)',
            hardwareProfile: {
                cpuModel: 'Intel Core i5-8250U',
                gpuModel: 'Intel(R) UHD Graphics 620',
                ramGb: 16,
                storageGb: 512
            },
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

    const p = profiles[targetOs] || profiles.windows;
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
            vendor: '',
            buildID: '20181001000000'
        },
        prototypeIntegrity: {
            toStringIntact: true,
            functionToString: {
                exists: true,
                isMethod: true,
                source: 'function toString() {\n    [native code]\n}',
                name: 'toString',
                length: 0,
                isNative: true
            },
            ownNavigatorOverrides: [],
            userAgentGetter: { exists: true, isGetter: true, source: 'function get userAgent() {\n    [native code]\n}', isNative: true },
            webdriverGetter: { exists: true, isGetter: true, source: 'function get webdriver() {\n    [native code]\n}', isNative: true },
            platformGetter: { exists: true, isGetter: true, source: 'function get platform() {\n    [native code]\n}', isNative: true },
            hardwareConcurrencyGetter: { exists: true, isGetter: true, source: 'function get hardwareConcurrency() {\n    [native code]\n}', isNative: true },
            performanceNow: { exists: true, isMethod: true, source: 'function now() {\n    [native code]\n}', name: 'now', length: 0, isNative: true },
            webglGetParameter: { exists: true, isMethod: true, source: 'function getParameter() {\n    [native code]\n}', name: 'getParameter', length: 1, isNative: true },
            webgl2GetParameter: { exists: true, isMethod: true, source: 'function getParameter() {\n    [native code]\n}', name: 'getParameter', length: 1, isNative: true },
            webglReadPixels: { exists: true, isMethod: true, source: 'function readPixels() {\n    [native code]\n}', name: 'readPixels', length: 7, isNative: true },
            webglDrawArrays: { exists: true, isMethod: true, source: 'function drawArrays() {\n    [native code]\n}', name: 'drawArrays', length: 3, isNative: true }
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
            unmaskedVendor: p.webglVendor,
            unmaskedRenderer: p.webglRenderer,
            extensionsCount: 28,
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: targetOs === 'windows' ? [32768, 32768] : [16384, 16384],
            maxVertexAttribs: 16,
            aliasedLineWidthRange: [1, 1]
        },
        canvas2d: {
            available: true,
            fnv1aHash: targetOs === 'windows' ? 'a94f3c1e8b204d71' : (targetOs === 'macos' ? 'c71d8a045e921b3f' : 'f1049c8e3d72a615'),
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
            width: p.screenWidth,
            height: p.screenHeight,
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
                colorGamutP3: targetOs === 'macos',
                dynamicRangeHigh: targetOs === 'macos',
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
            width: p.screenWidth,
            height: p.screenHeight,
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
            available: targetOs !== 'linux',
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
        hardwareProfile: p.hardwareProfile,
        gpuPerformance: computeGpuPerformanceScalingWeights(p.webglRenderer, {
            profileId: `diag-${targetOs}`,
            hostBaseline: SYNTHETIC_GPU_BASELINE
        }),
        storageEstimate: {
            quotaBytes: 21474836480,
            usageBytes: 4096
        }
    };
}

/**
 * Create a synthetic Playwright-compatible Page wrapper that returns C++-level Camoufox
 * telemetry snapshot in dry-run mode (when the Camoufox binary has not been fetched yet).
 */
function createSyntheticPage(telemetry) {
    return {
        isSynthetic: true,
        async evaluate() {
            return telemetry;
        }
    };
}

/**
 * Run negative control adversarial test to prove the coherence auditor catches:
 * 1. JS `stealth` prototype overrides on `navigator`
 * 2. Chrome User-Agent / `navigator.userAgentData` spoofed on a Firefox engine
 * 3. Dedicated Worker thread `hardwareConcurrency` / `platform` mismatch
 * 4. Windows identity claiming a non-ANGLE macOS/Linux GPU renderer
 */
function runAdversarialNegativeControl(tampered, evaluatePlatformCoherence) {
    tampered.navigator.userAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36';
    tampered.navigator.hasUserAgentData = true;
    tampered.prototypeIntegrity.ownNavigatorOverrides = ['userAgent', 'webdriver'];
    tampered.prototypeIntegrity.webdriverGetter.isNative = false;
    tampered.worker.platform = 'Linux x86_64';
    tampered.worker.hardwareConcurrency = 4;
    tampered.webgl.unmaskedRenderer = 'Apple M2 Pro';

    const evaluation = evaluatePlatformCoherence(tampered, 'windows');
    const failedNames = evaluation.checks
        .filter((check) => !check.passed && check.status !== 'not-tested')
        .map((check) => check.name);
    const expectedCatches = [
        'navigator-prototype-integrity',
        'dedicated-worker-parity',
        'engine-gecko-coherence',
        'os-platform-gpu-coherence'
    ];
    const caughtAll =
        evaluation.passed === false &&
        expectedCatches.every((checkName) => failedNames.includes(checkName));

    return {
        caughtAll,
        score: evaluation.score,
        failedChecks: failedNames
    };
}

async function auditLiveTarget(targetOs, auditProfileCoherence) {
    let profilesDir = null;
    let session = null;
    let auditReport = null;
    let unavailableReason = null;
    let cleanupConfirmed = true;

    try {
        await import('../src/config.js');
        const { createAndStartProfile } = await import('../src/camoufox/profile.js');
        profilesDir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'camoufox-diagnostic-profile-'));
        session = await createAndStartProfile(`diag-${targetOs}-${Date.now()}`, null, {
            os: targetOs,
            profilesDir,
            headless: true,
            humanize: true,
            recordTraffic: false,
            recordHar: false,
            sslKeyLog: false,
            neckoMozLog: false
        });

        const page = await session.getPage();
        auditReport = await auditProfileCoherence(page, targetOs);
        unavailableReason = auditReport.reason ?? null;
    } catch (error) {
        unavailableReason = session ? 'Live browser evidence could not be collected' : 'Camoufox browser could not be started';
        if (!session && error?.profileCleanup && error.profileCleanup !== 'deleted') cleanupConfirmed = false;
    } finally {
        if (session) {
            try {
                cleanupConfirmed = (await session.stop()) === true;
            } catch {
                cleanupConfirmed = false;
            }
        }
        if (profilesDir && cleanupConfirmed) {
            try {
                fs.rmSync(profilesDir, { recursive: true, force: true });
            } catch {
                cleanupConfirmed = false;
            }
        }
    }

    const cleanupStatus = profilesDir ? (cleanupConfirmed ? 'removed' : 'unconfirmed') : null;
    return { auditReport, unavailableReason, cleanupStatus };
}

/**
 * Run coherence audit across target OS profiles
 */
async function runDiagnostic() {
    const args = process.argv.slice(2);
    if (args.includes('--help') || args.includes('-h')) {
        console.log(USAGE);
        return;
    }

    const [
        { writeCaptureExport },
        { isCamoufoxModuleResolvable, isPackageEntryResolvable },
        { auditProfileCoherence, evaluatePlatformCoherence, computeGpuPerformanceScalingWeights }
    ] = await Promise.all([
        import('../src/camoufox/capture-io.js'),
        import('../src/camoufox/sdk-resolution.js'),
        import('../src/camoufox/coherence-auditor.js')
    ]);
    const forceDryRun = args.includes('--dry-run') || args.includes('--check-env');
    const osArg = args.find(arg => arg.startsWith('--os='));
    const requestedOs = osArg ? osArg.split('=')[1]?.toLowerCase() : null;
    const osTargets = requestedOs && SUPPORTED_OS_TARGETS.includes(requestedOs)
        ? [requestedOs]
        : SUPPORTED_OS_TARGETS;

    console.log('================================================================================');
    console.log('🦊 Camoufox Cross-OS Fingerprint Coherence Diagnostic CLI');
    console.log('================================================================================\n');

    const envStatus = {
        camoufoxSdkInstalled: isCamoufoxModuleResolvable(),
        playwrightCoreInstalled: isPackageEntryResolvable('playwright-core', import.meta)
    };
    console.log(`📚 camoufox-js SDK      : ${envStatus.camoufoxSdkInstalled ? 'Resolvable' : 'Unavailable'}`);
    console.log(`🎭 playwright-core      : ${envStatus.playwrightCoreInstalled ? 'Resolvable' : 'Unavailable'}`);
    console.log(`🎯 Target OS Profiles   : ${osTargets.join(', ')}\n`);

    const results = [];
    const statusLabels = {
        passed: 'PASS',
        failed: 'FAIL',
        incomplete: 'INCOMPLETE (checks not tested)',
        'not-tested': 'NOT TESTED'
    };

    for (const targetOs of osTargets) {
        console.log(`--------------------------------------------------------------------------------`);
        console.log(`🔍 Auditing OS Target: [${targetOs.toUpperCase()}]`);

        let auditReport = null;
        let unavailableReason = null;
        let cleanupStatus = null;

        if (forceDryRun) {
            const telemetry = getSyntheticCamoufoxTelemetry(targetOs, computeGpuPerformanceScalingWeights);
            auditReport = await auditProfileCoherence(createSyntheticPage(telemetry), targetOs);
        } else if (!envStatus.camoufoxSdkInstalled) {
            unavailableReason = 'Camoufox SDK is unavailable';
        } else {
            ({ auditReport, unavailableReason, cleanupStatus } = await auditLiveTarget(targetOs, auditProfileCoherence));
        }

        const status = auditReport?.status ?? 'not-tested';
        const passed = status === 'passed';
        const mode = forceDryRun
            ? 'dry-run-synthetic'
            : status === 'not-tested' ? 'live-browser-unavailable' : 'live-browser';
        const checks = auditReport?.checks ?? [];
        const scoreSummary = auditReport?.score == null ? '' : ` (${auditReport.score}/100, ${checks.length} checks)`;

        console.log(`   Mode      : ${mode}`);
        console.log(`   Result    : ${statusLabels[status]}${scoreSummary}`);
        if (unavailableReason) console.log(`   Reason    : ${unavailableReason}`);
        if (cleanupStatus === 'unconfirmed') console.error('   Diagnostic profile cleanup could not be confirmed');
        const failedChecks = checks.filter((check) => !check.passed && check.status !== 'not-tested');
        if (failedChecks.length > 0) {
            console.log(`   Failed    : ${failedChecks.map((check) => check.name).join(', ')}`);
        }
        const untestedChecks = checks.filter((check) => check.status === 'not-tested');
        if (untestedChecks.length > 0) {
            console.log(`   Not tested: ${untestedChecks.map((check) => check.name).join(', ')}`);
        }

        results.push({
            targetOs,
            mode,
            status,
            passed,
            unavailableReason,
            ...(cleanupStatus && { cleanupStatus }),
            auditReport
        });
    }

    const negativeControl = forceDryRun
        ? runAdversarialNegativeControl(
            getSyntheticCamoufoxTelemetry('windows', computeGpuPerformanceScalingWeights),
            evaluatePlatformCoherence
        )
        : null;
    if (negativeControl) {
        console.log('--------------------------------------------------------------------------------');
        console.log(`   Synthetic negative control: ${negativeControl.caughtAll ? 'PASS' : 'FAIL'}`);
        console.log(`   Flagged checks: ${negativeControl.failedChecks.join(', ')}`);
    }

    let overallStatus = 'passed';
    if (negativeControl?.caughtAll === false ||
        results.some(({ status, cleanupStatus }) => status === 'failed' || cleanupStatus === 'unconfirmed')) {
        overallStatus = 'failed';
    } else if (results.every(({ status }) => status === 'not-tested')) {
        overallStatus = 'not-tested';
    } else if (results.some(({ passed }) => !passed)) {
        overallStatus = 'incomplete';
    }
    const overallPassed = overallStatus === 'passed';
    const summaryReport = {
        timestamp: new Date().toISOString(),
        environment: envStatus,
        overallStatus,
        overallPassed,
        negativeControl,
        results
    };

    const containsLiveAudit = results.some(({ mode }) => mode === 'live-browser');
    const reportDirectory = containsLiveAudit
        ? (await import('../src/utils/state-paths.js')).ensureStateDirectory()
        : fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-audit-'));
    const reportPath = path.join(reportDirectory, REPORT_NAME);
    writeCaptureExport(reportPath, `${JSON.stringify(summaryReport, null, 2)}\n`, { replace: containsLiveAudit });
    console.log(`\n================================================================================`);
    console.log(`📄 Diagnostic report written to: ${reportPath}`);
    const auditLabel = forceDryRun ? 'Synthetic rule verification' : 'Live browser audit';
    console.log(`🏁 ${auditLabel}: ${statusLabels[overallStatus]}`);
    console.log(`================================================================================\n`);

    if (!overallPassed) {
        process.exitCode = 1;
    }
}

runDiagnostic().catch((error) => {
    const rejectedDestination = error?.message === 'Capture export destination must be an ordinary file';
    console.error(rejectedDestination
        ? 'Capture export destination must be an ordinary file'
        : 'Could not complete Camoufox coherence verification or write its diagnostic report');
    process.exitCode = 1;
});
