/**
 * Gmail Account Creator Bot
 * بوت إنشاء حسابات Gmail
 * 
 * Main entry point for the application
 * نقطة البداية الرئيسية للتطبيق
 */

import {
    appendAccountResult, migrateExistingAccountOutputs, recordAccountCleanup, writeRunSummary
} from './utils/account-results.js';
import { parseRunCounts } from './utils/cli-counts.js';
import { ensureStateDirectory, LEGACY_DIRECTORY, STATE_DIRECTORY } from './utils/state-paths.js';
import { randomUUID } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const RESULTS_FILE = path.join(STATE_DIRECTORY, 'results.json');
const SUMMARY_FILE = path.join(STATE_DIRECTORY, 'summary.json');

function accountOutputDiagnostic(error) {
    if (error?.code === 'ACCOUNT_OUTPUT_INVALID_DATA' || error?.code === 'ACCOUNT_OUTPUT_LOCK_FAILED') {
        return ' ' + error.message;
    }
    return '';
}

function prepareAccountOutputs() {
    try {
        ensureStateDirectory();
        migrateExistingAccountOutputs(RESULTS_FILE, SUMMARY_FILE, { legacyDirectory: LEGACY_DIRECTORY });
    } catch (error) {
        const details = error instanceof AggregateError
            ? error.errors.map(accountOutputDiagnostic).join('')
            : accountOutputDiagnostic(error);
        throw new AccountOutputWriteError(
            'Could not prepare results.json or summary.json in the application state directory.' + details, error
        );
    }
}

class AccountOutputWriteError extends Error {
    constructor(message, cause) {
        super(message, { cause });
        this.code = 'ACCOUNT_OUTPUT_WRITE_FAILED';
    }
}

async function loadRuntime(config) {
    const { default: proxyManager } = await import('./utils/proxy-manager.js');
    if (config.profileService === 'camoufox' && config.app?.testProxy === false && !proxyManager.proxies.length) {
        proxyManager.rejectUnselectedLegacyInventory();
    }
    const [
        { default: logger },
        { default: nameGenerator },
        { createGmailAccount }
    ] = await Promise.all([
        import('./utils/logger.js'),
        import('./utils/name-generator.js'),
        import('./gmail/creator.js')
    ]);
    return { config, logger, proxyManager, nameGenerator, createGmailAccount };
}

/**
 * Save account result
 * حفظ نتيجة الحساب
 */
function saveResult(result, logger) {
    let saved;
    try {
        saved = appendAccountResult(RESULTS_FILE, result);
    } catch (error) {
        const message = result.success
            ? 'An account was created and its result could not be saved safely in results.json.'
            : 'A failed account attempt could not be saved safely in results.json.';
        throw new AccountOutputWriteError(message + accountOutputDiagnostic(error), error);
    }
    logger.info('Result saved', { email: saved.email });
    return saved;
}

/**
 * Create single Gmail account
 * إنشاء حساب Gmail واحد
 */
async function createAccount(accountNumber = null) {
    const { default: config } = await import('./config.js');
    prepareAccountOutputs();
    const { result, failure } = await createAccountWithRuntime(await loadRuntime(config), accountNumber);
    if (!result.success) throw failure;
    return result;
}

async function createAccountWithRuntime(runtime, accountNumber, { signal, activeStops } = {}) {
    const { config, logger, proxyManager, nameGenerator, createGmailAccount } = runtime;
    const profileService = config.profileService || 'gpm';
    const serviceName = profileService === 'camoufox'
        ? 'Camoufox'
        : (profileService === 'dolphin' ? 'Dolphin Anty' : 'GPM Login');
    const accountLabel = accountNumber ? `[Account ${accountNumber}]` : '';
    let profile = null;
    let proxy = null;
    let savedResult;
    let failure;
    let profileCleanup;
    let stopping;
    const stop = () => {
        stopping ??= (async () => {
            const details = { profileId: profile.profileId, profileType: serviceName };
            try {
                if (await profile.stop() === true) {
                    logger.info(`${accountLabel} Profile stopped`, details);
                    return 'stopped';
                }
            } catch {
                // A thrown stop failure is also unconfirmed.
            }
            logger.warn(`${accountLabel} Profile shutdown unconfirmed`, details);
            return 'stop-unconfirmed';
        })();
        return stopping;
    };

    try {
        signal?.throwIfAborted();
        logger.info(`${accountLabel} === Starting Gmail Account Creation ===`);

        // Step 1: Get proxy
        proxy = proxyManager.getNextProxy();
        if (!proxy) {
            if (profileService === 'camoufox' && config.app?.testProxy === false) {
                logger.warn(`${accountLabel} No proxies configured; proceeding with direct connection (TEST_PROXY=false)`);
            } else {
                throw new Error('No proxies available');
            }
        } else {
            logger.info(`${accountLabel} Proxy selected`);
        }

        // Step 2: Generate account data
        const accountData = nameGenerator.generateAccountData();
        logger.info(`${accountLabel} Account data generated`, { 
            name: accountData.fullName,
            email: accountData.email
        });

        // Step 3: Create profile based on selected service
        const profileName = profileService === 'camoufox'
            ? `Gmail_${randomUUID()}`
            : `Gmail_${accountData.username}_${Date.now()}`;
        
        logger.info(`${accountLabel} Creating ${profileService.toUpperCase()} profile`, { name: profileName });
        
        // Format proxy according to service
        signal?.throwIfAborted();
        if (profileService === 'camoufox') {
            const { createAndStartProfile: createAndStartCamoufoxProfile } = await import('./camoufox/profile.js');
            signal?.throwIfAborted();
            const camoufoxProxy = proxy ? proxyManager.getCamoufoxFormat(proxy) : null;
            profile = await createAndStartCamoufoxProfile(profileName, camoufoxProxy, {
                os: config.camoufox?.os,
                presetId: config.camoufox?.presetId,
                country: config.camoufox?.country,
                headless: config.camoufox?.headless,
                humanize: config.camoufox?.humanize,
                geoip: config.camoufox?.geoip,
                canvas_noise: config.camoufox?.canvasNoise,
                enablePortScanProtection: config.camoufox?.enablePortScanProtection,
                portScanProtection: {
                    mode: config.camoufox?.portScanProtectionMode,
                    enabled: config.camoufox?.enablePortScanProtection
                },
                allowedLocalPorts: config.camoufox?.allowedLocalPorts,
                enableGpuPerformanceScaling: config.camoufox?.enableGpuPerformanceScaling,
                canvasSkipHosts: config.camoufox?.canvasSkipHosts,
                maxHammingDistance: config.camoufox?.maxHammingDistance,
                profilesDir: config.camoufox?.storageDir,
                accountId: accountNumber,
                accountEmail: accountData.email,
                recordTraffic: config.camoufox?.recordTraffic,
                recordBodies: config.camoufox?.recordBodies,
                recordWireLog: config.camoufox?.recordWireLog,
                sslKeyLog: config.camoufox?.sslKeyLog,
                neckoMozLog: config.camoufox?.neckoMozLog,
                neckoMozLogModules: config.camoufox?.neckoMozLogModules,
                recordHar: config.camoufox?.recordHar,
                maxBodyBytes: config.camoufox?.maxBodyBytes
            });
        } else if (profileService === 'dolphin') {
            // Lazy-load Dolphin Anty profile module only when selected
            const { createAndStartProfile: createAndStartDolphinProfile } = await import('./dolphin/profile.js');
            signal?.throwIfAborted();
            const dolphinProxy = proxy ? {
                ip: proxy.ip,
                port: proxy.port,
                username: proxy.username || '',
                password: proxy.password || '',
                type: proxy.type || 'http'
            } : null;
            profile = await createAndStartDolphinProfile(profileName, dolphinProxy);
        } else {
            // Lazy-load GPM Login profile module only when selected
            const { createAndStartProfile: createAndStartGPMProfile } = await import('./gpmlogin/profile.js');
            signal?.throwIfAborted();
            const gpmProxy = proxy ? {
                ip: proxy.ip,
                port: proxy.port,
                username: proxy.username || '',
                password: proxy.password || '',
                type: proxy.type || 'http'
            } : null;
            profile = await createAndStartGPMProfile(profileName, gpmProxy);
        }

        activeStops?.add(stop);
        signal?.throwIfAborted();

        const camoufoxTelemetry =
            typeof profile?.getTelemetrySummary === 'function' ? profile.getTelemetrySummary() : null;
        logger.info(`${accountLabel} Profile created and started`, {
            profileId: profile.profileId,
            ...(camoufoxTelemetry
                ? {
                      presetId: camoufoxTelemetry.presetId,
                      deviceModel: camoufoxTelemetry.deviceModel,
                      os: camoufoxTelemetry.os,
                      gpuPerformance: camoufoxTelemetry.gpuPerformance
                  }
                : {})
        });

        // Step 4: Get browser and page
        const browser = await profile.getBrowser();
        signal?.throwIfAborted();
        const page = await profile.getPage();
        signal?.throwIfAborted();

        if (!browser || !page) {
            throw new Error(`Failed to get browser instance from ${serviceName} profile`);
        }

        // Step 5: Create Gmail account
        logger.info(`${accountLabel} Starting Gmail account creation process`);
        if (typeof profile.setTrafficStep === 'function') {
            profile.setTrafficStep('signup-flow');
        }
        const result = await createGmailAccount(page, accountData, { profile });
        if (result?.email && typeof profile.updateTrafficAttribution === 'function') {
            profile.updateTrafficAttribution({ accountEmail: result.email });
        }

        // Step 6: Get profile IP (if available)
        let profileIP = null;
        try {
            if (!signal?.aborted) {
                if (typeof profile.setTrafficStep === 'function') {
                    profile.setTrafficStep('ip-check');
                }
                profileIP = await page.evaluate(() => {
                    return new Promise((resolve) => {
                        fetch('https://api.ipify.org?format=json')
                            .then(r => r.json())
                            .then(data => resolve(data.ip))
                            .catch(() => resolve(null));
                    });
                });
            }
        } catch (ipError) {
            logger.debug('Could not get profile IP', { error: ipError.message });
        }

        const finalCamoufoxTelemetry =
            typeof profile?.getTelemetrySummary === 'function' ? profile.getTelemetrySummary() : null;

        // Step 7: Save account outcome
        savedResult = saveResult({
            ...result,
            success: true,
            profileId: profile.profileId,
            profileType: serviceName,
            profileCleanup: 'pending',
            proxyIP: proxy ? proxy.ip : null,
            profileIP: profileIP,
            trafficAttribution: profile.trafficPaths || null,
            ...(finalCamoufoxTelemetry ? { camoufoxTelemetry: finalCamoufoxTelemetry } : {}),
            timestamp: new Date().toISOString()
        }, logger);
    } catch (error) {
        if (error instanceof AccountOutputWriteError) throw error;
        failure = error;
        logger.error(`${accountLabel} === Account Creation Failed ===`, {
            error: error?.message,
            stack: error?.stack
        });

        const profileId = profile?.profileId ?? error?.profileId ?? null;
        savedResult = saveResult({
            success: false,
            errorCode: error?.code,
            errorStage: error?.stage,
            profileId,
            ...(profileId !== null ? { profileType: serviceName } : {}),
            trafficAttribution: profile?.trafficPaths || null,
            profileCleanup: profile ? 'pending' : error?.profileCleanup,
            timestamp: new Date().toISOString()
        }, logger);
    } finally {
        activeStops?.delete(stop);
        if (profile) profileCleanup = await stop();
    }

    let result = savedResult;
    if (profile) {
        try {
            result = recordAccountCleanup(RESULTS_FILE, savedResult.resultId, profileCleanup);
        } catch (error) {
            throw new AccountOutputWriteError(
                'Could not save profile cleanup in results.json.' + accountOutputDiagnostic(error), error
            );
        }
    }
    if (result.success) {
        logger.info(`${accountLabel} === Account Creation Completed Successfully ===`, { email: result.email });
    }
    return { result, failure };
}

/**
 * Process queue with concurrency control
 * معالجة قائمة الانتظار مع التحكم في التزامن
 */
async function processQueue(total, concurrency, createTask, logger, signal) {
    const results = [];
    const executing = [];
    let completed = 0;
    let failed = 0;
    let outputWriteError;

    const executeTask = async (index) => {
        try {
            logger.info(`[Thread ${index + 1}] Starting account creation ${completed + failed + 1}/${total}`);
            const { result, failure } = await createTask(index + 1);
            results.push(result);
            if (result.success) {
                completed++;
                logger.info(`[Thread ${index + 1}] Account created successfully (${completed} success, ${failed} failed)`);
            } else {
                failed++;
                logger.error(`[Thread ${index + 1}] Account creation failed (${completed} success, ${failed} failed)`, {
                    error: failure?.message
                });
            }
        } catch (error) {
            if (error instanceof AccountOutputWriteError) {
                outputWriteError ??= error;
                return;
            }
            failed++;
            results.push({
                success: false,
                errorCode: error.code,
                errorStage: error.stage
            });
            logger.error(`[Thread ${index + 1}] Account creation failed (${completed} success, ${failed} failed)`, {
                error: error.message
            });
        }
    };

    for (let i = 0; i < total; i++) {
        // Wait if we've reached concurrency limit
        while (executing.length >= concurrency) {
            await Promise.race(executing);
        }
        if (outputWriteError || signal?.aborted) {
            break;
        }

        const promise = executeTask(i).then(() => {
            executing.splice(executing.indexOf(promise), 1);
        });

        executing.push(promise);
        if (executing.length < concurrency && i + 1 < total) {
            // Give signals and completions a turn even when the requested concurrency is very large.
            await setImmediate();
        }
    }

    // Wait for all remaining tasks
    await Promise.all(executing);
    if (outputWriteError) {
        throw outputWriteError;
    }

    return {
        results,
        stats: {
            total,
            completed,
            failed,
            ...(signal?.aborted ? { skipped: total - completed - failed } : {}),
            successRate: ((completed / total) * 100).toFixed(2) + '%'
        }
    };
}

/**
 * Main function
 * الدالة الرئيسية
 */
async function main({ signal } = {}) {
    signal?.throwIfAborted();
    const { default: config } = await import('./config.js');
    const { accountsCount, threadsCount: requestedThreads } = parseRunCounts(process.argv.slice(2));
    const threadsCount = Math.min(requestedThreads, accountsCount);
    signal?.throwIfAborted();
    prepareAccountOutputs();
    const runtime = await loadRuntime(config);
    const { logger, proxyManager } = runtime;
    const activeStops = new Set();
    const stopActiveProfiles = () => {
        for (const stop of activeStops) void stop();
    };
    signal?.addEventListener('abort', stopActiveProfiles, { once: true });

    try {
        signal?.throwIfAborted();
        logger.info('=== Gmail Account Creator Bot Started ===');
        logger.info('Configuration:', {
            accountsCount,
            threadsCount,
            hasGpmConnection: true, // GPM runs locally, no API key needed
            hasOmocaptchaKey: !!process.env.OMOCAPTCHA_KEY,
            hasSmsVerifyKey: !!process.env.SMS_VERIFY_API_KEY,
            proxyCount: proxyManager.proxies.length,
            availableProxies: proxyManager.getAvailableCount()
        });

        if (threadsCount < requestedThreads) {
            logger.warn('Threads count is greater than accounts count, setting threads to accounts count');
        }

        if (proxyManager.proxies.length < threadsCount) {
            logger.warn(`Only ${proxyManager.proxies.length} proxies available, but ${threadsCount} threads requested`);
        }

        logger.info(`Starting creation of ${accountsCount} accounts with ${threadsCount} concurrent threads`);

        const startTime = Date.now();
        
        // Process queue with concurrency control
        const { results, stats } = await processQueue(
            accountsCount,
            threadsCount,
            (accountNumber) => createAccountWithRuntime(runtime, accountNumber, { signal, activeStops }),
            logger,
            signal
        );

        const endTime = Date.now();
        const duration = ((endTime - startTime) / 1000).toFixed(2);

        // Print summary
        logger.info('=== Execution Summary ===');
        logger.info('Statistics:', {
            ...stats,
            duration: `${duration}s`,
            averageTime: `${(duration / accountsCount).toFixed(2)}s per account`
        });

        // Save run statistics and account outcomes
        const summary = {
            timestamp: new Date().toISOString(),
            configuration: {
                accountsCount,
                threadsCount,
                profileService: config.profileService || 'gpm',
                smsProvider: process.env.SMS_PROVIDER || 'sms-verification'
            },
            stats,
            duration: `${duration}s`,
            results
        };

        try {
            writeRunSummary(SUMMARY_FILE, summary);
        } catch (error) {
            throw new AccountOutputWriteError(
                'Run summary could not be saved safely in summary.json.' + accountOutputDiagnostic(error), error
            );
        }
        logger.info('Summary saved to summary.json');

        if (results.some(({ profileCleanup }) =>
            profileCleanup === 'stop-unconfirmed' || profileCleanup === 'delete-unconfirmed'
        )) {
            const error = new Error('Managed profile cleanup is unconfirmed. See summary.json for profile IDs.');
            error.code = 'PROFILE_CLEANUP_UNCONFIRMED';
            throw error;
        }
        logger.info(signal?.aborted ? '=== Bot execution interrupted ===' : '=== Bot execution completed ===');
    } catch (error) {
        if (error !== signal?.reason) logger.error('Fatal error in main', { error });
        throw error;
    } finally {
        signal?.removeEventListener('abort', stopActiveProfiles);
    }
}

export async function runCli() {
    const controller = new AbortController();
    const interrupt = (signal, exitCode) => {
        if (controller.signal.aborted) return;
        process.exitCode = exitCode;
        controller.abort(new Error(`Interrupted by ${signal}`));
    };
    const onSigint = () => interrupt('SIGINT', 130);
    const onSigterm = () => interrupt('SIGTERM', 143);
    process.on('SIGINT', onSigint);
    process.on('SIGTERM', onSigterm);

    try {
        await main({ signal: controller.signal });
    } catch (error) {
        if (error !== controller.signal.reason) {
            const safeMessage = error instanceof AccountOutputWriteError ||
                error?.code === 'INVALID_CLI_COUNT' || error?.code === 'PROFILE_CLEANUP_UNCONFIRMED' ||
                error?.code === 'PROXY_CONFIGURATION_ERROR' || error?.code === 'PRIVATE_ENV_CONFIGURATION_ERROR';
            console.error(safeMessage ? error.message : 'The run could not be completed.');
        }
        if (!controller.signal.aborted) process.exitCode = 1;
    } finally {
        process.off('SIGINT', onSigint);
        process.off('SIGTERM', onSigterm);
    }
}

// Run if this is the main module
// Check if this file is being run directly (not imported)
const isMainModule = (() => {
    if (!process.argv[1]) return false;
    try {
        const mainModulePath = pathToFileURL(path.resolve(process.argv[1])).href;
        const currentModulePath = pathToFileURL(fileURLToPath(import.meta.url)).href;
        return mainModulePath === currentModulePath;
    } catch {
        // Fallback: check if import.meta.url matches process.argv[1]
        const mainPath = process.argv[1].replace(/\\/g, '/');
        const currentPath = fileURLToPath(import.meta.url).replace(/\\/g, '/');
        return path.resolve(mainPath) === path.resolve(currentPath);
    }
})();

if (isMainModule) runCli();

export default {
    createAccount,
    main
};

