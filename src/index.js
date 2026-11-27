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
import { parseRunCountOptions, resolveRunCounts } from './utils/cli-counts.js';
import { requireControllerProfileId } from './utils/controller-id.js';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const PROFILE_TYPES = new Set(['Camoufox', 'Dolphin Anty', 'GPM Login']);
const UNCONFIRMED_CLEANUP = new Set([
    'allocation-unconfirmed', 'stop-unconfirmed', 'delete-unconfirmed', 'recycle-unconfirmed'
]);
const MANUAL_SIGNUP_REQUIRED = 'MANUAL_SIGNUP_REQUIRED';

function accountOutputDiagnostic(error) {
    if (error?.code === 'ACCOUNT_OUTPUT_INVALID_DATA' || error?.code === 'ACCOUNT_OUTPUT_LOCK_FAILED') {
        return ' ' + error.message;
    }
    return '';
}

async function prepareAccountOutputs(signal) {
    const { ensureStateDirectory, LEGACY_DIRECTORY, STATE_DIRECTORY } = await import('./utils/state-paths.js');
    signal?.throwIfAborted();
    const resultsFile = path.join(STATE_DIRECTORY, 'results.json');
    const summaryFile = path.join(STATE_DIRECTORY, 'summary.json');
    try {
        ensureStateDirectory();
        migrateExistingAccountOutputs(resultsFile, summaryFile, { legacyDirectory: LEGACY_DIRECTORY });
    } catch (error) {
        const details = error instanceof AggregateError
            ? error.errors.map(accountOutputDiagnostic).join('')
            : accountOutputDiagnostic(error);
        throw new AccountOutputWriteError(
            'Could not prepare results.json or summary.json in the application state directory.' + details, error
        );
    }
    return { resultsFile, summaryFile };
}

class AccountOutputWriteError extends Error {
    #outputMessage;

    constructor(message, cause) {
        super(message, { cause });
        this.#outputMessage = message;
        this.code = 'ACCOUNT_OUTPUT_WRITE_FAILED';
        this.unconfirmedProfiles = [];
    }

    addUnconfirmedProfiles(outcomes) {
        for (const { profileId, profileType, profileCleanup } of outcomes) {
            if (!UNCONFIRMED_CLEANUP.has(profileCleanup)) continue;
            const report = {
                profileType: PROFILE_TYPES.has(profileType) ? profileType : 'Profile',
                profileCleanup
            };
            try {
                report.profileId = requireControllerProfileId(profileId);
            } catch {
                // Preserve the cleanup status when no printable profile ID is available.
            }
            this.unconfirmedProfiles.push(report);
        }
        if (this.unconfirmedProfiles.length) {
            const details = new Set(this.unconfirmedProfiles.map(({ profileId, profileType, profileCleanup }) =>
                `${profileType} ${profileId ?? '(profile ID unavailable)'} (${profileCleanup})`));
            this.message = `${this.#outputMessage} Managed profile cleanup is unconfirmed. ${[...details].join(', ')}.`;
        }
    }
}

async function loadRuntime(config, resultsFile) {
    const { default: proxyManager } = await import('./utils/proxy-manager.js');
    const directConnection = proxyManager.proxies.length === 0;
    if (directConnection) {
        const supportsDirectConnection = config.profileService === 'camoufox' &&
            config.camoufox.portScanProtectionMode === 'url-only';
        if (!supportsDirectConnection || config.app.allowDirectConnection !== true) {
            const hint = supportsDirectConnection ? ' To allow direct Camoufox use, set CAMOUFOX_ALLOW_DIRECT=true.' : '';
            throw Object.assign(new Error('No proxies available. Add a proxy to config/proxies.txt.' + hint), {
                code: 'PROXY_CONFIGURATION_ERROR'
            });
        }
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
    return { config, resultsFile, logger, proxyManager, nameGenerator, createGmailAccount, directConnection };
}

/**
 * Save account result
 * حفظ نتيجة الحساب
 */
function saveResult(resultsFile, result, logger) {
    let saved;
    try {
        saved = appendAccountResult(resultsFile, result);
    } catch (error) {
        const message = result.success
            ? 'An account was created and its result could not be saved safely in results.json.'
            : 'The account attempt outcome could not be saved safely in results.json.';
        throw new AccountOutputWriteError(message + accountOutputDiagnostic(error), error);
    }
    logger.info('Result saved');
    return saved;
}

/**
 * Create single Gmail account
 * إنشاء حساب Gmail واحد
 */
async function createAccount(accountNumber = null) {
    const { default: config } = await import('./config.js');
    const { resultsFile } = await prepareAccountOutputs();
    const { result, failure } = await createAccountWithRuntime(await loadRuntime(config, resultsFile), accountNumber);
    if (!result.success) throw failure;
    return result;
}

async function createAccountWithRuntime(runtime, accountNumber, { signal, activeStops } = {}) {
    const { config, resultsFile, logger, proxyManager, nameGenerator, createGmailAccount, directConnection } = runtime;
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
    let outputWriteError;
    const saveOutcome = outcome => {
        try {
            return saveResult(resultsFile, outcome, logger);
        } catch (error) {
            if (error instanceof AccountOutputWriteError) outputWriteError = error;
            throw error;
        }
    };
    const stop = () => {
        stopping ??= (async () => {
            try {
                if (await profile.stop() === true) {
                    logger.info(`${accountLabel} Profile stopped`, { profileType: serviceName });
                    return 'stopped';
                }
            } catch {
                // A thrown stop failure is also unconfirmed.
            }
            logger.warn(`${accountLabel} Profile shutdown unconfirmed`, {
                profileId: profile.profileId,
                profileType: serviceName
            });
            return 'stop-unconfirmed';
        })();
        return stopping;
    };

    try {
        signal?.throwIfAborted();
        logger.info(`${accountLabel} === Starting Gmail Account Creation ===`);

        // Step 1: Get proxy
        proxy = proxyManager.getNextProxy();
        if (proxy) {
            logger.info(`${accountLabel} Proxy selected`);
        } else if (directConnection) {
            logger.warn(`${accountLabel} No proxies configured. Proceeding with the explicitly allowed direct connection.`);
        } else {
            throw new Error('No proxies available');
        }

        // Step 2: Generate account data
        const accountData = nameGenerator.generateAccountData();

        // Step 3: Create profile based on selected service
        const profileName = `Gmail_${randomUUID()}`;
        
        logger.info(`${accountLabel} Creating ${serviceName} profile`);
        
        // Format proxy according to service
        signal?.throwIfAborted();
        if (profileService === 'camoufox') {
            const { createAndStartProfile: createAndStartCamoufoxProfile } = await import('./camoufox/profile.js');
            signal?.throwIfAborted();
            const camoufoxProxy = proxy ? proxyManager.getCamoufoxFormat(proxy) : null;
            profile = await createAndStartCamoufoxProfile(profileName, camoufoxProxy, {
                signal,
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
                canvasSkipHosts: config.camoufox?.canvasSkipHosts,
                maxHammingDistance: config.camoufox?.maxHammingDistance,
                profilesDir: config.camoufox?.storageDir,
                accountId: accountNumber,
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
            profile = await createAndStartDolphinProfile(profileName, dolphinProxy, { signal });
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
            profile = await createAndStartGPMProfile(profileName, gpmProxy, { signal });
        }

        activeStops?.add(stop);
        signal?.throwIfAborted();

        logger.info(`${accountLabel} Profile created and started`, { profileType: serviceName });

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
        signal?.throwIfAborted();
        const result = await createGmailAccount(page, accountData, { profile, signal });

        const finalCamoufoxTelemetry =
            typeof profile?.getTelemetrySummary === 'function' ? profile.getTelemetrySummary() : null;

        // Save account outcome before attempting cleanup.
        savedResult = saveOutcome({
            ...result,
            success: true,
            profileId: profile.profileId,
            profileType: serviceName,
            profileCleanup: 'pending',
            proxyIP: proxy ? proxy.ip : null,
            trafficAttribution: profile.trafficPaths || null,
            ...(finalCamoufoxTelemetry ? { camoufoxTelemetry: finalCamoufoxTelemetry } : {}),
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        if (error instanceof AccountOutputWriteError) throw error;
        failure = error;

        const profileId = profile?.profileId ?? error?.profileId ?? null;
        profileCleanup = profile ? 'pending' : error?.profileCleanup;
        savedResult = saveOutcome({
            success: false,
            errorCode: error?.code,
            errorStage: error?.stage,
            profileId,
            ...(profileId !== null || UNCONFIRMED_CLEANUP.has(profileCleanup) ? { profileType: serviceName } : {}),
            trafficAttribution: profile?.trafficPaths || null,
            profileCleanup,
            timestamp: new Date().toISOString()
        });
    } finally {
        activeStops?.delete(stop);
        if (profile) profileCleanup = await stop();
        outputWriteError?.addUnconfirmedProfiles([{
            profileId: profile?.profileId ?? failure?.profileId,
            profileType: serviceName,
            profileCleanup
        }]);
    }

    let result = savedResult;
    if (profile) {
        try {
            result = recordAccountCleanup(resultsFile, savedResult.resultId, profileCleanup);
        } catch (error) {
            const writeError = new AccountOutputWriteError(
                'Could not save profile cleanup in results.json.' + accountOutputDiagnostic(error), error
            );
            writeError.addUnconfirmedProfiles([{ profileId: profile.profileId, profileType: serviceName, profileCleanup }]);
            throw writeError;
        }
    }
    if (result.success) {
        logger.info(`${accountLabel} === Account Creation Completed Successfully ===`);
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
    let manual = 0;
    let outputWriteError;
    const additionalUnconfirmedProfiles = [];

    const executeTask = async (index) => {
        try {
            logger.info(`[Thread ${index + 1}] Starting account attempt ${index + 1}/${total}`);
            const { result, failure } = await createTask(index + 1);
            results.push(result);
            if (result.success) {
                completed++;
                logger.info(`[Thread ${index + 1}] Account created successfully (${completed} success, ${failed} failed)`);
            } else if (result.errorCode === MANUAL_SIGNUP_REQUIRED) {
                manual++;
            } else {
                failed++;
                logger.error(`[Thread ${index + 1}] Account creation failed (${completed} success, ${failed} failed)`, {
                    error: failure
                });
            }
        } catch (error) {
            if (error instanceof AccountOutputWriteError) {
                if (outputWriteError) {
                    additionalUnconfirmedProfiles.push(...error.unconfirmedProfiles);
                } else {
                    outputWriteError = error;
                }
                return;
            }
            failed++;
            results.push({
                success: false,
                errorCode: error?.code,
                errorStage: error?.stage
            });
            logger.error(`[Thread ${index + 1}] Account creation failed (${completed} success, ${failed} failed)`, {
                error
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
        outputWriteError.addUnconfirmedProfiles(results.concat(additionalUnconfirmedProfiles));
        throw outputWriteError;
    }

    return {
        results,
        stats: {
            total,
            completed,
            failed,
            manual,
            ...(signal?.aborted ? { skipped: total - completed - failed - manual } : {}),
            successRate: ((completed / total) * 100).toFixed(2) + '%'
        }
    };
}

/**
 * Main function
 * الدالة الرئيسية
 */
async function main({ signal, failIfAllAttemptsFail = false } = {}) {
    signal?.throwIfAborted();
    const args = process.argv.slice(2);
    if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) {
        console.log([
            'Usage: gmail-account-creator [--accounts=N] [--threads=N]',
            '       gmail-account-creator --help',
            '       gmail-account-creator --version',
            '',
            'Counts can also be set with -a=N and -t=N.'
        ].join('\n'));
        return;
    }
    if (args.length === 1 && (args[0] === '--version' || args[0] === '-v')) {
        console.log(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
        return;
    }
    const countOptions = parseRunCountOptions(args);
    const { default: config } = await import('./config.js');
    const { accountsCount, threadsCount: requestedThreads } = resolveRunCounts(countOptions);
    const threadsCount = Math.min(requestedThreads, accountsCount);
    signal?.throwIfAborted();
    const { resultsFile, summaryFile } = await prepareAccountOutputs(signal);
    const runtime = await loadRuntime(config, resultsFile);
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
            profileService: config.profileService || 'gpm',
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
            writeRunSummary(summaryFile, summary);
        } catch (error) {
            const writeError = new AccountOutputWriteError(
                'Run summary could not be saved safely in summary.json.' + accountOutputDiagnostic(error), error
            );
            writeError.addUnconfirmedProfiles(results);
            throw writeError;
        }
        logger.info('Summary saved to summary.json');

        if (results.some(({ profileCleanup }) => UNCONFIRMED_CLEANUP.has(profileCleanup))) {
            const error = new Error('Managed profile cleanup is unconfirmed. Review summary.json and resolve the reported cleanup before continuing.');
            error.code = 'PROFILE_CLEANUP_UNCONFIRMED';
            throw error;
        }
        if (failIfAllAttemptsFail && !signal?.aborted && stats.failed === stats.total) {
            const error = new Error('All account attempts failed. See summary.json for details.');
            error.code = 'ACCOUNT_ATTEMPTS_FAILED';
            throw error;
        }
        if (!signal?.aborted && results.some(({ errorCode, profileCleanup }) =>
            errorCode === MANUAL_SIGNUP_REQUIRED && profileCleanup === 'stopped')) {
            logger.warn('Continue signup manually in a trusted browser you control.');
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
        await main({ signal: controller.signal, failIfAllAttemptsFail: true });
    } catch (error) {
        if (error !== controller.signal.reason) {
            const safeMessage = error instanceof AccountOutputWriteError ||
                error?.code === 'INVALID_CLI_COUNT' || error?.code === 'INVALID_CLI_ARGUMENT' ||
                error?.code === 'PROFILE_CLEANUP_UNCONFIRMED' || error?.code === 'ACCOUNT_ATTEMPTS_FAILED' ||
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

