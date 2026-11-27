import { createHash, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { withAccountOutputLock, withAccountOutputLockAsync } from './account-output-lock.js';
import { readPrivateFile, writePrivateFile } from './private-storage.js';

const ATTEMPT_FIELDS = ['orderId', 'profileId', 'profileType', 'proxyIP', 'profileIP', 'timestamp'];
const SUMMARY_FIELDS = [
    'email', 'firstName', 'lastName', 'fullName', 'username', 'phone', ...ATTEMPT_FIELDS
];
const RESULT_FIELDS = ['success', 'createdAt', ...SUMMARY_FIELDS];
const UNSUCCESSFUL_RESULT_FIELDS = ['success', 'createdAt', ...ATTEMPT_FIELDS];
const TRAFFIC_PATH_FIELDS = [
    'trafficDir', 'payloadsDir', 'preTlsWireLogPath', 'trafficNdjsonPath', 'attributionIndexPath', 'harPath'
];
const TELEMETRY_FIELDS = [
    'profileId', 'presetId', 'deviceModel', 'os', 'coherenceScore', 'coherencePassed'
];
const TELEMETRY_GROUPS = {
    gpuPerformance: ['targetGpuModel', 'antiPenetrationActive'],
    securityGuards: [
        'profileId', 'portScanProtectionEnabled', 'webrtcInitScriptAttached',
        'blockedPortScanCount', 'blockedInternalSchemeCount'
    ],
    fingerprintLedger: ['profileId', 'maxHammingDistance', 'totalEntries', 'driftAlertCount']
};
const UNRESOLVED_PROFILE_CLEANUP = new Set([
    'pending', 'allocation-unconfirmed', 'stop-unconfirmed', 'delete-unconfirmed', 'recycle-unconfirmed'
]);
const PROFILE_CLEANUP = new Set(['stopped', 'deleted', 'recycled', ...UNRESOLVED_PROFILE_CLEANUP]);
const RESULT_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SUMMARY_CLEANUP_SOURCE = /^[a-f0-9]{64}$/;
const MANUAL_STAGES = new Set(['password', 'verification', 'recovery-email', 'untrusted-page', 'completion']);
const outputDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function needsProfileCleanupReview(status) {
    return UNRESOLVED_PROFILE_CLEANUP.has(status);
}

function pickScalars(source, fields) {
    const selected = {};
    for (const field of fields) {
        const value = source?.[field];
        if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
            selected[field] = value;
        }
    }
    return selected;
}

function accountFields(record, fields) {
    const selected = pickScalars(record, fields);
    if (typeof selected.proxyIP === 'string') {
        const host = selected.proxyIP.replace(/^\[(.+)\]$/, '$1');
        if (!isIP(host) && !/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.?$/i.test(host)) {
            selected.proxyIP = null;
        }
    }
    if (typeof selected.profileIP === 'string' && !isIP(selected.profileIP)) {
        selected.profileIP = null;
    }
    return selected;
}

function failureDetails(record) {
    if (record.errorCode === 'MANUAL_SIGNUP_REQUIRED') {
        return {
            error: 'Manual signup is required',
            errorCode: 'MANUAL_SIGNUP_REQUIRED',
            ...(MANUAL_STAGES.has(record.errorStage) ? { errorStage: record.errorStage } : {})
        };
    }
    if (record.errorCode === 'PROFILE_ALLOCATION_UNCONFIRMED') {
        return { error: 'Managed profile allocation is unconfirmed', errorCode: 'PROFILE_ALLOCATION_UNCONFIRMED' };
    }
    return { error: 'Account creation failed' };
}

function invalidOutput(message) {
    return Object.assign(new Error(message), { code: 'ACCOUNT_OUTPUT_INVALID_DATA' });
}

function assertAccountRecord(record, label) {
    if (!record || typeof record !== 'object' || Array.isArray(record) || typeof record.success !== 'boolean') {
        throw invalidOutput(`Invalid account record in ${label}`);
    }
}

function savedAccountRecord(record) {
    assertAccountRecord(record, 'results.json');

    const selected = accountFields(record, record.success ? RESULT_FIELDS : UNSUCCESSFUL_RESULT_FIELDS);
    if (typeof record.resultId === 'string' && RESULT_ID.test(record.resultId)) selected.resultId = record.resultId;
    if (typeof record.summaryCleanupSource === 'string' && SUMMARY_CLEANUP_SOURCE.test(record.summaryCleanupSource)) {
        selected.summaryCleanupSource = record.summaryCleanupSource;
    }
    if (PROFILE_CLEANUP.has(record.profileCleanup)) selected.profileCleanup = record.profileCleanup;
    if (selected.success === false) {
        Object.assign(selected, failureDetails(record));
    }
    if (record.trafficAttribution !== undefined) {
        selected.trafficAttribution = record.trafficAttribution === null
            ? null
            : pickScalars(record.trafficAttribution, TRAFFIC_PATH_FIELDS);
    }
    if (record.camoufoxTelemetry) {
        const telemetry = record.camoufoxTelemetry;
        selected.camoufoxTelemetry = pickScalars(telemetry, TELEMETRY_FIELDS);
        for (const [name, fields] of Object.entries(TELEMETRY_GROUPS)) {
            if (telemetry[name] !== undefined) {
                selected.camoufoxTelemetry[name] = telemetry[name] === null ? null : pickScalars(telemetry[name], fields);
            }
        }
    }
    return selected;
}

function readExistingOutput(filePath, label, { restrict = true, checkAcl = restrict } = {}) {
    let bytes;
    try {
        bytes = readPrivateFile(filePath, null, { requireOwner: true, restrict, checkAcl });
    } catch (error) {
        if (error.code === 'ENOENT') {
            return undefined;
        }
        throw error;
    }

    let content;
    try {
        content = outputDecoder.decode(bytes);
    } catch {
        throw invalidOutput(`${label} contains invalid UTF-8`);
    }
    try {
        return { content, data: JSON.parse(content) };
    } catch {
        throw invalidOutput(`${label} contains invalid JSON`);
    }
}

function projectResults(data) {
    if (!Array.isArray(data)) {
        throw invalidOutput('Account results file must contain an array');
    }
    return data.map(savedAccountRecord);
}

function projectSummary(summary) {
    if (!summary || typeof summary !== 'object' || !Array.isArray(summary.results)) {
        throw invalidOutput('Run summary file must contain a results array');
    }
    const resultIds = uniquePositions(summary.results, (entry) => entry?.resultId);
    return {
        ...pickScalars(summary, ['timestamp']),
        configuration: pickScalars(summary.configuration, ['accountsCount', 'threadsCount', 'profileService', 'smsProvider']),
        stats: pickScalars(summary.stats, ['total', 'completed', 'failed', 'manual', 'successRate', 'skipped']),
        ...pickScalars(summary, ['duration']),
        results: summary.results.map((entry, index) => {
            assertAccountRecord(entry, 'summary.json');
            const cleanup = PROFILE_CLEANUP.has(entry.profileCleanup) ? { profileCleanup: entry.profileCleanup } : {};
            if (needsProfileCleanupReview(entry.profileCleanup)) {
                if (typeof entry.resultId === 'string' && RESULT_ID.test(entry.resultId) &&
                    resultIds.get(entry.resultId) === index) {
                    cleanup.resultId = entry.resultId;
                }
                if (!entry.success) Object.assign(cleanup, pickScalars(entry, ['timestamp']));
            }
            if (entry.success) {
                const record = accountFields(entry, SUMMARY_FIELDS);
                return {
                    success: true,
                    ...Object.fromEntries(SUMMARY_FIELDS.map((field) => [field, record[field] ?? null])),
                    ...cleanup,
                    error: null
                };
            }
            return {
                success: false,
                email: null,
                ...pickScalars(entry, ['profileId', 'profileType']),
                ...cleanup,
                ...failureDetails(entry)
            };
        })
    };
}

function accountOutputMigrations(resultsFile, summaryFile, legacyDirectory) {
    const outputs = [
        { filePath: resultsFile, label: 'Account results file', project: projectResults },
        { filePath: summaryFile, label: 'Run summary file', project: projectSummary }
    ];

    return outputs.map(({ filePath, label, project }) => ({
        filePath,
        migrate(temporaryPath) {
            const existing = readExistingOutput(filePath, label);
            const legacy = !existing && legacyDirectory
                ? readExistingOutput(path.join(legacyDirectory, path.basename(filePath)), label, { restrict: false })
                : undefined;
            const source = existing || legacy;
            if (!source) return;

            const records = project(source.data);
            const updated = JSON.stringify(records, null, 2);
            if (!existing || existing.content !== updated) {
                writePrivateFile(filePath, updated, { requireOwner: true, temporaryPath });
            }
            return records;
        }
    }));
}

function migrationReview(results, errors) {
    if (errors.length) throw new AggregateError(errors, errors.map((error) => error.message).join('\n'));
    const cleanupReview = [];
    for (const [index, { resultId, profileCleanup }] of (results ?? []).entries()) {
        if (needsProfileCleanupReview(profileCleanup)) {
            cleanupReview.push({ entry: index + 1, resultId, profileCleanup });
        }
    }
    return cleanupReview;
}

function uniquePositions(records, keyFor) {
    const indexed = new Map();
    for (const [index, record] of records.entries()) {
        const key = keyFor(record);
        if (key !== undefined) indexed.set(key, indexed.has(key) ? null : index);
    }
    return indexed;
}

function legacyCleanupKey({ profileId, profileType, profileCleanup, success }) {
    const hasProfileId = (typeof profileId === 'string' && profileId.length > 0) ||
        (Number.isSafeInteger(profileId) && profileId >= 0);
    if (!needsProfileCleanupReview(profileCleanup) || !hasProfileId) return;
    return JSON.stringify([profileId, profileType ?? null, profileCleanup, success]);
}

function recoverSummaryCleanup(resultsFile, summary, withLock) {
    return updateResults(resultsFile, (results) => {
        const resultsById = uniquePositions(results, ({ resultId }) => resultId);
        const legacyResults = uniquePositions(results, legacyCleanupKey);
        const legacySummary = uniquePositions(summary.results, legacyCleanupKey);
        const recovered = new Set(results.map(({ summaryCleanupSource }) => summaryCleanupSource));

        for (const [index, entry] of summary.results.entries()) {
            if (!needsProfileCleanupReview(entry.profileCleanup)) continue;
            const { success, resultId, profileId, profileType, profileCleanup, timestamp } = entry;
            // Make repeated imports of the same summary row idempotent, even after
            // its recovered cleanup has been confirmed in results.json.
            const source = createHash('sha256').update(JSON.stringify([
                summary.timestamp, index, success, resultId, profileId, profileType, profileCleanup, timestamp,
                entry.errorCode, entry.errorStage
            ])).digest('hex');
            if (recovered.has(source)) continue;

            const position = resultsById.get(resultId);
            const result = results[position];
            if (result?.success === success && ['profileId', 'profileType', 'timestamp'].every((field) =>
                result[field] == null || entry[field] == null || result[field] === entry[field])) {
                const status = result.profileCleanup;
                if (status === undefined || needsProfileCleanupReview(status)) {
                    results[position] = savedAccountRecord({
                        ...result,
                        profileId: profileId ?? result.profileId,
                        profileType: profileType ?? result.profileType,
                        timestamp: timestamp ?? result.timestamp,
                        profileCleanup: status === undefined || status === 'pending' ? profileCleanup : status
                    });
                }
                continue;
            }

            // An older summary may omit the result ID. Match only a single equivalent
            // unresolved cleanup state, accounting for reused controller profile IDs.
            const legacyKey = legacyCleanupKey(entry);
            const legacyResult = !resultId && legacySummary.get(legacyKey) === index &&
                results[legacyResults.get(legacyKey)];
            if (legacyResult && (timestamp == null || legacyResult.timestamp == null ||
                timestamp === legacyResult.timestamp)) continue;

            results.push(savedAccountRecord({
                ...pickScalars(entry, ['success', 'profileId', 'profileType', 'profileCleanup', 'timestamp',
                    'errorCode', 'errorStage']),
                resultId: resultId && !resultsById.has(resultId) ? resultId : randomUUID(),
                summaryCleanupSource: source
            }));
        }
        return results;
    }, withLock);
}

export function migrateExistingAccountOutputs(resultsFile, summaryFile, { legacyDirectory } = {}) {
    const errors = [];
    const [results, summary] = accountOutputMigrations(resultsFile, summaryFile, legacyDirectory).map(({ filePath, migrate }) => {
        try {
            return withAccountOutputLock(filePath, migrate);
        } catch (error) {
            errors.push(error);
            return undefined;
        }
    });
    if (!errors.length && summary?.results.some(({ profileCleanup }) => needsProfileCleanupReview(profileCleanup))) {
        return migrationReview(recoverSummaryCleanup(resultsFile, summary, withAccountOutputLock), errors);
    }
    return migrationReview(results, errors);
}

export async function migrateExistingAccountOutputsAsync(resultsFile, summaryFile, { legacyDirectory, signal } = {}) {
    const errors = [];
    const [resultsJob, summaryJob] = accountOutputMigrations(resultsFile, summaryFile, legacyDirectory);
    const migrateJob = async ({ filePath, migrate }) => {
        try {
            return await withAccountOutputLockAsync(filePath, migrate, { signal });
        } catch (error) {
            signal?.throwIfAborted();
            errors.push(error);
            return undefined;
        }
    };
    const results = await migrateJob(resultsJob);
    const summary = await migrateJob(summaryJob);
    if (!errors.length && summary?.results.some(({ profileCleanup }) => needsProfileCleanupReview(profileCleanup))) {
        const withLock = (filePath, operation) => withAccountOutputLockAsync(filePath, operation, { signal });
        return migrationReview(await recoverSummaryCleanup(resultsFile, summary, withLock), errors);
    }
    return migrationReview(results, errors);
}

function updateResults(filePath, update, withLock) {
    return withLock(filePath, (temporaryPath) => {
        const existing = readExistingOutput(filePath, 'Account results file');
        const results = existing ? projectResults(existing.data) : [];
        const updated = update(results);
        const content = JSON.stringify(results, null, 2);
        if (existing?.content !== content) {
            writePrivateFile(filePath, content, { requireOwner: true, temporaryPath });
        }
        return updated;
    });
}

function appendResult(filePath, record, withLock) {
    const added = savedAccountRecord({ ...record, createdAt: new Date().toISOString(), resultId: randomUUID() });
    return updateResults(filePath, (results) => {
        results.push(added);
        return added;
    }, withLock);
}

export function appendAccountResult(filePath, record) {
    return appendResult(filePath, record, withAccountOutputLock);
}

export async function appendAccountResultAsync(filePath, record) {
    return appendResult(filePath, record, withAccountOutputLockAsync);
}

function resultForCleanup(results, resultId) {
    const matches = results.filter((entry) => entry.resultId === resultId);
    if (matches.length > 1) throw invalidOutput('More than one result matches the cleanup ID in results.json.');
    const [record] = matches;
    if (!record) throw invalidOutput('The result to update is missing from results.json.');
    return record;
}

export function readSavedAccountCleanup(filePath, savedResult) {
    try {
        const existing = readExistingOutput(filePath, 'Account results file', { restrict: false, checkAcl: true });
        if (!existing) return undefined;
        const record = resultForCleanup(projectResults(existing.data), savedResult.resultId);
        if (record.createdAt === savedResult.createdAt && record.profileId === savedResult.profileId) {
            return { resultId: record.resultId, profileCleanup: record.profileCleanup };
        }
    } catch {
        // Keep the write error primary when the saved record cannot be verified.
    }
    return undefined;
}

function updateAccountCleanup(filePath, resultId, profileCleanup, withLock) {
    if (typeof resultId !== 'string' || !RESULT_ID.test(resultId)) {
        throw invalidOutput('Invalid result ID for profile cleanup.');
    }
    if (!PROFILE_CLEANUP.has(profileCleanup) || profileCleanup === 'pending') {
        throw invalidOutput('Invalid profile cleanup outcome.');
    }
    return updateResults(filePath, (results) => {
        const record = resultForCleanup(results, resultId);
        record.profileCleanup = profileCleanup;
        return record;
    }, withLock);
}

export function recordAccountCleanup(filePath, resultId, profileCleanup) {
    return updateAccountCleanup(filePath, resultId, profileCleanup, withAccountOutputLock);
}

export async function recordAccountCleanupAsync(filePath, resultId, profileCleanup) {
    return updateAccountCleanup(filePath, resultId, profileCleanup, withAccountOutputLockAsync);
}

function saveRunSummary(filePath, summary, withLock) {
    return withLock(filePath, (temporaryPath) => {
        writePrivateFile(filePath, JSON.stringify(projectSummary(summary), null, 2), { requireOwner: true, temporaryPath });
    });
}

export function writeRunSummary(filePath, summary) {
    saveRunSummary(filePath, summary, withAccountOutputLock);
}

export async function writeRunSummaryAsync(filePath, summary) {
    return saveRunSummary(filePath, summary, withAccountOutputLockAsync);
}
