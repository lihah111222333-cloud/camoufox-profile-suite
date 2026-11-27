import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { withAccountOutputLock } from './account-output-lock.js';
import { readPrivateFile, writePrivateFile } from './private-storage.js';

const SUMMARY_FIELDS = [
    'email', 'firstName', 'lastName', 'fullName', 'username', 'phone', 'orderId',
    'profileId', 'profileType', 'proxyIP', 'profileIP', 'timestamp'
];
const RESULT_FIELDS = ['success', 'createdAt', ...SUMMARY_FIELDS];
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
const PROFILE_CLEANUP = new Set([
    'pending', 'stopped', 'stop-unconfirmed', 'deleted', 'delete-unconfirmed',
    'allocation-unconfirmed', 'recycled', 'recycle-unconfirmed'
]);
const RESULT_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const MANUAL_STAGES = new Set(['password', 'verification', 'recovery-email', 'untrusted-page', 'completion']);
const outputDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

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

    const selected = accountFields(record, RESULT_FIELDS);
    if (typeof record.resultId === 'string' && RESULT_ID.test(record.resultId)) selected.resultId = record.resultId;
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

function readExistingOutput(filePath, label, { restrict = true } = {}) {
    let bytes;
    try {
        bytes = readPrivateFile(filePath, null, { requireOwner: true, restrict });
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
    return {
        ...pickScalars(summary, ['timestamp']),
        configuration: pickScalars(summary.configuration, ['accountsCount', 'threadsCount', 'profileService', 'smsProvider']),
        stats: pickScalars(summary.stats, ['total', 'completed', 'failed', 'manual', 'successRate', 'skipped']),
        ...pickScalars(summary, ['duration']),
        results: summary.results.map((entry) => {
            assertAccountRecord(entry, 'summary.json');
            const cleanup = PROFILE_CLEANUP.has(entry.profileCleanup) ? { profileCleanup: entry.profileCleanup } : {};
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

export function migrateExistingAccountOutputs(resultsFile, summaryFile, { legacyDirectory } = {}) {
    const outputs = [
        { filePath: resultsFile, label: 'Account results file', project: projectResults },
        { filePath: summaryFile, label: 'Run summary file', project: projectSummary }
    ];
    const errors = [];
    for (const { filePath, label, project } of outputs) {
        try {
            withAccountOutputLock(filePath, (temporaryPath) => {
                const existing = readExistingOutput(filePath, label);
                const legacy = !existing && legacyDirectory
                    ? readExistingOutput(path.join(legacyDirectory, path.basename(filePath)), label, { restrict: false })
                    : undefined;
                const source = existing || legacy;
                if (!source) return;

                const updated = JSON.stringify(project(source.data), null, 2);
                if (!existing || existing.content !== updated) {
                    writePrivateFile(filePath, updated, { requireOwner: true, temporaryPath });
                }
            });
        } catch (error) {
            errors.push(error);
        }
    }
    if (errors.length) {
        throw new AggregateError(errors, errors.map((error) => error.message).join('\n'));
    }
}

function updateResults(filePath, update) {
    return withAccountOutputLock(filePath, (temporaryPath) => {
        const existing = readExistingOutput(filePath, 'Account results file');
        const results = existing ? projectResults(existing.data) : [];
        const updated = update(results);
        writePrivateFile(filePath, JSON.stringify(results, null, 2), { requireOwner: true, temporaryPath });
        return updated;
    });
}

export function appendAccountResult(filePath, record) {
    const added = savedAccountRecord({ ...record, createdAt: new Date().toISOString(), resultId: randomUUID() });
    return updateResults(filePath, (results) => {
        results.push(added);
        return added;
    });
}

export function recordAccountCleanup(filePath, resultId, profileCleanup) {
    if (typeof resultId !== 'string' || !RESULT_ID.test(resultId)) {
        throw invalidOutput('Invalid result ID for profile cleanup.');
    }
    if (!PROFILE_CLEANUP.has(profileCleanup) || profileCleanup === 'pending') {
        throw invalidOutput('Invalid profile cleanup outcome.');
    }
    return updateResults(filePath, (results) => {
        const record = results.find((entry) => entry.resultId === resultId);
        if (!record) throw invalidOutput('The result to update is missing from results.json.');
        record.profileCleanup = profileCleanup;
        return record;
    });
}

export function writeRunSummary(filePath, summary) {
    withAccountOutputLock(filePath, (temporaryPath) => {
        writePrivateFile(filePath, JSON.stringify(projectSummary(summary), null, 2), { requireOwner: true, temporaryPath });
    });
}
