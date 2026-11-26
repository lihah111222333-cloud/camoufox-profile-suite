import { isIP } from 'node:net';
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
    gpuPerformance: [
        'targetGpuModel', 'hostChipModel', 'computeTimeMultiplier', 'throughputSpeedupRatio',
        'antiPenetrationActive'
    ],
    securityGuards: [
        'profileId', 'portScanProtectionEnabled', 'webrtcInitScriptAttached',
        'blockedPortScanCount', 'blockedInternalSchemeCount'
    ],
    fingerprintLedger: ['profileId', 'maxHammingDistance', 'totalEntries', 'driftAlertCount']
};
const MANUAL_STAGES = new Set(['password', 'verification', 'recovery-email', 'untrusted-page', 'completion']);

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
    return { error: 'Account creation failed' };
}

function assertAccountRecord(record, label) {
    if (!record || typeof record !== 'object' || Array.isArray(record) || typeof record.success !== 'boolean') {
        throw new Error(`Invalid account record in ${label}`);
    }
}

function savedAccountRecord(record) {
    assertAccountRecord(record, 'results.json');

    const selected = accountFields(record, RESULT_FIELDS);
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

function readExistingOutput(filePath, label) {
    let content;
    try {
        content = readPrivateFile(filePath);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return undefined;
        }
        throw error;
    }

    try {
        return { content, data: JSON.parse(content) };
    } catch {
        throw new Error(`${label} contains invalid JSON`);
    }
}

function projectResults(data) {
    if (!Array.isArray(data)) {
        throw new Error('Account results file must contain an array');
    }
    return data.map(savedAccountRecord);
}

function projectSummary(summary) {
    if (!summary || typeof summary !== 'object' || !Array.isArray(summary.results)) {
        throw new Error('Run summary file must contain a results array');
    }
    return {
        ...pickScalars(summary, ['timestamp']),
        configuration: pickScalars(summary.configuration, ['accountsCount', 'threadsCount', 'profileService', 'smsProvider']),
        stats: pickScalars(summary.stats, ['total', 'completed', 'failed', 'successRate']),
        ...pickScalars(summary, ['duration']),
        results: summary.results.map((entry) => {
            assertAccountRecord(entry, 'summary.json');
            if (entry.success) {
                const record = accountFields(entry, SUMMARY_FIELDS);
                return {
                    success: true,
                    ...Object.fromEntries(SUMMARY_FIELDS.map((field) => [field, record[field] ?? null])),
                    error: null
                };
            }
            return { success: false, email: null, ...failureDetails(entry) };
        })
    };
}

export function migrateExistingAccountOutputs(resultsFile, summaryFile) {
    const outputs = [
        { filePath: resultsFile, label: 'Account results file', project: projectResults },
        { filePath: summaryFile, label: 'Run summary file', project: projectSummary }
    ];
    const errors = [];
    for (const { filePath, label, project } of outputs) {
        try {
            const existing = readExistingOutput(filePath, label);
            if (existing) {
                const updated = JSON.stringify(project(existing.data), null, 2);
                if (existing.content !== updated) {
                    writePrivateFile(filePath, updated);
                }
            }
        } catch (error) {
            errors.push(error);
        }
    }
    if (errors.length) {
        throw new AggregateError(errors, errors.map((error) => error.message).join('\n'));
    }
}

export function appendAccountResult(filePath, record) {
    const existing = readExistingOutput(filePath, 'Account results file');
    const results = existing ? projectResults(existing.data) : [];
    const added = savedAccountRecord({ ...record, createdAt: new Date().toISOString() });
    results.push(added);
    writePrivateFile(filePath, JSON.stringify(results, null, 2));
    return added;
}

export function writeRunSummary(filePath, summary) {
    writePrivateFile(filePath, JSON.stringify(projectSummary(summary), null, 2));
}
