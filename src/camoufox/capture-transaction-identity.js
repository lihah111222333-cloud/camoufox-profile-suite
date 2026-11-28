import {
    captureEventProfileId, captureEventTraceId, validRecordedProfileId
} from './capture-export-policy.js';
import { isAnonymousProfileId, redactProfileId } from './traffic-redaction.js';

const observationPhases = new Map([
    ['egress', 'request'],
    ['security-block', 'request'],
    ['ingress', 'response'],
    ['request-finished', 'completion'],
    ['request-failed', 'completion']
]);

export function captureTransactionPhase(event) {
    return observationPhases.get(event?.type);
}

export function captureEventAccountId(event) {
    const id = Object.hasOwn(event?.attribution ?? {}, 'accountId')
        ? event.attribution.accountId : event?.accountId;
    if (Number.isSafeInteger(id)) return id;
    return typeof id === 'string' && id.trim() && id !== '[REDACTED]' ? id : null;
}

function recordedProfileId(event) {
    const id = captureEventProfileId(event);
    return id === null ? null : validRecordedProfileId(id);
}

export function captureIdentityObservation(event) {
    return {
        type: event.type,
        correlationId: event.correlationId,
        traceId: captureEventTraceId(event),
        profileId: captureEventProfileId(event),
        accountId: captureEventAccountId(event),
        profileContinuityUnproven: event.attribution?.profileContinuityUnproven
    };
}

function groupBy(observations, getKey) {
    const groups = new Map();
    for (const event of observations) {
        const key = getKey(event);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(event);
    }
    return groups;
}

/** Compare recorded identities before any labels are projected for display. */
export function createCaptureTransactionIndex(events, { profileScoped = false } = {}) {
    const legacyOwnersByTrace = new Map();
    const recorded = new Map();
    const sourceRows = [];
    for (const event of events) {
        const traceId = captureEventTraceId(event);
        const profileId = recordedProfileId(event);
        const alias = redactProfileId(profileId);
        if (alias !== profileId && isAnonymousProfileId(alias)) {
            if (!legacyOwnersByTrace.has(traceId)) legacyOwnersByTrace.set(traceId, new Map());
            const owners = legacyOwnersByTrace.get(traceId);
            owners.set(alias, !owners.has(alias) || owners.get(alias) === profileId ? profileId : null);
        }
        if (!event?.correlationId) continue;
        sourceRows.push(event);
        recorded.set(event, { profileId, traceId, accountId: captureEventAccountId(event) });
    }

    const profileOf = (event) => {
        const { profileId, traceId } = recorded.get(event) ?? {
            profileId: recordedProfileId(event),
            traceId: captureEventTraceId(event)
        };
        if (!isAnonymousProfileId(profileId)) return profileId;
        const owners = legacyOwnersByTrace.get(traceId);
        if (!owners?.has(profileId)) return profileId;
        return owners.get(profileId) ?? undefined;
    };

    const byObservation = new Map();
    const correlationGroups = groupBy(sourceRows, (event) =>
        JSON.stringify([recorded.get(event).traceId, event.correlationId]));
    for (const rows of correlationGroups.values()) {
        const knownProfiles = new Set(rows.map(profileOf).filter(Boolean));
        const soleProfile = !profileScoped && knownProfiles.size === 1 ? knownProfiles.values().next().value : null;
        const hasProfileConflict = knownProfiles.size > 1;
        const hasAmbiguousAlias = rows.some((event) => profileOf(event) === undefined);
        const profileGroups = groupBy(rows, (event) => {
            const profile = profileOf(event);
            if (profile === undefined || (profile === null && (profileScoped || hasProfileConflict))) return event;
            return profile ?? soleProfile;
        });

        const transactions = [];
        for (const [profile, profileRows] of profileGroups) {
            const knownAccounts = new Set(profileRows.map((event) => recorded.get(event).accountId).filter((id) => id !== null));
            const soleAccount = knownAccounts.size === 1 ? knownAccounts.values().next().value : null;
            const accountGroups = groupBy(profileRows, (event) => {
                const account = recorded.get(event).accountId;
                return account ?? (knownAccounts.size > 1 ? event : soleAccount);
            });

            for (const [account, accountRows] of accountGroups) {
                const phases = new Set();
                const firstContinuity =
                    (accountRows[0].attribution?.profileContinuityUnproven ?? accountRows[0].profileContinuityUnproven) === true;
                const hasConflictingPhases = accountRows.some((event) => {
                    const phase = captureTransactionPhase(event);
                    if (!phase) return false;
                    const unproven =
                        (event.attribution?.profileContinuityUnproven ?? event.profileContinuityUnproven) === true;
                    if (phases.has(phase) || (isAnonymousProfileId(profile) && unproven !== firstContinuity)) return true;
                    phases.add(phase);
                    return false;
                });
                const addTransaction = (observations) => {
                    const first = observations[0];
                    const transaction = {
                        correlationId: first.correlationId,
                        traceId: recorded.get(first).traceId,
                        profileId: typeof profile === 'object' ? null : profile,
                        accountId: typeof account === 'object' ? null : account,
                        observations,
                        hasProfileConflict,
                        hasAmbiguousAlias,
                        hasConflictingPhases
                    };
                    transactions.push(transaction);
                    for (const event of observations) byObservation.set(event, transaction);
                };
                if (hasConflictingPhases) {
                    for (const event of accountRows) addTransaction([event]);
                } else {
                    addTransaction(accountRows);
                }
            }
        }
        for (const transaction of transactions) transaction.hasSharedCorrelation = transactions.length > 1;
    }

    const transactions = [...new Set(sourceRows.map((event) => byObservation.get(event)))];
    const byCorrelation = groupBy(transactions, (transaction) => transaction.correlationId);
    return { transactions, byCorrelation, profileOf, get: (event) => byObservation.get(event) ?? null };
}
