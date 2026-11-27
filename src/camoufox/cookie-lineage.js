import crypto from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { redactDiagnosticText, redactUrlSecrets } from './traffic-redaction.js';

/**
 * Known anti-bot, risk-control, and session authentication cookie/token names across
 * Google, Cloudflare, Meta/Instagram, TikTok, and X/Twitter.
 */
export const ANTI_BOT_COOKIE_REGEX =
    /^(datr|sb|fr|c_user|xs|ig_did|mid|csrftoken|rur|ttwid|msToken|s_v_web_id|verifyFp|odin_tt|passport_csrf_token|guest_id|guest_id_marketing|guest_id_ads|ct0|auth_token|kdt|_twitter_sess|__cf_bm|cf_clearance|_cfuvid|NID|AEC|SOCS|SID|HSID|SSID|APISID|SAPISID|__Secure-[0-9A-Za-z_-]+|__Host-[0-9A-Za-z_-]+)$/i;

const COOKIE_VALUE_MASK = '[REDACTED]';
const COOKIE_PATH_MASK = /\[REDACTED(?::[a-f\d]{8})?\]|%5BREDACTED(?:%3A[a-f\d]{8})?%5D|\bprofile-legacy-\d{13}(?:-\d{1,8})?(?![a-z\d_-])/i;

/**
 * Parse a `Set-Cookie` response header string into structured metadata with a full
 * SHA-256 value digest (`valueSha256`) and masked preview (`maskedValue`) for
 * tamper-evident token rotation and lineage tracking.
 *
 * @param {string} rawSetCookieValue
 * @param {number} [observedAt=Date.now()]
 * @returns {{
 *   name: string,
 *   value: string,
 *   valueSha256: string,
 *   maskedValue: string,
 *   domain: string|null,
 *   path: string|null,
 *   secure: boolean,
 *   httpOnly: boolean,
 *   sameSite: string|null,
 *   partitioned: boolean,
 *   expires: string|null,
 *   maxAge: number|null,
 *   isDeleted: boolean,
 *   isAntiBotToken: boolean
 * }|null}
 */
export function parseSetCookieHeader(rawSetCookieValue, observedAt = Date.now()) {
    const parsed = parseSetCookie(rawSetCookieValue, observedAt);
    if (parsed?.path) parsed.path = redactUrlSecrets(parsed.path);
    return parsed;
}

function parseSetCookie(rawSetCookieValue, observedAt) {
    if (typeof rawSetCookieValue !== 'string') {
        return null;
    }
    const trimmedHeader = rawSetCookieValue.trim();
    if (!trimmedHeader) {
        return null;
    }

    const parts = trimmedHeader.split(';');
    const firstPart = (parts[0] || '').trim();
    const eqIdx = firstPart.indexOf('=');
    if (eqIdx <= 0) {
        return null;
    }

    const name = firstPart.slice(0, eqIdx).trim();
    if (!name) {
        return null;
    }
    const value = firstPart.slice(eqIdx + 1).trim();
    const valueSha256 = crypto.createHash('sha256').update(value, 'utf8').digest('hex');
    const maskedValue = COOKIE_VALUE_MASK;

    let domain = null;
    let cookiePath = null;
    let secure = false;
    let httpOnly = false;
    let sameSite = null;
    let partitioned = false;
    let expires = null;
    let maxAge = null;

    for (let i = 1; i < parts.length; i += 1) {
        const attrSegment = parts[i].trim();
        if (!attrSegment) continue;

        const attrEqIdx = attrSegment.indexOf('=');
        const attrName = (attrEqIdx >= 0 ? attrSegment.slice(0, attrEqIdx) : attrSegment)
            .trim()
            .toLowerCase();
        const attrVal = attrEqIdx >= 0 ? attrSegment.slice(attrEqIdx + 1).trim() : null;

        if (attrName === 'domain') {
            domain = attrVal || null;
        } else if (attrName === 'path') {
            cookiePath = attrVal || null;
        } else if (attrName === 'secure') {
            secure = true;
        } else if (attrName === 'httponly') {
            httpOnly = true;
        } else if (attrName === 'samesite') {
            sameSite = attrVal || null;
        } else if (attrName === 'partitioned') {
            partitioned = true;
        } else if (attrName === 'expires') {
            expires = attrVal || null;
        } else if (attrName === 'max-age') {
            const parsedMaxAge = attrVal !== null && attrVal !== '' ? Number(attrVal) : NaN;
            maxAge = Number.isFinite(parsedMaxAge) ? parsedMaxAge : null;
        }
    }

    const isDeleted = maxAge !== null ? maxAge <= 0 : Date.parse(expires) <= observedAt;

    const isAntiBotToken = ANTI_BOT_COOKIE_REGEX.test(name);

    return {
        name,
        value,
        valueSha256,
        maskedValue,
        domain,
        path: cookiePath,
        secure,
        httpOnly,
        sameSite,
        partitioned,
        expires,
        maxAge,
        isDeleted,
        isAntiBotToken
    };
}

/**
 * Parse an egress `Cookie` request header string (`"k1=v1; k2=v2"`) into an array
 * of structured cookie descriptors with SHA-256 value digests and masked previews.
 *
 * @param {string} rawCookieHeader
 * @returns {Array<{
 *   name: string,
 *   value: string,
 *   valueSha256: string,
 *   maskedValue: string,
 *   isAntiBotToken: boolean
 * }>}
 */
export function parseCookieHeader(rawCookieHeader) {
    if (typeof rawCookieHeader !== 'string' || !rawCookieHeader.trim()) {
        return [];
    }

    const results = [];
    const segments = rawCookieHeader.split(/[;\r\n]+/);

    for (const seg of segments) {
        const trimmed = seg.trim();
        if (!trimmed) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx <= 0) continue;

        const name = trimmed.slice(0, eqIdx).trim();
        if (!name) continue;
        const value = trimmed.slice(eqIdx + 1).trim();
        const valueSha256 = crypto.createHash('sha256').update(value, 'utf8').digest('hex');
        const maskedValue = COOKIE_VALUE_MASK;
        const isAntiBotToken = ANTI_BOT_COOKIE_REGEX.test(name);

        results.push({
            name,
            value,
            valueSha256,
            maskedValue,
            isAntiBotToken
        });
    }

    return results;
}

export function deriveCookieObservations(headers, name, observedAt) {
    return collectCookieObservations(headers, name, observedAt).map((observation) => {
        if (!observation.path) return observation;
        const path = redactUrlSecrets(observation.path);
        return {
            ...observation,
            path,
            ...(observation.path.startsWith('/') && path !== observation.path && { pathScopeUnknown: true })
        };
    });
}

function collectCookieObservations({ headers = {}, headersArray = [] }, name, observedAt = Date.now()) {
    const orderedValues = (Array.isArray(headersArray) ? headersArray : [])
        .filter((header) => String(header?.name).toLowerCase() === name)
        .map((header) => header?.value);
    const rawValues = orderedValues.length ? orderedValues : Object.entries(headers || {})
        .filter(([headerName]) => headerName.toLowerCase() === name)
        .flatMap(([, value]) => value);

    const parsed = name === 'set-cookie'
        ? rawValues.flatMap((value) => String(value ?? '').split(/\r?\n/).map((header) => parseSetCookie(header, observedAt)))
        : rawValues.flatMap(parseCookieHeader);
    return parsed.filter(Boolean).map(({ value, ...observation }) => observation);
}

const RETAINED_OBSERVATIONS_PER_SCOPE = 256;

function observationClock(event) {
    return Number.isFinite(event.epochMs) ? event.epochMs : Date.parse(event.timestamp);
}

function observationOrder(event, clock = observationClock(event)) {
    const sequence = event.observationSequence;
    return {
        clock: Number.isFinite(clock) ? clock : -Infinity,
        sequence: Number.isSafeInteger(sequence) && sequence > 0 ? sequence : 0
    };
}

function compareObservationOrder(first, second) {
    // Older records precede the sequenced format. New observations retain capture order across clock adjustments.
    if (first.sequence !== second.sequence) return first.sequence - second.sequence;
    if (first.clock !== second.clock) return first.clock < second.clock ? -1 : 1;
    return 0;
}

function matchingDomain(host, domain) {
    return Boolean(host && domain && (
        host === domain || (!isIP(host) && host.endsWith(`.${domain}`))
    ));
}

function matchingPath(requestPath, cookiePath) {
    return requestPath === cookiePath || (
        requestPath.startsWith(cookiePath) &&
        (cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/')
    );
}

function observedPath(path, obscured = false) {
    // A leading // can have its entire first component changed by URL redaction.
    const mask = obscured && path.startsWith('//') ? null : COOKIE_PATH_MASK.exec(path);
    if (mask) return { exact: null, prefix: path.slice(0, path.lastIndexOf('/', mask.index) + 1) || '/' };
    return obscured ? { exact: null, prefix: '/' } : { exact: path, prefix: path };
}

function matchingObservedPath(request, cookie) {
    if (cookie.exact !== null) {
        if (matchingPath(request.prefix, cookie.exact)) return true;
        return request.exact === null && cookie.exact.startsWith(request.prefix) ? null : false;
    }
    if (request.prefix.startsWith(cookie.prefix)) return null;
    return request.exact === null && cookie.prefix.startsWith(request.prefix) ? null : false;
}

function requestScope(event) {
    try {
        const { hostname, pathname, protocol } = new URL(event.url);
        return { hostname, pathname, secure: protocol === 'https:' || protocol === 'wss:' };
    } catch {
        return { hostname: null, pathname: '/', secure: false };
    }
}

function newEntry(observation, scope) {
    return {
        name: observation.name,
        isAntiBotToken: Boolean(observation.isAntiBotToken || ANTI_BOT_COOKIE_REGEX.test(observation.name)),
        ...scope,
        secure: null,
        httpOnly: null,
        sameSite: null,
        firstSetAt: null,
        firstSetByCorrelationId: null,
        firstSetAtStep: null,
        firstSetByTrigger: null,
        firstSetUrl: null,
        lastSetAt: null,
        lastSetByCorrelationId: null,
        lastSetAtStep: null,
        lastValueSha256: null,
        lastMaskedValue: COOKIE_VALUE_MASK,
        mutationsCount: 0,
        lastSentAt: null,
        lastSentByCorrelationId: null,
        lastSentAtStep: null,
        matchesLatestSetCookie: null
    };
}

// Track membership and the chronological tail without scanning previously recorded values.
function remember(recent, key, value, limit) {
    if (recent.has(key)) return false;
    recent.set(key, value);
    if (recent.size > limit) {
        recent.delete(recent.keys().next().value);
    }
    return true;
}

function entryFor(entries, observation, scope, key) {
    if (!entries.has(key)) {
        entries.set(key, {
            entry: newEntry(observation, scope),
            history: new Map(),
            historyCount: 0,
            sent: new Map(),
            sentCount: 0,
            pathEvidence: null,
            validDomain: false,
            expiresAt: null,
            lastSetOrder: null,
            hasUntimedSet: false,
            deleted: false
        });
    }
    return entries.get(key);
}

/** One projection for live capture, ledger replay, and offline queries. */
export class CookieLineage {
    #lastObservation = null;
    #unknownScopeCount = 0;

    constructor({ limit = RETAINED_OBSERVATIONS_PER_SCOPE } = {}) {
        this.limit = limit;
        this.byName = new Map();
        this.needsReplay = false;
    }

    observeAll(events) {
        const observations = events.flatMap((event) => {
            if ((event?.type !== 'ingress' && event?.type !== 'egress') ||
                (Array.isArray(event.cookieObservations) && event.cookieObservations.length === 0)) return [];
            return [{ event, order: observationOrder(event) }];
        });
        // Stable sorting preserves ledger order for legacy events with the same observation time.
        observations.sort((first, second) => compareObservationOrder(first.order, second.order));
        for (const { event } of observations) this.observe(event);
    }

    observe(event) {
        const incoming = event?.type === 'ingress';
        if (this.needsReplay || (!incoming && event?.type !== 'egress')) return;
        const timestamp = event.timestamp || null;
        const clock = observationClock(event);
        const hasClock = Number.isFinite(clock);
        const observations = Array.isArray(event.cookieObservations)
            ? event.cookieObservations
            : collectCookieObservations(event, incoming ? 'set-cookie' : 'cookie', clock);
        if (!observations.length) return;
        const order = observationOrder(event, clock);
        if (this.#lastObservation && compareObservationOrder(order, this.#lastObservation) < 0) {
            this.needsReplay = true;
            return;
        }
        this.#lastObservation = order;
        const actionStep = redactDiagnosticText(event.attribution?.actionStep || event.actionStep || 'init');
        const correlationId = event.correlationId || null;
        const triggerActionId = event.triggerAction?.actionId || event.attribution?.triggerAction?.actionId || null;
        const { hostname, pathname, secure } = requestScope(event);
        const requestPath = observedPath(pathname);

        for (const observation of observations) {
            if (typeof observation?.name !== 'string' || !observation.name) continue;
            const valueSha256 = typeof observation.valueSha256 === 'string' && /^[0-9a-f]{64}$/i.test(observation.valueSha256)
                ? observation.valueSha256.toLowerCase() : null;
            const partitionKey = typeof observation.partitionKey === 'string'
                ? redactUrlSecrets(observation.partitionKey)
                : typeof event.cookiePartitionKey === 'string' ? redactUrlSecrets(event.cookiePartitionKey) : null;
            if (!this.byName.has(observation.name)) {
                this.byName.set(observation.name, new Map());
            }
            const entries = this.byName.get(observation.name);

            if (incoming) {
                const hostOnly = !observation.domain;
                const declaredDomain = String(observation.domain || '').replace(/^\./, '');
                const domain = hostOnly
                    ? hostname
                    : /[\s@/#?]/.test(declaredDomain) ? '' : domainToASCII(declaredDomain);
                const explicitPath = typeof observation.path === 'string' &&
                    (observation.path.startsWith('/') || observation.path === COOKIE_VALUE_MASK);
                const rawPath = explicitPath ? observation.path : pathname.slice(0, pathname.lastIndexOf('/')) || '/';
                const path = redactUrlSecrets(rawPath);
                const pathEvidence = observedPath(rawPath, observation.pathScopeUnknown === true);
                const partitioned = Boolean(observation.partitioned || partitionKey);
                const validDomain = matchingDomain(hostname, domain);
                const scopeStatus = validDomain && pathEvidence.exact !== null ? 'set-cookie' : 'unknown';
                const scope = { domain: domain || hostname, hostOnly, path, partitioned, partitionKey, scopeStatus };
                // Keep separate settings when the capture cannot prove that their paths are identical.
                const pathIdentity = pathEvidence.exact ?? ++this.#unknownScopeCount;
                const scopeKey = JSON.stringify([scopeStatus, domain, hostOnly, pathIdentity, partitioned, partitionKey,
                    validDomain ? null : hostname]);
                const state = entryFor(entries, observation, scope, scopeKey);
                const { entry } = state;
                const maxAge = observation.maxAge;
                const expiresAt = Number.isFinite(maxAge) ? clock + maxAge * 1000 : Date.parse(observation.expires);
                const isDeleted = Boolean(observation.isDeleted || expiresAt <= clock ||
                    (Number.isFinite(maxAge) && maxAge <= 0));
                if (!state.historyCount) {
                    entry.firstSetAt = timestamp;
                    entry.firstSetByCorrelationId = correlationId;
                    entry.firstSetAtStep = actionStep;
                    entry.firstSetByTrigger = triggerActionId;
                    entry.firstSetUrl = event.url ? redactUrlSecrets(event.url) : null;
                }
                if (entry.lastValueSha256 !== valueSha256 || state.deleted !== isDeleted) {
                    entry.mutationsCount += 1;
                }
                entry.secure = Boolean(observation.secure);
                entry.httpOnly = Boolean(observation.httpOnly);
                entry.sameSite = observation.sameSite == null ? null : redactDiagnosticText(observation.sameSite);
                entry.lastSetAt = timestamp;
                entry.lastSetByCorrelationId = correlationId;
                entry.lastSetAtStep = actionStep;
                entry.lastValueSha256 = valueSha256;
                state.pathEvidence = pathEvidence;
                state.validDomain = validDomain;
                state.lastSetOrder = order;
                state.hasUntimedSet ||= !hasClock;
                state.expiresAt = expiresAt;
                state.deleted = isDeleted;
                const historyKey = JSON.stringify([correlationId ?? timestamp, valueSha256, isDeleted]);
                const stored = remember(state.history, historyKey, {
                    correlationId, actionStep, triggerActionId, timestamp,
                    status: event.status ?? null, valueSha256, maskedValue: COOKIE_VALUE_MASK, isDeleted
                }, this.limit);
                if (stored) state.historyCount += 1;
                continue;
            }

            const candidates = [];
            let hasUncertainCandidate = false;
            for (const state of entries.values()) {
                const { entry } = state;
                if (!state.validDomain || state.deleted || state.expiresAt <= clock ||
                    !valueSha256 || valueSha256 !== entry.lastValueSha256 || (entry.secure && !secure) ||
                    !hostname || !(entry.hostOnly ? hostname === entry.domain : matchingDomain(hostname, entry.domain)) ||
                    (entry.partitioned && partitionKey && entry.partitionKey && entry.partitionKey !== partitionKey)) {
                    continue;
                }
                const matchesPath = matchingObservedPath(requestPath, state.pathEvidence);
                if (matchesPath === false) continue;
                const clockMovedBack = state.lastSetOrder.clock > order.clock;
                const cannotUseClock = clockMovedBack &&
                    (!order.sequence || !state.lastSetOrder.sequence || Number.isFinite(state.expiresAt));
                if (matchesPath === null || !hasClock || state.hasUntimedSet || cannotUseClock) {
                    hasUncertainCandidate = true;
                } else {
                    candidates.push(state);
                }
            }
            const candidate = !hasUncertainCandidate && candidates.length === 1 ? candidates[0] : null;
            const matched = candidate && (!candidate.entry.partitioned || (
                partitionKey && candidate.entry.partitionKey === partitionKey
            ));
            let scopeStatus = 'unmatched';
            if (hasUncertainCandidate) scopeStatus = 'unknown';
            if (candidates.length > 1 || (candidates.length && !hasUncertainCandidate)) scopeStatus = 'ambiguous';
            const state = matched ? candidate : entryFor(entries, observation, {
                domain: hostname, hostOnly: null, path: null, partitioned: null, partitionKey, scopeStatus
            }, JSON.stringify([scopeStatus, hostname, partitionKey]));
            if (!correlationId || remember(state.sent, correlationId, correlationId, this.limit)) {
                state.sentCount += 1;
            }
            state.entry.lastSentAt = timestamp;
            state.entry.lastSentByCorrelationId = correlationId;
            state.entry.lastSentAtStep = actionStep;
            state.entry.matchesLatestSetCookie = matched ? true : null;
        }
    }

    snapshot() {
        return Object.fromEntries(Array.from(this.byName, ([name, entries]) => {
            const instances = Array.from(entries.values(), ({ entry, history, historyCount, sent, sentCount }) => ({
                ...entry,
                sentCount,
                valueHistory: Array.from(history.values(), (value) => ({ ...value })),
                valueHistoryOmittedCount: historyCount - history.size,
                sentInCorrelationIds: Array.from(sent.keys())
            }));
            const lineage = instances.length === 1
                ? instances[0]
                : { name, isAntiBotToken: instances.some((entry) => entry.isAntiBotToken), instances };
            return [name, lineage];
        }));
    }
}
