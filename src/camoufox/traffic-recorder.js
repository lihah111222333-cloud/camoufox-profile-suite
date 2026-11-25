/**
 * Camoufox Pre-TLS Egress/Ingress Traffic Recorder & Multi-Dimensional Attribution Engine
 *
 * Hooks Gecko / Necko channel lifecycle events exposed through Playwright's Juggler
 * bridge (`http-on-modify-request` prior to NSS TLS encryption on egress, and
 * `onDataAvailable` / `onStopRequest` immediately after NSS TLS decryption on ingress)
 * together with NSS `SSLKEYLOGFILE` key material reservation.
 *
 * Captures 100% plaintext HTTP/1.1, HTTP/2, and WebSocket traffic to disk without
 * any external MITM proxy, preserving authentic Firefox TLS (JA3/JA4) and HTTP/2
 * fingerprints while providing full correlation and root-cause anomaly attribution.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEFAULT_PROFILES_DIR = (process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR)
    ? path.resolve(process.env.CAMOUFOX_STORAGE_DIR || process.env.CAMOUFOX_PROFILES_DIR)
    : path.resolve(__dirname, '../../profiles');

const DEFAULT_MAX_INLINE_PREVIEW_BYTES = 4096;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024; // 5MB (5242880 bytes)

/**
 * Risk-control, challenge, and anti-bot signal patterns inspected across request URLs,
 * response URLs, status codes, headers, and text/JSON bodies.
 */
const RISK_SIGNAL_PATTERNS = [
    { name: 'captcha', regex: /\b(captcha|g-recaptcha|recaptcha|hcaptcha|funcaptcha)\b/i, severity: 'high' },
    { name: 'arkose', regex: /\b(arkose|arkoselabs|enforcement\.[a-z0-9.-]+)\b/i, severity: 'high' },
    { name: 'turnstile', regex: /\b(turnstile|cf-chl-|cf_chl_opt|challenges\.cloudflare\.com)\b/i, severity: 'high' },
    { name: 'botguard', regex: /\b(botguard|bgRequest|baa\.google|accounts\.google\.com\/v3\/signin\/challenge)\b/i, severity: 'medium' },
    { name: 'challenge', regex: /(?:\/challenge\b|[?&]challenge=|signin\/challenge|challenge\/ootp|challenge\/ipp|challenge\/pwd)/i, severity: 'high' },
    { name: 'checkpoint', regex: /(?:\/checkpoint\b|security_checkpoint|checkpoint_required)/i, severity: 'high' },
    { name: 'verify', regex: /(?:\/verify\b|phoneverification|idvreenable|sendidv|verifyphone)/i, severity: 'medium' },
    { name: 'deny', regex: /(?:\/deny\b|access_denied|account_disabled|unusual[_\s-]+traffic|automated[_\s-]+queries|sorry\/index)/i, severity: 'critical' }
];

const TEXTUAL_MIME_PATTERNS =
    /\b(json|text|html|xml|javascript|ecmascript|x-www-form-urlencoded|graphql|csv|plain|svg|css)\b/i;

/**
 * Determine default desktop OS name in Camoufox format ('windows' | 'macos' | 'linux').
 */
function detectDefaultOs() {
    if (process.env.CAMOUFOX_OS) {
        const cleaned = String(process.env.CAMOUFOX_OS).trim().toLowerCase();
        if (cleaned.startsWith('win')) return 'windows';
        if (cleaned.startsWith('mac') || cleaned === 'darwin' || cleaned === 'osx') return 'macos';
        if (cleaned.startsWith('lin') || cleaned === 'ubuntu') return 'linux';
    }
    if (process.platform === 'win32') return 'windows';
    if (process.platform === 'darwin') return 'macos';
    return 'linux';
}

/**
 * Redact credentials from a proxy configuration string or object.
 * Never persists raw proxy usernames or passwords to disk.
 *
 * @param {string|object|null|undefined} proxyInput
 * @returns {string|null}
 */
export function redactProxyUrl(proxyInput) {
    if (!proxyInput) {
        return null;
    }

    let rawServer = null;
    if (typeof proxyInput === 'string') {
        rawServer = proxyInput.trim();
    } else if (typeof proxyInput === 'object') {
        rawServer = proxyInput.server || proxyInput.url || proxyInput.host || null;
        if (rawServer && proxyInput.port && !String(rawServer).includes(`:${proxyInput.port}`)) {
            rawServer = `${rawServer}:${proxyInput.port}`;
        }
    }

    if (!rawServer) {
        return null;
    }

    const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawServer)
        ? rawServer
        : `http://${rawServer}`;

    try {
        const parsed = new URL(candidate);
        parsed.username = '';
        parsed.password = '';
        const formatted = parsed.toString();
        return formatted.endsWith('/') && !rawServer.endsWith('/')
            ? formatted.slice(0, -1)
            : formatted;
    } catch {
        // Fallback regex strip for user:pass@host:port
        return String(rawServer).replace(/(\/\/|^)([^/@:\s]+:[^/@\s]+@)/, '$1');
    }
}

/**
 * Compute full SHA-256 hex digest and 12-char content-address prefix.
 *
 * @param {Buffer|string} bufferOrString
 * @returns {{ sha256: string, shortSha256: string, byteLength: number, buffer: Buffer }}
 */
function hashPayload(bufferOrString) {
    const buffer = Buffer.isBuffer(bufferOrString)
        ? bufferOrString
        : Buffer.from(String(bufferOrString ?? ''), 'utf8');
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    return {
        sha256,
        shortSha256: sha256.slice(0, 12),
        byteLength: buffer.byteLength,
        buffer
    };
}

/**
 * Determine appropriate payload file extension (`.json`, `.txt`, or `.bin`)
 * based on MIME type and payload content.
 *
 * @param {string|null|undefined} mimeType
 * @param {Buffer} buffer
 * @returns {'json'|'txt'|'bin'}
 */
export function inferPayloadExtension(mimeType, buffer) {
    const normalizedMime = String(mimeType || '').toLowerCase();
    if (normalizedMime.includes('json')) {
        return 'json';
    }
    if (buffer && buffer.byteLength > 0) {
        const firstByte = buffer[0];
        if (firstByte === 0x7b || firstByte === 0x5b) {
            try {
                const sample = buffer.toString('utf8');
                JSON.parse(sample);
                return 'json';
            } catch {
                // Not valid JSON; continue classification
            }
        }
    }
    if (TEXTUAL_MIME_PATTERNS.test(normalizedMime)) {
        return 'txt';
    }
    if (buffer && buffer.byteLength > 0) {
        const checkLen = Math.min(buffer.byteLength, 512);
        let nonPrintable = 0;
        for (let i = 0; i < checkLen; i += 1) {
            const byte = buffer[i];
            if (byte === 0x00) {
                return 'bin';
            }
            if (byte < 0x09 || (byte > 0x0d && byte < 0x20)) {
                nonPrintable += 1;
            }
        }
        if (nonPrintable / checkLen < 0.05) {
            return 'txt';
        }
    }
    return 'bin';
}

/**
 * Build a safe UTF-8 inline preview for text/JSON payloads or a diagnostic summary
 * for binary payloads.
 *
 * @param {Buffer} buffer
 * @param {string|null|undefined} mimeType
 * @param {number} maxBytes
 * @returns {{ preview: string|null, truncated: boolean, encoding: 'utf8'|'hex-preview' }}
 */
function buildBodyPreview(buffer, mimeType, maxBytes = DEFAULT_MAX_INLINE_PREVIEW_BYTES) {
    if (!buffer || buffer.byteLength === 0 || maxBytes <= 0) {
        return { preview: null, truncated: false, encoding: 'utf8' };
    }

    const ext = inferPayloadExtension(mimeType, buffer);
    const truncated = buffer.byteLength > maxBytes;
    const slice = truncated ? buffer.subarray(0, maxBytes) : buffer;

    if (ext === 'json' || ext === 'txt') {
        return {
            preview: slice.toString('utf8'),
            truncated,
            encoding: 'utf8'
        };
    }

    const hexPreviewBytes = Math.min(slice.byteLength, 128);
    return {
        preview: `[binary ${buffer.byteLength} bytes; head_hex=${slice.subarray(0, hexPreviewBytes).toString('hex')}]`,
        truncated: buffer.byteLength > hexPreviewBytes,
        encoding: 'hex-preview'
    };
}

/**
 * Safely parse a URL into structured host, pathname, and search parameters.
 *
 * @param {string} rawUrl
 * @returns {{
 *   protocol: string|null,
 *   host: string,
 *   hostname: string,
 *   port: string|null,
 *   pathname: string,
 *   search: string,
 *   searchParams: Record<string, string|string[]>
 * }}
 */
function parseUrlComponents(rawUrl) {
    try {
        const parsed = new URL(String(rawUrl));
        const searchParams = {};
        for (const [key, value] of parsed.searchParams.entries()) {
            if (Object.prototype.hasOwnProperty.call(searchParams, key)) {
                if (Array.isArray(searchParams[key])) {
                    searchParams[key].push(value);
                } else {
                    searchParams[key] = [searchParams[key], value];
                }
            } else {
                searchParams[key] = value;
            }
        }
        return {
            protocol: parsed.protocol ? parsed.protocol.replace(/:$/, '') : null,
            host: parsed.host || parsed.hostname || 'unknown',
            hostname: parsed.hostname || 'unknown',
            port: parsed.port || null,
            pathname: parsed.pathname || '/',
            search: parsed.search || '',
            searchParams
        };
    } catch {
        return {
            protocol: null,
            host: 'unknown',
            hostname: 'unknown',
            port: null,
            pathname: String(rawUrl || ''),
            search: '',
            searchParams: {}
        };
    }
}

/**
 * Detect risk-control / challenge signals in a URL and optional body preview.
 *
 * @param {object} params
 * @param {string} params.url
 * @param {string|null} [params.bodyPreview]
 * @param {Record<string, string>} [params.headers]
 * @returns {Array<{ name: string, severity: string }>}
 */
export function detectRiskSignals({ url = '', bodyPreview = null, headers = {} } = {}) {
    const matched = [];
    const seen = new Set();

    const urlText = String(url || '');
    const headerText = headers && typeof headers === 'object'
        ? Object.entries(headers)
            .filter(([k]) => /location|www-authenticate|cf-mitigated|x-frame-options|server/i.test(k))
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n')
        : '';
    const bodyText = typeof bodyPreview === 'string' && !bodyPreview.startsWith('[binary ')
        ? bodyPreview.slice(0, 2048)
        : '';

    for (const pattern of RISK_SIGNAL_PATTERNS) {
        const hitInUrl = pattern.regex.test(urlText);
        const hitInHeaders = !hitInUrl && headerText ? pattern.regex.test(headerText) : false;
        // For body inspection, only flag high-confidence challenge markers or small challenge payloads
        const hitInBody = !hitInUrl && !hitInHeaders && bodyText
            ? (pattern.name !== 'verify' && pattern.regex.test(bodyText))
            : false;

        if ((hitInUrl || hitInHeaders || hitInBody) && !seen.has(pattern.name)) {
            seen.add(pattern.name);
            matched.push({
                name: pattern.name,
                severity: pattern.severity,
                source: hitInUrl ? 'url' : hitInHeaders ? 'headers' : 'body'
            });
        }
    }

    return matched;
}

/**
 * Normalize headers object and optional headersArray so Firefox's exact pre-TLS
 * header order is preserved whenever Playwright's `headersArray()` is available.
 *
 * @param {object} target - Playwright Request or Response
 * @returns {Promise<{ headers: Record<string, string>, headersArray: Array<{ name: string, value: string }> }>}
 */
async function extractHeadersWithOrder(target) {
    let headers = {};
    try {
        if (target && typeof target.headers === 'function') {
            headers = target.headers() || {};
        }
    } catch {
        headers = {};
    }

    let headersArray = [];
    try {
        if (target && typeof target.headersArray === 'function') {
            const rawArray = await target.headersArray();
            if (Array.isArray(rawArray)) {
                headersArray = rawArray.map((entry) => ({
                    name: String(entry.name ?? ''),
                    value: String(entry.value ?? '')
                }));
            }
        }
    } catch {
        headersArray = [];
    }

    if (headersArray.length === 0 && headers && typeof headers === 'object') {
        headersArray = Object.entries(headers).map(([name, value]) => ({
            name: String(name),
            value: String(value ?? '')
        }));
    }

    return { headers, headersArray };
}

/**
 * Camoufox Pre-TLS Traffic Recorder & Multi-Dimensional Attribution Engine.
 */
export class CamoufoxTrafficRecorder {
    /**
     * @param {object} [options]
     * @param {string} [options.profileId='default-profile']
     * @param {string} [options.profilesDir]
     * @param {string} [options.profileDir]
     * @param {string} [options.trafficDir]
     * @param {string} [options.traceId]
     * @param {string|null} [options.accountId=null]
     * @param {string|null} [options.accountEmail=null]
     * @param {string} [options.os]
     * @param {string|object|null} [options.proxy]
     * @param {string|null} [options.proxyServer]
     * @param {string} [options.actionStep='init']
     * @param {number} [options.maxInlinePreviewBytes=4096]
     * @param {number} [options.inlinePayloadThresholdBytes=0]
     * @param {boolean} [options.capturePayloads=true]
     * @param {boolean} [options.recordBodies=true]
     * @param {number} [options.maxBodyBytes=5242880]
     * @param {boolean} [options.recordWireLog=true]
     * @param {string|null} [options.preTlsWireLogPath=null]
     * @param {string|null} [options.neckoMozLogPath=null]
     * @param {string|null} [options.harPath=null]
     */
    constructor(options = {}) {
        const profileId = String(options.profileId || 'default-profile');
        const profilesDir = options.profilesDir
            ? path.resolve(options.profilesDir)
            : DEFAULT_PROFILES_DIR;
        const profileDir = options.profileDir
            ? path.resolve(options.profileDir)
            : path.join(profilesDir, profileId);
        const trafficDir = options.trafficDir
            ? path.resolve(options.trafficDir)
            : path.join(profileDir, 'traffic');

        this.profileId = profileId;
        this.profilesDir = profilesDir;
        this.profileDir = profileDir;
        this.trafficDir = trafficDir;

        this.payloadsDir = path.join(this.trafficDir, 'payloads');
        this.trafficNdjsonPath = path.join(this.trafficDir, 'traffic.ndjson');
        this.preTlsWireLogPath = options.preTlsWireLogPath
            ? path.resolve(options.preTlsWireLogPath)
            : path.join(this.trafficDir, 'pre-tls-wire.log');
        this.recordWireLog = options.recordWireLog !== false;
        this.neckoMozLogPath = options.neckoMozLogPath
            ? path.resolve(options.neckoMozLogPath)
            : path.join(this.trafficDir, 'necko-pre-tls.moz_log');
        this.sslKeyLogPath = options.sslKeyLogPath
            ? path.resolve(options.sslKeyLogPath)
            : path.join(this.trafficDir, 'sslkeylog.txt');
        this.attributionIndexPath = path.join(this.trafficDir, 'attribution-index.json');
        this.harPath = options.harPath
            ? path.resolve(options.harPath)
            : path.join(this.trafficDir, 'traffic.har');

        this.maxInlinePreviewBytes = Number.isFinite(options.maxInlinePreviewBytes)
            ? Math.max(0, Number(options.maxInlinePreviewBytes))
            : DEFAULT_MAX_INLINE_PREVIEW_BYTES;
        this.inlinePayloadThresholdBytes = Number.isFinite(options.inlinePayloadThresholdBytes)
            ? Math.max(0, Number(options.inlinePayloadThresholdBytes))
            : 0;
        const capturePayloads = options.recordBodies !== undefined
            ? options.recordBodies !== false
            : options.capturePayloads !== false;
        this.capturePayloads = capturePayloads;
        this.recordBodies = capturePayloads;
        this.maxBodyBytes =
            Number.isFinite(options.maxBodyBytes) && Number(options.maxBodyBytes) > 0
                ? Math.floor(Number(options.maxBodyBytes))
                : DEFAULT_MAX_BODY_BYTES;

        const traceId = options.traceId || crypto.randomUUID();
        this.traceId = traceId;
        this.traceIdShort = String(traceId).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8) || 'trace000';

        const initialStep = String(options.actionStep || 'init');
        const redactedProxy = redactProxyUrl(options.proxyServer || options.proxy || null);

        this.attribution = {
            traceId: this.traceId,
            profileId: this.profileId,
            accountId: options.accountId ?? null,
            accountEmail: options.accountEmail ?? null,
            os: options.os ? String(options.os).toLowerCase() : detectDefaultOs(),
            proxyServer: redactedProxy,
            actionStep: initialStep,
            stepIndex: 0
        };

        this.startedAt = new Date().toISOString();
        this.startedAtEpochMs = Date.now();
        this.endedAt = null;
        this.stopped = false;

        this.seq = 0;
        this.wsSeq = 0;
        this.triggerSeq = 0;
        this.lastTriggerAction = null;

        // Correlation & tracking stores
        this.requestCorrelationMap = new WeakMap();
        this.transactions = new Map();
        this.wsWireBlocks = new Map();
        this.attachedContexts = new WeakSet();
        this.attachedPagesHttp = new WeakSet();
        this.attachedPagesWs = new WeakSet();
        this.attachedWebSockets = new WeakSet();
        this.listenerDisposers = [];
        this.pendingTasks = new Set();

        // Aggregated metrics
        this.totals = {
            totalRequests: 0,
            totalResponses: 0,
            failedRequests: 0,
            wsFramesSent: 0,
            wsFramesReceived: 0,
            totalEgressBytes: 0,
            totalIngressBytes: 0
        };

        this.byActionStep = new Map();
        this.byDomain = new Map();
        this.byTriggerAction = new Map();
        this.anomaliesAndRiskSignals = [];
        this.recordedAnomalyKeys = new Set();

        this._ensureDirectories();
        this._ensureStepRecord(this.attribution.actionStep, this.attribution.stepIndex);
    }

    /**
     * Ensure `profiles/<profileId>/traffic/`, `payloads/`, `sslkeylog.txt`, and `pre-tls-wire.log` exist on disk.
     */
    _ensureDirectories() {
        fs.mkdirSync(this.trafficDir, { recursive: true });
        fs.mkdirSync(this.payloadsDir, { recursive: true });
        if (!fs.existsSync(this.sslKeyLogPath)) {
            fs.writeFileSync(
                this.sslKeyLogPath,
                '# NSS SSL/TLS Secrets Log (Camoufox Pre-TLS Traffic Recorder)\n',
                'utf8'
            );
        }
        if (this.recordWireLog && !fs.existsSync(this.preTlsWireLogPath)) {
            fs.writeFileSync(this.preTlsWireLogPath, '', 'utf8');
        }
    }

    /**
     * Return environment variables dictionary containing `SSLKEYLOGFILE` for Firefox/Camoufox NSS.
     *
     * @param {Record<string, string>} [baseEnv=process.env]
     * @returns {Record<string, string>}
     */
    getLaunchEnv(baseEnv = process.env) {
        this._ensureDirectories();
        return {
            ...(baseEnv || {}),
            SSLKEYLOGFILE: this.sslKeyLogPath
        };
    }

    /**
     * Return the reserved NSS `SSLKEYLOGFILE` path.
     *
     * @returns {string}
     */
    getSslKeyLogPath() {
        return this.sslKeyLogPath;
    }

    /**
     * Return a shallow immutable snapshot of the current attribution envelope.
     */
    getAttributionSnapshot() {
        return {
            traceId: this.attribution.traceId,
            profileId: this.attribution.profileId,
            accountId: this.attribution.accountId,
            accountEmail: this.attribution.accountEmail,
            os: this.attribution.os,
            proxyServer: this.attribution.proxyServer,
            actionStep: this.attribution.actionStep,
            stepIndex: this.attribution.stepIndex
        };
    }

    /**
     * Update attribution metadata (`accountId`, `accountEmail`, `proxyServer`, `os`, etc.) dynamically.
     *
     * @param {object} [partial={}]
     * @returns {object} Updated attribution snapshot
     */
    updateAttribution(partial = {}) {
        if (!partial || typeof partial !== 'object') {
            return this.getAttributionSnapshot();
        }

        if (partial.profileId !== undefined && partial.profileId !== null) {
            this.attribution.profileId = String(partial.profileId);
            this.profileId = this.attribution.profileId;
        }
        if (partial.accountId !== undefined) {
            this.attribution.accountId = partial.accountId ?? null;
        }
        if (partial.accountEmail !== undefined) {
            this.attribution.accountEmail = partial.accountEmail ?? null;
        }
        if (partial.os !== undefined && partial.os !== null) {
            this.attribution.os = String(partial.os).toLowerCase();
        }
        if (partial.proxyServer !== undefined || partial.proxy !== undefined) {
            this.attribution.proxyServer = redactProxyUrl(partial.proxyServer ?? partial.proxy);
        }
        if (partial.actionStep !== undefined && partial.actionStep !== null) {
            const nextStep = String(partial.actionStep);
            if (nextStep !== this.attribution.actionStep) {
                this.setStep(nextStep, partial.metadata || {});
            }
        }

        return this.getAttributionSnapshot();
    }

    /**
     * Advance workflow attribution to a named action step, incrementing `stepIndex`
     * and recording a `step-transition` event in `traffic.ndjson`.
     *
     * @param {string} stepName
     * @param {object} [metadata={}]
     * @returns {object} Current attribution snapshot
     */
    setStep(stepName, metadata = {}) {
        const cleanedStep = String(stepName || 'unnamed-step').trim() || 'unnamed-step';
        const previousStep = this.attribution.actionStep;
        const previousStepIndex = this.attribution.stepIndex;

        this.attribution.stepIndex += 1;
        this.attribution.actionStep = cleanedStep;

        this._ensureStepRecord(cleanedStep, this.attribution.stepIndex);

        const seq = this._nextSeq();
        this._appendNdjsonEvent({
            type: 'step-transition',
            eventType: 'step-transition',
            direction: 'internal',
            stage: 'workflow-attribution',
            timestamp: new Date().toISOString(),
            epochMs: Date.now(),
            seq,
            previousStep,
            previousStepIndex,
            actionStep: cleanedStep,
            stepIndex: this.attribution.stepIndex,
            metadata: metadata && typeof metadata === 'object' ? metadata : {},
            attribution: this.getAttributionSnapshot()
        });

        return this.getAttributionSnapshot();
    }

    /**
     * Record a causal UI driver action (`page.goto`, `page.click`, `page.fill`, `locator.press`, etc.)
     * so all subsequent pre-TLS network requests and responses are attributed to the exact UI trigger.
     *
     * @param {string} actionType - e.g. 'page.click', 'page.goto', 'page.fill'
     * @param {string|null} [target=null] - CSS selector, URL, or element descriptor
     * @param {object} [metadata={}] - Additional causal action metadata
     * @returns {object} Recorded trigger action snapshot
     */
    recordTriggerAction(actionType, target = null, metadata = {}) {
        this.triggerSeq += 1;
        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        this.lastTriggerAction = {
            actionId: `act-${this.traceIdShort}-${this.triggerSeq}`,
            actionType: String(actionType || 'unknown'),
            target: target ? String(target) : null,
            timestamp,
            epochMs,
            actionStep: this.attribution.actionStep,
            stepIndex: this.attribution.stepIndex,
            metadata: metadata && typeof metadata === 'object' ? metadata : {}
        };

        this._ensureTriggerActionRecord(this.lastTriggerAction);

        const seq = this._nextSeq();
        this._appendNdjsonEvent({
            type: 'trigger-action',
            eventType: 'trigger-action',
            direction: 'internal',
            stage: 'ui-driver-action',
            timestamp,
            epochMs,
            seq,
            actionId: this.lastTriggerAction.actionId,
            actionType: this.lastTriggerAction.actionType,
            target: this.lastTriggerAction.target,
            actionStep: this.lastTriggerAction.actionStep,
            stepIndex: this.lastTriggerAction.stepIndex,
            metadata: this.lastTriggerAction.metadata,
            triggerAction: {
                ...this.lastTriggerAction,
                elapsedSinceActionMs: 0
            },
            attribution: this.getAttributionSnapshot()
        });

        return { ...this.lastTriggerAction };
    }

    /**
     * Return a snapshot of the currently active causal UI trigger action with `elapsedSinceActionMs`.
     *
     * @param {number} [nowEpochMs=Date.now()]
     * @returns {object|null}
     */
    getActiveTriggerSnapshot(nowEpochMs = Date.now()) {
        if (!this.lastTriggerAction) {
            return null;
        }
        return {
            ...this.lastTriggerAction,
            elapsedSinceActionMs: Math.max(0, nowEpochMs - this.lastTriggerAction.epochMs)
        };
    }

    /**
     * Allocate the next monotonic event sequence integer.
     *
     * @returns {number}
     */
    _nextSeq() {
        this.seq += 1;
        return this.seq;
    }

    /**
     * Ensure per-step stats bucket exists.
     *
     * @param {string} stepName
     * @param {number} stepIndex
     */
    _ensureStepRecord(stepName, stepIndex) {
        if (!this.byActionStep.has(stepName)) {
            this.byActionStep.set(stepName, {
                stepIndex,
                requests: 0,
                responses: 0,
                failedRequests: 0,
                egressBytes: 0,
                ingressBytes: 0,
                statusCounts: {},
                domainsSet: new Set(),
                anomalyCount: 0
            });
        }
        return this.byActionStep.get(stepName);
    }

    /**
     * Ensure per-domain stats bucket exists.
     *
     * @param {string} host
     */
    _ensureDomainRecord(host) {
        const key = String(host || 'unknown').toLowerCase();
        if (!this.byDomain.has(key)) {
            this.byDomain.set(key, {
                requests: 0,
                responses: 0,
                failedRequests: 0,
                egressBytes: 0,
                ingressBytes: 0,
                statusCounts: {},
                totalDurationMs: 0,
                completedWithDurationCount: 0
            });
        }
        return this.byDomain.get(key);
    }

    /**
     * Ensure per-trigger-action stats bucket exists.
     *
     * @param {object|null} triggerAction
     * @returns {object|null}
     */
    _ensureTriggerActionRecord(triggerAction) {
        if (!triggerAction || !triggerAction.actionId) {
            return null;
        }
        const key = triggerAction.actionId;
        if (!this.byTriggerAction.has(key)) {
            this.byTriggerAction.set(key, {
                actionId: triggerAction.actionId,
                actionType: triggerAction.actionType || 'unknown',
                target: triggerAction.target ?? null,
                actionStep: triggerAction.actionStep || this.attribution.actionStep,
                stepIndex: triggerAction.stepIndex ?? this.attribution.stepIndex,
                timestamp: triggerAction.timestamp || new Date().toISOString(),
                metadata: triggerAction.metadata || {},
                requests: 0,
                responses: 0,
                failedRequests: 0,
                wsFramesSent: 0,
                wsFramesReceived: 0,
                egressBytes: 0,
                ingressBytes: 0,
                statusCounts: {},
                domainsSet: new Set(),
                correlationIdsSet: new Set(),
                anomalyCount: 0
            });
        }
        return this.byTriggerAction.get(key);
    }

    /**
     * Format a concise human-readable summary of a triggerAction snapshot for wire log headers.
     *
     * @param {object|null} triggerSnapshot
     * @returns {string}
     */
    _formatTriggerSummary(triggerSnapshot) {
        if (!triggerSnapshot || !triggerSnapshot.actionId) {
            return 'none';
        }
        const targetPart = triggerSnapshot.target ? `(${triggerSnapshot.target})` : '';
        return `${triggerSnapshot.actionType}${targetPart}#${triggerSnapshot.actionId}`;
    }

    /**
     * Append a single event line to `traffic.ndjson`.
     *
     * @param {object} record
     */
    _appendNdjsonEvent(record) {
        try {
            const line = `${JSON.stringify(record)}\n`;
            fs.appendFileSync(this.trafficNdjsonPath, line, 'utf8');
        } catch {
            // Ensure directory exists and retry once if needed
            try {
                this._ensureDirectories();
                fs.appendFileSync(this.trafficNdjsonPath, `${JSON.stringify(record)}\n`, 'utf8');
            } catch {
                // Swallow disk error to avoid crashing active browser automation
            }
        }
    }

    /**
     * Append a canonical pre-TLS / post-TLS raw HTTP or WebSocket wire block to `pre-tls-wire.log`.
     *
     * @param {string} wireBlock
     */
    _appendWireLogBlock(wireBlock) {
        if (!this.recordWireLog || !wireBlock) {
            return;
        }
        const entry = wireBlock.endsWith('\n') ? wireBlock : `${wireBlock}\n`;
        try {
            fs.appendFileSync(this.preTlsWireLogPath, entry, 'utf8');
        } catch {
            try {
                this._ensureDirectories();
                fs.appendFileSync(this.preTlsWireLogPath, entry, 'utf8');
            } catch {
                // Swallow disk error to avoid crashing active browser automation
            }
        }
    }

    /**
     * Persist a request/response/websocket payload buffer into `payloads/`.
     * Respects `this.capturePayloads` (`this.recordBodies`) and truncates at `this.maxBodyBytes`.
     *
     * @param {'req'|'res'|'ws'} prefix
     * @param {number} seq
     * @param {Buffer} buffer
     * @param {string} shortSha256
     * @param {string|null} mimeType
     * @returns {{ payloadFile: string|null, payloadPath: string|null, extension: string|null, payloadTruncated: boolean }}
     */
    _writePayloadFile(prefix, seq, buffer, shortSha256, mimeType) {
        if (!this.capturePayloads || !buffer || buffer.byteLength === 0) {
            return { payloadFile: null, payloadPath: null, extension: null, payloadTruncated: false };
        }
        if (buffer.byteLength < this.inlinePayloadThresholdBytes) {
            return { payloadFile: null, payloadPath: null, extension: null, payloadTruncated: false };
        }

        const payloadTruncated = this.maxBodyBytes > 0 && buffer.byteLength > this.maxBodyBytes;
        const toWrite = payloadTruncated ? buffer.subarray(0, this.maxBodyBytes) : buffer;

        const ext = inferPayloadExtension(mimeType, toWrite);
        const fileName = `${prefix}-${seq}-${shortSha256}.${ext}`;
        const relativePath = path.posix.join('payloads', fileName);
        const fullPath = path.join(this.payloadsDir, fileName);

        try {
            fs.writeFileSync(fullPath, toWrite);
            return {
                payloadFile: relativePath,
                payloadPath: fullPath,
                extension: ext,
                payloadTruncated
            };
        } catch {
            return { payloadFile: null, payloadPath: null, extension: ext, payloadTruncated };
        }
    }

    /**
     * Track an asynchronous event handler promise so `flushSummary()` and `stop()`
     * await all in-flight body and header captures before writing summary files.
     *
     * @param {Promise<any>} promise
     * @returns {Promise<any>}
     */
    _trackTask(promise) {
        const wrapped = Promise.resolve(promise)
            .catch(() => {})
            .finally(() => {
                this.pendingTasks.delete(wrapped);
            });
        this.pendingTasks.add(wrapped);
        return wrapped;
    }

    /**
     * Assign or retrieve a deterministic `correlationId` (`corr-<traceId_short>-<seq>`)
     * for a Playwright `Request` instance.
     *
     * @param {object} request
     * @returns {{ correlationId: string, seq: number, isNew: boolean, redirectedFromCorrelationId: string|null }}
     */
    _resolveRequestCorrelation(request) {
        if (request && typeof request === 'object' && this.requestCorrelationMap.has(request)) {
            const existing = this.requestCorrelationMap.get(request);
            return {
                ...existing,
                isNew: false
            };
        }

        const seq = this._nextSeq();
        const correlationId = `corr-${this.traceIdShort}-${seq}`;
        let redirectedFromCorrelationId = null;

        try {
            if (request && typeof request.redirectedFrom === 'function') {
                const parentReq = request.redirectedFrom();
                if (parentReq && this.requestCorrelationMap.has(parentReq)) {
                    redirectedFromCorrelationId = this.requestCorrelationMap.get(parentReq).correlationId;
                }
            }
        } catch {
            redirectedFromCorrelationId = null;
        }

        const entry = {
            correlationId,
            seq,
            redirectedFromCorrelationId
        };

        if (request && typeof request === 'object') {
            this.requestCorrelationMap.set(request, entry);
        }

        return {
            ...entry,
            isNew: true
        };
    }

    /**
     * Record a deduplicated anomaly or risk signal entry and increment step and trigger anomaly counters.
     *
     * @param {object} anomaly
     */
    _recordAnomaly(anomaly) {
        const dedupeKey = [
            anomaly.correlationId || '',
            anomaly.type || '',
            anomaly.status ?? '',
            anomaly.failureText || '',
            anomaly.url || ''
        ].join('|');

        if (this.recordedAnomalyKeys.has(dedupeKey)) {
            return;
        }
        this.recordedAnomalyKeys.add(dedupeKey);

        const stepName = anomaly.actionStep || this.attribution.actionStep;
        const stepBucket = this._ensureStepRecord(stepName, this.attribution.stepIndex);
        stepBucket.anomalyCount += 1;

        const effectiveTrigger =
            anomaly.triggerAction !== undefined
                ? anomaly.triggerAction
                : this.getActiveTriggerSnapshot();
        const triggerBucket = this._ensureTriggerActionRecord(effectiveTrigger);
        if (triggerBucket) {
            triggerBucket.anomalyCount += 1;
        }

        this.anomaliesAndRiskSignals.push({
            timestamp: anomaly.timestamp || new Date().toISOString(),
            correlationId: anomaly.correlationId || null,
            actionStep: stepName,
            triggerAction: effectiveTrigger || null,
            type: anomaly.type,
            severity: anomaly.severity || 'medium',
            method: anomaly.method || null,
            url: anomaly.url || null,
            status: anomaly.status ?? null,
            failureText: anomaly.failureText ?? null,
            payloadFile: anomaly.payloadFile ?? null,
            ...(anomaly.matchedSignals ? { matchedSignals: anomaly.matchedSignals } : {})
        });
    }

    /**
     * Attach pre-TLS egress & post-TLS ingress listeners to a Playwright `BrowserContext`.
     * Also attaches WebSocket listeners to all existing and future pages in the context.
     *
     * @param {object} context - Playwright BrowserContext
     * @returns {this}
     */
    attachContext(context) {
        if (!context || typeof context.on !== 'function' || this.attachedContexts.has(context)) {
            return this;
        }
        this.attachedContexts.add(context);

        const onRequest = (request) => this._trackTask(this._handleRequest(request));
        const onResponse = (response) => this._trackTask(this._handleResponse(response));
        const onRequestFinished = (request) => this._trackTask(this._handleRequestFinished(request));
        const onRequestFailed = (request) => this._trackTask(this._handleRequestFailed(request));
        const onPage = (page) => this._attachPageWebSocketsOnly(page);

        context.on('request', onRequest);
        context.on('response', onResponse);
        context.on('requestfinished', onRequestFinished);
        context.on('requestfailed', onRequestFailed);
        context.on('page', onPage);

        this.listenerDisposers.push(() => {
            if (typeof context.off === 'function') {
                context.off('request', onRequest);
                context.off('response', onResponse);
                context.off('requestfinished', onRequestFinished);
                context.off('requestfailed', onRequestFailed);
                context.off('page', onPage);
            } else if (typeof context.removeListener === 'function') {
                context.removeListener('request', onRequest);
                context.removeListener('response', onResponse);
                context.removeListener('requestfinished', onRequestFinished);
                context.removeListener('requestfailed', onRequestFailed);
                context.removeListener('page', onPage);
            }
        });

        try {
            if (typeof context.pages === 'function') {
                const existingPages = context.pages() || [];
                for (const page of existingPages) {
                    this._attachPageWebSocketsOnly(page);
                }
            }
        } catch {
            // Ignore if context.pages() is unavailable on mock context
        }

        return this;
    }

    /**
     * Attach pre-TLS egress, post-TLS ingress, and WebSocket listeners to a Playwright `Page`.
     * Automatically avoids double-hooking HTTP events if the page's parent `BrowserContext`
     * is already attached to this recorder.
     *
     * @param {object} page - Playwright Page
     * @returns {this}
     */
    attachPage(page) {
        if (!page || typeof page.on !== 'function') {
            return this;
        }

        // Always attach WebSocket hooks at page level
        this._attachPageWebSocketsOnly(page);

        // Check if parent BrowserContext is already capturing HTTP events
        let parentContextAttached = false;
        try {
            if (typeof page.context === 'function') {
                const ctx = page.context();
                if (ctx && this.attachedContexts.has(ctx)) {
                    parentContextAttached = true;
                }
            }
        } catch {
            parentContextAttached = false;
        }

        if (parentContextAttached || this.attachedPagesHttp.has(page)) {
            return this;
        }
        this.attachedPagesHttp.add(page);

        const onRequest = (request) => this._trackTask(this._handleRequest(request));
        const onResponse = (response) => this._trackTask(this._handleResponse(response));
        const onRequestFinished = (request) => this._trackTask(this._handleRequestFinished(request));
        const onRequestFailed = (request) => this._trackTask(this._handleRequestFailed(request));

        page.on('request', onRequest);
        page.on('response', onResponse);
        page.on('requestfinished', onRequestFinished);
        page.on('requestfailed', onRequestFailed);

        this.listenerDisposers.push(() => {
            if (typeof page.off === 'function') {
                page.off('request', onRequest);
                page.off('response', onResponse);
                page.off('requestfinished', onRequestFinished);
                page.off('requestfailed', onRequestFailed);
            } else if (typeof page.removeListener === 'function') {
                page.removeListener('request', onRequest);
                page.removeListener('response', onResponse);
                page.removeListener('requestfinished', onRequestFinished);
                page.removeListener('requestfailed', onRequestFailed);
            }
        });

        return this;
    }

    /**
     * Attach `page.on('websocket')` listener without duplicating HTTP listeners.
     *
     * @param {object} page
     */
    _attachPageWebSocketsOnly(page) {
        if (!page || typeof page.on !== 'function' || this.attachedPagesWs.has(page)) {
            return;
        }
        this.attachedPagesWs.add(page);

        const onWebSocket = (ws) => this._handleWebSocket(ws, page);
        page.on('websocket', onWebSocket);

        this.listenerDisposers.push(() => {
            if (typeof page.off === 'function') {
                page.off('websocket', onWebSocket);
            } else if (typeof page.removeListener === 'function') {
                page.removeListener('websocket', onWebSocket);
            }
        });
    }

    /**
     * Format a canonical pre-TLS egress raw HTTP wire dump block.
     *
     * @param {object} params
     * @returns {string}
     */
    _formatEgressWireBlock({
        timestamp,
        correlationId,
        actionStep,
        triggerSummary,
        method,
        parsedUrl,
        headersArray,
        bodyPreview
    }) {
        const headersText = Array.isArray(headersArray)
            ? headersArray.map((h) => `${h.name}: ${h.value}`).join('\r\n')
            : '';
        return [
            '================================================================================',
            `>>> EGRESS [PRE-TLS NECKO CHANNEL] [${timestamp}] [corr=${correlationId}] [step=${actionStep}] [trigger=${triggerSummary}]`,
            `${method} ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1`,
            `Host: ${parsedUrl.host}`,
            headersText,
            '',
            bodyPreview || '',
            '================================================================================'
        ].join('\n');
    }

    /**
     * Format a canonical post-TLS decrypted ingress raw HTTP wire dump block.
     *
     * @param {object} params
     * @returns {string}
     */
    _formatIngressWireBlock({
        timestamp,
        correlationId,
        effectiveStepName,
        serverAddr,
        securityDetails,
        status,
        statusText,
        headersArray,
        bodyPreview
    }) {
        const headersText = Array.isArray(headersArray)
            ? headersArray.map((h) => `${h.name}: ${h.value}`).join('\r\n')
            : '';
        return [
            '--------------------------------------------------------------------------------',
            `<<< INGRESS [POST-TLS NECKO CHANNEL] [${timestamp}] [corr=${correlationId}] [step=${effectiveStepName}] [remote=${serverAddr?.ipAddress || 'unknown'}:${serverAddr?.port || ''}] [tls=${securityDetails?.protocol || 'plain'}]`,
            `HTTP/1.1 ${status} ${statusText}`,
            headersText,
            '',
            bodyPreview || '',
            '--------------------------------------------------------------------------------'
        ].join('\n');
    }

    /**
     * Reconstruct the full egress + ingress raw HTTP wire dump string for a given `correlationId`
     * from recorded transactions or persisted `traffic.ndjson` events.
     *
     * @param {string} correlationId
     * @returns {string}
     */
    formatTransactionWireDump(correlationId) {
        if (!correlationId) {
            return '';
        }

        const tx = this.transactions.get(correlationId);
        if (tx && (tx.egressWireBlock || tx.ingressWireBlock)) {
            const parts = [];
            if (tx.egressWireBlock) parts.push(tx.egressWireBlock);
            if (tx.ingressWireBlock) parts.push(tx.ingressWireBlock);
            return parts.join('\n');
        }

        const wsBlocks = this.wsWireBlocks.get(correlationId);
        if (wsBlocks && wsBlocks.length > 0) {
            return wsBlocks.join('\n');
        }

        // Fallback: reconstruct from traffic.ndjson if events were flushed to disk
        if (fs.existsSync(this.trafficNdjsonPath)) {
            try {
                const lines = fs.readFileSync(this.trafficNdjsonPath, 'utf8').split('\n');
                const parts = [];
                for (const line of lines) {
                    if (!line.trim()) continue;
                    const evt = JSON.parse(line);
                    if (evt.correlationId !== correlationId) continue;
                    if (evt.type === 'egress') {
                        const parsedUrl = parseUrlComponents(evt.url || '');
                        const triggerSummary = this._formatTriggerSummary(evt.triggerAction);
                        parts.push(
                            this._formatEgressWireBlock({
                                timestamp: evt.timestamp,
                                correlationId: evt.correlationId,
                                actionStep: evt.attribution?.actionStep || 'init',
                                triggerSummary,
                                method: evt.method || 'GET',
                                parsedUrl,
                                headersArray: evt.headersArray || [],
                                bodyPreview: evt.bodyPreview || ''
                            })
                        );
                    } else if (evt.type === 'ingress') {
                        parts.push(
                            this._formatIngressWireBlock({
                                timestamp: evt.timestamp,
                                correlationId: evt.correlationId,
                                effectiveStepName: evt.attribution?.actionStep || 'init',
                                serverAddr: evt.serverAddr || null,
                                securityDetails: evt.securityDetails || null,
                                status: evt.status ?? 0,
                                statusText: evt.statusText || '',
                                headersArray: evt.headersArray || [],
                                bodyPreview: evt.bodyPreview || ''
                            })
                        );
                    }
                }
                return parts.join('\n');
            } catch {
                return '';
            }
        }

        return '';
    }

    /**
     * Handle pre-TLS egress `request` event (`http-on-modify-request` in Firefox Necko).
     *
     * @param {object} request - Playwright Request
     */
    async _handleRequest(request) {
        if (!request) return;

        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const { correlationId, seq, redirectedFromCorrelationId } =
            this._resolveRequestCorrelation(request);
        const attributionSnapshot = this.getAttributionSnapshot();
        const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs);

        let method = 'GET';
        let url = '';
        let resourceType = 'other';
        let isNavigationRequest = false;
        let frameUrl = null;

        try {
            if (typeof request.method === 'function') method = request.method() || 'GET';
        } catch {}
        try {
            if (typeof request.url === 'function') url = request.url() || '';
        } catch {}
        try {
            if (typeof request.resourceType === 'function') resourceType = request.resourceType() || 'other';
        } catch {}
        try {
            if (typeof request.isNavigationRequest === 'function') {
                isNavigationRequest = Boolean(request.isNavigationRequest());
            }
        } catch {}
        try {
            if (typeof request.frame === 'function') {
                const frame = request.frame();
                if (frame && typeof frame.url === 'function') {
                    frameUrl = frame.url() || null;
                }
            }
        } catch {}

        const parsedUrl = parseUrlComponents(url);
        const { headers, headersArray } = await extractHeadersWithOrder(request);
        const contentType = headers['content-type'] || headers['Content-Type'] || null;

        // Capture pre-TLS postData / postDataBuffer
        let postDataBuffer = null;
        let postDataString = null;
        try {
            if (typeof request.postDataBuffer === 'function') {
                postDataBuffer = request.postDataBuffer();
            }
        } catch {}
        try {
            if (typeof request.postData === 'function') {
                postDataString = request.postData();
            }
        } catch {}

        if (!postDataBuffer && typeof postDataString === 'string' && postDataString.length > 0) {
            postDataBuffer = Buffer.from(postDataString, 'utf8');
        }

        let postDataSha256 = null;
        let postDataBytes = 0;
        let bodyPreview = null;
        let bodyPreviewTruncated = false;
        let payloadFile = null;
        let payloadTruncated = false;

        if (postDataBuffer && postDataBuffer.byteLength > 0) {
            const hashed = hashPayload(postDataBuffer);
            postDataSha256 = hashed.sha256;
            postDataBytes = hashed.byteLength;

            const previewObj = buildBodyPreview(
                hashed.buffer,
                contentType || 'application/octet-stream',
                this.maxInlinePreviewBytes
            );
            bodyPreview = previewObj.preview;
            bodyPreviewTruncated = previewObj.truncated;

            const saved = this._writePayloadFile(
                'req',
                seq,
                hashed.buffer,
                hashed.shortSha256,
                contentType
            );
            payloadFile = saved.payloadFile;
            payloadTruncated = Boolean(saved.payloadTruncated);
        }

        // Estimate header byte size + body bytes for pre-TLS egress accounting
        const headerByteEstimate = headersArray.reduce(
            (acc, h) => acc + Buffer.byteLength(`${h.name}: ${h.value}\r\n`, 'utf8'),
            Buffer.byteLength(`${method} ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1\r\n\r\n`, 'utf8')
        );
        const estimatedEgressBytes = headerByteEstimate + postDataBytes;

        // Update counters
        this.totals.totalRequests += 1;
        this.totals.totalEgressBytes += estimatedEgressBytes;

        const stepBucket = this._ensureStepRecord(
            attributionSnapshot.actionStep,
            attributionSnapshot.stepIndex
        );
        stepBucket.requests += 1;
        stepBucket.egressBytes += estimatedEgressBytes;
        stepBucket.domainsSet.add(parsedUrl.host);

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        domainBucket.requests += 1;
        domainBucket.egressBytes += estimatedEgressBytes;

        const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
        if (triggerBucket) {
            triggerBucket.requests += 1;
            triggerBucket.egressBytes += estimatedEgressBytes;
            triggerBucket.domainsSet.add(parsedUrl.host);
            triggerBucket.correlationIdsSet.add(correlationId);
        }

        const triggerSummary = this._formatTriggerSummary(triggerSnapshot);
        const egressWireBlock = this._formatEgressWireBlock({
            timestamp,
            correlationId,
            actionStep: attributionSnapshot.actionStep,
            triggerSummary,
            method,
            parsedUrl,
            headersArray,
            bodyPreview
        });

        // Store transaction metadata for response / finish / failure linking
        this.transactions.set(correlationId, {
            correlationId,
            seq,
            method,
            url,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            resourceType,
            actionStep: attributionSnapshot.actionStep,
            stepIndex: attributionSnapshot.stepIndex,
            triggerAction: triggerSnapshot,
            startedAtEpochMs: epochMs,
            estimatedEgressBytes,
            countedIngressBytes: 0,
            requestPayloadFile: payloadFile,
            responsePayloadFile: null,
            status: null,
            egressWireBlock,
            ingressWireBlock: null
        });

        const egressEvent = {
            type: 'egress',
            eventType: 'egress',
            direction: 'egress',
            stage: 'pre-tls-necko-channel',
            timestamp,
            epochMs,
            seq,
            correlationId,
            redirectedFromCorrelationId,
            method,
            url,
            host: parsedUrl.host,
            hostname: parsedUrl.hostname,
            port: parsedUrl.port,
            pathname: parsedUrl.pathname,
            searchParams: parsedUrl.searchParams,
            resourceType,
            isNavigationRequest,
            frameUrl,
            headers,
            headersArray,
            postData: bodyPreview,
            bodyPreview,
            bodyPreviewTruncated,
            postDataSha256,
            postDataBytes,
            payloadFile,
            payloadTruncated,
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        };

        this._appendNdjsonEvent(egressEvent);
        this._appendWireLogBlock(egressWireBlock);

        // Inspect pre-TLS request URL for risk-control / challenge endpoints
        const riskSignals = detectRiskSignals({ url, bodyPreview, headers });
        if (riskSignals.length > 0) {
            const highestSeverity = riskSignals.some((s) => s.severity === 'critical')
                ? 'critical'
                : riskSignals.some((s) => s.severity === 'high')
                    ? 'high'
                    : 'medium';
            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: attributionSnapshot.actionStep,
                triggerAction: triggerSnapshot,
                type: `risk-signal:${riskSignals.map((s) => s.name).join('+')}`,
                severity: highestSeverity,
                method,
                url,
                status: null,
                failureText: null,
                payloadFile,
                matchedSignals: riskSignals
            });
        }
    }

    /**
     * Handle post-TLS decrypted ingress `response` event (`onDataAvailable`/`onStopRequest` in Necko).
     *
     * @param {object} response - Playwright Response
     */
    async _handleResponse(response) {
        if (!response) return;

        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const seq = this._nextSeq();
        const attributionSnapshot = this.getAttributionSnapshot();

        let request = null;
        try {
            if (typeof response.request === 'function') {
                request = response.request();
            }
        } catch {}

        const { correlationId, redirectedFromCorrelationId } = request
            ? this._resolveRequestCorrelation(request)
            : { correlationId: `corr-${this.traceIdShort}-${seq}`, redirectedFromCorrelationId: null };

        const tx = this.transactions.get(correlationId);
        const triggerSnapshot = tx?.triggerAction || this.getActiveTriggerSnapshot(epochMs);

        let url = tx?.url || '';
        let method = tx?.method || 'GET';
        let status = 0;
        let statusText = '';
        let ok = false;

        try {
            if (typeof response.url === 'function') url = response.url() || url;
        } catch {}
        try {
            if (request && typeof request.method === 'function') method = request.method() || method;
        } catch {}
        try {
            if (typeof response.status === 'function') status = Number(response.status() ?? 0);
        } catch {}
        try {
            if (typeof response.statusText === 'function') statusText = response.statusText() || '';
        } catch {}
        try {
            if (typeof response.ok === 'function') {
                ok = Boolean(response.ok());
            } else {
                ok = status >= 200 && status < 300;
            }
        } catch {
            ok = status >= 200 && status < 300;
        }

        const parsedUrl = parseUrlComponents(url);
        const { headers, headersArray } = await extractHeadersWithOrder(response);

        let serverAddr = null;
        try {
            if (typeof response.serverAddr === 'function') {
                serverAddr = (await response.serverAddr()) || null;
            }
        } catch {
            serverAddr = null;
        }

        let securityDetails = null;
        try {
            if (typeof response.securityDetails === 'function') {
                securityDetails = (await response.securityDetails()) || null;
            }
        } catch {
            securityDetails = null;
        }

        const rawContentType = headers['content-type'] || headers['Content-Type'] || '';
        const mimeType = rawContentType ? String(rawContentType).split(';')[0].trim().toLowerCase() : null;

        // Capture decrypted response body from Necko channel when capturePayloads (recordBodies) is enabled
        let bodyBuffer = null;
        let bodyReadError = null;
        const isRedirectStatus = status >= 300 && status < 400;
        const isEmptyBodyStatus = status === 204 || status === 205 || status === 304;

        if (this.capturePayloads && !isRedirectStatus && !isEmptyBodyStatus) {
            try {
                if (typeof response.body === 'function') {
                    const rawBody = await response.body();
                    if (rawBody) {
                        bodyBuffer = Buffer.isBuffer(rawBody)
                            ? rawBody
                            : Buffer.from(rawBody);
                    }
                } else if (typeof response.text === 'function') {
                    const rawText = await response.text();
                    if (rawText) {
                        bodyBuffer = Buffer.from(String(rawText), 'utf8');
                    }
                }
            } catch (err) {
                bodyReadError = err?.message || String(err);
            }
        }

        let bodySha256 = null;
        let bodyBytes = 0;
        let bodyPreview = null;
        let bodyPreviewTruncated = false;
        let payloadFile = null;
        let payloadTruncated = false;

        if (bodyBuffer && bodyBuffer.byteLength > 0) {
            const hashed = hashPayload(bodyBuffer);
            bodySha256 = hashed.sha256;
            bodyBytes = hashed.byteLength;

            const previewObj = buildBodyPreview(
                hashed.buffer,
                mimeType,
                this.maxInlinePreviewBytes
            );
            bodyPreview = previewObj.preview;
            bodyPreviewTruncated = previewObj.truncated;

            const saved = this._writePayloadFile(
                'res',
                seq,
                hashed.buffer,
                hashed.shortSha256,
                mimeType
            );
            payloadFile = saved.payloadFile;
            payloadTruncated = Boolean(saved.payloadTruncated);
        }

        const headerByteEstimate = headersArray.reduce(
            (acc, h) => acc + Buffer.byteLength(`${h.name}: ${h.value}\r\n`, 'utf8'),
            Buffer.byteLength(`HTTP/1.1 ${status} ${statusText}\r\n\r\n`, 'utf8')
        );
        const estimatedIngressBytes = headerByteEstimate + bodyBytes;

        // Update totals, step counters, domain counters, and triggerAction counters
        const effectiveStepName = tx?.actionStep || attributionSnapshot.actionStep;
        const effectiveStepIndex = tx?.stepIndex ?? attributionSnapshot.stepIndex;

        this.totals.totalResponses += 1;
        this.totals.totalIngressBytes += estimatedIngressBytes;

        const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
        stepBucket.responses += 1;
        stepBucket.ingressBytes += estimatedIngressBytes;
        stepBucket.domainsSet.add(parsedUrl.host);
        const statusKey = String(status);
        stepBucket.statusCounts[statusKey] = (stepBucket.statusCounts[statusKey] || 0) + 1;

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        domainBucket.responses += 1;
        domainBucket.ingressBytes += estimatedIngressBytes;
        domainBucket.statusCounts[statusKey] = (domainBucket.statusCounts[statusKey] || 0) + 1;

        const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
        if (triggerBucket) {
            triggerBucket.responses += 1;
            triggerBucket.ingressBytes += estimatedIngressBytes;
            triggerBucket.domainsSet.add(parsedUrl.host);
            triggerBucket.correlationIdsSet.add(correlationId);
            triggerBucket.statusCounts[statusKey] = (triggerBucket.statusCounts[statusKey] || 0) + 1;
        }

        const ingressWireBlock = this._formatIngressWireBlock({
            timestamp,
            correlationId,
            effectiveStepName,
            serverAddr,
            securityDetails,
            status,
            statusText,
            headersArray,
            bodyPreview
        });

        if (tx) {
            tx.status = status;
            tx.responsePayloadFile = payloadFile;
            tx.countedIngressBytes = estimatedIngressBytes;
            tx.ingressWireBlock = ingressWireBlock;
            const elapsed = Math.max(0, epochMs - tx.startedAtEpochMs);
            tx.responseDurationMs = elapsed;
        } else {
            this.transactions.set(correlationId, {
                correlationId,
                seq,
                method,
                url,
                host: parsedUrl.host,
                pathname: parsedUrl.pathname,
                resourceType: 'other',
                actionStep: effectiveStepName,
                stepIndex: effectiveStepIndex,
                triggerAction: triggerSnapshot,
                startedAtEpochMs: epochMs,
                estimatedEgressBytes: 0,
                countedIngressBytes: estimatedIngressBytes,
                requestPayloadFile: null,
                responsePayloadFile: payloadFile,
                status,
                egressWireBlock: null,
                ingressWireBlock
            });
        }

        const ingressEvent = {
            type: 'ingress',
            eventType: 'ingress',
            direction: 'ingress',
            stage: 'post-tls-necko-channel',
            timestamp,
            epochMs,
            seq,
            correlationId,
            redirectedFromCorrelationId,
            method,
            url,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            status,
            statusText,
            ok,
            mimeType,
            headers,
            headersArray,
            serverAddr,
            securityDetails,
            bodySha256,
            bodyBytes,
            bodyPreview,
            bodyPreviewTruncated,
            payloadFile,
            payloadTruncated,
            ...(bodyReadError ? { bodyReadError } : {}),
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        };

        this._appendNdjsonEvent(ingressEvent);
        this._appendWireLogBlock(ingressWireBlock);

        // Automatic HTTP Status & Risk Signal Anomaly Attribution
        if (status === 401 || status === 403 || status === 429 || status >= 500) {
            const severity = status === 429 || status === 403
                ? 'high'
                : status >= 500
                    ? 'high'
                    : 'medium';
            const typeLabel = status === 429
                ? 'http-429-rate-limit'
                : status === 403
                    ? 'http-403-forbidden'
                    : status === 401
                        ? 'http-401-unauthorized'
                        : `http-${status}-server-error`;

            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: effectiveStepName,
                triggerAction: triggerSnapshot,
                type: typeLabel,
                severity,
                method,
                url,
                status,
                failureText: statusText || `HTTP ${status}`,
                payloadFile: payloadFile || tx?.requestPayloadFile || null
            });
        }

        const riskSignals = detectRiskSignals({ url, bodyPreview, headers });
        if (riskSignals.length > 0) {
            const highestSeverity = riskSignals.some((s) => s.severity === 'critical')
                ? 'critical'
                : riskSignals.some((s) => s.severity === 'high')
                    ? 'high'
                    : 'medium';
            this._recordAnomaly({
                timestamp,
                correlationId,
                actionStep: effectiveStepName,
                triggerAction: triggerSnapshot,
                type: `risk-signal:${riskSignals.map((s) => s.name).join('+')}`,
                severity: highestSeverity,
                method,
                url,
                status,
                failureText: null,
                payloadFile: payloadFile || tx?.requestPayloadFile || null,
                matchedSignals: riskSignals
            });
        }
    }

    /**
     * Handle `requestfinished` lifecycle event to record Necko timing and exact wire sizes.
     *
     * @param {object} request - Playwright Request
     */
    async _handleRequestFinished(request) {
        if (!request) return;

        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const seq = this._nextSeq();
        const { correlationId } = this._resolveRequestCorrelation(request);
        const tx = this.transactions.get(correlationId);
        const attributionSnapshot = this.getAttributionSnapshot();
        const triggerSnapshot = tx?.triggerAction || this.getActiveTriggerSnapshot(epochMs);

        let url = tx?.url || '';
        let method = tx?.method || 'GET';
        try {
            if (typeof request.url === 'function') url = request.url() || url;
        } catch {}
        try {
            if (typeof request.method === 'function') method = request.method() || method;
        } catch {}

        const parsedUrl = parseUrlComponents(url);

        let timing = null;
        try {
            if (typeof request.timing === 'function') {
                timing = request.timing() || null;
            }
        } catch {
            timing = null;
        }

        let sizes = null;
        try {
            if (typeof request.sizes === 'function') {
                sizes = (await request.sizes()) || null;
            }
        } catch {
            sizes = null;
        }

        let durationMs = null;
        if (timing && typeof timing.responseEnd === 'number' && timing.responseEnd >= 0) {
            const startOffset = typeof timing.requestStart === 'number' && timing.requestStart >= 0
                ? timing.requestStart
                : 0;
            durationMs = Number(Math.max(0, timing.responseEnd - startOffset).toFixed(2));
        } else if (tx && typeof tx.startedAtEpochMs === 'number') {
            durationMs = Math.max(0, epochMs - tx.startedAtEpochMs);
        }

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        if (typeof durationMs === 'number' && Number.isFinite(durationMs)) {
            domainBucket.totalDurationMs += durationMs;
            domainBucket.completedWithDurationCount += 1;
        }

        // Reconcile wire byte sizes if Playwright's `request.sizes()` reported larger actual totals
        if (sizes && typeof sizes === 'object') {
            const actualReqBytes =
                (Number(sizes.requestHeadersSize) || 0) + (Number(sizes.requestBodySize) || 0);
            const actualResBytes =
                (Number(sizes.responseHeadersSize) || 0) + (Number(sizes.responseBodySize) || 0);

            const effectiveStepName = tx?.actionStep || attributionSnapshot.actionStep;
            const effectiveStepIndex = tx?.stepIndex ?? attributionSnapshot.stepIndex;
            const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
            const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);

            if (tx && actualReqBytes > tx.estimatedEgressBytes) {
                const deltaEgress = actualReqBytes - tx.estimatedEgressBytes;
                tx.estimatedEgressBytes = actualReqBytes;
                this.totals.totalEgressBytes += deltaEgress;
                stepBucket.egressBytes += deltaEgress;
                domainBucket.egressBytes += deltaEgress;
                if (triggerBucket) {
                    triggerBucket.egressBytes += deltaEgress;
                }
            }
            if (tx && actualResBytes > tx.countedIngressBytes) {
                const deltaIngress = actualResBytes - tx.countedIngressBytes;
                tx.countedIngressBytes = actualResBytes;
                this.totals.totalIngressBytes += deltaIngress;
                stepBucket.ingressBytes += deltaIngress;
                domainBucket.ingressBytes += deltaIngress;
                if (triggerBucket) {
                    triggerBucket.ingressBytes += deltaIngress;
                }
            }
        }

        this._appendNdjsonEvent({
            type: 'request-finished',
            eventType: 'request-finished',
            direction: 'lifecycle',
            stage: 'necko-transaction-complete',
            timestamp,
            epochMs,
            seq,
            correlationId,
            method,
            url,
            host: parsedUrl.host,
            status: tx?.status ?? null,
            durationMs,
            timing,
            sizes,
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        });
    }

    /**
     * Handle `requestfailed` event (e.g. `NS_ERROR_*`, proxy error, reset, abort, timeout).
     *
     * @param {object} request - Playwright Request
     */
    async _handleRequestFailed(request) {
        if (!request) return;

        const timestamp = new Date().toISOString();
        const epochMs = Date.now();
        const seq = this._nextSeq();
        const { correlationId } = this._resolveRequestCorrelation(request);
        const tx = this.transactions.get(correlationId);
        const attributionSnapshot = this.getAttributionSnapshot();
        const triggerSnapshot = tx?.triggerAction || this.getActiveTriggerSnapshot(epochMs);

        let url = tx?.url || '';
        let method = tx?.method || 'GET';
        let resourceType = tx?.resourceType || 'other';
        let failureText = 'UNKNOWN_NETWORK_FAILURE';

        try {
            if (typeof request.url === 'function') url = request.url() || url;
        } catch {}
        try {
            if (typeof request.method === 'function') method = request.method() || method;
        } catch {}
        try {
            if (typeof request.resourceType === 'function') {
                resourceType = request.resourceType() || resourceType;
            }
        } catch {}
        try {
            if (typeof request.failure === 'function') {
                const failureObj = request.failure();
                if (failureObj && failureObj.errorText) {
                    failureText = String(failureObj.errorText);
                }
            }
        } catch {}

        const parsedUrl = parseUrlComponents(url);
        const durationMs = tx && typeof tx.startedAtEpochMs === 'number'
            ? Math.max(0, epochMs - tx.startedAtEpochMs)
            : null;

        const effectiveStepName = tx?.actionStep || attributionSnapshot.actionStep;
        const effectiveStepIndex = tx?.stepIndex ?? attributionSnapshot.stepIndex;

        this.totals.failedRequests += 1;

        const stepBucket = this._ensureStepRecord(effectiveStepName, effectiveStepIndex);
        stepBucket.failedRequests += 1;
        stepBucket.domainsSet.add(parsedUrl.host);

        const domainBucket = this._ensureDomainRecord(parsedUrl.host);
        domainBucket.failedRequests += 1;
        if (typeof durationMs === 'number' && Number.isFinite(durationMs)) {
            domainBucket.totalDurationMs += durationMs;
            domainBucket.completedWithDurationCount += 1;
        }

        const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
        if (triggerBucket) {
            triggerBucket.failedRequests += 1;
            triggerBucket.domainsSet.add(parsedUrl.host);
            triggerBucket.correlationIdsSet.add(correlationId);
        }

        this._appendNdjsonEvent({
            type: 'request-failed',
            eventType: 'request-failed',
            direction: 'egress-failed',
            stage: 'necko-channel-error',
            timestamp,
            epochMs,
            seq,
            correlationId,
            method,
            url,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            resourceType,
            failureText,
            durationMs,
            payloadFile: tx?.requestPayloadFile || null,
            triggerAction: triggerSnapshot,
            attribution: attributionSnapshot
        });

        const isProxyOrTlsFailure =
            /proxy|tunnel|ssl|tls|cert|ns_error_proxy|ns_error_net_timeout|ns_error_connection_refused|timed?\s*out/i.test(
                failureText
            );

        this._recordAnomaly({
            timestamp,
            correlationId,
            actionStep: effectiveStepName,
            triggerAction: triggerSnapshot,
            type: isProxyOrTlsFailure ? 'network-proxy-or-tls-failure' : 'network-request-failed',
            severity: isProxyOrTlsFailure ? 'high' : 'medium',
            method,
            url,
            status: null,
            failureText,
            payloadFile: tx?.requestPayloadFile || null
        });
    }

    /**
     * Hook Playwright `WebSocket` lifecycle events (`framesent`, `framereceived`, `socketerror`, `close`).
     *
     * @param {object} ws - Playwright WebSocket instance
     */
    _handleWebSocket(ws) {
        if (!ws || typeof ws.on !== 'function' || this.attachedWebSockets.has(ws)) {
            return;
        }
        this.attachedWebSockets.add(ws);

        this.wsSeq += 1;
        const wsCorrelationId = `ws-${this.traceIdShort}-${this.wsSeq}`;
        this.wsWireBlocks.set(wsCorrelationId, []);
        let wsUrl = '';
        try {
            if (typeof ws.url === 'function') {
                wsUrl = ws.url() || '';
            }
        } catch {}

        const parsedUrl = parseUrlComponents(wsUrl);
        const openEpochMs = Date.now();

        this._appendNdjsonEvent({
            type: 'ws-open',
            eventType: 'ws-open',
            direction: 'ws-open',
            stage: 'pre-tls-websocket-open',
            timestamp: new Date().toISOString(),
            epochMs: openEpochMs,
            seq: this._nextSeq(),
            correlationId: wsCorrelationId,
            url: wsUrl,
            host: parsedUrl.host,
            pathname: parsedUrl.pathname,
            triggerAction: this.getActiveTriggerSnapshot(openEpochMs),
            attribution: this.getAttributionSnapshot()
        });

        const recordWsFrame = (direction, stage, frameData) => {
            const timestamp = new Date().toISOString();
            const epochMs = Date.now();
            const seq = this._nextSeq();
            const attributionSnapshot = this.getAttributionSnapshot();
            const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs);

            const rawPayload = frameData && typeof frameData === 'object' && 'payload' in frameData
                ? frameData.payload
                : frameData;

            const payloadBuffer = Buffer.isBuffer(rawPayload)
                ? rawPayload
                : Buffer.from(String(rawPayload ?? ''), 'utf8');

            const hashed = hashPayload(payloadBuffer);
            const previewObj = buildBodyPreview(
                hashed.buffer,
                'text/plain',
                this.maxInlinePreviewBytes
            );

            let payloadFile = null;
            let payloadTruncated = false;
            if (hashed.byteLength > this.maxInlinePreviewBytes) {
                const saved = this._writePayloadFile(
                    'ws',
                    seq,
                    hashed.buffer,
                    hashed.shortSha256,
                    'application/octet-stream'
                );
                payloadFile = saved.payloadFile;
                payloadTruncated = Boolean(saved.payloadTruncated);
            }

            const stepBucket = this._ensureStepRecord(
                attributionSnapshot.actionStep,
                attributionSnapshot.stepIndex
            );
            const domainBucket = this._ensureDomainRecord(parsedUrl.host);
            const triggerBucket = this._ensureTriggerActionRecord(triggerSnapshot);
            stepBucket.domainsSet.add(parsedUrl.host);

            if (direction === 'ws-egress') {
                this.totals.wsFramesSent += 1;
                this.totals.totalEgressBytes += hashed.byteLength;
                stepBucket.egressBytes += hashed.byteLength;
                domainBucket.egressBytes += hashed.byteLength;
                if (triggerBucket) {
                    triggerBucket.wsFramesSent += 1;
                    triggerBucket.egressBytes += hashed.byteLength;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    triggerBucket.correlationIdsSet.add(wsCorrelationId);
                }
            } else {
                this.totals.wsFramesReceived += 1;
                this.totals.totalIngressBytes += hashed.byteLength;
                stepBucket.ingressBytes += hashed.byteLength;
                domainBucket.ingressBytes += hashed.byteLength;
                if (triggerBucket) {
                    triggerBucket.wsFramesReceived += 1;
                    triggerBucket.ingressBytes += hashed.byteLength;
                    triggerBucket.domainsSet.add(parsedUrl.host);
                    triggerBucket.correlationIdsSet.add(wsCorrelationId);
                }
            }

            const triggerSummary = this._formatTriggerSummary(triggerSnapshot);
            const wsWireBlock =
                direction === 'ws-egress'
                    ? [
                          '================================================================================',
                          `>>> WS-EGRESS [PRE-TLS] [${timestamp}] [corr=${wsCorrelationId}] [step=${attributionSnapshot.actionStep}] [trigger=${triggerSummary}] [url=${wsUrl}] [bytes=${hashed.byteLength}]`,
                          previewObj.preview || '',
                          '================================================================================'
                      ].join('\n')
                    : [
                          '--------------------------------------------------------------------------------',
                          `<<< WS-INGRESS [POST-TLS] [${timestamp}] [corr=${wsCorrelationId}] [step=${attributionSnapshot.actionStep}] [trigger=${triggerSummary}] [url=${wsUrl}] [bytes=${hashed.byteLength}]`,
                          previewObj.preview || '',
                          '--------------------------------------------------------------------------------'
                      ].join('\n');

            const storedWsBlocks = this.wsWireBlocks.get(wsCorrelationId);
            if (storedWsBlocks) {
                storedWsBlocks.push(wsWireBlock);
            }

            this._appendNdjsonEvent({
                type: direction,
                eventType: direction,
                direction,
                stage,
                timestamp,
                epochMs,
                seq,
                correlationId: wsCorrelationId,
                url: wsUrl,
                host: parsedUrl.host,
                payloadSha256: hashed.sha256,
                payloadBytes: hashed.byteLength,
                bodyPreview: previewObj.preview,
                bodyPreviewTruncated: previewObj.truncated,
                payloadFile,
                payloadTruncated,
                triggerAction: triggerSnapshot,
                attribution: attributionSnapshot
            });
            this._appendWireLogBlock(wsWireBlock);
        };

        const onFrameSent = (frame) =>
            recordWsFrame('ws-egress', 'pre-tls-websocket-frame', frame);
        const onFrameReceived = (frame) =>
            recordWsFrame('ws-ingress', 'post-tls-websocket-frame', frame);

        const onSocketError = (errorMsg) => {
            const timestamp = new Date().toISOString();
            const epochMs = Date.now();
            const seq = this._nextSeq();
            const attributionSnapshot = this.getAttributionSnapshot();
            const triggerSnapshot = this.getActiveTriggerSnapshot(epochMs);
            const failureText = String(errorMsg || 'WEBSOCKET_ERROR');

            this._appendNdjsonEvent({
                type: 'ws-error',
                eventType: 'ws-error',
                direction: 'ws-error',
                stage: 'websocket-channel-error',
                timestamp,
                epochMs,
                seq,
                correlationId: wsCorrelationId,
                url: wsUrl,
                host: parsedUrl.host,
                failureText,
                triggerAction: triggerSnapshot,
                attribution: attributionSnapshot
            });

            this._recordAnomaly({
                timestamp,
                correlationId: wsCorrelationId,
                actionStep: attributionSnapshot.actionStep,
                triggerAction: triggerSnapshot,
                type: 'websocket-error',
                severity: 'medium',
                method: 'WEBSOCKET',
                url: wsUrl,
                status: null,
                failureText,
                payloadFile: null
            });
        };

        const onClose = () => {
            const closeEpochMs = Date.now();
            this._appendNdjsonEvent({
                type: 'ws-close',
                eventType: 'ws-close',
                direction: 'ws-close',
                stage: 'websocket-channel-closed',
                timestamp: new Date().toISOString(),
                epochMs: closeEpochMs,
                seq: this._nextSeq(),
                correlationId: wsCorrelationId,
                url: wsUrl,
                host: parsedUrl.host,
                triggerAction: this.getActiveTriggerSnapshot(closeEpochMs),
                attribution: this.getAttributionSnapshot()
            });
        };

        ws.on('framesent', onFrameSent);
        ws.on('framereceived', onFrameReceived);
        ws.on('socketerror', onSocketError);
        ws.on('close', onClose);
    }

    /**
     * Build the structured multi-dimensional attribution and root-cause summary report.
     *
     * @returns {object}
     */
    buildAttributionSummary() {
        const endedAtIso = this.endedAt || new Date().toISOString();
        const endedAtMs = this.endedAt ? Date.parse(this.endedAt) : Date.now();
        const totalDurationMs = Math.max(0, endedAtMs - this.startedAtEpochMs);

        const byActionStepObj = {};
        for (const [stepName, stats] of this.byActionStep.entries()) {
            byActionStepObj[stepName] = {
                stepIndex: stats.stepIndex,
                requests: stats.requests,
                responses: stats.responses,
                failedRequests: stats.failedRequests,
                egressBytes: stats.egressBytes,
                ingressBytes: stats.ingressBytes,
                statusCounts: { ...stats.statusCounts },
                domains: Array.from(stats.domainsSet),
                anomalyCount: stats.anomalyCount
            };
        }

        const byDomainObj = {};
        for (const [host, stats] of this.byDomain.entries()) {
            const avgDurationMs = stats.completedWithDurationCount > 0
                ? Number((stats.totalDurationMs / stats.completedWithDurationCount).toFixed(2))
                : 0;
            byDomainObj[host] = {
                requests: stats.requests,
                responses: stats.responses,
                failedRequests: stats.failedRequests,
                egressBytes: stats.egressBytes,
                ingressBytes: stats.ingressBytes,
                statusCounts: { ...stats.statusCounts },
                avgDurationMs
            };
        }

        const byTriggerActionObj = {};
        for (const [actionId, stats] of this.byTriggerAction.entries()) {
            byTriggerActionObj[actionId] = {
                actionId: stats.actionId,
                actionType: stats.actionType,
                target: stats.target,
                actionStep: stats.actionStep,
                stepIndex: stats.stepIndex,
                timestamp: stats.timestamp,
                metadata: stats.metadata,
                requests: stats.requests,
                responses: stats.responses,
                failedRequests: stats.failedRequests,
                wsFramesSent: stats.wsFramesSent,
                wsFramesReceived: stats.wsFramesReceived,
                egressBytes: stats.egressBytes,
                ingressBytes: stats.ingressBytes,
                statusCounts: { ...stats.statusCounts },
                domains: Array.from(stats.domainsSet),
                correlationIds: Array.from(stats.correlationIdsSet),
                anomalyCount: stats.anomalyCount
            };
        }

        return {
            session: {
                traceId: this.attribution.traceId,
                profileId: this.attribution.profileId,
                accountId: this.attribution.accountId,
                accountEmail: this.attribution.accountEmail,
                os: this.attribution.os,
                proxyServer: this.attribution.proxyServer,
                startedAt: this.startedAt,
                endedAt: endedAtIso,
                totalDurationMs
            },
            artifacts: {
                trafficNdjsonPath: this.trafficNdjsonPath,
                preTlsWireLogPath: this.preTlsWireLogPath,
                neckoMozLogPath: this.neckoMozLogPath,
                payloadsDir: this.payloadsDir,
                sslKeyLogPath: this.sslKeyLogPath,
                harPath: this.harPath,
                attributionIndexPath: this.attributionIndexPath
            },
            totals: {
                totalRequests: this.totals.totalRequests,
                totalResponses: this.totals.totalResponses,
                failedRequests: this.totals.failedRequests,
                wsFramesSent: this.totals.wsFramesSent,
                wsFramesReceived: this.totals.wsFramesReceived,
                totalEgressBytes: this.totals.totalEgressBytes,
                totalIngressBytes: this.totals.totalIngressBytes
            },
            byActionStep: byActionStepObj,
            byDomain: byDomainObj,
            byTriggerAction: byTriggerActionObj,
            anomaliesAndRiskSignals: [...this.anomaliesAndRiskSignals]
        };
    }

    /**
     * Wait for any in-flight asynchronous payload captures to complete and write
     * `attribution-index.json` to disk.
     *
     * @returns {Promise<object>} Written attribution summary object
     */
    async flushSummary() {
        if (this.pendingTasks.size > 0) {
            await Promise.allSettled(Array.from(this.pendingTasks));
        }

        this._ensureDirectories();
        const summary = this.buildAttributionSummary();
        fs.writeFileSync(
            this.attributionIndexPath,
            `${JSON.stringify(summary, null, 2)}\n`,
            'utf8'
        );
        return summary;
    }

    /**
     * Detach all active event listeners, await in-flight traffic captures,
     * mark the recording session as ended, and flush `attribution-index.json`.
     *
     * @returns {Promise<object>} Final attribution summary object
     */
    async stop() {
        if (!this.stopped) {
            this.stopped = true;
            this.endedAt = new Date().toISOString();

            while (this.listenerDisposers.length > 0) {
                const dispose = this.listenerDisposers.pop();
                try {
                    dispose();
                } catch {}
            }
        }

        return this.flushSummary();
    }
}

/**
 * Factory helper to create a new `CamoufoxTrafficRecorder` instance.
 *
 * @param {object} [options={}]
 * @returns {CamoufoxTrafficRecorder}
 */
export function createTrafficRecorder(options = {}) {
    return new CamoufoxTrafficRecorder(options);
}

export default CamoufoxTrafficRecorder;
