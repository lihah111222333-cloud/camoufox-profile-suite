/**
 * Camoufox Pre-TLS Egress/Ingress Traffic Recorder & Attribution Test Suite
 *
 * Verifies:
 * 1. Pre-TLS Egress & Post-TLS Decrypted Ingress Capture (`traffic.ndjson` & `payloads/`),
 *    preserving Firefox's exact pre-TLS `headersArray()` order, redirect chain correlation
 *    (`302 -> 200`), SHA-256 payload hashes (`postDataSha256`, `bodySha256`), `serverAddr()`,
 *    and `securityDetails()`.
 * 2. Workflow Step Attribution (`setTrafficStep` & `updateTrafficAttribution`) across multiple
 *    steps (`step-1-landing`, `step-2-form-submit`, `step-3-verification-challenge`), including
 *    strict proxy password redaction on disk.
 * 3. Anomaly & Risk-Control Root-Cause Attribution (`attribution-index.json`) for HTTP `429`
 *    on `/challenge/arkose`, HTTP `403`, and `requestfailed` (`NS_ERROR_PROXY_CONNECTION_REFUSED`).
 * 4. WebSocket Pre-TLS Frame Capture (`ws-egress` & `ws-ingress`) with SHA-256 payload hashing
 *    and `totals.wsFramesSent` / `totals.wsFramesReceived` accounting.
 * 5. Concurrent Multi-Profile Traffic & `SSLKEYLOGFILE` Isolation across `Profile_Traffic_Win`
 *    and `Profile_Traffic_Mac`.
 *
 * Uses only Node's built-in `node:assert/strict` (zero external dependencies).
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    setCamoufoxModule,
    closeSharedBrowser
} from '../src/camoufox/client.js';
import { CamoufoxProfile, createAndStartProfile } from '../src/camoufox/profile.js';
import {
    CamoufoxTrafficRecorder,
    redactProxyUrl,
    verifyTrafficIntegrity
} from '../src/camoufox/traffic-recorder.js';
import { detectGmailPage } from '../src/gmail/page-detector.js';
import { queryProfileTraffic } from './query-traffic-attribution.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Compute SHA-256 hex digest for assertions.
 */
function sha256Hex(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
    return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Parse an NDJSON file into an array of objects.
 */
function readNdjsonFile(filePath) {
    assert.equal(fs.existsSync(filePath), true, `Expected NDJSON file to exist at ${filePath}`);
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (!raw) return [];
    return raw.split('\n').map((line) => JSON.parse(line));
}

/**
 * Create a tiny event emitter mixin for mock BrowserContext, Page, and WebSocket objects.
 */
function createEventHub() {
    const listeners = new Map();
    return {
        on(event, handler) {
            if (!listeners.has(event)) {
                listeners.set(event, []);
            }
            listeners.get(event).push(handler);
        },
        off(event, handler) {
            const arr = listeners.get(event);
            if (!arr) return;
            const idx = arr.indexOf(handler);
            if (idx >= 0) arr.splice(idx, 1);
        },
        removeListener(event, handler) {
            this.off(event, handler);
        },
        emit(event, payload) {
            const arr = [...(listeners.get(event) || [])];
            for (const fn of arr) {
                fn(payload);
            }
        }
    };
}

/**
 * Simulate Playwright's asynchronous Necko request -> response -> requestfinished lifecycle.
 */
async function emitHttpTransaction(context, request, response) {
    context.emit('request', request);
    await new Promise((resolve) => setImmediate(resolve));
    if (response) {
        context.emit('response', response);
        await new Promise((resolve) => setImmediate(resolve));
    }
    context.emit('requestfinished', request);
    await new Promise((resolve) => setImmediate(resolve));
}

/**
 * Simulate Playwright's asynchronous Necko request -> requestfailed lifecycle.
 */
async function emitFailedHttpTransaction(context, request) {
    context.emit('request', request);
    await new Promise((resolve) => setImmediate(resolve));
    context.emit('requestfailed', request);
    await new Promise((resolve) => setImmediate(resolve));
}

/**
 * Build a mock Playwright/Juggler Request object.
 */
function createMockRequest({
    method = 'GET',
    url = 'https://accounts.google.com/',
    resourceType = 'document',
    isNavigationRequest = false,
    frameUrl = 'https://accounts.google.com/',
    headersArray = null,
    headers = null,
    postData = null,
    redirectedFrom = null,
    timing = { requestStart: 5.0, responseEnd: 47.5 },
    sizes = {
        requestHeadersSize: 320,
        requestBodySize: 0,
        responseHeadersSize: 280,
        responseBodySize: 0
    },
    failure = null
} = {}) {
    const resolvedHeadersArray = Array.isArray(headersArray)
        ? headersArray
        : Object.entries(headers || {}).map(([name, value]) => ({ name, value }));

    const resolvedHeadersObj = headers || Object.fromEntries(
        resolvedHeadersArray.map((h) => [h.name.toLowerCase(), h.value])
    );

    const postBuffer = postData !== null && postData !== undefined
        ? (Buffer.isBuffer(postData) ? postData : Buffer.from(String(postData), 'utf8'))
        : null;

    return {
        method: () => method,
        url: () => url,
        resourceType: () => resourceType,
        isNavigationRequest: () => Boolean(isNavigationRequest),
        frame: () => ({ url: () => frameUrl }),
        headers: () => ({ ...resolvedHeadersObj }),
        headersArray: async () => resolvedHeadersArray.map((h) => ({ ...h })),
        postData: () => (postBuffer ? postBuffer.toString('utf8') : null),
        postDataBuffer: () => postBuffer,
        redirectedFrom: () => redirectedFrom,
        timing: () => timing,
        sizes: async () => ({
            ...sizes,
            requestBodySize: sizes.requestBodySize || (postBuffer ? postBuffer.byteLength : 0)
        }),
        failure: () => (failure ? { errorText: failure } : null)
    };
}

/**
 * Build a mock Playwright/Juggler Response object.
 */
function createMockResponse({
    request,
    url = null,
    status = 200,
    statusText = 'OK',
    headersArray = null,
    headers = null,
    body = null,
    serverAddr = { ipAddress: '142.250.185.78', port: 443 },
    securityDetails = {
        protocol: 'TLS 1.3',
        subjectName: 'accounts.google.com',
        issuer: 'GTS CA 1C3'
    }
} = {}) {
    const resolvedUrl = url || (request ? request.url() : 'https://accounts.google.com/');
    const resolvedHeadersArray = Array.isArray(headersArray)
        ? headersArray
        : Object.entries(headers || {}).map(([name, value]) => ({ name, value }));

    const resolvedHeadersObj = headers || Object.fromEntries(
        resolvedHeadersArray.map((h) => [h.name.toLowerCase(), h.value])
    );

    const bodyBuffer = body !== null && body !== undefined
        ? (Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8'))
        : null;

    return {
        request: () => request,
        url: () => resolvedUrl,
        status: () => status,
        statusText: () => statusText,
        ok: () => status >= 200 && status < 300,
        headers: () => ({ ...resolvedHeadersObj }),
        headersArray: async () => resolvedHeadersArray.map((h) => ({ ...h })),
        body: async () => bodyBuffer,
        text: async () => (bodyBuffer ? bodyBuffer.toString('utf8') : ''),
        serverAddr: async () => serverAddr,
        securityDetails: async () => securityDetails
    };
}

/**
 * Build a mock Playwright WebSocket object.
 */
function createMockWebSocket(url = 'wss://accounts.google.com/v3/signin/ws') {
    const hub = createEventHub();
    let closed = false;
    return {
        ...hub,
        url: () => url,
        isClosed: () => closed,
        sendFrame(payload) {
            hub.emit('framesent', { payload });
        },
        receiveFrame(payload) {
            hub.emit('framereceived', { payload });
        },
        triggerError(errorMsg) {
            hub.emit('socketerror', errorMsg);
        },
        closeSocket() {
            closed = true;
            hub.emit('close');
        }
    };
}

/**
 * Create an isolated in-memory Mock Camoufox Engine supporting Playwright BrowserContext
 * and Page network/WebSocket event emission.
 */
function createMockCamoufoxEngine() {
    let browserIdSeq = 0;
    let contextIdSeq = 0;
    let pageIdSeq = 0;
    const launchedBrowsers = [];
    const createdContexts = [];

    function createMockPage(context) {
        const pageId = ++pageIdSeq;
        let closed = false;
        let currentUrl = 'about:blank';
        const hub = createEventHub();

        return {
            ...hub,
            pageId,
            context: () => context,
            url: () => currentUrl,
            isClosed: () => closed,
            async close() {
                closed = true;
            },
            async goto(url, options = {}) {
                currentUrl = String(url || 'about:blank');
                return { url: currentUrl, options, status: 200 };
            },
            async click(selector, options = {}) {
                return { selector, options };
            },
            async fill(selector, value, options = {}) {
                return { selector, value, options };
            },
            async type(selector, text, options = {}) {
                return { selector, text, options };
            },
            async press(selector, key, options = {}) {
                return { selector, key, options };
            },
            async waitForTimeout() {
                return null;
            },
            async evaluate(fn, arg) {
                if (typeof fn === 'function') {
                    return fn(arg);
                }
                return null;
            }
        };
    }

    function createMockContext(browser, contextOptions = {}) {
        const contextId = ++contextIdSeq;
        let closed = false;
        const pages = [];
        let cookieJar = [];
        const hub = createEventHub();

        const context = {
            ...hub,
            contextId,
            browser: () => browser,
            options: { ...contextOptions },
            isClosed: () => closed,
            pages: () => pages.filter((p) => !p.isClosed()),
            async newPage() {
                if (closed) {
                    throw new Error(`Cannot create page in closed BrowserContext #${contextId}`);
                }
                const page = createMockPage(context);
                pages.push(page);
                hub.emit('page', page);
                return page;
            },
            async addCookies(cookies = []) {
                cookieJar.push(...cookies.map((c) => ({ ...c })));
            },
            async cookies() {
                return cookieJar.map((c) => ({ ...c }));
            },
            async clearCookies() {
                cookieJar = [];
            },
            async storageState({ path: savePath } = {}) {
                const state = { cookies: cookieJar.map((c) => ({ ...c })), origins: [] };
                if (savePath) {
                    fs.mkdirSync(path.dirname(savePath), { recursive: true });
                    fs.writeFileSync(savePath, JSON.stringify(state, null, 2), 'utf8');
                }
                return state;
            },
            async addInitScript() {
                return true;
            },
            async close() {
                closed = true;
                for (const p of pages) {
                    await p.close();
                }
            }
        };

        createdContexts.push(context);
        return context;
    }

    function createMockBrowser(launchOptions = {}) {
        const browserId = ++browserIdSeq;
        let connected = true;
        const contexts = [];
        const hub = createEventHub();

        const browser = {
            ...hub,
            browserId,
            launchOptions: { ...launchOptions },
            isConnected: () => connected,
            contexts: () => contexts.filter((c) => !c.isClosed()),
            async newContext(contextOptions = {}) {
                const ctx = createMockContext(browser, {
                    os: launchOptions.os,
                    proxy: launchOptions.proxy,
                    ...contextOptions
                });
                contexts.push(ctx);
                return ctx;
            },
            async close() {
                if (!connected) return;
                connected = false;
                for (const ctx of contexts) {
                    if (!ctx.isClosed()) {
                        await ctx.close();
                    }
                }
                hub.emit('disconnected');
            }
        };

        launchedBrowsers.push(browser);
        return browser;
    }

    return {
        launchedBrowsers,
        createdContexts,
        async Camoufox(launchOptions = {}) {
            await new Promise((resolve) => setTimeout(resolve, 5));
            return createMockBrowser(launchOptions);
        },
        async AsyncCamoufox(launchOptions = {}) {
            await new Promise((resolve) => setTimeout(resolve, 5));
            return createMockBrowser(launchOptions);
        },
        async NewContext(browser, contextOptions = {}) {
            await new Promise((resolve) => setTimeout(resolve, 2));
            return browser.newContext(contextOptions);
        },
        async AsyncNewContext(browser, contextOptions = {}) {
            await new Promise((resolve) => setTimeout(resolve, 2));
            return browser.newContext(contextOptions);
        }
    };
}

async function runTests() {
    const tempProfilesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-traffic-test-'));
    const mockEngine = createMockCamoufoxEngine();
    setCamoufoxModule(mockEngine);

    let passedTests = 0;
    async function testSection(name, fn) {
        process.stdout.write(`🧪 Running: ${name} ... `);
        await fn();
        passedTests += 1;
        console.log('PASS ✅');
    }

    try {
        // =========================================================================
        // Test 1: Pre-TLS Egress & Post-TLS Decrypted Ingress Capture
        // =========================================================================
        await testSection(
            'Test 1: Pre-TLS Egress & Post-TLS Decrypted Ingress Capture (traffic.ndjson & payloads/)',
            async () => {
                const profile = await createAndStartProfile(
                    'Traffic_Test_1',
                    'http://10.0.1.15:8080:proxyUser:topSecretPass123',
                    {
                        profileId: 'traffic-test-1',
                        os: 'windows',
                        profilesDir: tempProfilesDir
                    }
                );

                const context = await profile.getContext();

                // Exact Firefox pre-TLS raw headersArray order
                const expectedRequestHeaderOrder = [
                    { name: 'Host', value: 'accounts.google.com' },
                    {
                        name: 'User-Agent',
                        value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0'
                    },
                    { name: 'Accept', value: 'application/json, text/plain, */*' },
                    { name: 'Accept-Language', value: 'en-US,en;q=0.5' },
                    { name: 'Content-Type', value: 'application/json' },
                    { name: 'Sec-Fetch-Dest', value: 'empty' },
                    { name: 'Sec-Fetch-Mode', value: 'cors' },
                    { name: 'Sec-Fetch-Site', value: 'same-origin' }
                ];

                const postPayloadObj = { username: 'alice', token: 'xyz' };
                const postPayloadJson = JSON.stringify(postPayloadObj);
                const expectedPostSha256 = sha256Hex(postPayloadJson);

                // Hop 1: POST request receiving 302 redirect
                const reqHop1 = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/lookup?hl=en&flowName=GlifWebSignIn',
                    resourceType: 'fetch',
                    isNavigationRequest: false,
                    headersArray: expectedRequestHeaderOrder,
                    postData: postPayloadJson
                });

                const resHop1 = createMockResponse({
                    request: reqHop1,
                    status: 302,
                    statusText: 'Found',
                    headersArray: [
                        { name: 'Location', value: 'https://accounts.google.com/v3/signin/identifier?hl=en' },
                        { name: 'Cache-Control', value: 'no-cache, no-store' }
                    ],
                    serverAddr: { ipAddress: '142.250.185.78', port: 443 },
                    securityDetails: { protocol: 'TLS 1.3', subjectName: 'accounts.google.com' }
                });

                await emitHttpTransaction(context, reqHop1, resHop1);

                // Hop 2: Follow-up redirected GET request -> 200 OK with decrypted JSON body
                const decryptedResponseJson = JSON.stringify({
                    status: 'ACCOUNT_READY',
                    sessionId: 'sess_987654321',
                    continuations: ['password_step']
                });
                const expectedBodySha256 = sha256Hex(decryptedResponseJson);

                const reqHop2 = createMockRequest({
                    method: 'GET',
                    url: 'https://accounts.google.com/v3/signin/identifier?hl=en',
                    resourceType: 'document',
                    isNavigationRequest: true,
                    redirectedFrom: reqHop1,
                    headersArray: [
                        { name: 'Host', value: 'accounts.google.com' },
                        {
                            name: 'User-Agent',
                            value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0'
                        }
                    ]
                });

                const resHop2 = createMockResponse({
                    request: reqHop2,
                    status: 200,
                    statusText: 'OK',
                    headersArray: [
                        { name: 'Content-Type', value: 'application/json; charset=utf-8' },
                        { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }
                    ],
                    body: Buffer.from(decryptedResponseJson, 'utf8'),
                    serverAddr: { ipAddress: '142.250.185.78', port: 443 },
                    securityDetails: { protocol: 'TLS 1.3', subjectName: 'accounts.google.com' }
                });

                await emitHttpTransaction(context, reqHop2, resHop2);

                await profile.getTrafficAttribution();

                const ndjsonPath = profile.trafficPaths.trafficNdjsonPath;
                const events = readNdjsonFile(ndjsonPath);

                const egressEvents = events.filter((e) => e.type === 'egress');
                const ingressEvents = events.filter((e) => e.type === 'ingress');
                const finishedEvents = events.filter((e) => e.type === 'request-finished');

                assert.equal(egressEvents.length, 2);
                assert.equal(ingressEvents.length, 2);
                assert.equal(finishedEvents.length, 2);

                const [egress1, egress2] = egressEvents;
                const [ingress1, ingress2] = ingressEvents;

                // Verify Correlation ID matching between egress and ingress
                assert.ok(egress1.correlationId.startsWith('corr-'));
                assert.equal(egress1.correlationId, ingress1.correlationId);
                assert.equal(egress2.correlationId, ingress2.correlationId);

                // Verify redirect chain correlation (302 -> 200)
                assert.equal(egress1.redirectedFromCorrelationId, null);
                assert.equal(egress2.redirectedFromCorrelationId, egress1.correlationId);
                assert.equal(ingress2.redirectedFromCorrelationId, egress1.correlationId);
                assert.equal(ingress1.status, 302);
                assert.equal(ingress2.status, 200);

                // Verify exact Firefox pre-TLS header ordering is preserved
                assert.deepEqual(egress1.headersArray, expectedRequestHeaderOrder);
                assert.deepEqual(egress1.searchParams, {
                    hl: 'en',
                    flowName: 'GlifWebSignIn'
                });

                // Verify pre-TLS POST payload SHA-256 and saved payload file on disk
                assert.equal(egress1.postDataSha256, expectedPostSha256);
                assert.equal(egress1.postDataBytes, Buffer.byteLength(postPayloadJson));
                assert.equal(egress1.bodyPreview, postPayloadJson);
                assert.ok(egress1.payloadFile && egress1.payloadFile.startsWith('payloads/req-'));

                const reqPayloadDiskPath = path.join(profile.trafficPaths.trafficDir, egress1.payloadFile);
                assert.equal(fs.existsSync(reqPayloadDiskPath), true);
                assert.equal(fs.readFileSync(reqPayloadDiskPath, 'utf8'), postPayloadJson);

                // Verify post-TLS decrypted response body SHA-256, serverAddr, securityDetails, and payload file
                assert.equal(ingress2.bodySha256, expectedBodySha256);
                assert.equal(ingress2.bodyBytes, Buffer.byteLength(decryptedResponseJson));
                assert.equal(ingress2.bodyPreview, decryptedResponseJson);
                assert.deepEqual(ingress2.serverAddr, { ipAddress: '142.250.185.78', port: 443 });
                assert.deepEqual(ingress2.securityDetails, {
                    protocol: 'TLS 1.3',
                    subjectName: 'accounts.google.com'
                });
                assert.ok(ingress2.payloadFile && ingress2.payloadFile.startsWith('payloads/res-'));

                const resPayloadDiskPath = path.join(profile.trafficPaths.trafficDir, ingress2.payloadFile);
                assert.equal(fs.existsSync(resPayloadDiskPath), true);
                assert.equal(fs.readFileSync(resPayloadDiskPath, 'utf8'), decryptedResponseJson);

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 2: Workflow Step Attribution (setTrafficStep & updateTrafficAttribution)
        // =========================================================================
        await testSection(
            'Test 2: Workflow Step Attribution (setTrafficStep, updateTrafficAttribution & proxy password redaction)',
            async () => {
                const secretPassword = ' UltraSecret_P@ssw0rd_NeverLeak! ';
                const rawProxy = `socks5://proxyAdmin:${secretPassword.trim()}@198.51.100.77:1080`;

                assert.equal(redactProxyUrl(rawProxy), 'socks5://198.51.100.77:1080');

                const profile = await createAndStartProfile('Traffic_Test_2', rawProxy, {
                    profileId: 'traffic-test-2',
                    os: 'macos',
                    profilesDir: tempProfilesDir,
                    accountId: 'acct-initial-001',
                    accountEmail: 'alice.initial@gmail.com'
                });

                const context = await profile.getContext();

                // Update account attribution dynamically before starting steps
                profile.updateTrafficAttribution({
                    accountId: 'acct-verified-777',
                    accountEmail: 'alice.verified777@gmail.com',
                    proxy: rawProxy
                });

                const steps = [
                    {
                        name: 'step-1-landing',
                        url: 'https://accounts.google.com/signup/v2/webcreateaccount'
                    },
                    {
                        name: 'step-2-form-submit',
                        url: 'https://accounts.google.com/lifecycle/steps/signup/name'
                    },
                    {
                        name: 'step-3-verification-challenge',
                        url: 'https://accounts.google.com/lifecycle/steps/signup/username'
                    }
                ];

                for (let i = 0; i < steps.length; i += 1) {
                    const step = steps[i];
                    const snap = profile.setTrafficStep(step.name, { phaseOrder: i + 1 });
                    assert.equal(snap.actionStep, step.name);
                    assert.equal(snap.stepIndex, i + 1);

                    const req = createMockRequest({
                        method: 'POST',
                        url: step.url,
                        postData: JSON.stringify({ step: step.name })
                    });
                    const res = createMockResponse({
                        request: req,
                        status: 200,
                        body: JSON.stringify({ ok: true, step: step.name })
                    });

                    await emitHttpTransaction(context, req, res);
                }

                await profile.getTrafficAttribution();

                const ndjsonRaw = fs.readFileSync(profile.trafficPaths.trafficNdjsonPath, 'utf8');
                const indexRaw = fs.readFileSync(profile.trafficPaths.attributionIndexPath, 'utf8');

                // Security invariant: proxy credentials must NEVER appear anywhere in traffic logs
                assert.equal(ndjsonRaw.includes(secretPassword.trim()), false);
                assert.equal(ndjsonRaw.includes('proxyAdmin'), false);
                assert.equal(indexRaw.includes(secretPassword.trim()), false);
                assert.equal(indexRaw.includes('proxyAdmin'), false);

                const events = readNdjsonFile(profile.trafficPaths.trafficNdjsonPath);
                const transitions = events.filter((e) => e.type === 'step-transition');
                assert.equal(transitions.length, 3);

                for (let i = 0; i < steps.length; i += 1) {
                    const expectedStep = steps[i].name;
                    const expectedIndex = i + 1;

                    const stepEgress = events.filter(
                        (e) => e.type === 'egress' && e.attribution.actionStep === expectedStep
                    );
                    const stepIngress = events.filter(
                        (e) => e.type === 'ingress' && e.attribution.actionStep === expectedStep
                    );

                    assert.equal(stepEgress.length, 1);
                    assert.equal(stepIngress.length, 1);

                    for (const record of [...stepEgress, ...stepIngress]) {
                        assert.equal(record.attribution.actionStep, expectedStep);
                        assert.equal(record.attribution.stepIndex, expectedIndex);
                        assert.equal(record.attribution.profileId, 'traffic-test-2');
                        assert.equal(record.attribution.accountId, 'acct-verified-777');
                        assert.equal(record.attribution.accountEmail, 'alice.verified777@gmail.com');
                        assert.equal(record.attribution.os, 'macos');
                        assert.equal(record.attribution.proxyServer, 'socks5://198.51.100.77:1080');
                    }
                }

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 3: Anomaly & Risk-Control Root-Cause Attribution (attribution-index.json)
        // =========================================================================
        await testSection(
            'Test 3: Anomaly & Risk-Control Root-Cause Attribution (attribution-index.json)',
            async () => {
                const profile = await createAndStartProfile(
                    'Traffic_Test_3',
                    'http://203.0.113.50:3128:user3:pass3',
                    {
                        profileId: 'traffic-test-3',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        accountId: 'acct-anomaly-99',
                        accountEmail: 'anomaly99@gmail.com'
                    }
                );

                const context = await profile.getContext();

                // 1) Step: challenge-step -> HTTP 429 Too Many Requests on /challenge/arkose
                profile.setTrafficStep('step-arkose-challenge');
                const arkoseReq = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/challenge/arkose?flow=signup',
                    headersArray: [{ name: 'Content-Type', value: 'application/json' }],
                    postData: JSON.stringify({ arkoseToken: 'tok_arkose_123' })
                });
                const arkoseRes = createMockResponse({
                    request: arkoseReq,
                    status: 429,
                    statusText: 'Too Many Requests',
                    headersArray: [{ name: 'Content-Type', value: 'application/json' }],
                    body: JSON.stringify({
                        error: 'RATE_LIMITED',
                        challenge: 'arkose_enforcement'
                    })
                });
                await emitHttpTransaction(context, arkoseReq, arkoseRes);

                // 2) Step: verify-step -> HTTP 403 Forbidden
                profile.setTrafficStep('step-forbidden-submit');
                const forbiddenReq = createMockRequest({
                    method: 'POST',
                    url: 'https://www.google.com/recaptcha/api2/reload?k=sitekey123',
                    headersArray: [{ name: 'Content-Type', value: 'application/json' }],
                    postData: JSON.stringify({ reason: 'reload' })
                });
                const forbiddenRes = createMockResponse({
                    request: forbiddenReq,
                    status: 403,
                    statusText: 'Forbidden',
                    headersArray: [{ name: 'Content-Type', value: 'text/plain' }],
                    body: '403 Forbidden: Unusual traffic detected'
                });
                await emitHttpTransaction(context, forbiddenReq, forbiddenRes);

                // 3) Step: proxy-drop-step -> requestfailed with NS_ERROR_PROXY_CONNECTION_REFUSED
                profile.setTrafficStep('step-proxy-failure');
                const failedReq = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/AccountsSignUpIdvChallenge',
                    headersArray: [{ name: 'Content-Type', value: 'application/json' }],
                    postData: JSON.stringify({ phone: '+12025550199' }),
                    failure: 'NS_ERROR_PROXY_CONNECTION_REFUSED'
                });
                await emitFailedHttpTransaction(context, failedReq);

                const summary = await profile.getTrafficAttribution();
                const diskSummary = JSON.parse(
                    fs.readFileSync(profile.trafficPaths.attributionIndexPath, 'utf8')
                );

                assert.deepEqual(summary.totals, diskSummary.totals);
                assert.equal(diskSummary.totals.totalRequests, 3);
                assert.equal(diskSummary.totals.totalResponses, 2);
                assert.equal(diskSummary.totals.failedRequests, 1);

                // Verify byActionStep aggregation
                assert.equal(diskSummary.byActionStep['step-arkose-challenge'].requests, 1);
                assert.equal(diskSummary.byActionStep['step-arkose-challenge'].responses, 1);
                assert.equal(diskSummary.byActionStep['step-arkose-challenge'].statusCounts['429'], 1);
                assert.ok(diskSummary.byActionStep['step-arkose-challenge'].anomalyCount >= 1);

                assert.equal(diskSummary.byActionStep['step-forbidden-submit'].statusCounts['403'], 1);
                assert.ok(diskSummary.byActionStep['step-forbidden-submit'].anomalyCount >= 1);

                assert.equal(diskSummary.byActionStep['step-proxy-failure'].requests, 1);
                assert.equal(diskSummary.byActionStep['step-proxy-failure'].failedRequests, 1);
                assert.ok(diskSummary.byActionStep['step-proxy-failure'].anomalyCount >= 1);

                // Verify byDomain aggregation
                assert.equal(diskSummary.byDomain['accounts.google.com'].requests, 2);
                assert.equal(diskSummary.byDomain['accounts.google.com'].responses, 1);
                assert.equal(diskSummary.byDomain['accounts.google.com'].failedRequests, 1);
                assert.equal(diskSummary.byDomain['www.google.com'].requests, 1);
                assert.equal(diskSummary.byDomain['www.google.com'].statusCounts['403'], 1);

                // Verify anomaliesAndRiskSignals entries for root-cause auditing
                const anomalies = diskSummary.anomaliesAndRiskSignals;
                assert.ok(Array.isArray(anomalies) && anomalies.length >= 3);

                const rateLimitAnomaly = anomalies.find((a) => a.type === 'http-429-rate-limit');
                assert.ok(rateLimitAnomaly, 'Expected http-429-rate-limit anomaly');
                assert.equal(rateLimitAnomaly.actionStep, 'step-arkose-challenge');
                assert.equal(rateLimitAnomaly.status, 429);
                assert.ok(rateLimitAnomaly.correlationId.startsWith('corr-'));
                assert.ok(
                    rateLimitAnomaly.payloadFile && rateLimitAnomaly.payloadFile.startsWith('payloads/res-')
                );

                const arkoseSignalAnomaly = anomalies.find(
                    (a) => a.type.startsWith('risk-signal:') && a.type.includes('arkose')
                );
                assert.ok(arkoseSignalAnomaly, 'Expected risk-signal anomaly containing arkose');
                assert.equal(arkoseSignalAnomaly.actionStep, 'step-arkose-challenge');

                const forbiddenAnomaly = anomalies.find((a) => a.type === 'http-403-forbidden');
                assert.ok(forbiddenAnomaly, 'Expected http-403-forbidden anomaly');
                assert.equal(forbiddenAnomaly.actionStep, 'step-forbidden-submit');
                assert.equal(forbiddenAnomaly.status, 403);
                assert.ok(
                    forbiddenAnomaly.payloadFile && forbiddenAnomaly.payloadFile.startsWith('payloads/res-')
                );

                const proxyFailureAnomaly = anomalies.find(
                    (a) => a.failureText === 'NS_ERROR_PROXY_CONNECTION_REFUSED'
                );
                assert.ok(proxyFailureAnomaly, 'Expected NS_ERROR_PROXY_CONNECTION_REFUSED anomaly');
                assert.equal(proxyFailureAnomaly.type, 'network-proxy-or-tls-failure');
                assert.equal(proxyFailureAnomaly.actionStep, 'step-proxy-failure');
                assert.equal(proxyFailureAnomaly.status, null);
                assert.ok(
                    proxyFailureAnomaly.payloadFile &&
                        proxyFailureAnomaly.payloadFile.startsWith('payloads/req-')
                );

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 4: WebSocket Pre-TLS Frame Capture (ws-egress & ws-ingress)
        // =========================================================================
        await testSection(
            'Test 4: WebSocket Pre-TLS Frame Capture (ws-egress & ws-ingress)',
            async () => {
                const profile = await createAndStartProfile('Traffic_Test_4', null, {
                    profileId: 'traffic-test-4',
                    os: 'linux',
                    profilesDir: tempProfilesDir
                });

                const page = await profile.getPage();
                profile.setTrafficStep('step-websocket-handshake');

                const wsUrl = 'wss://accounts.google.com/v3/signin/ws?client=firefox';
                const mockWs = createMockWebSocket(wsUrl);

                page.emit('websocket', mockWs);

                const outboundFrame1 = JSON.stringify({ action: 'auth_init', nonce: 'n_101' });
                const outboundFrame2 = JSON.stringify({ action: 'challenge_ack', seq: 2 });
                const inboundFrame1 = JSON.stringify({ status: 'challenge_ready', difficulty: 4 });

                mockWs.sendFrame(outboundFrame1);
                mockWs.receiveFrame(inboundFrame1);
                mockWs.sendFrame(outboundFrame2);
                mockWs.closeSocket();

                const summary = await profile.getTrafficAttribution();
                assert.equal(summary.totals.wsFramesSent, 2);
                assert.equal(summary.totals.wsFramesReceived, 1);

                const events = readNdjsonFile(profile.trafficPaths.trafficNdjsonPath);
                const wsOpen = events.filter((e) => e.type === 'ws-open');
                const wsEgress = events.filter((e) => e.type === 'ws-egress');
                const wsIngress = events.filter((e) => e.type === 'ws-ingress');
                const wsClose = events.filter((e) => e.type === 'ws-close');

                assert.equal(wsOpen.length, 1);
                assert.equal(wsEgress.length, 2);
                assert.equal(wsIngress.length, 1);
                assert.equal(wsClose.length, 1);

                const wsCorrId = wsOpen[0].correlationId;
                assert.ok(wsCorrId.startsWith('ws-'));
                assert.equal(wsEgress[0].correlationId, wsCorrId);
                assert.equal(wsEgress[1].correlationId, wsCorrId);
                assert.equal(wsIngress[0].correlationId, wsCorrId);
                assert.equal(wsClose[0].correlationId, wsCorrId);

                assert.equal(wsEgress[0].bodyPreview, outboundFrame1);
                assert.equal(wsEgress[0].payloadSha256, sha256Hex(outboundFrame1));
                assert.equal(wsEgress[1].bodyPreview, outboundFrame2);
                assert.equal(wsEgress[1].payloadSha256, sha256Hex(outboundFrame2));

                assert.equal(wsIngress[0].bodyPreview, inboundFrame1);
                assert.equal(wsIngress[0].payloadSha256, sha256Hex(inboundFrame1));
                assert.equal(wsIngress[0].attribution.actionStep, 'step-websocket-handshake');

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 5: Concurrent Multi-Profile Traffic & SSLKEYLOGFILE Isolation
        // =========================================================================
        await testSection(
            'Test 5: Concurrent Multi-Profile Traffic & SSLKEYLOGFILE Isolation (Profile_Traffic_Win vs Profile_Traffic_Mac)',
            async () => {
                const browserCountBefore = mockEngine.launchedBrowsers.length;

                const [profileWin, profileMac] = await Promise.all([
                    createAndStartProfile(
                        'Profile_Traffic_Win',
                        'http://10.100.1.1:8080:winUser:winSecretPass',
                        {
                            profileId: 'profile-traffic-win',
                            os: 'windows',
                            profilesDir: tempProfilesDir,
                            useSharedBrowser: false,
                            accountId: 'win-acct-1',
                            accountEmail: 'win.user@gmail.com'
                        }
                    ),
                    createAndStartProfile(
                        'Profile_Traffic_Mac',
                        'socks5://macUser:macSecretPass@10.100.2.2:1080',
                        {
                            profileId: 'profile-traffic-mac',
                            os: 'macos',
                            profilesDir: tempProfilesDir,
                            useSharedBrowser: false,
                            accountId: 'mac-acct-2',
                            accountEmail: 'mac.user@gmail.com'
                        }
                    )
                ]);

                assert.equal(mockEngine.launchedBrowsers.length - browserCountBefore, 2);

                // Verify each launched Camoufox browser received its own isolated SSLKEYLOGFILE in env
                const winLaunchEnv = profileWin.browser.launchOptions.env;
                const macLaunchEnv = profileMac.browser.launchOptions.env;

                assert.ok(winLaunchEnv && winLaunchEnv.SSLKEYLOGFILE);
                assert.ok(macLaunchEnv && macLaunchEnv.SSLKEYLOGFILE);
                assert.notEqual(winLaunchEnv.SSLKEYLOGFILE, macLaunchEnv.SSLKEYLOGFILE);
                assert.equal(winLaunchEnv.SSLKEYLOGFILE, profileWin.trafficPaths.sslKeyLogPath);
                assert.equal(macLaunchEnv.SSLKEYLOGFILE, profileMac.trafficPaths.sslKeyLogPath);
                assert.equal(fs.existsSync(profileWin.trafficPaths.sslKeyLogPath), true);
                assert.equal(fs.existsSync(profileMac.trafficPaths.sslKeyLogPath), true);

                // Emit concurrent distinct traffic on both profiles
                profileWin.setTrafficStep('win-step-signup');
                profileMac.setTrafficStep('mac-step-login');

                const winReq = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/win-only-endpoint',
                    postData: JSON.stringify({ profile: 'WIN_ONLY_PAYLOAD' })
                });
                const winRes = createMockResponse({
                    request: winReq,
                    status: 200,
                    body: JSON.stringify({ result: 'WIN_RESPONSE_OK' })
                });

                const macReq = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/mac-only-endpoint',
                    postData: JSON.stringify({ profile: 'MAC_ONLY_PAYLOAD' })
                });
                const macRes = createMockResponse({
                    request: macReq,
                    status: 201,
                    body: JSON.stringify({ result: 'MAC_RESPONSE_CREATED' })
                });

                await Promise.all([
                    emitHttpTransaction(profileWin.context, winReq, winRes),
                    emitHttpTransaction(profileMac.context, macReq, macRes)
                ]);

                // Stop both profiles concurrently and verify traffic summaries
                await Promise.all([profileWin.stop(), profileMac.stop()]);

                const winEvents = readNdjsonFile(profileWin.trafficPaths.trafficNdjsonPath);
                const macEvents = readNdjsonFile(profileMac.trafficPaths.trafficNdjsonPath);

                const winIndex = JSON.parse(
                    fs.readFileSync(profileWin.trafficPaths.attributionIndexPath, 'utf8')
                );
                const macIndex = JSON.parse(
                    fs.readFileSync(profileMac.trafficPaths.attributionIndexPath, 'utf8')
                );

                // Verify zero cross-profile contamination in NDJSON
                assert.equal(
                    winEvents.every((e) => e.attribution.profileId === 'profile-traffic-win'),
                    true
                );
                assert.equal(
                    winEvents.some((e) => JSON.stringify(e).includes('MAC_ONLY_PAYLOAD')),
                    false
                );
                assert.equal(
                    winEvents.some((e) => e.url && e.url.includes('mac-only-endpoint')),
                    false
                );

                assert.equal(
                    macEvents.every((e) => e.attribution.profileId === 'profile-traffic-mac'),
                    true
                );
                assert.equal(
                    macEvents.some((e) => JSON.stringify(e).includes('WIN_ONLY_PAYLOAD')),
                    false
                );
                assert.equal(
                    macEvents.some((e) => e.url && e.url.includes('win-only-endpoint')),
                    false
                );

                // Verify isolated attribution-index.json per profile
                assert.equal(winIndex.session.profileId, 'profile-traffic-win');
                assert.equal(winIndex.session.accountEmail, 'win.user@gmail.com');
                assert.equal(winIndex.session.os, 'windows');
                assert.equal(winIndex.session.proxyServer, 'http://10.100.1.1:8080');
                assert.ok(winIndex.byActionStep['win-step-signup']);
                assert.equal(winIndex.byActionStep['mac-step-login'], undefined);

                assert.equal(macIndex.session.profileId, 'profile-traffic-mac');
                assert.equal(macIndex.session.accountEmail, 'mac.user@gmail.com');
                assert.equal(macIndex.session.os, 'macos');
                assert.equal(macIndex.session.proxyServer, 'socks5://10.100.2.2:1080');
                assert.ok(macIndex.byActionStep['mac-step-login']);
                assert.equal(macIndex.byActionStep['win-step-signup'], undefined);

                // Clean up both profiles
                await Promise.all([profileWin.delete(), profileMac.delete()]);
                await closeSharedBrowser();
            }
        );

        // =========================================================================
        // Test 6: Pre-TLS Wire Log (pre-tls-wire.log), recordBodies: false, & maxBodyBytes Truncation
        // =========================================================================
        await testSection(
            'Test 6: Pre-TLS Wire Log (pre-tls-wire.log), recordBodies: false, & maxBodyBytes Truncation',
            async () => {
                // Part A: pre-tls-wire.log + formatTransactionWireDump + maxBodyBytes: 32 truncation
                const profileTrunc = await createAndStartProfile(
                    'Traffic_Test_6_Trunc',
                    'http://10.20.30.40:8080',
                    {
                        profileId: 'traffic-test-6-trunc',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        maxBodyBytes: 32
                    }
                );

                profileTrunc.setTrafficStep('step-6-wire-and-truncation');
                const truncContext = await profileTrunc.getContext();

                const longReqPayload = JSON.stringify({
                    message: 'THIS_REQUEST_BODY_IS_LONGER_THAN_32_BYTES_FOR_TRUNCATION_TEST',
                    seq: 601
                });
                const longResPayload = JSON.stringify({
                    status: 'OK_LONG_RESPONSE_BODY_EXCEEDING_32_BYTES_LIMIT_ON_DISK',
                    token: 'tok_abcdef1234567890'
                });

                assert.ok(Buffer.byteLength(longReqPayload) > 32);
                assert.ok(Buffer.byteLength(longResPayload) > 32);

                const req6 = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/wire-test?hl=en',
                    headersArray: [
                        { name: 'Host', value: 'accounts.google.com' },
                        { name: 'Content-Type', value: 'application/json' },
                        { name: 'X-Custom-Order', value: 'first-before-tls' }
                    ],
                    postData: longReqPayload
                });
                const res6 = createMockResponse({
                    request: req6,
                    status: 200,
                    statusText: 'OK',
                    headersArray: [
                        { name: 'Content-Type', value: 'application/json; charset=utf-8' },
                        { name: 'X-Frame-Options', value: 'DENY' }
                    ],
                    body: longResPayload
                });

                await emitHttpTransaction(truncContext, req6, res6);
                await profileTrunc.getTrafficAttribution();

                // Verify pre-tls-wire.log exists and contains canonical egress & ingress frames
                const wireLogPath = profileTrunc.trafficPaths.preTlsWireLogPath;
                assert.equal(fs.existsSync(wireLogPath), true, 'Expected pre-tls-wire.log to exist');
                const wireLogContent = fs.readFileSync(wireLogPath, 'utf8');
                assert.equal(
                    wireLogContent.includes('>>> EGRESS [PRE-TLS NECKO CHANNEL]'),
                    true,
                    'Expected pre-tls-wire.log to contain >>> EGRESS [PRE-TLS NECKO CHANNEL]'
                );
                assert.equal(
                    wireLogContent.includes('<<< INGRESS [POST-TLS NECKO CHANNEL]'),
                    true,
                    'Expected pre-tls-wire.log to contain <<< INGRESS [POST-TLS NECKO CHANNEL]'
                );
                assert.equal(wireLogContent.includes('POST /v3/signin/wire-test?hl=en HTTP/1.1'), true);
                assert.equal(wireLogContent.includes('X-Custom-Order: first-before-tls'), true);
                assert.equal(wireLogContent.includes('HTTP/1.1 200 OK'), true);

                // Verify recorder.formatTransactionWireDump(corrId)
                const truncEvents = readNdjsonFile(profileTrunc.trafficPaths.trafficNdjsonPath);
                const egress6 = truncEvents.find((e) => e.type === 'egress');
                const ingress6 = truncEvents.find((e) => e.type === 'ingress');
                assert.ok(egress6 && ingress6);

                const recorder6 = profileTrunc.getTrafficRecorder();
                const wireDump6 = recorder6.formatTransactionWireDump(egress6.correlationId);
                assert.equal(wireDump6.includes('>>> EGRESS [PRE-TLS NECKO CHANNEL]'), true);
                assert.equal(wireDump6.includes('<<< INGRESS [POST-TLS NECKO CHANNEL]'), true);
                assert.equal(wireDump6.includes(egress6.correlationId), true);
                assert.equal(wireDump6.includes(longReqPayload), true);
                assert.equal(wireDump6.includes(longResPayload), true);

                // Verify maxBodyBytes: 32 truncation on disk with payloadTruncated: true
                assert.equal(egress6.payloadTruncated, true);
                assert.equal(ingress6.payloadTruncated, true);
                assert.equal(egress6.postDataSha256, sha256Hex(longReqPayload));
                assert.equal(ingress6.bodySha256, sha256Hex(longResPayload));

                const req6DiskPath = path.join(profileTrunc.trafficPaths.trafficDir, egress6.payloadFile);
                const res6DiskPath = path.join(profileTrunc.trafficPaths.trafficDir, ingress6.payloadFile);
                assert.equal(fs.readFileSync(req6DiskPath).byteLength, 32);
                assert.equal(fs.readFileSync(res6DiskPath).byteLength, 32);
                assert.equal(
                    fs.readFileSync(req6DiskPath, 'utf8'),
                    Buffer.from(longReqPayload, 'utf8').subarray(0, 32).toString('utf8')
                );
                assert.equal(
                    fs.readFileSync(res6DiskPath, 'utf8'),
                    Buffer.from(longResPayload, 'utf8').subarray(0, 32).toString('utf8')
                );

                await profileTrunc.delete();

                // Part B: recordBodies: false suppresses writing files to payloads/
                const profileNoBodies = await createAndStartProfile(
                    'Traffic_Test_6_NoBodies',
                    null,
                    {
                        profileId: 'traffic-test-6-nobodies',
                        os: 'linux',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        recordBodies: false
                    }
                );

                const noBodiesContext = await profileNoBodies.getContext();
                const reqNoBody = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/no-body-persist',
                    postData: JSON.stringify({ secret: 'do_not_write_payload_file' })
                });
                const resNoBody = createMockResponse({
                    request: reqNoBody,
                    status: 200,
                    body: JSON.stringify({ ok: true })
                });

                await emitHttpTransaction(noBodiesContext, reqNoBody, resNoBody);
                await profileNoBodies.getTrafficAttribution();

                const payloadFiles = fs.readdirSync(profileNoBodies.trafficPaths.payloadsDir);
                assert.equal(
                    payloadFiles.length,
                    0,
                    'Expected payloads/ directory to remain empty when recordBodies: false'
                );

                const noBodyEvents = readNdjsonFile(profileNoBodies.trafficPaths.trafficNdjsonPath);
                const noBodyEgress = noBodyEvents.find((e) => e.type === 'egress');
                const noBodyIngress = noBodyEvents.find((e) => e.type === 'ingress');
                assert.equal(noBodyEgress.payloadFile, null);
                assert.equal(noBodyIngress.payloadFile, null);

                await profileNoBodies.delete();
            }
        );

        // =========================================================================
        // Test 7: Automatic Causal UI Action Attribution (triggerAction) & detectGmailPage Auto-Step Tagging
        // =========================================================================
        await testSection(
            'Test 7: Automatic Causal UI Action Attribution (triggerAction) & detectGmailPage Auto-Step Tagging',
            async () => {
                const profile = await createAndStartProfile(
                    'Traffic_Test_7_Causal',
                    'http://10.77.0.1:8080',
                    {
                        profileId: 'traffic-test-7-causal',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false
                    }
                );

                const page = await profile.getPage();
                const context = await profile.getContext();

                // 1) Navigate to /steps/signup/name and run detectGmailPage(page)
                await page.goto('https://accounts.google.com/lifecycle/steps/signup/name');
                const detectedSignup = await detectGmailPage(page);
                assert.equal(detectedSignup.type, 'SIGN_UP_FORM');
                assert.equal(
                    profile.getTrafficRecorder().getAttributionSnapshot().actionStep,
                    'gmail-page:sign_up_form'
                );

                // Perform UI fill action before emitting request
                await page.fill('input[name="firstName"]', 'Alice');

                const nameReq = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/lifecycle/steps/signup/name?hl=en',
                    postData: JSON.stringify({ firstName: 'Alice', lastName: 'Smith' })
                });
                const nameRes = createMockResponse({
                    request: nameReq,
                    status: 200,
                    body: JSON.stringify({ step: 'name_accepted' })
                });
                await emitHttpTransaction(context, nameReq, nameRes);

                // 2) Navigate to /challenge/phone and run detectGmailPage(page)
                await page.goto('https://accounts.google.com/v3/signin/challenge/phone');
                const detectedChallenge = await detectGmailPage(page);
                assert.equal(detectedChallenge.type, 'VERIFICATION_CODE');
                assert.equal(
                    profile.getTrafficRecorder().getAttributionSnapshot().actionStep,
                    'gmail-page:verification_code'
                );

                // Perform UI click action on #next-button before emitting challenge request
                await page.click('#next-button');

                const phoneReq = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/challenge/phone?flow=signup',
                    postData: JSON.stringify({ code: '123456' })
                });
                const phoneRes = createMockResponse({
                    request: phoneReq,
                    status: 429,
                    statusText: 'Too Many Requests',
                    body: JSON.stringify({ error: 'RATE_LIMIT_EXCEEDED' })
                });
                await emitHttpTransaction(context, phoneReq, phoneRes);

                const summary = await profile.getTrafficAttribution();
                const events = readNdjsonFile(profile.trafficPaths.trafficNdjsonPath);

                const egressEvents = events.filter((e) => e.type === 'egress');
                const ingressEvents = events.filter((e) => e.type === 'ingress');
                assert.equal(egressEvents.length, 2);
                assert.equal(ingressEvents.length, 2);

                // Verify first transaction (after detectGmailPage on /steps/signup/name + page.fill)
                const [egressName, egressPhone] = egressEvents;
                const [ingressName, ingressPhone] = ingressEvents;

                assert.equal(egressName.attribution.actionStep, 'gmail-page:sign_up_form');
                assert.equal(ingressName.attribution.actionStep, 'gmail-page:sign_up_form');
                assert.ok(egressName.triggerAction);
                assert.equal(egressName.triggerAction.actionType, 'page.fill');
                assert.equal(egressName.triggerAction.target, 'input[name="firstName"]');
                assert.equal(typeof egressName.triggerAction.elapsedSinceActionMs, 'number');
                assert.ok(egressName.triggerAction.elapsedSinceActionMs >= 0);

                // Verify second transaction (after detectGmailPage on /challenge/phone + page.click('#next-button'))
                assert.equal(egressPhone.attribution.actionStep, 'gmail-page:verification_code');
                assert.equal(ingressPhone.attribution.actionStep, 'gmail-page:verification_code');
                assert.ok(egressPhone.triggerAction);
                assert.equal(egressPhone.triggerAction.actionType, 'page.click');
                assert.equal(egressPhone.triggerAction.target, '#next-button');
                assert.ok(egressPhone.triggerAction.elapsedSinceActionMs >= 0);
                assert.ok(ingressPhone.triggerAction);
                assert.equal(ingressPhone.triggerAction.actionType, 'page.click');
                assert.equal(ingressPhone.triggerAction.target, '#next-button');
                assert.ok(ingressPhone.triggerAction.elapsedSinceActionMs >= 0);

                // Verify anomaliesAndRiskSignals include triggerAction
                const phoneAnomaly = summary.anomaliesAndRiskSignals.find(
                    (a) => a.type === 'http-429-rate-limit'
                );
                assert.ok(phoneAnomaly, 'Expected http-429-rate-limit anomaly');
                assert.equal(phoneAnomaly.actionStep, 'gmail-page:verification_code');
                assert.ok(phoneAnomaly.triggerAction);
                assert.equal(phoneAnomaly.triggerAction.actionType, 'page.click');
                assert.equal(phoneAnomaly.triggerAction.target, '#next-button');
                assert.ok(phoneAnomaly.triggerAction.elapsedSinceActionMs >= 0);

                // Verify byTriggerAction in attribution-index.json
                const triggerEntries = Object.values(summary.byTriggerAction || {});
                assert.ok(triggerEntries.length >= 2, 'Expected byTriggerAction entries in summary');

                const clickTriggerStats = triggerEntries.find(
                    (t) => t.actionType === 'page.click' && t.target === '#next-button'
                );
                assert.ok(clickTriggerStats, 'Expected byTriggerAction entry for page.click #next-button');
                assert.equal(clickTriggerStats.requests, 1);
                assert.equal(clickTriggerStats.responses, 1);
                assert.equal(clickTriggerStats.statusCounts['429'], 1);
                assert.ok(clickTriggerStats.anomalyCount >= 1);

                const fillTriggerStats = triggerEntries.find(
                    (t) => t.actionType === 'page.fill' && t.target === 'input[name="firstName"]'
                );
                assert.ok(fillTriggerStats, 'Expected byTriggerAction entry for page.fill firstName');
                assert.equal(fillTriggerStats.requests, 1);
                assert.equal(fillTriggerStats.responses, 1);
                assert.equal(fillTriggerStats.statusCounts['200'], 1);

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 8: Offline Query & Wire-Dump CLI (scripts/query-traffic-attribution.js) + Shared-Browser SSLKEYLOGFILE & MOZ_LOG
        // =========================================================================
        await testSection(
            'Test 8: Offline Query & Wire-Dump CLI (scripts/query-traffic-attribution.js) + Shared-Browser SSLKEYLOGFILE & MOZ_LOG',
            async () => {
                // 1) Verify neckoMozLog: true injects MOZ_LOG and MOZ_LOG_FILE into browser launch env
                const mozLogProfile = await createAndStartProfile(
                    'Traffic_Test_8_MozLog',
                    null,
                    {
                        profileId: 'traffic-test-8-mozlog',
                        os: 'linux',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        neckoMozLog: true
                    }
                );

                const mozEnv = mozLogProfile.browser.launchOptions.env;
                assert.ok(mozEnv && mozEnv.MOZ_LOG, 'Expected MOZ_LOG in launch env');
                assert.equal(mozEnv.MOZ_LOG.includes('nsHttp:5'), true);
                assert.equal(mozEnv.MOZ_LOG_FILE, mozLogProfile.trafficPaths.neckoMozLogPath);
                await mozLogProfile.delete();

                // 2) Verify shared-browser mode syncs _shared_sslkeylog.txt into per-profile sslkeylog.txt
                await closeSharedBrowser();
                const sharedProfile = await createAndStartProfile(
                    'Traffic_Test_8_Shared',
                    'http://10.88.0.1:8080',
                    {
                        profileId: 'traffic-test-8-shared',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: true,
                        accountId: 'acct-cli-888',
                        accountEmail: 'cli.audit888@gmail.com'
                    }
                );

                const sharedKeyLogPath = path.join(tempProfilesDir, '_shared_sslkeylog.txt');
                assert.equal(sharedProfile.browser._sharedSslKeyLogPath, sharedKeyLogPath);
                assert.equal(fs.existsSync(sharedKeyLogPath), true);

                // Simulate NSS writing a TLS 1.3 secret line into _shared_sslkeylog.txt
                const mockTlsSecretLine =
                    'CLIENT_HANDSHAKE_TRAFFIC_SECRET 0123456789abcdef0123456789abcdef aabbccddeeff00112233445566778899';
                fs.appendFileSync(sharedKeyLogPath, `${mockTlsSecretLine}\n`, 'utf8');

                const page = await sharedProfile.getPage();
                const context = await sharedProfile.getContext();

                sharedProfile.setTrafficStep('step-8-cli-audit');
                await page.click('#submit-audit-btn');

                const reqPayload8 = JSON.stringify({
                    username: 'cli.audit888',
                    challengeToken: 'tok_cli_wire_888'
                });
                const resPayload8 = JSON.stringify({
                    error: 'ARKOSE_CHALLENGE_REQUIRED',
                    code: 429
                });

                const req8 = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/challenge/arkose?hl=en',
                    headersArray: [
                        { name: 'Host', value: 'accounts.google.com' },
                        { name: 'Content-Type', value: 'application/json' },
                        { name: 'X-Audit-Header', value: 'pre-tls-verified' }
                    ],
                    postData: reqPayload8
                });
                const res8 = createMockResponse({
                    request: req8,
                    status: 429,
                    statusText: 'Too Many Requests',
                    headersArray: [
                        { name: 'Content-Type', value: 'application/json' },
                        { name: 'Retry-After', value: '30' }
                    ],
                    body: resPayload8
                });

                await emitHttpTransaction(context, req8, res8);

                // Stop profile (triggers syncSharedSslKeyLog + flushes attribution-index.json)
                await sharedProfile.stop();

                const profileSslKeyLogContent = fs.readFileSync(
                    sharedProfile.trafficPaths.sslKeyLogPath,
                    'utf8'
                );
                assert.equal(
                    profileSslKeyLogContent.includes(mockTlsSecretLine),
                    true,
                    'Expected shared _shared_sslkeylog.txt secrets to sync into per-profile sslkeylog.txt'
                );

                // 3) Verify programmatic queryProfileTraffic()
                const listResult = queryProfileTraffic({ profilesDir: tempProfilesDir });
                assert.equal(listResult.mode, 'list-profiles');
                assert.ok(listResult.profiles.some((p) => p.profileId === 'traffic-test-8-shared'));

                const anomaliesResult = queryProfileTraffic({
                    profilesDir: tempProfilesDir,
                    profile: 'traffic-test-8-shared',
                    anomaliesOnly: true
                });
                assert.equal(anomaliesResult.mode, 'anomalies');
                assert.ok(anomaliesResult.anomalies.length >= 1);
                const targetCorrId = anomaliesResult.anomalies[0].correlationId;
                assert.ok(targetCorrId && targetCorrId.startsWith('corr-'));

                const stepFilterResult = queryProfileTraffic({
                    profilesDir: tempProfilesDir,
                    profile: 'traffic-test-8-shared',
                    step: 'step-8-cli-audit',
                    trigger: '#submit-audit-btn',
                    domain: 'accounts.google.com',
                    status: '4xx'
                });
                assert.equal(stepFilterResult.transactions.length, 1);
                assert.equal(stepFilterResult.transactions[0].correlationId, targetCorrId);

                const wireResult = queryProfileTraffic({
                    profilesDir: tempProfilesDir,
                    profile: 'traffic-test-8-shared',
                    dumpWire: targetCorrId
                });
                assert.equal(wireResult.mode, 'wire-dump');
                assert.equal(wireResult.found, true);
                assert.equal(wireResult.correlationId, targetCorrId);
                assert.equal(wireResult.actionStep, 'step-8-cli-audit');
                assert.equal(wireResult.triggerAction.actionType, 'page.click');
                assert.equal(wireResult.triggerAction.target, '#submit-audit-btn');
                assert.equal(wireResult.requestPayload, reqPayload8);
                assert.equal(wireResult.responsePayload, resPayload8);
                assert.equal(wireResult.wireDump.includes('>>> EGRESS [PRE-TLS NECKO CHANNEL]'), true);
                assert.equal(wireResult.wireDump.includes('<<< INGRESS [POST-TLS NECKO CHANNEL]'), true);

                // 4) Spawn scripts/query-traffic-attribution.js CLI with --anomalies-only, --dump-wire, and --json
                const cliScriptPath = path.join(__dirname, 'query-traffic-attribution.js');

                const cliAnomaliesRaw = execFileSync(
                    process.execPath,
                    [
                        cliScriptPath,
                        `--profiles-dir=${tempProfilesDir}`,
                        '--profile=traffic-test-8-shared',
                        '--anomalies-only',
                        '--json'
                    ],
                    { encoding: 'utf8' }
                );
                const cliAnomaliesJson = JSON.parse(cliAnomaliesRaw);
                assert.equal(cliAnomaliesJson.mode, 'anomalies');
                assert.equal(cliAnomaliesJson.profileId, 'traffic-test-8-shared');
                assert.ok(cliAnomaliesJson.anomalies.some((a) => a.correlationId === targetCorrId));

                const cliWireJsonRaw = execFileSync(
                    process.execPath,
                    [
                        cliScriptPath,
                        `--profiles-dir=${tempProfilesDir}`,
                        `--dump-wire=${targetCorrId}`,
                        '--json'
                    ],
                    { encoding: 'utf8' }
                );
                const cliWireJson = JSON.parse(cliWireJsonRaw);
                assert.equal(cliWireJson.mode, 'wire-dump');
                assert.equal(cliWireJson.correlationId, targetCorrId);
                assert.equal(cliWireJson.requestPayload, reqPayload8);
                assert.equal(cliWireJson.responsePayload, resPayload8);

                const cliWireTextRaw = execFileSync(
                    process.execPath,
                    [
                        cliScriptPath,
                        `--profiles-dir=${tempProfilesDir}`,
                        '--profile=traffic-test-8-shared',
                        `--dump-wire=${targetCorrId}`
                    ],
                    { encoding: 'utf8' }
                );
                assert.equal(cliWireTextRaw.includes('>>> EGRESS [PRE-TLS NECKO CHANNEL]'), true);
                assert.equal(cliWireTextRaw.includes('<<< INGRESS [POST-TLS NECKO CHANNEL]'), true);
                assert.equal(cliWireTextRaw.includes('X-Audit-Header: pre-tls-verified'), true);
                assert.equal(cliWireTextRaw.includes(reqPayload8), true);
                assert.equal(cliWireTextRaw.includes(resPayload8), true);

                await sharedProfile.delete();
                await closeSharedBrowser();
            }
        );

        // =========================================================================
        // Test 9: Tamper-Evident SHA-256 Hash Chain, Payload Integrity Verification & Proxy-Authorization Redaction
        // =========================================================================
        await testSection(
            'Test 9: Tamper-Evident SHA-256 Hash Chain, Payload Integrity Verification & Proxy-Authorization Redaction',
            async () => {
                const profile = await createAndStartProfile(
                    'Traffic_Test_9_Integrity',
                    'http://10.99.0.1:8080:proxyUser9:proxySecret9',
                    {
                        profileId: 'traffic-test-9-integrity',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        accountId: 'acct-integrity-9',
                        accountEmail: 'integrity9@gmail.com'
                    }
                );

                const page = await profile.getPage();
                const context = await profile.getContext();

                profile.setTrafficStep('step-9-authenticated-submit');
                await page.click('#secure-submit');

                const proxySecretBase64 = 'dXNlcjpzZWNyZXQ=';
                const thirdPartyApiKey = 'omo_live_secret_api_key_99999';
                const reqBody9 = JSON.stringify({
                    email: 'integrity9@gmail.com',
                    action: 'verify_chain'
                });
                const resBody9 = JSON.stringify({
                    status: 'VERIFIED_OK',
                    step: 'step-9-authenticated-submit'
                });

                const req9 = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/challenge/verify?hl=en',
                    headersArray: [
                        { name: 'Host', value: 'accounts.google.com' },
                        { name: 'Proxy-Authorization', value: `Basic ${proxySecretBase64}` },
                        { name: 'X-Proxy-Authorization', value: `Bearer ${proxySecretBase64}` },
                        { name: 'X-Api-Key', value: thirdPartyApiKey },
                        { name: 'Omocaptcha-Key', value: thirdPartyApiKey },
                        { name: 'Content-Type', value: 'application/json' }
                    ],
                    postData: reqBody9
                });

                const res9 = createMockResponse({
                    request: req9,
                    status: 200,
                    statusText: 'OK',
                    headersArray: [
                        { name: 'Content-Type', value: 'application/json; charset=utf-8' },
                        { name: 'X-Frame-Options', value: 'SAMEORIGIN' }
                    ],
                    body: resBody9
                });

                await emitHttpTransaction(context, req9, res9);
                await profile.stop();
                const summary = JSON.parse(
                    fs.readFileSync(profile.trafficPaths.attributionIndexPath, 'utf8')
                );

                const trafficDir = profile.trafficPaths.trafficDir;
                const ndjsonPath = profile.trafficPaths.trafficNdjsonPath;
                const wireLogPath = profile.trafficPaths.preTlsWireLogPath;

                const ndjsonRaw = fs.readFileSync(ndjsonPath, 'utf8');
                const wireLogRaw = fs.readFileSync(wireLogPath, 'utf8');

                // 1) Verify Proxy-Authorization and third-party API keys are redacted in both traffic.ndjson and pre-tls-wire.log
                assert.equal(
                    ndjsonRaw.includes(proxySecretBase64),
                    false,
                    'Proxy-Authorization credentials must never leak into traffic.ndjson'
                );
                assert.equal(
                    wireLogRaw.includes(proxySecretBase64),
                    false,
                    'Proxy-Authorization credentials must never leak into pre-tls-wire.log'
                );
                assert.equal(
                    ndjsonRaw.includes(thirdPartyApiKey),
                    false,
                    'Third-party API keys must never leak into traffic.ndjson'
                );
                assert.equal(
                    wireLogRaw.includes(thirdPartyApiKey),
                    false,
                    'Third-party API keys must never leak into pre-tls-wire.log'
                );
                assert.equal(
                    wireLogRaw.includes('Proxy-Authorization: Basic [REDACTED]'),
                    true,
                    'Expected pre-tls-wire.log to show Proxy-Authorization: Basic [REDACTED]'
                );

                const events = readNdjsonFile(ndjsonPath);
                const egress9 = events.find((e) => e.type === 'egress');
                assert.ok(egress9, 'Expected egress event in traffic.ndjson');
                assert.equal(egress9.headers['proxy-authorization'], 'Basic [REDACTED]');
                assert.equal(egress9.headers['x-proxy-authorization'], 'Bearer [REDACTED]');
                assert.equal(egress9.headers['x-api-key'], '[REDACTED]');
                assert.equal(egress9.headers['omocaptcha-key'], '[REDACTED]');
                const proxyAuthArrEntry = egress9.headersArray.find(
                    (h) => h.name === 'Proxy-Authorization'
                );
                assert.ok(proxyAuthArrEntry);
                assert.equal(proxyAuthArrEntry.value, 'Basic [REDACTED]');

                // 2) Verify SHA-256 hash chain structure in traffic.ndjson and summary.integrity
                assert.ok(summary.integrity, 'Expected integrity section in attribution-index.json');
                assert.equal(summary.integrity.algorithm, 'sha256-chain');
                assert.equal(summary.integrity.genesisHash, '0'.repeat(64));
                assert.equal(summary.integrity.eventCount, events.length);
                assert.equal(summary.integrity.payloadCount, 2);

                let expectedPrevHash = '0'.repeat(64);
                for (const ev of events) {
                    assert.equal(ev.prevEventHash, expectedPrevHash);
                    assert.equal(typeof ev.eventHash, 'string');
                    assert.equal(ev.eventHash.length, 64);
                    expectedPrevHash = ev.eventHash;
                }
                assert.equal(summary.integrity.chainHeadHash, expectedPrevHash);

                // 3) Verify verifyTrafficIntegrity(trafficDir) and CLI --verify-integrity pass on untampered data
                const validCheck = verifyTrafficIntegrity(trafficDir);
                assert.equal(validCheck.valid, true, `Expected valid integrity, got errors: ${validCheck.errors.join('; ')}`);
                assert.equal(validCheck.eventCount, events.length);
                assert.equal(validCheck.verifiedPayloads, 2);
                assert.equal(validCheck.chainHeadHash, summary.integrity.chainHeadHash);
                assert.equal(validCheck.errors.length, 0);

                const queryCheck = queryProfileTraffic({
                    profilesDir: tempProfilesDir,
                    profile: 'traffic-test-9-integrity',
                    verifyIntegrity: true
                });
                assert.equal(queryCheck.mode, 'verify-integrity');
                assert.equal(queryCheck.valid, true);
                assert.equal(queryCheck.verifiedPayloads, 2);

                const cliScriptPath = path.join(__dirname, 'query-traffic-attribution.js');
                const cliValidOut = execFileSync(
                    process.execPath,
                    [
                        cliScriptPath,
                        `--profiles-dir=${tempProfilesDir}`,
                        '--profile=traffic-test-9-integrity',
                        '--verify-integrity',
                        '--json'
                    ],
                    { encoding: 'utf8' }
                );
                const cliValidJson = JSON.parse(cliValidOut);
                assert.equal(cliValidJson.valid, true);
                assert.equal(cliValidJson.verifiedPayloads, 2);

                // 4) Tamper with 1 byte in a payload file and verify detection
                const payloadRelPath = egress9.payloadFile;
                const payloadFullPath = path.join(trafficDir, payloadRelPath);
                const originalPayloadBuf = fs.readFileSync(payloadFullPath);
                const tamperedPayloadBuf = Buffer.from(originalPayloadBuf);
                tamperedPayloadBuf[0] = tamperedPayloadBuf[0] ^ 0xff;
                fs.writeFileSync(payloadFullPath, tamperedPayloadBuf);

                const payloadTamperCheck = verifyTrafficIntegrity(trafficDir);
                assert.equal(payloadTamperCheck.valid, false);
                assert.ok(payloadTamperCheck.errors.length >= 1);
                assert.equal(
                    payloadTamperCheck.errors.some((e) => e.includes('Payload SHA-256 mismatch')),
                    true
                );

                // Verify CLI --verify-integrity exits with non-zero code (1) on payload tampering
                let cliPayloadExitCode = 0;
                try {
                    execFileSync(
                        process.execPath,
                        [
                            cliScriptPath,
                            `--profiles-dir=${tempProfilesDir}`,
                            '--profile=traffic-test-9-integrity',
                            '--verify-integrity',
                            '--json'
                        ],
                        { encoding: 'utf8', stdio: 'pipe' }
                    );
                } catch (err) {
                    cliPayloadExitCode = err.status;
                    const errJson = JSON.parse(err.stdout);
                    assert.equal(errJson.valid, false);
                    assert.ok(errJson.errors.length >= 1);
                }
                assert.equal(cliPayloadExitCode, 1, 'Expected CLI --verify-integrity to exit with code 1 on payload tampering');

                // Restore payload file and verify integrity is valid again
                fs.writeFileSync(payloadFullPath, originalPayloadBuf);
                assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);

                // 5) Tamper with 1 field in traffic.ndjson and verify hash-chain detection
                const tamperedEvents = events.map((ev, idx) =>
                    idx === 0 ? { ...ev, actionStep: 'tampered-step-name' } : ev
                );
                fs.writeFileSync(
                    ndjsonPath,
                    `${tamperedEvents.map((e) => JSON.stringify(e)).join('\n')}\n`,
                    'utf8'
                );

                const chainTamperCheck = verifyTrafficIntegrity(trafficDir);
                assert.equal(chainTamperCheck.valid, false);
                assert.ok(chainTamperCheck.errors.length >= 1);
                assert.equal(
                    chainTamperCheck.errors.some((e) => e.includes('eventHash mismatch')),
                    true
                );

                let cliChainExitCode = 0;
                try {
                    execFileSync(
                        process.execPath,
                        [
                            cliScriptPath,
                            `--profiles-dir=${tempProfilesDir}`,
                            '--profile=traffic-test-9-integrity',
                            '--verify-integrity'
                        ],
                        { encoding: 'utf8', stdio: 'pipe' }
                    );
                } catch (err) {
                    cliChainExitCode = err.status;
                    assert.equal(err.stdout.includes('INVALID'), true);
                }
                assert.equal(cliChainExitCode, 1, 'Expected CLI --verify-integrity to exit with code 1 on NDJSON tampering');

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 10: Pre-TLS Wire Header Anomalies (Sec-CH-UA, Wire UA OS Mismatch, Proxy Leak), NSS sslkeylog.txt Integrity & Crash Self-Healing
        // =========================================================================
        await testSection(
            'Test 10: Pre-TLS Wire Header Anomalies (Sec-CH-UA, Wire UA OS Mismatch, Proxy Leak), NSS sslkeylog.txt Integrity & Crash Self-Healing',
            async () => {
                const profile = await createAndStartProfile(
                    'Traffic_Test_10_WireAnomalies',
                    'http://10.101.0.1:8080:proxyUser10:proxyPass10',
                    {
                        profileId: 'traffic-test-10-wire-anomalies',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        accountId: 'acct-wire-10',
                        accountEmail: 'wire10@gmail.com'
                    }
                );

                const context = await profile.getContext();
                const recorder = profile.getTrafficRecorder();
                const trafficDir = profile.trafficPaths.trafficDir;
                const ndjsonPath = profile.trafficPaths.trafficNdjsonPath;
                const sslKeyLogPath = profile.trafficPaths.sslKeyLogPath;

                profile.setTrafficStep('step-10-wire-header-inspection');

                // 1) Emit an egress request on a Windows Firefox profile carrying Chromium Sec-CH-UA,
                //    a mismatched macOS User-Agent, and an X-Forwarded-For proxy leak header
                const anomalousReq = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/lookup?hl=en',
                    headersArray: [
                        { name: 'Host', value: 'accounts.google.com' },
                        {
                            name: 'User-Agent',
                            value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0'
                        },
                        {
                            name: 'Sec-CH-UA',
                            value: '"Chromium";v="135", "Not-A.Brand";v="8"'
                        },
                        {
                            name: 'X-Forwarded-For',
                            value: '10.0.0.5'
                        },
                        { name: 'Content-Type', value: 'application/json' }
                    ],
                    postData: JSON.stringify({ identifier: 'wire10@gmail.com' })
                });

                const anomalousRes = createMockResponse({
                    request: anomalousReq,
                    status: 200,
                    statusText: 'OK',
                    headersArray: [{ name: 'Content-Type', value: 'application/json' }],
                    body: JSON.stringify({ status: 'OK' })
                });

                await emitHttpTransaction(context, anomalousReq, anomalousRes);

                // 2) Record valid NSS TLS 1.3 secrets via recordSslKeyLogSecret
                const clientRandomHex =
                    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
                const tls13Secrets = [
                    [
                        'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
                        'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90'
                    ],
                    [
                        'SERVER_HANDSHAKE_TRAFFIC_SECRET',
                        'b1c2d3e4f5061728394a5b6c7d8e9f01b1c2d3e4f5061728394a5b6c7d8e9f01'
                    ],
                    [
                        'CLIENT_TRAFFIC_SECRET_0',
                        'c1d2e3f405162738495a6b7c8d9e0f12c1d2e3f405162738495a6b7c8d9e0f12'
                    ],
                    [
                        'SERVER_TRAFFIC_SECRET_0',
                        'd1e2f30415263748596a7b8c9d0e1f23d1e2f30415263748596a7b8c9d0e1f23'
                    ]
                ];

                assert.equal(
                    typeof recorder.recordSslKeyLogSecret,
                    'function',
                    'Expected recorder.recordSslKeyLogSecret to be a function'
                );
                for (const [label, secretHex] of tls13Secrets) {
                    if (recorder.recordSslKeyLogSecret.length >= 2) {
                        recorder.recordSslKeyLogSecret(label, clientRandomHex, secretHex);
                    } else {
                        recorder.recordSslKeyLogSecret(
                            `${label} ${clientRandomHex} ${secretHex}`,
                            clientRandomHex,
                            secretHex
                        );
                    }
                }

                const summary = await profile.getTrafficAttribution();
                const anomalyTypes = summary.anomaliesAndRiskSignals.map((a) => a.type);

                assert.equal(
                    anomalyTypes.includes('wire-header-anomaly:chromium-client-hints-on-gecko'),
                    true,
                    `Expected wire-header-anomaly:chromium-client-hints-on-gecko in [${anomalyTypes.join(', ')}]`
                );
                assert.equal(
                    anomalyTypes.includes('wire-header-anomaly:ua-os-mismatch'),
                    true,
                    `Expected wire-header-anomaly:ua-os-mismatch in [${anomalyTypes.join(', ')}]`
                );
                assert.equal(
                    anomalyTypes.includes('proxy-anonymity-leak'),
                    true,
                    `Expected proxy-anonymity-leak in [${anomalyTypes.join(', ')}]`
                );

                // Verify NSS sslKeyLog summary metrics and cryptographic integrity
                assert.ok(summary.sslKeyLog, 'Expected summary.sslKeyLog block');
                assert.ok(
                    summary.sslKeyLog.tls13SessionCount >= 1,
                    `Expected summary.sslKeyLog.tls13SessionCount >= 1, got ${summary.sslKeyLog.tls13SessionCount}`
                );

                const integrityValid = verifyTrafficIntegrity(trafficDir);
                assert.equal(
                    integrityValid.valid,
                    true,
                    `Expected valid integrity after recording TLS 1.3 secrets, got errors: ${integrityValid.errors.join('; ')}`
                );

                // Tamper with sslkeylog.txt and assert verifyTrafficIntegrity detects it
                const originalSslKeyLog = fs.readFileSync(sslKeyLogPath, 'utf8');
                fs.writeFileSync(
                    sslKeyLogPath,
                    `${originalSslKeyLog}CLIENT_TRAFFIC_SECRET_0 ${clientRandomHex} ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n`,
                    'utf8'
                );
                const tamperedSslIntegrity = verifyTrafficIntegrity(trafficDir);
                assert.equal(
                    tamperedSslIntegrity.valid,
                    false,
                    'Expected verifyTrafficIntegrity(trafficDir).valid === false after tampering with sslkeylog.txt'
                );

                // Restore sslkeylog.txt and stop profile
                fs.writeFileSync(sslKeyLogPath, originalSslKeyLog, 'utf8');
                await profile.stop();
                assert.equal(verifyTrafficIntegrity(trafficDir).valid, true);

                // 3) Simulate a crashed partial trailing line in traffic.ndjson and verify self-healing on resume
                const preCrashIntegrity = verifyTrafficIntegrity(trafficDir);
                assert.equal(preCrashIntegrity.valid, true);

                fs.appendFileSync(ndjsonPath, '{"type":"egress","corrupted":', 'utf8');
                const healedRecorder = new CamoufoxTrafficRecorder({
                    profileId: 'traffic-test-10-wire-anomalies',
                    trafficDir,
                    sslKeyLogPath,
                    os: 'windows'
                });
                await healedRecorder.flushSummary();

                const rawNdjsonAfterHeal = fs.readFileSync(ndjsonPath, 'utf8');
                assert.equal(
                    rawNdjsonAfterHeal.includes('"corrupted"'),
                    false,
                    'Expected _resumeExistingChainIfPresent() to truncate corrupted partial trailing NDJSON line'
                );

                const postHealIntegrity = verifyTrafficIntegrity(trafficDir);
                assert.equal(
                    postHealIntegrity.valid,
                    true,
                    `Expected valid integrity after crash self-healing, got errors: ${postHealIntegrity.errors.join('; ')}`
                );
                assert.equal(postHealIntegrity.eventCount, preCrashIntegrity.eventCount);

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 11: W3C HAR 1.2 Export (recorder.exportHar() & query-traffic-attribution.js --export-har)
        // =========================================================================
        await testSection(
            'Test 11: W3C HAR 1.2 Export (recorder.exportHar() & query-traffic-attribution.js --export-har)',
            async () => {
                const profile = await createAndStartProfile(
                    'Traffic_Test_11_Har',
                    'http://10.102.0.1:8080',
                    {
                        profileId: 'traffic-test-11-har',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        accountId: 'acct-har-11',
                        accountEmail: 'har11@gmail.com'
                    }
                );

                const page = await profile.getPage();
                const context = await profile.getContext();
                const recorder = profile.getTrafficRecorder();
                const trafficDir = profile.trafficPaths.trafficDir;

                profile.setTrafficStep('step-11-har-export');
                await page.click('#har-submit-btn');

                const reqPostPayload = JSON.stringify({
                    username: 'har11@gmail.com',
                    flowName: 'GlifWebSignIn'
                });
                const resJsonPayload = JSON.stringify({
                    status: 'HAR_EXPORT_READY',
                    continuationToken: 'tok_har_11'
                });

                const req11 = createMockRequest({
                    method: 'POST',
                    url: 'https://accounts.google.com/v3/signin/identifier?hl=en&flowName=GlifWebSignIn',
                    resourceType: 'fetch',
                    headersArray: [
                        { name: 'Host', value: 'accounts.google.com' },
                        {
                            name: 'User-Agent',
                            value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0'
                        },
                        { name: 'Content-Type', value: 'application/json' },
                        { name: 'X-Har-Test', value: 'pre-tls-egress' }
                    ],
                    postData: reqPostPayload,
                    timing: { requestStart: 4.0, responseEnd: 46.5 }
                });

                const res11 = createMockResponse({
                    request: req11,
                    status: 200,
                    statusText: 'OK',
                    headersArray: [
                        { name: 'Content-Type', value: 'application/json; charset=utf-8' },
                        { name: 'X-Har-Response', value: 'post-tls-ingress' }
                    ],
                    body: resJsonPayload,
                    serverAddr: { ipAddress: '142.250.185.78', port: 443 },
                    securityDetails: {
                        protocol: 'TLS 1.3',
                        subjectName: 'accounts.google.com',
                        issuer: 'GTS CA 1C3'
                    }
                });

                await emitHttpTransaction(context, req11, res11);
                await profile.stop();

                // 1) Export HAR 1.2 directly via recorder.exportHar()
                assert.equal(
                    typeof recorder.exportHar,
                    'function',
                    'Expected recorder.exportHar to be a function'
                );
                const directHarPath = path.join(trafficDir, 'trace.har');
                await recorder.exportHar(directHarPath);
                assert.equal(
                    fs.existsSync(directHarPath),
                    true,
                    `Expected trace.har to exist at ${directHarPath}`
                );

                const directHar = JSON.parse(fs.readFileSync(directHarPath, 'utf8'));
                assert.ok(directHar && directHar.log, 'Expected top-level HAR log object');
                assert.equal(directHar.log.version, '1.2');
                assert.ok(directHar.log.creator && directHar.log.creator.name);
                assert.ok(
                    Array.isArray(directHar.log.entries) && directHar.log.entries.length >= 1,
                    'Expected at least 1 HAR entry'
                );

                const harEntry = directHar.log.entries.find((e) =>
                    e.request?.url?.includes('/v3/signin/identifier')
                );
                assert.ok(harEntry, 'Expected HAR entry for /v3/signin/identifier');
                assert.equal(harEntry.request.method, 'POST');
                assert.ok(
                    harEntry.request.headers.some(
                        (h) => h.name === 'X-Har-Test' && h.value === 'pre-tls-egress'
                    ),
                    'Expected HAR request headers to preserve X-Har-Test'
                );
                assert.ok(harEntry.request.postData, 'Expected HAR request.postData');
                assert.equal(harEntry.request.postData.text, reqPostPayload);

                assert.equal(harEntry.response.status, 200);
                assert.ok(
                    harEntry.response.headers.some(
                        (h) => h.name === 'X-Har-Response' && h.value === 'post-tls-ingress'
                    ),
                    'Expected HAR response headers to preserve X-Har-Response'
                );
                assert.ok(harEntry.response.content, 'Expected HAR response.content');
                assert.equal(harEntry.response.content.text, resJsonPayload);
                assert.ok(harEntry.timings && typeof harEntry.timings.wait === 'number');
                assert.ok(
                    harEntry._attribution,
                    'Expected HAR entry to include _attribution metadata'
                );
                assert.equal(harEntry._attribution.actionStep, 'step-11-har-export');

                // 2) Export HAR 1.2 via scripts/query-traffic-attribution.js --export-har
                const cliHarPath = path.join(trafficDir, 'cli-trace.har');
                const cliScriptPath = path.join(__dirname, 'query-traffic-attribution.js');
                execFileSync(
                    process.execPath,
                    [
                        cliScriptPath,
                        `--profiles-dir=${tempProfilesDir}`,
                        '--profile=traffic-test-11-har',
                        `--export-har=${cliHarPath}`
                    ],
                    { encoding: 'utf8' }
                );

                assert.equal(
                    fs.existsSync(cliHarPath),
                    true,
                    `Expected CLI --export-har to write ${cliHarPath}`
                );
                const cliHar = JSON.parse(fs.readFileSync(cliHarPath, 'utf8'));
                assert.equal(cliHar.log.version, '1.2');
                assert.ok(Array.isArray(cliHar.log.entries) && cliHar.log.entries.length >= 1);
                const cliHarEntry = cliHar.log.entries.find((e) =>
                    e.request?.url?.includes('/v3/signin/identifier')
                );
                assert.ok(cliHarEntry);
                assert.equal(cliHarEntry.request.postData.text, reqPostPayload);
                assert.equal(cliHarEntry.response.content.text, resJsonPayload);
                assert.ok(cliHarEntry._attribution);
                assert.equal(cliHarEntry._attribution.actionStep, 'step-11-har-export');

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 12: Cookie & Anti-Bot Token Causal Lineage (Set-Cookie -> Cookie Graph & --cookies / --cookie=<name> CLI)
        // =========================================================================
        await testSection(
            'Test 12: Cookie & Anti-Bot Token Causal Lineage (Set-Cookie -> Cookie Graph & --cookies / --cookie=<name> CLI)',
            async () => {
                const profile = await createAndStartProfile(
                    'Traffic_Test_12_Cookies',
                    'http://10.103.0.1:8080',
                    {
                        profileId: 'traffic-test-12-cookies',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        accountId: 'acct-cookies-12',
                        accountEmail: 'cookies12@gmail.com'
                    }
                );

                const context = await profile.getContext();
                const recorder = profile.getTrafficRecorder();

                // Step 1: step-1-landing -> ingress response returns multiple Set-Cookie headers
                profile.setTrafficStep('step-1-landing');
                const reqStep1 = createMockRequest({
                    method: 'GET',
                    url: 'https://www.tiktok.com/signup',
                    resourceType: 'document',
                    isNavigationRequest: true,
                    headersArray: [
                        { name: 'Host', value: 'www.tiktok.com' },
                        {
                            name: 'User-Agent',
                            value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0'
                        }
                    ]
                });
                const resStep1 = createMockResponse({
                    request: reqStep1,
                    status: 200,
                    statusText: 'OK',
                    headersArray: [
                        { name: 'Content-Type', value: 'text/html; charset=utf-8' },
                        {
                            name: 'Set-Cookie',
                            value: 'ttwid=1%7Cabc123xyz987secret; Domain=.tiktok.com; Path=/; Secure; HttpOnly'
                        },
                        {
                            name: 'Set-Cookie',
                            value: 'msToken=ms_initial_secret_token_111; Domain=.tiktok.com; Path=/; Secure; SameSite=None'
                        },
                        {
                            name: 'Set-Cookie',
                            value: '__cf_bm=cf_bot_mgmt_999; Domain=.tiktok.com; Path=/; Secure; HttpOnly'
                        }
                    ],
                    body: '<html><body>Landing</body></html>'
                });
                await emitHttpTransaction(context, reqStep1, resStep1);

                // Step 2: step-2-submit (after recordTriggerAction('page.click', '#submit-btn'))
                profile.setTrafficStep('step-2-submit');
                recorder.recordTriggerAction('page.click', '#submit-btn');

                const reqStep2 = createMockRequest({
                    method: 'POST',
                    url: 'https://www.tiktok.com/passport/web/account/create/',
                    resourceType: 'fetch',
                    headersArray: [
                        { name: 'Host', value: 'www.tiktok.com' },
                        {
                            name: 'User-Agent',
                            value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0'
                        },
                        {
                            name: 'Cookie',
                            value: 'ttwid=1%7Cabc123xyz987secret; msToken=ms_initial_secret_token_111; __cf_bm=cf_bot_mgmt_999'
                        },
                        { name: 'Content-Type', value: 'application/json' }
                    ],
                    postData: JSON.stringify({ email: 'cookies12@gmail.com' })
                });
                const resStep2 = createMockResponse({
                    request: reqStep2,
                    status: 200,
                    statusText: 'OK',
                    headersArray: [
                        { name: 'Content-Type', value: 'application/json' },
                        {
                            name: 'Set-Cookie',
                            value: 'msToken=ms_rotated_secret_token_222; Domain=.tiktok.com; Path=/; Secure'
                        }
                    ],
                    body: JSON.stringify({ message: 'success', next: 'verify' })
                });
                await emitHttpTransaction(context, reqStep2, resStep2);

                // Step 3: step-3-verify -> egress sends rotated msToken and original ttwid
                profile.setTrafficStep('step-3-verify');
                const reqStep3 = createMockRequest({
                    method: 'POST',
                    url: 'https://www.tiktok.com/passport/web/account/verify/',
                    resourceType: 'fetch',
                    headersArray: [
                        { name: 'Host', value: 'www.tiktok.com' },
                        {
                            name: 'User-Agent',
                            value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0'
                        },
                        {
                            name: 'Cookie',
                            value: 'ttwid=1%7Cabc123xyz987secret; msToken=ms_rotated_secret_token_222'
                        },
                        { name: 'Content-Type', value: 'application/json' }
                    ],
                    postData: JSON.stringify({ code: '654321' })
                });
                const resStep3 = createMockResponse({
                    request: reqStep3,
                    status: 200,
                    statusText: 'OK',
                    headersArray: [{ name: 'Content-Type', value: 'application/json' }],
                    body: JSON.stringify({ verified: true })
                });
                await emitHttpTransaction(context, reqStep3, resStep3);

                const summary = await profile.getTrafficAttribution();
                await profile.stop();
                const events = readNdjsonFile(profile.trafficPaths.trafficNdjsonPath);
                const egressEvents = events.filter((e) => e.type === 'egress');
                assert.equal(egressEvents.length, 3);
                const [corr1, corr2, corr3] = egressEvents.map((e) => e.correlationId);

                assert.ok(summary.cookieLineage, 'Expected summary.cookieLineage object');
                const { ttwid, msToken, __cf_bm: cfBm } = summary.cookieLineage;
                assert.ok(ttwid, 'Expected ttwid in summary.cookieLineage');
                assert.ok(msToken, 'Expected msToken in summary.cookieLineage');
                assert.ok(cfBm, 'Expected __cf_bm in summary.cookieLineage');

                // Verify isAntiBotToken flags
                assert.equal(ttwid.isAntiBotToken, true);
                assert.equal(msToken.isAntiBotToken, true);
                assert.equal(cfBm.isAntiBotToken, true);

                // Verify firstSetByCorrelationId and firstSetAtStep
                assert.equal(ttwid.firstSetByCorrelationId, corr1);
                assert.equal(ttwid.firstSetAtStep, 'step-1-landing');
                assert.equal(msToken.firstSetByCorrelationId, corr1);
                assert.equal(msToken.firstSetAtStep, 'step-1-landing');
                assert.equal(cfBm.firstSetByCorrelationId, corr1);
                assert.equal(cfBm.firstSetAtStep, 'step-1-landing');

                // Verify mutationsCount, valueHistory, and sentInCorrelationIds
                assert.equal(msToken.mutationsCount, 2);
                assert.equal(msToken.valueHistory.length, 2);
                assert.notEqual(
                    msToken.valueHistory[0].valueSha256,
                    msToken.valueHistory[1].valueSha256
                );
                assert.equal(
                    msToken.valueHistory[0].valueSha256,
                    sha256Hex('ms_initial_secret_token_111')
                );
                assert.equal(
                    msToken.valueHistory[1].valueSha256,
                    sha256Hex('ms_rotated_secret_token_222')
                );
                assert.equal(msToken.lastSetByCorrelationId, corr2);
                assert.equal(msToken.lastSetAtStep, 'step-2-submit');

                assert.equal(ttwid.sentInCorrelationIds.length, 2);
                assert.deepEqual(ttwid.sentInCorrelationIds, [corr2, corr3]);
                assert.equal(msToken.sentInCorrelationIds.length, 2);
                assert.deepEqual(msToken.sentInCorrelationIds, [corr2, corr3]);
                assert.equal(cfBm.sentInCorrelationIds.length, 1);
                assert.deepEqual(cfBm.sentInCorrelationIds, [corr2]);

                // Verify masking of raw secrets and exact SHA-256 matching
                assert.equal(
                    msToken.lastValueSha256,
                    sha256Hex('ms_rotated_secret_token_222')
                );
                assert.equal(
                    msToken.lastMaskedValue.includes('rotated_secret_token'),
                    false,
                    'Raw secret substring must never be exposed in lastMaskedValue'
                );
                assert.equal(
                    ttwid.lastMaskedValue.includes('abc123xyz987'),
                    false,
                    'Raw secret substring must never be exposed in ttwid.lastMaskedValue'
                );
                assert.equal(msToken.matchesLatestSetCookie, true);

                // Verify query-traffic-attribution.js --cookies --json and --cookie=msToken --json
                const cliScriptPath = path.join(__dirname, 'query-traffic-attribution.js');
                const allCookiesOut = execFileSync(
                    process.execPath,
                    [
                        cliScriptPath,
                        `--profiles-dir=${tempProfilesDir}`,
                        '--profile=traffic-test-12-cookies',
                        '--cookies',
                        '--json'
                    ],
                    { encoding: 'utf8' }
                );
                const allCookiesJson = JSON.parse(allCookiesOut);
                assert.equal(allCookiesJson.mode, 'cookies');
                assert.equal(allCookiesJson.count, 3);
                assert.equal(allCookiesJson.antiBotTokenCount, 3);
                assert.deepEqual(allCookiesJson.cookieLineage, summary.cookieLineage);

                const msTokenOut = execFileSync(
                    process.execPath,
                    [
                        cliScriptPath,
                        `--profiles-dir=${tempProfilesDir}`,
                        '--profile=traffic-test-12-cookies',
                        '--cookie=msToken',
                        '--json'
                    ],
                    { encoding: 'utf8' }
                );
                const msTokenJson = JSON.parse(msTokenOut);
                assert.equal(msTokenJson.mode, 'cookies');
                assert.equal(msTokenJson.cookieName, 'msToken');
                assert.equal(msTokenJson.found, true);
                assert.deepEqual(msTokenJson.cookie, summary.cookieLineage.msToken);

                await profile.delete();
            }
        );

        // =========================================================================
        // Test 13: C++ Necko MOZ_LOG (necko-pre-tls.moz_log) Pre-TLS Wire Block Parser & SHA-256 Tamper Detection
        // =========================================================================
        await testSection(
            'Test 13: C++ Necko MOZ_LOG (necko-pre-tls.moz_log) Pre-TLS Wire Block Parser & SHA-256 Tamper Detection',
            async () => {
                const profile = await createAndStartProfile(
                    'Traffic_Test_13_NeckoMozLog',
                    'http://10.104.0.1:8080',
                    {
                        profileId: 'traffic-test-13-necko-mozlog',
                        os: 'linux',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        neckoMozLog: true
                    }
                );

                const recorder = profile.getTrafficRecorder();
                const trafficDir = profile.trafficPaths.trafficDir;
                const neckoMozLogPath = profile.trafficPaths.neckoMozLogPath;

                assert.equal(
                    typeof recorder.recordNeckoMozLogBlock,
                    'function',
                    'Expected recorder.recordNeckoMozLogBlock to be a function'
                );

                const realisticNeckoMozLog = [
                    '2026-11-25 17:20:01.102000 UTC - [Parent 41200: Main Thread]: D/nsHostResolver nsHostResolver::ResolveHost [host=accounts.google.com flags=0]',
                    '2026-11-25 17:20:01.104500 UTC - [Parent 41200: Socket Thread]: V/nsSocketTransport nsSocketTransport::InitiateSocket [this=0x7f8b1c004000 host=accounts.google.com:443]',
                    '2026-11-25 17:20:01.105200 UTC - [Parent 41200: Socket Thread]: V/nsSocketTransport nsSocketTransport::OnSocketEvent [this=0x7f8b1c004000 type=MSG_ENSURE_CONNECT]',
                    '2026-11-25 17:20:01.112000 UTC - [Parent 41200: Main Thread]: V/nsHttp http request [',
                    '2026-11-25 17:20:01.112010 UTC - [Parent 41200: Main Thread]: V/nsHttp   POST /v3/signin/_/signup/bg HTTP/2.0',
                    '2026-11-25 17:20:01.112020 UTC - [Parent 41200: Main Thread]: V/nsHttp   Host: accounts.google.com',
                    '2026-11-25 17:20:01.112030 UTC - [Parent 41200: Main Thread]: V/nsHttp   User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
                    '2026-11-25 17:20:01.112040 UTC - [Parent 41200: Main Thread]: V/nsHttp   Accept: application/json',
                    '2026-11-25 17:20:01.112050 UTC - [Parent 41200: Main Thread]: V/nsHttp   Content-Type: application/json',
                    '2026-11-25 17:20:01.112060 UTC - [Parent 41200: Main Thread]: V/nsHttp ]',
                    '2026-11-25 17:20:01.113500 UTC - [Parent 41200: Socket Thread]: V/nsHttp Http2Session::WriteSegments [stream=0x7f8b1c009800 frame=HEADERS]',
                    '2026-11-25 17:20:01.148000 UTC - [Parent 41200: Socket Thread]: V/nsHttp Http2Session::ReadSegments [stream=0x7f8b1c009800 frame=DATA]',
                    '2026-11-25 17:20:01.149000 UTC - [Parent 41200: Main Thread]: V/nsHttp http response [',
                    '2026-11-25 17:20:01.149010 UTC - [Parent 41200: Main Thread]: V/nsHttp   HTTP/2.0 200 OK',
                    '2026-11-25 17:20:01.149020 UTC - [Parent 41200: Main Thread]: V/nsHttp   Content-Type: application/json',
                    '2026-11-25 17:20:01.149030 UTC - [Parent 41200: Main Thread]: V/nsHttp   Cache-Control: no-store',
                    '2026-11-25 17:20:01.149040 UTC - [Parent 41200: Main Thread]: V/nsHttp ]'
                ].join('\n');

                recorder.recordNeckoMozLogBlock(realisticNeckoMozLog);
                const summary = await recorder.flushSummary();
                await profile.stop();

                assert.ok(summary.neckoMozLog, 'Expected summary.neckoMozLog object');
                assert.equal(summary.neckoMozLog.exists, true);
                assert.ok(summary.neckoMozLog.requestBlockCount >= 1);
                assert.ok(summary.neckoMozLog.responseBlockCount >= 1);
                assert.ok(summary.neckoMozLog.http2FrameCount >= 1);
                assert.ok(summary.neckoMozLog.dnsLookupCount >= 1);
                assert.ok(summary.neckoMozLog.socketEventCount >= 1);
                assert.equal(
                    summary.neckoMozLog.parsedRequests[0].requestLine,
                    'POST /v3/signin/_/signup/bg HTTP/2.0'
                );
                assert.equal(
                    summary.neckoMozLog.parsedRequests[0].host,
                    'accounts.google.com'
                );
                assert.equal(
                    summary.neckoMozLog.parsedResponses[0].statusLine,
                    'HTTP/2.0 200 OK'
                );

                // Verify untampered integrity passes
                const validCheck = verifyTrafficIntegrity(trafficDir);
                assert.equal(
                    validCheck.valid,
                    true,
                    `Expected verifyTrafficIntegrity(trafficDir).valid === true, got errors: ${validCheck.errors.join('; ')}`
                );

                // Tamper with necko-pre-tls.moz_log on disk and verify tamper detection
                const originalMozLog = fs.readFileSync(neckoMozLogPath, 'utf8');
                fs.writeFileSync(
                    neckoMozLogPath,
                    `${originalMozLog}\n2026-11-25 17:20:02.000000 UTC - [Parent 41200: Main Thread]: V/nsHttp TAMPERED_LINE\n`,
                    'utf8'
                );

                const tamperedCheck = verifyTrafficIntegrity(trafficDir);
                assert.equal(
                    tamperedCheck.valid,
                    false,
                    'Expected verifyTrafficIntegrity(trafficDir).valid === false after tampering with necko-pre-tls.moz_log'
                );
                assert.equal(
                    tamperedCheck.errors.some((e) => e.includes('necko-pre-tls.moz_log')),
                    true
                );

                await profile.delete();
            }
        );

        console.log(`\n🎉 All ${passedTests} Camoufox pre-TLS traffic attribution & isolation test suites passed!`);
    } finally {
        setCamoufoxModule(null);
        fs.rmSync(tempProfilesDir, { recursive: true, force: true });
    }
}

runTests().catch((err) => {
    console.error('\n❌ Camoufox traffic attribution test suite failed:', err);
    process.exit(1);
});
