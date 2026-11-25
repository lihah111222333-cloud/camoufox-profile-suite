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
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
    setCamoufoxModule,
    closeSharedBrowser
} from '../src/camoufox/client.js';
import { CamoufoxProfile, createAndStartProfile } from '../src/camoufox/profile.js';
import { CamoufoxTrafficRecorder, redactProxyUrl } from '../src/camoufox/traffic-recorder.js';

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
        const hub = createEventHub();

        return {
            ...hub,
            pageId,
            context: () => context,
            isClosed: () => closed,
            async close() {
                closed = true;
            },
            async goto(url, options = {}) {
                return { url, options, status: 200 };
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
