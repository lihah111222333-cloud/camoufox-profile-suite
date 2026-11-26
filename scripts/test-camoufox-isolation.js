/**
 * Camoufox Multi-Context Isolation, Storage Persistence, Proxy & Coherence Test Suite
 *
 * Verifies:
 * 1. Concurrent multi-profile creation/start/stop/delete across OS targets (`windows`, `macos`, `linux`)
 *    in both standalone browser mode (`Camoufox`) and shared-browser mode (`NewContext`).
 * 2. Strict cookie (`datr`, `ig_did`, `ttwid`) and `localStorage` isolation between Profile A, Profile B, and Profile C.
 * 3. Persistent `storage-state.json` and `profile.json` reload across profile stop & restart, plus full directory cleanup on `profile.delete()`.
 * 4. Proxy normalization (`normalizeProxy`) across HTTP, HTTPS, SOCKS5, URL auth, `host:port:user:p@ss:word` (colons/@ in password),
 *    IPv6 literals (`http://[::1]:8080`, `[::1]:8080`, `{ host: '::1', port: 8080 }`), and missing/invalid port rejection.
 * 5. Desktop Firefox User-Agent coherence enforcement (`assertFirefoxCoherence`) rejecting Chrome, Safari, Edge, Mobile, Android, and iPhone UAs.
 *
 * Uses only Node's built-in `node:assert/strict` (zero external dependencies).
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import camoufoxClient, {
    setCamoufoxModule,
    assertFirefoxCoherence,
    normalizeProxy,
    normalizeTargetOs,
    createProfile,
    startProfile,
    stopProfile,
    deleteProfile,
    getProfile,
    listProfiles,
    updateProfileProxy,
    closeSharedBrowser,
    getStorageStatePath,
    getProfileMetadataPath,
    getActiveProfileIds,
    stopAllActiveProfiles,
    registerProcessCleanupHooks,
    unregisterProcessCleanupHooks
} from '../src/camoufox/client.js';
import { CamoufoxProfile, createAndStartProfile } from '../src/camoufox/profile.js';
import { verifyTrafficIntegrity } from '../src/camoufox/traffic-recorder.js';

/**
 * Create an isolated in-memory Mock Camoufox Engine that faithfully implements
 * Playwright's Browser, BrowserContext (`cookies`, `addCookies`, `storageState`, `newPage`),
 * and Page (`evaluate`, `goto`, etc.) semantics, loading initial state from `storageState` file path.
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
        let currentOrigin = 'https://accounts.google.com';

        return {
            pageId,
            context: () => context,
            isClosed: () => closed,
            async close() {
                closed = true;
            },
            async goto(url, options = {}) {
                try {
                    const parsed = new URL(url);
                    currentOrigin = parsed.origin;
                } catch {
                    currentOrigin = 'https://accounts.google.com';
                }
                return { url, options, status: 200 };
            },
            async setLocalStorageItem(origin, name, value) {
                context._setLocalStorage(origin || currentOrigin, name, value);
            },
            async getLocalStorageItem(origin, name) {
                return context._getLocalStorage(origin || currentOrigin, name);
            },
            async evaluate(fn, arg) {
                if (typeof fn === 'function') {
                    return fn(arg);
                }
                return null;
            },
            async $$(selector) {
                return [{ selector }];
            }
        };
    }

    function createMockContext(browser, contextOptions = {}) {
        const contextId = ++contextIdSeq;
        let closed = false;
        const pages = [];
        const listeners = new Map();
        // Deep-isolated per-context cookie jar and origin localStorage map
        let cookieJar = [];
        const originStorage = new Map();

        // Hydrate from persisted storage-state.json if provided
        const parsed = contextOptions.storageState;
        if (Array.isArray(parsed?.cookies)) {
            cookieJar = parsed.cookies.map((c) => ({ ...c }));
        }
        if (Array.isArray(parsed?.origins)) {
            for (const entry of parsed.origins) {
                const map = new Map();
                for (const item of entry.localStorage || []) {
                    map.set(item.name, item.value);
                }
                originStorage.set(entry.origin, map);
            }
        }

        const context = {
            contextId,
            browser: () => browser,
            options: { ...contextOptions },
            isClosed: () => closed,
            pages: () => pages.filter((p) => !p.isClosed()),
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
            emit(event, ...args) {
                for (const fn of [...(listeners.get(event) || [])]) {
                    fn(...args);
                }
            },
            async newPage() {
                if (closed) {
                    throw new Error(`Cannot create page in closed BrowserContext #${contextId}`);
                }
                const page = createMockPage(context);
                pages.push(page);
                return page;
            },
            async addCookies(cookies = []) {
                for (const cookie of cookies) {
                    const idx = cookieJar.findIndex(
                        (c) => c.name === cookie.name && c.domain === cookie.domain
                    );
                    const cloned = { ...cookie };
                    if (idx >= 0) {
                        cookieJar[idx] = cloned;
                    } else {
                        cookieJar.push(cloned);
                    }
                }
            },
            async cookies() {
                return cookieJar.map((c) => ({ ...c }));
            },
            async clearCookies() {
                cookieJar = [];
            },
            _setLocalStorage(origin, name, value) {
                if (!originStorage.has(origin)) {
                    originStorage.set(origin, new Map());
                }
                originStorage.get(origin).set(String(name), String(value));
            },
            _getLocalStorage(origin, name) {
                return originStorage.get(origin)?.get(String(name)) ?? null;
            },
            async storageState({ path: savePath } = {}) {
                const origins = [];
                for (const [origin, map] of originStorage.entries()) {
                    const localStorage = [];
                    for (const [name, value] of map.entries()) {
                        localStorage.push({ name, value });
                    }
                    origins.push({ origin, localStorage });
                }
                const state = {
                    cookies: cookieJar.map((c) => ({ ...c })),
                    origins
                };
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
        const listeners = new Map();

        const browser = {
            browserId,
            launchOptions: { ...launchOptions },
            isConnected: () => connected,
            contexts: () => contexts.filter((c) => !c.isClosed()),
            on(event, handler) {
                if (!listeners.has(event)) {
                    listeners.set(event, []);
                }
                listeners.get(event).push(handler);
            },
            async newContext(contextOptions = {}) {
                if (!connected) {
                    throw new Error(`Cannot create context on disconnected Browser #${browserId}`);
                }
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
                for (const fn of listeners.get('disconnected') || []) {
                    fn();
                }
            }
        };

        launchedBrowsers.push(browser);
        return browser;
    }

    const mockModule = {
        launchedBrowsers,
        createdContexts,
        async Camoufox(launchOptions = {}) {
            // Simulate async browser startup latency to test concurrency race conditions
            await new Promise((resolve) => setTimeout(resolve, 10));
            return createMockBrowser(launchOptions);
        },
        async AsyncCamoufox(launchOptions = {}) {
            await new Promise((resolve) => setTimeout(resolve, 10));
            return createMockBrowser(launchOptions);
        },
        async NewContext(browser, contextOptions = {}) {
            await new Promise((resolve) => setTimeout(resolve, 5));
            return browser.newContext(contextOptions);
        },
        async AsyncNewContext(browser, contextOptions = {}) {
            await new Promise((resolve) => setTimeout(resolve, 5));
            return browser.newContext(contextOptions);
        }
    };

    return mockModule;
}

async function runTests() {
    const tempProfilesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-isolation-test-'));
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
        // 1. Desktop Firefox User-Agent Coherence Enforcement
        // =========================================================================
        await testSection('Desktop Firefox User-Agent coherence enforcement (assertFirefoxCoherence)', async () => {
            const validDesktopFirefoxUAs = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0',
                'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
            ];

            for (const validUa of validDesktopFirefoxUAs) {
                assert.equal(assertFirefoxCoherence(validUa), true);
                assert.equal(assertFirefoxCoherence({ userAgent: validUa }), true);
                assert.equal(assertFirefoxCoherence({ config: { 'navigator.userAgent': validUa } }), true);
                assert.equal(
                    assertFirefoxCoherence({
                        firefox_user_prefs: { 'general.useragent.override': validUa }
                    }),
                    true
                );
            }

            const forbiddenUAs = [
                // Chrome Desktop
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
                // Safari macOS
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
                // Edge Chromium & Legacy Edge
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/135.0 Edge/18.19041',
                // Mobile / Android Firefox (Fennec / Fenix)
                'Mozilla/5.0 (Android 14; Mobile; rv:135.0) Gecko/135.0 Firefox/135.0',
                'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36',
                // iPhone / iPad Safari & FxiOS
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/135.0 Mobile/15E148 Safari/605.1.15',
                'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
                // Non-Gecko / Missing Firefox token
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101',
                'CustomBot/1.0'
            ];

            for (const badUa of forbiddenUAs) {
                assert.throws(() => assertFirefoxCoherence(badUa), /Forbidden User-Agent override/);
                assert.throws(() => assertFirefoxCoherence({ userAgent: badUa }), /Forbidden User-Agent override/);
                assert.throws(
                    () => assertFirefoxCoherence({ user_agent: badUa }),
                    /Forbidden User-Agent override/
                );
                assert.throws(
                    () => assertFirefoxCoherence({ config: { 'navigator.userAgent': badUa } }),
                    /Forbidden User-Agent override/
                );
                assert.throws(
                    () =>
                        assertFirefoxCoherence({
                            firefox_user_prefs: { 'general.useragent.override': badUa }
                        }),
                    /Forbidden User-Agent override/
                );
                await assert.rejects(
                    () =>
                        createProfile('bad-ua-profile', null, {
                            profilesDir: tempProfilesDir,
                            userAgent: badUa
                        }),
                    /Forbidden User-Agent override/
                );
            }

            // Target OS validation rejects mobile OS targets ('android', 'ios')
            assert.equal(normalizeTargetOs('win32'), 'windows');
            assert.equal(normalizeTargetOs('darwin'), 'macos');
            assert.equal(normalizeTargetOs('ubuntu'), 'linux');
            assert.throws(() => normalizeTargetOs('android'), /Invalid Camoufox target OS/);
            assert.throws(() => normalizeTargetOs('ios'), /Invalid Camoufox target OS/);
        });

        // =========================================================================
        // 2. Proxy Normalization Across All Formats & Edge Cases
        // =========================================================================
        await testSection('Proxy normalization (HTTP, SOCKS5, auth, colons in password, IPv6, invalid ports)', async () => {
            assert.equal(normalizeProxy(null), null);
            assert.equal(normalizeProxy(''), null);
            assert.equal(normalizeProxy('   '), null);

            // Standard HTTP & HTTPS URLs
            assert.deepEqual(normalizeProxy('http://198.51.100.10:8080'), {
                server: 'http://198.51.100.10:8080'
            });
            assert.deepEqual(normalizeProxy('https://proxy.example.com:443'), {
                server: 'https://proxy.example.com:443'
            });

            // SOCKS5 URL with credentials
            assert.deepEqual(normalizeProxy('socks5://user1:secretPass@1.2.3.4:1080'), {
                server: 'socks5://1.2.3.4:1080',
                username: 'user1',
                password: 'secretPass'
            });

            // SOCKS5 URL with colons and '@' inside password
            assert.deepEqual(normalizeProxy('socks5://user1:p@ss:word:123@1.2.3.4:1080'), {
                server: 'socks5://1.2.3.4:1080',
                username: 'user1',
                password: 'p@ss:word:123'
            });

            // host:port:user:pass format with colons and '@' in password
            assert.deepEqual(normalizeProxy('192.0.2.55:3128:myuser:p@ss:word'), {
                server: 'http://192.0.2.55:3128',
                username: 'myuser',
                password: 'p@ss:word'
            });
            assert.deepEqual(normalizeProxy('proxy.host.local:9000:admin:a:b:c:d'), {
                server: 'http://proxy.host.local:9000',
                username: 'admin',
                password: 'a:b:c:d'
            });

            // IPv6 URLs, unschemed IPv6 strings, and IPv6 objects
            assert.deepEqual(normalizeProxy('http://[::1]:8080'), {
                server: 'http://[::1]:8080'
            });
            assert.deepEqual(normalizeProxy('socks5://ipv6user:ipv6pass@[2001:db8::1]:1080'), {
                server: 'socks5://[2001:db8::1]:1080',
                username: 'ipv6user',
                password: 'ipv6pass'
            });
            assert.deepEqual(normalizeProxy('[::1]:8080'), {
                server: 'http://[::1]:8080'
            });
            assert.deepEqual(normalizeProxy('[2001:db8::1]:8080:user6:p@ss:6'), {
                server: 'http://[2001:db8::1]:8080',
                username: 'user6',
                password: 'p@ss:6'
            });
            assert.deepEqual(
                normalizeProxy({ host: '::1', port: 8080, type: 'socks5', username: 'u', password: 'p' }),
                {
                    server: 'socks5://[::1]:8080',
                    username: 'u',
                    password: 'p'
                }
            );
            assert.deepEqual(
                normalizeProxy({ host: '[2001:db8::2]', port: '3128', protocol: 'http' }),
                {
                    server: 'http://[2001:db8::2]:3128'
                }
            );

            // Object with { server, username, password }
            assert.deepEqual(
                normalizeProxy({
                    server: 'socks5://10.0.0.1:1080',
                    username: 'alice',
                    password: 'p:w'
                }),
                {
                    server: 'socks5://10.0.0.1:1080',
                    username: 'alice',
                    password: 'p:w'
                }
            );

            // Invalid / missing ports & malformed hosts must be rejected
            const invalidProxies = [
                '1.2.3.4',
                '1.2.3.4:',
                '1.2.3.4:abc',
                '1.2.3.4:0',
                '1.2.3.4:65536',
                '1.2.3.4:-80',
                '1.2.3.4:8080abc',
                ':8080',
                'http://1.2.3.4',
                'http://1.2.3.4:',
                'http://1.2.3.4:0',
                'http://1.2.3.4:70000',
                'http://1.2.3.4:notaport',
                'http://[::1]',
                'http://[::1]:',
                'http://[::1]:0',
                'http://[::1]:99999',
                '[::1]',
                '[::1]:',
                '[::1]:abc',
                'ftp://1.2.3.4:21',
                { host: '1.2.3.4' },
                { host: '1.2.3.4', port: '' },
                { host: '1.2.3.4', port: 'abc' },
                { host: '1.2.3.4', port: '8080xyz' },
                { host: '1.2.3.4', port: 0 },
                { host: '1.2.3.4', port: 65536 },
                { host: '', port: 8080 },
                { server: 'http://1.2.3.4' },
                { server: '1.2.3.4:99999' }
            ];

            for (const invalidProxy of invalidProxies) {
                assert.throws(
                    () => normalizeProxy(invalidProxy),
                    /proxy|port|host|protocol|Invalid/i,
                    `Expected normalizeProxy(${JSON.stringify(invalidProxy)}) to throw`
                );
            }
        });

        // =========================================================================
        // 3. Concurrent Multi-Profile Creation & Isolation (Standalone Mode)
        // =========================================================================
        await testSection(
            'Concurrent multi-profile creation (windows, macos, linux) & strict cookie/localStorage isolation (Standalone)',
            async () => {
                const initialBrowserCount = mockEngine.launchedBrowsers.length;

                // Start Profile A (windows), Profile B (macos), and Profile C (linux) concurrently
                const [profileA, profileB, profileC] = await Promise.all([
                    createAndStartProfile('Profile_A_Win', 'http://10.10.1.1:8080:userA:p@ss:A', {
                        profileId: 'profile-a-win',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false
                    }),
                    createAndStartProfile('Profile_B_Mac', 'socks5://userB:passB@10.10.2.2:1080', {
                        profileId: 'profile-b-mac',
                        os: 'macos',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false
                    }),
                    createAndStartProfile('Profile_C_Lin', 'http://[::1]:8080', {
                        profileId: 'profile-c-lin',
                        os: 'linux',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false
                    })
                ]);

                // 3 distinct standalone Browser instances and 3 distinct BrowserContexts
                assert.equal(mockEngine.launchedBrowsers.length - initialBrowserCount, 3);
                assert.notEqual(profileA.browser, profileB.browser);
                assert.notEqual(profileB.browser, profileC.browser);
                assert.notEqual(profileA.context, profileB.context);
                assert.notEqual(profileB.context, profileC.context);

                assert.equal(profileA.metadata.os, 'windows');
                assert.equal(profileB.metadata.os, 'macos');
                assert.equal(profileC.metadata.os, 'linux');

                // Set distinct tracking cookies (datr, ig_did, ttwid) & localStorage in each profile
                await Promise.all([
                    profileA.context.addCookies([
                        { name: 'datr', value: 'datr_WIN_A_111', domain: '.facebook.com', path: '/' },
                        { name: 'ig_did', value: 'ig_WIN_A_111', domain: '.instagram.com', path: '/' },
                        { name: 'ttwid', value: 'ttwid_WIN_A_111', domain: '.tiktok.com', path: '/' }
                    ]),
                    profileB.context.addCookies([
                        { name: 'datr', value: 'datr_MAC_B_222', domain: '.facebook.com', path: '/' },
                        { name: 'ig_did', value: 'ig_MAC_B_222', domain: '.instagram.com', path: '/' },
                        { name: 'ttwid', value: 'ttwid_MAC_B_222', domain: '.tiktok.com', path: '/' }
                    ]),
                    profileC.context.addCookies([
                        { name: 'datr', value: 'datr_LIN_C_333', domain: '.facebook.com', path: '/' },
                        { name: 'ig_did', value: 'ig_LIN_C_333', domain: '.instagram.com', path: '/' },
                        { name: 'ttwid', value: 'ttwid_LIN_C_333', domain: '.tiktok.com', path: '/' }
                    ])
                ]);

                const pageA = await profileA.getPage();
                const pageB = await profileB.getPage();
                const pageC = await profileC.getPage();

                await pageA.setLocalStorageItem('https://accounts.google.com', 'session_token', 'token_A_win');
                await pageB.setLocalStorageItem('https://accounts.google.com', 'session_token', 'token_B_mac');
                await pageC.setLocalStorageItem('https://accounts.google.com', 'session_token', 'token_C_lin');

                // Verify zero cross-profile leakage in memory
                const [cookiesA, cookiesB, cookiesC] = await Promise.all([
                    profileA.context.cookies(),
                    profileB.context.cookies(),
                    profileC.context.cookies()
                ]);

                assert.equal(cookiesA.find((c) => c.name === 'datr')?.value, 'datr_WIN_A_111');
                assert.equal(cookiesA.find((c) => c.name === 'ig_did')?.value, 'ig_WIN_A_111');
                assert.equal(cookiesA.find((c) => c.name === 'ttwid')?.value, 'ttwid_WIN_A_111');

                assert.equal(cookiesB.find((c) => c.name === 'datr')?.value, 'datr_MAC_B_222');
                assert.equal(cookiesB.find((c) => c.name === 'ig_did')?.value, 'ig_MAC_B_222');
                assert.equal(cookiesB.find((c) => c.name === 'ttwid')?.value, 'ttwid_MAC_B_222');

                assert.equal(cookiesC.find((c) => c.name === 'datr')?.value, 'datr_LIN_C_333');
                assert.equal(cookiesC.find((c) => c.name === 'ig_did')?.value, 'ig_LIN_C_333');
                assert.equal(cookiesC.find((c) => c.name === 'ttwid')?.value, 'ttwid_LIN_C_333');

                assert.equal(await pageA.getLocalStorageItem('https://accounts.google.com', 'session_token'), 'token_A_win');
                assert.equal(await pageB.getLocalStorageItem('https://accounts.google.com', 'session_token'), 'token_B_mac');
                assert.equal(await pageC.getLocalStorageItem('https://accounts.google.com', 'session_token'), 'token_C_lin');

                // Stop all three concurrently (persisting storage-state.json)
                await Promise.all([profileA.stop(), profileB.stop(), profileC.stop()]);
            }
        );

        // =========================================================================
        // 4. Storage State Persistence Across Stop & Restart + Delete Cleanup
        // =========================================================================
        await testSection('Storage state persistence across stop & restart and complete cleanup on delete()', async () => {
            const statePathA = getStorageStatePath('profile-a-win', tempProfilesDir);
            const statePathB = getStorageStatePath('profile-b-mac', tempProfilesDir);
            const statePathC = getStorageStatePath('profile-c-lin', tempProfilesDir);

            assert.equal(fs.existsSync(statePathA), true);
            assert.equal(fs.existsSync(statePathB), true);
            assert.equal(fs.existsSync(statePathC), true);

            const persistedA = JSON.parse(fs.readFileSync(statePathA, 'utf8'));
            const persistedB = JSON.parse(fs.readFileSync(statePathB, 'utf8'));

            // Ensure Profile A's disk storage-state.json has only Profile A's cookies
            assert.equal(persistedA.cookies.length, 3);
            assert.equal(persistedA.cookies.find((c) => c.name === 'datr')?.value, 'datr_WIN_A_111');
            assert.equal(
                persistedA.cookies.some((c) => c.value.includes('MAC_B') || c.value.includes('LIN_C')),
                false
            );
            assert.equal(persistedB.cookies.find((c) => c.name === 'datr')?.value, 'datr_MAC_B_222');

            // Restart Profile A and verify it reloads its saved storageStatePath and cookies/localStorage
            const restartedA = new CamoufoxProfile('profile-a-win', {
                profilesDir: tempProfilesDir
            });
            await restartedA.start();

            assert.equal(restartedA.storageStatePath, statePathA);
            assert.equal(restartedA.metadata.os, 'windows');
            assert.deepEqual(restartedA.metadata.proxy, {
                server: 'http://10.10.1.1:8080',
                username: 'userA',
                password: 'p@ss:A'
            });

            const reloadedCookiesA = await restartedA.context.cookies();
            assert.equal(reloadedCookiesA.find((c) => c.name === 'datr')?.value, 'datr_WIN_A_111');
            assert.equal(reloadedCookiesA.find((c) => c.name === 'ig_did')?.value, 'ig_WIN_A_111');
            assert.equal(reloadedCookiesA.find((c) => c.name === 'ttwid')?.value, 'ttwid_WIN_A_111');

            const reloadedPageA = await restartedA.getPage();
            assert.equal(
                await reloadedPageA.getLocalStorageItem('https://accounts.google.com', 'session_token'),
                'token_A_win'
            );

            // Update proxy for Profile A and verify metadata persistence
            await updateProfileProxy('profile-a-win', 'socks5://newuser:new:pass@192.0.2.99:1080', {
                profilesDir: tempProfilesDir
            });
            const updatedMetaA = await getProfile('profile-a-win', { profilesDir: tempProfilesDir });
            assert.deepEqual(updatedMetaA.proxy, {
                server: 'socks5://192.0.2.99:1080',
                username: 'newuser',
                password: 'new:pass'
            });

            // Delete Profile A via profile.delete() and verify complete cleanup on disk
            const profileDirA = path.dirname(statePathA);
            await restartedA.delete();
            assert.equal(fs.existsSync(profileDirA), false);
            assert.equal(fs.existsSync(statePathA), false);
            assert.equal(fs.existsSync(getProfileMetadataPath('profile-a-win', tempProfilesDir)), false);
            assert.equal(await getProfile('profile-a-win', { profilesDir: tempProfilesDir }), null);

            // Profiles B and C must remain untouched on disk after deleting Profile A
            assert.equal(fs.existsSync(statePathB), true);
            assert.equal(fs.existsSync(statePathC), true);
            const remaining = await listProfiles(tempProfilesDir);
            assert.equal(remaining.length, 2);
        });

        // =========================================================================
        // 5. Shared-Browser Mode (`NewContext`) Multi-OS Concurrent Isolation
        // =========================================================================
        await testSection(
            'Shared-browser mode (NewContext) concurrent multi-OS (windows, macos, linux) context isolation',
            async () => {
                await closeSharedBrowser();
                const browserCountBefore = mockEngine.launchedBrowsers.length;

                // Concurrently start 3 shared-browser profiles across windows, macos, linux
                const [sharedWin, sharedMac, sharedLin] = await Promise.all([
                    startProfile('shared-win', {
                        os: 'windows',
                        useSharedBrowser: true,
                        profilesDir: tempProfilesDir,
                        proxy: 'http://10.20.1.1:8080'
                    }),
                    startProfile('shared-mac', {
                        os: 'macos',
                        useSharedBrowser: true,
                        profilesDir: tempProfilesDir,
                        proxy: 'socks5://u:p@10.20.2.2:1080'
                    }),
                    startProfile('shared-lin', {
                        os: 'linux',
                        useSharedBrowser: true,
                        profilesDir: tempProfilesDir,
                        proxy: 'http://[::1]:8888'
                    })
                ]);

                // All 3 concurrent profiles in shared-browser mode must share ONE browser process
                assert.equal(mockEngine.launchedBrowsers.length - browserCountBefore, 1);
                const nativeBrowser = mockEngine.launchedBrowsers[browserCountBefore];
                const sessions = [sharedWin, sharedMac, sharedLin];
                assert.deepEqual(
                    new Set(nativeBrowser.contexts()),
                    new Set(sessions.map(({ context }) => context))
                );
                assert.equal(new Set(sessions.map(({ browser }) => browser)).size, 3);
                for (const { browser, context, page, ownsBrowser } of sessions) {
                    assert.equal(ownsBrowser, false);
                    assert.notEqual(browser, nativeBrowser);
                    assert.equal(context.browser(), browser);
                    assert.equal(page.browser(), browser);
                    assert.deepEqual(await browser.pages(), [page]);
                }

                // While having strictly distinct BrowserContexts with per-context OS and proxy
                assert.notEqual(sharedWin.context, sharedMac.context);
                assert.notEqual(sharedMac.context, sharedLin.context);
                assert.equal(sharedWin.context.options.os, 'windows');
                assert.equal(sharedMac.context.options.os, 'macos');
                assert.equal(sharedLin.context.options.os, 'linux');
                assert.equal(sharedWin.context.options.proxy.server, 'http://10.20.1.1:8080');
                assert.equal(sharedMac.context.options.proxy.server, 'socks5://10.20.2.2:1080');
                assert.equal(sharedLin.context.options.proxy.server, 'http://[::1]:8888');

                // Verify cookie isolation across shared-browser contexts
                await sharedWin.context.addCookies([
                    { name: 'datr', value: 'shared_win_datr', domain: '.facebook.com', path: '/' }
                ]);
                await sharedMac.context.addCookies([
                    { name: 'datr', value: 'shared_mac_datr', domain: '.facebook.com', path: '/' }
                ]);

                assert.equal((await sharedWin.context.cookies())[0].value, 'shared_win_datr');
                assert.equal((await sharedMac.context.cookies())[0].value, 'shared_mac_datr');
                assert.equal((await sharedLin.context.cookies()).length, 0);

                // Stopping one shared profile must close only its context, keeping the shared browser alive
                await stopProfile('shared-win', { profilesDir: tempProfilesDir });
                assert.equal(sharedWin.context.isClosed(), true);
                assert.equal(nativeBrowser.isConnected(), true);
                assert.deepEqual(await sharedWin.browser.pages(), []);
                await assert.rejects(sharedWin.browser.newPage(), /No active Playwright context/);
                assert.equal(sharedMac.browser.isConnected(), true);
                assert.equal(sharedMac.context.isClosed(), false);
                assert.equal(sharedLin.context.isClosed(), false);

                // Clean up remaining shared profiles and close shared browser
                await Promise.all([
                    deleteProfile('shared-win', { profilesDir: tempProfilesDir }),
                    deleteProfile('shared-mac', { profilesDir: tempProfilesDir }),
                    deleteProfile('shared-lin', { profilesDir: tempProfilesDir }),
                    deleteProfile('profile-b-mac', { profilesDir: tempProfilesDir }),
                    deleteProfile('profile-c-lin', { profilesDir: tempProfilesDir })
                ]);
                await closeSharedBrowser();

                assert.deepEqual(await listProfiles(tempProfilesDir), []);
            }
        );

        // =========================================================================
        // 6. Emergency Shutdown & Batch Flush (`stopAllActiveProfiles` & `getActiveProfileIds`)
        // =========================================================================
        await testSection(
            'Emergency shutdown & batch flush (stopAllActiveProfiles, getActiveProfileIds & cleanup hooks)',
            async () => {
                assert.deepEqual(getActiveProfileIds(), []);

                // Verify idempotent registration and unregistration of process cleanup hooks
                unregisterProcessCleanupHooks();
                const beforeSigint = process.listeners('SIGINT');
                const beforeSigterm = process.listeners('SIGTERM');
                assert.equal(registerProcessCleanupHooks(), true);
                assert.deepEqual(process.listeners('SIGINT'), beforeSigint);
                assert.deepEqual(process.listeners('SIGTERM'), beforeSigterm);
                assert.equal(registerProcessCleanupHooks(), false);
                assert.equal(unregisterProcessCleanupHooks(), true);
                assert.equal(unregisterProcessCleanupHooks(), false);

                // Launch 3 concurrent profiles (Shutdown_Win, Shutdown_Mac, Shutdown_Lin)
                const [shutdownWin, shutdownMac, shutdownLin] = await Promise.all([
                    createAndStartProfile('Shutdown_Win', 'http://10.30.1.1:8080', {
                        profileId: 'Shutdown_Win',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false
                    }),
                    createAndStartProfile('Shutdown_Mac', 'socks5://u:p@10.30.2.2:1080', {
                        profileId: 'Shutdown_Mac',
                        os: 'macos',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false
                    }),
                    createAndStartProfile('Shutdown_Lin', 'http://[::1]:8085', {
                        profileId: 'Shutdown_Lin',
                        os: 'linux',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: true
                    })
                ]);

                assert.deepEqual(process.listeners('SIGINT'), beforeSigint);
                assert.deepEqual(process.listeners('SIGTERM'), beforeSigterm);
                assert.equal(registerProcessCleanupHooks(), true);
                assert.equal(process.listenerCount('SIGINT'), beforeSigint.length + 1);
                assert.equal(process.listenerCount('SIGTERM'), beforeSigterm.length + 1);

                const activeIds = getActiveProfileIds();
                assert.equal(activeIds.length, 3);
                assert.deepEqual(
                    [...activeIds].sort(),
                    ['Shutdown_Lin', 'Shutdown_Mac', 'Shutdown_Win']
                );

                // Write cookies, localStorage, and emit pre-TLS traffic events in each active profile
                const activeProfilesList = [
                    { profile: shutdownWin, id: 'Shutdown_Win', tag: 'WIN' },
                    { profile: shutdownMac, id: 'Shutdown_Mac', tag: 'MAC' },
                    { profile: shutdownLin, id: 'Shutdown_Lin', tag: 'LIN' }
                ];

                for (const { profile, id, tag } of activeProfilesList) {
                    await profile.context.addCookies([
                        {
                            name: 'SID',
                            value: `sid_emergency_${tag}`,
                            domain: '.google.com',
                            path: '/'
                        }
                    ]);
                    const page = await profile.getPage();
                    await page.setLocalStorageItem(
                        'https://accounts.google.com',
                        'emergency_state',
                        `flushed_${tag}`
                    );

                    // Emit a synthetic pre-TLS request/response cycle on the context
                    profile.trafficRecorder.setStep(`signup_${tag.toLowerCase()}`);
                    profile.trafficRecorder.recordTriggerAction(
                        'page.goto',
                        `https://accounts.google.com/signup?profile=${id}`
                    );

                    const mockReq = {
                        method: () => 'POST',
                        url: () => `https://accounts.google.com/_/signup/validate?profile=${id}`,
                        resourceType: () => 'fetch',
                        isNavigationRequest: () => false,
                        headers: () => ({ 'content-type': 'application/json' }),
                        headersArray: async () => [
                            { name: 'content-type', value: 'application/json' }
                        ],
                        postDataBuffer: () =>
                            Buffer.from(JSON.stringify({ profileId: id, tag }), 'utf8')
                    };
                    const mockRes = {
                        request: () => mockReq,
                        url: () => `https://accounts.google.com/_/signup/validate?profile=${id}`,
                        status: () => 200,
                        statusText: () => 'OK',
                        headers: () => ({ 'content-type': 'application/json' }),
                        headersArray: async () => [
                            { name: 'content-type', value: 'application/json' }
                        ],
                        body: async () =>
                            Buffer.from(JSON.stringify({ ok: true, profileId: id }), 'utf8'),
                        serverAddr: async () => ({ ipAddress: '142.250.80.109', port: 443 }),
                        securityDetails: async () => ({ protocol: 'TLS 1.3' })
                    };

                    profile.context.emit('request', mockReq);
                    profile.context.emit('response', mockRes);
                    profile.context.emit('requestfinished', mockReq);
                }

                // Trigger emergency batch shutdown across all 3 active profiles
                const shutdownSummary = await stopAllActiveProfiles('test-emergency-shutdown');
                assert.equal(shutdownSummary.reason, 'test-emergency-shutdown');
                assert.equal(shutdownSummary.stoppedCount, 3);
                assert.equal(shutdownSummary.sharedBrowsersClosed, true);
                assert.deepEqual(
                    [...shutdownSummary.profileIds].sort(),
                    ['Shutdown_Lin', 'Shutdown_Mac', 'Shutdown_Win']
                );

                // Verify getActiveProfileIds() is now empty
                assert.deepEqual(getActiveProfileIds(), []);
                assert.deepEqual(process.listeners('SIGINT'), beforeSigint);
                assert.deepEqual(process.listeners('SIGTERM'), beforeSigterm);

                // Verify all underlying mock contexts and browsers were closed
                for (const { profile } of activeProfilesList) {
                    assert.equal(profile.context.isClosed(), true);
                    assert.equal(profile.browser.isConnected(), false);
                }

                // Verify all 3 profiles flushed storage-state.json and traffic/attribution-index.json to disk
                for (const { id, tag } of activeProfilesList) {
                    const storagePath = getStorageStatePath(id, tempProfilesDir);
                    assert.equal(fs.existsSync(storagePath), true);
                    const savedState = JSON.parse(fs.readFileSync(storagePath, 'utf8'));
                    assert.equal(
                        savedState.cookies.find((c) => c.name === 'SID')?.value,
                        `sid_emergency_${tag}`
                    );
                    const googleOrigin = savedState.origins.find(
                        (o) => o.origin === 'https://accounts.google.com'
                    );
                    assert.equal(
                        googleOrigin?.localStorage?.find((kv) => kv.name === 'emergency_state')
                            ?.value,
                        `flushed_${tag}`
                    );

                    const attributionPath = path.join(
                        tempProfilesDir,
                        id,
                        'traffic',
                        'attribution-index.json'
                    );
                    assert.equal(fs.existsSync(attributionPath), true);
                    const attributionReport = JSON.parse(fs.readFileSync(attributionPath, 'utf8'));
                    assert.equal(attributionReport.session.profileId, id);
                    assert.equal(attributionReport.totals.totalRequests, 1);
                    assert.equal(attributionReport.totals.totalResponses, 1);
                }

                unregisterProcessCleanupHooks();
            }
        );

        // =========================================================================
        // 7. Multi-Session Profile Restart Traffic Hash-Chain Continuity
        // =========================================================================
        await testSection(
            'Multi-session profile restart traffic hash-chain continuity (Restart_Chain_Win)',
            async () => {
                let responseBodyReads = 0;
                const profileSession1 = await createAndStartProfile(
                    'Restart_Chain_Win',
                    'http://10.40.1.1:8080',
                    {
                        profileId: 'Restart_Chain_Win',
                        os: 'windows',
                        profilesDir: tempProfilesDir,
                        useSharedBrowser: false,
                        recordBodies: true
                    }
                );

                profileSession1.setTrafficStep('fixture-phase-one');
                const session1ReqBody = JSON.stringify({ count: 1 });
                const session1ResBody = JSON.stringify({ ok: true, count: 1 });

                const mockReq1 = {
                    method: () => 'POST',
                    url: () => 'https://diagnostic.example.test/request-1',
                    resourceType: () => 'fetch',
                    isNavigationRequest: () => false,
                    headers: () => ({ 'content-type': 'application/json' }),
                    headersArray: async () => [{ name: 'content-type', value: 'application/json' }],
                    postDataBuffer: () => Buffer.from(session1ReqBody, 'utf8')
                };
                const mockRes1 = {
                    request: () => mockReq1,
                    url: () => 'https://diagnostic.example.test/request-1',
                    status: () => 200,
                    statusText: () => 'OK',
                    headers: () => ({ 'content-type': 'application/json' }),
                    headersArray: async () => [{ name: 'content-type', value: 'application/json' }],
                    async body() {
                        responseBodyReads += 1;
                        return Buffer.from(session1ResBody, 'utf8');
                    },
                    serverAddr: async () => ({ ipAddress: '192.0.2.10', port: 443 }),
                    securityDetails: async () => ({ protocol: 'TLS 1.3' })
                };

                profileSession1.context.emit('request', mockReq1);
                await new Promise((resolve) => setImmediate(resolve));
                profileSession1.context.emit('response', mockRes1);
                await new Promise((resolve) => setImmediate(resolve));
                profileSession1.context.emit('requestfinished', mockReq1);
                await new Promise((resolve) => setImmediate(resolve));

                const trafficDir = profileSession1.trafficPaths.trafficDir;
                const beforeSigint = process.listeners('SIGINT');
                const beforeSigterm = process.listeners('SIGTERM');
                assert.equal(registerProcessCleanupHooks(), true);
                assert.equal(process.listenerCount('SIGINT'), beforeSigint.length + 1);
                assert.equal(process.listenerCount('SIGTERM'), beforeSigterm.length + 1);
                assert.equal(await profileSession1.stop(), true);
                assert.deepEqual(process.listeners('SIGINT'), beforeSigint);
                assert.deepEqual(process.listeners('SIGTERM'), beforeSigterm);
                assert.equal(unregisterProcessCleanupHooks(), true);

                const integrityAfterSession1 = verifyTrafficIntegrity(trafficDir);
                assert.equal(
                    integrityAfterSession1.valid,
                    true,
                    `Expected valid traffic integrity after Session 1, got errors: ${integrityAfterSession1.errors.join('; ')}`
                );
                assert.ok(integrityAfterSession1.eventCount >= 2);
                assert.equal(integrityAfterSession1.verifiedPayloads, 1);
                const session1EventCount = integrityAfterSession1.eventCount;
                const session1ChainHead = integrityAfterSession1.chainHeadHash;

                // Restart the exact same profileId in a new CamoufoxProfile instance
                const profileSession2 = new CamoufoxProfile('Restart_Chain_Win', {
                    profilesDir: tempProfilesDir,
                    useSharedBrowser: false,
                    recordBodies: true
                });
                await profileSession2.start();
                profileSession2.setTrafficStep('fixture-phase-two');

                const session2ReqBody = JSON.stringify({ count: 2 });
                const session2ResBody = JSON.stringify({ ok: true, count: 2 });

                const mockReq2 = {
                    method: () => 'POST',
                    url: () => 'https://diagnostic.example.test/request-2',
                    resourceType: () => 'fetch',
                    isNavigationRequest: () => false,
                    headers: () => ({ 'content-type': 'application/json' }),
                    headersArray: async () => [{ name: 'content-type', value: 'application/json' }],
                    postDataBuffer: () => Buffer.from(session2ReqBody, 'utf8')
                };
                const mockRes2 = {
                    request: () => mockReq2,
                    url: () => 'https://diagnostic.example.test/request-2',
                    status: () => 200,
                    statusText: () => 'OK',
                    headers: () => ({ 'content-type': 'application/json' }),
                    headersArray: async () => [{ name: 'content-type', value: 'application/json' }],
                    async body() {
                        responseBodyReads += 1;
                        return Buffer.from(session2ResBody, 'utf8');
                    },
                    serverAddr: async () => ({ ipAddress: '192.0.2.10', port: 443 }),
                    securityDetails: async () => ({ protocol: 'TLS 1.3' })
                };

                profileSession2.context.emit('request', mockReq2);
                await new Promise((resolve) => setImmediate(resolve));
                profileSession2.context.emit('response', mockRes2);
                await new Promise((resolve) => setImmediate(resolve));
                profileSession2.context.emit('requestfinished', mockReq2);
                await new Promise((resolve) => setImmediate(resolve));

                assert.equal(await profileSession2.stop(), true);

                const integrityAfterSession2 = verifyTrafficIntegrity(trafficDir);
                assert.equal(
                    integrityAfterSession2.valid,
                    true,
                    `Expected valid multi-session traffic integrity after Session 2, got errors: ${integrityAfterSession2.errors.join('; ')}`
                );
                assert.ok(
                    integrityAfterSession2.eventCount >= session1EventCount + 2,
                    `Expected multi-session eventCount (${integrityAfterSession2.eventCount}) to include Session 1 (${session1EventCount}) and Session 2 events`
                );
                assert.notEqual(integrityAfterSession2.chainHeadHash, session1ChainHead);
                assert.equal(integrityAfterSession2.verifiedPayloads, 2);

                const finalIndex = JSON.parse(
                    fs.readFileSync(path.join(trafficDir, 'attribution-index.json'), 'utf8')
                );
                assert.equal(finalIndex.integrity.eventCount, integrityAfterSession2.eventCount);
                assert.equal(Object.keys(finalIndex.integrity.payloadManifest).length, 2);

                // Verify request payloads and response metadata from both sessions.
                const ndjsonLines = fs
                    .readFileSync(path.join(trafficDir, 'traffic.ndjson'), 'utf8')
                    .trim()
                    .split('\n')
                    .map((l) => JSON.parse(l));
                assert.equal(ndjsonLines.length, integrityAfterSession2.eventCount);
                const payloadEvents = ndjsonLines.filter((e) => e.payloadFile);
                assert.equal(payloadEvents.length, 2);
                assert.ok(payloadEvents.every((event) => event.type === 'egress'));
                const responses = ndjsonLines.filter((event) => event.type === 'ingress');
                assert.equal(responses.length, 2);
                assert.ok(responses.every((event) =>
                    event.status === 200 && event.bodyOmittedReason === 'unbounded-response-reader'
                ));
                assert.equal(responseBodyReads, 0);
                for (const ev of payloadEvents) {
                    assert.ok(
                        finalIndex.integrity.payloadManifest[ev.payloadFile],
                        `Expected payloadManifest to include ${ev.payloadFile}`
                    );
                    assert.equal(
                        fs.existsSync(path.join(trafficDir, ev.payloadFile)),
                        true,
                        `Expected payload file ${ev.payloadFile} to exist on disk`
                    );
                }

                await profileSession2.delete();
                unregisterProcessCleanupHooks();
            }
        );

        console.log(`\n🎉 All ${passedTests} Camoufox multi-context isolation & storage test suites passed!`);
    } finally {
        unregisterProcessCleanupHooks();
        setCamoufoxModule(null);
        fs.rmSync(tempProfilesDir, { recursive: true, force: true });
    }
}

runTests().catch((err) => {
    console.error('\n❌ Camoufox isolation test suite failed:', err);
    process.exit(1);
});
