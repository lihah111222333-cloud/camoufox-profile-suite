import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { pathToFileURL } from 'node:url';
import dotenv from 'dotenv';

const providers = [['GPM', 'gpmlogin'], ['Dolphin', 'dolphin']];
const fixtureKey = Symbol.for('managed-ownership-fixture');
const reference = 'globalThis[Symbol.for("managed-ownership-fixture")]';
const fixture = { dotenv };
const profiles = {};
let directory;
let output;

before(async () => {
    directory = await mkdtemp(path.join(tmpdir(), 'managed-ownership-'));
    await cp(new URL('../../src/', import.meta.url), path.join(directory, 'src'), { recursive: true });
    await writeFile(path.join(directory, 'package.json'), '{"type":"module"}');
    Object.assign(process.env, {
        PROFILE_SERVICE: 'gpm',
        GPM_API_URL: 'https://gpm-fixture.invalid',
        DOLPHIN_API_URL: 'https://dolphin-fixture.invalid',
        DOLPHIN_API_KEY: 'synthetic-dolphin-key',
        SMS_VERIFY_API_KEY: 'synthetic-unused-sms-key',
        GMAIL_CREATOR_STATE_DIR: path.join(directory, 'state'),
        GMAIL_CREATOR_LEGACY_DIR: path.join(directory, 'legacy'),
        LOG_LEVEL: 'silent'
    });
    globalThis[fixtureKey] = fixture;

    const replacements = {
        axios: [
            'module.exports = { create: () => ({',
            '    get: url => ' + reference + '.send("GET", url),',
            '    post: (url, body) => ' + reference + '.send("POST", url, body)',
            '}) };'
        ].join('\n'),
        dotenv: 'module.exports = ' + reference + '.dotenv;',
        'puppeteer-core': 'module.exports = { connect: () => ' + reference + '.connect() };',
        ws: [
            'const { EventEmitter } = require("node:events");',
            'module.exports = class extends EventEmitter {',
            '    constructor() { super(); queueMicrotask(() => this.emit("open")); }',
            '    terminate() { this.emit("close"); }',
            '    close() { this.terminate(); }',
            '};'
        ].join('\n')
    };
    for (const [dependency, source] of Object.entries(replacements)) {
        const target = path.join(directory, 'node_modules', dependency);
        await mkdir(target, { recursive: true });
        await writeFile(path.join(target, 'index.js'), source);
    }
    const load = filename => import(pathToFileURL(path.join(directory, 'src', filename)).href);
    for (const [, name] of providers) {
        profiles[name] = (await load(name + '/profile.js')).default;
    }
    output = await load('utils/account-results.js');
});

after(async () => {
    delete globalThis[fixtureKey];
    if (directory) await rm(directory, { recursive: true, force: true });
});

async function failureOf(promise) {
    try {
        await promise;
    } catch (error) {
        return error;
    }
    assert.fail('Expected a rejected operation');
}

function removeConnection(code) {
    return Object.assign(new Error('Synthetic transport failure'), { code, request: {} });
}

for (const [provider, name] of providers) {
    test(provider + ' preserves the original shutdown receipt when a dispatched start loses its response', async () => {
        for (const delivery of ['lost', 'acknowledged', 'not-sent', 'refused']) {
            const profileId = name + '-' + delivery;
            const otherProfileId = 'other-profile';
            const running = new Map([[profileId, false], [otherProfileId, true]]);
            const requests = [];
            const reason = new Error('Synthetic cancellation');
            const profile = new profiles[name](profileId);
            let cancellation = new AbortController();
            fixture.connect = () => assert.fail('Cancelled startup must not connect');
            fixture.send = async (_method, url, body) => {
                const route = new URL(url).pathname;
                if (route.includes('/stop/') || route === '/api/browser/closeProfiles') {
                    const id = body ? body.profileIds[0] : route.split('/').at(-1);
                    requests.push(['stop', id]);
                    running.set(id, false);
                    return { status: 204 };
                }
                const id = body ? body.profileId : route.split('/').at(-1);
                requests.push(['start', id]);
                cancellation.abort(reason);
                if (delivery === 'not-sent') throw removeConnection('ECONNREFUSED');
                if (delivery === 'refused') {
                    throw Object.assign(new Error('Synthetic controller refusal'), { response: { status: 403 } });
                }
                running.set(id, true);
                if (delivery === 'lost') throw removeConnection('ECONNRESET');
                const endpoint = 'wss://' + new URL(url).hostname + '/devtools/browser/fixture';
                return {
                    status: 200,
                    data: name === 'gpmlogin' ? { remote_debugging_address: endpoint } : { ws: endpoint }
                };
            };

            const first = await failureOf(profile.start({ signal: cancellation.signal }));
            const unknown = delivery === 'lost' || delivery === 'acknowledged';
            assert.equal(running.get(profileId), unknown, delivery);
            assert.equal(running.get(otherProfileId), true, delivery);
            assert.equal(first.profileCleanup, unknown ? 'stop-unconfirmed' : undefined, delivery);
            assert.equal(first.profileId, unknown ? profileId : undefined, delivery);
            if (delivery === 'lost') assert.equal(first.cause.transportCode, 'ECONNRESET');
            if (delivery === 'acknowledged') assert.equal(first.cause, reason);

            cancellation = new AbortController();
            const second = await failureOf(profile.start({ signal: cancellation.signal }));
            assert.equal(second.profileCleanup, first.profileCleanup, delivery);
            assert.deepEqual(requests, unknown ? [['start', profileId]] : [['start', profileId], ['start', profileId]]);
            if (!unknown) continue;

            const file = path.join(directory, profileId + '-results.json');
            const receipt = await output.appendAccountResultAsync(file, {
                success: false,
                profileId: first.profileId,
                profileType: provider,
                profileCleanup: first.profileCleanup
            });
            const [saved] = JSON.parse(await readFile(file, 'utf8'));
            assert.equal(saved.profileId, profileId);
            assert.equal(saved.profileCleanup, 'stop-unconfirmed');
            assert.equal(output.needsProfileCleanupReview(saved.profileCleanup), true);

            assert.equal(await profile.stop(), true);
            assert.equal(running.get(profileId), false);
            assert.equal(running.get(otherProfileId), true);
            assert.deepEqual(requests, [['start', profileId], ['stop', profileId]]);
            const confirmed = await output.recordAccountCleanupAsync(file, receipt.resultId, 'stopped');
            assert.equal(confirmed.profileId, profileId);
            assert.equal(confirmed.profileCleanup, 'stopped');
        }
    });

    test(provider + ' reports a borrowed tab without a page receipt and protects manual tabs', async t => {
        const originalTimeout = globalThis.setTimeout;
        t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) =>
            originalTimeout(callback, [2000, 3000].includes(delay) ? 0 : delay, ...args));
        for (const delivered of [false, true]) {
            const profileId = name + '-borrowed';
            const profile = new profiles[name](profileId, 'wss://borrowed.invalid/devtools/browser/fixture');
            const cancellation = new AbortController();
            const reason = new Error('Synthetic cancellation after page creation');
            const targetId = '0123456789abcdef0123456789abcdef';
            const tabs = new Set(['manual']);
            const closed = [];
            const restRequests = [];
            let connects = 0;
            let connected = true;
            fixture.send = async method => {
                restRequests.push(method);
                assert.fail('Borrowed connection must not send REST actions');
            };
            fixture.connect = () => {
                connects++;
                return {
                    isConnected: () => connected,
                    async pages() {
                        return [{
                            isClosed: () => !tabs.has('manual'),
                            async close() { closed.push('manual'); tabs.delete('manual'); }
                        }];
                    },
                    async newPage() {
                        tabs.add(targetId);
                        cancellation.abort(reason);
                        if (!delivered) {
                            connected = false;
                            throw removeConnection('ECONNRESET');
                        }
                        return {
                            isClosed: () => !tabs.has(targetId),
                            target: () => ({ _targetId: targetId }),
                            async close() { closed.push(targetId); tabs.delete(targetId); }
                        };
                    },
                    async disconnect() { connected = false; }
                };
            };

            const starting = await failureOf(profile.start({ signal: cancellation.signal }));
            if (delivered) {
                assert.equal(starting, reason);
                assert.equal(await profile.stop(), false);
                assert.deepEqual(closed, [targetId]);
                assert.deepEqual([...tabs], ['manual']);
            } else {
                const pending = {
                    profileId, profileCleanup: 'stop-unconfirmed', targetIds: [], unresolvedPageCount: 1
                };
                assert.deepEqual({ ...starting }, pending);
                await assert.rejects(profile.stop(), pending);
                await assert.rejects(profile.start(), pending);
                await assert.rejects(profile.stop(), pending);
                assert.deepEqual(closed, []);
                assert.deepEqual([...tabs], ['manual', targetId]);
            }
            assert.equal(connects, 1);
            assert.deepEqual(restRequests, []);
        }
    });
}
