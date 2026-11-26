import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { runInNewContext } from 'node:vm';

const stateDir = await mkdtemp(path.join(tmpdir(), 'gmail-signup-consent-'));
after(() => rm(stateDir, { recursive: true, force: true }));
const previousStateDir = process.env.GMAIL_CREATOR_STATE_DIR;
let createGmailAccount;
try {
    process.env.GMAIL_CREATOR_STATE_DIR = stateDir;
    ({ createGmailAccount } = await import('../../src/gmail/creator.js'));
} finally {
    if (previousStateDir === undefined) delete process.env.GMAIL_CREATOR_STATE_DIR;
    else process.env.GMAIL_CREATOR_STATE_DIR = previousStateDir;
}

const origin = 'https://accounts.google.com';
const nameUrl = origin + '/signup/name?fixture=1';
const usernameUrl = origin + '/signup/username?fixture=1';
const homeUrl = 'https://myaccount.google.com/u/1/?fixture=existing';
const account = Object.freeze({
    firstName: 'Fixture',
    lastName: 'Operator',
    username: 'fixture.candidate',
    email: 'fixture.candidate@example.invalid'
});
const manual = stage => ({ code: 'MANUAL_SIGNUP_REQUIRED', stage });

function formPage(address, { fields, labels = ['Next'], action = address, onInput, onClick } = {}, events) {
    const document = {};
    const form = { ownerDocument: document, isConnected: true, target: '', action };
    const control = () => ({
        ownerDocument: document,
        isConnected: true,
        getAttribute: () => null,
        getClientRects: () => [{}],
        hasAttribute: () => false
    });
    const inputs = fields.map(({ name, type = 'text', value = '' }) => ({
        ...control(),
        form,
        tagName: 'INPUT',
        type,
        value,
        matches: selector => selector.split(', ').includes('input[name="' + name + '"]'),
        dispatchEvent(event) {
            assert.equal(event.type, 'input');
            events.push([name, this.value]);
            onInput?.(form);
        }
    }));
    const buttons = labels.map(textContent => ({
        ...control(),
        form,
        tagName: 'BUTTON',
        type: 'submit',
        textContent,
        matches: () => false,
        click() {
            events.push(['click', textContent]);
            onClick?.();
        }
    }));
    form.elements = [...inputs, ...buttons];
    document.querySelectorAll = selector => selector === 'button'
        ? buttons : inputs.filter(input => input.matches(selector));
    return document;
}

function browserFixture({ initial, afterOpen, events, beforeEvaluation }) {
    let active = initial;
    let evaluations = 0;
    const changePage = state => { active = state; };
    return {
        changePage,
        page: {
            url: () => active.reported || active.address,
            async goto(address) {
                assert.equal(address, 'https://gmail.com');
                events.push(['open']);
                assert.ok(afterOpen);
                changePage(afterOpen);
            },
            async waitForTimeout() {},
            async evaluateHandle() {
                const expectedDocument = active.document;
                return {
                    async evaluate(operation, options) {
                        beforeEvaluation?.(++evaluations, changePage);
                        const location = new URL(active.address);
                        const window = {
                            origin: active.origin ?? location.origin,
                            getComputedStyle: () => ({ visibility: 'visible', opacity: '1' })
                        };
                        window.top = active.subframe ? {} : window;
                        return runInNewContext('(' + operation + ')(expectedDocument, options)', {
                            expectedDocument, options, document: active.document, location, window, URL, Event
                        });
                    },
                    async dispose() {}
                };
            }
        }
    };
}

const blank = { address: 'about:blank' };
const nameFields = [{ name: 'firstName' }, { name: 'lastName' }];

test('An existing Google Account home is manual completion and never a candidate success', async () => {
    const steps = [];
    await assert.rejects(createGmailAccount({ url: () => homeUrl }, account, {
        profile: { setStep: (step, data) => { steps.push([step, data]); } }
    }), manual('completion'));
    assert.deepEqual(steps.at(-1), ['gmail:manual-signup', { stage: 'completion' }]);
});

test('A unique verified Create account control opens signup only from an empty sign-in form', async () => {
    for (const existingIdentifier of ['', 'existing@example.invalid']) {
        const events = [];
        let menuOpened = false;
        const document = {
            querySelectorAll(selector) {
                if (selector === 'a') return menuOpened ? [createLink] : [];
                if (selector === 'div[role="button"]') return [toggle];
                return [identifier];
            }
        };
        const control = {
            ownerDocument: document, isConnected: true, getClientRects: () => [{}],
            getAttribute: () => null, hasAttribute: () => false, matches: () => false
        };
        const identifier = { ...control, value: existingIdentifier };
        const createLink = {
            ...control,
            textContent: 'Create account',
            href: nameUrl,
            target: '',
            click() {
                events.push(['link']);
                changePage({ address: nameUrl, document: namePage });
            }
        };
        const toggle = {
            ...control, textContent: 'Create account',
            click() {
                events.push(['menu']);
                menuOpened = true;
            }
        };
        const namePage = formPage(nameUrl, { fields: nameFields, labels: [] }, events);
        const { page, changePage } = browserFixture({
            initial: blank, afterOpen: { address: origin + '/v3/signin/identifier', document }, events
        });

        await assert.rejects(createGmailAccount(page, account), manual('completion'));
        assert.deepEqual(events, existingIdentifier ? [['open']] : [['open'], ['menu'], ['link']]);
    }
});

test('Verified ordinary controls advance while reaching Account home still requires human identity review', async () => {
    const events = [];
    const telemetry = [];
    const usernamePage = formPage(usernameUrl, {
        fields: [{ name: 'Username' }],
        onClick: () => changePage({ address: homeUrl })
    }, events);
    const namePage = formPage(nameUrl, {
        fields: nameFields,
        onClick: () => changePage({ address: usernameUrl, document: usernamePage })
    }, events);
    const { page, changePage } = browserFixture({
        initial: blank, afterOpen: { address: nameUrl, document: namePage }, events
    });

    await assert.rejects(createGmailAccount(page, account, {
        profile: { setStep: (step, data) => { telemetry.push([step, data]); } }
    }), manual('completion'));
    assert.deepEqual(telemetry, [
        ['gmail:init', {}],
        ['gmail:navigate-signup', {}],
        ['gmail:fill-name-form', {}],
        ['gmail:fill-username', {}],
        ['gmail:manual-signup', { stage: 'completion' }]
    ]);
    assert.deepEqual(events, [
        ['open'], ['firstName', account.firstName], ['lastName', account.lastName], ['click', 'Next'],
        ['Username', account.username], ['click', 'Next']
    ]);
});

test('A lookalike origin, opaque origin, subframe, or changed top-level document is read-only', async () => {
    const events = [];
    const document = formPage(nameUrl, { fields: nameFields }, events);
    for (const unsafe of [
        { address: 'https://accounts.google.com.example.invalid/signup/name', reported: nameUrl },
        { address: nameUrl, origin: 'null' },
        { address: nameUrl, subframe: true },
        { address: usernameUrl, reported: nameUrl }
    ]) {
        const { page } = browserFixture({
            initial: blank, afterOpen: { document, ...unsafe }, events
        });
        await assert.rejects(createGmailAccount(page, account), manual('untrusted-page'));
    }
    assert.deepEqual(events, Array(4).fill(['open']));

    const replacement = formPage(nameUrl, { fields: nameFields }, events);
    const { page } = browserFixture({
        initial: blank, afterOpen: { address: nameUrl, document }, events,
        beforeEvaluation: (count, changePage) => {
            if (count === 2) changePage({ address: nameUrl, document: replacement });
        }
    });
    await assert.rejects(createGmailAccount(page, account), manual('untrusted-page'));
    assert.deepEqual(events, Array(5).fill(['open']));
});

test('Incomplete, prefilled, mixed, or ambiguous forms hand off before input or submission', async () => {
    const events = [];
    const unsafeForms = [
        { fields: [nameFields[0]] },
        { fields: [{ name: 'firstName', value: 'Existing' }, nameFields[1]] },
        { fields: [...nameFields, { name: 'password', type: 'password' }] },
        { fields: [...nameFields, nameFields[0]] },
        { labels: ['Submit'] },
        { labels: ['Next', 'التالي'] },
        { action: 'https://example.invalid/' },
        { action: origin + '/challenge/sms' }
    ];
    for (const unsafe of unsafeForms) {
        const document = formPage(nameUrl, { fields: nameFields, ...unsafe }, events);
        const { page } = browserFixture({
            initial: blank, afterOpen: { address: nameUrl, document }, events
        });
        await assert.rejects(createGmailAccount(page, account), manual('completion'));
    }
    assert.deepEqual(events, Array(unsafeForms.length).fill(['open']));
});

test('Changed form action after input stops before entering more data or clicking Next', async () => {
    const events = [];
    const document = formPage(nameUrl, {
        fields: nameFields,
        onInput: form => { form.action = 'https://example.invalid/'; }
    }, events);
    const { page } = browserFixture({
        initial: blank, afterOpen: { address: nameUrl, document }, events
    });
    await assert.rejects(createGmailAccount(page, account), manual('completion'));
    assert.deepEqual(events, [['open'], ['firstName', account.firstName]]);
});

test('Existing sensitive signup steps hand off without touching the browser document', async () => {
    for (const [step, manualStage] of [
        ['/signup/password', 'password'],
        ['/challenge/sms', 'verification'],
        ['/v3/signin/addrecoveryemail', 'recovery-email'],
        ['/v3/signin/collectemailphone', 'verification'],
        ['/v3/signin/termsofservice', 'completion'],
        ['/v3/signin/confirmidentifier', 'completion'],
        ['/signup/username', 'completion']
    ]) {
        await assert.rejects(createGmailAccount({ url: () => origin + step }, account), manual(manualStage));
    }
});
