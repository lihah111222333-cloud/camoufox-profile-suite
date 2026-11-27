import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
    getSignupStage,
    ManualSignupRequiredError
} from '../../src/gmail/credential-handoff.js';

const GOOGLE_ACCOUNTS_ORIGIN = 'https://accounts.google.com';
const RECOVERY_URL = `${GOOGLE_ACCOUNTS_ORIGIN}/v3/signin/addrecoveryemail?signup=fixture`;
const CONFIRMATION_URL = `${GOOGLE_ACCOUNTS_ORIGIN}/v3/signin/confirmation`;
const PHONE_URL = `${GOOGLE_ACCOUNTS_ORIGIN}/v3/signin/collectemailphone`;

test('Signup stage classification requires an exact HTTPS origin and a pathname step', () => {
    assert.equal(getSignupStage(RECOVERY_URL), 'recovery-email');
    assert.equal(getSignupStage(PHONE_URL), 'phone');
    assert.equal(getSignupStage(CONFIRMATION_URL), 'confirmation');
    assert.equal(getSignupStage(`${GOOGLE_ACCOUNTS_ORIGIN}/?next=addrecoveryemail`), 'unknown');
    assert.equal(getSignupStage(`${GOOGLE_ACCOUNTS_ORIGIN}/addrecoveryemail-notice`), 'unknown');
    assert.equal(getSignupStage('https://myaccount.google.com/'), 'account-home');

    for (const address of [
        'http://accounts.google.com/v3/signin/addrecoveryemail',
        'https://accounts.google.com:8443/v3/signin/addrecoveryemail',
        'https://accounts.google.com.example.invalid/v3/signin/addrecoveryemail',
        'https://fixture@accounts.google.com/v3/signin/addrecoveryemail',
        'blob:https://accounts.google.com/document',
        'https://example.invalid/?continue=https://accounts.google.com'
    ]) {
        assert.equal(getSignupStage(address), null);
    }
});

test('Manual signup reports a stage without directing the operator to the managed page', () => {
    for (const stage of ['password', 'verification', 'recovery-email', 'untrusted-page', 'completion']) {
        const error = new ManualSignupRequiredError(stage);
        assert.equal(error.code, 'MANUAL_SIGNUP_REQUIRED');
        assert.equal(error.stage, stage);
        assert.equal(error.message, 'Manual signup is required');
    }
});

test('App diagnostics omit credentials and preserve private log permissions across runs', async t => {
    const scratch = await mkdtemp(path.join(tmpdir(), 'gmail-credential-log-'));
    t.after(() => rm(scratch, { recursive: true, force: true }));
    const files = [
        'src/utils/logger.js',
        'src/utils/private-storage.js',
        'src/utils/private-env.js',
        'src/utils/state-paths.js',
        'src/utils/cli-counts.js',
        'src/gmail/credential-handoff.js',
        'src/gmail/page-detector.js',
        'src/captcha/omo-handler.js',
        'src/config.js',
        'scripts/omocaptcha-extension.js'
    ];
    await writeFile(path.join(scratch, 'package.json'), '{"type":"module"}\n');
    await Promise.all(files.map(async file => {
        const destination = path.join(scratch, file);
        await mkdir(path.dirname(destination), { recursive: true });
        await copyFile(new URL(`../../${file}`, import.meta.url), destination);
    }));

    const logDirectory = path.join(scratch, 'logs');
    const activeLog = path.join(logDirectory, 'app-2030-01-02.log');
    const archivedLog = path.join(logDirectory, 'app-2030-01-01.log');
    const archivedContents = 'An existing fixture log file\n';
    const hasPosixModes = process.platform !== 'win32';
    const permissions = async file => (await stat(file)).mode & 0o777;
    await mkdir(logDirectory);
    await writeFile(archivedLog, archivedContents);
    if (hasPosixModes) {
        await chmod(logDirectory, 0o755);
        await chmod(archivedLog, 0o644);
    }

    const fakeSecret = 'synthetic-credential-fixture-123';
    const runLogger = source => spawnSync(process.execPath, ['--input-type=module', '-e', `
        const RealDate = Date;
        globalThis.Date = class extends RealDate {
            constructor(...args) {
                super(...(args.length ? args : ['2030-01-02T12:00:00Z']));
            }
        };
        const { default: logger } = await import('./src/utils/logger.js');
        ${source}
    `], {
        cwd: scratch,
        env: {
            NODE_OPTIONS: process.env.NODE_OPTIONS,
            GMAIL_CREATOR_STATE_DIR: scratch,
            PROFILE_SERVICE: 'gpm',
            OMOCAPTCHA_KEY: fakeSecret,
            LOG_LEVEL: 'DEBUG'
        },
        encoding: 'utf8'
    });
    const result = runLogger(`
        import assert from 'node:assert/strict';
        const { detectGmailPage, waitForElement } = await import('./src/gmail/page-detector.js');
        const main = await import('./src/captcha/omo-handler.js');
        const legacy = await import('./scripts/omocaptcha-extension.js');

        const secret = process.env.OMOCAPTCHA_KEY;
        const data = {
            password: secret, expected: secret, entered: secret, text: secret, phoneCode: secret,
            error: new TypeError(secret), stack: secret, status: 'fixture-status',
            url: 'https://accounts.google.com/' + secret + '?code=' + secret,
            nested: { code: secret, key: secret, omoCaptchaKey: secret, 'SMS_VERIFY_API_KEY': secret }
        };
        data.circular = data;
        logger.debug('Credential-safe diagnostic fixture', data);
        logger.warn('Fallback diagnostic fixture', { error: secret });
        logger.warn('Serialization failure fixture', {
            toString: () => secret,
            toJSON: () => { throw new Error(secret); }
        });

        const profile = new Proxy({}, {
            get(_target, property) {
                assert.match(property, /^_camoufox/);
                return undefined;
            }
        });
        for (const handler of [main, legacy]) {
            assert.equal(await handler.setupOMOCaptchaExtension(profile), false);
            assert.equal(await handler.setOMOCaptchaKeyViaAPI(profile), false);
            assert.equal(await handler.enterOMOCaptchaKey(profile), false);
        }

        let trace;
        const classification = await detectGmailPage({
            url: () => 'https://accounts.google.com/challenge/sms?code=' + secret + '#' + secret,
            setTrafficStep: (_step, fields) => { trace = fields; }
        });
        assert.deepEqual(classification, {
            type: 'VERIFICATION_CODE', elements: ['code'], action: 'enter_code'
        });
        assert.deepEqual(trace, { pageType: 'VERIFICATION_CODE', action: 'enter_code' });

        let inspections = 0;
        for (const address of [
            'https://' + secret + '.example.invalid/help?route=/signup/phone',
            'https://accounts.google.com/example/signup/name',
            'https://accounts.google.com/signup/name-old',
            'https://accounts.google.com/?next=/signup/phone',
            'https://accounts.google.com/#/challenge/sms',
            'https://accounts.google.com.example.invalid/signup/name',
            'http://accounts.google.com/signup/name',
            'blob:https://accounts.google.com/signup/name',
            'https://fixture@accounts.google.com/signup/name'
        ]) {
            trace = null;
            assert.deepEqual(await detectGmailPage({
                url: () => address,
                $: async () => { inspections++; return {}; },
                evaluate: async () => { inspections++; },
                waitForTimeout: async () => { inspections++; },
                setTrafficStep: (_step, fields) => { trace = fields; }
            }), { type: 'UNKNOWN', elements: [] });
            assert.equal(trace, null);
        }
        assert.equal(inspections, 0);

        let address = 'https://accounts.google.com/ServiceLogin';
        assert.deepEqual(await detectGmailPage({
            url: () => address,
            $: async () => { address = 'https://diagnostic-fixture.invalid/'; return {}; },
            setTrafficStep: (_step, fields) => { trace = fields; }
        }), { type: 'UNKNOWN', elements: [] });
        assert.equal(trace, null);

        assert.equal(await waitForElement({
            async waitForSelector() { throw new Error(secret); }
        }, 'input[data-fixture="' + secret + '"]'), null);
    `);
    assert.equal(result.status, 0, result.stderr);
    const firstRunFile = await readFile(activeLog, 'utf8');
    for (const output of [result.stdout, result.stderr, firstRunFile]) {
        assert.ok(!output.includes(fakeSecret));
    }
    for (const output of [result.stdout, firstRunFile]) {
        assert.match(output, /fixture-status/);
        assert.match(output, /https:\/\/accounts\.google\.com/);
        assert.match(output, /Unserializable log data/);
        assert.match(output, /Configure OMO Captcha credentials manually/);
    }

    if (hasPosixModes) {
        assert.equal(await permissions(logDirectory), 0o700);
        assert.equal(await permissions(activeLog), 0o600);
        await chmod(logDirectory, 0o755);
        await chmod(activeLog, 0o644);
    }

    const second = runLogger("logger.info('Second fixture log entry', { password: process.env.OMOCAPTCHA_KEY });");
    assert.equal(second.status, 0, second.stderr);
    const secondRunFile = await readFile(activeLog, 'utf8');
    assert.ok(secondRunFile.startsWith(firstRunFile));
    assert.match(secondRunFile, /Second fixture log entry/);
    for (const output of [second.stdout, second.stderr, secondRunFile]) {
        assert.ok(!output.includes(fakeSecret));
    }
    assert.equal(await readFile(archivedLog, 'utf8'), archivedContents);

    if (hasPosixModes) {
        assert.equal(await permissions(logDirectory), 0o700);
        assert.equal(await permissions(activeLog), 0o600);
        assert.equal(await permissions(archivedLog), 0o644);

        const unrelatedFile = path.join(scratch, 'unrelated.log');
        await writeFile(unrelatedFile, archivedContents);
        await chmod(unrelatedFile, 0o644);
        await rm(activeLog);
        await symlink(unrelatedFile, activeLog);
        const refused = runLogger("logger.warn('The log file should refuse a symbolic link');");
        assert.equal(refused.status, 0, refused.stderr);
        assert.equal(refused.stderr.trim(), 'Failed to write to the application log file');
        assert.equal(await readFile(unrelatedFile, 'utf8'), archivedContents);
        assert.equal(await permissions(unrelatedFile), 0o644);
    }
});
