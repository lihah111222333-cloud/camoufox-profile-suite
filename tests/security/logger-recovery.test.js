import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

const run = promisify(execFile);
const beforeMidnight = '2031-04-05T23:59:59.993Z';
const afterMidnight = '2031-04-06T00:00:00.010Z';
const logName = 'app-2031-04-05.log';
const loggerUrl = new URL('../../src/utils/logger.js', import.meta.url).href;
const script = `
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';

let now = process.env.FIXTURE_TIME;
const RealDate = Date;
globalThis.Date = class extends RealDate {
    constructor(...args) { super(...(args.length ? args : [now])); }
};

const { default: logger } = await import(process.env.FIXTURE_LOGGER);
const mode = process.argv[2];
if (mode === 'normal') {
    logger.info(process.argv[3]);
} else {
    logger.info('Before the fault');
    const expected = fs.statSync(process.env.FIXTURE_LOG);
    const writeSync = fs.writeSync;
    const writeFileSync = fs.writeFileSync;
    let injected = 0;
    const isLog = fd => {
        if (typeof fd !== 'number') return false;
        const actual = fs.fstatSync(fd);
        return actual.dev === expected.dev && actual.ino === expected.ino;
    };
    const diskFull = () => Object.assign(new Error('Fixture disk is full'), { code: 'ENOSPC' });
    function interruptedWrite(fd, data) {
        injected++;
        let count = 0;
        if (mode === 'short') {
            const bytes = Buffer.from(data);
            const split = bytes.indexOf(Buffer.from('雪'));
            assert.ok(split >= 0);
            count = writeSync(fd, bytes.subarray(0, split + 1));
        }
        const concurrent = spawnSync(process.execPath, [process.argv[1], 'normal', 'Concurrent append'], {
            encoding: 'utf8', timeout: 5000
        });
        assert.equal(concurrent.status, 0, concurrent.stderr);
        assert.equal(concurrent.stderr, '');
        return count;
    }
    fs.writeSync = (fd, data, ...rest) => {
        if (!isLog(fd)) return writeSync(fd, data, ...rest);
        const count = interruptedWrite(fd, data);
        if (mode === 'empty') throw diskFull();
        return count;
    };
    fs.writeFileSync = (fd, data, ...rest) => {
        // Exercise the same partial write on runtimes with the writeFileSync UTF-8 fast path.
        if (!isLog(fd)) return writeFileSync(fd, data, ...rest);
        interruptedWrite(fd, data);
        throw diskFull();
    };
    try {
        logger.info('Interrupted 雪');
    } finally {
        fs.writeSync = writeSync;
        fs.writeFileSync = writeFileSync;
    }
    assert.equal(injected, 1);
    logger.info('After the fault');
    now = process.env.FIXTURE_LATER;
    logger.info('After midnight');
}
`;
const firstLine = message => '[' + beforeMidnight + '] [INFO] ' + message;

async function fixture(t) {
    const state = await mkdtemp(path.join(tmpdir(), 'logger-recovery-'));
    t.after(() => rm(state, { recursive: true, force: true }));
    const program = path.join(state, 'writer.mjs');
    await writeFile(program, script);
    const logs = path.join(state, 'logs');
    return {
        logs,
        log: path.join(logs, logName),
        options: {
            env: {
                ...process.env,
                GMAIL_CREATOR_STATE_DIR: state,
                LOG_LEVEL: 'INFO',
                FIXTURE_LOGGER: loggerUrl,
                FIXTURE_TIME: beforeMidnight,
                FIXTURE_LATER: afterMidnight,
                FIXTURE_LOG: path.join(logs, logName)
            },
            timeout: 8_000
        },
        args: (...args) => [program, ...args]
    };
}

const lines = text => text.split('\n').filter(Boolean);

test('an application log short write preserves its bytes and separates an interleaved writer', async t => {
    const { log, logs, args, options } = await fixture(t);
    const child = spawnSync(process.execPath, args('short'), { ...options, encoding: 'utf8' });
    assert.equal(child.status, 0, child.error?.message || child.stderr);
    assert.equal(child.stderr, 'Failed to write to the application log file\n');
    assert.match(child.stdout, /Interrupted 雪/);
    assert.match(child.stdout, /After the fault/);
    const expectedPartial = Buffer.concat([Buffer.from(firstLine('Interrupted ')), Buffer.from([0xe9])]);
    const earlier = await readFile(log);
    const partialOffset = earlier.indexOf(expectedPartial);
    assert.ok(partialOffset > 0);
    assert.equal(earlier[partialOffset + expectedPartial.length], 0x0a);
    assert.deepEqual(lines(earlier.toString('utf8')), [
        firstLine('Before the fault'),
        firstLine('Interrupted \ufffd'),
        firstLine('Concurrent append'),
        firstLine('After the fault')
    ]);
    assert.deepEqual((await readdir(logs)).sort(), [logName, 'app-2031-04-06.log']);
    assert.deepEqual(lines(await readFile(path.join(logs, 'app-2031-04-06.log'), 'utf8')), [
        '[' + afterMidnight + '] [INFO] After midnight'
    ]);
});

test('an application log append still recovers when the disk writes zero bytes', async t => {
    const { log, args, options } = await fixture(t);
    const child = spawnSync(process.execPath, args('empty'), { ...options, encoding: 'utf8' });
    assert.equal(child.status, 0, child.error?.message || child.stderr);
    assert.equal(child.stderr, 'Failed to write to the application log file\n');
    assert.match(child.stdout, /Interrupted 雪/);
    assert.match(child.stdout, /After the fault/);
    assert.deepEqual(lines(await readFile(log, 'utf8')), [
        firstLine('Before the fault'),
        firstLine('Concurrent append'),
        firstLine('After the fault')
    ]);
});

test('concurrent application log writers preserve an old unfinished tail byte for byte', async t => {
    const { log, logs, args, options } = await fixture(t);
    await mkdir(logs, { mode: 0o700 });
    const oldContents = Buffer.from('[Old record]\n[Interrupted old log]');
    await writeFile(log, oldContents, { mode: 0o600 });
    const messages = Array.from({ length: 4 }, (_, index) => 'Writer ' + index);
    const writes = await Promise.all(messages.map(message => run(process.execPath, args('normal', message), options)));
    assert.ok(writes.every(write => !write.stderr));
    const recovered = await readFile(log);
    assert.deepEqual(recovered.subarray(0, oldContents.length), oldContents);
    assert.equal(recovered[oldContents.length], 0x0a);
    const newLines = lines(recovered.subarray(oldContents.length).toString('utf8')).sort();
    assert.deepEqual(newLines, messages.map(firstLine));
});
