import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

const WAIT_MS = 5_000;
const WAIT_INTERVAL_MS = 25;
const waitBuffer = new Int32Array(new SharedArrayBuffer(4));
const LOCK_COLLISION = new Set(['EEXIST', 'ENOTEMPTY', 'EPERM', 'EACCES', 'EISDIR', 'ENOTDIR']);
const OWNER_NAME = /^owner-([1-9][0-9]*)-[a-f0-9-]{36}$/;

function lockFailure(message) {
    return Object.assign(new Error(message), { code: 'ACCOUNT_OUTPUT_LOCK_FAILED' });
}

function removeEmptyLock(directory) {
    try {
        fs.rmdirSync(directory);
    } catch (error) {
        // A waiter can publish a new, nonempty lock as soon as the old owner is gone.
        if (error.code !== 'ENOENT' && error.code !== 'ENOTEMPTY' && error.code !== 'EEXIST') throw error;
    }
}

function removeOwner(directory, owner) {
    try {
        fs.unlinkSync(path.join(directory, owner));
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
    }
    removeEmptyLock(directory);
}

function discardDeadLock(directory, label) {
    let owners;
    try {
        const existing = fs.lstatSync(directory);
        if (!existing.isDirectory() || (typeof process.geteuid === 'function' && existing.uid !== process.geteuid())) {
            throw lockFailure(`Invalid ${label} writer lock. Inspect ${label}.lock with all writers stopped.`);
        }
        owners = fs.readdirSync(directory);
    } catch (error) {
        if (error.code === 'ENOENT') return;
        throw error;
    }

    if (owners.length === 0) {
        removeEmptyLock(directory);
        return;
    }
    const [owner] = owners;
    const pid = Number(OWNER_NAME.exec(owner)?.[1]);
    if (owners.length !== 1 || !Number.isInteger(pid) || pid > 0x7fff_ffff) {
        throw lockFailure(`Invalid ${label} writer lock. Inspect ${label}.lock with all writers stopped.`);
    }
    try {
        process.kill(pid, 0);
    } catch (error) {
        if (error.code === 'ESRCH') removeOwner(directory, owner);
        else if (error.code !== 'EPERM') throw error;
    }
}

export function withAccountOutputLock(filePath, operation) {
    const directory = `${path.resolve(filePath)}.lock`;
    const label = path.basename(filePath);
    const id = randomUUID();
    const owner = `owner-${process.pid}-${id}`;
    const staging = path.join(path.dirname(directory), `.${label}.writer-${id}.tmp`);
    fs.mkdirSync(staging, { mode: 0o700 });
    try {
        // Publish the already nonempty directory atomically. A stopped writer's
        // unique owner name lets a later process remove only that owner's entry.
        fs.closeSync(fs.openSync(path.join(staging, owner), 'wx', 0o600));
        const deadline = performance.now() + WAIT_MS;
        for (;;) {
            try {
                fs.renameSync(staging, directory);
                break;
            } catch (error) {
                if (!LOCK_COLLISION.has(error.code)) throw error;
                discardDeadLock(directory, label);
                if (performance.now() >= deadline) {
                    throw lockFailure(`Timed out waiting for the ${label} writer lock. Inspect ${label}.lock with all writers stopped.`);
                }
                Atomics.wait(waitBuffer, 0, 0, WAIT_INTERVAL_MS);
            }
        }
        try {
            return operation();
        } finally {
            removeOwner(directory, owner);
        }
    } finally {
        fs.rmSync(staging, { recursive: true, force: true });
    }
}
