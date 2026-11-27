import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as wait } from 'node:timers/promises';
import { describeProcessOwner, processOwnerStatus, readProcessOwner } from './process-owner.js';

const WAIT_MS = 5_000;
const WAIT_INTERVAL_MS = 25;
const waitBuffer = new Int32Array(new SharedArrayBuffer(4));
const LOCK_COLLISION = new Set(['EEXIST', 'ENOTEMPTY', 'EPERM', 'EACCES', 'EISDIR', 'ENOTDIR']);
const OWNER_NAME = /^owner-([1-9][0-9]*)-[a-f0-9-]{36}$/;

function lockFailure(message) {
    return Object.assign(new Error(message), { code: 'ACCOUNT_OUTPUT_LOCK_FAILED' });
}

function invalidLock(label) {
    return lockFailure(`Invalid ${label} writer lock. Inspect ${label}.lock with all writers stopped.`);
}

function ownedByWriter(stat) {
    return typeof process.geteuid !== 'function' || stat.uid === process.geteuid();
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

function removeSnapshot(directory, owner, label) {
    const snapshot = path.join(directory, `${owner}.snapshot`);
    try {
        const stat = fs.lstatSync(snapshot);
        if (!stat.isFile() || stat.nlink !== 1 || !ownedByWriter(stat)) throw invalidLock(label);
        fs.unlinkSync(snapshot);
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
    }
}

function discardDeadLock(directory, label) {
    try {
        const existing = fs.lstatSync(directory);
        if (!existing.isDirectory() || !ownedByWriter(existing)) throw invalidLock(label);
        const entries = fs.readdirSync(directory);
        if (!entries.length) {
            removeEmptyLock(directory);
            return;
        }

        const owner = entries.find((entry) => OWNER_NAME.test(entry));
        const pid = Number(OWNER_NAME.exec(owner)?.[1]);
        if (!Number.isInteger(pid) || pid > 0x7fff_ffff ||
            entries.some((entry) => entry !== owner && entry !== `${owner}.snapshot`)) throw invalidLock(label);

        const identity = readProcessOwner(path.join(directory, owner));
        if (!identity || (!identity.host && entries.length !== 1)) throw invalidLock(label);
        const status = processOwnerStatus(pid, identity);
        if (status === 'dead') {
            if (identity.host) removeSnapshot(directory, owner, label);
            removeOwner(directory, owner);
        }
        return status;
    } catch (error) {
        // Release can remove the named marker while a waiter is reading it.
        if (error.code !== 'ENOENT') throw error;
    }
}

function warnCleanup(label) {
    process.emitWarning(`Could not finish cleaning up the ${label} writer lock. Inspect its lock files with all writers stopped.`, {
        code: 'ACCOUNT_OUTPUT_LOCK_CLEANUP_FAILED'
    });
}

function releaseLock(directory, staging, owner, label) {
    try {
        removeSnapshot(directory, owner, label);
        const entries = fs.readdirSync(directory);
        if (entries.length !== 1 || entries[0] !== owner) throw invalidLock(label);
        // Free the shared lock name first. A failure deleting the detached owner
        // marker then leaves no private snapshot and cannot block the next writer.
        let released = directory;
        try {
            fs.renameSync(directory, staging);
            released = staging;
        } catch {
            // The ordinary owner-specific removal is still safe if renaming failed.
        }
        removeOwner(released, owner);
    } catch {
        warnCleanup(label);
    }
}

function* acquireAccountOutputLock(filePath) {
    const directory = `${path.resolve(filePath)}.lock`;
    const label = path.basename(filePath);
    const id = randomUUID();
    const owner = `owner-${process.pid}-${id}`;
    const staging = path.join(path.dirname(directory), `.${label}.writer-${id}.tmp`);
    fs.mkdirSync(staging, { mode: 0o700 });
    let acquired = false;
    try {
        // Publish the already nonempty directory atomically. A stopped writer's
        // unique owner name lets a later process remove only that owner's entry.
        fs.writeFileSync(path.join(staging, owner), describeProcessOwner(), { flag: 'wx', mode: 0o600 });
        const deadline = performance.now() + WAIT_MS;
        for (;;) {
            try {
                fs.renameSync(staging, directory);
                acquired = true;
                return { directory, staging, owner, label };
            } catch (error) {
                if (!LOCK_COLLISION.has(error.code)) throw error;
                const status = discardDeadLock(directory, label);
                if (performance.now() >= deadline) {
                    if (status === 'unverified') {
                        throw lockFailure(`Timed out waiting for the ${label} writer lock. The owner could not be verified. Follow the lock recovery steps in ENV_VARIABLES.md.`);
                    }
                    throw lockFailure(`Timed out waiting for the ${label} writer lock. Inspect ${label}.lock with all writers stopped.`);
                }
                yield;
            }
        }
    } finally {
        if (!acquired) {
            try {
                removeOwner(staging, owner);
            } catch {
                warnCleanup(label);
            }
        }
    }
}

function runLocked({ directory, staging, owner, label }, operation) {
    try {
        return operation(path.join(directory, `${owner}.snapshot`));
    } finally {
        releaseLock(directory, staging, owner, label);
    }
}

export function withAccountOutputLock(filePath, operation) {
    const acquisition = acquireAccountOutputLock(filePath);
    try {
        let lock = acquisition.next();
        while (!lock.done) {
            Atomics.wait(waitBuffer, 0, 0, WAIT_INTERVAL_MS);
            lock = acquisition.next();
        }
        return runLocked(lock.value, operation);
    } finally {
        acquisition.return();
    }
}

export async function withAccountOutputLockAsync(filePath, operation, { signal } = {}) {
    signal?.throwIfAborted();
    const acquisition = acquireAccountOutputLock(filePath);
    try {
        let lock = acquisition.next();
        while (!lock.done) {
            try {
                await wait(WAIT_INTERVAL_MS, undefined, { signal });
            } catch (error) {
                signal?.throwIfAborted();
                throw error;
            }
            signal?.throwIfAborted();
            lock = acquisition.next();
        }
        return runLocked(lock.value, operation);
    } finally {
        acquisition.return();
    }
}
