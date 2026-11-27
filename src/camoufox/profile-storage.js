import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { listCaptureDirectory, readCaptureFile } from './capture-io.js';
import {
    ensurePrivateDirectory,
    readPrivateFile,
    restrictPrivateFile,
    writePrivateFile
} from '../utils/private-storage.js';
import { describeProcessOwner, processOwnerStatus, readProcessOwner } from '../utils/process-owner.js';

// This directory name cannot be a valid profile ID.
export const PROFILE_LEASE_DIRECTORY = '.camoufox-leases~';
const NATIVE_EXIT_MARKER = '~native-exit-unconfirmed';

const EMPTY_STORAGE_STATE = { cookies: [], origins: [] };
const PRIVATE_SNAPSHOT = { requireOwner: true };
const EXISTING_PROFILE = { ...PRIVATE_SNAPSHOT, create: false };
const SNAPSHOT_OWNER_NAME = /^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.(-?\d+)\.(-?\d+)\.owner$/;
const NATIVE_LOG_NAMES = {
    sslKeyLogPath: 'sslkeylog.txt',
    neckoMozLogPath: 'necko-pre-tls.moz_log'
};

export function validateProfileId(value) {
    const id = typeof value === 'string' || Number.isSafeInteger(value) ? String(value) : '';
    const windowsAlias = process.platform === 'win32' &&
        (id.endsWith('.') || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(id));
    if (!/^[a-zA-Z0-9._-]+$/.test(id) || id === '.' || id === '..' || windowsAlias) {
        throw new TypeError('Invalid Camoufox profile ID');
    }
    return id;
}

export function resolveProfilesRoot(profilesDir, create = false) {
    const requestedRoot = path.resolve(profilesDir);
    let root;
    try {
        root = fs.realpathSync.native(requestedRoot);
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        if (!create) return requestedRoot;
        ensurePrivateDirectory(requestedRoot);
        root = fs.realpathSync.native(requestedRoot);
    }
    if (create && !fs.statSync(root).isDirectory()) {
        throw new Error('Camoufox profiles root is not a directory');
    }
    return root;
}

export function locateProfile(profileId, profilesDir, create = false) {
    const id = validateProfileId(profileId);
    const root = resolveProfilesRoot(profilesDir, create);
    return {
        id,
        profilesDir: root,
        profileDir: path.join(root, id),
        key: JSON.stringify([root, id])
    };
}

export function inspectProfileDirectory({ profileDir }) {
    try {
        const stats = fs.lstatSync(profileDir, { bigint: true });
        if (!stats.isDirectory() || fs.realpathSync.native(profileDir) !== profileDir) {
            throw new Error('Expected a direct Camoufox profile directory');
        }
        return stats;
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
    }
}

function parseProfileMetadata(raw, expectedId) {
    let metadata;
    try {
        metadata = JSON.parse(raw);
    } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
        throw Object.assign(new SyntaxError('Invalid Camoufox profile metadata JSON'), {
            code: 'ERR_CAMOUFOX_PROFILE_METADATA_INVALID'
        });
    }
    return requireProfileIdentity(metadata, expectedId);
}

function readProfileMetadataFile(location) {
    const metadataPath = path.join(location.profileDir, 'profile.json');
    return parseProfileMetadata(readPrivateFile(metadataPath), location.id);
}

function requireProfileIdentity(metadata, expectedId) {
    const ids = [metadata?.id, metadata?.profileId].filter((id) => id !== undefined);
    if (ids.length === 0 || ids.some((id) =>
        (typeof id !== 'string' && !Number.isSafeInteger(id)) || String(id) !== expectedId
    )) {
        throw new Error(`Camoufox profile metadata does not match ID: ${expectedId}`);
    }
    // Reopening republishes the metadata without the retired host calibration.
    delete metadata.gpuPerformance;
    return metadata;
}

export function readProfileMetadata(location, { readOnly = false } = {}) {
    if (!inspectProfileDirectory(location)) return null;
    if (!readOnly) return readProfileMetadataFile(location);
    const raw = readCaptureFile(location.profileDir, 'profile.json', { trustedLocal: true });
    return parseProfileMetadata(raw.toString('utf8'), location.id);
}

export function inspectProfileForDeletion(location) {
    const stats = inspectProfileDirectory(location);
    if (!stats) return null;
    const metadata = readProfileMetadataFile(location);
    return { dev: stats.dev, ino: stats.ino, generation: metadata._storageGeneration };
}

export function stampProfileIdentity(location, metadataPath, metadata) {
    const stats = inspectProfileDirectory(location);
    if (!stats) throw new Error('Camoufox profile directory is missing');
    const generation = randomUUID();
    writePrivateFile(metadataPath, JSON.stringify({ ...metadata, _storageGeneration: generation }, null, 2));
    return { dev: stats.dev, ino: stats.ino, generation };
}

export function assertProfileIdentity(location, identity) {
    const current = inspectProfileForDeletion(location);
    if (!current || !identity || current.dev !== identity.dev ||
        current.ino !== identity.ino || current.generation !== identity.generation) {
        throw Object.assign(new Error('Camoufox profile no longer matches the acquired storage identity'), {
            code: 'ERR_CAMOUFOX_PROFILE_STALE'
        });
    }
}

function leaseOwner(directory) {
    if (!inspectProfileDirectory({ profileDir: directory })) return null;
    try {
        const entries = fs.readdirSync(directory, { withFileTypes: true });
        const nativeExit = entries.find(({ name }) => name === NATIVE_EXIT_MARKER);
        if (nativeExit && !nativeExit.isFile()) throw new Error('Invalid Camoufox profile lease');
        const owners = entries.filter(({ name }) => name !== NATIVE_EXIT_MARKER);
        if (!owners.length) return nativeExit ? { nativeExitUnconfirmed: true } : null;
        const [owner] = owners;
        const pid = Number(/^([1-9]\d*)-[0-9a-f-]{36}$/.exec(owner.name)?.[1]);
        if (owners.length !== 1 || !owner.isFile() || !Number.isInteger(pid) || pid > 0x7fff_ffff) {
            throw new Error('Invalid Camoufox profile lease');
        }
        const identity = readProcessOwner(path.join(directory, owner.name));
        if (!identity) throw new Error('Invalid Camoufox profile lease');
        return { pid, name: owner.name, identity, nativeExitUnconfirmed: Boolean(nativeExit) };
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
    }
}

function removeLeaseOwner(directory, owner) {
    if (owner) fs.rmSync(path.join(directory, owner), { force: true });
    try {
        fs.rmdirSync(directory);
    } catch (error) {
        if (!['ENOENT', 'ENOTEMPTY', 'EEXIST'].includes(error.code)) throw error;
    }
}

export function nativeExitUnconfirmedError() {
    return Object.assign(new Error('Camoufox native browser exit is unconfirmed. Follow the lock recovery steps in ENV_VARIABLES.md.'), {
        code: 'ERR_CAMOUFOX_NATIVE_EXIT_UNCONFIRMED'
    });
}

function assertInactiveLeaseOwner(incumbent) {
    if (!incumbent) return;
    if (incumbent.nativeExitUnconfirmed) throw nativeExitUnconfirmedError();
    const status = processOwnerStatus(incumbent.pid, incumbent.identity);
    if (status === 'dead') return;
    const message = status === 'unverified'
        ? 'Camoufox profile lease owner could not be verified. Follow the lock recovery steps in ENV_VARIABLES.md.'
        : 'Camoufox profile is in use by an active owner';
    throw Object.assign(new Error(message), { code: 'ERR_CAMOUFOX_PROFILE_BUSY' });
}

export function assertProfileLeaseIdle({ profilesDir, id }) {
    assertInactiveLeaseOwner(leaseOwner(path.join(profilesDir, PROFILE_LEASE_DIRECTORY, id)));
}

export function acquireProfileLease(location) {
    const leaseRoot = path.join(location.profilesDir, PROFILE_LEASE_DIRECTORY);
    try {
        fs.mkdirSync(leaseRoot, { mode: 0o700 });
    } catch (error) {
        if (error.code !== 'EEXIST') throw error;
    }
    ensurePrivateDirectory(leaseRoot);
    return acquireDirectoryLease(path.join(leaseRoot, location.id));
}

export function acquireDirectoryLease(directory) {
    const leaseRoot = path.dirname(directory);
    const owner = `${process.pid}-${randomUUID()}`;
    const candidate = fs.mkdtempSync(path.join(leaseRoot, '~candidate-'));

    try {
        fs.writeFileSync(path.join(candidate, owner), describeProcessOwner(), { flag: 'wx', mode: 0o600 });
        // Publish a populated lease atomically. An incumbent's marker prevents
        // replacement, and cleanup can only remove a specific marker and an empty directory.
        while (true) {
            try {
                fs.renameSync(candidate, directory);
                return Object.freeze({ directory, owner });
            } catch (error) {
                const occupied = error.code === 'EEXIST' || error.code === 'ENOTEMPTY' ||
                    (process.platform === 'win32' && error.code === 'EPERM' && fs.existsSync(directory));
                if (!occupied) throw error;
            }

            const incumbent = leaseOwner(directory);
            assertInactiveLeaseOwner(incumbent);
            removeLeaseOwner(directory, incumbent?.name);
        }
    } catch (error) {
        fs.rmSync(candidate, { recursive: true, force: true });
        throw error;
    }
}

export function assertProfileLease({ directory, owner }) {
    const incumbent = leaseOwner(directory);
    if (incumbent?.name !== owner) {
        throw Object.assign(new Error('Camoufox profile lease is no longer held by this session'), {
            code: 'ERR_CAMOUFOX_PROFILE_STALE'
        });
    }
    return incumbent;
}

export function retainProfileLeaseForNativeExit(lease) {
    if (assertProfileLease(lease).nativeExitUnconfirmed) return;
    const markerPath = path.join(lease.directory, NATIVE_EXIT_MARKER);
    fs.closeSync(fs.openSync(markerPath, 'wx', 0o600));
}

export function releaseProfileLease({ directory, owner }) {
    const incumbent = leaseOwner(directory);
    if (incumbent?.name !== owner) return;
    if (incumbent.nativeExitUnconfirmed) throw nativeExitUnconfirmedError();
    removeLeaseOwner(directory, owner);
}

function hashStorageName(value) {
    return createHash('sha256').update(value).digest('hex');
}

export function captureWriterLeaseDirectory(trafficDir) {
    const key = hashStorageName(path.basename(trafficDir));
    return path.join(path.dirname(trafficDir), `.camoufox-traffic-${key}~`);
}

function captureTreeLeaseDirectory(directory) {
    const key = hashStorageName(path.basename(directory));
    return path.join(path.dirname(directory), PROFILE_LEASE_DIRECTORY, `~delete-${key}`);
}

function requireLeaseIdle(directory) {
    if (!fs.lstatSync(directory, { throwIfNoEntry: false })) return;
    // Reclaim a dead marker and reject a live or unverified owner.
    releaseProfileLease(acquireDirectoryLease(directory));
}

function checkCaptureTreeLeases(directory) {
    for (let current = directory; current !== path.dirname(current); current = path.dirname(current)) {
        requireLeaseIdle(captureTreeLeaseDirectory(current));
    }
}

/** Hold outside the tree while checking writers and moving or removing the directory. */
function acquireCaptureTreeLease(directory, writer = null) {
    const canonical = fs.realpathSync.native(directory);
    const writerDirectory = captureWriterLeaseDirectory(canonical);
    if (writer) {
        if (writer.directory !== writerDirectory) throw new Error('Capture writer does not own this directory');
        assertProfileLease(writer);
    }
    const leaseDirectory = captureTreeLeaseDirectory(canonical);
    ensurePrivateDirectory(path.dirname(leaseDirectory), { requireOwner: true });
    const lease = acquireDirectoryLease(leaseDirectory);
    try {
        if (!writer) requireLeaseIdle(writerDirectory);
        const pending = [canonical];
        while (pending.length) {
            const parent = pending.pop();
            const entries = listCaptureDirectory(parent, { trustedLocal: true });
            for (const entry of entries) {
                if (!entry.isDirectory()) continue;
                const child = path.join(parent, entry.name);
                if (/^\.camoufox-traffic-[a-f0-9]{64}~$/.test(entry.name)) requireLeaseIdle(child);
                else pending.push(child);
            }
        }
        return lease;
    } catch (error) {
        releaseProfileLease(lease);
        throw error;
    }
}

export function acquireProfileTrafficDeletionLease(profileDir) {
    return acquireCaptureTreeLease(profileDir);
}

/** Lock the capture at its pathname across both appends and whole-directory migration. */
export function acquireTrafficDirectoryLease(trafficDir) {
    checkCaptureTreeLeases(resolveExistingAncestors(path.resolve(trafficDir)));
    ensurePrivateDirectory(trafficDir);
    const directory = fs.realpathSync.native(trafficDir);
    const lease = acquireDirectoryLease(captureWriterLeaseDirectory(directory));
    try {
        // A tree mutation must see this writer, or this writer must see the
        // mutation before it can append any data.
        checkCaptureTreeLeases(directory);
        assertProfileLease(lease);
        return lease;
    } catch (error) {
        releaseProfileLease(lease);
        throw error;
    }
}

export function acquireProfileDeletionStaging(location) {
    const leaseRoot = path.join(location.profilesDir, PROFILE_LEASE_DIRECTORY);
    ensurePrivateDirectory(leaseRoot, { requireOwner: true });
    const directory = path.join(leaseRoot, '~deleting');
    ensurePrivateDirectory(directory, { requireOwner: true });
    const key = hashStorageName(location.id);
    return {
        directory,
        prefix: `${key}.`,
        lease: acquireDirectoryLease(path.join(directory, `~${key}`))
    };
}

function stagedDeletionName(staging, identity) {
    const generation = hashStorageName(JSON.stringify({ generation: identity.generation }));
    return `${staging.prefix}${identity.dev}.${identity.ino}.${generation}`;
}

export function stageProfileDeletion(location, staging, identity) {
    assertProfileIdentity(location, identity);
    // The rename records the verified identity outside the live profile. Later
    // cleanup can authenticate the remaining directory even if profile.json is gone.
    fs.renameSync(location.profileDir, path.join(staging.directory, stagedDeletionName(staging, identity)));
}

export function removeStagedProfileDeletions(staging, identity) {
    const { directory, prefix } = staging;
    const names = identity ? [stagedDeletionName(staging, identity)] :
        fs.readdirSync(directory).filter((name) => name.startsWith(prefix));
    let removed = false;
    for (const name of names) {
        const profileDir = path.join(directory, name);
        const stats = inspectProfileDirectory({ profileDir });
        if (!stats) continue;
        const match = /^(-?\d+)\.(-?\d+)\.[0-9a-f]{64}$/.exec(name.slice(prefix.length));
        if (!match || match[1] !== String(stats.dev) || match[2] !== String(stats.ino)) {
            throw new Error('Staged Camoufox profile does not match its deletion identity');
        }
        fs.rmSync(profileDir, { recursive: true });
        removed = true;
    }
    return removed;
}

export function resolveProfileNativeDirectory(profileId, profilesDir, { trustedLocal = false } = {}) {
    const location = locateProfile(profileId, profilesDir);
    if (!inspectProfileDirectory(location)) return null;
    const raw = readCaptureFile(location.profileDir, 'profile.json', { optional: true, trustedLocal });
    if (!raw) return null;
    parseProfileMetadata(raw.toString('utf8'), location.id);
    const nativeDir = path.join(location.profileDir, '.native');
    inspectProfileDirectory({ profileDir: nativeDir });
    return nativeDir;
}

function restrictIfPresent(filePath, options) {
    try {
        restrictPrivateFile(filePath, options);
        return true;
    } catch (error) {
        if (error.code === 'ENOENT') return false;
        throw error;
    }
}

export function restrictLegacySharedKeyLog(profilesDir) {
    restrictIfPresent(path.join(profilesDir, '_shared_sslkeylog.txt'));
}

export function initializeProfileStorageAt(location, metadata) {
    const { id, profileDir, profilesDir } = location;
    const requireUnusedId = () => {
        if (inspectProfileDirectory(location)) {
            throw Object.assign(new Error('Camoufox profile ID already exists'), { code: 'EEXIST' });
        }
    };
    requireUnusedId();

    // Callers hold the profile lease. A later attempt can discard an interrupted
    // initialization for this ID within the private staging area.
    const stagingRoot = path.join(profilesDir, PROFILE_LEASE_DIRECTORY, '~initializing');
    ensurePrivateDirectory(stagingRoot, { requireOwner: true });
    const staged = { profileDir: path.join(stagingRoot, id) };
    if (inspectProfileDirectory(staged)) fs.rmSync(staged.profileDir, { recursive: true });
    fs.mkdirSync(staged.profileDir, { mode: 0o700 });

    try {
        const storage = prepareProfileStorage(staged);
        const initialized = { ...metadata, _storageGeneration: randomUUID() };
        writePrivateFile(storage.metadataPath, JSON.stringify(initialized, null, 2));
        requireUnusedId();
        fs.renameSync(staged.profileDir, profileDir);
        return { storage: profileStoragePaths(profileDir), metadata: initialized };
    } catch (error) {
        fs.rmSync(staged.profileDir, { recursive: true, force: true });
        throw error;
    }
}

export function ensureProfileStorageAt(location) {
    if (!readProfileMetadata(location)) {
        throw Object.assign(new Error('Camoufox profile directory is missing'), { code: 'ENOENT' });
    }
    const storage = prepareProfileStorage(location);
    // Both callers hold this profile's lease throughout storage preparation.
    discardInterruptedSnapshots(location.profileDir);
    return storage;
}

function prepareProfileStorage(location) {
    const storage = profileStoragePaths(location.profileDir);
    const { profileDir, trafficDir, payloadsDir, storageStatePath } = storage;
    ensurePrivateDirectory(profileDir, EXISTING_PROFILE);
    for (const dir of [trafficDir, payloadsDir]) ensurePrivateDirectory(dir);
    if (!restrictIfPresent(storageStatePath, PRIVATE_SNAPSHOT)) {
        writePrivateFile(storageStatePath, JSON.stringify(EMPTY_STORAGE_STATE, null, 2), PRIVATE_SNAPSHOT);
    }
    return storage;
}

function snapshotStagingPrefix(profileDir) {
    const stats = inspectProfileDirectory({ profileDir });
    if (!stats) throw new Error('Camoufox profile directory is missing');
    return `.camoufox-storage-state~${stats.dev}.${stats.ino}.`;
}

function ownedSnapshotFile(stats) {
    return stats?.isFile() && stats.nlink === 1n &&
        (typeof process.geteuid !== 'function' || stats.uid === BigInt(process.geteuid()));
}

function discardInterruptedSnapshots(profileDir) {
    const prefix = snapshotStagingPrefix(profileDir);
    const statOptions = { bigint: true, throwIfNoEntry: false };
    for (const name of fs.readdirSync(profileDir)) {
        if (!name.startsWith(prefix)) continue;
        const match = SNAPSHOT_OWNER_NAME.exec(name.slice(prefix.length));
        if (!match) continue;

        const ownerPath = path.join(profileDir, name);
        const owner = fs.lstatSync(ownerPath, statOptions);
        if (!ownedSnapshotFile(owner) || owner.size !== 0n) continue;

        const [, id, device, inode] = match;
        const temporaryPath = path.join(profileDir, `${prefix}${id}.tmp`);
        const temporary = fs.lstatSync(temporaryPath, statOptions);
        if (temporary) {
            if (!ownedSnapshotFile(temporary) || temporary.dev.toString() !== device ||
                temporary.ino.toString() !== inode) continue;
            fs.unlinkSync(temporaryPath);
        }
        fs.unlinkSync(ownerPath);
    }
}

export function writeStorageState(storageStatePath, state) {
    const profileDir = path.dirname(storageStatePath);
    ensurePrivateDirectory(profileDir, EXISTING_PROFILE);
    const staging = path.join(profileDir, snapshotStagingPrefix(profileDir) + randomUUID());
    const temporaryPath = `${staging}.tmp`;
    let ownerPath;

    try {
        writePrivateFile(storageStatePath, JSON.stringify(state, null, 2), {
            ...PRIVATE_SNAPSHOT,
            temporaryPath,
            // Record the file's identity before any cookies reach disk.
            recordTemporaryFile(stats) {
                const marker = `${staging}.${stats.dev}.${stats.ino}.owner`;
                const fd = fs.openSync(marker, 'wx', 0o600);
                ownerPath = marker;
                fs.closeSync(fd);
            }
        });
    } finally {
        try {
            if (ownerPath && !fs.lstatSync(temporaryPath, { throwIfNoEntry: false })) {
                fs.rmSync(ownerPath, { force: true });
            }
        } catch {
            process.emitWarning('Could not clean up the Camoufox storage state marker.', {
                code: 'CAMOUFOX_SNAPSHOT_CLEANUP_FAILED'
            });
        }
    }
}

function profileStoragePaths(profileDir) {
    const trafficDir = path.join(profileDir, 'traffic');
    const payloadsDir = path.join(trafficDir, 'payloads');
    const nativeDir = path.join(profileDir, '.native');
    return {
        profileDir,
        storageStatePath: path.join(profileDir, 'storage-state.json'),
        metadataPath: path.join(profileDir, 'profile.json'),
        trafficDir,
        payloadsDir,
        nativeDir,
        sslKeyLogPath: path.join(nativeDir, NATIVE_LOG_NAMES.sslKeyLogPath),
        neckoMozLogPath: path.join(nativeDir, NATIVE_LOG_NAMES.neckoMozLogPath),
        preTlsWireLogPath: path.join(trafficDir, 'pre-tls-wire.log'),
        trafficNdjsonPath: path.join(trafficDir, 'traffic.ndjson'),
        attributionIndexPath: path.join(trafficDir, 'attribution-index.json'),
        harPath: path.join(trafficDir, 'trace.har')
    };
}

function captureEntriesIfPresent(directory) {
    try {
        return listCaptureDirectory(directory, { trustedLocal: true });
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        return [];
    }
}

function isNativeLogName({ name }) {
    return Object.values(NATIVE_LOG_NAMES).some((base) => name === base || name.startsWith(`${base}.`));
}

export function resolveExistingAncestors(filePath) {
    try {
        return fs.realpathSync.native(filePath);
    } catch (error) {
        const parent = path.dirname(filePath);
        if (error.code !== 'ENOENT' || parent === filePath) throw error;
        return path.join(resolveExistingAncestors(parent), path.basename(filePath));
    }
}

export function assertExternalNativePath(trafficDir, nativePath) {
    const inside = (capture, candidate) => {
        const relative = path.relative(capture, candidate);
        return !path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`);
    };
    if (inside(trafficDir, nativePath) ||
        inside(resolveExistingAncestors(trafficDir), resolveExistingAncestors(nativePath))) {
        throw new Error('Native logs require storage outside the traffic directory');
    }
}

export function restrictNativeLogs(storage) {
    if (!fs.existsSync(storage.nativeDir)) return;
    ensurePrivateDirectory(storage.nativeDir);
    for (const { name } of captureEntriesIfPresent(storage.nativeDir).filter(isNativeLogName)) {
        restrictPrivateFile(path.join(storage.nativeDir, name));
    }
}

export function archiveLegacyNativeLogs(storage, captureLease = null) {
    const capture = captureEntriesIfPresent(storage.trafficDir);
    const privateEntry = capture.find(({ name }) => name === '.private');
    const legacyPrivateDir = path.join(storage.trafficDir, '.private');
    const nested = privateEntry?.isDirectory() ? captureEntriesIfPresent(legacyPrivateDir) : [];
    if (!capture.some(isNativeLogName) && !nested.some(isNativeLogName) &&
        (!privateEntry || privateEntry.isDirectory())) return;

    if (!captureLease) {
        const lease = acquireTrafficDirectoryLease(storage.trafficDir);
        try {
            archiveLegacyNativeLogs(storage, lease);
        } finally {
            releaseProfileLease(lease);
        }
        return;
    }

    const treeLease = acquireCaptureTreeLease(storage.trafficDir, captureLease);
    try {
        assertExternalNativePath(storage.trafficDir, storage.nativeDir);
        ensurePrivateDirectory(storage.nativeDir);
        // Preserve the whole archive with its manifest. Never dereference entries during the move.
        const directories = [
            [storage.trafficDir, capture],
            [storage.payloadsDir, captureEntriesIfPresent(storage.payloadsDir)],
            [legacyPrivateDir, nested]
        ];
        for (const [directory, entries] of directories) {
            if (entries.length === 0) continue;
            ensurePrivateDirectory(directory);
            for (const entry of entries) {
                if (entry.isFile()) restrictPrivateFile(path.join(directory, entry.name));
            }
        }
        const legacyDir = fs.mkdtempSync(path.join(storage.nativeDir, 'legacy-'));
        try {
            fs.renameSync(storage.trafficDir, path.join(legacyDir, 'traffic'));
        } catch (error) {
            fs.rmdirSync(legacyDir);
            throw error;
        }
        ensurePrivateDirectory(storage.trafficDir);
        ensurePrivateDirectory(storage.payloadsDir);
    } finally {
        releaseProfileLease(treeLease);
    }
}

export function prepareNativeLogs(storage, {
    sslKeyLog, neckoMozLog, harPath,
    sslKeyLogPath = storage.sslKeyLogPath, neckoMozLogPath = storage.neckoMozLogPath
}) {
    if (sslKeyLog || neckoMozLog) ensurePrivateDirectory(storage.nativeDir);
    restrictIfPresent(storage.harPath);
    if (harPath && harPath !== storage.harPath) restrictIfPresent(harPath);
    restrictNativeLogs(storage);

    if (sslKeyLog && !restrictIfPresent(sslKeyLogPath)) {
        writePrivateFile(sslKeyLogPath, '# NSS SSL/TLS Secrets Log\n');
    }
    if (neckoMozLog && !restrictIfPresent(neckoMozLogPath)) {
        writePrivateFile(neckoMozLogPath, '');
    }
}

export function readStorageState(storageStatePath) {
    const raw = readPrivateFile(storageStatePath, 'utf8', PRIVATE_SNAPSHOT);
    try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed?.cookies) && Array.isArray(parsed?.origins)) return parsed;
    } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
    }
    throw Object.assign(new Error('Invalid Camoufox storage state. Restore or move the damaged snapshot before retrying.'), {
        code: 'ERR_CAMOUFOX_STORAGE_STATE_INVALID'
    });
}
