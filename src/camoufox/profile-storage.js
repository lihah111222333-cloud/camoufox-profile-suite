import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { listCaptureDirectory, readCaptureFile } from './capture-io.js';
import {
    ensurePrivateDirectory,
    readPrivateFile,
    restrictPrivateFile,
    writePrivateFile
} from '../utils/private-storage.js';
import { describeProcessOwner, isDeadProcessOwner, readProcessOwner } from '../utils/process-owner.js';

// This directory name cannot be a valid profile ID.
export const PROFILE_LEASE_DIRECTORY = '.camoufox-leases~';

const EMPTY_STORAGE_STATE = { cookies: [], origins: [] };
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
            throw new Error(`Expected a direct Camoufox profile directory: ${profileDir}`);
        }
        return stats;
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
    }
}

function readProfileMetadataFile(location) {
    const metadataPath = path.join(location.profileDir, 'profile.json');
    return requireProfileIdentity(JSON.parse(readPrivateFile(metadataPath)), location.id);
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
    return requireProfileIdentity(JSON.parse(raw.toString('utf8')), location.id);
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
        const owners = fs.readdirSync(directory, { withFileTypes: true });
        if (!owners.length) return null;
        const [owner] = owners;
        const pid = Number(/^([1-9]\d*)-[0-9a-f-]{36}$/.exec(owner.name)?.[1]);
        if (owners.length !== 1 || !owner.isFile() || !Number.isInteger(pid) || pid > 0x7fff_ffff) {
            throw new Error('Invalid Camoufox profile lease');
        }
        const identity = readProcessOwner(path.join(directory, owner.name));
        if (!identity) throw new Error('Invalid Camoufox profile lease');
        return { pid, name: owner.name, identity };
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
            if (incumbent && !isDeadProcessOwner(incumbent.pid, incumbent.identity)) {
                throw Object.assign(new Error('Camoufox profile is in use by an active owner'), {
                    code: 'ERR_CAMOUFOX_PROFILE_BUSY'
                });
            }
            removeLeaseOwner(directory, incumbent?.name);
        }
    } catch (error) {
        fs.rmSync(candidate, { recursive: true, force: true });
        throw error;
    }
}

export function assertProfileLease({ directory, owner }) {
    if (leaseOwner(directory)?.name !== owner) {
        throw Object.assign(new Error('Camoufox profile lease is no longer held by this session'), {
            code: 'ERR_CAMOUFOX_PROFILE_STALE'
        });
    }
}

export function releaseProfileLease({ directory, owner }) {
    if (leaseOwner(directory)?.name === owner) removeLeaseOwner(directory, owner);
}

export function resolveProfileNativeDirectory(profileId, profilesDir, { trustedLocal = false } = {}) {
    const location = locateProfile(profileId, profilesDir);
    if (!inspectProfileDirectory(location)) return null;
    const raw = readCaptureFile(location.profileDir, 'profile.json', { optional: true, trustedLocal });
    if (!raw) return null;
    requireProfileIdentity(JSON.parse(raw.toString('utf8')), location.id);
    const nativeDir = path.join(location.profileDir, '.native');
    inspectProfileDirectory({ profileDir: nativeDir });
    return nativeDir;
}

function restrictIfPresent(filePath) {
    try {
        restrictPrivateFile(filePath);
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
    return prepareProfileStorage(location);
}

function prepareProfileStorage(location) {
    const storage = profileStoragePaths(location.profileDir);
    const { profileDir, trafficDir, payloadsDir, storageStatePath } = storage;
    for (const dir of [profileDir, trafficDir, payloadsDir]) ensurePrivateDirectory(dir);
    if (!restrictIfPresent(storageStatePath)) {
        writePrivateFile(storageStatePath, JSON.stringify(EMPTY_STORAGE_STATE, null, 2));
    }
    return storage;
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

function resolveExistingAncestors(filePath) {
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

export function archiveLegacyNativeLogs(storage, acquireCaptureLease) {
    const capture = captureEntriesIfPresent(storage.trafficDir);
    const privateEntry = capture.find(({ name }) => name === '.private');
    const legacyPrivateDir = path.join(storage.trafficDir, '.private');
    const nested = privateEntry?.isDirectory() ? captureEntriesIfPresent(legacyPrivateDir) : [];
    if (!capture.some(isNativeLogName) && !nested.some(isNativeLogName) &&
        (!privateEntry || privateEntry.isDirectory())) return;

    if (acquireCaptureLease) {
        const lease = acquireCaptureLease(storage.trafficDir);
        try {
            archiveLegacyNativeLogs(storage);
        } finally {
            releaseProfileLease(lease);
        }
        return;
    }

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
    const raw = readPrivateFile(storageStatePath);
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
