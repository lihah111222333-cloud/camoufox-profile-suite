import fs from 'node:fs';
import path from 'node:path';
import { readCaptureFile } from './capture-io.js';
import {
    ensurePrivateDirectory,
    readPrivateFile,
    restrictPrivateFile,
    writePrivateFile
} from '../utils/private-storage.js';

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

function inspectProfileDirectory({ profileDir }) {
    let stats;
    try {
        stats = fs.lstatSync(profileDir);
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
    }
    if (!stats.isDirectory() || fs.realpathSync.native(profileDir) !== profileDir) {
        throw new Error(`Expected a direct Camoufox profile directory: ${profileDir}`);
    }
    return stats;
}

function readProfileMetadataFile(location, requireMetadata) {
    const metadataPath = path.join(location.profileDir, 'profile.json');
    let metadata;
    try {
        metadata = JSON.parse(readPrivateFile(metadataPath));
    } catch (error) {
        if (error.code === 'ENOENT' && !requireMetadata) return null;
        throw error;
    }
    return requireProfileIdentity(metadata, location.id);
}

function requireProfileIdentity(metadata, expectedId) {
    const ids = [metadata?.id, metadata?.profileId].filter((id) => id !== undefined);
    if (ids.length === 0 || ids.some((id) =>
        (typeof id !== 'string' && !Number.isSafeInteger(id)) || String(id) !== expectedId
    )) {
        throw new Error(`Camoufox profile metadata does not match ID: ${expectedId}`);
    }
    return metadata;
}

export function readProfileMetadata(location) {
    return inspectProfileDirectory(location) ? readProfileMetadataFile(location, false) : null;
}

export function inspectProfileForDeletion(location) {
    const stats = inspectProfileDirectory(location);
    if (stats) readProfileMetadataFile(location, true);
    return stats;
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

export function ensureProfileStorageAt(location) {
    const { profileDir } = location;
    inspectProfileDirectory(location);
    const trafficDir = path.join(profileDir, 'traffic');
    const payloadsDir = path.join(trafficDir, 'payloads');
    const nativeDir = path.join(profileDir, '.native');
    for (const dir of [profileDir, trafficDir, payloadsDir]) ensurePrivateDirectory(dir);

    const storageStatePath = path.join(profileDir, 'storage-state.json');
    const metadataPath = path.join(profileDir, 'profile.json');
    restrictIfPresent(metadataPath);
    if (!restrictIfPresent(storageStatePath)) {
        writePrivateFile(storageStatePath, JSON.stringify(EMPTY_STORAGE_STATE, null, 2));
    }
    return {
        profileDir,
        storageStatePath,
        metadataPath,
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

function nativeLogNames(directory) {
    try {
        return fs.readdirSync(directory).filter((name) =>
            Object.values(NATIVE_LOG_NAMES).some((base) => name === base || name.startsWith(`${base}.`))
        );
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        return [];
    }
}

export function restrictNativeLogs(storage) {
    if (!fs.existsSync(storage.nativeDir)) return;
    ensurePrivateDirectory(storage.nativeDir);
    for (const name of nativeLogNames(storage.nativeDir)) {
        restrictPrivateFile(path.join(storage.nativeDir, name));
    }
}

export function prepareNativeLogs(storage, { sslKeyLog, neckoMozLog, harPath }) {
    const legacyFiles = nativeLogNames(storage.trafficDir);
    if (legacyFiles.length > 0 || sslKeyLog || neckoMozLog) {
        ensurePrivateDirectory(storage.nativeDir);
    }
    if (legacyFiles.length > 0) {
        // Keep the full legacy archive together so its manifest still describes the preserved files.
        for (const directory of [storage.trafficDir, storage.payloadsDir]) {
            for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
                if (entry.isFile() || (directory === storage.trafficDir && legacyFiles.includes(entry.name))) {
                    restrictPrivateFile(path.join(directory, entry.name));
                }
            }
        }
        const legacyDir = fs.mkdtempSync(path.join(storage.nativeDir, 'legacy-'));
        fs.renameSync(storage.trafficDir, path.join(legacyDir, 'traffic'));
        ensurePrivateDirectory(storage.trafficDir);
        ensurePrivateDirectory(storage.payloadsDir);
    }
    restrictIfPresent(storage.harPath);
    if (harPath && harPath !== storage.harPath) restrictIfPresent(harPath);
    restrictNativeLogs(storage);

    if (sslKeyLog && !restrictIfPresent(storage.sslKeyLogPath)) {
        writePrivateFile(storage.sslKeyLogPath, '# NSS SSL/TLS Secrets Log\n');
    }
    if (neckoMozLog && !restrictIfPresent(storage.neckoMozLogPath)) {
        writePrivateFile(storage.neckoMozLogPath, '');
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
    writePrivateFile(storageStatePath, JSON.stringify(EMPTY_STORAGE_STATE, null, 2));
    return EMPTY_STORAGE_STATE;
}
