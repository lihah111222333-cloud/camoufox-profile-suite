import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensurePrivateDirectory } from './private-storage.js';

export const PACKAGE_ROOT = path.resolve(fileURLToPath(new URL('../../', import.meta.url)));

export function configurationError(message) {
    return Object.assign(new Error(message), { code: 'PRIVATE_ENV_CONFIGURATION_ERROR' });
}

function configuredDirectory(name, fallback) {
    const value = process.env[name];
    if (value === undefined) return { directory: fallback };
    if (!path.isAbsolute(value)) return { error: name + ' must be an absolute path' };
    return { directory: path.resolve(value) };
}

const home = os.homedir();
const userStateBase = [process.env.XDG_STATE_HOME, process.platform === 'win32' ? process.env.LOCALAPPDATA : undefined]
    .find((value) => value && path.isAbsolute(value)) || path.join(home, '.local', 'state');

// Resolve the launch values before reading .env. Keep the published names
// available for valid configurations and report errors when the paths are used.
const state = configuredDirectory('GMAIL_CREATOR_STATE_DIR', path.join(userStateBase, 'gmail-account-creator'));
const checkoutDirectory = fs.existsSync(path.join(PACKAGE_ROOT, '.git')) ? PACKAGE_ROOT : undefined;
const legacy = configuredDirectory('GMAIL_CREATOR_LEGACY_DIR', checkoutDirectory);
const DEDICATED_DIRECTORY_REQUIRED = 'GMAIL_CREATOR_STATE_DIR must name a dedicated directory';
const stateError = state.error ?? (
    state.directory === path.parse(state.directory).root || state.directory === path.resolve(home)
        ? DEDICATED_DIRECTORY_REQUIRED
        : undefined
);

export const STATE_DIRECTORY = stateError ? undefined : state.directory;
export const LEGACY_DIRECTORY = legacy.directory;

export function getStateDirectory() {
    if (stateError) throw configurationError(stateError);
    return STATE_DIRECTORY;
}

export function getLegacyDirectory() {
    if (legacy.error) throw configurationError(legacy.error);
    return LEGACY_DIRECTORY;
}

export function validateExistingStateDirectory() {
    const stateDirectory = getStateDirectory();
    let existing;
    try {
        existing = fs.lstatSync(stateDirectory, { bigint: true, throwIfNoEntry: false });
    } catch (cause) {
        throw new Error('Could not inspect GMAIL_CREATOR_STATE_DIR', { cause });
    }
    if (!existing) return false;
    if (!existing.isDirectory() ||
        (typeof process.geteuid === 'function' && existing.uid !== BigInt(process.geteuid()))) {
        throw new Error('GMAIL_CREATOR_STATE_DIR must name a real directory owned by the current user');
    }
    let homeIdentity;
    try {
        homeIdentity = fs.statSync(home, { bigint: true, throwIfNoEntry: false });
    } catch (error) {
        // A service can use an independent state directory when its HOME is unavailable.
        if (error.code !== 'EACCES' && error.code !== 'EPERM' && error.code !== 'ENOTDIR') throw error;
    }
    if (homeIdentity && existing.dev === homeIdentity.dev && existing.ino === homeIdentity.ino) {
        throw configurationError(DEDICATED_DIRECTORY_REQUIRED);
    }
    return true;
}

export function ensureStateDirectory() {
    validateExistingStateDirectory();
    const stateDirectory = getStateDirectory();
    ensurePrivateDirectory(stateDirectory, { requireOwner: true });
    return stateDirectory;
}

export function getDefaultProfilesDirectory(env = process.env) {
    const setting = env.CAMOUFOX_STORAGE_DIR ? 'CAMOUFOX_STORAGE_DIR' : 'CAMOUFOX_PROFILES_DIR';
    const configured = env[setting];
    if (!configured) return path.join(getStateDirectory(), 'profiles');
    if (!configured.trim()) throw configurationError(setting + ' must name a nonempty profiles root directory');
    return path.resolve(configured);
}
