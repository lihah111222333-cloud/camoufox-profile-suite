import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensurePrivateDirectory } from './private-storage.js';

export const PACKAGE_ROOT = path.resolve(fileURLToPath(new URL('../../', import.meta.url)));

function absoluteOverride(name) {
    const value = process.env[name];
    if (value === undefined) return undefined;
    if (!path.isAbsolute(value)) throw new Error(`${name} must be an absolute path`);
    return path.resolve(value);
}

const home = os.homedir();
const userStateBase = [process.env.XDG_STATE_HOME, process.platform === 'win32' ? process.env.LOCALAPPDATA : undefined]
    .find((value) => value && path.isAbsolute(value)) || path.join(home, '.local', 'state');

// Resolve once, before reading an application .env file.
export const STATE_DIRECTORY = absoluteOverride('GMAIL_CREATOR_STATE_DIR') ||
    path.join(userStateBase, 'gmail-account-creator');
export const LEGACY_DIRECTORY = absoluteOverride('GMAIL_CREATOR_LEGACY_DIR') ||
    (fs.existsSync(path.join(PACKAGE_ROOT, '.git')) ? PACKAGE_ROOT : undefined);

const DEDICATED_DIRECTORY_REQUIRED = 'GMAIL_CREATOR_STATE_DIR must name a dedicated directory';
if (STATE_DIRECTORY === path.parse(STATE_DIRECTORY).root || STATE_DIRECTORY === path.resolve(home)) {
    throw new Error(DEDICATED_DIRECTORY_REQUIRED);
}

export function validateExistingStateDirectory() {
    let existing;
    try {
        existing = fs.lstatSync(STATE_DIRECTORY, { bigint: true, throwIfNoEntry: false });
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
        throw new Error(DEDICATED_DIRECTORY_REQUIRED);
    }
    return true;
}

export function ensureStateDirectory() {
    validateExistingStateDirectory();
    ensurePrivateDirectory(STATE_DIRECTORY, { requireOwner: true });
    return STATE_DIRECTORY;
}

export function getDefaultProfilesDirectory(env = process.env) {
    const configured = env.CAMOUFOX_STORAGE_DIR || env.CAMOUFOX_PROFILES_DIR;
    return configured ? path.resolve(configured) : path.join(STATE_DIRECTORY, 'profiles');
}
