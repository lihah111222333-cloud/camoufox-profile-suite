import { createDecipheriv } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isMainThread } from 'node:worker_threads';
import { readPrivateFile } from './private-storage.js';
import {
    configurationError, getDefaultProfilesDirectory, getLegacyDirectory, getStateDirectory, validateExistingStateDirectory
} from './state-paths.js';

export { configurationError };

function parseEnvironment(content) {
    const values = Object.create(null);
    // Quoted values may span lines and preserve escaped delimiters. Double
    // quotes also expand dotenv's newline and carriage return escapes. A final
    // backslash can be a literal separator immediately before the closing quote.
    const entry = /^[ \t]*(?:export[ \t]+)?([\w.-]+)(?:[ \t]*=[ \t]*|:[ \t]+)(?:"((?:\\[\s\S]|[^"\\])*(?:\\)?)"|'((?:\\[\s\S]|[^'\\])*(?:\\)?)'|`((?:\\[\s\S]|[^`\\])*(?:\\)?)`|([^#\n]*?))[ \t]*(?:#.*)?$/gm;
    const source = content.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
    for (const [, name, doubleQuoted, singleQuoted, backtickQuoted, unquoted] of source.matchAll(entry)) {
        values[name] = doubleQuoted?.replace(/\\n/g, '\n').replace(/\\r/g, '\r') ??
            singleQuoted ?? backtickQuoted ?? unquoted.trim();
    }
    return values;
}

function readEnvironmentFile(filePath, readOnly) {
    try {
        return readPrivateFile(filePath, 'utf8', { requireOwner: true, restrict: !readOnly, checkAcl: true });
    } catch (error) {
        if (error.code === 'ENOENT') return undefined;
        throw configurationError('Could not read ' + path.basename(filePath) + ' as a private configuration file');
    }
}

function createVaultParser(value) {
    const keys = [];
    for (const candidate of value.split(',')) {
        try {
            const key = new URL(candidate.trim());
            const environment = key.searchParams.get('environment');
            if (key.protocol === 'dotenv:' && environment && /[a-f0-9]{64}$/i.test(key.password)) {
                keys.push({ field: 'DOTENV_VAULT_' + environment.toUpperCase(), password: key.password });
            }
        } catch {
            // A later rotation key may be usable.
        }
    }
    if (!keys.length) throw configurationError('Invalid DOTENV_KEY');

    return content => {
        const vault = parseEnvironment(content);
        for (const { field, password } of keys) {
            if (!vault[field]) continue;
            try {
                // Dotenv Vault stores a 12-byte nonce, AES-256-GCM ciphertext and a 16-byte tag.
                const bytes = Buffer.from(vault[field], 'base64');
                if (bytes.length < 28) continue;
                const key = Buffer.from(password.slice(-64), 'hex');
                const decrypt = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12), { authTagLength: 16 });
                decrypt.setAuthTag(bytes.subarray(-16));
                const decoded = Buffer.concat([decrypt.update(bytes.subarray(12, -16)), decrypt.final()]);
                return parseEnvironment(decoded.toString('utf8'));
            } catch {
                // A later rotation key may decrypt this environment.
            }
        }
        throw configurationError('Could not decrypt environment vault');
    };
}

const configFiles = ['.env', '.emv', '.env.vault', '.emv.vault'];

function hasEnvironmentFile(directory, filename) {
    try {
        return Boolean(fs.lstatSync(path.join(directory, filename), { throwIfNoEntry: false }));
    } catch {
        throw configurationError('Could not inspect private configuration file ' + filename);
    }
}

function selectEnvironmentDirectory() {
    const stateDirectory = getStateDirectory();
    const legacyDirectory = getLegacyDirectory();
    if (!validateExistingStateDirectory()) return legacyDirectory;

    // A current configuration owns the selection even when the caller only
    // needs some of its fields. A legacy file never fills in a current file.
    if (configFiles.some(filename => hasEnvironmentFile(stateDirectory, filename))) {
        return stateDirectory;
    }
    return legacyDirectory;
}

function applyEnvironment(env, values, caseInsensitive, onlyKey) {
    if (!values) return;
    for (const [name, value] of Object.entries(values)) {
        const key = caseInsensitive ? name.toUpperCase() : name;
        if (onlyKey !== undefined && key !== onlyKey) continue;
        // The vault key is supplied by the launch environment.
        if (key === 'DOTENV_KEY') continue;
        if (!(key in env) || (key === 'PROFILE_SERVICE' && !env.PROFILE_SERVICE?.trim())) env[key] = value;
    }
}

export function loadApplicationEnvironment({ env = process.env, readOnly = false, includeGoLoginFallback = false } = {}) {
    const vaultKey = env.DOTENV_KEY;
    let directory;
    try {
        directory = selectEnvironmentDirectory();
    } catch (error) {
        throw configurationError(error.message);
    }
    if (!directory) return env;

    let parseVault;
    const read = filename => {
        const vaultFilename = filename + '.vault';
        if (vaultKey) {
            const vault = readEnvironmentFile(path.join(directory, vaultFilename), readOnly);
            if (vault !== undefined) {
                parseVault ??= createVaultParser(vaultKey);
                try {
                    return parseVault(vault);
                } catch {
                    throw configurationError('Could not parse environment configuration in ' + vaultFilename);
                }
            }
        }
        const plaintext = readEnvironmentFile(path.join(directory, filename), readOnly);
        if (plaintext !== undefined) return parseEnvironment(plaintext);
        if (!vaultKey && hasEnvironmentFile(directory, vaultFilename)) {
            // A plaintext .emv can still provide the usual same-source fallback.
            if (filename === '.env' && hasEnvironmentFile(directory, '.emv')) return undefined;
            throw configurationError('DOTENV_KEY is required to read ' + vaultFilename);
        }
    };

    // Stage additions until all required files have been read. Fall back to
    // the original environment for precedence checks without copying its keys.
    const staged = Object.create(env);
    // Only Windows' main-thread process environment ignores key casing.
    const caseInsensitive = process.platform === 'win32' && isMainThread && env === process.env;
    applyEnvironment(staged, read('.env'), caseInsensitive);
    if (!staged.PROFILE_SERVICE?.trim()) {
        applyEnvironment(staged, read('.emv'), caseInsensitive);
    } else if (includeGoLoginFallback && !('GOLOGIN_API_KEY' in staged)) {
        // Keep support for a legacy GoLogin key without activating unrelated
        // fallback settings once the application service is configured.
        applyEnvironment(staged, read('.emv'), caseInsensitive, 'GOLOGIN_API_KEY');
    }
    return Object.assign(env, staged);
}

export function getConfiguredProfilesDirectory() {
    return getDefaultProfilesDirectory(loadApplicationEnvironment({ env: { ...process.env }, readOnly: true }));
}

const recordingBooleans = {
    recordTraffic: ['CAMOUFOX_RECORD_TRAFFIC', true],
    recordBodies: ['CAMOUFOX_RECORD_BODIES', false],
    recordWireLog: ['CAMOUFOX_RECORD_WIRE_LOG', true],
    sslKeyLog: ['CAMOUFOX_SSLKEYLOG', false],
    neckoMozLog: ['CAMOUFOX_NECKO_MOZ_LOG', false],
    recordHar: ['CAMOUFOX_RECORD_HAR', false]
};

export function resolveRecordingOptions(options = {}, env = process.env) {
    const result = {};
    for (const [option, [name, fallback]] of Object.entries(recordingBooleans)) {
        const supplied = options[option];
        if (supplied !== undefined) {
            if (typeof supplied !== 'boolean') throw new TypeError(option + ' must be a boolean');
            result[option] = supplied;
        } else {
            const value = env[name];
            if (value !== undefined && value !== 'true' && value !== 'false') {
                throw configurationError(name + ' must be true or false');
            }
            result[option] = value === undefined ? fallback : value === 'true';
        }
    }
    const name = 'CAMOUFOX_TRAFFIC_MAX_BODY_BYTES';
    const value = env[name];
    const bytes = options.maxBodyBytes ?? (value === undefined ? 5 * 1024 * 1024 : Number(value));
    if (options.maxBodyBytes === null || !Number.isSafeInteger(bytes) || bytes < 1 ||
        (options.maxBodyBytes === undefined && value !== undefined && !/^[0-9]+$/.test(value))) {
        if (options.maxBodyBytes !== undefined) throw new TypeError('maxBodyBytes must be a positive safe integer');
        throw configurationError(name + ' must be a positive safe integer');
    }
    result.maxBodyBytes = bytes;
    return result;
}
