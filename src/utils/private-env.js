import { createDecipheriv } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { readPrivateFile } from './private-storage.js';
import { getDefaultProfilesDirectory, LEGACY_DIRECTORY, STATE_DIRECTORY, validateExistingStateDirectory } from './state-paths.js';

export function configurationError(message) {
    return Object.assign(new Error(message), { code: 'PRIVATE_ENV_CONFIGURATION_ERROR' });
}

function parseEnvironment(content) {
    const values = Object.create(null);
    // Quoted values may span lines and preserve escaped delimiters. Double
    // quotes also expand dotenv's newline and carriage return escapes.
    const entry = /^[ \t]*(?:export[ \t]+)?([\w.-]+)(?:[ \t]*=[ \t]*|:[ \t]+)(?:"((?:\\[\s\S]|[^"\\])*)"|'((?:\\[\s\S]|[^'\\])*)'|`((?:\\[\s\S]|[^`\\])*)`|([^#\n]*?))[ \t]*(?:#.*)?$/gm;
    const source = content.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
    for (const [, name, doubleQuoted, singleQuoted, backtickQuoted, unquoted] of source.matchAll(entry)) {
        values[name] = doubleQuoted?.replace(/\\n/g, '\n').replace(/\\r/g, '\r') ??
            singleQuoted ?? backtickQuoted ?? unquoted.trim();
    }
    return values;
}

function readEnvironmentFile(filePath, parse, readOnly) {
    let content;
    try {
        content = readPrivateFile(filePath, 'utf8', { requireOwner: true, restrict: !readOnly });
    } catch (error) {
        if (error.code === 'ENOENT') return undefined;
        throw configurationError('Could not read ' + path.basename(filePath) + ' as a private configuration file');
    }
    try {
        return parse(content);
    } catch {
        throw configurationError('Could not parse environment configuration in ' + path.basename(filePath));
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

const configFiles = ['.env', '.emv'];

function selectEnvironmentDirectory(useVault) {
    if (!validateExistingStateDirectory()) return LEGACY_DIRECTORY;

    // A current configuration owns the selection even when the caller only
    // needs some of its fields. A legacy file never fills in a current file.
    const candidates = useVault ? [...configFiles, ...configFiles.map(file => file + '.vault')] : configFiles;
    for (const file of candidates) {
        try {
            if (fs.lstatSync(path.join(STATE_DIRECTORY, file), { throwIfNoEntry: false })) return STATE_DIRECTORY;
        } catch {
            throw configurationError('Could not inspect private configuration in GMAIL_CREATOR_STATE_DIR');
        }
    }
    return LEGACY_DIRECTORY;
}

function applyEnvironment(env, values, onlyKey) {
    if (!values) return;
    for (const [key, value] of Object.entries(values)) {
        if (onlyKey !== undefined && key !== onlyKey) continue;
        // The vault key is supplied by the launch environment.
        if (key === 'DOTENV_KEY') continue;
        if (!(key in env) || (key === 'PROFILE_SERVICE' && !env.PROFILE_SERVICE?.trim())) env[key] = value;
    }
}

export function loadApplicationEnvironment({ env = process.env, readOnly = false } = {}) {
    let directory;
    try {
        directory = selectEnvironmentDirectory(Boolean(env.DOTENV_KEY));
    } catch (error) {
        throw configurationError(error.message);
    }
    const parseVault = env.DOTENV_KEY && createVaultParser(env.DOTENV_KEY);
    if (!directory) return env;

    const read = filename => {
        const filePath = path.join(directory, filename);
        return (parseVault && readEnvironmentFile(filePath + '.vault', parseVault, readOnly)) ||
            readEnvironmentFile(filePath, parseEnvironment, readOnly);
    };

    applyEnvironment(env, read('.env'));
    if (!env.PROFILE_SERVICE?.trim()) {
        applyEnvironment(env, read('.emv'));
    } else if (!('GOLOGIN_API_KEY' in env)) {
        // Keep support for a legacy GoLogin key without activating unrelated
        // fallback settings once the application service is configured.
        applyEnvironment(env, read('.emv'), 'GOLOGIN_API_KEY');
    }
    return env;
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
