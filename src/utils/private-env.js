import fs from 'node:fs';
import path from 'node:path';
import { readPrivateFile } from './private-storage.js';
import { LEGACY_DIRECTORY, STATE_DIRECTORY, validateExistingStateDirectory } from './state-paths.js';

function parseEnvironment(content) {
    const values = Object.create(null);
    // Match the whole input so quoted values can span lines. Unquoted values and
    // whitespace around the assignment stay confined to their own line.
    const entry = /^([^#=\r\n]+)=[ \t]*(?:"([^"]*)"|'([^']*)'|`([^`]*)`|([^#\r\n]*))/gm;
    for (const [, name, doubleQuoted, singleQuoted, backtickQuoted, unquoted] of content.replace(/\r\n/g, '\n').matchAll(entry)) {
        const key = name.trim().replace(/^export[ \t]+/, '');
        if (!key) continue;
        values[key] = doubleQuoted?.replace(/\\n/g, '\n') ?? singleQuoted ?? backtickQuoted ?? unquoted.trim();
    }
    return values;
}

function loadPrivateEnvFile(filePath, parse, env, readOnly) {
    let content;
    try {
        content = readPrivateFile(filePath, 'utf8', { requireOwner: true, restrict: !readOnly });
    } catch (error) {
        if (error.code === 'ENOENT') return false;
        throw new Error('Could not read ' + path.basename(filePath) + ' as a private configuration file');
    }

    try {
        for (const [key, value] of Object.entries(parse(content))) {
            if (!(key in env)) env[key] = value;
        }
    } catch {
        throw new Error('Could not parse environment configuration in ' + path.basename(filePath));
    }
    return true;
}

function createVaultParser(value, parse, decrypt) {
    const keys = [];
    for (const candidate of value.split(',')) {
        try {
            const key = new URL(candidate.trim());
            const environment = key.searchParams.get('environment');
            if (key.protocol === 'dotenv:' && environment && /[a-f0-9]{64}$/i.test(key.password)) {
                keys.push({ field: `DOTENV_VAULT_${environment.toUpperCase()}`, password: key.password });
            }
        } catch {
            // A later rotation key may be usable.
        }
    }
    if (!keys.length) throw new Error('Invalid DOTENV_KEY');

    return (content) => {
        const vault = parse(content);
        for (const { field, password } of keys) {
            if (!vault[field]) continue;
            try {
                return parse(decrypt(vault[field], password));
            } catch {
                // A later rotation key may decrypt this environment.
            }
        }
        throw new Error('Could not decrypt environment vault');
    };
}

function selectEnvironmentDirectory(files, useVault) {
    if (!validateExistingStateDirectory()) return LEGACY_DIRECTORY;

    // A configuration in the current state directory owns the selection,
    // even if the caller does not need to read every file there.
    const candidates = useVault ? [...files, ...files.map((file) => `${file}.vault`)] : files;
    for (const file of candidates) {
        try {
            if (fs.lstatSync(path.join(STATE_DIRECTORY, file), { throwIfNoEntry: false })) return STATE_DIRECTORY;
        } catch {
            throw new Error('Could not inspect private configuration in GMAIL_CREATOR_STATE_DIR');
        }
    }
    return LEGACY_DIRECTORY;
}

export function loadPrivateEnvironment(
    primaryFile, fallbackFile, needsFallback, parse = parseEnvironment, decrypt,
    { env = process.env, readOnly = false } = {}
) {
    const vaultKey = decrypt && env.DOTENV_KEY;
    const parseVault = vaultKey && createVaultParser(vaultKey, parse, decrypt);
    const directory = selectEnvironmentDirectory([primaryFile, fallbackFile], Boolean(env.DOTENV_KEY));
    if (!directory) return;

    const load = (filename) => {
        const filePath = path.join(directory, filename);
        return (parseVault && loadPrivateEnvFile(`${filePath}.vault`, parseVault, env, readOnly)) ||
            loadPrivateEnvFile(filePath, parse, env, readOnly);
    };

    load(primaryFile);
    if (needsFallback(env)) load(fallbackFile);
}

export function loadApplicationEnvironment(options) {
    loadPrivateEnvironment(
        '.env', '.emv', env => !env.PROFILE_SERVICE && !env.DOLPHIN_API_KEY, parseEnvironment, undefined, options
    );
}
