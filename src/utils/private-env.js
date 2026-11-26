import path from 'node:path';
import util from 'node:util';
import { readPrivateFile } from './private-storage.js';
import { LEGACY_DIRECTORY, STATE_DIRECTORY } from './state-paths.js';

function parseLegacyEnv(content) {
    const values = Object.create(null);
    for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;
        const equals = line.indexOf('=');
        if (equals <= 0) continue;
        const key = line.slice(0, equals).trim();
        if (!(key in values)) {
            values[key] = line.slice(equals + 1).trim().replace(/^['"]|['"]$/g, '');
        }
    }
    return values;
}

function loadPrivateEnvFile(filePath, parse) {
    let content;
    try {
        content = readPrivateFile(filePath, 'utf8', { requireOwner: true });
    } catch (error) {
        if (error.code === 'ENOENT') return false;
        throw new Error('Could not read ' + path.basename(filePath) + ' as a private configuration file');
    }

    try {
        for (const [key, value] of Object.entries(parse(content))) {
            if (!(key in process.env)) process.env[key] = value;
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

export function loadPrivateEnvironment(
    primaryFile, fallbackFile, needsFallback, parse = util.parseEnv ?? parseLegacyEnv, decrypt
) {
    const vaultKey = decrypt && process.env.DOTENV_KEY;
    const parseVault = vaultKey && createVaultParser(vaultKey, parse, decrypt);
    const load = (directory, filename) => {
        const filePath = path.join(directory, filename);
        return (parseVault && loadPrivateEnvFile(`${filePath}.vault`, parseVault)) ||
            loadPrivateEnvFile(filePath, parse);
    };

    for (const directory of [STATE_DIRECTORY, LEGACY_DIRECTORY]) {
        if (!directory) continue;
        const loadedPrimary = load(directory, primaryFile);
        const loadedFallback = needsFallback() && load(directory, fallbackFile);
        if (loadedPrimary || loadedFallback) return;
    }
}
