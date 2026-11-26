export function parseAccountCount(value, source = 'ACCOUNTS_COUNT') {
    return parseCount(value, source);
}

export function parseThreadCount(value, source = 'THREADS_COUNT') {
    return parseCount(value, source);
}

function parseCount(value, source) {
    if (typeof value === 'string' && /^[0-9]+$/.test(value)) {
        const count = Number(value);
        if (Number.isSafeInteger(count) && count >= 1) return count;
    }
    const error = new Error(`${source} must be an integer from 1 to ${Number.MAX_SAFE_INTEGER}`);
    error.code = 'INVALID_CLI_COUNT';
    throw error;
}

export function parseRunCounts(args, env = process.env) {
    let accountsCount;
    let threadsCount;
    for (const arg of args) {
        const separator = arg.indexOf('=');
        const name = separator === -1 ? arg : arg.slice(0, separator);
        const value = separator === -1 ? undefined : arg.slice(separator + 1);
        if (name === '--accounts' || name === '-a') accountsCount = parseAccountCount(value, name);
        if (name === '--threads' || name === '-t') threadsCount = parseThreadCount(value, name);
    }
    return {
        accountsCount: accountsCount ?? parseAccountCount(env.ACCOUNTS_COUNT ?? '1'),
        threadsCount: threadsCount ?? parseThreadCount(env.THREADS_COUNT ?? '1')
    };
}
