/**
 * Logger utility for the application
 * نظام السجلات للتطبيق
 */

import path from 'path';
import { appendPrivateFile, ensurePrivateDirectory } from './private-storage.js';
import { ensureStateDirectory } from './state-paths.js';

const LOG_LEVELS = {
    SILENT: -1,
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3
};
let warnedInvalidLogLevel = false;

const REDACTED_FIELDS = new Set([
    'code', 'otp', 'otpcode', 'phonecode', 'verificationcode', 'lastcode',
    'password', 'passwd', 'proxypassword', 'passphrase', 'passcode',
    'key', 'apikey', 'omocaptchakey', 'token', 'secret', 'credential', 'credentials',
    'authorization', 'cookie', 'setcookie',
    'expected', 'actual', 'entered', 'currentvalue', 'text',
    'stack', 'errormessage', 'message', 'response',
    'name', 'firstname', 'lastname', 'fullname', 'username', 'email', 'accountemail',
    'emailaddress', 'contactemail', 'recoveryemail', 'recoveryemailaddress',
    'phone', 'phonenumber', 'telephone', 'telephonenumber', 'mobile', 'mobilephone', 'mobilenumber',
    'mobilephonenumber', 'contactphone', 'contactphonenumber', 'recoveryphone', 'recoveryphonenumber',
    'birthdate', 'birthday', 'dateofbirth', 'dob',
    'profilename', 'foldername', 'title',
    'id', 'accountid', 'browserid', 'profileid', 'profileids', 'folderid', 'folderids',
    'cpu', 'cpumodel', 'gpu', 'gpumodel', 'gpuperformance', 'hostbaseline', 'hostchipmodel',
    'hostcpu', 'hostgpu', 'hostcpumodel', 'hostgpumodel'
]);
const ERROR_NAMES = new Set(['Error', 'TypeError', 'RangeError', 'SyntaxError', 'TimeoutError', 'AbortError']);

function getErrorType(error) {
    return ERROR_NAMES.has(error.name) ? error.name : 'Error';
}

function safeStringify(data) {
    const seen = new WeakSet();
    try {
        if (data instanceof Error) return JSON.stringify({ name: getErrorType(data) });
        return JSON.stringify(data, (key, value) => {
            const field = key.toLowerCase().replace(/[^a-z0-9]/g, '');
            if (field === 'error' || field === 'err') {
                return value instanceof Error ? { type: getErrorType(value) } : '[Redacted]';
            }
            if (REDACTED_FIELDS.has(field) || /(?:apikey|paths?|dirs?|director(?:y|ies))$/.test(field)) {
                return '[Redacted]';
            }
            if (typeof value === 'string' &&
                (path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || /^file:/i.test(value))) {
                return '[Redacted]';
            }
            if (field.endsWith('url') && typeof value === 'string') {
                try {
                    const origin = new URL(value).origin;
                    return origin === 'null' ? '[Redacted]' : origin;
                } catch {
                    return '[Redacted]';
                }
            }
            if (typeof value === 'bigint') {
                return value.toString();
            }
            if (value instanceof Error) {
                return { type: getErrorType(value) };
            }
            if (typeof value === 'object' && value !== null) {
                if (seen.has(value)) {
                    return '[Circular]';
                }
                seen.add(value);
            }
            return value;
        });
    } catch {
        return '"[Unserializable log data]"';
    }
}

function formatMessage(timestamp, level, message, data) {
    const dataStr = data ? ` | Data: ${safeStringify(data)}` : '';
    return `[${timestamp}] [${level}] ${message}${dataStr}\n`;
}

function shouldLog(level) {
    const configuredLevel = (process.env.LOG_LEVEL || 'INFO').trim().toUpperCase();
    if (Object.hasOwn(LOG_LEVELS, configuredLevel)) {
        return LOG_LEVELS[level] <= LOG_LEVELS[configuredLevel];
    }
    if (!warnedInvalidLogLevel) {
        warnedInvalidLogLevel = true;
        console.warn('Invalid LOG_LEVEL. Using INFO.');
    }
    return LOG_LEVELS[level] <= LOG_LEVELS.INFO;
}

function writeLog(level, message, data = null) {
    if (!shouldLog(level)) return;

    const timestamp = new Date().toISOString();
    const formatted = formatMessage(timestamp, level, message, data);
    
    // Console output
    const colors = {
        ERROR: '\x1b[31m', // Red
        WARN: '\x1b[33m',  // Yellow
        INFO: '\x1b[36m',  // Cyan
        DEBUG: '\x1b[90m'  // Gray
    };
    const reset = '\x1b[0m';
    console.log(`${colors[level] || ''}${formatted.trim()}${reset}`);

    // File output
    try {
        const logDir = path.join(ensureStateDirectory(), 'logs');
        ensurePrivateDirectory(logDir, { requireOwner: true });
        const logFile = path.join(logDir, `app-${timestamp.slice(0, 10)}.log`);
        appendPrivateFile(logFile, formatted, { requireOwner: true });
    } catch {
        console.error('Failed to write to the application log file');
    }
}

export const logger = {
    error: (message, data) => writeLog('ERROR', message, data),
    warn: (message, data) => writeLog('WARN', message, data),
    info: (message, data) => writeLog('INFO', message, data),
    debug: (message, data) => writeLog('DEBUG', message, data)
};

export default logger;


