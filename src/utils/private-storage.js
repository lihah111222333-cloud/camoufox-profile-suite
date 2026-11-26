import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
// Windows deployments rely on the access control lists set by the operator.
const SUPPORTS_OWNER_MODES = process.platform !== 'win32';
const OPEN_EXISTING = (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);
const APPEND_EXISTING = fs.constants.O_WRONLY | fs.constants.O_APPEND;

function restrictMode(fd, stats, mode) {
    if (SUPPORTS_OWNER_MODES && (stats.mode & 0o7777) !== mode) {
        fs.fchmodSync(fd, mode);
    }
}

function openPrivateFile(filePath, access = fs.constants.O_RDONLY) {
    const existing = fs.lstatSync(filePath);
    if (!existing.isFile() || existing.nlink !== 1) {
        throw new Error(`Expected a regular file with one directory entry: ${filePath}`);
    }

    const fd = fs.openSync(filePath, access | OPEN_EXISTING);
    try {
        const opened = fs.fstatSync(fd);
        if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== existing.dev || opened.ino !== existing.ino) {
            throw new Error(`File changed while opening: ${filePath}`);
        }
        restrictMode(fd, opened, FILE_MODE);
        return fd;
    } catch (error) {
        fs.closeSync(fd);
        throw error;
    }
}

// Only call this for application-owned directories.
export function ensurePrivateDirectory(directory) {
    fs.mkdirSync(directory, { recursive: true, mode: DIRECTORY_MODE });
    const existing = fs.lstatSync(directory);
    if (!existing.isDirectory()) {
        throw new Error(`Expected a directory: ${directory}`);
    }
    if (!SUPPORTS_OWNER_MODES || (existing.mode & 0o7777) === DIRECTORY_MODE) {
        return;
    }

    const fd = fs.openSync(directory, OPEN_EXISTING | (fs.constants.O_DIRECTORY ?? 0));
    try {
        const opened = fs.fstatSync(fd);
        if (!opened.isDirectory() || opened.dev !== existing.dev || opened.ino !== existing.ino) {
            throw new Error(`Directory changed while opening: ${directory}`);
        }
        restrictMode(fd, opened, DIRECTORY_MODE);
    } finally {
        fs.closeSync(fd);
    }
}

export function restrictPrivateFile(filePath) {
    fs.closeSync(openPrivateFile(filePath));
}

export function readPrivateFile(filePath, encoding = 'utf8') {
    const fd = openPrivateFile(filePath);
    try {
        return fs.readFileSync(fd, encoding);
    } finally {
        fs.closeSync(fd);
    }
}

export function writePrivateFile(filePath, data) {
    try {
        restrictPrivateFile(filePath);
    } catch (error) {
        if (error.code !== 'ENOENT') {
            throw error;
        }
    }

    const temporaryPath = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${randomUUID()}.tmp`);
    const fd = fs.openSync(temporaryPath, 'wx', FILE_MODE);
    try {
        try {
            restrictMode(fd, fs.fstatSync(fd), FILE_MODE);
            fs.writeFileSync(fd, data);
        } finally {
            fs.closeSync(fd);
        }
        fs.renameSync(temporaryPath, filePath);
    } catch (error) {
        fs.rmSync(temporaryPath, { force: true });
        throw error;
    }
}

export function appendPrivateFile(filePath, data) {
    let fd;
    try {
        fd = openPrivateFile(filePath, APPEND_EXISTING);
    } catch (error) {
        if (error.code !== 'ENOENT') {
            throw error;
        }
        try {
            fd = fs.openSync(filePath, 'ax', FILE_MODE);
            restrictMode(fd, fs.fstatSync(fd), FILE_MODE);
        } catch (createError) {
            if (fd !== undefined) {
                fs.closeSync(fd);
            }
            if (createError.code !== 'EEXIST') {
                throw createError;
            }
            fd = openPrivateFile(filePath, APPEND_EXISTING);
        }
    }
    try {
        fs.writeFileSync(fd, data);
    } finally {
        fs.closeSync(fd);
    }
}
