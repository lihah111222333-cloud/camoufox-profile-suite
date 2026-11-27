import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { constants as bufferLimits } from 'node:buffer';

const MAX_CAPTURE_BYTES = 128 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
const MAX_PAYLOAD_DEPTH = 32;
const MAX_PAYLOAD_ENTRIES = 100_000;
const MAX_LOCAL_BYTES = bufferLimits.MAX_STRING_LENGTH;
const STAT_OPTIONS = { bigint: true };
const IS_LINUX = process.platform === 'linux';
// Darwin's sys/fcntl.h defines O_NOFOLLOW_ANY, which Node does not expose.
const NOFOLLOW_ANY = process.platform === 'darwin' ? 0x20000000 : 0;
const SECURE_DIRECTORY_OPEN = IS_LINUX || Boolean(NOFOLLOW_ANY);
const FILE_FLAGS = (NOFOLLOW_ANY || fs.constants.O_NOFOLLOW) | fs.constants.O_NONBLOCK;
const DIR_FLAGS = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | FILE_FLAGS;
const UNSAFE_NAME = /[\\:\x00-\x1f\x7f]/;

function captureError(message, code = 'ERR_CAPTURE_UNSAFE') {
    return Object.assign(new Error(message), { code });
}

function sameNode(left, right) {
    return left.dev === right.dev && left.ino === right.ino;
}

function sameVersion(left, right) {
    return sameNode(left, right) && left.nlink === right.nlink && left.size === right.size &&
        left.ctimeNs === right.ctimeNs && left.mtimeNs === right.mtimeNs;
}

export function resolveFilesystemPath(value) {
    const resolved = path.resolve(value);
    // These macOS system aliases are outside the supplied capture or output tree.
    return NOFOLLOW_ANY && /^\/(?:tmp|var|etc)(?:\/|$)/.test(resolved)
        ? `/private${resolved}`
        : resolved;
}

function resolveExistingAncestors(filePath) {
    try {
        return fs.realpathSync.native(filePath);
    } catch (error) {
        const parent = path.dirname(filePath);
        if (error.code !== 'ENOENT' || parent === filePath) throw error;
        return path.join(resolveExistingAncestors(parent), path.basename(filePath));
    }
}

function openDirectoryEntry(entry) {
    if (SECURE_DIRECTORY_OPEN) return fs.openSync(entry, DIR_FLAGS);
    const stat = fs.lstatSync(entry, STAT_OPTIONS);
    if (!stat.isDirectory()) throw captureError('Capture directory must not be linked');
    return null;
}

function closeDirectory(fd) {
    if (fd !== null) fs.closeSync(fd);
}

function directoryStat(directory) {
    return directory.fd === null ? fs.lstatSync(directory.path, STAT_OPTIONS) : fs.fstatSync(directory.fd, STAT_OPTIONS);
}

function openDirectory(directoryPath, { create = false, trustedLocal = false } = {}) {
    if (!SECURE_DIRECTORY_OPEN && !trustedLocal) {
        throw captureError('No-follow capture directory access requires Linux or macOS');
    }

    const root = path.parse(directoryPath).root;
    const names = directoryPath.slice(root.length).split(path.sep).filter(Boolean);
    let fd = openDirectoryEntry(root);
    let current = root;
    try {
        for (const name of names) {
            const parent = IS_LINUX ? `/proc/self/fd/${fd}` : current;
            const entry = path.join(parent, name);
            let next;
            try {
                next = openDirectoryEntry(entry);
            } catch (error) {
                if (IS_LINUX && error.code === 'ENOENT' && !fs.existsSync(parent)) {
                    throw captureError('Descriptor-relative capture access requires /proc/self/fd');
                }
                if (!create || error.code !== 'ENOENT') throw error;
                try {
                    fs.mkdirSync(entry, { mode: 0o700 });
                } catch (mkdirError) {
                    if (mkdirError.code !== 'EEXIST') throw mkdirError;
                }
                next = openDirectoryEntry(entry);
            }
            closeDirectory(fd);
            fd = next;
            current = path.join(current, name);
        }
        const directory = {
            fd,
            path: directoryPath,
            lookup: IS_LINUX ? `/proc/self/fd/${fd}` : directoryPath
        };
        return { ...directory, stat: directoryStat(directory) };
    } catch (error) {
        closeDirectory(fd);
        throw error;
    }
}

function assertDirectory(directory) {
    const current = fs.lstatSync(directory.path, { ...STAT_OPTIONS, throwIfNoEntry: false });
    if (!current?.isDirectory() || !sameNode(directory.stat, current) ||
        path.relative(directory.path, fs.realpathSync.native(directory.path)) !== '') {
        throw captureError('Capture directory changed during access');
    }
}

function withCaptureDirectory(trafficDir, parents, trustedLocal, useDirectory) {
    const root = openDirectory(resolveFilesystemPath(trafficDir), { trustedLocal });
    let directory = root;
    try {
        if (parents.length > 0) directory = openDirectory(path.join(root.path, ...parents), { trustedLocal });
        const verifyDirectories = () => {
            assertDirectory(root);
            if (directory !== root) assertDirectory(directory);
        };
        verifyDirectories();
        return useDirectory(directory, verifyDirectories);
    } finally {
        if (directory !== root) closeDirectory(directory.fd);
        closeDirectory(root.fd);
    }
}

function withCaptureFile(trafficDir, components, { trustedLocal, maxBytes, flags, prefixBytes }, useFile) {
    const maximum = trustedLocal ? MAX_LOCAL_BYTES : MAX_CAPTURE_BYTES;
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > maximum) {
        throw captureError('Invalid capture file size limit');
    }
    if (prefixBytes !== undefined && (!Number.isSafeInteger(prefixBytes) || prefixBytes < 0)) {
        throw captureError('Invalid capture file prefix length');
    }
    const name = components.at(-1);
    return withCaptureDirectory(trafficDir, components.slice(0, -1), trustedLocal, (directory, verifyDirectories) => {
        const entry = path.join(directory.lookup, name);
        const before = fs.lstatSync(entry, STAT_OPTIONS);
        if (!before.isFile() || before.nlink !== 1n) {
            throw captureError('Capture entry must be a regular file with one directory link');
        }
        if ((prefixBytes === undefined ? before.size : BigInt(prefixBytes)) > BigInt(maxBytes)) {
            throw captureError(`Capture entry exceeds ${maxBytes} bytes`, 'ERR_CAPTURE_TOO_LARGE');
        }

        let fd;
        try {
            fd = fs.openSync(entry, flags | FILE_FLAGS);
        } catch (error) {
            if (error.code === 'ENOENT') throw captureError('Capture file changed during access');
            throw error;
        }
        try {
            const verifyFile = () => {
                verifyDirectories();
                const current = fs.lstatSync(entry, { ...STAT_OPTIONS, throwIfNoEntry: false });
                if (!sameVersion(before, fs.fstatSync(fd, STAT_OPTIONS)) ||
                    !current || !sameVersion(before, current)) {
                    throw captureError('Capture file changed during access');
                }
            };
            verifyFile();
            return useFile(fd, Number(before.size), verifyFile, entry);
        } finally {
            fs.closeSync(fd);
        }
    });
}

function readBytes(fd, size, verifyFile) {
    const bytes = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
        const count = fs.readSync(fd, bytes, offset, size - offset, offset);
        if (count === 0) throw captureError('Capture file changed during access');
        offset += count;
    }
    verifyFile();
    return bytes;
}

function splitFileName(name) {
    if (typeof name !== 'string' || UNSAFE_NAME.test(name) || name.length > 1024) {
        throw captureError('Invalid capture file reference');
    }
    const components = name.split('/');
    if (components.some((part) => !part || part === '.' || part === '..')) {
        throw captureError('Invalid capture file reference');
    }
    return components;
}

function captureFileComponents(fileName) {
    const components = splitFileName(fileName);
    if (components.length === 1 || fileName === '.private/sslkeylog.txt' ||
        fileName === '.private/necko-pre-tls.moz_log') return components;
    throw captureError('Invalid capture file reference');
}

function payloadFileComponents(relativePath) {
    const components = splitFileName(relativePath);
    if (components.length < 2 || components.length > MAX_PAYLOAD_DEPTH + 1 || components[0] !== 'payloads') {
        throw captureError('Capture payload reference must be inside payloads/');
    }
    return components;
}

/** Read an ordinary file explicitly referenced from the capture's payload directory. */
export function readCapturePayload(trafficDir, relativePath, { maxBytes = MAX_PAYLOAD_BYTES, trustedLocal = false } = {}) {
    return withCaptureFile(trafficDir, payloadFileComponents(relativePath), {
        trustedLocal, maxBytes, flags: fs.constants.O_RDONLY
    }, readBytes);
}

export function hashCapturePayload(trafficDir, relativePath, {
    trustedLocal = false, maxBytes = trustedLocal ? MAX_LOCAL_BYTES : MAX_CAPTURE_BYTES
} = {}) {
    return withCaptureFile(trafficDir, payloadFileComponents(relativePath), {
        trustedLocal, maxBytes, flags: fs.constants.O_RDONLY
    }, (fd, size, verifyFile) => hashFileBytes(fd, size, size, verifyFile));
}

/** Measure a payload already on disk without reading its contents. */
export function measureCapturePayload(trafficDir, relativePath, { trustedLocal = false } = {}) {
    return withCaptureFile(trafficDir, payloadFileComponents(relativePath), {
        trustedLocal, maxBytes: trustedLocal ? MAX_LOCAL_BYTES : MAX_CAPTURE_BYTES, flags: fs.constants.O_RDONLY
    }, (_fd, size) => size);
}

/** Remove a recorder-owned abandoned attachment after verifying its file identity. */
export function removeCapturePayload(trafficDir, relativePath, { trustedLocal = false } = {}) {
    return withCaptureFile(trafficDir, payloadFileComponents(relativePath), {
        trustedLocal, maxBytes: trustedLocal ? MAX_LOCAL_BYTES : MAX_CAPTURE_BYTES, flags: fs.constants.O_RDONLY
    }, (_fd, _size, _verifyFile, entry) => fs.unlinkSync(entry));
}

/** Read a fixed capture artifact, optionally allowing an absent file. */
export function readCaptureFile(trafficDir, fileName, {
    optional = false, trustedLocal = false, maxBytes = trustedLocal ? MAX_LOCAL_BYTES : MAX_CAPTURE_BYTES
} = {}) {
    return accessCaptureArtifact(trafficDir, fileName, { optional, trustedLocal, maxBytes }, readBytes);
}

function accessCaptureArtifact(trafficDir, fileName, { optional, trustedLocal, maxBytes, prefixBytes }, useFile) {
    const components = captureFileComponents(fileName);
    if (optional && !SECURE_DIRECTORY_OPEN && !trustedLocal &&
        !fs.lstatSync(path.join(trafficDir, ...components), { throwIfNoEntry: false })) return null;
    try {
        return withCaptureFile(trafficDir, components, { trustedLocal, maxBytes, prefixBytes, flags: fs.constants.O_RDONLY }, useFile);
    } catch (error) {
        if (optional && error.code === 'ENOENT') return null;
        throw error;
    }
}

/** Hash a bounded capture file or its checkpointed prefix without loading it into memory. */
export function hashCaptureFile(trafficDir, fileName, {
    optional = false, trustedLocal = false, maxBytes = MAX_CAPTURE_BYTES, prefixBytes
} = {}) {
    return accessCaptureArtifact(trafficDir, fileName, { optional, trustedLocal, maxBytes, prefixBytes }, (fd, size, verifyFile) => {
        const length = prefixBytes ?? size;
        if (length > size) {
            throw captureError(`${fileName} byte length mismatch`);
        }

        return hashFileBytes(fd, size, length, verifyFile);
    });
}

function hashFileBytes(fd, size, length, verifyFile) {
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(Math.min(length, 64 * 1024));
    let offset = 0;
    while (offset < length) {
        const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, length - offset), offset);
        if (count === 0) throw captureError('Capture file changed during access');
        hash.update(buffer.subarray(0, count));
        offset += count;
    }
    verifyFile();
    return { sha256: hash.digest('hex'), bytes: size };
}

function verifyDirectoryListing(directory, verifyDirectories) {
    verifyDirectories();
    if (!sameVersion(directory.stat, directoryStat(directory))) {
        throw captureError('Capture directory changed during listing');
    }
}

/** List a caller-selected directory without traversing links. */
export function listCaptureDirectory(directory, { trustedLocal = false } = {}) {
    return withCaptureDirectory(directory, [], trustedLocal, (opened, verifyDirectories) => {
        const entries = fs.readdirSync(opened.lookup, { withFileTypes: true });
        verifyDirectoryListing(opened, verifyDirectories);
        return entries;
    });
}

export function listCapturePayloads(trafficDir, { trustedLocal = false } = {}) {
    const files = [];
    let visited = 0;
    let opened = false;

    function visit(components) {
        withCaptureDirectory(trafficDir, components, trustedLocal, (directory, verifyDirectories) => {
            opened = true;
            const listing = fs.opendirSync(directory.lookup);
            try {
                let entry;
                while ((entry = listing.readSync()) !== null) {
                    visited += 1;
                    if (visited > MAX_PAYLOAD_ENTRIES) {
                        throw captureError('Capture payload directory exceeds inventory limits', 'ERR_CAPTURE_TOO_LARGE');
                    }
                    const relativePath = [...components, entry.name].join('/');
                    splitFileName(relativePath);
                    if (entry.isDirectory()) {
                        if (components.length >= MAX_PAYLOAD_DEPTH) {
                            throw captureError('Capture payload directory exceeds inventory limits', 'ERR_CAPTURE_TOO_LARGE');
                        }
                        visit([...components, entry.name]);
                    } else if (entry.isFile()) {
                        files.push(relativePath);
                    } else {
                        throw captureError(`Expected regular payload file or directory: ${relativePath}`);
                    }
                }
            } finally {
                listing.closeSync();
            }
            verifyDirectoryListing(directory, verifyDirectories);
        });
    }

    try {
        visit(['payloads']);
    } catch (error) {
        if (opened || error.code !== 'ENOENT') throw error;
    }
    return files;
}

/** Trim a validated crash suffix from the same file whose bytes were verified. */
export function truncateCaptureFile(trafficDir, fileName, expectedBytes, length, { trustedLocal = false } = {}) {
    if (!Buffer.isBuffer(expectedBytes) || !Number.isSafeInteger(length) ||
        length < 0 || length > expectedBytes.length) {
        throw captureError('Invalid capture recovery length');
    }
    const maxBytes = trustedLocal ? MAX_LOCAL_BYTES : MAX_CAPTURE_BYTES;
    return withCaptureFile(trafficDir, captureFileComponents(fileName), { trustedLocal, maxBytes, flags: fs.constants.O_RDWR },
        (fd, size, verifyFile) => {
            if (size !== expectedBytes.length || !readBytes(fd, size, verifyFile).equals(expectedBytes)) {
                throw captureError('Capture changed after recovery validation');
            }
            fs.ftruncateSync(fd, length);
        });
}

/** Publish a private file through a temporary inode in the destination directory. */
export function writeCaptureExport(outputPath, content, { replace = true, protectedPaths = [], recordedWirePath } = {}) {
    const resolvedOutput = resolveFilesystemPath(outputPath);
    const protectedFiles = [...protectedPaths];
    // An archived wire path can only veto publication at the selected destination.
    if (typeof recordedWirePath === 'string' && path.isAbsolute(recordedWirePath)) {
        const wirePath = resolveFilesystemPath(recordedWirePath);
        const comparable = (value) => NOFOLLOW_ANY || process.platform === 'win32'
            ? value.normalize('NFC').toLowerCase() : value;
        if (comparable(wirePath) === comparable(resolvedOutput)) protectedFiles.push(wirePath);
    }
    const reserved = protectedFiles.map((filePath) => resolveExistingAncestors(resolveFilesystemPath(filePath)));
    const physicalOutput = reserved.length ? resolveExistingAncestors(resolvedOutput) : resolvedOutput;
    for (const source of reserved) {
        const relative = path.relative(source, physicalOutput);
        if (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)) {
            throw captureError('Capture export destination overlaps the input capture');
        }
    }
    // The standalone default is already relative to the operator's pinned cwd.
    const parent = path.dirname(path.resolve(outputPath));
    const useWorkingDirectory = !replace && parent === process.cwd();
    const directory = useWorkingDirectory ? null : openDirectory(path.dirname(resolvedOutput), {
        create: replace, trustedLocal: true
    });
    const lookup = directory?.lookup || '.';
    const target = path.join(lookup, path.basename(outputPath));
    const temporary = path.join(lookup, `.capture-export-${randomUUID()}.tmp`);
    try {
        if (directory) {
            assertDirectory(directory);
            const existing = fs.lstatSync(target, { ...STAT_OPTIONS, throwIfNoEntry: false });
            if (existing && (!existing.isFile() || existing.nlink !== 1n)) {
                throw captureError('Capture export destination must be an ordinary file');
            }
            if (existing && reserved.some((source) => {
                const sourceNode = fs.lstatSync(source, { ...STAT_OPTIONS, throwIfNoEntry: false });
                return sourceNode && sameNode(existing, sourceNode);
            })) {
                throw captureError('Capture export destination overlaps the input capture');
            }
        }
        const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT |
            fs.constants.O_EXCL | FILE_FLAGS, 0o600);
        try {
            const created = fs.fstatSync(fd, STAT_OPTIONS);
            let bytes = 0;
            const chunks = typeof content === 'string' || ArrayBuffer.isView(content) ? [content] : content;
            for (const chunk of chunks) {
                const buffer = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
                fs.writeFileSync(fd, buffer);
                bytes += buffer.byteLength;
            }
            fs.fsyncSync(fd);
            if (directory) assertDirectory(directory);
            if (!sameNode(created, fs.lstatSync(temporary, STAT_OPTIONS))) {
                throw captureError('Capture export temporary file changed during writing');
            }
            if (replace) fs.renameSync(temporary, target);
            else fs.linkSync(temporary, target);
            return bytes;
        } finally {
            try {
                const existing = fs.lstatSync(temporary, { ...STAT_OPTIONS, throwIfNoEntry: false });
                if (existing && sameNode(existing, fs.fstatSync(fd, STAT_OPTIONS))) fs.unlinkSync(temporary);
            } finally {
                fs.closeSync(fd);
            }
        }
    } finally {
        if (directory) closeDirectory(directory.fd);
    }
}
