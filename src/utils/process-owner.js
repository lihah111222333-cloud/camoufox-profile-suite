import childProcess from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readPrivateFile } from './private-storage.js';

const OWNER_METADATA = /^([a-f0-9]{64}) ([a-f0-9]{64}|-)(?: ([a-f0-9]{64}) ([a-f0-9]{64}|-))?\n$/;
const BOOT_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const MAX_MARKER_BYTES = 260;

function digest(value) {
    return createHash('sha256').update(value).digest('hex');
}

const windowsRoot = process.env.SystemRoot;
let host;
let ownGeneration;
let ownScope;

function hostDigest() {
    return host ??= digest(`${process.platform}:${os.hostname()}`);
}

function readLinuxScope() {
    try {
        // A single NSpid also rules out a parent namespace with a coincidentally equal PID.
        const pid = String(process.pid);
        if (fs.readlinkSync('/proc/self') !== pid) return null;
        const status = fs.readFileSync('/proc/self/status', 'utf8');
        if (/^NSpid:[ \t]*([0-9]+)[ \t]*$/m.exec(status)?.[1] !== pid) return null;
    } catch {
        return null;
    }

    const scope = {};
    try {
        const bootId = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
        if (BOOT_ID.test(bootId)) {
            scope.bootId = bootId;
            const namespace = fs.readlinkSync('/proc/self/ns/pid');
            if (/^pid:\[[0-9]+\]$/.test(namespace)) {
                scope.boot = digest('linux:' + bootId.toLowerCase());
                scope.namespace = digest(namespace);
            }
        }
    } catch {
        // Keep the validated PID view available for compatibility with earlier markers.
    }
    return scope;
}

function readLinuxProcess(pid, bootId) {
    if (!bootId) return {};
    try {
        const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
        const commandEnd = stat.lastIndexOf(')');
        if (!stat.startsWith(`${pid} (`) || commandEnd <= String(pid).length + 1) return {};
        // The command can contain spaces and parentheses. Fields 3, 20 and 22 follow it.
        const fields = stat.slice(commandEnd + 1).trim().split(/\s+/);
        const [state] = fields;
        const threads = fields[17];
        const start = fields[19];
        if (!/^[a-zA-Z]$/.test(state) || !/^[1-9][0-9]*$/.test(threads) || !/^[0-9]+$/.test(start)) return {};
        return {
            generation: digest(`${bootId}:${start}`),
            // A zombie thread-group leader can still have live worker threads.
            exited: state === 'Z' && threads === '1'
        };
    } catch {
        return {};
    }
}

function readProcessScope() {
    try {
        if (process.platform === 'darwin') {
            const boot = childProcess.execFileSync('/usr/sbin/sysctl', ['-n', 'kern.bootsessionuuid'], {
                encoding: 'utf8', env: { LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'ignore'], timeout: 1_000
            }).trim();
            if (BOOT_ID.test(boot)) return { boot: digest('darwin:' + boot.toLowerCase()), namespace: '-' };
        }
    } catch {
        // The original host and process checks remain available without a boot marker.
    }
    return {};
}

function processGeneration(pid) {
    try {
        if (process.platform === 'darwin' || process.platform === 'freebsd') {
            const start = childProcess.execFileSync('/bin/ps', ['-p', String(pid), '-o', 'lstart='], {
                encoding: 'utf8', env: { LC_ALL: 'C', TZ: 'UTC0' }, stdio: ['ignore', 'pipe', 'ignore'], timeout: 1_000
            }).trim();
            if (start) return digest(start);
        } else if (process.platform === 'win32' && /^[a-z]:[\\/]windows[\\/]?$/i.test(windowsRoot || '')) {
            const powershell = path.join(windowsRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
            const start = childProcess.execFileSync(powershell, [
                '-NoProfile', '-NonInteractive', '-Command', `(Get-Process -Id ${pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks`
            ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 1_000, windowsHide: true }).trim();
            if (/^[0-9]+$/.test(start)) return digest(start);
        }
    } catch {
        // A failed query leaves this process's generation unknown.
    }
    return '-';
}

export function describeProcessOwner() {
    const linux = process.platform === 'linux';
    const scope = linux ? readLinuxScope() : (ownScope ??= readProcessScope());
    const generation = linux ? readLinuxProcess(process.pid, scope?.bootId).generation ?? '-'
        : (ownGeneration ??= processGeneration(process.pid));
    const coordinates = scope?.boot ? ` ${scope.boot} ${scope.namespace}` : '';
    return `${hostDigest()} ${generation}${coordinates}\n`;
}

export function isSameProcessScope(identity) {
    const scope = process.platform === 'linux' ? readLinuxScope() : (ownScope ??= readProcessScope());
    return Boolean(scope?.boot && identity.boot === scope.boot && identity.namespace === scope.namespace);
}

export function readProcessOwner(filePath) {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_MARKER_BYTES ||
        (typeof process.geteuid === 'function' && stat.uid !== process.geteuid())) return null;

    const marker = readPrivateFile(filePath, 'utf8', { requireOwner: true, restrict: false, expectedFile: stat });
    if (!marker) return { host: '', generation: '-' };
    const match = OWNER_METADATA.exec(marker);
    if (match?.[0] !== marker) return null;
    const [, host, generation, boot, namespace] = match;
    return boot ? { host, generation, boot, namespace } : { host, generation };
}

export function processOwnerStatus(pid, identity) {
    const linux = process.platform === 'linux';
    const scope = linux ? readLinuxScope() : identity.boot ? (ownScope ??= readProcessScope()) : {};
    if (!scope || (linux && identity.boot && !scope.boot)) return 'unverified';
    const sameBoot = identity.boot && identity.boot === scope.boot;
    // A boot match can establish ownership after a rename, within the same PID namespace.
    if (sameBoot && identity.namespace !== scope.namespace) return 'unverified';
    if (!sameBoot && identity.host && identity.host !== hostDigest()) return 'unverified';
    try {
        process.kill(pid, 0);
    } catch (error) {
        if (error.code === 'ESRCH') return 'dead';
        if (error.code === 'EPERM') return 'unverified';
        throw error;
    }
    if (identity.generation === '-') return 'unverified';
    if (linux) {
        const { generation, exited } = readLinuxProcess(pid, scope.bootId);
        if (!generation) return 'unverified';
        if (generation === identity.generation) return exited ? 'dead' : 'active';
        // Earlier markers can contain a generation sampled from an unrelated procfs view.
        return sameBoot ? 'dead' : 'unverified';
    }
    const current = pid === process.pid ? (ownGeneration ??= processGeneration(pid)) : processGeneration(pid);
    if (current === '-') return 'unverified';
    return current === identity.generation ? 'active' : 'dead';
}
