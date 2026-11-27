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

const host = digest(`${process.platform}:${os.hostname()}`);
const windowsRoot = process.env.SystemRoot;
let ownGeneration;
let ownScope;

function readProcessScope() {
    try {
        if (process.platform === 'linux') {
            // The procfs view must use the same PIDs as process.kill().
            if (fs.readlinkSync('/proc/self') !== String(process.pid)) return {};
            const boot = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
            const namespace = fs.readlinkSync('/proc/self/ns/pid');
            if (BOOT_ID.test(boot) && /^pid:\[[0-9]+\]$/.test(namespace)) {
                return { boot: digest('linux:' + boot.toLowerCase()), namespace: digest(namespace) };
            }
        } else if (process.platform === 'darwin') {
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
        if (process.platform === 'linux') {
            const boot = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
            const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
            // The command name can contain spaces and closing parentheses. Starttime is field 22.
            const start = stat.slice(stat.lastIndexOf(')') + 1).trim().split(/\s+/)[19];
            if (/^[a-f0-9-]{36}$/.test(boot) && /^[0-9]+$/.test(start || '')) {
                return digest(`${boot}:${start}`);
            }
        } else if (process.platform === 'darwin' || process.platform === 'freebsd') {
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
    const generation = ownGeneration ??= processGeneration(process.pid);
    const { boot, namespace } = ownScope ??= readProcessScope();
    const scope = boot ? ` ${boot} ${namespace}` : '';
    return `${host} ${generation}${scope}\n`;
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
    const scope = identity.boot ? (ownScope ??= readProcessScope()) : {};
    const sameBoot = identity.boot && identity.boot === scope.boot;
    // A boot match can establish ownership after a rename, within the same PID namespace.
    if (sameBoot && identity.namespace !== scope.namespace) return 'unverified';
    if (!sameBoot && identity.host && identity.host !== host) return 'unverified';
    try {
        process.kill(pid, 0);
    } catch (error) {
        if (error.code === 'ESRCH') return 'dead';
        if (error.code === 'EPERM') return 'unverified';
        throw error;
    }
    if (identity.generation === '-') return 'unverified';
    const current = pid === process.pid ? (ownGeneration ??= processGeneration(pid)) : processGeneration(pid);
    if (current === '-') return 'unverified';
    return current === identity.generation ? 'active' : 'dead';
}
