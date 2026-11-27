import childProcess from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readPrivateFile } from './private-storage.js';

const OWNER_METADATA = /^([a-f0-9]{64}) ([a-f0-9]{64}|-)\n$/;
const MAX_MARKER_BYTES = 130;

function digest(value) {
    return createHash('sha256').update(value).digest('hex');
}

const host = digest(`${process.platform}:${os.hostname()}`);
const windowsRoot = process.env.SystemRoot;
let ownGeneration;

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
    return `${host} ${generation}\n`;
}

export function readProcessOwner(filePath) {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_MARKER_BYTES ||
        (typeof process.geteuid === 'function' && stat.uid !== process.geteuid())) return null;

    const marker = readPrivateFile(filePath, 'utf8', { requireOwner: true, restrict: false, expectedFile: stat });
    if (!marker) return { host: '', generation: '-' };
    const match = OWNER_METADATA.exec(marker);
    return match?.[0] === marker ? { host: match[1], generation: match[2] } : null;
}

export function isDeadProcessOwner(pid, { host: ownerHost, generation }) {
    if (ownerHost && ownerHost !== host) return false;
    try {
        process.kill(pid, 0);
    } catch (error) {
        if (error.code === 'ESRCH') return true;
        if (error.code === 'EPERM') return false;
        throw error;
    }
    if (generation === '-') return false;
    const current = pid === process.pid ? (ownGeneration ??= processGeneration(pid)) : processGeneration(pid);
    return current !== '-' && current !== generation;
}
