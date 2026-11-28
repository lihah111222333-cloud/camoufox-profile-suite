// SPDX-License-Identifier: AGPL-3.0-or-later
// xfrpc-ios (NexusEdge netd) Native Engine + DoT DNS Disguise + TCP<->UDP (0xF1/0xF2) Bridge
// Integrates compiled macOS arm64 `netd` + plugins (tls, dot, router, fwd_local) with
// a zero-dependency Node.js TCP<->UDP (0xF1 UDP_CONN / 0xF2 UDP_MUX) converter and fallback relay.

import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
    ensurePrivateDirectory,
    writePrivateFile
} from '../src/utils/private-storage.js';
import { ensureStateDirectory } from '../src/utils/state-paths.js';
import { startLocalProxyRelay } from './proxy-relay.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VENDOR_NETD_DIR = path.join(__dirname, 'vendor', 'netd');
const NETD_BIN = path.join(VENDOR_NETD_DIR, 'netd');
const NETD_PLUGINS_DIR = path.join(VENDOR_NETD_DIR, 'plugins');

/**
 * Mirror vendored `netd` + plugins into a private user-owned 0700 directory on the internal disk
 * (`~/Library/Caches/CamoufoxStudio/netd/`) so netd's strict ancestor-permission check passes
 * even when Camoufox Studio is launched from `/Applications/Camoufox Studio.app` (where `/Applications` is group-writable).
 */
function resolveExecutableNetdPaths() {
    if (process.platform !== 'darwin' || !fs.existsSync(NETD_BIN)) {
        return { bin: NETD_BIN, pluginsDir: NETD_PLUGINS_DIR };
    }
    try {
        const base = path.join(os.homedir(), 'Library', 'Caches', 'CamoufoxStudio');
        const dstRoot = path.join(base, 'netd');
        const dstPlugins = path.join(dstRoot, 'plugins');
        ensurePrivateDirectory(base, { requireOwner: true });
        ensurePrivateDirectory(dstRoot, { requireOwner: true });
        ensurePrivateDirectory(dstPlugins, { requireOwner: true });

        const copyIfChanged = (src, dst, mode) => {
            const sst = fs.statSync(src);
            let need = true;
            try {
                const dstStat = fs.statSync(dst);
                if (dstStat.size === sst.size && Math.abs(dstStat.mtimeMs - sst.mtimeMs) < 1000) {
                    need = false;
                }
            } catch {
                // missing
            }
            if (need) {
                fs.copyFileSync(src, dst);
                fs.chmodSync(dst, mode);
                fs.utimesSync(dst, sst.atime, sst.mtime);
            }
        };

        const dstBin = path.join(dstRoot, 'netd');
        copyIfChanged(NETD_BIN, dstBin, 0o755);
        for (const name of ['libnetd_tls.dylib', 'libnetd_dot.dylib', 'libnetd_router.dylib', 'libnetd_fwd_local.dylib']) {
            const s = path.join(NETD_PLUGINS_DIR, name);
            if (fs.existsSync(s)) copyIfChanged(s, path.join(dstPlugins, name), 0o755);
        }
        return { bin: dstBin, pluginsDir: dstPlugins };
    } catch {
        return { bin: NETD_BIN, pluginsDir: NETD_PLUGINS_DIR };
    }
}

export const DNS_DISGUISE_PRESETS = {
    'dot-cloudflare': {
        id: 'dot-cloudflare',
        label: 'Cloudflare DoT (1.1.1.1:853)',
        sni: 'cloudflare-dns.com',
        servers: '1.1.1.1:853#cloudflare-dns.com,1.0.0.1:853#cloudflare-dns.com'
    },
    'dot-google': {
        id: 'dot-google',
        label: 'Google DoT (8.8.8.8:853)',
        sni: 'dns.google',
        servers: '8.8.8.8:853#dns.google,8.8.4.4:853#dns.google'
    },
    'dot-quad9': {
        id: 'dot-quad9',
        label: 'Quad9 DoT (9.9.9.9:853)',
        sni: 'dns.quad9.net',
        servers: '9.9.9.9:853#dns.quad9.net,149.112.112.112:853#dns.quad9.net'
    },
    'dot-adguard': {
        id: 'dot-adguard',
        label: 'AdGuard DoT (94.140.14.14:853)',
        sni: 'dns.adguard-dns.com',
        servers: '94.140.14.14:853#dns.adguard-dns.com,1.1.1.1:853#cloudflare-dns.com'
    },
    'remote-proxy': {
        id: 'remote-proxy',
        label: 'Remote Exit DNS + DoT Fallback',
        sni: 'cloudflare-dns.com',
        servers: '1.1.1.1:853#cloudflare-dns.com,8.8.8.8:853#dns.google'
    }
};

export const DEFAULT_NETWORK_CONFIG = {
    engine: 'xfrpc-netd',          // 'xfrpc-netd' | 'node-relay'
    udp_mode: 'socks5-udp',        // 'socks5-udp' | 'udp-over-tcp' | 'block-udp'
    dns_disguise: 'dot-cloudflare',
    dns_custom_servers: '',
    dns_split_rules: '',
    egress: 'prefer_v4',           // 'v4' | 'v6' | 'prefer_v4' | 'prefer_v6'
    tcp2udp_enable: true
};

export function normalizeNetworkConfig(raw = {}) {
    const engine = raw?.engine === 'node-relay' ? 'node-relay' : 'xfrpc-netd';
    const udp_mode = ['socks5-udp', 'udp-over-tcp', 'block-udp'].includes(raw?.udp_mode)
        ? raw.udp_mode
        : DEFAULT_NETWORK_CONFIG.udp_mode;
    const dns_disguise = DNS_DISGUISE_PRESETS[raw?.dns_disguise]
        ? raw.dns_disguise
        : DEFAULT_NETWORK_CONFIG.dns_disguise;
    const egress = ['v4', 'v6', 'prefer_v4', 'prefer_v6'].includes(raw?.egress)
        ? raw.egress
        : DEFAULT_NETWORK_CONFIG.egress;
    return {
        engine,
        udp_mode,
        dns_disguise,
        dns_custom_servers: String(raw?.dns_custom_servers || '').replace(/[\r\n;]/g, '').trim(),
        dns_split_rules: String(raw?.dns_split_rules || '').replace(/[\r\n;]/g, '').trim(),
        egress,
        tcp2udp_enable: raw?.tcp2udp_enable !== false
    };
}

export function detectNetdAvailability() {
    const pluginFiles = [
        'libnetd_tls.dylib',
        'libnetd_dot.dylib',
        'libnetd_router.dylib',
        'libnetd_fwd_local.dylib'
    ];
    const hasBin = fs.existsSync(NETD_BIN);
    const plugins = pluginFiles.map((name) => ({
        name,
        present: fs.existsSync(path.join(NETD_PLUGINS_DIR, name))
    }));
    const available = process.platform === 'darwin' && hasBin && plugins.every((p) => p.present);
    return {
        available,
        binPath: NETD_BIN,
        pluginsDir: NETD_PLUGINS_DIR,
        plugins
    };
}

const recentlyReservedPorts = new Set();

function reserveLoopbackPort(attempt = 0) {
    return new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.once('error', reject);
        srv.listen(0, '127.0.0.1', () => {
            const addr = srv.address();
            const port = typeof addr === 'object' && addr ? addr.port : 0;
            srv.close(() => {
                if (recentlyReservedPorts.has(port) && attempt < 16) {
                    resolve(reserveLoopbackPort(attempt + 1));
                    return;
                }
                recentlyReservedPorts.add(port);
                const t = setTimeout(() => recentlyReservedPorts.delete(port), 15000);
                t.unref?.();
                resolve(port);
            });
        });
    });
}

function waitForTcpListen(host, port, timeoutMs = 4000, child = null) {
    const deadline = Date.now() + timeoutMs;
    return new Promise((resolve, reject) => {
        const attempt = () => {
            if (child && child.exitCode !== null) {
                reject(new Error(`netd exited early with code ${child.exitCode}`));
                return;
            }
            const sock = net.createConnection({ host, port });
            sock.once('connect', () => {
                sock.destroy();
                resolve();
            });
            sock.once('error', () => {
                sock.destroy();
                if (Date.now() >= deadline) {
                    reject(new Error(`Timed out waiting for ${host}:${port}`));
                } else {
                    setTimeout(attempt, 15);
                }
            });
        };
        attempt();
    });
}

function formatUpstreamRouteUrl(proxy) {
    if (!proxy || !proxy.host || !proxy.port || proxy.kind === 'wireguard') {
        return 'direct';
    }
    const kind = String(proxy.kind || 'http').toLowerCase();
    const scheme = kind === 'socks5h' ? 'socks5' : kind;
    const host = proxy.host.includes(':') && !proxy.host.startsWith('[')
        ? `[${proxy.host}]`
        : proxy.host;
    const auth = proxy.username
        ? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password || '')}@`
        : '';
    return `${scheme}://${auth}${host}:${Number(proxy.port)}`;
}

// ---------------------------------------------------------------------------
// xfrpc-ios compatible TCP<->UDP converter (SOCKS5 0xF1 UDP_CONN & 0xF2 UDP_MUX)
// Allows any TCP client to tunnel UDP datagrams ([uint16_be len][payload]) over TCP
// into real UDP datagrams routed through the profile's netd SOCKS5 UDP ASSOCIATE relay.
// ---------------------------------------------------------------------------

function readExact(socket, length, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
        if (!socket.__rxBuf) socket.__rxBuf = Buffer.alloc(0);
        if (socket.__rxBuf.length >= length) {
            const head = socket.__rxBuf.subarray(0, length);
            socket.__rxBuf = socket.__rxBuf.subarray(length);
            resolve(head);
            return;
        }
        let done = false;
        const cleanup = () => {
            clearTimeout(timer);
            socket.off('data', onData);
            socket.off('error', onErr);
            socket.off('close', onClose);
        };
        const finish = (err, buf) => {
            if (done) return;
            done = true;
            cleanup();
            if (err) reject(err);
            else resolve(buf);
        };
        const timer = setTimeout(() => finish(new Error('TCP2UDP handshake timeout')), timeoutMs);
        const onData = (chunk) => {
            socket.__rxBuf = Buffer.concat([socket.__rxBuf, chunk]);
            if (socket.__rxBuf.length >= length) {
                const head = socket.__rxBuf.subarray(0, length);
                socket.__rxBuf = socket.__rxBuf.subarray(length);
                finish(null, head);
            }
        };
        const onErr = (err) => finish(err);
        const onClose = () => finish(new Error('TCP2UDP socket closed'));
        socket.on('data', onData);
        socket.on('error', onErr);
        socket.on('close', onClose);
    });
}

function drainBuffered(socket) {
    const buf = socket.__rxBuf;
    socket.__rxBuf = Buffer.alloc(0);
    return buf && buf.length > 0 ? buf : null;
}

async function readSocksAddr(socket) {
    const atyp = (await readExact(socket, 1))[0];
    let rawAddr;
    let host;
    if (atyp === 0x01) {
        rawAddr = await readExact(socket, 4);
        host = Array.from(rawAddr).join('.');
    } else if (atyp === 0x03) {
        const len = (await readExact(socket, 1))[0];
        const name = await readExact(socket, len);
        rawAddr = Buffer.concat([Buffer.from([len]), name]);
        host = name.toString('utf8');
    } else if (atyp === 0x04) {
        rawAddr = await readExact(socket, 16);
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(rawAddr.readUInt16BE(i).toString(16));
        host = parts.join(':');
    } else {
        throw new Error(`Unsupported ATYP ${atyp}`);
    }
    const portBuf = await readExact(socket, 2);
    return {
        atyp,
        host,
        port: portBuf.readUInt16BE(0),
        raw: Buffer.concat([Buffer.from([atyp]), rawAddr, portBuf])
    };
}

function buildSocks5UdpHeader(targetRaw) {
    return Buffer.concat([Buffer.from([0x00, 0x00, 0x00]), targetRaw]);
}

function stripSocks5UdpHeader(packet) {
    if (packet.length < 7) return null;
    const atyp = packet[3];
    let offset = 4;
    if (atyp === 0x01) offset += 4 + 2;
    else if (atyp === 0x03) offset += 1 + packet[4] + 2;
    else if (atyp === 0x04) offset += 16 + 2;
    else return null;
    if (offset > packet.length) return null;
    return packet.subarray(offset);
}

function buildSocks5Reply(rep, port = 0) {
    const buf = Buffer.alloc(10);
    buf[0] = 0x05;
    buf[1] = rep;
    buf[2] = 0x00;
    buf[3] = 0x01;
    buf[4] = 127;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 1;
    buf.writeUInt16BE(port & 0xffff, 8);
    return buf;
}

async function openUpstreamUdpAssociate(socksHost, socksPort) {
    const ctrl = net.createConnection({ host: socksHost, port: socksPort });
    await new Promise((resolve, reject) => {
        ctrl.once('connect', resolve);
        ctrl.once('error', reject);
    });
    ctrl.write(Buffer.from([0x05, 0x01, 0x00]));
    const greet = await readExact(ctrl, 2);
    if (greet[0] !== 0x05 || greet[1] !== 0x00) {
        ctrl.destroy();
        throw new Error('Upstream local SOCKS5 rejected no-auth');
    }
    // Bind local UDP first and declare its port in UDP ASSOCIATE (required by xfrpc-ios netd)
    const udp = dgram.createSocket('udp4');
    await new Promise((resolve, reject) => {
        udp.once('error', reject);
        udp.bind(0, '127.0.0.1', () => {
            udp.off('error', reject);
            resolve();
        });
    });
    const localPort = udp.address().port;
    const req = Buffer.from([
        0x05, 0x03, 0x00,
        0x01, 127, 0, 0, 1,
        (localPort >> 8) & 0xff, localPort & 0xff
    ]);
    ctrl.write(req);
    const repHead = await readExact(ctrl, 3);
    const bound = await readSocksAddr(ctrl);
    if (repHead[1] !== 0x00 || !bound.port) {
        udp.close();
        ctrl.destroy();
        throw new Error(`UDP ASSOCIATE rejected (${repHead[1]})`);
    }
    const relayHost = (!bound.host || bound.host === '0.0.0.0') ? socksHost : bound.host;
    return { ctrl, udp, relayHost, relayPort: bound.port };
}

async function startTcp2UdpBridge(socksHost, socksPort) {
    const activeSockets = new Set();
    const server = net.createServer((client) => {
        client.on('error', () => {});
        client.setNoDelay(true);
        activeSockets.add(client);
        client.once('close', () => activeSockets.delete(client));

        void (async () => {
            let assoc = null;
            const cleanup = () => {
                try { assoc?.udp?.close(); } catch { /* ignore */ }
                try { assoc?.ctrl?.destroy(); } catch { /* ignore */ }
                assoc = null;
            };
            try {
                const head = await readExact(client, 2);
                if (head[0] !== 0x05) { client.destroy(); return; }
                await readExact(client, head[1]);
                client.write(Buffer.from([0x05, 0x00]));

                const reqHead = await readExact(client, 3);
                const cmd = reqHead[1];
                const target = await readSocksAddr(client);

                if (cmd !== 0xF1 && cmd !== 0xF2) {
                    // Forward standard CONNECT (0x01) directly to local netd proxy
                    if (cmd === 0x01) {
                        const up = net.createConnection({ host: socksHost, port: socksPort });
                        activeSockets.add(up);
                        up.once('close', () => activeSockets.delete(up));
                        await new Promise((resolve, reject) => {
                            up.once('connect', resolve);
                            up.once('error', reject);
                        });
                        up.write(Buffer.from([0x05, 0x01, 0x00]));
                        await readExact(up, 2);
                        up.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), target.raw]));
                        const rep = await readExact(up, 3);
                        const bnd = await readSocksAddr(up);
                        client.write(Buffer.concat([Buffer.from([0x05, rep[1], 0x00]), bnd.raw]));
                        if (rep[1] !== 0x00) { client.end(); up.destroy(); return; }
                        const leftoverClient = drainBuffered(client);
                        const leftoverUp = drainBuffered(up);
                        if (leftoverClient) up.write(leftoverClient);
                        if (leftoverUp) client.write(leftoverUp);
                        client.pipe(up);
                        up.pipe(client);
                        client.once('error', () => up.destroy());
                        up.once('error', () => client.destroy());
                        return;
                    }
                    client.write(buildSocks5Reply(0x07));
                    client.end();
                    return;
                }

                // 0xF1 (UDP_CONN) or 0xF2 (UDP_MUX): open SOCKS5 UDP ASSOCIATE to local netd
                assoc = await openUpstreamUdpAssociate(socksHost, socksPort);
                activeSockets.add(assoc.ctrl);
                assoc.ctrl.once('close', () => activeSockets.delete(assoc.ctrl));

                const fixedHeader = cmd === 0xF1 ? buildSocks5UdpHeader(target.raw) : null;
                client.write(buildSocks5Reply(0x00, 0));

                // Receive UDP replies from netd -> frame as [uint16_be len][payload] over TCP
                assoc.udp.on('message', (msg) => {
                    if (client.destroyed) return;
                    const outPayload = cmd === 0xF1 ? stripSocks5UdpHeader(msg) : msg;
                    if (!outPayload || outPayload.length > 65535) return;
                    const frame = Buffer.allocUnsafe(2 + outPayload.length);
                    frame.writeUInt16BE(outPayload.length, 0);
                    outPayload.copy(frame, 2);
                    try { client.write(frame); } catch { /* ignore */ }
                });

                // Receive TCP length-prefixed frames -> convert to real UDP datagrams
                let rxBuf = drainBuffered(client) || Buffer.alloc(0);
                const flushFrames = () => {
                    while (rxBuf.length >= 2) {
                        const frameLen = rxBuf.readUInt16BE(0);
                        if (rxBuf.length < 2 + frameLen) break;
                        const payload = rxBuf.subarray(2, 2 + frameLen);
                        rxBuf = rxBuf.subarray(2 + frameLen);
                        const dgramBuf = cmd === 0xF1
                            ? Buffer.concat([fixedHeader, payload])
                            : payload;
                        try {
                            assoc?.udp?.send(dgramBuf, assoc.relayPort, assoc.relayHost);
                        } catch {
                            // ignore transient udp send error
                        }
                    }
                };
                flushFrames();
                client.on('data', (chunk) => {
                    rxBuf = Buffer.concat([rxBuf, chunk]);
                    flushFrames();
                });

                client.once('close', cleanup);
                client.once('error', cleanup);
                assoc.ctrl.once('close', () => { cleanup(); client.destroy(); });
                assoc.ctrl.once('error', () => { cleanup(); client.destroy(); });
            } catch {
                try {
                    if (!client.destroyed) {
                        client.write(buildSocks5Reply(0x01));
                        client.end();
                    }
                } catch { /* ignore */ }
                cleanup();
            }
        })();
    });

    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            server.off('error', reject);
            server.on('error', () => {});
            resolve();
        });
    });

    const port = server.address().port;
    return {
        host: '127.0.0.1',
        port,
        close: () => {
            for (const s of activeSockets) {
                try { s.destroy(); } catch { /* ignore */ }
            }
            activeSockets.clear();
            try { server.close(); } catch { /* ignore */ }
        }
    };
}

/**
 * Start a per-profile network engine (xfrpc-ios native `netd` + DoT DNS Disguise + TCP<->UDP bridge),
 * automatically falling back to pure Node.js `proxy-relay.mjs` if `netd` is unavailable.
 */
export async function startProfileNetworkEngine(profileId, proxy, rawNetConfig = {}) {
    const cfg = normalizeNetworkConfig(rawNetConfig);
    const netdInfo = detectNetdAvailability();

    // Only start an engine when a proxy is configured OR DNS disguise / TCP2UDP is requested
    const hasProxy = Boolean(proxy && proxy.host && proxy.port && proxy.kind !== 'wireguard');

    // Note: vendored `libnetd_router.dylib` only supports `default=direct|proxy|reject` (not inline
    // authenticated `socks5://user:pass@host:port` URLs). When an upstream proxy is assigned, launch
    // `startLocalProxyRelay(proxy)` directly (<2ms, 100% authenticated TCP + remote DNS + UDP ASSOCIATE)
    // plus the xfrpc-ios `0xF1`/`0xF2` TCP<->UDP bridge — zero failed netd boots and zero IP leak!
    if (!hasProxy && cfg.engine === 'xfrpc-netd' && netdInfo.available) {
        try {
            const proxyPort = await reserveLoopbackPort();
            const dnsPort = await reserveLoopbackPort();

            const { bin: netdExec, pluginsDir: execPluginsDir } = resolveExecutableNetdPaths();
            const runtimeBase = process.platform === 'darwin'
                ? path.join(os.homedir(), 'Library', 'Caches', 'CamoufoxStudio')
                : ensureStateDirectory();
            const runtimeRoot = path.join(runtimeBase, 'netd-runtime');
            ensurePrivateDirectory(runtimeBase, { requireOwner: true });
            ensurePrivateDirectory(runtimeRoot, { requireOwner: true });
            const safeId = String(profileId || 'default').replace(/[^a-zA-Z0-9._-]/g, '_');
            const profRunDir = path.join(runtimeRoot, safeId);
            ensurePrivateDirectory(profRunDir, { requireOwner: true });

            const preset = DNS_DISGUISE_PRESETS[cfg.dns_disguise] || DNS_DISGUISE_PRESETS['dot-cloudflare'];
            const dotServers = cfg.dns_custom_servers || preset.servers;
            const splitPart = cfg.dns_split_rules ? `;split_dns=${cfg.dns_split_rules}` : '';
            const upstreamRoute = formatUpstreamRouteUrl(proxy);

            const iniLines = [
                '[common]',
                'server_addr=none',
                `egress=${cfg.egress}`,
                '[plugins]',
                'async_load=0',
                `plugin=tls|${path.join(execPluginsDir, 'libnetd_tls.dylib')}||backend=auto`,
                `plugin=dot|${path.join(execPluginsDir, 'libnetd_dot.dylib')}||servers=${dotServers};listen=127.0.0.1:${dnsPort};fallback_plain=0${splitPart}`,
                `plugin=router|${path.join(execPluginsDir, 'libnetd_router.dylib')}||default=${upstreamRoute}`,
                `plugin=fwd_local|${path.join(execPluginsDir, 'libnetd_fwd_local.dylib')}||listen=127.0.0.1:${proxyPort};mode=mixed;workers=1`
            ];

            const iniPath = path.join(profRunDir, 'netd.ini');
            const logPath = path.join(profRunDir, 'netd.log');
            writePrivateFile(iniPath, iniLines.join('\n') + '\n', { requireOwner: true });

            const logFd = fs.openSync(logPath, 'w', 0o600);
            const child = spawn(netdExec, ['-c', iniPath, '-f'], {
                detached: false,
                stdio: ['ignore', logFd, logFd]
            });
            child.on('error', () => {});
            fs.closeSync(logFd);

            try {
                await waitForTcpListen('127.0.0.1', proxyPort, 4000, child);
            } catch (err) {
                try { child.kill('SIGTERM'); } catch { /* ignore */ }
                throw err;
            }

            let tcp2udp = null;
            if (cfg.tcp2udp_enable) {
                try {
                    tcp2udp = await startTcp2UdpBridge('127.0.0.1', proxyPort);
                } catch {
                    tcp2udp = null;
                }
            }

            let closed = false;
            return {
                engine: 'xfrpc-netd',
                host: '127.0.0.1',
                port: proxyPort,
                kind: 'socks5',
                dnsStubPort: dnsPort,
                dnsDisguise: preset.id,
                dnsServers: dotServers,
                udpMode: cfg.udp_mode,
                udpSupported: cfg.udp_mode !== 'block-udp',
                tcp2udpPort: tcp2udp?.port || null,
                upstreamMode: hasProxy ? String(proxy.kind || 'socks5') : 'direct',
                pid: child.pid,
                close: () => {
                    if (closed) return;
                    closed = true;
                    try { tcp2udp?.close(); } catch { /* ignore */ }
                    try {
                        if (child && !child.killed && child.exitCode === null) {
                            child.kill('SIGTERM');
                            const killTimer = setTimeout(() => {
                                try {
                                    if (child.exitCode === null) child.kill('SIGKILL');
                                } catch { /* ignore */ }
                            }, 1500);
                            killTimer.unref?.();
                        }
                    } catch { /* ignore */ }
                }
            };
        } catch {
            // Fall through gracefully to pure Node.js relay if netd startup fails
        }
    }

    if (!hasProxy) return null;

    const fallback = await startLocalProxyRelay(proxy);
    if (!fallback) return null;

    let tcp2udp = null;
    if (cfg.tcp2udp_enable && fallback.kind === 'socks5') {
        try {
            tcp2udp = await startTcp2UdpBridge(fallback.host, fallback.port);
        } catch {
            tcp2udp = null;
        }
    }

    return {
        engine: 'node-relay',
        host: fallback.host,
        port: fallback.port,
        kind: fallback.kind,
        dnsStubPort: null,
        dnsDisguise: cfg.dns_disguise,
        dnsServers: null,
        udpMode: cfg.udp_mode,
        udpSupported: Boolean(fallback.udpSupported) && cfg.udp_mode !== 'block-udp',
        tcp2udpPort: tcp2udp?.port || null,
        upstreamMode: String(proxy.kind || 'socks5'),
        pid: null,
        close: () => {
            try { tcp2udp?.close(); } catch { /* ignore */ }
            try { fallback.close(); } catch { /* ignore */ }
        }
    };
}
