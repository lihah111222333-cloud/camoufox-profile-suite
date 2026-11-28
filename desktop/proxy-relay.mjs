// SPDX-License-Identifier: AGPL-3.0-or-later
// Zero-dependency local loopback proxy relay for Camoufox Studio.
// - Translates local unauthenticated SOCKS5 (TCP CONNECT + UDP ASSOCIATE, RFC 1928)
//   to an upstream SOCKS5 server with RFC 1929 username/password authentication.
// - Translates local unauthenticated HTTP/CONNECT proxy to an upstream HTTP/HTTPS proxy
//   with Proxy-Authorization injection.
// Strictly binds to 127.0.0.1 on an ephemeral port and never logs credentials.

import dgram from 'node:dgram';
import net from 'node:net';

const SOCKS_VER = 0x05;

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

        const timer = setTimeout(() => finish(new Error('SOCKS5 handshake timeout')), timeoutMs);

        const onData = (chunk) => {
            socket.__rxBuf = Buffer.concat([socket.__rxBuf, chunk]);
            if (socket.__rxBuf.length >= length) {
                const head = socket.__rxBuf.subarray(0, length);
                socket.__rxBuf = socket.__rxBuf.subarray(length);
                finish(null, head);
            }
        };

        const onErr = (err) => finish(err);
        const onClose = () => finish(new Error('SOCKS5 socket closed prematurely'));

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

async function readSocks5Address(socket) {
    const atypBuf = await readExact(socket, 1);
    const atyp = atypBuf[0];
    let addrRaw;
    let host;

    if (atyp === 0x01) {
        addrRaw = await readExact(socket, 4);
        host = Array.from(addrRaw).join('.');
    } else if (atyp === 0x03) {
        const lenBuf = await readExact(socket, 1);
        const nameBuf = await readExact(socket, lenBuf[0]);
        addrRaw = Buffer.concat([lenBuf, nameBuf]);
        host = nameBuf.toString('utf8');
    } else if (atyp === 0x04) {
        addrRaw = await readExact(socket, 16);
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
            parts.push(addrRaw.readUInt16BE(i).toString(16));
        }
        host = parts.join(':');
    } else {
        throw new Error(`Unsupported SOCKS5 address type: ${atyp}`);
    }

    const portBuf = await readExact(socket, 2);
    const port = portBuf.readUInt16BE(0);
    return {
        atyp,
        host,
        port,
        raw: Buffer.concat([atypBuf, addrRaw, portBuf])
    };
}

function buildSocks5Reply(rep, ip = '127.0.0.1', port = 0) {
    const parts = ip.split('.').map((n) => Number.parseInt(n, 10) & 0xff);
    const buf = Buffer.alloc(10);
    buf[0] = SOCKS_VER;
    buf[1] = rep;
    buf[2] = 0x00;
    buf[3] = 0x01; // IPv4
    buf[4] = parts[0] || 0;
    buf[5] = parts[1] || 0;
    buf[6] = parts[2] || 0;
    buf[7] = parts[3] || 0;
    buf.writeUInt16BE(port & 0xffff, 8);
    return buf;
}

async function connectUpstreamSocks5(upstream) {
    const socket = net.createConnection({
        host: upstream.host,
        port: Number(upstream.port)
    });

    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            socket.destroy();
            reject(new Error('Upstream SOCKS5 connect timeout'));
        }, 15000);
        socket.once('connect', () => {
            clearTimeout(timer);
            resolve();
        });
        socket.once('error', (err) => {
            clearTimeout(timer);
            reject(err);
        });
    });

    const hasAuth = Boolean(upstream.username);
    const methods = hasAuth ? [0x00, 0x02] : [0x00];
    socket.write(Buffer.from([SOCKS_VER, methods.length, ...methods]));

    const greeting = await readExact(socket, 2);
    if (greeting[0] !== SOCKS_VER || greeting[1] === 0xff) {
        socket.destroy();
        throw new Error('Upstream SOCKS5 rejected auth methods');
    }

    if (greeting[1] === 0x02) {
        const userBuf = Buffer.from(String(upstream.username || ''), 'utf8').subarray(0, 255);
        const passBuf = Buffer.from(String(upstream.password || ''), 'utf8').subarray(0, 255);
        const authReq = Buffer.concat([
            Buffer.from([0x01, userBuf.length]),
            userBuf,
            Buffer.from([passBuf.length]),
            passBuf
        ]);
        socket.write(authReq);
        const authResp = await readExact(socket, 2);
        if (authResp[1] !== 0x00) {
            socket.destroy();
            throw new Error('Upstream SOCKS5 authentication failed');
        }
    }

    return socket;
}

async function handleSocks5Client(clientSocket, upstream, activeSockets) {
    activeSockets.add(clientSocket);
    clientSocket.on('error', () => {});
    clientSocket.once('close', () => activeSockets.delete(clientSocket));

    let upstreamSocket = null;
    let localUdp = null;
    let upstreamUdp = null;

    const cleanup = () => {
        try { upstreamSocket?.destroy(); } catch { /* ignore */ }
        try { localUdp?.close(); } catch { /* ignore */ }
        try { upstreamUdp?.close(); } catch { /* ignore */ }
        localUdp = null;
        upstreamUdp = null;
    };

    try {
        // 1. Local browser SOCKS5 greeting (no auth required on 127.0.0.1)
        const head = await readExact(clientSocket, 2);
        if (head[0] !== SOCKS_VER) {
            clientSocket.destroy();
            return;
        }
        await readExact(clientSocket, head[1]);
        clientSocket.write(Buffer.from([SOCKS_VER, 0x00]));

        // 2. Local browser SOCKS5 request header
        const reqHead = await readExact(clientSocket, 3);
        const cmd = reqHead[1];
        const target = await readSocks5Address(clientSocket);

        // 3. Connect & authenticate with upstream SOCKS5
        upstreamSocket = await connectUpstreamSocks5(upstream);
        upstreamSocket.on('error', () => cleanup());
        activeSockets.add(upstreamSocket);
        upstreamSocket.once('close', () => activeSockets.delete(upstreamSocket));

        if (cmd === 0x01) {
            // ---- TCP CONNECT ----
            const upstreamReq = Buffer.concat([Buffer.from([SOCKS_VER, 0x01, 0x00]), target.raw]);
            upstreamSocket.write(upstreamReq);

            const respHead = await readExact(upstreamSocket, 3);
            const bound = await readSocks5Address(upstreamSocket);
            if (respHead[1] !== 0x00) {
                clientSocket.write(buildSocks5Reply(respHead[1]));
                clientSocket.end();
                cleanup();
                return;
            }

            clientSocket.write(Buffer.concat([Buffer.from([SOCKS_VER, 0x00, 0x00]), bound.raw]));
            const leftC = drainBuffered(clientSocket);
            const leftU = drainBuffered(upstreamSocket);
            if (leftC) upstreamSocket.write(leftC);
            if (leftU) clientSocket.write(leftU);
            clientSocket.pipe(upstreamSocket);
            upstreamSocket.pipe(clientSocket);
            clientSocket.once('error', cleanup);
            clientSocket.once('close', cleanup);
            upstreamSocket.once('error', () => clientSocket.destroy());
            upstreamSocket.once('close', () => clientSocket.destroy());
            return;
        }

        if (cmd === 0x03) {
            // ---- UDP ASSOCIATE (RFC 1928 §7) ----
            const udpAssocReq = Buffer.from([
                SOCKS_VER, 0x03, 0x00,
                0x01, 0, 0, 0, 0, // 0.0.0.0
                0, 0              // port 0
            ]);
            upstreamSocket.write(udpAssocReq);

            const respHead = await readExact(upstreamSocket, 3);
            const upstreamBound = await readSocks5Address(upstreamSocket);
            if (respHead[1] !== 0x00 || !upstreamBound.port) {
                clientSocket.write(buildSocks5Reply(respHead[1] || 0x01));
                clientSocket.end();
                cleanup();
                return;
            }

            const upstreamUdpHost = (!upstreamBound.host || upstreamBound.host === '0.0.0.0' || upstreamBound.host === '::')
                ? upstream.host
                : upstreamBound.host;
            const upstreamUdpPort = upstreamBound.port;

            localUdp = dgram.createSocket('udp4');
            upstreamUdp = dgram.createSocket('udp4');

            await new Promise((resolve, reject) => {
                localUdp.once('error', reject);
                localUdp.bind(0, '127.0.0.1', () => {
                    localUdp.off('error', reject);
                    resolve();
                });
            });

            await new Promise((resolve, reject) => {
                upstreamUdp.once('error', reject);
                upstreamUdp.bind(0, () => {
                    upstreamUdp.off('error', reject);
                    resolve();
                });
            });

            let clientUdpEndpoint = null;

            localUdp.on('message', (msg, rinfo) => {
                // Only accept UDP packets from loopback
                if (rinfo.address !== '127.0.0.1') return;
                clientUdpEndpoint = { address: rinfo.address, port: rinfo.port };
                // Forward RFC 1928 SOCKS5 UDP datagram verbatim to upstream UDP relay
                try {
                    upstreamUdp?.send(msg, upstreamUdpPort, upstreamUdpHost);
                } catch {
                    // ignore transient send errors
                }
            });

            upstreamUdp.on('message', (msg) => {
                if (!clientUdpEndpoint) return;
                try {
                    localUdp?.send(msg, clientUdpEndpoint.port, clientUdpEndpoint.address);
                } catch {
                    // ignore transient send errors
                }
            });

            localUdp.on('error', cleanup);
            upstreamUdp.on('error', cleanup);

            const localUdpPort = localUdp.address().port;
            clientSocket.write(buildSocks5Reply(0x00, '127.0.0.1', localUdpPort));

            // Keep UDP relay alive strictly for the lifetime of the TCP control channel
            clientSocket.on('data', () => {});
            upstreamSocket.on('data', () => {});
            clientSocket.once('close', cleanup);
            clientSocket.once('error', cleanup);
            upstreamSocket.once('close', () => {
                cleanup();
                clientSocket.destroy();
            });
            upstreamSocket.once('error', () => {
                cleanup();
                clientSocket.destroy();
            });
            return;
        }

        // Unsupported command (BIND etc.)
        clientSocket.write(buildSocks5Reply(0x07));
        clientSocket.end();
        cleanup();
    } catch {
        try {
            if (!clientSocket.destroyed) {
                clientSocket.write(buildSocks5Reply(0x01));
                clientSocket.end();
            }
        } catch {
            // ignore
        }
        cleanup();
    }
}

function handleHttpProxyClient(clientSocket, upstream, activeSockets) {
    activeSockets.add(clientSocket);
    clientSocket.on('error', () => {});
    clientSocket.once('close', () => activeSockets.delete(clientSocket));

    const authHeader = upstream.username
        ? `Proxy-Authorization: Basic ${Buffer.from(`${upstream.username}:${upstream.password || ''}`).toString('base64')}\r\n`
        : '';

    let buffered = Buffer.alloc(0);
    let upstreamSocket = null;

    const cleanup = () => {
        try { upstreamSocket?.destroy(); } catch { /* ignore */ }
        try { clientSocket.destroy(); } catch { /* ignore */ }
    };

    const onData = (chunk) => {
        buffered = Buffer.concat([buffered, chunk]);
        const headerEnd = buffered.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
            if (buffered.length > 65536) cleanup();
            return;
        }
        clientSocket.off('data', onData);

        const rawHead = buffered.subarray(0, headerEnd).toString('latin1');
        const rest = buffered.subarray(headerEnd + 4);
        const lines = rawHead.split('\r\n');
        const filtered = lines.filter((line, idx) => idx === 0 || !/^proxy-authorization:/i.test(line));
        const injected = `${filtered.join('\r\n')}\r\n${authHeader}\r\n`;

        upstreamSocket = net.createConnection({
            host: upstream.host,
            port: Number(upstream.port)
        });
        activeSockets.add(upstreamSocket);
        upstreamSocket.once('close', () => activeSockets.delete(upstreamSocket));

        upstreamSocket.once('connect', () => {
            upstreamSocket.write(Buffer.from(injected, 'latin1'));
            if (rest.length > 0) upstreamSocket.write(rest);
            clientSocket.pipe(upstreamSocket);
            upstreamSocket.pipe(clientSocket);
        });
        upstreamSocket.once('error', cleanup);
        upstreamSocket.once('close', () => clientSocket.destroy());
        clientSocket.once('error', cleanup);
        clientSocket.once('close', () => upstreamSocket?.destroy());
    };

    clientSocket.on('data', onData);
    clientSocket.once('error', cleanup);
}

/**
 * Start a local loopback proxy relay for a single browser profile session.
 * Returns `{ host: '127.0.0.1', port, kind, udpSupported, close() }`.
 */
export async function startLocalProxyRelay(proxy) {
    if (!proxy || !proxy.host || !proxy.port || proxy.kind === 'wireguard') {
        return null;
    }

    const kind = String(proxy.kind || 'http').toLowerCase();
    const isSocks5 = kind === 'socks5' || kind === 'socks5h';
    const isHttp = kind === 'http' || kind === 'https';

    if (!isSocks5 && !isHttp) {
        return null;
    }

    const activeSockets = new Set();
    const server = net.createServer((socket) => {
        socket.on('error', () => {});
        socket.setNoDelay(true);
        if (isSocks5) {
            void handleSocks5Client(socket, proxy, activeSockets);
        } else {
            handleHttpProxyClient(socket, proxy, activeSockets);
        }
    });
    server.on('error', () => {});

    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            server.off('error', reject);
            resolve();
        });
    });

    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;

    return {
        host: '127.0.0.1',
        port,
        kind: isSocks5 ? 'socks5' : 'http',
        udpSupported: isSocks5,
        close: () => {
            for (const sock of activeSockets) {
                try { sock.destroy(); } catch { /* ignore */ }
            }
            activeSockets.clear();
            try { server.close(); } catch { /* ignore */ }
        }
    };
}
