/**
 * Proxy Manager
 * إدارة البروكسيات من ملف TXT
 */

import fs from 'fs';
import path from 'path';
import logger from './logger.js';
import { ensurePrivateDirectory, readPrivateFile } from './private-storage.js';
import { ensureStateDirectory, LEGACY_DIRECTORY, PACKAGE_ROOT, STATE_DIRECTORY } from './state-paths.js';

const PROXY_INVENTORY = path.join('config', 'proxies.txt');
const PROXIES_FILE = path.join(STATE_DIRECTORY, PROXY_INVENTORY);
const PROXY_FILE_OPTIONS = { requireOwner: true };
const INVALID_INVENTORY = 'Invalid proxy configuration in config/proxies.txt. Check the indicated lines.';

function proxyConfigurationError(message) {
    return Object.assign(new Error(message), { code: 'PROXY_CONFIGURATION_ERROR' });
}

function hasUnselectedLegacyInventory() {
    if (STATE_DIRECTORY === PACKAGE_ROOT || LEGACY_DIRECTORY === PACKAGE_ROOT) return false;
    try {
        fs.lstatSync(path.join(PACKAGE_ROOT, PROXY_INVENTORY));
        return true;
    } catch (error) {
        if (error.code === 'ENOENT') return false;
        throw proxyConfigurationError('Could not check for an existing installation proxy inventory');
    }
}

function readProxyInventory() {
    for (const directory of [STATE_DIRECTORY, LEGACY_DIRECTORY]) {
        if (!directory) continue;
        try {
            return readPrivateFile(path.join(directory, PROXY_INVENTORY), 'utf8', PROXY_FILE_OPTIONS);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
    }

    if (hasUnselectedLegacyInventory()) {
        // Leave the state path available for explicit legacy adoption.
        return '';
    }

    ensureStateDirectory();
    ensurePrivateDirectory(path.dirname(PROXIES_FILE), { requireOwner: true });
    let fd;
    try {
        fd = fs.openSync(PROXIES_FILE, 'wx', 0o600);
    } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        return readPrivateFile(PROXIES_FILE, 'utf8', PROXY_FILE_OPTIONS);
    }

    try {
        if (process.platform !== 'win32' && (fs.fstatSync(fd).mode & 0o7777) !== 0o600) {
            fs.fchmodSync(fd, 0o600);
        }
        fs.writeFileSync(fd, '# Proxy format: ip:port:username:password\n', 'utf8');
    } finally {
        fs.closeSync(fd);
    }
    logger.warn('Created an empty proxy inventory in config/proxies.txt');
    return '';
}

class ProxyManager {
    #proxies;

    constructor() {
        this.usedProxies = new Set();
    }

    get proxies() {
        if (!this.#proxies) this.loadProxies();
        return this.#proxies;
    }

    /**
     * Parse a single proxy line supporting:
     * - `ip:port` or `ip:port:username:password` (including passwords containing `:`)
     * - `[ipv6]:port` or `[ipv6]:port:username:password`
     * - `http://user:pass@host:port`, `https://...`, `socks5://...`
     */
    parseProxyLine(rawLine) {
        if (!rawLine || typeof rawLine !== 'string') return null;
        let line = rawLine.trim();
        if (!line || line.startsWith('#')) return null;

        // Normalize unschemed user:pass@host:port lines by prepending http://
        if (!line.includes('://') && line.includes('@')) {
            const atIdx = line.lastIndexOf('@');
            const afterAt = line.slice(atIdx + 1);
            if (this._splitHostAndRemainder(afterAt.replace(/\/+$/, ''))) {
                line = `http://${line}`;
            }
        }

        let type = 'http';
        let ip = '';
        let port = '';
        let username = '';
        let password = '';

        // 1. URL scheme format: protocol://[user:pass@]host:port or protocol://host:port:user:pass
        const schemeMatch = line.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.+)$/);
        if (schemeMatch) {
            type = schemeMatch[1].toLowerCase();
            const rest = schemeMatch[2].trim().replace(/\/+$/, '');
            if (rest.includes('@')) {
                const lastAt = rest.lastIndexOf('@');
                const authPart = rest.slice(0, lastAt);
                const hostPart = rest.slice(lastAt + 1);
                const colonIdx = authPart.indexOf(':');
                try {
                    username = decodeURIComponent(colonIdx >= 0 ? authPart.slice(0, colonIdx) : authPart);
                    if (colonIdx >= 0) password = decodeURIComponent(authPart.slice(colonIdx + 1));
                } catch {
                    return null;
                }
                const parsedHost = this._splitHostAndRemainder(hostPart);
                if (!parsedHost || parsedHost.extra.length > 0) return null;
                ip = parsedHost.ip;
                port = parsedHost.port;
            } else {
                const parsedHost = this._splitHostAndRemainder(rest);
                if (!parsedHost) return null;
                ip = parsedHost.ip;
                port = parsedHost.port;
                username = parsedHost.extra[0] || '';
                password = parsedHost.extra.slice(1).join(':');
            }
        } else {
            // 2. Unschemed host:port[:user[:pass]] or [ipv6]:port[:user[:pass]]
            const parsedHost = this._splitHostAndRemainder(line);
            if (!parsedHost) return null;
            ip = parsedHost.ip;
            port = parsedHost.port;
            username = parsedHost.extra[0] || '';
            password = parsedHost.extra.slice(1).join(':');
        }

        const portNum = Number.parseInt(port, 10);
        if (!ip || !/^\d+$/.test(port) || Number.isNaN(portNum) || portNum < 1 || portNum > 65535) {
            return null;
        }

        return {
            ip: ip.trim(),
            port: String(portNum),
            username: username.trim(),
            password: password.trim(),
            type,
            raw: line
        };
    }

    _splitHostAndRemainder(input) {
        if (input.startsWith('[')) {
            const closeIdx = input.indexOf(']');
            if (closeIdx <= 1 || input[closeIdx + 1] !== ':') return null;
            const ip = input.slice(0, closeIdx + 1);
            const afterBracket = input.slice(closeIdx + 2).split(':');
            const port = (afterBracket[0] || '').trim();
            return { ip, port, extra: afterBracket.slice(1) };
        }
        const parts = input.split(':');
        if (parts.length < 2) return null;
        return {
            ip: parts[0].trim(),
            port: parts[1].trim(),
            extra: parts.slice(2)
        };
    }

    /**
     * Load proxies from file
     * تحميل البروكسيات من الملف
     */
    loadProxies() {
        this.#proxies = undefined;
        this.usedProxies.clear();

        let content;
        try {
            content = readProxyInventory();
        } catch {
            throw proxyConfigurationError('Could not safely read or create config/proxies.txt');
        }

        const proxies = [];
        let invalid = false;
        for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
            const line = rawLine.trim();
            if (!line || line.startsWith('#')) continue;
            const proxy = this.parseProxyLine(line);
            if (!proxy) {
                logger.warn('Invalid proxy format in config/proxies.txt', { lineNumber: index + 1 });
                invalid = true;
            } else {
                proxies.push(proxy);
            }
        }
        if (invalid) throw proxyConfigurationError(INVALID_INVENTORY);

        this.#proxies = proxies;
        logger.info('Loaded proxies from config/proxies.txt', { proxyCount: proxies.length });
    }

    rejectUnselectedLegacyInventory() {
        if (hasUnselectedLegacyInventory()) {
            throw proxyConfigurationError('An installation proxy inventory exists. Move it to the state directory or set GMAIL_CREATOR_LEGACY_DIR before connecting directly.');
        }
    }

    /**
     * Get next available proxy
     * الحصول على بروكسي متاح
     */
    getNextProxy() {
        const proxies = this.proxies;
        if (proxies.length === 0) return null;
        const available = proxies.filter(p => !this.usedProxies.has(p.raw));
        
        if (available.length === 0) {
            logger.warn('No available proxies, resetting used proxies');
            this.usedProxies.clear();
            return proxies[0];
        }

        const proxy = available[Math.floor(Math.random() * available.length)];
        this.usedProxies.add(proxy.raw);
        return proxy;
    }

    /**
     * Mark proxy as used
     * تحديد البروكسي كمستخدم
     */
    markAsUsed(proxy) {
        if (proxy && proxy.raw) {
            this.usedProxies.add(proxy.raw);
        }
    }

    /**
     * Release proxy (mark as available)
     * تحرير البروكسي
     */
    releaseProxy(proxy) {
        if (proxy && proxy.raw) {
            this.usedProxies.delete(proxy.raw);
        }
    }

    /**
     * Get proxy in GPM Login format
     * الحصول على البروكسي بتنسيق GPM Login
     */
    getGPMLoginFormat(proxy) {
        if (!proxy) return null;

        return {
            ip: proxy.ip,
            port: proxy.port,
            username: proxy.username || '',
            password: proxy.password || '',
            type: proxy.type || 'http'
        };
    }

    /**
     * Get proxy in Camoufox / Playwright format
     */
    getCamoufoxFormat(proxy) {
        if (!proxy) return null;
        const protocol = (proxy.type || 'http').toLowerCase();
        const host = proxy.ip.includes(':') && !proxy.ip.startsWith('[') ? `[${proxy.ip}]` : proxy.ip;
        const formatted = {
            server: `${protocol}://${host}:${proxy.port}`
        };
        if (proxy.username) formatted.username = proxy.username;
        if (proxy.password) formatted.password = proxy.password;
        return formatted;
    }

    /**
     * Get proxy in GoLogin format (legacy - kept for compatibility)
     * الحصول على البروكسي بتنسيق GoLogin (قديم - محفوظ للتوافق)
     */
    getGoLoginFormat(proxy) {
        return this.getGPMLoginFormat(proxy);
    }

    /**
     * Get proxy string format (ip:port:user:pass)
     * الحصول على البروكسي كسلسلة نصية
     */
    getStringFormat(proxy) {
        if (!proxy) return null;
        return proxy.raw;
    }

    /**
     * Get available count
     * عدد البروكسيات المتاحة
     */
    getAvailableCount() {
        return this.proxies.length - this.usedProxies.size;
    }

    /**
     * Reset all used proxies
     * إعادة تعيين جميع البروكسيات المستخدمة
     */
    reset() {
        this.usedProxies.clear();
        logger.info('All proxies reset');
    }
}

export default new ProxyManager();


