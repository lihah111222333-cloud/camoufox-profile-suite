/**
 * Proxy Manager
 * إدارة البروكسيات من ملف TXT
 */

import fs from 'fs';
import path from 'path';
import logger from './logger.js';
import { parseProxyAddress } from './proxy-protocol.js';
import { ensurePrivateDirectory, readPrivateFile } from './private-storage.js';
import {
    ensureStateDirectory, getLegacyDirectory, getStateDirectory, PACKAGE_ROOT, validateExistingStateDirectory
} from './state-paths.js';

const PROXY_INVENTORY = path.join('config', 'proxies.txt');
const PROXY_FILE_OPTIONS = { requireOwner: true };
const INVALID_INVENTORY = 'Invalid proxy configuration in config/proxies.txt. Check the indicated lines. ' +
    'Keep the configured scheme and percent-encode credential delimiters in a URL such as ' +
    'http://user:pass%40word%3Aend@proxy.example:8080.';

function proxyConfigurationError(message) {
    return Object.assign(new Error(message), { code: 'PROXY_CONFIGURATION_ERROR' });
}

function hasUnselectedLegacyInventory(directories = [getStateDirectory(), getLegacyDirectory()]) {
    const selected = directories.filter(Boolean);
    if (selected.includes(PACKAGE_ROOT)) return false;
    try {
        fs.lstatSync(path.join(PACKAGE_ROOT, PROXY_INVENTORY));
        const root = fs.statSync(PACKAGE_ROOT, { bigint: true });
        return !selected.some((directory) => {
            const stats = fs.statSync(directory, { bigint: true, throwIfNoEntry: false });
            return stats?.isDirectory() && stats.dev === root.dev && stats.ino === root.ino;
        });
    } catch (error) {
        if (error.code === 'ENOENT') return false;
        throw proxyConfigurationError('Could not check for an existing installation proxy inventory');
    }
}

function readProxyInventory() {
    const stateDirectory = validateExistingStateDirectory() ? getStateDirectory() : undefined;
    const directories = [stateDirectory, getLegacyDirectory()];
    for (const directory of directories) {
        if (!directory) continue;
        try {
            return readPrivateFile(path.join(directory, PROXY_INVENTORY), 'utf8', PROXY_FILE_OPTIONS);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
    }

    if (hasUnselectedLegacyInventory(directories)) {
        // Leave the state path available for explicit legacy adoption.
        return '';
    }

    const proxiesFile = path.join(ensureStateDirectory(), PROXY_INVENTORY);
    ensurePrivateDirectory(path.dirname(proxiesFile), { requireOwner: true });
    let fd;
    try {
        fd = fs.openSync(proxiesFile, 'wx', 0o600);
    } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        return readPrivateFile(proxiesFile, 'utf8', PROXY_FILE_OPTIONS);
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
        return parseProxyAddress(rawLine);
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


