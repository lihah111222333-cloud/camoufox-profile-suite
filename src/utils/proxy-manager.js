/**
 * Proxy Manager
 * إدارة البروكسيات من ملف TXT
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import logger from './logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PROXIES_FILE = path.join(__dirname, '../../config/proxies.txt');

class ProxyManager {
    constructor() {
        this.proxies = [];
        this.usedProxies = new Set();
        this.loadProxies();
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
                if (colonIdx >= 0) {
                    username = decodeURIComponent(authPart.slice(0, colonIdx));
                    password = decodeURIComponent(authPart.slice(colonIdx + 1));
                } else {
                    username = decodeURIComponent(authPart);
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
        try {
            if (!fs.existsSync(PROXIES_FILE)) {
                logger.warn('Proxies file not found, creating empty file');
                fs.writeFileSync(PROXIES_FILE, '# Proxy format: ip:port:username:password\n', 'utf8');
                return;
            }

            const content = fs.readFileSync(PROXIES_FILE, 'utf8');
            const lines = content.split(/\r?\n/).map(line => line.trim()).filter(line => {
                // Skip empty lines and comments
                return line && !line.startsWith('#');
            });

            this.proxies = lines.map((line, index) => {
                const proxy = this.parseProxyLine(line);
                if (proxy) {
                    if (index === 0) {
                        logger.info('Example proxy loaded', {
                            ip: proxy.ip,
                            port: proxy.port,
                            type: proxy.type,
                            hasUsername: !!proxy.username,
                            hasPassword: !!proxy.password,
                            usernameLength: proxy.username.length,
                            passwordLength: proxy.password.length
                        });
                    }
                    return proxy;
                }
                logger.warn('Invalid proxy format', { line, lineNumber: index + 1 });
                return null;
            }).filter(p => p !== null);

            logger.info(`Loaded ${this.proxies.length} proxies from file`);
        } catch (error) {
            logger.error('Error loading proxies', { error: error.message });
            this.proxies = [];
        }
    }

    /**
     * Get next available proxy
     * الحصول على بروكسي متاح
     */
    getNextProxy() {
        const available = this.proxies.filter(p => !this.usedProxies.has(p.raw));
        
        if (available.length === 0) {
            logger.warn('No available proxies, resetting used proxies');
            this.usedProxies.clear();
            return this.proxies[0] || null;
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


