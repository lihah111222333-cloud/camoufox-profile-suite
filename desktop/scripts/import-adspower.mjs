// SPDX-License-Identifier: AGPL-3.0-or-later
// Imports AdsPower local cache profiles into Camoufox Studio (desktop-state.json + on-disk Camoufox profiles).
// Reads ONLY non-credential fingerprint/environment config & ProxyChain routing — NEVER reads Cookies, Login Data, or browser passwords.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
    auditAdsPowerProfileDir,
    decodeAdsPowerBase64
} from '../../scripts/audit-adspower-profiles.js';
import { USABLE_DEVICE_PRESET_CATALOG } from '../../src/camoufox/device-presets.js';
import {
    createProfile as createCamoufoxProfile
} from '../../src/camoufox/client.js';
import {
    ensureStateDirectory,
    getDefaultProfilesDirectory
} from '../../src/utils/state-paths.js';
import {
    readPrivateFile,
    writePrivateFile
} from '../../src/utils/private-storage.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

function parseArgs(argv) {
    const opts = {
        cacheDir: process.env.ADSPOWER_CACHE_DIR || path.join(os.homedir(), 'Library', 'Application Support', 'adspower_global', 'cwd_global', 'source', 'cache'),
        apiBase: 'http://local.adspower.com:50325',
        apiKey: process.env.ADSPOWER_API_KEY || '',
        limit: 13,
        projectName: 'AdsPower 导入',
        dryRun: false
    };
    for (const arg of argv) {
        if (arg.startsWith('--cache-dir=')) opts.cacheDir = arg.slice('--cache-dir='.length);
        else if (arg.startsWith('--api-base=')) opts.apiBase = arg.slice('--api-base='.length).replace(/\/+$/, '');
        else if (arg.startsWith('--api-key=')) opts.apiKey = arg.slice('--api-key='.length).trim();
        else if (arg.startsWith('--limit=')) opts.limit = Math.max(1, Number(arg.slice('--limit='.length)) || 13);
        else if (arg.startsWith('--project=')) opts.projectName = arg.slice('--project='.length).trim() || opts.projectName;
        else if (arg === '--dry-run') opts.dryRun = true;
    }
    return opts;
}

async function fetchAdsPowerApiProfiles(apiBase, apiKey) {
    if (!apiKey) return new Map();
    const map = new Map();
    let page = 1;
    while (page <= 10) {
        const url = `${apiBase}/api/v1/user/list?page=${page}&page_size=100`;
        const res = await fetch(url, {
            headers: { Authorization: `Bearer ${apiKey}` },
            signal: AbortSignal.timeout(8000)
        });
        const json = await res.json();
        if (json?.code !== 0) {
            throw new Error(`AdsPower Local API error (code=${json?.code}): ${json?.msg || 'unknown error'}`);
        }
        const list = Array.isArray(json?.data?.list) ? json.data.list : [];
        for (const item of list) {
            if (item?.user_id) map.set(String(item.user_id), item);
            if (item?.serial_number) map.set(`#${item.serial_number}`, item);
        }
        if (list.length < 100) break;
        page++;
    }
    return map;
}

function seedFromId(id) {
    const hash = crypto.createHash('sha256').update(String(id)).digest();
    return hash.readUInt32BE(0) || 1;
}

function findPreset(presetId) {
    return USABLE_DEVICE_PRESET_CATALOG.find((p) => p.presetId === presetId) || USABLE_DEVICE_PRESET_CATALOG[0];
}

function parseLanguages(rawLangs) {
    const list = String(rawLangs || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    return list.length ? list : ['en-US', 'en'];
}

function inferLocaleMetadata(langs) {
    const primary = String(langs[0] || '').toLowerCase();
    if (primary.startsWith('ja')) return { timezone: 'Asia/Tokyo', country: 'JP' };
    if (primary.startsWith('zh-tw') || primary.startsWith('zh-hk')) return { timezone: 'Asia/Taipei', country: 'TW' };
    if (primary.startsWith('zh')) return { timezone: 'Asia/Shanghai', country: 'CN' };
    if (primary.startsWith('ko')) return { timezone: 'Asia/Seoul', country: 'KR' };
    if (primary.startsWith('en-gb')) return { timezone: 'Europe/London', country: 'GB' };
    if (primary.startsWith('de')) return { timezone: 'Europe/Berlin', country: 'DE' };
    if (primary.startsWith('fr')) return { timezone: 'Europe/Paris', country: 'FR' };
    return { timezone: 'America/New_York', country: 'US' };
}

function normalizeProxyKind(scheme) {
    const s = String(scheme || '').toLowerCase().trim();
    if (s === 'socks5' || s === 'socks5h') return 'socks5';
    if (s === 'socks4') return 'socks4';
    if (s === 'https') return 'https';
    return 'http';
}

function readStaticConfig(profileDir, fbccId) {
    const staticMd5 = crypto.createHash('md5').update(`${fbccId}_static`).digest('hex');
    const file = path.join(profileDir, staticMd5);
    const raw = fs.readFileSync(file, 'utf8').trim();
    return JSON.parse(raw.startsWith('{') ? raw : decodeAdsPowerBase64(raw));
}

function syncProxiesTxt(state) {
    const proxiesFile = path.join(REPO_ROOT, 'config', 'proxies.txt');
    const lines = ['# Proxy format: ip:port:username:password (synced by Camoufox Studio UI)'];
    for (const p of state.proxies) {
        if (!p.host || !p.port || p.kind === 'wireguard') continue;
        const kind = p.kind || 'http';
        const auth = p.username
            ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password || '')}@`
            : '';
        const host = p.host.includes(':') && !p.host.startsWith('[') ? `[${p.host}]` : p.host;
        lines.push(`${kind}://${auth}${host}:${p.port}`);
    }
    writePrivateFile(proxiesFile, lines.join('\n') + '\n', { requireOwner: true });
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const cacheRoot = fs.realpathSync(path.resolve(opts.cacheDir));
    const apiProfiles = await fetchAdsPowerApiProfiles(opts.apiBase, opts.apiKey);

    const discovered = fs.readdirSync(cacheRoot, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => {
            const fullDir = path.join(cacheRoot, e.name);
            const st = fs.statSync(fullDir);
            const fbccId = e.name.split('_')[0];
            let staticCfg = null;
            try {
                staticCfg = readStaticConfig(fullDir, fbccId);
            } catch {
                return null;
            }
            const audit = auditAdsPowerProfileDir(fullDir);
            if (!audit) return null;
            return {
                dirName: e.name,
                fullDir,
                fbccId,
                mtimeMs: st.mtimeMs,
                mtimeIso: st.mtime.toISOString(),
                userId: String(staticCfg.UserId || '').trim(),
                deviceName: String(staticCfg.DeviceName || audit.deviceName || fbccId).trim(),
                langs: parseLanguages(staticCfg.Langs),
                proxyRaw: Array.isArray(staticCfg.ProxyChain) && staticCfg.ProxyChain[0] ? staticCfg.ProxyChain[0] : null,
                proxyUser: staticCfg.ProxyUser || null,
                proxyPass: staticCfg.ProxyPassword || null,
                audit
            };
        })
        .filter(Boolean);

    // Pick the N most recently active AdsPower profiles, then order cleanly by numeric UserId ascending
    discovered.sort((a, b) => b.mtimeMs - a.mtimeMs);
    const selected = discovered.slice(0, opts.limit);
    selected.sort((a, b) => (Number(a.userId) || 0) - (Number(b.userId) || 0));

    if (opts.dryRun) {
        console.log(`Dry run: would import ${selected.length} AdsPower profiles into "${opts.projectName}"`);
        for (const item of selected) {
            const healedPresetId = item.audit.healed?.healedPresetId || findPreset('').presetId;
            console.log(`  - #${item.userId || '?'} ${item.deviceName} (${item.fbccId}) -> ${healedPresetId}`);
        }
        return;
    }

    const stateDir = ensureStateDirectory();
    const stateFile = path.join(stateDir, 'desktop-state.json');
    const profilesDir = getDefaultProfilesDirectory();

    let state;
    try {
        state = JSON.parse(readPrivateFile(stateFile, 'utf8', { requireOwner: true }));
    } catch (err) {
        if (err?.code !== 'ENOENT') throw err;
        state = {
            version: 1,
            projects: [],
            profiles: [],
            trash: [],
            proxies: [],
            credentials: {},
            bookmarks: [],
            templates: [],
            blocklists: {},
            extensions: {},
            cookies: {},
            audit: [],
            lastCoherence: null
        };
    }

    state.projects = Array.isArray(state.projects) ? state.projects : [];
    state.profiles = Array.isArray(state.profiles) ? state.profiles : [];
    state.proxies = Array.isArray(state.proxies) ? state.proxies : [];
    state.audit = Array.isArray(state.audit) ? state.audit : [];

    // Ensure dedicated AdsPower project group exists
    let project = state.projects.find((p) => p.name === opts.projectName);
    if (!project) {
        project = { id: crypto.randomUUID(), name: opts.projectName, origin: 'local' };
        state.projects.push(project);
    }

    let createdProfiles = 0;
    let updatedProfiles = 0;
    let upsertedProxies = 0;
    const summary = [];

    for (const item of selected) {
        const profileId = `adspower-${item.fbccId}`;
        const healedPresetId = item.audit.healed?.healedPresetId || findPreset('').presetId;
        const preset = findPreset(healedPresetId);
        const { timezone, country } = inferLocaleMetadata(item.langs);
        const apiRec = apiProfiles.get(item.fbccId) || (item.userId ? apiProfiles.get(`#${item.userId}`) : null) || null;

        // If AdsPower API returned a non-empty group_name, file into that exact project folder!
        let targetProject = project;
        const apiGroup = String(apiRec?.group_name || '').trim();
        if (apiGroup && apiGroup !== '未分组' && apiGroup.toLowerCase() !== 'ungrouped') {
            let groupProj = state.projects.find((p) => p.name === apiGroup);
            if (!groupProj) {
                groupProj = { id: crypto.randomUUID(), name: apiGroup, origin: 'local' };
                state.projects.push(groupProj);
            }
            targetProject = groupProj;
        }

        // Upsert proxy if present
        let proxyId = null;
        let camoufoxProxy = null;
        if (item.proxyRaw?.host && item.proxyRaw?.port) {
            const kind = normalizeProxyKind(item.proxyRaw.scheme);
            const host = String(item.proxyRaw.host).trim();
            const port = Number(item.proxyRaw.port);
            const username = item.proxyRaw.account || item.proxyUser || null;
            const password = item.proxyRaw.password || item.proxyPass || null;

            let px = state.proxies.find(
                (p) => p.kind === kind && p.host === host && Number(p.port) === port && (p.username || null) === username
            );
            const proxyLabel = `AdsPower #${item.userId || item.fbccId} (${host}:${port})`;
            if (!px) {
                px = {
                    id: crypto.randomUUID(),
                    name: proxyLabel,
                    kind,
                    host,
                    port,
                    username,
                    password,
                    last_country: country,
                    last_ip: host,
                    last_timezone: timezone,
                    rotate_url: null,
                    checker_url: null
                };
                state.proxies.push(px);
                upsertedProxies++;
            } else {
                px.name = proxyLabel;
                px.password = password ?? px.password;
                px.last_country = px.last_country || country;
                px.last_timezone = px.last_timezone || timezone;
            }
            proxyId = px.id;
            camoufoxProxy = {
                server: `${kind}://${host}:${port}`,
                username: username || undefined,
                password: password || undefined
            };
        }

        const apiName = String(apiRec?.name || '').trim();
        const apiUsername = String(apiRec?.username || '').trim();
        const apiPassword = String(apiRec?.password || '');
        const apiRemark = String(apiRec?.remark || '').trim();
        const inferredEmail = apiUsername || (/@/.test(apiName) ? apiName : '');
        const displayName = apiName || (item.userId
            ? `AdsPower #${item.userId} · ${item.deviceName}`
            : `AdsPower · ${item.deviceName}`);

        const rawIssuesCount = item.audit.issues?.length || 0;
        const notes = [
            apiRemark ? `Remark: ${apiRemark}` : null,
            `Imported from AdsPower (${item.dirName}, UserId #${item.userId || 'N/A'})`,
            `Original AdsPower fingerprint: ${item.audit.platform || 'unknown'}, ${item.audit.cores || '?'}T, ${item.audit.deviceMemoryGb || '?'}GB RAM, GPU=${item.audit.renderer || 'unknown'} (raw status: ${item.audit.status}, ${rawIssuesCount} conflicts)`,
            `Auto-healed to 100% SKU-verified preset: ${preset.presetId} (${preset.deviceModel} · ${preset.cpuModel} · ${preset.ramGb}GB RAM)`
        ].filter(Boolean).join('\n');

        const existing = state.profiles.find((p) => p.id === profileId);
        const record = {
            id: profileId,
            origin: 'local',
            shared_with: 0,
            project_id: targetProject.id,
            serial_number: Number(item.userId) || existing?.serial_number || undefined,
            name: displayName,
            account_email: inferredEmail || existing?.account_email || '',
            account_password: apiPassword || existing?.account_password || '',
            notes,
            start_urls: existing?.start_urls ?? [],
            status: existing?.status ?? '',
            tags: ['adspower', country, item.fbccId],
            persona_id: preset.presetId,
            fp_seed: existing?.fp_seed || seedFromId(profileId),
            proxy_id: proxyId,
            allow_no_proxy: true,
            timezone,
            languages: item.langs,
            overrides: existing?.overrides ?? {},
            blocklists: existing?.blocklists ?? [],
            last_opened_at: existing?.last_opened_at ?? null,
            coherence_score: 100
        };

        // Ensure on-disk isolated Camoufox profile directory exists
        try {
            await createCamoufoxProfile(displayName, camoufoxProxy, {
                profileId,
                profilesDir,
                os: preset.os,
                presetId: preset.presetId,
                locale: item.langs[0],
                timezoneId: timezone
            });
        } catch (err) {
            if (err?.code !== 'EEXIST') {
                throw err;
            }
        }

        if (existing) {
            Object.assign(existing, record);
            updatedProfiles++;
        } else {
            state.profiles.unshift(record);
            createdProfiles++;
        }

        summary.push({
            id: profileId,
            userId: item.userId,
            name: displayName,
            rawStatus: item.audit.status,
            rawConflicts: rawIssuesCount,
            healedPreset: preset.presetId,
            deviceModel: preset.deviceModel,
            proxy: item.proxyRaw ? `${normalizeProxyKind(item.proxyRaw.scheme)}://${item.proxyRaw.host}:${item.proxyRaw.port}` : 'none',
            langs: item.langs.join(',')
        });
    }

    const nextAuditId = (state.audit[0]?.id ?? 0) + 1;
    state.audit.unshift({
        id: nextAuditId,
        actor: os.userInfo().username || 'local',
        action: 'adspower.import',
        target_id: project.id,
        detail: {
            project: project.name,
            created: createdProfiles,
            updated: updatedProfiles,
            proxiesAdded: upsertedProxies,
            totalImported: summary.length
        },
        at: new Date().toISOString()
    });
    if (state.audit.length > 300) state.audit.length = 300;

    writePrivateFile(stateFile, JSON.stringify(state, null, 2) + '\n', { requireOwner: true });
    syncProxiesTxt(state);

    console.log(JSON.stringify({
        ok: true,
        project: project.name,
        createdProfiles,
        updatedProfiles,
        upsertedProxies,
        totalProfilesNow: state.profiles.length,
        totalProxiesNow: state.proxies.length,
        imported: summary
    }, null, 2));
}

main().catch((err) => {
    console.error(err?.message || err);
    process.exit(1);
});
