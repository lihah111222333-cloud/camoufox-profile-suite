// SPDX-License-Identifier: AGPL-3.0-or-later
// Stages the minimal self-contained Camoufox Studio Node.js runtime into
// desktop/src-tauri/resources/suite/ for standalone macOS .app / .dmg packaging.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const desktopDir = path.resolve(__dirname, '..');
const repoRoot = path.resolve(desktopDir, '..');
const stageRoot = path.join(desktopDir, 'src-tauri', 'resources', 'suite');

function copyDir(src, dst) {
    fs.mkdirSync(dst, { recursive: true });
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const s = path.join(src, entry.name);
        const d = path.join(dst, entry.name);
        if (entry.isDirectory()) {
            copyDir(s, d);
        } else if (entry.isFile()) {
            fs.copyFileSync(s, d);
        }
    }
}

function copyFile(rel) {
    const src = path.join(repoRoot, rel);
    const dst = path.join(stageRoot, rel);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(src, dst);
}

fs.rmSync(stageRoot, { recursive: true, force: true });
fs.mkdirSync(stageRoot, { recursive: true });

// Minimal ESM package marker so Node treats .js files as ES modules
fs.writeFileSync(
    path.join(stageRoot, 'package.json'),
    JSON.stringify({ name: 'camoufox-studio-runtime', version: '1.0.0', private: true, type: 'module' }, null, 2) + '\n'
);

// Backend bridge & built frontend
copyFile('desktop/server.mjs');
copyFile('desktop/proxy-relay.mjs');
copyFile('desktop/netd-bridge.mjs');
copyFile('desktop/browser-branding.mjs');
copyFile('desktop/browser-hud.py');
copyDir(path.join(desktopDir, 'dist'), path.join(stageRoot, 'desktop', 'dist'));

// Vendored xfrpc-ios (NexusEdge netd) native engine & core plugins
const vendorNetd = path.join(desktopDir, 'vendor', 'netd');
if (fs.existsSync(vendorNetd)) {
    copyDir(vendorNetd, path.join(stageRoot, 'desktop', 'vendor', 'netd'));
    fs.chmodSync(path.join(stageRoot, 'desktop', 'vendor', 'netd'), 0o700);
    fs.chmodSync(path.join(stageRoot, 'desktop', 'vendor', 'netd', 'plugins'), 0o700);
    fs.chmodSync(path.join(stageRoot, 'desktop', 'vendor', 'netd', 'netd'), 0o755);
}

// Pure Node.js Camoufox engine, device presets, hardware SKU models, utils & diagnostics
copyDir(path.join(repoRoot, 'src', 'camoufox'), path.join(stageRoot, 'src', 'camoufox'));
copyDir(path.join(repoRoot, 'src', 'utils'), path.join(stageRoot, 'src', 'utils'));
copyFile('src/config.js');
copyFile('scripts/audit-adspower-profiles.js');
copyFile('scripts/ensure-camoufox-baseline.js');
copyFile('scripts/query-traffic-attribution.js');
copyFile('scripts/verify-camoufox-coherence.js');
copyFile('config/names.json');

// Stage Camoufox + Playwright runtime dependencies (excluding heavy UI build devDependencies)
const DEV_ONLY_PREFIXES = [
    '@tauri-apps',
    '@types',
    '@vitejs',
    '@biomejs',
    'esbuild',
    'postcss',
    'react',
    'react-dom',
    'rollup',
    'scheduler',
    'typescript',
    'vite'
];
const srcNodeModules = fs.existsSync(path.join(desktopDir, 'node_modules', 'camoufox'))
    ? path.join(desktopDir, 'node_modules')
    : path.join(repoRoot, 'node_modules');
if (fs.existsSync(srcNodeModules)) {
    const dstNodeModules = path.join(stageRoot, 'node_modules');
    fs.mkdirSync(dstNodeModules, { recursive: true });
    for (const entry of fs.readdirSync(srcNodeModules, { withFileTypes: true })) {
        if (entry.name === '.bin' || entry.name === '.package-lock.json' || entry.name === '.vite') continue;
        if (DEV_ONLY_PREFIXES.some((p) => entry.name === p || entry.name.startsWith(`${p}/`))) continue;
        const s = path.join(srcNodeModules, entry.name);
        const d = path.join(dstNodeModules, entry.name);
        if (entry.isDirectory()) {
            copyDir(s, d);
        } else if (entry.isFile()) {
            fs.copyFileSync(s, d);
        }
    }
}

console.log(`Staged standalone runtime -> ${stageRoot}`);
