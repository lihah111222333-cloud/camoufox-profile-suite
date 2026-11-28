#!/usr/bin/env node
/**
 * Repository Baseline Installer for Camoufox Anti-Detect Engine
 *
 * Ensures the paired C++-patched Camoufox browser bundle (`Camoufox.app` / `camoufox-bin` / `camoufox.exe`),
 * MaxMind GeoIP database (`mmdb`), and `fpgen` fingerprint model are installed in the user cache.
 * Uses multi-connection `aria2c` acceleration when available, with full SHA-256 verification via
 * Camoufox's official `installVersioned` installer.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

function findAria2cBinary() {
    const candidates = process.platform === 'darwin'
        ? ['/opt/homebrew/bin/aria2c', '/usr/local/bin/aria2c', 'aria2c']
        : ['aria2c'];
    for (const bin of candidates) {
        if (bin.includes('/')) {
            try {
                if (fs.existsSync(bin) && fs.statSync(bin).isFile()) return bin;
            } catch {
                // continue
            }
        } else {
            const pathDirs = String(process.env.PATH || '').split(path.delimiter);
            for (const dir of pathDirs) {
                if (!dir) continue;
                const full = path.join(dir, process.platform === 'win32' ? 'aria2c.exe' : 'aria2c');
                try {
                    if (fs.existsSync(full) && fs.statSync(full).isFile()) return full;
                } catch {
                    // continue
                }
            }
        }
    }
    return null;
}

function downloadWithAria2c(aria2Bin, url, destDir, destName) {
    return new Promise((resolve, reject) => {
        const args = [
            '--allow-overwrite=true',
            '--auto-file-renaming=false',
            '--continue=true',
            '--max-connection-per-server=16',
            '--split=16',
            '--min-split-size=1M',
            '--file-allocation=none',
            '--summary-interval=5',
            '--dir', destDir,
            '--out', destName,
            url
        ];
        const child = spawn(aria2Bin, args, {
            stdio: ['ignore', 'inherit', 'inherit']
        });
        child.once('error', reject);
        child.once('exit', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`aria2c exited with status ${code}`));
        });
    });
}

function ensureFlatMacAppSymlink(installDir, activeDir) {
    if (process.platform !== 'darwin' || !installDir || !activeDir) return;
    const activeApp = path.join(activeDir, 'Camoufox.app');
    const flatApp = path.join(installDir, 'Camoufox.app');
    if (!fs.existsSync(activeApp) || path.resolve(activeApp) === path.resolve(flatApp)) return;
    try {
        const existing = fs.lstatSync(flatApp, { throwIfNoEntry: false });
        if (existing) {
            if (existing.isSymbolicLink()) {
                fs.unlinkSync(flatApp);
            } else {
                return;
            }
        }
        fs.symlinkSync(activeApp, flatApp, 'dir');
    } catch {
        // non-fatal convenience link
    }
}

export async function ensureCamoufoxBaseline({ quiet = false, allowSkipInCi = false } = {}) {
    if (
        process.env.CAMOUFOX_SKIP_AUTO_FETCH === '1' ||
        process.env.CAMOUFOX_SKIP_AUTO_FETCH === 'true' ||
        process.env.npm_config_package_lock_only === 'true' ||
        (allowSkipInCi && (process.env.CI === 'true' || process.env.CI === '1'))
    ) {
        if (!quiet) {
            console.log('[camoufox-baseline] Skipping automatic browser binary fetch (env opt-out / CI).');
        }
        return { skipped: true, executablePath: null };
    }

    const [
        pkgmanMod,
        multiversionMod,
        pathsMod,
        pinMod,
        geoMod,
        fpgenMod
    ] = await Promise.all([
        import('camoufox/dist/pkgman.js'),
        import('camoufox/dist/multiversion.js'),
        import('camoufox/dist/paths.js'),
        import('camoufox/dist/browser-pin.js'),
        import('camoufox/dist/geolocation.js'),
        import('fpgen-js')
    ]);

    const { CamoufoxFetcher, RepoConfig, taggedVersions, launchPath } = pkgmanMod;
    const { COMPAT_FLAG, getActivePath, loadConfig } = multiversionMod;
    const { INSTALL_DIR } = pathsMod;
    const { effectivePin } = pinMod;
    const { allowGeoip, downloadMmdb } = geoMod;
    const { ensureModel } = fpgenMod;

    // Fast path: check if a valid paired Camoufox binary is already installed
    let activeDir = null;
    try {
        if (fs.existsSync(COMPAT_FLAG)) {
            activeDir = getActivePath();
        }
        if (activeDir) {
            const execPath = launchPath(activeDir);
            if (fs.existsSync(execPath)) {
                ensureFlatMacAppSymlink(INSTALL_DIR, activeDir);
                if (allowGeoip()) {
                    await downloadMmdb();
                }
                await ensureModel();
                if (!quiet) {
                    console.log(`[camoufox-baseline] Camoufox engine ready: ${execPath}`);
                }
                return { skipped: false, installedNow: false, activeDir, executablePath: execPath };
            }
        }
    } catch {
        activeDir = null;
    }

    if (fs.existsSync(INSTALL_DIR) && fs.readdirSync(INSTALL_DIR).length > 0 && !fs.existsSync(COMPAT_FLAG)) {
        fs.rmSync(INSTALL_DIR, { recursive: true, force: true });
    }

    const aria2Bin = findAria2cBinary();
    class BaselineCamoufoxFetcher extends CamoufoxFetcher {
        static async downloadFile(tempFileStream, url) {
            if (aria2Bin) {
                const dlDir = fs.mkdtempSync(path.join(os.tmpdir(), 'camoufox-aria2-'));
                const dlName = 'camoufox-bundle.zip';
                const dlPath = path.join(dlDir, dlName);
                try {
                    console.log(`[camoufox-baseline] Accelerating download via aria2c (16x): ${url}`);
                    await downloadWithAria2c(aria2Bin, url, dlDir, dlName);
                    await pipeline(fs.createReadStream(dlPath), tempFileStream, { end: false });
                    return;
                } catch (err) {
                    console.warn(`[camoufox-baseline] aria2c fallback to built-in fetcher: ${err.message}`);
                } finally {
                    fs.rmSync(dlDir, { recursive: true, force: true });
                }
            }
            await CamoufoxFetcher.downloadFile(tempFileStream, url);
        }
    }

    const config = loadConfig();
    const pin = effectivePin(config);
    let repoConfig = null;
    let selectedVersion = undefined;
    if (pin) {
        repoConfig = RepoConfig.findByName(pin.repoName);
        const matches = await taggedVersions(repoConfig, pin.tag);
        selectedVersion = matches.find((v) => v.version.fullString === `${pin.version}-${pin.build}`) || matches[0];
    }

    const fetcher = await new BaselineCamoufoxFetcher(repoConfig ?? undefined, selectedVersion).init();
    if (!quiet) {
        console.log(`[camoufox-baseline] Installing Camoufox v${fetcher.verstr}...`);
    }
    await fetcher.install(false);

    if (allowGeoip()) {
        await downloadMmdb();
    }
    await ensureModel();

    const finalActive = getActivePath();
    const executablePath = launchPath(finalActive || undefined);
    ensureFlatMacAppSymlink(INSTALL_DIR, finalActive);

    if (!quiet) {
        console.log(`[camoufox-baseline] Installed & verified Camoufox: ${executablePath}`);
    }
    return { skipped: false, installedNow: true, activeDir: finalActive, executablePath };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);
if (isMain) {
    const isPostinstall = process.argv.includes('--postinstall');
    ensureCamoufoxBaseline({
        quiet: false,
        allowSkipInCi: isPostinstall
    }).catch((error) => {
        if (isPostinstall) {
            console.warn(
                `[camoufox-baseline] Deferred automatic Camoufox download during postinstall (${error.message}). ` +
                'It will retry automatically on first launch or via `npm run setup:camoufox`.'
            );
            process.exitCode = 0;
            return;
        }
        console.error(`[camoufox-baseline] Failed to install Camoufox baseline: ${error.message}`);
        process.exitCode = 1;
    });
}
