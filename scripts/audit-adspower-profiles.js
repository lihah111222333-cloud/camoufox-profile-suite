/**
 * Local AdsPower Profile Cache Reverse-Engineering & Exact Hardware SKU Auditor CLI
 *
 * Decodes AdsPower's custom shuffled-Base64 (`StaticConfig`, `DynamicConfig`) and `WebGLFP`
 * cache files from `/Volumes/hello/PrivacyData/adspower_global/cwd_global/source/cache`
 * (without reading or exposing any user cookies, passwords, or tokens) and audits every
 * profile against `validateHardwareModelSpec`.
 *
 * Usage:
 *   node scripts/audit-adspower-profiles.js [--cache-dir=/path/to/cache]
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { validateHardwareModelSpec } from '../src/camoufox/hardware-models.js';
import {
    USABLE_DEVICE_PRESET_CATALOG,
    listUsableDevicePresets,
    sanitizeAdsPowerProfileToCoherentPreset
} from '../src/camoufox/device-presets.js';

const STD_BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ADSPOWER_CUSTOM_BASE64_ALPHABET =
    'hTy1bfRJz4nLPcBCO7WtmNIaGvVeul5Zo8kq32UxrYw_-0gsjp96SDFXQiEMKdHA';

/**
 * Decode AdsPower's custom shuffled-alphabet Base64 string (`c.decodeBase64` in `main.min.js`
 * and `ReadEncodedFileToString` in `SunBrowser Framework` `../../base/command_line.cc`).
 *
 * @param {string} encoded
 * @returns {string}
 */
export function decodeAdsPowerBase64(encoded) {
    if (!encoded || typeof encoded !== 'string') return '';
    let std = '';
    for (let i = 0; i < encoded.length; i++) {
        const ch = encoded[i];
        const idx = ADSPOWER_CUSTOM_BASE64_ALPHABET.indexOf(ch);
        std += idx < 0 ? ch : STD_BASE64_ALPHABET[idx];
    }
    return Buffer.from(std, 'base64').toString('utf8');
}

/**
 * Audit a single AdsPower profile cache directory.
 *
 * @param {string} profileDir
 * @returns {object | null}
 */
export function auditAdsPowerProfileDir(profileDir) {
    const dirName = path.basename(profileDir);
    const fbccId = dirName.split('_')[0];
    const staticMd5 = crypto.createHash('md5').update(`${fbccId}_static`).digest('hex');
    const webglMd5 = crypto.createHash('md5').update(`${fbccId}_webgl`).digest('hex');

    const staticPath = path.join(profileDir, staticMd5);
    if (!fs.existsSync(staticPath)) {
        return null;
    }

    let staticConfig = {};
    try {
        const raw = fs.readFileSync(staticPath, 'utf8').trim();
        const decoded = raw.startsWith('{') ? raw : decodeAdsPowerBase64(raw);
        staticConfig = JSON.parse(decoded);
    } catch {
        return null;
    }

    let webglConfig = {};
    try {
        const files = fs.readdirSync(profileDir).filter((f) => f.startsWith(webglMd5));
        if (files.length > 0) {
            webglConfig = JSON.parse(fs.readFileSync(path.join(profileDir, files[0]), 'utf8').trim());
        }
    } catch {
        webglConfig = {};
    }

    const platform = staticConfig.Platform || 'MacIntel';
    const targetOs = platform.toLowerCase().includes('win')
        ? 'win'
        : platform.toLowerCase().includes('mac')
          ? 'mac'
          : 'lin';

    const uam = staticConfig.UserAgentMetadata || {};
    const telemetry = {
        navigator: {
            platform,
            hardwareConcurrency: Number(staticConfig.HardwareConcurrency),
            maxTouchPoints: Number(staticConfig.MaxTouchPoints ?? 0)
        },
        webgl: {
            unmaskedVendor: webglConfig.UNMASKED_VENDOR_WEBGL || '',
            unmaskedRenderer: webglConfig.UNMASKED_RENDERER_WEBGL || '',
            GPUAdapterInfo: webglConfig.GPUAdapterInfo || null
        },
        screen: {},
        userAgentMetadata: uam,
        hardwareProfile: {
            deviceName: staticConfig.DeviceName || null,
            productType: staticConfig.ProductType || null,
            architecture: uam.architecture || null,
            osVersion: uam.platformVersion || null,
            ramGb: staticConfig.DeviceMemory ? Number(staticConfig.DeviceMemory) : null,
            webgpuAdapterInfo: webglConfig.GPUAdapterInfo || null
        }
    };

    const result = validateHardwareModelSpec(telemetry, targetOs);
    const healed = sanitizeAdsPowerProfileToCoherentPreset({
        fbccId,
        Platform: platform,
        DeviceName: staticConfig.DeviceName || null,
        HardwareConcurrency: staticConfig.HardwareConcurrency,
        DeviceMemory: staticConfig.DeviceMemory,
        UNMASKED_RENDERER_WEBGL: webglConfig.UNMASKED_RENDERER_WEBGL || null,
        GPUAdapterInfo: webglConfig.GPUAdapterInfo || null,
        UserAgentMetadata: uam
    });

    return {
        profileDirName: dirName,
        fbccId,
        platform,
        deviceName: staticConfig.DeviceName || null,
        cores: staticConfig.HardwareConcurrency,
        deviceMemoryGb: staticConfig.DeviceMemory,
        architecture: uam.architecture || null,
        osVersion: uam.platformVersion || null,
        renderer: webglConfig.UNMASKED_RENDERER_WEBGL || null,
        webgpuArch: webglConfig.GPUAdapterInfo?.architecture || null,
        passed: result.passed,
        matchedSku: result.matchedSku,
        issues: result.issues,
        healed
    };
}

function printUsablePresets() {
    const allPresets = listUsableDevicePresets();
    console.log('================================================================================');
    console.log(`🖥️  Camoufox Absorbed & 100% SKU-Verified Device Preset Catalog (${allPresets.length} Presets)`);
    console.log('================================================================================');
    for (const os of ['macos', 'windows', 'linux']) {
        const group = listUsableDevicePresets({ os });
        console.log(`\n▶ [${os.toUpperCase()}] (${group.length} verified device models):`);
        for (const p of group) {
            console.log(
                `  • ${p.presetId.padEnd(36)} | ${p.deviceModel.padEnd(34)} | ${p.cpuModel.padEnd(32)} | ${String(p.hardwareConcurrency).padStart(2)}T | ${String(p.ramGb).padStart(3)}GB RAM | ${String(p.storageGb).padStart(4)}GB SSD | ${p.screen.width}x${p.screen.height}@${p.screen.devicePixelRatio}x`
            );
        }
    }
}

function main() {
    if (process.argv.includes('--list-presets')) {
        printUsablePresets();
        return;
    }

    const showHeal = process.argv.includes('--heal');
    const argDir = process.argv.find((a) => a.startsWith('--cache-dir='))?.split('=')[1];
    const cacheRoot =
        argDir || '/Volumes/hello/PrivacyData/adspower_global/cwd_global/source/cache';

    if (!fs.existsSync(cacheRoot)) {
        console.log(`AdsPower cache directory not found at: ${cacheRoot}`);
        process.exit(0);
    }

    const dirs = fs
        .readdirSync(cacheRoot)
        .map((d) => path.join(cacheRoot, d))
        .filter((p) => fs.statSync(p).isDirectory());

    const reports = [];
    for (const dir of dirs) {
        const rep = auditAdsPowerProfileDir(dir);
        if (rep) reports.push(rep);
    }

    const passedCount = reports.filter((r) => r.passed).length;
    const failedCount = reports.length - passedCount;
    const healedPassCount = reports.filter((r) => r.healed?.validation?.passed).length;

    console.log('================================================================================');
    console.log('🔍 AdsPower Local Profile Cache Hardware SKU Coherence Audit');
    console.log('================================================================================');
    console.log(`📂 Cache Directory : ${cacheRoot}`);
    console.log(`📊 Audited Profiles: ${reports.length} (Raw Passed: ${passedCount}, Raw Failed: ${failedCount}, Auto-Healed Passed: ${healedPassCount}/${reports.length})\n`);

    for (const r of reports) {
        const badge = r.passed ? '✅ PASS' : '❌ FAIL';
        console.log(
            `${badge} [${r.profileDirName}] Device="${r.deviceName}" | Arch=${r.architecture} | OS=${r.osVersion} | Cores=${r.cores} | Mem=${r.deviceMemoryGb}GB | GPU="${r.renderer}" | WebGPU_Arch=${r.webgpuArch}`
        );
        for (const issue of r.issues) {
            console.log(`   ↳ ⚠️  ${issue}`);
        }
        if (!r.passed && showHeal && r.healed) {
            const hp = r.healed.healedProfile.hardwareProfile;
            console.log(
                `   ↳ 🛠️  AUTO-HEALED -> Preset="${r.healed.healedPresetId}" (${hp.deviceModel} | ${hp.cpuModel} | ${r.healed.healedProfile.telemetry.navigator.hardwareConcurrency} Cores | ${hp.ramGb}GB RAM | ${hp.storageGb}GB SSD | GPU="${r.healed.healedProfile.telemetry.webgl.unmaskedRenderer}" | Host="${r.healed.healedProfile.deviceName}") [SKU Verified: ${r.healed.validation.passed ? '100% PASS' : 'FAIL'}]`
            );
        }
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}
