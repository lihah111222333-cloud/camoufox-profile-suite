/**
 * Local AdsPower Profile Cache Reverse-Engineering & Exact Hardware SKU Auditor CLI
 *
 * Decodes AdsPower's custom shuffled-Base64 (`StaticConfig`, `DynamicConfig`) and `WebGLFP`
 * cache files from the selected local cache directory
 * (without reading or exposing any user cookies, passwords, or tokens) and audits every
 * profile against `validateHardwareModelSpec`.
 *
 * Usage:
 *   node scripts/audit-adspower-profiles.js --cache-dir=/path/to/cache [--heal]
 *   node scripts/audit-adspower-profiles.js --list-presets
 */

import path from 'path';
import crypto from 'crypto';
import { pathToFileURL } from 'url';
import { listCaptureDirectory, readCaptureFile } from '../src/camoufox/capture-io.js';
import { validateHardwareModelSpec } from '../src/camoufox/hardware-models.js';
import {
    listUsableDevicePresets,
    sanitizeAdsPowerProfileToCoherentPreset
} from '../src/camoufox/device-presets.js';

const STD_BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ADSPOWER_CUSTOM_BASE64_ALPHABET =
    'hTy1bfRJz4nLPcBCO7WtmNIaGvVeul5Zo8kq32UxrYw_-0gsjp96SDFXQiEMKdHA';
const MAX_CACHE_FILE_BYTES = 4 * 1024 * 1024;

function readCacheObject(profileDir, fileName, { encoded = false, optional = false } = {}) {
    const bytes = readCaptureFile(profileDir, fileName, { maxBytes: MAX_CACHE_FILE_BYTES, optional });
    if (!bytes) return null;
    const raw = bytes.toString('utf8').trim();
    const parsed = JSON.parse(encoded && !raw.startsWith('{') ? decodeAdsPowerBase64(raw) : raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new TypeError('Expected an AdsPower cache object');
    }
    return parsed;
}

function displayField(value) {
    if (value !== null && typeof value === 'object') return '[Invalid value]';
    const text = String(value);
    const preview = text.length > 512 ? `${text.slice(0, 512)}…` : text;
    return preview.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, (character) =>
        `\\u{${character.codePointAt(0).toString(16)}}`);
}

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
    try {
        return inspectAdsPowerProfileDir(profileDir);
    } catch {
        return null;
    }
}

function inspectAdsPowerProfileDir(profileDir) {
    const dirName = path.basename(profileDir);
    const fbccId = dirName.split('_')[0];
    const staticMd5 = crypto.createHash('md5').update(`${fbccId}_static`).digest('hex');
    const webglMd5 = crypto.createHash('md5').update(`${fbccId}_webgl`).digest('hex');

    const staticConfig = readCacheObject(profileDir, staticMd5, { encoded: true, optional: true });
    if (!staticConfig) return null;
    const webglEntry = listCaptureDirectory(profileDir).find(({ name }) => name.startsWith(webglMd5));
    const webglConfig = webglEntry ? readCacheObject(profileDir, webglEntry.name) : {};

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
            deviceMemory: staticConfig.DeviceMemory ? Number(staticConfig.DeviceMemory) : null,
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
    const rawCacheArg = process.argv.find((a) => a.startsWith('--cache-dir='));
    const argDir = rawCacheArg ? rawCacheArg.slice('--cache-dir='.length) : null;
    if (!argDir) {
        console.error('Specify the AdsPower cache directory with --cache-dir=/path/to/cache.');
        process.exitCode = 1;
        return;
    }
    const cacheRoot = path.resolve(argDir);
    let dirs;
    try {
        dirs = listCaptureDirectory(cacheRoot).filter((entry) => entry.isDirectory());
    } catch {
        console.error('The AdsPower cache directory must be readable and cannot be linked.');
        process.exitCode = 1;
        return;
    }

    const reports = [];
    for (const dir of dirs) {
        const rep = auditAdsPowerProfileDir(path.join(cacheRoot, dir.name));
        if (rep) reports.push(rep);
    }

    const passedCount = reports.filter((r) => r.passed).length;
    const failedCount = reports.length - passedCount;
    const healedPassCount = reports.filter((r) => r.healed?.validation?.passed).length;

    console.log('================================================================================');
    console.log('🔍 AdsPower Local Profile Cache Hardware SKU Coherence Audit');
    console.log('================================================================================');
    console.log(`Unreadable or unsupported profile directories: ${dirs.length - reports.length}`);
    console.log(`📊 Audited Profiles: ${reports.length} (Raw Passed: ${passedCount}, Raw Failed: ${failedCount}, Auto-Healed Passed: ${healedPassCount}/${reports.length})\n`);

    for (const [index, r] of reports.entries()) {
        const badge = r.passed ? '✅ PASS' : '❌ FAIL';
        const fields = [
            `Device="${displayField(r.deviceName)}"`,
            `Arch=${displayField(r.architecture)}`,
            `OS=${displayField(r.osVersion)}`,
            `Cores=${displayField(r.cores)}`,
            `Mem=${displayField(r.deviceMemoryGb)}GB`,
            `GPU="${displayField(r.renderer)}"`,
            `WebGPU_Arch=${displayField(r.webgpuArch)}`
        ];
        console.log(`${badge} [Profile ${index + 1}] ${fields.join(' | ')}`);
        for (const issue of r.issues) {
            console.log(`   ↳ ⚠️  ${displayField(issue)}`);
        }
        if (!r.passed && showHeal && r.healed) {
            const { hardwareProfile, telemetry } = r.healed.healedProfile;
            const details = [
                displayField(hardwareProfile.deviceModel),
                displayField(hardwareProfile.cpuModel),
                `${displayField(telemetry.navigator.hardwareConcurrency)} Cores`,
                `${displayField(hardwareProfile.ramGb)}GB RAM`,
                `${displayField(hardwareProfile.storageGb)}GB SSD`,
                `GPU="${displayField(telemetry.webgl.unmaskedRenderer)}"`
            ];
            const verdict = r.healed.validation.passed ? '100% PASS' : 'FAIL';
            console.log(`   ↳ 🛠️  AUTO-HEALED -> Preset="${displayField(r.healed.healedPresetId)}" (${details.join(' | ')}) [SKU Verified: ${verdict}]`);
        }
    }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
    main();
}
