/**
 * Authoritative Multi-Vendor Hardware SKU & Exact Device Model Parameter Catalog for Camoufox
 *
 * Enforces exact model-level hardware parameter coherence across ALL major device ecosystems:
 *   1. Apple Silicon SoC SKUs (M1 / M2 / M3 / M4 base, Pro, Max, Ultra — 15 SKUs):
 *      - Unified CPU + GPU die lockstep, exact core count, Unified Memory capacity & core-to-RAM die pairing,
 *        factory SSD tiers, and notched/non-notched/desktop panel form-factor lockstep.
 *   2. Intel-based Apple Mac SKUs (2017–2020 MacBook Air, MacBook Pro 13"/15"/16", iMac 27" 5K / iMac Pro, Mac Pro Xeon W):
 *      - Exact Intel CPU core/thread count, Intel Iris Plus / UHD 617/630 / AMD Radeon Pro 555X–5600M / Vega / W-series GPU lockstep,
 *        RAM & SSD limits, and non-notched / desktop panel enforcement.
 *   3. Windows 11 ARM64 Qualcomm Snapdragon X Copilot+ PC SoCs (X Elite X1E-84/80/78, X Plus X1P-64/42):
 *      - Unified Oryon CPU core count (12 / 10 / 8 cores), Adreno X1-85 / X1-45 GPU lockstep, LPDDR5x RAM tiers, and OS lockstep.
 *   4. Windows & Linux OEM Laptop / Ultrabook / Gaming Laptop / Workstation Device SKUs (`OEM_DEVICE_MODEL_CATALOG`):
 *      - Lenovo ThinkPad (X1 Carbon Gen 10/11/12, T14 Gen 4 AMD, P16 Gen 2 Workstation)
 *      - Dell XPS (XPS 13 9320/9340, XPS 15 9530, XPS 16 9640)
 *      - Microsoft Surface (Surface Laptop 5, Surface Pro 9 with 3:2 aspect ratio & touch requirement, Surface Laptop Studio 2)
 *      - ASUS ROG (Zephyrus G14 AMD, Strix SCAR 16/18), Razer Blade 16, HP Spectre x360 14, LG Gram 16, Samsung Galaxy Book4 Pro,
 *        Framework Laptop 13, System76 Lemur Pro / Oryx Pro.
 *   5. 80+ Desktop & Mobile x86_64 PC CPU SKUs (Intel 8th–14th Gen U/P/H/HX/K/KF/F, Core Ultra Series 1 & Series 2 Lunar Lake / Arrow Lake,
 *      AMD Ryzen 3000–9000 Desktop/Mobile & Ryzen AI 300):
 *      - Exact physical core / logical thread counts (including non-HT Lunar Lake 8C/8T & Arrow Lake 14T/20T/24T)
 *      - On-package MoP RAM lockstep on Intel Lunar Lake (Core Ultra 7 256V = 16GB only; 258V / 288V = 32GB only)
 *      - Integrated GPU presence (`hasIntegratedGpu: false` on Intel -F/-KF and AMD Ryzen 3000/5000 non-G CPUs)
 *      - Generation-specific integrated GPU model lockstep (`expectedIgpuPattern`: e.g. i7-13700K -> UHD 770, i5-8250U -> UHD 620,
 *        Ryzen 7 6800U -> Radeon 680M, Ryzen 7 7840HS -> Radeon 780M, Ryzen AI 9 HX 370 -> Radeon 890M)
 *      - CPU form-factor (`desktop` vs `mobile-ultrabook` vs `mobile-h`) vs GPU form-factor (`desktop` vs `laptop`) cross-check.
 *   6. 40+ Desktop & Laptop GPU SKUs + PCI Vendor/Device ID Registry (`PC_GPU_SKU_CATALOG` & `PCI_DEVICE_ID_CATALOG`):
 *      - Exact VRAM capacity tiers (`vramGb`, e.g. Desktop RTX 4090 = 24GB vs RTX 4090 Laptop GPU = 16GB; RTX 3060 = 8/12GB; GTX 1650 = 4GB)
 *      - PCI Vendor ID (`0x10de` NVIDIA, `0x1002` AMD, `0x8086` Intel, `0x5143` Qualcomm) and PCI Device ID spoofing detection
 *      - Windows ANGLE Vendor/Renderer lockstep, Direct3D Shader Model lockstep, and WebGL hardware parameter limits.
 */

const BYTES_PER_GB_BINARY = 1024 ** 3; // 1 GiB = 1,073,741,824 bytes

export const APPLE_LAPTOP_PANELS = Object.freeze({
    // Non-notched 13.3" Retina (M1 MacBook Air 2020, M1/M2 13.3" MacBook Pro Touch Bar, Intel 13" MacBook Air/Pro)
    nonNotch13: Object.freeze(['1280x800', '1440x900', '1680x1050']),
    // Non-notched 15.4" / 16.0" Intel MacBook Pro Retina (2016-2019)
    nonNotch15And16: Object.freeze(['1440x900', '1680x1050', '1792x1120', '1920x1200', '2048x1280']),
    // Notched 13.6" Liquid Retina (M2 / M3 / M4 MacBook Air)
    air13Notch: Object.freeze(['1024x665', '1280x832', '1470x956', '1710x1112']),
    // Notched 15.3" Liquid Retina (M2 / M3 / M4 MacBook Air 15")
    air15Notch: Object.freeze(['1280x828', '1440x932', '1710x1107']),
    // Notched 14.2" Liquid Retina XDR (14" MacBook Pro)
    pro14Notch: Object.freeze(['1147x745', '1352x878', '1512x982', '1800x1169']),
    // Notched 16.2" Liquid Retina XDR (16" MacBook Pro)
    pro16Notch: Object.freeze(['1312x848', '1496x967', '1728x1117', '2056x1329']),
    // Desktop / External Apple Displays (24" iMac 4.5K, 27" 5K iMac/Studio Display, 32" 6K Pro Display XDR, 1080p/1440p/4K)
    desktopDisplays: Object.freeze([
        '1920x1080',
        '2240x1260',
        '2560x1440',
        '2880x1620',
        '3008x1692',
        '3200x1800',
        '3840x2160'
    ])
});

const ALL_NOTCHED_AIR_PANELS = Object.freeze([
    ...APPLE_LAPTOP_PANELS.air13Notch,
    ...APPLE_LAPTOP_PANELS.air15Notch
]);

const ALL_NOTCHED_PRO_PANELS = Object.freeze([
    ...APPLE_LAPTOP_PANELS.pro14Notch,
    ...APPLE_LAPTOP_PANELS.pro16Notch
]);

const ALL_NOTCHED_LAPTOP_PANELS = Object.freeze([
    ...ALL_NOTCHED_AIR_PANELS,
    ...ALL_NOTCHED_PRO_PANELS
]);

const ALL_LAPTOP_PANELS = Object.freeze([
    ...APPLE_LAPTOP_PANELS.nonNotch13,
    ...APPLE_LAPTOP_PANELS.nonNotch15And16,
    ...ALL_NOTCHED_LAPTOP_PANELS
]);

const DEFAULT_APPLE_METAL_WEBGL_LIMITS = Object.freeze({
    maxTextureSize: 16384,
    maxCubeMapTextureSize: 16384,
    maxRenderbufferSize: 16384,
    maxViewportDims: Object.freeze([16384, 16384]),
    maxVertexAttribs: 16,
    aliasedLineWidthRange: Object.freeze([1, 1])
});

/**
 * 1. Authoritative Apple Silicon SoC SKU Catalog (M1 through M4 families).
 */
export const APPLE_SILICON_SKU_CATALOG = Object.freeze({
    'Apple M1': Object.freeze({
        chip: 'Apple M1',
        generation: 1,
        tier: 'base',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M1',
        allowedCores: Object.freeze([8]),
        allowedRamGb: Object.freeze([8, 16]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedCoreRamPairs: Object.freeze([{ cores: 8, ramGb: Object.freeze([8, 16]) }]),
        formFactors: Object.freeze(['laptop-non-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...APPLE_LAPTOP_PANELS.nonNotch13,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: ALL_NOTCHED_LAPTOP_PANELS,
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M1 Pro': Object.freeze({
        chip: 'Apple M1 Pro',
        generation: 1,
        tier: 'pro',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M1 Pro',
        allowedCores: Object.freeze([8, 10]),
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096, 8192]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 8, ramGb: Object.freeze([16, 32]) },
            { cores: 10, ramGb: Object.freeze([16, 32]) }
        ]),
        formFactors: Object.freeze(['laptop-pro-notch']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M1 Max': Object.freeze({
        chip: 'Apple M1 Max',
        generation: 1,
        tier: 'max',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M1 Max',
        allowedCores: Object.freeze([10]),
        allowedRamGb: Object.freeze([32, 64]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096, 8192]),
        allowedCoreRamPairs: Object.freeze([{ cores: 10, ramGb: Object.freeze([32, 64]) }]),
        formFactors: Object.freeze(['laptop-pro-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M1 Ultra': Object.freeze({
        chip: 'Apple M1 Ultra',
        generation: 1,
        tier: 'ultra',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M1 Ultra',
        allowedCores: Object.freeze([20]),
        allowedRamGb: Object.freeze([64, 128]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096, 8192]),
        allowedCoreRamPairs: Object.freeze([{ cores: 20, ramGb: Object.freeze([64, 128]) }]),
        formFactors: Object.freeze(['desktop']),
        allowedPanels: APPLE_LAPTOP_PANELS.desktopDisplays,
        forbiddenPanels: ALL_LAPTOP_PANELS,
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M2': Object.freeze({
        chip: 'Apple M2',
        generation: 2,
        tier: 'base',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M2',
        allowedCores: Object.freeze([8]),
        allowedRamGb: Object.freeze([8, 16, 24]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedCoreRamPairs: Object.freeze([{ cores: 8, ramGb: Object.freeze([8, 16, 24]) }]),
        formFactors: Object.freeze(['laptop-air-notch', 'laptop-non-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: ALL_NOTCHED_PRO_PANELS,
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M2 Pro': Object.freeze({
        chip: 'Apple M2 Pro',
        generation: 2,
        tier: 'pro',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M2 Pro',
        allowedCores: Object.freeze([10, 12]),
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096, 8192]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 10, ramGb: Object.freeze([16, 32]) },
            { cores: 12, ramGb: Object.freeze([16, 32]) }
        ]),
        formFactors: Object.freeze(['laptop-pro-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M2 Max': Object.freeze({
        chip: 'Apple M2 Max',
        generation: 2,
        tier: 'max',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M2 Max',
        allowedCores: Object.freeze([12]),
        allowedRamGb: Object.freeze([32, 64, 96]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096, 8192]),
        allowedCoreRamPairs: Object.freeze([{ cores: 12, ramGb: Object.freeze([32, 64, 96]) }]),
        formFactors: Object.freeze(['laptop-pro-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M2 Ultra': Object.freeze({
        chip: 'Apple M2 Ultra',
        generation: 2,
        tier: 'ultra',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M2 Ultra',
        allowedCores: Object.freeze([24]),
        allowedRamGb: Object.freeze([64, 128, 192]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096, 8192]),
        allowedCoreRamPairs: Object.freeze([{ cores: 24, ramGb: Object.freeze([64, 128, 192]) }]),
        formFactors: Object.freeze(['desktop']),
        allowedPanels: APPLE_LAPTOP_PANELS.desktopDisplays,
        forbiddenPanels: ALL_LAPTOP_PANELS,
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M3': Object.freeze({
        chip: 'Apple M3',
        generation: 3,
        tier: 'base',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M3',
        allowedCores: Object.freeze([8]),
        allowedRamGb: Object.freeze([8, 16, 24]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedCoreRamPairs: Object.freeze([{ cores: 8, ramGb: Object.freeze([8, 16, 24]) }]),
        formFactors: Object.freeze(['laptop-air-notch', 'laptop-pro-14-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.pro14Notch,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...APPLE_LAPTOP_PANELS.pro16Notch,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M3 Pro': Object.freeze({
        chip: 'Apple M3 Pro',
        generation: 3,
        tier: 'pro',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M3 Pro',
        allowedCores: Object.freeze([11, 12]),
        // 192-bit Unified Memory bus on M3 Pro exclusively supports 18GB or 36GB
        allowedRamGb: Object.freeze([18, 36]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 11, ramGb: Object.freeze([18, 36]) },
            { cores: 12, ramGb: Object.freeze([18, 36]) }
        ]),
        formFactors: Object.freeze(['laptop-pro-notch']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M3 Max': Object.freeze({
        chip: 'Apple M3 Max',
        generation: 3,
        tier: 'max',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M3 Max',
        allowedCores: Object.freeze([14, 16]),
        allowedRamGb: Object.freeze([36, 48, 64, 96, 128]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096, 8192]),
        // 14-core M3 Max uses 384-bit bus (36GB / 96GB); 16-core M3 Max uses 512-bit bus (48GB / 64GB / 128GB)
        allowedCoreRamPairs: Object.freeze([
            { cores: 14, ramGb: Object.freeze([36, 96]) },
            { cores: 16, ramGb: Object.freeze([48, 64, 128]) }
        ]),
        formFactors: Object.freeze(['laptop-pro-notch']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M3 Ultra': Object.freeze({
        chip: 'Apple M3 Ultra',
        generation: 3,
        tier: 'ultra',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M3 Ultra',
        allowedCores: Object.freeze([28, 32]),
        allowedRamGb: Object.freeze([96, 256, 512]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096, 8192, 16384]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 28, ramGb: Object.freeze([96, 256]) },
            { cores: 32, ramGb: Object.freeze([96, 256, 512]) }
        ]),
        formFactors: Object.freeze(['desktop']),
        allowedPanels: APPLE_LAPTOP_PANELS.desktopDisplays,
        forbiddenPanels: ALL_LAPTOP_PANELS,
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M4': Object.freeze({
        chip: 'Apple M4',
        generation: 4,
        tier: 'base',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M4',
        allowedCores: Object.freeze([8, 9, 10]),
        allowedRamGb: Object.freeze([16, 24, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 8, ramGb: Object.freeze([16, 24]) },
            { cores: 9, ramGb: Object.freeze([16, 24]) },
            { cores: 10, ramGb: Object.freeze([16, 24, 32]) }
        ]),
        formFactors: Object.freeze(['laptop-air-notch', 'laptop-pro-14-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.pro14Notch,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...APPLE_LAPTOP_PANELS.pro16Notch,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M4 Pro': Object.freeze({
        chip: 'Apple M4 Pro',
        generation: 4,
        tier: 'pro',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M4 Pro',
        allowedCores: Object.freeze([12, 14]),
        allowedRamGb: Object.freeze([24, 48, 64]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 12, ramGb: Object.freeze([24, 48]) },
            { cores: 14, ramGb: Object.freeze([24, 48, 64]) }
        ]),
        formFactors: Object.freeze(['laptop-pro-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M4 Max': Object.freeze({
        chip: 'Apple M4 Max',
        generation: 4,
        tier: 'max',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M4 Max',
        allowedCores: Object.freeze([14, 16]),
        allowedRamGb: Object.freeze([36, 48, 64, 128]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096, 8192]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 14, ramGb: Object.freeze([36]) },
            { cores: 16, ramGb: Object.freeze([48, 64, 128]) }
        ]),
        formFactors: Object.freeze(['laptop-pro-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M4 Ultra': Object.freeze({
        chip: 'Apple M4 Ultra',
        generation: 4,
        tier: 'ultra',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M4 Ultra',
        allowedCores: Object.freeze([28, 32]),
        allowedRamGb: Object.freeze([96, 128, 256, 512]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096, 8192, 16384]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 28, ramGb: Object.freeze([96, 128, 256]) },
            { cores: 32, ramGb: Object.freeze([96, 128, 256, 512]) }
        ]),
        formFactors: Object.freeze(['desktop']),
        allowedPanels: APPLE_LAPTOP_PANELS.desktopDisplays,
        forbiddenPanels: ALL_LAPTOP_PANELS,
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M5': Object.freeze({
        chip: 'Apple M5',
        generation: 5,
        tier: 'base',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M5',
        allowedCores: Object.freeze([8, 9, 10]),
        allowedRamGb: Object.freeze([16, 24, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 8, ramGb: Object.freeze([16, 24]) },
            { cores: 9, ramGb: Object.freeze([16, 24]) },
            { cores: 10, ramGb: Object.freeze([16, 24, 32]) }
        ]),
        formFactors: Object.freeze(['laptop-air-notch', 'laptop-pro-14-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.pro14Notch,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...APPLE_LAPTOP_PANELS.pro16Notch,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M5 Pro': Object.freeze({
        chip: 'Apple M5 Pro',
        generation: 5,
        tier: 'pro',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M5 Pro',
        allowedCores: Object.freeze([12, 14, 18]),
        allowedRamGb: Object.freeze([24, 36, 48, 64]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 12, ramGb: Object.freeze([24, 36, 48]) },
            { cores: 14, ramGb: Object.freeze([24, 36, 48, 64]) },
            { cores: 18, ramGb: Object.freeze([24, 36, 48, 64]) }
        ]),
        formFactors: Object.freeze(['laptop-pro-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M5 Max': Object.freeze({
        chip: 'Apple M5 Max',
        generation: 5,
        tier: 'max',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M5 Max',
        allowedCores: Object.freeze([14, 16, 20, 24]),
        allowedRamGb: Object.freeze([36, 48, 64, 96, 128]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096, 8192]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 14, ramGb: Object.freeze([36]) },
            { cores: 16, ramGb: Object.freeze([48, 64, 128]) },
            { cores: 20, ramGb: Object.freeze([48, 64, 96, 128]) },
            { cores: 24, ramGb: Object.freeze([64, 96, 128]) }
        ]),
        formFactors: Object.freeze(['laptop-pro-notch', 'desktop']),
        allowedPanels: Object.freeze([
            ...ALL_NOTCHED_PRO_PANELS,
            ...APPLE_LAPTOP_PANELS.desktopDisplays
        ]),
        forbiddenPanels: Object.freeze([
            ...ALL_NOTCHED_AIR_PANELS,
            ...APPLE_LAPTOP_PANELS.nonNotch13
        ]),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    'Apple M5 Ultra': Object.freeze({
        chip: 'Apple M5 Ultra',
        generation: 5,
        tier: 'ultra',
        cpuArch: 'arm',
        cpuVendor: 'apple',
        gpuRenderer: 'Apple M5 Ultra',
        allowedCores: Object.freeze([28, 32]),
        allowedRamGb: Object.freeze([96, 256, 512]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096, 8192, 16384]),
        allowedCoreRamPairs: Object.freeze([
            { cores: 28, ramGb: Object.freeze([96, 256]) },
            { cores: 32, ramGb: Object.freeze([96, 256, 512]) }
        ]),
        formFactors: Object.freeze(['desktop']),
        allowedPanels: APPLE_LAPTOP_PANELS.desktopDisplays,
        forbiddenPanels: ALL_LAPTOP_PANELS,
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    })
});

export const APPLE_SILICON_MIN_MACOS_VERSION = Object.freeze({
    1: 11.0, // M1 requires macOS 11.0 Big Sur+
    2: 12.4, // M2 requires macOS 12.4 Monterey+
    3: 14.0, // M3 requires macOS 14.0 Sonoma+
    4: 14.5, // M4 requires macOS 14.5 Sonoma / 15.0 Sequoia+
    5: 15.4  // M5 requires macOS 15.4 Sequoia / 26.0 Tahoe+
});

/**
 * 2. Authoritative Intel-based Apple Mac Device & GPU SKU Catalog (2017–2020).
 */
export const INTEL_MAC_SKU_CATALOG = Object.freeze({
    'MacBook Air (Intel 2018-2020)': Object.freeze({
        id: 'MacBook Air (Intel 2018-2020)',
        cpuVendor: 'intel',
        gpuPattern: /Intel\(R\)\s+(?:UHD\s+Graphics\s+617|Iris\(TM\)\s+Plus\s+Graphics(?!\s+6[45]\d))/i,
        allowedCores: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16]),
        allowedStorageGb: Object.freeze([128, 256, 512, 1024, 2048]),
        formFactors: Object.freeze(['laptop-non-notch']),
        forbiddenPanels: ALL_NOTCHED_LAPTOP_PANELS
    }),
    'MacBook Pro 13-inch (Intel 2018-2020)': Object.freeze({
        id: 'MacBook Pro 13-inch (Intel 2018-2020)',
        cpuVendor: 'intel',
        gpuPattern: /Intel\(R\)\s+Iris\(TM\)\s+(?:Plus\s+)?Graphics(?:\s+(?:540|550|6100|640|645|650|655|G7))?|Intel\s+Iris(?:\s+Pro)?\s+OpenGL\s+Engine/i,
        allowedCores: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16, 32]),
        allowedStorageGb: Object.freeze([128, 256, 512, 1024, 2048, 4096]),
        formFactors: Object.freeze(['laptop-non-notch']),
        forbiddenPanels: ALL_NOTCHED_LAPTOP_PANELS
    }),
    'MacBook Pro 15/16-inch (Intel 2018-2019)': Object.freeze({
        id: 'MacBook Pro 15/16-inch (Intel 2018-2019)',
        cpuVendor: 'intel',
        gpuPattern: /AMD\s+Radeon\s+Pro\s+(?:555X|560X|5300M|5500M|5600M|Vega\s+(?:16|20))|Intel\(R\)\s+UHD\s+Graphics\s+630/i,
        allowedCores: Object.freeze([12, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048, 4096, 8192]),
        formFactors: Object.freeze(['laptop-non-notch']),
        forbiddenPanels: ALL_NOTCHED_LAPTOP_PANELS
    }),
    'iMac 27-inch 5K / iMac Pro (Intel)': Object.freeze({
        id: 'iMac 27-inch 5K / iMac Pro (Intel)',
        cpuVendor: 'intel',
        gpuPattern: /AMD\s+Radeon\s+Pro\s+(?:570X|575X|580X|5300(?!M)|5500\s+XT|5700(?:\s+XT)?|Vega\s+(?:48|56|64|64X))/i,
        allowedCores: Object.freeze([6, 8, 12, 16, 20, 28, 36]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128, 256]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048, 4096, 8192]),
        formFactors: Object.freeze(['desktop']),
        forbiddenPanels: ALL_LAPTOP_PANELS
    }),
    'Mac Pro (Intel Xeon W 2019)': Object.freeze({
        id: 'Mac Pro (Intel Xeon W 2019)',
        cpuVendor: 'intel',
        gpuPattern: /AMD\s+Radeon\s+Pro\s+(?:W5500X|W5700X|W6600X|W6800X|W6900X|Vega\s+II)/i,
        allowedCores: Object.freeze([16, 24, 32, 48, 56]),
        allowedRamGb: Object.freeze([32, 48, 96, 192, 384, 768, 1536]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048, 4096, 8192]),
        formFactors: Object.freeze(['desktop']),
        forbiddenPanels: ALL_LAPTOP_PANELS
    })
});

/**
 * 3. Authoritative Qualcomm Snapdragon X (Windows 11 ARM64 Copilot+ PC) SoC SKU Catalog.
 */
export const QUALCOMM_SNAPDRAGON_SKU_CATALOG = Object.freeze({
    'Snapdragon X Elite X1E-84-100': Object.freeze({
        chip: 'Snapdragon X Elite X1E-84-100',
        vendor: 'qualcomm',
        allowedCores: Object.freeze([12]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        gpuPattern: /Adreno(?:\(TM\))?\s+X1-85|Qualcomm\(R\)\s+Adreno(?!\s*(?:\(TM\))?\s*X1-45)/i,
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Snapdragon X Elite X1E-80-100': Object.freeze({
        chip: 'Snapdragon X Elite X1E-80-100',
        vendor: 'qualcomm',
        allowedCores: Object.freeze([12]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        gpuPattern: /Adreno(?:\(TM\))?\s+X1-85|Qualcomm\(R\)\s+Adreno(?!\s*(?:\(TM\))?\s*X1-45)/i,
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Snapdragon X Elite X1E-78-100': Object.freeze({
        chip: 'Snapdragon X Elite X1E-78-100',
        vendor: 'qualcomm',
        allowedCores: Object.freeze([12]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        gpuPattern: /Adreno(?:\(TM\))?\s+X1-85|Qualcomm\(R\)\s+Adreno(?!\s*(?:\(TM\))?\s*X1-45)/i,
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Snapdragon X Plus X1P-64-100': Object.freeze({
        chip: 'Snapdragon X Plus X1P-64-100',
        vendor: 'qualcomm',
        allowedCores: Object.freeze([10]),
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        gpuPattern: /Adreno(?:\(TM\))?\s+X1-85|Qualcomm\(R\)\s+Adreno(?!\s*(?:\(TM\))?\s*X1-45)/i,
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Snapdragon X Plus X1P-42-100': Object.freeze({
        chip: 'Snapdragon X Plus X1P-42-100',
        vendor: 'qualcomm',
        allowedCores: Object.freeze([8]),
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024]),
        gpuPattern: /Adreno(?:\(TM\))?\s+X1-45|Qualcomm\(R\)\s+Adreno(?!\s*(?:\(TM\))?\s*X1-85)/i,
        allowedOs: Object.freeze(['win', 'lin'])
    })
});

/**
 * 4. Authoritative Windows & Linux OEM Laptop / Ultrabook / Gaming Laptop / Workstation Device SKU Catalog.
 */
export const OEM_DEVICE_MODEL_CATALOG = Object.freeze({
    'Lenovo ThinkPad X1 Carbon Gen 10': Object.freeze({
        model: 'Lenovo ThinkPad X1 Carbon Gen 10',
        brand: 'Lenovo',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([10, 12, 16]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+(?:Iris\(R\)\s+Xe|UHD)\s+Graphics/i,
        allowedRamGb: Object.freeze([8, 16, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Lenovo ThinkPad X1 Carbon Gen 11': Object.freeze({
        model: 'Lenovo ThinkPad X1 Carbon Gen 11',
        brand: 'Lenovo',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([10, 12, 14, 16, 20]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+(?:Iris\(R\)\s+Xe|UHD)\s+Graphics/i,
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Lenovo ThinkPad X1 Carbon Gen 12': Object.freeze({
        model: 'Lenovo ThinkPad X1 Carbon Gen 12',
        brand: 'Lenovo',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([12, 14, 16, 18, 22]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+(?:Arc\(TM\)\s+)?Graphics/i,
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Lenovo ThinkPad T14 Gen 4 (AMD)': Object.freeze({
        model: 'Lenovo ThinkPad T14 Gen 4 (AMD)',
        brand: 'Lenovo',
        cpuVendor: 'amd',
        allowedCores: Object.freeze([6, 8, 12, 16]),
        igpuOnly: true,
        gpuPattern: /AMD\s+Radeon(?:\(TM\))?\s+(?:740M|780M|Graphics)/i,
        allowedRamGb: Object.freeze([8, 16, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Lenovo ThinkPad P16 Gen 2': Object.freeze({
        model: 'Lenovo ThinkPad P16 Gen 2',
        brand: 'Lenovo',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([16, 20, 24, 28, 32]),
        igpuOnly: false,
        gpuPattern: /Intel\(R\)\s+UHD\s+Graphics|NVIDIA\s+RTX\s+(?:A1000|A2000|2000|3500|4000|5000)\s+Ada/i,
        allowedRamGb: Object.freeze([16, 32, 48, 64, 96, 128, 192]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096, 8192]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Dell XPS 13 9320': Object.freeze({
        model: 'Dell XPS 13 9320',
        brand: 'Dell',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([12, 14, 16, 20]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+Iris\(R\)\s+Xe\s+Graphics/i,
        allowedRamGb: Object.freeze([8, 16, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Dell XPS 13 9340': Object.freeze({
        model: 'Dell XPS 13 9340',
        brand: 'Dell',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([14, 16, 18, 22]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+(?:Arc\(TM\)\s+)?Graphics/i,
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Dell XPS 15 9530': Object.freeze({
        model: 'Dell XPS 15 9530',
        brand: 'Dell',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([12, 14, 16, 20]),
        igpuOnly: false,
        gpuPattern: /Intel\(R\)\s+(?:Iris\(R\)\s+Xe|Arc\(TM\)|UHD)\s+Graphics|NVIDIA\s+GeForce\s+RTX\s+40[567]0\s+Laptop\s+GPU/i,
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096, 8192]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Dell XPS 16 9640': Object.freeze({
        model: 'Dell XPS 16 9640',
        brand: 'Dell',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([16, 22]),
        igpuOnly: false,
        gpuPattern: /Intel\(R\)\s+Arc\(TM\)\s+Graphics|NVIDIA\s+GeForce\s+RTX\s+40[567]0\s+Laptop\s+GPU/i,
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([512, 1024, 2048, 4096]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Microsoft Surface Laptop 5': Object.freeze({
        model: 'Microsoft Surface Laptop 5',
        brand: 'Microsoft',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([10, 12]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+Iris\(R\)\s+Xe\s+Graphics/i,
        allowedRamGb: Object.freeze([8, 16, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024]),
        aspectRatio3by2: true,
        allowedOs: Object.freeze(['win'])
    }),
    'Surface Laptop 7th Edition (Snapdragon X Elite)': Object.freeze({
        model: 'Surface Laptop 7th Edition (Snapdragon X Elite)',
        brand: 'Microsoft',
        cpuVendor: 'qualcomm',
        allowedCores: Object.freeze([10, 12]),
        igpuOnly: true,
        gpuPattern: /Adreno(?:\(TM\))?\s+X1-(?:85|45)|Qualcomm\(R\)\s+Adreno/i,
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([256, 512, 1024]),
        aspectRatio3by2: true,
        allowedOs: Object.freeze(['win'])
    }),
    'ASUS Zenbook S 14 (Lunar Lake)': Object.freeze({
        model: 'ASUS Zenbook S 14 (Lunar Lake)',
        brand: 'ASUS',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([8]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+Arc\(TM\)\s+(?:140V\s+|130V\s+)?Graphics/i,
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'ThinkPad T480 (Intel i5-8250U)': Object.freeze({
        model: 'ThinkPad T480 (Intel i5-8250U)',
        brand: 'Lenovo',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([4, 8]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+UHD\s+Graphics\s+620/i,
        allowedRamGb: Object.freeze([8, 16, 32]),
        allowedStorageGb: Object.freeze([256, 512, 1024]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Microsoft Surface Pro 9': Object.freeze({
        model: 'Microsoft Surface Pro 9',
        brand: 'Microsoft',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([10, 12]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+Iris\(R\)\s+Xe\s+Graphics/i,
        allowedRamGb: Object.freeze([8, 16, 32]),
        allowedStorageGb: Object.freeze([128, 256, 512, 1024]),
        aspectRatio3by2: true,
        requiresTouchScreen: true,
        allowedOs: Object.freeze(['win'])
    }),
    'Microsoft Surface Laptop Studio 2': Object.freeze({
        model: 'Microsoft Surface Laptop Studio 2',
        brand: 'Microsoft',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([14, 20]),
        igpuOnly: false,
        gpuPattern: /Intel\(R\)\s+Iris\(R\)\s+Xe\s+Graphics|NVIDIA\s+(?:GeForce\s+RTX\s+40[56]0\s+Laptop\s+GPU|RTX\s+2000\s+Ada)/i,
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([512, 1024, 2048]),
        aspectRatio3by2: true,
        allowedOs: Object.freeze(['win'])
    }),
    'ASUS ROG Zephyrus G14 (2024)': Object.freeze({
        model: 'ASUS ROG Zephyrus G14 (2024)',
        brand: 'ASUS',
        cpuVendor: 'amd',
        allowedCores: Object.freeze([8, 16]),
        igpuOnly: false,
        gpuPattern: /AMD\s+Radeon(?:\(TM\))?\s+(?:780M|Graphics)|NVIDIA\s+GeForce\s+RTX\s+40[567]0\s+Laptop\s+GPU/i,
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'ASUS ROG Strix SCAR 16': Object.freeze({
        model: 'ASUS ROG Strix SCAR 16',
        brand: 'ASUS',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([24, 32]),
        igpuOnly: false,
        gpuPattern: /Intel\(R\)\s+UHD\s+Graphics|NVIDIA\s+GeForce\s+RTX\s+40[89]0\s+Laptop\s+GPU/i,
        allowedRamGb: Object.freeze([16, 32, 64]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Razer Blade 16': Object.freeze({
        model: 'Razer Blade 16',
        brand: 'Razer',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([24, 32]),
        igpuOnly: false,
        gpuPattern: /Intel\(R\)\s+UHD\s+Graphics|NVIDIA\s+GeForce\s+RTX\s+40[6789]0\s+Laptop\s+GPU/i,
        allowedRamGb: Object.freeze([16, 32, 64, 96]),
        allowedStorageGb: Object.freeze([1024, 2048, 4096, 8192]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'HP Spectre x360 14': Object.freeze({
        model: 'HP Spectre x360 14',
        brand: 'HP',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([10, 12, 16, 22]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+(?:Iris\(R\)\s+Xe|Arc\(TM\))\s+Graphics/i,
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'LG Gram 16': Object.freeze({
        model: 'LG Gram 16',
        brand: 'LG',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([12, 14, 16, 20, 22]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+(?:Iris\(R\)\s+Xe|Arc\(TM\))\s+Graphics/i,
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([512, 1024, 2048]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'Samsung Galaxy Book4 Pro': Object.freeze({
        model: 'Samsung Galaxy Book4 Pro',
        brand: 'Samsung',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([16, 22]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+Arc\(TM\)\s+Graphics/i,
        allowedRamGb: Object.freeze([16, 32]),
        allowedStorageGb: Object.freeze([512, 1024]),
        allowedOs: Object.freeze(['win'])
    }),
    'Framework Laptop 13': Object.freeze({
        model: 'Framework Laptop 13',
        brand: 'Framework',
        cpuVendor: null,
        allowedCores: Object.freeze([8, 12, 14, 16, 20, 22]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+(?:Iris\(R\)\s+Xe|Arc\(TM\))\s+Graphics|AMD\s+Radeon(?:\(TM\))?\s+(?:760M|780M|Graphics)/i,
        allowedRamGb: Object.freeze([8, 16, 32, 64, 96]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048, 4096]),
        allowedOs: Object.freeze(['win', 'lin'])
    }),
    'System76 Lemur Pro': Object.freeze({
        model: 'System76 Lemur Pro',
        brand: 'System76',
        cpuVendor: 'intel',
        allowedCores: Object.freeze([10, 12, 14, 16, 20, 22]),
        igpuOnly: true,
        gpuPattern: /Intel\(R\)\s+(?:Iris\(R\)\s+Xe|Arc\(TM\)|UHD)\s+Graphics/i,
        allowedRamGb: Object.freeze([8, 16, 24, 32, 40, 48, 56]),
        allowedStorageGb: Object.freeze([256, 512, 1024, 2048, 4096, 8192]),
        allowedOs: Object.freeze(['lin', 'win'])
    })
});

/**
 * 5. Authoritative x86_64 Desktop & Mobile PC CPU SKU Catalog (Intel & AMD — 65+ SKUs).
 */
export const PC_CPU_SKU_CATALOG = Object.freeze({
    // --- Intel 8th–11th Gen Mobile & Desktop ---
    'Intel Core i3-10100': Object.freeze({
        model: 'Intel Core i3-10100',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 4,
        threads: 8,
        allowedThreads: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+630\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i5-8250U': Object.freeze({
        model: 'Intel Core i5-8250U',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 4,
        threads: 8,
        allowedThreads: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16, 32]),
        maxRamGb: 32,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+620\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i7-8550U': Object.freeze({
        model: 'Intel Core i7-8550U',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 4,
        threads: 8,
        allowedThreads: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16, 32]),
        maxRamGb: 32,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+620\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i7-8750H': Object.freeze({
        model: 'Intel Core i7-8750H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+630\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i7-9750H': Object.freeze({
        model: 'Intel Core i7-9750H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+630\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i9-9880H': Object.freeze({
        model: 'Intel Core i9-9880H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+630\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i9-9980HK': Object.freeze({
        model: 'Intel Core i9-9980HK',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+630\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i5-10400': Object.freeze({
        model: 'Intel Core i5-10400',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+630\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i5-10400F': Object.freeze({
        model: 'Intel Core i5-10400F',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: false
    }),
    'Intel Core i7-10700K': Object.freeze({
        model: 'Intel Core i7-10700K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+630\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i5-1135G7': Object.freeze({
        model: 'Intel Core i5-1135G7',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 4,
        threads: 8,
        allowedThreads: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i7-1165G7': Object.freeze({
        model: 'Intel Core i7-1165G7',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 4,
        threads: 8,
        allowedThreads: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i5-11400': Object.freeze({
        model: 'Intel Core i5-11400',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+730\b|(?!\s+\d{3}))/i
    }),
    // --- Intel 12th Gen Alder Lake Mobile & Desktop ---
    'Intel Core i5-1235U': Object.freeze({
        model: 'Intel Core i5-1235U',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 10,
        threads: 12,
        allowedThreads: Object.freeze([10, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i7-1255U': Object.freeze({
        model: 'Intel Core i7-1255U',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 10,
        threads: 12,
        allowedThreads: Object.freeze([10, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i5-1240P': Object.freeze({
        model: 'Intel Core i5-1240P',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 12,
        threads: 16,
        allowedThreads: Object.freeze([12, 16]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i7-1260P': Object.freeze({
        model: 'Intel Core i7-1260P',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 12,
        threads: 16,
        allowedThreads: Object.freeze([12, 16]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i7-12700H': Object.freeze({
        model: 'Intel Core i7-12700H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 14,
        threads: 20,
        allowedThreads: Object.freeze([14, 20]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i5-12400': Object.freeze({
        model: 'Intel Core i5-12400',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+730\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i5-12400F': Object.freeze({
        model: 'Intel Core i5-12400F',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: false
    }),
    'Intel Core i7-12700K': Object.freeze({
        model: 'Intel Core i7-12700K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 12,
        threads: 20,
        allowedThreads: Object.freeze([12, 20]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i9-12900K': Object.freeze({
        model: 'Intel Core i9-12900K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 16,
        threads: 24,
        allowedThreads: Object.freeze([16, 24]),
        allowedRamGb: Object.freeze([32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    // --- Intel 13th & 14th Gen Raptor Lake Mobile & Desktop ---
    'Intel Core i5-1335U': Object.freeze({
        model: 'Intel Core i5-1335U',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 10,
        threads: 12,
        allowedThreads: Object.freeze([10, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i7-1355U': Object.freeze({
        model: 'Intel Core i7-1355U',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 10,
        threads: 12,
        allowedThreads: Object.freeze([10, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i7-1370P': Object.freeze({
        model: 'Intel Core i7-1370P',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 14,
        threads: 20,
        allowedThreads: Object.freeze([14, 20]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i7-13700H': Object.freeze({
        model: 'Intel Core i7-13700H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 14,
        threads: 20,
        allowedThreads: Object.freeze([14, 20]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i9-13900H': Object.freeze({
        model: 'Intel Core i9-13900H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 14,
        threads: 20,
        allowedThreads: Object.freeze([14, 20]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Iris\(R\)\s+Xe\s+Graphics|UHD\s+Graphics(?!\s+\d{3})/i
    }),
    'Intel Core i9-13980HX': Object.freeze({
        model: 'Intel Core i9-13980HX',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 24,
        threads: 32,
        allowedThreads: Object.freeze([24, 32]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i9-14900HX': Object.freeze({
        model: 'Intel Core i9-14900HX',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 24,
        threads: 32,
        allowedThreads: Object.freeze([24, 32]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i5-13400': Object.freeze({
        model: 'Intel Core i5-13400',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 10,
        threads: 16,
        allowedThreads: Object.freeze([10, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+730\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i5-13400F': Object.freeze({
        model: 'Intel Core i5-13400F',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 10,
        threads: 16,
        allowedThreads: Object.freeze([10, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: false
    }),
    'Intel Core i5-13600K': Object.freeze({
        model: 'Intel Core i5-13600K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 14,
        threads: 20,
        allowedThreads: Object.freeze([14, 20]),
        allowedRamGb: Object.freeze([16, 32, 64, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i5-14600K': Object.freeze({
        model: 'Intel Core i5-14600K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 14,
        threads: 20,
        allowedThreads: Object.freeze([14, 20]),
        allowedRamGb: Object.freeze([16, 32, 64, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i7-13700K': Object.freeze({
        model: 'Intel Core i7-13700K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 16,
        threads: 24,
        allowedThreads: Object.freeze([16, 24]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i7-13700KF': Object.freeze({
        model: 'Intel Core i7-13700KF',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 16,
        threads: 24,
        allowedThreads: Object.freeze([16, 24]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: false
    }),
    'Intel Core i7-14700K': Object.freeze({
        model: 'Intel Core i7-14700K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 20,
        threads: 28,
        allowedThreads: Object.freeze([20, 28]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i9-13900K': Object.freeze({
        model: 'Intel Core i9-13900K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 24,
        threads: 32,
        allowedThreads: Object.freeze([24, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i9-13900KF': Object.freeze({
        model: 'Intel Core i9-13900KF',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 24,
        threads: 32,
        allowedThreads: Object.freeze([24, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: false
    }),
    'Intel Core i9-14900K': Object.freeze({
        model: 'Intel Core i9-14900K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 24,
        threads: 32,
        allowedThreads: Object.freeze([24, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /UHD\s+Graphics(?:\s+770\b|(?!\s+\d{3}))/i
    }),
    'Intel Core i9-14900KF': Object.freeze({
        model: 'Intel Core i9-14900KF',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 24,
        threads: 32,
        allowedThreads: Object.freeze([24, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: false
    }),
    // --- Intel Core Ultra Series 1 (Meteor Lake) & Series 2 (Lunar Lake MoP / Arrow Lake No-HT) ---
    'Intel Core Ultra 5 125U': Object.freeze({
        model: 'Intel Core Ultra 5 125U',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 12,
        threads: 14,
        allowedThreads: Object.freeze([12, 14]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+(?:Arc\(TM\)\s+)?Graphics/i
    }),
    'Intel Core Ultra 7 155U': Object.freeze({
        model: 'Intel Core Ultra 7 155U',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 12,
        threads: 14,
        allowedThreads: Object.freeze([12, 14]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+(?:Arc\(TM\)\s+)?Graphics/i
    }),
    'Intel Core Ultra 5 125H': Object.freeze({
        model: 'Intel Core Ultra 5 125H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 14,
        threads: 18,
        allowedThreads: Object.freeze([14, 18]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+(?:Arc\(TM\)\s+)?Graphics/i
    }),
    'Intel Core Ultra 7 155H': Object.freeze({
        model: 'Intel Core Ultra 7 155H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 16,
        threads: 22,
        allowedThreads: Object.freeze([16, 22]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+(?:Arc\(TM\)\s+)?Graphics/i
    }),
    'Intel Core Ultra 9 185H': Object.freeze({
        model: 'Intel Core Ultra 9 185H',
        vendor: 'intel',
        formFactor: 'mobile-h',
        physicalCores: 16,
        threads: 22,
        allowedThreads: Object.freeze([16, 22]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+(?:Arc\(TM\)\s+)?Graphics/i
    }),
    // Lunar Lake: Memory-on-Package (MoP) strictly locks 256V to 16GB and 258V/288V to 32GB, 8C/8T (no HT)
    'Intel Core Ultra 7 256V': Object.freeze({
        model: 'Intel Core Ultra 7 256V',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 8,
        threads: 8,
        allowedThreads: Object.freeze([8]),
        allowedRamGb: Object.freeze([16]),
        maxRamGb: 16,
        strictAllowedRam: true,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+Arc\(TM\)\s+(?:140V\s+)?Graphics/i
    }),
    'Intel Core Ultra 7 258V': Object.freeze({
        model: 'Intel Core Ultra 7 258V',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 8,
        threads: 8,
        allowedThreads: Object.freeze([8]),
        allowedRamGb: Object.freeze([32]),
        maxRamGb: 32,
        strictAllowedRam: true,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+Arc\(TM\)\s+(?:140V\s+)?Graphics/i
    }),
    'Intel Core Ultra 9 288V': Object.freeze({
        model: 'Intel Core Ultra 9 288V',
        vendor: 'intel',
        formFactor: 'mobile-ultrabook',
        physicalCores: 8,
        threads: 8,
        allowedThreads: Object.freeze([8]),
        allowedRamGb: Object.freeze([32]),
        maxRamGb: 32,
        strictAllowedRam: true,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+Arc\(TM\)\s+(?:140V\s+)?Graphics/i
    }),
    // Arrow Lake Desktop: Hyper-Threading removed (14C/14T, 20C/20T, 24C/24T)
    'Intel Core Ultra 5 245K': Object.freeze({
        model: 'Intel Core Ultra 5 245K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 14,
        threads: 14,
        allowedThreads: Object.freeze([14]),
        allowedRamGb: Object.freeze([16, 32, 48, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+Graphics/i
    }),
    'Intel Core Ultra 7 265K': Object.freeze({
        model: 'Intel Core Ultra 7 265K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 20,
        threads: 20,
        allowedThreads: Object.freeze([20]),
        allowedRamGb: Object.freeze([16, 32, 48, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+Graphics/i
    }),
    'Intel Core Ultra 9 285K': Object.freeze({
        model: 'Intel Core Ultra 9 285K',
        vendor: 'intel',
        formFactor: 'desktop',
        physicalCores: 24,
        threads: 24,
        allowedThreads: Object.freeze([24]),
        allowedRamGb: Object.freeze([32, 48, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Intel\(R\)\s+Graphics/i
    }),

    // --- AMD Ryzen 3000 & 5000 Desktop (Non-G models physically have NO integrated GPU!) ---
    'AMD Ryzen 5 3600': Object.freeze({
        model: 'AMD Ryzen 5 3600',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: false
    }),
    'AMD Ryzen 5 5600X': Object.freeze({
        model: 'AMD Ryzen 5 5600X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: false
    }),
    'AMD Ryzen 5 5600G': Object.freeze({
        model: 'AMD Ryzen 5 5600G',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:Vega|Graphics)/i
    }),
    'AMD Ryzen 7 5700G': Object.freeze({
        model: 'AMD Ryzen 7 5700G',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:Vega|Graphics)/i
    }),
    'AMD Ryzen 7 5800X': Object.freeze({
        model: 'AMD Ryzen 7 5800X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: false
    }),
    'AMD Ryzen 7 5800X3D': Object.freeze({
        model: 'AMD Ryzen 7 5800X3D',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: false
    }),
    'AMD Ryzen 9 5900X': Object.freeze({
        model: 'AMD Ryzen 9 5900X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 12,
        threads: 24,
        allowedThreads: Object.freeze([12, 24]),
        allowedRamGb: Object.freeze([32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: false
    }),
    'AMD Ryzen 9 5950X': Object.freeze({
        model: 'AMD Ryzen 9 5950X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 16,
        threads: 32,
        allowedThreads: Object.freeze([16, 32]),
        allowedRamGb: Object.freeze([32, 64, 128]),
        maxRamGb: 128,
        hasIntegratedGpu: false
    }),

    // --- AMD Ryzen 5000 / 6000 / 7000 / 8000 / AI 300 Mobile APUs ---
    'AMD Ryzen 5 5500U': Object.freeze({
        model: 'AMD Ryzen 5 5500U',
        vendor: 'amd',
        formFactor: 'mobile-ultrabook',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32]),
        maxRamGb: 32,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:Vega|Graphics)/i
    }),
    'AMD Ryzen 7 5800U': Object.freeze({
        model: 'AMD Ryzen 7 5800U',
        vendor: 'amd',
        formFactor: 'mobile-ultrabook',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([8, 16, 32]),
        maxRamGb: 32,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:Vega|Graphics)/i
    }),
    'AMD Ryzen 5 6600U': Object.freeze({
        model: 'AMD Ryzen 5 6600U',
        vendor: 'amd',
        formFactor: 'mobile-ultrabook',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32]),
        maxRamGb: 32,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:660M|Graphics)/i
    }),
    'AMD Ryzen 7 6800U': Object.freeze({
        model: 'AMD Ryzen 7 6800U',
        vendor: 'amd',
        formFactor: 'mobile-ultrabook',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32]),
        maxRamGb: 32,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:680M|Graphics)/i
    }),
    'AMD Ryzen 7 7735HS': Object.freeze({
        model: 'AMD Ryzen 7 7735HS',
        vendor: 'amd',
        formFactor: 'mobile-h',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:680M|Graphics)/i
    }),
    'AMD Ryzen 5 7540U': Object.freeze({
        model: 'AMD Ryzen 5 7540U',
        vendor: 'amd',
        formFactor: 'mobile-ultrabook',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:740M|Graphics)/i
    }),
    'AMD Ryzen 7 7840U': Object.freeze({
        model: 'AMD Ryzen 7 7840U',
        vendor: 'amd',
        formFactor: 'mobile-ultrabook',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:780M|Graphics)/i
    }),
    'AMD Ryzen 7 7840HS': Object.freeze({
        model: 'AMD Ryzen 7 7840HS',
        vendor: 'amd',
        formFactor: 'mobile-h',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:780M|Graphics)/i
    }),
    'AMD Ryzen 9 7940HS': Object.freeze({
        model: 'AMD Ryzen 9 7940HS',
        vendor: 'amd',
        formFactor: 'mobile-h',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:780M|Graphics)/i
    }),
    'AMD Ryzen 7 8845HS': Object.freeze({
        model: 'AMD Ryzen 7 8845HS',
        vendor: 'amd',
        formFactor: 'mobile-h',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:780M|Graphics)/i
    }),
    'AMD Ryzen 9 8945HS': Object.freeze({
        model: 'AMD Ryzen 9 8945HS',
        vendor: 'amd',
        formFactor: 'mobile-h',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:780M|Graphics)/i
    }),
    'AMD Ryzen AI 9 365': Object.freeze({
        model: 'AMD Ryzen AI 9 365',
        vendor: 'amd',
        formFactor: 'mobile-h',
        physicalCores: 10,
        threads: 20,
        allowedThreads: Object.freeze([10, 20]),
        allowedRamGb: Object.freeze([16, 24, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:880M|Graphics)/i
    }),
    'AMD Ryzen AI 9 HX 370': Object.freeze({
        model: 'AMD Ryzen AI 9 HX 370',
        vendor: 'amd',
        formFactor: 'mobile-h',
        physicalCores: 12,
        threads: 24,
        allowedThreads: Object.freeze([12, 24]),
        allowedRamGb: Object.freeze([16, 24, 32, 64]),
        maxRamGb: 64,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /Radeon(?:\(TM\))?\s+(?:890M|Graphics)/i
    }),

    // --- AMD Ryzen 7000 & 9000 Desktop (RDNA2 integrated graphics on IOD) ---
    'AMD Ryzen 5 7600X': Object.freeze({
        model: 'AMD Ryzen 5 7600X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /AMD\s+Radeon\(TM\)\s+Graphics/i
    }),
    'AMD Ryzen 7 7700X': Object.freeze({
        model: 'AMD Ryzen 7 7700X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /AMD\s+Radeon\(TM\)\s+Graphics/i
    }),
    'AMD Ryzen 7 7800X3D': Object.freeze({
        model: 'AMD Ryzen 7 7800X3D',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /AMD\s+Radeon\(TM\)\s+Graphics/i
    }),
    'AMD Ryzen 9 7900X': Object.freeze({
        model: 'AMD Ryzen 9 7900X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 12,
        threads: 24,
        allowedThreads: Object.freeze([12, 24]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /AMD\s+Radeon\(TM\)\s+Graphics/i
    }),
    'AMD Ryzen 9 7950X': Object.freeze({
        model: 'AMD Ryzen 9 7950X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 16,
        threads: 32,
        allowedThreads: Object.freeze([16, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /AMD\s+Radeon\(TM\)\s+Graphics/i
    }),
    'AMD Ryzen 7 9800X3D': Object.freeze({
        model: 'AMD Ryzen 7 9800X3D',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /AMD\s+Radeon\(TM\)\s+Graphics/i
    }),
    'AMD Ryzen 9 9950X': Object.freeze({
        model: 'AMD Ryzen 9 9950X',
        vendor: 'amd',
        formFactor: 'desktop',
        physicalCores: 16,
        threads: 32,
        allowedThreads: Object.freeze([16, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192,
        hasIntegratedGpu: true,
        expectedIgpuPattern: /AMD\s+Radeon\(TM\)\s+Graphics/i
    })
});

/**
 * 6. Authoritative PCI Device ID to GPU Identity Registry (`PCI_DEVICE_ID_CATALOG`).
 * Used to catch spoofing where a renderer string claims one GPU model (e.g. RTX 4090)
 * while retaining the PCI Device ID of another GPU (e.g. 0x5917 Intel UHD 620).
 */
export const PCI_DEVICE_ID_CATALOG = Object.freeze({
    '0x5917': Object.freeze({ vendor: 'intel', name: 'Intel(R) UHD Graphics 620', pattern: /UHD\s+Graphics\s+620/i }),
    '0x3e92': Object.freeze({ vendor: 'intel', name: 'Intel(R) UHD Graphics 630', pattern: /UHD\s+Graphics\s+630/i }),
    '0x3e9b': Object.freeze({ vendor: 'intel', name: 'Intel(R) UHD Graphics 630', pattern: /UHD\s+Graphics\s+630/i }),
    '0x8a52': Object.freeze({ vendor: 'intel', name: 'Intel(R) Iris(TM) Plus Graphics', pattern: /Iris.*Plus/i }),
    '0x9a49': Object.freeze({ vendor: 'intel', name: 'Intel(R) Iris(R) Xe Graphics', pattern: /Iris\(R\)\s+Xe/i }),
    '0x46a6': Object.freeze({ vendor: 'intel', name: 'Intel(R) Iris(R) Xe Graphics', pattern: /Iris\(R\)\s+Xe/i }),
    '0xa7a1': Object.freeze({ vendor: 'intel', name: 'Intel(R) Iris(R) Xe Graphics', pattern: /Iris\(R\)\s+Xe/i }),
    '0x4680': Object.freeze({ vendor: 'intel', name: 'Intel(R) UHD Graphics 770', pattern: /UHD\s+Graphics(?:\s+770)?/i }),
    '0xa780': Object.freeze({ vendor: 'intel', name: 'Intel(R) UHD Graphics 770', pattern: /UHD\s+Graphics(?:\s+770)?/i }),
    '0x56a0': Object.freeze({ vendor: 'intel', name: 'Intel(R) Arc(TM) A770 Graphics', pattern: /Arc\(TM\)\s+A770/i }),
    '0x2684': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 4090', pattern: /RTX\s*4090(?!\s+Laptop)/i }),
    '0x2717': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 4090 Laptop GPU', pattern: /RTX\s*4090\s+Laptop/i }),
    '0x2704': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 4080', pattern: /RTX\s*4080(?!\s+Laptop)/i }),
    '0x2786': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 4070', pattern: /RTX\s*4070(?!\s+Laptop)/i }),
    '0x2882': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 4060', pattern: /RTX\s*4060(?!\s+Laptop)/i }),
    '0x2204': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 3090', pattern: /RTX\s*3090(?!\s+Laptop)/i }),
    '0x2206': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 3080', pattern: /RTX\s*3080(?!\s+Laptop)/i }),
    '0x2484': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 3070', pattern: /RTX\s*3070(?!\s+Laptop)/i }),
    '0x2503': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 3060', pattern: /RTX\s*3060(?!\s+Laptop)/i }),
    '0x2504': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 3060', pattern: /RTX\s*3060(?!\s+Laptop)/i }),
    '0x2520': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce RTX 3060 Laptop GPU', pattern: /RTX\s*3060\s+Laptop/i }),
    '0x1f82': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce GTX 1650', pattern: /GTX\s*1650/i }),
    '0x2184': Object.freeze({ vendor: 'nvidia', name: 'NVIDIA GeForce GTX 1660', pattern: /GTX\s*1660/i }),
    '0x744c': Object.freeze({ vendor: 'amd', name: 'AMD Radeon RX 7900 XTX', pattern: /RX\s*7900\s*XTX/i }),
    '0x747e': Object.freeze({ vendor: 'amd', name: 'AMD Radeon RX 7800 XT', pattern: /RX\s*7800\s*XT/i }),
    '0x73ff': Object.freeze({ vendor: 'amd', name: 'AMD Radeon RX 6600', pattern: /RX\s*6600/i }),
    '0x73df': Object.freeze({ vendor: 'amd', name: 'AMD Radeon RX 6700 XT', pattern: /RX\s*6700\s*XT/i })
});

export const PCI_VENDOR_ID_BY_GPU_VENDOR = Object.freeze({
    nvidia: '0x10de',
    amd: '0x1002',
    intel: '0x8086',
    qualcomm: '0x5143',
    apple: '0x106b'
});

/**
 * 7. Authoritative GPU SKU Catalog (NVIDIA GeForce Desktop/Laptop, AMD Radeon RX/Pro/APU, Intel UHD/Iris/Arc, Qualcomm Adreno).
 */
export const PC_GPU_SKU_CATALOG = Object.freeze([
    // --- NVIDIA Laptop GPUs (must precede generic RTX patterns) ---
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4090 Laptop GPU',
        pattern: /RTX\s*4090\s+Laptop\s+GPU/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'laptop',
        vramGb: Object.freeze([16]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4080 Laptop GPU',
        pattern: /RTX\s*4080\s+Laptop\s+GPU/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'laptop',
        vramGb: Object.freeze([12]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4070 Laptop GPU',
        pattern: /RTX\s*4070\s+Laptop\s+GPU/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'laptop',
        vramGb: Object.freeze([8]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4060 Laptop GPU',
        pattern: /RTX\s*4060\s+Laptop\s+GPU/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'laptop',
        vramGb: Object.freeze([8]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4050 Laptop GPU',
        pattern: /RTX\s*4050\s+Laptop\s+GPU/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'laptop',
        vramGb: Object.freeze([6]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 3060 Laptop GPU',
        pattern: /RTX\s*3060\s+Laptop\s+GPU/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'laptop',
        vramGb: Object.freeze([6]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),

    // --- NVIDIA Desktop GPUs ---
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4090',
        pattern: /RTX\s*4090/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([24]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4080',
        pattern: /RTX\s*4080/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([12, 16]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4070',
        pattern: /RTX\s*4070/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([12, 16]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4060',
        pattern: /RTX\s*4060/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([8, 16]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 3090',
        pattern: /RTX\s*3090/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([24]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 3080',
        pattern: /RTX\s*3080/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([10, 12]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 3070',
        pattern: /RTX\s*3070/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([8]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 3060',
        pattern: /RTX\s*3060/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([8, 12]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 3050',
        pattern: /RTX\s*3050/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'both',
        vramGb: Object.freeze([4, 6, 8]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce RTX 2060',
        pattern: /RTX\s*2060/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'both',
        vramGb: Object.freeze([6, 12]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce GTX 1660',
        pattern: /GTX\s*1660/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'both',
        vramGb: Object.freeze([6]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'NVIDIA GeForce GTX 1650',
        pattern: /GTX\s*1650/i,
        vendor: 'nvidia',
        pciVendorId: '0x10de',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        formFactor: 'both',
        vramGb: Object.freeze([4]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),

    // --- AMD Radeon Discrete & Workstation GPUs ---
    Object.freeze({
        id: 'AMD Radeon RX 7900 XTX',
        pattern: /Radeon\s+RX\s+7900\s+XTX/i,
        vendor: 'amd',
        pciVendorId: '0x1002',
        angleVendor: 'AMD',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([24]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    }),
    Object.freeze({
        id: 'AMD Radeon RX 7800 XT',
        pattern: /Radeon\s+RX\s+7800\s+XT/i,
        vendor: 'amd',
        pciVendorId: '0x1002',
        angleVendor: 'AMD',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([16]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    }),
    Object.freeze({
        id: 'AMD Radeon RX 6000/7000 Discrete',
        pattern: /Radeon\s+RX\s+(6[6-9]\d0|7[6-9]\d0)/i,
        vendor: 'amd',
        pciVendorId: '0x1002',
        angleVendor: 'AMD',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([8, 12, 16, 20, 24]),
        osSupport: Object.freeze(['win', 'lin', 'mac']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    }),
    Object.freeze({
        id: 'AMD Radeon Pro Mobile (Intel MacBook Pro 15/16)',
        pattern: /AMD\s+Radeon\s+Pro\s+(?:555X|560X|5300M|5500M|5600M|Vega\s+(?:16|20))/i,
        vendor: 'amd',
        pciVendorId: '0x1002',
        angleVendor: 'AMD',
        isIntegrated: false,
        formFactor: 'laptop',
        vramGb: Object.freeze([4, 8]),
        osSupport: Object.freeze(['mac', 'win', 'lin']),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    Object.freeze({
        id: 'AMD Radeon Pro Desktop (Intel iMac / Mac Pro)',
        pattern: /AMD\s+Radeon\s+Pro\s+(?:570X|575X|580X|5500\s+XT|5700(?:\s+XT)?|Vega\s+(?:48|56|64|64X|II)|W5500X|W5700X|W6800X|W6900X)/i,
        vendor: 'amd',
        pciVendorId: '0x1002',
        angleVendor: 'AMD',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([4, 8, 16, 32, 64]),
        osSupport: Object.freeze(['mac', 'win', 'lin']),
        webglLimits: DEFAULT_APPLE_METAL_WEBGL_LIMITS
    }),
    Object.freeze({
        id: 'AMD Radeon Integrated APU',
        pattern: /Radeon\(TM\)\s+Graphics|Radeon(?:\(TM\))?\s+(?:610M|660M|680M|740M|760M|780M|880M|890M|Vega)|Radeon\s+HD\s+3200/i,
        vendor: 'amd',
        pciVendorId: '0x1002',
        angleVendor: 'AMD',
        isIntegrated: true,
        cpuVendorLock: 'amd',
        formFactor: 'both',
        vramGb: Object.freeze([1, 2, 4, 8]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    }),

    // --- Intel Discrete Arc & Integrated GPUs ---
    Object.freeze({
        id: 'Intel Arc Discrete Graphics (A380/A750/A770)',
        pattern: /Intel\(R\)\s+Arc\(TM\)\s+A[357]\d0/i,
        vendor: 'intel',
        pciVendorId: '0x8086',
        angleVendor: 'Intel',
        isIntegrated: false,
        formFactor: 'desktop',
        vramGb: Object.freeze([6, 8, 16]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    }),
    Object.freeze({
        id: 'Intel Integrated UHD / Iris Xe / Arc Graphics',
        pattern: /Intel\(R\)\s+(?:UHD|Iris|HD|Arc\(TM\)|Graphics)/i,
        vendor: 'intel',
        pciVendorId: '0x8086',
        angleVendor: 'Intel',
        isIntegrated: true,
        cpuVendorLock: 'intel',
        formFactor: 'both',
        vramGb: Object.freeze([1, 2, 4, 8]),
        osSupport: Object.freeze(['win', 'lin', 'mac']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    }),

    // --- Qualcomm Adreno Integrated SoC GPU ---
    Object.freeze({
        id: 'Qualcomm Adreno X1 Integrated GPU',
        pattern: /Adreno(?:\(TM\))?\s+X1-(?:85|45)|Qualcomm\(R\)\s+Adreno/i,
        vendor: 'qualcomm',
        pciVendorId: '0x5143',
        angleVendor: 'Qualcomm',
        isIntegrated: true,
        cpuVendorLock: 'qualcomm',
        formFactor: 'laptop',
        vramGb: Object.freeze([2, 4, 8]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    })
]);

export const STANDARD_PC_RAM_GB_TIERS = Object.freeze([
    4, 8, 12, 16, 24, 32, 40, 48, 56, 64, 96, 128, 192, 256, 384, 512, 768, 1536
]);
export const STANDARD_PC_STORAGE_GB_TIERS = Object.freeze([
    128, 256, 512, 1000, 1024, 2000, 2048, 4000, 4096, 8000, 8192, 16384
]);

/**
 * Parse canonical Apple Silicon SKU key (e.g. `'Apple M1'`, `'Apple M2 Pro'`, `'Apple M3 Max'`)
 * from a GPU renderer or CPU model string.
 *
 * @param {string | null | undefined} text
 * @returns {string | null}
 */
export function parseAppleSiliconSkuName(text) {
    if (!text || typeof text !== 'string') return null;
    const match = text.match(/\bApple\s+(M[1-5](?:\s+(?:Pro|Max|Ultra))?)\b/i);
    if (!match) return null;
    const rawSuffix = match[1].trim().replace(/\s+/g, ' ');
    const parts = rawSuffix.split(' ');
    const gen = parts[0].toUpperCase();
    const tier = parts[1]
        ? parts[1].charAt(0).toUpperCase() + parts[1].slice(1).toLowerCase()
        : null;
    const canonical = tier ? `Apple ${gen} ${tier}` : `Apple ${gen}`;
    return Object.prototype.hasOwnProperty.call(APPLE_SILICON_SKU_CATALOG, canonical)
        ? canonical
        : null;
}

/**
 * Look up an Intel-based Apple Mac SKU by deviceModel or WebGL renderer when on macOS.
 *
 * @param {string | null | undefined} deviceModel
 * @param {string | null | undefined} renderer
 * @returns {object | null}
 */
export function lookupIntelMacSku(deviceModel, renderer) {
    if (deviceModel && typeof deviceModel === 'string') {
        const trimmed = deviceModel.trim();
        if (Object.prototype.hasOwnProperty.call(INTEL_MAC_SKU_CATALOG, trimmed)) {
            return INTEL_MAC_SKU_CATALOG[trimmed];
        }
        const lower = trimmed.toLowerCase();
        for (const [key, spec] of Object.entries(INTEL_MAC_SKU_CATALOG)) {
            if (lower.includes(key.toLowerCase())) {
                return spec;
            }
        }
    }
    if (renderer && typeof renderer === 'string') {
        for (const spec of Object.values(INTEL_MAC_SKU_CATALOG)) {
            if (spec.gpuPattern.test(renderer)) {
                return spec;
            }
        }
    }
    return null;
}

/**
 * Look up a Qualcomm Snapdragon X SoC SKU by CPU model string.
 *
 * @param {string | null | undefined} cpuModel
 * @returns {object | null}
 */
export function lookupSnapdragonSku(cpuModel) {
    if (!cpuModel || typeof cpuModel !== 'string') return null;
    const trimmed = cpuModel.trim();
    if (Object.prototype.hasOwnProperty.call(QUALCOMM_SNAPDRAGON_SKU_CATALOG, trimmed)) {
        return QUALCOMM_SNAPDRAGON_SKU_CATALOG[trimmed];
    }
    const lower = trimmed.toLowerCase();
    for (const [key, spec] of Object.entries(QUALCOMM_SNAPDRAGON_SKU_CATALOG)) {
        if (lower.includes(key.toLowerCase())) {
            return spec;
        }
    }
    return null;
}

/**
 * Look up an OEM Laptop / Desktop / Tablet device model SKU (`Lenovo ThinkPad`, `Dell XPS`,
 * `Microsoft Surface`, `ASUS ROG`, `Razer Blade`, `HP Spectre`, `Framework`, `System76`, etc.).
 *
 * @param {string | null | undefined} deviceModel
 * @returns {object | null}
 */
export function lookupOemDeviceSku(deviceModel) {
    if (!deviceModel || typeof deviceModel !== 'string') return null;
    const trimmed = deviceModel.trim();
    if (Object.prototype.hasOwnProperty.call(OEM_DEVICE_MODEL_CATALOG, trimmed)) {
        return OEM_DEVICE_MODEL_CATALOG[trimmed];
    }
    const lower = trimmed.toLowerCase();
    for (const [key, spec] of Object.entries(OEM_DEVICE_MODEL_CATALOG)) {
        if (lower.includes(key.toLowerCase())) {
            return spec;
        }
    }
    return null;
}

/**
 * Look up a PC CPU SKU by model name (case-insensitive exact or longest-key substring match).
 *
 * @param {string | null | undefined} cpuModel
 * @returns {object | null}
 */
export function lookupPcCpuSku(cpuModel) {
    if (!cpuModel || typeof cpuModel !== 'string') return null;
    const trimmed = cpuModel.trim();
    if (Object.prototype.hasOwnProperty.call(PC_CPU_SKU_CATALOG, trimmed)) {
        return PC_CPU_SKU_CATALOG[trimmed];
    }
    const lower = trimmed.toLowerCase();
    // Sort keys by descending length so "Intel Core i5-12400F" matches before "Intel Core i5-12400"
    const sortedEntries = Object.entries(PC_CPU_SKU_CATALOG).sort((a, b) => b[0].length - a[0].length);
    for (const [key, spec] of sortedEntries) {
        if (lower.includes(key.toLowerCase())) {
            return spec;
        }
    }
    return null;
}

/**
 * Look up a PC GPU SKU by WebGL `unmaskedRenderer`.
 *
 * @param {string | null | undefined} renderer
 * @returns {object | null}
 */
export function lookupPcGpuSku(renderer) {
    if (!renderer || typeof renderer !== 'string') return null;
    for (const spec of PC_GPU_SKU_CATALOG) {
        if (spec.pattern.test(renderer)) {
            return spec;
        }
    }
    return null;
}

/**
 * Validate exact hardware SKU & device model parameters across:
 *   - Apple Silicon SoCs (M1..M4 base/Pro/Max/Ultra)
 *   - Intel-based Apple Macs (MacBook Air, MacBook Pro 13/15/16, iMac 5K/Pro, Mac Pro Xeon W)
 *   - Qualcomm Snapdragon X Elite / Plus ARM64 SoCs
 *   - Windows & Linux OEM Device Models (ThinkPad, Dell XPS, Surface, ROG, Razer, Spectre, Framework, System76)
 *   - 65+ Desktop & Mobile Intel/AMD CPUs (thread count, Lunar Lake MoP RAM, iGPU presence & generation lockstep, CPU vs GPU form-factor)
 *   - 35+ GPUs (VRAM capacity, PCI Vendor/Device ID spoofing, Windows ANGLE vendor/shader model, WebGL hardware limits)
 *
 * @param {object} telemetry Browser telemetry object
 * @param {string | null} [targetOs] Normalized target OS (`'win'` | `'mac'` | `'lin'`)
 * @returns {{
 *   passed: boolean,
 *   matchedSku: string | null,
 *   issues: string[]
 * }}
 */
export function validateHardwareModelSpec(telemetry, targetOs = null) {
    if (typeof targetOs === 'string') {
        const lowerOs = targetOs.trim().toLowerCase();
        if (lowerOs.startsWith('win')) targetOs = 'win';
        else if (lowerOs.startsWith('mac') || lowerOs === 'darwin' || lowerOs === 'osx') targetOs = 'mac';
        else if (lowerOs.startsWith('lin') || lowerOs === 'ubuntu') targetOs = 'lin';
    }
    const issues = [];
    if (!telemetry || typeof telemetry !== 'object') {
        return {
            passed: false,
            matchedSku: null,
            issues: ['Missing telemetry object for exact hardware SKU audit']
        };
    }

    const nav = telemetry.navigator || {};
    const webgl = telemetry.webgl || {};
    const scr = telemetry.screen || {};
    const hw = telemetry.hardwareProfile || {};
    const storageEstimate = telemetry.storageEstimate || hw.storageEstimate || null;

    const toOptionalNumber = (v) =>
        v !== undefined && v !== null && v !== '' && typeof v !== 'boolean' ? Number(v) : null;

    const renderer = String(webgl.unmaskedRenderer || '').trim();
    const vendor = String(webgl.unmaskedVendor || '').trim();
    const cores = toOptionalNumber(nav.hardwareConcurrency);
    const panelKey =
        Number.isFinite(scr.width) && Number.isFinite(scr.height)
            ? `${scr.width}x${scr.height}`
            : null;

    const deviceModel = hw.deviceModel ? String(hw.deviceModel).trim() : null;
    const cpuModel = hw.cpuModel ? String(hw.cpuModel).trim() : null;
    const gpuModel = hw.gpuModel ? String(hw.gpuModel).trim() : null;
    const ramGb = toOptionalNumber(hw.ramGb);
    const storageGb = toOptionalNumber(hw.storageGb);
    const vramGb = toOptionalNumber(hw.vramGb);
    const pciVendorId = hw.pciVendorId ? String(hw.pciVendorId).trim().toLowerCase() : null;
    const pciDeviceId = hw.pciDeviceId ? String(hw.pciDeviceId).trim().toLowerCase() : null;

    const gpuAppleSkuName = parseAppleSiliconSkuName(renderer);
    const cpuAppleSkuName = parseAppleSiliconSkuName(cpuModel);
    const explicitGpuAppleSkuName = parseAppleSiliconSkuName(gpuModel);

    let matchedSku = gpuAppleSkuName || cpuAppleSkuName || explicitGpuAppleSkuName || null;

    // =========================================================================
    // Rule A: SoC CPU-to-GPU Lockstep (Apple Silicon Unified Die & Explicit GPU Model)
    // =========================================================================
    if (cpuAppleSkuName && gpuAppleSkuName && cpuAppleSkuName !== gpuAppleSkuName) {
        issues.push(
            `Apple Silicon SoC CPU/GPU model mismatch: CPU is "${cpuAppleSkuName}" but WebGL GPU renderer is "${gpuAppleSkuName}" (Unified SoC die cannot mix different Apple M chips)`
        );
    } else if (cpuAppleSkuName && renderer && !gpuAppleSkuName) {
        issues.push(
            `Apple Silicon CPU "${cpuAppleSkuName}" paired with non-Apple-Silicon WebGL GPU renderer "${renderer}"`
        );
    } else if (gpuAppleSkuName && cpuModel && !cpuAppleSkuName) {
        issues.push(
            `Apple Silicon WebGL GPU "${gpuAppleSkuName}" paired with non-Apple-Silicon CPU model "${cpuModel}"`
        );
    }

    if (explicitGpuAppleSkuName && gpuAppleSkuName && explicitGpuAppleSkuName !== gpuAppleSkuName) {
        issues.push(
            `Hardware profile gpuModel "${gpuModel}" contradicts WebGL unmaskedRenderer "${renderer}"`
        );
    } else if (explicitGpuAppleSkuName && renderer && !gpuAppleSkuName) {
        issues.push(
            `Apple Silicon hardwareProfile.gpuModel "${gpuModel}" contradicts non-Apple-Silicon WebGL renderer "${renderer}"`
        );
    } else if (!explicitGpuAppleSkuName && gpuModel && gpuAppleSkuName) {
        issues.push(
            `Non-Apple-Silicon hardwareProfile.gpuModel "${gpuModel}" contradicts Apple Silicon WebGL renderer "${renderer}"`
        );
    }
    if (cpuAppleSkuName && explicitGpuAppleSkuName && cpuAppleSkuName !== explicitGpuAppleSkuName) {
        issues.push(
            `Apple Silicon CPU "${cpuAppleSkuName}" contradicts hardwareProfile.gpuModel "${explicitGpuAppleSkuName}"`
        );
    }

    // =========================================================================
    // Rule B, C, D, E: Exact Apple Silicon SKU Parameter Validation
    // =========================================================================
    const activeAppleSkuName = gpuAppleSkuName || cpuAppleSkuName || explicitGpuAppleSkuName;
    if (activeAppleSkuName) {
        const sku = APPLE_SILICON_SKU_CATALOG[activeAppleSkuName];

        // Rule B: Exact SKU CPU Core Count
        if (!Number.isInteger(cores) || !sku.allowedCores.includes(cores)) {
            issues.push(
                `${sku.chip} exact core count violation: navigator.hardwareConcurrency=${cores} is invalid for ${sku.chip} (physical options: [${sku.allowedCores.join(', ')}] cores)`
            );
        }

        // Rule C: Exact SKU Unified Memory (RAM) Capacity & Core-to-RAM Die Pairing
        if (ramGb !== null) {
            if (!Number.isFinite(ramGb) || !sku.allowedRamGb.includes(ramGb)) {
                issues.push(
                    `${sku.chip} exact Unified Memory (RAM) violation: ramGb=${ramGb}GB does not exist on ${sku.chip} (factory RAM tiers: [${sku.allowedRamGb.join('GB, ')}GB])`
                );
            } else if (Number.isInteger(cores) && sku.allowedCores.includes(cores)) {
                const pairRule = sku.allowedCoreRamPairs.find((p) => p.cores === cores);
                if (pairRule && !pairRule.ramGb.includes(ramGb)) {
                    issues.push(
                        `${sku.chip} (${cores}-core die) cannot be configured with ${ramGb}GB Unified Memory (allowed RAM for ${cores}-core ${sku.chip}: [${pairRule.ramGb.join('GB, ')}GB])`
                    );
                }
            }
        }

        // Rule D (Apple Silicon): Exact Factory SSD Storage Tier
        if (storageGb !== null) {
            if (!Number.isFinite(storageGb) || !sku.allowedStorageGb.includes(storageGb)) {
                issues.push(
                    `${sku.chip} exact SSD storage capacity violation: storageGb=${storageGb}GB is not a valid factory SSD tier for ${sku.chip} (allowed: [${sku.allowedStorageGb.join('GB, ')}GB])`
                );
            }
        }

        // Rule E: Exact SKU Form-Factor & Display Panel Resolution Coherence
        if (panelKey && sku.forbiddenPanels.includes(panelKey)) {
            if (sku.tier === 'ultra') {
                issues.push(
                    `${sku.chip} is a desktop-only SoC (Mac Studio / Mac Pro) and cannot be paired with built-in MacBook laptop display panel ${panelKey}`
                );
            } else if (sku.chip === 'Apple M1') {
                issues.push(
                    `Apple M1 (2020 13.3" MacBook Air/Pro) did not ship with a notched Liquid Retina display panel (${panelKey})`
                );
            } else if (sku.tier === 'pro' || sku.tier === 'max') {
                issues.push(
                    `${sku.chip} (14"/16" MacBook Pro / Mac Studio) cannot be paired with MacBook Air or legacy non-notch 13.3" panel ${panelKey}`
                );
            } else {
                issues.push(
                    `${sku.chip} cannot be paired with incompatible display panel resolution ${panelKey}`
                );
            }
        }

        // Rule N: Apple Silicon Generation vs Minimum Bootable macOS Version (platformVersion / osVersion)
        const rawOsVer = hw.osVersion ?? hw.platformVersion ?? telemetry.userAgentMetadata?.platformVersion ?? null;
        if (rawOsVer !== null && rawOsVer !== undefined && String(rawOsVer).trim() !== '') {
            const rawOsVerStr = String(rawOsVer).trim();
            const verMatch = rawOsVerStr.match(/^(\d+)(?:\.(\d+))?/);
            if (verMatch) {
                const maj = Number(verMatch[1]);
                const min = Number(verMatch[2] || 0);
                const minRequired = APPLE_SILICON_MIN_MACOS_VERSION[sku.generation] || 11.0;
                const minReqMaj = Math.floor(minRequired);
                const minReqMin = Math.round((minRequired - minReqMaj) * 10);
                // Static Firefox UA reports 10.15, but explicit platformVersion / osVersion must meet min boot OS
                if (rawOsVerStr !== '10.15' && (maj < minReqMaj || (maj === minReqMaj && min < minReqMin))) {
                    issues.push(
                        `${sku.chip} minimum bootable macOS violation: osVersion="${rawOsVerStr}" is older than ${sku.chip}'s factory minimum macOS ${minRequired.toFixed(1)}`
                    );
                }
            }
        }
    }

    // =========================================================================
    // Rule M: Apple Mac Product Line (DeviceName / ProductType / deviceModel:
    //         MacBook Air, MacBook Pro, Mac mini, iMac, Mac Studio, Mac Pro)
    //         vs SoC Tier & CPU Architecture Lockstep (Discovered via AdsPower Audit)
    // =========================================================================
    const macProductLabel = Array.from(
        new Set(
            [hw.deviceName, hw.productType, deviceModel]
                .filter((s) => s && typeof s === 'string')
                .map((s) => s.trim())
                .filter(Boolean)
        )
    ).join(' ');
    const cpuArchClaim = String(hw.architecture || telemetry.userAgentMetadata?.architecture || '').trim().toLowerCase();
    if (activeAppleSkuName && cpuArchClaim === 'x86') {
        issues.push(
            `Apple Silicon SoC "${activeAppleSkuName}" architecture violation: architecture="x86" is impossible on ARM64 Apple Silicon`
        );
    }
    if (macProductLabel) {
        const isMacStudio = /\bMac[\s_-]+Studio\b/i.test(macProductLabel);
        const isMacBookAir = /\bMacBook[\s_-]+Air\b/i.test(macProductLabel);
        const isMacBookPro = /\bMacBook[\s_-]+Pro\b/i.test(macProductLabel);
        const isMacMini = /\bMac[\s_-]+mini\b/i.test(macProductLabel);
        const isIMacPro = /\biMac[\s_-]+Pro\b/i.test(macProductLabel);
        const isIMac = !isIMacPro && /\biMac\b/i.test(macProductLabel);
        const isMacPro = /\bMac[\s_-]+Pro\b/i.test(macProductLabel);

        if (isMacStudio) {
            if (cpuArchClaim === 'x86' || (!activeAppleSkuName && /Intel|AMD|Radeon/i.test(renderer))) {
                issues.push(
                    `Mac product line violation: "${macProductLabel}" (Mac Studio, introduced 2022) is Apple Silicon Max/Ultra exclusive and never existed with x86 Intel/AMD hardware ("${renderer || cpuArchClaim}")`
                );
            } else if (activeAppleSkuName) {
                const sku = APPLE_SILICON_SKU_CATALOG[activeAppleSkuName];
                if (sku.tier !== 'max' && sku.tier !== 'ultra') {
                    issues.push(
                        `Mac product line violation: "${macProductLabel}" (Mac Studio) only ships with Max or Ultra SoCs (M1/M2/M3/M4 Max or Ultra), never with ${sku.tier}-tier "${sku.chip}"`
                    );
                }
            }
        } else if (isMacBookAir && activeAppleSkuName) {
            const sku = APPLE_SILICON_SKU_CATALOG[activeAppleSkuName];
            if (sku.tier !== 'base') {
                issues.push(
                    `Mac product line violation: "${macProductLabel}" (MacBook Air) only ships with base Apple M-series SoCs (M1/M2/M3/M4/M5), never with ${sku.tier}-tier "${sku.chip}"`
                );
            }
        } else if (isMacBookPro && activeAppleSkuName) {
            const sku = APPLE_SILICON_SKU_CATALOG[activeAppleSkuName];
            if (sku.tier === 'ultra') {
                issues.push(
                    `Mac product line violation: "${macProductLabel}" (MacBook Pro) never ships with desktop-only Ultra-tier SoC "${sku.chip}"`
                );
            }
        } else if (isMacMini && activeAppleSkuName) {
            const sku = APPLE_SILICON_SKU_CATALOG[activeAppleSkuName];
            if (sku.tier === 'max' || sku.tier === 'ultra') {
                issues.push(
                    `Mac product line violation: "${macProductLabel}" (Mac mini) only ships with base or Pro Apple Silicon SoCs, never with ${sku.tier}-tier "${sku.chip}"`
                );
            }
        } else if (isIMacPro && activeAppleSkuName) {
            issues.push(
                `Mac product line violation: "${macProductLabel}" (2017 iMac Pro) is Intel Xeon W + Radeon Pro Vega exclusive and never existed with Apple Silicon "${activeAppleSkuName}"`
            );
        } else if (isIMac && activeAppleSkuName) {
            const sku = APPLE_SILICON_SKU_CATALOG[activeAppleSkuName];
            if (sku.tier !== 'base') {
                issues.push(
                    `Mac product line violation: Apple Silicon "${macProductLabel}" (24-inch iMac) only ships with base M-series SoCs (M1/M3/M4/M5), never with ${sku.tier}-tier "${sku.chip}"`
                );
            }
        } else if (isMacPro) {
            if (activeAppleSkuName) {
                const sku = APPLE_SILICON_SKU_CATALOG[activeAppleSkuName];
                if (sku.tier !== 'ultra') {
                    issues.push(
                        `Mac product line violation: Apple Silicon "${macProductLabel}" (Mac Pro) exclusively ships with Ultra-tier SoCs (M2 Ultra / M3 Ultra), never with ${sku.tier}-tier "${sku.chip}"`
                    );
                }
            } else if (/Intel.*Iris|Intel.*HD\s+Graphics|Intel.*UHD\s+Graphics/i.test(renderer)) {
                issues.push(
                    `Mac product line violation: Intel "${macProductLabel}" (Mac Pro Xeon workstation) has no integrated Intel GPU and cannot render via laptop iGPU "${renderer}"`
                );
            }
        }
    }

    // =========================================================================
    // Rule O: WebGPU GPUAdapterInfo (vendor / architecture) vs WebGL Renderer Lockstep
    // =========================================================================
    const webgpuAdapter =
        hw.webgpuAdapterInfo ||
        webgl.gpuAdapterInfo ||
        webgl.GPUAdapterInfo ||
        telemetry.webgpu?.adapterInfo ||
        null;
    if (webgpuAdapter && typeof webgpuAdapter === 'object' && renderer) {
        const wVendor = String(webgpuAdapter.vendor || '').trim().toLowerCase();
        const wArch = String(webgpuAdapter.architecture || '').trim().toLowerCase();

        if (/AMD|Radeon/i.test(renderer)) {
            if (wVendor && wVendor !== 'amd') {
                issues.push(
                    `WebGPU GPUAdapterInfo.vendor="${wVendor}" contradicts AMD WebGL renderer "${renderer}"`
                );
            }
            if (/^gen-\d|^xe2?-|^common-\d|^metal-\d|ada-lovelace|ampere|turing|adreno/i.test(wArch)) {
                issues.push(
                    `WebGPU GPUAdapterInfo.architecture="${wArch}" (Intel/Apple architecture) contradicts AMD WebGL renderer "${renderer}"`
                );
            }
        } else if (/NVIDIA|GeForce|Quadro|RTX|GTX/i.test(renderer)) {
            if (wVendor && wVendor !== 'nvidia') {
                issues.push(
                    `WebGPU GPUAdapterInfo.vendor="${wVendor}" contradicts NVIDIA WebGL renderer "${renderer}"`
                );
            }
            if (/^gen-\d|^xe2?-|^common-\d|^metal-\d|rdna|gcn|adreno/i.test(wArch)) {
                issues.push(
                    `WebGPU GPUAdapterInfo.architecture="${wArch}" contradicts NVIDIA WebGL renderer "${renderer}"`
                );
            }
        } else if (activeAppleSkuName) {
            if (wVendor && wVendor !== 'apple') {
                issues.push(
                    `WebGPU GPUAdapterInfo.vendor="${wVendor}" contradicts Apple Silicon WebGL renderer "${renderer}"`
                );
            }
            if (/^gen-\d|^xe2?-|rdna|gcn|ada-lovelace|ampere|turing|adreno/i.test(wArch)) {
                issues.push(
                    `WebGPU GPUAdapterInfo.architecture="${wArch}" contradicts Apple Silicon WebGL renderer "${renderer}"`
                );
            }
        } else if (/Qualcomm|Adreno/i.test(renderer)) {
            if (wVendor && wVendor !== 'qualcomm') {
                issues.push(
                    `WebGPU GPUAdapterInfo.vendor="${wVendor}" contradicts Qualcomm Adreno WebGL renderer "${renderer}"`
                );
            }
            if (/^gen-\d|^xe2?-|^common-\d|^metal-\d|rdna|gcn|ada-lovelace|ampere|turing/i.test(wArch)) {
                issues.push(
                    `WebGPU GPUAdapterInfo.architecture="${wArch}" contradicts Qualcomm Adreno WebGL renderer "${renderer}"`
                );
            }
        } else if (/Intel/i.test(renderer)) {
            if (wVendor && wVendor !== 'intel') {
                issues.push(
                    `WebGPU GPUAdapterInfo.vendor="${wVendor}" contradicts Intel WebGL renderer "${renderer}"`
                );
            }
            if (/^common-\d|^metal-\d|rdna|gcn|ada-lovelace|ampere|turing|adreno/i.test(wArch)) {
                issues.push(
                    `WebGPU GPUAdapterInfo.architecture="${wArch}" contradicts Intel WebGL renderer "${renderer}"`
                );
            }
            // 6th–9th Gen Intel GPUs (HD 520/530/620/630, Iris 540/550/Pro/6100, Iris Plus 640/645/650/655, UHD 617/620/630) are Gen8/Gen9, NEVER Gen12LP!
            const isLegacyGen8Or9Intel =
                /Iris(?:\(TM\))?\s+(?:Pro|Graphics\s+(?:540|550|6100)|Plus\s+Graphics(?:\s+6[45]\d)?)|(?:HD|UHD)\s+Graphics\s+(?:5\d\d|6\d\d)|Iris\s+OpenGL\s+Engine/i.test(
                    renderer
                );
            if (isLegacyGen8Or9Intel && wArch === 'gen-12lp') {
                issues.push(
                    `WebGPU GPUAdapterInfo.architecture="gen-12lp" (Intel 11th/12th-Gen Tiger/Alder Lake) contradicts legacy Gen8/Gen9 Intel GPU "${renderer}" (expected "gen-9")`
                );
            }
        }
    }

    // =========================================================================
    // Rule P: Cross-OS Hostname, IEEE 802.3 OUI MAC Address & W3C DeviceMemory
    //         Coherence (Discovered via Ziniao SuperBrowser V6 Reverse-Engineering)
    // =========================================================================
    const rawHostName = String(hw.deviceName || hw.device_info_str || '').trim();
    if (rawHostName && targetOs) {
        if (targetOs === 'mac' && /^(?:DESKTOP|LAPTOP|WIN)-[A-Z0-9]+$/i.test(rawHostName)) {
            issues.push(
                `Cross-OS DeviceName violation: Windows hostname pattern "${rawHostName}" (DESKTOP-/LAPTOP-/WIN-) cannot appear on macOS targetOs="mac"`
            );
        } else if (targetOs === 'lin' && /^(?:DESKTOP|WIN)-[A-Z0-9]+$/i.test(rawHostName)) {
            issues.push(
                `Cross-OS DeviceName violation: Windows hostname pattern "${rawHostName}" (DESKTOP-/WIN-) cannot appear on Linux targetOs="lin"`
            );
        } else if (
            (targetOs === 'win' || targetOs === 'lin') &&
            /\b(?:MacBook|iMac|Mac[\s_-]+mini|Mac[\s_-]+Studio|Mac[\s_-]+Pro)\b/i.test(rawHostName)
        ) {
            issues.push(
                `Cross-OS DeviceName violation: Apple Mac hostname "${rawHostName}" cannot appear on targetOs="${targetOs}"`
            );
        }
    }

    const rawMacAddr = String(hw.macAddress || hw.mac_address_str || '').trim();
    if (rawMacAddr) {
        const macMatch = rawMacAddr.match(/^([0-9A-Fa-f]{2})(?:[:-][0-9A-Fa-f]{2}){5}$/);
        if (!macMatch || /^00(?:[:-]00){5}$/.test(rawMacAddr)) {
            issues.push(`Invalid IEEE 802.3 MAC address format: "${rawMacAddr}"`);
        } else {
            const firstOctet = parseInt(macMatch[1], 16);
            if ((firstOctet & 0x01) !== 0) {
                issues.push(
                    `MAC address "${rawMacAddr}" has multicast bit set (first octet 0x${macMatch[1].toUpperCase()} bit 0 === 1); physical NIC MAC must be unicast`
                );
            }
            if ((firstOctet & 0x02) !== 0) {
                issues.push(
                    `MAC address "${rawMacAddr}" has Locally Administered bit set (first octet 0x${macMatch[1].toUpperCase()} bit 1 === 1, typical of Ziniao random MAC / VM spoof); physical OEM/Apple NICs use globally unique IEEE OUI (bit 1 === 0)`
                );
            }
        }
    }

    const rawDeviceMemory =
        hw.deviceMemory !== undefined && hw.deviceMemory !== null
            ? toOptionalNumber(hw.deviceMemory)
            : nav.deviceMemory !== undefined && nav.deviceMemory !== null
              ? toOptionalNumber(nav.deviceMemory)
              : null;
    if (rawDeviceMemory !== null) {
        const validW3cDeviceMemory = [0.25, 0.5, 1, 2, 4, 8];
        if (!validW3cDeviceMemory.includes(rawDeviceMemory)) {
            issues.push(
                `W3C Device Memory specification violation: deviceMemory=${rawDeviceMemory}GB is not a power-of-two W3C value (allowed: [0.25, 0.5, 1, 2, 4, 8]GB; Ziniao 6GB spoofing signature)`
            );
        }
    }

    if (
        Number.isFinite(scr.width) &&
        Number.isFinite(scr.height) &&
        scr.width === 1024 &&
        scr.height === 1366 &&
        targetOs
    ) {
        issues.push(
            'Desktop screen resolution violation: portrait 1024x1366 (Ziniao headless window fallback) is an iPad Pro tablet portrait resolution and impossible on a desktop monitor/laptop'
        );
    }

    // =========================================================================
    // Rule I: Intel-based Apple Mac Device & GPU SKU Coherence (2017–2020 Intel Macs)
    // =========================================================================
    const intelMacSku =
        !activeAppleSkuName && targetOs === 'mac'
            ? lookupIntelMacSku(deviceModel, renderer)
            : lookupIntelMacSku(deviceModel, null);

    if (intelMacSku) {
        if (!matchedSku) {
            matchedSku = intelMacSku.id;
        }
        if (targetOs && targetOs !== 'mac') {
            issues.push(`Intel Mac SKU "${intelMacSku.id}" cannot run under targetOs="${targetOs}"`);
        }
        if (cpuModel && /(?:AMD|Ryzen|Threadripper|Snapdragon|Qualcomm|Apple\s+M\d)/i.test(cpuModel)) {
            issues.push(
                `Intel Mac SKU "${intelMacSku.id}" CPU vendor violation: requires an Intel Core/Xeon CPU, got "${cpuModel}"`
            );
        }
        if (renderer && !intelMacSku.gpuPattern.test(renderer)) {
            issues.push(
                `Intel Mac SKU "${intelMacSku.id}" GPU mismatch: WebGL renderer "${renderer}" does not match factory GPU specification`
            );
        }
        if (!Number.isInteger(cores) || !intelMacSku.allowedCores.includes(cores)) {
            issues.push(
                `Intel Mac SKU "${intelMacSku.id}" core count violation: navigator.hardwareConcurrency=${cores} is not valid (allowed: [${intelMacSku.allowedCores.join(', ')}])`
            );
        }
        if (ramGb !== null && (!Number.isFinite(ramGb) || !intelMacSku.allowedRamGb.includes(ramGb))) {
            issues.push(
                `Intel Mac SKU "${intelMacSku.id}" RAM capacity violation: ramGb=${ramGb}GB is not a valid factory configuration (allowed: [${intelMacSku.allowedRamGb.join('GB, ')}GB])`
            );
        }
        if (storageGb !== null && (!Number.isFinite(storageGb) || !intelMacSku.allowedStorageGb.includes(storageGb))) {
            issues.push(
                `Intel Mac SKU "${intelMacSku.id}" SSD storage violation: storageGb=${storageGb}GB is not a valid factory configuration (allowed: [${intelMacSku.allowedStorageGb.join('GB, ')}GB])`
            );
        }
        if (panelKey && intelMacSku.forbiddenPanels.includes(panelKey)) {
            issues.push(
                `Intel Mac SKU "${intelMacSku.id}" display panel violation: resolution ${panelKey} is incompatible with ${intelMacSku.id} form factor`
            );
        }
    }

    // =========================================================================
    // Rule J: Qualcomm Snapdragon X (Windows 11 ARM64 Copilot+ PC) Unified SoC Coherence
    // =========================================================================
    const snapdragonSku = lookupSnapdragonSku(cpuModel);
    const isAdrenoX1Renderer = /Adreno(?:\(TM\))?\s+X1-(?:85|45)|Qualcomm\(R\)\s+Adreno/i.test(renderer);

    if (snapdragonSku) {
        if (!matchedSku) {
            matchedSku = snapdragonSku.chip;
        }
        if (cpuArchClaim === 'x86') {
            issues.push(
                `Qualcomm ARM64 SoC "${snapdragonSku.chip}" architecture violation: architecture="x86" is impossible on ARM64 Oryon`
            );
        }
        if (targetOs && !snapdragonSku.allowedOs.includes(targetOs)) {
            issues.push(
                `Qualcomm SoC "${snapdragonSku.chip}" is not supported on targetOs="${targetOs}" (allowed: [${snapdragonSku.allowedOs.join(', ')}])`
            );
        }
        if (renderer && !snapdragonSku.gpuPattern.test(renderer)) {
            issues.push(
                `Qualcomm Unified SoC "${snapdragonSku.chip}" CPU/GPU mismatch: cannot pair with non-Adreno WebGL renderer "${renderer}"`
            );
        }
        if (!Number.isInteger(cores) || !snapdragonSku.allowedCores.includes(cores)) {
            issues.push(
                `Qualcomm SoC "${snapdragonSku.chip}" core count violation: navigator.hardwareConcurrency=${cores} (expected [${snapdragonSku.allowedCores.join(', ')}] cores)`
            );
        }
        if (ramGb !== null && (!Number.isFinite(ramGb) || !snapdragonSku.allowedRamGb.includes(ramGb))) {
            issues.push(
                `Qualcomm SoC "${snapdragonSku.chip}" LPDDR5x RAM violation: ramGb=${ramGb}GB (allowed: [${snapdragonSku.allowedRamGb.join('GB, ')}GB])`
            );
        }
        if (storageGb !== null && (!Number.isFinite(storageGb) || !snapdragonSku.allowedStorageGb.includes(storageGb))) {
            issues.push(
                `Qualcomm SoC "${snapdragonSku.chip}" SSD storage violation: storageGb=${storageGb}GB (allowed: [${snapdragonSku.allowedStorageGb.join('GB, ')}GB])`
            );
        }
    } else if (isAdrenoX1Renderer && cpuModel && !/Snapdragon|Qualcomm/i.test(cpuModel)) {
        issues.push(
            `Qualcomm Adreno X1 GPU ("${renderer}") cannot be paired with non-Qualcomm CPU "${cpuModel}"`
        );
    }

    // =========================================================================
    // Rule K: OEM Laptop / Ultrabook / Gaming Laptop / Workstation Device Model Coherence
    // (ThinkPad, Dell XPS, Microsoft Surface, ASUS ROG, Razer Blade, HP Spectre, Framework, System76)
    // =========================================================================
    const oemDeviceSku = lookupOemDeviceSku(deviceModel);
    const pcCpuSku = lookupPcCpuSku(cpuModel);
    const pcGpuSku = lookupPcGpuSku(renderer);

    if (oemDeviceSku) {
        matchedSku = oemDeviceSku.model;

        if (targetOs && !oemDeviceSku.allowedOs.includes(targetOs)) {
            issues.push(
                `OEM device model "${oemDeviceSku.model}" OS violation: cannot run targetOs="${targetOs}" (allowed: [${oemDeviceSku.allowedOs.join(', ')}])`
            );
        }
        if (pcCpuSku && pcCpuSku.formFactor === 'desktop') {
            issues.push(
                `OEM laptop/tablet "${oemDeviceSku.model}" cannot house desktop socket CPU "${pcCpuSku.model}"`
            );
        }
        if (oemDeviceSku.cpuVendor && pcCpuSku && pcCpuSku.vendor !== oemDeviceSku.cpuVendor) {
            issues.push(
                `OEM device model "${oemDeviceSku.model}" CPU vendor violation: requires ${oemDeviceSku.cpuVendor.toUpperCase()} CPU but got "${pcCpuSku.model}" (${pcCpuSku.vendor.toUpperCase()})`
            );
        } else if (oemDeviceSku.cpuVendor && cpuModel) {
            const lowerCpu = cpuModel.toLowerCase();
            if (
                oemDeviceSku.cpuVendor === 'intel' &&
                (lowerCpu.includes('amd') || lowerCpu.includes('ryzen') || lowerCpu.includes('apple') || lowerCpu.includes('snapdragon') || lowerCpu.includes('qualcomm'))
            ) {
                issues.push(
                    `OEM device model "${oemDeviceSku.model}" requires an Intel processor but hardwareProfile.cpuModel is "${cpuModel}"`
                );
            } else if (
                oemDeviceSku.cpuVendor === 'amd' &&
                (lowerCpu.includes('intel') || lowerCpu.includes('apple') || lowerCpu.includes('snapdragon') || lowerCpu.includes('qualcomm'))
            ) {
                issues.push(
                    `OEM device model "${oemDeviceSku.model}" requires an AMD Ryzen processor but hardwareProfile.cpuModel is "${cpuModel}"`
                );
            } else if (
                oemDeviceSku.cpuVendor === 'qualcomm' &&
                (lowerCpu.includes('intel') || lowerCpu.includes('amd') || lowerCpu.includes('ryzen') || lowerCpu.includes('apple'))
            ) {
                issues.push(
                    `OEM device model "${oemDeviceSku.model}" requires a Qualcomm Snapdragon processor but hardwareProfile.cpuModel is "${cpuModel}"`
                );
            }
        }
        if (!Number.isInteger(cores) || !oemDeviceSku.allowedCores.includes(cores)) {
            issues.push(
                `OEM device model "${oemDeviceSku.model}" core/thread count violation: navigator.hardwareConcurrency=${cores} is not valid for ${oemDeviceSku.model} (allowed: [${oemDeviceSku.allowedCores.join(', ')}])`
            );
        }
        if (oemDeviceSku.igpuOnly && pcGpuSku && !pcGpuSku.isIntegrated) {
            issues.push(
                `OEM Ultrabook "${oemDeviceSku.model}" is integrated-GPU only and cannot house discrete GPU "${renderer}"`
            );
        }
        if (renderer && oemDeviceSku.gpuPattern && !oemDeviceSku.gpuPattern.test(renderer)) {
            issues.push(
                `OEM device model "${oemDeviceSku.model}" GPU mismatch: WebGL renderer "${renderer}" is not offered on ${oemDeviceSku.model}`
            );
        }
        if (ramGb !== null && (!Number.isFinite(ramGb) || !oemDeviceSku.allowedRamGb.includes(ramGb))) {
            issues.push(
                `OEM device model "${oemDeviceSku.model}" RAM capacity violation: ramGb=${ramGb}GB is not offered on ${oemDeviceSku.model} (factory RAM tiers: [${oemDeviceSku.allowedRamGb.join('GB, ')}GB])`
            );
        }
        if (storageGb !== null && (!Number.isFinite(storageGb) || !oemDeviceSku.allowedStorageGb.includes(storageGb))) {
            issues.push(
                `OEM device model "${oemDeviceSku.model}" SSD storage violation: storageGb=${storageGb}GB is not offered on ${oemDeviceSku.model} (allowed: [${oemDeviceSku.allowedStorageGb.join('GB, ')}GB])`
            );
        }
        if (oemDeviceSku.aspectRatio3by2 && Number.isFinite(scr.width) && Number.isFinite(scr.height) && scr.height > 0) {
            const ratio = scr.width / scr.height;
            // Microsoft Surface 3:2 PixelSense panels have width/height ratio ~ 1.50 (tolerance 1.48..1.52)
            if (Math.abs(ratio - 1.5) > 0.03) {
                issues.push(
                    `OEM device "${oemDeviceSku.model}" has a 3:2 PixelSense display (ratio 1.50) but screen resolution is ${scr.width}x${scr.height} (ratio ${ratio.toFixed(2)})`
                );
            }
        }
        if (oemDeviceSku.requiresTouchScreen && Number(nav.maxTouchPoints) <= 0) {
            issues.push(
                `OEM 2-in-1 tablet "${oemDeviceSku.model}" requires touchscreen support (navigator.maxTouchPoints > 0) but reported maxTouchPoints=${nav.maxTouchPoints}`
            );
        }
    }

    // =========================================================================
    // Rule F: PC (Intel / AMD) CPU Model vs Threads, RAM Ceiling, MoP RAM,
    //         iGPU Presence/Generation Lockstep & CPU-to-GPU Form-Factor Lockstep
    // =========================================================================
    if (!matchedSku && (pcCpuSku || pcGpuSku)) {
        matchedSku = [pcCpuSku?.model, pcGpuSku?.id].filter(Boolean).join(' + ');
    }

    if (pcCpuSku) {
        if (targetOs === 'mac' && gpuAppleSkuName) {
            issues.push(
                `x86_64 PC CPU "${pcCpuSku.model}" cannot be paired with Apple Silicon GPU "${gpuAppleSkuName}"`
            );
        }
        if (!Number.isInteger(cores) || !pcCpuSku.allowedThreads.includes(cores)) {
            issues.push(
                `CPU SKU "${pcCpuSku.model}" thread count violation: navigator.hardwareConcurrency=${cores} does not match ${pcCpuSku.model} (${pcCpuSku.physicalCores}C/${pcCpuSku.threads}T, allowed: [${pcCpuSku.allowedThreads.join(', ')}])`
            );
        }
        if (ramGb !== null) {
            if (pcCpuSku.strictAllowedRam && !pcCpuSku.allowedRamGb.includes(ramGb)) {
                issues.push(
                    `CPU SKU "${pcCpuSku.model}" on-package memory (MoP) violation: ramGb=${ramGb}GB is impossible on ${pcCpuSku.model} (soldered on-package RAM options: [${pcCpuSku.allowedRamGb.join('GB, ')}GB])`
                );
            } else if (!Number.isFinite(ramGb) || ramGb > pcCpuSku.maxRamGb || !STANDARD_PC_RAM_GB_TIERS.includes(ramGb)) {
                issues.push(
                    `CPU SKU "${pcCpuSku.model}" RAM capacity violation: ramGb=${ramGb}GB exceeds ${pcCpuSku.maxRamGb}GB hardware ceiling or is not a valid DIMM tier`
                );
            }
        }

        // Check 1: CPU without integrated graphics (Intel -F/-KF and AMD Ryzen 3000/5000 non-G)
        if (pcCpuSku.hasIntegratedGpu === false && pcGpuSku?.isIntegrated) {
            issues.push(
                `CPU SKU "${pcCpuSku.model}" physically lacks an integrated GPU (hasIntegratedGpu=false) and cannot render via integrated GPU "${renderer}"`
            );
        }

        // Check 2: CPU vendor vs integrated GPU vendor
        if (pcGpuSku?.isIntegrated && pcGpuSku.cpuVendorLock && pcCpuSku.vendor !== pcGpuSku.cpuVendorLock) {
            issues.push(
                `CPU SKU "${pcCpuSku.model}" (${pcCpuSku.vendor.toUpperCase()}) cannot pair with integrated ${pcGpuSku.vendor.toUpperCase()} iGPU "${renderer}"`
            );
        }

        // Check 3: CPU generation vs specific integrated GPU model pattern
        if (
            pcCpuSku.hasIntegratedGpu &&
            pcCpuSku.expectedIgpuPattern &&
            pcGpuSku?.isIntegrated &&
            pcGpuSku.cpuVendorLock === pcCpuSku.vendor &&
            !pcCpuSku.expectedIgpuPattern.test(renderer)
        ) {
            issues.push(
                `CPU SKU "${pcCpuSku.model}" integrated GPU generation mismatch: WebGL renderer "${renderer}" does not match ${pcCpuSku.model}'s built-in iGPU (${pcCpuSku.expectedIgpuPattern})`
            );
        }

        // Check 4: Desktop CPU vs Mobile-only GPU / Mobile Laptop CPU vs Desktop-only GPU
        if (pcCpuSku.formFactor === 'desktop' && renderer) {
            const isMobileOnlyGpu =
                pcGpuSku?.formFactor === 'laptop' ||
                /Laptop\s+GPU|Max-Q|\b(?:610M|660M|680M|740M|760M|780M|880M|890M)\b|Iris\(TM\)\s+Plus\s+Graphics\s+6[45]\d|UHD\s+Graphics\s+620/i.test(
                    renderer
                );
            if (isMobileOnlyGpu) {
                issues.push(
                    `Desktop CPU SKU "${pcCpuSku.model}" cannot be paired with laptop/mobile-only GPU "${renderer}"`
                );
            }
        } else if (pcCpuSku.formFactor === 'mobile-ultrabook' && pcGpuSku?.formFactor === 'desktop') {
            issues.push(
                `Low-power Ultrabook CPU SKU "${pcCpuSku.model}" cannot be paired with full-size desktop discrete GPU "${renderer}"`
            );
        } else if (pcCpuSku.formFactor === 'mobile-h' && pcGpuSku?.formFactor === 'desktop') {
            issues.push(
                `High-performance laptop CPU SKU "${pcCpuSku.model}" cannot be paired with full-size desktop discrete GPU "${renderer}"`
            );
        }
    } else if (!activeAppleSkuName && !snapdragonSku && cpuModel) {
        // Infer CPU vendor from raw cpuModel string for iGPU vendor cross-check
        const cpuLower = cpuModel.toLowerCase();
        const isIntelCpu = cpuLower.includes('intel');
        const isAmdCpu = cpuLower.includes('amd') || cpuLower.includes('ryzen');
        if (isIntelCpu && pcGpuSku?.isIntegrated && pcGpuSku.cpuVendorLock === 'amd') {
            issues.push(
                `Intel CPU "${cpuModel}" cannot have an integrated AMD Radeon APU GPU ("${renderer}")`
            );
        }
        if (isAmdCpu && pcGpuSku?.isIntegrated && pcGpuSku.cpuVendorLock === 'intel') {
            issues.push(
                `AMD CPU "${cpuModel}" cannot have an integrated Intel UHD/Iris GPU ("${renderer}")`
            );
        }
    }

    // =========================================================================
    // Rule L: GPU VRAM Capacity, OS Support & PCI Vendor/Device ID Spoofing Detection
    // =========================================================================
    if (pcGpuSku && targetOs && Array.isArray(pcGpuSku.osSupport) && !pcGpuSku.osSupport.includes(targetOs)) {
        issues.push(
            `GPU SKU "${pcGpuSku.id}" OS compatibility violation: not supported on targetOs="${targetOs}" (supported: [${pcGpuSku.osSupport.join(', ')}])`
        );
    }

    if (pcGpuSku && vramGb !== null) {
        if (!Number.isFinite(vramGb) || !pcGpuSku.vramGb.includes(vramGb)) {
            issues.push(
                `GPU SKU "${pcGpuSku.id}" VRAM capacity violation: vramGb=${vramGb}GB does not match factory VRAM configuration (allowed: [${pcGpuSku.vramGb.join('GB, ')}GB])`
            );
        }
    }

    if (pcGpuSku && pciVendorId) {
        const expectedPciVendor = PCI_VENDOR_ID_BY_GPU_VENDOR[pcGpuSku.vendor];
        if (expectedPciVendor && pciVendorId !== expectedPciVendor) {
            issues.push(
                `GPU PCI Vendor ID mismatch: hardwareProfile.pciVendorId="${pciVendorId}" contradicts ${pcGpuSku.vendor.toUpperCase()} GPU "${renderer}" (expected ${expectedPciVendor})`
            );
        }
    }

    // Extract PCI Device ID from ANGLE renderer string e.g. "(0x00002504)" or explicit hw.pciDeviceId
    const rendererPciMatch = renderer.match(/\(\s*0x0*([0-9a-fA-F]{4})\s*\)/);
    const rendererPciId = rendererPciMatch ? `0x${rendererPciMatch[1].toLowerCase()}` : null;
    const explicitPciId = pciDeviceId
        ? pciDeviceId.replace(/^0x0+([0-9a-f]{4})$/i, '0x$1').toLowerCase()
        : null;

    if (rendererPciId && explicitPciId && rendererPciId !== explicitPciId) {
        issues.push(
            `GPU PCI Device ID mismatch: hardwareProfile.pciDeviceId="${explicitPciId}" contradicts renderer PCI ID "${rendererPciId}" in "${renderer}"`
        );
    }

    const normalizedPciDeviceId = rendererPciId || explicitPciId;

    if (normalizedPciDeviceId && Object.prototype.hasOwnProperty.call(PCI_DEVICE_ID_CATALOG, normalizedPciDeviceId)) {
        const pciEntry = PCI_DEVICE_ID_CATALOG[normalizedPciDeviceId];
        if (renderer && !pciEntry.pattern.test(renderer)) {
            issues.push(
                `GPU PCI Device ID spoofing detected: PCI ID ${normalizedPciDeviceId} belongs to "${pciEntry.name}" (${pciEntry.vendor.toUpperCase()}), which contradicts claimed WebGL renderer "${renderer}"`
            );
        }
    }

    // Generic PC RAM & Storage validation when no Apple Silicon / Intel Mac / OEM SKU is active
    if (!activeAppleSkuName && !intelMacSku && !oemDeviceSku && !snapdragonSku) {
        if (ramGb !== null && !pcCpuSku) {
            if (!Number.isFinite(ramGb) || !STANDARD_PC_RAM_GB_TIERS.includes(ramGb)) {
                issues.push(
                    `Invalid PC RAM capacity ramGb=${ramGb}GB (must be a standard DDR4/DDR5 capacity: [${STANDARD_PC_RAM_GB_TIERS.join(', ')}] GB)`
                );
            }
        }
        if (storageGb !== null) {
            if (!Number.isFinite(storageGb) || !STANDARD_PC_STORAGE_GB_TIERS.includes(storageGb)) {
                issues.push(
                    `Invalid PC SSD/NVMe storage capacity storageGb=${storageGb}GB (must be a standard tier: [${STANDARD_PC_STORAGE_GB_TIERS.join(', ')}] GB)`
                );
            }
        }
    }

    // =========================================================================
    // Rule D (Browser Storage Quota vs Physical Disk Size):
    // navigator.storage.estimate().quota cannot exceed physical disk capacity
    // =========================================================================
    if (storageEstimate && typeof storageEstimate === 'object') {
        const quotaBytes = Number(
            storageEstimate.quotaBytes ?? storageEstimate.quota ?? NaN
        );
        const usageBytes = Number(
            storageEstimate.usageBytes ?? storageEstimate.usage ?? 0
        );

        if (Number.isFinite(quotaBytes)) {
            if (quotaBytes <= 0) {
                issues.push(`Browser StorageManager quotaBytes (${quotaBytes}) must be positive`);
            }
            if (Number.isFinite(usageBytes) && usageBytes > quotaBytes) {
                issues.push(
                    `Browser StorageManager usageBytes (${usageBytes}) exceeds quotaBytes (${quotaBytes})`
                );
            }
            if (storageGb !== null && Number.isFinite(storageGb) && storageGb > 0) {
                const maxPhysicalBytes = storageGb * BYTES_PER_GB_BINARY;
                if (quotaBytes > maxPhysicalBytes) {
                    issues.push(
                        `Browser StorageManager quotaBytes (${(quotaBytes / BYTES_PER_GB_BINARY).toFixed(1)} GiB) exceeds physical disk capacity storageGb (${storageGb} GiB)`
                    );
                }
            }
        }
    }

    // =========================================================================
    // Rule G: Windows ANGLE Vendor vs Renderer Inner Vendor & Shader Model Lockstep
    // =========================================================================
    if (targetOs === 'win' && renderer) {
        const angleRendererMatch = renderer.match(/^ANGLE\s*\(\s*([^,]+)\s*,\s*([^,]+)(?:,\s*([^)]+))?\)/i);
        const angleVendorMatch = vendor.match(/^Google Inc\.\s*\(\s*([^)]+)\s*\)$/i);

        if (angleRendererMatch && angleVendorMatch) {
            const innerRendererVendor = angleRendererMatch[1].trim().toLowerCase();
            const innerUnmaskedVendor = angleVendorMatch[1].trim().toLowerCase();
            if (innerRendererVendor !== innerUnmaskedVendor) {
                issues.push(
                    `Windows ANGLE vendor mismatch: unmaskedVendor is "${vendor}" (inner="${angleVendorMatch[1].trim()}") but unmaskedRenderer is "${renderer}" (inner="${angleRendererMatch[1].trim()}")`
                );
            }
        }

        // Check inner vendor vs GPU brand inside renderer description
        if (angleRendererMatch) {
            const innerVendor = angleRendererMatch[1].trim().toLowerCase();
            const gpuDesc = angleRendererMatch[2].trim();
            if (innerVendor === 'intel' && /(?:NVIDIA|GeForce|Radeon|AMD)/i.test(gpuDesc)) {
                issues.push(
                    `Windows ANGLE renderer inner vendor "Intel" contradicts discrete GPU description "${gpuDesc}"`
                );
            } else if (innerVendor === 'nvidia' && /(?:Intel\(R\)|Radeon|AMD)/i.test(gpuDesc)) {
                issues.push(
                    `Windows ANGLE renderer inner vendor "NVIDIA" contradicts GPU description "${gpuDesc}"`
                );
            } else if (innerVendor === 'amd' && /(?:NVIDIA|GeForce|Intel\(R\))/i.test(gpuDesc)) {
                issues.push(
                    `Windows ANGLE renderer inner vendor "AMD" contradicts GPU description "${gpuDesc}"`
                );
            }
        }

        // Direct3D 11 must pair with Shader Model 5.0 (vs_5_0 ps_5_0), Direct3D 9 with vs_3_0 ps_3_0
        if (/Direct3D11/i.test(renderer) && /vs_3_0|ps_3_0/i.test(renderer)) {
            issues.push(
                `Windows ANGLE Direct3D11 renderer "${renderer}" reports legacy Direct3D9 shader model (vs_3_0/ps_3_0) instead of vs_5_0 ps_5_0`
            );
        }
        if (/Direct3D9/i.test(renderer) && /vs_5_0|ps_5_0/i.test(renderer)) {
            issues.push(
                `Windows ANGLE Direct3D9 renderer "${renderer}" reports Direct3D11 shader model (vs_5_0/ps_5_0)`
            );
        }
        if (/\b(?:Mesa|radeonsi|llvmpipe|softpipe)\b/i.test(renderer)) {
            issues.push(
                `Windows targetOs="win" cannot use Linux Mesa/Gallium OpenGL renderer "${renderer}"`
            );
        }
    } else if ((targetOs === 'mac' || targetOs === 'lin') && renderer) {
        if (/Direct3D(?:11|9)|D3D11|D3D9|vs_5_0|ps_5_0/i.test(renderer)) {
            issues.push(
                `Non-Windows targetOs="${targetOs}" cannot use Windows Direct3D ANGLE renderer "${renderer}"`
            );
        }
        if (targetOs === 'mac' && /\b(?:Mesa|radeonsi|llvmpipe|softpipe)\b/i.test(renderer)) {
            issues.push(
                `macOS targetOs="mac" cannot use Linux Mesa/Gallium renderer "${renderer}"`
            );
        }
    }

    // =========================================================================
    // Rule H: GPU Model WebGL Parameter Limits Coherence
    // =========================================================================
    if (Array.isArray(webgl.maxViewportDims) && webgl.maxViewportDims.length === 2) {
        const [vpW, vpH] = webgl.maxViewportDims.map(Number);
        if (!Number.isFinite(vpW) || !Number.isFinite(vpH) || vpW < 16384 || vpH < 16384 || vpW !== vpH) {
            issues.push(
                `WebGL MAX_VIEWPORT_DIMS=[${vpW}, ${vpH}] is invalid for desktop GPU hardware (expected square >= [16384, 16384])`
            );
        } else if (activeAppleSkuName && (vpW !== 16384 || vpH !== 16384)) {
            issues.push(
                `WebGL MAX_VIEWPORT_DIMS=[${vpW}, ${vpH}] contradicts Apple Silicon Metal limit [16384, 16384] for "${activeAppleSkuName}"`
            );
        }
    }
    if (webgl.maxTextureSize !== undefined && webgl.maxTextureSize !== null) {
        const maxTex = Number(webgl.maxTextureSize);
        if ((activeAppleSkuName || pcGpuSku) && maxTex !== 16384) {
            const skuLabel = activeAppleSkuName || pcGpuSku.id;
            issues.push(
                `WebGL MAX_TEXTURE_SIZE=${maxTex} contradicts GPU SKU "${skuLabel}" hardware specification (expected 16384)`
            );
        } else if (maxTex < 8192) {
            issues.push(`WebGL MAX_TEXTURE_SIZE=${maxTex} is abnormally low for desktop hardware (< 8192)`);
        }
    }

    if (webgl.maxCubeMapTextureSize !== undefined && webgl.maxCubeMapTextureSize !== null) {
        const maxCube = Number(webgl.maxCubeMapTextureSize);
        if ((activeAppleSkuName || pcGpuSku) && maxCube !== 16384) {
            const skuLabel = activeAppleSkuName || pcGpuSku.id;
            issues.push(
                `WebGL MAX_CUBE_MAP_TEXTURE_SIZE=${maxCube} contradicts GPU SKU "${skuLabel}" hardware specification (expected 16384)`
            );
        }
    }

    if (webgl.maxRenderbufferSize !== undefined && webgl.maxRenderbufferSize !== null) {
        const maxRb = Number(webgl.maxRenderbufferSize);
        if ((activeAppleSkuName || pcGpuSku) && maxRb < 16384) {
            const skuLabel = activeAppleSkuName || pcGpuSku.id;
            issues.push(
                `WebGL MAX_RENDERBUFFER_SIZE=${maxRb} contradicts GPU SKU "${skuLabel}" hardware specification (expected >= 16384)`
            );
        }
    }

    if (Array.isArray(webgl.aliasedLineWidthRange) && webgl.aliasedLineWidthRange.length === 2) {
        const [minLine, maxLine] = webgl.aliasedLineWidthRange.map(Number);
        // Both Windows ANGLE (D3D11) and macOS Metal strictly clamp ALIASED_LINE_WIDTH_RANGE to [1, 1]
        if ((targetOs === 'win' || targetOs === 'mac') && (minLine !== 1 || maxLine !== 1)) {
            issues.push(
                `WebGL ALIASED_LINE_WIDTH_RANGE=[${minLine}, ${maxLine}] is invalid for ${targetOs === 'win' ? 'Windows ANGLE D3D11' : 'macOS Metal'} (must be [1, 1])`
            );
        }
    }

    return {
        passed: issues.length === 0,
        matchedSku,
        issues
    };
}

export default {
    APPLE_LAPTOP_PANELS,
    APPLE_SILICON_SKU_CATALOG,
    INTEL_MAC_SKU_CATALOG,
    QUALCOMM_SNAPDRAGON_SKU_CATALOG,
    OEM_DEVICE_MODEL_CATALOG,
    PC_CPU_SKU_CATALOG,
    PC_GPU_SKU_CATALOG,
    PCI_DEVICE_ID_CATALOG,
    PCI_VENDOR_ID_BY_GPU_VENDOR,
    STANDARD_PC_RAM_GB_TIERS,
    STANDARD_PC_STORAGE_GB_TIERS,
    parseAppleSiliconSkuName,
    lookupIntelMacSku,
    lookupSnapdragonSku,
    lookupOemDeviceSku,
    lookupPcCpuSku,
    lookupPcGpuSku,
    validateHardwareModelSpec
};
