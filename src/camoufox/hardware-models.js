/**
 * Authoritative Hardware SKU & Exact Device Model Parameter Catalog for Camoufox
 *
 * Enforces exact model-level hardware parameter coherence across:
 *   1. Apple Silicon SoC SKUs (M1 / M2 / M3 / M4 base, Pro, Max, Ultra):
 *      - Unified CPU + GPU die lockstep (cannot pair M1 CPU with M2 GPU)
 *      - Exact physical core count (`navigator.hardwareConcurrency`) per SKU
 *      - Exact Unified Memory (`ramGb`) capacities & core-to-RAM die pairings
 *        (e.g. M1 max 16GB, M1 Max max 64GB, M3 Pro 192-bit bus 18GB/36GB only,
 *         14-core M3 Max 36GB/96GB vs 16-core M3 Max 48GB/64GB/128GB)
 *      - Exact Apple factory SSD storage tiers (`storageGb`) & browser StorageManager quota ceiling
 *      - Form-factor display panel resolution lockstep (e.g. base M1 had no notch;
 *        M1/M2/M3 Ultra are desktop-only Mac Studio / Mac Pro and cannot use laptop notched panels)
 *   2. Desktop/Laptop x86_64 PC CPU SKUs (Intel Core 10th-14th Gen, AMD Ryzen 5000-9000):
 *      - Exact logical thread count (`hardwareConcurrency`), max RAM capacity, and iGPU vendor lockstep
 *   3. GPU Architecture & WebGL Hardware Parameter Limits:
 *      - Windows ANGLE `unmaskedVendor` (`Google Inc. (<Vendor>)`) vs `unmaskedRenderer` (`ANGLE (<Vendor>, ...)`)
 *      - Direct3D 11 (`vs_5_0 ps_5_0`) vs Direct3D 9 (`vs_3_0 ps_3_0`) shader model lockstep
 *      - WebGL hardware parameter limits (`MAX_TEXTURE_SIZE`, `MAX_CUBE_MAP_TEXTURE_SIZE`,
 *        `MAX_RENDERBUFFER_SIZE`, `MAX_VIEWPORT_DIMS`, `ALIASED_LINE_WIDTH_RANGE`)
 */

const BYTES_PER_GB_BINARY = 1024 ** 3; // 1 GiB = 1,073,741,824 bytes

export const APPLE_LAPTOP_PANELS = Object.freeze({
    // Non-notched 13.3" Retina (M1 MacBook Air 2020, M1/M2 13.3" MacBook Pro Touch Bar)
    nonNotch13: Object.freeze(['1280x800', '1440x900', '1680x1050']),
    // Notched 13.6" Liquid Retina (M2 / M3 / M4 MacBook Air)
    air13Notch: Object.freeze(['1024x665', '1280x832', '1470x956', '1710x1112']),
    // Notched 15.3" Liquid Retina (M2 / M3 / M4 MacBook Air 15")
    air15Notch: Object.freeze(['1280x828', '1440x932', '1710x1107']),
    // Notched 14.2" Liquid Retina XDR (14" MacBook Pro)
    pro14Notch: Object.freeze(['1147x745', '1352x878', '1512x982', '1800x1169']),
    // Notched 16.2" Liquid Retina XDR (16" MacBook Pro)
    pro16Notch: Object.freeze(['1312x848', '1496x967', '1728x1117', '2056x1329']),
    // Desktop / External Apple Displays (24" iMac 4.5K, 27" 5K Studio Display, 32" 6K Pro Display XDR, 1080p/1440p/4K)
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
 * Authoritative Apple Silicon SoC SKU Catalog (M1 through M4 families).
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
        // 14-core M4 Max only ships with 36GB; 16-core M4 Max ships with 48GB, 64GB, or 128GB
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
    })
});

/**
 * Authoritative x86_64 Desktop & Laptop PC CPU SKU Catalog (Intel & AMD).
 */
export const PC_CPU_SKU_CATALOG = Object.freeze({
    'Intel Core i3-10100': Object.freeze({
        model: 'Intel Core i3-10100',
        vendor: 'intel',
        physicalCores: 4,
        threads: 8,
        allowedThreads: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16, 32, 64]),
        maxRamGb: 128
    }),
    'Intel Core i5-8250U': Object.freeze({
        model: 'Intel Core i5-8250U',
        vendor: 'intel',
        physicalCores: 4,
        threads: 8,
        allowedThreads: Object.freeze([4, 8]),
        allowedRamGb: Object.freeze([8, 16, 32]),
        maxRamGb: 32
    }),
    'Intel Core i5-10400': Object.freeze({
        model: 'Intel Core i5-10400',
        vendor: 'intel',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128
    }),
    'Intel Core i5-11400': Object.freeze({
        model: 'Intel Core i5-11400',
        vendor: 'intel',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128
    }),
    'Intel Core i5-12400': Object.freeze({
        model: 'Intel Core i5-12400',
        vendor: 'intel',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([8, 16, 32, 64, 128]),
        maxRamGb: 128
    }),
    'Intel Core i5-13400': Object.freeze({
        model: 'Intel Core i5-13400',
        vendor: 'intel',
        physicalCores: 10,
        threads: 16,
        allowedThreads: Object.freeze([10, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128, 192]),
        maxRamGb: 192
    }),
    'Intel Core i5-13600K': Object.freeze({
        model: 'Intel Core i5-13600K',
        vendor: 'intel',
        physicalCores: 14,
        threads: 20,
        allowedThreads: Object.freeze([14, 20]),
        allowedRamGb: Object.freeze([16, 32, 64, 128, 192]),
        maxRamGb: 192
    }),
    'Intel Core i5-14600K': Object.freeze({
        model: 'Intel Core i5-14600K',
        vendor: 'intel',
        physicalCores: 14,
        threads: 20,
        allowedThreads: Object.freeze([14, 20]),
        allowedRamGb: Object.freeze([16, 32, 64, 128, 192]),
        maxRamGb: 192
    }),
    'Intel Core i7-10700K': Object.freeze({
        model: 'Intel Core i7-10700K',
        vendor: 'intel',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128
    }),
    'Intel Core i7-12700K': Object.freeze({
        model: 'Intel Core i7-12700K',
        vendor: 'intel',
        physicalCores: 12,
        threads: 20,
        allowedThreads: Object.freeze([12, 20]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128
    }),
    'Intel Core i7-13700K': Object.freeze({
        model: 'Intel Core i7-13700K',
        vendor: 'intel',
        physicalCores: 16,
        threads: 24,
        allowedThreads: Object.freeze([16, 24]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'Intel Core i7-14700K': Object.freeze({
        model: 'Intel Core i7-14700K',
        vendor: 'intel',
        physicalCores: 20,
        threads: 28,
        allowedThreads: Object.freeze([20, 28]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'Intel Core i9-12900K': Object.freeze({
        model: 'Intel Core i9-12900K',
        vendor: 'intel',
        physicalCores: 16,
        threads: 24,
        allowedThreads: Object.freeze([16, 24]),
        allowedRamGb: Object.freeze([32, 64, 128]),
        maxRamGb: 128
    }),
    'Intel Core i9-13900K': Object.freeze({
        model: 'Intel Core i9-13900K',
        vendor: 'intel',
        physicalCores: 24,
        threads: 32,
        allowedThreads: Object.freeze([24, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'Intel Core i9-14900K': Object.freeze({
        model: 'Intel Core i9-14900K',
        vendor: 'intel',
        physicalCores: 24,
        threads: 32,
        allowedThreads: Object.freeze([24, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'AMD Ryzen 5 5600X': Object.freeze({
        model: 'AMD Ryzen 5 5600X',
        vendor: 'amd',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128
    }),
    'AMD Ryzen 5 7600X': Object.freeze({
        model: 'AMD Ryzen 5 7600X',
        vendor: 'amd',
        physicalCores: 6,
        threads: 12,
        allowedThreads: Object.freeze([6, 12]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'AMD Ryzen 7 5800X': Object.freeze({
        model: 'AMD Ryzen 7 5800X',
        vendor: 'amd',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 128]),
        maxRamGb: 128
    }),
    'AMD Ryzen 7 7700X': Object.freeze({
        model: 'AMD Ryzen 7 7700X',
        vendor: 'amd',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'AMD Ryzen 7 7800X3D': Object.freeze({
        model: 'AMD Ryzen 7 7800X3D',
        vendor: 'amd',
        physicalCores: 8,
        threads: 16,
        allowedThreads: Object.freeze([8, 16]),
        allowedRamGb: Object.freeze([16, 32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'AMD Ryzen 9 5900X': Object.freeze({
        model: 'AMD Ryzen 9 5900X',
        vendor: 'amd',
        physicalCores: 12,
        threads: 24,
        allowedThreads: Object.freeze([12, 24]),
        allowedRamGb: Object.freeze([32, 64, 128]),
        maxRamGb: 128
    }),
    'AMD Ryzen 9 5950X': Object.freeze({
        model: 'AMD Ryzen 9 5950X',
        vendor: 'amd',
        physicalCores: 16,
        threads: 32,
        allowedThreads: Object.freeze([16, 32]),
        allowedRamGb: Object.freeze([32, 64, 128]),
        maxRamGb: 128
    }),
    'AMD Ryzen 9 7900X': Object.freeze({
        model: 'AMD Ryzen 9 7900X',
        vendor: 'amd',
        physicalCores: 12,
        threads: 24,
        allowedThreads: Object.freeze([12, 24]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'AMD Ryzen 9 7950X': Object.freeze({
        model: 'AMD Ryzen 9 7950X',
        vendor: 'amd',
        physicalCores: 16,
        threads: 32,
        allowedThreads: Object.freeze([16, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192
    }),
    'AMD Ryzen 9 9950X': Object.freeze({
        model: 'AMD Ryzen 9 9950X',
        vendor: 'amd',
        physicalCores: 16,
        threads: 32,
        allowedThreads: Object.freeze([16, 32]),
        allowedRamGb: Object.freeze([32, 64, 96, 128, 192]),
        maxRamGb: 192
    })
});

/**
 * Authoritative GPU SKU Catalog (NVIDIA GeForce, AMD Radeon, Intel UHD/Iris/Arc).
 */
export const PC_GPU_SKU_CATALOG = Object.freeze([
    Object.freeze({
        id: 'NVIDIA GeForce RTX 4090',
        pattern: /RTX\s*4090/i,
        vendor: 'nvidia',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        id: 'NVIDIA GeForce RTX 2060',
        pattern: /RTX\s*2060/i,
        vendor: 'nvidia',
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
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
        angleVendor: 'NVIDIA',
        isIntegrated: false,
        vramGb: Object.freeze([4]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([32768, 32768])
        })
    }),
    Object.freeze({
        id: 'AMD Radeon RX 6000/7000 Discrete',
        pattern: /Radeon\s+RX\s+(6[6-9]\d0|7[6-9]\d0)/i,
        vendor: 'amd',
        angleVendor: 'AMD',
        isIntegrated: false,
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
        id: 'AMD Radeon Integrated APU',
        pattern: /Radeon\(TM\)\s+Graphics|Radeon\s+(680M|780M|890M|Vega)/i,
        vendor: 'amd',
        angleVendor: 'AMD',
        isIntegrated: true,
        cpuVendorLock: 'amd',
        vramGb: Object.freeze([1, 2, 4, 8]),
        osSupport: Object.freeze(['win', 'lin']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    }),
    Object.freeze({
        id: 'Intel Integrated UHD / Iris Xe Graphics',
        pattern: /Intel\(R\)\s+(UHD|Iris|HD)\s+Graphics/i,
        vendor: 'intel',
        angleVendor: 'Intel',
        isIntegrated: true,
        cpuVendorLock: 'intel',
        vramGb: Object.freeze([1, 2, 4]),
        osSupport: Object.freeze(['win', 'lin', 'mac']),
        webglLimits: Object.freeze({
            maxTextureSize: 16384,
            maxCubeMapTextureSize: 16384,
            maxRenderbufferSize: 16384,
            maxViewportDims: Object.freeze([16384, 16384])
        })
    })
]);

export const STANDARD_PC_RAM_GB_TIERS = Object.freeze([4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256]);
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
    const match = text.match(/\bApple\s+(M[1-4](?:\s+(?:Pro|Max|Ultra))?)\b/i);
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
 * Look up a PC CPU SKU by model name (case-insensitive substring or exact match).
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
    for (const [key, spec] of Object.entries(PC_CPU_SKU_CATALOG)) {
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
 * Validate exact hardware SKU & device model parameters across CPU, GPU, RAM, Disk/Storage,
 * Display Panel Form-Factor, Windows ANGLE Vendor/Shader Model, and WebGL Hardware Limits.
 *
 * @param {object} telemetry Browser telemetry object (with `.navigator`, `.webgl`, `.screen`, and optional `.hardwareProfile` / `.storageEstimate`)
 * @param {string | null} [targetOs] Normalized target OS (`'win'` | `'mac'` | `'lin'`)
 * @returns {{
 *   passed: boolean,
 *   matchedSku: string | null,
 *   issues: string[]
 * }}
 */
export function validateHardwareModelSpec(telemetry, targetOs = null) {
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

    const renderer = String(webgl.unmaskedRenderer || '').trim();
    const vendor = String(webgl.unmaskedVendor || '').trim();
    const cores = Number(nav.hardwareConcurrency);
    const panelKey =
        Number.isFinite(scr.width) && Number.isFinite(scr.height)
            ? `${scr.width}x${scr.height}`
            : null;

    const cpuModel = hw.cpuModel ? String(hw.cpuModel).trim() : null;
    const gpuModel = hw.gpuModel ? String(hw.gpuModel).trim() : null;
    const ramGb =
        hw.ramGb !== undefined && hw.ramGb !== null ? Number(hw.ramGb) : null;
    const storageGb =
        hw.storageGb !== undefined && hw.storageGb !== null ? Number(hw.storageGb) : null;

    const gpuAppleSkuName = parseAppleSiliconSkuName(renderer);
    const cpuAppleSkuName = parseAppleSiliconSkuName(cpuModel);
    const explicitGpuAppleSkuName = parseAppleSiliconSkuName(gpuModel);

    let matchedSku = gpuAppleSkuName || cpuAppleSkuName || null;

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
    }

    // =========================================================================
    // Rule B, C, D, E: Exact Apple Silicon SKU Parameter Validation
    // =========================================================================
    const activeAppleSkuName = gpuAppleSkuName || cpuAppleSkuName;
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
    }

    // =========================================================================
    // Rule F: PC (Intel / AMD) CPU Model vs Threads, RAM Ceiling & Integrated GPU Lockstep
    // =========================================================================
    const pcCpuSku = lookupPcCpuSku(cpuModel);
    const pcGpuSku = lookupPcGpuSku(renderer);
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
            if (!Number.isFinite(ramGb) || ramGb > pcCpuSku.maxRamGb || !STANDARD_PC_RAM_GB_TIERS.includes(ramGb)) {
                issues.push(
                    `CPU SKU "${pcCpuSku.model}" RAM capacity violation: ramGb=${ramGb}GB exceeds ${pcCpuSku.maxRamGb}GB hardware ceiling or is not a valid DIMM tier`
                );
            }
        }
    } else if (!activeAppleSkuName && cpuModel) {
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

    if (pcCpuSku && pcGpuSku?.isIntegrated && pcGpuSku.cpuVendorLock && pcCpuSku.vendor !== pcGpuSku.cpuVendorLock) {
        issues.push(
            `CPU SKU "${pcCpuSku.model}" (${pcCpuSku.vendor.toUpperCase()}) cannot pair with integrated ${pcGpuSku.vendor.toUpperCase()} iGPU "${renderer}"`
        );
    }

    // Generic PC RAM & Storage validation when no Apple Silicon SKU is active
    if (!activeAppleSkuName) {
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
    }

    // =========================================================================
    // Rule H: GPU Model WebGL Parameter Limits Coherence
    // =========================================================================
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
    PC_CPU_SKU_CATALOG,
    PC_GPU_SKU_CATALOG,
    STANDARD_PC_RAM_GB_TIERS,
    STANDARD_PC_STORAGE_GB_TIERS,
    parseAppleSiliconSkuName,
    lookupPcCpuSku,
    lookupPcGpuSku,
    validateHardwareModelSpec
};
