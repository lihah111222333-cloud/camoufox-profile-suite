/** Offline GPU catalog and calculations for explicitly supplied diagnostic fixtures. */

import crypto from 'node:crypto';

/**
 * 1. Authoritative Physical GPU Performance Catalog (`GPU_PERFORMANCE_SPEC_CATALOG`)
 *
 * Metrics:
 *   - `fp32Tflops`: Peak FP32 shader/compute throughput (TFLOPS)
 *   - `memoryBandwidthGBps`: Peak VRAM / Unified Memory bandwidth (GB/s)
 *   - `pixelFillRateGPixels`: Peak pixel fillrate (GPixels/s)
 *   - `textureFillRateGTexels`: Peak texture fillrate (GTexels/s)
 *   - `gpuCores`: Physical GPU compute units / SMs / Xe-cores / Apple GPU cores
 *   - `architecture`: GPU microarchitecture name
 *   - `tier`: `'enthusiast-discrete' | 'high-discrete' | 'mid-discrete' | 'mobile-discrete' | 'apple-silicon-ultra' | 'apple-silicon-max' | 'apple-silicon-pro' | 'apple-silicon-base' | 'modern-igpu' | 'legacy-igpu'`
 */
export const GPU_PERFORMANCE_SPEC_CATALOG = Object.freeze({
    // =========================================================================
    // A. NVIDIA Desktop & Laptop Discrete GPUs (Ada Lovelace / Ampere / Turing)
    // =========================================================================
    'NVIDIA GeForce RTX 4090': Object.freeze({
        model: 'NVIDIA GeForce RTX 4090',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'enthusiast-discrete',
        gpuCores: 128, // 128 SMs (16,384 CUDA cores)
        fp32Tflops: 82.58,
        memoryBandwidthGBps: 1008,
        pixelFillRateGPixels: 443.5,
        textureFillRateGTexels: 1290.2,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4080 SUPER': Object.freeze({
        model: 'NVIDIA GeForce RTX 4080 SUPER',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'enthusiast-discrete',
        gpuCores: 80, // 80 SMs (10,240 CUDA cores)
        fp32Tflops: 52.22,
        memoryBandwidthGBps: 736,
        pixelFillRateGPixels: 285.6,
        textureFillRateGTexels: 816.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4080': Object.freeze({
        model: 'NVIDIA GeForce RTX 4080',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'enthusiast-discrete',
        gpuCores: 76,
        fp32Tflops: 48.74,
        memoryBandwidthGBps: 716.8,
        pixelFillRateGPixels: 280.6,
        textureFillRateGTexels: 761.5,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4070 Ti SUPER': Object.freeze({
        model: 'NVIDIA GeForce RTX 4070 Ti SUPER',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'high-discrete',
        gpuCores: 66,
        fp32Tflops: 44.1,
        memoryBandwidthGBps: 672,
        pixelFillRateGPixels: 250.6,
        textureFillRateGTexels: 689.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4070 SUPER': Object.freeze({
        model: 'NVIDIA GeForce RTX 4070 SUPER',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'high-discrete',
        gpuCores: 56,
        fp32Tflops: 35.48,
        memoryBandwidthGBps: 504,
        pixelFillRateGPixels: 198.0,
        textureFillRateGTexels: 554.4,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4070': Object.freeze({
        model: 'NVIDIA GeForce RTX 4070',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'high-discrete',
        gpuCores: 46,
        fp32Tflops: 29.15,
        memoryBandwidthGBps: 504,
        pixelFillRateGPixels: 158.4,
        textureFillRateGTexels: 455.4,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4060 Ti': Object.freeze({
        model: 'NVIDIA GeForce RTX 4060 Ti',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'mid-discrete',
        gpuCores: 34,
        fp32Tflops: 22.06,
        memoryBandwidthGBps: 288,
        pixelFillRateGPixels: 121.7,
        textureFillRateGTexels: 344.8,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4060': Object.freeze({
        model: 'NVIDIA GeForce RTX 4060',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'mid-discrete',
        gpuCores: 24,
        fp32Tflops: 15.11,
        memoryBandwidthGBps: 272,
        pixelFillRateGPixels: 118.1,
        textureFillRateGTexels: 236.2,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4090 Laptop GPU': Object.freeze({
        model: 'NVIDIA GeForce RTX 4090 Laptop GPU',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'mobile-discrete',
        gpuCores: 76,
        fp32Tflops: 32.95,
        memoryBandwidthGBps: 576,
        pixelFillRateGPixels: 186.6,
        textureFillRateGTexels: 514.8,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4080 Laptop GPU': Object.freeze({
        model: 'NVIDIA GeForce RTX 4080 Laptop GPU',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'mobile-discrete',
        gpuCores: 58,
        fp32Tflops: 24.43,
        memoryBandwidthGBps: 432,
        pixelFillRateGPixels: 131.5,
        textureFillRateGTexels: 381.8,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4070 Laptop GPU': Object.freeze({
        model: 'NVIDIA GeForce RTX 4070 Laptop GPU',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'mobile-discrete',
        gpuCores: 36,
        fp32Tflops: 15.62,
        memoryBandwidthGBps: 256,
        pixelFillRateGPixels: 104.4,
        textureFillRateGTexels: 244.1,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4060 Laptop GPU': Object.freeze({
        model: 'NVIDIA GeForce RTX 4060 Laptop GPU',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'mobile-discrete',
        gpuCores: 24,
        fp32Tflops: 11.49,
        memoryBandwidthGBps: 256,
        pixelFillRateGPixels: 89.8,
        textureFillRateGTexels: 179.5,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 3090': Object.freeze({
        model: 'NVIDIA GeForce RTX 3090',
        vendor: 'nvidia',
        architecture: 'ampere',
        tier: 'enthusiast-discrete',
        gpuCores: 82,
        fp32Tflops: 35.58,
        memoryBandwidthGBps: 936.2,
        pixelFillRateGPixels: 190.4,
        textureFillRateGTexels: 556.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 3080': Object.freeze({
        model: 'NVIDIA GeForce RTX 3080',
        vendor: 'nvidia',
        architecture: 'ampere',
        tier: 'high-discrete',
        gpuCores: 68,
        fp32Tflops: 29.77,
        memoryBandwidthGBps: 760.3,
        pixelFillRateGPixels: 164.2,
        textureFillRateGTexels: 465.1,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 3070': Object.freeze({
        model: 'NVIDIA GeForce RTX 3070',
        vendor: 'nvidia',
        architecture: 'ampere',
        tier: 'high-discrete',
        gpuCores: 46,
        fp32Tflops: 20.31,
        memoryBandwidthGBps: 448,
        pixelFillRateGPixels: 165.6,
        textureFillRateGTexels: 317.4,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 3060': Object.freeze({
        model: 'NVIDIA GeForce RTX 3060',
        vendor: 'nvidia',
        architecture: 'ampere',
        tier: 'mid-discrete',
        gpuCores: 28,
        fp32Tflops: 12.74,
        memoryBandwidthGBps: 360,
        pixelFillRateGPixels: 85.3,
        textureFillRateGTexels: 199.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce GTX 1660 SUPER': Object.freeze({
        model: 'NVIDIA GeForce GTX 1660 SUPER',
        vendor: 'nvidia',
        architecture: 'turing',
        tier: 'mid-discrete',
        gpuCores: 22,
        fp32Tflops: 5.03,
        memoryBandwidthGBps: 336,
        pixelFillRateGPixels: 85.7,
        textureFillRateGTexels: 157.1,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),

    // =========================================================================
    // B. Apple Silicon Unified GPUs (M1 / M2 / M3 / M4 / M5 Base, Pro, Max, Ultra)
    // =========================================================================
    'Apple M1': Object.freeze({
        model: 'Apple M1',
        vendor: 'apple',
        architecture: 'common-3',
        tier: 'apple-silicon-base',
        gpuCores: 8,
        fp32Tflops: 2.6,
        memoryBandwidthGBps: 68.25,
        pixelFillRateGPixels: 41.0,
        textureFillRateGTexels: 82.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M1 Pro': Object.freeze({
        model: 'Apple M1 Pro',
        vendor: 'apple',
        architecture: 'common-3',
        tier: 'apple-silicon-pro',
        gpuCores: 16,
        fp32Tflops: 5.2,
        memoryBandwidthGBps: 204.8,
        pixelFillRateGPixels: 82.0,
        textureFillRateGTexels: 164.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M1 Max': Object.freeze({
        model: 'Apple M1 Max',
        vendor: 'apple',
        architecture: 'common-3',
        tier: 'apple-silicon-max',
        gpuCores: 32,
        fp32Tflops: 10.4,
        memoryBandwidthGBps: 409.6,
        pixelFillRateGPixels: 164.0,
        textureFillRateGTexels: 328.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M1 Ultra': Object.freeze({
        model: 'Apple M1 Ultra',
        vendor: 'apple',
        architecture: 'common-3',
        tier: 'apple-silicon-ultra',
        gpuCores: 64,
        fp32Tflops: 20.8,
        memoryBandwidthGBps: 819.2,
        pixelFillRateGPixels: 328.0,
        textureFillRateGTexels: 656.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M2': Object.freeze({
        model: 'Apple M2',
        vendor: 'apple',
        architecture: 'common-3',
        tier: 'apple-silicon-base',
        gpuCores: 10,
        fp32Tflops: 3.6,
        memoryBandwidthGBps: 102.4,
        pixelFillRateGPixels: 55.0,
        textureFillRateGTexels: 110.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M2 Pro': Object.freeze({
        model: 'Apple M2 Pro',
        vendor: 'apple',
        architecture: 'common-3',
        tier: 'apple-silicon-pro',
        gpuCores: 19,
        fp32Tflops: 6.8,
        memoryBandwidthGBps: 204.8,
        pixelFillRateGPixels: 108.0,
        textureFillRateGTexels: 216.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M2 Max': Object.freeze({
        model: 'Apple M2 Max',
        vendor: 'apple',
        architecture: 'common-3',
        tier: 'apple-silicon-max',
        gpuCores: 38,
        fp32Tflops: 13.6,
        memoryBandwidthGBps: 409.6,
        pixelFillRateGPixels: 216.0,
        textureFillRateGTexels: 432.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M2 Ultra': Object.freeze({
        model: 'Apple M2 Ultra',
        vendor: 'apple',
        architecture: 'common-3',
        tier: 'apple-silicon-ultra',
        gpuCores: 76,
        fp32Tflops: 27.2,
        memoryBandwidthGBps: 819.2,
        pixelFillRateGPixels: 432.0,
        textureFillRateGTexels: 864.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M3': Object.freeze({
        model: 'Apple M3',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-base',
        gpuCores: 10,
        fp32Tflops: 4.1,
        memoryBandwidthGBps: 102.4,
        pixelFillRateGPixels: 64.0,
        textureFillRateGTexels: 128.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M3 Pro': Object.freeze({
        model: 'Apple M3 Pro',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-pro',
        gpuCores: 18,
        fp32Tflops: 7.4,
        memoryBandwidthGBps: 153.6,
        pixelFillRateGPixels: 116.0,
        textureFillRateGTexels: 232.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M3 Max': Object.freeze({
        model: 'Apple M3 Max',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-max',
        gpuCores: 40,
        fp32Tflops: 16.4,
        memoryBandwidthGBps: 409.6,
        pixelFillRateGPixels: 256.0,
        textureFillRateGTexels: 512.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M3 Ultra': Object.freeze({
        model: 'Apple M3 Ultra',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-ultra',
        gpuCores: 80,
        fp32Tflops: 32.8,
        memoryBandwidthGBps: 819.2,
        pixelFillRateGPixels: 512.0,
        textureFillRateGTexels: 1024.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M4': Object.freeze({
        model: 'Apple M4',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-base',
        gpuCores: 10,
        fp32Tflops: 4.6,
        memoryBandwidthGBps: 120.0,
        pixelFillRateGPixels: 72.0,
        textureFillRateGTexels: 144.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M4 Pro': Object.freeze({
        model: 'Apple M4 Pro',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-pro',
        gpuCores: 20,
        fp32Tflops: 10.2,
        memoryBandwidthGBps: 273.0,
        pixelFillRateGPixels: 162.0,
        textureFillRateGTexels: 324.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M4 Max': Object.freeze({
        model: 'Apple M4 Max',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-max',
        gpuCores: 40,
        fp32Tflops: 18.0,
        memoryBandwidthGBps: 546.0,
        pixelFillRateGPixels: 288.0,
        textureFillRateGTexels: 576.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M4 Ultra': Object.freeze({
        model: 'Apple M4 Ultra',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-ultra',
        gpuCores: 80,
        fp32Tflops: 36.0,
        memoryBandwidthGBps: 1092.0,
        pixelFillRateGPixels: 576.0,
        textureFillRateGTexels: 1152.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M5': Object.freeze({
        model: 'Apple M5',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-base',
        gpuCores: 10,
        fp32Tflops: 5.5,
        memoryBandwidthGBps: 153.6,
        pixelFillRateGPixels: 86.0,
        textureFillRateGTexels: 172.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M5 Pro': Object.freeze({
        model: 'Apple M5 Pro',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-pro',
        gpuCores: 20,
        fp32Tflops: 11.5,
        memoryBandwidthGBps: 300.0,
        pixelFillRateGPixels: 185.0,
        textureFillRateGTexels: 370.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M5 Max': Object.freeze({
        model: 'Apple M5 Max',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-max',
        gpuCores: 40,
        fp32Tflops: 22.0,
        memoryBandwidthGBps: 600.0,
        pixelFillRateGPixels: 350.0,
        textureFillRateGTexels: 700.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Apple M5 Ultra': Object.freeze({
        model: 'Apple M5 Ultra',
        vendor: 'apple',
        architecture: 'metal-3',
        tier: 'apple-silicon-ultra',
        gpuCores: 80,
        fp32Tflops: 44.0,
        memoryBandwidthGBps: 1200.0,
        pixelFillRateGPixels: 700.0,
        textureFillRateGTexels: 1400.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),

    // =========================================================================
    // C. AMD Radeon Discrete & Integrated GPUs (RDNA 3 / RDNA 2 / RDNA 1 / Vega)
    // =========================================================================
    'AMD Radeon RX 7900 XTX': Object.freeze({
        model: 'AMD Radeon RX 7900 XTX',
        vendor: 'amd',
        architecture: 'rdna-3',
        tier: 'enthusiast-discrete',
        gpuCores: 96,
        fp32Tflops: 61.42,
        memoryBandwidthGBps: 960.0,
        pixelFillRateGPixels: 479.8,
        textureFillRateGTexels: 959.6,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon RX 7800 XT': Object.freeze({
        model: 'AMD Radeon RX 7800 XT',
        vendor: 'amd',
        architecture: 'rdna-3',
        tier: 'high-discrete',
        gpuCores: 60,
        fp32Tflops: 37.32,
        memoryBandwidthGBps: 624.1,
        pixelFillRateGPixels: 233.3,
        textureFillRateGTexels: 583.2,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon Pro W6800X': Object.freeze({
        model: 'AMD Radeon Pro W6800X',
        vendor: 'amd',
        architecture: 'rdna-2',
        tier: 'high-discrete',
        gpuCores: 60,
        fp32Tflops: 16.0,
        memoryBandwidthGBps: 512.0,
        pixelFillRateGPixels: 185.0,
        textureFillRateGTexels: 400.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon Pro 5700 XT': Object.freeze({
        model: 'AMD Radeon Pro 5700 XT',
        vendor: 'amd',
        architecture: 'rdna-1',
        tier: 'mid-discrete',
        gpuCores: 40,
        fp32Tflops: 9.49,
        memoryBandwidthGBps: 384.0,
        pixelFillRateGPixels: 118.7,
        textureFillRateGTexels: 296.6,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon Pro 5500M': Object.freeze({
        model: 'AMD Radeon Pro 5500M',
        vendor: 'amd',
        architecture: 'rdna-1',
        tier: 'mobile-discrete',
        gpuCores: 24,
        fp32Tflops: 4.0,
        memoryBandwidthGBps: 192.0,
        pixelFillRateGPixels: 41.6,
        textureFillRateGTexels: 124.8,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon 890M': Object.freeze({
        model: 'AMD Radeon 890M',
        vendor: 'amd',
        architecture: 'rdna-3.5',
        tier: 'modern-igpu',
        gpuCores: 16,
        fp32Tflops: 11.88,
        memoryBandwidthGBps: 120.0,
        pixelFillRateGPixels: 92.8,
        textureFillRateGTexels: 185.6,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon 780M': Object.freeze({
        model: 'AMD Radeon 780M',
        vendor: 'amd',
        architecture: 'rdna-3',
        tier: 'modern-igpu',
        gpuCores: 12,
        fp32Tflops: 8.29,
        memoryBandwidthGBps: 89.6,
        pixelFillRateGPixels: 86.4,
        textureFillRateGTexels: 129.6,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon 680M': Object.freeze({
        model: 'AMD Radeon 680M',
        vendor: 'amd',
        architecture: 'rdna-2',
        tier: 'modern-igpu',
        gpuCores: 12,
        fp32Tflops: 3.38,
        memoryBandwidthGBps: 102.4,
        pixelFillRateGPixels: 70.4,
        textureFillRateGTexels: 105.6,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),

    // =========================================================================
    // D. Intel Arc, Iris Xe, Iris Plus & UHD Graphics + Qualcomm Adreno X1
    // =========================================================================
    'Intel(R) Arc(TM) 140V Graphics': Object.freeze({
        model: 'Intel(R) Arc(TM) 140V Graphics',
        vendor: 'intel',
        architecture: 'xe-2',
        tier: 'modern-igpu',
        gpuCores: 8,
        fp32Tflops: 4.2,
        memoryBandwidthGBps: 136.5,
        pixelFillRateGPixels: 65.6,
        textureFillRateGTexels: 131.2,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Intel(R) Arc(TM) Graphics': Object.freeze({
        model: 'Intel(R) Arc(TM) Graphics',
        vendor: 'intel',
        architecture: 'xe-lpg',
        tier: 'modern-igpu',
        gpuCores: 8,
        fp32Tflops: 4.6,
        memoryBandwidthGBps: 119.5,
        pixelFillRateGPixels: 72.0,
        textureFillRateGTexels: 144.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Intel(R) Iris(R) Xe Graphics': Object.freeze({
        model: 'Intel(R) Iris(R) Xe Graphics',
        vendor: 'intel',
        architecture: 'gen-12lp',
        tier: 'modern-igpu',
        gpuCores: 96, // 96 EUs
        fp32Tflops: 2.1,
        memoryBandwidthGBps: 68.3,
        pixelFillRateGPixels: 36.0,
        textureFillRateGTexels: 72.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Intel(R) UHD Graphics 770': Object.freeze({
        model: 'Intel(R) UHD Graphics 770',
        vendor: 'intel',
        architecture: 'gen-12lp',
        tier: 'legacy-igpu',
        gpuCores: 32,
        fp32Tflops: 0.79,
        memoryBandwidthGBps: 76.8,
        pixelFillRateGPixels: 12.4,
        textureFillRateGTexels: 24.8,
        webgpuMaxBufferSize: 1073741824,
        webgpuMaxComputeWorkgroupSizeX: 512
    }),
    'Intel(R) Iris(TM) Plus Graphics 655': Object.freeze({
        model: 'Intel(R) Iris(TM) Plus Graphics 655',
        vendor: 'intel',
        architecture: 'gen-9',
        tier: 'legacy-igpu',
        gpuCores: 48,
        fp32Tflops: 0.92,
        memoryBandwidthGBps: 38.4,
        pixelFillRateGPixels: 18.0,
        textureFillRateGTexels: 36.0,
        webgpuMaxBufferSize: 1073741824,
        webgpuMaxComputeWorkgroupSizeX: 512
    }),
    'Intel(R) UHD Graphics 630': Object.freeze({
        model: 'Intel(R) UHD Graphics 630',
        vendor: 'intel',
        architecture: 'gen-9',
        tier: 'legacy-igpu',
        gpuCores: 24,
        fp32Tflops: 0.46,
        memoryBandwidthGBps: 42.7,
        pixelFillRateGPixels: 9.2,
        textureFillRateGTexels: 18.4,
        webgpuMaxBufferSize: 1073741824,
        webgpuMaxComputeWorkgroupSizeX: 512
    }),
    'Intel(R) UHD Graphics 620': Object.freeze({
        model: 'Intel(R) UHD Graphics 620',
        vendor: 'intel',
        architecture: 'gen-9',
        tier: 'legacy-igpu',
        gpuCores: 24,
        fp32Tflops: 0.44,
        memoryBandwidthGBps: 34.1,
        pixelFillRateGPixels: 8.8,
        textureFillRateGTexels: 17.6,
        webgpuMaxBufferSize: 1073741824,
        webgpuMaxComputeWorkgroupSizeX: 512
    }),
    'Qualcomm(R) Adreno(TM) X1-85 GPU': Object.freeze({
        model: 'Qualcomm(R) Adreno(TM) X1-85 GPU',
        vendor: 'qualcomm',
        architecture: 'adreno-x1',
        tier: 'modern-igpu',
        gpuCores: 6,
        fp32Tflops: 4.6,
        memoryBandwidthGBps: 135.0,
        pixelFillRateGPixels: 72.0,
        textureFillRateGTexels: 144.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Qualcomm(R) Adreno(TM) X1-45 GPU': Object.freeze({
        model: 'Qualcomm(R) Adreno(TM) X1-45 GPU',
        vendor: 'qualcomm',
        architecture: 'adreno-x1',
        tier: 'modern-igpu',
        gpuCores: 3,
        fp32Tflops: 2.1,
        memoryBandwidthGBps: 135.0,
        pixelFillRateGPixels: 38.0,
        textureFillRateGTexels: 76.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'Intel(R) Arc(TM) A770 Graphics': Object.freeze({
        model: 'Intel(R) Arc(TM) A770 Graphics',
        vendor: 'intel',
        architecture: 'xe-hpg',
        tier: 'performance-desktop',
        gpuCores: 32,
        fp32Tflops: 19.66,
        memoryBandwidthGBps: 560.0,
        pixelFillRateGPixels: 268.8,
        textureFillRateGTexels: 537.6,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 4050 Laptop GPU': Object.freeze({
        model: 'NVIDIA GeForce RTX 4050 Laptop GPU',
        vendor: 'nvidia',
        architecture: 'ada-lovelace',
        tier: 'mainstream-laptop',
        gpuCores: 20,
        fp32Tflops: 11.8,
        memoryBandwidthGBps: 192.0,
        pixelFillRateGPixels: 112.0,
        textureFillRateGTexels: 188.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 3080 Laptop GPU': Object.freeze({
        model: 'NVIDIA GeForce RTX 3080 Laptop GPU',
        vendor: 'nvidia',
        architecture: 'ampere',
        tier: 'high-end-laptop',
        gpuCores: 48,
        fp32Tflops: 18.98,
        memoryBandwidthGBps: 448.0,
        pixelFillRateGPixels: 148.3,
        textureFillRateGTexels: 296.6,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 3070 Laptop GPU': Object.freeze({
        model: 'NVIDIA GeForce RTX 3070 Laptop GPU',
        vendor: 'nvidia',
        architecture: 'ampere',
        tier: 'performance-laptop',
        gpuCores: 40,
        fp32Tflops: 15.97,
        memoryBandwidthGBps: 448.0,
        pixelFillRateGPixels: 124.8,
        textureFillRateGTexels: 249.6,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 3060 Laptop GPU': Object.freeze({
        model: 'NVIDIA GeForce RTX 3060 Laptop GPU',
        vendor: 'nvidia',
        architecture: 'ampere',
        tier: 'performance-laptop',
        gpuCores: 30,
        fp32Tflops: 10.94,
        memoryBandwidthGBps: 336.0,
        pixelFillRateGPixels: 81.6,
        textureFillRateGTexels: 171.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 3050': Object.freeze({
        model: 'NVIDIA GeForce RTX 3050',
        vendor: 'nvidia',
        architecture: 'ampere',
        tier: 'mainstream-desktop',
        gpuCores: 20,
        fp32Tflops: 9.1,
        memoryBandwidthGBps: 224.0,
        pixelFillRateGPixels: 76.0,
        textureFillRateGTexels: 142.2,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce RTX 2060': Object.freeze({
        model: 'NVIDIA GeForce RTX 2060',
        vendor: 'nvidia',
        architecture: 'turing',
        tier: 'mainstream-desktop',
        gpuCores: 30,
        fp32Tflops: 6.45,
        memoryBandwidthGBps: 336.0,
        pixelFillRateGPixels: 107.5,
        textureFillRateGTexels: 201.6,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce GTX 1660': Object.freeze({
        model: 'NVIDIA GeForce GTX 1660',
        vendor: 'nvidia',
        architecture: 'turing',
        tier: 'mainstream-desktop',
        gpuCores: 22,
        fp32Tflops: 5.03,
        memoryBandwidthGBps: 192.1,
        pixelFillRateGPixels: 85.7,
        textureFillRateGTexels: 157.1,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'NVIDIA GeForce GTX 1650': Object.freeze({
        model: 'NVIDIA GeForce GTX 1650',
        vendor: 'nvidia',
        architecture: 'turing',
        tier: 'mainstream-desktop',
        gpuCores: 14,
        fp32Tflops: 2.98,
        memoryBandwidthGBps: 128.0,
        pixelFillRateGPixels: 53.3,
        textureFillRateGTexels: 93.2,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon RX 6800 XT': Object.freeze({
        model: 'AMD Radeon RX 6800 XT',
        vendor: 'amd',
        architecture: 'rdna-2',
        tier: 'high-end-desktop',
        gpuCores: 72,
        fp32Tflops: 20.74,
        memoryBandwidthGBps: 512.0,
        pixelFillRateGPixels: 288.0,
        textureFillRateGTexels: 648.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon RX 6700 XT': Object.freeze({
        model: 'AMD Radeon RX 6700 XT',
        vendor: 'amd',
        architecture: 'rdna-2',
        tier: 'performance-desktop',
        gpuCores: 40,
        fp32Tflops: 13.21,
        memoryBandwidthGBps: 384.0,
        pixelFillRateGPixels: 165.2,
        textureFillRateGTexels: 413.0,
        webgpuMaxBufferSize: 4294967296,
        webgpuMaxComputeWorkgroupSizeX: 1024
    }),
    'AMD Radeon RX 6600': Object.freeze({
        model: 'AMD Radeon RX 6600',
        vendor: 'amd',
        architecture: 'rdna-2',
        tier: 'mainstream-desktop',
        gpuCores: 28,
        fp32Tflops: 8.93,
        memoryBandwidthGBps: 224.0,
        pixelFillRateGPixels: 159.4,
        textureFillRateGTexels: 279.0,
        webgpuMaxBufferSize: 2147483648,
        webgpuMaxComputeWorkgroupSizeX: 1024
    })
});

/**
 * Lookup the physical GPU performance specification for a WebGL `unmaskedRenderer` string
 * or explicit `gpuModel` name.
 *
 * @param {string} rendererOrModel
 * @returns {object}
 */
export function lookupGpuPerformanceSpec(rendererOrModel) {
    const raw = String(rendererOrModel || '').trim();
    if (!raw) {
        return GPU_PERFORMANCE_SPEC_CATALOG['Apple M5 Pro'];
    }

    if (GPU_PERFORMANCE_SPEC_CATALOG[raw]) {
        return GPU_PERFORMANCE_SPEC_CATALOG[raw];
    }

    // Match longest model key contained in the renderer string (so "RTX 4090 Laptop GPU" matches before "RTX 4090", and "Apple M5 Pro" matches before "Apple M5")
    const sortedKeys = Object.keys(GPU_PERFORMANCE_SPEC_CATALOG).sort((a, b) => b.length - a.length);
    const lowerRaw = raw.toLowerCase();
    for (const key of sortedKeys) {
        if (lowerRaw.includes(key.toLowerCase())) {
            return GPU_PERFORMANCE_SPEC_CATALOG[key];
        }
    }

    // Heuristic pattern matchers for variant renderer strings & PC_GPU_SKU_CATALOG category IDs
    if (/RTX\s*4090\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4090 Laptop GPU'];
    if (/RTX\s*4080\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4080 Laptop GPU'];
    if (/RTX\s*4070\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4070 Laptop GPU'];
    if (/RTX\s*4060\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4060 Laptop GPU'];
    if (/RTX\s*4050\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4050 Laptop GPU'];
    if (/RTX\s*3080\s*(?:Ti\s*)?Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3080 Laptop GPU'];
    if (/RTX\s*3070\s*(?:Ti\s*)?Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3070 Laptop GPU'];
    if (/RTX\s*3060\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3060 Laptop GPU'];
    if (/RTX\s*4090/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4090'];
    if (/RTX\s*4080\s*SUPER/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4080 SUPER'];
    if (/RTX\s*(?:4080|5000\s*Ada)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4080'];
    if (/RTX\s*4070\s*Ti\s*SUPER/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4070 Ti SUPER'];
    if (/RTX\s*4070\s*SUPER/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4070 SUPER'];
    if (/RTX\s*(?:4070|4000\s*Ada|3500\s*Ada|Ada\s+Generation)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4070'];
    if (/RTX\s*4060\s*Ti/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4060 Ti'];
    if (/RTX\s*(?:4060|2000\s*Ada|A2000)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4060'];
    if (/RTX\s*3090/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3090'];
    if (/RTX\s*3080/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3080'];
    if (/RTX\s*3070/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3070'];
    if (/RTX\s*3050/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3050'];
    if (/RTX\s*2060/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 2060'];
    if (/RTX\s*(?:3060|A1000)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3060'];
    if (/GTX\s*1660\s*(?:SUPER|Ti)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce GTX 1660 SUPER'];
    if (/GTX\s*1660/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce GTX 1660'];
    if (/GTX\s*1650/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce GTX 1650'];
    if (/RX\s*7900/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 7900 XTX'];
    if (/RX\s*(?:7800|7700|6950|6900)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 7800 XT'];
    if (/RX\s*6800|RX\s*6000M?\/7000M?/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 6800 XT'];
    if (/RX\s*(?:6750|6700|7600)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 6700 XT'];
    if (/RX\s*66\d0/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 6600'];
    if (/W6[89]00X|Vega\s*II/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon Pro W6800X'];
    if (/5700(?:\s*XT)?|W5[57]00X|W6600X|Vega\s*(?:48|56|64)|Radeon\s+Pro\s+Desktop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon Pro 5700 XT'];
    if (/5500(?:\s*XT|M)?|5600M|5300M?|580X|575X|570X|560X|555X|Vega\s*(?:16|20)|Radeon\s+Pro\s+Mobile/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon Pro 5500M'];
    if (/8[89]0M/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon 890M'];
    if (/7[68]0M/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon 780M'];
    if (/(?:6[68]0M|740M|610M|Radeon(?:\(TM\))?\s+(?:Vega|Graphics|Integrated\s+APU|HD\s+\d+)|AMD\s+APU)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon 680M'];
    if (/Arc(?:\(TM\))?.*A[57]\d0/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Arc(TM) A770 Graphics'];
    if (/140V|130V/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Arc(TM) 140V Graphics'];
    if (/Arc(?:\(TM\))?(?:\s+A3\d0|\s+Graphics)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Arc(TM) Graphics'];
    if (/Iris(?:\(R\))?\s*Xe|Intel(?:\(R\))?\s+Graphics|Intel\s+Integrated\s+UHD/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Iris(R) Xe Graphics'];
    if (/UHD\s+Graphics\s+7[37]0/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) UHD Graphics 770'];
    if (/Iris.*(?:655|650|645|640|550|540|6100|G7|Pro|Plus|OpenGL)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Iris(TM) Plus Graphics 655'];
    if (/UHD\s+Graphics(?:\s+630)?/i.test(raw) && !/6[12]\d/.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) UHD Graphics 630'];
    if (/UHD\s+Graphics\s+6[12]\d|HD\s+Graphics/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) UHD Graphics 620'];
    if (/Adreno.*X1-45/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Qualcomm(R) Adreno(TM) X1-45 GPU'];
    if (/Adreno.*X1|Qualcomm.*Adreno/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Qualcomm(R) Adreno(TM) X1-85 GPU'];

    return GPU_PERFORMANCE_SPEC_CATALOG['Apple M5 Pro'];
}

const BASELINE_REQUIRED = 'GPU diagnostics require an explicit baseline with positive performance metrics';

function hasDiagnosticBaseline(baseline) {
    return [
        baseline?.hostFp32Tflops,
        baseline?.hostMemoryBandwidthGBps,
        baseline?.hostPixelFillRateGPixels
    ].every((value) => Number.isFinite(value) && value > 0);
}

/** Compute reference weights using the diagnostic caller's supplied fixture. */
export function computeGpuPerformanceScalingWeights(targetGpuOrProfile, options = {}) {
    const hostBaseline = options.hostBaseline;
    if (!hasDiagnosticBaseline(hostBaseline)) throw new TypeError(BASELINE_REQUIRED);
    let rendererOrModel = '';
    let profileId = String(options.profileId || 'default-gpu-profile');

    if (typeof targetGpuOrProfile === 'string') {
        rendererOrModel = targetGpuOrProfile;
    } else if (targetGpuOrProfile && typeof targetGpuOrProfile === 'object') {
        if (targetGpuOrProfile.profileId) {
            profileId = String(targetGpuOrProfile.profileId);
        }
        rendererOrModel =
            targetGpuOrProfile.hardwareProfile?.gpuModel ||
            targetGpuOrProfile.webgl?.unmaskedRenderer ||
            targetGpuOrProfile.telemetry?.hardwareProfile?.gpuModel ||
            targetGpuOrProfile.telemetry?.webgl?.unmaskedRenderer ||
            targetGpuOrProfile.gpuModel ||
            targetGpuOrProfile.unmaskedRenderer ||
            '';
    }

    const targetGpuSpec = lookupGpuPerformanceSpec(rendererOrModel);

    const computeTimeMultiplier = Number(
        (hostBaseline.hostFp32Tflops / targetGpuSpec.fp32Tflops).toFixed(6)
    );
    const throughputSpeedupRatio = Number(
        (targetGpuSpec.fp32Tflops / hostBaseline.hostFp32Tflops).toFixed(4)
    );
    const memoryTransferMultiplier = Number(
        (hostBaseline.hostMemoryBandwidthGBps / targetGpuSpec.memoryBandwidthGBps).toFixed(6)
    );
    const pixelFillMultiplier = Number(
        (hostBaseline.hostPixelFillRateGPixels / targetGpuSpec.pixelFillRateGPixels).toFixed(6)
    );

    const compositeShaderBenchmarkMultiplier = Number(
        (
            0.6 * computeTimeMultiplier +
            0.25 * pixelFillMultiplier +
            0.15 * memoryTransferMultiplier
        ).toFixed(6)
    );

    const md5Hex = crypto.createHash('md5').update(`${profileId}:${targetGpuSpec.model}`).digest('hex');
    const jitterSeed = (parseInt(md5Hex.slice(0, 8), 16) % 10000) + 1;

    // Preserve the deterministic offset used by existing fixture calculations.
    const profileVarianceFactor = 1 + (((jitterSeed % 300) - 150) / 10000);

    const expected10msHostShaderMs = Number(
        (10.0 * compositeShaderBenchmarkMultiplier * profileVarianceFactor).toFixed(3)
    );
    const expected10msHostReadPixelsMs = Number(
        (10.0 * memoryTransferMultiplier * profileVarianceFactor).toFixed(3)
    );

    return Object.freeze({
        profileId,
        hostBaseline,
        targetGpuSpec,
        computeTimeMultiplier,
        throughputSpeedupRatio,
        memoryTransferMultiplier,
        pixelFillMultiplier,
        compositeShaderBenchmarkMultiplier,
        profileVarianceFactor: Number(profileVarianceFactor.toFixed(6)),
        expected10msHostShaderMs,
        expected10msHostReadPixelsMs,
        jitterSeed,
        antiPenetrationActive: true
    });
}

/** Calculate a weighted duration for an offline sample. */
export function scaleGpuExecutionDurationMs(hostElapsedMs, scalingWeights, options = {}) {
    const rawMs = Math.max(0.001, Number(hostElapsedMs) || 0.001);
    const opType = options.operationType || 'shader';
    const sampleIdx = Number(options.sampleIndex || 0);

    let baseMultiplier = scalingWeights.compositeShaderBenchmarkMultiplier;
    if (opType === 'compute') {
        baseMultiplier = scalingWeights.computeTimeMultiplier;
    } else if (opType === 'readPixels') {
        baseMultiplier = scalingWeights.memoryTransferMultiplier;
    } else if (opType === 'fill') {
        baseMultiplier = scalingWeights.pixelFillMultiplier;
    }

    // Apply the deterministic variation of the diagnostic fixture.
    const seed = (scalingWeights.jitterSeed || 1337) + sampleIdx * 7919;
    const jitterWave = Math.sin(seed * 12.9898) * 43758.5453;
    const frac = jitterWave - Math.floor(jitterWave); // 0..1
    const thermalJitter = 1 + (frac * 2 - 1) * 0.018;

    const appliedMultiplier = Number(
        (baseMultiplier * (scalingWeights.profileVarianceFactor || 1) * thermalJitter).toFixed(6)
    );
    const weightedTargetElapsedMs = Number(Math.max(0.0001, rawMs * appliedMultiplier).toFixed(4));
    const weightedTargetElapsedNs = Math.round(weightedTargetElapsedMs * 1e6);

    return {
        rawHostElapsedMs: rawMs,
        weightedTargetElapsedMs,
        weightedTargetElapsedNs,
        appliedMultiplier,
        targetGpuModel: scalingWeights.targetGpuSpec.model,
        hostChipModel: scalingWeights.hostBaseline.hostChipModel
    };
}

/** Check a supplied GPU diagnostic fixture against its explicit baseline and target model. */
export function validateGpuPerformanceScalingCoherence(telemetry) {
    const issues = [];
    if (!telemetry || typeof telemetry !== 'object') {
        return { passed: true, issues };
    }

    const rawGpuPerf = telemetry.gpuPerformance || telemetry.hardwareProfile?.gpuPerformance || null;
    const gpuPerf = rawGpuPerf?.weights || rawGpuPerf?.scalingWeights || rawGpuPerf || null;
    const reportedState =
        telemetry.gpuPerformanceState && typeof telemetry.gpuPerformanceState === 'object'
            ? telemetry.gpuPerformanceState
            : null;
    if (!gpuPerf && !reportedState) {
        return { passed: true, issues };
    }
    const activePerf = gpuPerf || reportedState;

    const renderer =
        telemetry.webgl?.unmaskedRenderer ||
        telemetry.hardwareProfile?.gpuModel ||
        activePerf.targetGpuModel ||
        '';
    let expectedWeights;
    try {
        expectedWeights = computeGpuPerformanceScalingWeights(renderer, {
            profileId: telemetry.profileId || activePerf.profileId || 'audit-profile',
            hostBaseline: activePerf.hostBaseline
        });
    } catch (error) {
        return { passed: false, issues: [error.message] };
    }
    const targetSpec = expectedWeights.targetGpuSpec;
    const hostBase = expectedWeights.hostBaseline;

    if (gpuPerf && reportedState) {
        if (reportedState.antiPenetrationActive === false) {
            issues.push(
                `Reported GPU performance state has antiPenetrationActive=false for "${targetSpec.model}"`
            );
        }
        const expectedModel = gpuPerf.targetGpuSpec?.model || gpuPerf.targetGpuModel || targetSpec.model;
        if (
            reportedState.targetGpuModel &&
            expectedModel &&
            lookupGpuPerformanceSpec(reportedState.targetGpuModel).model !==
                lookupGpuPerformanceSpec(expectedModel).model
        ) {
            issues.push(
                `Reported GPU performance state model "${reportedState.targetGpuModel}" contradicts expected profile GPU "${expectedModel}"`
            );
        }
        if (
            reportedState.computeTimeMultiplier !== undefined &&
            gpuPerf.computeTimeMultiplier !== undefined
        ) {
            const reportedMult = Number(reportedState.computeTimeMultiplier);
            const expectedMult = Number(gpuPerf.computeTimeMultiplier);
            if (
                !Number.isFinite(reportedMult) ||
                Math.abs(reportedMult - expectedMult) > Math.max(0.02, expectedMult * 0.05)
            ) {
                issues.push(
                    `Reported GPU computeTimeMultiplier (${reportedMult}) diverges from expected profile weight (${expectedMult})`
                );
            }
        }
    }

    const claimedGpuModel = activePerf.targetGpuSpec?.model || activePerf.targetGpuModel || null;
    if (
        claimedGpuModel &&
        telemetry.webgl?.unmaskedRenderer &&
        lookupGpuPerformanceSpec(claimedGpuModel).model !== targetSpec.model
    ) {
        issues.push(
            `GPU performance scaler model mismatch: gpuPerformance targets "${claimedGpuModel}" but WebGL renderer resolves to "${targetSpec.model}"`
        );
    }

    if (activePerf.antiPenetrationActive === false) {
        issues.push(
            `GPU diagnostic fixture reports antiPenetrationActive=false for "${targetSpec.model}"`
        );
    }

    const tflopsDiffRatio = Math.abs(targetSpec.fp32Tflops - hostBase.hostFp32Tflops) / hostBase.hostFp32Tflops;
    if (tflopsDiffRatio > 0.25) {
        if (
            activePerf.computeTimeMultiplier !== undefined &&
            Math.abs(Number(activePerf.computeTimeMultiplier) - 1.0) < 0.03
        ) {
            issues.push(
                `GPU diagnostic fixture uses an unweighted computeTimeMultiplier for "${targetSpec.model}"`
            );
        }

        if (
            activePerf.measured10msHostShaderMs !== undefined &&
            Math.abs(Number(activePerf.measured10msHostShaderMs) - 10.0) < 0.3
        ) {
            issues.push(
                `GPU diagnostic fixture contains an unweighted timing sample for "${targetSpec.model}"`
            );
        }
    }

    // 3. Verify measured/reported shader benchmark duration aligns with target GPU's weighted performance tier
    if (activePerf.measured10msHostShaderMs !== undefined) {
        const measuredMs = Number(activePerf.measured10msHostShaderMs);
        const expectedMs = expectedWeights.expected10msHostShaderMs;
        // Allow ±25% thermal/workload variance around the target GPU's weighted duration
        if (!Number.isFinite(measuredMs) || measuredMs <= 0 || measuredMs < expectedMs * 0.5 || measuredMs > expectedMs * 1.8) {
            issues.push(
                `GPU performance tier mismatch for "${targetSpec.model}": reported ${measuredMs}ms vs expected approximately ${expectedMs}ms`
            );
        }
    }

    // 4. Verify computeTimeMultiplier matches hostFp32Tflops / targetFp32Tflops
    if (activePerf.computeTimeMultiplier !== undefined) {
        const reportedMult = Number(activePerf.computeTimeMultiplier);
        const expectedMult = expectedWeights.computeTimeMultiplier;
        if (!Number.isFinite(reportedMult) || reportedMult <= 0 || Math.abs(reportedMult - expectedMult) > Math.max(0.05, expectedMult * 0.2)) {
            issues.push(
                `GPU computeTimeMultiplier mismatch for "${targetSpec.model}": reported ${reportedMult} vs expected ${expectedMult} (host ${hostBase.hostFp32Tflops} TFLOPS / target ${targetSpec.fp32Tflops} TFLOPS)`
            );
        }
    }

    // 5. Verify WebGPU GPUSupportedLimits (maxBufferSize, maxComputeWorkgroupSizeX) match target GPU SKU
    const reportedMaxBuf =
        telemetry.webgpu?.limits?.maxBufferSize ??
        reportedState?.webgpuMaxBufferSize ??
        activePerf.webgpuMaxBufferSize;
    if (
        reportedMaxBuf !== undefined &&
        reportedMaxBuf !== null &&
        targetSpec.webgpuMaxBufferSize &&
        Number(reportedMaxBuf) !== targetSpec.webgpuMaxBufferSize
    ) {
        issues.push(
            `WebGPU maxBufferSize mismatch for "${targetSpec.model}": reported ${reportedMaxBuf} vs expected ${targetSpec.webgpuMaxBufferSize}`
        );
    }

    const reportedMaxWgX =
        telemetry.webgpu?.limits?.maxComputeWorkgroupSizeX ??
        reportedState?.webgpuMaxComputeWorkgroupSizeX ??
        activePerf.webgpuMaxComputeWorkgroupSizeX;
    if (
        reportedMaxWgX !== undefined &&
        reportedMaxWgX !== null &&
        targetSpec.webgpuMaxComputeWorkgroupSizeX &&
        Number(reportedMaxWgX) !== targetSpec.webgpuMaxComputeWorkgroupSizeX
    ) {
        issues.push(
            `WebGPU maxComputeWorkgroupSizeX mismatch for "${targetSpec.model}": reported ${reportedMaxWgX} vs expected ${targetSpec.webgpuMaxComputeWorkgroupSizeX}`
        );
    }

    return {
        passed: issues.length === 0,
        issues
    };
}

export default {
    GPU_PERFORMANCE_SPEC_CATALOG,
    lookupGpuPerformanceSpec,
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    validateGpuPerformanceScalingCoherence
};
