/**
 * Host-Calibrated GPU Performance Weighting & Anti-Penetration Engine
 * (`src/camoufox/gpu-performance-scaler.js`)
 *
 * Defends against GPU performance timing side-channel attacks (Google BotGuard, Arkose BDA,
 * CreepJS, FingerprintJS Pro, Picassofp, WebGL/WebGPU compute benchmarks) that measure actual
 * shader/draw/readPixels/WebGPU execution time to pierce through spoofed `UNMASKED_RENDERER_WEBGL`
 * and `GPUAdapterInfo` strings.
 *
 * Core Pipeline:
 *   1. `collectHostMacPerformanceBaseline()`:
 *      Collects the local host Mac's physical hardware specification (`Apple M5 Pro`, 18-core CPU,
 *      20-core GPU, 64GB Unified Memory, Metal 4) and executes a deterministic Float32 matrix/shader
 *      throughput micro-benchmark to calibrate the host baseline (`hostFp32Tflops`, `hostMemoryBandwidthGBps`,
 *      `hostPixelFillRateGPixels`, `hostMeasuredOpsPerMs`).
 *   2. `GPU_PERFORMANCE_SPEC_CATALOG` & `lookupGpuPerformanceSpec(rendererOrModel)`:
 *      Authoritative physical performance catalog for 45+ GPUs across NVIDIA (RTX 4090 / 4080S / 4070S /
 *      4060 / 3090 / 3080 / 3070 / 3060 / GTX 1660S + Laptop GPUs), AMD (RX 7900 XTX / 7800 XT / 6800 XT /
 *      Radeon Pro W6800X / 5700 XT / 5500M / Radeon 890M / 780M / 680M / Vega 8), Intel (Arc A770 /
 *      Arc 140V / Arc Graphics / Iris Xe / UHD 770 / UHD 630 / UHD 620 / Iris Plus 655 / 645 / 540),
 *      Qualcomm (Adreno X1-85 / X1-45), and Apple Silicon (`Apple M1` through `Apple M5 Ultra`).
 *   3. `computeGpuPerformanceScalingWeights(targetGpuOrProfile, options)`:
 *      Computes exact Host-to-Target performance scaling ratios:
 *        - `computeTimeMultiplier = hostFp32Tflops / targetFp32Tflops`
 *          (e.g., Host `Apple M5 Pro` 11.5 TFLOPS -> Target `RTX 4090` 82.58 TFLOPS: multiplier = `0.1393`,
 *           making GPU benchmarks return 7.18x faster RTX 4090 timing instead of leaking host Mac timing;
 *           Target `Intel UHD Graphics 620` 0.44 TFLOPS: multiplier = `26.14`, making GPU benchmarks return
 *           26.1x slower integrated GPU timing!).
 *        - `memoryTransferMultiplier = hostMemoryBandwidthGBps / targetMemoryBandwidthGBps`
 *          (weights `gl.readPixels`, `gl.texImage2D`, `GPUBuffer.mapAsync`).
 *        - `pixelFillMultiplier = hostPixelFillRateGPixels / targetPixelFillRateGPixels`
 *          (weights `gl.drawArrays`, `gl.drawElements`, `canvas.toDataURL`).
 *   4. `scaleGpuExecutionDurationMs(hostElapsedMs, scalingWeights, options)`:
 *      Transforms any raw host Mac GPU execution duration into the target GPU's weighted execution
 *      duration with deterministic per-profile thermal/clock micro-jitter (±1.8%), blocking host
 *      hardware penetration.
 *   5. `buildGpuPerformanceInitScript(scalingWeights)` & `attachGpuPerformanceScalerToContext(context, scalingWeights)`:
 *      Generates an in-browser JS/WebGL/WebGPU performance weighting & virtual GPU clock dilation
 *      init script that hooks:
 *        - `EXT_disjoint_timer_query` & `EXT_disjoint_timer_query_webgl2` (`TIME_ELAPSED_EXT` nanosecond queries)
 *        - `WebGLRenderingContext` & `WebGL2RenderingContext` (`drawArrays`, `drawElements`,
 *          `drawArraysInstanced`, `drawElementsInstanced`, `finish`, `flush`, `readPixels`, `clientWaitSync`)
 *        - `Performance.prototype.now` & `Date.now` Virtual GPU Time Dilation during active GPU draw/compute bursts
 *          (compressing elapsed deltas when `computeTimeMultiplier < 1` for RTX 4090, or dilating deltas
 *           when `computeTimeMultiplier > 1` for UHD 620, while strictly preserving monotonic `performance.now()`)
 *        - `GPUQueue.prototype.onSubmittedWorkDone` & `GPUBuffer.prototype.mapAsync`
 *        - `Function.prototype.toString` native-code cloaking so all hooked methods remain 100% `[native code]`.
 */

import os from 'os';
import crypto from 'crypto';
import { execSync } from 'child_process';

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

    // Heuristic pattern matchers for variant renderer strings
    if (/RTX\s*4090\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4090 Laptop GPU'];
    if (/RTX\s*4080\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4080 Laptop GPU'];
    if (/RTX\s*4070\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4070 Laptop GPU'];
    if (/RTX\s*4060\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4060 Laptop GPU'];
    if (/RTX\s*4050\s*Laptop/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4050 Laptop GPU'];
    if (/RTX\s*4090/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4090'];
    if (/RTX\s*4080\s*SUPER/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4080 SUPER'];
    if (/RTX\s*(?:4080|5000\s*Ada)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4080'];
    if (/RTX\s*4070\s*Ti\s*SUPER/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4070 Ti SUPER'];
    if (/RTX\s*4070\s*SUPER/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4070 SUPER'];
    if (/RTX\s*(?:4070|4000\s*Ada|3500\s*Ada)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4070'];
    if (/RTX\s*4060\s*Ti/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4060 Ti'];
    if (/RTX\s*(?:4060|2000\s*Ada|A2000)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 4060'];
    if (/RTX\s*3090/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3090'];
    if (/RTX\s*3080/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3080'];
    if (/RTX\s*3070/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3070'];
    if (/RTX\s*(?:3060|3050|2060|A1000)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce RTX 3060'];
    if (/GTX\s*1660/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce GTX 1660 SUPER'];
    if (/GTX\s*1650/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['NVIDIA GeForce GTX 1650'];
    if (/RX\s*7900\s*XTX/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 7900 XTX'];
    if (/RX\s*7800\s*XT/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 7800 XT'];
    if (/RX\s*6800\s*XT/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 6800 XT'];
    if (/RX\s*6700\s*XT/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 6700 XT'];
    if (/RX\s*6600/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon RX 6600'];
    if (/W6[89]00X|Vega\s*II/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon Pro W6800X'];
    if (/5700(?:\s*XT)?|W5[57]00X|W6600X|Vega\s*(?:48|56|64)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon Pro 5700 XT'];
    if (/5500(?:\s*XT|M)?|5600M|5300M?|580X|575X|570X|560X|555X|Vega\s*(?:16|20)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon Pro 5500M'];
    if (/8[89]0M/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon 890M'];
    if (/7[68]0M/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon 780M'];
    if (/(?:6[68]0M|740M|610M|Radeon(?:\(TM\))?\s+(?:Vega|Graphics))/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['AMD Radeon 680M'];
    if (/Arc\(TM\)\s+A7[57]0/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Arc(TM) A770 Graphics'];
    if (/140V|130V/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Arc(TM) 140V Graphics'];
    if (/Arc\(TM\)\s+(?:A380\s+)?Graphics/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Arc(TM) Graphics'];
    if (/Iris\(R\)\s+Xe|Intel\(R\)\s+Graphics/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Iris(R) Xe Graphics'];
    if (/UHD\s+Graphics\s+7[37]0/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) UHD Graphics 770'];
    if (/Iris.*(?:655|650|645|640|550|540|6100|G7|Pro|Plus|OpenGL)/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) Iris(TM) Plus Graphics 655'];
    if (/UHD\s+Graphics(?:\s+630)?/i.test(raw) && !/6[12]\d/.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) UHD Graphics 630'];
    if (/UHD\s+Graphics\s+6[12]\d|HD\s+Graphics/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Intel(R) UHD Graphics 620'];
    if (/Adreno.*X1-45/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Qualcomm(R) Adreno(TM) X1-45 GPU'];
    if (/Adreno.*X1|Qualcomm.*Adreno/i.test(raw)) return GPU_PERFORMANCE_SPEC_CATALOG['Qualcomm(R) Adreno(TM) X1-85 GPU'];

    return GPU_PERFORMANCE_SPEC_CATALOG['Apple M5 Pro'];
}

let cachedHostBaseline = null;

/**
 * 2. Collect & Benchmark Local Host Mac Performance Baseline (`collectHostMacPerformanceBaseline`)
 *
 * Probes the physical host Mac's CPU/GPU model (`Apple M5 Pro`, 18 CPU cores, 20 GPU cores, 64GB RAM)
 * and runs a fast Float32 SIMD/matrix shader-math micro-benchmark to calibrate real-time host execution speed.
 *
 * @param {{ forceRefresh?: boolean }} [options]
 * @returns {{
 *   hostChipModel: string,
 *   hostCpuCores: number,
 *   hostGpuCores: number,
 *   hostRamGb: number,
 *   hostFp32Tflops: number,
 *   hostMemoryBandwidthGBps: number,
 *   hostPixelFillRateGPixels: number,
 *   hostMeasuredMatrixOpsPerMs: number,
 *   hostBenchmarkDurationMs: number,
 *   calibratedAt: string
 * }}
 */
export function collectHostMacPerformanceBaseline(options = {}) {
    if (cachedHostBaseline && !options.forceRefresh) {
        return cachedHostBaseline;
    }

    const cpus = os.cpus() || [];
    let hostChipModel = cpus[0]?.model ? String(cpus[0].model).trim() : 'Apple M5 Pro';
    const hostCpuCores = cpus.length || 18;
    const hostRamGb = Math.round(os.totalmem() / 1024 ** 3) || 64;

    if (process.platform === 'darwin' && (!hostChipModel || hostChipModel === 'Unknown')) {
        try {
            hostChipModel = execSync('sysctl -n machdep.cpu.brand_string', {
                encoding: 'utf8',
                timeout: 1500
            }).trim();
        } catch {
            hostChipModel = 'Apple M5 Pro';
        }
    }

    const matchedGpuSpec = lookupGpuPerformanceSpec(hostChipModel);

    // Run a fast deterministic Float32 32x32 matrix-multiply shader math micro-benchmark (~1-2ms)
    const n = 32;
    const matA = new Float32Array(n * n);
    const matB = new Float32Array(n * n);
    const matC = new Float32Array(n * n);
    for (let i = 0; i < n * n; i++) {
        matA[i] = ((i * 17 + 3) % 97) * 0.01;
        matB[i] = ((i * 29 + 7) % 89) * 0.01;
    }

    const iterations = 40;
    const t0 = performance.now();
    for (let iter = 0; iter < iterations; iter++) {
        for (let r = 0; r < n; r++) {
            const rOff = r * n;
            for (let k = 0; k < n; k++) {
                const aVal = matA[rOff + k];
                const kOff = k * n;
                for (let c = 0; c < n; c++) {
                    matC[rOff + c] += aVal * matB[kOff + c];
                }
            }
        }
    }
    const elapsedMs = Math.max(0.05, performance.now() - t0);
    const totalFlops = iterations * 2 * n * n * n; // 2 * 32^3 * 40 = 2,621,440 FLOPs
    const hostMeasuredMatrixOpsPerMs = Math.round(totalFlops / elapsedMs);

    cachedHostBaseline = Object.freeze({
        hostChipModel,
        hostCpuCores,
        hostGpuCores: matchedGpuSpec.gpuCores || 20,
        hostRamGb,
        hostFp32Tflops: matchedGpuSpec.fp32Tflops,
        hostMemoryBandwidthGBps: matchedGpuSpec.memoryBandwidthGBps,
        hostPixelFillRateGPixels: matchedGpuSpec.pixelFillRateGPixels,
        hostMeasuredMatrixOpsPerMs,
        hostBenchmarkDurationMs: Number(elapsedMs.toFixed(4)),
        calibratedAt: new Date().toISOString()
    });

    return cachedHostBaseline;
}

/**
 * 3. Compute Host-to-Target GPU Performance Scaling Weights (`computeGpuPerformanceScalingWeights`)
 *
 * Calculates the exact performance multipliers to transform raw host Mac GPU timing into
 * the target device's expected GPU timing:
 *   - `computeTimeMultiplier = hostFp32Tflops / targetFp32Tflops`
 *     * `< 1.0` when Target GPU is faster than Host Mac (e.g. `RTX 4090` 82.58 TFLOPS vs Host `Apple M5 Pro` 11.5 TFLOPS -> `0.1393`, i.e. 7.18x faster!)
 *     * `= 1.0` when Target GPU equals Host Mac (`Apple M5 Pro` -> `1.0000`)
 *     * `> 1.0` when Target GPU is slower than Host Mac (e.g. `Intel UHD 620` 0.44 TFLOPS vs Host `Apple M5 Pro` 11.5 TFLOPS -> `26.1364`, i.e. 26.14x slower!)
 *   - `memoryTransferMultiplier = hostMemoryBandwidthGBps / targetMemoryBandwidthGBps`
 *   - `pixelFillMultiplier = hostPixelFillRateGPixels / targetPixelFillRateGPixels`
 *   - `compositeShaderBenchmarkMultiplier`: weighted blend (60% FP32 compute + 25% pixel fill + 15% memory bandwidth)
 *
 * @param {string | object} targetGpuOrProfile Target GPU name, WebGL renderer string, or device profile/telemetry
 * @param {{
 *   profileId?: string,
 *   hostBaseline?: object
 * }} [options]
 * @returns {{
 *   profileId: string,
 *   hostBaseline: object,
 *   targetGpuSpec: object,
 *   computeTimeMultiplier: number,
 *   throughputSpeedupRatio: number,
 *   memoryTransferMultiplier: number,
 *   pixelFillMultiplier: number,
 *   compositeShaderBenchmarkMultiplier: number,
 *   expected10msHostShaderMs: number,
 *   expected10msHostReadPixelsMs: number,
 *   jitterSeed: number,
 *   antiPenetrationActive: boolean
 * }}
 */
export function computeGpuPerformanceScalingWeights(targetGpuOrProfile, options = {}) {
    const hostBaseline = options.hostBaseline || collectHostMacPerformanceBaseline();
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

    // Tiny deterministic per-profile baseline offset (±1.5%) so two profiles with the same GPU model
    // don't produce identical down-to-the-microsecond benchmark constants
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

/**
 * 4. Weight Raw Host Mac GPU Execution Duration to Target GPU Performance
 *    (`scaleGpuExecutionDurationMs`)
 *
 * Converts a raw host Mac measured duration (`hostElapsedMs`) into the weighted duration
 * for the target GPU (`operationType: 'shader' | 'compute' | 'readPixels' | 'fill'`),
 * adding realistic hardware thermal/clock micro-jitter (±1.8%) so the host Mac's raw
 * execution time never leaks through.
 *
 * @param {number} hostElapsedMs Raw elapsed time measured on the local host Mac (in ms)
 * @param {object} scalingWeights Output of `computeGpuPerformanceScalingWeights`
 * @param {{
 *   operationType?: 'shader' | 'compute' | 'readPixels' | 'fill',
 *   sampleIndex?: number
 * }} [options]
 * @returns {{
 *   rawHostElapsedMs: number,
 *   weightedTargetElapsedMs: number,
 *   weightedTargetElapsedNs: number,
 *   appliedMultiplier: number,
 *   targetGpuModel: string,
 *   hostChipModel: string
 * }}
 */
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

    // Deterministic pseudo-random thermal/clock micro-jitter in [-1.8%, +1.8%]
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

/**
 * 5. Build In-Browser Anti-Penetration GPU Performance Init Script (`buildGpuPerformanceInitScript`)
 *
 * Injects a stealth C++-grade prototype-preserving GPU performance weighting layer into the
 * browser context (`context.addInitScript`) that intercepts:
 *   - `EXT_disjoint_timer_query` / `EXT_disjoint_timer_query_webgl2` hardware GPU nanosecond timers
 *   - `WebGLRenderingContext` / `WebGL2RenderingContext` (`drawArrays`, `drawElements`,
 *     `drawArraysInstanced`, `drawElementsInstanced`, `finish`, `flush`, `readPixels`, `clientWaitSync`)
 *   - Virtual GPU Clock Dilation on `Performance.prototype.now` & `Date.now` during active GPU
 *     draw/compute/readPixels bursts (compressing elapsed time when spoofing `RTX 4090` so it
 *     measures 7.18x faster than the host Mac, or dilating elapsed time when spoofing `Intel UHD 620`
 *     so it measures 26.1x slower than the host Mac, while strictly preserving monotonic `performance.now()`)
 *   - `GPUQueue.prototype.onSubmittedWorkDone` & `GPUBuffer.prototype.mapAsync`
 *   - Native `Function.prototype.toString` cloaking so every hooked method reports `[native code]`.
 *
 * @param {object} scalingWeights Output of `computeGpuPerformanceScalingWeights`
 * @returns {string} JavaScript init script source
 */
export function buildGpuPerformanceInitScript(scalingWeights) {
    const configPayload = JSON.stringify({
        profileId: scalingWeights.profileId || 'default-gpu-profile',
        targetGpuModel: scalingWeights.targetGpuSpec.model,
        computeTimeMultiplier: scalingWeights.computeTimeMultiplier,
        memoryTransferMultiplier: scalingWeights.memoryTransferMultiplier,
        pixelFillMultiplier: scalingWeights.pixelFillMultiplier,
        compositeShaderBenchmarkMultiplier: scalingWeights.compositeShaderBenchmarkMultiplier,
        profileVarianceFactor: scalingWeights.profileVarianceFactor || 1,
        jitterSeed: scalingWeights.jitterSeed || 1337,
        webgpuMaxBufferSize: scalingWeights.targetGpuSpec.webgpuMaxBufferSize || 2147483648,
        webgpuMaxComputeWorkgroupSizeX:
            scalingWeights.targetGpuSpec.webgpuMaxComputeWorkgroupSizeX || 1024
    });

    return `(() => {
    const CFG = ${configPayload};
    try {
        Object.defineProperty(globalThis, '__camoufoxGpuPerformanceState', {
            value: Object.freeze({
                profileId: CFG.profileId,
                targetGpuModel: CFG.targetGpuModel,
                computeTimeMultiplier: CFG.computeTimeMultiplier,
                memoryTransferMultiplier: CFG.memoryTransferMultiplier,
                pixelFillMultiplier: CFG.pixelFillMultiplier,
                compositeShaderBenchmarkMultiplier: CFG.compositeShaderBenchmarkMultiplier,
                profileVarianceFactor: CFG.profileVarianceFactor,
                antiPenetrationActive: true
            }),
            enumerable: false,
            configurable: false,
            writable: false
        });
    } catch {}
    const nativeToString = Function.prototype.toString;
    const cloakedFns = new WeakMap();

    const cloak = (wrappedFn, origFn) => {
        try {
            const sourceStr = cloakedFns.has(origFn)
                ? cloakedFns.get(origFn)
                : nativeToString.call(origFn);
            cloakedFns.set(wrappedFn, sourceStr);
        } catch {}
        return wrappedFn;
    };

    const patchedToString = function toString() {
        if (cloakedFns.has(this)) {
            return cloakedFns.get(this);
        }
        return nativeToString.call(this);
    };
    cloak(patchedToString, nativeToString);
    Object.defineProperty(Function.prototype, 'toString', {
        value: patchedToString,
        writable: true,
        configurable: true
    });

    let sampleCounter = 0;
    const nextJitter = () => {
        sampleCounter = (sampleCounter + 1) | 0;
        const s = Math.sin((CFG.jitterSeed + sampleCounter * 7919) * 12.9898) * 43758.5453;
        const frac = s - Math.floor(s);
        return 1 + (frac * 2 - 1) * 0.018;
    };

    // Virtual GPU Clock Dilation state (strictly monotonic with bounded burst window)
    const origPerfNow = Performance.prototype.now;
    const origDateNow = Date.now;
    const basePerfOrigin = origPerfNow.call(performance);
    const baseDateOrigin = origDateNow.call(Date);
    const MAX_GPU_BURST_WINDOW_MS = 100;

    let lastRealPerfNow = basePerfOrigin;
    let virtualPerfNow = basePerfOrigin;
    let activeGpuBurstMode = null; // null | 'shader' | 'compute' | 'readPixels' | 'fill'
    let gpuBurstPendingDrawCalls = 0;

    const getActiveMultiplier = () => {
        if (!activeGpuBurstMode) return 1.0;
        const base =
            activeGpuBurstMode === 'readPixels'
                ? CFG.memoryTransferMultiplier
                : activeGpuBurstMode === 'fill'
                  ? CFG.pixelFillMultiplier
                  : activeGpuBurstMode === 'compute'
                    ? CFG.computeTimeMultiplier
                    : CFG.compositeShaderBenchmarkMultiplier;
        return base * CFG.profileVarianceFactor * nextJitter();
    };

    const advanceVirtualClock = () => {
        const realNow = origPerfNow.call(performance);
        const realDelta = Math.max(0, realNow - lastRealPerfNow);
        lastRealPerfNow = realNow;

        let scaledDelta = realDelta;
        if (activeGpuBurstMode) {
            const mult = getActiveMultiplier();
            if (realDelta > MAX_GPU_BURST_WINDOW_MS) {
                // Cap any single unsynchronized GPU burst to MAX_GPU_BURST_WINDOW_MS so idle pages never drift Date.now()
                const burstPortion = MAX_GPU_BURST_WINDOW_MS;
                const idlePortion = realDelta - MAX_GPU_BURST_WINDOW_MS;
                scaledDelta = burstPortion * mult + idlePortion;
                activeGpuBurstMode = null;
                gpuBurstPendingDrawCalls = 0;
            } else {
                scaledDelta = realDelta * mult;
            }
        }
        // Enforce strict monotonicity (+0.001ms minimum step when realDelta > 0)
        const minStep = realDelta > 0 ? Math.min(realDelta * 0.01, 0.001) : 0;
        virtualPerfNow = Math.max(virtualPerfNow + minStep, virtualPerfNow + scaledDelta);
        return virtualPerfNow;
    };

    const patchedPerfNow = function now() {
        return advanceVirtualClock();
    };
    cloak(patchedPerfNow, origPerfNow);
    Object.defineProperty(Performance.prototype, 'now', {
        value: patchedPerfNow,
        writable: true,
        configurable: true
    });

    const patchedDateNow = function now() {
        const vNow = advanceVirtualClock();
        return Math.round(baseDateOrigin + (vNow - basePerfOrigin));
    };
    cloak(patchedDateNow, origDateNow);
    Object.defineProperty(Date, 'now', {
        value: patchedDateNow,
        writable: true,
        configurable: true
    });

    const hookedProtos = new WeakSet();
    const timerQueries = new WeakSet();
    const scaledQueryResults = new WeakMap();

    const hookWebGLPrototype = (proto) => {
        if (!proto || hookedProtos.has(proto)) return;
        hookedProtos.add(proto);

        for (const drawMethod of ['drawArrays', 'drawElements', 'drawArraysInstanced', 'drawElementsInstanced']) {
            if (typeof proto[drawMethod] === 'function') {
                const origDraw = proto[drawMethod];
                const wrappedDraw = function (...args) {
                    advanceVirtualClock();
                    activeGpuBurstMode = 'shader';
                    gpuBurstPendingDrawCalls += 1;
                    return origDraw.apply(this, args);
                };
                cloak(wrappedDraw, origDraw);
                Object.defineProperty(proto, drawMethod, {
                    value: wrappedDraw,
                    writable: true,
                    configurable: true
                });
            }
        }

        if (typeof proto.flush === 'function') {
            const origFlush = proto.flush;
            const wrappedFlush = function (...args) {
                advanceVirtualClock();
                if (gpuBurstPendingDrawCalls > 0) {
                    activeGpuBurstMode = 'shader';
                }
                return origFlush.apply(this, args);
            };
            cloak(wrappedFlush, origFlush);
            Object.defineProperty(proto, 'flush', {
                value: wrappedFlush,
                writable: true,
                configurable: true
            });
        }

        if (typeof proto.finish === 'function') {
            const origFinish = proto.finish;
            const wrappedFinish = function (...args) {
                advanceVirtualClock();
                activeGpuBurstMode = 'shader';
                const res = origFinish.apply(this, args);
                advanceVirtualClock();
                gpuBurstPendingDrawCalls = 0;
                activeGpuBurstMode = null;
                return res;
            };
            cloak(wrappedFinish, origFinish);
            Object.defineProperty(proto, 'finish', {
                value: wrappedFinish,
                writable: true,
                configurable: true
            });
        }

        if (typeof proto.clientWaitSync === 'function') {
            const origWaitSync = proto.clientWaitSync;
            const wrappedWaitSync = function (...args) {
                advanceVirtualClock();
                activeGpuBurstMode = 'shader';
                const res = origWaitSync.apply(this, args);
                advanceVirtualClock();
                gpuBurstPendingDrawCalls = 0;
                activeGpuBurstMode = null;
                return res;
            };
            cloak(wrappedWaitSync, origWaitSync);
            Object.defineProperty(proto, 'clientWaitSync', {
                value: wrappedWaitSync,
                writable: true,
                configurable: true
            });
        }

        if (typeof proto.readPixels === 'function') {
            const origReadPixels = proto.readPixels;
            const wrappedReadPixels = function (...args) {
                advanceVirtualClock();
                activeGpuBurstMode = gpuBurstPendingDrawCalls > 0 ? 'shader' : 'readPixels';
                const res = origReadPixels.apply(this, args);
                advanceVirtualClock();
                gpuBurstPendingDrawCalls = 0;
                activeGpuBurstMode = null;
                return res;
            };
            cloak(wrappedReadPixels, origReadPixels);
            Object.defineProperty(proto, 'readPixels', {
                value: wrappedReadPixels,
                writable: true,
                configurable: true
            });
        }

        // Track WebGL2 TIME_ELAPSED_EXT (0x88BF) queries via beginQuery
        if (typeof proto.beginQuery === 'function') {
            const origBeginQuery = proto.beginQuery;
            const wrappedBeginQuery = function (target, query) {
                if (query && typeof query === 'object') {
                    scaledQueryResults.delete(query);
                    if (target === 0x88BF) {
                        timerQueries.add(query);
                    } else {
                        timerQueries.delete(query);
                    }
                }
                return origBeginQuery.call(this, target, query);
            };
            cloak(wrappedBeginQuery, origBeginQuery);
            Object.defineProperty(proto, 'beginQuery', {
                value: wrappedBeginQuery,
                writable: true,
                configurable: true
            });
        }

        // Hook WebGL2 hardware timer queries (TIME_ELAPSED_EXT = 0x88BF, QUERY_RESULT = 0x8866)
        if (typeof proto.getQueryParameter === 'function') {
            const origGetQueryParam = proto.getQueryParameter;
            const wrappedGetQueryParam = function (query, pname) {
                const val = origGetQueryParam.call(this, query, pname);
                if (pname === 0x8866 && typeof val === 'number' && val > 0) {
                    const isKnownNonTimer =
                        query && typeof query === 'object' && query.target && query.target !== 0x88BF;
                    if (!isKnownNonTimer && (!timerQueries.size || timerQueries.has(query))) {
                        if (query && typeof query === 'object' && scaledQueryResults.has(query)) {
                            return scaledQueryResults.get(query);
                        }
                        const scaled = Math.max(
                            100,
                            Math.round(val * CFG.computeTimeMultiplier * CFG.profileVarianceFactor * nextJitter())
                        );
                        if (query && typeof query === 'object') {
                            scaledQueryResults.set(query, scaled);
                        }
                        return scaled;
                    }
                }
                return val;
            };
            cloak(wrappedGetQueryParam, origGetQueryParam);
            Object.defineProperty(proto, 'getQueryParameter', {
                value: wrappedGetQueryParam,
                writable: true,
                configurable: true
            });
        }

        // Hook getExtension('EXT_disjoint_timer_query')
        if (typeof proto.getExtension === 'function') {
            const origGetExt = proto.getExtension;
            const wrappedGetExt = function (name) {
                const ext = origGetExt.call(this, name);
                if (ext && typeof name === 'string' && /disjoint_timer_query/i.test(name)) {
                    if (typeof ext.beginQueryEXT === 'function' && !ext._camoufoxBeginScaled) {
                        const origBeginExt = ext.beginQueryEXT.bind(ext);
                        const wrappedBeginExt = function (target, query) {
                            if (query && typeof query === 'object') {
                                scaledQueryResults.delete(query);
                                if (target === 0x88BF) {
                                    timerQueries.add(query);
                                }
                            }
                            return origBeginExt(target, query);
                        };
                        cloak(wrappedBeginExt, ext.beginQueryEXT);
                        Object.defineProperty(ext, 'beginQueryEXT', {
                            value: wrappedBeginExt,
                            writable: true,
                            configurable: true
                        });
                        Object.defineProperty(ext, '_camoufoxBeginScaled', { value: true, enumerable: false });
                    }
                    if (typeof ext.getQueryObjectEXT === 'function' && !ext._camoufoxScaled) {
                        const origGetQueryObj = ext.getQueryObjectEXT.bind(ext);
                        const wrappedGetQueryObj = function (query, pname) {
                            const val = origGetQueryObj(query, pname);
                            if (pname === 0x8866 && typeof val === 'number' && val > 0) {
                                if (query && typeof query === 'object' && scaledQueryResults.has(query)) {
                                    return scaledQueryResults.get(query);
                                }
                                const scaled = Math.max(
                                    100,
                                    Math.round(val * CFG.computeTimeMultiplier * CFG.profileVarianceFactor * nextJitter())
                                );
                                if (query && typeof query === 'object') {
                                    scaledQueryResults.set(query, scaled);
                                }
                                return scaled;
                            }
                            return val;
                        };
                        cloak(wrappedGetQueryObj, ext.getQueryObjectEXT);
                        Object.defineProperty(ext, 'getQueryObjectEXT', {
                            value: wrappedGetQueryObj,
                            writable: true,
                            configurable: true
                        });
                        Object.defineProperty(ext, '_camoufoxScaled', { value: true, enumerable: false });
                    }
                }
                return ext;
            };
            cloak(wrappedGetExt, origGetExt);
            Object.defineProperty(proto, 'getExtension', {
                value: wrappedGetExt,
                writable: true,
                configurable: true
            });
        }
    };

    if (typeof WebGLRenderingContext !== 'undefined') {
        hookWebGLPrototype(WebGLRenderingContext.prototype);
    }
    if (typeof WebGL2RenderingContext !== 'undefined') {
        hookWebGLPrototype(WebGL2RenderingContext.prototype);
    }

    // Hook HTMLCanvasElement.prototype.toDataURL & OffscreenCanvas.prototype.convertToBlob for pending GPU bursts
    if (typeof HTMLCanvasElement !== 'undefined' && HTMLCanvasElement.prototype && typeof HTMLCanvasElement.prototype.toDataURL === 'function') {
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        const wrappedToDataURL = function (...args) {
            if (gpuBurstPendingDrawCalls > 0) {
                advanceVirtualClock();
                activeGpuBurstMode = 'fill';
                const res = origToDataURL.apply(this, args);
                advanceVirtualClock();
                gpuBurstPendingDrawCalls = 0;
                activeGpuBurstMode = null;
                return res;
            }
            return origToDataURL.apply(this, args);
        };
        cloak(wrappedToDataURL, origToDataURL);
        Object.defineProperty(HTMLCanvasElement.prototype, 'toDataURL', {
            value: wrappedToDataURL,
            writable: true,
            configurable: true
        });
    }

    if (typeof OffscreenCanvas !== 'undefined' && OffscreenCanvas.prototype && typeof OffscreenCanvas.prototype.convertToBlob === 'function') {
        const origConvertToBlob = OffscreenCanvas.prototype.convertToBlob;
        const wrappedConvertToBlob = function (...args) {
            if (gpuBurstPendingDrawCalls > 0) {
                advanceVirtualClock();
                activeGpuBurstMode = 'fill';
                return origConvertToBlob.apply(this, args).finally(() => {
                    advanceVirtualClock();
                    gpuBurstPendingDrawCalls = 0;
                    activeGpuBurstMode = null;
                });
            }
            return origConvertToBlob.apply(this, args);
        };
        cloak(wrappedConvertToBlob, origConvertToBlob);
        Object.defineProperty(OffscreenCanvas.prototype, 'convertToBlob', {
            value: wrappedConvertToBlob,
            writable: true,
            configurable: true
        });
    }

    // Hook WebGPU GPUQueue.prototype.onSubmittedWorkDone & GPUBuffer.prototype.mapAsync
    if (typeof GPUQueue !== 'undefined' && GPUQueue.prototype && typeof GPUQueue.prototype.onSubmittedWorkDone === 'function') {
        const origWorkDone = GPUQueue.prototype.onSubmittedWorkDone;
        const wrappedWorkDone = function () {
            advanceVirtualClock();
            activeGpuBurstMode = 'compute';
            return origWorkDone.call(this).finally(() => {
                advanceVirtualClock();
                activeGpuBurstMode = null;
            });
        };
        cloak(wrappedWorkDone, origWorkDone);
        Object.defineProperty(GPUQueue.prototype, 'onSubmittedWorkDone', {
            value: wrappedWorkDone,
            writable: true,
            configurable: true
        });
    }

    if (typeof GPUBuffer !== 'undefined' && GPUBuffer.prototype && typeof GPUBuffer.prototype.mapAsync === 'function') {
        const origMapAsync = GPUBuffer.prototype.mapAsync;
        const wrappedMapAsync = function (...args) {
            advanceVirtualClock();
            activeGpuBurstMode = 'readPixels';
            return origMapAsync.apply(this, args).finally(() => {
                advanceVirtualClock();
                activeGpuBurstMode = null;
            });
        };
        cloak(wrappedMapAsync, origMapAsync);
        Object.defineProperty(GPUBuffer.prototype, 'mapAsync', {
            value: wrappedMapAsync,
            writable: true,
            configurable: true
        });
    }
})();`;
}

/**
 * 6. Attach GPU Performance Weighting Init Script to a Playwright BrowserContext
 *    (`attachGpuPerformanceScalerToContext`)
 *
 * @param {object} context Playwright BrowserContext
 * @param {string | object} targetGpuOrProfile
 * @param {{ profileId?: string, hostBaseline?: object }} [options]
 * @returns {Promise<{ scalingWeights: object, initScriptAttached: boolean }>}
 */
export async function attachGpuPerformanceScalerToContext(context, targetGpuOrProfile, options = {}) {
    const scalingWeights =
        targetGpuOrProfile && targetGpuOrProfile.computeTimeMultiplier !== undefined
            ? targetGpuOrProfile
            : computeGpuPerformanceScalingWeights(targetGpuOrProfile, options);

    let initScriptAttached = false;
    if (context && typeof context.addInitScript === 'function') {
        const scriptSource = buildGpuPerformanceInitScript(scalingWeights);
        await context.addInitScript(scriptSource);
        initScriptAttached = true;
    }

    return {
        scalingWeights,
        initScriptAttached
    };
}

/**
 * 7. Audit GPU Performance Scaling & Anti-Penetration Coherence
 *    (`validateGpuPerformanceScalingCoherence` - Check 18 in `coherence-auditor.js`)
 *
 * Verifies that:
 *   1. The profile's `gpuPerformance` telemetry matches the claimed WebGL/WebGPU SKU's physical
 *      FP32 TFLOPS and memory bandwidth tier (`expected10msHostShaderMs` / `computeTimeMultiplier`).
 *   2. Raw host Mac GPU performance did NOT penetrate through when the profile claims a different
 *      GPU tier (e.g., if the profile claims `NVIDIA GeForce RTX 4090` 82.58 TFLOPS or `Intel UHD 620`
 *      0.44 TFLOPS, reporting raw unscaled host `Apple M5 Pro` 11.5 TFLOPS execution time is flagged
 *      as a host-penetration leak!).
 *   3. WebGL hardware timer query / shader benchmark timing does not contradict the GPU's tier
 *      (e.g., a 0.44 TFLOPS `Intel UHD Graphics 620` completing a 10ms reference shader benchmark
 *      in `< 3ms` like an 82.6 TFLOPS `RTX 4090`, or an `RTX 4090` taking `> 50ms` like an integrated GPU).
 *
 * @param {object} telemetry Browser telemetry object
 * @returns {{ passed: boolean, issues: string[] }}
 */
export function validateGpuPerformanceScalingCoherence(telemetry) {
    const issues = [];
    if (!telemetry || typeof telemetry !== 'object') {
        return { passed: true, issues };
    }

    const gpuPerf = telemetry.gpuPerformance || telemetry.hardwareProfile?.gpuPerformance || null;
    if (!gpuPerf) {
        return { passed: true, issues };
    }

    const renderer =
        telemetry.webgl?.unmaskedRenderer ||
        telemetry.hardwareProfile?.gpuModel ||
        gpuPerf.targetGpuModel ||
        '';
    const expectedWeights = computeGpuPerformanceScalingWeights(renderer, {
        profileId: telemetry.profileId || gpuPerf.profileId || 'audit-profile',
        hostBaseline: gpuPerf.hostBaseline || undefined
    });
    const targetSpec = expectedWeights.targetGpuSpec;
    const hostBase = expectedWeights.hostBaseline;

    const claimedGpuModel = gpuPerf.targetGpuSpec?.model || gpuPerf.targetGpuModel || null;
    if (
        claimedGpuModel &&
        telemetry.webgl?.unmaskedRenderer &&
        claimedGpuModel !== targetSpec.model
    ) {
        issues.push(
            `GPU performance scaler model mismatch: gpuPerformance targets "${claimedGpuModel}" but WebGL renderer resolves to "${targetSpec.model}"`
        );
    }

    // 1. Check anti-penetration guard flag
    if (gpuPerf.antiPenetrationActive === false) {
        issues.push(
            `GPU performance anti-penetration guard is disabled (antiPenetrationActive=false) for "${targetSpec.model}"; raw host Mac ("${hostBase.hostChipModel}") performance will leak`
        );
    }

    // 2. Detect raw host Mac performance penetration when target GPU differs significantly from host Mac
    const tflopsDiffRatio = Math.abs(targetSpec.fp32Tflops - hostBase.hostFp32Tflops) / hostBase.hostFp32Tflops;
    if (tflopsDiffRatio > 0.25) {
        if (
            gpuPerf.computeTimeMultiplier !== undefined &&
            Math.abs(Number(gpuPerf.computeTimeMultiplier) - 1.0) < 0.03
        ) {
            issues.push(
                `Host Mac GPU performance penetration detected: target GPU "${targetSpec.model}" (${targetSpec.fp32Tflops} TFLOPS) differs from host Mac "${hostBase.hostChipModel}" (${hostBase.hostFp32Tflops} TFLOPS), but computeTimeMultiplier=${gpuPerf.computeTimeMultiplier} (~1.0 unscaled) exposes raw host Mac performance`
            );
        }

        if (
            gpuPerf.measured10msHostShaderMs !== undefined &&
            Math.abs(Number(gpuPerf.measured10msHostShaderMs) - 10.0) < 0.3
        ) {
            issues.push(
                `Host Mac GPU timing leak detected: 10ms host shader benchmark returned unscaled ${gpuPerf.measured10msHostShaderMs}ms for "${targetSpec.model}" (expected weighted ~${expectedWeights.expected10msHostShaderMs}ms)`
            );
        }
    }

    // 3. Verify measured/reported shader benchmark duration aligns with target GPU's weighted performance tier
    if (gpuPerf.measured10msHostShaderMs !== undefined) {
        const measuredMs = Number(gpuPerf.measured10msHostShaderMs);
        const expectedMs = expectedWeights.expected10msHostShaderMs;
        // Allow ±25% thermal/workload variance around the target GPU's weighted duration
        if (!Number.isFinite(measuredMs) || measuredMs <= 0 || measuredMs < expectedMs * 0.5 || measuredMs > expectedMs * 1.8) {
            issues.push(
                `GPU performance tier mismatch: "${targetSpec.model}" (${targetSpec.fp32Tflops} TFLOPS) reported shader benchmark duration ${measuredMs}ms, which contradicts its weighted performance profile (~${expectedMs}ms relative to host "${hostBase.hostChipModel}")`
            );
        }
    }

    // 4. Verify computeTimeMultiplier matches hostFp32Tflops / targetFp32Tflops
    if (gpuPerf.computeTimeMultiplier !== undefined) {
        const reportedMult = Number(gpuPerf.computeTimeMultiplier);
        const expectedMult = expectedWeights.computeTimeMultiplier;
        if (!Number.isFinite(reportedMult) || reportedMult <= 0 || Math.abs(reportedMult - expectedMult) > Math.max(0.05, expectedMult * 0.2)) {
            issues.push(
                `GPU computeTimeMultiplier mismatch for "${targetSpec.model}": reported ${reportedMult} vs expected ${expectedMult} (host ${hostBase.hostFp32Tflops} TFLOPS / target ${targetSpec.fp32Tflops} TFLOPS)`
            );
        }
    }

    return {
        passed: issues.length === 0,
        issues
    };
}

export default {
    GPU_PERFORMANCE_SPEC_CATALOG,
    lookupGpuPerformanceSpec,
    collectHostMacPerformanceBaseline,
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    buildGpuPerformanceInitScript,
    attachGpuPerformanceScalerToContext,
    validateGpuPerformanceScalingCoherence
};
