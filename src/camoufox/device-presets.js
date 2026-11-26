/**
 * Ready-to-Use Multi-Vendor Device Preset Catalog & Absorbed AdsPower Strengths
 *
 * Combines:
 *   1. 36+ Atomic, 100% SKU-Verified Usable Device Presets (`USABLE_DEVICE_PRESET_CATALOG`)
 *      covering Windows (ThinkPad, Dell XPS, Surface, ROG, Razer, Spectre, Galaxy Book4,
 *      Snapdragon X Elite/Plus, Intel/AMD Desktops), macOS (Apple Silicon M1–M5 & Intel Macs),
 *      and Linux (Framework 13, System76 Lemur Pro, ThinkPad T14 AMD, Ryzen/Intel Workstations).
 *   2. Absorbed AdsPower Architectural Strengths (sanitized for strict C++ cross-layer coherence):
 *      - Deterministic `profileId` (`fbccId`) hash-seeded hardware preset selection, hostname
 *        (`DeviceName`), IEEE OUI `MacAddress`, and deterministic `AudioFp` / `CanvasMark` /
 *        `ClientRectFp` seeds (`resolveDeterministicDeviceProfile`).
 *      - 50+ Locale auto-completion (`Module 99825`), 60+ Country-to-Language & IANA Timezone
 *        mapping (`Module 53716` & `Module 41056`), and RFC-9110 `Accept-Language` q-factor
 *        builder (`Module 82088`).
 *      - OS-authentic MediaDevices & deterministic USB Camera `VID:PID` generator
 *        (`Module 82088` + Camoufox `media-devices.json`) with pre-permission empty-label hygiene.
 *      - OS-authentic `SpeechSynthesis` (`TTSEngines`) voice list selector with automatic
 *        primary-language `default: true, localService: true` binding (`Module 82088`).
 *      - AdsPower Broken-Profile Auto-Healer (`sanitizeAdsPowerProfileToCoherentPreset`) that
 *        repairs contradictory AdsPower profiles into 100/100 SKU-coherent configurations.
 */

import crypto from 'crypto';
import {
    APPLE_SILICON_SKU_CATALOG,
    APPLE_SILICON_MIN_MACOS_VERSION,
    parseAppleSiliconSkuName,
    validateHardwareModelSpec
} from './hardware-models.js';
import {
    SENSITIVE_LOCAL_PORT_CATALOG,
    BLOCKED_INTERNAL_URL_PATTERNS,
    DEFAULT_CANVAS_SKIP_HOSTS,
    COUNTRY_METRO_COORDINATES_CATALOG,
    isLocalOrPrivateTarget,
    classifyScannedPortRisk,
    evaluatePortScanRequest,
    evaluateInternalSchemeAccess,
    computeHexHammingDistance,
    computeHashSimilarity,
    shouldSkipCanvasNoiseForHost,
    isSoftwareRasterizerRenderer,
    CanvasWebglConsistencyLedger,
    validateOsAndBrowserVersionMatch,
    resolveGeoCoordinatesWithDeterministicJitter,
    attachZiniaoSecurityGuardsToContext
} from './ziniao-security.js';
import {
    GPU_PERFORMANCE_SPEC_CATALOG,
    lookupGpuPerformanceSpec,
    collectHostMacPerformanceBaseline,
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    buildGpuPerformanceInitScript,
    attachGpuPerformanceScalerToContext,
    validateGpuPerformanceScalingCoherence
} from './gpu-performance-scaler.js';

export {
    SENSITIVE_LOCAL_PORT_CATALOG,
    BLOCKED_INTERNAL_URL_PATTERNS,
    DEFAULT_CANVAS_SKIP_HOSTS,
    COUNTRY_METRO_COORDINATES_CATALOG,
    isLocalOrPrivateTarget,
    classifyScannedPortRisk,
    evaluatePortScanRequest,
    evaluateInternalSchemeAccess,
    computeHexHammingDistance,
    computeHashSimilarity,
    shouldSkipCanvasNoiseForHost,
    isSoftwareRasterizerRenderer,
    CanvasWebglConsistencyLedger,
    validateOsAndBrowserVersionMatch,
    resolveGeoCoordinatesWithDeterministicJitter,
    attachZiniaoSecurityGuardsToContext,
    GPU_PERFORMANCE_SPEC_CATALOG,
    lookupGpuPerformanceSpec,
    collectHostMacPerformanceBaseline,
    computeGpuPerformanceScalingWeights,
    scaleGpuExecutionDurationMs,
    buildGpuPerformanceInitScript,
    attachGpuPerformanceScalerToContext,
    validateGpuPerformanceScalingCoherence
};

/**
 * 1. OS-Specific Authentic Font Catalogs
 * Absorbed from AdsPower `Module 98733` + Camoufox `launcher-constants.json`, strictly partitioned
 * by OS so Windows never leaks macOS `Helvetica Neue`/`Menlo`/`SF Pro` and macOS never leaks
 * Windows `Segoe UI`/`Consolas`/`Calibri`.
 */
export const OS_FONT_CATALOG = Object.freeze({
    windows: Object.freeze([
        'Arial',
        'Arial Black',
        'Bahnschrift',
        'Calibri',
        'Calibri Light',
        'Cambria',
        'Cambria Math',
        'Candara',
        'Comic Sans MS',
        'Consolas',
        'Constantia',
        'Corbel',
        'Courier New',
        'Ebrima',
        'Franklin Gothic Medium',
        'Gabriola',
        'Gadugi',
        'Georgia',
        'HoloLens MDL2 Assets',
        'Impact',
        'Ink Free',
        'Javanese Text',
        'Leelawadee UI',
        'Lucida Console',
        'Lucida Sans Unicode',
        'MS Gothic',
        'MS PGothic',
        'MS Sans Serif',
        'MS UI Gothic',
        'MV Boli',
        'Malgun Gothic',
        'Marlett',
        'Microsoft Himalaya',
        'Microsoft JhengHei',
        'Microsoft JhengHei UI',
        'Microsoft New Tai Lue',
        'Microsoft PhagsPa',
        'Microsoft Sans Serif',
        'Microsoft Tai Le',
        'Microsoft YaHei',
        'Microsoft YaHei UI',
        'Microsoft Yi Baiti',
        'MingLiU-ExtB',
        'MingLiU_HKSCS-ExtB',
        'Mongolian Baiti',
        'Myanmar Text',
        'NSimSun',
        'Nirmala UI',
        'PMingLiU-ExtB',
        'Palatino Linotype',
        'Segoe Fluent Icons',
        'Segoe MDL2 Assets',
        'Segoe Print',
        'Segoe Script',
        'Segoe UI',
        'Segoe UI Black',
        'Segoe UI Emoji',
        'Segoe UI Historic',
        'Segoe UI Light',
        'Segoe UI Semibold',
        'Segoe UI Semilight',
        'Segoe UI Symbol',
        'Segoe UI Variable Display',
        'Segoe UI Variable Small',
        'Segoe UI Variable Text',
        'SimSun',
        'SimSun-ExtB',
        'Sitka Banner',
        'Sitka Display',
        'Sitka Heading',
        'Sitka Small',
        'Sitka Subheading',
        'Sitka Text',
        'Sylfaen',
        'Symbol',
        'Tahoma',
        'Times New Roman',
        'Trebuchet MS',
        'Verdana',
        'Webdings',
        'Wingdings',
        'Yu Gothic',
        'Yu Gothic UI'
    ]),
    macos: Object.freeze([
        'American Typewriter',
        'Andale Mono',
        'Apple Braille',
        'Apple Chancery',
        'Apple Color Emoji',
        'Apple SD Gothic Neo',
        'Apple Symbols',
        'AppleGothic',
        'AppleMyungjo',
        'Arial',
        'Arial Black',
        'Arial Hebrew',
        'Arial Narrow',
        'Arial Rounded MT Bold',
        'Arial Unicode MS',
        'Avenir',
        'Avenir Next',
        'Avenir Next Condensed',
        'Baskerville',
        'Big Caslon',
        'Brush Script MT',
        'Chalkboard',
        'Chalkboard SE',
        'Chalkduster',
        'Charter',
        'Cochin',
        'Comic Sans MS',
        'Copperplate',
        'Corsiva Hebrew',
        'Courier',
        'Courier New',
        'DIN Alternate',
        'DIN Condensed',
        'Didot',
        'Euphemia UCAS',
        'Futura',
        'Geneva',
        'Georgia',
        'Gill Sans',
        'Helvetica',
        'Helvetica Neue',
        'Herculanum',
        'Hiragino Maru Gothic ProN',
        'Hiragino Mincho ProN',
        'Hiragino Sans',
        'Hoefler Text',
        'Impact',
        'Kefa',
        'Kohinoor Bangla',
        'Kohinoor Devanagari',
        'Lucida Grande',
        'Luminari',
        'Marker Felt',
        'Menlo',
        'Monaco',
        'Noteworthy',
        'Optima',
        'Palatino',
        'Papyrus',
        'Phosphate',
        'PingFang HK',
        'PingFang SC',
        'PingFang TC',
        'PT Mono',
        'PT Sans',
        'PT Serif',
        'Rockwell',
        'SF Pro',
        'Savoye LET',
        'SignPainter',
        'Skia',
        'Snell Roundhand',
        'STHeiti',
        'STSong',
        'Sukhumvit Set',
        'Tahoma',
        'Times',
        'Times New Roman',
        'Trattatello',
        'Trebuchet MS',
        'Verdana',
        'Zapf Dingbats',
        'Zapfino'
    ]),
    linux: Object.freeze([
        'Arimo',
        'Cantarell',
        'Cousine',
        'DejaVu Math TeX Gyre',
        'DejaVu Sans',
        'DejaVu Sans Condensed',
        'DejaVu Sans Mono',
        'DejaVu Serif',
        'Droid Sans Fallback',
        'FreeMono',
        'FreeSans',
        'FreeSerif',
        'Liberation Mono',
        'Liberation Sans',
        'Liberation Sans Narrow',
        'Liberation Serif',
        'Nimbus Mono PS',
        'Nimbus Roman',
        'Nimbus Sans',
        'Noto Color Emoji',
        'Noto Mono',
        'Noto Sans',
        'Noto Sans CJK JP',
        'Noto Sans CJK KR',
        'Noto Sans CJK SC',
        'Noto Sans CJK TC',
        'Noto Serif',
        'Tinos',
        'Twemoji Mozilla',
        'Ubuntu',
        'Ubuntu Condensed',
        'Ubuntu Mono',
        'URW Bookman',
        'URW Gothic',
        'Arial',
        'Times New Roman',
        'Courier New'
    ])
});

/**
 * 2. Absorbed AdsPower Locale Auto-Completion Matrix (`Module 99825` - 50+ locales)
 */
export const LOCALE_FALLBACK_CHAINS = Object.freeze([
    Object.freeze(['am', 'en-GB', 'en']),
    Object.freeze(['ar', 'en-US', 'en']),
    Object.freeze(['ar-SA', 'ar', 'en-US', 'en']),
    Object.freeze(['bg-BG', 'bg']),
    Object.freeze(['bn-IN', 'bn', 'en-US', 'en']),
    Object.freeze(['ca-ES', 'ca']),
    Object.freeze(['cs-CZ', 'cs']),
    Object.freeze(['da-DK', 'da', 'en-US', 'en']),
    Object.freeze(['de-DE', 'de', 'en-US', 'en']),
    Object.freeze(['de-AT', 'de-DE', 'de', 'en-US', 'en']),
    Object.freeze(['de-CH', 'de-DE', 'de', 'en-US', 'en']),
    Object.freeze(['el-GR', 'el']),
    Object.freeze(['en-GB', 'en-US', 'en']),
    Object.freeze(['en-AU', 'en-GB', 'en-US', 'en']),
    Object.freeze(['en-CA', 'en-US', 'en']),
    Object.freeze(['en-US', 'en']),
    Object.freeze(['es-ES', 'es']),
    Object.freeze(['es-MX', 'es-419', 'es', 'en-US', 'en']),
    Object.freeze(['es-AR', 'es-419', 'es']),
    Object.freeze(['es-419', 'es']),
    Object.freeze(['et-EE', 'et', 'en-US', 'en']),
    Object.freeze(['fa', 'en-US', 'en']),
    Object.freeze(['fi-FI', 'fi', 'en-US', 'en']),
    Object.freeze(['fil', 'fil-PH', 'tl', 'en-US', 'en']),
    Object.freeze(['fr-FR', 'fr', 'en-US', 'en']),
    Object.freeze(['fr-CA', 'fr', 'en-CA', 'en-US', 'en']),
    Object.freeze(['gu-IN', 'gu', 'hi-IN', 'hi', 'en-US', 'en']),
    Object.freeze(['he-IL', 'he', 'en-US', 'en']),
    Object.freeze(['hi-IN', 'hi', 'en-US', 'en']),
    Object.freeze(['hr-HR', 'hr', 'en-US', 'en']),
    Object.freeze(['hu-HU', 'hu', 'en-US', 'en']),
    Object.freeze(['id-ID', 'id', 'en-US', 'en']),
    Object.freeze(['it-IT', 'it', 'en-US', 'en']),
    Object.freeze(['ja-JP', 'ja', 'en-US', 'en']),
    Object.freeze(['ja', 'en-US', 'en']),
    Object.freeze(['kn-IN', 'kn', 'en-US', 'en']),
    Object.freeze(['ko-KR', 'ko', 'en-US', 'en']),
    Object.freeze(['lt', 'en-US', 'en', 'ru', 'pl']),
    Object.freeze(['lv-LV', 'lv', 'en-US', 'en']),
    Object.freeze(['ml-IN', 'ml', 'en-US', 'en']),
    Object.freeze(['mr-IN', 'mr', 'hi-IN', 'hi', 'en-US', 'en']),
    Object.freeze(['ms-MY', 'ms', 'en-US', 'en']),
    Object.freeze(['nb-NO', 'nb', 'no', 'nn', 'en-US', 'en']),
    Object.freeze(['nl-NL', 'nl', 'en-US', 'en']),
    Object.freeze(['pl-PL', 'pl', 'en-US', 'en']),
    Object.freeze(['pt-BR', 'pt', 'en-US', 'en']),
    Object.freeze(['pt-PT', 'pt', 'en-US', 'en']),
    Object.freeze(['ro-RO', 'ro', 'en-US', 'en']),
    Object.freeze(['ru-RU', 'ru', 'en-US', 'en']),
    Object.freeze(['sk-SK', 'sk', 'cs', 'en-US', 'en']),
    Object.freeze(['sl-SI', 'sl', 'en-GB', 'en']),
    Object.freeze(['sr-RS', 'sr', 'en-US', 'en']),
    Object.freeze(['sv-SE', 'sv', 'en-US', 'en']),
    Object.freeze(['sw', 'en-GB', 'en']),
    Object.freeze(['th-TH', 'th', 'en-US', 'en']),
    Object.freeze(['tr-TR', 'tr', 'en-US', 'en']),
    Object.freeze(['uk-UA', 'uk', 'en-US', 'en']),
    Object.freeze(['vi-VN', 'vi', 'fr-FR', 'fr', 'en-US', 'en']),
    Object.freeze(['zh-CN', 'zh']),
    Object.freeze(['zh-TW', 'zh', 'en-US', 'en']),
    Object.freeze(['zh-HK', 'zh-TW', 'zh', 'en-US', 'en'])
]);

/**
 * 3. Absorbed AdsPower Country-to-Timezone & Language Catalog (`Module 41056` & `Module 53716`)
 */
export const COUNTRY_GEO_PROFILE_CATALOG = Object.freeze({
    US: Object.freeze({ country: 'US', primaryLang: 'en-US', timeZone: 'America/New_York', allTimeZones: Object.freeze(['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles']) }),
    CA: Object.freeze({ country: 'CA', primaryLang: 'en-CA', timeZone: 'America/Toronto', allTimeZones: Object.freeze(['America/Toronto', 'America/Vancouver', 'America/Edmonton', 'America/Halifax']) }),
    GB: Object.freeze({ country: 'GB', primaryLang: 'en-GB', timeZone: 'Europe/London', allTimeZones: Object.freeze(['Europe/London']) }),
    AU: Object.freeze({ country: 'AU', primaryLang: 'en-AU', timeZone: 'Australia/Sydney', allTimeZones: Object.freeze(['Australia/Sydney', 'Australia/Melbourne', 'Australia/Brisbane', 'Australia/Perth']) }),
    DE: Object.freeze({ country: 'DE', primaryLang: 'de-DE', timeZone: 'Europe/Berlin', allTimeZones: Object.freeze(['Europe/Berlin']) }),
    AT: Object.freeze({ country: 'AT', primaryLang: 'de-AT', timeZone: 'Europe/Vienna', allTimeZones: Object.freeze(['Europe/Vienna']) }),
    CH: Object.freeze({ country: 'CH', primaryLang: 'de-CH', timeZone: 'Europe/Zurich', allTimeZones: Object.freeze(['Europe/Zurich']) }),
    FR: Object.freeze({ country: 'FR', primaryLang: 'fr-FR', timeZone: 'Europe/Paris', allTimeZones: Object.freeze(['Europe/Paris']) }),
    NL: Object.freeze({ country: 'NL', primaryLang: 'nl-NL', timeZone: 'Europe/Amsterdam', allTimeZones: Object.freeze(['Europe/Amsterdam']) }),
    ES: Object.freeze({ country: 'ES', primaryLang: 'es-ES', timeZone: 'Europe/Madrid', allTimeZones: Object.freeze(['Europe/Madrid']) }),
    IT: Object.freeze({ country: 'IT', primaryLang: 'it-IT', timeZone: 'Europe/Rome', allTimeZones: Object.freeze(['Europe/Rome']) }),
    PL: Object.freeze({ country: 'PL', primaryLang: 'pl-PL', timeZone: 'Europe/Warsaw', allTimeZones: Object.freeze(['Europe/Warsaw']) }),
    SE: Object.freeze({ country: 'SE', primaryLang: 'sv-SE', timeZone: 'Europe/Stockholm', allTimeZones: Object.freeze(['Europe/Stockholm']) }),
    NO: Object.freeze({ country: 'NO', primaryLang: 'nb-NO', timeZone: 'Europe/Oslo', allTimeZones: Object.freeze(['Europe/Oslo']) }),
    FI: Object.freeze({ country: 'FI', primaryLang: 'fi-FI', timeZone: 'Europe/Helsinki', allTimeZones: Object.freeze(['Europe/Helsinki']) }),
    DK: Object.freeze({ country: 'DK', primaryLang: 'da-DK', timeZone: 'Europe/Copenhagen', allTimeZones: Object.freeze(['Europe/Copenhagen']) }),
    CZ: Object.freeze({ country: 'CZ', primaryLang: 'cs-CZ', timeZone: 'Europe/Prague', allTimeZones: Object.freeze(['Europe/Prague']) }),
    RO: Object.freeze({ country: 'RO', primaryLang: 'ro-RO', timeZone: 'Europe/Bucharest', allTimeZones: Object.freeze(['Europe/Bucharest']) }),
    HU: Object.freeze({ country: 'HU', primaryLang: 'hu-HU', timeZone: 'Europe/Budapest', allTimeZones: Object.freeze(['Europe/Budapest']) }),
    GR: Object.freeze({ country: 'GR', primaryLang: 'el-GR', timeZone: 'Europe/Athens', allTimeZones: Object.freeze(['Europe/Athens']) }),
    PT: Object.freeze({ country: 'PT', primaryLang: 'pt-PT', timeZone: 'Europe/Lisbon', allTimeZones: Object.freeze(['Europe/Lisbon']) }),
    TR: Object.freeze({ country: 'TR', primaryLang: 'tr-TR', timeZone: 'Europe/Istanbul', allTimeZones: Object.freeze(['Europe/Istanbul']) }),
    UA: Object.freeze({ country: 'UA', primaryLang: 'uk-UA', timeZone: 'Europe/Kyiv', allTimeZones: Object.freeze(['Europe/Kyiv']) }),
    RU: Object.freeze({ country: 'RU', primaryLang: 'ru-RU', timeZone: 'Europe/Moscow', allTimeZones: Object.freeze(['Europe/Moscow', 'Asia/Yekaterinburg', 'Asia/Novosibirsk']) }),
    JP: Object.freeze({ country: 'JP', primaryLang: 'ja-JP', timeZone: 'Asia/Tokyo', allTimeZones: Object.freeze(['Asia/Tokyo']) }),
    KR: Object.freeze({ country: 'KR', primaryLang: 'ko-KR', timeZone: 'Asia/Seoul', allTimeZones: Object.freeze(['Asia/Seoul']) }),
    CN: Object.freeze({ country: 'CN', primaryLang: 'zh-CN', timeZone: 'Asia/Shanghai', allTimeZones: Object.freeze(['Asia/Shanghai']) }),
    TW: Object.freeze({ country: 'TW', primaryLang: 'zh-TW', timeZone: 'Asia/Taipei', allTimeZones: Object.freeze(['Asia/Taipei']) }),
    HK: Object.freeze({ country: 'HK', primaryLang: 'zh-HK', timeZone: 'Asia/Hong_Kong', allTimeZones: Object.freeze(['Asia/Hong_Kong']) }),
    SG: Object.freeze({ country: 'SG', primaryLang: 'en-US', timeZone: 'Asia/Singapore', allTimeZones: Object.freeze(['Asia/Singapore']) }),
    MY: Object.freeze({ country: 'MY', primaryLang: 'ms-MY', timeZone: 'Asia/Kuala_Lumpur', allTimeZones: Object.freeze(['Asia/Kuala_Lumpur']) }),
    TH: Object.freeze({ country: 'TH', primaryLang: 'th-TH', timeZone: 'Asia/Bangkok', allTimeZones: Object.freeze(['Asia/Bangkok']) }),
    VN: Object.freeze({ country: 'VN', primaryLang: 'vi-VN', timeZone: 'Asia/Ho_Chi_Minh', allTimeZones: Object.freeze(['Asia/Ho_Chi_Minh']) }),
    ID: Object.freeze({ country: 'ID', primaryLang: 'id-ID', timeZone: 'Asia/Jakarta', allTimeZones: Object.freeze(['Asia/Jakarta']) }),
    PH: Object.freeze({ country: 'PH', primaryLang: 'fil', timeZone: 'Asia/Manila', allTimeZones: Object.freeze(['Asia/Manila']) }),
    IN: Object.freeze({ country: 'IN', primaryLang: 'hi-IN', timeZone: 'Asia/Kolkata', allTimeZones: Object.freeze(['Asia/Kolkata']) }),
    AE: Object.freeze({ country: 'AE', primaryLang: 'ar', timeZone: 'Asia/Dubai', allTimeZones: Object.freeze(['Asia/Dubai']) }),
    SA: Object.freeze({ country: 'SA', primaryLang: 'ar-SA', timeZone: 'Asia/Riyadh', allTimeZones: Object.freeze(['Asia/Riyadh']) }),
    IL: Object.freeze({ country: 'IL', primaryLang: 'he-IL', timeZone: 'Asia/Jerusalem', allTimeZones: Object.freeze(['Asia/Jerusalem']) }),
    BR: Object.freeze({ country: 'BR', primaryLang: 'pt-BR', timeZone: 'America/Sao_Paulo', allTimeZones: Object.freeze(['America/Sao_Paulo']) }),
    MX: Object.freeze({ country: 'MX', primaryLang: 'es-MX', timeZone: 'America/Mexico_City', allTimeZones: Object.freeze(['America/Mexico_City']) }),
    AR: Object.freeze({ country: 'AR', primaryLang: 'es-AR', timeZone: 'America/Argentina/Buenos_Aires', allTimeZones: Object.freeze(['America/Argentina/Buenos_Aires']) })
});

/**
 * 4. OS-Authentic SpeechSynthesis Voices (`TTSEngines`) Catalog
 * Absorbed from AdsPower's 67 `TTSEngines` + Camoufox `voice-uris.json`, partitioned by OS so
 * Windows only exposes `urn:moz-tts:sapi:*` voices, macOS only exposes `com.apple.*` voices
 * (excluding Google Chrome-only cloud voices), and Linux only exposes `urn:moz-tts:speechd:*`.
 */
export const OS_SPEECH_VOICES_CATALOG = Object.freeze({
    windows: Object.freeze([
        Object.freeze({ name: 'Microsoft David Desktop - English (United States)', lang: 'en-US', voiceURI: 'urn:moz-tts:sapi:Microsoft David Desktop - English (United States)?en-US' }),
        Object.freeze({ name: 'Microsoft Zira Desktop - English (United States)', lang: 'en-US', voiceURI: 'urn:moz-tts:sapi:Microsoft Zira Desktop - English (United States)?en-US' }),
        Object.freeze({ name: 'Microsoft Mark - English (United States)', lang: 'en-US', voiceURI: 'urn:moz-tts:sapi:Microsoft Mark - English (United States)?en-US' }),
        Object.freeze({ name: 'Microsoft Hazel Desktop - English (Great Britain)', lang: 'en-GB', voiceURI: 'urn:moz-tts:sapi:Microsoft Hazel Desktop - English (Great Britain)?en-GB' }),
        Object.freeze({ name: 'Microsoft Hedda Desktop - German', lang: 'de-DE', voiceURI: 'urn:moz-tts:sapi:Microsoft Hedda Desktop - German?de-DE' }),
        Object.freeze({ name: 'Microsoft Hortense Desktop - French', lang: 'fr-FR', voiceURI: 'urn:moz-tts:sapi:Microsoft Hortense Desktop - French?fr-FR' }),
        Object.freeze({ name: 'Microsoft Helena Desktop - Spanish (Spain)', lang: 'es-ES', voiceURI: 'urn:moz-tts:sapi:Microsoft Helena Desktop - Spanish (Spain)?es-ES' }),
        Object.freeze({ name: 'Microsoft Sabina Desktop - Spanish (Mexico)', lang: 'es-MX', voiceURI: 'urn:moz-tts:sapi:Microsoft Sabina Desktop - Spanish (Mexico)?es-MX' }),
        Object.freeze({ name: 'Microsoft Elsa Desktop - Italian (Italy)', lang: 'it-IT', voiceURI: 'urn:moz-tts:sapi:Microsoft Elsa Desktop - Italian (Italy)?it-IT' }),
        Object.freeze({ name: 'Microsoft Haruka Desktop - Japanese', lang: 'ja-JP', voiceURI: 'urn:moz-tts:sapi:Microsoft Haruka Desktop - Japanese?ja-JP' }),
        Object.freeze({ name: 'Microsoft Heami Desktop - Korean', lang: 'ko-KR', voiceURI: 'urn:moz-tts:sapi:Microsoft Heami Desktop - Korean?ko-KR' }),
        Object.freeze({ name: 'Microsoft Huihui Desktop - Chinese (Simplified)', lang: 'zh-CN', voiceURI: 'urn:moz-tts:sapi:Microsoft Huihui Desktop - Chinese (Simplified)?zh-CN' }),
        Object.freeze({ name: 'Microsoft Hanhan Desktop - Chinese (Taiwan)', lang: 'zh-TW', voiceURI: 'urn:moz-tts:sapi:Microsoft Hanhan Desktop - Chinese (Taiwan)?zh-TW' }),
        Object.freeze({ name: 'Microsoft Tracy Desktop - Chinese (Traditional, Hong Kong S.A.R.)', lang: 'zh-HK', voiceURI: 'urn:moz-tts:sapi:Microsoft Tracy Desktop - Chinese (Traditional, Hong Kong S.A.R.)?zh-HK' }),
        Object.freeze({ name: 'Microsoft Maria Desktop - Portuguese (Brazil)', lang: 'pt-BR', voiceURI: 'urn:moz-tts:sapi:Microsoft Maria Desktop - Portuguese (Brazil)?pt-BR' }),
        Object.freeze({ name: 'Microsoft Irina Desktop - Russian', lang: 'ru-RU', voiceURI: 'urn:moz-tts:sapi:Microsoft Irina Desktop - Russian?ru-RU' }),
        Object.freeze({ name: 'Microsoft Paulina Desktop - Polish', lang: 'pl-PL', voiceURI: 'urn:moz-tts:sapi:Microsoft Paulina Desktop - Polish?pl-PL' })
    ]),
    macos: Object.freeze([
        Object.freeze({ name: 'Samantha', lang: 'en-US', voiceURI: 'com.apple.speech.synthesis.voice.samantha' }),
        Object.freeze({ name: 'Alex', lang: 'en-US', voiceURI: 'com.apple.speech.synthesis.voice.Alex' }),
        Object.freeze({ name: 'Victoria', lang: 'en-US', voiceURI: 'com.apple.speech.synthesis.voice.Victoria' }),
        Object.freeze({ name: 'Fred', lang: 'en-US', voiceURI: 'com.apple.speech.synthesis.voice.Fred' }),
        Object.freeze({ name: 'Daniel', lang: 'en-GB', voiceURI: 'com.apple.voice.compact.en-GB.Daniel' }),
        Object.freeze({ name: 'Karen', lang: 'en-AU', voiceURI: 'com.apple.voice.compact.en-AU.Karen' }),
        Object.freeze({ name: 'Moira', lang: 'en-IE', voiceURI: 'com.apple.voice.compact.en-IE.Moira' }),
        Object.freeze({ name: 'Rishi', lang: 'en-IN', voiceURI: 'com.apple.voice.compact.en-IN.Rishi' }),
        Object.freeze({ name: 'Tessa', lang: 'en-ZA', voiceURI: 'com.apple.voice.compact.en-ZA.Tessa' }),
        Object.freeze({ name: 'Anna', lang: 'de-DE', voiceURI: 'com.apple.voice.compact.de-DE.Anna' }),
        Object.freeze({ name: 'Thomas', lang: 'fr-FR', voiceURI: 'com.apple.voice.compact.fr-FR.Thomas' }),
        Object.freeze({ name: 'Amelie', lang: 'fr-CA', voiceURI: 'com.apple.voice.compact.fr-CA.Amelie' }),
        Object.freeze({ name: 'Monica', lang: 'es-ES', voiceURI: 'com.apple.voice.compact.es-ES.Monica' }),
        Object.freeze({ name: 'Paulina', lang: 'es-MX', voiceURI: 'com.apple.voice.compact.es-MX.Paulina' }),
        Object.freeze({ name: 'Alice', lang: 'it-IT', voiceURI: 'com.apple.voice.compact.it-IT.Alice' }),
        Object.freeze({ name: 'Kyoko', lang: 'ja-JP', voiceURI: 'com.apple.voice.compact.ja-JP.Kyoko' }),
        Object.freeze({ name: 'Yuna', lang: 'ko-KR', voiceURI: 'com.apple.voice.compact.ko-KR.Yuna' }),
        Object.freeze({ name: 'Ting-Ting', lang: 'zh-CN', voiceURI: 'com.apple.voice.compact.zh-CN.Tingting' }),
        Object.freeze({ name: 'Mei-Jia', lang: 'zh-TW', voiceURI: 'com.apple.voice.compact.zh-TW.Meijia' }),
        Object.freeze({ name: 'Sin-ji', lang: 'zh-HK', voiceURI: 'com.apple.voice.compact.zh-HK.Sinji' }),
        Object.freeze({ name: 'Luciana', lang: 'pt-BR', voiceURI: 'com.apple.voice.compact.pt-BR.Luciana' }),
        Object.freeze({ name: 'Milena', lang: 'ru-RU', voiceURI: 'com.apple.voice.compact.ru-RU.Milena' }),
        Object.freeze({ name: 'Xander', lang: 'nl-NL', voiceURI: 'com.apple.voice.compact.nl-NL.Xander' }),
        Object.freeze({ name: 'Zosia', lang: 'pl-PL', voiceURI: 'com.apple.voice.compact.pl-PL.Zosia' }),
        Object.freeze({ name: 'Yelda', lang: 'tr-TR', voiceURI: 'com.apple.voice.compact.tr-TR.Yelda' }),
        Object.freeze({ name: 'Damayanti', lang: 'id-ID', voiceURI: 'com.apple.voice.compact.id-ID.Damayanti' }),
        Object.freeze({ name: 'Kanya', lang: 'th-TH', voiceURI: 'com.apple.voice.compact.th-TH.Kanya' }),
        Object.freeze({ name: 'Alva', lang: 'sv-SE', voiceURI: 'com.apple.voice.compact.sv-SE.Alva' }),
        Object.freeze({ name: 'Nora', lang: 'nb-NO', voiceURI: 'com.apple.voice.compact.nb-NO.Nora' }),
        Object.freeze({ name: 'Sara', lang: 'da-DK', voiceURI: 'com.apple.voice.compact.da-DK.Sara' }),
        Object.freeze({ name: 'Satu', lang: 'fi-FI', voiceURI: 'com.apple.voice.compact.fi-FI.Satu' }),
        Object.freeze({ name: 'Zuzana', lang: 'cs-CZ', voiceURI: 'com.apple.voice.compact.cs-CZ.Zuzana' }),
        Object.freeze({ name: 'Mariska', lang: 'hu-HU', voiceURI: 'com.apple.voice.compact.hu-HU.Mariska' }),
        Object.freeze({ name: 'Melina', lang: 'el-GR', voiceURI: 'com.apple.voice.compact.el-GR.Melina' }),
        Object.freeze({ name: 'Carmit', lang: 'he-IL', voiceURI: 'com.apple.voice.compact.he-IL.Carmit' }),
        Object.freeze({ name: 'Maged', lang: 'ar-SA', voiceURI: 'com.apple.voice.compact.ar-001.Maged' })
    ]),
    linux: Object.freeze([
        Object.freeze({ name: 'English (America)', lang: 'en-US', voiceURI: 'urn:moz-tts:speechd:English%20(America)?en' }),
        Object.freeze({ name: 'English (Great Britain)', lang: 'en-GB', voiceURI: 'urn:moz-tts:speechd:English%20(Great%20Britain)?en-gb' }),
        Object.freeze({ name: 'German', lang: 'de-DE', voiceURI: 'urn:moz-tts:speechd:German?de' }),
        Object.freeze({ name: 'French (France)', lang: 'fr-FR', voiceURI: 'urn:moz-tts:speechd:French%20(France)?fr' }),
        Object.freeze({ name: 'Spanish (Spain)', lang: 'es-ES', voiceURI: 'urn:moz-tts:speechd:Spanish%20(Spain)?es' }),
        Object.freeze({ name: 'Italian', lang: 'it-IT', voiceURI: 'urn:moz-tts:speechd:Italian?it' }),
        Object.freeze({ name: 'Portuguese (Brazil)', lang: 'pt-BR', voiceURI: 'urn:moz-tts:speechd:Portuguese%20(Brazil)?pt-br' }),
        Object.freeze({ name: 'Russian', lang: 'ru-RU', voiceURI: 'urn:moz-tts:speechd:Russian?ru' }),
        Object.freeze({ name: 'Mandarin', lang: 'zh-CN', voiceURI: 'urn:moz-tts:speechd:Mandarin?zh' }),
        Object.freeze({ name: 'Japanese', lang: 'ja-JP', voiceURI: 'urn:moz-tts:speechd:Japanese?ja' })
    ])
});

/**
 * 5. OS-Authentic MediaDevices Audio/Video Hardware Cards
 * Absorbed from AdsPower `Module 82088` (`createmediaDevices`) + Camoufox `media-devices.json`.
 */
export const OS_MEDIA_DEVICES_CATALOG = Object.freeze({
    windows: Object.freeze({
        audioCards: Object.freeze([
            Object.freeze({ input: 'Microphone Array (Realtek(R) Audio)', output: 'Speakers (Realtek(R) Audio)' }),
            Object.freeze({ input: 'Microphone (Realtek(R) Audio)', output: 'Speakers (Realtek(R) Audio)' }),
            Object.freeze({ input: 'Microphone Array (Intel® Smart Sound Technology for Digital Microphones)', output: 'Speaker (Realtek(R) Audio)' }),
            Object.freeze({ input: 'Microphone Array (Realtek High Definition Audio)', output: 'Speaker/Headphone (Realtek High Definition Audio)' }),
            Object.freeze({ input: 'Microphone Array (2- Realtek High Definition Audio)', output: 'Speaker/Headphone (2- Realtek High Definition Audio)' }),
            Object.freeze({ input: 'Microphone Array (Conexant SmartAudio HD)', output: 'Speaker (Conexant SmartAudio HD)' }),
            Object.freeze({ input: 'Microphone (Conexant ISST Audio)', output: 'Speakers (Conexant ISST Audio)' }),
            Object.freeze({ input: 'Microphone Array (Synaptics Audio)', output: 'Speaker (Synaptics Audio)' }),
            Object.freeze({ input: 'Microphone Array (AMD Audio Device)', output: 'Speakers (Realtek(R) Audio)' }),
            Object.freeze({ input: 'Microphone (High Definition Audio Device)', output: 'Speakers (High Definition Audio Device)' })
        ]),
        cameras: Object.freeze([
            'Integrated Camera',
            'Integrated Webcam',
            'HD User Facing',
            'HP TrueVision FHD Camera',
            'FHD Webcam',
            'HD Pro Webcam C920'
        ])
    }),
    macos: Object.freeze({
        audioCards: Object.freeze([
            Object.freeze({ input: 'MacBook Pro Microphone', output: 'MacBook Pro Speakers' }),
            Object.freeze({ input: 'MacBook Air Microphone', output: 'MacBook Air Speakers' }),
            Object.freeze({ input: 'Built-in Microphone', output: 'Built-in Output' }),
            Object.freeze({ input: 'Studio Display Microphone', output: 'Studio Display Speakers' }),
            Object.freeze({ input: 'iMac Microphone', output: 'iMac Speakers' })
        ]),
        cameras: Object.freeze([
            'FaceTime HD Camera',
            'FaceTime HD Camera (Built-in)',
            'Studio Display Camera'
        ])
    }),
    linux: Object.freeze({
        audioCards: Object.freeze([
            Object.freeze({ input: 'Alder Lake PCH-P High Definition Audio Controller Analog Stereo', output: 'Alder Lake PCH-P High Definition Audio Controller Analog Stereo' }),
            Object.freeze({ input: 'Raptor Lake-P/U/H cAVS Analog Stereo', output: 'Raptor Lake-P/U/H cAVS Analog Stereo' }),
            Object.freeze({ input: 'Family 17h/19h HD Audio Controller Analog Stereo', output: 'Family 17h/19h HD Audio Controller Analog Stereo' }),
            Object.freeze({ input: 'Rembrandt Radeon High Definition Audio Controller Analog Stereo', output: 'Rembrandt Radeon High Definition Audio Controller Analog Stereo' }),
            Object.freeze({ input: 'Built-in Audio Analog Stereo', output: 'Built-in Audio Analog Stereo' })
        ]),
        cameras: Object.freeze([
            'Integrated Camera: Integrated C (04f2:b6d9)',
            'Integrated_Webcam_HD: Integrate (0c45:6a06)',
            'Chicony USB2.0 Camera: Chicony (04f2:b6ea)',
            'Laptop_Integrated_Webcam_HD: In (0c45:64d0)',
            'HD Pro Webcam C920 (046d:082d)'
        ])
    })
});

/**
 * 6. Ready-to-Use 100% SKU-Verified Device Preset Catalog (`USABLE_DEVICE_PRESET_CATALOG`)
 *
 * Every entry in this catalog is an atomic, real-world machine specification that passes
 * all 17/17 Camoufox & exact hardware SKU coherence checks (`100/100`).
 */
export const USABLE_DEVICE_PRESET_CATALOG = Object.freeze([
    // =========================================================================
    // A. macOS Apple Silicon (M1 / M2 / M3 / M4 / M5) & Intel Mac Presets
    // =========================================================================
    Object.freeze({
        presetId: 'mac-mba13-m1-8c-16g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Air (M1, 2020)',
        deviceNameSuffix: 'MacBook Air',
        macOuiPrefixes: Object.freeze(['F0:18:98', '3C:22:FB', 'A8:5C:2C']),
        cpuModel: 'Apple M1',
        gpuModel: 'Apple M1',
        hardwareConcurrency: 8,
        ramGb: 16,
        storageGb: 512,
        architecture: 'arm',
        osVersion: '14.6.1',
        screen: Object.freeze({ width: 1440, height: 900, availWidth: 1440, availHeight: 862, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M1',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'common-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mba13-m2-8c-16g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Air 13.6" (M2, 2022)',
        deviceNameSuffix: 'MacBook Air',
        macOuiPrefixes: Object.freeze(['F0:18:98', '3C:22:FB', '14:98:77']),
        cpuModel: 'Apple M2',
        gpuModel: 'Apple M2',
        hardwareConcurrency: 8,
        ramGb: 16,
        storageGb: 512,
        architecture: 'arm',
        osVersion: '15.2.0',
        screen: Object.freeze({ width: 1470, height: 956, availWidth: 1470, availHeight: 918, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M2',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'common-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mba15-m3-8c-24g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Air 15.3" (M3, 2024)',
        deviceNameSuffix: 'MacBook Air',
        macOuiPrefixes: Object.freeze(['14:98:77', '3C:22:FB']),
        cpuModel: 'Apple M3',
        gpuModel: 'Apple M3',
        hardwareConcurrency: 8,
        ramGb: 24,
        storageGb: 1024,
        architecture: 'arm',
        osVersion: '15.3.1',
        screen: Object.freeze({ width: 1710, height: 1107, availWidth: 1710, availHeight: 1069, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M3',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp14-m1-pro-10c-32g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 14" (M1 Pro, 2021)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['F0:18:98', '3C:22:FB']),
        cpuModel: 'Apple M1 Pro',
        gpuModel: 'Apple M1 Pro',
        hardwareConcurrency: 10,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'arm',
        osVersion: '14.7.0',
        screen: Object.freeze({ width: 1512, height: 982, availWidth: 1512, availHeight: 944, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M1 Pro',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'common-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp14-m2-pro-10c-16g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 14" (M2 Pro, 2023)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['3C:22:FB', '14:98:77']),
        cpuModel: 'Apple M2 Pro',
        gpuModel: 'Apple M2 Pro',
        hardwareConcurrency: 10,
        ramGb: 16,
        storageGb: 512,
        architecture: 'arm',
        osVersion: '15.2.0',
        screen: Object.freeze({ width: 1512, height: 982, availWidth: 1512, availHeight: 944, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M2 Pro',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'common-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp16-m2-max-12c-64g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 16" (M2 Max, 2023)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['3C:22:FB', '14:98:77']),
        cpuModel: 'Apple M2 Max',
        gpuModel: 'Apple M2 Max',
        hardwareConcurrency: 12,
        ramGb: 64,
        storageGb: 2048,
        architecture: 'arm',
        osVersion: '15.3.0',
        screen: Object.freeze({ width: 1728, height: 1117, availWidth: 1728, availHeight: 1079, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M2 Max',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'common-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp14-m3-pro-12c-18g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 14" (M3 Pro, 2023)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['14:98:77', 'A8:5C:2C']),
        cpuModel: 'Apple M3 Pro',
        gpuModel: 'Apple M3 Pro',
        hardwareConcurrency: 12,
        ramGb: 18,
        storageGb: 512,
        architecture: 'arm',
        osVersion: '15.3.2',
        screen: Object.freeze({ width: 1512, height: 982, availWidth: 1512, availHeight: 944, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M3 Pro',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp16-m3-max-16c-64g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 16" (M3 Max, 2023)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['14:98:77', 'A8:5C:2C']),
        cpuModel: 'Apple M3 Max',
        gpuModel: 'Apple M3 Max',
        hardwareConcurrency: 16,
        ramGb: 64,
        storageGb: 2048,
        architecture: 'arm',
        osVersion: '15.4.0',
        screen: Object.freeze({ width: 1728, height: 1117, availWidth: 1728, availHeight: 1079, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M3 Max',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp14-m4-pro-14c-48g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 14" (M4 Pro, 2024)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['14:98:77', 'A8:5C:2C']),
        cpuModel: 'Apple M4 Pro',
        gpuModel: 'Apple M4 Pro',
        hardwareConcurrency: 14,
        ramGb: 48,
        storageGb: 1024,
        architecture: 'arm',
        osVersion: '15.4.1',
        screen: Object.freeze({ width: 1512, height: 982, availWidth: 1512, availHeight: 944, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M4 Pro',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp16-m4-max-16c-128g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 16" (M4 Max, 2024)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['14:98:77', 'A8:5C:2C']),
        cpuModel: 'Apple M4 Max',
        gpuModel: 'Apple M4 Max',
        hardwareConcurrency: 16,
        ramGb: 128,
        storageGb: 4096,
        architecture: 'arm',
        osVersion: '15.5.0',
        screen: Object.freeze({ width: 1728, height: 1117, availWidth: 1728, availHeight: 1079, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M4 Max',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp14-m5-10c-24g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 14" (M5, 2025)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['14:98:77', 'A8:5C:2C']),
        cpuModel: 'Apple M5',
        gpuModel: 'Apple M5',
        hardwareConcurrency: 10,
        ramGb: 24,
        storageGb: 1024,
        architecture: 'arm',
        osVersion: '26.1.0',
        screen: Object.freeze({ width: 1512, height: 982, availWidth: 1512, availHeight: 944, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M5',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp16-m5-pro-18c-64g',
        os: 'macos',
        category: 'apple-silicon-laptop',
        deviceModel: 'MacBook Pro 16" (M5 Pro, 2025)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['14:98:77', 'A8:5C:2C']),
        cpuModel: 'Apple M5 Pro',
        gpuModel: 'Apple M5 Pro',
        hardwareConcurrency: 18,
        ramGb: 64,
        storageGb: 2048,
        architecture: 'arm',
        osVersion: '26.1.0',
        screen: Object.freeze({ width: 1728, height: 1117, availWidth: 1728, availHeight: 1079, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M5 Pro',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mini-m4-10c-16g',
        os: 'macos',
        category: 'apple-silicon-desktop',
        deviceModel: 'Mac mini (M4, 2024)',
        deviceNameSuffix: 'Mac mini',
        macOuiPrefixes: Object.freeze(['14:98:77', '3C:22:FB']),
        cpuModel: 'Apple M4',
        gpuModel: 'Apple M4',
        hardwareConcurrency: 10,
        ramGb: 16,
        storageGb: 512,
        architecture: 'arm',
        osVersion: '15.3.0',
        screen: Object.freeze({ width: 2560, height: 1440, availWidth: 2560, availHeight: 1402, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M4',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-imac24-m3-8c-16g',
        os: 'macos',
        category: 'apple-silicon-desktop',
        deviceModel: 'iMac 24-inch (M3, 2023)',
        deviceNameSuffix: 'iMac',
        macOuiPrefixes: Object.freeze(['14:98:77', '3C:22:FB']),
        cpuModel: 'Apple M3',
        gpuModel: 'Apple M3',
        hardwareConcurrency: 8,
        ramGb: 16,
        storageGb: 512,
        architecture: 'arm',
        osVersion: '15.2.0',
        screen: Object.freeze({ width: 2240, height: 1260, availWidth: 2240, availHeight: 1222, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M3',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'metal-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-studio-m2-ultra-24c-128g',
        os: 'macos',
        category: 'apple-silicon-desktop',
        deviceModel: 'Mac Studio (M2 Ultra, 2023)',
        deviceNameSuffix: 'Mac Studio',
        macOuiPrefixes: Object.freeze(['14:98:77', '3C:22:FB']),
        cpuModel: 'Apple M2 Ultra',
        gpuModel: 'Apple M2 Ultra',
        hardwareConcurrency: 24,
        ramGb: 128,
        storageGb: 2048,
        architecture: 'arm',
        osVersion: '15.3.0',
        screen: Object.freeze({ width: 2560, height: 1440, availWidth: 2560, availHeight: 1402, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Apple',
            unmaskedRenderer: 'Apple M2 Ultra',
            GPUAdapterInfo: Object.freeze({ vendor: 'apple', architecture: 'common-3' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp13-intel-i5-iris655',
        os: 'macos',
        category: 'intel-mac-laptop',
        deviceModel: 'MacBook Pro 13-inch (Intel 2018-2020)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['F0:18:98', '00:1C:B3']),
        cpuModel: 'Intel Core i5-8259U',
        gpuModel: 'Intel(R) Iris(TM) Plus Graphics 655',
        hardwareConcurrency: 8,
        ramGb: 16,
        storageGb: 512,
        architecture: 'x86',
        osVersion: '14.7.1',
        webgpuAvailable: false,
        screen: Object.freeze({ width: 1440, height: 900, availWidth: 1440, availHeight: 862, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Intel Inc.',
            unmaskedRenderer: 'Intel(R) Iris(TM) Plus Graphics 655',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'gen-9' })
        })
    }),
    Object.freeze({
        presetId: 'mac-mbp16-intel-i9-radeon5500m',
        os: 'macos',
        category: 'intel-mac-laptop',
        deviceModel: 'MacBook Pro 15/16-inch (Intel 2018-2019)',
        deviceNameSuffix: 'MacBook Pro',
        macOuiPrefixes: Object.freeze(['F0:18:98', '00:1C:B3']),
        cpuModel: 'Intel Core i9-9880H',
        gpuModel: 'AMD Radeon Pro 5500M',
        hardwareConcurrency: 16,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '14.7.1',
        webgpuAvailable: false,
        screen: Object.freeze({ width: 1792, height: 1120, availWidth: 1792, availHeight: 1082, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'ATI Technologies Inc.',
            unmaskedRenderer: 'AMD Radeon Pro 5500M OpenGL Engine',
            GPUAdapterInfo: Object.freeze({ vendor: 'amd', architecture: 'rdna-1' })
        })
    }),
    Object.freeze({
        presetId: 'mac-imac27-intel-5700xt',
        os: 'macos',
        category: 'intel-mac-desktop',
        deviceModel: 'iMac 27-inch 5K / iMac Pro (Intel)',
        deviceNameSuffix: 'iMac',
        macOuiPrefixes: Object.freeze(['F0:18:98', '00:1C:B3']),
        cpuModel: 'Intel Core i7-10700K',
        gpuModel: 'AMD Radeon Pro 5700 XT',
        hardwareConcurrency: 16,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '14.7.1',
        webgpuAvailable: false,
        screen: Object.freeze({ width: 2560, height: 1440, availWidth: 2560, availHeight: 1402, colorDepth: 30, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'ATI Technologies Inc.',
            unmaskedRenderer: 'AMD Radeon Pro 5700 XT OpenGL Engine',
            GPUAdapterInfo: Object.freeze({ vendor: 'amd', architecture: 'rdna-1' })
        })
    }),

    // =========================================================================
    // B. Windows 10/11 OEM Laptops, Copilot+ ARM64 & Custom Gaming Desktops
    // =========================================================================
    Object.freeze({
        presetId: 'win-thinkpad-x1-gen11-i7-32g',
        os: 'windows',
        category: 'windows-oem-ultrabook',
        deviceModel: 'Lenovo ThinkPad X1 Carbon Gen 11',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', 'A4:34:D9', '54:E1:AD']),
        cpuModel: 'Intel Core i7-1355U',
        gpuModel: 'Intel(R) Iris(R) Xe Graphics',
        hardwareConcurrency: 12,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '10.0.22631',
        screen: Object.freeze({ width: 1920, height: 1200, availWidth: 1920, availHeight: 1152, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (Intel)',
            unmaskedRenderer: 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x0000A7A1) Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'gen-12lp' })
        })
    }),
    Object.freeze({
        presetId: 'win-thinkpad-x1-gen12-ultra7-32g',
        os: 'windows',
        category: 'windows-oem-ultrabook',
        deviceModel: 'Lenovo ThinkPad X1 Carbon Gen 12',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', 'A4:34:D9', '54:E1:AD']),
        cpuModel: 'Intel Core Ultra 7 155H',
        gpuModel: 'Intel(R) Arc(TM) Graphics',
        hardwareConcurrency: 22,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '10.0.26100',
        screen: Object.freeze({ width: 1920, height: 1200, availWidth: 1920, availHeight: 1152, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (Intel)',
            unmaskedRenderer: 'ANGLE (Intel, Intel(R) Arc(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'xe-lpg' })
        })
    }),
    Object.freeze({
        presetId: 'win-dell-xps13-9340-ultra7-32g',
        os: 'windows',
        category: 'windows-oem-ultrabook',
        deviceModel: 'Dell XPS 13 9340',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', 'A4:34:D9']),
        cpuModel: 'Intel Core Ultra 7 155H',
        gpuModel: 'Intel(R) Arc(TM) Graphics',
        hardwareConcurrency: 22,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '10.0.26100',
        screen: Object.freeze({ width: 1920, height: 1200, availWidth: 1920, availHeight: 1152, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (Intel)',
            unmaskedRenderer: 'ANGLE (Intel, Intel(R) Arc(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'xe-lpg' })
        })
    }),
    Object.freeze({
        presetId: 'win-dell-xps16-9640-rtx4070-32g',
        os: 'windows',
        category: 'windows-oem-creator-laptop',
        deviceModel: 'Dell XPS 16 9640',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', 'A4:34:D9']),
        cpuModel: 'Intel Core Ultra 9 185H',
        gpuModel: 'NVIDIA GeForce RTX 4070 Laptop GPU',
        hardwareConcurrency: 22,
        ramGb: 32,
        vramGb: 8,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '10.0.26100',
        screen: Object.freeze({ width: 1920, height: 1200, availWidth: 1920, availHeight: 1152, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (NVIDIA)',
            unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'nvidia', architecture: 'ada-lovelace' })
        })
    }),
    Object.freeze({
        presetId: 'win-surface-laptop5-i7-16g',
        os: 'windows',
        category: 'windows-oem-ultrabook',
        deviceModel: 'Microsoft Surface Laptop 5',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', '28:18:78']),
        cpuModel: 'Intel Core i7-1255U',
        gpuModel: 'Intel(R) Iris(R) Xe Graphics',
        hardwareConcurrency: 12,
        ramGb: 16,
        storageGb: 512,
        architecture: 'x86',
        osVersion: '10.0.22631',
        screen: Object.freeze({ width: 1504, height: 1003, availWidth: 1504, availHeight: 955, colorDepth: 24, devicePixelRatio: 1.5 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (Intel)',
            unmaskedRenderer: 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'gen-12lp' })
        })
    }),
    Object.freeze({
        presetId: 'win-surface-pro9-i7-16g-touch',
        os: 'windows',
        category: 'windows-oem-2in1',
        deviceModel: 'Microsoft Surface Pro 9',
        deviceNamePrefix: 'DESKTOP-',
        macOuiPrefixes: Object.freeze(['28:18:78', '8C:8D:28']),
        cpuModel: 'Intel Core i7-1255U',
        gpuModel: 'Intel(R) Iris(R) Xe Graphics',
        hardwareConcurrency: 12,
        maxTouchPoints: 10,
        ramGb: 16,
        storageGb: 512,
        architecture: 'x86',
        osVersion: '10.0.22631',
        screen: Object.freeze({ width: 1440, height: 960, availWidth: 1440, availHeight: 912, colorDepth: 24, devicePixelRatio: 2 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (Intel)',
            unmaskedRenderer: 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'gen-12lp' })
        })
    }),
    Object.freeze({
        presetId: 'win-rog-zephyrus-g14-2024-rtx4070',
        os: 'windows',
        category: 'windows-oem-gaming-laptop',
        deviceModel: 'ASUS ROG Zephyrus G14 (2024)',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['04:42:1A', 'F0:2F:74']),
        cpuModel: 'AMD Ryzen 9 8945HS',
        gpuModel: 'NVIDIA GeForce RTX 4070 Laptop GPU',
        hardwareConcurrency: 16,
        ramGb: 32,
        vramGb: 8,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '10.0.22631',
        screen: Object.freeze({ width: 1920, height: 1200, availWidth: 1920, availHeight: 1152, colorDepth: 24, devicePixelRatio: 1.5 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (NVIDIA)',
            unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'nvidia', architecture: 'ada-lovelace' })
        })
    }),
    Object.freeze({
        presetId: 'win-razer-blade16-i9-rtx4090',
        os: 'windows',
        category: 'windows-oem-gaming-laptop',
        deviceModel: 'Razer Blade 16',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', 'A4:34:D9']),
        cpuModel: 'Intel Core i9-14900HX',
        gpuModel: 'NVIDIA GeForce RTX 4090 Laptop GPU',
        hardwareConcurrency: 32,
        ramGb: 64,
        vramGb: 16,
        storageGb: 2048,
        architecture: 'x86',
        osVersion: '10.0.26100',
        screen: Object.freeze({ width: 2560, height: 1600, availWidth: 2560, availHeight: 1552, colorDepth: 24, devicePixelRatio: 1.5 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (NVIDIA)',
            unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Laptop GPU (0x00002717) Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'nvidia', architecture: 'ada-lovelace' })
        })
    }),
    Object.freeze({
        presetId: 'win-lunar-lake-ultra7-258v-32g',
        os: 'windows',
        category: 'windows-oem-ultrabook',
        deviceModel: 'ASUS Zenbook S 14 (Lunar Lake)',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', 'A4:34:D9']),
        cpuModel: 'Intel Core Ultra 7 258V',
        gpuModel: 'Intel(R) Arc(TM) 140V Graphics',
        hardwareConcurrency: 8,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '10.0.26100',
        screen: Object.freeze({ width: 1920, height: 1200, availWidth: 1920, availHeight: 1152, colorDepth: 24, devicePixelRatio: 1.5 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (Intel)',
            unmaskedRenderer: 'ANGLE (Intel, Intel(R) Arc(TM) 140V Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'xe2-lpg' })
        })
    }),
    Object.freeze({
        presetId: 'win-snapdragon-x-elite-12c-32g',
        os: 'windows',
        category: 'windows-copilot-arm64',
        deviceModel: 'Surface Laptop 7th Edition (Snapdragon X Elite)',
        deviceNamePrefix: 'LAPTOP-',
        macOuiPrefixes: Object.freeze(['28:18:78', '8C:8D:28']),
        cpuModel: 'Snapdragon X Elite X1E-84-100',
        gpuModel: 'Qualcomm(R) Adreno(TM) X1-85 GPU',
        hardwareConcurrency: 12,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'arm',
        osVersion: '10.0.26100',
        screen: Object.freeze({ width: 1504, height: 1003, availWidth: 1504, availHeight: 955, colorDepth: 24, devicePixelRatio: 1.5 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (Qualcomm)',
            unmaskedRenderer: 'ANGLE (Qualcomm, Qualcomm(R) Adreno(TM) X1-85 GPU Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'qualcomm', architecture: 'adreno-x1' })
        })
    }),
    Object.freeze({
        presetId: 'win-desktop-i5-12400f-rtx3060-16g',
        os: 'windows',
        category: 'windows-desktop-pc',
        deviceModel: 'Custom Desktop PC (Intel 12th Gen + RTX 3060)',
        deviceNamePrefix: 'DESKTOP-',
        macOuiPrefixes: Object.freeze(['00:E0:4C', '04:42:1A']),
        cpuModel: 'Intel Core i5-12400F',
        gpuModel: 'NVIDIA GeForce RTX 3060',
        hardwareConcurrency: 12,
        ramGb: 16,
        vramGb: 12,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '10.0.22631',
        screen: Object.freeze({ width: 1920, height: 1080, availWidth: 1920, availHeight: 1032, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (NVIDIA)',
            unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'nvidia', architecture: 'ampere' })
        })
    }),
    Object.freeze({
        presetId: 'win-desktop-i7-13700k-rtx4070-32g',
        os: 'windows',
        category: 'windows-desktop-pc',
        deviceModel: 'Custom Desktop PC (Intel 13th Gen + RTX 4070)',
        deviceNamePrefix: 'DESKTOP-',
        macOuiPrefixes: Object.freeze(['00:E0:4C', '04:42:1A']),
        cpuModel: 'Intel Core i7-13700K',
        gpuModel: 'NVIDIA GeForce RTX 4070',
        hardwareConcurrency: 24,
        ramGb: 32,
        vramGb: 12,
        storageGb: 2048,
        architecture: 'x86',
        osVersion: '10.0.22631',
        screen: Object.freeze({ width: 2560, height: 1440, availWidth: 2560, availHeight: 1392, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (NVIDIA)',
            unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 (0x00002786) Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'nvidia', architecture: 'ada-lovelace' })
        })
    }),
    Object.freeze({
        presetId: 'win-desktop-r7-7800x3d-rtx4080-32g',
        os: 'windows',
        category: 'windows-desktop-pc',
        deviceModel: 'Custom Gaming Desktop (AMD Ryzen 7 7800X3D + RTX 4080)',
        deviceNamePrefix: 'DESKTOP-',
        macOuiPrefixes: Object.freeze(['00:E0:4C', '04:42:1A']),
        cpuModel: 'AMD Ryzen 7 7800X3D',
        gpuModel: 'NVIDIA GeForce RTX 4080',
        hardwareConcurrency: 16,
        ramGb: 32,
        vramGb: 16,
        storageGb: 2048,
        architecture: 'x86',
        osVersion: '10.0.26100',
        screen: Object.freeze({ width: 2560, height: 1440, availWidth: 2560, availHeight: 1392, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (NVIDIA)',
            unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4080 (0x00002704) Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'nvidia', architecture: 'ada-lovelace' })
        })
    }),
    Object.freeze({
        presetId: 'win-desktop-i9-14900k-rtx4090-64g',
        os: 'windows',
        category: 'windows-desktop-pc',
        deviceModel: 'Custom Workstation Desktop (Intel i9-14900K + RTX 4090)',
        deviceNamePrefix: 'DESKTOP-',
        macOuiPrefixes: Object.freeze(['00:E0:4C', '04:42:1A']),
        cpuModel: 'Intel Core i9-14900K',
        gpuModel: 'NVIDIA GeForce RTX 4090',
        hardwareConcurrency: 32,
        ramGb: 64,
        vramGb: 24,
        storageGb: 4096,
        architecture: 'x86',
        osVersion: '10.0.26100',
        screen: Object.freeze({ width: 3840, height: 2160, availWidth: 3840, availHeight: 2112, colorDepth: 24, devicePixelRatio: 1.5 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Google Inc. (NVIDIA)',
            unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 (0x00002684) Direct3D11 vs_5_0 ps_5_0, D3D11)',
            GPUAdapterInfo: Object.freeze({ vendor: 'nvidia', architecture: 'ada-lovelace' })
        })
    }),

    // =========================================================================
    // C. Linux Laptop & Workstation Presets (Framework, System76, ThinkPad, Ryzen)
    // =========================================================================
    Object.freeze({
        presetId: 'lin-framework13-r7-7840u-32g',
        os: 'linux',
        category: 'linux-oem-laptop',
        deviceModel: 'Framework Laptop 13',
        deviceNamePrefix: 'framework-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', 'A4:34:D9']),
        cpuModel: 'AMD Ryzen 7 7840U',
        gpuModel: 'AMD Radeon 780M',
        hardwareConcurrency: 16,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '6.8.0',
        webgpuAvailable: false,
        screen: Object.freeze({ width: 1920, height: 1200, availWidth: 1920, availHeight: 1172, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'AMD',
            unmaskedRenderer: 'AMD Radeon 780M (radeonsi, phoenix, LLVM 17.0.6, DRM 3.57, 6.8.0-45-generic)',
            GPUAdapterInfo: Object.freeze({ vendor: 'amd', architecture: 'rdna-3' })
        })
    }),
    Object.freeze({
        presetId: 'lin-system76-lemur-pro-i7-32g',
        os: 'linux',
        category: 'linux-oem-laptop',
        deviceModel: 'System76 Lemur Pro',
        deviceNamePrefix: 'lemur-',
        macOuiPrefixes: Object.freeze(['8C:8D:28', 'A4:34:D9']),
        cpuModel: 'Intel Core i7-1355U',
        gpuModel: 'Intel(R) Iris(R) Xe Graphics',
        hardwareConcurrency: 12,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '6.8.0',
        webgpuAvailable: false,
        screen: Object.freeze({ width: 1920, height: 1080, availWidth: 1920, availHeight: 1052, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Intel',
            unmaskedRenderer: 'Mesa Intel(R) Iris(R) Xe Graphics (RPL-U)',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'gen-12lp' })
        })
    }),
    Object.freeze({
        presetId: 'lin-thinkpad-t14-gen4-amd-32g',
        os: 'linux',
        category: 'linux-oem-laptop',
        deviceModel: 'Lenovo ThinkPad T14 Gen 4 (AMD)',
        deviceNamePrefix: 'thinkpad-',
        macOuiPrefixes: Object.freeze(['54:E1:AD', '8C:8D:28']),
        cpuModel: 'AMD Ryzen 7 7840U',
        gpuModel: 'AMD Radeon 780M',
        hardwareConcurrency: 16,
        ramGb: 32,
        storageGb: 1024,
        architecture: 'x86',
        osVersion: '6.8.0',
        webgpuAvailable: false,
        screen: Object.freeze({ width: 1920, height: 1200, availWidth: 1920, availHeight: 1172, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'AMD',
            unmaskedRenderer: 'AMD Radeon 780M (radeonsi, phoenix, LLVM 17.0.6)',
            GPUAdapterInfo: Object.freeze({ vendor: 'amd', architecture: 'rdna-3' })
        })
    }),
    Object.freeze({
        presetId: 'lin-workstation-r9-7950x-rx7800xt-64g',
        os: 'linux',
        category: 'linux-workstation',
        deviceModel: 'Custom Linux Workstation (AMD Ryzen 9 7950X + Radeon RX 7800 XT)',
        deviceNamePrefix: 'workstation-',
        macOuiPrefixes: Object.freeze(['00:E0:4C', '04:42:1A']),
        cpuModel: 'AMD Ryzen 9 7950X',
        gpuModel: 'AMD Radeon RX 7800 XT',
        hardwareConcurrency: 32,
        ramGb: 64,
        vramGb: 16,
        storageGb: 2048,
        architecture: 'x86',
        osVersion: '6.8.0',
        webgpuAvailable: false,
        screen: Object.freeze({ width: 2560, height: 1440, availWidth: 2560, availHeight: 1412, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'AMD',
            unmaskedRenderer: 'AMD Radeon RX 7800 XT (radeonsi, navi32, LLVM 17.0.6)',
            GPUAdapterInfo: Object.freeze({ vendor: 'amd', architecture: 'rdna-3' })
        })
    }),
    Object.freeze({
        presetId: 'lin-laptop-i5-8250u-uhd620-16g',
        os: 'linux',
        category: 'linux-laptop',
        deviceModel: 'ThinkPad T480 (Intel i5-8250U)',
        deviceNamePrefix: 'thinkpad-',
        macOuiPrefixes: Object.freeze(['54:E1:AD', '00:1B:21']),
        cpuModel: 'Intel Core i5-8250U',
        gpuModel: 'Intel(R) UHD Graphics 620',
        hardwareConcurrency: 8,
        ramGb: 16,
        storageGb: 512,
        architecture: 'x86',
        osVersion: '6.5.0',
        webgpuAvailable: false,
        screen: Object.freeze({ width: 1920, height: 1080, availWidth: 1920, availHeight: 1052, colorDepth: 24, devicePixelRatio: 1 }),
        webgl: Object.freeze({
            unmaskedVendor: 'Intel',
            unmaskedRenderer: 'Mesa Intel(R) UHD Graphics 620 (KBL GT2)',
            GPUAdapterInfo: Object.freeze({ vendor: 'intel', architecture: 'gen-9' })
        })
    })
]);

/**
 * Normalize OS key to `'windows' | 'macos' | 'linux'`.
 *
 * @param {string} [os]
 * @returns {'windows' | 'macos' | 'linux'}
 */
export function normalizePresetOs(os) {
    const raw = String(os || 'windows').trim().toLowerCase();
    if (raw.startsWith('mac') || raw === 'darwin' || raw === 'osx') return 'macos';
    if (raw.startsWith('lin') || raw === 'ubuntu') return 'linux';
    return 'windows';
}

/**
 * List usable device presets filtered by OS and/or category.
 *
 * @param {{ os?: string, category?: string }} [filter]
 * @returns {Array<object>}
 */
export function listUsableDevicePresets(filter = {}) {
    let list = [...USABLE_DEVICE_PRESET_CATALOG];
    if (filter.os) {
        const targetOs = normalizePresetOs(filter.os);
        list = list.filter((p) => p.os === targetOs);
    }
    if (filter.category) {
        const cat = String(filter.category).trim().toLowerCase();
        list = list.filter((p) => p.category.toLowerCase().includes(cat));
    }
    return list;
}

/**
 * Absorbed AdsPower Language Auto-Completer (`Module 99825` + `Module 82088.compatiLangs`).
 * Expands a single language tag (e.g. `'ja'`, `'de-DE'`, `'zh-HK'`, `'en-US'`) or partial array
 * into a complete browser `navigator.languages` array.
 *
 * @param {string | string[]} primaryLangOrList
 * @returns {string[]}
 */
export function expandCompatibleLanguages(primaryLangOrList) {
    const input = Array.isArray(primaryLangOrList)
        ? primaryLangOrList.filter(Boolean).map((s) => String(s).trim())
        : typeof primaryLangOrList === 'string' && primaryLangOrList.trim()
          ? [primaryLangOrList.trim()]
          : ['en-US', 'en'];

    if (input.length === 0) return ['en-US', 'en'];

    if (input.length === 1) {
        const target = input[0];
        const lower = target.toLowerCase();
        // Search exact match at index 0 first, then case-insensitive match
        for (const chain of LOCALE_FALLBACK_CHAINS) {
            if (chain[0].toLowerCase() === lower) {
                return [...chain];
            }
        }
        for (const chain of LOCALE_FALLBACK_CHAINS) {
            if (chain.some((item) => item.toLowerCase() === lower)) {
                return [...chain];
            }
        }
    }

    // Apply AdsPower Module 82088 compatiLangs rules
    const result = [...input];
    const pairs = [
        ['zh-HK', 'zh-TW'],
        ['en', 'en-US'],
        ['pt', 'pt-BR'],
        ['es', 'es-ES']
    ];
    for (const [a, b] of pairs) {
        if (result.includes(a) && !result.includes(b)) {
            result.push(b);
        }
    }
    const basePrefix = result[0].split(/[-_]/)[0];
    if (basePrefix && !result.includes(basePrefix)) {
        result.push(basePrefix);
    }
    return result;
}

/**
 * Absorbed AdsPower `getAccept` RFC-9110 `Accept-Language` Header Generator (`Module 82088`).
 * Ensures wire `Accept-Language` header matches DOM `navigator.languages` 100%.
 *
 * @param {string | string[]} languages
 * @returns {string}
 */
export function buildAcceptLanguageHeader(languages) {
    const langs = expandCompatibleLanguages(languages);
    let header = '';
    let qStep = 0;
    const seen = [];

    for (let i = 0; i < langs.length; i++) {
        const curr = langs[i];
        const next = langs[i + 1] || '';
        const currBase = curr.split('-')[0];
        const nextBase = next.split('-')[0];

        if (i === 0) {
            header += curr;
            qStep += 1;
        } else if (!seen.includes(curr)) {
            const qVal = Math.max(1, 10 - qStep);
            header += `,${curr};q=0.${qVal}`;
            qStep += 1;
        }

        if (curr !== currBase && currBase !== nextBase && !seen.includes(currBase)) {
            const qVal = Math.max(1, 10 - qStep);
            header += `,${currBase};q=0.${qVal}`;
            qStep += 1;
            seen.push(currBase);
        }
        seen.push(curr);
    }

    return header;
}

/**
 * Absorbed AdsPower Country-to-Language & Timezone Resolver (`Module 41056` & `Module 53716`).
 *
 * @param {string} countryCode ISO 3166-1 alpha-2 country code (e.g. `'US'`, `'JP'`, `'DE'`, `'GB'`)
 * @param {string} [preferredTimeZone]
 * @returns {{ country: string, primaryLang: string, languages: string[], acceptLanguage: string, timeZone: string }}
 */
export function resolveCountryGeoProfile(countryCode = 'US', preferredTimeZone = null) {
    const code = String(countryCode || 'US').trim().toUpperCase();
    const entry = COUNTRY_GEO_PROFILE_CATALOG[code] || COUNTRY_GEO_PROFILE_CATALOG.US;
    const languages = expandCompatibleLanguages(entry.primaryLang);
    const acceptLanguage = buildAcceptLanguageHeader(languages);
    const timeZone =
        preferredTimeZone && entry.allTimeZones.includes(preferredTimeZone)
            ? preferredTimeZone
            : preferredTimeZone || entry.timeZone;

    return {
        country: entry.country,
        primaryLang: languages[0],
        languages,
        acceptLanguage,
        timeZone
    };
}

/**
 * Absorbed AdsPower `setSpeechVoices` (`Module 82088`) with strict OS Voice URI partitioning.
 * Marks the voice matching `primaryLang` as `{ default: true, localService: true }`.
 *
 * @param {string} os `'windows' | 'macos' | 'linux'`
 * @param {string} [primaryLang='en-US']
 * @returns {Array<{ name: string, lang: string, voiceURI: string, default: boolean, localService: boolean }>}
 */
export function selectCoherentSpeechVoices(os = 'windows', primaryLang = 'en-US') {
    const normOs = normalizePresetOs(os);
    const catalog = OS_SPEECH_VOICES_CATALOG[normOs] || OS_SPEECH_VOICES_CATALOG.windows;
    const langPrefix = String(primaryLang || 'en-US').split('-')[0].toLowerCase();

    const voices = catalog.map((v) => ({
        name: v.name,
        lang: v.lang,
        voiceURI: v.voiceURI,
        default: false,
        localService: true
    }));

    let matched = voices.find((v) => v.lang.toLowerCase() === String(primaryLang).toLowerCase());
    if (!matched) {
        matched = voices.find((v) => v.lang.toLowerCase().startsWith(langPrefix));
    }
    if (!matched && voices.length > 0) {
        matched = voices[0];
    }
    if (matched) {
        matched.default = true;
        const idx = voices.indexOf(matched);
        if (idx > 0) {
            voices.splice(idx, 1);
            voices.unshift(matched);
        }
    }

    return voices;
}

/**
 * Absorbed AdsPower `createmediaDevices` (`Module 82088`) + Camoufox `media-devices.json`.
 * Deterministically generates OS-matched audio input/output & webcam devices from `profileId`,
 * enforcing empty `label: ""` before `getUserMedia` permission grant (`permissionGranted: false`)
 * while preserving `hardwareLabel` for C++ media-device configuration.
 *
 * @param {string} profileId
 * @param {string} [os='windows']
 * @param {{ permissionGranted?: boolean, deviceModel?: string }} [options]
 * @returns {Array<{ kind: string, label: string, hardwareLabel: string, deviceId: string, groupId: string }>}
 */
function float64ToHex(val) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setFloat64(0, val, false);
    const hi = view.getUint32(0, false).toString(16).padStart(8, '0');
    const lo = view.getUint32(4, false).toString(16).padStart(8, '0');
    return `0x${hi}${lo}`;
}

export function createCoherentMediaDevices(profileId = 'default-profile', os = 'windows', options = {}) {
    const normOs = normalizePresetOs(os);
    const permissionGranted = Boolean(options.permissionGranted || options.includeLabels);
    const catalog = OS_MEDIA_DEVICES_CATALOG[normOs] || OS_MEDIA_DEVICES_CATALOG.windows;

    const hashHex = crypto.createHash('md5').update(String(profileId)).digest('hex');
    const seedInt = parseInt(hashHex.slice(0, 8), 16);

    // Match Mac product line audio card when on macOS
    let card = catalog.audioCards[seedInt % catalog.audioCards.length];
    if (normOs === 'macos' && options.deviceModel) {
        if (/MacBook\s+Air/i.test(options.deviceModel)) {
            card = catalog.audioCards.find((c) => c.input.includes('MacBook Air')) || card;
        } else if (/MacBook\s+Pro/i.test(options.deviceModel)) {
            card = catalog.audioCards.find((c) => c.input.includes('MacBook Pro')) || card;
        } else if (/iMac/i.test(options.deviceModel)) {
            card = catalog.audioCards.find((c) => c.input.includes('iMac')) || card;
        } else if (/Mac\s+(?:Studio|mini|Pro)/i.test(options.deviceModel)) {
            card = catalog.audioCards.find((c) => c.input.includes('Studio Display') || c.input.includes('Built-in')) || card;
        }
    }

    // AdsPower Module 82088 USB VID:PID camera suffix derivation for Windows
    const vid = hashHex.slice(0, 4);
    const pid = hashHex.slice(4, 8);
    const baseCam = catalog.cameras[seedInt % catalog.cameras.length];
    const camHardwareLabel =
        normOs === 'windows' && baseCam === 'Integrated Camera'
            ? `Integrated Camera (${vid}:${pid})`
            : baseCam;

    const audioGroupId = crypto.createHash('sha256').update(`${profileId}:audio-group`).digest('hex').slice(0, 32);
    const videoGroupId = crypto.createHash('sha256').update(`${profileId}:video-group`).digest('hex').slice(0, 32);

    return [
        {
            kind: 'audioinput',
            label: permissionGranted ? card.input : '',
            hardwareLabel: card.input,
            deviceId: crypto.createHash('sha256').update(`${profileId}:audioinput:0`).digest('hex').slice(0, 32),
            groupId: audioGroupId
        },
        {
            kind: 'videoinput',
            label: permissionGranted ? camHardwareLabel : '',
            hardwareLabel: camHardwareLabel,
            deviceId: crypto.createHash('sha256').update(`${profileId}:videoinput:0`).digest('hex').slice(0, 32),
            groupId: videoGroupId
        },
        {
            kind: 'audiooutput',
            label: permissionGranted ? card.output : '',
            hardwareLabel: card.output,
            deviceId: crypto.createHash('sha256').update(`${profileId}:audiooutput:0`).digest('hex').slice(0, 32),
            groupId: audioGroupId
        }
    ];
}

/**
 * Absorbed AdsPower Deterministic Fingerprint Seed & Hostname/MAC Generator
 * (`Module 82088` `setAudioNoise`, `setCanvasNoise`, `FingerprintTask.setClientRects`,
 *  `FingerprintTask.setDeviceName`, `FingerprintTask.setMacAddress`).
 *
 * Given a `profileId` (and optional `{ os, presetId, country, language, timeZone }`),
 * deterministically resolves a 100% SKU-coherent device profile and telemetry fixture.
 *
 * @param {string} profileId
 * @param {{
 *   os?: 'windows' | 'macos' | 'linux' | 'win' | 'mac' | 'lin',
 *   presetId?: string,
 *   country?: string,
 *   language?: string | string[],
 *   timeZone?: string,
 *   firefoxVersion?: string
 * }} [options]
 * @returns {object}
 */
export function resolveDeterministicDeviceProfile(profileId = 'camoufox-profile-1', options = {}) {
    const idStr = String(profileId || 'camoufox-profile-1');
    const md5Hex = crypto.createHash('md5').update(idStr).digest('hex');
    const seedInt = parseInt(md5Hex.slice(0, 8), 16);

    let preset = null;
    if (options.presetId) {
        const requestedId = String(options.presetId).trim();
        preset =
            USABLE_DEVICE_PRESET_CATALOG.find((p) => p.presetId === requestedId) ||
            USABLE_DEVICE_PRESET_CATALOG.find((p) => p.presetId.startsWith(requestedId)) ||
            null;
    }
    if (!preset) {
        const targetOs = normalizePresetOs(options.os || 'windows');
        const candidates = listUsableDevicePresets({ os: targetOs });
        preset = candidates[seedInt % candidates.length] || USABLE_DEVICE_PRESET_CATALOG[0];
    }

    const normOs = preset.os;
    const ffVer = options.firefoxVersion || '135.0';

    // AdsPower Module 82088 deterministic noise seeds
    let charSum = 0;
    let hash32 = 0;
    for (let i = 0; i < idStr.length; i++) {
        const code = idStr.charCodeAt(i);
        charSum += code;
        hash32 = (Math.imul(31, hash32) + code) | 0;
    }
    const audioFpSeed = (charSum % 2000) - 1000 || 1;
    const clientRectFpSeed = (Math.abs(hash32) % 20000) - 10000 || 1;
    const canvasSeed = parseInt(md5Hex.slice(8, 16), 16) % 10000;

    // Deterministic Hostname (DeviceName) matched to the exact device model
    const macNames = ['Alex', 'Jordan', 'Taylor', 'Morgan', 'Casey', 'Riley', 'Avery', 'Quinn', 'Cameron', 'Parker'];
    const hostSuffixHex = md5Hex.slice(0, 7).toUpperCase();
    const deviceName =
        normOs === 'macos'
            ? `${macNames[seedInt % macNames.length]}'s ${preset.deviceNameSuffix || 'MacBook Pro'}`
            : normOs === 'windows'
              ? `${preset.deviceNamePrefix || 'DESKTOP-'}${hostSuffixHex}`
              : `${preset.deviceNamePrefix || 'ubuntu-'}${md5Hex.slice(0, 4)}`;

    // Deterministic IEEE OUI MAC Address matched to device NIC vendor
    const ouiList = preset.macOuiPrefixes || ['8C:8D:28'];
    const oui = ouiList[seedInt % ouiList.length];
    const nicBytes = [md5Hex.slice(16, 18), md5Hex.slice(18, 20), md5Hex.slice(20, 22)]
        .map((b) => b.toUpperCase())
        .join(':');
    const macAddress = `${oui}:${nicBytes}`;

    // Language & Geo/Timezone resolution
    const geo = resolveCountryGeoProfile(options.country || 'US', options.timeZone || null);
    const languages = options.language
        ? expandCompatibleLanguages(options.language)
        : geo.languages;
    const primaryLang = languages[0];
    const acceptLanguage = buildAcceptLanguageHeader(languages);
    const timeZone = options.timeZone || geo.timeZone;
    const geolocation = resolveGeoCoordinatesWithDeterministicJitter(idStr, geo.country);
    const gpuPerformance = computeGpuPerformanceScalingWeights(
        preset.gpuModel || preset.webgl.unmaskedRenderer,
        { profileId: idStr }
    );
    const securityPolicy = {
        portScanProtection: {
            enabled: options.portScanProtection !== undefined ? Boolean(options.portScanProtection) : true,
            allowedPorts: Array.isArray(options.allowedLocalPorts) ? [...options.allowedLocalPorts] : []
        },
        canvasSkipHosts: [...DEFAULT_CANVAS_SKIP_HOSTS, ...(options.canvasSkipHosts || [])],
        skipCpuSoftwareCanvasMask: true
    };

    // User-Agent & Platform strings
    const userAgent =
        normOs === 'windows'
            ? `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${ffVer}) Gecko/20100101 Firefox/${ffVer}`
            : normOs === 'macos'
              ? `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:${ffVer}) Gecko/20100101 Firefox/${ffVer}`
              : `Mozilla/5.0 (X11; Linux x86_64; rv:${ffVer}) Gecko/20100101 Firefox/${ffVer}`;
    const platform =
        normOs === 'windows' ? 'Win32' : normOs === 'macos' ? 'MacIntel' : 'Linux x86_64';
    const oscpu =
        normOs === 'windows'
            ? 'Windows NT 10.0; Win64; x64'
            : normOs === 'macos'
              ? 'Intel Mac OS X 10.15'
              : 'Linux x86_64';

    const fonts = [...(OS_FONT_CATALOG[normOs] || OS_FONT_CATALOG.windows)];
    const speechVoices = selectCoherentSpeechVoices(normOs, primaryLang);
    const mediaDevices = createCoherentMediaDevices(idStr, normOs, {
        permissionGranted: false,
        deviceModel: preset.deviceModel
    });

    // StorageManager quota scaled to physical SSD storageGb (never exceeding physical disk!)
    const quotaBytes = Math.min(20, Math.floor(preset.storageGb * 0.1)) * 1024 ** 3;
    const usageBytes = ((seedInt % 512) + 4) * 1024;

    const sin1e6 = Math.sin(1e6);
    const cos1e6 = Math.cos(1e6);
    const tan1e6 = Math.tan(1e6);
    const powPi = Math.pow(3.141592653589793, -7.3);

    const candidatePorts =
        normOs === 'linux'
            ? [32768 + (seedInt % 10000), 45000 + (seedInt % 10000)]
            : [49152 + (seedInt % 8000), 58000 + (seedInt % 7000)];

    const navigatorObj = {
        userAgent,
        platform,
        oscpu,
        hardwareConcurrency: preset.hardwareConcurrency,
        maxTouchPoints: preset.maxTouchPoints ?? 0,
        language: primaryLang,
        languages,
        webdriver: false,
        pdfViewerEnabled: true,
        cookieEnabled: true,
        hasUserAgentData: false,
        hasWindowChrome: false,
        vendor: '',
        buildID: '20181001000000'
    };

    const screenObj = {
        width: preset.screen.width,
        height: preset.screen.height,
        availWidth: preset.screen.availWidth,
        availHeight: preset.screen.availHeight,
        colorDepth: preset.screen.colorDepth,
        pixelDepth: preset.screen.colorDepth,
        innerWidth: preset.screen.availWidth,
        innerHeight: preset.screen.availHeight - 86,
        outerWidth: preset.screen.availWidth,
        outerHeight: preset.screen.availHeight,
        devicePixelRatio: preset.screen.devicePixelRatio,
        mediaQueries: {
            deviceWidthMatches: true,
            deviceHeightMatches: true,
            innerWidthMatches: true,
            innerHeightMatches: true,
            dprResolutionMatches: true,
            orientationLandscape: preset.screen.width >= preset.screen.height,
            orientationPortrait: preset.screen.height > preset.screen.width,
            colorBitsAtLeast8: true,
            colorGamutSrgb: true,
            colorGamutP3: normOs === 'macos',
            dynamicRangeHigh: normOs === 'macos',
            pointerFine: true,
            pointerCoarse: (preset.maxTouchPoints ?? 0) > 0,
            hoverSupported: true
        }
    };

    const webglObj = {
        available: true,
        vendor: 'Mozilla',
        renderer: 'Mozilla',
        version: 'WebGL 2.0',
        shadingLanguageVersion: 'WebGL GLSL ES 3.00',
        unmaskedVendor: preset.webgl.unmaskedVendor,
        unmaskedRenderer: preset.webgl.unmaskedRenderer,
        extensionsCount: 28,
        maxTextureSize: 16384,
        maxCubeMapTextureSize: 16384,
        maxRenderbufferSize: 16384,
        maxViewportDims:
            normOs === 'windows' && preset.webgl.unmaskedVendor.includes('NVIDIA')
                ? [32768, 32768]
                : [16384, 16384],
        maxVertexAttribs: 16,
        aliasedLineWidthRange: [1, 1],
        GPUAdapterInfo: preset.webgl.GPUAdapterInfo
    };

    const webgpuObj = {
        available: preset.webgpuAvailable !== undefined ? preset.webgpuAvailable : normOs !== 'linux',
        requestAdapterNative: true,
        adapterInfo: preset.webgl.GPUAdapterInfo
    };

    const hardwareProfile = {
        deviceModel: preset.deviceModel,
        deviceName,
        productType: deviceName,
        cpuModel: preset.cpuModel,
        gpuModel: preset.gpuModel,
        ramGb: preset.ramGb,
        vramGb: preset.vramGb ?? null,
        storageGb: preset.storageGb,
        architecture: preset.architecture,
        osVersion: preset.osVersion,
        macAddress,
        webgpuAdapterInfo: preset.webgl.GPUAdapterInfo
    };

    const storageEstimate = {
        quotaBytes,
        usageBytes
    };

    let timezoneOffsetMinutes = 300;
    try {
        const tzParts = new Intl.DateTimeFormat('en-US', {
            timeZone,
            timeZoneName: 'shortOffset'
        }).formatToParts(new Date());
        const offsetPart = tzParts.find((p) => p.type === 'timeZoneName')?.value || '';
        const offMatch = offsetPart.match(/GMT([+-])(\d{1,2})(?::(\d{2}))?/);
        if (offMatch) {
            const sign = offMatch[1] === '+' ? -1 : 1; // Date.prototype.getTimezoneOffset convention (UTC - local)
            timezoneOffsetMinutes = sign * (Number(offMatch[2]) * 60 + Number(offMatch[3] || 0));
        } else if (offsetPart === 'GMT' || offsetPart === 'UTC') {
            timezoneOffsetMinutes = 0;
        }
    } catch {
        timezoneOffsetMinutes = 300;
    }

    const intlObj = {
        timeZone,
        locale: primaryLang,
        calendar: 'gregory',
        numberingSystem: 'latn',
        timezoneOffsetMinutes
    };

    const telemetry = {
        navigator: navigatorObj,
        prototypeIntegrity: {
            toStringIntact: true,
            ownNavigatorOverrides: [],
            userAgentGetter: {
                exists: true,
                isGetter: true,
                source: 'function get userAgent() {\n    [native code]\n}',
                isNative: true
            },
            webdriverGetter: {
                exists: true,
                isGetter: true,
                source: 'function get webdriver() {\n    [native code]\n}',
                isNative: true
            },
            platformGetter: {
                exists: true,
                isGetter: true,
                source: 'function get platform() {\n    [native code]\n}',
                isNative: true
            },
            hardwareConcurrencyGetter: {
                exists: true,
                isGetter: true,
                source: 'function get hardwareConcurrency() {\n    [native code]\n}',
                isNative: true
            },
            webglGetParameter: {
                exists: true,
                isMethod: true,
                source: 'function getParameter() {\n    [native code]\n}',
                isNative: true
            },
            webgl2GetParameter: {
                exists: true,
                isMethod: true,
                source: 'function getParameter() {\n    [native code]\n}',
                isNative: true
            }
        },
        worker: {
            supported: true,
            ok: true,
            userAgent,
            platform,
            hardwareConcurrency: preset.hardwareConcurrency,
            languages,
            language: primaryLang,
            webdriver: false,
            timeZone,
            math: { sin1e6, cos1e6, tan1e6, powPi }
        },
        webgl: webglObj,
        canvas2d: {
            available: true,
            fnv1aHash: md5Hex.slice(0, 16),
            pixelSampleSum: 480000 + (seedInt % 5000),
            dataUrlLength: 3420
        },
        audio: {
            available: true,
            sampleRate: 48000,
            maxChannelCount: 2,
            channelCount: 2,
            state: 'running'
        },
        mathPrecision: {
            sin1e6,
            cos1e6,
            tan1e6,
            powPi,
            hex: {
                sin1e6: float64ToHex(sin1e6),
                cos1e6: float64ToHex(cos1e6),
                tan1e6: float64ToHex(tan1e6),
                powPi: float64ToHex(powPi)
            }
        },
        screen: screenObj,
        intl: intlObj,
        automationGlobals: [],
        webrtc: {
            available: true,
            candidatePorts,
            candidateIps: ['203.0.113.45'],
            privateIpLeaked: false
        },
        speechVoices,
        fonts,
        media: {
            devices: mediaDevices
        },
        iframeParity: {
            ok: true,
            userAgent,
            platform,
            oscpu,
            hardwareConcurrency: preset.hardwareConcurrency,
            webdriver: false,
            language: primaryLang,
            languages,
            width: preset.screen.width,
            height: preset.screen.height,
            colorDepth: preset.screen.colorDepth,
            pixelDepth: preset.screen.colorDepth,
            userAgentGetterNative: true,
            webdriverGetterNative: true
        },
        geckoApiSurface: {
            hasDeviceMemory: false,
            hasGetBattery: false,
            hasBluetooth: false,
            hasUsb: false,
            hasSerial: false,
            hasHid: false,
            hasOpenDatabase: false,
            hasMozInnerScreenX: true,
            performanceNowMonotonic: true
        },
        webgpu: webgpuObj,
        stackAndMediaHygiene: {
            hasAtSignFormat: true,
            leakedStackMarkers: [],
            enumerateDevicesNative: true,
            unpermittedLabelsLeaked: false,
            mediaDevices: {
                available: true,
                enumerateDevicesNative: true,
                unpermittedLabelsLeaked: false
            }
        },
        hardwareProfile,
        gpuPerformance,
        storageEstimate
    };

    return {
        profileId: idStr,
        presetId: preset.presetId,
        os: normOs,
        category: preset.category,
        deviceName,
        productType: deviceName,
        macAddress,
        language: primaryLang,
        languages,
        acceptLanguage,
        timeZone,
        geolocation,
        securityPolicy,
        gpuPerformance,
        seeds: {
            audioFp: audioFpSeed,
            clientRectFp: clientRectFpSeed,
            canvasMark: canvasSeed
        },
        headers: {
            'User-Agent': userAgent,
            'Accept-Language': acceptLanguage
        },
        navigator: navigatorObj,
        screen: screenObj,
        webgl: webglObj,
        webgpu: webgpuObj,
        hardwareProfile,
        storageEstimate,
        intl: intlObj,
        fonts,
        speechVoices,
        mediaDevices,
        telemetry
    };
}

/**
 * 7. AdsPower Broken-Profile Auto-Healer (`sanitizeAdsPowerProfileToCoherentPreset`)
 *
 * Takes a raw/broken AdsPower profile report (from `auditAdsPowerProfileDir` or raw AdsPower config)
 * where `DeviceName`, `HardwareConcurrency`, `DeviceMemory`, `osVersion`, `UNMASKED_RENDERER_WEBGL`,
 * and `GPUAdapterInfo.architecture` contradict each other, and repairs them into a 100% SKU-coherent
 * hardware specification that passes `validateHardwareModelSpec`.
 *
 * @param {object} rawAdsPowerProfile
 * @returns {{
 *   healedTelemetry: object,
 *   validation: { passed: boolean, matchedSku: string | null, issues: string[] },
 *   repairsApplied: string[]
 * }}
 */
export function sanitizeAdsPowerProfileToCoherentPreset(rawAdsPowerProfile = {}) {
    const repairsApplied = [];
    const profileId = String(
        rawAdsPowerProfile.fbccId ||
            rawAdsPowerProfile.profileDirName ||
            rawAdsPowerProfile.profileId ||
            'adspower-healed-profile'
    );
    const rawPlatform = String(
        rawAdsPowerProfile.os ||
            rawAdsPowerProfile.Platform ||
            rawAdsPowerProfile.platform ||
            rawAdsPowerProfile.navigator?.platform ||
            rawAdsPowerProfile.userAgent ||
            'MacIntel'
    );
    const normOs = normalizePresetOs(rawPlatform);
    const renderer = String(
        rawAdsPowerProfile.UNMASKED_RENDERER_WEBGL ||
            rawAdsPowerProfile.WebGLRenderer ||
            rawAdsPowerProfile.webglRenderer ||
            rawAdsPowerProfile.renderer ||
            rawAdsPowerProfile.webgl?.unmaskedRenderer ||
            'Apple M2 Pro'
    ).trim();
    const rawDeviceName = String(
        rawAdsPowerProfile.DeviceName ||
            rawAdsPowerProfile.deviceName ||
            rawAdsPowerProfile.hardwareProfile?.deviceName ||
            "User's MacBook Pro"
    ).trim();
    const uam = rawAdsPowerProfile.UserAgentMetadata || rawAdsPowerProfile.userAgentMetadata || {};
    const rawOsVer = String(
        rawAdsPowerProfile.osVersion ||
            uam.platformVersion ||
            rawAdsPowerProfile.hardwareProfile?.osVersion ||
            '15.4.0'
    ).trim();
    const rawCores = Number(
        rawAdsPowerProfile.HardwareConcurrency ||
            rawAdsPowerProfile.cores ||
            rawAdsPowerProfile.navigator?.hardwareConcurrency ||
            8
    );
    const rawRamGb = Number(
        rawAdsPowerProfile.DeviceMemory ||
            rawAdsPowerProfile.deviceMemoryGb ||
            rawAdsPowerProfile.hardwareProfile?.ramGb ||
            16
    );

    if (normOs !== 'macos') {
        // Resolve matching Windows or Linux preset (preserving Laptop vs Desktop GPU distinction)
        const osPresets = listUsableDevicePresets({ os: normOs });
        const lowerRenderer = renderer.toLowerCase();
        const isLaptopGpuInput = /laptop|\b\d{3}m\b/i.test(renderer);
        const sortedOsPresets = [...osPresets].sort((a, b) => b.gpuModel.length - a.gpuModel.length);
        let candidatePreset = sortedOsPresets.find((p) => {
            if (!renderer) return false;
            const presetIsLaptop = /laptop|\b\d{3}m\b/i.test(p.gpuModel);
            if (presetIsLaptop !== isLaptopGpuInput && /RTX|GTX|RX\s*\d/i.test(renderer)) {
                return false;
            }
            return (
                p.webgl.unmaskedRenderer.toLowerCase().includes(lowerRenderer) ||
                lowerRenderer.includes(p.gpuModel.toLowerCase())
            );
        });
        if (!candidatePreset && normOs === 'windows') {
            if (/RTX\s*4090\s*Laptop/i.test(renderer)) {
                candidatePreset = osPresets.find((p) => p.presetId === 'win-razer-blade16-i9-rtx4090');
            } else if (/RTX\s*4090/i.test(renderer)) {
                candidatePreset = osPresets.find((p) => p.presetId === 'win-desktop-i9-14900k-rtx4090-64g');
            } else if (/RTX\s*4080/i.test(renderer)) {
                candidatePreset = osPresets.find((p) => p.presetId === 'win-desktop-r7-7800x3d-rtx4080-32g');
            } else if (/RTX\s*4070\s*Laptop/i.test(renderer)) {
                candidatePreset = osPresets.find((p) => p.presetId === 'win-dell-xps16-9640-rtx4070-32g');
            } else if (/RTX\s*4070/i.test(renderer)) {
                candidatePreset = osPresets.find((p) => p.presetId === 'win-desktop-i7-13700k-rtx4070-32g');
            }
        }
        const healedProfile = resolveDeterministicDeviceProfile(profileId, {
            os: normOs,
            presetId: candidatePreset?.presetId
        });
        repairsApplied.push(
            `Mapped non-macOS profile (${rawPlatform}) to SKU-verified preset "${healedProfile.presetId}"`
        );
        return {
            healedPresetId: healedProfile.presetId,
            healedProfile,
            healedTelemetry: healedProfile.telemetry,
            validation: validateHardwareModelSpec(healedProfile.telemetry, normOs),
            repairsApplied
        };
    }

    const isSoftwareOrCrossOsOnMac =
        /SwiftShader|llvmpipe|softpipe|Basic\s+Render|Direct3D|D3D11|NVIDIA|GeForce|RTX|GTX|Qualcomm|Adreno/i.test(
            renderer
        );
    const appleSkuName =
        parseAppleSiliconSkuName(renderer) || (isSoftwareOrCrossOsOnMac ? 'Apple M3 Pro' : null);

    if (appleSkuName) {
        const sku = APPLE_SILICON_SKU_CATALOG[appleSkuName];
        // Find matching Apple Silicon preset or closest tier preset
        const matchedPreset =
            listUsableDevicePresets({ os: 'macos' }).find((p) => p.cpuModel === sku.chip) ||
            listUsableDevicePresets({ os: 'macos' }).find((p) => p.presetId === 'mac-mbp14-m3-pro-12c-18g');

        const healedProfile = resolveDeterministicDeviceProfile(profileId, {
            os: 'macos',
            presetId: matchedPreset.presetId
        });

        // 1. Heal cores to nearest valid core count for this exact Apple Silicon SKU
        let healedCores = rawCores;
        if (!sku.allowedCores.includes(healedCores)) {
            healedCores = sku.allowedCores[0];
            repairsApplied.push(
                `Repaired ${sku.chip} hardwareConcurrency from ${rawCores} -> ${healedCores} cores`
            );
        }

        // 2. Heal RAM to valid factory RAM tier for (chip, cores)
        const pairRule = sku.allowedCoreRamPairs.find((p) => p.cores === healedCores);
        const allowedRam = pairRule ? pairRule.ramGb : sku.allowedRamGb;
        let healedRamGb = rawRamGb;
        if (!allowedRam.includes(healedRamGb)) {
            healedRamGb = allowedRam[0];
            repairsApplied.push(
                `Repaired ${sku.chip} (${healedCores}C) Unified Memory from ${rawRamGb}GB -> ${healedRamGb}GB`
            );
        }

        // 3. Heal macOS version to meet minimum bootable macOS for chip generation
        const minOs = APPLE_SILICON_MIN_MACOS_VERSION[sku.generation] || 11.0;
        const minReqMaj = Math.floor(minOs);
        const minReqMin = Math.round((minOs - minReqMaj) * 10);
        const verMatch = rawOsVer.match(/^(\d+)(?:\.(\d+))?/);
        const majVer = verMatch ? Number(verMatch[1]) : 0;
        const minVer = verMatch ? Number(verMatch[2] || 0) : 0;
        let healedOsVer = rawOsVer;
        if (majVer < minReqMaj || (majVer === minReqMaj && minVer < minReqMin)) {
            healedOsVer = sku.generation >= 5 ? '26.1.0' : '15.4.0';
            repairsApplied.push(
                `Repaired ${sku.chip} macOS version from ${rawOsVer} -> ${healedOsVer} (min boot OS ${minOs.toFixed(1)})`
            );
        }

        // 4. Heal DeviceName product line to match chip tier (base / pro / max / ultra) and strip Windows/product-only hostnames
        const isLeakedWinHost = /^(?:DESKTOP|LAPTOP|WIN)-/i.test(rawDeviceName);
        const rawCandidateOwner = isLeakedWinHost
            ? 'Alex'
            : rawDeviceName.split(/['.-]/)[0]?.trim() || 'Alex';
        const ownerPrefix = /^(?:Mac|MacBook|iMac|MacStudio|MacPro|MacMini|localhost|User|Admin)$/i.test(
            rawCandidateOwner
        )
            ? 'Alex'
            : rawCandidateOwner;
        let healedDeviceName = rawDeviceName;
        if (sku.tier === 'base') {
            if (
                isLeakedWinHost ||
                /\b(?:Mac\s+Studio|Mac\s+Pro|Mac[-_]Studio|Mac[-_]Pro|iMac[-_\s]+Pro)\b/i.test(rawDeviceName)
            ) {
                healedDeviceName = `${ownerPrefix}'s MacBook Air`;
                repairsApplied.push(
                    `Repaired DeviceName from "${rawDeviceName}" -> "${healedDeviceName}" for base-tier ${sku.chip}`
                );
            }
        } else if (sku.tier === 'pro') {
            if (
                isLeakedWinHost ||
                /\b(?:MacBook[-_\s]+Air|Mac[-_\s]+Studio|iMac|Mac[-_\s]+Pro)\b/i.test(rawDeviceName)
            ) {
                healedDeviceName = `${ownerPrefix}'s MacBook Pro`;
                repairsApplied.push(
                    `Repaired DeviceName from "${rawDeviceName}" -> "${healedDeviceName}" for Pro-tier ${sku.chip}`
                );
            }
        } else if (sku.tier === 'max') {
            if (
                isLeakedWinHost ||
                /\b(?:MacBook[-_\s]+Air|Mac[-_\s]+mini|iMac|Mac[-_\s]+Pro)\b/i.test(rawDeviceName)
            ) {
                healedDeviceName = `${ownerPrefix}'s MacBook Pro`;
                repairsApplied.push(
                    `Repaired DeviceName from "${rawDeviceName}" -> "${healedDeviceName}" for Max-tier ${sku.chip}`
                );
            }
        } else if (sku.tier === 'ultra') {
            if (isLeakedWinHost || !/\b(?:Mac[-_\s]+Studio|Mac[-_\s]+Pro)\b/i.test(rawDeviceName)) {
                healedDeviceName = `${ownerPrefix}'s Mac Studio`;
                repairsApplied.push(
                    `Repaired DeviceName from "${rawDeviceName}" -> "${healedDeviceName}" for Ultra-tier ${sku.chip}`
                );
            }
        }

        // 5. Native Firefox Metal renderer string (strip Chromium ANGLE wrapper)
        const healedRenderer = sku.gpuRenderer;
        if (renderer !== healedRenderer) {
            repairsApplied.push(`Normalized WebGL renderer from "${renderer}" -> "${healedRenderer}"`);
        }

        const healedArch = sku.generation >= 3 ? 'metal-3' : 'common-3';
        const width =
            sku.tier === 'ultra' ? 2560 : sku.chip === 'Apple M1' ? 1440 : sku.tier === 'base' ? 1470 : 1512;
        const height =
            sku.tier === 'ultra' ? 1440 : sku.chip === 'Apple M1' ? 900 : sku.tier === 'base' ? 956 : 982;

        healedProfile.deviceName = healedDeviceName;
        healedProfile.productType = healedDeviceName;
        healedProfile.telemetry.navigator.hardwareConcurrency = healedCores;
        healedProfile.telemetry.worker.hardwareConcurrency = healedCores;
        healedProfile.telemetry.iframeParity.hardwareConcurrency = healedCores;
        healedProfile.telemetry.webgl.unmaskedVendor = 'Apple';
        healedProfile.telemetry.webgl.unmaskedRenderer = healedRenderer;
        healedProfile.telemetry.webgl.GPUAdapterInfo = { vendor: 'apple', architecture: healedArch };
        healedProfile.telemetry.webgpu.adapterInfo = { vendor: 'apple', architecture: healedArch };
        healedProfile.telemetry.screen.width = width;
        healedProfile.telemetry.screen.height = height;
        healedProfile.telemetry.screen.availWidth = width;
        healedProfile.telemetry.screen.availHeight = height - 38;
        healedProfile.telemetry.screen.innerWidth = width;
        healedProfile.telemetry.screen.innerHeight = Math.max(400, height - 122);
        healedProfile.telemetry.screen.outerWidth = width;
        healedProfile.telemetry.screen.outerHeight = height - 38;
        healedProfile.telemetry.iframeParity.width = width;
        healedProfile.telemetry.iframeParity.height = height;
        healedProfile.hardwareProfile = {
            ...healedProfile.hardwareProfile,
            deviceModel:
                sku.tier === 'ultra'
                    ? `Mac Studio (${sku.chip})`
                    : sku.tier === 'base'
                      ? `MacBook Air (${sku.chip})`
                      : `MacBook Pro (${sku.chip})`,
            deviceName: healedDeviceName,
            productType: healedDeviceName,
            cpuModel: sku.chip,
            gpuModel: sku.gpuRenderer,
            ramGb: healedRamGb,
            storageGb: sku.allowedStorageGb[0],
            architecture: 'arm',
            osVersion: healedOsVer,
            webgpuAdapterInfo: { vendor: 'apple', architecture: healedArch }
        };
        healedProfile.telemetry.hardwareProfile = healedProfile.hardwareProfile;
        const refreshedMediaDevices = createCoherentMediaDevices(profileId, 'macos', {
            permissionGranted: false,
            deviceModel: healedProfile.hardwareProfile.deviceModel
        });
        healedProfile.mediaDevices = refreshedMediaDevices;
        if (healedProfile.telemetry.media) {
            healedProfile.telemetry.media.devices = refreshedMediaDevices;
        }
        if (healedProfile.telemetry.stackAndMediaHygiene) {
            healedProfile.telemetry.stackAndMediaHygiene.mediaDevices = refreshedMediaDevices;
        }
        healedProfile.gpuPerformance = computeGpuPerformanceScalingWeights(sku.gpuRenderer, {
            profileId
        });
        healedProfile.telemetry.gpuPerformance = healedProfile.gpuPerformance;

        return {
            healedPresetId: healedProfile.presetId,
            healedProfile,
            healedTelemetry: healedProfile.telemetry,
            validation: validateHardwareModelSpec(healedProfile.telemetry, 'mac'),
            repairsApplied
        };
    }

    // Intel / AMD Mac healing
    const isAmdRadeonMobile = /5500M|5600M|5300M|560X|555X|Vega\s*(?:16|20)/i.test(renderer);
    const isAmdRadeon = /AMD|Radeon/i.test(renderer);
    const intelPresetId = isAmdRadeonMobile
        ? 'mac-mbp16-intel-i9-radeon5500m'
        : isAmdRadeon
          ? 'mac-imac27-intel-5700xt'
          : 'mac-mbp13-intel-i5-iris655';
    const healedProfile = resolveDeterministicDeviceProfile(profileId, {
        os: 'macos',
        presetId: intelPresetId
    });
    repairsApplied.push(`Mapped Intel Mac profile to SKU-verified preset "${intelPresetId}"`);

    return {
        healedPresetId: healedProfile.presetId,
        healedProfile,
        healedTelemetry: healedProfile.telemetry,
        validation: validateHardwareModelSpec(healedProfile.telemetry, 'mac'),
        repairsApplied
    };
}

/**
 * 8. Ziniao SuperBrowser V5/V6 Broken-Profile Auto-Healer & Feature Absorber
 *    (`sanitizeZiniaoProfileToCoherentPreset`)
 *
 * Absorbs Ziniao's positive security features:
 *   - Local Port-Scan Protection (`port_scan_protection`: blocks websites from scanning 127.0.0.1/localhost ports)
 *   - Per-Domain Canvas/WebGL Consistency & Skip-Hosts (`canvas_fingerprint_skip_hosts`)
 * while repairing Ziniao's reverse-engineered fingerprint defects:
 *   - `concurrent_hardware_num = 3` (impossible odd logical thread count) or 12-core cap on 14/16/24/32-core hardware
 *   - `device_memory = 6` (violates W3C power-of-2 Device Memory spec `[0.25, 0.5, 1, 2, 4, 8]`)
 *   - `h1a()` generating Windows `DESKTOP-XXXXXX` hostnames on macOS/Linux
 *   - `m1a()` setting Locally Administered MAC bit (`a |= 2`, `x2:xx:xx`) instead of a real hardware IEEE OUI
 *   - Headless fallback `1024x1366` portrait window and `webgl_metadata = 1` (`--disable-gpu` SwiftShader fallback)
 *
 * @param {object} rawZiniaoConfig
 * @returns {{
 *   healedPresetId: string,
 *   healedProfile: object,
 *   healedTelemetry: object,
 *   absorbedSecurityPolicy: {
 *     portScanProtection: { enabled: boolean, allowedPorts: number[] },
 *     canvasSkipHosts: string[]
 *   },
 *   validation: { passed: boolean, matchedSku: string | null, issues: string[] },
 *   repairsApplied: string[]
 * }}
 */
export function sanitizeZiniaoProfileToCoherentPreset(rawZiniaoConfig = {}) {
    const repairsApplied = [];
    const adv =
        rawZiniaoConfig.Detail?.advanced ||
        rawZiniaoConfig.browser_custome_v1 ||
        rawZiniaoConfig.advanced_config_v1 ||
        rawZiniaoConfig;

    const profileId = String(
        rawZiniaoConfig.ContainerId ||
            rawZiniaoConfig.BrowserName ||
            adv.mixture_key ||
            rawZiniaoConfig.id ||
            'ziniao-healed-profile'
    );

    const rawOsInput = adv.os ?? adv.system_value ?? rawZiniaoConfig.system_value ?? rawZiniaoConfig.os ?? 1;
    const sysVal = Number(rawOsInput);
    const osStr = typeof rawOsInput === 'string' ? rawOsInput.toLowerCase() : '';
    const uaStr = String(
        rawZiniaoConfig.Detail?.browser?.user_agent ||
            adv.ua ||
            rawZiniaoConfig.UserAgent ||
            ''
    );
    const normOs =
        sysVal === 2 || osStr.startsWith('mac') || /Macintosh|Mac OS X/i.test(uaStr)
            ? 'macos'
            : sysVal === 3 || osStr.startsWith('lin') || /X11;\s*Linux/i.test(uaStr)
              ? 'linux'
              : 'windows';

    const rawCores = Number(adv.hardware_concurrency ?? adv.concurrent_hardware_num ?? 8);
    if (rawCores === 3 || rawCores % 2 !== 0) {
        repairsApplied.push(
            `Repaired Ziniao odd hardware_concurrency=${rawCores} (from kwn=[2,3,4,6,8,10,12]) to physical SKU core count`
        );
    }

    const rawMem = Number(adv.memery_device ?? adv.device_memory ?? 8);
    if (rawMem === 6 || ![0, 0.25, 0.5, 1, 2, 4, 8].includes(rawMem)) {
        repairsApplied.push(
            `Repaired Ziniao non-power-of-two device_memory=${rawMem}GB (W3C spec violation) to authentic factory RAM tier`
        );
    }

    const rawHost = String(adv.device_info_str || rawZiniaoConfig.device_info_str || '').trim();
    if (rawHost && normOs !== 'windows' && /^(?:DESKTOP|LAPTOP|WIN)-/i.test(rawHost)) {
        repairsApplied.push(
            `Repaired Ziniao h1a() Windows hostname "${rawHost}" on ${normOs} to OS-authentic hostname`
        );
    }

    const rawMac = String(adv.mac_address_str || rawZiniaoConfig.mac_address_str || '').trim();
    if (rawMac) {
        const firstByte = parseInt(rawMac.slice(0, 2), 16);
        if (!Number.isNaN(firstByte) && (firstByte & 0x02) !== 0) {
            repairsApplied.push(
                `Repaired Ziniao m1a() Locally Administered random MAC "${rawMac}" (bit 1 === 1) to globally unique IEEE OUI MAC`
            );
        }
    }

    if (Number(adv.webgl_metadata) === 1 || Number(adv.webgl_metadata?.switcher) === 1) {
        repairsApplied.push(
            'Removed Ziniao webgl_metadata=1 (--disable-gpu SwiftShader fallback) and restored hardware-accelerated GPU SKU'
        );
    }

    const renderer = String(
        adv.webgl_metadata?.render ||
            adv.webgl_renderer ||
            rawZiniaoConfig.webgl_renderer ||
            ''
    ).trim();

    const delegated = sanitizeAdsPowerProfileToCoherentPreset({
        fbccId: profileId,
        Platform: normOs === 'macos' ? 'MacIntel' : normOs === 'linux' ? 'Linux x86_64' : 'Win32',
        DeviceName:
            normOs === 'macos' && /^(?:DESKTOP|LAPTOP|WIN)-/i.test(rawHost)
                ? "Alex's MacBook Pro"
                : rawHost || undefined,
        HardwareConcurrency: rawCores,
        DeviceMemory: rawMem,
        UNMASKED_RENDERER_WEBGL: renderer || undefined
    });

    const portProt = adv.port_scan_protection || {};
    const portProtEnabled =
        Number(portProt.switcher ?? adv.port_protection ?? 1) === 1;
    const rawPortsStr = String(portProt.value ?? adv.port_protection_msg ?? '').trim();
    const allowedPorts = rawPortsStr
        ? rawPortsStr
              .split(',')
              .map((s) => Number(s.trim()))
              .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535)
        : [];

    const skipHostsRaw =
        rawZiniaoConfig.canvas_fingerprint_skip_hosts ||
        rawZiniaoConfig.Raw?.canvas_fingerprint_skip_hosts ||
        [];
    const parsedSkipHosts = Array.isArray(skipHostsRaw)
        ? skipHostsRaw
        : typeof skipHostsRaw === 'string' && skipHostsRaw.trim()
          ? skipHostsRaw.split('|').map((s) => s.trim()).filter(Boolean)
          : [];
    const canvasSkipHosts =
        parsedSkipHosts.length > 0
            ? parsedSkipHosts
            : [...DEFAULT_CANVAS_SKIP_HOSTS];

    const absorbedSecurityPolicy = {
        portScanProtection: {
            enabled: portProtEnabled,
            allowedPorts,
            allowSameOriginLocalDev: false
        },
        canvasSkipHosts,
        skipCpuSoftwareCanvasMask: true
    };

    delegated.healedProfile.securityPolicy = absorbedSecurityPolicy;

    return {
        healedPresetId: delegated.healedPresetId,
        healedProfile: delegated.healedProfile,
        healedTelemetry: delegated.healedTelemetry,
        absorbedSecurityPolicy,
        validation: delegated.validation,
        repairsApplied: [...repairsApplied, ...delegated.repairsApplied]
    };
}

export default {
    OS_FONT_CATALOG,
    LOCALE_FALLBACK_CHAINS,
    COUNTRY_GEO_PROFILE_CATALOG,
    OS_SPEECH_VOICES_CATALOG,
    OS_MEDIA_DEVICES_CATALOG,
    USABLE_DEVICE_PRESET_CATALOG,
    normalizePresetOs,
    listUsableDevicePresets,
    expandCompatibleLanguages,
    buildAcceptLanguageHeader,
    resolveCountryGeoProfile,
    selectCoherentSpeechVoices,
    createCoherentMediaDevices,
    resolveDeterministicDeviceProfile,
    sanitizeAdsPowerProfileToCoherentPreset,
    sanitizeZiniaoProfileToCoherentPreset
};
