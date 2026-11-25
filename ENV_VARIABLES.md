# Environment Variables (.env)

## SMS Provider Configuration

### اختيار مزود خدمة الأرقام

```env
# SMS Provider Selection
# Options: 'sms-verification' (default) or 'fivesim-legacy'
SMS_PROVIDER=sms-verification
```

#### المزودون المدعومون:

1. **SMS Verification** (افتراضي)
   - API: `api.sms-verification.com`
   - متغيرات مطلوبة:
     ```env
     SMS_VERIFY_API_KEY=your_api_key_here
     SMS_VERIFY_LANG=ru  # أو 'en'
     ```

2. **5SIM Legacy** 
   - API: `api1.5sim.net`
   - متغيرات مطلوبة:
     ```env
     SMS_PROVIDER=fivesim-legacy
     FIVESIM_API_KEY=your_api_key_here
     # أو يمكن استخدام SMS_VERIFY_API_KEY
     ```

### إعدادات 5SIM Legacy (اختيارية)

```env
# Country (default: 'england')
# Available: saudiarabia, england, russia, india, germany, etc.
FIVESIM_COUNTRY=saudiarabia

# Operator (default: 'any')
# ⚠️ RECOMMENDED: Use 'any' to avoid NO_NUMBERS errors
# Options: any, virtual58, vodafone, virtual15, etc.
FIVESIM_OPERATOR=any

# Service (default: 'go' for Google/YouTube)
# Options: 'go' (Google/YouTube), 'fu' (Snapchat), etc.
FIVESIM_SERVICE=go

# Maximum price in dollars (default: 50)
FIVESIM_MAX_PRICE=50
```

## مثال كامل لملف .env

### استخدام SMS Verification (افتراضي)
```env
# SMS Provider
SMS_PROVIDER=sms-verification
SMS_VERIFY_API_KEY=your_sms_verify_api_key
SMS_VERIFY_LANG=ru
```

### استخدام 5SIM Legacy
```env
# SMS Provider
SMS_PROVIDER=fivesim-legacy
FIVESIM_API_KEY=your_5sim_api_key
FIVESIM_COUNTRY=saudiarabia
FIVESIM_OPERATOR=any
FIVESIM_SERVICE=go
FIVESIM_MAX_PRICE=50
```

**ملاحظة:** إذا لم يتم تحديد `FIVESIM_COUNTRY` أو `FIVESIM_OPERATOR` في `.env`، سيتم استخدام القيم من الكود (الدولة المحددة في `config.smsVerify.countries` والمشغل `any`).

## ملاحظات

- إذا لم يتم تحديد `SMS_PROVIDER`، سيتم استخدام `sms-verification` افتراضياً
- يمكن استخدام `SMS_VERIFY_API_KEY` مع 5SIM Legacy إذا لم يتم تحديد `FIVESIM_API_KEY`
- جميع الإعدادات الاختيارية لها قيم افتراضية معقولة

---

## Camoufox Antidetect Browser Configuration (Open-Source Firefox Engine)

يمكنك استبدال Dolphin Anty أو GPM Login بمحرك **Camoufox** المفتوح المصدر (`PROFILE_SERVICE=camoufox`):

```env
# Select Camoufox as profile engine ('gpm', 'dolphin', or 'camoufox')
PROFILE_SERVICE=camoufox

# Target Desktop OS fingerprint ('windows', 'macos', or 'linux')
CAMOUFOX_OS=windows

# Headless mode ('false', 'true', or 'virtual')
CAMOUFOX_HEADLESS=false

# Enable myuri humanized cursor/scroll/typing dynamics (default: true)
CAMOUFOX_HUMANIZE=true

# Automatically align timezone, locale, geolocation & WebRTC IP with proxy GeoIP (default: true)
CAMOUFOX_GEOIP=true

# Controlled canvas readback protection for cross-OS isolation (default: true)
CAMOUFOX_CANVAS_NOISE=true

# Persistent storage directory for profile cookies (datr, ig_did, ttwid) & localStorage
CAMOUFOX_STORAGE_DIR=./profiles

# Optional: run in-browser C++ fingerprint coherence audit automatically on profile startup
CAMOUFOX_AUDIT_ON_START=false

# Pre-TLS traffic recording (Necko egress/ingress NDJSON + per-profile/account attribution index)
CAMOUFOX_RECORD_TRAFFIC=true

# Capture plaintext request/response bodies inside profiles/<profileId>/traffic/payloads/
CAMOUFOX_RECORD_BODIES=true

# Write canonical pre-TLS HTTP/1.1 & HTTP/2 wire stream to profiles/<profileId>/traffic/pre-tls-wire.log
CAMOUFOX_RECORD_WIRE_LOG=true

# Export Firefox NSS TLS 1.2/1.3 secrets to profiles/<profileId>/traffic/sslkeylog.txt
CAMOUFOX_SSLKEYLOG=true

# Optional: enable Firefox C++ Necko kernel MOZ_LOG to profiles/<profileId>/traffic/necko-pre-tls.moz_log
CAMOUFOX_NECKO_MOZ_LOG=false
CAMOUFOX_NECKO_MOZ_LOG_MODULES=timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4

# Optional: record full Playwright HAR 1.2 archive to profiles/<profileId>/traffic/trace.har
CAMOUFOX_RECORD_HAR=false

# Maximum plaintext body size (in bytes) captured per request/response (default: 5MB)
CAMOUFOX_TRAFFIC_MAX_BODY_BYTES=5242880
```

