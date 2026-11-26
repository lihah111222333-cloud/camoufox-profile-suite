# Environment Variables (.env)

## SMS Provider Configuration

يستخدم مزود SMS Verification مفتاحه الخاص. توقّف محول 5SIM Legacy عن إرسال الطلبات لأن نقطة الاتصال القديمة تستخدم HTTP. عند اختيار المحول القديم، تتوقف العملية محلياً قبل إرسال أي مفتاح.

```env
SMS_PROVIDER=sms-verification
SMS_VERIFY_API_KEY=your_sms_verify_api_key
SMS_VERIFY_LANG=ru
```

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

# URL filtering checks browser-visible destinations.
CAMOUFOX_PORT_SCAN_MODE=url-only

# Optional: run in-browser C++ fingerprint coherence audit automatically on profile startup
CAMOUFOX_AUDIT_ON_START=false

# Pre-TLS traffic recording (Necko egress/ingress NDJSON + per-profile/account attribution index)
CAMOUFOX_RECORD_TRAFFIC=true

# Record eligible request and WebSocket content. Responses without a bounded reader retain metadata.
CAMOUFOX_RECORD_BODIES=true

# Write canonical pre-TLS HTTP/1.1 & HTTP/2 wire stream to profiles/<profileId>/traffic/pre-tls-wire.log
CAMOUFOX_RECORD_WIRE_LOG=true

# Private TLS key log for a dedicated browser process, stored in the profile .native directory
CAMOUFOX_SSLKEYLOG=false

# Optional: enable Firefox C++ Necko kernel MOZ_LOG for a dedicated browser in the profile .native directory
CAMOUFOX_NECKO_MOZ_LOG=false
CAMOUFOX_NECKO_MOZ_LOG_MODULES=timestamp,nsHttp:5,nsSocketTransport:5,nsHostResolver:4

# Optional: export a sanitized HAR 1.2 archive to profiles/<profileId>/traffic/trace.har
CAMOUFOX_RECORD_HAR=false

# Maximum stored body size in bytes
CAMOUFOX_TRAFFIC_MAX_BODY_BYTES=5242880
```

In a deployment that forces browser traffic through a controlled proxy, `CAMOUFOX_PORT_SCAN_MODE=managed-proxy` checks the selected profile proxy against `CAMOUFOX_MANAGED_EGRESS_ORIGIN`. Set the origin to the operator's existing proxy scheme, host and explicit port, without credentials. The proxy owns the policy for the resolved destination IP on every connection, including redirected requests. Its ACL must be verified at the proxy. The `transport` setting requires verified enforcement and stops if the launcher cannot provide it.

On the first reopen of a profile with legacy native logs inside `traffic/`, the application keeps the original archive and its manifest together under the same profile’s private `.native/legacy-*/traffic/` directory. New diagnostics are written to the profile’s current `traffic/` directory.

## Host filesystem permissions

On POSIX hosts, the app sets private directory and file modes to `0700` and `0600`. These settings follow the host running Node.js.

On native Windows, deploy the app in a dedicated local NTFS directory with operator-provisioned discretionary access control lists (DACLs). Limit access to the app's run account and authorized system principals. Verify the DACLs on the directories holding results, summaries, logs, browser state and native diagnostics, and on any existing files. Also check a synthetic record after creation and atomic replacement by the run account, since a new file inherits access from its containing directory. The app relies on this Windows host setup.
