# Environment Variables (.env)

## Configuration and local state

The app keeps `.env`, the optional `.emv`, `config/proxies.txt`, `results.json`, `summary.json`, `logs/` and the default Camoufox `profiles/` under its state directory. Set `GMAIL_CREATOR_STATE_DIR` to an absolute path to a dedicated directory in the shell environment before launch. The default is `$XDG_STATE_HOME/gmail-account-creator` when `XDG_STATE_HOME` is absolute. The next choice on Windows is `%LOCALAPPDATA%\gmail-account-creator`. The fallback is `~/.local/state/gmail-account-creator`.

The app can read legacy configuration and import sanitized history when the corresponding state files are missing. A source checkout uses its root as the legacy directory. To adopt configuration and history from another installation, set `GMAIL_CREATOR_LEGACY_DIR` to its absolute path in the shell environment before launch. Existing state outputs take precedence. Original files and logs stay in place. Startup reports invalid history and keeps the original file available for review. Set `CAMOUFOX_STORAGE_DIR` to the absolute path of an existing profile store to keep using it.

Within the selected configuration directory, settings supplied by the launch environment take precedence over `.env`. An empty `PROFILE_SERVICE` is treated as unset. If the service is still unset, `.emv` can supply fallback settings. Once a service is selected, `.emv` is read for a missing GoLogin key when GoLogin configuration is requested. Applications and direct SDK callers use the same profile storage and deployment network configuration. A launch `DOTENV_KEY` is validated when a selected encrypted configuration file is read.

Concurrent runs append to `results.json`. `summary.json` holds the latest completed run. If a write times out while another process owns the lock, stop all writers sharing this state directory before inspecting a stranded `results.json.lock` or `summary.json.lock`.

`ACCOUNTS_COUNT` and `THREADS_COUNT` accept positive safe integers in decimal notation. Both default to 1. Concurrency is capped at the requested account count. Explicit `--accounts=N` / `-a=N` and `--threads=N` / `-t=N` take precedence over the environment values.

### Recovering local locks

Use separate state and profile directories for different machines or PID namespaces. A lock created in the same system boot and PID namespace can be recovered after a hostname change when the owner has exited. This uses local boot information on Linux and macOS when available. The app also understands earlier lock formats and retains its hostname and PID checks. Locks from a different hostname with unavailable or different boot information are kept for operator review.

If a lock's owner cannot be verified, stop and verify that all writers on every machine using that directory have exited. If any writer may still be active, leave the directory in place and start in separate state and profile directories. Once all writers have stopped, make a private backup before moving the affected lock directory to a private archive outside the live store. Preserve the entire lock, including any staged snapshot, together with the committed output for review. Account output locks sit beside `results.json` and `summary.json`. A profile lease sits under `.camoufox-leases~` and a capture writer lease sits beside its capture directory.

### Running an older version

Before switching versions, stop all writers and retain a private copy of the newer state and profile store, including stranded locks and staged snapshots. Start the older version with `GMAIL_CREATOR_STATE_DIR` set to a separate private directory. Set `GMAIL_CREATOR_LEGACY_DIR` explicitly to an empty private directory or a copy of the compatible pre-upgrade history. When supplying an explicit `CAMOUFOX_STORAGE_DIR`, point it to a separate directory or a copy of a compatible pre-upgrade profile store. Otherwise use the version-specific default profile directory under its state directory.

Some older versions rewrite existing outputs at startup and can remove newer cleanup states or error categories. They can also reject newer lock markers and snapshots left by an interrupted writer. Use the originating or a compatible newer version with a preserved copy to investigate its interrupted write. Resume the newer version with its original state directory and retain any results recorded during the rollback separately.

## Browser controller connection

GPM Login and Dolphin Anty REST API requests require HTTPS with certificate and hostname verification. If the API certificate uses a private CA, set `NODE_EXTRA_CA_CERTS` to the CA's PEM file before starting Node.

For a controller that serves HTTP on a dedicated host where you trust every local user and process, set `GPM_TRUSTED_HTTP_API_URL` or `DOLPHIN_TRUSTED_HTTP_API_URL` to the matching `GPM_API_URL` or `DOLPHIN_API_URL` base. Include the exact port and any base path, and use a numeric loopback address such as `127.0.0.1` or `[::1]`. This HTTP mode relies on the host's isolation. Use verified HTTPS on a shared host.

Set `DOLPHIN_API_KEY` to the complete Authorization header value for the configured endpoint. Use `Bearer <token>` when the controller requires Bearer authentication, or the raw key when it requires the raw value. Every Dolphin request starts with that configured value. Folder reads retain a compatibility attempt with Bearer after HTTP 401 for a raw key. Use the complete Authorization value to configure profile access.

`DOLPHIN_FOLDER_ID` selects the destination folder directly. If it is unset, the client looks for a folder named `gmail-accounts` and tries to create it if missing. If the folder cannot be selected or created, profile creation stops. Run `npm run list-folders` to see the available IDs.

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

# Optional existing storage directory for profile state. Default: profiles/ in the state directory.
# CAMOUFOX_STORAGE_DIR=/path/to/existing/profiles

# URL filtering checks browser-visible destinations.
CAMOUFOX_PORT_SCAN_MODE=url-only

# Explicitly allow a direct connection in URL-only mode when the proxy inventory is empty.
CAMOUFOX_ALLOW_DIRECT=false

# Optional: run in-browser C++ fingerprint coherence audit automatically on profile startup
CAMOUFOX_AUDIT_ON_START=false

# Pre-TLS traffic recording (Necko egress/ingress NDJSON + per-profile/account attribution index)
CAMOUFOX_RECORD_TRAFFIC=true

# Opt in to private raw attachments for eligible requests and WebSocket frames.
CAMOUFOX_RECORD_BODIES=false

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

Recording switches accept exactly `true` or `false`. `CAMOUFOX_TRAFFIC_MAX_BODY_BYTES` accepts a positive safe integer in decimal notation. Omit a setting to use its default. Invalid explicit settings stop startup before capture begins.

In a deployment that forces browser traffic through a controlled proxy, `CAMOUFOX_PORT_SCAN_MODE=managed-proxy` checks the selected profile proxy against `CAMOUFOX_MANAGED_EGRESS_ORIGIN`. Set the origin to the operator's existing proxy scheme, host and explicit port, without credentials. The proxy owns the policy for the resolved destination IP on every connection, including redirected requests. Its ACL must be verified at the proxy. The `transport` setting requires verified enforcement and stops if the launcher cannot provide it.

The CLI requires a valid proxy inventory with at least one entry by default. For an explicitly direct Camoufox CLI deployment in `url-only` mode with an empty inventory, set `CAMOUFOX_ALLOW_DIRECT=true`. Managed proxy mode always requires its configured proxy. A current `config/proxies.txt` takes precedence over the legacy file even if the current file is empty or contains only comments.

`TEST_PROXY` controls the optional TCP preflight in the standalone GoLogin profile factory. The Camoufox, GPM Login and Dolphin Anty CLI startup paths rely on the proxy inventory and do not use this setting.

The recorder defaults to metadata. Enabling `CAMOUFOX_RECORD_BODIES` stores eligible raw attachments under the profile's private `traffic/payloads/` directory. Redacted wire and HAR views can include a restricted set of fields from eligible complete structured bodies. Reconstruct older wire data through the attribution CLI and review exported data before sharing it. Keep raw attachments, native TLS keys and native Necko logs private.

When reopening a profile with old native logs inside `traffic/`, the app keeps the original archive and its manifest together under the profile's private `.native/legacy-*/traffic/` directory. The current recorder writes the traffic archive under `traffic/` and native diagnostics under `.native/`.

Ordinary attribution reports omit Cookie value digests. The explicit `--cookies` and `--cookie` queries include those digests for private investigation. Historical raw ledgers and logs retain the data originally written to them.

When a HAR-only export fails, the recorder keeps the captured data in private scratch storage. After correcting the output problem, call `stopProfile(profileId, { profilesDir })` again to retry the original export. An ordinary startup leaves a pending export for the operator to resolve.

## Host filesystem permissions

On POSIX hosts, the app sets private directory and file modes to `0700` and `0600`. These settings follow the host running Node.js.

On macOS, review extended ACLs on state and configuration directories, existing files and newly replaced files. Mode bits such as `0700` and `0600` describe POSIX permissions. Apply owner-only effective access before placing private data in a directory. The app refuses ACL grants on its state directory and on checked current result and configuration files. An ACL check preserves existing deny entries and refuses replacement when it could remove such restrictions. Verify effective permissions on any separate profile or capture directories you configure.

On native Windows, deploy the app in a dedicated local NTFS directory with operator-provisioned discretionary access control lists (DACLs). Limit access to the app's run account and authorized system principals. Verify the DACLs on the directories holding results, summaries, logs, browser state and native diagnostics, and on any existing files. Also check a synthetic record after creation and atomic replacement by the run account, since a new file inherits access from its containing directory. The app relies on this Windows host setup.
