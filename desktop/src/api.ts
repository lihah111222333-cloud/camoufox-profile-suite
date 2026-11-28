// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

// The server is the only authority on what a user may do. Nothing here decides
// permissions; it reads the set the server resolved and renders accordingly.
//
// Two transports, one surface:
//
//   * In the packaged app, every call is a Tauri command. The session token
//     lives in Rust and in the OS keychain, and never enters this document.
//   * Under `npm run dev` in a plain browser there is no Rust side, so calls go
//     out via fetch through Vite's proxy and the token sits in localStorage.
//
// The browser path is kept because the edit-reload loop for the interface is
// seconds there and tens of seconds through a Tauri rebuild. It is a
// development convenience and is not what ships — which is why the token
// handling differs, and why that difference is stated here rather than hidden.

// Adapted for Camoufox Studio HTTP Web UI mode (local loopback /rpc transport).

export const isDesktop = true;

export type Perm =
  | "view" | "launch" | "edit_profile" | "edit_fingerprint" | "edit_proxy"
  | "reveal_secrets" | "export_cookies" | "create_profile" | "delete_profile"
  | "manage_access";

export interface Project {
  /** Which world it lives in: this machine, or the server. */
  origin: Origin;
  id: string;
  name: string;
  profile_count: number;
}

export interface ProxySummary {
  id: string;
  name: string;
  kind: string;
  /** Already masked by the server when the caller lacks reveal_secrets.
   *  Never masked in local mode — there is nobody to hide it from. */
  display: string;
  has_rotation?: boolean;
  country: string | null;
  last_ip?: string | null;
  /** The exit's zone from the last check, if any — what "follow the exit" resolves to. */
  last_timezone?: string | null;
}

export interface LockInfo {
  user_id: string;
  user_email: string;
  machine_name: string;
  acquired_at: string;
  expires_at: string;
}

/** A login stored beside a profile: what a shared account needs besides cookies. */
export interface Credential {
  id: string;
  profile_id: string;
  label: string;
  site: string;
  username: string | null;
  password: string | null;
  /** An `otpauth://` URI once saved; a bare base32 secret is accepted on input.
   *  Present here because the operator has to be able to see and correct what
   *  they typed — there is nobody on this machine to hide it from. */
  totp: string | null;
  notes: string;
  /** Team mode only: the server had this login and this machine's organisation
   *  key did not open it — almost always a key rotated after this copy was
   *  handed over. Shown, not hidden: an empty row reads as a deleted password. */
  unreadable?: boolean;
}

export interface TotpCode {
  code: string;
  seconds_remaining: number;
  /** The one after this. Shown so a code handed over with two seconds left is
   *  not a login that fails for a reason nobody blames on the clock. */
  next: string;
}

/** Which world a row came from: this machine's own store, or the server.
 *
 *  Connected to a server the list carries both, so the shell's mode no longer
 *  tells an action where to send itself -- the row does. Every call that acts
 *  on ONE existing profile passes it. */
export type Origin = "local" | "team" | "shared";

export interface Profile {
  id: string;
  origin: Origin;
  /** How many people hold this profile through a share. Zero for a local one. */
  shared_with: number;
  /** Team profiles: the current version's size on the server, encrypted and
   *  compressed. Absent before the first upload and from older servers. */
  bundle_bytes?: number | null;
  /** Null when the profile is in no project. Profiles is the master list —
   *  every profile on this machine — and a project is a grouping a profile can
   *  be put into or taken out of without ever being at risk. */
  project_id: string | null;
  /** Where it is filed, so the flat list can show it without a call per row. */
  project_name: string | null;
  /** Optional inline new project name created on save in local mode. */
  project_name_new?: string;
  name: string;
  /** Persistent sequential number (#82, #91, #1...) shown in list, browser bar & Dock icon. */
  serial_number?: number;
  /** Primary account email/login bound to this profile for quick categorization. */
  account_email?: string;
  /** Primary account password stored in 0600 local state. */
  account_password?: string;
  /** Primary account 2FA TOTP Base32 secret (or otpauth:// URI) stored in 0600 local state. */
  account_totp?: string;
  /** Round-tripped by the editor; both were absent from the row until 12.09.2026,
   *  and the editor wrote the absence back on every save. */
  notes?: string;
  start_urls?: string[];
  /** The account's stage — see status.ts. Empty is none. */
  status?: string;
  tags: string[];
  persona_id: string;
  /** Zero in team mode — the server never exposes a seed. */
  fp_seed: number;
  proxy: ProxySummary | null;
  /** Which proxy, on the way IN. `proxy` above is what comes back OUT. */
  proxy_id?: string | null;
  /** May this one open with no proxy at all? Off everywhere it was not asked
   *  for, and never true for a team profile — that one opens on somebody
   *  else's machine, where "this machine" would be theirs. */
  allow_no_proxy?: boolean;
  /** Null means "follow the proxy's exit", resolved at launch. */
  timezone: string | null;
  languages: string[] | null;
  /** Machine fields pinned by hand over the persona. Absent or empty is "as
   *  the machine has it". Validated with the persona on save and at launch. */
  overrides?: MachineOverrides;
  /** Names of domain lists the relay applies. Local profiles only; absent
   *  from what a server returns. */
  blocklists?: string[];
  lock: LockInfo | null;
  permissions: Perm[];
  /** Local mode only: the agent knows what it launched. In team mode a
   *  colleague's browser shows up through `lock`, not here. */
  running: boolean;
  last_opened_at: string | null;
}

/** A named list of domains the relay refuses — or, with `@allow-only` on its
 *  first line, the only domains it permits; or, with `@local`, hosts on this
 *  machine's own network that every profile here reaches directly. */
export interface DomainList {
  name: string;
  domains: number;
  allow_only: boolean;
  local: boolean;
}

export interface LoginOutcome {
  me: Me | null;
  challenge: string | null;
  must_enrol_totp: boolean;
}

export interface SecurityPolicy {
  second_factor: "off" | "new_device" | "always";
  ip_allowlist: string[];
  owner_exempt_from_allowlist: boolean;
  /** A fresh code before purging, removing a member, changing the policy. */
  sensitive_actions_2fa: boolean;
}

export interface LoginEvent {
  id: number;
  email: string;
  outcome: string;
  ip: string | null;
  machine_name: string;
  user_agent: string | null;
  at: string;
}

export interface SessionRow {
  id: string;
  user_id: string;
  email: string;
  machine_name: string;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  last_seen_at: string;
  current: boolean;
}

export interface WarmPlan {
  urls: string[];
  dwell_seconds: [number, number];
  follow_link: boolean;
  close_after: boolean;
  /** Set on a farming session: the run reports back to its plan. */
  farm_id?: string;
}

/** A link, or a folder of them: a folder is a node with no `url`. */
export interface BookmarkNode {
  title: string;
  url?: string | null;
  children?: BookmarkNode[];
}

/** A tree of folders and links given to many profiles. See agent/src/bookmarks.rs. */
export interface BookmarkSet {
  id: string;
  name: string;
  nodes: BookmarkNode[];
  profiles: string[];
  all_profiles: boolean;
}

/** A warm-up on a schedule, over days. See agent/src/farm.rs. */
export interface FarmSpec {
  name: string;
  urls: string[];
  days: number;
  sites_per_day: [number, number];
  /** Local hours, [from, to), in each profile's own timezone. */
  hours: [number, number];
  dwell_seconds: [number, number];
  follow_link: boolean;
  at_once: number;
  set_stage: boolean;
}

export interface FarmTarget {
  id: string;
  name: string;
  origin: Origin;
  timezone: string | null;
}

export type FarmOutcome =
  | { kind: "done"; sites: number; cookies: number }
  | { kind: "failed"; error: string }
  | { kind: "skipped"; why: string };

export interface FarmSession {
  at_ms: number;
  urls: string[];
  started_ms?: number | null;
  ended?: FarmOutcome | null;
}

export interface FarmTrack {
  days_done: number;
  day?: string | null;
  sessions: FarmSession[];
  sites: number;
  cookies?: number | null;
  last_error?: string | null;
  stage_pending?: string | null;
}

export interface Farm {
  id: string;
  created_ms: number;
  spec: FarmSpec;
  targets: FarmTarget[];
  tracks: Record<string, FarmTrack>;
  paused: boolean;
}

export interface FarmDue {
  farm_id: string;
  profile_id: string;
  name: string;
  origin: Origin;
}

export interface WarmProgress {
  profile_id: string;
  name: string;
  total: number;
  done: number;
  current: string | null;
  cookies_before: number;
  cookies_now: number;
  finished: boolean;
  stopped: boolean;
  error: string | null;
  started_at_ms: number;
}

/** A role the organisation named itself: a set of project rights given to
 *  people project by project. Changing it changes everyone on it. */
export interface AccessRole {
  id: string;
  name: string;
  permissions: Perm[];
  updated_at: string;
  /** How many project grants follow it. */
  grants: number;
}

export interface OrgDomainList {
  id: string;
  name: string;
  body: string;
  updated_at: string;
  domains: number;
  allow_only: boolean;
  local: boolean;
}

export interface MirrorStatus {
  active: boolean;
  typing: boolean;
  members: { profile_id: string; name: string; pages: number }[];
  mirrored: number;
}

export interface Diagnosis {
  ok: boolean;
  steps: { step: string; ok: boolean; ms: number | null; detail: string; code: string | null }[];
  exit: {
    ip: string | null; country: string | null; region: string | null; city: string | null;
    timezone: string | null; org: string | null;
  };
  notes: { code: string; detail: string }[];
}

export interface Extension {
  id: string;
  name: string;
  version: string;
  path: string;
}

/** What the batch dialog remembers under a name. Never a seed, never a
 *  persona: those are per profile by design. */
export interface ProfileTemplate {
  name: string;
  pattern: string;
  proxy_id: string;
  tags: string[];
  status: string;
  start_urls: string[];
  languages: string[];
  timezone: string;
  notes: string;
}

/** Where the key pinning an extension's id came from (agent ext.rs): the
 *  developer's manifest, one this machine made for an earlier install of an
 *  extension with this name, or one made just now. Null for a .crx. */
export type KeySource = "manifest" | "saved" | "generated" | null;

/** An extension as the operator handed it over: a .crx or .zip, or a folder's
 *  files with paths relative to the folder chosen. */
export type ExtensionPackage =
  | { packageB64: string }
  | { files: { path: string; b64: string }[] };

/** One open account-recovery attempt (server recovery.rs). */
export interface RecoveryAttempt {
  id: string;
  email: string;
  factor: "totp" | "email" | "wait";
  created_at: string;
  ready_at: string | null;
  ip: string | null;
  machine_name: string;
}

export interface RecoveryStatus {
  has_key: boolean;
  created_at: string | null;
  pending: RecoveryAttempt[];
}

/** Where a recovery stands: which second step, and whether it is passed. */
export interface RecoveryStep {
  factor: "totp" | "email" | "wait";
  ready: boolean;
  ready_at: string | null;
}

export interface ExtensionEverywhere {
  id: string;
  name: string;
  version: string;
  profiles: { id: string; name: string; version: string }[];
}

/** One row of shared/extensions/catalogue.json. */
export interface CatalogueEntry {
  id: string;
  name: string;
  summary: { en: string; ru: string };
  category: string;
  homepage: string;
  licence: string;
  added_by: string;
  added_on: string;
}

export interface StoreInstallResult {
  extension: Extension | null;
  installed: string[];
  skipped: { id: string; reason: string }[];
  /** How many distinct proxies the package was fetched through. */
  routes: number;
}

export interface Usage {
  total: number;
  cache: number;
  keep: number;
  files: number;
}

/** Mirrors fury_shared::overrides::MachineOverrides. Every key optional. */
export interface MachineOverrides {
  ui_locale?: string;
  screen?: { width: number; height: number; device_pixel_ratio: number };
  cores?: number;
  memory_gb?: number;
  /** Id of a persona of the same OS whose GPU this one takes. */
  gpu?: string;
  geolocation?: { latitude: number; longitude: number };
  /** Canvas and WebGL readback: noised (absent, the default) or this machine's own. */
  canvas?: "noise" | "real";
  netinfo?: {
    effectiveType?: "slow-2g" | "2g" | "3g" | "4g";
    downlink?: number;
    rtt?: number;
    saveData?: boolean;
  };
  fonts_hidden?: string[];
}

/** What the pickers may offer for one machine, filtered by its OS. */
export interface OverrideOptions {
  screens: [number, number][];
  device_pixel_ratios: number[];
  cores: number[];
  memory_gb: number[];
  gpus: { id: string; renderer: string }[];
  ui_locales: string[];
}

export type Vendor = "gologin" | "dolphin" | "adspower" | "undetectable" | "kameleo" | "vision" | "octo";

export interface VendorProfile {
  id: string;
  name: string;
  notes: string;
  tags: string[];
  /** "win", "mac", "lin", "android", or "" when the source does not say. */
  os: string;
  /** host:port, for showing. */
  proxy: string | null;
  /** What that source needs back to read the profile; passed through. */
  extra: unknown;
}

export interface VendorDetail {
  proxy_line: string | null;
  proxy_note: string | null;
  start_url: string | null;
  cookies: unknown[];
  /** Why there are no cookies, when the source says: sync off, a running profile. */
  cookie_note?: string | null;
  /** The OS when only the profile's detail says it (Octo); wins over the list's. */
  os?: string | null;
}

export interface Persona {
  id: string;
  os: string;
  gpu: string;
  screen: string;
  weight: number;
  source: string | null;
  /** Not built in: captured here, fetched from the team, or FURY_PERSONAS. */
  own?: boolean;
}

/** A machine in this computer's personas folder: captured here, or an
 *  organisation machine the app fetched. */
export interface KeptPersona {
  id: string;
  persona: Record<string, unknown> & { id: string };
  in_team: boolean | null;
}

export interface Preview {
  user_agent: string;
  platform: string;
  languages: string[];
  timezone: string;
  hardware_concurrency: number;
  device_memory: number;
  /** null when the profile reports the monitor it runs on (no screen pinned). */
  screen: string | null;
  gpu_vendor: string;
  gpu_renderer: string;
  client_hints_platform: string;
  chrome_version: string;
  client_hints: string;
  avail: string | null;
  device_pixel_ratio: number | null;
  color_depth: number;
  max_touch_points: number;
  /** null when the persona has no WebGPU adapter data. */
  webgpu: string | null;
  webgl_extensions: number;
  audio_sample_rate: number;
  /** null when the persona carries no voice list — the vector then follows the host. */
  voices: number | null;
  media_devices: string | null;
  ui_locale: string;
  webrtc: string;
  js_heap_gb: number | null;
  persona_source: string | null;
  persona_weight: number;
  fonts: number;
  noise: { canvas: boolean; audio: boolean; client_rects: boolean };
  /** Contradictions that make this device impossible. Non-empty blocks saving:
   *  an inconsistent profile stands out more than an un-spoofed one. */
  problems: string[];
  options: OverrideOptions;
  /** The persona's own values, for "as the machine has it". */
  base: {
    screen: [number, number];
    device_pixel_ratio: number;
    cores: number;
    memory_gb: number;
    gpu: string;
  };
  /** Only when the profile pins a position; otherwise it follows the exit. */
  geolocation: { latitude: number; longitude: number } | null;
}

/** What `parse_proxy_line` found in a pasted line. */
export interface ParsedProxyLine {
  kind: string;
  host: string;
  port: number;
  username: string | null;
  password: string | null;
  shape: "Url" | "HostPort" | "HostPortUserPass" | "AtSign" | "UserPassHostPort" | "HostPortAtUserPass";
}

export interface LocalProxy {
  id: string;
  name: string;
  kind: string;
  host: string;
  port: number;
  username: string | null;
  password: string | null;
  /** A team proxy: its login and password are on the server, sealed, and
   *  never sent here. Blank fields in the form keep them. */
  sealed?: boolean;
  /** A team proxy: who added it, by email; null when nobody is recorded. */
  added_by?: string | null;
  /** A team proxy: whether this account may change or delete it. `false` only
   *  when the server said so; absent from an older server, which does not. */
  may_change?: boolean | null;
  last_country: string | null;
  last_ip: string | null;
  /** The exit's zone from the last check; absent from a server-side proxy. */
  last_timezone?: string | null;
  /** Provider link that hands out a new exit IP. */
  rotate_url: string | null;
  /** Where to ask what the exit looks like; null uses the default. */
  checker_url: string | null;
}

export interface Me {
  user_id: string;
  email: string;
  org_id: string;
  role: "owner" | "admin" | "manager" | "member";
  /** The team server's own version. Missing on servers before 0.4.2. */
  server_version?: string;
}

/** What the shell knows before anyone signs in. */
export interface Shell {
  server_url: string | null;
  machine_name: string;
  signed_in: boolean;
  native: boolean;
  /** "local" needs no account at all; "team" is a server someone chose. */
  mode: "local" | "team";
  agent_ready: boolean;
  /** Whether a browser is installed at all. The application and the browser are
   *  two downloads, so "the app runs" and "there is something to launch" are
   *  different questions. */
  core_ready: boolean;
  /** The agent's own sentence about why there is none, when it has one — a
   *  stale FURY_CORE reads nothing like a missing download. */
  core_problem: string | null;
  /** Installed, but a different Chrome from the one this version claims to
   *  be. core_ready is false with it, so the download bar shows. */
  core_outdated?: { have: string; need: number } | null;
  /** The right Chrome, but an older Fury build of it than this version
   *  expects. Not blocking: core_ready stays true and profiles launch; the
   *  shell offers the new build. `have` is null for a core installed before
   *  releases were recorded. */
  core_stale?: { have: string | null; need: string } | null;
  /** Progress of a core download the user asked for, straight from the agent.
   *  Absent until the agent has been asked once. `running` false with
   *  `installed` set means it finished; with `error` set means it did not. */
  /** Where the agent writes its own log. Shown on the About screen: a person
   *  reporting a problem should not have to be told the path per platform. */
  log_file?: string | null;
  core_download?: {
    running: boolean;
    downloaded: number;
    total: number;
    installed: string | null;
    error: string | null;
  } | null;
  /** Whether the organisation key is remembered between launches. */
  remember_org_key: boolean;
  /** This build, for the About panel and for any bug report that follows. */
  version: string;
  /** Whether this process holds the organisation key. A session survives a
   *  restart; the key deliberately does not. So "signed in" and "able to
   *  decrypt" are different states, and both have to be visible. */
  org_key_ready: boolean;
  last_email: string | null;
  /** The server this machine was last pointed at, kept after it stops being
   *  pointed at one — so returning is a button that knows the address rather
   *  than a first-run screen asking for it. */
  last_server: string | null;
  /** Signed in, holding no key, and there is none on the server to hold — the
   *  member enrolled and nobody has handed it over yet. Distinct from
   *  `org_key_ready` being false for the ordinary reason, because a password
   *  fixes one of those and cannot fix the other. False against a server too
   *  old to answer the question. */
  awaiting_key: boolean;
}

/** Note what is absent: the lock token. It authorises overwriting a bundle,
 *  so in the desktop build it stays in Rust — the interface only needs to know
 *  when the lock lapses and how a launch would be constrained. */
export interface LaunchResult {
  /** True when a browser actually started. False in team mode, where all that
   *  happened was taking the lock — saying otherwise would have the operator
   *  waiting for a window that never appears. */
  launched: boolean;
  pid?: number;
  expires_at?: string;
  restrictions?: Record<string, boolean>;
  renewed?: boolean;
}

const TOKEN_KEY = "fury.token";

// A build that once ran in the browser leaves a token behind in the webview's
// data store, where it survives every later launch of the packaged app. The
// server would happily keep renewing it — sessions slide forward on each
// authenticated request — so the copy the desktop stopped using is exactly the
// copy nothing will ever expire. Drop it on sight.
if (isDesktop && typeof localStorage !== "undefined") {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem("fury.machine_id");
}

/** A profile a bulk action (warming, mirroring) could not take. `code` is
 *  set when the reason is one of the application's own, so it can be shown in
 *  the interface's language rather than the agent's. */
export type Assistants = {
  agent: string | null;
  agent_problem: "missing" | "not_installed" | null;
  clients: { id: "claude_desktop" | "cursor"; installed: boolean; connected: boolean; stale: boolean; config: string }[];
  claude_code: string | null;
  snippet: string | null;
  skill_installed: boolean;
  skill_path: string;
};

export type Refusal = { id: string; reason: string; code?: string | null };

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body: unknown = null,
    /** Set for failures this application produced itself, so the interface can
     *  say them in the operator's language. The message is the fallback. */
    public code: string | null = null,
  ) {
    super(message);
  }
}

/** Turns a status and the server's JSON body into something worth reading. */
function describe(status: number, body: any): string {
  if (body?.error === "denied") {
    return `Not permitted: this action needs "${body.missing_permission}".`;
  }
  if (body?.error === "locked") {
    const h = body.holder ?? {};
    return `In use by ${h.user_email ?? "someone"} on ${h.machine_name ?? "another machine"}.`;
  }
  if (status === 401) return "Session expired. Sign in again.";
  // 404 covers both "gone" and "not yours" — the server deliberately does not
  // distinguish them, so neither does this message.
  if (status === 404) return "Not found, or you no longer have access.";
  if (body?.message) return body.message;
  // status 0 means the request never reached a server; the Rust side has
  // already written a specific sentence for that case.
  if (status === 0) return "Could not reach the server.";
  return `Request failed (${status}).`;
}

// ---------------------------------------------------------------------------
// desktop transport
// ---------------------------------------------------------------------------

/** Rust rejects with the serialised ApiErr — {status, body, message}. */
/** What an invitation code is for. `creates_org_key` is the server's word, not
 *  the client's: a member who decided for themselves that they were an owner
 *  would generate a second organisation key, and their data would then be
 *  readable by nobody. */
export type Invitation = {
  email: string;
  organization: string;
  role: string;
  creates_org_key: boolean;
  /** The server sends six digits to `email` and wants them back before the
   *  account is made (server 0018). Absent on an older server. */
  email_check?: boolean;
};

export type UpdateProgress = {
  stage: "idle" | "checking" | "stopping" | "downloading" | "installing" | "restarting" | "failed";
  received: number;
  total: number | null;
  error: string | null;
};

async function cmd<T>(name: string, args: Record<string, unknown> = {}): Promise<T> {
  if (name === "open_url" && typeof args.url === "string" && args.url) {
    window.open(args.url, "_blank", "noopener,noreferrer");
    return undefined as T;
  }
  let res: Response;
  const controller = new AbortController();
  const longRunning =
    name === "launch_many" ||
    name === "suite_run_coherence" ||
    name === "suite_audit_profile" ||
    name === "suite_ensure_baseline" ||
    name === "suite_run_cli";
  const timeoutMs = longRunning ? 120000 : 25000;
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    res = await fetch("/rpc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method: name, params: args }),
      signal: controller.signal,
    });
  } catch (err: any) {
    const msg = err?.name === "AbortError"
      ? "本地服务响应超时，请稍后重试。"
      : (err?.message || "Could not reach local Camoufox Studio HTTP bridge.");
    throw new ApiError(0, msg);
  } finally {
    window.clearTimeout(timer);
  }

  const payload = await res.json().catch(() => null);
  if (!res.ok || payload?.ok === false) {
    const status = typeof payload?.status === "number" ? payload.status : res.status;
    const body = payload?.body ?? null;
    const message =
      typeof payload?.message === "string" ? payload.message : describe(status, body);
    throw new ApiError(status, message, body, typeof payload?.code === "string" ? payload.code : null);
  }
  return payload.result as T;
}

// ---------------------------------------------------------------------------
// browser transport (development only)
// ---------------------------------------------------------------------------

export function storedToken(): string | null {
  return isDesktop ? null : localStorage.getItem(TOKEN_KEY);
}

async function http<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = storedToken();
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers ?? {}),
    },
  });

  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => null);

  if (!res.ok) {
    // 401 means the session is gone — expired, or revoked because someone
    // removed this operator. Both mean the same thing to the UI, and holding a
    // dead token would only produce a wall of errors.
    if (res.status === 401) localStorage.removeItem(TOKEN_KEY);
    throw new ApiError(res.status, describe(res.status, body), body);
  }
  return body as T;
}

/** Stable per installation, so the lock list names the same browser each time. */
function devMachineId(): string {
  const key = "fury.machine_id";
  let id = localStorage.getItem(key);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(key, id);
  }
  return id;
}

// ---------------------------------------------------------------------------

export const api = {
  shell(): Promise<Shell> {
    if (isDesktop) return cmd<Shell>("shell_state");
    return Promise.resolve({
      mode: "team" as const,
      agent_ready: false,
      core_ready: true,
      core_problem: null,
      core_download: null,
      remember_org_key: true,
      version: "dev",
      org_key_ready: false,
      last_email: null,
      last_server: null,
      awaiting_key: false,
      // Vite proxies /v1, so in this mode the address is fixed by the dev
      // config rather than chosen by the operator.
      server_url: "http://127.0.0.1:8901 (vite proxy)",
      machine_name: navigator.platform || "this browser",
      signed_in: storedToken() !== null,
      native: false,
    });
  },

  setServer(url: string): Promise<Shell> {
    if (!isDesktop) {
      return Promise.reject(
        new ApiError(0, "The server address is fixed by vite.config.ts in development."),
      );
    }
    return cmd<Shell>("set_server", { url });
  },

  /** What an invitation code is for, before anyone types a password. The
   *  address travels with the call because this is how someone reaches a server
   *  for the first time — there is nothing in settings yet. */
  async invitation(url: string, code: string): Promise<Invitation> {
    if (!isDesktop) {
      return Promise.reject(
        new ApiError(0, "Enrolment generates keys in Rust and is desktop-only."),
      );
    }
    return cmd<Invitation>("invitation", { url, code });
  },

  /** Redeem it. The password is passed to Rust and no further: the keys are
   *  generated there, and only wrapped material reaches the server. */
  /** Whether a server takes open sign-ups. An old server that never heard of
   *  the question answers no, which is the right answer. */
  serverAllowsSignup: (url: string): Promise<boolean> =>
    cmd<boolean>("server_allows_signup", { url }),

  /** Make an account with no invitation, on a server that allows it. Creates
   *  an organisation with you as its owner. */
  signup: (url: string, email: string, password: string, orgName: string): Promise<Me> =>
    cmd<Me>("signup", { url, email, password, orgName }),

  async enrol(url: string, code: string, password: string, createsOrg: boolean, emailProof?: string | null): Promise<Me> {
    if (!isDesktop) {
      return Promise.reject(
        new ApiError(0, "Enrolment generates keys in Rust and is desktop-only."),
      );
    }
    return cmd<Me>("enrol", { url, code, password, createsOrg, emailProof: emailProof ?? null });
  },

  /** Ask for the letter with six digits. `sent` false means the last one went
   *  out under a minute ago: wait `retry_after` seconds. */
  invitationEmail: (url: string, code: string, lang: string): Promise<{ sent: boolean; retry_after: number }> =>
    cmd("invitation_email", { url, code, lang }),
  /** The six digits in, the proof that `enrol` carries out. */
  invitationEmailVerify: (url: string, code: string, emailCode: string): Promise<{ email_proof: string }> =>
    cmd("invitation_email_verify", { url, code, emailCode }),
  /** Eight digits from a member's public key as the server lists it, to
   *  compare with what that person's own Fury shows (crypto::verify_code). */
  verifyCode: (publicKey: string): Promise<string> => cmd<string>("verify_code", { publicKey }),
  /** This installation's own code, from the key it made or opened itself.
   *  Null when it has not seen that key (see own_verify_code). */
  ownVerifyCode: (): Promise<string | null> => cmd<string | null>("own_verify_code"),
  /** What a server says before anyone signs in. Empty from an old one. */
  serverInfo: (url: string): Promise<{ open_signup?: boolean; email_check?: boolean }> =>
    cmd("server_info", { url }),

  /** A sign-in comes back as an identity, or as a challenge when the
   *  organisation wants a code first — then `loginTotp` finishes it. */
  async login(email: string, password: string): Promise<LoginOutcome> {
    if (isDesktop) return cmd<LoginOutcome>("login", { email, password });

    const res = await fetch("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, machine_name: navigator.platform }),
    });
    if (!res.ok) throw new ApiError(res.status, "Wrong email or password.");
    const body = await res.json();
    if (body.second_factor === "totp") return { me: null, challenge: body.challenge, must_enrol_totp: false };
    localStorage.setItem(TOKEN_KEY, body.token);
    return { me: await http<Me>("/v1/me"), challenge: null, must_enrol_totp: !!body.must_enrol_totp };
  },
  loginTotp: (email: string, password: string, challenge: string, code: string): Promise<LoginOutcome> =>
    cmd<LoginOutcome>("login_totp", { email, password, challenge, code }),

  // ---- team security -----------------------------------------------------

  // ---- account recovery and owner hand-over (docs/25) ----
  recoveryStatus: (): Promise<RecoveryStatus> => cmd("recovery_status"),
  /** Returns the printed recovery code, once. */
  recoveryCreate: (password: string, totpCode: string | null): Promise<string> =>
    cmd("recovery_create", { password, totpCode }),
  recoveryCancel: (id: string): Promise<unknown> => cmd("recovery_cancel", { id }),
  orgRecoveries: (): Promise<RecoveryAttempt[]> => cmd("org_recoveries"),
  handOverOwnership: (userId: string, password: string, totpCode: string | null): Promise<unknown> =>
    cmd("hand_over_ownership", { userId, password, totpCode }),
  recoveryStart: (email: string, code: string, lang: string): Promise<RecoveryStep> =>
    cmd("recovery_start", { email, code, lang }),
  recoveryPoll: (): Promise<RecoveryStep> => cmd("recovery_poll"),
  recoveryVerify: (code: string): Promise<RecoveryStep> => cmd("recovery_verify", { code }),
  recoveryFinish: (password: string): Promise<{ me: Me; code: string }> => cmd("recovery_finish", { password }),
  recoveryAbandon: (): Promise<void> => cmd("recovery_abandon"),
  saveRecoveryFile: (code: string, email: string): Promise<string> => cmd("save_recovery_file", { code, email }),
  totpStatus: (): Promise<{ enabled: boolean; enabled_at: string | null; pending: boolean; required_by_org: string }> =>
    cmd("totp_status"),
  totpSetup: (): Promise<{ uri: string; secret: string }> => cmd("totp_setup"),
  totpConfirm: (code: string): Promise<{ enabled: boolean }> => cmd("totp_confirm", { code }),
  /** Marks this session as recently verified; see stepUp.ts. */
  totpVerify: (code: string): Promise<{ verified: boolean; minutes: number }> => cmd("totp_verify", { code }),
  totpDisable: (code: string): Promise<{ enabled: boolean }> => cmd("totp_disable", { code }),
  orgSecurity: (): Promise<{ policy: SecurityPolicy; members: { user_id: string; email: string; totp_enabled_at: string | null }[] }> =>
    cmd("org_security"),
  setOrgSecurity: (policy: SecurityPolicy): Promise<{ policy: SecurityPolicy }> => cmd("set_org_security", { policy }),
  loginEvents: (before?: number | null, outcome?: string | null, email?: string | null): Promise<LoginEvent[]> =>
    cmd("login_events", { before: before ?? null, outcome: outcome ?? null, email: email ?? null }),
  sessions: (all: boolean): Promise<SessionRow[]> => cmd("sessions", { all }),
  revokeSession: (id: string): Promise<{ revoked: number }> => cmd("revoke_session", { id }),
  revokeMemberSessions: (userId: string): Promise<{ revoked: number }> => cmd("revoke_member_sessions", { userId }),

  async logout(): Promise<void> {
    if (isDesktop) return cmd<void>("logout");
    // Revoke first, forget second. Clearing the token up front would send the
    // request unauthenticated, leaving a live session on the server — the
    // opposite of what signing out is for. The local token is dropped even if
    // the call fails, so a user on a dead network still ends up logged out.
    try {
      await http("/v1/auth/logout", { method: "POST" });
    } catch {
      // Already invalid, or unreachable. Either way, nothing left to do.
    } finally {
      localStorage.removeItem(TOKEN_KEY);
    }
  },

  me: (): Promise<Me> => (isDesktop ? cmd<Me>("me") : http<Me>("/v1/me")),

  projects: (): Promise<Project[]> =>
    isDesktop ? cmd<Project[]>("projects") : http<Project[]>("/v1/projects"),

  createProjectIn: (name: string, origin: Origin): Promise<{ id: string }> =>
    cmd<{ id: string }>("create_project", { name, origin }),

  /** Every profile when `projectId` is omitted — which is the Profiles view,
   *  and the ordinary case. Passing one narrows it. */
  profiles: (projectId?: string, origin?: Origin): Promise<Profile[]> =>
    isDesktop
      ? cmd<Profile[]>("profiles", { projectId: projectId ?? null, origin: origin ?? null })
      : projectId
        ? http<Profile[]>(`/v1/projects/${projectId}/profiles`)
        : Promise.resolve([]),

  // ---- the team (server only) ------------------------------------------

  /** Who did what, newest first. Owners and admins only; the server refuses
   *  everyone else, so a Member never sees this screen offered. */
  audit: (before?: number, filters?: { action?: string; actor?: string; since?: string; until?: string }): Promise<
    {
      id: number;
      actor: string;
      action: string;
      target_id: string | null;
      detail: unknown;
      at: string;
    }[]
  > => cmd("audit", {
    before: before ?? null,
    action: filters?.action || null,
    actor: filters?.actor || null,
    since: filters?.since || null,
    until: filters?.until || null,
  }),

  orgMembers: (): Promise<{
    members: {
      user_id: string;
      email: string;
      role: string;
      public_key: string;
      has_key: boolean;
      joined_at: string;
      is_you: boolean;
    }[];
    invited: { email: string; role: string; expires_at: string }[];
  }> => cmd("org_members"),

  setRememberOrgKey: (remember: boolean): Promise<Shell> =>
    cmd<Shell>("set_remember_org_key", { remember }),

  invite: (email: string, role: string): Promise<{ code: string; expires_in_hours: number }> =>
    cmd("invite", { email, role }),

  setMemberRole: (userId: string, role: string): Promise<{ role: string; changed: boolean }> =>
    cmd("set_member_role", { userId, role }),

  /** Seal the organisation key to a member's public key. Happens in Rust; the
   *  key itself never reaches this side. */
  handOverKey: (userId: string, publicKey: string): Promise<unknown> =>
    cmd("hand_over_key", { userId, publicKey }),

  grants: (projectId: string): Promise<{
    granted: {
      user_id: string;
      email: string;
      role: string;
      permissions: Perm[];
      domain_lists?: string[];
      access_role?: string | null;
    }[];
    implicit: { user_id: string; email: string; role: string }[];
  }> => cmd("grants", { projectId }),

  /** `domainLists` undefined keeps what the grant already carries. So does
   *  `accessRole` undefined; `null` unlinks the grant from its role, so the
   *  `permissions` sent stand on their own; an id links it, and the server
   *  takes the role's boxes instead of `permissions`. */
  grantAccess: (
    projectId: string,
    userId: string,
    permissions: Perm[],
    domainLists?: string[],
    accessRole?: string | null,
  ): Promise<unknown> =>
    cmd("grant_access", {
      projectId,
      userId,
      permissions,
      domainLists: domainLists ?? null,
      accessRole: accessRole ?? null,
      link: accessRole !== undefined,
    }),

  /** The organisation's own roles (server 0017) — readable by every member,
   *  written by owners and admins. */
  accessRoles: (): Promise<AccessRole[]> => cmd<AccessRole[]>("access_roles"),
  saveAccessRole: (id: string | null, name: string, permissions: Perm[]): Promise<{ id: string; grants_rewritten: number }> =>
    cmd("save_access_role", { id, name, permissions }),
  deleteAccessRole: (id: string): Promise<unknown> => cmd("delete_access_role", { id }),

  /** The organisation's domain lists — readable by every member, written by
   *  owners and admins, attached to grants. */
  orgDomainLists: (): Promise<OrgDomainList[]> => cmd<OrgDomainList[]>("org_domain_lists"),
  saveOrgDomainList: (id: string | null, name: string, body: string): Promise<{ id: string; domains: number }> =>
    cmd("save_org_domain_list", { id, name, body }),
  deleteOrgDomainList: (id: string): Promise<unknown> => cmd("delete_org_domain_list", { id }),

  revokeAccess: (projectId: string, userId: string): Promise<unknown> =>
    cmd("revoke_access", { projectId, userId }),

  /** Remove a member and replace the organisation key. Pass null to rotate
   *  without removing anyone — after a lost laptop, say. */
  removeMember: (userId: string | null): Promise<{ generation: number; unreadable?: number }> =>
    cmd("remove_member", { userId }),

  /** AI assistants over MCP: which are connected, and connecting them. See
   *  src-tauri/assistants.rs. */
  assistants: (): Promise<Assistants> => cmd("assistants_state"),
  assistantsConnect: (client: string): Promise<Assistants> => cmd("assistants_connect", { client }),
  assistantsDisconnect: (client: string): Promise<Assistants> => cmd("assistants_disconnect", { client }),
  assistantsInstallSkill: (): Promise<Assistants> => cmd("assistants_install_skill"),

  /** Ask the release feed whether there is a newer build. Installing is
   *  installUpdate, below. */
  checkUpdate: (): Promise<{
    current: string;
    latest: string | null;
    url: string | null;
    download: string | null;
    notes: string | null;
    status: "current" | "available" | "unpublished" | "unreachable";
    message: string | null;
  }> =>
    isDesktop
      ? cmd("check_update")
      : Promise.resolve({
          current: "dev",
          latest: null,
          url: null,
          download: null,
          notes: null,
          status: "unreachable" as const,
          message: "Update checks are desktop-only.",
        }),

  /** Move profiles into a project, or out of every project with `null`. */
  moveProfiles: (
    ids: string[],
    projectId: string | null,
    origin?: Origin,
  ): Promise<{ moved: number }> =>
    isDesktop
      ? cmd<{ moved: number }>("move_profiles", { ids, projectId, origin: origin ?? null })
      : Promise.reject(new ApiError(0, "Moving profiles is desktop-only for now.")),

  launch: (profileId: string, force = false, origin?: Origin): Promise<LaunchResult> =>
    isDesktop
      ? cmd<LaunchResult>("launch", { profileId, force, origin: origin ?? null })
      : http<LaunchResult>(`/v1/profiles/${profileId}/lock`, {
          method: "POST",
          body: JSON.stringify({
            machine_id: devMachineId(),
            machine_name: navigator.platform,
            force,
          }),
        }).then((r) => ({ ...r, launched: false })),

  stop: (profileId: string, origin?: Origin): Promise<unknown> =>
    isDesktop
      ? cmd<unknown>("stop", { profileId, origin: origin ?? null })
      : http(`/v1/profiles/${profileId}/unlock`, { method: "POST" }),

  // Local mode only: with a server, profiles and proxies are edited where the
  // permissions live, and that screen does not exist yet.
  disconnectServer: (): Promise<Shell> => cmd<Shell>("disconnect_server"),
  saveServerKit: (dir: string): Promise<{ path: string; files: number }> =>
    cmd<{ path: string; files: number }>("save_server_kit", { dir }),
  personas: (): Promise<Persona[]> => cmd<Persona[]>("personas"),
  preview: (spec: {
    persona_id: string;
    fp_seed: number;
    /** Null follows the exit; the caller passes what it knows of it so the
     *  panel shows what the launch will claim, not what the field contains. */
    timezone: string | null;
    languages: string[] | null;
    overrides?: MachineOverrides;
    /** Not saved yet: answer with what saving it will store. */
    is_new?: boolean;
  }): Promise<Preview> => cmd<Preview>("preview", { spec }),
  /** `origin` picks this machine's list or the team's; absent, the shell's mode. */
  proxies: (origin?: Origin): Promise<LocalProxy[]> =>
    cmd<LocalProxy[]>("proxies", { origin: origin ?? null }),

  /** Logins stored beside a profile. Local mode only for now — see commands.rs. */
  credentials: (profileId: string): Promise<Credential[]> =>
    cmd<Credential[]>("credentials", { profileId }),
  saveCredential: (credential: Credential): Promise<{ id: string }> =>
    cmd<{ id: string }>("save_credential", { credential }),
  deleteCredential: (id: string, profileId: string): Promise<unknown> =>
    cmd("delete_credential", { id, profileId }),
  /** Six digits and how long they last. The seed stays in the agent. */
  /** Ask the agent to fetch and install the browser. Returns once the download
   *  has started; watch shell.core_download for the rest. */
  downloadCore: (): Promise<void> => cmd<void>("download_core"),

  /** Open a link in the operator's own browser. An <a target="_blank"> inside
   *  the application window has nowhere to go — the window is not a browser —
   *  so a link that looks like one does nothing until it goes through here. */
  openUrl: (url: string): Promise<void> => cmd<void>("open_url", { url }),

  /** Download, verify against the release key, install and restart (from
   *  0.3.0; src-tauri/update.rs). Rejects with code `profiles_open`,
   *  `no_signed_update` or `update_failed`; on success the application
   *  restarts and the promise never settles. */
  installUpdate: (): Promise<void> => cmd<void>("install_update"),
  updateProgress: (): Promise<UpdateProgress> => cmd<UpdateProgress>("update_progress"),

  totpCode: (profileId: string, id: string): Promise<TotpCode> =>
    cmd<TotpCode>("totp_code", { profileId, id }),

  saveProxy: (proxy: Partial<LocalProxy>, origin?: Origin): Promise<{ id: string }> =>
    cmd<{ id: string }>("save_proxy", { proxy, origin: origin ?? null }),
  deleteProxy: (id: string, origin?: Origin): Promise<unknown> =>
    cmd("delete_proxy", { id, origin: origin ?? null }),
  checkProxy: (url: string, checkerUrl?: string | null, proxyId?: string | null, origin?: Origin): Promise<{
    ok: boolean; error?: string; ip?: string; country?: string;
    city?: string; timezone?: string; org?: string; ms?: number;
    /** ipinfo.io's country when the IP database places the exit elsewhere:
     *  where the server physically is (agent/src/geodb.rs). */
    checker_country?: string | null;
    /** Why it failed, for the interface's own sentence (ipc.rs check_failure). */
    error_code?: string | null;
    /** The checker's own words when it answered without an IP (error_code
     *  noIp, issue 39): "HTTP 429: Rate limit exceeded". */
    error_detail?: string | null;
    /** A protocol this address DOES answer on, when the one it was given got
     *  nothing. Present only on a failure, and only when the other family
     *  actually worked — see agent/src/diagnose.rs `speaks_instead`. */
    suggested_kind?: string | null;
  }> => cmd("check_proxy", { url, checkerUrl: checkerUrl || null, proxyId: proxyId || null, origin: origin ?? null }),
  /** The check step by step; the first failing step carries a `code` the
   *  interface translates. See agent/src/diagnose.rs. */
  diagnoseProxy: (url: string, checkerUrl?: string | null, proxyId?: string | null): Promise<Diagnosis> =>
    cmd<Diagnosis>("diagnose_proxy", { url, checkerUrl: checkerUrl || null, proxyId: proxyId || null }),
  rotateProxy: (id: string, origin?: Origin): Promise<{ ok: boolean; status?: number; error?: string; error_code?: string }> =>
    cmd("rotate_proxy", { id, origin: origin ?? null }),
  // ---- giving one profile to one person --------------------------------

  /** Seals the profile key to the recipient and posts it. All of that happens
   *  in Rust: the key is derived from the organisation key, which the webview
   *  never sees and must not. */
  shareProfile: (
    profileId: string,
    email: string,
    permissions: string[],
    expiresAt?: string | null,
  ): Promise<{ ok: boolean }> =>
    cmd("share_profile", { profileId, email, permissions, expiresAt: expiresAt ?? null }),

  profileShares: (
    profileId: string,
  ): Promise<{ user_id: string; email: string; permissions: number; expires_at: string | null }[]> =>
    cmd("profile_shares", { profileId }),

  revokeShare: (profileId: string, userId: string): Promise<unknown> =>
    cmd("revoke_share", { profileId, userId }),

  /** Copy a local profile onto the server, browser data and all.
   *
   *  The local original stays where it is. `proxy_moved` comes back true when an
   *  exit went with it: it is re-sealed under the organisation key, joins the
   *  team's proxy list, and becomes usable by anyone the profile is shared
   *  with. */
  uploadProfile: (
    id: string,
    projectId: string,
  ): Promise<{ id: string; bytes: number; proxy_moved: boolean }> =>
    cmd("upload_profile", { id, projectId }),

  /** What other people have given to this account. */
  sharedWithMe: (): Promise<Profile[]> => cmd<Profile[]>("shared_with_me"),

  saveProfile: (profile: unknown, origin?: Origin): Promise<{ id: string }> =>
    cmd<{ id: string }>("save_profile", { profile, origin: origin ?? null }),
  deleteProfile: (id: string, origin?: Origin): Promise<unknown> =>
    cmd("delete_profile", { id, origin: origin ?? null }),

  /** Many profiles from one template. Each gets its own seed and its own
   *  persona — see the agent for why that is the whole safety property. */
  createProfiles: (
    count: number,
    namePattern: string,
    template: unknown,
    origin?: Origin,
  ): Promise<{ created: unknown[]; failed: { n: number; error: string }[] }> =>
    cmd("create_profiles", { count, namePattern, template, origin: origin ?? null }),
  /** Saved answers to the batch dialog, by name (docs/16 5.6). */
  templates: (): Promise<ProfileTemplate[]> => cmd("templates"),
  saveTemplate: (template: ProfileTemplate): Promise<{ saved: string }> => cmd("save_template", { template }),
  deleteTemplate: (name: string): Promise<unknown> => cmd("delete_template", { name }),

  /** Copies the setup, never the identity: same persona and proxy, a fresh
   *  seed, no browser data. */
  /** The copy is made where the profile lives — the agent locally, the server
   *  in team mode — because only they hold the fields the listing omits. */
  cloneProfile: (
    id: string,
    count: number,
    name?: string,
    origin?: Origin,
  ): Promise<{ created: unknown[]; failed?: { n: number; error: string }[] }> =>
    cmd("clone_profile", { id, count, name: name || null, origin: origin ?? null }),

  /** One line as the block importer would read it, or null if it is not one. */
  parseProxyLine: (line: string): Promise<ParsedProxyLine | null> =>
    cmd("parse_proxy_line", { line }),

  /** `http` or `socks5` when exactly one answers at this address, null when
   *  neither or both do. No credentials are sent. See relay.rs `sniff_kind`. */
  sniffProxyKind: (host: string, port: number): Promise<{ kind: "http" | "socks5" | null }> =>
    cmd("sniff_proxy_kind", { host, port }),

  /** A pasted supplier block. Every line is reported back with its number. */
  importProxies: (
    text: string,
    namePrefix: string,
    origin?: Origin,
  ): Promise<{
    saved: { id: string; line: number; host: string; port: number; shape: string }[];
    rejected: { line: number; error: string; code?: string }[];
  }> => cmd("import_proxies", { text, namePrefix, origin: origin ?? null }),

  exportCookies: (id: string): Promise<{ cookies: unknown[] }> =>
    cmd("export_cookies", { id }),
  importCookies: (
    id: string,
    cookies: unknown[],
  ): Promise<{ imported: number; session_only: number; skipped: number }> =>
    cmd("import_cookies", { id, cookies }),

  /** Another anti-detect browser, through its API. The token is passed per
   *  call and kept nowhere; `base` overrides where a local API answers. */
  vendorList: (vendor: Vendor, token: string, base: string | null): Promise<VendorProfile[]> =>
    cmd<VendorProfile[]>("vendor_list", { vendor, token, base }),
  vendorProfile: (vendor: Vendor, token: string, base: string | null, profile: VendorProfile): Promise<VendorDetail> =>
    cmd<VendorDetail>("vendor_profile", { vendor, token, base, profile }),
  // ---- synchronised windows ---------------------------------------------

  /** Start mirroring between these profiles. Ones not open are launched with
   *  the debugging port; ones open without it are refused by id. */
  mirrorStart: (profileIds: string[], typing: boolean): Promise<{
    joined: string[]; refused: Refusal[]; status: MirrorStatus;
  }> => cmd("mirror_start", { profileIds, typing }),
  mirrorStop: (): Promise<unknown> => cmd("mirror_stop"),
  mirrorStatus: (): Promise<MirrorStatus> => cmd<MirrorStatus>("mirror_status"),
  mirrorTyping: (on: boolean): Promise<unknown> => cmd("mirror_typing", { on }),

  /** Saved local proxies whose password the keychain will not open now
   *  (they read back blank); `retry` asks the keychain again. */
  vaultStatus: (retry = false): Promise<{ available: boolean; unreadable: string[] }> =>
    cmd("vault_status", { retry }),

  // ---- warming ------------------------------------------------------------

  /** A team profile is opened by the shell first, lock and all, with the
   *  debugging port; a local one by the agent. */
  warmStart: (profiles: { id: string; origin: Origin }[], plan: WarmPlan): Promise<{ started: string[]; refused: Refusal[] }> =>
    cmd("warm_start", { profiles, plan }),
  warmStatus: (): Promise<WarmProgress[]> => cmd<WarmProgress[]>("warm_status"),
  warmStop: (id: string): Promise<unknown> => cmd("warm_stop", { id }),
  warmClear: (): Promise<unknown> => cmd("warm_clear"),
  warmDefaults: (): Promise<{ urls: string[] }> => cmd("warm_defaults"),

  // ---- bookmark sets ---------------------------------------------------------
  bookmarkSets: (): Promise<BookmarkSet[]> =>
    cmd<{ sets: BookmarkSet[] }>("bookmarks_list").then((r) => r.sets),
  saveBookmarkSet: (set: BookmarkSet): Promise<{ id: string }> => cmd("bookmarks_save", { set }),
  deleteBookmarkSet: (id: string): Promise<unknown> => cmd("bookmarks_delete", { id }),

  // ---- farming: warm-ups on a schedule -----------------------------------

  farmList: (): Promise<{ now_ms: number; farms: Farm[] }> => cmd("farm_list"),
  farmCreate: (spec: FarmSpec, targets: FarmTarget[]): Promise<{ id: string }> => cmd("farm_create", { spec, targets }),
  farmDelete: (id: string): Promise<unknown> => cmd("farm_delete", { id }),
  farmPause: (id: string, paused: boolean): Promise<unknown> => cmd("farm_pause", { id, paused }),
  farmDue: (): Promise<FarmDue[]> => cmd<FarmDue[]>("farm_due"),
  /** Marks the session started and returns the warm-up plan to run it with. */
  farmClaim: (farmId: string, profileId: string): Promise<WarmPlan> => cmd<WarmPlan>("farm_claim", { farmId, profileId }),
  farmFail: (farmId: string, profileId: string, error: string): Promise<unknown> => cmd("farm_fail", { farmId, profileId, error }),
  farmStageApplied: (farmId: string, profileId: string): Promise<unknown> => cmd("farm_stage_applied", { farmId, profileId }),

  // ---- this machine as a persona ----------------------------------------

  /** Runs the installed Chrome at the probe and converts the dump. ~10 s;
   *  a Chrome window opens and closes. Nothing is sent anywhere. */
  capturePersona: (): Promise<{ persona: Record<string, unknown> & { id: string }; problems: string[]; browser: string }> =>
    cmd("capture_persona"),
  /** Writes it to ~/Downloads/fury-persona-<id>.json; returns the path. */
  savePersonaFile: (persona: unknown): Promise<string> => cmd<string>("save_persona_file", { persona }),
  /** Keep a capture on this machine as a persona; returns its id. */
  usePersonaHere: (persona: unknown): Promise<string> => cmd<string>("use_persona_here", { persona }),
  /** Kept here and added to the organisation's machines on the server. */
  sharePersonaWithTeam: (persona: unknown): Promise<string> => cmd<string>("share_persona_with_team", { persona }),
  /** Machines kept on this computer; `in_team` null outside team mode or when
   *  the server cannot say. */
  keptPersonas: (): Promise<KeptPersona[]> => cmd<KeptPersona[]>("kept_personas"),

  // ---- domain lists ------------------------------------------------------

  blocklists: (): Promise<DomainList[]> => cmd<DomainList[]>("blocklists"),
  readBlocklist: (name: string): Promise<{ name: string; text: string }> =>
    cmd("read_blocklist", { name }),
  saveBlocklist: (name: string, text: string): Promise<DomainList> =>
    cmd<DomainList>("save_blocklist", { name, text }),
  deleteBlocklist: (name: string): Promise<unknown> => cmd("delete_blocklist", { name }),

  // ---- extensions and disk usage ----------------------------------------

  /** Installed into one profile. Identity survives cloning — see ext.rs. */
  extensions: (profileId: string): Promise<Extension[]> =>
    cmd<Extension[]>("extensions", { profileId }),
  /** A .crx, .zip or folder, as bytes: it was chosen in the webview.
   *  Installing the same extension twice replaces it. */
  installExtension: (profileId: string, pkg: ExtensionPackage): Promise<Extension & { key_source: KeySource }> =>
    cmd("install_extension", { profileId, ...pkg }),
  /** Every extension on this machine, grouped by id, with the profiles it is in. */
  allExtensions: (): Promise<ExtensionEverywhere[]> => cmd<ExtensionEverywhere[]>("all_extensions"),
  /** The same, counting the team profiles named here as well. */
  allExtensionsWith: (team: { id: string; name: string }[]): Promise<ExtensionEverywhere[]> =>
    cmd<ExtensionEverywhere[]>("all_extensions_with", { team }),
  /** By Web Store id into team profiles: each one's lock is taken for the
   *  download, so the package comes through that profile's proxy. */
  installExtensionFromStoreTeam: (profileIds: string[], extId: string): Promise<{
    extension: Extension | null; installed: string[]; skipped: { id: string; reason: string }[];
  }> => cmd("install_extension_from_store_team", { profileIds, extId }),
  /** One .crx into many profiles. Open profiles are skipped and named. */
  installExtensionMany: (profileIds: string[], pkg: ExtensionPackage): Promise<{
    extension: Extension | null; installed: string[]; skipped: { id: string; reason: string }[]; key_source: KeySource;
  }> => cmd("install_extension_many", { profileIds, ...pkg }),
  /** One profile's extension with its storage -- so signed in -- into others.
   *  Every browser involved must be closed; see ext::copy_with_state. */
  copyExtensionWithState: (fromProfileId: string, extId: string, profileIds: string[], withState = true): Promise<{
    extension: Extension | null; installed: string[]; skipped: { id: string; reason: string }[];
  }> => cmd("copy_extension_with_state", { fromProfileId, extId, profileIds, withState }),
  removeExtension: (profileId: string, id: string): Promise<unknown> =>
    cmd("remove_extension", { profileId, id }),
  extensionCatalogue: (): Promise<CatalogueEntry[]> => cmd("extension_catalogue"),
  /** By Web Store id, fetched through each profile's own proxy (docs/12, B). */
  installExtensionFromStore: (profileIds: string[], extId: string): Promise<StoreInstallResult> =>
    cmd("install_extension_from_store", { profileIds, extId }),

  /** A fresh fingerprint seed. Refused while the profile is open. Everything a
   *  site tied to the old fingerprint stops matching — which is the point, and
   *  the reason the interface confirms first. */
  reseedProfile: (id: string, origin?: Origin): Promise<{ id: string; fp_seed: number }> =>
    cmd("reseed_profile", { id, origin: origin ?? null }),

  /** How big a profile is on disk and how much of it is cache. */
  profileUsage: (id: string): Promise<Usage> => cmd<Usage>("profile_usage", { id }),
  /** Removes caches only. The agent refuses while the profile is open. */
  trimProfile: (id: string): Promise<{ bytes: number; removed: string[] }> =>
    cmd("trim_profile", { id }),

  exportProject: (id: string, path: string, passphrase: string, withData = true):
    Promise<{ path: string; bytes: number }> =>
    cmd("export_project", { id, path, passphrase, withData }),
  importProject: (path: string, passphrase: string):
    Promise<{ project_id: string; profiles: number }> =>
    cmd("import_project", { path, passphrase }),
  trash: (): Promise<Profile[]> => cmd<Profile[]>("trash"),
  /** Both take the row's origin: the trash holds this machine's deletions and
   *  the server's side by side, and restoring is a different call in each. */
  restoreProfile: (id: string, origin?: Origin): Promise<unknown> =>
    cmd("restore_profile", { id, origin: origin ?? null }),
  purgeProfile: (id: string, origin?: Origin): Promise<unknown> =>
    cmd("purge_profile", { id, origin: origin ?? null }),
  renameProject: (id: string, name: string, origin?: Origin): Promise<unknown> =>
    cmd("rename_project", { id, name, origin: origin ?? null }),
  deleteProject: (id: string, origin?: Origin): Promise<unknown> =>
    cmd("delete_project", { id, origin: origin ?? null }),
  createProject: (name: string): Promise<{ id: string }> =>
    cmd<{ id: string }>("create_project", { name }),

  // ---- Camoufox Suite Lab (Donut-inspired diagnostics & traffic) --------
  suiteOverview: (): Promise<SuiteOverview> => cmd<SuiteOverview>("suite_overview"),
  suiteEnsureBaseline: (): Promise<{ ok: boolean; status: string; browser: { kind: string; label: string; version?: string | null } | null }> =>
    cmd("suite_ensure_baseline"),
  suitePresets: (): Promise<SuitePreset[]> => cmd<SuitePreset[]>("suite_presets"),
  suiteRunCoherence: (dryRun = false): Promise<SuiteCoherenceRun> =>
    cmd<SuiteCoherenceRun>("suite_run_coherence", { dryRun }),
  suiteAuditProfile: (profileId: string, targetUrl?: string): Promise<SuiteSingleProfileAudit> =>
    cmd<SuiteSingleProfileAudit>("suite_audit_profile", { profileId, targetUrl: targetUrl || null }),
  suiteTrafficSummary: (): Promise<SuiteTrafficSummary> => cmd<SuiteTrafficSummary>("suite_traffic_summary"),
  suiteTrafficProfiles: (): Promise<SuiteTrafficProfileItem[]> => cmd<SuiteTrafficProfileItem[]>("suite_traffic_profiles"),
  suiteTrafficQuery: (params: {
    profileId: string;
    step?: string;
    trigger?: string;
    domain?: string;
    status?: string;
    platform?: string;
  }): Promise<SuiteTrafficQueryResult> => cmd<SuiteTrafficQueryResult>("suite_traffic_query", params),
  suiteTrafficWireDump: (profileId: string, correlationId: string): Promise<SuiteTrafficWireDumpResult> =>
    cmd<SuiteTrafficWireDumpResult>("suite_traffic_wire_dump", { profileId, correlationId }),
  suiteTrafficExportHar: (profileId: string, domain?: string, status?: string): Promise<{ harPath?: string; entryCount?: number; bytes?: number }> =>
    cmd("suite_traffic_export_har", { profileId, domain: domain || undefined, status: status || undefined }),
  suiteAuditAdspower: (cacheDir: string): Promise<SuiteAdsPowerAudit> =>
    cmd<SuiteAdsPowerAudit>("suite_audit_adspower", { cacheDir }),
  suiteHealAdspower: (cacheDir: string, fbccIds?: string[]): Promise<{ imported: { id: string; source: string; presetId: string }[] }> =>
    cmd("suite_heal_adspower", { cacheDir, fbccIds: fbccIds ?? null }),
  suiteResultsHistory: (): Promise<SuiteResultsHistory> => cmd<SuiteResultsHistory>("suite_results_history"),
  suiteGetEnv: (): Promise<SuiteEnvConfig> => cmd<SuiteEnvConfig>("suite_get_env"),
  suiteSaveEnv: (values: Record<string, string>): Promise<SuiteEnvConfig> =>
    cmd<SuiteEnvConfig>("suite_save_env", { values }),
  suiteCliInfo: (): Promise<SuiteCliInfo> => cmd<SuiteCliInfo>("suite_cli_info"),
  suiteRotateApiKey: (): Promise<{ apiKey: string; apiKeyCreatedAt: string }> =>
    cmd("suite_rotate_api_key"),
  suiteGetKeys: (): Promise<SuiteSecretKeys> => cmd<SuiteSecretKeys>("suite_get_keys"),
  suiteSaveKeys: (values: Record<string, string>): Promise<SuiteSecretKeys> =>
    cmd<SuiteSecretKeys>("suite_save_keys", { values }),
  suiteRunCli: (commandId: string): Promise<SuiteCliRunResult> =>
    cmd<SuiteCliRunResult>("suite_run_cli", { commandId }),
  suiteNetworkStatus: (): Promise<SuiteNetworkStatus> =>
    cmd<SuiteNetworkStatus>("suite_network_status"),
  suiteSaveNetworkDefaults: (config: Partial<SuiteNetworkConfig>): Promise<{ ok: boolean; defaults: SuiteNetworkConfig }> =>
    cmd("suite_save_network_defaults", { config }),
  launchMany: (ids: string[]): Promise<{ launched: string[]; failed: { id: string; error: string }[] }> =>
    cmd("launch_many", { ids }),
  stopMany: (ids: string[]): Promise<{ ok: boolean; stopped: number; total: number }> =>
    cmd("stop_many", { ids }),
  autofillProfile: (profileId: string, field: "email" | "password" | "totp"): Promise<{ ok: boolean; field: string }> =>
    cmd("autofill_profile", { profileId, field }),
  importAccountsBatch: (payload: {
    items: { email: string; password: string; totp: string; proxyLine?: string; name?: string }[];
    projectId?: string | null;
    projectNameNew?: string;
    defaultProxyId?: string | null;
    startUrls?: string[];
    autoGeo?: boolean;
  }): Promise<{
    created: { id: string; email: string; country: string | null; timezone: string | null; hasTotp: boolean }[];
    failed: { index: number; email: string; error: string }[];
  }> => cmd("import_accounts_batch", payload),
};

export interface SuiteTrafficBucket {
  time: number;
  bandwidth: number;
  requests: number;
}

export interface SuiteTrafficEvent {
  profileId: string;
  timestamp: string;
  type: string;
  method: string;
  status: number | null;
  host: string;
  step: string;
  bytes: number;
}

export interface SuiteTrafficSummary {
  profilesDir: string;
  profileCaptures: number;
  totalEvents: number;
  totalBytes: number;
  buckets: SuiteTrafficBucket[];
  recentEvents: SuiteTrafficEvent[];
}

export interface SuiteMeasuredTelemetry {
  userAgent: string | null;
  platform: string | null;
  oscpu: string | null;
  hardwareConcurrency: number | null;
  language: string | null;
  languages: string[];
  webdriver: boolean | null;
  webglVendor: string | null;
  webglRenderer: string | null;
  webglVersion: string | null;
  webglExtensionsCount: number | null;
  webgpuAvailable: boolean | null;
  canvasHash: string | null;
  audioSampleRate: number | null;
  audioChannels: number | null;
  mathSinHex: string | null;
  mathCosHex: string | null;
  screen: string | null;
  timeZone: string | null;
  intlLocale: string | null;
  voicesCount: number;
  sampleVoices: string[];
  detectedFonts: string[];
  workerParityOk: boolean;
  iframeParityOk: boolean;
  toStringIntact: boolean;
  ownNavigatorOverrides: string[];
  automationGlobals: string[];
  storageQuotaBytes: number | null;
}

export interface SuiteCoherenceCheckItem {
  id?: string;
  name: string;
  category?: "runtime-dom" | "pre-tls-wire" | string;
  passed: boolean;
  status?: string;
  details?: string;
  detail?: string;
}

export interface SuiteCoherenceResultItem {
  targetOs?: string;
  presetId?: string;
  deviceModel?: string;
  mode?: string;
  status?: string;
  passed?: boolean;
  score?: number;
  totalChecks?: number;
  wireInspectedRequests?: number;
  integrityValid?: boolean;
  measured?: SuiteMeasuredTelemetry | null;
  auditReport?: {
    score?: number;
    status?: string;
    passed?: boolean;
    checks?: SuiteCoherenceCheckItem[];
  } | null;
  checks?: SuiteCoherenceCheckItem[];
}

export interface SuiteCoherenceRun {
  timestamp: string;
  mode?: string;
  report: {
    mode?: string;
    engine?: string;
    engineVersion?: string | null;
    overallPassed?: boolean;
    overallStatus?: string;
    generatedAt?: string;
    results?: SuiteCoherenceResultItem[] | Record<string, SuiteCoherenceResultItem>;
    crossProfileIsolation?: {
      passed: boolean;
      profileA: { presetId: string; gpu?: string | null; cores?: number | null; canvasHash?: string | null; timeZone?: string | null; language?: string | null };
      profileB: { presetId: string; gpu?: string | null; cores?: number | null; canvasHash?: string | null; timeZone?: string | null; language?: string | null };
    } | null;
    negativeControl?: {
      passed?: boolean;
      caughtAll?: boolean;
      flaggedChecks?: string[];
      failedChecks?: string[];
    };
  } | null;
  stdout: string;
  stderr: string;
}

export interface SuiteSingleProfileAudit {
  profileId: string;
  serialNumber: number | null;
  profileName: string;
  accountEmail: string;
  presetId: string;
  deviceModel: string;
  targetOs: string;
  targetUrl: string;
  engine: string;
  passed: boolean;
  score: number;
  domScore: number | null;
  wireScore: number | null;
  wireInspectedRequests: number;
  checks: SuiteCoherenceCheckItem[];
  comparisons: { field: string; expected: string; observed: string; matched: boolean }[];
  measured: SuiteMeasuredTelemetry | null;
  integrity: {
    valid: boolean;
    eventCount?: number;
    verifiedPayloads?: number;
    chainHeadHash?: string;
    errors?: string[];
  } | null;
  ledgerResult: {
    passed?: boolean;
    firstSeen?: boolean;
    hammingDistance?: number;
    similarity?: number;
    reason?: string;
  } | null;
  auditedAt: string;
}

export interface SuiteTrafficProfileItem {
  profileId: string;
  serialNumber: number | null;
  profileName: string;
  accountEmail: string;
  os?: string | null;
  running: boolean;
  recordingActive: boolean;
  anomalyCount?: number;
  totals?: {
    totalRequests?: number;
    totalResponses?: number;
    failedRequests?: number;
    wsFramesSent?: number;
    wsFramesReceived?: number;
  };
}

export interface SuiteTrafficTransactionItem {
  correlationId: string;
  method?: string;
  url?: string;
  status?: number | null;
  failureText?: string | null;
  actionStep?: string | null;
  timestamp?: string;
  durationMs?: number | null;
  requestBytes?: number | null;
  responseBytes?: number | null;
  triggerAction?: {
    actionId?: string;
    actionType?: string;
    target?: string;
    association?: string;
  } | null;
}

export interface SuiteTrafficSignatureItem {
  platform: string;
  signatureName: string;
  location: string;
  correlationId?: string | null;
  actionStep?: string | null;
  triggerActionId?: string | null;
  triggerTarget?: string | null;
  valueLength?: number;
  maskedPreview?: string;
  valueSha256?: string;
  url?: string;
}

export interface SuiteTrafficCookieItem {
  name: string;
  isAntiBotToken?: boolean;
  scopeStatus?: string;
  domain?: string | null;
  path?: string | null;
  secure?: boolean | null;
  httpOnly?: boolean | null;
  sameSite?: string | null;
  firstSetByCorrelationId?: string | null;
  firstSetAtStep?: string | null;
  firstSetByTrigger?: string | null;
  firstSetUrl?: string | null;
  lastMaskedValue?: string;
  lastValueSha256?: string | null;
  mutationsCount?: number;
  sentCount?: number;
}

export interface SuiteTrafficAnomalyItem {
  severity?: string;
  type: string;
  correlationId?: string | null;
  actionStep?: string | null;
  status?: number | null;
  failureText?: string | null;
  url?: string | null;
  reason?: string | null;
  triggerAction?: { actionType?: string; target?: string } | null;
}

export interface SuiteTrafficQueryResult {
  profileId: string;
  serialNumber: number | null;
  profileName: string;
  accountEmail: string;
  recordingActive: boolean;
  integrity: {
    valid: boolean;
    scope?: string;
    eventCount?: number;
    verifiedPayloads?: number;
    payloadManifestVerified?: boolean;
    chainHeadHash?: string;
    errors?: string[];
  } | null;
  cookies: SuiteTrafficCookieItem[];
  antiBotTokenCount: number;
  totals: {
    totalRequests?: number;
    totalResponses?: number;
    failedRequests?: number;
    wsFramesSent?: number;
    wsFramesReceived?: number;
  };
  artifacts?: {
    trafficNdjsonPath?: string | null;
    attributionIndexPath?: string | null;
    sslKeyLogPath?: string | null;
    preTlsWireLogPath?: string | null;
    neckoMozLogPath?: string | null;
  };
  byActionStep: Record<string, { requests?: number; responses?: number; failed?: number }>;
  byDomain: Record<string, { requests?: number; responses?: number; failed?: number }>;
  platformSignatures: {
    totalDetected: number;
    byPlatform: Record<string, number>;
    signatures: SuiteTrafficSignatureItem[];
  };
  neckoMozLog: Record<string, unknown> | null;
  anomalies: SuiteTrafficAnomalyItem[];
  transactions: SuiteTrafficTransactionItem[];
  eventsCount: number;
}

export interface SuiteTrafficWireDumpResult {
  mode: string;
  found: boolean;
  profileId: string;
  correlationId: string;
  wireDump: string;
  bodyPolicyReason?: string | null;
  transaction?: Record<string, unknown> | null;
  anomalies?: SuiteTrafficAnomalyItem[];
}

export interface SuiteOverview {
  profileCount: number;
  runningCount: number;
  recordingCount?: number;
  projectCount: number;
  proxyCount: number;
  presetCount: number;
  camoufoxSdkReady: boolean;
  isAntidetectEngine?: boolean;
  baselineStatus?: "idle" | "installing" | "ready" | "failed";
  baselineError?: string | null;
  browserLauncher?: { kind: string; label: string; version?: string | null } | null;
  stateDir: string;
  profilesDir: string;
  profileService: string;
  lastCoherence: SuiteCoherenceRun | null;
  traffic: SuiteTrafficSummary;
  recentResultsCount: number;
  summaryStats: Record<string, unknown> | null;
}

export interface SuitePreset {
  presetId: string;
  os: "macos" | "windows" | "linux";
  category: string;
  deviceModel: string;
  cpuModel: string;
  gpuModel: string;
  hardwareConcurrency: number;
  ramGb: number;
  storageGb: number;
  architecture: string;
  osVersion: string;
  screen: { width: number; height: number; devicePixelRatio: number };
  webgl: { unmaskedVendor: string; unmaskedRenderer: string; GPUAdapterInfo?: { vendor?: string; architecture?: string } };
}

export interface SuiteAdsPowerAuditItem {
  profileDirName: string;
  fbccId: string;
  platform: string | null;
  deviceName: string | null;
  cores: number | null;
  deviceMemoryGb: number | null;
  renderer: string | null;
  status: string;
  passed: boolean;
  matchedSku: string | null;
  issues: unknown[];
  healed?: {
    healedPresetId?: string;
    healedProfile?: { presetId?: string; os?: string; deviceModel?: string };
    repairsApplied?: string[];
    preset?: { presetId?: string; deviceModel?: string };
    os?: string;
  } | null;
}

export interface SuiteAdsPowerAudit {
  cacheDir: string;
  totalScanned: number;
  totalDecoded: number;
  passedCount: number;
  failedCount: number;
  profiles: SuiteAdsPowerAuditItem[];
}

export interface SuiteResultsHistory {
  stateDir: string;
  results: {
    resultId?: string;
    success?: boolean;
    email?: string;
    errorCode?: string;
    errorStage?: string;
    profileId?: string;
    profileType?: string;
    profileCleanup?: string;
    proxyIP?: string | null;
    timestamp?: string;
  }[];
  summary: {
    timestamp?: string;
    duration?: string;
    configuration?: Record<string, unknown>;
    stats?: { total?: number; completed?: number; failed?: number; manual?: number; successRate?: string };
  } | null;
}

export interface SuiteEnvConfig {
  path: string;
  exists: boolean;
  keys: string[];
  values: Record<string, string>;
}


export interface SuiteCliInfo {
  endpoint: string;
  apiBase: string;
  apiKey: string;
  apiKeyCreatedAt: string | null;
  desktopMode: boolean;
  repoRoot: string;
  stateDir: string;
  endpoints: { method: string; path: string; desc: string }[];
  cliCommands: { id: string; label: string; cmd: string }[];
}

export interface SuiteSecretKeyItem {
  key: string;
  label: string;
  group: string;
  secret: boolean;
  placeholder: string;
  configured: boolean;
  value: string;
}

export interface SuiteSecretKeys {
  path: string;
  exists: boolean;
  items: SuiteSecretKeyItem[];
}

export interface SuiteCliRunResult {
  commandId: string;
  cmd: string;
  exitCode: number;
  durationMs: number;
  stdout: string;
  stderr: string;
}

export interface SuiteNetworkConfig {
  engine: "xfrpc-netd" | "node-relay";
  udp_mode: "socks5-udp" | "udp-over-tcp" | "block-udp";
  dns_disguise: string;
  dns_custom_servers: string;
  dns_split_rules: string;
  egress: "v4" | "v6" | "prefer_v4" | "prefer_v6";
  tcp2udp_enable: boolean;
}

export interface SuiteDnsPreset {
  id: string;
  label: string;
  sni: string;
  servers: string;
}

export interface SuiteActiveRelay {
  profile_id: string;
  profile_name: string;
  engine: string;
  proxy_port: number;
  dns_stub_port: number | null;
  dns_disguise: string;
  tcp2udp_port: number | null;
  udp_mode: string;
  udp_supported: boolean;
  upstream_mode: string;
}

export interface SuiteNetworkStatus {
  netd: {
    available: boolean;
    binPath: string;
    pluginsDir: string;
    plugins: { name: string; present: boolean }[];
  };
  defaults: SuiteNetworkConfig;
  dns_presets: SuiteDnsPreset[];
  active_relays: SuiteActiveRelay[];
}
