// SPDX-License-Identifier: AGPL-3.0-or-later
// Client-side RFC 6238 SHA-1 TOTP generator (WebCrypto, zero dependencies)
// + smart `Account + Password + 2FA (+ optional Proxy)` line parser.

export interface LiveTotp {
  code: string;
  remaining: number;
}

export function extractBase32Secret(input: string): string {
  let raw = String(input || "").trim();
  if (!raw) return "";
  if (raw.toLowerCase().startsWith("otpauth://")) {
    try {
      raw = new URL(raw).searchParams.get("secret") || "";
    } catch {
      return "";
    }
  }
  return raw.toUpperCase().replace(/[^A-Z2-7]/g, "");
}

export function isLikelyTotpSecret(token: string): boolean {
  const raw = String(token || "").trim();
  if (!raw) return false;
  if (raw.toLowerCase().startsWith("otpauth://")) return true;
  const cleaned = raw.toUpperCase().replace(/[\s-]+/g, "");
  // Typical Google/standard Base32 2FA secret: 16..64 chars of A-Z2-7, contains letters (not pure digits)
  return /^[A-Z2-7]{16,64}=*$/.test(cleaned) && /[A-Z]/.test(cleaned) && !raw.includes("@") && !raw.includes(":");
}

export function isLikelyProxyToken(token: string): boolean {
  const s = String(token || "").trim();
  if (!s) return false;
  if (/^(socks5h?|socks4|https?):\/\//i.test(s)) return true;
  // host:port or host:port:user:pass
  if (/^(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}(?::[^:\s]+:[^:\s]+)?$/.test(s)) return true;
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:\d{2,5}(?::[^:\s]+:[^:\s]+)?$/.test(s)) return true;
  return false;
}

function base32ToBytes(secret: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = extractBase32Secret(secret);
  let bits = "";
  for (const ch of cleaned) {
    const idx = alphabet.indexOf(ch);
    if (idx >= 0) bits += idx.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

export async function computeLiveTotp(secretOrUri: string): Promise<LiveTotp | null> {
  const keyBytes = base32ToBytes(secretOrUri);
  if (keyBytes.length === 0) return null;
  const now = Math.floor(Date.now() / 1000);
  const step = Math.floor(now / 30);
  const remaining = 30 - (now % 30);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(step / 0x100000000));
  view.setUint32(4, step >>> 0);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes.buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, buf));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return {
    code: String(binary % 1_000_000).padStart(6, "0"),
    remaining,
  };
}

export interface ParsedAccountLine {
  raw: string;
  email: string;
  password: string;
  totp: string;
  proxyLine: string;
}

/**
 * Parses a single pasted line containing Account/Email + Password + 2FA (+ optional Proxy).
 * Supports delimiters: `----`, `\t`, `|`, `,`, `;`, whitespace, or `email:pass:2fa`.
 */
export function parseAccountLine(rawLine: string): ParsedAccountLine | null {
  const line = String(rawLine || "").trim();
  if (!line || line.startsWith("#")) return null;

  let tokens: string[];
  if (line.includes("----")) {
    tokens = line.split(/\s*----\s*/).filter(Boolean);
  } else if (line.includes("\t")) {
    tokens = line.split(/\t+/).map((x) => x.trim()).filter(Boolean);
  } else if (line.includes("|")) {
    tokens = line.split(/\s*\|\s*/).filter(Boolean);
  } else if (line.includes(",") && !line.includes(" ")) {
    tokens = line.split(",").map((x) => x.trim()).filter(Boolean);
  } else if (line.includes(";") && !line.includes(" ")) {
    tokens = line.split(";").map((x) => x.trim()).filter(Boolean);
  } else if (/\s+/.test(line)) {
    tokens = line.split(/\s+/).filter(Boolean);
  } else if (line.includes(":")) {
    // Only split by `:` when the whole line is NOT a single proxy string
    if (isLikelyProxyToken(line)) {
      return { raw: line, email: "", password: "", totp: "", proxyLine: line };
    }
    tokens = line.split(":").map((x) => x.trim()).filter(Boolean);
  } else {
    tokens = [line];
  }

  let proxyLine = "";
  let email = "";
  let totp = "";
  const rest: string[] = [];

  for (const tok of tokens) {
    if (!proxyLine && isLikelyProxyToken(tok)) {
      proxyLine = tok;
    } else if (!email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(tok)) {
      email = tok;
    } else if (!totp && isLikelyTotpSecret(tok)) {
      totp = tok;
    } else {
      rest.push(tok);
    }
  }

  if (!email && rest.length > 0) {
    email = rest.shift() || "";
  }
  const password = rest.shift() || "";
  if (!totp && rest.length > 0) {
    // In case user pasted a shorter/unusual 2FA token as the 3rd field
    const maybe = rest.shift() || "";
    if (isLikelyProxyToken(maybe) && !proxyLine) proxyLine = maybe;
    else totp = maybe;
  }

  if (!email && !password && !totp) return null;
  return { raw: line, email, password, totp, proxyLine };
}

export function parseAccountBatch(text: string): ParsedAccountLine[] {
  const out: ParsedAccountLine[] = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const parsed = parseAccountLine(line);
    if (parsed) out.push(parsed);
  }
  return out;
}
