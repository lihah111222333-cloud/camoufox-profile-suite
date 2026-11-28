// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

import type { LocalProxy, Profile } from "./api";

/** What a row says about itself before it is opened (docs/12 B, docs/16 5.9).
 *
 *  The persona validator runs in the editor, where a person is already busy
 *  with one profile. The list is where the hundred-profile operator lives, and
 *  a contradiction that is only visible one editor at a time is invisible.
 *  These are the contradictions that can be read off the row itself, without
 *  a network call: the ones between what the profile claims and where its
 *  traffic comes out.
 *
 *  Two levels. `block` is the rule from docs/01 — a red badge disables Open
 *  with the reason, rather than warning and letting it happen. `warn` is a
 *  heuristic that is right more often than not and is never allowed to stop
 *  anybody. */
export type Level = "ok" | "warn" | "block";

export interface Verdict {
  level: Level;
  /** i18n keys with their variables, for the row's hover and the disabled Open. */
  notes: { key: "cons.personaUnknown" | "cons.tzMismatch" | "cons.langCountry"; vars?: Record<string, string | number> }[];
  /** Bilingual anti-fraud consistency diagnostics (cross-region duplicate accounts, engine fallback). */
  customNotes?: { zh: string; en: string }[];
}

/** Languages a person in this country plausibly has FIRST in their list.
 *  English is not here: an English-first browser exists everywhere, so it is
 *  never flagged. What is flagged is Russian-first on a US exit, or German-first
 *  on a Brazilian one — the mismatch anti-fraud sees at a glance. Conservative
 *  on purpose: a country not in this table is never flagged. */
const FIRST_LANGUAGES: Record<string, string[]> = {
  US: [], GB: [], CA: ["fr"], AU: [], NZ: [], IE: [],
  DE: ["de"], AT: ["de"], CH: ["de", "fr", "it"],
  FR: ["fr"], BE: ["fr", "nl"], NL: ["nl"], LU: ["fr", "de"],
  ES: ["es", "ca"], MX: ["es"], AR: ["es"], CO: ["es"], CL: ["es"], PE: ["es"],
  IT: ["it"], PT: ["pt"], BR: ["pt"],
  PL: ["pl"], CZ: ["cs"], SK: ["sk"], HU: ["hu"], RO: ["ro"], BG: ["bg"], GR: ["el"],
  RU: ["ru"], BY: ["ru", "be"], KZ: ["ru", "kk"], UA: ["uk", "ru"], MD: ["ro", "ru"], GE: ["ka", "ru"], AM: ["hy", "ru"], UZ: ["uz", "ru"],
  TR: ["tr"], IL: ["he", "ru"], AE: ["ar"], SA: ["ar"], EG: ["ar"],
  SE: ["sv"], NO: ["nb", "no"], DK: ["da"], FI: ["fi", "sv"],
  JP: ["ja"], KR: ["ko"], CN: ["zh"], TW: ["zh"], HK: ["zh"],
  ID: ["id"], VN: ["vi"], TH: ["th"], IN: ["hi"], PH: ["fil", "tl"],
};

/** Judge one row. `personas` is the catalogue's ids, or null while unknown.
 *
 *  How many profiles share an exit is not judged here any more. It was a
 *  warning from three on, and on a mobile proxy it was wrong: a carrier hands
 *  one address to thousands of real subscribers, sites expect many accounts
 *  behind it, and affiliates run 50 profiles on one US mobile exit (tester,
 *  18.11.2026). The triangle then lit every row and hid the warnings that are
 *  real. The count stays in the proxy cell as a plain fact (`exitSharing`). */
export function assess(
  p: Profile,
  personas: Set<string> | null,
  allProfiles?: Profile[] | null,
): Verdict {
  const notes: Verdict["notes"] = [];
  const customNotes: NonNullable<Verdict["customNotes"]> = [];
  let level: Level = "ok";
  const raise = (to: Level) => {
    if (to === "block" || (to === "warn" && level === "ok")) level = to;
  };

  // A persona that left the catalogue — a contributed file withdrawn, a
  // rename — cannot be launched; the agent would refuse. Say so here.
  if (personas && !personas.has(p.persona_id)) {
    notes.push({ key: "cons.personaUnknown", vars: { id: p.persona_id } });
    raise("block");
  }

  // The cheapest check in the industry: a clock that does not match the exit.
  // Only when the profile pins a zone AND the proxy has been checked; a
  // profile that follows the exit cannot disagree with it.
  const exitTz = p.proxy?.last_timezone ?? null;
  if (p.timezone && exitTz && p.timezone !== exitTz) {
    notes.push({ key: "cons.tzMismatch", vars: { profile: p.timezone, exit: exitTz } });
    raise("block");
  }

  // First language against the exit country. Heuristic, so a warning.
  const country = p.proxy?.country?.toUpperCase() ?? null;
  const first = p.languages?.[0]?.split("-")[0]?.toLowerCase() ?? null;
  if (country && first && first !== "en" && country in FIRST_LANGUAGES && !FIRST_LANGUAGES[country].includes(first)) {
    notes.push({ key: "cons.langCountry", vars: { lang: p.languages![0], country } });
    raise("warn");
  }

  // Cross-profile same-account multi-country / multi-timezone collision check:
  // Logging the exact same Google account simultaneously across JP and US exits
  // triggers Google Family Group country mismatch & BotGuard session challenges.
  const acct = (p.account_email ?? "").trim().toLowerCase();
  if (acct && Array.isArray(allProfiles) && allProfiles.length > 1) {
    const myRegion = country || (p.timezone ?? exitTz ?? "");
    const conflicts = allProfiles.filter((other) => {
      if (other.id === p.id) return false;
      const otherAcct = (other.account_email ?? "").trim().toLowerCase();
      if (otherAcct !== acct) return false;
      const otherCountry = other.proxy?.country?.toUpperCase() ?? null;
      const otherRegion = otherCountry || (other.timezone ?? other.proxy?.last_timezone ?? "");
      return Boolean(myRegion && otherRegion && myRegion !== otherRegion);
    });
    if (conflicts.length > 0) {
      const labels = conflicts
        .map((c) => `${c.serial_number != null ? `#${c.serial_number}` : c.name} (${c.proxy?.country || c.timezone || "?"})`)
        .join(", ");
      const anyConcurrentOpen = p.running && conflicts.some((c) => c.running);
      customNotes.push({
        zh: `同一账号 ${p.account_email} 同时存在于不同国家/时区环境 [${labels}]${anyConcurrentOpen ? " 且正并发打开" : ""}，极易触发 Google 跨国风控与家庭组国家不匹配`,
        en: `Account ${p.account_email} is bound to conflicting country/timezone profile(s) [${labels}]${anyConcurrentOpen ? " and open concurrently" : ""} — triggers Google region mismatch`,
      });
      raise("warn");
    }
  }

  return customNotes.length > 0 ? { level, notes, customNotes } : { level, notes };
}

/** How many profiles share each exit. Keyed by the exit IP when the proxy has
 *  been checked — two proxies with the same exit are the same exit — and by
 *  the proxy otherwise. Counted over every profile, not the filtered view: the
 *  question is how many accounts a site sees from that address.
 *
 *  A proxy with a rotation link is not counted: its exit changes, so the
 *  address from the last check says nothing about where the next launch
 *  comes out, and such proxies are mostly mobile, where a shared address is
 *  normal anyway. */
export function exitSharing(all: Profile[], proxies: LocalProxy[] | null): Map<string, number> {
  const ipOf = new Map<string, string>();
  const rotating = new Set<string>();
  for (const x of proxies ?? []) {
    if (x.last_ip) ipOf.set(x.id, x.last_ip);
    if (x.rotate_url?.trim()) rotating.add(x.id);
  }
  const key = (p: Profile) =>
    p.proxy && !rotating.has(p.proxy.id) ? (ipOf.get(p.proxy.id) ?? `proxy:${p.proxy.id}`) : null;
  const counts = new Map<string, number>();
  for (const p of all) {
    const k = key(p);
    if (k) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const out = new Map<string, number>();
  for (const p of all) {
    const k = key(p);
    out.set(p.id, k ? (counts.get(k) ?? 0) : 0);
  }
  return out;
}
