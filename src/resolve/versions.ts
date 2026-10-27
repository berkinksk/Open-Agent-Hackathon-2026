// Version comparison and the NVD version-range check.
//
// compareVersions(a, b) orders dotted versions with numeric parts, pre-release tags and suffixes:
//   2.14.1 < 2.15.0 · 1.0 == 1.0.0 · 2.0-beta9 < 2.0-rc1 < 2.0 · 1.0.2 < 1.0.2k < 1.0.3 · 13.1-48.47 < 13.1-49.13
//   "2019 CU12" == "2019:cumulative_update_12" (the Exchange CPE spelling)
// isAffected(version, ranges) applies NVD cpeMatch bounds (start/end, including/excluding) and exact-version CPEs,
// and answers true, false or "unknown" (Kleene logic: an under-specified version such as "2.4" against a bound
// "2.4.49" is "unknown", never a guess).
import type { NvdRange } from "../contracts.ts";

export type Tri = boolean | "unknown";

// ---------- version parts ----------
type Tok =
  | { k: "num"; s: string }               // digits, leading zeros stripped
  | { k: "pre"; rank: number; s: string } // pre-release tag: sorts before the release
  | { k: "txt"; s: string };              // any other letters: sorts after the release (1.0.2k, 8.9p1, cu12)

// Ranked pre-release tags. Single letters a/b/m count only when a number follows (3.12.0a1, 1.0-M2).
const PRE_WORDS: Record<string, number> = {
  dev: 0, snapshot: 0, nightly: 0,
  alpha: 1, beta: 2,
  milestone: 3, pre: 3, preview: 3, ea: 3,
  rc: 4, cr: 4,
};
const PRE_LETTERS: Record<string, number> = { a: 1, b: 2, m: 3 };
const NOISE_WORDS = new Set(["v", "ver", "version", "release", "final", "ga", "build"]);

/** Lower-case, drop parentheticals and the "v"/"version" prefix, and fold CPE/inventory spellings together. */
export function normaliseVersion(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/\([^)]*\)/g, " ")
    .replace(/cumulative[\s_-]*update/g, "cu")
    .replace(/service[\s_-]*pack/g, "sp")
    .replace(/update[\s_-]*rollup/g, "ur")
    .replace(/security[\s_-]*update/g, "su")
    .replace(/\s+/g, " ")
    .trim();
}

function versionParts(raw: string): Tok[] {
  const parts = normaliseVersion(raw).match(/\d+|[a-z]+/g) ?? [];
  const out: Tok[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (/^\d+$/.test(p)) { out.push({ k: "num", s: p.replace(/^0+(?=\d)/, "") }); continue; }
    if (NOISE_WORDS.has(p)) continue;
    if (p in PRE_WORDS) { out.push({ k: "pre", rank: PRE_WORDS[p], s: p }); continue; }
    const nextIsNum = i + 1 < parts.length && /^\d+$/.test(parts[i + 1]);
    if (p in PRE_LETTERS && nextIsNum) { out.push({ k: "pre", rank: PRE_LETTERS[p], s: p }); continue; }
    out.push({ k: "txt", s: p });
  }
  return out;
}

/** True when the string carries at least one digit (a version we can compare at all). */
export function hasVersion(v: string | null | undefined): v is string {
  return typeof v === "string" && /\d/.test(v) && versionParts(v).length > 0;
}

function cmpNum(a: string, b: string): number {
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

const KIND_RANK = { pre: 0, txt: 2, num: 3 } as const; // the end of a version ranks 1

/** Compare one position. `undefined` = the version has ended there (acts as 0 against a number). */
function cmpTok(x: Tok | undefined, y: Tok | undefined): number {
  if (!x && !y) return 0;
  if (!x) return -cmpTok(y, undefined);
  if (!y) {
    if (x.k === "num") return x.s === "0" ? 0 : 1;
    return x.k === "pre" ? -1 : 1;
  }
  if (x.k !== y.k) return KIND_RANK[x.k] < KIND_RANK[y.k] ? -1 : 1;
  if (x.k === "num") return cmpNum(x.s, y.s);
  if (x.k === "pre" && y.k === "pre") {
    if (x.rank !== y.rank) return x.rank < y.rank ? -1 : 1;
    return 0;
  }
  return x.s < y.s ? -1 : x.s > y.s ? 1 : 0;
}

/** Total order on version strings: -1, 0 or 1. Never throws; a version without parts sorts first. */
export function compareVersions(a: string, b: string): number {
  const ta = versionParts(a);
  const tb = versionParts(b);
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const c = cmpTok(ta[i], tb[i]);
    if (c !== 0) return c;
  }
  return 0;
}

/**
 * Like compareVersions, but "unknown" when `version` is a less specific prefix of `bound`:
 * "13.1" vs "13.1-49.13", "2.4" vs "2.4.49", "2019" vs "2019 CU12". Trailing zeros ("1.0" vs "1.0.0") are equal,
 * and a release is above its own pre-releases ("2.0" vs "2.0-beta9").
 */
export function compareToBound(version: string, bound: string): number | "unknown" {
  const tv = versionParts(version);
  const tb = versionParts(bound);
  for (let i = 0; i < tv.length; i++) {
    const c = cmpTok(tv[i], tb[i]);
    if (c !== 0) return c;
  }
  // every part of `version` matched; look at what the bound has left
  for (let i = tv.length; i < tb.length; i++) {
    const t = tb[i];
    if (t.k === "num" && t.s === "0") continue;
    if (t.k === "pre") return 1;
    return "unknown";
  }
  return 0;
}

// ---------- CPE ----------
export interface Cpe { part: string; vendor: string; product: string; version: string; update: string; }

/** Parse a CPE 2.3 formatted string (`cpe:2.3:a:apache:log4j:2.0:beta9:*:...`), honouring `\` escapes. */
export function parseCpe(criteria: string): Cpe | null {
  if (typeof criteria !== "string" || !criteria.toLowerCase().startsWith("cpe:2.3:")) return null;
  const fields: string[] = [];
  let cur = "";
  for (let i = 0; i < criteria.length; i++) {
    const ch = criteria[i];
    if (ch === "\\" && i + 1 < criteria.length) { cur += criteria[++i]; continue; }
    if (ch === ":") { fields.push(cur); cur = ""; continue; }
    cur += ch;
  }
  fields.push(cur);
  if (fields.length < 7) return null;
  return {
    part: fields[2].toLowerCase(), vendor: fields[3].toLowerCase(), product: fields[4].toLowerCase(),
    version: fields[5], update: fields[6],
  };
}

function words(s: string): string[] {
  return s.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 0);
}

function wordsMatch(a: string, b: string): boolean {
  if (a === b) return true;
  const [s, l] = a.length <= b.length ? [a, b] : [b, a];
  return s.length >= 3 && l.startsWith(s); // log4j ~ log4j2
}

/**
 * Keep the ranges whose CPE belongs to this vendor/product (KEV names or CPE names both work):
 * vendor words must match ("Palo Alto Networks" ~ paloaltonetworks); among those, the CPE products sharing
 * the most product words win. If no CPE product shares a word, every range of the vendor is kept
 * (the CVE is listed against that vendor, so its products are the candidates). No vendor match → [].
 */
export function rangesForProduct(ranges: NvdRange[], vendor: string, product: string): NvdRange[] {
  const vWords = words(vendor);
  const vJoined = vWords.join("");
  const pWords = words(product).filter((w) => !["and", "the", "for", "of"].includes(w));
  const scored: { r: NvdRange; score: number }[] = [];
  for (const r of ranges) {
    const cpe = parseCpe(r.criteria);
    if (!cpe) continue;
    const cvWords = words(cpe.vendor);
    const vendorOk = cvWords.join("") === vJoined || cvWords.some((w) => vWords.some((x) => wordsMatch(w, x)));
    if (!vendorOk) continue;
    const cpWords = words(cpe.product);
    const score = pWords.filter((w) => cpWords.some((c) => wordsMatch(w, c))).length;
    scored.push({ r, score });
  }
  const best = Math.max(0, ...scored.map((s) => s.score));
  return scored.filter((s) => s.score === best).map((s) => s.r);
}

// ---------- the range check ----------
function and(vals: Tri[]): Tri {
  if (vals.includes(false)) return false;
  if (vals.includes("unknown")) return "unknown";
  return true;
}
function or(vals: Tri[]): Tri {
  if (vals.includes(true)) return true;
  if (vals.includes("unknown")) return "unknown";
  return false;
}
function cmpTri(version: string, bound: string, test: (c: number) => boolean): Tri {
  const c = compareToBound(version, bound);
  return c === "unknown" ? "unknown" : test(c);
}
function nonEmpty(s: string | undefined): s is string {
  return typeof s === "string" && s.trim() !== "";
}

/**
 * True when the row's "version" is the edition that the CPE product itself names: Windows "23H2" against
 * windows_11_23h2, "2019" against windows_server_2019. The CPE's bounds are then build numbers (10.0.22631.4317), and
 * an edition label cannot be placed among them: comparing "23H2" with "10.0.22631" would read 23 > 10 and wrongly say
 * "not affected".
 */
export function namesEdition(version: string, criteria: string): boolean {
  const cpe = parseCpe(criteria);
  if (!cpe) return false;
  const v = normaliseVersion(version).replace(/[^a-z0-9]+/g, "");
  if (!v) return false;
  return cpe.product.split(/[^a-z0-9]+/).includes(v);
}

/** Does `version` fall inside one NVD cpeMatch entry? */
export function inRange(version: string, r: NvdRange): Tri {
  if (namesEdition(version, r.criteria)) return "unknown";
  const conds: Tri[] = [];
  if (nonEmpty(r.version_start_including)) conds.push(cmpTri(version, r.version_start_including, (c) => c >= 0));
  if (nonEmpty(r.version_start_excluding)) conds.push(cmpTri(version, r.version_start_excluding, (c) => c > 0));
  if (nonEmpty(r.version_end_including)) conds.push(cmpTri(version, r.version_end_including, (c) => c <= 0));
  if (nonEmpty(r.version_end_excluding)) conds.push(cmpTri(version, r.version_end_excluding, (c) => c < 0));
  if (conds.length > 0) return and(conds);

  // no bounds: the CPE itself names the version
  const cpe = parseCpe(r.criteria);
  if (!cpe) return "unknown";
  if (cpe.version === "*") return true;                 // every version of the product
  if (cpe.version === "-" || cpe.version === "") return "unknown"; // "not applicable": no version to compare
  const update = cpe.update;
  if (update === "*" || update === "") {
    // e.g. exchange_server:2019:* = any update of 2019: "2019 CU12" matches, "2019.1" does not
    const c = compareToBound(version, cpe.version);
    if (c === "unknown") return "unknown";
    if (c === 0) return true;
    const tv = versionParts(version);
    const tc = versionParts(cpe.version);
    const prefixOk = tc.every((t, i) => cmpTok(tv[i], t) === 0);
    return prefixOk && tv.length > tc.length && tv[tc.length].k === "txt";
  }
  const exact = update === "-" ? cpe.version : `${cpe.version}-${update}`;
  const c = compareToBound(version, exact);
  return c === "unknown" ? "unknown" : c === 0;
}

/**
 * Is `version` affected by any vulnerable range? true / false / "unknown".
 * "unknown" when the version is missing or has no digits, when no vulnerable range is given
 * (e.g. NVD has not analysed the CVE yet), or when the version is too vague to place.
 * Pass only the ranges of the right product (see rangesForProduct).
 */
export function isAffected(version: string | null | undefined, ranges: NvdRange[]): Tri {
  const vulnerable = (ranges ?? []).filter((r) => r && r.vulnerable);
  if (vulnerable.length === 0) return "unknown";
  if (vulnerable.some((r) => isAllVersions(r))) return true;
  if (!hasVersion(version)) return "unknown";
  return or(vulnerable.map((r) => inRange(version, r)));
}

/** A vulnerable entry with no bounds and CPE version "*": every version is affected, no version check needed. */
export function isAllVersions(r: NvdRange): boolean {
  if (!r.vulnerable) return false;
  if ([r.version_start_including, r.version_start_excluding, r.version_end_including, r.version_end_excluding].some(nonEmpty)) return false;
  const cpe = parseCpe(r.criteria);
  return cpe !== null && cpe.version === "*";
}

/** The lowest fixed version the ranges imply ("upgrade to >= X"), from versionEndExcluding; null when none. */
export function fixedVersion(version: string | null | undefined, ranges: NvdRange[]): string | null {
  const ends = ranges
    .filter((r) => r.vulnerable && nonEmpty(r.version_end_excluding))
    .filter((r) => !hasVersion(version) || inRange(version, r) === true)
    .map((r) => r.version_end_excluding as string);
  if (ends.length === 0) return null;
  return ends.sort(compareVersions)[0];
}
