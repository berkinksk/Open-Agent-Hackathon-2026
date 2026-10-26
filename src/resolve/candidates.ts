// Candidate filter v0: for one messy inventory string, the top-K CISA KEV (vendor, product) pairs by
// token overlap, with a small alias map ("svr" -> server, "httpd" -> http server, "fortigate" -> fortios).
// It keeps the jury's prompts small. A1's normaliser (src/resolve/normalise.ts) replaces it at integration;
// run.ts reaches it only through the Pipeline seam.
//
// Same-vendor siblings are kept on purpose (a vendor match alone scores 0.2): the look-alike products
// (FortiClient EMS for "FortiClient VPN", Exchange Server for "Exchange Online") must be in front of the
// jury and the critic, because that is where the real mistakes happen.
import type { Candidate, InventoryRow, JurorVote, KevPair } from "../contracts.ts";

export const DEFAULT_K = 12;

/** Unicode-safe clean-up: NFKC (turns U+202F, U+00A0 into spaces), collapse whitespace, trim. */
export function cleanName(s: string): string {
  return (s ?? "").normalize("NFKC").replace(/\s+/g, " ").trim();
}

/** v0 product family: the cleaned "Vendor Product". Spellings that differ only in case or spacing share it. */
export function familyV0(p: KevPair): string {
  return `${cleanName(p.vendor)} ${cleanName(p.product)}`;
}

/** The comparison key for any family string (v0 or A1's). */
export function familyKey(family: string): string {
  return cleanName(family).toLowerCase();
}

const STOPWORDS = new Set([
  "and", "or", "the", "a", "an", "for", "of", "in", "on", "at", "by", "to", "with", "via", "from", "into",
  "bundled", "inside", "installed", "running", "x64", "x86", "amd64", "arm64", "bit", "edition", "version",
  "ver", "build", "update", "updates", "patch", "latest", "multiple", "products", "product", "software",
  "suite", "tenant", "laptop", "laptops", "desktop", "desktops", "pc", "host", "hosts", "prod", "dev",
  "32bit", "64bit",
]);

/** Expansions added to the inventory tokens (never to KEV names). */
const TOKEN_ALIASES: Record<string, string[]> = {
  svr: ["server"], srv: ["server"], httpd: ["http", "server"], apache2: ["http", "server"],
  log4j: ["log4j2"], fortigate: ["fortios"], ics: ["connect", "secure"], globalprotect: ["pan", "os"],
  panos: ["pan", "os"], vcenter: ["server"], vcsa: ["vcenter", "server"], win10: ["windows"],
  win11: ["windows"], win: ["windows"], app: ["application"], iis: ["internet", "information", "services"],
};

/** Inventory tokens that imply a KEV vendor (lowercase vendor names as KEV writes them). */
const VENDOR_HINTS: Record<string, string> = {
  ms: "microsoft", msft: "microsoft", m365: "microsoft", o365: "microsoft", office365: "microsoft",
  exchange: "microsoft", outlook: "microsoft", sharepoint: "microsoft", windows: "microsoft", win10: "microsoft",
  win11: "microsoft", iis: "microsoft", httpd: "apache", tomcat: "apache", log4j: "apache", log4j2: "apache",
  struts: "apache", netscaler: "citrix", fortigate: "fortinet", forticlient: "fortinet", fortios: "fortinet",
  anyconnect: "cisco", webex: "cisco", vcenter: "vmware", esxi: "vmware", vsphere: "vmware", ics: "ivanti",
  pulse: "ivanti", globalprotect: "palo alto networks", panos: "palo alto networks", acrobat: "adobe",
  chrome: "google", chromium: "google", confluence: "atlassian", jira: "atlassian", firefox: "mozilla",
};
const VENDOR_WORDS = new Set<string>([...Object.values(VENDOR_HINTS), "ms", "msft"]);

function isVersionish(t: string): boolean {
  return /^\d+$/.test(t)                                   // 2019, 13, 2
    || /^\d+[a-z]{1,2}\d*$/.test(t)                        // 60f, 2r2
    || /^(v|cu|sp|u|r|kb|rev|rc|b)\d+[a-z]?$/.test(t);     // v8, cu12, u3, r2
}

/** Lowercase word tokens without stopwords and version fragments. */
export function tokenize(s: string): string[] {
  return cleanName(s).toLowerCase().split(/[^a-z0-9+#]+/).filter((t) => t && !STOPWORDS.has(t) && !isVersionish(t));
}

/** v0 version: the first dotted version ("v8.6" -> 8.6), else a year with an optional CU/SP/R suffix, else "v8"-style. */
export function parseVersionV0(raw: string): string | null {
  const s = cleanName(raw);
  const dotted = s.match(/\bv?(\d+(?:\.\d+)+(?:[-_.]?[A-Za-z0-9]+)*)/i);
  if (dotted) return dotted[1];
  const year = s.match(/\b(?:19|20)\d{2}(?:\s+(?:CU|SP|R|U)\s?\d+)?\b/i);
  if (year) return year[0];
  const v = s.match(/\bv(\d+)\b/i);
  return v ? v[1] : null;
}

interface RawView { all: Set<string>; productCount: number; vendors: Set<string>; }

function viewOf(raw: string): RawView {
  const base = tokenize(raw);
  const all = new Set<string>(base);
  const vendors = new Set<string>();
  for (const t of base) {
    for (const extra of TOKEN_ALIASES[t] ?? []) all.add(extra);
    const hint = VENDOR_HINTS[t] ?? (t.startsWith("forti") ? "fortinet" : undefined);
    if (hint) vendors.add(hint);
    vendors.add(t); // a vendor named in the text ("citrix", "apache") matches by its first token
  }
  const productCount = base.filter((t) => !VENDOR_WORDS.has(t)).length;
  return { all, productCount: Math.max(1, productCount), vendors };
}

function vendorMatches(view: RawView, vendor: string): boolean {
  const v = cleanName(vendor).toLowerCase();
  if (view.vendors.has(v)) return true;
  const first = tokenize(v)[0];
  return first !== undefined && view.vendors.has(first);
}

function scorePair(view: RawView, p: KevPair): { score: number; reason: string } {
  const pTokens = [...new Set(tokenize(p.product))];
  let overlap = 0;
  const hits: string[] = [];
  for (const t of pTokens) {
    if (view.all.has(t)) { overlap += 1; hits.push(t); continue; }
    if (t.length >= 4) {
      for (const r of view.all) {
        if (r.length >= 4 && (r.startsWith(t) || t.startsWith(r))) { overlap += 0.5; hits.push(`${t}~${r}`); break; }
      }
    }
  }
  // A KEV product named only after its vendor ("Apache / Apache") is a vague entry: half weight.
  const vague = cleanName(p.product).toLowerCase() === cleanName(p.vendor).toLowerCase();
  const productCover = (pTokens.length ? overlap / pTokens.length : 0) * (vague ? 0.5 : 1);
  const rawCover = Math.min(1, overlap / view.productCount);
  const vendor = vendorMatches(view, p.vendor);
  const score = Math.round((0.6 * productCover + 0.2 * rawCover + (vendor ? 0.2 : 0)) * 1000) / 1000;
  const reason = `${hits.length ? `tokens ${hits.join(", ")} (${overlap}/${pTokens.length})` : "no product tokens"}${vendor ? "; vendor match" : ""}`;
  return { score, reason };
}

/** True when the pair's text is already clean (no stray or odd whitespace). */
function isClean(p: KevPair): boolean {
  return cleanName(p.vendor) === p.vendor && cleanName(p.product) === p.product;
}

/**
 * Top-k candidates for one inventory string: one per family, score > 0, sorted by score then family.
 * Each candidate keeps a real KEV spelling (the clean one when a family has several).
 */
export function candidatesV0(raw: string, pairs: KevPair[], k = DEFAULT_K): Candidate[] {
  const view = viewOf(raw);
  const best = new Map<string, Candidate>();
  for (const p of pairs) {
    if (!p || typeof p.vendor !== "string" || typeof p.product !== "string") continue;
    const { score, reason } = scorePair(view, p);
    if (score <= 0) continue;
    const family = familyV0(p);
    const key = familyKey(family);
    const prev = best.get(key);
    if (!prev || (!isClean(prev) && isClean(p))) best.set(key, { vendor: p.vendor, product: p.product, family, score, reason });
  }
  return [...best.values()]
    .sort((a, b) => b.score - a.score || familyKey(a.family).localeCompare(familyKey(b.family)))
    .slice(0, Math.max(0, k));
}

/** A null vote at or above this confidence means "nothing plausible", so the jury records no_match. */
export const CONFIDENT_NONE = 0.6;
const MATCH_MIN = 0.5;
const MARGIN = 0.1;

/**
 * Deterministic vote v0 (sample mode, or Nightshift down): the top candidate when it is plausible and
 * clearly ahead of the next family; a confident null when nothing is plausible; an unsure null otherwise.
 */
export function deterministicVoteV0(row: InventoryRow, cands: Candidate[]): JurorVote {
  const [top, second] = cands;
  const none = (confidence: number): JurorVote => ({ row_id: row.row_id, juror: "normaliser", vendor: null, product: null, confidence });
  if (!top || top.score < MATCH_MIN) return none(0.8);
  if (second && second.score >= top.score - MARGIN - 1e-9) return none(0.3);
  return { row_id: row.row_id, juror: "normaliser", vendor: top.vendor, product: top.product, confidence: top.score };
}
