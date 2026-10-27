// Verifier: before a line is shown, every cited KEV and EPSS value is compared with a fresh single-source
// re-query (Queries.kevVerify / epssVerify, which never use the cache). Any mismatch, missing value or unreachable
// source blocks the line (verified: false) with a note; nothing is ever relaxed.
//   KEV:  due_date, date_added, ransomware_use, vendor, product of each cited listing, plus the derived earliest due
//         date (and overdue days when the run date is given).
//   EPSS: exact when the cited score_date equals the live one, otherwise within a tolerance (default 0.02).
//         A missing live score is "unknown", never 0.
//   Every distinct cited value is compared: PatchLine.kev, PatchLine.epss and the evidence items are all checked, so
//   evidence that states another value for the same CVE and field cannot hide behind an earlier match.
import type { EpssScore, Evidence, KevEntry, Mode, PatchLine, Policy, Queries, Tracer } from "../contracts.ts";

export interface VerifyOptions {
  /** The run's as-of date (YYYY-MM-DD): re-derives `overdue_days` from the live due date. */
  asOf?: string;
  /** Re-derives the this_cycle EPSS threshold with the live score. */
  policy?: Policy;
  /** Allowed EPSS drift when the cited and live score dates differ. Default 0.02. */
  epssTolerance?: number;
  /** How the notes name the re-check source. Sample mode re-checks against the snapshot, and says so. */
  source?: "live" | "snapshot";
}

const CVE_RE = /CVE-\d{4}-\d{4,}/i;
const KEV_FIELDS = ["due_date", "date_added", "ransomware_use", "vendor", "product"] as const;
type KevField = (typeof KEV_FIELDS)[number];
const FIELD_ALIASES: Record<string, string> = {
  duedate: "due_date", dateadded: "date_added", knownransomwarecampaignuse: "ransomware_use",
  known_ransomware_campaign_use: "ransomware_use", vendorproject: "vendor", vendor_project: "vendor", score: "epss",
};
const DAY_MS = 86_400_000;

const upper = (s: string): string => String(s ?? "").trim().toUpperCase();
const day10 = (s: string | null | undefined): string => String(s ?? "").trim().slice(0, 10);
const isIsoDate = (s: string | null | undefined): boolean => /^\d{4}-\d{2}-\d{2}$/.test(day10(s));
const normText = (s: string | null | undefined): string => String(s ?? "").toLowerCase().replace(/\s+/g, " ").trim();

function cveIn(s: string | null | undefined): string | null {
  const m = String(s ?? "").match(CVE_RE);
  return m ? m[0].toUpperCase() : null;
}
function fieldOf(field: string): string {
  const last = String(field ?? "").split(/[.:/\s]+/).filter(Boolean).pop() ?? "";
  const snake = last.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  return FIELD_ALIASES[snake] ?? FIELD_ALIASES[snake.replace(/_/g, "")] ?? snake;
}
/** A KEV value as it is compared: dates on their first 10 characters, text trimmed and lower-cased. */
function kevNorm(field: KevField, v: string | null | undefined): string {
  return field === "due_date" || field === "date_added" ? day10(v) : normText(v);
}
function sameKev(field: KevField, cited: string, live: string): boolean {
  return kevNorm(field, cited) === kevNorm(field, live);
}
function fmt(n: number): string {
  return Number.isFinite(n) ? String(Math.round(n * 1e6) / 1e6) : String(n);
}
function daysBetween(from: string, to: string): number {
  return Math.round((Date.parse(`${day10(to)}T00:00:00Z`) - Date.parse(`${day10(from)}T00:00:00Z`)) / DAY_MS);
}

/** The cited EPSS score date for a CVE, from the line's evidence (as_of of a zetaris:epss item). */
function citedEpssDate(evidence: Evidence[], cve: string): string | null {
  for (const e of evidence ?? []) {
    if (e?.source !== "zetaris:epss") continue;
    if ((cveIn(e.field) ?? cveIn(e.query)) === cve && e.as_of) return day10(e.as_of);
  }
  return null;
}

/** Compare every cited value with the re-queried rows. `null` = that source could not be re-queried (fail closed). */
export function verifyLines(lines: PatchLine[], liveKev: KevEntry[] | null, liveEpss: EpssScore[] | null, opts: VerifyOptions = {}): PatchLine[] {
  const src = opts.source ?? "live";
  const tol = opts.epssTolerance ?? 0.02;
  const kevMap = new Map<string, KevEntry>((liveKev ?? []).map((e) => [upper(e.cve_id), e]));
  const epssMap = new Map<string, EpssScore>((liveEpss ?? []).map((e) => [upper(e.cve_id), e]));

  return lines.map((line) => {
    const notes: string[] = [];
    let blocked = false;
    let checked = 0;
    let kevDownNoted = false;
    let epssDownNoted = false;
    const seen = new Set<string>();
    const block = (msg: string): void => { blocked = true; notes.push(`blocked: ${msg}`); };
    const kevDown = (what: string): void => {
      if (!kevDownNoted) block(`KEV could not be re-queried (${src}); ${what} not verified`);
      kevDownNoted = true;
    };
    const epssDown = (what: string): void => {
      if (!epssDownNoted) block(`EPSS could not be re-queried (${src}); ${what} not verified`);
      epssDownNoted = true;
    };

    // One comparison per distinct cited value: the key holds the normalised value, so a second citation of the same
    // CVE and field that states a different value (say, in the evidence) is compared too, never skipped.
    const compareKev = (id: string, field: KevField, cited: string): void => {
      const key = `kev|${id}|${field}|${kevNorm(field, cited)}`;
      if (seen.has(key)) return;
      seen.add(key);
      if (liveKev === null) { kevDown(`${id} ${field}`); return; }
      const live = kevMap.get(id);
      if (!live) { if (!seen.has(`${id}|missing`)) block(`${id} is not in the ${src} KEV catalogue`); seen.add(`${id}|missing`); return; }
      checked++;
      if (!sameKev(field, cited, live[field])) block(`${id} ${field}: cited "${String(cited).trim()}", ${src} "${String(live[field] ?? "").trim()}"`);
    };

    // The cited score date is part of the key too: it decides between the exact and the tolerance comparison.
    const compareEpss = (id: string, field: "epss" | "percentile", cited: number, citedDate: string | null): void => {
      const key = `epss|${id}|${field}|${String(cited)}|${citedDate ?? ""}`;
      if (seen.has(key)) return;
      seen.add(key);
      if (liveEpss === null) { epssDown(`${id} ${field}`); return; }
      const live = epssMap.get(id);
      if (!live) { if (!seen.has(`${id}|nolive`)) block(`no ${src} EPSS score for ${id} (unknown, not 0)`); seen.add(`${id}|nolive`); return; }
      checked++;
      const liveVal = field === "epss" ? live.epss : live.percentile;
      const sameDay = citedDate !== null && citedDate === day10(live.score_date);
      const ok = Number.isFinite(cited) && Number.isFinite(liveVal) && Math.abs(cited - liveVal) <= (sameDay ? 1e-9 : tol);
      if (!ok) {
        block(`${id} ${field}: cited ${fmt(cited)}${citedDate ? ` (${citedDate})` : ""}, ${src} ${fmt(liveVal)} (${day10(live.score_date)})${sameDay ? ", same score date" : `, beyond the ${tol} tolerance`}`);
      }
    };

    // 1. the decision must rest on what it cites
    const kevCited = line.kev?.cves ?? [];
    if (line.decision === "patch_now" && kevCited.length === 0) block("patch_now without a cited KEV listing");
    if (line.decision === "this_cycle" && !line.epss) block("this_cycle without a cited EPSS score");

    // 2. KEV listings
    for (const c of kevCited) {
      const id = upper(c.cve_id);
      for (const f of KEV_FIELDS) if (String(c[f] ?? "").trim() !== "") compareKev(id, f, c[f]);
    }
    if (line.kev && kevCited.length > 0 && liveKev !== null) {
      const liveDues = kevCited.map((c) => kevMap.get(upper(c.cve_id))?.due_date).filter(isIsoDate).map(day10).sort();
      if (line.kev.earliest_due && liveDues.length > 0) {
        checked++;
        if (day10(line.kev.earliest_due) !== liveDues[0]) block(`earliest KEV due date: cited ${day10(line.kev.earliest_due)}, ${src} ${liveDues[0]}`);
        if (opts.asOf && typeof line.kev.overdue_days === "number" && line.kev.overdue_days > 0) {
          const expected = daysBetween(liveDues[0], opts.asOf);
          if (expected !== line.kev.overdue_days) block(`overdue by ${line.kev.overdue_days} day(s) cited, but the ${src} due date ${liveDues[0]} gives ${expected} as of ${day10(opts.asOf)}`);
        }
      }
    }

    // 3. the cited EPSS score
    if (line.epss) {
      const id = upper(line.epss.cve_id);
      const citedDate = citedEpssDate(line.evidence, id);
      compareEpss(id, "epss", line.epss.max, citedDate);
      if (typeof line.epss.percentile === "number") compareEpss(id, "percentile", line.epss.percentile, citedDate);
      const live = epssMap.get(id);
      if (opts.policy && line.decision === "this_cycle" && live) {
        const threshold = line.internet_facing ? opts.policy.epss_this_cycle_internet : opts.policy.epss_this_cycle;
        if (!(live.epss >= threshold)) block(`${src} EPSS ${fmt(live.epss)} for ${id} is below the this_cycle threshold ${threshold}`);
      }
    }

    // 4. any other KEV/EPSS value the evidence cites by CVE id
    for (const e of line.evidence ?? []) {
      if (e?.source !== "zetaris:kev" && e?.source !== "zetaris:epss") continue;
      const id = cveIn(e.field) ?? cveIn(e.query);
      if (!id) continue;
      const f = fieldOf(e.field);
      if (e.source === "zetaris:kev" && (KEV_FIELDS as readonly string[]).includes(f) && String(e.value ?? "").trim() !== "") {
        compareKev(id, f as KevField, e.value);
      } else if (e.source === "zetaris:epss" && (f === "epss" || f === "percentile")) {
        const n = Number(e.value);
        if (!Number.isFinite(n)) { block(`evidence ${e.field} for ${id} is not a number ("${e.value}")`); continue; }
        compareEpss(id, f, n, e.as_of ? day10(e.as_of) : null);
      }
    }

    if (!blocked) {
      notes.push(checked > 0
        ? `re-checked ${checked} cited value(s) against ${src === "live" ? "live single-source Zetaris queries" : "the sample snapshot"}: all match`
        : "no KEV or EPSS values cited; nothing to re-check");
    }
    return { ...line, verified: !blocked, verifier_notes: notes };
  });
}

/** The CVE ids whose KEV listings and EPSS scores the lines cite. */
export function citedCves(lines: PatchLine[]): { kev: string[]; epss: string[] } {
  const kev = new Set<string>();
  const epss = new Set<string>();
  for (const line of lines) {
    for (const c of line.kev?.cves ?? []) { const id = cveIn(c.cve_id); if (id) kev.add(id); }
    if (line.epss) { const id = cveIn(line.epss.cve_id); if (id) epss.add(id); }
    for (const e of line.evidence ?? []) {
      const id = cveIn(e?.field) ?? cveIn(e?.query);
      if (!id) continue;
      if (e.source === "zetaris:kev") kev.add(id);
      if (e.source === "zetaris:epss") epss.add(id);
    }
  }
  return { kev: [...kev].sort(), epss: [...epss].sort() };
}

export interface LiveVerifyResult {
  lines: PatchLine[];
  kev_checked: string[];
  epss_checked: string[];
  errors: string[];
  blocked_rows: string[];
}

function chunks<T>(xs: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}

/**
 * Re-query every cited CVE (kevVerify and epssVerify, <= 100 ids per call, never cached) and verify the lines.
 * A failed re-query fails closed: the lines citing that source are blocked.
 */
export async function verifyLive(
  lines: PatchLine[],
  queries: Pick<Queries, "kevVerify" | "epssVerify">,
  opts: VerifyOptions & { tracer?: Tracer | null; mode?: Mode; batchSize?: number } = {},
): Promise<LiveVerifyResult> {
  const ids = citedCves(lines);
  const size = Math.min(Math.max(1, opts.batchSize ?? 100), 100);
  const errors: string[] = [];
  const msg = (e: unknown): string => (e instanceof Error ? e.message : String(e)).replace(/\s+/g, " ").slice(0, 200);
  const t0 = Date.now();

  let liveKev: KevEntry[] | null = [];
  if (ids.kev.length > 0) {
    try { for (const c of chunks(ids.kev, size)) liveKev.push(...(await queries.kevVerify(c))); }
    catch (e) { liveKev = null; errors.push(`kevVerify failed: ${msg(e)}`); }
  }
  let liveEpss: EpssScore[] | null = [];
  if (ids.epss.length > 0) {
    try { for (const c of chunks(ids.epss, size)) liveEpss.push(...(await queries.epssVerify(c))); }
    catch (e) { liveEpss = null; errors.push(`epssVerify failed: ${msg(e)}`); }
  }

  const source = opts.source ?? (opts.mode === "sample" ? "snapshot" : "live");
  const out = verifyLines(lines, liveKev, liveEpss, { ...opts, source });
  const blockedRows = out.filter((l) => !l.verified).map((l) => l.row_id);

  if (opts.tracer) {
    try {
      opts.tracer.emit({
        agent: "verifier", action: "recheck", target_agent: "reporter",
        input_summary: `${lines.length} line(s); ${ids.kev.length} KEV + ${ids.epss.length} EPSS CVE(s), re-queried ${source}`,
        output_summary: `${out.length - blockedRows.length}/${out.length} verified; ${blockedRows.length} blocked${errors.length ? `; ${errors.length} source error(s)` : ""}`,
        latency_ms: Date.now() - t0,
        status: errors.length ? "error" : blockedRows.length ? "blocked" : "ok",
        details: { source, kev_ids: ids.kev, epss_ids: ids.epss, blocked_rows: blockedRows, errors },
      });
      for (const l of out) {
        if (l.verified) continue;
        opts.tracer.emit({
          agent: "verifier", action: "block_line", target_agent: "reporter", status: "blocked",
          input_summary: `${l.row_id} ${l.decision} "${String(l.software).slice(0, 80)}"`,
          output_summary: l.verifier_notes[0] ?? "blocked",
          details: { row_id: l.row_id, notes: l.verifier_notes },
        });
      }
    } catch { /* tracing never breaks verification */ }
  }
  return { lines: out, kev_checked: ids.kev, epss_checked: ids.epss, errors, blocked_rows: blockedRows };
}
