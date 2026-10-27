// The sample snapshot (design §10): real rows captured through Zetaris by scripts/snapshot.ts, stored in
// data/sample/snapshot.json, and served offline by src/sample/queries.ts. It holds INPUT data only (the inventory,
// KEV, EPSS, NVD ranges and product lookups, each with its capture date); it never holds model replies, decisions or
// any other output, so a sample run computes everything itself.
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { EpssScore, InventoryRow, KevEntry, KevPair, NvdProductHit, NvdRange } from "../contracts.ts";
import { REPO_ROOT } from "../config.ts";

export const SNAPSHOT_SCHEMA = "exposureledger.sample-snapshot.v1";
export const DEFAULT_SNAPSHOT_FILE = join(REPO_ROOT, "data", "sample", "snapshot.json");
/** The snapshot's path as the README and the trace name it. */
export const SNAPSHOT_REL_PATH = "data/sample/snapshot.json";

/** One Zetaris statement the capture ran (for provenance; never replayed). */
export interface CaptureQuery { label: string; sql: string; sql_hash: string; rows: number; ms: number; at: string; }

/** How one NVD CVE record was read during the capture (the NVD adapter's lookup state). */
export interface NvdSnapshotRecord {
  state: "ok" | "no_configurations" | "not_found" | "cached" | "fallback";
  as_of: string;            // YYYY-MM-DD: the day the record was read through Zetaris
  table: string | null;
  ranges: NvdRange[];
  detail?: string;
}

export interface NvdProductSnapshot {
  state: "ok" | "cached" | "fallback";
  as_of: string;
  table: string | null;
  hits: NvdProductHit[];
  detail?: string;
}

export interface SampleSnapshot {
  schema: string;
  description: string;
  captured_at: string;      // ISO time the capture started
  finished_at: string;      // ISO time the capture finished
  capture: {
    tool: string; prefix: string; zetaris_queries: number; zetaris_ms: number;
    queries: CaptureQuery[]; notes: string[];
  };
  sources: {
    inventory: { object: string; captured_at: string; rows: number; synthetic: boolean };
    kev: {
      object: string; captured_at: string; catalog_version: string | null; pairs: number; entries: number;
      scope: "full_catalogue" | "inventory_vendors"; inventory_vendors: string[];
    };
    epss: { object: string; captured_at: string; requested: number; scored: number; score_dates: string[] };
    nvd: { object: string; captured_at: string; cves: number; states: Record<string, number>; plan: string };
    nvd_products: { object: string; captured_at: string; lookups: number; window_days: number; page_size: number };
  };
  inventory: InventoryRow[];
  kev_pairs: KevPair[];
  kev_entries: KevEntry[];
  /** Every CVE whose EPSS score was asked for during the capture (a CVE in this list without a score had none). */
  epss_requested: string[];
  epss: EpssScore[];
  /** CVE id -> the NVD record read through Zetaris. */
  nvd: Record<string, NvdSnapshotRecord>;
  /** CVE id -> why the capture could not read it (these CVEs are absent from `nvd`). */
  nvd_errors: Record<string, string>;
  /** "cpe:<vendor>:<product>" -> the NVD product lookup (recent CVEs). */
  nvd_products: Record<string, NvdProductSnapshot>;
}

export class SnapshotError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SnapshotError";
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const ISO_DAY = /^\d{4}-\d{2}-\d{2}/;

function need(cond: boolean, what: string): void {
  if (!cond) throw new SnapshotError(`invalid sample snapshot: ${what}`);
}

/**
 * Parse and validate snapshot text. Numbers that JSON cannot hold (a missing EPSS percentile, NaN) are stored as null
 * and come back as NaN, exactly as the live adapter returns them.
 */
export function parseSnapshot(text: string): SampleSnapshot {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch (e) { throw new SnapshotError(`the sample snapshot is not valid JSON: ${(e as Error).message}`); }
  need(isObj(raw), "not a JSON object");
  const s = raw as Obj;
  need(s.schema === SNAPSHOT_SCHEMA, `schema must be ${SNAPSHOT_SCHEMA} (got ${JSON.stringify(s.schema)})`);
  need(isStr(s.captured_at) && ISO_DAY.test(s.captured_at), "captured_at must be an ISO time");
  need(isObj(s.sources), "sources missing");
  const src = s.sources as Obj;
  for (const k of ["inventory", "kev", "epss", "nvd", "nvd_products"]) {
    need(isObj(src[k]) && isStr((src[k] as Obj).captured_at) && ISO_DAY.test((src[k] as Obj).captured_at as string), `sources.${k}.captured_at missing`);
  }
  need(Array.isArray(s.inventory), "inventory must be an array");
  for (const [i, r] of (s.inventory as unknown[]).entries()) {
    need(isObj(r) && isStr(r.row_id) && isStr(r.software) && typeof r.internet_facing === "boolean", `inventory[${i}] is not an inventory row`);
  }
  need(Array.isArray(s.kev_pairs) && (s.kev_pairs as unknown[]).length > 0, "kev_pairs must be a non-empty array");
  for (const [i, p] of (s.kev_pairs as unknown[]).entries()) need(isObj(p) && isStr(p.vendor) && isStr(p.product), `kev_pairs[${i}] is not a (vendor, product) pair`);
  need(Array.isArray(s.kev_entries) && (s.kev_entries as unknown[]).length > 0, "kev_entries must be a non-empty array");
  for (const [i, e] of (s.kev_entries as unknown[]).entries()) {
    need(isObj(e) && isStr(e.cve_id) && isStr(e.vendor) && isStr(e.product) && isStr(e.due_date) && isStr(e.catalog_version), `kev_entries[${i}] is not a KEV entry`);
  }
  need(Array.isArray(s.epss_requested) && (s.epss_requested as unknown[]).every(isStr), "epss_requested must be a list of CVE ids");
  need(Array.isArray(s.epss), "epss must be an array");
  const epss: EpssScore[] = (s.epss as unknown[]).map((x, i) => {
    need(isObj(x) && isStr(x.cve_id) && typeof x.epss === "number" && Number.isFinite(x.epss) && isStr(x.score_date), `epss[${i}] is not an EPSS score`);
    const o = x as Obj;
    return { cve_id: o.cve_id as string, epss: o.epss as number, percentile: typeof o.percentile === "number" ? o.percentile : Number.NaN, score_date: o.score_date as string };
  });
  need(isObj(s.nvd), "nvd must be an object keyed by CVE id");
  for (const [k, r] of Object.entries(s.nvd as Obj)) {
    need(isObj(r) && Array.isArray(r.ranges) && isStr(r.as_of) && isStr(r.state), `nvd.${k} is not an NVD record`);
    for (const [j, x] of (r.ranges as unknown[]).entries()) need(isObj(x) && isStr(x.cve_id) && isStr(x.criteria) && typeof x.vulnerable === "boolean", `nvd.${k}.ranges[${j}] is not an NVD range`);
  }
  need(s.nvd_errors === undefined || isObj(s.nvd_errors), "nvd_errors must be an object");
  need(isObj(s.nvd_products), "nvd_products must be an object");
  for (const [k, r] of Object.entries(s.nvd_products as Obj)) need(isObj(r) && Array.isArray(r.hits) && isStr(r.as_of), `nvd_products.${k} is not a product lookup`);
  return { ...(s as unknown as SampleSnapshot), epss, nvd_errors: (s.nvd_errors as Record<string, string> | undefined) ?? {} };
}

const loaded = new Map<string, { mtimeMs: number; size: number; snap: SampleSnapshot }>();

/** Load a snapshot file (cached per path until the file changes). Throws SnapshotError with a fix when it is unusable. */
export function loadSnapshot(file: string = DEFAULT_SNAPSHOT_FILE): SampleSnapshot {
  let st;
  try { st = statSync(file); } catch {
    throw new SnapshotError(`the sample snapshot ${file} is missing; capture it with "npm run snapshot" (needs Zetaris), or restore it from git`);
  }
  const hit = loaded.get(file);
  if (hit && hit.mtimeMs === st.mtimeMs && hit.size === st.size) return hit.snap;
  const snap = parseSnapshot(readFileSync(file, "utf8"));
  loaded.set(file, { mtimeMs: st.mtimeMs, size: st.size, snap });
  return snap;
}

/** YYYY-MM-DD of an ISO time. */
export function dayOf(iso: string): string {
  return String(iso ?? "").slice(0, 10);
}

/**
 * Serialise with one record per line inside the large arrays and maps, so a re-capture diffs row by row.
 * The result parses back to the same value (checked by the snapshot script and the tests).
 */
export function formatSnapshot(s: SampleSnapshot): string {
  const ind = "  ";
  const line = (v: unknown): string => JSON.stringify(v);
  const block = (v: unknown, depth: number): string => {
    const pad = ind.repeat(depth);
    if (Array.isArray(v)) {
      if (!v.length) return "[]";
      if (v.every((x) => typeof x !== "object" || x === null)) return line(v);
      return `[\n${v.map((x) => `${pad}${ind}${line(x)}`).join(",\n")}\n${pad}]`;
    }
    if (isObj(v)) {
      const entries = Object.entries(v);
      if (!entries.length) return "{}";
      // top level: every member on its own block; below it: one line per member, except lists of records
      const member = (x: unknown): string => (depth === 0 || (Array.isArray(x) && x.some(isObj)) ? block(x, depth + 1) : line(x));
      return `{\n${entries.map(([k, x]) => `${pad}${ind}${line(k)}: ${member(x)}`).join(",\n")}\n${pad}}`;
    }
    return line(v);
  };
  return `${block(s, 0)}\n`;
}
