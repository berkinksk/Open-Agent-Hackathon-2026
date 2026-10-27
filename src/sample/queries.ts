// The named Queries over the sample snapshot (design §6, §10): the same contract as the live Zetaris adapter, served
// from data/sample/snapshot.json with no network. Each call applies the same selection the live SQL applies
// (lower(trim()) on KEV names, exact CVE ids, EPSS rows without a score skipped, never 0) and traces what it served,
// labelled "snapshot" with the capture date. Gaps are never filled in: a CVE the capture did not read has no NVD
// ranges here (state "error", "not in the sample snapshot"), so the pipeline's fail-closed rules apply to it.
import type {
  EpssScore, InventoryRow, KevEntry, KevPair, NvdProductHit, NvdRange, Queries, Tracer,
} from "../contracts.ts";
import { ConfigError } from "../config.ts";
import { cleanCveIds } from "../adapters/queries.ts";
import { normaliseCveId } from "../adapters/nvd.ts";
import type { NvdLookupStatus } from "../adapters/nvd.ts";
import { DEFAULT_SNAPSHOT_FILE, SNAPSHOT_REL_PATH, SnapshotError, dayOf, loadSnapshot } from "./snapshot.ts";
import type { SampleSnapshot } from "./snapshot.ts";

/** What a sample run reports about its data (for the run manifest and the report banner). */
export interface SnapshotInfo {
  file: string;
  captured_at: string;
  captured_day: string;
  inventory_day: string;
  kev_catalog_version: string | null;
  kev_scope: SampleSnapshot["sources"]["kev"]["scope"];
  epss_score_dates: string[];
  nvd_cves: number;
}

export interface SampleQueries extends Queries {
  /** Per-lookup NVD states, the shape the fact store reads from the live NVD adapter. */
  nvdStatus(): NvdLookupStatus[];
  /** A sample lookup never costs an NVD request, so it never counts against the run's NVD budget. */
  nvdCached(cveId: string): boolean;
  snapshotInfo(): SnapshotInfo;
}

export interface SampleQueriesConfig {
  tracer: Tracer;
  /** Another snapshot file (default data/sample/snapshot.json). */
  file?: string;
  /** An in-memory snapshot (tests); wins over `file`. */
  snapshot?: SampleSnapshot;
}

const lowerTrim = (s: string | null | undefined): string => String(s ?? "").trim().toLowerCase();
const pairKey = (vendor: string, product: string): string => `${lowerTrim(vendor)}\u0000${lowerTrim(product)}`;
const clone = <T>(x: T): T => structuredClone(x);

function kevSort(a: KevEntry, b: KevEntry): number {
  return a.vendor.localeCompare(b.vendor) || a.product.localeCompare(b.product) || a.cve_id.localeCompare(b.cve_id);
}

export function createSampleQueries(cfg: SampleQueriesConfig): SampleQueries {
  const { tracer } = cfg;
  const file = cfg.file ?? DEFAULT_SNAPSHOT_FILE;
  let snap: SampleSnapshot;
  try {
    snap = cfg.snapshot ?? loadSnapshot(file);
  } catch (e) {
    if (e instanceof SnapshotError) throw new ConfigError(`sample mode cannot start: ${e.message}`);
    throw e;
  }
  const where = cfg.snapshot ? "in-memory snapshot" : file === DEFAULT_SNAPSHOT_FILE ? SNAPSHOT_REL_PATH : file;
  const src = snap.sources;

  // indexes, built once per run
  const byPair = new Map<string, KevEntry[]>();
  const byCve = new Map<string, KevEntry[]>();
  for (const e of snap.kev_entries) {
    const k = pairKey(e.vendor, e.product);
    (byPair.get(k) ?? byPair.set(k, []).get(k)!).push(e);
    const c = e.cve_id.trim().toUpperCase();
    (byCve.get(c) ?? byCve.set(c, []).get(c)!).push(e);
  }
  // a full-catalogue snapshot has no gap (a vendor missing from it is missing from KEV); a vendor slice can have one
  const coveredVendors = src.kev.scope === "inventory_vendors" ? new Set(snap.kev_entries.map((e) => lowerTrim(e.vendor))) : null;
  const epssBy = new Map<string, EpssScore>();
  for (const s of snap.epss) epssBy.set(s.cve_id.trim().toUpperCase(), s);
  const epssAsked = new Set(snap.epss_requested.map((c) => c.trim().toUpperCase()));
  const nvdBy = new Map(Object.entries(snap.nvd).map(([k, v]) => [k.trim().toUpperCase(), v]));
  const nvdErr = new Map(Object.entries(snap.nvd_errors ?? {}).map(([k, v]) => [k.trim().toUpperCase(), v]));
  const statuses: NvdLookupStatus[] = [];

  const emit = (action: string, status: "ok" | "fallback" | "error", input: string, output: string, details: Record<string, unknown> = {}): void => {
    try {
      tracer.emit({
        agent: "sample_store", action, status, input_summary: input, output_summary: output,
        details: { query: action, source: "snapshot", file: where, ...details },
      });
    } catch { /* tracing never breaks a query */ }
  };
  const noteInvalid = (q: string, invalid: string[]): void => {
    if (invalid.length) emit("invalid_cve_ids", "error", `${q}: ${invalid.length} id(s) not shaped like CVE-YYYY-NNNN`, "ignored; no score or listing can exist for them", { where: q, invalid: invalid.slice(0, 20) });
  };

  emit("snapshot_loaded", "ok", where,
    `sample snapshot captured ${dayOf(snap.captured_at)} through Zetaris: ${snap.inventory.length} inventory rows, ${snap.kev_entries.length} KEV entries (catalog ${src.kev.catalog_version ?? "?"}), ${snap.epss.length} EPSS scores (${src.epss.score_dates.join(", ") || "no date"}), ${nvdBy.size} NVD records; no network in this run`,
    {
      captured_at: snap.captured_at, kev_scope: src.kev.scope, kev_pairs: snap.kev_pairs.length,
      sources: Object.fromEntries(Object.entries(src).map(([k, v]) => [k, { object: v.object, captured_at: v.captured_at }])),
    });

  function kevFor(pairs: KevPair[]): { out: KevEntry[]; uncovered: string[] } {
    const keys = new Map<string, KevPair>();
    for (const p of pairs ?? []) {
      const v = lowerTrim(p?.vendor);
      const pr = lowerTrim(p?.product);
      if (v && pr) keys.set(`${v}\u0000${pr}`, p);
    }
    const out: KevEntry[] = [];
    const uncovered = new Set<string>();
    for (const [k, p] of keys) {
      const got = byPair.get(k);
      if (got) out.push(...got);
      else if (coveredVendors && !coveredVendors.has(lowerTrim(p.vendor))) uncovered.add(p.vendor.trim());
    }
    return { out: out.sort(kevSort), uncovered: [...uncovered].sort() };
  }

  function scores(cveIds: string[], q: string): EpssScore[] {
    const { valid, invalid } = cleanCveIds(cveIds ?? []);
    noteInvalid(q, invalid);
    const out: EpssScore[] = [];
    const notAsked: string[] = [];
    let noScore = 0;
    for (const id of valid) {
      const s = epssBy.get(id);
      if (s) out.push(clone(s));
      else if (epssAsked.has(id)) noScore++;
      else notAsked.push(id);
    }
    emit(q, notAsked.length ? "fallback" : "ok", `${valid.length} CVE(s)`,
      `${out.length} score(s) from the snapshot (score date ${src.epss.score_dates.join(", ") || "?"})${noScore ? `; ${noScore} had no EPSS score at capture` : ""}${notAsked.length ? `; ${notAsked.length} not in the snapshot (no score; never treated as 0)` : ""}`,
      { requested: valid.length, scored: out.length, no_score_at_capture: noScore, not_in_snapshot: notAsked.slice(0, 20), captured_at: src.epss.captured_at });
    return out;
  }

  return {
    async inventory(): Promise<InventoryRow[]> {
      emit("inventory", "ok", "el.inventory (synthetic)", `${snap.inventory.length} row(s) from the snapshot (captured ${dayOf(src.inventory.captured_at)})`, { rows: snap.inventory.length, captured_at: src.inventory.captured_at, object: src.inventory.object });
      return clone(snap.inventory);
    },

    async kevPairs(): Promise<KevPair[]> {
      emit("kevPairs", "ok", "distinct KEV (vendor, product)", `${snap.kev_pairs.length} pair(s) from the snapshot (catalog ${src.kev.catalog_version ?? "?"})`, { pairs: snap.kev_pairs.length, captured_at: src.kev.captured_at });
      return clone(snap.kev_pairs);
    },

    async kevByProducts(pairs: KevPair[]): Promise<KevEntry[]> {
      const { out, uncovered } = kevFor(pairs);
      emit("kevByProducts", uncovered.length ? "fallback" : "ok", `${(pairs ?? []).length} KEV spelling(s)`,
        `${out.length} KEV entr${out.length === 1 ? "y" : "ies"} from the snapshot (catalog ${src.kev.catalog_version ?? "?"})${uncovered.length ? `; vendor(s) outside the snapshot's KEV slice: ${uncovered.slice(0, 5).join(", ")} (those rows fail closed)` : ""}`,
        { entries: out.length, uncovered_vendors: uncovered, kev_scope: src.kev.scope, captured_at: src.kev.captured_at });
      return clone(out);
    },

    async kevVerify(cveIds: string[]): Promise<KevEntry[]> {
      const { valid, invalid } = cleanCveIds(cveIds ?? []);
      noteInvalid("kevVerify", invalid);
      const out = valid.flatMap((id) => byCve.get(id) ?? []).sort(kevSort);
      emit("kevVerify", "ok", `${valid.length} CVE(s)`, `${out.length} KEV listing(s) re-read from the snapshot (not live: sample mode)`, { requested: valid.length, found: out.length, captured_at: src.kev.captured_at });
      return clone(out);
    },

    async epss(cveIds: string[]): Promise<EpssScore[]> {
      return scores(cveIds, "epss");
    },

    async epssVerify(cveIds: string[]): Promise<EpssScore[]> {
      return scores(cveIds, "epssVerify");
    },

    async nvdCves(cveIds: string[]): Promise<NvdRange[]> {
      const out: NvdRange[] = [];
      const seen = new Set<string>();
      for (const raw of cveIds ?? []) {
        const id = normaliseCveId(raw);
        if (!id) {
          statuses.push({ key: String(raw), state: "invalid", table: null, ranges: 0, detail: "not a CVE id; skipped" });
          continue;
        }
        if (seen.has(id)) continue;
        seen.add(id);
        const rec = nvdBy.get(id);
        if (rec) {
          statuses.push({ key: id, state: "cached", table: rec.table, ranges: rec.ranges.length, as_of: rec.as_of, detail: `sample snapshot: read through Zetaris on ${rec.as_of} (${rec.state})` });
          out.push(...clone(rec.ranges));
          emit("nvdCves", "ok", id, `${rec.ranges.length} range(s) from the snapshot (read ${rec.as_of}, ${rec.state})`, { cve_id: id, state: rec.state, as_of: rec.as_of });
        } else {
          const why = nvdErr.has(id) ? `the capture could not read it (${nvdErr.get(id)})` : "not in the sample snapshot";
          statuses.push({ key: id, state: "error", table: null, ranges: 0, detail: why });
          emit("nvdCves", "fallback", id, `no NVD record: ${why}; the version stays unconfirmed (fail-closed)`, { cve_id: id });
        }
      }
      return out;
    },

    async nvdProduct(cpeVendor: string, cpeProduct: string): Promise<NvdProductHit[]> {
      const key = `cpe:${lowerTrim(cpeVendor)}:${lowerTrim(cpeProduct)}`;
      const rec = snap.nvd_products[key];
      if (!rec) {
        statuses.push({ key, state: "error", table: null, ranges: 0, detail: "not in the sample snapshot" });
        emit("nvdProduct", "fallback", key, "no product lookup in the snapshot for this CPE product", { key });
        return [];
      }
      const n = rec.hits.reduce((a, h) => a + h.ranges.length, 0);
      statuses.push({ key, state: "cached", table: rec.table, ranges: n, as_of: rec.as_of, detail: `sample snapshot: read through Zetaris on ${rec.as_of}` });
      emit("nvdProduct", "ok", key, `${rec.hits.length} CVE(s), ${n} range(s) from the snapshot (read ${rec.as_of})`, { key, as_of: rec.as_of });
      return clone(rec.hits);
    },

    nvdStatus(): NvdLookupStatus[] {
      return statuses.map((s) => ({ ...s }));
    },

    nvdCached(_cveId: string): boolean {
      return true;
    },

    snapshotInfo(): SnapshotInfo {
      return {
        file: where, captured_at: snap.captured_at, captured_day: dayOf(snap.captured_at),
        inventory_day: dayOf(src.inventory.captured_at), kev_catalog_version: src.kev.catalog_version,
        kev_scope: src.kev.scope, epss_score_dates: [...src.epss.score_dates], nvd_cves: nvdBy.size,
      };
    },
  };
}
