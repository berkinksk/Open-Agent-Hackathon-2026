// The pipeline (v0): inventory -> KEV names -> candidates (normaliser) -> resolver jury -> KEV entries ->
// EPSS -> NVD ranges (when that helper is live) -> exposure analyst -> reporter -> RunResponse, also
// written to output/run-<id>.json. run() never throws: a bad request or an unreadable inventory becomes a
// structured error response; an unreadable KEV or EPSS source fails closed (ask_owner, never monitor).
// The agents never see SQL: every fact comes through the named Queries of the injected Deps.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_POLICY, MODELS } from "./contracts.ts";
import type {
  Candidate, Deps, EpssScore, InventoryRow, JurorVote, KevEntry, KevPair, Llm, NvdRange, OwnerQuestion,
  PatchLine, Policy, Receipt, Resolution, RunManifest, RunRequest, RunResponse, Tracer,
} from "./contracts.ts";
import { runJury } from "./agents/jury.ts";
import type { JuryItem } from "./agents/jury.ts";
import { whyFor } from "./agents/reporter.ts";
import { assessRow, citeKev, mergePolicy, PolicyError, sortLines, summarise } from "./policy/analyst.ts";
import type { AnalystContext } from "./policy/analyst.ts";
import { candidatesV0, deterministicVoteV0, familyKey, familyV0, parseVersionV0 } from "./resolve/candidates.ts";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_OUTPUT_DIR = join(REPO_ROOT, "output");
export const MAX_ROWS = 200;
export const EPSS_BATCH = 100;
export const MAX_NVD_CVES = 8;
export const MAX_RANGE_EVIDENCE = 4;
export const ENGINE_SOURCE = "Meterless/Meterless@1742dec engines/world-model (Apache-2.0)";

/** What the pipeline needs from the normaliser. v0 lives in resolve/candidates.ts; A1's normaliser plugs in here. */
export interface Pipeline {
  name: string;
  prepare(row: InventoryRow, pairs: KevPair[]): { candidates: Candidate[]; version: string | null };
  family(p: KevPair): string;
  vote(row: InventoryRow, candidates: Candidate[]): JurorVote;
}

export const V0_PIPELINE: Pipeline = {
  name: "candidates-v0",
  prepare: (row, pairs) => ({ candidates: candidatesV0(row.software, pairs), version: parseVersionV0(row.software) }),
  family: familyV0,
  vote: deterministicVoteV0,
};

export interface RunOptions {
  pipeline?: Pipeline;
  /** Where output/run-<id>.json goes; null = do not write (tests). */
  outputDir?: string | null;
}

export class RequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestError";
  }
}

// ---------------------------------------------------------------- input

function text(v: unknown): string {
  return typeof v === "string" ? v.trim() : typeof v === "number" && Number.isFinite(v) ? String(v) : "";
}

function toBool(v: unknown): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  return /^(1|true|yes|y|on)$/i.test(text(v));
}

/**
 * Inventory rows from the request (strict: a bad row is an error) or from Queries (lenient: a bad row is
 * skipped and reported). Only `software` is required; the other fields get safe defaults.
 */
export function normaliseInventory(input: unknown, opts: { strict: boolean }): { rows: InventoryRow[]; skipped: string[] } {
  if (!Array.isArray(input)) throw new RequestError("inventory must be an array of rows");
  const rows: InventoryRow[] = [];
  const skipped: string[] = [];
  const ids = new Set<string>();
  input.forEach((raw, i) => {
    const fail = (why: string): void => {
      if (opts.strict) throw new RequestError(`inventory[${i}]: ${why}`);
      skipped.push(`row ${i + 1}: ${why}`);
    };
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return fail("not an object");
    const r = raw as Record<string, unknown>;
    const software = text(r.software);
    if (!software) return fail("software is missing");
    if (software.length > 300) return fail("software is longer than 300 characters");
    const row_id = text(r.row_id) || `R${String(i + 1).padStart(2, "0")}`;
    if (ids.has(row_id)) return fail(`duplicate row_id ${row_id}`);
    ids.add(row_id);
    const asset_id = text(r.asset_id) || `A${String(i + 1).padStart(2, "0")}`;
    rows.push({
      row_id, asset_id, asset_name: text(r.asset_name) || asset_id, asset_type: text(r.asset_type) || "unknown",
      internet_facing: toBool(r.internet_facing), owner_team: text(r.owner_team), software,
    });
  });
  return { rows, skipped };
}

function filterRows(rows: InventoryRow[], ids: unknown): { rows: InventoryRow[]; missing: string[] } {
  if (ids === undefined || ids === null) return { rows, missing: [] };
  if (!Array.isArray(ids) || ids.some((x) => typeof x !== "string")) throw new RequestError("row_ids must be an array of strings");
  const want = [...new Set((ids as string[]).map((s) => s.trim()).filter(Boolean))];
  const have = new Set(rows.map((r) => r.row_id));
  const out = rows.filter((r) => want.includes(r.row_id));
  if (!out.length) throw new RequestError(`none of the requested row_ids are in the inventory: ${want.slice(0, 5).join(", ")}`);
  return { rows: out, missing: want.filter((id) => !have.has(id)) };
}

// ---------------------------------------------------------------- helpers

function msg(e: unknown): string {
  return String((e as Error)?.message ?? e).replace(/\s+/g, " ").trim().slice(0, 300);
}

function isDormant(e: unknown): boolean {
  return /^dormant\b/i.test(msg(e));
}

function chunk<T>(xs: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}

function safeFileId(id: string): string {
  return id.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 80) || "run";
}

/** Wraps the model client so every receipt (ok or error) lands in the run's receipt list. */
function recordingLlm(inner: Llm, sink: Receipt[]): Llm {
  return {
    async chat(req) {
      try {
        const r = await inner.chat(req);
        sink.push(r.receipt);
        return r;
      } catch (e) {
        const receipt: Receipt = {
          call_id: "client-error", agent: req.agent, requested_model: MODELS[req.model], response_model: null,
          routed_model: null, receipt_id: null, latency_ms: 0, status: "error", error: msg(e),
        };
        sink.push(receipt);
        return { text: "", json: null, receipt };
      }
    },
  };
}

/** One score per CVE (the latest score date), with numbers coerced and non-numbers dropped. */
function epssIndex(scores: EpssScore[]): Map<string, EpssScore> {
  const out = new Map<string, EpssScore>();
  for (const s of scores) {
    const score: EpssScore = { cve_id: String(s?.cve_id ?? ""), epss: Number(s?.epss), percentile: Number(s?.percentile), score_date: String(s?.score_date ?? "") };
    if (!score.cve_id || !Number.isFinite(score.epss)) continue;
    const prev = out.get(score.cve_id);
    if (!prev || score.score_date > prev.score_date) out.set(score.cve_id, score);
  }
  return out;
}

function rangeText(r: NvdRange): string {
  const parts = [
    r.version_start_including && `>= ${r.version_start_including}`, r.version_start_excluding && `> ${r.version_start_excluding}`,
    r.version_end_including && `<= ${r.version_end_including}`, r.version_end_excluding && `< ${r.version_end_excluding}`,
  ].filter(Boolean);
  return `${r.criteria}${parts.length ? ` ${parts.join(" ")}` : ""}`;
}

function writeOutput(dir: string, res: RunResponse, tracer: Tracer): void {
  try {
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `run-${safeFileId(res.run_id)}.json`);
    writeFileSync(file, `${JSON.stringify(res, null, 2)}\n`, "utf8");
    tracer.emit({ agent: "pipeline", action: "output_written", status: "ok", output_summary: file });
  } catch (e) {
    tracer.emit({ agent: "pipeline", action: "output_written", status: "error", output_summary: `could not write the run JSON: ${msg(e)}` });
  }
}

// ---------------------------------------------------------------- run

export async function run(req: RunRequest, deps: Deps): Promise<RunResponse> {
  return runWith(req, deps);
}

export async function runWith(req: RunRequest, deps: Deps, opts: RunOptions = {}): Promise<RunResponse> {
  const pipeline = opts.pipeline ?? V0_PIPELINE;
  const outputDir = opts.outputDir === undefined ? DEFAULT_OUTPUT_DIR : opts.outputDir;
  const { tracer } = deps;
  const t0 = performance.now();
  const timing: Record<string, number> = {};
  const started_at = deps.clock.now().toISOString();
  const as_of = started_at.slice(0, 10);
  const live = deps.mode === "live";
  const receipts: Receipt[] = [];
  const llm = deps.llm ? recordingLlm(deps.llm, receipts) : null;
  const helpers_live: string[] = [];
  const helpers_dormant: string[] = [];
  const problems: string[] = [];
  const sources: RunManifest["sources"] = [];
  let policy: Policy = deps.policy ?? DEFAULT_POLICY;

  const timed = async <T>(key: string, fn: () => Promise<T> | T): Promise<T> => {
    const s = performance.now();
    try {
      return await fn();
    } finally {
      timing[key] = (timing[key] ?? 0) + Math.round(performance.now() - s);
    }
  };

  const respond = (status: RunResponse["status"], lines: PatchLine[], owner_questions: OwnerQuestion[], error?: RunResponse["error"]): RunResponse => {
    timing.total = Math.round(performance.now() - t0);
    const response: RunResponse = {
      run_id: tracer.run_id, mode: deps.mode, status, started_at, finished_at: deps.clock.now().toISOString(), as_of,
      timing_ms: timing, summary: summarise(lines), lines, owner_questions, receipts,
      trace_file: tracer.file, report_file: null,
      manifest: { engine: "world-model", engine_source: ENGINE_SOURCE, sources, models: MODELS, helpers_live, helpers_dormant, policy },
      ...(error ? { error } : {}),
    };
    tracer.emit({
      agent: "pipeline", action: status === "error" ? "run_error" : "run_complete", status: status === "error" ? "error" : status === "partial" ? "fallback" : "ok",
      output_summary: error
        ? `${error.type}: ${error.message}`
        : `${status}: ${response.summary.patch_now} patch_now, ${response.summary.this_cycle} this_cycle, ${response.summary.ask_owner} ask_owner, ${response.summary.monitor} monitor in ${timing.total} ms`,
      details: { timing_ms: timing, problems, receipts: receipts.length },
    });
    if (outputDir) writeOutput(outputDir, response, tracer);
    return response;
  };

  try {
    tracer.emit({
      agent: "pipeline", action: "run_start", status: "ok",
      input_summary: `mode ${deps.mode}; ${req.inventory !== undefined ? `${Array.isArray(req.inventory) ? req.inventory.length : "?"} rows in the request` : "inventory from Queries"}${req.row_ids ? `; row_ids ${req.row_ids.length}` : ""}`,
      details: { pipeline: pipeline.name, as_of, models: MODELS },
    });
    try {
      policy = mergePolicy(deps.policy ?? DEFAULT_POLICY, req.policy);
    } catch (e) {
      if (e instanceof PolicyError) return respond("error", [], [], { type: "invalid_request", message: e.message, recoverable: true });
      throw e;
    }

    // 1. Inventory: the request's rows, or el.inventory through Queries.
    const inventoryFrom: AnalystContext["inventoryFrom"] = req.inventory !== undefined ? "request" : "zetaris";
    let rows: InventoryRow[];
    try {
      const raw = req.inventory !== undefined ? req.inventory : await timed("inventory", () => deps.queries.inventory());
      const { rows: all, skipped } = normaliseInventory(raw, { strict: inventoryFrom === "request" });
      if (skipped.length) {
        tracer.emit({ agent: "pipeline", action: "inventory_rows_skipped", status: "error", output_summary: `${skipped.length} unusable inventory row(s) skipped`, details: { skipped } });
      }
      const picked = filterRows(all, req.row_ids);
      rows = picked.rows;
      if (picked.missing.length) {
        tracer.emit({ agent: "pipeline", action: "row_ids_missing", status: "error", output_summary: `${picked.missing.length} requested row_id(s) not in the inventory`, details: { missing: picked.missing } });
      }
      if (!rows.length) throw new RequestError("the inventory has no usable rows");
      if (rows.length > MAX_ROWS) throw new RequestError(`too many rows: ${rows.length} (at most ${MAX_ROWS} per run)`);
    } catch (e) {
      if (e instanceof RequestError) return respond("error", [], [], { type: "invalid_request", message: e.message, recoverable: true });
      return respond("error", [], [], { type: "inventory_unavailable", message: msg(e), recoverable: true });
    }
    sources.push({
      name: inventoryFrom === "request" ? "Inventory (request rows)" : "Inventory (synthetic)",
      object: inventoryFrom === "request" ? "run request" : live ? "el.inventory" : "sample snapshot (el.inventory)",
      live: inventoryFrom === "zetaris" && live, as_of,
    });
    tracer.emit({
      agent: "pipeline", action: "inventory_loaded", target_agent: "normaliser", status: "ok",
      output_summary: `${rows.length} row(s) from ${inventoryFrom === "request" ? "the request" : live ? "Zetaris el.inventory" : "the sample snapshot"}`,
    });

    // 2. KEV names (distinct vendor, product).
    let pairs: KevPair[] = [];
    let kevPairsError: string | null = null;
    try {
      const got = await timed("kev_pairs", () => deps.queries.kevPairs());
      if (!Array.isArray(got)) throw new Error("kevPairs returned no list");
      // KEV always lists products; an empty answer is a failed read, not "nothing is exploited".
      if (got.length === 0) throw new Error("KEV returned no (vendor, product) pairs");
      pairs = got;
    } catch (e) {
      kevPairsError = msg(e);
      problems.push("kev_pairs");
    }
    tracer.emit({
      agent: "pipeline", action: "kev_pairs", status: kevPairsError ? "error" : "ok",
      output_summary: kevPairsError ? `KEV names unavailable (${kevPairsError}); every row fails closed to ask_owner` : `${pairs.length} distinct KEV (vendor, product) pairs`,
    });

    // 3. Normaliser: candidates and version per row.
    const items: JuryItem[] = await timed("normalise", () => rows.map((row) => {
      const p = pipeline.prepare(row, pairs);
      return { row, candidates: p.candidates, version: p.version };
    }));
    const withCands = items.filter((i) => i.candidates.length).length;
    tracer.emit({
      agent: "normaliser", action: "candidates_built", target_agent: "resolver_jury", status: "ok",
      output_summary: `${items.length} row(s): ${withCands} with KEV candidates, ${items.length - withCands} without`,
      details: {
        pipeline: pipeline.name,
        rows: items.map((i) => ({ row_id: i.row.row_id, version: i.version, top: i.candidates.slice(0, 3).map((c) => `${c.family} (${c.score})`) })),
      },
    });

    // 4. Resolver jury (Bolt + Lightning, Ultra on splits; deterministic without a model).
    let resolutions: Resolution[] = [];
    if (!kevPairsError) {
      const out = await timed("jury", () => runJury(items, { llm, tracer, mode: deps.mode, fallbackVote: (it) => pipeline.vote(it.row, it.candidates) }));
      resolutions = out.resolutions;
      if (live && !llm) problems.push("no_model_client");
      if (out.stats.failed_calls) problems.push("model_calls_failed");
      if (live && out.stats.deterministic) problems.push("jury_fallback");
      tracer.emit({ agent: "resolver_jury", action: "handoff", target_agent: "exposure_analyst", status: "ok", output_summary: `${resolutions.filter((r) => r.status === "matched").length} matched, ${resolutions.filter((r) => r.status === "no_match").length} no_match, ${resolutions.filter((r) => r.status === "unresolved").length} unresolved` });
    }

    // 5. Facts for the matched families: KEV entries (every spelling of the family), EPSS, NVD ranges.
    const familyPairs = new Map<string, KevPair[]>();
    for (const p of pairs) {
      const k = familyKey(pipeline.family(p));
      const list = familyPairs.get(k);
      if (list) list.push(p);
      else familyPairs.set(k, [p]);
    }
    const families = [...new Set(resolutions.filter((r) => r.status === "matched" && r.family).map((r) => familyKey(r.family as string)))];
    const wanted = families.flatMap((f) => familyPairs.get(f) ?? []);
    let kevEntries: KevEntry[] = [];
    let kevError: string | null = null;
    if (wanted.length) {
      try {
        kevEntries = await timed("facts", () => deps.queries.kevByProducts(wanted));
      } catch (e) {
        kevError = msg(e);
        problems.push("kev_entries");
      }
      tracer.emit({
        agent: "exposure_analyst", action: "kev_lookup", status: kevError ? "error" : "ok",
        input_summary: `${wanted.length} KEV spelling(s) for ${families.length} matched famil${families.length === 1 ? "y" : "ies"}`,
        output_summary: kevError ? `KEV entries unavailable (${kevError}); matched rows fail closed` : `${kevEntries.length} KEV entries`,
      });
    }
    const kevByFamily = new Map<string, KevEntry[]>();
    for (const e of kevEntries) {
      const k = familyKey(pipeline.family(e));
      const list = kevByFamily.get(k);
      if (list) list.push(e);
      else kevByFamily.set(k, [e]);
    }
    const catalogVersion = kevEntries.find((e) => e.catalog_version)?.catalog_version ?? null;
    sources.push({ name: "CISA KEV", object: live ? "el.kev" : "sample snapshot (el.kev)", live, ...(catalogVersion ? { as_of: catalogVersion } : {}) });

    const citedByFamily = new Map(families.map((f) => [f, citeKev(kevByFamily.get(f) ?? [])]));
    const cited = [...new Set([...citedByFamily.values()].flat().map((e) => e.cve_id))].sort();
    const epssScores: EpssScore[] = [];
    let epssError: string | null = null;
    if (cited.length) {
      try {
        for (const batch of chunk(cited, EPSS_BATCH)) epssScores.push(...await timed("facts", () => deps.queries.epss(batch)));
      } catch (e) {
        epssError = msg(e);
        problems.push("epss");
      }
      tracer.emit({
        agent: "exposure_analyst", action: "epss_lookup", status: epssError ? "error" : "ok",
        input_summary: `${cited.length} cited CVE(s) in ${Math.ceil(cited.length / EPSS_BATCH)} batch(es)`,
        output_summary: epssError ? `EPSS unavailable (${epssError}); nothing is relaxed to monitor` : `${epssScores.length} EPSS score(s)`,
      });
    }
    const epssByCve = epssIndex(epssScores);
    const epssDate = [...epssByCve.values()].map((s) => s.score_date).filter(Boolean).sort().pop();
    sources.push({ name: "FIRST EPSS", object: live ? "EL_EPSS.el_epss_<batch>" : "sample snapshot (EPSS)", live, ...(epssDate ? { as_of: epssDate } : {}) });

    const deciding = [...new Set(families.map((f) => citedByFamily.get(f)?.[0]?.cve_id).filter((x): x is string => !!x))].slice(0, MAX_NVD_CVES);
    const nvdByCve = new Map<string, NvdRange[]>();
    let nvdLive = false;
    if (deciding.length) {
      try {
        const ranges = await timed("facts", () => deps.queries.nvdCves(deciding));
        for (const r of ranges) {
          const list = nvdByCve.get(r.cve_id);
          if (list) list.push(r);
          else nvdByCve.set(r.cve_id, [r]);
        }
        nvdLive = true;
        helpers_live.push("nvdCves");
        tracer.emit({ agent: "exposure_analyst", action: "nvd_lookup", status: "ok", input_summary: `${deciding.length} deciding CVE(s)`, output_summary: `${ranges.length} version range(s)` });
      } catch (e) {
        if (isDormant(e)) {
          helpers_dormant.push("nvdCves");
          tracer.emit({ agent: "exposure_analyst", action: "helper_dormant", status: "ok", output_summary: `nvdCves is dormant (${msg(e)}); version ranges are not checked in this run` });
        } else {
          problems.push("nvd");
          tracer.emit({ agent: "exposure_analyst", action: "nvd_lookup", status: "error", output_summary: `NVD ranges unavailable (${msg(e)})` });
        }
      }
    }
    sources.push({ name: "NIST NVD", object: live ? "EL_NVD.el_nvd_<cve>" : "sample snapshot (NVD)", live: live && nvdLive });
    // Not wired into this pipeline build yet; listed so the manifest never over-claims.
    helpers_dormant.push("nvdProduct", "critic", "verifier", "world_model");
    tracer.emit({ agent: "pipeline", action: "helpers", status: "ok", output_summary: `live: ${helpers_live.join(", ") || "none"}; dormant: ${helpers_dormant.join(", ")}` });

    // 6. Exposure analyst (policy as code), then the reporter's "why".
    const ctx: AnalystContext = { asOf: as_of, policy, live, inventoryFrom, kevPairsError, kevByFamily, kevError, catalogVersion, epssByCve, epssError };
    const assessments = await timed("analyst", () => rows.map((row, i) => assessRow(row, resolutions[i], ctx)));
    for (const a of assessments) {
      const deciding0 = a.line.kev?.cves[0]?.cve_id;
      const ranges = deciding0 ? nvdByCve.get(deciding0) ?? [] : [];
      for (const r of ranges.slice(0, MAX_RANGE_EVIDENCE)) {
        a.line.evidence.push({ source: "zetaris:nvd", query: "nvdCves", field: "version_range", value: `${deciding0}: ${rangeText(r)}`, live });
      }
      a.line.why = whyFor(a.line, a.owner, policy);
    }
    const lines = sortLines(assessments.map((a) => a.line));
    const ownerByRow = new Map(assessments.filter((a) => a.owner).map((a) => [a.line.row_id, a.owner as OwnerQuestion]));
    const owner_questions = lines.filter((l) => ownerByRow.has(l.row_id)).map((l) => ownerByRow.get(l.row_id) as OwnerQuestion);
    const s = summarise(lines);
    tracer.emit({
      agent: "exposure_analyst", action: "decisions", target_agent: "reporter", status: "ok",
      output_summary: `${s.patch_now} patch_now, ${s.this_cycle} this_cycle, ${s.ask_owner} ask_owner, ${s.monitor} monitor (as of ${as_of})`,
      details: { lines: lines.map((l) => ({ row_id: l.row_id, decision: l.decision, target_date: l.target_date, overdue_days: l.kev?.overdue_days ?? null, epss: l.epss?.max ?? null })) },
    });
    tracer.emit({ agent: "reporter", action: "why_written", status: "ok", output_summary: `${lines.length} line(s), template wording from structured facts only` });

    return respond(problems.length ? "partial" : "success", lines, owner_questions);
  } catch (e) {
    return respond("error", [], [], { type: "internal_error", message: msg(e), recoverable: false });
  }
}
