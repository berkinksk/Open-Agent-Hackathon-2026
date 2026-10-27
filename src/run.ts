// The pipeline (v1, integrated; design §8):
//   1. inventory (el.inventory through Zetaris, or the request's rows)
//   2. KEV names (distinct vendor, product), once per run
//   3. Normaliser: parse, product type, top-K KEV candidates, the deterministic third vote
//   4. Resolver jury (Bolt + Lightning, Ultra on splits) while the fact store prefetches KEV, EPSS and the
//      deciding NVD CVE for the families the normaliser matched (one Zetaris query at a time)
//   5. Conflict Critic loop: deterministic checks, Ultra on contested approvals, send-backs to the resolver
//      (Lightning, then Ultra), NVD ranges for version evidence, ask_owner after max_critic_rounds
//   6. Exposure Analyst (policy as code) + the critic's verdict -> decisions and dates; Windows rows without a build
//      share one owner question per edition
//   7. Verifier: every cited KEV and EPSS value re-queried live (cache bypassed); a mismatch blocks the line
//   8. World Model: entities, facts with provenance, review queue, audit -> logs/audit-<id>.jsonl, output/world/
//   9. RunResponse -> output/run-<id>.json and output/report-<id>.html (the trace is logs/trace-<id>.jsonl)
// run() never throws: a bad request or an unreadable inventory is a structured error; an unreadable KEV or EPSS
// source fails closed (ask_owner, never monitor). The agents never see SQL: every fact comes through Queries.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_POLICY, MODELS } from "./contracts.ts";
import type {
  Candidate, Deps, Evidence, InventoryRow, JurorVote, KevEntry, KevPair, Llm, NvdRange, OwnerQuestion, ParsedSoftware,
  PatchLine, Policy, ProductType, Receipt, Resolution, RunManifest, RunRequest, RunResponse, Tracer,
} from "./contracts.ts";
import { runJury } from "./agents/jury.ts";
import type { JuryItem } from "./agents/jury.ts";
import { whyConfirmed, whyFor, whyNotAffected, whyVersionUnconfirmed } from "./agents/reporter.ts";
import type { CriticOutcome, CriticRules } from "./agents/critic.ts";
import { verifyLive } from "./agents/verifier.ts";
import { addDays, assessRow, citeKev, mergePolicy, PolicyError, scopeKevToVersion, sortLines, summarise } from "./policy/analyst.ts";
import type { VersionScopeResult } from "./policy/analyst.ts";
import type { AnalystContext } from "./policy/analyst.ts";
import { groupWindowsQuestions, rangesForEdition, WINDOWS_FAMILY, windowsEdition } from "./policy/windows.ts";
import { createLedgerWorld, ENGINE_SOURCE } from "./engine/index.ts";
import type { Explanation } from "./engine/index.ts";
import { reportFileName, writeReport } from "./report/index.ts";
import { FactStore } from "./pipeline/facts.ts";
import type { QueriesWithNvdStatus } from "./pipeline/facts.ts";
import { hasBlocker, runCriticLoop, withNormaliserVote } from "./pipeline/critic-loop.ts";
import { earlierRunsFor, openPreviousWorld, readRunIndex, rowMemoryKey, sinceLastRun, writeRunIndex } from "./pipeline/memory.ts";
import type { CriticLoopStats } from "./pipeline/critic-loop.ts";
import {
  familiesOf, familyOf, kevProductType, matchedKevPart, normaliserVote, parseSoftware, topCandidates,
} from "./resolve/normalise.ts";
import { candidatesV0, deterministicVoteV0, familyKey, familyV0, parseVersionV0 } from "./resolve/candidates.ts";
import { hasVersion, rangesForProduct } from "./resolve/versions.ts";
import { withNetworkGuard } from "./sample/guard.ts";
import type { Discovery, NaiveJoin, NaiveJoinInput } from "./adapters/queries.ts";

export { ENGINE_SOURCE };

/** What the sample store reports about its snapshot (src/sample/queries.ts); absent on the live Queries. */
interface SnapshotAware { snapshotInfo?: () => { file: string; captured_day: string; inventory_day: string } }
/** The live Queries' cache-backed reads (src/adapters/queries.ts sourceStatus): served live, or from the saved copy. */
interface ReadStatusAware { sourceStatus?: () => { query: string; label: string; fromCache: boolean; cachedAt?: string; rows: number }[] }
/** The live Queries' discovery prelude and naive federated join (src/adapters/queries.ts); absent on the sample store. */
interface FederationAware {
  discover?: () => Promise<Discovery>;
  naiveJoin?: (input: NaiveJoinInput) => Promise<NaiveJoin>;
}

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_OUTPUT_DIR = join(REPO_ROOT, "output");
export const MAX_ROWS = 200;
export const EPSS_BATCH = 100;
/** Top-K KEV candidates per row (design §3). */
export const CANDIDATES_K = 12;
/** Wall-time budget for NVD lookups per run (NVD's keyless rate limit: a cold CVE costs ~12 s through Zetaris). */
export const NVD_BUDGET_MS = 60_000;
export const NVD_MAX_CVES = 16;
/** A family with at most this many KEV CVEs is checked in full, so "not affected" can be proven; larger: the 2 newest. */
export const NVD_SMALL_FAMILY = 3;
export const MAX_ULTRA_CRITIQUES = 16;
/**
 * Critic rule switches and Ultra's final match check, as settled by the integration experiments on the dev rows
 * (one variable at a time; see docs/design.md "Changes after testing").
 */
export const CRITIC_RULES: Partial<CriticRules> = { osVsApplication: true, unsureNormaliserIsNoVote: true };
export const ULTRA_MATCH_CHECK = true;
/** Once NVD confirms one KEV CVE of a match, look up the line's other cited CVEs too (within the NVD budget). */
export const COMPLETE_VERSION_CHECK = true;
export const MAX_RANGE_EVIDENCE = 4;

/** What the pipeline needs from the normaliser. A1's normaliser is the default; v0 is kept for comparison. */
export interface Pipeline {
  name: string;
  prepare(row: InventoryRow, pairs: KevPair[], parsed?: ParsedSoftware): { candidates: Candidate[]; version: string | null };
  family(p: KevPair): string;
  vote(row: InventoryRow, candidates: Candidate[], parsed?: ParsedSoftware): JurorVote;
  parse?(row: InventoryRow): ParsedSoftware;
  /** Every family a KEV pair names (combos name several); default [family(p)]. */
  families?(p: KevPair): string[];
  /** The family and type of the product of `p` this row matched (row-aware for combos); default family(p). */
  matchedFamily?(parsed: ParsedSoftware, p: KevPair): { family: string; product_type: ProductType };
}

export function normaliserPipeline(k = CANDIDATES_K): Pipeline {
  return {
    name: k === CANDIDATES_K ? "normaliser" : `normaliser-k${k}`,
    parse: (row) => parseSoftware(row.software),
    prepare: (row, pairs, parsed) => {
      const p = parsed ?? parseSoftware(row.software);
      return { candidates: topCandidates(p, pairs, k), version: p.version };
    },
    family: familyOf,
    families: familiesOf,
    matchedFamily: (parsed, p) => {
      const m = matchedKevPart(parsed, p);
      return { family: m.family, product_type: m.product_type };
    },
    vote: (row, cands, parsed) => normaliserVote(row, parsed ?? parseSoftware(row.software), cands),
  };
}

export const NORMALISER_PIPELINE: Pipeline = normaliserPipeline();

/** S2's v0 candidate filter (token overlap): kept for comparison and tests; not the default. */
export const V0_PIPELINE: Pipeline = {
  name: "candidates-v0",
  prepare: (row, pairs) => ({ candidates: candidatesV0(row.software, pairs), version: parseVersionV0(row.software) }),
  family: familyV0,
  vote: (row, cands) => deterministicVoteV0(row, cands),
};

export interface RunOptions {
  pipeline?: Pipeline;
  /** Where output/run-<id>.json, the report and the saved world go; null = write nothing (tests). */
  outputDir?: string | null;
  /** Where the World Model audit goes; default: the trace file's folder (logs/). null = no audit file. */
  logsDir?: string | null;
  nvdBudgetMs?: number;
  nvdMaxCves?: number;
  maxUltraCritiques?: number;
  juryBatchSize?: number;
  criticRules?: Partial<CriticRules>;
  ultraMatchCheck?: boolean;
  /** Complete the version check of confirmed matches (default COMPLETE_VERSION_CHECK). */
  completeVersionCheck?: boolean;
  /** Memory across runs (default: live runs that save their world). False switches it off. */
  memory?: boolean;
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

function safeFileId(id: string): string {
  return id.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 80) || "run";
}

function worldNamespace(id: string): string {
  const s = id.replace(/[^A-Za-z0-9_.-]/g, "_").replace(/^[^A-Za-z0-9]+/, "").slice(0, 100);
  return s || "run";
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

/** The analyst's policy lines (the rule applied, the KEV/EPSS disagreement): replaced when the critic changes the decision. */
function isPolicyRule(e: Evidence): boolean {
  return e.source === "agent" && e.query === "policy" && (e.field === "rule" || e.field === "kev_epss_disagreement");
}

const byDateDesc = (a: KevEntry, b: KevEntry): number =>
  (b.date_added ?? "").localeCompare(a.date_added ?? "") || b.cve_id.localeCompare(a.cve_id);
/** Sort key for "earliest due date first" (an entry without a valid due date last). */
const dueKey = (e: KevEntry): string => (/^\d{4}-\d{2}-\d{2}/.test(e.due_date ?? "") ? e.due_date.slice(0, 10) : "9999-99-99");

function uniqCves(entries: KevEntry[]): string[] {
  return [...new Set([...entries].sort(byDateDesc).map((e) => e.cve_id.trim().toUpperCase()))];
}

/** A few compact provenance items from the World Model's explanation of one line. */
function worldEvidence(x: Explanation): Evidence[] {
  const current = x.items.filter((i) => i.current);
  const at = current.map((i) => i.at).sort().pop();
  const ev: Evidence[] = [{
    source: "world_model", query: `explain(${x.row_id})`, field: "provenance",
    value: `${current.length} current fact(s) about this row, its asset and ${x.cves.length} CVE(s), from ${x.sources.join(", ")}`,
    ...(at ? { as_of: at } : {}), live: false,
  }];
  const res = current.find((i) => i.predicate === "resolves_to" && i.entity_id === x.software.id);
  if (res) {
    const v = res.value as { status?: string; receipt_ids?: string[] };
    ev.push({
      source: "world_model", query: `explain(${x.row_id})`, field: `resolves_to <- ${res.source}`,
      value: `${v.status ?? "?"} by ${res.by ?? "?"}${v.receipt_ids?.length ? `; receipts ${v.receipt_ids.join(", ")}` : ""}`,
      as_of: res.at, live: false,
    });
  }
  if (x.family && x.family.aliases.length > 1) {
    const names = x.family.aliases.filter((a) => a !== x.family?.name);
    ev.push({
      source: "world_model", query: `explain(${x.row_id})`, field: "kev_family_spellings",
      value: `${x.family.name}: ${names.slice(0, 6).join(" | ")}${names.length > 6 ? ` (+${names.length - 6} more)` : ""}`, live: false,
    });
  }
  return ev;
}

/** Why NVD's "not affected" must not relax a KEV-listed patch_now line to monitor; null when it may. */
export type RelaxBlock =
  | { kind: "source_unavailable"; detail: string; what: string }
  | { kind: "uncovered"; detail: string; cves: string[] };

/**
 * NVD placing the version outside every range of the family's KEV CVEs relaxes a patch_now line to monitor only when
 * (1) KEV entries and EPSS were both read in this run (fail-closed, design §5.5: an unreadable source never relaxes a
 * decision to monitor) and (2) the critic's version check covered every KEV CVE the line cites.
 */
export function notAffectedBlock(
  familyCves: string[], cited: Pick<KevEntry, "cve_id">[], ctx: { kevError?: string | null; epssError?: string | null },
): RelaxBlock | null {
  const down = [
    ctx.kevError ? { what: "the KEV entries", why: String(ctx.kevError).slice(0, 160) } : null,
    ctx.epssError ? { what: "FIRST EPSS", why: String(ctx.epssError).slice(0, 160) } : null,
  ].filter((x): x is { what: string; why: string } => !!x);
  if (down.length) {
    return {
      kind: "source_unavailable",
      what: `${down.map((d) => d.what).join(" and ")} could not be read`,
      detail: down.map((d) => `${d.what} could not be read (${d.why})`).join("; "),
    };
  }
  const have = new Set(familyCves.map((c) => String(c ?? "").trim().toUpperCase()));
  const missing = [...new Set(cited.map((e) => String(e.cve_id ?? "").trim().toUpperCase()))].filter((c) => c && !have.has(c));
  if (missing.length) {
    return { kind: "uncovered", cves: missing, detail: `the version check did not cover ${missing.length} cited KEV CVE(s): ${missing.slice(0, 3).join(", ")}${missing.length > 3 ? ` and ${missing.length - 3} more` : ""}` };
  }
  return null;
}

/** What the naive join found for one row, next to the agents' answer. */
export interface NaiveJoinRowCompare {
  row_id: string;
  naive: string[];          // "vendor / product" hits of the plain join
  agents: string | null;    // the agents' KEV product, null = no KEV product or left to the owner
  outcome: "agree" | "naive_only" | "naive_other" | "agents_only" | "neither" | "owner";
}

/**
 * Sets the naive join's hits against the agents' final answers, row by row: agree (a hit names the agents' family),
 * naive_only (hits, but the agents found no KEV product: look-alikes such as "Word" in "Word Online"), naive_other (hits,
 * but on other products than the agents' match), agents_only (the agents matched a family the join missed), neither,
 * owner (the agents left the row to the owner).
 */
export function compareNaiveJoin(
  rows: InventoryRow[], hits: { row_id: string; vendor: string; product: string }[],
  resOf: (rowId: string) => Resolution | undefined, familiesOf: (p: KevPair) => string[],
): { rows: NaiveJoinRowCompare[]; counts: Record<NaiveJoinRowCompare["outcome"] | "rows" | "rows_hit", number>; summary: string } {
  const byRow = new Map<string, { vendor: string; product: string }[]>();
  for (const h of hits) byRow.set(h.row_id, [...(byRow.get(h.row_id) ?? []), h]);
  const out: NaiveJoinRowCompare[] = rows.map((r) => {
    const naive = byRow.get(r.row_id) ?? [];
    const res = resOf(r.row_id);
    const label = (p: { vendor: string; product: string }) => `${p.vendor.trim()} / ${p.product.trim()}`;
    const naiveText = [...new Set(naive.map(label))];
    if (!res || res.status === "unresolved") return { row_id: r.row_id, naive: naiveText, agents: null, outcome: "owner" };
    if (res.status !== "matched" || !res.vendor || !res.product) {
      return { row_id: r.row_id, naive: naiveText, agents: null, outcome: naive.length ? "naive_only" : "neither" };
    }
    const fam = res.family ? familyKey(res.family) : null;
    const famsOfRes = new Set([...(fam ? [fam] : []), ...familiesOf({ vendor: res.vendor, product: res.product }).map(familyKey)]);
    const agree = naive.some((h) => familiesOf(h).some((f) => famsOfRes.has(familyKey(f))));
    const agents = label({ vendor: res.vendor, product: res.product });
    return { row_id: r.row_id, naive: naiveText, agents, outcome: agree ? "agree" : naive.length ? "naive_other" : "agents_only" };
  });
  const c = (o: NaiveJoinRowCompare["outcome"]) => out.filter((x) => x.outcome === o).length;
  const counts = {
    rows: out.length, rows_hit: out.filter((x) => x.naive.length).length,
    agree: c("agree"), naive_only: c("naive_only"), naive_other: c("naive_other"), agents_only: c("agents_only"), neither: c("neither"), owner: c("owner"),
  };
  const summary = `a plain SQL join of the inventory and KEV inside Zetaris (KEV product name inside the software text) hits ${counts.rows_hit} of ${counts.rows} row(s): `
    + `${counts.agree} agree with the agents, ${counts.naive_only} are look-alikes the agents found no KEV product for, ${counts.naive_other} name another product than the agents' match; `
    + `the agents resolve ${counts.agents_only} row(s) the join misses${counts.owner ? `, and leave ${counts.owner} to the owner` : ""}`;
  return { rows: out, counts, summary };
}

// ---------------------------------------------------------------- run

export async function run(req: RunRequest, deps: Deps): Promise<RunResponse> {
  const opts = runOptionsFromEnv(process.env);
  // sample mode (design §10): no network at all; fetch and net.Socket.connect throw for the whole run
  if (deps.mode === "sample") return withNetworkGuard(() => runWith(req, deps, opts), { tracer: deps.tracer });
  return runWith(req, deps, opts);
}

/** Operator knobs read by run(): EL_NVD_BUDGET_S (seconds of NVD lookups per run; default 60). */
export function runOptionsFromEnv(env: Record<string, string | undefined>): RunOptions {
  const raw = env.EL_NVD_BUDGET_S;
  const s = raw === undefined || raw.trim() === "" ? Number.NaN : Number(raw);
  return Number.isFinite(s) && s >= 0 && s <= 1800 ? { nvdBudgetMs: Math.round(s * 1000), nvdMaxCves: Math.max(NVD_MAX_CVES, Math.ceil(s / 6)) } : {};
}

export async function runWith(req: RunRequest, deps: Deps, opts: RunOptions = {}): Promise<RunResponse> {
  const pipeline = opts.pipeline ?? NORMALISER_PIPELINE;
  const outputDir = opts.outputDir === undefined ? DEFAULT_OUTPUT_DIR : opts.outputDir;
  const logsDir = opts.logsDir === undefined ? (deps.tracer.file ? dirname(deps.tracer.file) : null) : opts.logsDir;
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
  const famsOf = (p: KevPair): string[] => (pipeline.families ? pipeline.families(p) : [pipeline.family(p)]);

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
    let reportFile: string | null = null;
    if (outputDir && !error) {
      try { reportFile = join(outputDir, reportFileName(tracer.run_id)); } catch { reportFile = null; }
    }
    const response: RunResponse = {
      run_id: tracer.run_id, mode: deps.mode, status, started_at, finished_at: deps.clock.now().toISOString(), as_of,
      timing_ms: timing, summary: summarise(lines), lines, owner_questions, receipts,
      trace_file: tracer.file, report_file: reportFile,
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
    if (reportFile && outputDir) {
      try {
        const file = writeReport(response, { dir: outputDir });
        tracer.emit({ agent: "reporter", action: "report_written", status: "ok", output_summary: file });
      } catch (e) {
        response.report_file = null;
        tracer.emit({ agent: "reporter", action: "report_written", status: "error", output_summary: `could not write the HTML report: ${msg(e)}` });
      }
    }
    if (outputDir) writeOutput(outputDir, response, tracer);
    return response;
  };

  try {
    tracer.emit({
      agent: "pipeline", action: "run_start", status: "ok",
      input_summary: `mode ${deps.mode}; ${req.inventory !== undefined ? `${Array.isArray(req.inventory) ? req.inventory.length : "?"} rows in the request` : "inventory from Queries"}${req.row_ids ? `; row_ids ${req.row_ids.length}` : ""}`,
      details: {
        pipeline: pipeline.name, as_of, models: MODELS,
        critic_rules: { ...CRITIC_RULES, ...(opts.criticRules ?? {}) }, ultra_match_check: opts.ultraMatchCheck ?? ULTRA_MATCH_CHECK,
        complete_version_check: opts.completeVersionCheck ?? COMPLETE_VERSION_CHECK,
        nvd_budget_ms: opts.nvdBudgetMs ?? NVD_BUDGET_MS, jury_batch: opts.juryBatchSize ?? 10, candidates_k: CANDIDATES_K,
      },
    });
    // discovery prelude (live): the sources registered in Zetaris, each REST table with its endpoint (display only)
    const fed = deps.queries as FederationAware;
    if (live && typeof fed.discover === "function") {
      try {
        const d = await timed("discovery", () => (fed.discover as () => Promise<Discovery>)());
        helpers_live.push("zetaris.discovery");
        tracer.emit({
          agent: "zetaris", action: "discovery", target_agent: "normaliser", status: "ok", latency_ms: d.ms,
          output_summary: `sources discovered: ${d.databases.length} database(s) (${d.databases.join(", ")}); ${d.tables.map((t) => `${t.db}.${t.name} <- ${t.source.replace(/^https?:\/\//, "").slice(0, 90)}`).join("; ")}`,
          details: { databases: d.databases, tables: d.tables, sql: d.sql, ms: d.ms },
        });
      } catch (e) {
        tracer.emit({ agent: "zetaris", action: "discovery", status: "error", output_summary: `discovery failed (display only; the run goes on): ${msg(e)}` });
      }
    }
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
    // sample mode: the snapshot the facts come from, with its capture date (design §10 "stamped with the snapshot date")
    const snapshot = !live ? (deps.queries as SnapshotAware).snapshotInfo?.() ?? null : null;
    if (snapshot) sources.push({ name: "Sample snapshot", object: `${snapshot.file} (captured through Zetaris)`, live: false, as_of: snapshot.captured_day });
    sources.push({
      name: inventoryFrom === "request" ? "Inventory (request rows)" : "Inventory (synthetic)",
      object: inventoryFrom === "request" ? "run request" : live ? "el.inventory" : "sample snapshot (el.inventory)",
      live: inventoryFrom === "zetaris" && live,
      as_of: snapshot && inventoryFrom === "zetaris" ? snapshot.inventory_day : as_of,
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

    // 3. Normaliser: parse, candidates, version and the deterministic vote per row.
    const parsedBy = new Map<string, ParsedSoftware>();
    const items: JuryItem[] = await timed("normalise", () => rows.map((row) => {
      const parsed0 = pipeline.parse ? pipeline.parse(row) : null;
      const p = pipeline.prepare(row, pairs, parsed0 ?? undefined);
      parsedBy.set(row.row_id, parsed0 ?? { raw: row.software, vendor_hint: null, product_hint: row.software, version: p.version, product_type: "unknown", tokens: [] });
      return { row, candidates: p.candidates, version: p.version };
    }));
    const itemsById = new Map(items.map((i) => [i.row.row_id, i]));
    const normVotes = new Map(items.map((i) => [i.row.row_id, pipeline.vote(i.row, i.candidates, parsedBy.get(i.row.row_id))]));
    const voteKinds = { match: 0, no_match: 0, abstain: 0 };
    for (const v of normVotes.values()) voteKinds[v.vendor && v.product ? "match" : v.confidence >= 0.6 ? "no_match" : "abstain"]++;
    const withCands = items.filter((i) => i.candidates.length).length;
    tracer.emit({
      agent: "normaliser", action: "candidates_built", target_agent: "resolver_jury", status: "ok",
      output_summary: `${items.length} row(s): ${withCands} with KEV candidates, ${items.length - withCands} without; normaliser vote: ${voteKinds.match} match, ${voteKinds.no_match} no match, ${voteKinds.abstain} unsure`,
      details: {
        pipeline: pipeline.name,
        rows: items.map((i) => {
          const v = normVotes.get(i.row.row_id);
          const p = parsedBy.get(i.row.row_id);
          return {
            row_id: i.row.row_id, version: i.version, type: p?.product_type ?? "unknown",
            vote: v?.vendor ? `${v.vendor} / ${v.product}` : v && v.confidence >= 0.6 ? "none" : "unsure",
            top: i.candidates.slice(0, 3).map((c) => `${c.family} (${c.score})`),
          };
        }),
      },
    });

    // The fact store and the run's NVD plan.
    const nvdBudgetMs = opts.nvdBudgetMs ?? NVD_BUDGET_MS;
    const facts = new FactStore({
      queries: deps.queries as QueriesWithNvdStatus, tracer, pairs, familiesOf: famsOf, timed,
      nvdBudgetMs, nvdMaxCves: opts.nvdMaxCves ?? NVD_MAX_CVES,
    });
    const rowFamily = (row: InventoryRow, res: Pick<Resolution, "status" | "vendor" | "product" | "family">): string | null => {
      if (res.status !== "matched" || !res.vendor || !res.product) return null;
      const parsed = parsedBy.get(row.row_id);
      if (pipeline.matchedFamily && parsed) return pipeline.matchedFamily(parsed, { vendor: res.vendor, product: res.product }).family;
      return res.family ?? pipeline.family({ vendor: res.vendor, product: res.product });
    };
    const isWindows = (fam: string | null): boolean => !!fam && familyKey(fam) === WINDOWS_FAMILY;
    const usableVersion = (row: InventoryRow, res: Pick<Resolution, "version">): string | null => {
      const v = res.version ?? parsedBy.get(row.row_id)?.version ?? null;
      return hasVersion(v) ? v : null;
    };
    /** The family CVEs this row's version check may look up in NVD, newest first. */
    const nvdPlanFor = (row: InventoryRow, res: Pick<Resolution, "status" | "vendor" | "product" | "family" | "version">): string[] => {
      const fam = rowFamily(row, res);
      if (!fam) return [];
      const cves = uniqCves(facts.entries(fam));
      if (!cves.length) return [];
      if (isWindows(fam)) return cves.slice(0, 1); // the newest: it names the first fixed build per edition
      if (!usableVersion(row, res)) return [];
      return cves.length <= NVD_SMALL_FAMILY ? cves : cves.slice(0, 2);
    };
    const citedOf = (fam: string): string[] => citeKev(facts.entries(fam)).map((e) => e.cve_id);
    /**
     * live/as_of for NVD evidence resting on these CVEs: live only when every one of them that was looked up was read
     * through Zetaris in this run; today's cache and the client's fallback copy are labelled not live, with their day.
     */
    const nvdRead = (cves: string[]): Pick<Evidence, "live" | "as_of"> => {
      const looked = [...new Set(cves.map((c) => String(c).trim().toUpperCase()))].filter((c) => facts.nvdLooked(c));
      const isLive = live && looked.length > 0 && looked.every((c) => facts.nvdLive(c));
      const days = looked.map((c) => facts.nvdAsOf.get(c)).filter((d): d is string => !!d).sort();
      const day = isLive ? days[days.length - 1] : days[0]; // not live: the oldest day the evidence rests on
      return { live: isLive, ...(day ? { as_of: day } : {}) };
    };

    // 4. Resolver jury, with the fact prefetch for the normaliser's matches running alongside.
    const prefetchRows = items
      .map((i) => ({ i, v: normVotes.get(i.row.row_id) as JurorVote }))
      .filter((x) => x.v?.vendor && x.v.product)
      .sort((a, b) => Number(b.i.row.internet_facing) - Number(a.i.row.internet_facing));
    const asRes = (x: { i: JuryItem; v: JurorVote }) => ({ status: "matched" as const, vendor: x.v.vendor, product: x.v.product, family: null, version: x.i.version });
    let prefetchNvd: Promise<unknown> = Promise.resolve();
    const prefetch = kevPairsError ? Promise.resolve() : (async () => {
      const fams = [...new Set(prefetchRows.map((x) => rowFamily(x.i.row, asRes(x))).filter((f): f is string => !!f))];
      if (!fams.length) return;
      await facts.ensureFamilies(fams, "prefetch for the normaliser's matches, while the jury votes");
      await facts.ensureEpss(fams.flatMap(citedOf));
      const deciding = [...new Set(prefetchRows.map((x) => nvdPlanFor(x.i.row, asRes(x))[0]).filter((c): c is string => !!c))];
      if (deciding.length) prefetchNvd = facts.ensureNvd(deciding, "prefetch: the newest KEV CVE of each family the normaliser matched (internet-facing first)");
    })();

    let resolutions: Resolution[] = [];
    let juryStats: Record<string, unknown> | null = null;
    if (!kevPairsError) {
      const out = await timed("jury", () => runJury(items, {
        llm, tracer, mode: deps.mode, batchSize: opts.juryBatchSize,
        fallbackVote: (it) => normVotes.get(it.row.row_id) as JurorVote,
      }));
      juryStats = { ...out.stats };
      // the normaliser's vote is the third vote the critic scores; the family is the product the row matched
      resolutions = out.resolutions.map((r, idx) => {
        const row = items[idx].row;
        const withVote = withNormaliserVote(r, normVotes.get(row.row_id));
        const fam = rowFamily(row, withVote);
        return fam ? { ...withVote, family: fam } : withVote;
      });
      // a run is partial when model calls failed or no model client exists; a row whose jurors gave no valid
      // answer falls back to the deterministic vote (traced as such) without making the whole run partial
      if (live && !llm) problems.push("no_model_client");
      if (out.stats.failed_calls) problems.push("model_calls_failed");
      tracer.emit({ agent: "resolver_jury", action: "handoff", target_agent: "critic", status: "ok", output_summary: `${resolutions.filter((r) => r.status === "matched").length} matched, ${resolutions.filter((r) => r.status === "no_match").length} no_match, ${resolutions.filter((r) => r.status === "unresolved").length} unresolved` });
    }
    await prefetch;

    // 5. Facts for every matched family, then the critic loop.
    const matchedFams = (rs: Iterable<Resolution>): string[] => [...new Set([...rs].filter((r) => r.status === "matched" && r.family).map((r) => r.family as string))];
    if (!kevPairsError) {
      const fams = matchedFams(resolutions);
      await facts.ensureFamilies(fams, "the jury's matches");
      await facts.ensureEpss(fams.flatMap(citedOf));
    }
    const analystCtx = (): AnalystContext => ({
      asOf: as_of, policy, live, inventoryFrom, kevPairsError, kevByFamily: facts.kevByFamily(), kevError: facts.kevError,
      catalogVersion: facts.catalogVersion(), epssByCve: facts.epssIndex(), epssError: facts.epssError,
    });

    const resById = new Map(resolutions.map((r) => [r.row_id, r]));
    let outcomes = new Map<string, CriticOutcome>();
    let finalRes = resById;
    let loopStats: CriticLoopStats | null = null;
    const criticOn = !kevPairsError && !facts.kevError && resolutions.length === rows.length;
    if (criticOn) {
      const editionOf = new Map(rows.map((r) => [r.row_id, windowsEdition(r.software)]));
      const loop = await timed("critic", () => runCriticLoop({
        rows, items: itemsById, parsed: parsedBy, resolutions: resById, facts, llm, tracer, policy, mode: deps.mode,
        familyOf: pipeline.family, familiesOf: famsOf,
        kevType: (parsed, p) => (pipeline.matchedFamily ? pipeline.matchedFamily(parsed, p).product_type : "unknown"),
        rowFamily: (row, res) => rowFamily(row, res),
        evidenceFor: (row, res) => assessRow(row, res, analystCtx()).line.evidence,
        nvdPlan: nvdPlanFor,
        rangesFilter: (row, res, ranges) => {
          if (!isWindows(rowFamily(row, res))) return ranges;
          const ed = editionOf.get(row.row_id);
          return ed ? rangesForEdition(ed, ranges) : [];
        },
        onResolutionsChanged: async (changed) => {
          const fams = matchedFams(changed.map((c) => {
            const fam = rowFamily(c.row, c.res);
            return fam ? { ...c.res, family: fam } : c.res;
          }));
          await facts.ensureFamilies(fams, "families named by the resolver's re-decide");
          await facts.ensureEpss(fams.flatMap(citedOf));
        },
        maxUltraCritiques: opts.maxUltraCritiques ?? MAX_ULTRA_CRITIQUES,
        criticRules: { ...CRITIC_RULES, ...(opts.criticRules ?? {}) },
        ultraMatchCheck: opts.ultraMatchCheck ?? ULTRA_MATCH_CHECK,
        // once NVD confirms one KEV CVE, the line's other cited CVEs are looked up too (most urgent first: the earliest
        // due date, then the highest EPSS), so the ones NVD places outside are dropped on evidence
        ...((opts.completeVersionCheck ?? COMPLETE_VERSION_CHECK) ? {
          completeVersionCheck: (row: InventoryRow, res: Resolution) => {
            const fam = rowFamily(row, res);
            if (!fam) return [];
            const epssOf = (c: string): number => facts.epssIndex().get(c.trim().toUpperCase())?.epss ?? -1;
            return citeKev(facts.entries(fam))
              .sort((a, b) => dueKey(a).localeCompare(dueKey(b)) || epssOf(b.cve_id) - epssOf(a.cve_id) || a.cve_id.localeCompare(b.cve_id))
              .map((e) => e.cve_id);
          },
        } : {}),
      }));
      outcomes = loop.outcomes;
      loopStats = loop.stats;
      // re-decided rows: the row-aware family again
      finalRes = new Map([...loop.resolutions.entries()].map(([id, r]) => {
        const row = itemsById.get(id)?.row;
        const fam = row ? rowFamily(row, r) : null;
        return [id, fam ? { ...r, family: fam } : r];
      }));
      helpers_live.push("critic");
      if (llm) helpers_live.push("critic.ultra_review"); else helpers_dormant.push("critic.ultra_review (no model client)");
    } else {
      helpers_dormant.push("critic (skipped: KEV unavailable, rows fail closed)");
      tracer.emit({ agent: "critic", action: "skipped", status: "fallback", output_summary: "KEV could not be read, so every row already fails closed to ask_owner; the critic has nothing to review" });
    }
    // re-decides may have named new families; the last NVD reads finish inside the run's budget
    if (!kevPairsError) await facts.ensureEpss(matchedFams(finalRes.values()).flatMap(citedOf));
    await prefetchNvd;
    await facts.settle();
    // Zetaris answered from the client's saved copy (the live read failed): that data is labelled not live, the run is
    // partial, and no line is relaxed to monitor on it (BUILD_KIT: "the cached snapshot, labelled"; design §5.5)
    const readStatus = live ? ((deps.queries as ReadStatusAware).sourceStatus?.() ?? []) : [];
    const fallbackReads = readStatus.filter((x) => x.fromCache);
    const staleOf = (qs: string[]): { day: string } | null => {
      const hit = fallbackReads.filter((x) => qs.includes(x.query));
      if (!hit.length) return null;
      const days = hit.map((x) => String(x.cachedAt ?? "").slice(0, 10)).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort();
      return { day: days[0] ?? "an unknown day" };
    };
    const staleInventory = staleOf(["inventory"]);
    const staleKev = staleOf(["kevPairs", "kevByProducts"]);
    const staleEpss = staleOf(["epss"]);
    if (fallbackReads.length) {
      problems.push("zetaris_fallback");
      tracer.emit({
        agent: "pipeline", action: "zetaris_fallback", status: "fallback",
        output_summary: `${fallbackReads.length} Zetaris read(s) served from the client's cached copy (the live read failed): ${[...new Set(fallbackReads.map((x) => x.query))].join(", ")}; labelled not live, nothing relaxed to monitor on them`,
        details: { reads: fallbackReads },
      });
    }
    const cachedObject = (o: string, day: string): string => `${o} (cached copy saved ${day}; the live read failed)`;
    if (staleInventory) {
      const inv = sources.find((x) => x.name === "Inventory (synthetic)");
      if (inv) Object.assign(inv, { live: false, as_of: staleInventory.day, object: cachedObject(inv.object, staleInventory.day) });
    }
    const nvdLooked = [...facts.nvdState.entries()].filter(([c]) => facts.nvdLooked(c)).map(([c]) => c);
    if (facts.nvdDormant) helpers_dormant.push("nvdCves");
    else if (nvdLooked.length) helpers_live.push("nvdCves");
    // KEV and EPSS are labelled live only when this run read something from them (a read served from the saved copy is
    // the stale case above). Nothing read (Zetaris unreachable with no saved copy, a failed read, or no KEV CVE to
    // score) is labelled not live. KEV: the name list is read first, and every other KEV read needs it.
    const readLive = (qs: string[]): boolean => readStatus.some((x) => qs.includes(x.query) && !x.fromCache);
    const kevRead = !kevPairsError || readLive(["kevPairs", "kevByProducts"]);
    const epssRead = facts.epssScores().length > 0 || readLive(["epss"]);
    const notRead = (o: string, what: string): string => `${o} (no ${what} read in this run)`;
    const catalog = facts.catalogVersion();
    sources.push(staleKev
      ? { name: "CISA KEV", object: cachedObject(`el.kev${catalog ? `, catalog ${catalog}` : ""}`, staleKev.day), live: false, as_of: staleKev.day }
      : live && !kevRead ? { name: "CISA KEV", object: notRead("el.kev", "value"), live: false }
      : { name: "CISA KEV", object: live ? "el.kev" : "sample snapshot (el.kev)", live, ...(catalog ? { as_of: catalog } : {}) });
    const epssDate = facts.epssScores().map((s) => s.score_date).filter(Boolean).sort().pop();
    sources.push(staleEpss
      ? { name: "FIRST EPSS", object: cachedObject(`EL_EPSS.el_epss_<batch>${epssDate ? `, scores of ${epssDate}` : ""}`, staleEpss.day), live: false, as_of: staleEpss.day }
      : live && !epssRead ? { name: "FIRST EPSS", object: notRead("EL_EPSS.el_epss_<batch>", "score"), live: false }
      : { name: "FIRST EPSS", object: live ? "EL_EPSS.el_epss_<batch>" : "sample snapshot (EPSS)", live, ...(epssDate ? { as_of: epssDate } : {}) });
    // NVD is "live" only when this run read some CVE through Zetaris; today's cache is labelled with its day
    const nvdLiveCves = nvdLooked.filter((c) => facts.nvdLive(c));
    const nvdOld = nvdLooked.filter((c) => !facts.nvdLive(c));
    const nvdOldDays = [...new Set(nvdOld.map((c) => facts.nvdAsOf.get(c)).filter((d): d is string => !!d))].sort();
    const nvdCachedText = `${nvdOld.length} cached${nvdOldDays.length ? ` ${nvdOldDays.join(", ")}` : ""}`;
    const nvdIsLive = live && nvdLiveCves.length > 0 && !facts.nvdDormant;
    sources.push({
      name: "NIST NVD",
      object: !live ? "sample snapshot (NVD)"
        : nvdIsLive ? `EL_NVD.el_nvd_<cve>${nvdOld.length ? ` (${nvdLiveCves.length} read live, ${nvdCachedText})` : ""}`
        : nvdOld.length ? `EL_NVD.el_nvd_<cve> (${nvdCachedText})` : "EL_NVD.el_nvd_<cve>",
      live: nvdIsLive,
      ...(!nvdIsLive && nvdOldDays.length ? { as_of: nvdOldDays[0] } : nvdIsLive ? { as_of } : {}),
    });
    helpers_dormant.push("nvdProduct (the this_cycle bucket needs it: empty in this build)");
    if (facts.kevError) problems.push("kev_entries");
    if (facts.epssError) problems.push("epss");

    // 6. Exposure Analyst + the critic's verdict -> decisions; Windows rows share one question per edition.
    const ctx = analystCtx();
    const lineOwner = new Map<string, OwnerQuestion>();
    const versionUnconfirmed = new Set<string>();
    const unresolvedByCritic: string[] = [];
    const notAffected: string[] = [];
    const notAffectedHeld: string[] = [];
    const versionScoped: { row_id: string; basis: VersionScopeResult["basis"]; cited: string[]; inside: string[]; outside: string[]; unchecked_cited: string[] }[] = [];
    // a row the jury never saw (the KEV names could not be read) is unresolved, with the version parsed from its text,
    // as the jury's own unresolved rows carry it (the report's "Resolved" column shows it)
    const noJuryResolution = (row: InventoryRow): Resolution => ({
      row_id: row.row_id, status: "unresolved", vendor: null, product: null, family: null,
      version: itemsById.get(row.row_id)?.version ?? null, product_type: "unknown", votes: [], adjudicated_by: null, confidence: 0,
    });
    const lines0: PatchLine[] = await timed("analyst", () => rows.map((row) => {
      let res = finalRes.get(row.row_id) ?? noJuryResolution(row);
      const o = outcomes.get(row.row_id);
      // the critic rejected the match and no retry fixed it: nothing is matched, the owner decides
      if (res && o && o.verdict.verdict !== "approve" && res.status === "matched" && hasBlocker(o)) {
        res = { ...res, status: "unresolved", vendor: null, product: null, family: null, adjudicated_by: "critic", confidence: 0 };
        finalRes.set(row.row_id, res);
        unresolvedByCritic.push(row.row_id);
      }
      const a = assessRow(row, res, ctx);
      let line = a.line;
      if (!o) {
        if (a.owner) lineOwner.set(row.row_id, a.owner);
        line.why = whyFor(line, a.owner, policy);
        return line;
      }
      // a line cites the KEV CVEs NVD does not rule out for the installed version: NVD's per-CVE check drops only the
      // CVEs it places the version outside; the confirmed ones and the ones not version-checked stay cited, and the due
      // date, overdue days and EPSS come from both (fail-closed)
      const rowVersion = res?.version ?? parsedBy.get(row.row_id)?.version ?? null;
      const scope = scopeKevToVersion(line, o.cve_status, { ...ctx, version: hasVersion(rowVersion) ? rowVersion : null }, (cves) => nvdRead(cves));
      line = scope.line;
      if (scope.changed) {
        versionScoped.push({
          row_id: row.row_id, basis: scope.basis, cited: (line.kev?.cves ?? []).map((e) => e.cve_id),
          inside: scope.inside.map((e) => e.cve_id), outside: scope.outside.map((e) => e.cve_id),
          unchecked_cited: scope.unchecked.map((e) => e.cve_id),
        });
      }
      const whyPatch = (owner: OwnerQuestion | null): string =>
        line.decision === "patch_now" && scope.basis === "inside"
          ? whyConfirmed(line, policy, {
            version: hasVersion(rowVersion) ? rowVersion : null, outside: scope.outside.length, inside: scope.inside.map((e) => e.cve_id),
          })
          : whyFor(line, owner, policy);
      const verdict = o.verdict.verdict === "send_back" ? { ...o.verdict, verdict: "ask_owner" as const } : o.verdict;
      line.critic = verdict;
      const fam = res ? rowFamily(row, res) : null;
      const versionCheck = o.checks.find((c) => c.rule === "version");
      if (verdict.verdict === "approve") {
        if (versionCheck?.pass && (o.version_status === "affected" || o.version_status === "not_affected" || o.version_status === "not_needed")) {
          line.evidence.push({ source: "zetaris:nvd", query: "nvdCves", field: "version_check", value: versionCheck.detail, ...nvdRead(o.family_cves) });
        }
        const relax = o.version_status === "not_affected" && line.decision === "patch_now";
        const block = relax ? notAffectedBlock(o.family_cves, line.kev?.cves ?? [], ctx) : null;
        if (relax && block?.kind === "source_unavailable") {
          // fail-closed (design §5.5): NVD says "not affected", but an unread source never relaxes a line to monitor
          notAffectedHeld.push(row.row_id);
          const version = res?.version ?? parsedBy.get(row.row_id)?.version ?? null;
          const label = (res?.product ?? "the product").trim();
          const cves = o.family_cves;
          const cveText = `${cves.slice(0, 3).join(", ")}${cves.length > 3 ? ` and ${cves.length - 3} more` : ""}`;
          const reason = `KEV lists ${label}, and NVD places version ${version ?? "?"} outside every affected range of ${cveText}, but ${block.detail}, so the line is not relaxed to monitor (fail-closed)`;
          const owner: OwnerQuestion = {
            row_id: row.row_id, asset_name: o.asset_name,
            question: `Can you confirm that ${o.asset_name} runs ${label} ${version ?? "(which version?)"}, outside NVD's affected ranges for ${cveText}? Otherwise re-run when ${block.what.replace(/ could not be read$/, "")} can be read.`,
            reason,
          };
          line.decision = "ask_owner";
          line.target_date = null;
          line.evidence = line.evidence.filter((e) => !isPolicyRule(e));
          line.evidence.push({ source: "agent", query: "policy", field: "rule", value: `ask_owner: ${reason}`.slice(0, 400), live: false });
          lineOwner.set(row.row_id, owner);
          line.why = whyFor(line, owner, policy);
        } else if (relax && block) {
          // the version check did not cover every cited KEV CVE: "not affected" is unproven, so patch_now stays
          notAffectedHeld.push(row.row_id);
          line.evidence.push({ source: "agent", query: "critic", field: "not_affected_unproven", value: `NVD places the version outside the ranges it checked, but ${block.detail}; the line stays patch_now (fail-closed)`, live: false });
          line.why = whyPatch(a.owner);
          if (a.owner) lineOwner.set(row.row_id, a.owner);
        } else if (relax) {
          notAffected.push(row.row_id);
          const version = res?.version ?? parsedBy.get(row.row_id)?.version ?? null;
          line.decision = "monitor";
          line.target_date = addDays(as_of, policy.sla_days.monitor_review);
          line.evidence = line.evidence.filter((e) => !isPolicyRule(e));
          line.evidence.push({ source: "agent", query: "policy", field: "rule", value: `monitor: the installed version is outside every NVD range of the ${o.family_cves.length} KEV CVE(s) of the family; review every ${policy.sla_days.monitor_review} days`, live: false });
          line.why = whyNotAffected(line, policy, { cves: o.family_cves.length, version });
        } else {
          line.why = whyPatch(a.owner);
          if (a.owner) lineOwner.set(row.row_id, a.owner);
        }
      } else {
        const versionOnly = !hasBlocker(o) && res?.status === "matched" && versionCheck !== undefined && !versionCheck.pass;
        if (versionOnly && line.decision === "patch_now" && verdict.rubric.total >= policy.rubric_auto_min) {
          // controller ruling: a KEV-listed family with an unknown or unconfirmable version stays patch_now
          // (fail-closed), flagged "version unconfirmed", with the critic's concrete question attached
          versionUnconfirmed.add(row.row_id);
          line.evidence.push({ source: "agent", query: "critic", field: "version_unconfirmed", value: versionCheck?.detail ?? "version not confirmed", live: false });
          line.evidence.push({ source: "agent", query: "policy", field: "rule", value: "patch_now (fail-closed): KEV-listed, version unconfirmed; the owner confirms the version", live: false });
          if (o.owner_question) lineOwner.set(row.row_id, o.owner_question);
          line.why = whyVersionUnconfirmed(line, policy, {
            ...(isWindows(fam) ? { group: windowsEdition(row.software)?.label ?? "Windows", action: "install the latest cumulative update" } : {}),
            outside: scope.outside.length,
          });
        } else {
          // a match the critic did not approve (rubric, version, Ultra): the owner decides; the KEV listing stays as
          // context while the row is still matched (a rejected match was turned into "unresolved" above)
          line.decision = "ask_owner";
          line.target_date = null;
          if (res?.status !== "matched") { line.kev = null; line.epss = null; }
          const owner = o.owner_question ?? a.owner;
          line.evidence = line.evidence.filter((e) => !isPolicyRule(e));
          line.evidence.push({ source: "agent", query: "policy", field: "rule", value: `ask_owner: ${owner?.reason ?? verdict.reasons.join("; ")}`.slice(0, 400), live: false });
          if (owner) lineOwner.set(row.row_id, owner);
          line.why = whyFor(line, owner, policy);
        }
      }
      // NVD ranges behind the line's version check (the claimed product's CPEs only, at most a few), as cited evidence
      if (o.claimed && (line.decision !== "ask_owner" || notAffectedHeld.includes(row.row_id))) {
        // the cited CVEs' ranges first (after the version scope, the CVEs NVD places the version inside)
        const order = [...new Set([...(line.kev?.cves ?? []).map((e) => e.cve_id.trim().toUpperCase()), ...o.family_cves])];
        const all = order.flatMap((c) => facts.nvdRanges.get(c) ?? []);
        const ed = isWindows(fam) ? windowsEdition(row.software) : null;
        const own = isWindows(fam) ? (ed ? rangesForEdition(ed, all) : []) : rangesForProduct(all, o.claimed.vendor, o.claimed.product);
        const mine = own.filter((r) => r.vulnerable).slice(0, MAX_RANGE_EVIDENCE);
        for (const r of mine) line.evidence.push({ source: "zetaris:nvd", query: "nvdCves", field: "version_range", value: `${r.cve_id}: ${rangeText(r)}`, ...nvdRead([r.cve_id]) });
      }
      return line;
    }));

    // Cached Zetaris copies: their evidence is not live, and a line resting on a cached KEV or EPSS read is never relaxed
    // to monitor (a stale KEV name list could hide a newly listed product): such lines go to the owner (fail-closed)
    const heldStale: string[] = [];
    if (staleInventory || staleKev || staleEpss) {
      const staleNote = [
        staleInventory && `the inventory (cached copy saved ${staleInventory.day})`,
        staleKev && `CISA KEV (cached copy saved ${staleKev.day})`,
        staleEpss && `FIRST EPSS (cached copy saved ${staleEpss.day})`,
      ].filter(Boolean).join(", ");
      for (const l of lines0) {
        l.evidence = l.evidence.map((e) => ((staleKev && e.source === "zetaris:kev") || (staleEpss && e.source === "zetaris:epss") || (staleInventory && e.source === "zetaris:inventory")) ? { ...e, live: false } : e);
        l.evidence.push({ source: "agent", query: "zetaris_fallback", field: "cached_copy", value: `read from the Zetaris client's cached copy because the live read failed: ${staleNote}`, live: false });
        if (l.decision !== "monitor" || !(staleKev || staleEpss)) continue;
        heldStale.push(l.row_id);
        const what = [staleKev && `CISA KEV (served from a cached copy saved ${staleKev.day})`, staleEpss && `FIRST EPSS (served from a cached copy saved ${staleEpss.day})`].filter(Boolean).join(" and ");
        const owner: OwnerQuestion = {
          row_id: l.row_id, asset_name: l.asset_name,
          question: `Please re-run when Zetaris answers live, or confirm that "${l.software}" on ${l.asset_name} is not affected by a current KEV listing.`,
          reason: `${what} could not be read live, so this row was not relaxed to monitor (fail-closed)`,
        };
        l.decision = "ask_owner";
        l.target_date = null;
        l.evidence = l.evidence.filter((e) => !isPolicyRule(e));
        l.evidence.push({ source: "agent", query: "policy", field: "rule", value: `ask_owner: ${owner.reason}`, live: false });
        lineOwner.set(l.row_id, owner);
        l.why = whyFor(l, owner, policy);
      }
    }

    // The naive federated join inside Zetaris: what a plain SQL join of the inventory and KEV finds, set against the
    // agents' answers (evidence and display only, never a decision input)
    if (live && !kevPairsError && typeof fed.naiveJoin === "function") {
      try {
        const input: NaiveJoinInput = inventoryFrom === "zetaris" ? { from: "inventory", rowIds: rows.map((r) => r.row_id) } : { from: "values", rows };
        const j = await timed("federated_join", () => (fed.naiveJoin as (i: NaiveJoinInput) => Promise<NaiveJoin>)(input));
        const cmp = compareNaiveJoin(rows, j.rows, (id) => lines0.find((l) => l.row_id === id)?.resolution, famsOf);
        helpers_live.push("zetaris.naive_join");
        tracer.emit({
          agent: "zetaris", action: "naive_join", target_agent: "exposure_analyst", status: "ok", latency_ms: j.ms,
          input_summary: `${rows.length} row(s) x CISA KEV, joined inside Zetaris on "the KEV product name appears in the software text"`,
          output_summary: cmp.summary,
          details: { sql: j.sql, ms: j.ms, hits: j.rows.length, ...cmp.counts, rows: cmp.rows },
        });
      } catch (e) {
        tracer.emit({ agent: "zetaris", action: "naive_join", status: "error", output_summary: `the naive join failed (display only; the run goes on): ${msg(e)}` });
      }
    }

    // Windows: one question per edition for the rows whose build is unconfirmed
    const winMembers = lines0.filter((l) => versionUnconfirmed.has(l.row_id) && isWindows(l.resolution.family))
      .map((l) => ({ row: rows.find((r) => r.row_id === l.row_id) as InventoryRow, edition: windowsEdition(l.software) }));
    let groupedRows = new Set<string>();
    const groupQuestion = new Map<string, OwnerQuestion>();
    if (winMembers.length) {
      const winEntries = facts.entries(WINDOWS_FAMILY);
      const newest = [...winEntries].sort(byDateDesc)[0] ?? null;
      const groups = groupWindowsQuestions(winMembers, newest, newest ? facts.nvdRanges.get(newest.cve_id.toUpperCase()) ?? [] : [], uniqCves(winEntries).length);
      for (const g of groups) {
        for (const id of g.row_ids) { groupedRows.add(id); lineOwner.delete(id); }
        groupQuestion.set(g.row_ids[0], g.question);
      }
      groupedRows = new Set(groups.flatMap((g) => g.row_ids));
      tracer.emit({
        agent: "exposure_analyst", action: "windows_grouped", target_agent: "owner", status: "ok",
        input_summary: `${winMembers.length} Windows row(s) without a build number`,
        output_summary: `${groups.length} owner question(s), one per edition: ${groups.map((g) => `${g.label} x${g.row_ids.length}${g.fixed_build ? ` (fixed from ${g.fixed_build})` : ""}`).join("; ")}`,
        details: { groups: groups.map((g) => ({ label: g.label, rows: g.row_ids, fixed_build: g.fixed_build })), newest_kev_cve: newest?.cve_id ?? null },
      });
    }

    let lines = sortLines(lines0);
    tracer.emit({
      agent: "exposure_analyst", action: "decisions", target_agent: "verifier", status: "ok",
      output_summary: `${summarise(lines).patch_now} patch_now (${versionUnconfirmed.size} version unconfirmed), ${summarise(lines).this_cycle} this_cycle, ${summarise(lines).ask_owner} ask_owner, ${summarise(lines).monitor} monitor (as of ${as_of})`,
      details: {
        version_unconfirmed: [...versionUnconfirmed], not_affected: notAffected, not_affected_held: notAffectedHeld, rejected_by_critic: unresolvedByCritic,
        version_scoped: versionScoped, held_cached_source: heldStale,
        lines: lines.map((l) => ({ row_id: l.row_id, decision: l.decision, target_date: l.target_date, overdue_days: l.kev?.overdue_days ?? null, epss: l.epss?.max ?? null, critic: l.critic?.verdict ?? null })),
      },
    });

    // 7. Verifier: re-query every cited KEV listing and EPSS score (live; the cache is bypassed).
    const verified = await timed("verifier", () => verifyLive(lines, deps.queries, { tracer, mode: deps.mode, asOf: as_of, policy }));
    lines = verified.lines;
    if (verified.errors.length) problems.push("verifier");
    helpers_live.push("verifier");

    // 8. World Model: ingest the run with provenance, explain each line, audit, persist.
    try {
      await timed("world_model", async () => {
        const world = createLedgerWorld({
          namespace: worldNamespace(tracer.run_id), ...(outputDir ? { persistDir: join(outputDir, "world") } : {}), tracer,
          resolver: { autoMergeAt: 1.01 }, // controller ruling: KEV spellings are never auto-merged, near-duplicates are queued
        });
        // memory across runs (live runs that save their world), kept per row: each row's last earlier run, read back from
        // its saved world through the engine, before this run is ingested; it keeps the patch_now clock (so this run's
        // world records the kept target) and says what changed since then. A run on another subset of the rows moves only
        // its own rows' pointers.
        const memoryOn = live && !!outputDir && opts.memory !== false;
        const worldDir = outputDir ? join(outputDir, "world") : "";
        const memoryKeys = rows.map((r) => ({ row_id: r.row_id, key: rowMemoryKey(inventoryFrom, r) }));
        if (memoryOn) {
          try {
            const { runs: earlier, fresh } = earlierRunsFor(readRunIndex(worldDir), memoryKeys, tracer.run_id);
            const opened = earlier.map((g) => ({ ...g, world: openPreviousWorld(worldDir, g.pointer) }));
            const diff = opened.some((g) => g.world) ? sinceLastRun(lines, opened, fresh) : null;
            if (diff && diff.previous.length) {
              helpers_live.push("world_model.since_last_run");
              tracer.emit({
                agent: "world_model", action: "since_last_run", target_agent: "reporter", status: "ok",
                input_summary: `each row's last earlier run (${diff.previous.length} run(s): ${diff.previous.map((p) => `${p.run_id} x${p.rows.length}`).join(", ")}), reopened read-only from its saved world`,
                output_summary: diff.summary, details: { ...diff },
              });
            } else {
              tracer.emit({ agent: "world_model", action: "since_last_run", status: "ok", output_summary: `no earlier run on these ${rows.length} row(s): this run's world is their first` });
            }
          } catch (e) {
            tracer.emit({ agent: "world_model", action: "since_last_run", status: "error", output_summary: `the earlier runs could not be read (${msg(e)}); this run is unaffected` });
          }
        }
        const fams = matchedFams(finalRes.values());
        const usedKev = [...new Map(fams.flatMap((f) => facts.entries(f)).map((e) => [`${e.cve_id}|${e.vendor}|${e.product}`, e])).values()];
        const spellings = fams.flatMap((f) => facts.pairsFor(f));
        await world.ingestRun({
          runId: tracer.run_id, asOf: as_of, rows, resolutions: rows.map((r) => finalRes.get(r.row_id)).filter((r): r is Resolution => !!r),
          kev: usedKev, epss: facts.epssScores(), decisions: lines, kevPairs: spellings, familyOf: pipeline.family, mode: deps.mode,
          ...(inventoryFrom === "request" ? { sources: { inventory: "request:inventory" } } : {}),
        });
        let explained = 0;
        for (const l of lines) {
          const x = world.explain(l.row_id, { maxCves: 3 });
          if (x) { l.evidence.push(...worldEvidence(x)); explained++; }
        }
        const review = world.reviewQueue();
        const audit = logsDir ? world.writeAudit(logsDir, tracer.run_id) : null;
        const saved = outputDir ? world.persist() : null;
        if (memoryOn && saved) {
          try { writeRunIndex(worldDir, memoryKeys.map((k) => k.key), { run_id: tracer.run_id, namespace: worldNamespace(tracer.run_id), as_of, rows: rows.length }); }
          catch (e) { tracer.emit({ agent: "world_model", action: "run_index", status: "error", output_summary: `the run index could not be written (${msg(e)})` }); }
        }
        const stats = world.stats();
        tracer.emit({
          agent: "world_model", action: "explain_audit", status: "ok",
          output_summary: `${explained} line(s) explained with provenance; ${stats.events_total} engine events; ${review.length} KEV spelling pair(s) in the merge-review queue${audit ? `; audit ${audit}` : ""}`,
          details: {
            review_queue: review.slice(0, 10).map((r) => `${r.left.name} ~ ${r.right.name} (${r.similarity})`),
            audit_file: audit, world_file: saved, stats,
          },
        });
        const m = world.manifest();
        helpers_live.push("world_model", ...m.helpers_live);
        helpers_dormant.push(...m.helpers_dormant);
      });
    } catch (e) {
      problems.push("world_model");
      helpers_dormant.push("world_model (ingest failed)");
      tracer.emit({ agent: "world_model", action: "ingest_failed", status: "error", output_summary: msg(e) });
    }

    // 9. Owner questions in the patch-list order (one per Windows edition group).
    const owner_questions: OwnerQuestion[] = [];
    for (const l of lines) {
      const g = groupQuestion.get(l.row_id);
      if (g) { owner_questions.push(g); continue; }
      if (groupedRows.has(l.row_id)) continue;
      const q = lineOwner.get(l.row_id);
      if (q) owner_questions.push(q);
    }
    if (juryStats || loopStats) {
      tracer.emit({
        agent: "pipeline", action: "agents_summary", status: "ok",
        output_summary: `jury ${juryStats ? `${juryStats.agreed} agreed, ${juryStats.splits} split (${juryStats.adjudicated} by Ultra)` : "skipped"}; critic ${loopStats ? `${loopStats.reviews} reviews in ${loopStats.rounds} round(s), ${loopStats.sent_back} send-back(s) (${loopStats.redecided.lightning} to Lightning, ${loopStats.redecided.ultra} to Ultra, ${loopStats.nvd_sendbacks} for NVD ranges), ${loopStats.ultra_critiques} Ultra critique(s)` : "skipped"}; ${owner_questions.length} owner question(s)`,
        details: { jury: juryStats, critic: loopStats, nvd: { ...facts.nvdCounts(live), ms: facts.nvdMs, states: Object.fromEntries(facts.nvdState) } },
      });
    }
    // the jury runs only after the KEV names are read; without them no model was asked, so it is listed as dormant
    if (juryStats) helpers_live.unshift("normaliser", "resolver_jury");
    else {
      helpers_live.unshift("normaliser");
      helpers_dormant.push("resolver_jury (skipped: KEV names unavailable, rows fail closed)");
    }
    helpers_live.push("report");
    return respond(problems.length ? "partial" : "success", lines, owner_questions);
  } catch (e) {
    return respond("error", [], [], { type: "internal_error", message: msg(e), recoverable: false });
  }
}
