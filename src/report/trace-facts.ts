// Facts the report reads from the run's own trace (logs/trace-<run_id>.jsonl). Pure: no clock, no IO.
// Everything here is a lookup or a count over trace events; nothing is invented. Unknown or malformed
// event shapes are skipped, so an older or partial trace still renders.
//
// Event shapes read (as the pipeline writes them; see src/run.ts, src/agents/*, src/adapters/*):
// - Zetaris:            agent "Zetaris", action sql_query | sql_ddl, latency_ms, details {label, sql, sql_hash, rows, fromCache, cache_mode}
// - jury split:         action split_detected, details.splits[] {row_id, bolt, lightning}
// - Ultra adjudication: action ultra_adjudication, receipt_id, details.decisions[] {row_id, ultra, sided_with, reason}
// - critic review:      agent "critic", action approve | send_back | ask_owner (any action with details.row_id), details {row_id, rubric, reasons, ultra_critique?}
// - critic round:       action critic_round, input_summary / output_summary
// - re-decide:          action redecide, receipt_id, details.decisions[] {row_id, rejected, answer, changed, reason}
// - same-product check: action same_product_check, receipt_id, details {row_id, answer {same, reason}}
// - step summaries:     inventory_loaded, kev_pairs, candidates_built, jury_summary, decisions, recheck, ingest_run, agents_summary

import type { Receipt, TraceEvent } from "../contracts.ts";

export interface ZetarisQuery {
  ts: string; label: string; kind: "query" | "ddl"; ms: number | null; rows: number | null;
  fromCache: boolean | null; cacheMode: string; sql: string; sqlHash: string; status: string; outcome: string;
}
export interface UltraDecision {
  row_id: string; ultra: string; sided_with: string; reason: string; receipt_id: string | null;
  bolt: string | null; lightning: string | null;
}
export interface CatchStep {
  ts: string; actor: string; kind: "critic" | "redecide" | "check"; status: string;
  proposal: string; text: string; rubric: number | null; receipt_id: string | null;
}
export interface PipelineStep { agent: string; models: string[]; text: string[] }
/**
 * Per-CVE NVD outcomes of the run (agents_summary.details.nvd.states), counted by kind. `read` = NVD answered in this
 * run (ok, no_configurations, not_found: the set src/pipeline/facts.ts calls NVD_READ_LIVE); in sample mode the
 * snapshot answers instead. `error` covers failed and invalid lookups, which are not records.
 */
export interface NvdStateCounts { read: number; cached: number; fallback: number; error: number; skipped_budget: number; dormant: number }
export interface NvdFacts {
  /** null when the run recorded no per-CVE outcomes (then only `lookups` is known). */
  states: NvdStateCounts | null;
  ms: number | null;
  /** NVD adapter events in the trace (CVE and product lookups). */
  lookups: number;
}
export interface TraceFacts {
  /** Non-llm_call events that cite a receipt (what that model call was used for). */
  byReceipt: Map<string, TraceEvent[]>;
  adjudications: UltraDecision[];
  /** Rows the critic sent back at least once, with every step about them in trace order. */
  catches: Map<string, CatchStep[]>;
  rounds: TraceEvent[];
  zetaris: ZetarisQuery[];
  nvd: NvdFacts | null;
  pipeline: PipelineStep[];
  reviewQueue: string[];
}

// ---------- small readers ----------

function str(v: unknown): string {
  return typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);
}
function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
function list(v: unknown): Record<string, unknown>[] {
  return Array.isArray(v) ? v.filter((x) => x && typeof x === "object" && !Array.isArray(x)) as Record<string, unknown>[] : [];
}
function details(e: TraceEvent): Record<string, unknown> {
  return obj(e.details);
}
function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.map(str).filter(Boolean) : [];
}

/** The model short name (Bolt, Lightning, Ultra) of an ID, juror key or agent name; "" if none. */
export function modelShort(id: unknown): string {
  const s = str(id).toLowerCase();
  if (/bolt/.test(s)) return "Bolt";
  if (/lightning/.test(s)) return "Lightning";
  if (/ultra/.test(s)) return "Ultra";
  return "";
}

/** The jurors' and Ultra's sentinels in trace text: "null" = no KEV product, "no vote" = no valid answer. */
export function pickText(v: unknown): string {
  const s = str(v).trim();
  if (s === "" || s === "null") return "no KEV product";
  if (s === "no vote") return "no valid vote";
  return s;
}

/**
 * A query or registration the Zetaris client itself ran and timed. Other agents' events are never counted, even when
 * they carry SQL: the NVD adapter copies the SQL of its read into `nvd_cve` and times the whole lookup (rate-limit
 * pacing included), so counting it would show the same query twice and add NVD time to Zetaris time.
 */
export function isZetarisEvent(e: TraceEvent): boolean {
  return (/^zetaris$/i.test(str(e.agent)) && /^sql_(query|ddl)$/.test(str(e.action))) || /zetaris/i.test(str(e.action));
}

const NVD_READ = new Set(["ok", "no_configurations", "not_found"]);

/** Counts agents_summary.details.nvd.states by kind; null when the run recorded none. */
function nvdStateCounts(v: unknown): NvdStateCounts | null {
  const states = Object.values(obj(v)).map(str);
  if (!states.length) return null;
  const c: NvdStateCounts = { read: 0, cached: 0, fallback: 0, error: 0, skipped_budget: 0, dormant: 0 };
  for (const s of states) {
    if (NVD_READ.has(s)) c.read++;
    else if (s === "cached" || s === "fallback" || s === "skipped_budget" || s === "dormant") c[s as keyof NvdStateCounts]++;
    else c.error++; // "error", "invalid" or an unknown state (the pipeline maps unknown states to error too)
  }
  return c;
}

function rowOf(e: TraceEvent): string {
  return str(details(e).row_id);
}

/** The match a critic event reviewed: the part of input_summary after "->", e.g. `R07 "x" -> OpenSSL / OpenSSL`. */
function proposalOf(e: TraceEvent): string {
  const s = str(e.input_summary);
  const i = s.lastIndexOf("->");
  return i >= 0 ? s.slice(i + 2).trim() : "";
}

// ---------- the index ----------

export function indexTrace(trace: TraceEvent[], receipts: Receipt[]): TraceFacts {
  const evs = trace.filter((e) => e && typeof e === "object");
  const receiptModel = new Map<string, string>();
  for (const r of receipts) if (r && typeof r.receipt_id === "string") receiptModel.set(r.receipt_id, modelShort(r.requested_model) || modelShort(r.routed_model));
  const actor = (e: TraceEvent, rid: string | null): string =>
    (rid && receiptModel.get(rid)) || modelShort(e.model) || modelShort(details(e).model_id) || modelShort(e.agent) || str(e.agent);

  // what each receipted call was used for
  const byReceipt = new Map<string, TraceEvent[]>();
  const cite = (rid: unknown, e: TraceEvent) => {
    const k = str(rid);
    if (!k) return;
    const a = byReceipt.get(k) ?? [];
    a.push(e);
    byReceipt.set(k, a);
  };
  for (const e of evs) {
    if (e.action === "llm_call") continue;
    cite(e.receipt_id, e);
    const uc = obj(details(e).ultra_critique);
    if (uc.receipt_id && uc.receipt_id !== e.receipt_id) cite(uc.receipt_id, e);
  }

  // jury splits and Ultra's adjudications
  const splits = new Map<string, { bolt: string | null; lightning: string | null }>();
  for (const e of evs.filter((x) => x.action === "split_detected")) {
    for (const s of list(details(e).splits)) {
      const id = str(s.row_id);
      if (id) splits.set(id, { bolt: s.bolt === undefined ? null : str(s.bolt), lightning: s.lightning === undefined ? null : str(s.lightning) });
    }
  }
  const adjudications: UltraDecision[] = [];
  for (const e of evs.filter((x) => x.action === "ultra_adjudication")) {
    for (const d of list(details(e).decisions)) {
      const id = str(d.row_id);
      if (!id) continue;
      const sp = splits.get(id);
      adjudications.push({
        row_id: id, ultra: str(d.ultra), sided_with: str(d.sided_with), reason: str(d.reason),
        receipt_id: str(e.receipt_id) || null, bolt: sp?.bolt ?? null, lightning: sp?.lightning ?? null,
      });
    }
  }

  // the critic loop, per row
  const steps = new Map<string, CatchStep[]>();
  const add = (row: string, s: CatchStep) => {
    if (!row) return;
    const a = steps.get(row) ?? [];
    a.push(s);
    steps.set(row, a);
  };
  const sentBack = new Set<string>();
  for (const e of evs) {
    const d = details(e);
    // a critic review of one row (the pipeline's actions are approve | send_back | ask_owner; older traces say "review")
    if (/^critic$/i.test(str(e.agent)) && rowOf(e) && e.action !== "llm_call") {
      const row = rowOf(e);
      if (e.status === "sent_back") sentBack.add(row);
      const uc = obj(d.ultra_critique);
      const ucRid = str(uc.receipt_id) || null;
      const reasons = strList(d.reasons);
      add(row, {
        ts: str(e.ts), actor: ucRid ? `Critic + ${receiptModel.get(ucRid) || "Ultra"}` : "Critic", kind: "critic",
        status: str(e.status) || "ok", proposal: proposalOf(e), text: reasons[0] ?? str(e.output_summary),
        rubric: num(obj(d.rubric).total) ?? num(d.rubric_total), receipt_id: ucRid ?? (str(e.receipt_id) || null),
      });
    } else if (e.action === "redecide") {
      const rid = str(e.receipt_id) || null;
      for (const x of list(d.decisions)) {
        add(str(x.row_id), {
          ts: str(e.ts), actor: actor(e, rid), kind: "redecide", status: x.changed === false ? "unchanged" : "changed",
          proposal: pickText(x.answer), text: str(x.reason), rubric: null, receipt_id: rid,
        });
      }
    } else if (e.action === "same_product_check") {
      const rid = str(e.receipt_id) || null;
      const ans = obj(d.answer);
      add(rowOf(e), {
        ts: str(e.ts), actor: actor(e, rid), kind: "check", status: ans.same === true ? "same product" : ans.same === false ? "different product" : "unclear",
        proposal: proposalOf(e).replace(/\s*\(.*\)\s*$/, ""), text: str(ans.reason), rubric: null, receipt_id: rid,
      });
    }
  }
  const catches = new Map<string, CatchStep[]>();
  // trace order is time order; a stable sort by timestamp keeps it when events were appended out of order
  for (const [row, s] of steps) if (sentBack.has(row)) catches.set(row, [...s].sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0)));

  // Zetaris queries
  const zetaris: ZetarisQuery[] = evs.filter((e) => isZetarisEvent(e) && (num(e.latency_ms) !== null || num(details(e).ms) !== null)).map((e) => {
    const d = details(e);
    const cache = d.from_cache ?? d.fromCache ?? d.cache;
    return {
      ts: str(e.ts),
      label: str(d.label) || str(d.query) || str(d.name) || str(e.action),
      kind: /ddl/i.test(str(e.action)) ? "ddl" : "query",
      ms: num(e.latency_ms) ?? num(d.ms),
      rows: num(d.rows) ?? num(d.row_count) ?? num(d.rowCount),
      fromCache: typeof cache === "boolean" ? cache : null,
      cacheMode: str(d.cache_mode),
      sql: str(d.sql),
      sqlHash: str(d.sql_hash),
      status: str(e.status) || "ok",
      outcome: str(e.output_summary),
    };
  });

  // NVD: the run's per-CVE outcomes when present, else the lookup events. The summary's live_calls counter is not
  // used: it counts every non-cached attempt, failed lookups included (and sample-mode misses).
  const summary = evs.find((e) => e.action === "agents_summary");
  const nvdD = obj(summary ? obj(details(summary).nvd) : {});
  const nvdEvents = evs.filter((e) => /^nvd$/i.test(str(e.agent)));
  const nvd: NvdFacts | null = Object.keys(nvdD).length || nvdEvents.length
    ? { states: nvdStateCounts(nvdD.states), ms: num(nvdD.ms), lookups: nvdEvents.length }
    : null;

  // the pipeline, in the agents' own words
  const first = (action: string) => evs.find((e) => e.action === action);
  const said = (e: TraceEvent | undefined, withInput = false): string[] =>
    e ? [withInput ? str(e.input_summary) : "", str(e.output_summary)].filter(Boolean) : [];
  const callers = (re: RegExp) => [...new Set(receipts.filter((r) => re.test(str(r.agent))).map((r) => modelShort(r.requested_model)).filter(Boolean))];
  const pipeline: PipelineStep[] = [];
  const push = (agent: string, models: string[], text: string[]) => { if (text.length) pipeline.push({ agent, models, text }); };
  push("Zetaris", [], [...said(first("inventory_loaded")), ...said(first("kev_pairs"))]);
  push("Normaliser", [], said(first("candidates_built")));
  const jury = first("jury_summary");
  const adj = first("ultra_adjudication");
  push("Resolver jury", callers(/^jury\./), [...said(jury), ...(adj ? [`Ultra: ${str(adj.output_summary)}`] : [])]);
  const critic = obj(summary ? obj(details(summary).critic) : {});
  if (Object.keys(critic).length) {
    const re = obj(critic.redecided);
    const parts = [
      num(critic.reviews) !== null ? `${critic.reviews} reviews in ${num(critic.rounds) ?? "?"} round(s)` : "",
      num(critic.sent_back) !== null ? `${critic.sent_back} send-back(s)${
        num(re.lightning) !== null || num(re.ultra) !== null || num(critic.nvd_sendbacks) !== null
          ? ` (${[num(re.lightning) !== null ? `${re.lightning} re-decided by Lightning` : "", num(re.ultra) !== null ? `${re.ultra} by Ultra` : "", num(critic.nvd_sendbacks) !== null ? `${critic.nvd_sendbacks} for NVD ranges` : ""].filter(Boolean).join(", ")})`
          : ""}` : "",
      num(critic.ultra_critiques) !== null ? `${critic.ultra_critiques} Ultra critique(s)` : "",
      num(critic.match_checks) !== null ? `${critic.match_checks} same-product check(s)` : "",
    ].filter(Boolean);
    push("Conflict critic", callers(/^(critic|resolver\.retry)/), parts.length ? [parts.join("; ")] : []);
  } else {
    push("Conflict critic", callers(/^(critic|resolver\.retry)/), evs.filter((e) => e.action === "critic_round").map((e) => str(e.output_summary)).filter(Boolean));
  }
  push("Exposure analyst", [], said(first("decisions")));
  push("Verifier", [], said(first("recheck"), true));
  const ingest = first("ingest_run");
  push("World Model", [], said(ingest));
  const reviewQueue = strList(details(ingest ?? ({} as TraceEvent)).review_queue);

  return {
    byReceipt, adjudications, catches, rounds: evs.filter((e) => e.action === "critic_round"),
    zetaris, nvd, pipeline, reviewQueue,
  };
}
