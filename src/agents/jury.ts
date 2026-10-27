// Resolver jury v0. Bolt and Lightning each map every inventory row (batches of 10) to ONE KEV
// candidate from that row's own list, or to null. Agreement (same product family, or both null) is
// accepted. A split (different answers, one null, or one juror with no valid vote) goes to Ultra in a
// batched call; Ultra sees both votes and the candidates. Rows with no candidate at all, and runs
// without a model (sample mode, Nightshift down), use the deterministic vote, labelled as such.
//
// Model self-confidence is kept on each vote but never trusted: the models never flag ambiguity and
// all three fall for look-alikes. Resolution.confidence is the share of valid votes that agree with
// the final answer. Every reply is validated against the schema; anything off-list is discarded.
import { MODELS } from "../contracts.ts";
import type {
  Candidate, ChatRequest, ChatResult, InventoryRow, JurorVote, Llm, Mode, ModelKey, ProductType, Receipt,
  Resolution, Tracer,
} from "../contracts.ts";
import { CONFIDENT_NONE, cleanName, familyKey } from "../resolve/candidates.ts";

export const JURY_BATCH_SIZE = 10;
export const PRODUCT_TYPES: readonly ProductType[] = [
  "server", "network_appliance", "client", "cloud_service", "library", "os", "unknown",
];

export interface JuryItem { row: InventoryRow; candidates: Candidate[]; version: string | null; }

export interface JuryOptions {
  llm: Llm | null;
  tracer: Tracer;
  mode: Mode;
  /** The deterministic vote (A1's normaliserVote, or the v0 one). */
  fallbackVote: (item: JuryItem) => JurorVote;
  batchSize?: number;
}

export interface JuryStats {
  rows: number; batches: number; agreed: number; splits: number; adjudicated: number;
  unresolved: number; no_candidates: number; deterministic: number;
  calls: Record<ModelKey, number>; failed_calls: number;
}

export interface JuryOutcome { resolutions: Resolution[]; stats: JuryStats; }

// ---------------------------------------------------------------- prompts

const RULES = [
  "A different product from the same vendor is NOT a match. A management server or console is not the endpoint client or agent, and a cloud or online service is not the on-premises server software.",
  "Copy vendor and product EXACTLY as written in the candidate list.",
  "product_type is the kind of software the INVENTORY item is: one of server, network_appliance, client, cloud_service, library, os, unknown.",
  "version is the version written in the inventory item, or null.",
  "confidence is a number from 0 to 1.",
];

export const JUROR_SYSTEM = [
  "You are a juror in a software exposure check. An IT admin typed each inventory item by hand.",
  "For each item, choose AT MOST ONE (vendor, product) pair from that item's OWN candidate list that names the same software product, or null when none does.",
  ...RULES,
  'Answer ONLY with a JSON object: {"results":[{"id":"I1","vendor":"..." or null,"product":"..." or null,"product_type":"...","version":"..." or null,"confidence":0.0}]} with exactly one result per item.',
].join("\n");

export const ADJUDICATOR_SYSTEM = [
  "You are the adjudicator in a software exposure check. An IT admin typed each inventory item by hand.",
  "Two jurors disagreed about which candidate, if any, names the same software product as each item, or one juror gave no valid answer.",
  "For each item, decide: pick either juror's answer, another pair from the item's OWN candidate list, or null when none fits.",
  ...RULES,
  'Answer ONLY with a JSON object: {"results":[{"id":"I1","vendor":"..." or null,"product":"..." or null,"product_type":"...","version":"..." or null,"confidence":0.0,"reason":"one short sentence"}]} with exactly one result per item.',
].join("\n");

export interface BatchEntry { localId: string; item: JuryItem; }
export interface SplitEntry extends BatchEntry { bolt: ParsedVote | null; lightning: ParsedVote | null; }

function pairText(vendor: string, product: string): string {
  return `(${cleanName(vendor)}, ${cleanName(product)})`;
}

function itemHeader(e: BatchEntry): string {
  const type = cleanName(e.item.row.asset_type ?? "") || "unknown";
  return `${e.localId} ${JSON.stringify(cleanName(e.item.row.software))} (asset type: ${type})`;
}

function candidateLine(e: BatchEntry): string {
  return `   candidates: ${e.item.candidates.map((c) => pairText(c.vendor, c.product)).join(" | ")}`;
}

/** The juror prompt for one batch (the same prompt goes to Bolt and Lightning). */
export function buildJurorPrompt(entries: BatchEntry[]): { system: string; user: string } {
  const lines = ["Inventory items (synthetic data), each with its own candidate list:"];
  for (const e of entries) lines.push(itemHeader(e), candidateLine(e));
  return { system: JUROR_SYSTEM, user: lines.join("\n") };
}

function voteText(v: ParsedVote | null): string {
  if (!v) return "no valid answer";
  return v.candidate ? pairText(v.candidate.vendor, v.candidate.product) : "null (no candidate fits)";
}

/** The adjudicator prompt: each split item with both votes (neutral labels) and its candidates. */
export function buildAdjudicatorPrompt(entries: SplitEntry[]): { system: string; user: string } {
  const lines = ["Disputed inventory items (synthetic data):"];
  for (const e of entries) {
    lines.push(itemHeader(e), `   juror A: ${voteText(e.bolt)}`, `   juror B: ${voteText(e.lightning)}`, candidateLine(e));
  }
  return { system: ADJUDICATOR_SYSTEM, user: lines.join("\n") };
}

// ---------------------------------------------------------------- reply validation

export interface ParsedVote {
  localId: string;
  candidate: Candidate | null;   // the KEV pair from the row's list, or null = "nothing fits"
  product_type: ProductType;
  version: string | null;
  confidence: number;
  reason: string | null;
}
export interface ParsedReply { votes: Map<string, ParsedVote>; problems: string[]; }

const NONE_WORDS = /^(null|none|n\/a|na|nil|unknown|no match|nothing|-)$/i;

function textOrNull(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = cleanName(v);
  return !s || NONE_WORDS.test(s) ? null : s;
}

function norm(s: string): string {
  return cleanName(s).toLowerCase();
}

/** The row's candidate named by a reply: exact (normalised) pair, else a unique product-name match. */
export function findCandidate(cands: Candidate[], vendor: string, product: string): Candidate | null {
  const v = norm(vendor);
  const p = norm(product);
  const exact = cands.find((c) => norm(c.vendor) === v && norm(c.product) === p);
  if (exact) return exact;
  const byProduct = cands.filter((c) => norm(c.product) === p);
  return byProduct.length === 1 ? byProduct[0] : null;
}

function toConfidence(v: unknown): number {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : Number.NaN;
  if (!Number.isFinite(n)) return 0.5;
  const x = n > 1 && n <= 100 ? n / 100 : n;
  return Math.round(Math.min(1, Math.max(0, x)) * 1000) / 1000;
}

function toVersion(v: unknown): string | null {
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  const s = textOrNull(v);
  return s ? s.slice(0, 40) : null;
}

function idKey(v: unknown): string {
  const s = typeof v === "number" ? `i${v}` : typeof v === "string" ? v.trim().toLowerCase() : "";
  return /^\d+$/.test(s) ? `i${s}` : s;
}

/**
 * Validate a juror or adjudicator reply against the batch. Accepts {"results":[...]} or a bare array.
 * A pair that is not in the row's own candidate list is discarded (no vote); half an answer
 * ("Apache", null) and the strings "null"/"none" count as null; an unknown product_type becomes "unknown".
 */
export function parseVotes(json: unknown, entries: BatchEntry[]): ParsedReply {
  const problems: string[] = [];
  const votes = new Map<string, ParsedVote>();
  const results = Array.isArray(json)
    ? json
    : json && typeof json === "object" && Array.isArray((json as { results?: unknown }).results)
      ? (json as { results: unknown[] }).results
      : null;
  if (!results) {
    problems.push(json === null ? "reply had no JSON" : "reply has no results array");
    return { votes, problems };
  }
  const byId = new Map(entries.map((e) => [e.localId.toLowerCase(), e]));
  for (const r of results) {
    if (!r || typeof r !== "object" || Array.isArray(r)) { problems.push("a result is not an object"); continue; }
    const rec = r as Record<string, unknown>;
    const entry = byId.get(idKey(rec.id));
    if (!entry) { problems.push(`unknown id ${JSON.stringify(rec.id)}`); continue; }
    if (votes.has(entry.localId)) { problems.push(`${entry.localId}: duplicate result ignored`); continue; }
    const vendor = textOrNull(rec.vendor);
    const product = textOrNull(rec.product);
    let candidate: Candidate | null = null;
    if (vendor !== null && product !== null) {
      candidate = findCandidate(entry.item.candidates, vendor, product);
      if (!candidate) { problems.push(`${entry.localId}: (${vendor}, ${product}) is not in its candidate list`); continue; }
    } else if (vendor !== null || product !== null) {
      problems.push(`${entry.localId}: half an answer (${vendor ?? "null"}, ${product ?? "null"}) counted as null`);
    }
    const typeRaw = typeof rec.product_type === "string" ? rec.product_type.trim().toLowerCase() : "";
    const typeOk = (PRODUCT_TYPES as readonly string[]).includes(typeRaw);
    if (typeRaw && !typeOk) problems.push(`${entry.localId}: invalid product_type ${JSON.stringify(typeRaw)}`);
    votes.set(entry.localId, {
      localId: entry.localId,
      candidate,
      product_type: typeOk ? (typeRaw as ProductType) : "unknown",
      version: toVersion(rec.version),
      confidence: toConfidence(rec.confidence),
      reason: typeof rec.reason === "string" ? cleanName(rec.reason).slice(0, 200) : null,
    });
  }
  return { votes, problems };
}

// ---------------------------------------------------------------- resolutions

function sameAnswer(a: Candidate | null, b: Candidate | null): boolean {
  if (!a || !b) return !a && !b;
  return familyKey(a.family) === familyKey(b.family);
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

/** Share of valid votes that agree with the final answer (model self-confidence is not used). */
function consensus(final: Candidate | null, votes: (ParsedVote | null)[]): number {
  const valid = votes.filter((v): v is ParsedVote => v !== null);
  if (!valid.length) return 0;
  return round2(valid.filter((v) => sameAnswer(v.candidate, final)).length / valid.length);
}

function jurorVote(item: JuryItem, juror: ModelKey, v: ParsedVote, receipt: Receipt): JurorVote {
  return {
    row_id: item.row.row_id, juror, vendor: v.candidate?.vendor ?? null, product: v.candidate?.product ?? null,
    product_type: v.product_type, confidence: v.confidence, receipt_id: receipt.receipt_id,
  };
}

function agreedVersion(a: ParsedVote | null, b: ParsedVote | null): string | null {
  if (a?.version && b?.version && norm(a.version) === norm(b.version)) return a.version;
  return null;
}

function resolution(item: JuryItem, final: Candidate | null, fields: Partial<Resolution>): Resolution {
  return {
    row_id: item.row.row_id,
    status: final ? "matched" : "no_match",
    vendor: final?.vendor ?? null,
    product: final?.product ?? null,
    family: final?.family ?? null,
    version: item.version,
    product_type: "unknown",
    votes: [],
    adjudicated_by: null,
    confidence: 0,
    ...fields,
  };
}

function unresolved(item: JuryItem, votes: JurorVote[], adjudicatedBy: Resolution["adjudicated_by"] = null): Resolution {
  return resolution(item, null, { status: "unresolved", votes, adjudicated_by: adjudicatedBy, confidence: 0 });
}

/** A resolution from the deterministic vote alone (sample mode, no candidates, or no model votes). */
export function deterministicResolution(item: JuryItem, vote: JurorVote, prior: JurorVote[] = []): Resolution {
  const votes = [...prior, vote];
  const conf = round2(Math.min(1, Math.max(0, Number.isFinite(vote.confidence) ? vote.confidence : 0)));
  if (vote.vendor && vote.product) {
    const cand = findCandidate(item.candidates, vote.vendor, vote.product);
    if (!cand) return unresolved(item, votes);
    return resolution(item, cand, { votes, adjudicated_by: "rules", confidence: conf, product_type: vote.product_type ?? "unknown" });
  }
  if (item.candidates.length === 0 || conf >= CONFIDENT_NONE) {
    return resolution(item, null, { votes, adjudicated_by: "rules", confidence: conf, product_type: vote.product_type ?? "unknown" });
  }
  return unresolved(item, votes);
}

// ---------------------------------------------------------------- the jury

function chunk<T>(xs: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}

/** llm.chat that cannot throw: a thrown error becomes an error receipt. */
async function safeChat(llm: Llm, req: ChatRequest): Promise<ChatResult> {
  try {
    return await llm.chat(req);
  } catch (e) {
    return {
      text: "", json: null,
      receipt: {
        call_id: "client-error", agent: req.agent, requested_model: MODELS[req.model], response_model: null,
        routed_model: null, receipt_id: null, latency_ms: 0, status: "error",
        error: String((e as Error)?.message ?? e).slice(0, 300),
      },
    };
  }
}

function describe(v: ParsedVote | null): string {
  if (!v) return "no vote";
  return v.candidate ? `${cleanName(v.candidate.vendor)} / ${cleanName(v.candidate.product)}` : "null";
}

interface JurorBatchResult { receipt: Receipt; votes: Map<string, ParsedVote>; problems: string[]; }

async function askJuror(
  llm: Llm, model: "bolt" | "lightning", entries: BatchEntry[], batchNo: number, opts: JuryOptions, stats: JuryStats,
): Promise<JurorBatchResult> {
  const prompt = buildJurorPrompt(entries);
  const res = await safeChat(llm, { model, agent: `jury.${model}`, system: prompt.system, user: prompt.user, json: true });
  stats.calls[model]++;
  const ok = res.receipt.status === "ok";
  if (!ok) stats.failed_calls++;
  const parsed = ok ? parseVotes(res.json, entries) : { votes: new Map<string, ParsedVote>(), problems: [`call failed: ${res.receipt.error ?? "error"}`] };
  const vs = [...parsed.votes.values()];
  const matched = vs.filter((v) => v.candidate).length;
  opts.tracer.emit({
    agent: `jury.${model}`,
    action: "jury_vote",
    target_agent: "resolver_jury",
    receipt_id: res.receipt.receipt_id,
    latency_ms: res.receipt.latency_ms,
    status: ok ? "ok" : "error",
    input_summary: `batch ${batchNo}: ${entries.length} rows`,
    output_summary: `${model}: ${matched} matched, ${vs.length - matched} null, ${entries.length - vs.length} without a valid vote`,
    details: {
      batch: batchNo,
      juror: model,
      model_id: MODELS[model],
      routed_model: res.receipt.routed_model,
      votes: entries.map((e) => ({ id: e.localId, row_id: e.item.row.row_id, vote: describe(parsed.votes.get(e.localId) ?? null), confidence: parsed.votes.get(e.localId)?.confidence ?? null })),
      problems: parsed.problems,
    },
  });
  return { receipt: res.receipt, votes: parsed.votes, problems: parsed.problems };
}

/** Run the jury over all items. The order of `resolutions` matches `items`. */
export async function runJury(items: JuryItem[], opts: JuryOptions): Promise<JuryOutcome> {
  const size = Math.max(1, Math.floor(opts.batchSize ?? JURY_BATCH_SIZE));
  const stats: JuryStats = {
    rows: items.length, batches: 0, agreed: 0, splits: 0, adjudicated: 0, unresolved: 0, no_candidates: 0,
    deterministic: 0, calls: { bolt: 0, lightning: 0, ultra: 0 }, failed_calls: 0,
  };
  const out = new Map<string, Resolution>();
  const { tracer } = opts;

  // Rows with no candidate: no KEV name is even close, so no model is asked.
  const toAsk: JuryItem[] = [];
  const noCand: string[] = [];
  for (const item of items) {
    if (item.candidates.length === 0) {
      out.set(item.row.row_id, deterministicResolution(item, opts.fallbackVote(item)));
      noCand.push(item.row.row_id);
    } else toAsk.push(item);
  }
  stats.no_candidates = noCand.length;
  if (noCand.length) {
    tracer.emit({
      agent: "resolver_jury", action: "no_candidates", status: "ok",
      output_summary: `${noCand.length} row(s) have no KEV candidate: no_match by rule, no model call`,
      details: { row_ids: noCand },
    });
  }

  if (!opts.llm) {
    for (const item of toAsk) {
      const r = deterministicResolution(item, opts.fallbackVote(item));
      out.set(item.row.row_id, r);
      if (r.status === "unresolved") stats.unresolved++;
    }
    stats.deterministic = toAsk.length;
    tracer.emit({
      agent: "resolver_jury", action: "deterministic_vote",
      status: opts.mode === "sample" ? "ok" : "fallback",
      output_summary: `${toAsk.length} row(s) resolved by the deterministic normaliser vote (${opts.mode === "sample" ? "sample mode: no models" : "no model client"})`,
      details: { row_ids: toAsk.map((i) => i.row.row_id) },
    });
    return { resolutions: items.map((i) => out.get(i.row.row_id) as Resolution), stats };
  }
  const llm = opts.llm;

  // 1. Bolt and Lightning on every batch, all at once; the client's semaphore caps concurrency at 4.
  const batches: BatchEntry[][] = chunk(toAsk, size).map((b) => b.map((item, i) => ({ localId: `I${i + 1}`, item })));
  stats.batches = batches.length;
  const juryRuns = await Promise.all(batches.map(async (entries, bi) => {
    const [bolt, lightning] = await Promise.all([
      askJuror(llm, "bolt", entries, bi + 1, opts, stats),
      askJuror(llm, "lightning", entries, bi + 1, opts, stats),
    ]);
    return { entries, bolt, lightning, batchNo: bi + 1 };
  }));

  // 2. Compare the votes.
  const splits: (SplitEntry & { votes: JurorVote[] })[] = [];
  for (const { entries, bolt, lightning, batchNo } of juryRuns) {
    const batchSplits: Record<string, string>[] = [];
    for (const e of entries) {
      const b = bolt.votes.get(e.localId) ?? null;
      const l = lightning.votes.get(e.localId) ?? null;
      const votes: JurorVote[] = [];
      if (b) votes.push(jurorVote(e.item, "bolt", b, bolt.receipt));
      if (l) votes.push(jurorVote(e.item, "lightning", l, lightning.receipt));
      if (b && l && sameAnswer(b.candidate, l.candidate)) {
        const final = l.candidate ?? b.candidate;
        out.set(e.item.row.row_id, resolution(e.item, final, {
          votes,
          version: e.item.version ?? agreedVersion(b, l),
          product_type: b.product_type === l.product_type ? l.product_type : "unknown",
          confidence: consensus(final, [b, l]),
        }));
        stats.agreed++;
      } else {
        splits.push({ ...e, bolt: b, lightning: l, votes });
        batchSplits.push({ row_id: e.item.row.row_id, bolt: describe(b), lightning: describe(l) });
      }
    }
    if (batchSplits.length) {
      tracer.emit({
        agent: "resolver_jury", action: "split_detected", target_agent: "jury.adjudicate", status: "ok",
        output_summary: `batch ${batchNo}: ${batchSplits.length} split row(s) sent to Ultra`,
        details: { batch: batchNo, splits: batchSplits },
      });
    }
  }

  // 3. No juror produced a usable vote (both calls failed): the deterministic vote decides, labelled.
  const contested = splits.filter((s) => s.bolt || s.lightning);
  const voteless = splits.filter((s) => !s.bolt && !s.lightning);
  for (const s of voteless) {
    const r = deterministicResolution(s.item, opts.fallbackVote(s.item), s.votes);
    out.set(s.item.row.row_id, r);
    if (r.status === "unresolved") stats.unresolved++;
  }
  stats.deterministic += voteless.length;
  if (voteless.length) {
    tracer.emit({
      agent: "resolver_jury", action: "deterministic_vote", status: "fallback",
      output_summary: `${voteless.length} row(s) got no valid juror vote; the deterministic normaliser vote decides`,
      details: { row_ids: voteless.map((s) => s.item.row.row_id) },
    });
  }

  // 4. Ultra adjudicates the contested rows, in batches.
  stats.splits = contested.length;
  await Promise.all(chunk(contested, size).map(async (group, gi) => {
    const entries: SplitEntry[] = group.map((s, i) => ({ localId: `I${i + 1}`, item: s.item, bolt: s.bolt, lightning: s.lightning }));
    const prompt = buildAdjudicatorPrompt(entries);
    const res = await safeChat(llm, { model: "ultra", agent: "jury.adjudicate", system: prompt.system, user: prompt.user, json: true });
    stats.calls.ultra++;
    const ok = res.receipt.status === "ok";
    if (!ok) stats.failed_calls++;
    const parsed = ok ? parseVotes(res.json, entries) : { votes: new Map<string, ParsedVote>(), problems: [`call failed: ${res.receipt.error ?? "error"}`] };
    const decisions: Record<string, string>[] = [];
    group.forEach((s, i) => {
      const u = parsed.votes.get(`I${i + 1}`) ?? null;
      if (!u) {
        out.set(s.item.row.row_id, unresolved(s.item, s.votes));
        stats.unresolved++;
        decisions.push({ row_id: s.item.row.row_id, ultra: "no valid answer", outcome: "unresolved" });
        return;
      }
      const votes = [...s.votes, jurorVote(s.item, "ultra", u, res.receipt)];
      out.set(s.item.row.row_id, resolution(s.item, u.candidate, {
        votes,
        version: s.item.version ?? u.version,
        product_type: u.product_type,
        adjudicated_by: "ultra",
        confidence: consensus(u.candidate, [s.bolt, s.lightning, u]),
      }));
      stats.adjudicated++;
      const sided = s.bolt && sameAnswer(u.candidate, s.bolt.candidate) ? "bolt"
        : s.lightning && sameAnswer(u.candidate, s.lightning.candidate) ? "lightning" : "neither";
      decisions.push({ row_id: s.item.row.row_id, ultra: describe(u), sided_with: sided, reason: u.reason ?? "" });
    });
    const decided = decisions.filter((d) => d.sided_with).length;
    tracer.emit({
      agent: "jury.adjudicate", action: "ultra_adjudication", target_agent: "resolver_jury",
      receipt_id: res.receipt.receipt_id, latency_ms: res.receipt.latency_ms, status: ok ? "ok" : "error",
      input_summary: `group ${gi + 1}: ${group.length} split row(s)`,
      output_summary: `${decided} of ${group.length} decided; ${group.length - decided} unresolved`,
      details: { model_id: MODELS.ultra, routed_model: res.receipt.routed_model, decisions, problems: parsed.problems },
    });
  }));

  tracer.emit({
    agent: "resolver_jury", action: "jury_summary", status: "ok",
    output_summary: `${stats.rows} rows: ${stats.agreed} agreed, ${stats.splits} split (${stats.adjudicated} decided by Ultra), ${stats.unresolved} unresolved, ${stats.no_candidates} without candidates, ${stats.deterministic} deterministic`,
    details: { ...stats },
  });
  return { resolutions: items.map((i) => out.get(i.row.row_id) as Resolution), stats };
}

// ---------------------------------------------------------------- critic send-back: the resolver re-decides

export const RESOLVER_RETRY_SYSTEM = [
  "You are the resolver in a software exposure check, re-deciding items that a critic rejected. An IT admin typed each inventory item by hand.",
  "For each item you see the rejected answer and the critic's reason. Use the reason: choose AT MOST ONE (vendor, product) pair from that item's OWN candidate list that names the same software product AND the same kind of product, or null when none does.",
  ...RULES,
  'Answer ONLY with a JSON object: {"results":[{"id":"I1","vendor":"..." or null,"product":"..." or null,"product_type":"...","version":"..." or null,"confidence":0.0,"reason":"one short sentence"}]} with exactly one result per item.',
].join("\n");

export interface RetryEntry extends BatchEntry { rejected: string; note: string; }

/** The re-decide prompt: each sent-back item with the rejected answer, the critic's reason and its candidates. */
export function buildRetryPrompt(entries: RetryEntry[]): { system: string; user: string } {
  const lines = ["Items the critic sent back (synthetic data):"];
  for (const e of entries) {
    lines.push(itemHeader(e), `   rejected answer: ${e.rejected}`, `   critic: ${cleanName(e.note).slice(0, 500)}`, candidateLine(e));
  }
  return { system: RESOLVER_RETRY_SYSTEM, user: lines.join("\n") };
}

export interface RedecideInput { item: JuryItem; previous: Resolution; note: string; }
export interface RedecideOutcome {
  row_id: string;
  resolution: Resolution;
  /** The re-decider's vote, or null when its reply had no valid answer for the row (the previous resolution stands). */
  vote: JurorVote | null;
  receipt: Receipt;
  changed: boolean;
}

/** Share of the model votes that name the same family as the final answer (null = "no KEV product"). */
function voteShare(item: JuryItem, final: Candidate | null, votes: JurorVote[]): number {
  const model = votes.filter((v) => v.juror !== "normaliser");
  if (!model.length) return 0;
  const famOf = (v: JurorVote): string | null => {
    if (!v.vendor || !v.product) return null;
    const c = findCandidate(item.candidates, v.vendor, v.product);
    return c ? familyKey(c.family) : `${norm(v.vendor)}|${norm(v.product)}`;
  };
  const target = final ? familyKey(final.family) : null;
  return round2(model.filter((v) => famOf(v) === target).length / model.length);
}

function previousText(r: Resolution): string {
  return r.vendor && r.product ? pairText(r.vendor, r.product) : r.status === "no_match" ? "null (no candidate fits)" : "no settled answer";
}

/**
 * The critic sent these rows back: one model re-decides them with the critic's reason (batches of 10, one call per
 * batch). Round 1 uses Lightning, round 2 Ultra (the caller picks). A row without a valid answer keeps its previous
 * resolution, so the critic reviews it again and, once the rounds are spent, asks the owner.
 * With `rowFamily` (the pipeline's row-aware family: the product of a combo spelling the row matched), the new
 * resolution carries that family and `changed` compares row families, so a repeated answer is never "changed".
 */
export async function redecide(
  inputs: RedecideInput[], model: "lightning" | "ultra",
  opts: { llm: Llm; tracer: Tracer; round: number; batchSize?: number; rowFamily?: (row: InventoryRow, res: Resolution) => string | null },
): Promise<RedecideOutcome[]> {
  const size = Math.max(1, Math.floor(opts.batchSize ?? JURY_BATCH_SIZE));
  const famOf = (row: InventoryRow, r: Resolution): string | null =>
    r.status !== "matched" ? null : (opts.rowFamily ? opts.rowFamily(row, r) : null) ?? r.family;
  const keyOf = (row: InventoryRow, r: Resolution): string => {
    const f = famOf(row, r);
    return r.status === "matched" && f ? familyKey(f) : r.status;
  };
  const out = new Map<string, RedecideOutcome>();
  await Promise.all(chunk(inputs, size).map(async (group, gi) => {
    const entries: RetryEntry[] = group.map((g, i) => ({ localId: `I${i + 1}`, item: g.item, rejected: previousText(g.previous), note: g.note }));
    const prompt = buildRetryPrompt(entries);
    const res = await safeChat(opts.llm, { model, agent: `resolver.retry.${model}`, system: prompt.system, user: prompt.user, json: true });
    const ok = res.receipt.status === "ok";
    const parsed = ok ? parseVotes(res.json, entries) : { votes: new Map<string, ParsedVote>(), problems: [`call failed: ${res.receipt.error ?? "error"}`] };
    const decisions: Record<string, unknown>[] = [];
    group.forEach((g, i) => {
      const v = parsed.votes.get(`I${i + 1}`) ?? null;
      if (!v) {
        out.set(g.item.row.row_id, { row_id: g.item.row.row_id, resolution: g.previous, vote: null, receipt: res.receipt, changed: false });
        decisions.push({ row_id: g.item.row.row_id, rejected: previousText(g.previous), answer: "no valid answer", changed: false });
        return;
      }
      const vote = jurorVote(g.item, model, v, res.receipt);
      const votes = [...g.previous.votes, vote];
      const next0 = resolution(g.item, v.candidate, {
        votes,
        version: g.item.version ?? v.version,
        product_type: v.product_type,
        adjudicated_by: model,
        confidence: voteShare(g.item, v.candidate, votes),
      });
      const nextFam = famOf(g.item.row, next0);
      const next = nextFam && nextFam !== next0.family ? { ...next0, family: nextFam } : next0;
      const changed = keyOf(g.item.row, g.previous) !== keyOf(g.item.row, next);
      out.set(g.item.row.row_id, { row_id: g.item.row.row_id, resolution: next, vote, receipt: res.receipt, changed });
      decisions.push({ row_id: g.item.row.row_id, rejected: previousText(g.previous), answer: describe(v), changed, reason: v.reason ?? "" });
    });
    const changedN = decisions.filter((d) => d.changed).length;
    opts.tracer.emit({
      agent: `resolver.retry.${model}`, action: "redecide", target_agent: "critic",
      receipt_id: res.receipt.receipt_id, latency_ms: res.receipt.latency_ms, status: ok ? "ok" : "error", retry_count: opts.round,
      input_summary: `round ${opts.round}, group ${gi + 1}: ${group.length} row(s) sent back by the critic`,
      output_summary: `${changedN} of ${group.length} changed their answer`,
      details: { model_id: MODELS[model], routed_model: res.receipt.routed_model, decisions, problems: parsed.problems },
    });
  }));
  return inputs.map((g) => out.get(g.item.row.row_id) as RedecideOutcome);
}

// ---------------------------------------------------------------- single models (eval arms)

/**
 * One model's votes over the items, with the jury's own prompt, batching and validation, and no second vote, no
 * Ultra and no critic: the single-model arms of the accuracy table. Rows without candidates get a null vote by rule
 * (no call), exactly as in the jury. Rows whose reply has no valid vote are left out (the eval counts them missing).
 */
export async function voteWithModel(
  model: ModelKey, items: { row: InventoryRow; candidates: Candidate[] }[], deps: { llm: Llm | null; tracer: Tracer },
  opts: { batchSize?: number } = {},
): Promise<{ votes: JurorVote[]; receipts: Receipt[] }> {
  if (!deps.llm) throw new Error("voteWithModel needs a model client (live mode)");
  const receipts: Receipt[] = [];
  const inner = deps.llm;
  const llm: Llm = { async chat(req) { const r = await safeChat(inner, req); receipts.push(r.receipt); return r; } };
  const ask = items.filter((i) => i.candidates.length > 0).map((i) => ({ row: i.row, candidates: i.candidates, version: null }));
  const resolutions = ask.length ? await runSingleJuror(ask, model, { llm, tracer: deps.tracer, batchSize: opts.batchSize }) : [];
  const byRow = new Map(resolutions.map((r) => [r.row_id, r]));
  const votes: JurorVote[] = [];
  for (const it of items) {
    if (it.candidates.length === 0) {
      votes.push({ row_id: it.row.row_id, juror: "normaliser", vendor: null, product: null, confidence: 0.8 });
      continue;
    }
    const r = byRow.get(it.row.row_id);
    const v = r?.votes.find((x) => x.juror === model);
    if (r && r.status !== "unresolved" && v) votes.push(v);
  }
  return { votes, receipts };
}

/**
 * One model alone, with the same juror prompt and validation (no Ultra): the single-model arms of the
 * accuracy table. A row without a valid vote comes back unresolved.
 */
export async function runSingleJuror(items: JuryItem[], model: ModelKey, opts: { llm: Llm; tracer: Tracer; batchSize?: number }): Promise<Resolution[]> {
  const size = Math.max(1, Math.floor(opts.batchSize ?? JURY_BATCH_SIZE));
  const out = new Map<string, Resolution>();
  await Promise.all(chunk(items, size).map(async (b, bi) => {
    const entries = b.map((item, i) => ({ localId: `I${i + 1}`, item }));
    const prompt = buildJurorPrompt(entries);
    const res = await safeChat(opts.llm, { model, agent: `single.${model}`, system: prompt.system, user: prompt.user, json: true });
    const parsed = res.receipt.status === "ok" ? parseVotes(res.json, entries) : { votes: new Map<string, ParsedVote>(), problems: [] };
    for (const e of entries) {
      const v = parsed.votes.get(e.localId) ?? null;
      out.set(e.item.row.row_id, v
        ? resolution(e.item, v.candidate, { votes: [jurorVote(e.item, model, v, res.receipt)], product_type: v.product_type, confidence: v.confidence, version: e.item.version ?? v.version })
        : unresolved(e.item, []));
    }
    opts.tracer.emit({
      agent: `single.${model}`, action: "single_model_vote", receipt_id: res.receipt.receipt_id,
      latency_ms: res.receipt.latency_ms, status: res.receipt.status === "ok" ? "ok" : "error",
      output_summary: `batch ${bi + 1}: ${parsed.votes.size} of ${entries.length} valid votes`,
      details: { problems: parsed.problems },
    });
  }));
  return items.map((i) => out.get(i.row.row_id) as Resolution);
}
