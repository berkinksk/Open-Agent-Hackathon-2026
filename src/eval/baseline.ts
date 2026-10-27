// The one-call baseline arm: a single model call given every row and the union of all candidates.
// It answers "is the jury + critic worth it over just asking one model once?".
import type { InventoryRow, KevPair, Llm, ModelKey } from "../contracts.ts";
import { canonRowId, normName } from "./answers.ts";
import type { ArmOutput, ArmPrediction } from "./types.ts";

const SYSTEM = [
  "You match software inventory entries to products in the CISA Known Exploited Vulnerabilities (KEV) catalogue.",
  "You get a list of inventory rows and a list of candidate KEV (vendor, product) pairs.",
  "For each row, choose the one candidate pair that names the same product the row describes, or null if no candidate is that product.",
  "A similar name is not enough: a cloud or online service is not the on-premises server, and an endpoint client is not the server or management console.",
  "Copy vendor and product exactly as written in the candidate list.",
  'Reply with JSON only: {"results":[{"row_id":"...","vendor":"..." or null,"product":"..." or null}]}, with one entry per row.',
].join(" ");

/** Deduplicates candidate pairs (case/space-insensitive) and sorts them for a stable prompt. */
export function uniqueCandidates(pairs: KevPair[]): KevPair[] {
  const seen = new Map<string, KevPair>();
  for (const p of pairs) {
    const k = `${normName(p.vendor)}|${normName(p.product)}`;
    if (!seen.has(k)) seen.set(k, { vendor: p.vendor, product: p.product });
  }
  return [...seen.values()].sort((a, b) =>
    a.vendor.localeCompare(b.vendor) || a.product.localeCompare(b.product));
}

export function buildBaselinePrompt(rows: InventoryRow[], candidates: KevPair[]): { system: string; user: string } {
  const cands = uniqueCandidates(candidates).map((c, i) => `${i + 1}. ${c.vendor.trim()} | ${c.product.trim()}`);
  const items = rows.map((r) => {
    const ctx = r.asset_type && r.asset_type.trim() !== "" ? ` [asset type: ${r.asset_type.trim()}]` : "";
    return `- ${r.row_id}: ${JSON.stringify(r.software)}${ctx}`;
  });
  const user = [
    `Candidate KEV pairs (vendor | product), ${cands.length} in total:`,
    ...cands,
    "",
    `Inventory rows, ${rows.length} in total:`,
    ...items,
  ].join("\n");
  return { system: SYSTEM, user };
}

/** Extracts the JSON object from a reply: the parsed json if present, else the text after any </think>. */
export function extractJson(json: unknown, text: string): unknown {
  if (json !== null && json !== undefined) return json;
  const afterThink = text.includes("</think>") ? text.slice(text.lastIndexOf("</think>") + 8) : text;
  const start = afterThink.search(/[[{]/);
  if (start < 0) return null;
  const end = Math.max(afterThink.lastIndexOf("}"), afterThink.lastIndexOf("]"));
  if (end <= start) return null;
  try { return JSON.parse(afterThink.slice(start, end + 1)); } catch { return null; }
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() !== "" && v.trim().toLowerCase() !== "null" ? v : null;
}

/** Turns the reply into predictions for the asked rows only. Unknown or repeated row ids are ignored. */
export function parseBaselineReply(reply: unknown, rows: InventoryRow[]): ArmPrediction[] | null {
  const list = Array.isArray(reply)
    ? reply
    : reply && typeof reply === "object" && Array.isArray((reply as { results?: unknown }).results)
      ? (reply as { results: unknown[] }).results
      : null;
  if (!list) return null;
  const asked = new Map(rows.map((r) => [canonRowId(r.row_id), r.row_id] as const));
  const out = new Map<string, ArmPrediction>();
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    const rawId = typeof o.row_id === "string" ? o.row_id : null;
    const id = rawId ? asked.get(canonRowId(rawId)) : undefined;
    if (!id || out.has(id)) continue;
    const product = str(o.product);
    out.set(id, { row_id: id, vendor: product ? str(o.vendor) : null, product });
  }
  return [...out.values()];
}

/** Runs the baseline: exactly one model call. A reply that cannot be parsed leaves every row missing. */
export async function runBaseline(
  llm: Llm,
  rows: InventoryRow[],
  candidates: KevPair[],
  model: ModelKey = "ultra",
): Promise<ArmOutput> {
  const { system, user } = buildBaselinePrompt(rows, candidates);
  const res = await llm.chat({
    model,
    agent: "eval_baseline",
    system,
    user,
    json: true,
    max_tokens: Math.min(8000, 300 + rows.length * 60),
  });
  const preds = parseBaselineReply(extractJson(res.json, res.text), rows);
  const notes = [`one ${model} call given all ${rows.length} rows and ${uniqueCandidates(candidates).length} candidate pairs`];
  if (preds === null) notes.push("the reply could not be parsed as JSON, so every row counts as missing");
  return { predictions: preds ?? [], receipts: [res.receipt], notes };
}
