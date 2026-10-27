// Scoring against human answers, by KEV family: any listed spelling counts, and "none" is correct
// when the prediction is null. Names are compared case- and space-insensitively.
import { MODELS } from "../contracts.ts";
import type { PatchLine, Receipt, Resolution } from "../contracts.ts";
import { canonRowId, normName } from "./answers.ts";
import type { AnswerRow, ArmMetrics, ArmPrediction, CallStats, RowOutcome, RowScore } from "./types.ts";

export { normName } from "./answers.ts";

function blankToNull(s: string | null | undefined): string | null {
  return typeof s === "string" && s.trim() !== "" ? s : null;
}

/**
 * A prediction is "null" (not in KEV) when it names no product. A vendor without a product
 * claims no KEV entry, so it counts as null.
 */
export function isNullPrediction(p: Pick<ArmPrediction, "product"> | undefined): boolean {
  return blankToNull(p?.product ?? null) === null;
}

/** True when the predicted vendor and product match the answer (any listed spelling). */
export function matchesAnswer(p: Pick<ArmPrediction, "vendor" | "product">, a: AnswerRow): boolean {
  if (a.is_none) return false;
  const v = blankToNull(p.vendor);
  const pr = blankToNull(p.product);
  if (v === null || pr === null) return false;
  const vendorOk = a.kev_vendors.some((x) => normName(x) === normName(v));
  const productOk = a.kev_products.some((x) => normName(x) === normName(pr));
  return vendorOk && productOk;
}

/** Scores one row. `p` undefined = the arm returned nothing for this row. */
export function scoreRow(a: AnswerRow, p: ArmPrediction | undefined): RowScore {
  let outcome: RowOutcome;
  if (!p) outcome = "missing";
  else if (a.is_none) {
    if (!isNullPrediction(p) && !p.abstained) outcome = "false_match";
    else outcome = p.abstained ? "none_abstained" : "none_ok";
  } else if (p.abstained) outcome = "abstained";
  else if (isNullPrediction(p)) outcome = "missed";
  else outcome = matchesAnswer(p, a) ? "match_ok" : "wrong_match";
  const correct = outcome === "match_ok" || outcome === "none_ok" || outcome === "none_abstained";
  return {
    row_id: a.row_id,
    outcome,
    correct,
    predicted: {
      vendor: p && !p.abstained ? blankToNull(p.vendor) : null,
      product: p && !p.abstained ? blankToNull(p.product) : null,
    },
    expected: { vendor: a.kev_vendor, products: a.kev_products, none: a.is_none },
    used_ultra: Boolean(p?.used_ultra),
    lookalike: a.lookalike,
  };
}

function ratio(n: number, d: number): number | null {
  return d === 0 ? null : n / d;
}

/** Scores every answer row against an arm's predictions and summarises the receipts. */
export function scoreArm(
  answers: AnswerRow[],
  predictions: ArmPrediction[],
  receipts: Receipt[],
  timeMs: number,
): { metrics: ArmMetrics; rows: RowScore[]; extra_predictions: string[] } {
  const byId = new Map<string, ArmPrediction>();
  for (const p of predictions) {
    const id = canonRowId(p.row_id);
    if (!byId.has(id)) byId.set(id, p); // first prediction per row wins
  }
  const asked = new Set(answers.map((a) => a.row_id));
  const extra = [...byId.keys()].filter((id) => !asked.has(id));
  const rows = answers.map((a) => scoreRow(a, byId.get(a.row_id)));
  const count = (o: RowOutcome) => rows.filter((r) => r.outcome === o).length;

  const correct = rows.filter((r) => r.correct).length;
  const correctStrict = count("match_ok") + count("none_ok");
  const kevRows = answers.filter((a) => !a.is_none).length;
  const noneRows = answers.length - kevRows;
  const noneRejected = count("none_ok") + count("none_abstained");
  const lookalikeRows = rows.filter((r) => r.lookalike && r.expected.none);
  const ultraRows = rows.filter((r) => r.used_ultra).length;
  const s = callStats(receipts);

  const metrics: ArmMetrics = {
    rows: rows.length,
    correct,
    accuracy: ratio(correct, rows.length),
    correct_strict: correctStrict,
    accuracy_strict: ratio(correctStrict, rows.length),
    kev_rows: kevRows,
    kev_matched: count("match_ok"),
    none_rows: noneRows,
    none_rejected: noneRejected,
    lookalike_rows: lookalikeRows.length,
    lookalike_rejected: lookalikeRows.filter((r) => r.correct).length,
    abstained: count("abstained") + count("none_abstained"),
    missing: count("missing"),
    wrong_match: count("wrong_match"),
    false_match: count("false_match"),
    missed: count("missed"),
    ultra_rows: ultraRows,
    ultra_share: ratio(ultraRows, rows.length),
    ...s,
    time_ms: timeMs,
  };
  return { metrics, rows, extra_predictions: extra };
}

/** Model-call totals from an arm's receipts: calls per requested model, Ultra calls, failures and tokens. */
export function callStats(receipts: Receipt[]): CallStats {
  const callsByModel: Record<string, number> = {};
  let promptTokens = 0;
  let completionTokens = 0;
  let callErrors = 0;
  for (const r of receipts) {
    callsByModel[r.requested_model] = (callsByModel[r.requested_model] ?? 0) + 1;
    promptTokens += r.prompt_tokens ?? 0;
    completionTokens += r.completion_tokens ?? 0;
    if (r.status === "error") callErrors++;
  }
  return {
    calls: receipts.length,
    calls_by_model: callsByModel,
    ultra_calls: receipts.filter((r) => r.requested_model === MODELS.ultra).length,
    call_errors: callErrors,
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    tokens: promptTokens + completionTokens,
  };
}

/**
 * Maps the pipeline's Resolution to a prediction. An unresolved row, or one the critic sent to the
 * owner, is an abstention (null). Ultra counts as used when it adjudicated or cast a vote.
 */
export function predictionFromResolution(
  res: Resolution,
  critic?: PatchLine["critic"],
): ArmPrediction {
  const abstained = res.status === "unresolved" || critic?.verdict === "ask_owner";
  const usedUltra = res.adjudicated_by === "ultra" || res.votes.some((v) => v.juror === "ultra");
  if (abstained) return { row_id: res.row_id, vendor: null, product: null, abstained: true, used_ultra: usedUltra };
  if (res.status === "no_match") return { row_id: res.row_id, vendor: null, product: null, used_ultra: usedUltra };
  return { row_id: res.row_id, vendor: res.vendor, product: res.product, used_ultra: usedUltra };
}
