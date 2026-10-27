// An unlabelled development run: before a human answer sheet exists, the arms still run on the development rows
// (the inventory minus the sealed test rows), and the run reports what can be measured without answers: what each
// arm named, how often it agrees with the full system, the share of rows that needed Ultra, the model calls, the
// tokens, the time and the full system's decisions. There is no accuracy: nothing here is scored against answers.
import type { InventoryRow, KevPair } from "../contracts.ts";
import { canonRowId, normName } from "./answers.ts";
import { callStats, isNullPrediction } from "./score.ts";
import { ArmUnavailableError } from "./types.ts";
import type {
  ArmName, ArmOutput, ArmPrediction, ResolveArm, UnlabelledArmMetrics, UnlabelledArmResult, UnlabelledEvalResult, UnlabelledRow,
} from "./types.ts";

export interface UnlabelledInput {
  arms: ArmName[];
  inventory: InventoryRow[];
  testIds: string[];
  resolveArm: ResolveArm;
  /** Every KEV family a pair names (A1's familiesOf); agreement then counts any spelling of one family. */
  families?: (p: KevPair) => string[];
  now?: () => number;           // monotonic ms, for arm timing
  clock?: () => Date;           // for generated_at
  log?: (line: string) => void; // aggregate progress only
}

/** The development rows: every inventory row that is not a sealed test row (first row per id). */
export function devRowsOf(inventory: InventoryRow[], testIds: string[]): { rows: InventoryRow[]; sealed_excluded: number } {
  const sealed = new Set(testIds.map(canonRowId));
  const seen = new Set<string>();
  const rows: InventoryRow[] = [];
  let excluded = 0;
  for (const r of inventory) {
    const id = canonRowId(r.row_id);
    if (seen.has(id)) continue;
    seen.add(id);
    if (sealed.has(id)) excluded++;
    else rows.push(r);
  }
  return { rows, sealed_excluded: excluded };
}

function blank(s: string | null | undefined): string | null {
  return typeof s === "string" && s.trim() !== "" ? s : null;
}

/** One row's answer from an arm's predictions (first prediction per row wins, as in scoring). */
function rowAnswer(id: string, p: ArmPrediction | undefined): UnlabelledRow {
  if (!p) return { row_id: id, vendor: null, product: null, abstained: false, missing: true, used_ultra: false };
  const abstained = Boolean(p.abstained);
  const named = !abstained && !isNullPrediction(p);
  return {
    row_id: id,
    vendor: named ? blank(p.vendor) : null,
    product: named ? blank(p.product) : null,
    abstained,
    missing: false,
    used_ultra: Boolean(p.used_ultra),
    ...(p.decision !== undefined ? { decision: p.decision } : {}),
  };
}

/**
 * Do two answers agree? Both "no KEV product", or both name a KEV product of the same family (any spelling,
 * when `families` is given; otherwise the same vendor and product, case- and space-insensitive).
 * Returns null when either one abstained or is missing (not comparable).
 */
export function sameAnswer(a: UnlabelledRow, b: UnlabelledRow, families?: (p: KevPair) => string[]): boolean | null {
  if (a.abstained || a.missing || b.abstained || b.missing) return null;
  const aNull = a.product === null;
  const bNull = b.product === null;
  if (aNull || bNull) return aNull && bNull;
  if (normName(a.vendor ?? "") === normName(b.vendor ?? "") && normName(a.product!) === normName(b.product!)) return true;
  if (!families) return false;
  const fa = new Set(families({ vendor: a.vendor ?? "", product: a.product! }));
  return families({ vendor: b.vendor ?? "", product: b.product! }).some((f) => fa.has(f));
}

function ratio(n: number, d: number): number | null {
  return d === 0 ? null : n / d;
}

/** Summarises one arm's output over the asked rows (no answers, so no accuracy). */
export function summariseUnlabelledArm(
  rowIds: string[],
  out: ArmOutput,
  timeMs: number,
): { metrics: UnlabelledArmMetrics; rows: UnlabelledRow[]; extra_predictions: string[] } {
  const byId = new Map<string, ArmPrediction>();
  for (const p of out.predictions) {
    const id = canonRowId(p.row_id);
    if (!byId.has(id)) byId.set(id, p);
  }
  const asked = new Set(rowIds.map(canonRowId));
  const extra = [...byId.keys()].filter((id) => !asked.has(id));
  const rows = rowIds.map((id) => rowAnswer(canonRowId(id), byId.get(canonRowId(id))));
  const ultraRows = rows.filter((r) => r.used_ultra).length;
  const reviewed = out.run?.ultra_reviewed_rows;
  const metrics: UnlabelledArmMetrics = {
    rows: rows.length,
    named_kev: rows.filter((r) => !r.missing && !r.abstained && r.product !== null).length,
    no_kev: rows.filter((r) => !r.missing && !r.abstained && r.product === null).length,
    abstained: rows.filter((r) => r.abstained).length,
    missing: rows.filter((r) => r.missing).length,
    ultra_rows: ultraRows,
    ultra_share: ratio(ultraRows, rows.length),
    ultra_reviewed: reviewed ? reviewed.filter((id) => asked.has(canonRowId(id))).length : null,
    agree_with_full: null,
    ...callStats(out.receipts),
    time_ms: timeMs,
  };
  return { metrics, rows, extra_predictions: extra };
}

/** Runs each arm, one after another, on the development rows, and compares every arm with the full system. */
export async function runUnlabelledEvaluation(input: UnlabelledInput): Promise<UnlabelledEvalResult> {
  const now = input.now ?? (() => performance.now());
  const clock = input.clock ?? (() => new Date());
  const log = input.log ?? (() => {});
  if (input.arms.length === 0) throw new Error("no arms selected");
  const { rows, sealed_excluded } = devRowsOf(input.inventory, input.testIds);
  if (rows.length === 0) throw new Error("no dev rows to run (every inventory row is a sealed test row)");
  const ids = rows.map((r) => canonRowId(r.row_id));

  const results: UnlabelledArmResult[] = [];
  for (const arm of input.arms) {
    const t0 = now();
    try {
      const raw = await input.resolveArm(arm, structuredClone(rows));
      if (!raw || !Array.isArray(raw.predictions) || !Array.isArray(raw.receipts)) throw new Error("resolveArm returned no {predictions, receipts}");
      const ms = Math.round(now() - t0);
      const s = summariseUnlabelledArm(ids, raw, ms);
      results.push({
        arm, status: "ok", notes: raw.notes ?? [], metrics: s.metrics, rows: s.rows,
        disagree_with_full: [], extra_predictions: s.extra_predictions, ...(raw.run ? { run: raw.run } : {}),
      });
      const m = s.metrics;
      log(`arm ${arm}: ${m.named_kev} named a KEV product, ${m.no_kev} none, ${m.abstained} to the owner; ${m.calls} model calls, ${(ms / 1000).toFixed(1)} s`);
    } catch (e) {
      const unavailable = e instanceof ArmUnavailableError;
      const message = e instanceof Error ? e.message : String(e);
      results.push({ arm, status: unavailable ? "unavailable" : "error", message, notes: [], metrics: null, rows: [], disagree_with_full: [], extra_predictions: [] });
      log(`arm ${arm}: ${unavailable ? "not run" : "failed"}: ${message}`);
    }
  }

  const full = results.find((r) => r.arm === "full" && r.status === "ok");
  if (full) {
    const fullBy = new Map(full.rows.map((r) => [r.row_id, r] as const));
    for (const r of results) {
      if (r === full || !r.metrics) continue;
      let compared = 0;
      let agree = 0;
      for (const row of r.rows) {
        const f = fullBy.get(row.row_id);
        const same = f ? sameAnswer(row, f, input.families) : null;
        if (same === null) continue;
        compared++;
        if (same) agree++;
        else r.disagree_with_full.push(row.row_id);
      }
      r.metrics.agree_with_full = { compared, agree };
    }
  }

  return { kind: "unlabelled", set: "dev", generated_at: clock().toISOString(), rows_evaluated: rows.length, sealed_rows_excluded: sealed_excluded, arms: results };
}
