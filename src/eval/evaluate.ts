// The evaluation runner: picks the rows (dev, or the sealed test rows with --final), runs each arm through
// the injected resolveArm one after another, and scores the predictions. It never prints per-row results.
import type { InventoryRow, KevPair, ModelKey } from "../contracts.ts";
import { canonRowId, normName } from "./answers.ts";
import { scoreArm } from "./score.ts";
import { assertSetAllowed, selectRows } from "./split.ts";
import { ArmUnavailableError } from "./types.ts";
import type { AnswerRow, AnswerSheet, ArmName, ArmOutput, ArmResult, EvalResult, EvalSet, ResolveArm, SheetIssue } from "./types.ts";

export interface EvalInput {
  set: EvalSet;
  final: boolean;
  arms: ArmName[];
  labels: AnswerSheet;
  testIds: string[];
  /** The inventory rows (by row_id). null = build rows from the label sheet's software column. */
  inventory: InventoryRow[] | null;
  resolveArm: ResolveArm;
  now?: () => number;          // monotonic ms, for arm timing
  clock?: () => Date;          // for generated_at
  log?: (line: string) => void; // aggregate progress only
  baselineModel?: ModelKey;
  /** Every KEV family a pair names (A1's familiesOf): scores by KEV family (design §12). Absent: listed spellings only. */
  families?: (p: KevPair) => string[];
}

function rowFromLabel(a: AnswerRow): InventoryRow {
  return { row_id: a.row_id, asset_id: "", asset_name: "", asset_type: "", internet_facing: false, owner_team: "", software: a.software };
}

/** Pairs each selected label with its inventory row. Rows that cannot be built are reported, not guessed. */
export function buildEvalRows(
  answers: AnswerRow[],
  inventory: InventoryRow[] | null,
): { rows: InventoryRow[]; answers: AnswerRow[]; no_row: string[]; software_mismatches: string[] } {
  const inv = new Map<string, InventoryRow>();
  for (const r of inventory ?? []) {
    const id = canonRowId(r.row_id);
    if (!inv.has(id)) inv.set(id, r);
  }
  const rows: InventoryRow[] = [];
  const kept: AnswerRow[] = [];
  const noRow: string[] = [];
  const mismatches: string[] = [];
  for (const a of answers) {
    const r = inv.get(a.row_id);
    if (r) {
      if (a.software !== "" && normName(a.software) !== normName(r.software)) mismatches.push(a.row_id);
      rows.push(r);
      kept.push(a);
    } else if (inventory === null && a.software !== "") {
      rows.push(rowFromLabel(a));
      kept.push(a);
    } else {
      noRow.push(a.row_id);
    }
  }
  return { rows, answers: kept, no_row: noRow, software_mismatches: mismatches };
}

function validateOutput(out: unknown): ArmOutput {
  const o = out as ArmOutput | null;
  if (!o || !Array.isArray(o.predictions) || !Array.isArray(o.receipts)) {
    throw new Error("resolveArm returned no {predictions, receipts}");
  }
  return o;
}

/** Dev runs never show the details of a sealed test row's answer (an issue can quote it): only its id and line. */
export function withholdSealedIssues(issues: SheetIssue[], testIds: string[]): SheetIssue[] {
  const sealed = new Set(testIds.map(canonRowId));
  return issues.map((i) =>
    i.row_id !== null && sealed.has(i.row_id)
      ? { ...i, problem: "an issue on a sealed test row (details withheld outside the final run)" }
      : i,
  );
}

function pct(n: number | null): string {
  return n === null ? "n/a" : `${(n * 100).toFixed(1)}%`;
}

export async function runEvaluation(input: EvalInput): Promise<EvalResult> {
  const now = input.now ?? (() => performance.now());
  const clock = input.clock ?? (() => new Date());
  const log = input.log ?? (() => {});
  assertSetAllowed(input.set, input.final);
  if (input.arms.length === 0) throw new Error("no arms selected");

  const sel = selectRows(input.set, input.labels.rows, input.testIds);
  if (sel.missing_labels.length > 0) {
    // A refused final run: say why each test row is unusable, so the sheet can be fixed before the one run.
    const why = sel.missing_labels.map((id) => {
      const found = input.labels.issues.filter((i) => i.row_id === id).map((i) => `line ${i.line}: ${i.problem}`);
      return `${id} (${found.length > 0 ? found.join(" | ") : "not in the answer sheet"})`;
    });
    throw new Error(
      `${sel.missing_labels.length} test row(s) have no usable agreed answer: ${why.join("; ")}. Fix the answer sheet, then run again`,
    );
  }
  const built = buildEvalRows(sel.answers, input.inventory);
  if (input.set === "test" && built.no_row.length > 0) {
    throw new Error(`${built.no_row.length} test row(s) are missing from the inventory: ${built.no_row.join(", ")}`);
  }
  if (built.rows.length === 0) throw new Error(`no ${input.set} rows to evaluate`);

  let unlabelled: string[] = [];
  if (input.inventory && input.set === "dev") {
    const labelled = new Set(input.labels.rows.map((a) => a.row_id));
    const sealed = new Set(input.testIds.map(canonRowId));
    unlabelled = input.inventory.map((r) => canonRowId(r.row_id)).filter((id) => !labelled.has(id) && !sealed.has(id));
  }

  const results: ArmResult[] = [];
  for (const arm of input.arms) {
    const t0 = now();
    try {
      const out = validateOutput(await input.resolveArm(arm, structuredClone(built.rows)));
      const ms = Math.round(now() - t0);
      const scored = scoreArm(built.answers, out.predictions, out.receipts, ms, input.families);
      results.push({ arm, status: "ok", notes: out.notes ?? [], metrics: scored.metrics, rows: scored.rows, extra_predictions: scored.extra_predictions });
      const m = scored.metrics;
      log(`arm ${arm}: ${m.correct}/${m.rows} correct (${pct(m.accuracy)}), ${m.calls} model calls, ${(ms / 1000).toFixed(1)} s`);
    } catch (e) {
      const unavailable = e instanceof ArmUnavailableError;
      const message = e instanceof Error ? e.message : String(e);
      results.push({ arm, status: unavailable ? "unavailable" : "error", message, notes: [], metrics: null, rows: [], extra_predictions: [] });
      log(`arm ${arm}: ${unavailable ? "not run" : "failed"}: ${message}`);
    }
  }

  return {
    set: input.set,
    final: input.final,
    generated_at: clock().toISOString(),
    labels_source: input.labels.source,
    rows_evaluated: built.rows.length,
    sealed_rows_excluded: sel.sealed_excluded,
    unlabelled_rows: unlabelled,
    rows_without_inventory: built.no_row,
    label_issues: input.set === "dev" ? withholdSealedIssues(input.labels.issues, input.testIds) : input.labels.issues,
    software_mismatches: built.software_mismatches,
    arms: results,
    ...(input.arms.includes("baseline") && input.baselineModel ? { baseline_model: input.baselineModel } : {}),
    scoring: input.families ? "kev_family" : "listed_spellings",
  };
}
