// Renders an EvalResult as a Markdown table and a JSON document. Per-row results go into the files only
// (dev set: misses listed in the Markdown; test set: per-row only in the JSON of the final run).
import { MODELS } from "../contracts.ts";
import { mdCell } from "./csv.ts";
import type { ArmName, ArmResult, EvalResult, RowScore } from "./types.ts";

const ARM_LABELS: Record<ArmName, string> = {
  full: "Full system (jury + Ultra + critic)",
  bolt: "Bolt alone",
  lightning: "Lightning alone",
  ultra: "Ultra alone",
  baseline: "One-call baseline",
  normaliser: "Normaliser alone (no model)",
};

export function armLabel(arm: ArmName, r?: EvalResult): string {
  if (arm === "baseline" && r?.baseline_model) return `${ARM_LABELS.baseline} (${r.baseline_model})`;
  return ARM_LABELS[arm];
}

function frac(n: number, d: number): string {
  return d === 0 ? "–" : `${n}/${d} (${((n / d) * 100).toFixed(1)}%)`;
}
function int(n: number): string {
  return n.toLocaleString("en-GB");
}
function secs(ms: number): string {
  return `${(ms / 1000).toFixed(1)} s`;
}
/** "1 row", "2 rows". */
export function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** The headline table: one line per arm. */
export function renderSummaryTable(r: EvalResult): string {
  const head = "| Arm | Accuracy | Strict | KEV rows matched | None rows rejected | Abstained | Rows needing Ultra | Ultra calls | Model calls | Tokens | Time |";
  const sep = "|---|---|---|---|---|---|---|---|---|---|---|";
  const lines = r.arms.map((a) => {
    const name = mdCell(armLabel(a.arm, r));
    if (!a.metrics) {
      return `| ${name} | not run: ${mdCell(a.message ?? a.status)} | | | | | | | | | |`;
    }
    const m = a.metrics;
    const cells = [
      name,
      frac(m.correct, m.rows),
      frac(m.correct_strict, m.rows),
      frac(m.kev_matched, m.kev_rows),
      frac(m.none_rejected, m.none_rows),
      String(m.abstained),
      frac(m.ultra_rows, m.rows),
      m.calls === 0 ? "0" : `${m.ultra_calls} of ${m.calls}`,
      String(m.calls),
      int(m.tokens),
      secs(m.time_ms),
    ];
    return `| ${cells.join(" | ")} |`;
  });
  return [head, sep, ...lines].join("\n");
}

function callsByModelTable(r: EvalResult): string {
  const known = new Map<string, string>(Object.entries(MODELS).map(([k, v]) => [v, k]));
  const rows = r.arms.filter((a) => a.metrics && a.metrics.calls > 0).map((a) => {
    const m = a.metrics!;
    const by = (key: string) => String(m.calls_by_model[MODELS[key as keyof typeof MODELS]] ?? 0);
    const other = Object.entries(m.calls_by_model).filter(([id]) => !known.has(id)).reduce((s, [, n]) => s + n, 0);
    return `| ${mdCell(armLabel(a.arm, r))} | ${by("bolt")} | ${by("lightning")} | ${by("ultra")} | ${other} | ${m.call_errors} | ${int(m.prompt_tokens)} | ${int(m.completion_tokens)} |`;
  });
  if (rows.length === 0) return "";
  return [
    "| Arm | Bolt | Lightning | Ultra | Other | Failed calls | Prompt tokens | Completion tokens |",
    "|---|---|---|---|---|---|---|---|",
    ...rows,
  ].join("\n");
}

function showPredicted(s: RowScore): string {
  if (s.outcome === "missing") return "(no prediction)";
  if (s.outcome === "abstained" || s.outcome === "none_abstained") return "(left to the owner)";
  return s.predicted.product === null ? "null" : `${s.predicted.vendor ?? "?"} / ${s.predicted.product}`;
}
function showExpected(s: RowScore): string {
  return s.expected.none ? "none" : `${s.expected.vendor ?? "?"} / ${s.expected.products.join("; ")}`;
}

function missesTable(r: EvalResult): string {
  const lines: string[] = [];
  for (const a of r.arms) {
    for (const s of a.rows) {
      if (s.correct && s.outcome !== "none_abstained") continue;
      lines.push(`| ${mdCell(s.row_id)} | ${mdCell(armLabel(a.arm, r))} | ${s.outcome} | ${mdCell(showPredicted(s))} | ${mdCell(showExpected(s))} |`);
    }
  }
  if (lines.length === 0) return "No misses.";
  return ["| Row | Arm | Outcome | Predicted | Expected |", "|---|---|---|---|---|", ...lines].join("\n");
}

export function renderEvalMarkdown(r: EvalResult): string {
  const out: string[] = [];
  out.push(`# Matching accuracy: ${r.set} set${r.final ? " (final run)" : ""}`, "");
  out.push(`- **Generated:** ${r.generated_at}`);
  out.push(`- **Rows scored:** ${r.rows_evaluated}` + (r.set === "dev" ? ` (development rows; ${plural(r.sealed_rows_excluded, "sealed test row")} withheld)` : " (the sealed test rows)"));
  out.push(`- **Answers:** ${mdCell(r.labels_source)} (human answer sheet)`);
  out.push("- **Scoring:** by KEV family. A row is correct when the vendor matches and the product is any spelling the answer lists (case- and space-insensitive), or when the answer is `none` and the arm names no KEV product.");
  out.push("- **Strict:** the same, but an abstention (left to the owner) never counts as correct.");
  out.push("- **Arms** ran one after another, never in parallel.");
  out.push("");
  out.push(renderSummaryTable(r), "");
  const byModel = callsByModelTable(r);
  if (byModel) out.push("## Model calls by model", "", byModel, "");

  const notes: string[] = [];
  for (const a of r.arms) {
    for (const n of a.notes) notes.push(`${armLabel(a.arm, r)}: ${n}`);
    if (a.extra_predictions.length > 0) notes.push(`${armLabel(a.arm, r)}: ${a.extra_predictions.length} prediction(s) for rows that were not asked (ignored)`);
  }
  if (r.software_mismatches.length > 0) notes.push(`The answer sheet's software text differs from the inventory for: ${r.software_mismatches.join(", ")} (check the row ids line up)`);
  if (r.rows_without_inventory.length > 0) notes.push(`Labelled rows missing from the inventory (skipped): ${r.rows_without_inventory.join(", ")}`);
  if (r.unlabelled_rows.length > 0) notes.push(`Inventory rows without a usable label (not scored): ${r.unlabelled_rows.length}`);
  for (const i of r.label_issues) notes.push(`Answer sheet line ${i.line}${i.row_id ? ` (${i.row_id})` : ""}: ${i.problem}`);
  if (notes.length > 0) out.push("## Notes", "", ...notes.map((n) => `- ${mdCell(n)}`), "");

  if (r.set === "dev") out.push("## Misses on development rows", "", missesTable(r), "");
  out.push("Every number above comes from this run's real predictions and receipts; nothing is hand-entered.", "");
  return out.join("\n");
}

/** JSON for the evidence file. Per-row outcomes are included for dev, and for test only on the final run. */
export function evalJson(r: EvalResult): Record<string, unknown> {
  const keepRows = r.set === "dev" || r.final;
  return {
    ...r,
    arms: r.arms.map((a: ArmResult) => ({ ...a, label: armLabel(a.arm, r), rows: keepRows ? a.rows : [] })),
  };
}

/** A file stem like eval-2026-10-27-103000-test (UTC). */
export function evalFileStem(set: string, d: Date): string {
  const iso = d.toISOString();
  return `eval-${iso.slice(0, 10)}-${iso.slice(11, 19).replace(/:/g, "")}-${set}`;
}
