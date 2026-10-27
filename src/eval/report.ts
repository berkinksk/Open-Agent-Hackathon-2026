// Renders an EvalResult as a Markdown table and a JSON document. Per-row results go into the files only
// (dev set: misses listed in the Markdown; test set: per-row only in the JSON of the final run).
import { MODELS } from "../contracts.ts";
import { mdCell } from "./csv.ts";
import type { ArmName, ArmResult, EvalResult, RowScore, UnlabelledEvalResult, UnlabelledRow } from "./types.ts";

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

// ---------- unlabelled development runs ----------

function answerText(r: UnlabelledRow | undefined): string {
  if (!r || r.missing) return "(no prediction)";
  if (r.abstained) return "(left to the owner)";
  return r.product === null ? "no KEV product" : `${r.vendor ?? "?"} / ${r.product}`;
}

function share(n: number | null, d: number): string {
  return n === null ? "n/a" : frac(n, d);
}

/** The headline table of an unlabelled run: one line per arm, no accuracy. */
export function renderUnlabelledSummaryTable(r: UnlabelledEvalResult): string {
  const head = "| Arm | Named a KEV product | No KEV product | Left to the owner | Agrees with the full system | Rows: split decided by Ultra | Rows: Ultra in any role | Ultra calls | Model calls | Tokens | Time |";
  const sep = "|---|---|---|---|---|---|---|---|---|---|---|";
  const lines = r.arms.map((a) => {
    const name = mdCell(ARM_LABELS[a.arm]);
    if (!a.metrics) return `| ${name} | not run: ${mdCell(a.message ?? a.status)} | | | | | | | | | |`;
    const m = a.metrics;
    const agree = a.arm === "full" ? "–" : m.agree_with_full ? frac(m.agree_with_full.agree, m.agree_with_full.compared) : "n/a";
    const cells = [
      name, String(m.named_kev), String(m.no_kev), String(m.abstained) + (m.missing ? ` (+${m.missing} missing)` : ""), agree,
      frac(m.ultra_rows, m.rows), share(m.ultra_reviewed, m.rows),
      m.calls === 0 ? "0" : `${m.ultra_calls} of ${m.calls}`, String(m.calls), int(m.tokens), secs(m.time_ms),
    ];
    return `| ${cells.join(" | ")} |`;
  });
  return [head, sep, ...lines].join("\n");
}

function unlabelledCallsTable(r: UnlabelledEvalResult): string {
  const rows = r.arms.filter((a) => a.metrics && a.metrics.calls > 0).map((a) => {
    const m = a.metrics!;
    const by = (key: keyof typeof MODELS) => String(m.calls_by_model[MODELS[key]] ?? 0);
    return `| ${mdCell(ARM_LABELS[a.arm])} | ${by("bolt")} | ${by("lightning")} | ${by("ultra")} | ${m.call_errors} | ${int(m.prompt_tokens)} | ${int(m.completion_tokens)} |`;
  });
  if (rows.length === 0) return "";
  return ["| Arm | Bolt | Lightning | Ultra | Failed calls | Prompt tokens | Completion tokens |", "|---|---|---|---|---|---|---|", ...rows].join("\n");
}

export function renderUnlabelledMarkdown(r: UnlabelledEvalResult): string {
  const out: string[] = [];
  out.push("# Development run, unlabelled (no accuracy)", "");
  out.push(`- **Generated:** ${r.generated_at}`);
  out.push(`- **Rows:** ${r.rows_evaluated} development rows (the inventory minus ${plural(r.sealed_rows_excluded, "sealed test row")}, which never reached an arm).`);
  out.push("- **No accuracy:** no human answer sheet was given, so nothing is scored. This run measures what each arm named, its agreement with the full system, the rows that needed Ultra, the model calls, the tokens, the time and the full system's decisions.");
  out.push("- **Agreement** counts the rows both arms answered: the same KEV family (any spelling) or both \"no KEV product\". Rows left to the owner are not compared.");
  out.push("- **Rows: split decided by Ultra** = the jurors disagreed and Ultra decided (or voted). **Rows: Ultra in any role** adds Ultra's critiques, same-product checks and re-decides (full system, read from its trace).");
  out.push("- **Arms** ran one after another, never in parallel.");
  out.push("");
  out.push(renderUnlabelledSummaryTable(r), "");
  const calls = unlabelledCallsTable(r);
  if (calls) out.push("## Model calls by model", "", calls, "");

  const full = r.arms.find((a) => a.arm === "full" && a.run);
  if (full?.run) {
    const d = full.run.decisions;
    const n = (k: string) => String(d[k] ?? 0);
    out.push("## Full system: decisions", "");
    out.push("| patch_now | this_cycle | monitor | ask_owner | Owner questions | Run status | Run id |", "|---|---|---|---|---|---|---|");
    out.push(`| ${n("patch_now")} | ${n("this_cycle")} | ${n("monitor")} | ${n("ask_owner")} | ${full.run.owner_questions} | ${mdCell(full.run.status)} | ${mdCell(full.run.run_id)} |`, "");
    const t = Object.entries(full.run.timing_ms);
    if (t.length > 0) out.push(`Pipeline timing: ${t.map(([k, v]) => `${mdCell(k)} ${secs(v)}`).join(" · ")}.`, "");
  }

  const notes: string[] = [];
  for (const a of r.arms) {
    for (const n of a.notes) notes.push(`${ARM_LABELS[a.arm]}: ${n}`);
    if (a.extra_predictions.length > 0) notes.push(`${ARM_LABELS[a.arm]}: ${a.extra_predictions.length} prediction(s) for rows that were not asked (ignored)`);
  }
  if (notes.length > 0) out.push("## Notes", "", ...notes.map((n) => `- ${mdCell(n)}`), "");

  const fullRows = new Map((r.arms.find((a) => a.arm === "full" && a.status === "ok")?.rows ?? []).map((x) => [x.row_id, x] as const));
  const lines: string[] = [];
  for (const a of r.arms) {
    if (a.arm === "full") continue;
    const by = new Map(a.rows.map((x) => [x.row_id, x] as const));
    for (const id of a.disagree_with_full) {
      lines.push(`| ${mdCell(id)} | ${mdCell(ARM_LABELS[a.arm])} | ${mdCell(answerText(by.get(id)))} | ${mdCell(answerText(fullRows.get(id)))} |`);
    }
  }
  if (fullRows.size > 0) {
    out.push("## Development rows where an arm and the full system differ", "");
    out.push(lines.length === 0 ? "None." : ["| Row | Arm | Arm's answer | Full system's answer |", "|---|---|---|---|", ...lines].join("\n"), "");
  }
  out.push("Every number above comes from this run's real predictions and receipts; nothing is hand-entered.", "");
  return out.join("\n");
}

/** JSON for the evidence file of an unlabelled run (dev rows only, so per-row answers are kept). */
export function unlabelledJson(r: UnlabelledEvalResult): Record<string, unknown> {
  return { ...r, arms: r.arms.map((a) => ({ ...a, label: ARM_LABELS[a.arm] })) };
}

/** A file stem like eval-2026-10-27-103000-test (UTC). */
export function evalFileStem(set: string, d: Date): string {
  const iso = d.toISOString();
  return `eval-${iso.slice(0, 10)}-${iso.slice(11, 19).replace(/:/g, "")}-${set}`;
}
