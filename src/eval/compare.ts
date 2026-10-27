// Compares two human answer sheets row by row, so the two labellers can settle their differences.
import { canonRowId, normName } from "./answers.ts";
import { mdCell } from "./csv.ts";
import type { AnswerRow, AnswerSheet, SheetIssue } from "./types.ts";

export type CompareKind = "agree" | "spellings_differ" | "disagree" | "only_a" | "only_b";

export interface CompareRow {
  row_id: string;
  kind: CompareKind;
  reason: string;                 // why it is not a plain agreement ("" when it is)
  software: string;
  a: AnswerRow | null;
  b: AnswerRow | null;
  union_products: string[];       // spellings_differ: the suggested combined spelling list
  flags: string[];                // "unsure (A)", "software text differs"
}

export interface Comparison {
  names: [string, string];
  rows: CompareRow[];             // every row in either sheet, in sheet-A order then sheet-B order
  counts: Record<CompareKind, number>;
  issues: { a: SheetIssue[]; b: SheetIssue[] };
}

function overlap(x: string[], y: string[]): boolean {
  const s = new Set(x.map(normName));
  return y.some((v) => s.has(normName(v)));
}
function sameSet(x: string[], y: string[]): boolean {
  const sx = new Set(x.map(normName));
  const sy = new Set(y.map(normName));
  return sx.size === sy.size && [...sx].every((v) => sy.has(v));
}
function union(x: string[], y: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of [...x, ...y]) {
    if (seen.has(normName(v))) continue;
    seen.add(normName(v));
    out.push(v);
  }
  return out;
}

/** Classifies one pair of answers for the same row. */
export function classifyPair(a: AnswerRow, b: AnswerRow): { kind: CompareKind; reason: string } {
  if (a.is_none && b.is_none) return { kind: "agree", reason: "" };
  if (a.is_none !== b.is_none) return { kind: "disagree", reason: "one says none, the other names a KEV product" };
  if (!overlap(a.kev_vendors, b.kev_vendors)) return { kind: "disagree", reason: "different KEV vendor" };
  if (!overlap(a.kev_products, b.kev_products)) return { kind: "disagree", reason: "different KEV product" };
  if (sameSet(a.kev_products, b.kev_products) && sameSet(a.kev_vendors, b.kev_vendors)) return { kind: "agree", reason: "" };
  return { kind: "spellings_differ", reason: "same product, different spelling lists" };
}

/**
 * Compares sheet A with sheet B. `restrictTo` (e.g. the test row ids) limits the comparison to those rows.
 */
export function compareAnswerSheets(
  a: AnswerSheet,
  b: AnswerSheet,
  opts: { names?: [string, string]; restrictTo?: string[] } = {},
): Comparison {
  const names = opts.names ?? ["A", "B"];
  const only = opts.restrictTo ? new Set(opts.restrictTo.map(canonRowId)) : null;
  const keep = (r: AnswerRow) => !only || only.has(r.row_id);
  const aRows = a.rows.filter(keep);
  const bRows = b.rows.filter(keep);
  const bById = new Map(bRows.map((r) => [r.row_id, r] as const));
  const aIds = new Set(aRows.map((r) => r.row_id));
  const rows: CompareRow[] = [];

  for (const ra of aRows) {
    const rb = bById.get(ra.row_id) ?? null;
    const flags: string[] = [];
    if (ra.unsure) flags.push(`unsure (${names[0]})`);
    if (!rb) {
      rows.push({ row_id: ra.row_id, kind: "only_a", reason: `no answer in ${names[1]}`, software: ra.software, a: ra, b: null, union_products: [], flags });
      continue;
    }
    if (rb.unsure) flags.push(`unsure (${names[1]})`);
    if (ra.software !== "" && rb.software !== "" && normName(ra.software) !== normName(rb.software)) flags.push("software text differs");
    const { kind, reason } = classifyPair(ra, rb);
    rows.push({
      row_id: ra.row_id, kind, reason, software: ra.software || rb.software, a: ra, b: rb,
      union_products: kind === "spellings_differ" ? union(ra.kev_products, rb.kev_products) : [],
      flags,
    });
  }
  for (const rb of bRows) {
    if (aIds.has(rb.row_id)) continue;
    rows.push({
      row_id: rb.row_id, kind: "only_b", reason: `no answer in ${names[0]}`, software: rb.software, a: null, b: rb,
      union_products: [], flags: rb.unsure ? [`unsure (${names[1]})`] : [],
    });
  }
  // Rows the sheets list as unusable (blank, conflicting) and that the other sheet answered show up as only_a/only_b.
  const counts: Record<CompareKind, number> = { agree: 0, spellings_differ: 0, disagree: 0, only_a: 0, only_b: 0 };
  for (const r of rows) counts[r.kind]++;
  const keepIssue = (i: SheetIssue) => !only || i.row_id === null || only.has(i.row_id);
  return { names, rows, counts, issues: { a: a.issues.filter(keepIssue), b: b.issues.filter(keepIssue) } };
}

function showAnswer(r: AnswerRow | null): string {
  if (!r) return "–";
  if (r.is_none) return "none";
  return `${r.kev_vendors.join("; ")} / ${r.kev_products.join("; ")}`;
}

/** The Markdown table for the labellers' meeting: disagreements first, then spelling differences and unsure rows. */
export function renderComparisonMarkdown(c: Comparison): string {
  const [na, nb] = c.names.map(mdCell);
  const both = c.counts.agree + c.counts.spellings_differ + c.counts.disagree;
  const out: string[] = [];
  out.push(`# Answer comparison: ${na} vs ${nb}`, "");
  out.push(`- **Rows in both sheets:** ${both} · agree: ${c.counts.agree} · same product, different spellings: ${c.counts.spellings_differ} · **disagree: ${c.counts.disagree}**`);
  const onlyA = c.rows.filter((r) => r.kind === "only_a").map((r) => r.row_id);
  const onlyB = c.rows.filter((r) => r.kind === "only_b").map((r) => r.row_id);
  out.push(`- **Only in ${na}:** ${onlyA.length}${onlyA.length ? ` (${onlyA.join(", ")})` : ""}`);
  out.push(`- **Only in ${nb}:** ${onlyB.length}${onlyB.length ? ` (${onlyB.join(", ")})` : ""}`);
  out.push("- Names are compared case- and space-insensitively. A row agrees when both say none, or both name the same vendor and the same set of product spellings.", "");

  const dis = c.rows.filter((r) => r.kind === "disagree");
  out.push(`## Disagreements (${dis.length}): decide these together`, "");
  if (dis.length === 0) out.push("None.", "");
  else {
    out.push(`| Row | Software | ${na} | ${nb} | Why | Notes |`, "|---|---|---|---|---|---|");
    for (const r of dis) {
      const notes = [r.a?.notes ? `${na}: ${r.a.notes}` : "", r.b?.notes ? `${nb}: ${r.b.notes}` : "", ...r.flags].filter(Boolean).join("; ");
      out.push(`| ${mdCell(r.row_id)} | ${mdCell(r.software)} | ${mdCell(showAnswer(r.a))} | ${mdCell(showAnswer(r.b))} | ${mdCell(r.reason)} | ${mdCell(notes)} |`);
    }
    out.push("");
  }

  const sp = c.rows.filter((r) => r.kind === "spellings_differ");
  if (sp.length > 0) {
    out.push(`## Same product, different spelling lists (${sp.length}): suggested answer = the union`, "");
    out.push(`| Row | Software | ${na} | ${nb} | Suggested kev_products |`, "|---|---|---|---|---|");
    for (const r of sp) out.push(`| ${mdCell(r.row_id)} | ${mdCell(r.software)} | ${mdCell(showAnswer(r.a))} | ${mdCell(showAnswer(r.b))} | ${mdCell(r.union_products.join("; "))} |`);
    out.push("");
  }

  const flagged = c.rows.filter((r) => r.kind !== "disagree" && r.flags.length > 0);
  if (flagged.length > 0) {
    out.push(`## Flagged rows that otherwise agree (${flagged.length})`, "");
    out.push(`| Row | Software | ${na} | ${nb} | Flags |`, "|---|---|---|---|---|");
    for (const r of flagged) out.push(`| ${mdCell(r.row_id)} | ${mdCell(r.software)} | ${mdCell(showAnswer(r.a))} | ${mdCell(showAnswer(r.b))} | ${mdCell(r.flags.join("; "))} |`);
    out.push("");
  }

  const issues = [
    ...c.issues.a.map((i) => `${na} line ${i.line}${i.row_id ? ` (${i.row_id})` : ""}: ${i.problem}`),
    ...c.issues.b.map((i) => `${nb} line ${i.line}${i.row_id ? ` (${i.row_id})` : ""}: ${i.problem}`),
  ];
  if (issues.length > 0) out.push("## Sheet issues (rows left out of the comparison)", "", ...issues.map((s) => `- ${mdCell(s)}`), "");
  return out.join("\n");
}
