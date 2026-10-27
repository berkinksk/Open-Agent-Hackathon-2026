// The dev/test split. The test rows (data/eval/test_rows.json) stay sealed: the dev set never contains
// them, and the test set is refused unless the caller passes --final.
import { createHash } from "node:crypto";
import { canonRowId } from "./answers.ts";
import type { AnswerRow, EvalSet } from "./types.ts";

export const DEFAULT_TEST_ROWS_PATH = "data/eval/test_rows.json";

export interface TestRowsFile {
  row_ids: string[];           // canonical ids
  meta: Record<string, unknown>; // seed, method, picked_at... (whatever the file carries)
}

/**
 * Reads the sealed test-row list. Accepts {row_ids: [...]} (also `test_rows` or `rows`),
 * a bare array of ids, or an array of objects with `row_id`.
 */
export function parseTestRows(json: unknown): TestRowsFile {
  let list: unknown = json;
  let meta: Record<string, unknown> = {};
  if (json && typeof json === "object" && !Array.isArray(json)) {
    const o = json as Record<string, unknown>;
    list = o.row_ids ?? o.test_rows ?? o.rows;
    meta = Object.fromEntries(Object.entries(o).filter(([k]) => !["row_ids", "test_rows", "rows"].includes(k)));
  }
  if (!Array.isArray(list)) throw new Error("test rows file: expected {row_ids: [...]} or an array of row ids");
  const ids = list.map((x, i) => {
    const raw = typeof x === "string" ? x : x && typeof x === "object" ? (x as { row_id?: unknown }).row_id : undefined;
    if (typeof raw !== "string" || raw.trim() === "") throw new Error(`test rows file: entry ${i} has no row id`);
    return canonRowId(raw);
  });
  if (ids.length === 0) throw new Error("test rows file: the list is empty");
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup) throw new Error(`test rows file: duplicate row id ${dup}`);
  return { row_ids: ids, meta };
}

/** Throws unless the set may be evaluated. The test set needs --final. */
export function assertSetAllowed(set: EvalSet, final: boolean): void {
  if (set === "test" && !final) {
    throw new Error("the test rows are sealed: --set test needs --final (run it once, with the agreed answers)");
  }
}

export interface Selection {
  answers: AnswerRow[];        // the labelled rows to evaluate, in label-sheet order
  sealed_excluded: number;     // dev: labelled rows withheld because they are test rows
  missing_labels: string[];    // test: test ids without a usable label
}

/**
 * Chooses the rows to evaluate.
 * - dev: every labelled row that is NOT a test row.
 * - test: exactly the test rows; every one must have a label.
 */
export function selectRows(set: EvalSet, answers: AnswerRow[], testIds: string[]): Selection {
  const sealed = new Set(testIds.map(canonRowId));
  if (set === "dev") {
    const dev = answers.filter((a) => !sealed.has(a.row_id));
    return { answers: dev, sealed_excluded: answers.length - dev.length, missing_labels: [] };
  }
  const byId = new Map(answers.map((a) => [a.row_id, a] as const));
  const picked: AnswerRow[] = [];
  const missing: string[] = [];
  for (const id of sealed) {
    const a = byId.get(id);
    if (a) picked.push(a); else missing.push(id);
  }
  return { answers: picked, sealed_excluded: 0, missing_labels: missing };
}

/**
 * A reproducible random pick: order the ids by sha256(seed + ":" + id) and take the first n.
 * Anyone with the seed and the id list can re-derive the same pick.
 */
export function pickTestRows(rowIds: string[], n: number, seed: string): { method: string; seed: string; n: number; row_ids: string[] } {
  const ids = [...new Set(rowIds.map(canonRowId))];
  if (n > ids.length) throw new Error(`cannot pick ${n} rows from ${ids.length}`);
  const keyed = ids.map((id) => ({ id, k: createHash("sha256").update(`${seed}:${id}`).digest("hex") }));
  keyed.sort((x, y) => (x.k < y.k ? -1 : x.k > y.k ? 1 : 0));
  return { method: "sha256(seed:row_id) ascending, first n", seed, n, row_ids: keyed.slice(0, n).map((x) => x.id) };
}
