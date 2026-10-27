// Picks the sealed test rows for the accuracy test: a reproducible random pick from the team's software list.
//   npm run pick-test-rows -- --in <software_list.csv> [--n 30] [--seed <text>] [--out data/eval/test_rows.json]
//                             [--answer-template <file.csv>] [--force]
// The default seed is the SHA-256 of the CSV file's bytes, so the pick depends only on the list itself: anyone
// with the same file can re-derive it (pickTestRows in src/eval/split.ts). The optional answer template lists
// the picked rows with empty answer columns, for the teammate who labels them. An existing, different pick is
// never overwritten without --force.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ANSWER_COLUMNS } from "../src/eval/answers.ts";
import { DEFAULT_TEST_ROWS_PATH, pickTestRows } from "../src/eval/split.ts";
import { parseSoftwareList } from "./convert-inventory.ts";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function csvCell(v: string): string {
  return /[",\r\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v;
}

/** Natural row order: R2 before R10. */
function byRowId(a: string, b: string): number {
  return a.localeCompare(b, "en", { numeric: true });
}

export interface TestRowsPick {
  file: { description: string; method: string; seed: string; seed_source: string; n: number; source_rows: number; row_ids: string[] };
  template: string;
}

export function buildTestRows(fileBytes: Buffer, n: number, seedArg?: string): TestRowsPick {
  const rows = parseSoftwareList(fileBytes.toString("utf8"));
  const seed = seedArg ?? createHash("sha256").update(fileBytes).digest("hex");
  const pick = pickTestRows(rows.map((r) => r.row_id), n, seed);
  const ids = [...pick.row_ids].sort(byRowId);
  const picked = new Set(ids);
  const lines = rows
    .filter((r) => picked.has(r.row_id))
    .sort((a, b) => byRowId(a.row_id, b.row_id))
    .map((r) => ANSWER_COLUMNS.map((c) => (c === "row_id" ? r.row_id : c === "software" ? csvCell(r.software) : "")).join(","));
  return {
    file: {
      description: "Sealed test rows for the accuracy test: never tune on them; evaluate them once, with the agreed answers.",
      method: pick.method,
      seed,
      seed_source: seedArg === undefined ? `sha256 of the software list file (${fileBytes.length} bytes)` : "given with --seed",
      n,
      source_rows: rows.length,
      row_ids: ids,
    },
    template: [ANSWER_COLUMNS.join(","), ...lines].join("\n") + "\n",
  };
}

/** Runs the CLI. Returns the exit code: 0 written, 1 failed, 2 usage error or refusal. */
export function main(argv: string[], out = (s: string) => console.log(s), err = (s: string) => console.error(s)): number {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--force") args.set("--force", "1");
    else args.set(argv[i], argv[++i] ?? "");
  }
  const input = args.get("--in");
  const n = Number(args.get("--n") ?? "30");
  if (!input || !Number.isInteger(n) || n < 1) {
    err("usage: pick-test-rows --in <software_list.csv> [--n 30] [--seed <text>] [--out data/eval/test_rows.json] [--answer-template <file.csv>] [--force]");
    return 2;
  }
  const outPath = path.resolve(REPO_ROOT, args.get("--out") ?? DEFAULT_TEST_ROWS_PATH);
  try {
    const pick = buildTestRows(readFileSync(input), n, args.get("--seed"));
    const json = JSON.stringify(pick.file, null, 2) + "\n";
    if (existsSync(outPath) && readFileSync(outPath, "utf8") !== json && !args.has("--force")) {
      err(`pick-test-rows: ${outPath} already holds a different pick; pass --force only if nobody has labelled it yet`);
      return 2;
    }
    mkdirSync(path.dirname(outPath), { recursive: true });
    writeFileSync(outPath, json);
    out(`Picked ${n} of ${pick.file.source_rows} rows (seed ${pick.file.seed.slice(0, 12)}…); wrote ${outPath}`);
    const template = args.get("--answer-template");
    if (template) {
      writeFileSync(template, pick.template);
      out(`Wrote the answer template ${template}`);
    }
    return 0;
  } catch (e) {
    err(`pick-test-rows: ${(e as Error).message}`);
    return 1;
  }
}

const invokedDirectly = process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) process.exitCode = main(process.argv.slice(2));
