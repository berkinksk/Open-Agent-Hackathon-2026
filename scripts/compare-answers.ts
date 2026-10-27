// Compares two human answer sheets and lists the rows where they differ, for the labellers to settle.
//   node --experimental-transform-types --no-warnings scripts/compare-answers.ts <sheet-a.csv> <sheet-b.csv>
//        [--names NameA,NameB] [--test-rows data/eval/test_rows.json] [--out <file.md>] [--json <file.json>]
// --test-rows limits the comparison to the sealed test rows. Without --out, the Markdown goes to stdout.
// The sheets hold answers for sealed rows: keep them, and this output, outside the repository.
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseAnswerSheet } from "../src/eval/answers.ts";
import { compareAnswerSheets, renderComparisonMarkdown } from "../src/eval/compare.ts";
import { parseTestRows } from "../src/eval/split.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const USAGE =
  "usage: compare-answers <sheet-a.csv> <sheet-b.csv> [--names A,B] [--test-rows <json>] [--out <file.md>] [--json <file.json>]";

export interface CompareArgs { a: string; b: string; names: [string, string]; testRows: string | null; out: string | null; json: string | null; }

export function parseCompareArgs(argv: string[]): CompareArgs {
  const files: string[] = [];
  const r: CompareArgs = { a: "", b: "", names: ["A", "B"], testRows: null, out: null, json: null };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new Error(`${flag} needs a value`);
      return v;
    };
    if (flag === "--names") {
      const parts = value().split(",").map((s) => s.trim());
      if (parts.length !== 2 || parts.some((p) => p === "")) throw new Error("--names needs two names, e.g. --names A,B");
      r.names = [parts[0], parts[1]];
    } else if (flag === "--test-rows") r.testRows = value();
    else if (flag === "--out") r.out = value();
    else if (flag === "--json") r.json = value();
    else if (flag === "--help" || flag === "-h") throw new Error("help");
    else if (flag.startsWith("--")) throw new Error(`unknown option ${flag}`);
    else files.push(flag);
  }
  if (files.length !== 2) throw new Error("give exactly two answer sheets");
  r.a = files[0];
  r.b = files[1];
  return r;
}

export async function main(
  argv: string[],
  o: { cwd?: string; repoRoot?: string; stdout?: (s: string) => void; stderr?: (s: string) => void } = {},
): Promise<number> {
  const cwd = o.cwd ?? process.cwd();
  const root = o.repoRoot ?? REPO_ROOT;
  const out = o.stdout ?? ((s: string) => process.stdout.write(s + "\n"));
  const err = o.stderr ?? ((s: string) => process.stderr.write(s + "\n"));
  let args: CompareArgs;
  try {
    args = parseCompareArgs(argv);
  } catch (e) {
    const msg = (e as Error).message;
    err(msg === "help" ? USAGE : `compare-answers: ${msg}\n${USAGE}`);
    return 2;
  }
  try {
    const read = (p: string) => readFileSync(path.resolve(cwd, p), "utf8");
    const sheetA = parseAnswerSheet(read(args.a), path.basename(args.a));
    const sheetB = parseAnswerSheet(read(args.b), path.basename(args.b));
    const restrictTo = args.testRows
      ? parseTestRows(JSON.parse(readFileSync(path.resolve(root, args.testRows), "utf8"))).row_ids
      : undefined;
    const cmp = compareAnswerSheets(sheetA, sheetB, { names: args.names, restrictTo });
    const md = renderComparisonMarkdown(cmp);
    if (args.out) {
      writeFileSync(path.resolve(cwd, args.out), md + "\n");
      out(`compare-answers: ${cmp.counts.disagree} disagreement(s), ${cmp.counts.spellings_differ} spelling difference(s); wrote ${args.out}`);
    } else out(md);
    if (args.json) writeFileSync(path.resolve(cwd, args.json), JSON.stringify(cmp, null, 2) + "\n");
    return 0;
  } catch (e) {
    err(`compare-answers: ${(e as Error).message}`);
    return 1;
  }
}

const invokedDirectly = process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
