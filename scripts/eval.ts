// Accuracy evaluation CLI.
//   npm run eval -- --set dev --labels <answers.csv> [--arms full,bolt,lightning,baseline,normaliser]
//   npm run eval -- --set test --final --labels data/test_answers.csv
// Options: --test-rows <json> (default data/eval/test_rows.json) · --inventory <json>|deps|labels (default deps)
//          --out-dir <dir> (default output) · --mode live|sample · --baseline-model bolt|lightning|ultra (default ultra)
// The test rows are sealed: --set test is refused without --final, and the dev set never includes them.
// Every answer name is checked against the KEV pairs (deps.queries.kevPairs()); a name not in KEV leaves its row
// unlabelled, and a --final run refuses when that check cannot run.
// Stdout shows only the per-arm summary; per-row results go to the output files.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Deps, InventoryRow, KevPair, Mode, ModelKey } from "../src/contracts.ts";
import { checkAnswersAgainstKev, parseAnswerSheet } from "../src/eval/answers.ts";
import { runEvaluation } from "../src/eval/evaluate.ts";
import { evalFileStem, evalJson, plural, renderEvalMarkdown, renderSummaryTable } from "../src/eval/report.ts";
import { assertSetAllowed, DEFAULT_TEST_ROWS_PATH, parseTestRows } from "../src/eval/split.ts";
import { ARM_NAMES, DEFAULT_ARMS } from "../src/eval/types.ts";
import type { ArmName, EvalSet, ResolveArm } from "../src/eval/types.ts";
import { createResolveArm } from "../src/eval/wiring.ts";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export class UsageError extends Error {
  constructor(message: string) { super(message); this.name = "UsageError"; }
}

export interface EvalArgs {
  set: EvalSet;
  final: boolean;
  labels: string;
  arms: ArmName[];
  testRows: string;
  inventory: string;   // a JSON path, "deps" or "labels"
  outDir: string;
  mode: Mode;
  baselineModel: ModelKey;
}

export const USAGE = [
  "usage: eval --labels <answers.csv> [--set dev|test] [--final] [--arms full,bolt,lightning,baseline,normaliser]",
  "            [--test-rows data/eval/test_rows.json] [--inventory <json>|deps|labels] [--out-dir output]",
  "            [--mode live|sample] [--baseline-model bolt|lightning|ultra]",
].join("\n");

export function parseEvalArgs(argv: string[], env: Record<string, string | undefined> = {}): EvalArgs {
  const a: EvalArgs = {
    set: "dev", final: false, labels: "", arms: [...DEFAULT_ARMS], testRows: DEFAULT_TEST_ROWS_PATH,
    inventory: "deps", outDir: "output", mode: env.SAMPLE_MODE === "true" ? "sample" : "live", baselineModel: "ultra",
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new UsageError(`${flag} needs a value`);
      return v;
    };
    switch (flag) {
      case "--set": {
        const v = value();
        if (v !== "dev" && v !== "test") throw new UsageError("--set must be dev or test");
        a.set = v;
        break;
      }
      case "--final": a.final = true; break;
      case "--labels": a.labels = value(); break;
      case "--arms": {
        const list = value().split(",").map((s) => s.trim()).filter(Boolean);
        const bad = list.filter((s) => !(ARM_NAMES as readonly string[]).includes(s));
        if (bad.length > 0) throw new UsageError(`unknown arm(s): ${bad.join(", ")}; known: ${ARM_NAMES.join(", ")}`);
        if (list.length === 0) throw new UsageError("--arms is empty");
        a.arms = [...new Set(list)] as ArmName[];
        break;
      }
      case "--test-rows": a.testRows = value(); break;
      case "--inventory": a.inventory = value(); break;
      case "--out-dir": a.outDir = value(); break;
      case "--mode": {
        const v = value();
        if (v !== "live" && v !== "sample") throw new UsageError("--mode must be live or sample");
        a.mode = v;
        break;
      }
      case "--sample": a.mode = "sample"; break;
      case "--baseline-model": {
        const v = value();
        if (v !== "bolt" && v !== "lightning" && v !== "ultra") throw new UsageError("--baseline-model must be bolt, lightning or ultra");
        a.baselineModel = v;
        break;
      }
      case "--help": case "-h": throw new UsageError("help");
      default: throw new UsageError(`unknown option ${flag}`);
    }
  }
  if (a.labels === "") throw new UsageError("--labels <answers.csv> is required (keep answer sheets outside the repository)");
  return a;
}

/** Reads an inventory JSON: an array of rows, or {items|rows|inventory: [...]}. Missing asset fields get defaults. */
export function parseInventoryJson(json: unknown): InventoryRow[] {
  const list = Array.isArray(json)
    ? json
    : json && typeof json === "object"
      ? ((json as Record<string, unknown>).items ?? (json as Record<string, unknown>).rows ?? (json as Record<string, unknown>).inventory)
      : null;
  if (!Array.isArray(list)) throw new Error("inventory: expected an array of rows, or {items: [...]}");
  return list.map((x, i) => {
    const o = (x ?? {}) as Record<string, unknown>;
    if (typeof o.row_id !== "string" || typeof o.software !== "string") throw new Error(`inventory: row ${i} needs row_id and software`);
    const s = (k: string) => (typeof o[k] === "string" ? (o[k] as string) : "");
    const net = o.internet_facing;
    return {
      row_id: o.row_id, software: o.software, asset_id: s("asset_id"), asset_name: s("asset_name"),
      asset_type: s("asset_type"), owner_team: s("owner_team"),
      internet_facing: net === true || (typeof net === "string" && /^(true|yes|y|1)$/i.test(net.trim())),
    };
  });
}

export interface EvalWiring {
  resolveArm: ResolveArm;
  loadInventory?: () => Promise<InventoryRow[]>;
  /** The KEV (vendor, product) pairs, to check every answer name. Required for a --final run. */
  loadKevPairs?: () => Promise<KevPair[]>;
}

interface DepsModule { makeDeps(opts: { mode: Mode; runId?: string }): Deps; }

/** The default wiring: the pipeline's makeDeps (src/deps.ts) and the arms in src/eval/wiring.ts. */
export async function defaultWiring(args: EvalArgs, stamp: string): Promise<EvalWiring> {
  let mod: DepsModule;
  try {
    mod = (await import("../src/deps.ts")) as DepsModule;
  } catch (e) {
    if ((e as { code?: string })?.code === "ERR_MODULE_NOT_FOUND") throw new Error("the pipeline is not wired yet: src/deps.ts is missing");
    throw e;
  }
  const depsFor = (arm: string) => mod.makeDeps({ mode: args.mode, runId: `${stamp}-${arm}` });
  let data: Deps | null = null; // one Deps (one trace file) for the inventory and the KEV pairs
  const dataDeps = () => (data ??= depsFor("data"));
  return {
    resolveArm: createResolveArm({ depsFor, baselineModel: args.baselineModel }),
    loadInventory: () => dataDeps().queries.inventory(),
    loadKevPairs: () => dataDeps().queries.kevPairs(),
  };
}

function isInside(child: string, parent: string): boolean {
  const rel = path.relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

export interface MainOptions {
  cwd?: string;
  repoRoot?: string;
  env?: Record<string, string | undefined>;
  now?: () => Date;
  stdout?: (s: string) => void;
  stderr?: (s: string) => void;
  wiring?: (args: EvalArgs, stamp: string) => Promise<EvalWiring>;
}

/** Runs the CLI. Returns the exit code: 0 done, 1 failed, 2 usage error or refusal. */
export async function main(argv: string[], o: MainOptions = {}): Promise<number> {
  const cwd = o.cwd ?? process.cwd();
  const root = o.repoRoot ?? REPO_ROOT;
  const out = o.stdout ?? ((s: string) => process.stdout.write(s + "\n"));
  const err = o.stderr ?? ((s: string) => process.stderr.write(s + "\n"));
  const now = o.now ?? (() => new Date());

  let args: EvalArgs;
  try {
    args = parseEvalArgs(argv, o.env ?? process.env);
    assertSetAllowed(args.set, args.final); // refuse before reading any file
  } catch (e) {
    const msg = (e as Error).message;
    err(msg === "help" ? USAGE : `eval: ${msg}\n${e instanceof UsageError ? USAGE : ""}`.trimEnd());
    return 2;
  }
  if (args.final && args.set === "dev") err("eval: --final has no effect on the dev set");

  try {
    const labelsPath = path.resolve(cwd, args.labels);
    if (isInside(labelsPath, root) && path.relative(root, labelsPath) !== path.join("data", "test_answers.csv")) {
      err("eval: warning: the answer sheet is inside the repository; keep answer sheets outside it and never commit them");
    }
    const testRowsPath = path.resolve(root, args.testRows);
    let testIds: string[];
    try {
      testIds = parseTestRows(JSON.parse(readFileSync(testRowsPath, "utf8"))).row_ids;
    } catch (e) {
      err(`eval: cannot read the sealed test-row list ${args.testRows} (${(e as Error).message}); it is needed for both sets, so the dev set can exclude the test rows`);
      return 2;
    }
    let labels = parseAnswerSheet(readFileSync(labelsPath, "utf8"), path.basename(labelsPath));
    const stamp = evalFileStem(args.set, now());
    const wiring = await (o.wiring ?? defaultWiring)(args, stamp);

    // Every answer name must be a KEV name: a typo or a comment in an answer cell would silently mis-score.
    let kevProblem: string | null = null;
    if (!wiring.loadKevPairs) kevProblem = "no KEV loader is wired";
    else {
      try {
        labels = checkAnswersAgainstKev(labels, await wiring.loadKevPairs());
      } catch (e) {
        kevProblem = (e as Error).message;
      }
    }
    if (kevProblem !== null) {
      if (args.final) {
        err(`eval: refusing the final run: the answer names cannot be checked against KEV (${kevProblem})`);
        return 2;
      }
      err(`eval: warning: the answer names were not checked against KEV (${kevProblem})`);
    }
    if (labels.issues.length > 0) {
      err(`eval: warning: ${plural(labels.issues.length, "answer-sheet issue")}; unusable rows are left unlabelled (details in the output Notes)`);
    }

    let inventory: InventoryRow[] | null;
    if (args.inventory === "labels") inventory = null;
    else if (args.inventory === "deps") {
      if (wiring.loadInventory) inventory = await wiring.loadInventory();
      else { err("eval: warning: no inventory loader; using the answer sheet's software column"); inventory = null; }
    } else inventory = parseInventoryJson(JSON.parse(readFileSync(path.resolve(cwd, args.inventory), "utf8")));

    const result = await runEvaluation({
      set: args.set, final: args.final, arms: args.arms, labels, testIds, inventory,
      resolveArm: wiring.resolveArm, clock: now, log: (s) => err(`eval: ${s}`), baselineModel: args.baselineModel,
    });

    const dir = path.resolve(root, args.outDir);
    mkdirSync(dir, { recursive: true });
    const mdPath = path.join(dir, `${stamp}.md`);
    const jsonPath = path.join(dir, `${stamp}.json`);
    writeFileSync(mdPath, renderEvalMarkdown(result));
    writeFileSync(jsonPath, JSON.stringify(evalJson(result), null, 2) + "\n");

    out(`Matching accuracy, ${result.set} set: ${plural(result.rows_evaluated, "row")}` + (result.set === "dev" ? ` (${plural(result.sealed_rows_excluded, "sealed test row")} withheld)` : " (final run)"));
    out(renderSummaryTable(result));
    out(`Wrote ${path.relative(cwd, mdPath) || mdPath} and ${path.relative(cwd, jsonPath) || jsonPath}`);
    return result.arms.some((a) => a.status === "ok") ? 0 : 1;
  } catch (e) {
    err(`eval: ${(e as Error).message}`);
    return 1;
  }
}

const invokedDirectly = process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
