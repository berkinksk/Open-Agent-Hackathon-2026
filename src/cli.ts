// npm run cli -- [--input <file.json>] [--sample] [--rows R01,R02] [--run-id <id>]
// One run. The input file holds a RunRequest (or a bare array of inventory rows); without
// --input the run reads the inventory from Zetaris (el.inventory). Prints the decision counts
// and the output paths, and writes output/run-<id>.json. Exit code: 0 success or partial,
// 1 the run failed, 2 usage or configuration error.
import { readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import type { Decision, Mode, RunRequest, RunResponse } from "./contracts.ts";
import { ConfigError, REPO_ROOT, loadConfig } from "./config.ts";
import type { MakeDepsFn, RunFn } from "./server.ts";
import { DEFAULT_OUTPUT_DIR, RequestError, errorResponse, lazyRun, normaliseRunRequest, saveRunFile } from "./server.ts";

export interface CliArgs { input?: string; sample: boolean; rows?: string[]; runId?: string; help: boolean; }

export const USAGE = "usage: npm run cli -- [--input <file.json>] [--sample] [--rows R01,R02] [--run-id <id>]";

export function parseCliArgs(argv: string[]): CliArgs {
  const out: CliArgs = { sample: false, help: false };
  const value = (i: number, flag: string) => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith("--")) throw new RequestError(`${flag} needs a value`);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf("=");
    const flag = a.startsWith("--") && eq > 0 ? a.slice(0, eq) : a;
    const inline = a.startsWith("--") && eq > 0 ? a.slice(eq + 1) : undefined;
    const take = () => (inline !== undefined ? inline : value(i++, flag));
    if (flag === "--input" || flag === "-i") out.input = take();
    else if (flag === "--sample") out.sample = true;
    else if (flag === "--rows") out.rows = take().split(",").map((s) => s.trim()).filter(Boolean);
    else if (flag === "--run-id") out.runId = take();
    else if (flag === "--help" || flag === "-h") out.help = true;
    else throw new RequestError(`unknown argument: ${a}`);
  }
  return out;
}

export function buildRequest(args: CliArgs, cwd: string): RunRequest {
  let body: unknown = {};
  if (args.input) {
    const p = resolve(cwd, args.input);
    let text: string;
    try { text = readFileSync(p, "utf8"); } catch (e) { throw new RequestError(`cannot read --input ${args.input}: ${(e as { code?: string }).code ?? (e as Error).message}`); }
    try { body = JSON.parse(text); } catch (e) { throw new RequestError(`--input ${args.input} is not valid JSON: ${(e as Error).message}`); }
  }
  const req = normaliseRunRequest(body);
  if (args.rows) req.row_ids = args.rows;
  if (args.runId !== undefined) req.run_id = normaliseRunRequest({ run_id: args.runId }).run_id;
  if (args.sample) req.sample_mode = true;
  return req;
}

const DECISIONS: Decision[] = ["patch_now", "this_cycle", "monitor", "ask_owner"];

function rel(p: string | null | undefined): string {
  if (!p) return "(not written)";
  const r = relative(REPO_ROOT, p);
  return r && !r.startsWith("..") ? r : p;
}

export function formatSummary(resp: RunResponse, runFile: string | null): string {
  const secs = Date.parse(resp.finished_at) - Date.parse(resp.started_at);
  const lines = [
    `run ${resp.run_id}  mode=${resp.mode}  status=${resp.status}  as_of=${resp.as_of}${Number.isFinite(secs) ? `  ${(secs / 1000).toFixed(1)} s` : ""}`,
    ...DECISIONS.map((d) => `  ${d.padEnd(11)} ${resp.summary?.[d] ?? 0}`),
    `  owner questions: ${resp.owner_questions?.length ?? 0}   model calls: ${resp.receipts?.length ?? 0}   lines: ${resp.lines?.length ?? 0}`,
  ];
  if (resp.error) lines.push(`  error: ${resp.error.type}: ${resp.error.message}`);
  lines.push("outputs:", `  run     ${rel(runFile)}`, `  report  ${rel(resp.report_file)}`, `  trace   ${rel(resp.trace_file)}`);
  return lines.join("\n");
}

export interface CliOptions {
  run?: RunFn;
  makeDeps?: MakeDepsFn;
  outputDir?: string;
  env?: Record<string, string | undefined>;
  cwd?: string;
  print?: (s: string) => void;
  printErr?: (s: string) => void;
}

export async function main(argv: string[], o: CliOptions = {}): Promise<number> {
  const print = o.print ?? ((s: string) => console.log(s));
  const printErr = o.printErr ?? ((s: string) => console.error(s));
  let args: CliArgs;
  let req: RunRequest;
  try {
    args = parseCliArgs(argv);
    if (args.help) { print(USAGE); return 0; }
    req = buildRequest(args, o.cwd ?? process.cwd());
  } catch (err) {
    printErr(`[ERROR] ${(err as Error).message}`);
    printErr(USAGE);
    return 2;
  }
  const cfg = loadConfig(o.env ?? process.env);
  const mode: Mode = cfg.sampleMode || req.sample_mode === true ? "sample" : "live";
  const makeDeps = o.makeDeps ?? (await import("./deps.ts")).makeDeps;
  const run = o.run ?? lazyRun;

  let deps;
  try {
    deps = makeDeps({ mode, runId: req.run_id, policy: req.policy });
  } catch (err) {
    printErr(`[ERROR] ${(err as Error).message}`);
    return err instanceof ConfigError ? 2 : 1;
  }
  let resp: RunResponse;
  try {
    resp = await run({ ...req, run_id: deps.tracer.run_id, sample_mode: mode === "sample" }, deps);
  } catch (err) {
    const { body } = errorResponse(err, { runId: deps.tracer.run_id, mode, traceFile: deps.tracer.file || null });
    deps.tracer.emit({ agent: "CLI", action: "run_failed", status: "error", output_summary: `${body.error.type}: ${body.error.message.slice(0, 200)}` });
    printErr(JSON.stringify(body, null, 2));
    return 1;
  }
  let runFile: string | null = null;
  try { runFile = saveRunFile(resp, o.outputDir ?? DEFAULT_OUTPUT_DIR); } catch (e) { printErr(`[WARN] could not save the run file: ${(e as Error).message}`); }
  print("");
  print(formatSummary(resp, runFile));
  return resp.status === "error" ? 1 : 0;
}

if (import.meta.main) {
  process.exitCode = await main(process.argv.slice(2));
}
