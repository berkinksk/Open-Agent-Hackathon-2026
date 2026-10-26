import { after, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Deps, Mode, Policy, RunRequest, RunResponse } from "../src/contracts.ts";
import { DEFAULT_POLICY, MODELS } from "../src/contracts.ts";
import { ConfigError, REPO_ROOT } from "../src/config.ts";
import { memoryTracer } from "../src/trace.ts";
import { buildRequest, formatSummary, main, parseCliArgs } from "../src/cli.ts";
import type { MakeDepsFn } from "../src/server.ts";

const TMP_ROOT = join(REPO_ROOT, "output", ".test-tmp");
const made: string[] = [];
function tmp(): string { mkdirSync(TMP_ROOT, { recursive: true }); const d = mkdtempSync(join(TMP_ROOT, "cli-")); made.push(d); return d; }
after(() => { for (const d of made) rmSync(d, { recursive: true, force: true }); });

function resp(req: RunRequest, deps: Deps, status: RunResponse["status"] = "success"): RunResponse {
  return {
    run_id: deps.tracer.run_id, mode: deps.mode, status, started_at: "2026-10-26T21:00:00.000Z", finished_at: "2026-10-26T21:00:02.000Z",
    as_of: "2026-10-26", timing_ms: {}, summary: { patch_now: 2, this_cycle: 1, monitor: 5, ask_owner: 3 },
    lines: [], owner_questions: [{ row_id: "R1", asset_name: "fw", question: "Which FortiOS version?", reason: "version missing" }],
    receipts: [], trace_file: join(REPO_ROOT, "logs", `trace-${deps.tracer.run_id}.jsonl`), report_file: join(REPO_ROOT, "output", `report-${deps.tracer.run_id}.html`),
    manifest: { engine: "world-model", engine_source: "x", sources: [], models: MODELS, helpers_live: [], helpers_dormant: [], policy: deps.policy },
  };
}

function stubDeps(log: { mode: Mode; runId?: string; policy?: Partial<Policy> }[] = []): MakeDepsFn {
  return (o) => {
    log.push(o);
    return { mode: o.mode, clock: { now: () => new Date() }, llm: null, queries: {} as Deps["queries"], tracer: memoryTracer(o.runId ?? "cli-gen"), policy: DEFAULT_POLICY };
  };
}

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, print: (s: string) => out.push(s), printErr: (s: string) => err.push(s) };
}

test("parseCliArgs: --input, --sample, --rows, --run-id, = forms, and errors", () => {
  assert.deepEqual(parseCliArgs(["--input", "a.json", "--sample", "--rows", "R01, R02", "--run-id", "x1"]), { input: "a.json", sample: true, rows: ["R01", "R02"], runId: "x1", help: false });
  assert.equal(parseCliArgs(["--input=b.json"]).input, "b.json");
  assert.equal(parseCliArgs(["-h"]).help, true);
  assert.throws(() => parseCliArgs(["--input"]), /needs a value/);
  assert.throws(() => parseCliArgs(["--input", "--sample"]), /needs a value/);
  assert.throws(() => parseCliArgs(["--bogus"]), /unknown argument/);
});

test("buildRequest: reads a RunRequest or a bare array; --rows and --sample override the file", () => {
  const dir = tmp();
  writeFileSync(join(dir, "req.json"), JSON.stringify({ inventory: [{ row_id: "R01", software: "a 1" }, { row_id: "R02", software: "b 2" }], row_ids: ["R01"] }));
  writeFileSync(join(dir, "arr.json"), JSON.stringify([{ software: "c 3" }]));
  const r = buildRequest({ input: "req.json", sample: true, rows: ["R02"], help: false }, dir);
  assert.deepEqual(r.row_ids, ["R02"]);
  assert.equal(r.sample_mode, true);
  assert.equal(r.inventory!.length, 2);
  assert.equal(buildRequest({ input: join(dir, "arr.json"), sample: false, help: false }, "/").inventory![0].row_id, "R001");
  assert.deepEqual(buildRequest({ sample: false, help: false }, dir), {}, "no --input -> read the inventory from Zetaris");
  assert.throws(() => buildRequest({ input: "missing.json", sample: false, help: false }, dir), /cannot read --input/);
  writeFileSync(join(dir, "bad.json"), "{");
  assert.throws(() => buildRequest({ input: "bad.json", sample: false, help: false }, dir), /not valid JSON/);
});

test("main: runs, prints the decision counts and output paths, writes output/run-<id>.json, exits 0", async () => {
  const dir = tmp();
  const outDir = join(dir, "output");
  writeFileSync(join(dir, "in.json"), JSON.stringify({ inventory: [{ row_id: "R01", software: "MS Exchange Svr 2019 CU12" }] }));
  const c = capture();
  let seen: RunRequest | null = null;
  const log: { mode: Mode }[] = [];
  const code = await main(["--input", "in.json", "--run-id", "cli-1"], {
    cwd: dir, outputDir: outDir, env: {}, makeDeps: stubDeps(log), print: c.print, printErr: c.printErr,
    run: async (req, deps) => { seen = req; return resp(req, deps); },
  });
  assert.equal(code, 0, c.err.join("\n"));
  assert.equal(log[0].mode, "live");
  assert.equal(seen!.run_id, "cli-1");
  const text = c.out.join("\n");
  assert.match(text, /run cli-1 {2}mode=live {2}status=success {2}as_of=2026-10-26 {2}2\.0 s/);
  assert.match(text, /patch_now\s+2/);
  assert.match(text, /this_cycle\s+1/);
  assert.match(text, /monitor\s+5/);
  assert.match(text, /ask_owner\s+3/);
  assert.match(text, /owner questions: 1/);
  assert.match(text, /trace {3}logs\/trace-cli-1\.jsonl/);
  assert.match(text, /report {2}output\/report-cli-1\.html/);
  const saved = JSON.parse(readFileSync(join(outDir, "run-cli-1.json"), "utf8"));
  assert.equal(saved.summary.patch_now, 2);
});

test("main: --sample or SAMPLE_MODE=true selects sample mode", async () => {
  const log: { mode: Mode }[] = [];
  const c = capture();
  const o = { outputDir: tmp(), makeDeps: stubDeps(log), print: c.print, printErr: c.printErr, run: async (req: RunRequest, deps: Deps) => resp(req, deps) };
  assert.equal(await main(["--sample"], { ...o, env: {} }), 0);
  assert.equal(await main([], { ...o, env: { SAMPLE_MODE: "true" } }), 0);
  assert.deepEqual(log.map((l) => l.mode), ["sample", "sample"]);
});

test("main: exit 2 on usage or config errors, exit 1 when the run fails (structured error printed)", async () => {
  const c = capture();
  assert.equal(await main(["--nope"], { print: c.print, printErr: c.printErr }), 2);
  assert.equal(await main(["--input", "does-not-exist.json"], { cwd: tmp(), print: c.print, printErr: c.printErr }), 2);
  const cfgErr: MakeDepsFn = () => { throw new ConfigError("live mode needs Zetaris and Nightshift settings (missing: ZETARIS_API_KEY)", ["ZETARIS_API_KEY"]); };
  assert.equal(await main([], { env: {}, makeDeps: cfgErr, run: async (r, d) => resp(r, d), print: c.print, printErr: c.printErr }), 2);
  assert.match(c.err.join("\n"), /missing: ZETARIS_API_KEY/);

  const c2 = capture();
  const outDir = tmp();
  const code = await main(["--run-id", "cli-fail"], { env: {}, outputDir: outDir, makeDeps: stubDeps(), print: c2.print, printErr: c2.printErr, run: async () => { throw new Error("upstream down"); } });
  assert.equal(code, 1);
  const body = JSON.parse(c2.err.join("\n"));
  assert.deepEqual([body.run_id, body.status, body.error.message], ["cli-fail", "error", "upstream down"]);
  assert.ok(!existsSync(join(outDir, "run-cli-fail.json")));

  const c3 = capture();
  assert.equal(await main([], { env: {}, outputDir: tmp(), makeDeps: stubDeps(), print: c3.print, printErr: c3.printErr, run: async (r, d) => resp(r, d, "error") }), 1);
});

test("formatSummary tolerates a missing report file", () => {
  const deps = stubDeps()({ mode: "sample", runId: "fs-1" });
  const r = { ...resp({}, deps), report_file: null };
  assert.match(formatSummary(r, null), /report {2}\(not written\)/);
});
