import { after, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer as createNetServer } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Deps, Mode, Policy, RunRequest, RunResponse } from "../src/contracts.ts";
import { DEFAULT_POLICY, MODELS } from "../src/contracts.ts";
import { ConfigError, REPO_ROOT } from "../src/config.ts";
import { memoryTracer } from "../src/trace.ts";
import { createApp, normaliseRunRequest, RequestError } from "../src/server.ts";
import type { MakeDepsFn, RunFn } from "../src/server.ts";

const TMP_ROOT = join(REPO_ROOT, "output", ".test-tmp");
const made: string[] = [];
function tmp(): string { mkdirSync(TMP_ROOT, { recursive: true }); const d = mkdtempSync(join(TMP_ROOT, "server-")); made.push(d); return d; }
after(() => { for (const d of made) rmSync(d, { recursive: true, force: true }); });

function fakeResponse(req: RunRequest, deps: Deps, status: RunResponse["status"] = "success"): RunResponse {
  return {
    run_id: deps.tracer.run_id, mode: deps.mode, status, started_at: "2026-10-26T21:00:00.000Z", finished_at: "2026-10-26T21:00:01.500Z",
    as_of: "2026-10-26", timing_ms: { total: 1500 }, summary: { patch_now: 1, this_cycle: 0, monitor: req.inventory?.length ? req.inventory.length - 1 : 0, ask_owner: 0 },
    lines: [], owner_questions: [], receipts: [], trace_file: deps.tracer.file, report_file: null,
    manifest: { engine: "world-model", engine_source: "x", sources: [], models: MODELS, helpers_live: [], helpers_dormant: [], policy: deps.policy },
  };
}

function stubMakeDeps(log: { mode: Mode; runId?: string; policy?: Partial<Policy> }[] = []): MakeDepsFn {
  let n = 0;
  return (o) => {
    log.push(o);
    const t = memoryTracer(o.runId ?? `stub-${++n}`);
    return { mode: o.mode, clock: { now: () => new Date() }, llm: null, queries: {} as Deps["queries"], tracer: t, policy: { ...DEFAULT_POLICY, ...(o.policy ?? {}) } as Policy };
  };
}

async function start(opts: Partial<Parameters<typeof createApp>[0]> & { run: RunFn }) {
  const outputDir = opts.outputDir ?? tmp();
  const app = createApp({ makeDeps: stubMakeDeps(), outputDir, env: {}, log: () => {}, ...opts });
  await new Promise<void>((ok) => app.listen(0, "127.0.0.1", ok));
  const base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
  return { base, outputDir, app, close: () => new Promise<void>((ok) => { app.closeAllConnections(); app.close(() => ok()); }) };
}

const post = (url: string, body: unknown) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) });

test("POST /run -> RunResponse JSON; the request is normalised; output/run-<id>.json is written", async () => {
  let got: RunRequest | null = null;
  const s = await start({ run: async (req, deps) => { got = req; return fakeResponse(req, deps); } });
  try {
    const res = await post(`${s.base}/run`, { run_id: "demo-001", inventory: [{ software: "MS Exchange Svr 2019 CU12", internet_facing: "yes" }, { row_id: "R9", software: "log4j-core 2.14.1", asset_name: "erp" }] });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /application\/json/);
    const body = (await res.json()) as RunResponse;
    assert.equal(body.run_id, "demo-001");
    assert.equal(body.status, "success");
    assert.equal(body.mode, "live");
    assert.deepEqual(got!.inventory![0], { row_id: "R001", asset_id: "asset-R001", asset_name: "asset-R001", asset_type: "unknown", internet_facing: true, owner_team: "", software: "MS Exchange Svr 2019 CU12" });
    assert.equal(got!.inventory![1].row_id, "R9");
    assert.equal(got!.inventory![1].asset_name, "erp");
    assert.equal(got!.sample_mode, false);
    const saved = JSON.parse(readFileSync(join(s.outputDir, "run-demo-001.json"), "utf8"));
    assert.equal(saved.run_id, "demo-001");
  } finally { await s.close(); }
});

test("sample mode: requested per run, or forced for every run by SAMPLE_MODE", async () => {
  const log: { mode: Mode }[] = [];
  const s = await start({ makeDeps: stubMakeDeps(log), run: async (req, deps) => fakeResponse(req, deps) });
  try {
    assert.equal(((await (await post(`${s.base}/run`, { sample_mode: true })).json()) as RunResponse).mode, "sample");
  } finally { await s.close(); }
  const s2 = await start({ forceSample: true, makeDeps: stubMakeDeps(log), run: async (req, deps) => fakeResponse(req, deps) });
  try {
    assert.equal(((await (await post(`${s2.base}/run`, { sample_mode: false })).json()) as RunResponse).mode, "sample");
  } finally { await s2.close(); }
  assert.deepEqual(log.map((l) => l.mode), ["sample", "sample"]);
});

test("structured errors: bad JSON 400, invalid rows 400, too large 413, wrong method 405, unknown route 404", async () => {
  const s = await start({ run: async (req, deps) => fakeResponse(req, deps), maxBodyBytes: 2000 });
  try {
    let r = await post(`${s.base}/run`, "{not json");
    assert.equal(r.status, 400);
    let b = (await r.json()) as any;
    assert.deepEqual([b.status, b.error.type, b.error.recoverable], ["error", "BadRequest", false]);
    r = await post(`${s.base}/run`, { inventory: [{ row_id: "R1" }] });
    assert.equal(r.status, 400);
    assert.match(((await r.json()) as any).error.message, /software is required/);
    r = await post(`${s.base}/run`, { inventory: [{ software: "a", row_id: "X" }, { software: "b", row_id: "X" }] });
    assert.match(((await r.json()) as any).error.message, /duplicate row_id/);
    r = await post(`${s.base}/run`, { run_id: "../../etc/passwd" });
    assert.equal(r.status, 400);
    r = await post(`${s.base}/run`, { inventory: [{ software: "x".repeat(3000) }] });
    assert.equal(r.status, 413);
    r = await fetch(`${s.base}/run`);
    assert.equal(r.status, 405);
    assert.equal(r.headers.get("allow"), "POST");
    r = await fetch(`${s.base}/nope`);
    assert.equal(r.status, 404);
    b = await r.json();
    assert.equal(b.error.type, "NotFound");
  } finally { await s.close(); }
});

test("a run that throws -> 500 with run_id, type and trace file; a run that returns status error -> 500 with its body", async () => {
  const s = await start({ run: async () => { throw new TypeError("kaput"); } });
  try {
    const r = await post(`${s.base}/run`, { run_id: "boom-1" });
    assert.equal(r.status, 500);
    const b = (await r.json()) as any;
    assert.deepEqual([b.run_id, b.status, b.error.type, b.error.message, b.mode], ["boom-1", "error", "TypeError", "kaput", "live"]);
  } finally { await s.close(); }
  const s2 = await start({ run: async (req, deps) => fakeResponse(req, deps, "error") });
  try {
    const r = await post(`${s2.base}/run`, {});
    assert.equal(r.status, 500);
    assert.equal(((await r.json()) as RunResponse).status, "error");
  } finally { await s2.close(); }
});

test("missing configuration -> 503 ConfigError (recoverable); an invalid policy -> 400", async () => {
  const s = await start({
    run: async (req, deps) => fakeResponse(req, deps),
    makeDeps: (o) => {
      if (o.policy) throw new ConfigError("invalid policy: epss_this_cycle must be a number in [0, 1]", [], ["epss_this_cycle"]);
      throw new ConfigError("live mode needs Zetaris and Nightshift settings (missing: ZETARIS_API_KEY)", ["ZETARIS_API_KEY"]);
    },
  });
  try {
    let r = await post(`${s.base}/run`, {});
    assert.equal(r.status, 503);
    let b = (await r.json()) as any;
    assert.deepEqual([b.error.type, b.error.recoverable], ["ConfigError", true]);
    r = await post(`${s.base}/run`, { policy: { epss_this_cycle: 5 } });
    assert.equal(r.status, 400);
    b = await r.json();
    assert.equal(b.error.type, "ConfigError");
  } finally { await s.close(); }
});

test("runs are processed one at a time", async () => {
  let active = 0;
  let max = 0;
  const s = await start({ run: async (req, deps) => { active++; max = Math.max(max, active); await new Promise((r) => setTimeout(r, 60)); active--; return fakeResponse(req, deps); } });
  try {
    const rs = await Promise.all([1, 2, 3].map((i) => post(`${s.base}/run`, { run_id: `par-${i}` })));
    assert.deepEqual(rs.map((r) => r.status), [200, 200, 200]);
    assert.equal(max, 1);
  } finally { await s.close(); }
});

test("the hard run cap returns 504 RunTimeout, and the next run still waits for the slow one to finish", async () => {
  let finished = 0;
  const order: string[] = [];
  const s = await start({
    runTimeoutMs: 50,
    run: async (req, deps) => { order.push(`start ${req.run_id}`); await new Promise((r) => setTimeout(r, req.run_id === "slow" ? 200 : 1)); finished++; order.push(`end ${req.run_id}`); return fakeResponse(req, deps); },
  });
  try {
    const slow = post(`${s.base}/run`, { run_id: "slow" });
    await new Promise((r) => setTimeout(r, 10));
    const next = post(`${s.base}/run`, { run_id: "next" });
    const r1 = await slow;
    assert.equal(r1.status, 504);
    const b = (await r1.json()) as any;
    assert.deepEqual([b.error.type, b.error.recoverable, b.run_id], ["RunTimeout", true, "slow"]);
    assert.equal((await next).status, 200);
    assert.deepEqual(order, ["start slow", "end slow", "start next", "end next"]);
    assert.equal(finished, 2);
  } finally { await s.close(); }
});

test("GET /health reports mode and missing settings by name only; GET / lists the endpoints", async () => {
  const s = await start({ run: async (req, deps) => fakeResponse(req, deps) });
  try {
    const r = await fetch(`${s.base}/health`);
    assert.equal(r.status, 200);
    const b = (await r.json()) as any;
    assert.equal(b.status, "ok");
    assert.equal(b.mode, "live");
    assert.equal(b.busy, 0);
    assert.ok(b.config.missing.includes("ZETARIS_API_KEY"));
    const idx = (await (await fetch(`${s.base}/`)).json()) as any;
    assert.ok("POST /run" in idx.endpoints);
  } finally { await s.close(); }
});

test("GET /report/:id serves output/report-<id>.html, 404 when absent, 400 for unsafe ids", async () => {
  const dir = tmp();
  writeFileSync(join(dir, "report-r1.html"), "<html><body>patch list</body></html>");
  const s = await start({ outputDir: dir, run: async (req, deps) => fakeResponse(req, deps) });
  try {
    let r = await fetch(`${s.base}/report/r1`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type") ?? "", /text\/html/);
    assert.equal(await r.text(), "<html><body>patch list</body></html>");
    assert.equal((await fetch(`${s.base}/report/r1.html`)).status, 200);
    r = await fetch(`${s.base}/report/r2`);
    assert.equal(r.status, 404);
    r = await fetch(`${s.base}/report/..%2F..%2Fpackage`);
    assert.equal(r.status, 400);
    assert.ok(!existsSync(join(dir, "..", "report-..")));
  } finally { await s.close(); }
});

test("GET /report/:id renders from output/run-<id>.json when no HTML was saved; the page carries a CSP header", async () => {
  const dir = tmp();
  const logs = tmp();
  const resp = fakeResponse({}, { tracer: memoryTracer("r7") } as unknown as Deps);
  writeFileSync(join(dir, "run-r7.json"), JSON.stringify({ ...resp, run_id: "r7" }));
  const s = await start({ outputDir: dir, logsDir: logs, run: async (req, deps) => fakeResponse(req, deps) });
  try {
    const r = await fetch(`${s.base}/report/r7`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-security-policy") ?? "", /default-src 'none'/);
    assert.match(await r.text(), /<!doctype html>/i);
  } finally { await s.close(); }
});

test("normaliseRunRequest: a bare array is the inventory; types are checked", () => {
  assert.equal(normaliseRunRequest([{ software: "x" }]).inventory!.length, 1);
  assert.deepEqual(normaliseRunRequest({ row_ids: [" R1 ", "R2"] }).row_ids, ["R1", "R2"]);
  assert.equal(normaliseRunRequest({ inventory: [{ software: "x", internet_facing: false }] }).inventory![0].internet_facing, false);
  for (const bad of [null, "x", { inventory: {} }, { inventory: [] }, { row_ids: [1] }, { policy: [] }, { sample_mode: 3 }, { inventory: [{ software: {} }] }]) {
    assert.throws(() => normaliseRunRequest(bad), RequestError, JSON.stringify(bad));
  }
});

test("npm start entry: boots in sample mode with no .env, binds 0.0.0.0:$PORT and answers /health", async () => {
  const port = await new Promise<number>((ok) => { const n = createNetServer(); n.listen(0, "127.0.0.1", () => { const p = (n.address() as { port: number }).port; n.close(() => ok(p)); }); });
  const child = spawn(process.execPath, ["--experimental-transform-types", "--no-warnings", join(REPO_ROOT, "src", "server.ts")], {
    cwd: REPO_ROOT, env: { PATH: process.env.PATH ?? "", SAMPLE_MODE: "true", PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (c) => (out += c));
  child.stderr.on("data", (c) => (out += c));
  try {
    const t0 = Date.now();
    while (!out.includes("listening") && Date.now() - t0 < 10_000 && child.exitCode === null) await new Promise((r) => setTimeout(r, 50));
    assert.match(out, new RegExp(`listening on http://0\\.0\\.0\\.0:${port} \\(mode=sample\\)`));
    const b = (await (await fetch(`http://127.0.0.1:${port}/health`)).json()) as any;
    assert.equal(b.mode, "sample");
    assert.equal(b.config.ok, true);
  } finally {
    child.kill("SIGTERM");
    await new Promise((r) => child.once("exit", r));
  }
});
