import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../src/config.ts";
import { createTracer, formatLine, makeRedactor, memoryTracer } from "../src/trace.ts";

const TMP_ROOT = join(REPO_ROOT, "output", ".test-tmp");
const made: string[] = [];
function tmp(): string { mkdirSync(TMP_ROOT, { recursive: true }); const d = mkdtempSync(join(TMP_ROOT, "trace-")); made.push(d); return d; }
after(() => { for (const d of made) rmSync(d, { recursive: true, force: true }); });

test("writes one JSON object per line to <dir>/trace-<run_id>.jsonl (creating the dir) with contract fields and judge aliases", () => {
  const dir = join(tmp(), "nested", "logs");
  const lines: string[] = [];
  const t = createTracer("run-abc", { dir, print: (l) => lines.push(l) });
  assert.equal(t.run_id, "run-abc");
  assert.equal(t.file, join(dir, "trace-run-abc.jsonl"));
  t.emit({ agent: "Resolver", action: "jury_vote", status: "ok", target_agent: "Critic", model: "nvidia/nemotron-3.5-bolt-e4b", routed_model: "nvidia/nemotron-3.5-bolt-e4b", receipt_id: "rcpt_1", latency_ms: 6400, confidence: 0.9, retry_count: 0, output_summary: "10 votes" });
  t.emit({ agent: "Zetaris", action: "sql_query", status: "fallback", details: { rows: 3 } });
  const recs = readFileSync(t.file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(recs.length, 2);
  for (const k of ["ts", "timestamp", "run_id", "agent", "agent_name", "action", "status"]) assert.ok(k in recs[0], k);
  assert.equal(recs[0].ts, recs[0].timestamp);
  assert.equal(recs[0].agent_name, "Resolver");
  assert.equal(recs[0].run_id, "run-abc");
  assert.equal(recs[0].model, "nvidia/nemotron-3.5-bolt-e4b");
  assert.equal(recs[1].details.rows, 3);
  assert.ok(!Number.isNaN(Date.parse(recs[0].ts)));
  // readable stdout line per event
  assert.equal(lines.length, 2);
  assert.match(lines[0], /^\[INFO\] run_id=run-abc Resolver jury_vote ok -> Critic model=nvidia\/nemotron-3.5-bolt-e4b receipt=rcpt_1 6400ms \| 10 votes$/);
  assert.match(lines[1], /^\[WARN\] run_id=run-abc Zetaris sql_query fallback/);
});

test("stdout can be switched off; error events print as [ERROR]", () => {
  const lines: string[] = [];
  const t = createTracer("quiet", { dir: tmp(), stdout: false, print: (l) => lines.push(l) });
  t.emit({ agent: "A", action: "x", status: "error" });
  assert.equal(lines.length, 0);
  assert.match(formatLine({ ts: "t", run_id: "r", agent: "A", action: "x", status: "error" }), /^\[ERROR\] run_id=r A x error$/);
});

test("secret values and bearer tokens are scrubbed from the file and from stdout", () => {
  const secret = "s3cr3t-value-0042";
  const lines: string[] = [];
  const t = createTracer("redact", { dir: tmp(), redact: [secret], print: (l) => lines.push(l) });
  t.emit({ agent: "A", action: "x", status: "error", output_summary: `failed with key ${secret}`, details: { header: "Authorization: Bearer abc.def-123" } });
  const file = readFileSync(t.file, "utf8");
  assert.ok(!file.includes(secret));
  assert.ok(!file.includes("abc.def-123"));
  assert.ok(file.includes("***redacted"));
  assert.ok(!lines.join("\n").includes(secret));
  assert.equal(makeRedactor([])("Bearer xyz"), "Bearer ***redacted");
});

test("unsafe run ids are refused (they become file names)", () => {
  assert.throws(() => createTracer("../../etc/x", { dir: tmp() }));
  assert.throws(() => createTracer("a/b", { dir: tmp() }));
});

test("emit never throws, even when the log file cannot be written", () => {
  const blocker = join(tmp(), "not-a-dir");
  writeFileSync(blocker, "x");
  const t = createTracer("broken", { dir: blocker, stdout: false });
  const origErr = console.error;
  console.error = () => {};
  try { assert.doesNotThrow(() => t.emit({ agent: "A", action: "x", status: "ok" })); }
  finally { console.error = origErr; }
});

test("memoryTracer keeps events for tests", () => {
  const m = memoryTracer("m");
  m.emit({ agent: "A", action: "x", status: "ok" });
  assert.equal(m.events[0].run_id, "m");
});
