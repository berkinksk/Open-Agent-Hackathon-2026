// Tests for scripts/verify.ts. No network: Zetaris and Nightshift are a local node:http mock on port 0,
// the sub-commands (verify:engine, npm test) go through an injected fake runner, and traces are fixtures.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, utimesSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { MODELS } from "../src/contracts.ts";
import {
  auditReceipts, checkEnv, checkNightshift, checkReceipts, checkViews, checkZetaris, childEnv, envProblems,
  exitCode, isSampleMode, isSetupTrace, listRunTraces, namesForPrefix, npmCommand, parseTestCounts, pickTrace,
  receiptsResult, redact, requestedModel, runVerify, spawnRunner, zetarisSql,
} from "../scripts/verify.ts";
import type { CheckResult, CmdResult, Env, Runner } from "../scripts/verify.ts";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ZKEY = "fixture-zetaris-credential-0001";
const NTOK = "fixture-nightshift-credential-0002";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function liveEnv(base: string, extra: Env = {}): Env {
  return {
    ZETARIS_REST_URL: `${base}/api/v1.0`, ZETARIS_ORG_ID: "1", ZETARIS_API_KEY: ZKEY,
    METERLESS_BASE_URL: `${base}/v1`, METERLESS_RUNTIME_TOKEN: NTOK, ...extra,
  };
}

function tmpRoot(): string {
  return mkdtempSync(path.join(os.tmpdir(), "verify-test-"));
}

const ev = (o: Record<string, unknown>) =>
  JSON.stringify({ ts: "2026-10-26T20:00:00.000Z", run_id: "r1", agent: "jury", action: "model_call", status: "ok", ...o });

const GOOD_TRACE = [
  ev({ agent: "pipeline", action: "start", model: undefined }),
  ev({ action: "jury_vote", model: "bolt", routed_model: MODELS.bolt, receipt_id: "rcpt_req_aaaa0001" }),
  ev({ action: "jury_vote", model: MODELS.lightning, routed_model: MODELS.lightning, receipt_id: "rcpt_req_aaaa0002" }),
  ev({ agent: "jury", action: "ultra_adjudication", model: MODELS.ultra, routed_model: MODELS.ultra, receipt_id: "rcpt_req_aaaa0003" }),
  ev({ agent: "normaliser", action: "vote", model: "normaliser" }),
  ev({ agent: "zetaris", action: "query", details: { label: "kevPairs", ms: 812 } }),
].join("\n") + "\n";

/** The shape npm run setup writes (scripts/setup.ts → createTracer("setup-<ts>")): Zetaris DDL only. */
const SETUP_TRACE = [
  ev({ run_id: "setup-20261026T212327Z", agent: "Zetaris", action: "sql_query", input_summary: "setup_show_databases: SHOW LIGHTNING DATABASES" }),
  ev({ run_id: "setup-20261026T212327Z", agent: "Zetaris", action: "sql_query", input_summary: "CREATE LIGHTNING DATABASE EL_KEV" }),
].join("\n") + "\n";

/** A sample-mode run: real logic, no model calls. */
const SAMPLE_TRACE = [
  ev({ run_id: "s1", agent: "pipeline", action: "start" }),
  ev({ run_id: "s1", agent: "normaliser", action: "vote", model: "normaliser" }),
].join("\n") + "\n";

/** Writes logs/<name> under root with a fixed mtime (ISO time), and returns its path. */
function writeTrace(root: string, name: string, text: string, mtime: string): string {
  const logs = path.join(root, "logs");
  mkdirSync(logs, { recursive: true });
  const p = path.join(logs, name);
  writeFileSync(p, text);
  utimesSync(p, new Date(mtime), new Date(mtime));
  return p;
}

function fakeRunner(outputs: Partial<Record<"engine" | "tests", Partial<CmdResult>>> = {}) {
  const calls: { cmd: string; args: string[]; env: Env; timeoutMs: number }[] = [];
  const runner: Runner = async (cmd, args, opts) => {
    calls.push({ cmd, args, env: opts.env, timeoutMs: opts.timeoutMs });
    const key = args.includes("verify:engine") ? "engine" : "tests";
    const base: CmdResult = key === "engine"
      ? { code: 0, output: "conformance: 8/8 checks passed\nidempotency: diff empty\nengine checks: 3/3 OK\n", ms: 900, timedOut: false }
      : { code: 0, output: "✔ something\nℹ tests 42\nℹ pass 42\nℹ fail 0\n", ms: 3000, timedOut: false };
    return { ...base, ...outputs[key] };
  };
  return { runner, calls };
}

const throwingFetch = (async () => { throw new Error("network must not be used"); }) as unknown as typeof fetch;

// ---------------------------------------------------------------- mock Zetaris + Nightshift

interface Seen { method: string; url: string; headers: http.IncomingHttpHeaders; body: Record<string, unknown> | null; }
interface MockState {
  dbs: string[]; kevRows: string[][]; models: string[]; inFlight: number; maxInFlight: number;
  echoAuthOnError: boolean;
}

let server: http.Server;
let base = "";
const seen: Seen[] = [];
const state: MockState = { dbs: [], kevRows: [], models: [], inFlight: 0, maxInFlight: 0, echoAuthOnError: false };

function resetMock() {
  seen.length = 0;
  state.dbs = ["EL_INVENTORY", "EL_KEV", "EL_EPSS", "EL_NVD", "FZ_OTHER"];
  state.kevRows = [["CVE-2021-44228", "Apache", "Log4j2"]];
  state.models = [MODELS.bolt, MODELS.lightning, MODELS.ultra, "meterless/auto"];
  state.inFlight = 0;
  state.maxInFlight = 0;
  state.echoAuthOnError = false;
}

before(async () => {
  resetMock();
  server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : null;
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });
      if (req.url?.startsWith("/hang")) return; // never answers
      const send = (status: number, payload: unknown, delay = 0) => {
        state.inFlight++;
        state.maxInFlight = Math.max(state.maxInFlight, state.inFlight);
        setTimeout(() => {
          state.inFlight--;
          res.writeHead(status, { "Content-Type": "application/json" });
          res.end(JSON.stringify(payload));
        }, delay);
      };
      if (req.method === "GET" && req.url === "/v1/models") {
        if (req.headers.authorization !== `Bearer ${NTOK}`) return send(401, { error: "unauthorized" });
        return send(200, { object: "list", data: state.models.map((id) => ({ id, object: "model" })) });
      }
      if (req.method === "POST" && req.url === "/api/v1.0/sql-editor/sqls/run") {
        if (req.headers.authorization !== `Bearer ${ZKEY}`) return send(400, { msg: "Unauthorized" });
        const sql = String(body?.sql ?? "");
        const ok = (headers: string[], data: string[][]) => send(200, { headers, data, total: data.length, timeUsed: 5 }, 15);
        if (sql === "SELECT 1 AS ok") return ok(["ok"], [["1"]]);
        if (sql === "SHOW LIGHTNING DATABASES") return ok(["name", "description"], state.dbs.map((d) => [d, "x"]));
        if (sql === "SELECT * FROM el.inventory LIMIT 1") return ok(["row_id", "software"], [["R01", "log4j-core 2.14.1"]]);
        if (sql === "SELECT * FROM el.kev LIMIT 1") return ok(["cve_id", "vendor", "product"], state.kevRows);
        const echo = state.echoAuthOnError ? ` (request auth: ${req.headers.authorization})` : "";
        return send(400, { msg: `Table or view not found: ${sql}${echo}` });
      }
      send(404, { msg: "no route" });
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

function zcfg(url = `${base}/api/v1.0`, timeoutMs = 5000) {
  return { url, apiKey: ZKEY, orgId: "1", timeoutMs, fetchImpl: globalThis.fetch };
}

/** A local port with nothing listening on it. */
async function closedPort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  const port = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

// ---------------------------------------------------------------- env checker

describe("env checker", () => {
  test("all five variables set → PASS, and no value is ever printed", () => {
    const env = liveEnv("http://127.0.0.1:9");
    const r = checkEnv(env);
    assert.equal(r.status, "PASS");
    for (const v of Object.values(env)) assert.ok(!r.detail.includes(v as string), "a value leaked into the detail");
  });

  test("missing, placeholder and malformed values → FAIL naming the variables only", () => {
    const env = liveEnv("http://127.0.0.1:9", {
      METERLESS_RUNTIME_TOKEN: undefined, ZETARIS_API_KEY: "your-zetaris-api-key", METERLESS_BASE_URL: "127.0.0.1:8088/v1",
    });
    const r = checkEnv(env);
    assert.equal(r.status, "FAIL");
    assert.match(r.detail, /missing: METERLESS_RUNTIME_TOKEN/);
    assert.match(r.detail, /placeholder: ZETARIS_API_KEY/);
    assert.match(r.detail, /not an http\(s\) URL: METERLESS_BASE_URL/);
    assert.ok(!r.detail.includes("your-zetaris-api-key"));
    assert.ok(!r.detail.includes("127.0.0.1:8088"));
    assert.deepEqual(envProblems(env), {
      missing: ["METERLESS_RUNTIME_TOKEN"], placeholder: ["ZETARIS_API_KEY"], badUrl: ["METERLESS_BASE_URL"],
    });
  });

  test("whitespace-only counts as missing", () => {
    assert.deepEqual(envProblems(liveEnv("http://h", { ZETARIS_ORG_ID: "   " })).missing, ["ZETARIS_ORG_ID"]);
  });

  test("sample mode → SKIP, even with nothing set", () => {
    const r = checkEnv({ SAMPLE_MODE: "true" });
    assert.equal(r.status, "SKIP");
    assert.match(r.detail, /0\/5 required variables set/);
  });

  test("SAMPLE_MODE parsing matches the app config's truthy values", () => {
    for (const v of ["true", "TRUE", " True ", "1", "yes", "y", "on"]) assert.equal(isSampleMode({ SAMPLE_MODE: v }), true, v);
    for (const v of ["false", "", "0", "no", "off", undefined]) assert.equal(isSampleMode({ SAMPLE_MODE: v }), false, String(v));
  });

  test("redact replaces secret values and ignores very short ones", () => {
    assert.equal(redact(`a ${ZKEY} b ${ZKEY}`, [ZKEY]), "a …redacted b …redacted");
    assert.equal(redact("abc", ["ab"]), "abc");
  });

  test("childEnv removes the two credentials without touching the input", () => {
    const env = liveEnv("http://h", { SAMPLE_MODE: "false" });
    const c = childEnv(env);
    assert.equal(c.ZETARIS_API_KEY, undefined);
    assert.equal(c.METERLESS_RUNTIME_TOKEN, undefined);
    assert.equal(c.ZETARIS_REST_URL, env.ZETARIS_REST_URL);
    assert.equal(env.ZETARIS_API_KEY, ZKEY);
  });
});

// ---------------------------------------------------------------- receipts checker

describe("receipts checker (fixture traces)", () => {
  test("a good trace → PASS with per-model counts; deterministic steps are not model calls", () => {
    const a = auditReceipts(GOOD_TRACE);
    assert.equal(a.events, 6);
    assert.equal(a.modelCalls, 3);
    assert.equal(a.checked, 3);
    assert.deepEqual(a.failures, []);
    const r = receiptsResult("/x/logs/trace-r1.jsonl", a);
    assert.equal(r.status, "PASS");
    assert.match(r.detail, /trace-r1\.jsonl: 3\/3 model calls/);
    assert.match(r.detail, /bolt 1, lightning 1, ultra 1/);
  });

  test("a call without receipt_id → FAIL with its line number", () => {
    const text = GOOD_TRACE + ev({ model: "lightning", routed_model: MODELS.lightning, receipt_id: null }) + "\n";
    const r = receiptsResult("t.jsonl", auditReceipts(text));
    assert.equal(r.status, "FAIL");
    assert.match(r.detail, /1 of 4 model calls lack a valid receipt/);
    assert.match(r.tail?.[0] ?? "", /^line 7 jury\/model_call: no receipt_id$/);
  });

  test("routed_model missing or not pinned → FAIL", () => {
    const a = auditReceipts([
      ev({ model: "bolt", receipt_id: "rcpt_1" }),
      ev({ model: "bolt", routed_model: "other/model-x", receipt_id: "rcpt_2" }),
    ].join("\n"));
    assert.equal(a.failures.length, 2);
    assert.deepEqual(a.failures[0].problems, ["no routed_model"]);
    assert.match(a.failures[1].problems[0], /routed_model "other\/model-x" is not a pinned model/);
  });

  test("meterless/auto requested → FAIL even when the route was a pinned model", () => {
    const a = auditReceipts(ev({ model: "meterless/auto", routed_model: MODELS.bolt, receipt_id: "rcpt_3" }));
    assert.equal(a.modelCalls, 1);
    assert.match(a.failures[0].problems[0], /requested model "meterless\/auto" is not a pinned ID/);
  });

  test("requested one pinned model but routed to another → FAIL", () => {
    const a = auditReceipts(ev({ model: "bolt", routed_model: MODELS.lightning, receipt_id: "rcpt_4" }));
    assert.deepEqual(a.failures[0].problems, [`requested ${MODELS.bolt} but routed to ${MODELS.lightning}`]);
  });

  test("failed calls (status error or fallback) are exempt; only exempt calls → SKIP", () => {
    const text = [
      ev({ model: "lightning", status: "error", routed_model: null, receipt_id: null }),
      ev({ model: "ultra", status: "fallback" }),
    ].join("\n");
    const a = auditReceipts(text);
    assert.equal(a.exempt, 2);
    assert.equal(a.checked, 0);
    const r = receiptsResult("t.jsonl", a);
    assert.equal(r.status, "SKIP");
    assert.match(r.detail, /all 2 model call\(s\) failed, so there is no receipt to check/);
    const live = receiptsResult("t.jsonl", a, { live: true });
    assert.equal(live.status, "FAIL", "live mode: a run whose model calls all failed proves nothing");
    assert.match(live.detail, /was Nightshift reachable/);
    const mixed = receiptsResult("t.jsonl", auditReceipts(GOOD_TRACE + text));
    assert.equal(mixed.status, "PASS");
    assert.match(mixed.detail, /2 failed call\(s\) had no receipt and were not counted/);
  });

  test("a line that is not a JSON object → FAIL", () => {
    const r = receiptsResult("t.jsonl", auditReceipts(GOOD_TRACE + "{not json\n[1,2]\n"));
    assert.equal(r.status, "FAIL");
    assert.match(r.detail, /2 line\(s\) are not JSON objects \(lines 7, 8\)/);
  });

  test("a trace with no model calls → SKIP in sample mode, FAIL in live mode, with an accurate reason", () => {
    const a = auditReceipts(SETUP_TRACE);
    const r = receiptsResult("trace-setup-x.jsonl", a);
    assert.equal(r.status, "SKIP");
    assert.match(r.detail, /no model-call events, so no receipt was checked \(setup and sample-mode traces make no model calls\)/);
    assert.doesNotMatch(r.detail, /a sample-mode run makes none/);
    const live = receiptsResult("trace-setup-x.jsonl", a, { live: true, note: "chosen with --trace" });
    assert.equal(live.status, "FAIL");
    assert.match(live.detail, /live mode needs the trace of a live run \[chosen with --trace\]$/);
  });

  test("requestedModel: keys, IDs, provider IDs; prototype names are not models", () => {
    assert.deepEqual(requestedModel("ultra"), { isCall: true, pinnedId: MODELS.ultra, raw: "ultra" });
    assert.equal(requestedModel(MODELS.bolt).pinnedId, MODELS.bolt);
    assert.deepEqual(requestedModel("meterless/auto"), { isCall: true, pinnedId: null, raw: "meterless/auto" });
    assert.equal(requestedModel("toString").isCall, false);
    assert.equal(requestedModel("rules").isCall, false);
    assert.equal(requestedModel(42).isCall, false);
  });

  test("pickTrace takes the newest run trace with a model call; checkReceipts audits it, --trace overrides", () => {
    const root = tmpRoot();
    try {
      assert.deepEqual(listRunTraces(path.join(root, "nope")), { files: [], setupIgnored: 0 });
      const empty = checkReceipts(root, undefined, { live: true });
      assert.equal(empty.status, "SKIP");
      assert.match(empty.detail, /no run trace in logs\/ yet, so no receipt was checked/);
      const older = writeTrace(root, "trace-run-a.jsonl", GOOD_TRACE, "2026-10-26T10:00:00Z");
      const newer = writeTrace(root, "trace-run-b.jsonl", ev({ model: "bolt", routed_model: MODELS.bolt }) + "\n", "2026-10-26T11:00:00Z");
      writeTrace(root, "audit-run-c.jsonl", "junk", "2026-10-26T12:00:00Z");
      assert.deepEqual(listRunTraces(path.join(root, "logs")).files, [newer, older]);
      assert.equal(pickTrace(path.join(root, "logs")).file, newer);
      const r = checkReceipts(root);
      assert.equal(r.status, "FAIL");
      assert.match(r.detail, /^trace-run-b\.jsonl: 1 of 1 model calls lack a valid receipt \[the newest trace with model calls\]$/);
      const forced = checkReceipts(root, "logs/trace-run-a.jsonl");
      assert.equal(forced.status, "PASS");
      assert.match(forced.detail, /^trace-run-a\.jsonl: 3\/3 .*\[chosen with --trace\]$/);
      assert.equal(checkReceipts(root, "logs/missing.jsonl").status, "FAIL");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("regression: a setup trace newer than the run trace is ignored; the run trace is audited and named", () => {
    const root = tmpRoot();
    try {
      writeTrace(root, "trace-run-1.jsonl", GOOD_TRACE, "2026-10-26T20:00:00Z");
      const setup = writeTrace(root, "trace-setup-20261026T212327Z.jsonl", SETUP_TRACE, "2026-10-26T21:23:27Z");
      assert.ok(isSetupTrace(path.basename(setup)));
      assert.ok(!isSetupTrace("trace-run-1.jsonl"));
      assert.equal(listRunTraces(path.join(root, "logs")).setupIgnored, 1);
      for (const live of [true, false]) {
        const r = checkReceipts(root, undefined, { live });
        assert.equal(r.status, "PASS", r.detail);
        assert.match(r.detail, /^trace-run-1\.jsonl: 3\/3 model calls carry a receipt_id/);
        assert.match(r.detail, /\[the newest trace with model calls; 1 setup trace\(s\) ignored\]$/);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("newer traces without model calls (sample runs) are passed over and named; a newer all-failed run is not hidden", () => {
    const root = tmpRoot();
    try {
      writeTrace(root, "trace-run-1.jsonl", GOOD_TRACE, "2026-10-26T20:00:00Z");
      writeTrace(root, "trace-sample-2.jsonl", SAMPLE_TRACE, "2026-10-26T20:10:00Z");
      writeTrace(root, "trace-setup-20261026T202000Z.jsonl", SETUP_TRACE, "2026-10-26T20:20:00Z");
      const r = checkReceipts(root, undefined, { live: true });
      assert.equal(r.status, "PASS", r.detail);
      assert.match(r.detail, /^trace-run-1\.jsonl: 3\/3/);
      assert.match(r.detail, /1 newer trace\(s\) without model calls skipped \(trace-sample-2\.jsonl\); 1 setup trace\(s\) ignored\]$/);

      // A later live run whose model calls all failed is the one audited: live FAIL, sample SKIP.
      const failed = [ev({ model: "bolt", status: "error", receipt_id: null }), ev({ model: "lightning", status: "fallback" })].join("\n");
      writeTrace(root, "trace-run-3.jsonl", failed, "2026-10-26T20:30:00Z");
      const live = checkReceipts(root, undefined, { live: true });
      assert.equal(live.status, "FAIL");
      assert.match(live.detail, /^trace-run-3\.jsonl: all 2 model call\(s\) failed/);
      assert.equal(checkReceipts(root, undefined, { live: false }).status, "SKIP");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("no run trace with model calls (only setup and sample traces) → SKIP with an accurate reason, in both modes", () => {
    const root = tmpRoot();
    try {
      writeTrace(root, "trace-setup-20261026T212316Z.jsonl", SETUP_TRACE, "2026-10-26T21:23:16Z");
      writeTrace(root, "trace-setup-20261026T212327Z.jsonl", SETUP_TRACE, "2026-10-26T21:23:27Z");
      writeTrace(root, "trace-s1-wiring-check.jsonl", SAMPLE_TRACE, "2026-10-26T21:31:00Z");
      const p = pickTrace(path.join(root, "logs"));
      assert.equal(p.file, null);
      assert.deepEqual(p.passedOver, ["trace-s1-wiring-check.jsonl"]);
      for (const live of [true, false]) {
        const r = checkReceipts(root, undefined, { live });
        assert.equal(r.status, "SKIP");
        assert.match(r.detail, /^no run trace in logs\/ has a model call, so no receipt was checked \(1 trace\(s\) without model calls skipped \(trace-s1-wiring-check\.jsonl\); 2 setup trace\(s\) ignored\); a live run writes one/);
        assert.doesNotMatch(r.detail, /sample-mode run makes none/);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------- helpers

describe("helpers", () => {
  test("parseTestCounts reads spec and TAP summaries", () => {
    assert.deepEqual(parseTestCounts("✔ a\nℹ tests 5\nℹ suites 1\nℹ pass 5\nℹ fail 0\n"), { pass: 5, fail: 0 });
    assert.deepEqual(parseTestCounts("ok 1\n# tests 4\n# pass 3\n# fail 1\n"), { pass: 3, fail: 1 });
    assert.equal(parseTestCounts("nothing here"), null);
  });

  test("namesForPrefix follows the setup naming and rejects unsafe prefixes", () => {
    assert.deepEqual(namesForPrefix("EL_"), {
      databases: ["EL_INVENTORY", "EL_KEV", "EL_EPSS", "EL_NVD"], views: ["el.inventory", "el.kev"],
    });
    assert.deepEqual(namesForPrefix("EL_T1_")?.views, ["el_t1.inventory", "el_t1.kev"]);
    for (const bad of ["el", "el_", "EL", "XX_", "EL_t1_", "EL;DROP_", "1EL_", "", "EL _"]) assert.equal(namesForPrefix(bad), null, bad);
  });

  test("namesForPrefix agrees with the setup script's naming (elNames in src/adapters/queries.ts)", async () => {
    const { elNames } = await import("../src/adapters/queries.ts");
    for (const p of ["EL_", "EL_T1_", "EL_DEV_2_"]) {
      const n = elNames(p);
      assert.deepEqual(namesForPrefix(p), {
        databases: [n.invDb, n.kevDb, n.epssDb, n.nvdDb], views: [n.inventoryRef, n.kevRef],
      }, p);
    }
  });

  test("npmCommand reuses the running npm when npm_execpath points at npm-cli.js", () => {
    const cli = "/usr/lib/node_modules/npm/bin/npm-cli.js";
    assert.deepEqual(npmCommand(["test"], { npm_execpath: cli }), [process.execPath, [cli, "test"]]);
    const [cmd, args] = npmCommand(["test"], {});
    assert.match(cmd, /^npm(\.cmd)?$/);
    assert.deepEqual(args, ["test"]);
  });

  test("spawnRunner captures output and the exit code, and enforces its timeout", async () => {
    const r = await spawnRunner(process.execPath, ["-e", "console.log('hello'); console.error('oops'); process.exit(3)"],
      { cwd: REPO, env: { PATH: process.env.PATH }, timeoutMs: 10_000 });
    assert.equal(r.code, 3);
    assert.match(r.output, /hello/);
    assert.match(r.output, /oops/);
    assert.equal(r.timedOut, false);
    const slow = await spawnRunner(process.execPath, ["-e", "setTimeout(() => {}, 20000)"],
      { cwd: REPO, env: { PATH: process.env.PATH }, timeoutMs: 200 });
    assert.equal(slow.timedOut, true);
    assert.notEqual(slow.code, 0);
  });
});

// ---------------------------------------------------------------- live checks against the mock

describe("Zetaris and Nightshift checks (local mock server)", () => {
  test("SELECT 1 → PASS, with the documented request shape", async () => {
    resetMock();
    const r = await checkZetaris(zcfg());
    assert.equal(r.status, "PASS", r.detail);
    const q = seen[0];
    assert.equal(q.method, "POST");
    assert.equal(q.url, "/api/v1.0/sql-editor/sqls/run");
    assert.equal(q.headers.authorization, `Bearer ${ZKEY}`);
    assert.equal(q.headers["x-org-id"], "1");
    assert.match(String(q.headers["x-request-id"]), UUID);
    assert.match(String(q.headers["content-type"]), /application\/json/);
    assert.match(String(q.body?.queryId), UUID);
    assert.deepEqual({ sql: q.body?.sql, source: q.body?.source, limit: q.body?.limit }, { sql: "SELECT 1 AS ok", source: "SqlEditor", limit: 1 });
  });

  test("a trailing slash on ZETARIS_REST_URL is tolerated", async () => {
    resetMock();
    assert.equal((await checkZetaris(zcfg(`${base}/api/v1.0/`))).status, "PASS");
  });

  test("HTTP 400 → the Zetaris message is reported", async () => {
    resetMock();
    const r = await zetarisSql(zcfg(), "SELECT * FROM el.nothing LIMIT 1", 1);
    assert.equal(r.ok, false);
    assert.match(r.ok ? "" : r.error, /^HTTP 400: Table or view not found/);
  });

  test("timeout and refused connection → FAIL with a clear reason", async () => {
    const hung = await checkZetaris(zcfg(`${base}/hang`, 150));
    assert.equal(hung.status, "FAIL");
    assert.match(hung.detail, /timed out after 150 ms/);
    const port = await closedPort();
    const refused = await checkZetaris(zcfg(`http://127.0.0.1:${port}/api/v1.0`));
    assert.equal(refused.status, "FAIL");
    assert.match(refused.detail, /cannot connect \(ECONNREFUSED\)/);
  });

  test("views: discovery, then LIMIT 1 per view, strictly one query at a time → PASS", async () => {
    resetMock();
    const r = await checkViews(zcfg(), "EL_");
    assert.equal(r.status, "PASS", r.detail);
    assert.deepEqual(seen.map((s) => s.body?.sql), [
      "SHOW LIGHTNING DATABASES", "SELECT * FROM el.inventory LIMIT 1", "SELECT * FROM el.kev LIMIT 1",
    ]);
    assert.equal(state.maxInFlight, 1);
    assert.match(r.detail, /databases EL_INVENTORY, EL_KEV, EL_EPSS, EL_NVD present/);
  });

  test("views: a missing database and an empty view → FAIL", async () => {
    resetMock();
    state.dbs = ["EL_INVENTORY", "EL_KEV", "EL_EPSS"];
    state.kevRows = [];
    const r = await checkViews(zcfg(), "EL_");
    assert.equal(r.status, "FAIL");
    assert.match(r.detail, /databases missing: EL_NVD/);
    assert.match(r.detail, /el\.kev: 0 rows/);
  });

  test("views: a fresh prefix queries its own objects; an unsafe prefix sends no SQL", async () => {
    resetMock();
    const r = await checkViews(zcfg(), "EL_T1_");
    assert.equal(r.status, "FAIL");
    assert.match(r.detail, /EL_T1_INVENTORY/);
    assert.ok(seen.some((s) => s.body?.sql === "SELECT * FROM el_t1.kev LIMIT 1"));
    resetMock();
    assert.equal((await checkViews(zcfg(), "EL; DROP_")).status, "FAIL");
    assert.equal(seen.length, 0);
  });

  test("Nightshift /models → PASS with the Meterless headers; a missing pinned model or a bad token → FAIL", async () => {
    resetMock();
    const cfg = { baseUrl: `${base}/v1`, token: NTOK, timeoutMs: 5000, fetchImpl: globalThis.fetch };
    const ok = await checkNightshift(cfg);
    assert.equal(ok.status, "PASS", ok.detail);
    assert.match(ok.detail, /4 models, all 3 pinned Nemotron IDs listed/);
    const h = seen[0].headers;
    assert.equal(seen[0].url, "/v1/models");
    assert.equal(h.authorization, `Bearer ${NTOK}`);
    assert.equal(h["meterless-app"], "exposureledger");
    assert.equal(h["meterless-scope"], "user");

    state.models = [MODELS.bolt, MODELS.lightning];
    const missing = await checkNightshift(cfg);
    assert.equal(missing.status, "FAIL");
    assert.match(missing.detail, new RegExp(`not listed: ${MODELS.ultra.replace(/[./]/g, "\\$&")}`));

    const denied = await checkNightshift({ ...cfg, token: "wrong-token-value" });
    assert.equal(denied.status, "FAIL");
    assert.match(denied.detail, /HTTP 401: token rejected/);
    const port = await closedPort();
    const down = await checkNightshift({ ...cfg, baseUrl: `http://127.0.0.1:${port}/v1` });
    assert.match(down.detail, /cannot reach Nightshift: cannot connect \(ECONNREFUSED\) \(is the Nightshift app open\?\)/);
  });
});

// ---------------------------------------------------------------- orchestration

describe("runVerify", () => {
  const statuses = (rs: CheckResult[]) => Object.fromEntries(rs.map((r) => [r.id, r.status]));

  test("sample mode: live checks SKIP, no network is touched, sub-commands run without credentials", async () => {
    const root = tmpRoot();
    try {
      const { runner, calls } = fakeRunner();
      const lines: string[] = [];
      const rs = await runVerify({
        env: { ...liveEnv("http://127.0.0.1:9"), SAMPLE_MODE: "true", PATH: "/usr/bin" },
        root, runner, fetchImpl: throwingFetch, print: (l) => lines.push(l),
      });
      assert.deepEqual(statuses(rs), {
        env: "SKIP", zetaris: "SKIP", nightshift: "SKIP", views: "SKIP", engine: "PASS", tests: "PASS", receipts: "SKIP",
      });
      assert.equal(exitCode(rs), 0);
      assert.equal(calls.length, 2);
      assert.ok(calls[0].args.includes("verify:engine"));
      assert.ok(calls[1].args.includes("test"));
      for (const c of calls) {
        assert.equal(c.env.ZETARIS_API_KEY, undefined);
        assert.equal(c.env.METERLESS_RUNTIME_TOKEN, undefined);
        assert.equal(c.env.PATH, "/usr/bin");
      }
      assert.match(rs.find((r) => r.id === "tests")?.detail ?? "", /42 passed, 0 failed/);
      assert.equal(lines.length, 7);
      assert.ok(lines.every((l) => /^(PASS|FAIL|SKIP)\s/.test(l)));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("live, everything healthy → all 7 PASS and the checks run in the documented order", async () => {
    resetMock();
    const root = tmpRoot();
    try {
      mkdirSync(path.join(root, "logs"));
      writeFileSync(path.join(root, "logs", "trace-good.jsonl"), GOOD_TRACE);
      const { runner } = fakeRunner();
      const lines: string[] = [];
      const rs = await runVerify({ env: liveEnv(base), root, runner, print: (l) => lines.push(l) });
      assert.deepEqual(rs.map((r) => r.id), ["env", "zetaris", "nightshift", "views", "engine", "tests", "receipts"]);
      assert.ok(rs.every((r) => r.status === "PASS"), lines.join("\n"));
      assert.equal(exitCode(rs), 0);
      assert.equal(state.maxInFlight, 1);
      const out = lines.join("\n");
      assert.ok(!out.includes(ZKEY) && !out.includes(NTOK));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("regression: a trace written during the tests step does not change which trace is audited", async () => {
    resetMock();
    const root = tmpRoot();
    try {
      writeTrace(root, "trace-good.jsonl", GOOD_TRACE, "2026-10-26T20:00:00Z");
      const intruder = path.join(root, "logs", "trace-zz-written-by-tests.jsonl");
      const { runner: inner, calls } = fakeRunner();
      // Like a test (or a setup run) that writes into logs/: a newer trace whose model call has no receipt.
      const runner: Runner = async (cmd, args, o) => {
        if (args.includes("test")) {
          writeFileSync(intruder, ev({ model: "bolt", routed_model: MODELS.bolt }) + "\n");
          utimesSync(intruder, new Date("2026-10-26T23:00:00Z"), new Date("2026-10-26T23:00:00Z"));
        }
        return inner(cmd, args, o);
      };
      const lines: string[] = [];
      const rs = await runVerify({ env: liveEnv(base), root, runner, print: (l) => lines.push(l) });
      assert.equal(calls.length, 2, "the engine and tests steps both ran");
      assert.ok(existsSync(intruder), "the fake tests step wrote its trace");
      assert.equal(pickTrace(path.join(root, "logs")).file, intruder, "a later pick would now choose the intruder");
      const receipts = rs.find((r) => r.id === "receipts");
      assert.equal(receipts?.status, "PASS", receipts?.detail);
      assert.match(receipts?.detail ?? "", /^trace-good\.jsonl: 3\/3 model calls/);
      assert.doesNotMatch(receipts?.detail ?? "", /trace-zz-written-by-tests/);
      assert.deepEqual(rs.map((r) => r.id), ["env", "zetaris", "nightshift", "views", "engine", "tests", "receipts"]);
      assert.ok(/^PASS\s+receipts\s+trace-good\.jsonl/.test(lines[6]), lines[6]);
      assert.equal(exitCode(rs), 0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("live mode, an explicit --trace without model calls → receipts FAIL; sample mode → SKIP", async () => {
    const root = tmpRoot();
    try {
      const f = writeTrace(root, "trace-setup-20261026T212327Z.jsonl", SETUP_TRACE, "2026-10-26T21:23:27Z");
      const live = await runVerify({
        env: liveEnv("http://127.0.0.1:9"), root, trace: f, only: ["receipts"], runner: fakeRunner().runner,
        fetchImpl: throwingFetch, print: () => {},
      });
      assert.equal(live.find((r) => r.id === "receipts")?.status, "FAIL");
      assert.equal(exitCode(live), 1);
      const sample = await runVerify({
        env: { SAMPLE_MODE: "true" }, root, trace: f, only: ["receipts"], runner: fakeRunner().runner,
        fetchImpl: throwingFetch, print: () => {},
      });
      assert.equal(sample.find((r) => r.id === "receipts")?.status, "SKIP");
      assert.equal(exitCode(sample), 0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("a credential echoed back in an error message is redacted", async () => {
    resetMock();
    state.kevRows = [];
    state.echoAuthOnError = true;
    const root = tmpRoot();
    try {
      const lines: string[] = [];
      const rs = await runVerify({
        env: liveEnv(base), root, prefix: "EL_T2_", only: ["views"], fetchImpl: globalThis.fetch,
        runner: fakeRunner().runner, print: (l) => lines.push(l),
      });
      const views = rs.find((r) => r.id === "views");
      assert.equal(views?.status, "FAIL");
      assert.match(views?.detail ?? "", /Bearer …redacted/);
      assert.ok(!lines.join("\n").includes(ZKEY));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("live with no credentials → env FAIL, the live checks SKIP without any request, exit 1", async () => {
    const root = tmpRoot();
    try {
      const rs = await runVerify({ env: {}, root, runner: fakeRunner().runner, fetchImpl: throwingFetch, print: () => {} });
      assert.deepEqual(statuses(rs), {
        env: "FAIL", zetaris: "SKIP", nightshift: "SKIP", views: "SKIP", engine: "PASS", tests: "PASS", receipts: "SKIP",
      });
      assert.equal(exitCode(rs), 1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("Zetaris down → zetaris FAIL and the views check is skipped, not left to time out", async () => {
    const root = tmpRoot();
    try {
      const port = await closedPort();
      const env = liveEnv(base, { ZETARIS_REST_URL: `http://127.0.0.1:${port}/api/v1.0` });
      const rs = await runVerify({ env, root, runner: fakeRunner().runner, print: () => {} });
      assert.equal(statuses(rs).zetaris, "FAIL");
      assert.equal(statuses(rs).views, "SKIP");
      assert.match(rs.find((r) => r.id === "views")?.detail ?? "", /not answering/);
      assert.equal(exitCode(rs), 1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("failing sub-commands → FAIL with the output tail; a timeout is reported", async () => {
    const root = tmpRoot();
    try {
      const { runner } = fakeRunner({
        engine: { code: 1, output: "conformance: 7/8 checks passed\nFAIL idempotency\n" },
        tests: { code: 1, output: "✖ broken\nℹ tests 10\nℹ pass 8\nℹ fail 2\n" },
      });
      const rs = await runVerify({ env: { SAMPLE_MODE: "true" }, root, runner, print: () => {} });
      const engine = rs.find((r) => r.id === "engine");
      const tests = rs.find((r) => r.id === "tests");
      assert.equal(engine?.status, "FAIL");
      assert.deepEqual(engine?.tail, ["conformance: 7/8 checks passed", "FAIL idempotency"]);
      assert.equal(tests?.status, "FAIL");
      assert.match(tests?.detail ?? "", /exited 1: 2 failed, 8 passed/);
      assert.equal(exitCode(rs), 1);

      const slow = fakeRunner({ tests: { code: null, timedOut: true, output: "" } });
      const rs2 = await runVerify({ env: { SAMPLE_MODE: "true" }, root, runner: slow.runner, only: ["tests"], print: () => {} });
      assert.match(rs2.find((r) => r.id === "tests")?.detail ?? "", /timed out/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("--only / --skip select checks; unselected ones SKIP and run nothing", async () => {
    const root = tmpRoot();
    try {
      const { runner, calls } = fakeRunner();
      const rs = await runVerify({ env: {}, root, runner, fetchImpl: throwingFetch, only: ["receipts"], print: () => {} });
      assert.equal(calls.length, 0);
      assert.equal(rs.filter((r) => r.detail === "not selected").length, 6);
      const rs2 = await runVerify({ env: { SAMPLE_MODE: "true" }, root, runner, skip: ["tests", "engine"], print: () => {} });
      assert.equal(calls.length, 0);
      assert.equal(exitCode(rs2), 0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------- the CLI itself

function runCli(args: string[], env: Env): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-transform-types", "--no-warnings", "scripts/verify.ts", ...args], {
      cwd: REPO, env: env as Record<string, string>, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { out += d; });
    child.on("close", (code) => resolve({ code, out }));
  });
}

describe("CLI", () => {
  test("--json with a bad fixture trace exits 1; a good one exits 0; an unknown check id exits 2", async () => {
    const root = tmpRoot();
    try {
      const bad = path.join(root, "trace-bad.jsonl");
      const good = path.join(root, "trace-good.jsonl");
      writeFileSync(bad, ev({ model: "bolt" }) + "\n");
      writeFileSync(good, GOOD_TRACE);
      const env = { PATH: process.env.PATH, SAMPLE_MODE: "true" };
      const r1 = await runCli(["--only", "receipts", "--trace", bad, "--json"], env);
      assert.equal(r1.code, 1, r1.out);
      const j1 = JSON.parse(r1.out) as { ok: boolean; mode: string; results: CheckResult[] };
      assert.equal(j1.ok, false);
      assert.equal(j1.mode, "sample");
      assert.equal(j1.results.find((r) => r.id === "receipts")?.status, "FAIL");

      const r2 = await runCli(["--only", "receipts", "--trace", good], env);
      assert.equal(r2.code, 0, r2.out);
      assert.match(r2.out, /^verify \(mode: sample, prefix: EL_\)/);
      assert.match(r2.out, /PASS\s+receipts\s+trace-good\.jsonl: 3\/3/);
      assert.match(r2.out, /verify: 1 passed, 0 failed, 6 skipped → OK/);

      const r3 = await runCli(["--only", "bogus"], env);
      assert.equal(r3.code, 2);
      assert.match(r3.out, /unknown check id\(s\): bogus/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
