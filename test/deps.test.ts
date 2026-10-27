import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_POLICY } from "../src/contracts.ts";
import type { Llm, Queries } from "../src/contracts.ts";
import { ConfigError, REPO_ROOT, isSafeId } from "../src/config.ts";
import { makeDeps, mergePolicy, resolvePolicy, sampleStorePresent, validatePolicy } from "../src/deps.ts";

const TMP_ROOT = join(REPO_ROOT, "output", ".test-tmp");
const made: string[] = [];
function tmp(): string { mkdirSync(TMP_ROOT, { recursive: true }); const d = mkdtempSync(join(TMP_ROOT, "deps-")); made.push(d); return d; }
after(() => { for (const d of made) rmSync(d, { recursive: true, force: true }); });

const FAKE_KEY = "zk-fake-deps-77aa88bb";
const FAKE_TOKEN = "ns-fake-deps-11cc22dd";
const FULL = {
  ZETARIS_REST_URL: "http://127.0.0.1:1/api/v1.0", ZETARIS_ORG_ID: "1", ZETARIS_API_KEY: FAKE_KEY,
  METERLESS_BASE_URL: "http://127.0.0.1:1/v1", METERLESS_RUNTIME_TOKEN: FAKE_TOKEN,
};
const stubQueries = {} as Queries;
const stubLlm: Llm = { async chat() { throw new Error("not used"); } };

test("live: builds Zetaris queries and the Nightshift LLM from env, without any network call", () => {
  const dir = tmp();
  const d = makeDeps({ mode: "live", runId: "deps-live-1" }, { env: FULL, logDir: dir, stdout: false, policyFile: null });
  assert.equal(d.mode, "live");
  assert.ok(d.llm && typeof d.llm.chat === "function");
  for (const k of ["inventory", "kevPairs", "kevByProducts", "kevVerify", "epss", "epssVerify", "nvdCves", "nvdProduct"] as const) assert.equal(typeof d.queries[k], "function", k);
  assert.equal(d.tracer.run_id, "deps-live-1");
  assert.equal(d.tracer.file, join(dir, "trace-deps-live-1.jsonl"));
  assert.ok(d.clock.now() instanceof Date);
  assert.deepEqual(d.policy, DEFAULT_POLICY);
  const trace = readFileSync(d.tracer.file, "utf8");
  const ev = JSON.parse(trace.trim().split("\n")[0]);
  assert.equal(ev.action, "deps_ready");
  assert.equal(ev.details.queries, "zetaris");
  assert.equal(ev.details.llm, "nightshift");
  assert.ok(!trace.includes(FAKE_KEY) && !trace.includes(FAKE_TOKEN), "no secret in the trace");
});

test("live without settings: a ConfigError that names the missing variables, never their values", () => {
  let err: unknown;
  try { makeDeps({ mode: "live", runId: "deps-missing" }, { env: { ZETARIS_API_KEY: FAKE_KEY }, logDir: tmp(), stdout: false }); } catch (e) { err = e; }
  assert.ok(err instanceof ConfigError);
  const e = err as ConfigError;
  assert.deepEqual(e.missing, ["ZETARIS_REST_URL", "ZETARIS_ORG_ID", "METERLESS_BASE_URL", "METERLESS_RUNTIME_TOKEN"]);
  assert.ok(!e.message.includes(FAKE_KEY));
});

test("live with injected queries needs only the Nightshift settings (and vice versa)", () => {
  const onlyNs = { METERLESS_BASE_URL: FULL.METERLESS_BASE_URL, METERLESS_RUNTIME_TOKEN: FAKE_TOKEN };
  assert.equal(makeDeps({ mode: "live", runId: "deps-q" }, { env: onlyNs, queries: stubQueries, logDir: tmp(), stdout: false }).queries, stubQueries);
  const onlyZ = { ZETARIS_REST_URL: FULL.ZETARIS_REST_URL, ZETARIS_ORG_ID: "1", ZETARIS_API_KEY: FAKE_KEY };
  assert.equal(makeDeps({ mode: "live", runId: "deps-l" }, { env: onlyZ, llm: stubLlm, logDir: tmp(), stdout: false }).llm, stubLlm);
});

test("sample: no LLM ever, and no settings needed", () => {
  const d = makeDeps({ mode: "sample", runId: "deps-sample" }, { env: {}, queries: stubQueries, llm: stubLlm, logDir: tmp(), stdout: false });
  assert.equal(d.mode, "sample");
  assert.equal(d.llm, null, "sample mode drops even an injected LLM");
});

test("sample without the sample store fails clearly (until src/sample/queries.ts exists)", () => {
  if (sampleStorePresent()) {
    const d = makeDeps({ mode: "sample", runId: "deps-store" }, { env: {}, logDir: tmp(), stdout: false });
    assert.equal(d.llm, null);
    return;
  }
  assert.throws(() => makeDeps({ mode: "sample", runId: "deps-nostore" }, { env: {}, logDir: tmp(), stdout: false }), (e: unknown) => e instanceof ConfigError && /src\/sample\/queries\.ts/.test((e as Error).message));
});

test("run ids: generated when absent, refused when unsafe", () => {
  const d = makeDeps({ mode: "sample" }, { env: {}, queries: stubQueries, logDir: tmp(), stdout: false });
  assert.ok(isSafeId(d.tracer.run_id));
  assert.match(d.tracer.run_id, /^\d{8}-\d{6}Z-[0-9a-f]{4}$/);
  assert.match(d.tracer.file, /trace-\d{8}-\d{6}Z-[0-9a-f]{4}\.jsonl$/);
  assert.throws(() => makeDeps({ mode: "sample", runId: "../x" }, { env: {}, queries: stubQueries, logDir: tmp(), stdout: false }), ConfigError);
});

test("policy: DEFAULT_POLICY <- config file <- per-run patch, deep-merging sla_days; invalid values refused", () => {
  const file = join(tmp(), "policy.json");
  writeFileSync(file, JSON.stringify({ epss_this_cycle: 0.2, sla_days: { this_cycle: 21 } }));
  const p = resolvePolicy({ sla_days: { patch_now: 3 } } as never, file);
  assert.equal(p.epss_this_cycle, 0.2);
  assert.deepEqual(p.sla_days, { patch_now: 3, this_cycle: 21, monitor_review: 90 });
  assert.equal(p.epss_this_cycle_internet, DEFAULT_POLICY.epss_this_cycle_internet);
  assert.deepEqual(resolvePolicy(undefined, null), DEFAULT_POLICY);
  assert.throws(() => resolvePolicy({ epss_this_cycle: 2 }, null), ConfigError);
  assert.throws(() => resolvePolicy({ max_critic_rounds: 1.5 }, null), ConfigError);
  assert.deepEqual(validatePolicy(mergePolicy(DEFAULT_POLICY, { rubric_auto_min: 10 })), ["rubric_auto_min must be an integer in [0, 9]"]);
  const d = makeDeps({ mode: "sample", runId: "deps-pol", policy: { epss_this_cycle_internet: 0.01 } }, { env: {}, queries: stubQueries, logDir: tmp(), stdout: false });
  assert.equal(d.policy.epss_this_cycle_internet, 0.01);
});

test("the repo's config/policy.json is valid", () => {
  assert.equal(validatePolicy(resolvePolicy()).length, 0);
});
