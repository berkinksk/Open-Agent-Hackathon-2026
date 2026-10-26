import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ConfigError, DEFAULT_INVENTORY_URL, checkConfig, describeConfig, isSafeId, isValidPrefix, loadConfig, newRunId, parseBool, requireConfig,
} from "../src/config.ts";

const FAKE_KEY = "zk-fake-value-9f8e7d6c";
const FAKE_TOKEN = "ns-fake-value-1a2b3c4d";
const FULL = {
  ZETARIS_REST_URL: "http://localhost:8888/api/v1.0/", ZETARIS_ORG_ID: "1", ZETARIS_API_KEY: FAKE_KEY,
  METERLESS_BASE_URL: "http://127.0.0.1:8088/v1", METERLESS_RUNTIME_TOKEN: FAKE_TOKEN,
};

test("defaults: PORT 8000, prefix EL_, the public inventory URL, live mode", () => {
  const c = loadConfig({});
  assert.equal(c.port, 8000);
  assert.equal(c.prefix, "EL_");
  assert.equal(c.inventoryUrl, DEFAULT_INVENTORY_URL);
  assert.equal(c.sampleMode, false);
});

test("reads every variable; trims trailing slashes from URLs; SAMPLE_MODE parses as a boolean", () => {
  const c = loadConfig({ ...FULL, SAMPLE_MODE: "true", PORT: "9001", EL_PREFIX: "EL_T1_", INVENTORY_URL: "https://x.example/inv.json" });
  assert.equal(c.zetaris.restUrl, "http://localhost:8888/api/v1.0");
  assert.equal(c.zetaris.apiKey, FAKE_KEY);
  assert.equal(c.meterless.token, FAKE_TOKEN);
  assert.equal(c.sampleMode, true);
  assert.equal(c.port, 9001);
  assert.equal(c.prefix, "EL_T1_");
  assert.equal(c.inventoryUrl, "https://x.example/inv.json");
  for (const v of ["1", "yes", "TRUE", "on"]) assert.equal(parseBool(v), true, v);
  for (const v of ["", "0", "false", "no", undefined]) assert.equal(parseBool(v), false, String(v));
});

test("checkConfig reports missing variables by name only", () => {
  const live = checkConfig(loadConfig({}), "live");
  assert.equal(live.ok, false);
  assert.deepEqual(live.missing, ["ZETARIS_REST_URL", "ZETARIS_ORG_ID", "ZETARIS_API_KEY", "METERLESS_BASE_URL", "METERLESS_RUNTIME_TOKEN"]);
  assert.deepEqual(checkConfig(loadConfig({}), "zetaris").missing, ["ZETARIS_REST_URL", "ZETARIS_ORG_ID", "ZETARIS_API_KEY"]);
  assert.equal(checkConfig(loadConfig({}), "sample").ok, true, "sample mode needs nothing");
  assert.equal(checkConfig(loadConfig(FULL), "live").ok, true);
});

test("invalid values are named without printing any value", () => {
  const env = { ...FULL, ZETARIS_REST_URL: "not a url", PORT: "99999", EL_PREFIX: "FZ_" };
  const c = checkConfig(loadConfig(env), "live");
  assert.equal(c.ok, false);
  assert.deepEqual(c.invalid.map((s) => s.split(":")[0]), ["ZETARIS_REST_URL", "PORT", "EL_PREFIX"]);
  let msg = "";
  try { requireConfig(loadConfig({ ZETARIS_API_KEY: FAKE_KEY, PORT: "x" }), "live"); } catch (e) { assert.ok(e instanceof ConfigError); msg = (e as Error).message; }
  assert.match(msg, /missing: ZETARIS_REST_URL/);
  assert.match(msg, /PORT/);
  assert.ok(!msg.includes(FAKE_KEY));
});

test("describeConfig never shows secret values", () => {
  const d = describeConfig(loadConfig(FULL));
  const s = JSON.stringify(d);
  assert.ok(!s.includes(FAKE_KEY) && !s.includes(FAKE_TOKEN));
  assert.equal(d.ZETARIS_API_KEY, "(set, redacted)");
  assert.equal(describeConfig(loadConfig({})).METERLESS_RUNTIME_TOKEN, "(unset)");
});

test("prefixes stay in the EL_ namespace; run ids are file-name safe", () => {
  for (const p of ["EL_", "EL_T1_", "EL_DEV_2_"]) assert.equal(isValidPrefix(p), true, p);
  for (const p of ["el_", "EL", "FZ_", "EL_t1_", "EL_T1", "EL__", ""]) assert.equal(isValidPrefix(p), false, p);
  for (const id of ["run-20261026-213000Z-ab12", "demo_001", "eval-2026-10-26-213000-dev-bolt"]) assert.equal(isSafeId(id), true, id);
  for (const id of ["../etc", "a/b", "", "x".repeat(81), "-lead", "a b"]) assert.equal(isSafeId(id), false, id);
  const id = newRunId(new Date("2026-10-26T21:30:05.123Z"));
  assert.match(id, /^run-20261026-213005Z-[0-9a-f]{4}$/);
  assert.equal(isSafeId(id), true);
});
