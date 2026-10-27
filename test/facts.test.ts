// FactStore: KEV entries per family (every spelling), EPSS batches, NVD lookups inside a budget. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { EpssScore, KevEntry, KevPair, NvdRange, Queries, TraceEvent, Tracer } from "../src/contracts.ts";
import { FactStore } from "../src/pipeline/facts.ts";
import type { QueriesWithNvdStatus } from "../src/pipeline/facts.ts";
import { familiesOf } from "../src/resolve/normalise.ts";

const tracer = (): Tracer & { events: TraceEvent[] } => {
  const events: TraceEvent[] = [];
  return { run_id: "t", file: "", events, emit(e) { events.push({ ts: "", run_id: "t", ...e }); } };
};
const kev = (cve_id: string, vendor: string, product: string, date_added = "2026-01-01"): KevEntry => ({
  cve_id, vendor, product, vulnerability_name: "test", date_added, due_date: "2026-01-22", ransomware_use: "Unknown",
  required_action: "Apply updates.", short_description: "", notes: "", catalog_version: "2026.10.23",
});
const PAIRS: KevPair[] = [{ vendor: "Microsoft", product: "Windows" }, { vendor: "Microsoft", product: "Windows " }, { vendor: "Microsoft", product: "Win32k" }, { vendor: "Apache", product: "Log4j2" }];
const ENTRIES = [kev("CVE-2099-0001", "Microsoft", "Windows"), kev("CVE-2099-0002", "Microsoft", "Windows "), kev("CVE-2099-0003", "Microsoft", "Win32k"), kev("CVE-2021-44228", "Apache", "Log4j2")];

function queries(over: Partial<QueriesWithNvdStatus> = {}): QueriesWithNvdStatus & { log: string[] } {
  const log: string[] = [];
  const base: Queries = {
    async inventory() { return []; },
    async kevPairs() { return PAIRS; },
    async kevByProducts(p) { log.push(`kev:${p.length}`); return ENTRIES.filter((e) => p.some((x) => x.vendor === e.vendor && x.product === e.product)); },
    async kevVerify() { return []; },
    async epss(ids) { log.push(`epss:${ids.length}`); return ids.map((cve_id): EpssScore => ({ cve_id, epss: 0.5, percentile: 0.9, score_date: "2026-10-25" })); },
    async epssVerify() { return []; },
    async nvdCves(ids) { log.push(`nvd:${ids.join(",")}`); return ids.map((cve_id): NvdRange => ({ cve_id, criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", vulnerable: true })); },
    async nvdProduct() { return []; },
  };
  return Object.assign(base, { log }, over);
}

test("KEV entries are fetched once per family and indexed under every family they name (trailing-space spelling included)", async () => {
  const q = queries();
  const f = new FactStore({ queries: q, tracer: tracer(), pairs: PAIRS, familiesOf, nvdBudgetMs: 1000, nvdMaxCves: 4 });
  await f.ensureFamilies(["microsoft:windows"]);
  await f.ensureFamilies(["microsoft:windows"]); // cached: no second query
  assert.deepEqual(q.log, ["kev:3"]);
  assert.deepEqual(f.entries("microsoft:windows").map((e) => e.cve_id).sort(), ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]);
  assert.equal(f.catalogVersion(), "2026.10.23");
  assert.deepEqual(f.pairsFor("microsoft:windows").map((p) => p.product), ["Windows", "Windows ", "Win32k"]);
});

test("a failed KEV read is recorded (fail closed downstream), never thrown", async () => {
  const f = new FactStore({ queries: queries({ kevByProducts: async () => { throw new Error("watchdog fired"); } }), tracer: tracer(), pairs: PAIRS, familiesOf, nvdBudgetMs: 1000, nvdMaxCves: 4 });
  await f.ensureFamilies(["apache:log4j"]);
  assert.match(f.kevError ?? "", /watchdog/);
  assert.deepEqual(f.entries("apache:log4j"), []);
});

test("EPSS: once per CVE, a failed read sets epssError", async () => {
  const q = queries();
  const f = new FactStore({ queries: q, tracer: tracer(), pairs: PAIRS, familiesOf, nvdBudgetMs: 1000, nvdMaxCves: 4 });
  await f.ensureEpss(["cve-2021-44228", "CVE-2021-44228"]);
  await f.ensureEpss(["CVE-2021-44228"]);
  assert.deepEqual(q.log, ["epss:1"]);
  assert.equal(f.epssIndex().get("CVE-2021-44228")?.epss, 0.5);
  const bad = new FactStore({ queries: queries({ epss: async () => { throw new Error("503"); } }), tracer: tracer(), pairs: PAIRS, familiesOf, nvdBudgetMs: 1000, nvdMaxCves: 4 });
  await bad.ensureEpss(["CVE-2021-44228"]);
  assert.match(bad.epssError ?? "", /503/);
});

test("NVD: the cap counts live lookups only; today's cache is free; the rest is skipped, never re-requested", async () => {
  const cached = new Set(["CVE-2000-0003"]);
  const q = queries({ nvdCached: (id: string) => cached.has(id), nvdStatus: () => [] });
  const status: { key: string; state: string; ranges: number }[] = [];
  q.nvdStatus = () => status;
  const inner = q.nvdCves;
  q.nvdCves = async (ids) => { const r = await inner(ids); status.push({ key: ids[0], state: cached.has(ids[0]) ? "cached" : "ok", ranges: 1 }); return r; };
  const t = tracer();
  const f = new FactStore({ queries: q, tracer: t, pairs: PAIRS, familiesOf, nvdBudgetMs: 60_000, nvdMaxCves: 1 });
  const done = await f.ensureNvd(["CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"], "test");
  assert.deepEqual(done, ["CVE-2000-0001", "CVE-2000-0003"]);
  assert.equal(f.nvdState.get("CVE-2000-0002"), "skipped_budget");
  assert.equal(f.nvdState.get("CVE-2000-0003"), "cached");
  assert.equal(f.nvdCalls, 1);
  assert.equal(f.nvdCachedHits, 1);
  assert.ok(f.nvdLooked("CVE-2000-0001") && f.nvdGivenUp("CVE-2000-0002"));
  assert.equal(f.rangesFor(["CVE-2000-0001", "CVE-2000-0002"]).length, 1);
  await f.ensureNvd(["CVE-2000-0002"], "again"); // given up: not asked again
  assert.equal(q.log.filter((l) => l.startsWith("nvd:")).length, 2);
  assert.ok(t.events.some((e) => e.action === "nvd_lookup"));
});

test("NVD: a dormant helper marks every CVE dormant, once", async () => {
  const q = queries({ nvdCves: async () => { throw new Error("dormant: no NVD adapter"); } });
  const f = new FactStore({ queries: q, tracer: tracer(), pairs: PAIRS, familiesOf, nvdBudgetMs: 60_000, nvdMaxCves: 8 });
  await f.ensureNvd(["CVE-2000-0001", "CVE-2000-0002"], "test");
  assert.match(f.nvdDormant ?? "", /^dormant/);
  assert.equal(f.nvdState.get("CVE-2000-0002"), "dormant");
  assert.equal(f.nvdCalls, 0);
});

test("NVD: an exhausted time budget skips the remaining CVEs", async () => {
  let clock = 0;
  const q = queries({ nvdCves: async (ids) => { clock += 5000; return ids.map((cve_id) => ({ cve_id, criteria: "x", vulnerable: false })); } });
  const f = new FactStore({ queries: q, tracer: tracer(), pairs: PAIRS, familiesOf, nvdBudgetMs: 6000, nvdMaxCves: 10, now: () => clock });
  const done = await f.ensureNvd(["CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"], "test");
  assert.deepEqual(done, ["CVE-2000-0001", "CVE-2000-0002"]);
  assert.equal(f.nvdState.get("CVE-2000-0003"), "skipped_budget");
});

test("NVD: only reads through Zetaris in this run are live; today's cache and the client's fallback copy keep their day", async () => {
  const reads: Record<string, { state: string; as_of?: string }> = {
    "CVE-2000-0001": { state: "ok", as_of: "2026-10-27" },
    "CVE-2000-0002": { state: "cached", as_of: "2026-10-27" },
    "CVE-2000-0003": { state: "fallback", as_of: "2026-10-20" },
    "CVE-2000-0004": { state: "no_configurations", as_of: "2026-10-27" },
    "CVE-2000-0005": { state: "error" },
  };
  const status: { key: string; state: string; ranges: number; as_of?: string }[] = [];
  const q = queries();
  const inner = q.nvdCves;
  q.nvdCves = async (ids) => { const r = await inner(ids); status.push({ key: ids[0], ranges: 1, ...reads[ids[0]] }); return r; };
  q.nvdStatus = () => status;
  q.nvdCached = (id: string) => reads[id]?.state === "cached";
  const f = new FactStore({ queries: q, tracer: tracer(), pairs: PAIRS, familiesOf, nvdBudgetMs: 60_000, nvdMaxCves: 8 });
  await f.ensureNvd(Object.keys(reads), "test");
  assert.deepEqual(Object.keys(reads).map((c) => f.nvdLive(c)), [true, false, false, true, false]);
  assert.equal(f.nvdLive("CVE-2000-0009"), false); // never looked up
  assert.equal(f.nvdAsOf.get("CVE-2000-0002"), "2026-10-27");
  assert.equal(f.nvdAsOf.get("CVE-2000-0003"), "2026-10-20");
  assert.equal(f.nvdAsOf.has("CVE-2000-0005"), false);
});
