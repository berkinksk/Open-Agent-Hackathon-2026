// The sample store: the named Queries over a snapshot, with the live adapter's selection rules and labelled gaps.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { KevEntry } from "../src/contracts.ts";
import { ConfigError, REPO_ROOT } from "../src/config.ts";
import { memoryTracer } from "../src/trace.ts";
import { createSampleQueries } from "../src/sample/queries.ts";
import { SNAPSHOT_SCHEMA, SnapshotError, formatSnapshot, parseSnapshot } from "../src/sample/snapshot.ts";
import type { SampleSnapshot } from "../src/sample/snapshot.ts";
import { FactStore } from "../src/pipeline/facts.ts";
import { familiesOf } from "../src/resolve/normalise.ts";

const TMP = join(REPO_ROOT, "output", ".test-tmp", "sample-queries");

function kev(cve: string, vendor: string, product: string, added = "2026-01-01"): KevEntry {
  return {
    cve_id: cve, vendor, product, vulnerability_name: `${vendor} ${product} flaw`, date_added: added, due_date: "2026-01-22",
    ransomware_use: "Unknown", required_action: "Apply updates.", short_description: "A flaw.", notes: "", catalog_version: "2026.10.23",
  };
}

function fixture(over: Partial<SampleSnapshot> = {}): SampleSnapshot {
  const at = "2026-10-27T00:30:00.000Z";
  return {
    schema: SNAPSHOT_SCHEMA, description: "test", captured_at: at, finished_at: at,
    capture: { tool: "test", prefix: "EL_", zetaris_queries: 0, zetaris_ms: 0, queries: [], notes: [] },
    sources: {
      inventory: { object: "el.inventory", captured_at: at, rows: 1, synthetic: true },
      kev: { object: "el.kev", captured_at: at, catalog_version: "2026.10.23", pairs: 4, entries: 4, scope: "full_catalogue", inventory_vendors: ["Microsoft"] },
      epss: { object: "EL_EPSS.el_epss_<batch>", captured_at: at, requested: 3, scored: 2, score_dates: ["2026-10-26"] },
      nvd: { object: "EL_NVD.el_nvd_<cve>", captured_at: at, cves: 1, states: { ok: 1 }, plan: "1 CVE" },
      nvd_products: { object: "EL_NVD.el_nvdp_<hash>", captured_at: at, lookups: 1, window_days: 120, page_size: 20 },
    },
    inventory: [{ row_id: "R01", asset_id: "A1", asset_name: "pc-01", asset_type: "laptop", internet_facing: false, owner_team: "IT", software: "Windows 11 23H2" }],
    kev_pairs: [
      { vendor: "Fortinet", product: "FortiOS" }, { vendor: "Microsoft", product: "Windows" },
      { vendor: "Microsoft", product: "Windows " }, { vendor: "Acme", product: "Widget" },
    ],
    kev_entries: [
      kev("CVE-2026-0001", "Microsoft", "Windows", "2026-09-01"), kev("CVE-2026-0002", "Microsoft", "Windows ", "2026-10-01"),
      kev("CVE-2025-1111", "Fortinet", "FortiOS"), kev("CVE-2024-2222", "Acme", "Widget"),
    ],
    epss_requested: ["CVE-2026-0001", "CVE-2026-0002", "CVE-2025-1111"],
    epss: [
      { cve_id: "CVE-2026-0001", epss: 0.5, percentile: 0.97, score_date: "2026-10-26" },
      { cve_id: "CVE-2025-1111", epss: 0.02, percentile: Number.NaN, score_date: "2026-10-26" },
    ],
    nvd: {
      "CVE-2026-0002": { state: "ok", as_of: "2026-10-27", table: "el_nvd_cve_2026_0002", ranges: [
        { cve_id: "CVE-2026-0002", criteria: "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*", vulnerable: true, version_end_excluding: "10.0.22631.4000" },
      ] },
    },
    nvd_errors: { "CVE-2026-0001": "timeout" },
    nvd_products: { "cpe:acme:widget": { state: "ok", as_of: "2026-10-27", table: "el_nvdp_1234abcd", hits: [{ cve_id: "CVE-2026-5555", published: "2026-10-01", ranges: [] }] } },
    ...over,
  };
}

test("kevByProducts applies the live rule lower(trim()): 'Windows' finds both KEV spellings; unknown pairs find nothing", async () => {
  const t = memoryTracer();
  const q = createSampleQueries({ tracer: t, snapshot: fixture() });
  const got = await q.kevByProducts([{ vendor: " microsoft ", product: "WINDOWS" }, { vendor: "Nobody", product: "Nothing" }]);
  assert.deepEqual(got.map((e) => `${e.cve_id}|${e.product}`), ["CVE-2026-0001|Windows", "CVE-2026-0002|Windows "]);
  const ev = t.events.find((e) => e.action === "kevByProducts");
  assert.equal(ev?.agent, "sample_store");
  assert.equal(ev?.status, "ok", "a full-catalogue snapshot has no coverage gap: a pair KEV does not list is simply absent");
  assert.equal((ev?.details as { source?: string }).source, "snapshot");
  assert.deepEqual(await q.kevByProducts([]), []);
});

test("an inventory-vendors snapshot labels a vendor outside its KEV slice as a fallback (the row then fails closed)", async () => {
  const s = fixture();
  s.sources.kev.scope = "inventory_vendors";
  s.kev_entries = s.kev_entries.filter((e) => e.vendor !== "Acme");
  const t = memoryTracer();
  const q = createSampleQueries({ tracer: t, snapshot: s });
  assert.deepEqual(await q.kevByProducts([{ vendor: "Acme", product: "Widget" }]), []);
  const ev = t.events.find((e) => e.action === "kevByProducts");
  assert.equal(ev?.status, "fallback");
  assert.match(ev?.output_summary ?? "", /outside the snapshot's KEV slice: Acme/);
});

test("kevVerify and epssVerify re-read the snapshot (labelled not live); invalid ids are reported, not guessed", async () => {
  const t = memoryTracer();
  const q = createSampleQueries({ tracer: t, snapshot: fixture() });
  assert.deepEqual((await q.kevVerify(["cve-2025-1111", "nope"])).map((e) => e.cve_id), ["CVE-2025-1111"]);
  assert.ok(t.events.some((e) => e.action === "invalid_cve_ids" && e.status === "error"));
  assert.match(t.events.find((e) => e.action === "kevVerify")?.output_summary ?? "", /re-read from the snapshot \(not live: sample mode\)/);
  assert.deepEqual((await q.epssVerify(["CVE-2026-0001"])).map((s) => s.epss), [0.5]);
});

test("epss: a CVE without a score stays missing (never 0); a CVE outside the capture is a labelled fallback", async () => {
  const t = memoryTracer();
  const q = createSampleQueries({ tracer: t, snapshot: fixture() });
  const got = await q.epss(["CVE-2026-0001", "CVE-2026-0002", "CVE-2099-9999"]);
  assert.deepEqual(got.map((s) => s.cve_id), ["CVE-2026-0001"]);
  const ev = t.events.find((e) => e.action === "epss");
  assert.equal(ev?.status, "fallback");
  assert.match(ev?.output_summary ?? "", /1 had no EPSS score at capture; 1 not in the snapshot \(no score; never treated as 0\)/);
});

test("nvdCves: a captured CVE is served as a cached read with its capture day; a missing one is an error, never 'no ranges'", async () => {
  const t = memoryTracer();
  const q = createSampleQueries({ tracer: t, snapshot: fixture() });
  const r = await q.nvdCves(["cve-2026-0002", "CVE-2026-0002", "CVE-2026-0001", "CVE-2099-1", "junk"]);
  assert.equal(r.length, 1);
  assert.equal(r[0].version_end_excluding, "10.0.22631.4000");
  const st = q.nvdStatus();
  assert.deepEqual(st.map((s) => [s.key, s.state]), [["CVE-2026-0002", "cached"], ["CVE-2026-0001", "error"], ["CVE-2099-1", "invalid"], ["junk", "invalid"]]);
  assert.equal(st[0].as_of, "2026-10-27");
  assert.match(st[0].detail ?? "", /sample snapshot: read through Zetaris on 2026-10-27/);
  assert.match(st[1].detail ?? "", /could not read it \(timeout\)/);
  assert.equal(q.nvdCached("CVE-2099-9999"), true, "a sample lookup never spends the NVD budget");
  assert.ok(t.events.some((e) => e.action === "nvdCves" && e.status === "fallback" && /fail-closed/.test(e.output_summary ?? "")));
});

test("nvdProduct serves a captured lookup and reports a missing one", async () => {
  const q = createSampleQueries({ tracer: memoryTracer(), snapshot: fixture() });
  assert.deepEqual((await q.nvdProduct("ACME", "Widget")).map((h) => h.cve_id), ["CVE-2026-5555"]);
  assert.deepEqual(await q.nvdProduct("acme", "gadget"), []);
  assert.deepEqual(q.nvdStatus().map((s) => [s.key, s.state]), [["cpe:acme:widget", "cached"], ["cpe:acme:gadget", "error"]]);
});

test("the store hands out copies: a caller that mutates rows cannot change the next run's data", async () => {
  const snap = fixture();
  const q = createSampleQueries({ tracer: memoryTracer(), snapshot: snap });
  const inv = await q.inventory();
  inv[0].software = "changed";
  (await q.kevByProducts([{ vendor: "Acme", product: "Widget" }]))[0].due_date = "1999-01-01";
  assert.equal((await q.inventory())[0].software, "Windows 11 23H2");
  assert.equal((await q.kevVerify(["CVE-2024-2222"]))[0].due_date, "2026-01-22");
  assert.equal(snap.inventory[0].software, "Windows 11 23H2");
});

test("loading traces the snapshot and its dates; snapshotInfo gives the capture dates for the run manifest", () => {
  const t = memoryTracer();
  const q = createSampleQueries({ tracer: t, snapshot: fixture() });
  const ev = t.events[0];
  assert.equal(ev.action, "snapshot_loaded");
  assert.match(ev.output_summary ?? "", /captured 2026-10-27 through Zetaris: 1 inventory rows, 4 KEV entries \(catalog 2026\.10\.23\).*no network in this run/);
  const info = q.snapshotInfo();
  assert.equal(info.captured_day, "2026-10-27");
  assert.equal(info.inventory_day, "2026-10-27");
  assert.equal(info.kev_catalog_version, "2026.10.23");
  assert.equal(info.kev_scope, "full_catalogue");
});

test("the fact store over the sample store: captured CVEs count as looked up (not live); missing ones are given up, never skipped for budget", async () => {
  const q = createSampleQueries({ tracer: memoryTracer(), snapshot: fixture() });
  const facts = new FactStore({ queries: q, tracer: memoryTracer(), pairs: fixture().kev_pairs, familiesOf, nvdBudgetMs: 0, nvdMaxCves: 0 });
  await facts.ensureNvd(["CVE-2026-0002", "CVE-2026-0001"], "test");
  assert.equal(facts.nvdState.get("CVE-2026-0002"), "cached");
  assert.equal(facts.nvdLooked("CVE-2026-0002"), true);
  assert.equal(facts.nvdLive("CVE-2026-0002"), false, "snapshot data is never labelled live");
  assert.equal(facts.nvdAsOf.get("CVE-2026-0002"), "2026-10-27");
  assert.equal(facts.nvdState.get("CVE-2026-0001"), "error");
  assert.equal(facts.nvdGivenUp("CVE-2026-0001"), true);
  assert.equal(facts.nvdDormant, null);
  await facts.ensureFamilies(["microsoft:windows"]);
  assert.deepEqual(facts.entries("microsoft:windows").map((e) => e.cve_id).sort(), ["CVE-2026-0001", "CVE-2026-0002"]);
  assert.equal(facts.kevError, null);
});

test("format and parse round-trip; a missing percentile comes back as NaN, like the live adapter's", () => {
  const s = fixture();
  const text = formatSnapshot(s);
  const back = parseSnapshot(text);
  assert.ok(Number.isNaN(back.epss.find((x) => x.cve_id === "CVE-2025-1111")?.percentile));
  assert.deepEqual(back.kev_entries, s.kev_entries);
  assert.deepEqual(back.nvd, s.nvd);
  assert.ok(text.split("\n").some((l) => l.trim().startsWith('{"cve_id":"CVE-2026-0001"')), "one KEV entry per line");
  assert.throws(() => parseSnapshot(JSON.stringify({ ...s, schema: "other" })), SnapshotError);
  assert.throws(() => parseSnapshot(JSON.stringify({ ...s, kev_entries: [] })), /kev_entries must be a non-empty array/);
  assert.throws(() => parseSnapshot(JSON.stringify({ ...s, inventory: [{ software: 1 }] })), /inventory\[0\]/);
  assert.throws(() => parseSnapshot("{not json"), /not valid JSON/);
});

test("a missing or broken snapshot file stops sample mode with a ConfigError that says how to fix it", () => {
  mkdirSync(TMP, { recursive: true });
  try {
    assert.throws(() => createSampleQueries({ tracer: memoryTracer(), file: join(TMP, "absent.json") }),
      (e: unknown) => e instanceof ConfigError && /missing; capture it with "npm run snapshot"/.test((e as Error).message));
    const bad = join(TMP, "bad.json");
    writeFileSync(bad, JSON.stringify({ schema: "nope" }));
    assert.throws(() => createSampleQueries({ tracer: memoryTracer(), file: bad }), (e: unknown) => e instanceof ConfigError && /schema must be/.test((e as Error).message));
    const good = join(TMP, "good.json");
    writeFileSync(good, formatSnapshot(fixture()));
    assert.equal(createSampleQueries({ tracer: memoryTracer(), file: good }).snapshotInfo().file, good);
  } finally {
    rmSync(TMP, { recursive: true, force: true });
  }
});
