// scripts/snapshot.ts (the capture) against a fake Zetaris client and a fake NVD adapter, and the shipped snapshot.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { KevEntry, NvdRange } from "../src/contracts.ts";
import { REPO_ROOT } from "../src/config.ts";
import { KEV_COLUMNS, epssTableName } from "../src/adapters/queries.ts";
import type { NvdLookupStatus } from "../src/adapters/nvd.ts";
import type { QueryOptions, QueryResult } from "../src/adapters/zetaris.ts";
import { captureSnapshot, nvdPlan, parseSnapshotArgs, writeSnapshot } from "../scripts/snapshot.ts";
import type { CaptureNvd } from "../scripts/snapshot.ts";
import { DEFAULT_SNAPSHOT_FILE, SNAPSHOT_SCHEMA, loadSnapshot, parseSnapshot } from "../src/sample/snapshot.ts";

const TMP = join(REPO_ROOT, "output", ".test-tmp", "sample-snapshot");

const inventoryRows = [
  { row_id: "R2", asset_id: "pc-01", asset_name: "pc-01", asset_type: "laptop", internet_facing: "no", owner_team: "IT", software: "Microsoft Windows 11 23H2" },
  { row_id: "R1", asset_id: "web-01", asset_name: "web-01", asset_type: "server", internet_facing: "yes", owner_team: "IT", software: "Apache Tomcat 9.0.80" },
  { row_id: "R3", asset_id: "fw-01", asset_name: "fw-01", asset_type: "firewall", internet_facing: "yes", owner_team: "IT", software: "Fortinet FortiOS 7.2.4" },
];

function entry(cve: string, vendor: string, product: string, added: string): Record<string, string> {
  return {
    cve_id: cve, vendor, product, vulnerability_name: `${product} flaw`, date_added: added, due_date: "2026-01-01",
    ransomware_use: "Unknown", required_action: "Patch.", short_description: "A flaw.", notes: "", catalog_version: "2026.10.23",
  };
}
const kevRows = [
  entry("CVE-2026-1001", "Apache", "Tomcat", "2026-08-04"), entry("CVE-2025-1002", "Apache", "Tomcat", "2025-04-01"),
  entry("CVE-2020-1003", "Apache", "Tomcat", "2020-03-01"), entry("CVE-2017-1004", "Apache", "Tomcat", "2017-10-01"),
  entry("CVE-2026-2001", "Microsoft", "Windows", "2026-10-16"), entry("CVE-2025-2002", "Microsoft", "Windows ", "2025-01-01"),
  entry("CVE-2024-2003", "Microsoft", "Windows", "2024-01-01"),
  entry("CVE-2024-3001", "Fortinet", "FortiOS", "2024-02-09"), entry("CVE-2018-3002", "Fortinet", "FortiOS", "2021-11-03"),
  ...Array.from({ length: 150 }, (_, i) => entry(`CVE-2019-${String(9000 + i)}`, "Acme", "Widget", "2019-01-01")),
];
const pairRows = [...new Map(kevRows.map((e) => [`${e.vendor}|${e.product}`, { vendor: e.vendor, product: e.product }])).values()];

class FakeZetaris {
  inFlight = 0;
  maxInFlight = 0;
  queries: { sql: string; opts?: QueryOptions }[] = [];
  ddls: string[] = [];
  epssBatches = new Map<string, string[]>();
  truncate = "";
  fromCache = "";
  async query(sql: string, opts?: QueryOptions): Promise<QueryResult> {
    this.inFlight++;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    try {
      await new Promise((r) => setTimeout(r, 1));
      this.queries.push({ sql, opts });
      let rows: Record<string, string>[];
      if (/FROM el\.inventory$/.test(sql)) rows = inventoryRows.map((r) => Object.fromEntries(Object.entries(r)));
      else if (/^SELECT DISTINCT vendor, product FROM el\.kev/.test(sql)) rows = pairRows;
      else if (sql === `SELECT ${KEV_COLUMNS.join(", ")} FROM el.kev`) rows = kevRows;
      else {
        const m = sql.match(/FROM el_epss\.(el_epss_[0-9a-f]{8}) LATERAL VIEW explode\(data\) AS d$/);
        if (!m) throw new Error(`unexpected SQL: ${sql}`);
        rows = (this.epssBatches.get(m[1]) ?? []).filter((c) => c !== "CVE-2019-9007").map((c, i) => ({ cve_id: c, epss: String(0.001 * (i + 1)), percentile: "0.5", score_date: "2026-10-26" }));
      }
      const total = this.truncate && sql.includes(this.truncate) ? rows.length + 5 : rows.length;
      return { rows, ms: 3, fromCache: !!this.fromCache && sql.includes(this.fromCache), total };
    } finally {
      this.inFlight--;
    }
  }
  async ddl(sql: string): Promise<{ outcome: "created" | "exists"; ms: number }> {
    this.ddls.push(sql);
    const m = sql.match(/^CREATE LIGHTNING REST TABLE (el_epss_[0-9a-f]{8}) FROM EL_EPSS REQUEST\(endpoint "https:\/\/api\.first\.org\/data\/v1\/epss\?cve=([^"]+)"/);
    if (!m) throw new Error(`unexpected DDL: ${sql}`);
    this.epssBatches.set(m[1], m[2].split(","));
    return { outcome: "created", ms: 2 };
  }
}

function fakeNvd(failOnce: string[] = []): CaptureNvd & { asked: string[] } {
  const statuses: NvdLookupStatus[] = [];
  const asked: string[] = [];
  const failed = new Set<string>();
  return {
    asked,
    async nvdCves(ids: string[]): Promise<NvdRange[]> {
      const id = ids[0];
      asked.push(id);
      if (failOnce.includes(id) && !failed.has(id)) {
        failed.add(id);
        statuses.push({ key: id, state: "error", table: null, ranges: 0, detail: "rate limited" });
        return [];
      }
      const product = id.startsWith("CVE-2026-1") || id.startsWith("CVE-2025-1") ? "apache:tomcat" : id.includes("-200") ? "microsoft:windows_11_23h2" : "fortinet:fortios";
      const part = product.startsWith("microsoft") ? "o" : "a";
      const ranges: NvdRange[] = [{ cve_id: id, criteria: `cpe:2.3:${part}:${product}:*:*:*:*:*:*:*:*`, vulnerable: true, version_end_excluding: "99" }];
      statuses.push({ key: id, state: "ok", table: `el_nvd_${id.toLowerCase().replace(/-/g, "_")}`, ranges: 1, as_of: "2026-10-27" });
      return ranges;
    },
    async nvdProduct(v: string, p: string) {
      statuses.push({ key: `cpe:${v}:${p}`, state: "ok", table: "el_nvdp_00000000", ranges: 0, as_of: "2026-10-27" });
      return [{ cve_id: "CVE-2026-7777", published: "2026-10-01T00:00:00", ranges: [] }];
    },
    status: () => statuses.map((s) => ({ ...s })),
  };
}

const clock = () => new Date("2026-10-27T01:00:00.000Z");

test("the capture reads every source live, one query at a time, with the cache bypassed, and stores what it read with dates", async () => {
  const z = new FakeZetaris();
  const nvd = fakeNvd(["CVE-2024-3001"]);
  const { snapshot: s, plan } = await captureSnapshot({ client: z, nvd, now: clock, products: 3 });
  assert.ok(s);
  assert.equal(z.maxInFlight, 1, "one Zetaris query at a time");
  assert.ok(z.queries.every((q) => q.opts?.cache === "bypass"), "the snapshot is never filled from the app's cache");
  assert.ok(z.queries.every((q) => q.opts?.label?.startsWith("snapshot:")));
  // EPSS: every captured KEV CVE, in batches of <= 100, one EL_EPSS REST table each (the live naming rule)
  assert.equal(s.epss_requested.length, kevRows.length);
  assert.equal(z.ddls.length, 2);
  for (const [table, ids] of z.epssBatches) {
    assert.ok(ids.length <= 100);
    assert.equal(table, epssTableName(ids));
  }
  assert.equal(s.epss.length, kevRows.length - 1, "a CVE without a score is not invented");
  assert.ok(!s.epss.some((x) => x.cve_id === "CVE-2019-9007"));
  assert.ok(s.epss_requested.includes("CVE-2019-9007"), "but it is recorded as asked");
  // the NVD plan of the pipeline: Windows the newest, small family all, larger family the 2 newest; internet-facing first
  assert.deepEqual(plan.map((f) => [f.family, f.cves]), [
    ["apache:tomcat", ["CVE-2026-1001", "CVE-2025-1002"]],
    ["fortinet:fortios", ["CVE-2024-3001", "CVE-2018-3002"]],
    ["microsoft:windows", ["CVE-2026-2001"]],
  ]);
  assert.deepEqual(Object.keys(s.nvd), ["CVE-2018-3002", "CVE-2024-3001", "CVE-2025-1002", "CVE-2026-1001", "CVE-2026-2001"]);
  assert.equal(nvd.asked.filter((c) => c === "CVE-2024-3001").length, 2, "a failed NVD read is retried once");
  assert.deepEqual(s.nvd_errors, {});
  assert.ok(Object.values(s.nvd).every((r) => r.as_of === "2026-10-27" && r.state === "ok"));
  assert.deepEqual(Object.keys(s.nvd_products), ["cpe:apache:tomcat", "cpe:fortinet:fortios"], "product lookups for internet-facing families; Windows has none");
  // sources, dates and provenance
  assert.equal(s.schema, SNAPSHOT_SCHEMA);
  assert.equal(s.captured_at, "2026-10-27T01:00:00.000Z");
  for (const k of ["inventory", "kev", "epss", "nvd", "nvd_products"] as const) assert.match(s.sources[k].captured_at, /^2026-10-27T/);
  assert.equal(s.sources.kev.scope, "full_catalogue");
  assert.equal(s.sources.kev.catalog_version, "2026.10.23");
  assert.deepEqual(s.sources.epss.score_dates, ["2026-10-26"]);
  assert.deepEqual(s.inventory.map((r) => r.row_id), ["R1", "R2", "R3"]);
  assert.equal(s.inventory[0].internet_facing, true);
  assert.deepEqual(s.capture.queries.map((q) => q.label), ["inventory", "kevPairs", "kevEntries(all)", "epss(100)", "epss(59)"]);
  assert.ok(s.capture.queries.every((q) => /^[0-9a-f]{64}$/.test(q.sql_hash)));
  // input data only, and it round-trips through the file format
  assert.deepEqual(Object.keys(s).sort(), ["capture", "captured_at", "description", "epss", "epss_requested", "finished_at", "inventory", "kev_entries", "kev_pairs", "nvd", "nvd_errors", "nvd_products", "schema", "sources"]);
  mkdirSync(TMP, { recursive: true });
  try {
    const file = join(TMP, "snap.json");
    writeSnapshot(file, s, []);
    assert.deepEqual(parseSnapshot(readFileSync(file, "utf8")).kev_entries, s.kev_entries);
    assert.deepEqual(readdirSync(TMP), ["snap.json"], "no temp file left behind");
  } finally {
    rmSync(TMP, { recursive: true, force: true });
  }
});

test("the vendor-slice scope reads only the vendors the inventory's candidates name", async () => {
  const z = new FakeZetaris();
  const orig = z.query.bind(z);
  z.query = async (sql: string, opts?: QueryOptions) => {
    const m = sql.match(/WHERE lower\(trim\(vendor\)\) IN \((.*)\)$/);
    if (!m) return orig(sql, opts);
    const want = new Set([...m[1].matchAll(/'([^']*)'/g)].map((x) => x[1]));
    z.queries.push({ sql, opts });
    const rows = kevRows.filter((e) => want.has(e.vendor.trim().toLowerCase()));
    return { rows, ms: 1, fromCache: false, total: rows.length };
  };
  const { snapshot: s, inventoryVendors } = await captureSnapshot({ client: z, nvd: fakeNvd(), now: clock, kevScope: "vendors", products: 0 });
  assert.ok(inventoryVendors.includes("Apache") && inventoryVendors.includes("Fortinet") && inventoryVendors.includes("Microsoft"));
  assert.equal(s?.sources.kev.scope, "inventory_vendors");
  assert.ok(s!.kev_entries.every((e) => inventoryVendors.includes(e.vendor)));
});

test("an incomplete or cached answer stops the capture: nothing half-read is ever written", async () => {
  const z1 = new FakeZetaris();
  z1.truncate = "FROM el.kev";
  await assert.rejects(captureSnapshot({ client: z1, nvd: fakeNvd(), now: clock }), /truncated/);
  const z2 = new FakeZetaris();
  z2.fromCache = "el.inventory";
  await assert.rejects(captureSnapshot({ client: z2, nvd: fakeNvd(), now: clock }), /answered from a cache, not live/);
});

test("--plan stops after the KEV read; the NVD budget and cap leave the rest labelled 'not captured'", async () => {
  const z = new FakeZetaris();
  const nvd = fakeNvd();
  const p = await captureSnapshot({ client: z, nvd, now: clock, planOnly: true });
  assert.equal(p.snapshot, null);
  assert.equal(z.ddls.length, 0);
  assert.equal(nvd.asked.length, 0);
  const capped = await captureSnapshot({ client: new FakeZetaris(), nvd: fakeNvd(), now: clock, nvdMax: 2, products: 0 });
  assert.equal(Object.keys(capped.snapshot!.nvd).length, 2);
  assert.equal(Object.keys(capped.snapshot!.nvd_errors).length, 3);
  assert.ok(Object.values(capped.snapshot!.nvd_errors).every((v) => /budget was spent/.test(v)));
  assert.equal(capped.snapshot!.sources.nvd.states.not_captured, 3);
});

test("nvdPlan follows the pipeline's rule even for a row without a version", () => {
  const rows = [{ row_id: "X", asset_id: "a", asset_name: "a", asset_type: "server", internet_facing: false, owner_team: "", software: "Apache Tomcat" }];
  const plan = nvdPlan(rows, pairRows, kevRows as unknown as KevEntry[]);
  assert.deepEqual(plan.map((f) => f.cves), [["CVE-2026-1001", "CVE-2025-1002"]]);
});

test("writeSnapshot refuses a snapshot that contains a configured secret value, and writes nothing", async () => {
  const { snapshot: s } = await captureSnapshot({ client: new FakeZetaris(), nvd: fakeNvd(), now: clock, products: 0 });
  s!.inventory[0].software = "contains SECRETVALUE123 by mistake";
  mkdirSync(TMP, { recursive: true });
  try {
    const file = join(TMP, "x.json");
    assert.throws(() => writeSnapshot(file, s!, ["SECRETVALUE123"]), /refused: a configured secret value appears/);
    assert.equal(existsSync(file), false);
  } finally {
    rmSync(TMP, { recursive: true, force: true });
  }
});

test("parseSnapshotArgs: defaults and checked flags", () => {
  const d = parseSnapshotArgs([]);
  assert.equal(d.out, DEFAULT_SNAPSHOT_FILE);
  assert.equal(d.kevScope, "all");
  assert.equal(d.products, 3);
  const a = parseSnapshotArgs(["--kev-scope", "vendors", "--nvd-budget-s=60", "--nvd-max", "5", "--products", "0", "--plan"]);
  assert.deepEqual([a.kevScope, a.nvdBudgetS, a.nvdMax, a.products, a.plan], ["vendors", 60, 5, 0, true]);
  assert.throws(() => parseSnapshotArgs(["--kev-scope", "some"]), /all or vendors/);
  assert.throws(() => parseSnapshotArgs(["--nvd-max", "-1"]), /--nvd-max/);
  assert.throws(() => parseSnapshotArgs(["--bogus"]), /unknown argument/);
});

test("the shipped snapshot is valid, dated, input data only, and consistent with itself", () => {
  const s = loadSnapshot();
  assert.equal(s.schema, SNAPSHOT_SCHEMA);
  for (const k of ["inventory", "kev", "epss", "nvd", "nvd_products"] as const) assert.match(s.sources[k].captured_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.deepEqual(Object.keys(s).sort(), ["capture", "captured_at", "description", "epss", "epss_requested", "finished_at", "inventory", "kev_entries", "kev_pairs", "nvd", "nvd_errors", "nvd_products", "schema", "sources"]);
  const raw = readFileSync(DEFAULT_SNAPSHOT_FILE, "utf8");
  for (const k of ["decision", "receipt_id", "verdict", "why", "routed_model"]) assert.ok(!raw.includes(`"${k}":`), `no output field ${k} in the snapshot`);
  assert.equal(s.inventory.length, s.sources.inventory.rows);
  assert.equal(new Set(s.inventory.map((r) => r.row_id)).size, s.inventory.length);
  assert.equal(s.kev_entries.length, s.sources.kev.entries);
  assert.equal(s.kev_pairs.length, s.sources.kev.pairs);
  const kevCves = new Set(s.kev_entries.map((e) => e.cve_id.trim().toUpperCase()));
  assert.ok([...kevCves].every((c) => s.epss_requested.includes(c)), "EPSS was asked for every KEV CVE");
  assert.ok(s.epss.every((x) => kevCves.has(x.cve_id) && Number.isFinite(x.epss) && /^\d{4}-\d{2}-\d{2}$/.test(x.score_date)));
  for (const [cve, r] of Object.entries(s.nvd)) {
    assert.ok(kevCves.has(cve), `${cve} is a KEV CVE`);
    assert.match(r.as_of, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(r.ranges.every((x) => x.cve_id === cve));
  }
  assert.ok(Object.keys(s.nvd).length > 0);
});
