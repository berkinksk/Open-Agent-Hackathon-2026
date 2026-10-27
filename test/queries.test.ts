import { test } from "node:test";
import assert from "node:assert/strict";
import type { QueryOptions, QueryResult, DdlResult } from "../src/adapters/zetaris.ts";
import type { SqlClient } from "../src/adapters/queries.ts";
import {
  EPSS_BATCH_MAX, cleanCveIds, createZetarisQueries, elNames, epssTableName, naiveJoinSql, toEpssScore,
} from "../src/adapters/queries.ts";
import { guardSql, SerialQueue, ZetarisClient } from "../src/adapters/zetaris.ts";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { memoryTracer } from "../src/trace.ts";

interface Call { kind: "query" | "ddl"; sql: string; opts: any; }

/** A fake client: records calls; `answer` decides the rows for each query. */
function fakeClient(answer: (sql: string) => Record<string, string>[] = () => [], ddlAnswer: (sql: string) => DdlResult | Error = () => ({ outcome: "created", ms: 1 })) {
  const calls: Call[] = [];
  const c: SqlClient & { calls: Call[] } = {
    calls,
    async query(sql: string, opts?: QueryOptions): Promise<QueryResult> {
      guardSql(sql); // the real client refuses these; prove our SQL passes its guards
      calls.push({ kind: "query", sql, opts });
      return { rows: answer(sql), ms: 1, fromCache: false };
    },
    async ddl(sql: string, opts?: { label?: string }): Promise<DdlResult> {
      guardSql(sql);
      calls.push({ kind: "ddl", sql, opts });
      const r = ddlAnswer(sql);
      if (r instanceof Error) throw r;
      return r;
    },
  };
  return c;
}

const cves = (n: number, start = 1) => Array.from({ length: n }, (_, i) => `CVE-2024-${String(start + i).padStart(5, "0")}`);

test("names follow the prefix: EL_ -> EL_* databases, el_* tables, container el", () => {
  const a = elNames("EL_");
  assert.equal(a.invDb, "EL_INVENTORY");
  assert.equal(a.kevRaw, "el_kev_raw");
  assert.equal(a.container, "el");
  assert.equal(a.kevRef, "el.kev");
  const b = elNames("EL_T1_");
  assert.equal(b.epssDb, "EL_T1_EPSS");
  assert.equal(b.invRaw, "el_t1_inventory_raw");
  assert.equal(b.container, "el_t1");
  assert.equal(b.inventoryRef, "el_t1.inventory");
  assert.throws(() => elNames("FZ_"));
  assert.throws(() => elNames("el_"));
});

test("inventory(): reads el.inventory, parses internet_facing to a boolean, cache=use", async () => {
  const c = fakeClient(() => [
    { row_id: "R01", asset_id: "A1", asset_name: "mail-01", asset_type: "server", internet_facing: "true", owner_team: "IT", software: "MS Exchange Svr 2019 CU12" },
    { row_id: "R02", asset_id: "A2", asset_name: "lap-7", asset_type: "laptop", internet_facing: "false", owner_team: "", software: "FortiClient VPN 7.0.9" },
    { row_id: "", asset_id: "", asset_name: "", asset_type: "", internet_facing: "", owner_team: "", software: "  " },
  ]);
  const q = createZetarisQueries({ client: c, tracer: memoryTracer(), prefix: "EL_" });
  const rows = await q.inventory();
  assert.equal(rows.length, 2, "an entirely empty row is dropped");
  assert.equal(rows[0].internet_facing, true);
  assert.equal(rows[1].internet_facing, false);
  assert.equal(rows[0].software, "MS Exchange Svr 2019 CU12");
  assert.match(c.calls[0].sql, /FROM el\.inventory$/);
  assert.equal(c.calls[0].opts.cache, "use");
  assert.ok(c.calls[0].opts.limit >= 1000, "explicit limit");
});

test("kevPairs(): DISTINCT vendor, product from the KEV view; raw spellings kept", async () => {
  const c = fakeClient(() => [{ vendor: "Microsoft", product: "Windows" }, { vendor: "Microsoft", product: "Windows " }]);
  const q = createZetarisQueries({ client: c, tracer: memoryTracer(), prefix: "EL_T1_" });
  const pairs = await q.kevPairs();
  assert.deepEqual(pairs, [{ vendor: "Microsoft", product: "Windows" }, { vendor: "Microsoft", product: "Windows " }]);
  assert.match(c.calls[0].sql, /^SELECT DISTINCT vendor, product FROM el_t1\.kev/);
  assert.equal(c.calls[0].opts.cache, "use");
});

test("kevByProducts(): escaped, trimmed, case-insensitive match; de-duplicated; chunked; empty -> no query", async () => {
  const c = fakeClient(() => [{ cve_id: "CVE-2021-44228", vendor: "Apache", product: "Log4j2", catalog_version: "2026.10.23" }]);
  const q = createZetarisQueries({ client: c, tracer: memoryTracer(), prefix: "EL_" });
  assert.deepEqual(await q.kevByProducts([]), []);
  assert.equal(c.calls.length, 0);

  const out = await q.kevByProducts([{ vendor: "O'Reilly", product: "Back\\slash" }, { vendor: " Apache ", product: "Log4j2" }, { vendor: "apache", product: "LOG4J2" }]);
  assert.equal(c.calls.length, 1);
  const sql = c.calls[0].sql;
  assert.ok(sql.includes("lower(trim(vendor)) = 'o\\'reilly'"), sql);
  assert.ok(sql.includes("lower(trim(product)) = 'back\\\\slash'"), sql);
  assert.equal((sql.match(/'apache'/g) ?? []).length, 1, "duplicates collapse");
  assert.match(sql, /^SELECT cve_id, vendor, product, vulnerability_name, date_added, due_date, ransomware_use, required_action, short_description, notes, catalog_version FROM el\.kev WHERE /);
  // every KevEntry field is present (missing ones as "")
  assert.equal(out[0].cve_id, "CVE-2021-44228");
  assert.equal(out[0].notes, "");

  c.calls.length = 0;
  const many = Array.from({ length: 250 }, (_, i) => ({ vendor: `V${i}`, product: `P${i}` }));
  await q.kevByProducts(many);
  assert.equal(c.calls.length, 3, "chunks of 100 pairs");
});

test("kevVerify(): live only (cache=bypass), ids cleaned, invalid ids reported and skipped", async () => {
  const c = fakeClient(() => [{ cve_id: "CVE-2025-61624", vendor: "Fortinet", product: "Multiple Products" }]);
  const tracer = memoryTracer();
  const q = createZetarisQueries({ client: c, tracer, prefix: "EL_" });
  const out = await q.kevVerify([" cve-2025-61624 ", "CVE-2025-61624", "not-a-cve", "CVE-2021-44228"]);
  assert.equal(out.length, 1);
  assert.equal(c.calls.length, 1);
  assert.equal(c.calls[0].opts.cache, "bypass");
  assert.ok(c.calls[0].sql.endsWith("WHERE cve_id IN ('CVE-2021-44228', 'CVE-2025-61624')"), c.calls[0].sql);
  const ev = tracer.events.find((e) => e.action === "invalid_cve_ids");
  assert.ok(ev);
  assert.deepEqual((ev!.details as any).invalid, ["not-a-cve"]);
});

test("epss(): batches of <=100, one REST table per sorted batch, LATERAL VIEW explode(data), numbers parsed in code", async () => {
  const c = fakeClient((sql) => {
    const t = sql.match(/FROM el_epss\.(el_epss_[0-9a-f]{8})/)![1];
    return [
      { cve_id: "CVE-2024-00001", epss: "0.11388", percentile: "0.95963", score_date: "2026-10-26", _t: t },
      { cve_id: "CVE-2024-00002", epss: "", percentile: "", score_date: "2026-10-26" }, // no score: skipped, never 0
    ];
  });
  const q = createZetarisQueries({ client: c, tracer: memoryTracer(), prefix: "EL_" });
  const ids = cves(250).reverse();
  const out = await q.epss(ids);
  const ddl = c.calls.filter((x) => x.kind === "ddl");
  const sel = c.calls.filter((x) => x.kind === "query");
  assert.equal(ddl.length, 3);
  assert.equal(sel.length, 3);
  const sorted = cves(250);
  const first = sorted.slice(0, EPSS_BATCH_MAX);
  assert.equal(ddl[0].sql,
    `CREATE LIGHTNING REST TABLE ${epssTableName(first)} FROM EL_EPSS REQUEST(endpoint "https://api.first.org/data/v1/epss?cve=${first.join(",")}", method "get", response_type "json", http_encoding "URLENCODED") HEADER () BODY ()`);
  assert.match(epssTableName(first), /^el_epss_[0-9a-f]{8}$/);
  assert.match(sel[0].sql, /^SELECT d\.cve AS cve_id, d\.epss AS epss, d\.percentile AS percentile, d\.`date` AS score_date FROM el_epss\.el_epss_[0-9a-f]{8} LATERAL VIEW explode\(data\) AS d$/);
  assert.equal(sel[0].opts.cache, "use");
  assert.equal(out.length, 3, "one parsed row per batch; empty scores skipped");
  assert.equal(out[0].epss, 0.11388);
  assert.equal(typeof out[0].percentile, "number");

  c.calls.length = 0;
  await q.epss(ids);
  assert.equal(c.calls.filter((x) => x.kind === "ddl").length, 0, "tables already registered by this instance");
});

test("epss(): an 'already exists' table is reused; a failed registration fails closed (throws)", async () => {
  const ok = fakeClient(() => [{ cve_id: "CVE-2021-44228", epss: "0.99999", percentile: "1.0", score_date: "2026-10-26" }], () => ({ outcome: "exists", ms: 1 }));
  const q1 = createZetarisQueries({ client: ok, tracer: memoryTracer(), prefix: "EL_" });
  assert.equal((await q1.epss(["CVE-2021-44228"])).length, 1);

  const bad = fakeClient(() => [], () => new Error("HTTP 500: connector failed"));
  const q2 = createZetarisQueries({ client: bad, tracer: memoryTracer(), prefix: "EL_" });
  await assert.rejects(q2.epss(["CVE-2021-44228"]), /connector failed/);
});

test("epssVerify(): the same tables as epss(), cache bypassed, filtered to the asked ids; unknown ids get a new table", async () => {
  const c = fakeClient(() => [{ cve_id: "CVE-2024-00003", epss: "0.2", percentile: "0.9", score_date: "2026-10-26" }]);
  const q = createZetarisQueries({ client: c, tracer: memoryTracer(), prefix: "EL_" });
  await q.epss(cves(5));
  const table = epssTableName(cves(5));
  c.calls.length = 0;
  const v = await q.epssVerify(["CVE-2024-00003"]);
  assert.equal(v.length, 1);
  assert.equal(c.calls.length, 1, "no new registration");
  assert.equal(c.calls[0].opts.cache, "bypass");
  assert.ok(c.calls[0].sql.includes(`FROM el_epss.${table} `));
  assert.ok(c.calls[0].sql.endsWith("WHERE d.cve IN ('CVE-2024-00003')"));

  c.calls.length = 0;
  await q.epssVerify(["CVE-2023-99999"]);
  assert.equal(c.calls[0].kind, "ddl");
  assert.equal(c.calls[1].opts.cache, "bypass");
});

test("nvdCves / nvdProduct are dormant until A3", async () => {
  const q = createZetarisQueries({ client: fakeClient(), tracer: memoryTracer(), prefix: "EL_" });
  await assert.rejects(q.nvdCves(["CVE-2021-44228"]), /^Error: dormant/);
  await assert.rejects(q.nvdProduct("apache", "log4j"), /dormant/);
});

test("helpers: cleanCveIds and toEpssScore", () => {
  assert.deepEqual(cleanCveIds(["cve-2021-44228", "CVE-2021-44228", "CVE-21-1", "x"]), { valid: ["CVE-2021-44228"], invalid: ["CVE-21-1", "x"] });
  assert.equal(toEpssScore({ cve_id: "CVE-2021-44228", epss: "abc", percentile: "1", score_date: "" }), null);
  assert.deepEqual(toEpssScore({ cve_id: "cve-2021-44228", epss: "0.5", percentile: "0.7", score_date: "2026-10-26" }), { cve_id: "CVE-2021-44228", epss: 0.5, percentile: 0.7, score_date: "2026-10-26" });
});

test("sourceStatus: a live read, then the client's cached copy after a failure (fromCache + cachedAt), with a real client", async () => {
  let calls = 0;
  const fakeFetch = (async () => {
    calls++;
    if (calls === 1) return new Response(JSON.stringify({ headers: ["vendor", "product"], data: [["Apache", "Log4j2"]], total: 1, timeUsed: 3 }), { status: 200 });
    throw new TypeError("fetch failed");
  }) as typeof fetch;
  const dir = mkdtempSync(join(tmpdir(), "el-queries-cache-"));
  try {
    const client = new ZetarisClient({ restUrl: "http://zetaris.invalid/api/v1.0", orgId: "1", apiKey: "test-key-abcdef123456", fetchImpl: fakeFetch, retryDelayMs: 1, cacheDir: dir, queue: new SerialQueue() });
    const q = createZetarisQueries({ client, tracer: memoryTracer(), prefix: "EL_" });
    assert.deepEqual(await q.kevPairs(), [{ vendor: "Apache", product: "Log4j2" }]);
    assert.deepEqual(await q.kevPairs(), [{ vendor: "Apache", product: "Log4j2" }]); // the live read failed: served from the cache
    const st = q.sourceStatus();
    assert.equal(st.length, 2);
    assert.deepEqual(st.map((x) => [x.query, x.fromCache]), [["kevPairs", false], ["kevPairs", true]]);
    assert.equal(st[0].cachedAt, undefined);
    assert.match(st[1].cachedAt ?? "", /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(st[1].rows, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("sourceStatus lists only cache-backed reads: the verifier's bypass reads are never listed", async () => {
  const c = fakeClient((sql) => (sql.includes("epss") ? [{ cve_id: "CVE-2024-00001", epss: "0.1", percentile: "0.5", score_date: "2026-10-26" }] : []));
  const q = createZetarisQueries({ client: c, tracer: memoryTracer(), prefix: "EL_" });
  await q.epss(["CVE-2024-00001"]);
  await q.epssVerify(["CVE-2024-00001"]);
  await q.kevVerify(["CVE-2024-00001"]);
  await q.inventory();
  assert.deepEqual(q.sourceStatus().map((x) => [x.query, x.fromCache]), [["epss", false], ["inventory", false]]);
});

test("naiveJoinSql: inventory rows by id, or the request's rows as inline VALUES (quotes escaped); both pass the guards", () => {
  const inv = naiveJoinSql({ from: "inventory", rowIds: ["R05", "R12", "R05"] });
  assert.equal(inv, "SELECT i.row_id, k.vendor, k.product, count(DISTINCT k.cve_id) AS kev_cves FROM el.inventory i JOIN el.kev k ON instr(lower(i.software), lower(trim(k.product))) > 0 WHERE i.row_id IN ('R05', 'R12') GROUP BY i.row_id, k.vendor, k.product ORDER BY i.row_id, k.vendor, k.product");
  const vals = naiveJoinSql({ from: "values", rows: [{ row_id: "Q1", software: "Bob's  WordPress 6.4" }] }, "EL_T1_");
  assert.match(vals, /FROM \(VALUES \('Q1', 'Bob\\'s WordPress 6\.4'\)\) AS i\(row_id, software\) JOIN el_t1\.kev k ON/);
  guardSql(inv);
  guardSql(vals);
});

test("discover and naiveJoin: SHOW statements and the join, live (cache bypassed), parsed", async () => {
  const c = fakeClient((sql) => {
    if (sql === "SHOW LIGHTNING DATABASES") return [{ name: "EL_KEV" }, { name: "EL_INVENTORY" }, { name: "EL_T1_KEV" }, { name: "FZ_OTHER" }];
    if (sql.startsWith("SHOW LIGHTNING TABLES")) return [{ name: sql.endsWith("EL_KEV") ? "el_kev_raw" : "el_inventory_raw", source_table: "https://raw.githubusercontent.com/x/y.json" }];
    return [{ row_id: "R12", vendor: "TeamViewer", product: "Desktop", kev_cves: "1" }, { row_id: "R20", vendor: "Microsoft", product: "Word", kev_cves: "4" }];
  });
  const q = createZetarisQueries({ client: c, tracer: memoryTracer(), prefix: "EL_" });
  const d = await q.discover();
  assert.deepEqual(d.databases, ["EL_INVENTORY", "EL_KEV"]);
  assert.deepEqual(d.tables.map((t) => `${t.db}.${t.name}`), ["EL_INVENTORY.el_inventory_raw", "EL_KEV.el_kev_raw"]);
  assert.deepEqual(d.sql, ["SHOW LIGHTNING DATABASES", "SHOW LIGHTNING TABLES EL_INVENTORY", "SHOW LIGHTNING TABLES EL_KEV"]);
  const j = await q.naiveJoin({ from: "inventory", rowIds: ["R12", "R20"] });
  assert.deepEqual(j.rows, [{ row_id: "R12", vendor: "TeamViewer", product: "Desktop", kev_cves: 1 }, { row_id: "R20", vendor: "Microsoft", product: "Word", kev_cves: 4 }]);
  assert.ok(c.calls.every((x) => x.opts.cache === "bypass"));
  assert.deepEqual(q.sourceStatus(), [], "display reads are not cache-backed reads");
});
