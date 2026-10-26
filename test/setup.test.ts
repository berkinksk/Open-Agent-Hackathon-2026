import { test } from "node:test";
import assert from "node:assert/strict";
import type { DdlResult, QueryOptions, QueryResult } from "../src/adapters/zetaris.ts";
import { guardSql } from "../src/adapters/zetaris.ts";
import { KEV_URL } from "../src/adapters/queries.ts";
import { formatTable, parseSetupArgs, planSetup, preflightInventory, runSetup } from "../scripts/setup.ts";

const INV_URL = "https://example.invalid/data/inventory.json";
const GOOD_INV = { items: [{ row_id: "R01", asset_id: "A1", asset_name: "n", asset_type: "server", internet_facing: true, owner_team: "IT", software: "x 1.0" }] };

function jsonFetch(status: number, body: unknown): typeof fetch {
  return (async () => new Response(JSON.stringify(body), { status })) as typeof fetch;
}

/** A fake Zetaris that keeps a catalogue of objects, answers SHOW, and says "already exists" like the real one. */
function fakeZetaris(initial: { dbs?: string[]; tables?: Record<string, Record<string, string>>; containers?: string[]; views?: string[] } = {}, failOn?: RegExp) {
  const dbs = new Set(initial.dbs ?? []);
  const tables: Record<string, Record<string, string>> = structuredClone(initial.tables ?? {});
  const containers = new Set(initial.containers ?? []);
  const views = new Set(initial.views ?? []);
  const log: { kind: string; sql: string; opts?: QueryOptions }[] = [];
  return {
    log, dbs, tables,
    async query(sql: string, opts?: QueryOptions): Promise<QueryResult> {
      guardSql(sql);
      log.push({ kind: "query", sql, opts });
      if (sql === "SHOW LIGHTNING DATABASES") return { rows: [...dbs].map((name) => ({ name, description: "", id: "1" })), ms: 1, fromCache: false };
      let m = sql.match(/^SHOW LIGHTNING TABLES (\w+)$/);
      if (m) return { rows: Object.entries(tables[m[1]] ?? {}).map(([name, source_table]) => ({ name, source_table, materialized_table: "", table_type: "REST", format: "json", id: "1" })), ms: 1, fromCache: false };
      if (/FROM el(_t1)?\.kev LIMIT 1/.test(sql)) return { rows: [{ cve_id: "CVE-2026-114625", vendor: "Arista", product: "VeloCloud Orchestrator", date_added: "2026-10-23", due_date: "2026-10-26", catalog_version: "2026.10.23" }], ms: 3, fromCache: false };
      if (/FROM el(_t1)?\.inventory LIMIT 1/.test(sql)) return { rows: [{ row_id: "R01", software: "x 1.0" }], ms: 3, fromCache: false };
      if (/explode\(data\)/.test(sql)) return { rows: [{ cve_id: "CVE-2021-44228", epss: "0.99999", percentile: "1.0", score_date: "2026-10-26" }], ms: 2, fromCache: false };
      return { rows: [], ms: 1, fromCache: false };
    },
    async ddl(sql: string): Promise<DdlResult> {
      guardSql(sql);
      log.push({ kind: "ddl", sql });
      if (failOn && failOn.test(sql)) throw new Error("HTTP 500: connector failed");
      let m: RegExpMatchArray | null;
      if ((m = sql.match(/^CREATE LIGHTNING DATABASE (\w+)/))) { if (dbs.has(m[1])) return { outcome: "exists", ms: 1 }; dbs.add(m[1]); }
      else if ((m = sql.match(/^CREATE LIGHTNING REST TABLE (\w+) FROM (\w+) REQUEST\(endpoint "([^"]+)"/))) {
        tables[m[2]] ??= {};
        if (tables[m[2]][m[1]]) return { outcome: "exists", ms: 1 };
        tables[m[2]][m[1]] = m[3];
      } else if ((m = sql.match(/^CREATE SCHEMASTORE CONTAINER (\w+)/))) { if (containers.has(m[1])) return { outcome: "exists", ms: 1 }; containers.add(m[1]); }
      else if ((m = sql.match(/^CREATE SCHEMASTORE VIEW (\w+) WITH CONTAINER (\w+)/))) { const k = `${m[2]}.${m[1]}`; if (views.has(k)) return { outcome: "exists", ms: 1 }; views.add(k); }
      return { outcome: "created", ms: 2 };
    },
  };
}

test("planSetup: proven patterns, EL_/el_ names only, never a DROP, every statement passes the client guards", () => {
  const steps = planSetup("EL_", INV_URL);
  const sql = steps.map((s) => s.sql).join("\n");
  assert.ok(!/\bdrop\b/i.test(sql));
  for (const s of steps) { assert.doesNotThrow(() => guardSql(s.sql), s.sql); if (s.check) assert.doesNotThrow(() => guardSql(s.check!)); }
  assert.deepEqual(steps.map((s) => s.object), [
    "EL_INVENTORY", "EL_INVENTORY.el_inventory_raw", "EL_KEV", "EL_KEV.el_kev_raw", "EL_EPSS", "EL_NVD", "el", "el.kev", "el.inventory",
  ]);
  assert.ok(sql.includes(`CREATE LIGHTNING REST TABLE el_kev_raw FROM EL_KEV REQUEST(endpoint "${KEV_URL}", method "get", response_type "json", http_encoding "URLENCODED") HEADER () BODY ()`));
  assert.ok(sql.includes(`endpoint "${INV_URL}"`));
  const kevView = steps.find((s) => s.object === "el.kev")!.sql;
  for (const f of ["v.cveID AS cve_id", "v.vendorProject AS vendor", "v.product AS product", "v.vulnerabilityName AS vulnerability_name", "v.dateAdded AS date_added",
    "v.dueDate AS due_date", "v.knownRansomwareCampaignUse AS ransomware_use", "v.requiredAction AS required_action", "v.shortDescription AS short_description",
    "v.notes AS notes", "catalogVersion AS catalog_version", "FROM el_kev.el_kev_raw LATERAL VIEW explode(vulnerabilities) AS v"]) assert.ok(kevView.includes(f), f);
  assert.ok(steps.find((s) => s.object === "el.inventory")!.sql.includes("FROM el_inventory.el_inventory_raw LATERAL VIEW explode(items) AS i"));
  for (const s of steps) if (s.kind === "database") assert.match(s.sql, /DESCRIBE BY "[A-Za-z0-9 _.,-]+"$/, "DESCRIBE BY charset");
});

test("planSetup --prefix EL_T1_ replaces EL_/el_ everywhere", () => {
  const steps = planSetup("EL_T1_", INV_URL);
  assert.deepEqual(steps.map((s) => s.object), [
    "EL_T1_INVENTORY", "EL_T1_INVENTORY.el_t1_inventory_raw", "EL_T1_KEV", "EL_T1_KEV.el_t1_kev_raw", "EL_T1_EPSS", "EL_T1_NVD", "el_t1", "el_t1.kev", "el_t1.inventory",
  ]);
  const sql = steps.map((s) => s.sql).join("\n");
  assert.ok(!/\bEL_(INVENTORY|KEV|EPSS|NVD)\b/.test(sql));
  assert.ok(sql.includes("FROM el_t1_kev.el_t1_kev_raw"));
  assert.throws(() => planSetup("FZ_", INV_URL));
});

test("runSetup from an empty Zetaris creates everything, then LIMIT 1 per object and an EPSS smoke batch", async () => {
  const z = fakeZetaris();
  const { rows, ok } = await runSetup(z, { prefix: "EL_", inventoryUrl: INV_URL, fetchImpl: jsonFetch(200, GOOD_INV) });
  assert.equal(ok, true, formatTable(rows));
  assert.ok(rows.filter((r) => r.kind !== "check").every((r) => r.state === "created"));
  assert.match(rows.find((r) => r.object === "el.kev")!.check, /^LIMIT 1 -> CVE-2026-114625/);
  assert.match(rows.find((r) => r.object === "el.inventory")!.check, /^LIMIT 1 -> R01/);
  const smoke = rows.find((r) => r.kind === "check")!;
  assert.equal(smoke.state, "ok");
  assert.match(smoke.check, /CVE-2021-44228 epss=0.99999/);
  const checks = z.log.filter((l) => l.kind === "query" && / LIMIT 1$/.test(l.sql));
  assert.equal(checks.length, 2);
  assert.ok(checks.every((c) => c.opts?.cache === "bypass" && c.opts?.limit === 1));
});

test("runSetup is idempotent: a second run creates nothing new and still passes", async () => {
  const z = fakeZetaris();
  await runSetup(z, { prefix: "EL_", inventoryUrl: INV_URL, fetchImpl: jsonFetch(200, GOOD_INV) });
  const dbCount = z.dbs.size;
  z.log.length = 0;
  const { rows, ok } = await runSetup(z, { prefix: "EL_", inventoryUrl: INV_URL, fetchImpl: jsonFetch(200, GOOD_INV) });
  assert.equal(ok, true);
  assert.equal(z.dbs.size, dbCount);
  assert.ok(rows.filter((r) => r.kind !== "check").every((r) => r.state === "exists"), formatTable(rows));
  // databases and tables are recognised by SHOW, so no CREATE is even sent for them
  assert.equal(z.log.filter((l) => l.kind === "ddl" && /^CREATE LIGHTNING (DATABASE|REST TABLE el_(kev|inventory)_raw)/.test(l.sql)).length, 0);
});

test("an unpublished inventory file is skipped (with its view) and setup reports incomplete; KEV still works", async () => {
  const z = fakeZetaris();
  const { rows, ok } = await runSetup(z, { prefix: "EL_", inventoryUrl: INV_URL, fetchImpl: jsonFetch(404, { error: "nope" }) });
  assert.equal(ok, false);
  const raw = rows.find((r) => r.object === "EL_INVENTORY.el_inventory_raw")!;
  assert.equal(raw.state, "skipped");
  assert.match(raw.note, /HTTP 404/);
  assert.equal(rows.find((r) => r.object === "el.inventory")!.state, "skipped");
  assert.equal(rows.find((r) => r.object === "el.kev")!.state, "created");
  assert.ok(!z.log.some((l) => /el_inventory_raw FROM/.test(l.sql)), "no REST table over a missing file");
});

test("preflight rejects an inventory without the InventoryRow fields", async () => {
  const r = await preflightInventory(INV_URL, jsonFetch(200, { items: [{ row_id: "R00", software: "test 1.0" }] }));
  assert.equal(r.ok, false);
  assert.match(r.reason, /asset_id/);
  assert.equal((await preflightInventory(INV_URL, jsonFetch(200, GOOD_INV))).ok, true);
  assert.equal((await preflightInventory(INV_URL, (async () => { throw new TypeError("fetch failed"); }) as typeof fetch)).ok, false);
});

test("an existing table whose endpoint differs is reported, never dropped or recreated", async () => {
  const z = fakeZetaris({ dbs: ["EL_KEV"], tables: { EL_KEV: { el_kev_raw: "https://old.example/kev.json" } } });
  const { rows } = await runSetup(z, { prefix: "EL_", inventoryUrl: INV_URL, fetchImpl: jsonFetch(200, GOOD_INV) });
  const r = rows.find((x) => x.object === "EL_KEV.el_kev_raw")!;
  assert.equal(r.state, "exists");
  assert.match(r.note, /endpoint differs/);
  assert.ok(!z.log.some((l) => /el_kev_raw FROM/.test(l.sql)));
});

test("a failing CREATE is an error row, and objects that need it are skipped", async () => {
  const z = fakeZetaris({}, /el_kev_raw FROM/);
  const { rows, ok } = await runSetup(z, { prefix: "EL_", inventoryUrl: INV_URL, fetchImpl: jsonFetch(200, GOOD_INV) });
  assert.equal(ok, false);
  assert.equal(rows.find((r) => r.object === "EL_KEV.el_kev_raw")!.state, "error");
  assert.equal(rows.find((r) => r.object === "el.kev")!.state, "skipped");
  assert.equal(rows.find((r) => r.object === "el.inventory")!.state, "created");
});

test("parseSetupArgs and formatTable", () => {
  assert.deepEqual(parseSetupArgs(["--prefix", "EL_T1_", "--dry-run"]), { prefix: "EL_T1_", dryRun: true, preflight: true, help: false });
  assert.equal(parseSetupArgs(["--prefix=EL_T2_", "--no-preflight"]).prefix, "EL_T2_");
  assert.throws(() => parseSetupArgs(["--drop"]));
  const t = formatTable([{ object: "el.kev", kind: "view", state: "exists", note: "", check: "LIMIT 1 -> x", ms: 1 }]);
  assert.match(t, /^object\s+kind\s+state\s+check \/ note/);
  assert.match(t, /el\.kev\s+view\s+exists\s+LIMIT 1 -> x/);
});
