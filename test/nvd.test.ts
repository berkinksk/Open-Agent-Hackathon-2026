import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Clock, Tracer, TraceEvent } from "../src/contracts.ts";
import {
  createLimiter, createNvdQueries, nvdCveEndpoint, nvdCveTable, nvdProductEndpoint, nvdProductTable,
  parseNvdConfigurations, parseNvdVulnerabilities, rangesForCpe,
} from "../src/adapters/nvd.ts";
import type { NvdSqlClient } from "../src/adapters/nvd.ts";
import { isAffected, rangesForProduct } from "../src/resolve/versions.ts";

// A HAND-WRITTEN fixture in the NVD CVE API 2.0 shape (abbreviated; not a captured record).
// It mixes bounded ranges, exact-version CPEs, a second vendor, and an AND node whose platform is not vulnerable.
const FIXTURE = {
  resultsPerPage: 1, startIndex: 0, totalResults: 1, format: "NVD_CVE", version: "2.0", timestamp: "2026-10-26T12:00:00.000",
  vulnerabilities: [{
    cve: {
      id: "CVE-2021-44228", sourceIdentifier: "security@apache.org", published: "2021-12-10T10:15:09.143",
      lastModified: "2026-01-01T00:00:00.000", vulnStatus: "Analyzed",
      descriptions: [{ lang: "en", value: "hand-written test description" }],
      configurations: [
        { nodes: [{ operator: "OR", negate: false, cpeMatch: [
          { vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", versionStartIncluding: "2.13.0", versionEndExcluding: "2.15.0", matchCriteriaId: "A1" },
          { vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", versionStartIncluding: "2.4", versionEndExcluding: "2.12.2", matchCriteriaId: "A2" },
          { vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*", matchCriteriaId: "A3" },
          { vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:2.0:rc1:*:*:*:*:*:*", matchCriteriaId: "A4" },
        ] }] },
        { operator: "AND", nodes: [
          { operator: "OR", negate: false, cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:o:siemens:example_firmware:*:*:*:*:*:*:*:*", versionEndExcluding: "3.0", matchCriteriaId: "S1" }] },
          { operator: "OR", negate: false, cpeMatch: [{ vulnerable: false, criteria: "cpe:2.3:h:siemens:example_device:-:*:*:*:*:*:*:*", matchCriteriaId: "S2" }] },
        ] },
        { nodes: [{ operator: "OR", negate: true, cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:2.16.0:*:*:*:*:*:*:*", matchCriteriaId: "N1" }] }] },
      ],
      references: [{ url: "https://example.invalid/advisory" }],
    },
  }],
};
// Shape of a CVE NVD has not analysed yet (very common for new 2026 KEV entries): no configurations.
const AWAITING = { vulnerabilities: [{ cve: { id: "CVE-2026-99001", published: "2026-10-20T10:00:00.000", vulnStatus: "Awaiting Analysis" } }] };

const fixedClock = (iso: string): Clock => ({ now: () => new Date(iso) });

interface Call { sql: string; opts: Record<string, unknown> | undefined; }
type Responder = (sql: string) => Record<string, string>[] | Error;

function mockClient(respond: Responder): NvdSqlClient & { calls: Call[] } {
  const calls: Call[] = [];
  return {
    calls,
    async query(sql: string, opts?: Record<string, unknown>) {
      calls.push({ sql, opts });
      const r = respond(sql);
      if (r instanceof Error) throw r;
      return { rows: r, ms: 1, fromCache: false };
    },
  };
}

function defaultResponder(payloads: Record<string, unknown>): Responder {
  return (sql: string) => {
    if (/^CREATE LIGHTNING DATABASE/.test(sql)) return new Error('HTTP 400: A database named "EL_NVD" already exists.');
    if (/^SHOW LIGHTNING TABLES/.test(sql)) return [];
    if (/^CREATE LIGHTNING REST TABLE/.test(sql)) return [];
    const m = sql.match(/FROM el_nvd\.(\w+)/);
    if (m && m[1] in payloads) return [{ v: JSON.stringify((payloads[m[1]] as { vulnerabilities: unknown }).vulnerabilities) }];
    return new Error(`unexpected SQL in test: ${sql}`);
  };
}

function fakeTime(): { now: () => number; sleep: (ms: number) => Promise<void>; slept: number[] } {
  let t = 1_000_000;
  const slept: number[] = [];
  return { now: () => t, sleep: async (ms: number) => { slept.push(ms); t += ms; }, slept };
}

function recorder(): Tracer & { events: Omit<TraceEvent, "ts" | "run_id">[] } {
  const events: Omit<TraceEvent, "ts" | "run_id">[] = [];
  return { run_id: "t", file: "/dev/null", events, emit: (e) => { events.push(e); } };
}

test("names and endpoints follow the EL_/el_ rules", () => {
  assert.equal(nvdCveTable("cve-2021-44228"), "el_nvd_cve_2021_44228");
  assert.equal(nvdCveTable("CVE-2021-44228", "EL_T1_"), "el_t1_nvd_cve_2021_44228");
  assert.equal(nvdCveEndpoint("cve-2021-44228"), "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228");
  assert.throws(() => nvdCveTable("CVE-2021-44228; DROP"), /invalid CVE id/);
  const ep = nvdProductEndpoint("Apache", "log4j", new Date("2026-10-26T15:00:00Z"));
  assert.equal(ep, "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:*:apache:log4j&pubStartDate=2026-06-29T00:00:00.000&pubEndDate=2026-10-26T23:59:59.999&resultsPerPage=50");
  assert.match(nvdProductTable(ep), /^el_nvdp_[0-9a-f]{8}$/);
  assert.throws(() => nvdProductEndpoint('apache"', "log4j", new Date()), /invalid CPE/);
});

test("parseNvdConfigurations: every cpeMatch, bounds kept, negated and platform entries not vulnerable", () => {
  const cve = FIXTURE.vulnerabilities[0].cve;
  const ranges = parseNvdConfigurations(cve.id, cve.configurations);
  assert.equal(ranges.length, 7);
  assert.deepEqual(ranges[0], {
    cve_id: "CVE-2021-44228", criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", vulnerable: true,
    version_start_including: "2.13.0", version_end_excluding: "2.15.0",
  });
  assert.equal(ranges.find((r) => r.criteria.includes("example_device"))?.vulnerable, false);
  assert.equal(ranges.find((r) => r.criteria.includes("2.16.0"))?.vulnerable, false); // negated node
  // the parsed ranges drive the version check, product-filtered
  const log4j = rangesForProduct(ranges, "Apache", "Log4j2");
  assert.equal(isAffected("2.14.1", log4j), true);
  assert.equal(isAffected("2.0-rc1", log4j), true);
  assert.equal(isAffected("2.17.1", log4j), false);
  assert.equal(isAffected("2.16.0", log4j), false);
});

test("parseNvdVulnerabilities accepts the array, the whole response, or to_json text", () => {
  const a = parseNvdVulnerabilities(FIXTURE.vulnerabilities);
  const b = parseNvdVulnerabilities(FIXTURE);
  const c = parseNvdVulnerabilities(JSON.stringify(FIXTURE.vulnerabilities));
  assert.equal(a.length, 1);
  assert.deepEqual(a, b);
  assert.deepEqual(a, c);
  assert.equal(a[0].published, "2021-12-10T10:15:09.143");
  assert.equal(a[0].vuln_status, "Analyzed");
  assert.equal(a[0].has_configurations, true);
  const awaiting = parseNvdVulnerabilities(AWAITING);
  assert.equal(awaiting[0].has_configurations, false);
  assert.deepEqual(awaiting[0].ranges, []);
  assert.deepEqual(parseNvdVulnerabilities("[]"), []);
  assert.deepEqual(parseNvdVulnerabilities(""), []);
});

test("nvdCves registers idempotently, reads to_json(vulnerabilities), parses, and caches per day", async () => {
  const client = mockClient(defaultResponder({ el_nvd_cve_2021_44228: FIXTURE }));
  const time = fakeTime();
  const tracer = recorder();
  let now = "2026-10-26T10:00:00Z";
  const nvd = createNvdQueries({ client, tracer, clock: { now: () => new Date(now) }, cacheDir: null, now: time.now, sleep: time.sleep });

  const ranges = await nvd.nvdCves(["cve-2021-44228", "CVE-2021-44228"]); // de-duplicated
  assert.equal(ranges.length, 7);
  assert.deepEqual(client.calls.map((c) => c.sql), [
    'CREATE LIGHTNING DATABASE EL_NVD DESCRIBE BY "NVD CVE records"',
    "SHOW LIGHTNING TABLES EL_NVD",
    'CREATE LIGHTNING REST TABLE el_nvd_cve_2021_44228 FROM EL_NVD REQUEST(endpoint "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228", method "get", response_type "json", http_encoding "URLENCODED") HEADER () BODY ()',
    "SELECT to_json(vulnerabilities) AS v FROM el_nvd.el_nvd_cve_2021_44228 LIMIT 5",
  ]);
  assert.equal(client.calls[3].opts?.cache, "use");
  assert.equal(client.calls[3].opts?.timeoutMs, 60_000);
  assert.deepEqual(nvd.status().map((s) => s.state), ["ok"]);
  assert.ok(tracer.events.some((e) => e.agent === "nvd" && e.status === "ok"));

  // same day: served from the day cache, no new statement
  await nvd.nvdCves(["CVE-2021-44228"]);
  assert.equal(client.calls.length, 4);
  assert.equal(nvd.status()[1].state, "cached");

  // next day: the table exists now, so only the SELECT runs again
  now = "2026-10-27T10:00:00Z";
  await nvd.nvdCves(["CVE-2021-44228"]);
  assert.equal(client.calls.length, 5);
  assert.match(client.calls[4].sql, /^SELECT to_json/);
});

test("nvdCves spaces NVD-touching statements at least 6 s apart", async () => {
  const client = mockClient(defaultResponder({ el_nvd_cve_2021_44228: FIXTURE, el_nvd_cve_2026_99001: AWAITING }));
  const time = fakeTime();
  const starts: number[] = [];
  const timed: NvdSqlClient = {
    async query(sql, opts) {
      if (/REST TABLE|^SELECT/.test(sql)) starts.push(time.now());
      return client.query(sql, opts);
    },
  };
  const nvd = createNvdQueries({ client: timed, clock: fixedClock("2026-10-26T10:00:00Z"), cacheDir: null, now: time.now, sleep: time.sleep });
  await nvd.nvdCves(["CVE-2021-44228", "CVE-2026-99001"]);
  assert.equal(starts.length, 4); // two CREATE REST TABLE + two SELECT
  for (let i = 1; i < starts.length; i++) assert.ok(starts[i] - starts[i - 1] >= 6000, `gap ${starts[i] - starts[i - 1]} ms`);
  assert.deepEqual(nvd.status().map((s) => s.state), ["ok", "no_configurations"]);
});

test("createLimiter serialises concurrent callers", async () => {
  const time = fakeTime();
  const limiter = createLimiter(6000, time.now, time.sleep);
  const order: number[] = [];
  await Promise.all([1, 2, 3].map((i) => limiter.schedule(async () => { order.push(time.now()); return i; })));
  assert.equal(order.length, 3);
  assert.ok(order[1] - order[0] >= 6000 && order[2] - order[1] >= 6000);
});

test("nvdCves skips an existing table, accepts 'already exists', and skips invalid ids", async () => {
  const responder = defaultResponder({ el_nvd_cve_2021_44228: FIXTURE, el_nvd_cve_2026_99001: AWAITING });
  const client = mockClient((sql) => {
    if (/^SHOW LIGHTNING TABLES/.test(sql)) return [{ name: "el_nvd_cve_2021_44228", source_table: nvdCveEndpoint("CVE-2021-44228") }];
    if (/^CREATE LIGHTNING REST TABLE el_nvd_cve_2026_99001/.test(sql)) return new Error('HTTP 400: A table named "el_nvd_cve_2026_99001" already exists in database "EL_NVD".');
    return responder(sql);
  });
  const time = fakeTime();
  const nvd = createNvdQueries({ client, clock: fixedClock("2026-10-26T10:00:00Z"), cacheDir: null, now: time.now, sleep: time.sleep });
  const ranges = await nvd.nvdCves(["CVE-2021-44228", "not-a-cve'; --", "CVE-2026-99001"]);
  assert.equal(ranges.length, 7);
  const sqls = client.calls.map((c) => c.sql);
  assert.ok(!sqls.some((s) => /REST TABLE el_nvd_cve_2021_44228/.test(s)), "an existing table is not re-created");
  assert.ok(sqls.some((s) => /REST TABLE el_nvd_cve_2026_99001/.test(s)));
  assert.ok(!sqls.some((s) => /not-a-cve/.test(s)), "an invalid id never reaches SQL");
  assert.deepEqual(nvd.status().map((s) => s.state), ["invalid", "ok", "no_configurations"]);
});

test("nvdCves uses the client's ddl() when it has one", async () => {
  const ddls: string[] = [];
  const base = mockClient(defaultResponder({ el_nvd_cve_2021_44228: FIXTURE }));
  const client: NvdSqlClient = {
    query: base.query,
    async ddl(sql: string) { ddls.push(sql); return { outcome: "exists" as const, ms: 1 }; },
  };
  const time = fakeTime();
  const nvd = createNvdQueries({ client, clock: fixedClock("2026-10-26T10:00:00Z"), cacheDir: null, now: time.now, sleep: time.sleep });
  assert.equal((await nvd.nvdCves(["CVE-2021-44228"])).length, 7);
  assert.equal(ddls.length, 2);
  assert.ok(!base.calls.some((c) => /^CREATE/.test(c.sql)));
});

test("a failed read tries the whole-response fallback; a total failure is recorded and other CVEs continue", async () => {
  const base = defaultResponder({ el_nvd_cve_2026_99001: AWAITING });
  const client = mockClient((sql) => {
    if (/el_nvd_cve_2021_44228/.test(sql) && /^SELECT to_json\(vulnerabilities\)/.test(sql)) return new Error("HTTP 400: cannot resolve vulnerabilities");
    if (/el_nvd_cve_2021_44228/.test(sql) && /^SELECT to_json\(struct\(\*\)\)/.test(sql)) return [{ v: JSON.stringify(FIXTURE) }];
    if (/el_nvd_cve_2026_00002/.test(sql) && /^SELECT/.test(sql)) return new Error("watchdog fired after 120000 ms");
    if (/el_nvd_cve_2021_44228|el_nvd_cve_2026_00002/.test(sql)) return [];
    return base(sql);
  });
  const time = fakeTime();
  const tracer = recorder();
  const nvd = createNvdQueries({ client, tracer, clock: fixedClock("2026-10-26T10:00:00Z"), cacheDir: null, now: time.now, sleep: time.sleep });
  const ranges = await nvd.nvdCves(["CVE-2021-44228", "CVE-2026-00002", "CVE-2026-99001"]);
  assert.equal(ranges.length, 7);
  const st = nvd.status();
  assert.deepEqual(st.map((s) => s.state), ["ok", "error", "no_configurations"]);
  assert.match(st[1].detail ?? "", /watchdog/);
  assert.ok(tracer.events.some((e) => e.status === "error" && e.input_summary === "CVE-2026-00002"));
});

test("a table answering for another CVE is an error, not data", async () => {
  const client = mockClient((sql) => {
    if (/^SELECT/.test(sql)) return [{ v: JSON.stringify(AWAITING.vulnerabilities) }];
    return /^CREATE LIGHTNING DATABASE/.test(sql) ? new Error("HTTP 400: already exists") : [];
  });
  const time = fakeTime();
  const nvd = createNvdQueries({ client, clock: fixedClock("2026-10-26T10:00:00Z"), cacheDir: null, now: time.now, sleep: time.sleep });
  assert.deepEqual(await nvd.nvdCves(["CVE-2021-44228"]), []);
  assert.equal(nvd.status()[0].state, "error");
  assert.match(nvd.status()[0].detail ?? "", /CVE-2026-99001, not CVE-2021-44228/);
});

test("status() carries the day of each read: today for a live read and today's cache, the client cache's day for a fallback", async () => {
  const time = fakeTime();
  const client = mockClient(defaultResponder({ el_nvd_cve_2021_44228: FIXTURE }));
  const nvd = createNvdQueries({ client, clock: fixedClock("2026-10-27T10:00:00Z"), cacheDir: null, now: time.now, sleep: time.sleep });
  await nvd.nvdCves(["CVE-2021-44228"]);
  await nvd.nvdCves(["CVE-2021-44228"]);
  assert.deepEqual(nvd.status().map((s) => [s.state, s.as_of]), [["ok", "2026-10-27"], ["cached", "2026-10-27"]]);
  // the live read failed and the Zetaris client served its SQL cache, saved a week earlier
  const fallback: NvdSqlClient = {
    async query(sql: string) {
      if (/^CREATE LIGHTNING DATABASE/.test(sql)) throw new Error('HTTP 400: A database named "EL_NVD" already exists.');
      if (/^SELECT/.test(sql)) return { rows: [{ v: JSON.stringify(FIXTURE.vulnerabilities) }], ms: 1, fromCache: true, cachedAt: "2026-10-20T08:00:00.000Z" };
      return { rows: [], ms: 1, fromCache: false };
    },
  };
  const n2 = createNvdQueries({ client: fallback, clock: fixedClock("2026-10-27T10:00:00Z"), cacheDir: null, now: time.now, sleep: time.sleep });
  assert.equal((await n2.nvdCves(["CVE-2021-44228"])).length, 7);
  assert.deepEqual(n2.status().map((s) => [s.state, s.as_of]), [["fallback", "2026-10-20"]]);
});

test("the day cache survives a new instance through the disk cache", async () => {
  const dir = mkdtempSync(join(tmpdir(), "nvd-cache-test-"));
  try {
    const time = fakeTime();
    const c1 = mockClient(defaultResponder({ el_nvd_cve_2021_44228: FIXTURE }));
    const n1 = createNvdQueries({ client: c1, clock: fixedClock("2026-10-26T10:00:00Z"), cacheDir: dir, now: time.now, sleep: time.sleep });
    await n1.nvdCves(["CVE-2021-44228"]);
    const c2 = mockClient(() => new Error("must not be called"));
    const n2 = createNvdQueries({ client: c2, clock: fixedClock("2026-10-26T18:00:00Z"), cacheDir: dir, now: time.now, sleep: time.sleep });
    assert.equal((await n2.nvdCves(["CVE-2021-44228"])).length, 7);
    assert.equal(c2.calls.length, 0);
    assert.equal(n2.status()[0].state, "cached");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("nvdProduct registers a hashed table over a 120-day window and keeps only that CPE's ranges", async () => {
  const asOf = new Date("2026-10-26T10:00:00Z");
  const endpoint = nvdProductEndpoint("apache", "log4j", asOf);
  const table = nvdProductTable(endpoint);
  const client = mockClient((sql) => {
    if (/^CREATE LIGHTNING DATABASE/.test(sql)) return new Error("already exists");
    if (/^SHOW/.test(sql)) return [];
    if (/^CREATE LIGHTNING REST TABLE/.test(sql)) return [];
    if (sql.includes(`el_nvd.${table}`)) return [{ total: "1", v: JSON.stringify(FIXTURE.vulnerabilities) }];
    return new Error(`unexpected ${sql}`);
  });
  const time = fakeTime();
  const nvd = createNvdQueries({ client, clock: { now: () => asOf }, cacheDir: null, now: time.now, sleep: time.sleep });
  const hits = await nvd.nvdProduct("Apache", "log4j");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].cve_id, "CVE-2021-44228");
  assert.equal(hits[0].published, "2021-12-10T10:15:09.143");
  assert.ok(hits[0].ranges.length === 5 && hits[0].ranges.every((r) => r.criteria.includes(":apache:log4j:")));
  const create = client.calls.find((c) => /REST TABLE/.test(c.sql))?.sql ?? "";
  assert.ok(create.includes(`REST TABLE ${table} FROM EL_NVD`));
  assert.ok(create.includes("virtualMatchString=cpe:2.3:*:apache:log4j&pubStartDate=2026-06-29T00:00:00.000&pubEndDate=2026-10-26T23:59:59.999"));
  assert.deepEqual(await nvd.nvdProduct("bad vendor!", "x"), []);
  assert.deepEqual(nvd.status().map((s) => s.state), ["ok", "invalid"]);
  assert.deepEqual(rangesForCpe(hits[0].ranges, "cisco", "x"), []);
});
