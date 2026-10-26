import { after, test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { IncomingMessage } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../src/config.ts";
import {
  SerialQueue, ZetarisClient, ZetarisError, guardSql, isAlreadyExists, sqlHash, sqlString,
} from "../src/adapters/zetaris.ts";
import { memoryTracer } from "../src/trace.ts";

const KEY = "test-key-abcdef123456";
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

interface Seen { path: string; method: string; headers: IncomingMessage["headers"]; body: any; start: number; end: number; }
type Reply = { status?: number; json?: unknown; delayMs?: number; raw?: string };

async function mockZetaris(handler: (body: any, n: number) => Reply) {
  const seen: Seen[] = [];
  let active = 0;
  let maxActive = 0;
  const server = createServer((req, res) => {
    let text = "";
    req.on("data", (c) => (text += c));
    req.on("end", async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      const body = text ? JSON.parse(text) : null;
      const rec: Seen = { path: req.url ?? "", method: req.method ?? "", headers: req.headers, body, start: Date.now(), end: 0 };
      seen.push(rec);
      const r = handler(body, seen.length);
      if (r.delayMs) await new Promise((ok) => setTimeout(ok, r.delayMs));
      rec.end = Date.now();
      active--;
      if (res.destroyed) return;
      res.writeHead(r.status ?? 200, { "Content-Type": "application/json" });
      res.end(r.raw ?? JSON.stringify(r.json ?? { headers: ["x"], data: [["1"]], total: 1, timeUsed: 5 }));
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}/api/v1.0`,
    seen,
    maxActive: () => maxActive,
    close: () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }),
  };
}

// Temp dirs live inside the repo (output/ is gitignored); each test file removes only its own.
const TMP_ROOT = join(REPO_ROOT, "output", ".test-tmp");
const made: string[] = [];
function tmp(): string { mkdirSync(TMP_ROOT, { recursive: true }); const d = mkdtempSync(join(TMP_ROOT, "zetaris-")); made.push(d); return d; }
after(() => { for (const d of made) rmSync(d, { recursive: true, force: true }); });

function client(url: string, extra: Partial<ConstructorParameters<typeof ZetarisClient>[0]> = {}) {
  const tracer = memoryTracer("t");
  const c = new ZetarisClient({ restUrl: url, orgId: "1", apiKey: KEY, tracer, cacheDir: tmp(), queue: new SerialQueue(), retryDelayMs: 10, ...extra });
  return { c, tracer };
}

test("request shape: POST /sql-editor/sqls/run with auth, org, request id and the documented body", async () => {
  const z = await mockZetaris(() => ({ json: { headers: ["cve_id", "epss", "flag", "missing"], data: [["CVE-2021-44228", "0.99999", "true", null]], total: 1, timeUsed: 12 } }));
  try {
    const { c } = client(z.url + "/");
    const r = await c.query("SELECT cve_id FROM el.kev;", { label: "t", limit: 7, cache: "bypass" });
    assert.equal(z.seen.length, 1);
    const s = z.seen[0];
    assert.equal(s.method, "POST");
    assert.equal(s.path, "/api/v1.0/sql-editor/sqls/run");
    assert.equal(s.headers.authorization, `Bearer ${KEY}`);
    assert.equal(s.headers["x-org-id"], "1");
    assert.match(String(s.headers["x-request-id"]), UUID_V4);
    assert.match(String(s.headers["content-type"]), /application\/json/);
    assert.deepEqual(Object.keys(s.body).sort(), ["limit", "queryId", "source", "sql"]);
    assert.match(s.body.queryId, UUID_V4);
    assert.equal(s.body.sql, "SELECT cve_id FROM el.kev", "trailing semicolon stripped");
    assert.equal(s.body.source, "SqlEditor");
    assert.equal(s.body.limit, 7);
    // values stay strings; null becomes ""
    assert.deepEqual(r.rows, [{ cve_id: "CVE-2021-44228", epss: "0.99999", flag: "true", missing: "" }]);
    assert.equal(r.fromCache, false);
    assert.equal(typeof r.ms, "number");
  } finally { await z.close(); }
});

test("queue of 1: concurrent calls run one at a time, in FIFO order", async () => {
  const z = await mockZetaris((b) => ({ delayMs: b.sql.includes("'a'") ? 120 : 20, json: { headers: ["v"], data: [[b.sql]], total: 1 } }));
  try {
    const { c } = client(z.url);
    const sqls = ["SELECT 'a'", "SELECT 'b'", "SELECT 'c'", "SELECT 'd'"];
    const results = await Promise.all(sqls.map((s) => c.query(s, { cache: "bypass" })));
    assert.equal(z.maxActive(), 1, "never more than one query at the server");
    assert.deepEqual(z.seen.map((s) => s.body.sql), sqls, "FIFO");
    for (let i = 1; i < z.seen.length; i++) assert.ok(z.seen[i].start >= z.seen[i - 1].end, "no overlap");
    assert.deepEqual(results.map((r) => r.rows[0].v), sqls);
  } finally { await z.close(); }
});

test("two clients for the same URL share the process-wide queue", async () => {
  const z = await mockZetaris(() => ({ delayMs: 40 }));
  try {
    const a = new ZetarisClient({ restUrl: z.url, orgId: "1", apiKey: KEY, cacheDir: tmp() });
    const b = a.withTracer(memoryTracer("other"));
    const c2 = new ZetarisClient({ restUrl: z.url, orgId: "1", apiKey: KEY, cacheDir: tmp() });
    assert.equal(a.queue, b.queue);
    assert.equal(a.queue, c2.queue);
    await Promise.all([a.query("SELECT 1", { cache: "bypass" }), b.query("SELECT 2", { cache: "bypass" }), c2.query("SELECT 3", { cache: "bypass" })]);
    assert.equal(z.maxActive(), 1);
  } finally { await z.close(); }
});

test("a failed query releases the queue for the next one", async () => {
  const z = await mockZetaris((b) => (b.sql === "SELECT bad" ? { status: 400, json: { msg: "syntax error" } } : {}));
  try {
    const { c } = client(z.url);
    const [bad, good] = await Promise.allSettled([c.query("SELECT bad", { cache: "bypass" }), c.query("SELECT 1", { cache: "bypass" })]);
    assert.equal(bad.status, "rejected");
    assert.equal(good.status, "fulfilled");
  } finally { await z.close(); }
});

test("timeout -> cache fallback when cache=use (labelled in the trace)", async () => {
  let slow = false;
  const z = await mockZetaris(() => ({ delayMs: slow ? 400 : 0, json: { headers: ["vendor"], data: [["Apache"]], total: 1 } }));
  try {
    const { c, tracer } = client(z.url, { timeoutMs: 100 });
    const live = await c.query("SELECT vendor FROM el.kev", { label: "kevPairs" });
    assert.equal(live.fromCache, false);
    slow = true;
    const r = await c.query("SELECT vendor FROM el.kev", { label: "kevPairs" });
    assert.equal(r.fromCache, true);
    assert.deepEqual(r.rows, [{ vendor: "Apache" }]);
    assert.ok(r.cachedAt);
    const last = tracer.events.at(-1)!;
    assert.equal(last.status, "fallback");
    assert.equal(last.agent, "Zetaris");
    assert.equal((last.details as any).fromCache, true);
    assert.equal((last.details as any).error_kind, "timeout");
    assert.equal((last.details as any).label, "kevPairs");
    assert.equal((last.details as any).sql_hash, sqlHash("SELECT vendor FROM el.kev"));
  } finally { await z.close(); }
});

test("timeout without a cached copy throws a timeout error", async () => {
  const z = await mockZetaris(() => ({ delayMs: 300 }));
  try {
    const { c, tracer } = client(z.url, { timeoutMs: 80 });
    await assert.rejects(c.query("SELECT 42"), (e: unknown) => e instanceof ZetarisError && e.kind === "timeout");
    assert.equal(tracer.events.at(-1)!.status, "error");
  } finally { await z.close(); }
});

test("cache=bypass never reads or writes the cache", async () => {
  let fail = false;
  const z = await mockZetaris(() => (fail ? { status: 500, json: { msg: "boom" } } : { json: { headers: ["n"], data: [["1"]], total: 1 } }));
  try {
    const dir = tmp();
    const { c } = client(z.url, { cacheDir: dir });
    await c.query("SELECT n FROM el.kev", { cache: "use" });          // populates the cache
    assert.equal(readdirSync(dir).length, 1);
    await c.query("SELECT m FROM el.kev", { cache: "bypass" });       // must not write
    assert.equal(readdirSync(dir).length, 1);
    fail = true;
    await assert.rejects(c.query("SELECT n FROM el.kev", { cache: "bypass" }), (e: unknown) => e instanceof ZetarisError && e.status === 500);
    const r = await c.query("SELECT n FROM el.kev", { cache: "use" }); // the same SQL with use falls back
    assert.equal(r.fromCache, true);
  } finally { await z.close(); }
});

test("cache=write saves but never falls back", async () => {
  let fail = false;
  const z = await mockZetaris(() => (fail ? { status: 503, json: { msg: "down" } } : {}));
  try {
    const dir = tmp();
    const { c } = client(z.url, { cacheDir: dir });
    await c.query("SELECT 1 AS x", { cache: "write" });
    assert.equal(readdirSync(dir).length, 1);
    fail = true;
    await assert.rejects(c.query("SELECT 1 AS x", { cache: "write" }));
  } finally { await z.close(); }
});

test("DDL and SHOW statements never touch the cache", async () => {
  const z = await mockZetaris(() => ({}));
  try {
    const dir = tmp();
    const { c } = client(z.url, { cacheDir: dir });
    await c.query("SHOW LIGHTNING DATABASES", { cache: "write" });
    await c.ddl("CREATE SCHEMASTORE CONTAINER el_x");
    assert.equal(existsSync(dir) ? readdirSync(dir).length : 0, 0);
  } finally { await z.close(); }
});

test("'already exists' (HTTP 400) is success for ddl(); any other 400 is an error", async () => {
  const z = await mockZetaris((b) => {
    if (b.sql.includes("EL_DUP")) return { status: 400, json: { msg: 'A database named "EL_DUP" already exists.' } };
    if (b.sql.includes("EL_BAD")) return { status: 400, json: { msg: "Syntax error at line 1" } };
    return { json: { headers: [], data: [], total: 0 } };
  });
  try {
    const { c, tracer } = client(z.url);
    assert.deepEqual((await c.ddl('CREATE LIGHTNING DATABASE EL_NEW DESCRIBE BY "x"')).outcome, "created");
    const dup = await c.ddl('CREATE LIGHTNING DATABASE EL_DUP DESCRIBE BY "x"');
    assert.equal(dup.outcome, "exists");
    assert.equal(tracer.events.at(-1)!.status, "ok");
    assert.equal((tracer.events.at(-1)!.details as any).outcome, "exists");
    await assert.rejects(c.ddl('CREATE LIGHTNING DATABASE EL_BAD DESCRIBE BY "x"'), (e: unknown) => e instanceof ZetarisError && e.status === 400 && !isAlreadyExists(e));
    assert.equal(tracer.events.at(-1)!.status, "error");
    // query() does not hide "already exists": callers that create objects use ddl()
    await assert.rejects(c.query('CREATE LIGHTNING DATABASE EL_DUP DESCRIBE BY "x"'), (e: unknown) => isAlreadyExists(e));
  } finally { await z.close(); }
});

test("the 120 s watchdog (scaled down) aborts a call whose per-attempt timeout is longer", async () => {
  const z = await mockZetaris(() => ({ delayMs: 500 }));
  try {
    const { c } = client(z.url, { timeoutMs: 5_000, watchdogMs: 100 });
    const t0 = Date.now();
    await assert.rejects(c.query("SELECT 1", { cache: "bypass" }), (e: unknown) => e instanceof ZetarisError && e.kind === "watchdog");
    assert.ok(Date.now() - t0 < 450, "returned at the watchdog, not at the server's reply");
  } finally { await z.close(); }
});

test("one retry on a network error, then success (retry_count in the trace)", async () => {
  let calls = 0;
  const fakeFetch = (async () => {
    calls++;
    if (calls === 1) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNRESET" } });
    return new Response(JSON.stringify({ headers: ["ok"], data: [["1"]], total: 1 }), { status: 200 });
  }) as typeof fetch;
  const tracer = memoryTracer();
  const c = new ZetarisClient({ restUrl: "http://zetaris.invalid/api/v1.0", orgId: "1", apiKey: KEY, tracer, fetchImpl: fakeFetch, retryDelayMs: 5, cacheDir: tmp(), queue: new SerialQueue() });
  const r = await c.query("SELECT 1", { cache: "bypass" });
  assert.equal(calls, 2);
  assert.deepEqual(r.rows, [{ ok: "1" }]);
  assert.equal(tracer.events.at(-1)!.retry_count, 1);
});

test("a persistent network error is retried once, then thrown", async () => {
  let calls = 0;
  const fakeFetch = (async () => { calls++; throw new TypeError("fetch failed"); }) as typeof fetch;
  const c = new ZetarisClient({ restUrl: "http://zetaris.invalid/api/v1.0", orgId: "1", apiKey: KEY, fetchImpl: fakeFetch, retryDelayMs: 5, cacheDir: tmp(), queue: new SerialQueue() });
  await assert.rejects(c.query("SELECT 1", { cache: "bypass" }), (e: unknown) => e instanceof ZetarisError && e.kind === "network" && e.attempts === 2);
  assert.equal(calls, 2);
});

test("an HTTP error is not retried", async () => {
  const z = await mockZetaris(() => ({ status: 500, json: { msg: "internal" } }));
  try {
    const { c } = client(z.url);
    await assert.rejects(c.query("SELECT 1", { cache: "bypass" }));
    assert.equal(z.seen.length, 1);
  } finally { await z.close(); }
});

test("guards: DROP, other destructive statements, the taxi tables and foreign namespaces are refused before sending", async () => {
  const z = await mockZetaris(() => ({}));
  try {
    const { c } = client(z.url);
    for (const sql of [
      "DROP LIGHTNING DATABASE EL_KEV", "  drop view el.kev", "DELETE FROM el.kev", "TRUNCATE TABLE x", "ALTER TABLE x",
      "SELECT * FROM ny_taxi.yellow_taxi LIMIT 1", "SELECT count(*) FROM ny_taxi.hvv",
      'CREATE LIGHTNING DATABASE FOO DESCRIBE BY "x"', "CREATE LIGHTNING REST TABLE fz_x FROM EL_KEV REQUEST() HEADER () BODY ()",
      "CREATE SCHEMASTORE CONTAINER other", "CREATE SCHEMASTORE VIEW v WITH CONTAINER other AS SELECT 1", "CREATE NAMESPACE x",
    ]) {
      await assert.rejects(c.query(sql), (e: unknown) => e instanceof ZetarisError && e.kind === "refused", sql);
    }
    assert.equal(z.seen.length, 0, "nothing reached the server");
    assert.doesNotThrow(() => guardSql('CREATE LIGHTNING DATABASE EL_T1_KEV DESCRIBE BY "x"'));
    assert.doesNotThrow(() => guardSql("CREATE SCHEMASTORE CONTAINER el"));
    assert.doesNotThrow(() => guardSql("CREATE SCHEMASTORE VIEW kev WITH CONTAINER el_t1 AS SELECT 1"));
  } finally { await z.close(); }
});

test("the API key never appears in trace events or in the client's JSON form", async () => {
  const z = await mockZetaris(() => ({ status: 400, json: { msg: "bad" } }));
  try {
    const { c, tracer } = client(z.url);
    await c.query("SELECT 1", { cache: "bypass" }).catch(() => {});
    await c.ddl("CREATE SCHEMASTORE CONTAINER el").catch(() => {});
    assert.ok(tracer.events.length >= 2);
    assert.ok(!JSON.stringify(tracer.events).includes(KEY));
    assert.ok(!JSON.stringify(c).includes(KEY));
  } finally { await z.close(); }
});

test("a non-JSON or malformed 200 reply is a bad_response error", async () => {
  const z = await mockZetaris(() => ({ raw: "<html>oops</html>" }));
  try {
    const { c } = client(z.url);
    await assert.rejects(c.query("SELECT 1", { cache: "bypass" }), (e: unknown) => e instanceof ZetarisError && e.kind === "bad_response");
  } finally { await z.close(); }
});

test("sqlString escapes with backslashes (Spark concatenates '')", () => {
  assert.equal(sqlString("It's"), "'It\\'s'");
  assert.equal(sqlString("a\\b"), "'a\\\\b'");
  assert.equal(sqlString("plain"), "'plain'");
});
