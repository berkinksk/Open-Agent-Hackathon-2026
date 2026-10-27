// NIST NVD through Zetaris: Queries.nvdCves (one REST table per CVE) and Queries.nvdProduct (recent CVEs for a
// CPE vendor:product). Each table is registered idempotently in <PREFIX>NVD; every statement that makes Zetaris
// fetch from NVD is spaced >= 6 s apart (NVD's keyless limit); results are cached per as-of day.
// The CPE `configurations` are parsed here into NvdRange[]; the version check itself lives in resolve/versions.ts.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Clock, NvdProductHit, NvdRange, Queries, Tracer } from "../contracts.ts";
import { parseCpe } from "../resolve/versions.ts";

// ---------- the client seam (a structural subset of adapters/zetaris.ts ZetarisClient) ----------
export interface NvdSqlClient {
  query(sql: string, opts?: { cache?: "use" | "bypass" | "write"; timeoutMs?: number; label?: string; limit?: number }):
    Promise<{ rows: Record<string, string>[]; ms: number; fromCache: boolean; cachedAt?: string }>;
  /** Optional: CREATE that treats 400 + "already exists" as success. Falls back to query() when absent. */
  ddl?(sql: string, opts?: { label?: string; timeoutMs?: number }): Promise<{ outcome: "created" | "exists"; ms: number }>;
}

export interface NvdConfig {
  client: NvdSqlClient;
  tracer?: Tracer | null;
  prefix?: string;              // default "EL_" → database EL_NVD, tables el_nvd_*
  clock?: Clock;                // the as-of date (cache day, product window)
  minIntervalMs?: number;       // spacing of NVD-touching statements, default 6000
  now?: () => number;           // wall time for the limiter (tests)
  sleep?: (ms: number) => Promise<void>;
  timeoutMs?: number;           // per statement, default 60000 (the client's watchdog still applies)
  cacheDir?: string | null;     // per-day disk cache; null = memory only. Default output/cache/nvd
  productWindowDays?: number;   // nvdProduct: published in the last N days, default 120 (NVD's maximum)
  productPageSize?: number;     // nvdProduct: resultsPerPage, default 50 (keeps the source KB-sized)
}

export type NvdLookupState = "ok" | "cached" | "fallback" | "no_configurations" | "not_found" | "error" | "invalid";
export interface NvdLookupStatus {
  key: string;                  // CVE id, or "cpe:<vendor>:<product>"
  state: NvdLookupState;
  table: string | null;
  ranges: number;
  detail?: string;
  /**
   * The day (YYYY-MM-DD) the data was read from NVD through Zetaris: today for a live read ("ok", "no_configurations",
   * "not_found"), the cache day for "cached" (today's per-day cache, filled by an earlier run), the client cache's save
   * day for "fallback" when known. Absent on errors.
   */
  as_of?: string;
}

export interface NvdQueries extends Pick<Queries, "nvdCves" | "nvdProduct"> {
  /** What happened to every lookup of this instance, in order (for the manifest and the trace). */
  status(): NvdLookupStatus[];
  /** True when today's cache already holds this CVE (a lookup costs no NVD request). */
  cachedCve(cveId: string): boolean;
}

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const CPE_NAME_RE = /^[a-z0-9][a-z0-9_.\-~]{0,99}$/;
const PREFIX_RE = /^[A-Za-z][A-Za-z0-9_]*_$/;
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const DEFAULT_NVD_CACHE_DIR = join(REPO_ROOT, "output", "cache", "nvd");

// ---------- names and endpoints ----------
export function normaliseCveId(id: string): string | null {
  const s = String(id ?? "").trim().toUpperCase();
  return CVE_RE.test(s) ? s : null;
}
export function nvdDatabase(prefix = "EL_"): string {
  checkPrefix(prefix);
  return `${prefix.toUpperCase()}NVD`;
}
export function nvdCveTable(cveId: string, prefix = "EL_"): string {
  const id = normaliseCveId(cveId);
  if (!id) throw new Error(`nvd: invalid CVE id ${JSON.stringify(cveId)}`);
  checkPrefix(prefix);
  return `${prefix.toLowerCase()}nvd_${id.toLowerCase().replace(/-/g, "_")}`;
}
export function nvdCveEndpoint(cveId: string): string {
  const id = normaliseCveId(cveId);
  if (!id) throw new Error(`nvd: invalid CVE id ${JSON.stringify(cveId)}`);
  return `${NVD_API}?cveId=${id}`;
}
/** pubStartDate/pubEndDate must both be set and span at most 120 days (NVD API rule). */
export function nvdProductEndpoint(cpeVendor: string, cpeProduct: string, asOf: Date, windowDays = 120, pageSize = 50): string {
  const v = String(cpeVendor ?? "").toLowerCase();
  const p = String(cpeProduct ?? "").toLowerCase();
  if (!CPE_NAME_RE.test(v) || !CPE_NAME_RE.test(p)) throw new Error(`nvd: invalid CPE vendor/product ${JSON.stringify(`${cpeVendor}:${cpeProduct}`)}`);
  const days = Math.min(Math.max(1, Math.floor(windowDays)), 120);
  const day = asOf.toISOString().slice(0, 10);
  const start = new Date(Date.parse(`${day}T00:00:00.000Z`) - (days - 1) * 86_400_000).toISOString().slice(0, 10);
  const size = Math.min(Math.max(1, Math.floor(pageSize)), 2000);
  return `${NVD_API}?virtualMatchString=cpe:2.3:*:${v}:${p}&pubStartDate=${start}T00:00:00.000&pubEndDate=${day}T23:59:59.999&resultsPerPage=${size}`;
}
export function nvdProductTable(endpoint: string, prefix = "EL_"): string {
  checkPrefix(prefix);
  return `${prefix.toLowerCase()}nvdp_${createHash("sha256").update(endpoint).digest("hex").slice(0, 8)}`;
}
function checkPrefix(prefix: string): void {
  if (!PREFIX_RE.test(prefix)) throw new Error(`nvd: invalid object prefix ${JSON.stringify(prefix)}`);
}

export function createDatabaseSql(prefix = "EL_"): string {
  return `CREATE LIGHTNING DATABASE ${nvdDatabase(prefix)} DESCRIBE BY "NVD CVE records"`;
}
export function createRestTableSql(table: string, endpoint: string, prefix = "EL_"): string {
  if (endpoint.includes('"')) throw new Error("nvd: endpoint must not contain a double quote");
  return `CREATE LIGHTNING REST TABLE ${table} FROM ${nvdDatabase(prefix)} REQUEST(endpoint "${endpoint}", method "get", response_type "json", http_encoding "URLENCODED") HEADER () BODY ()`;
}

// ---------- parsing (NVD CVE API 2.0 shape) ----------
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
const isTrue = (v: unknown): boolean => v === true || v === "true";
const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() !== "" ? v : undefined);

/** `cve.configurations` → NvdRange[] (every cpeMatch; entries under a negated node count as not vulnerable). */
export function parseNvdConfigurations(cveId: string, configurations: unknown): NvdRange[] {
  const out: NvdRange[] = [];
  const seen = new Set<string>();
  const walkNode = (node: unknown, negated: boolean): void => {
    if (!isObj(node)) return;
    const neg = negated || isTrue(node.negate);
    for (const m of asArray(node.cpeMatch)) {
      if (!isObj(m) || typeof m.criteria !== "string") continue;
      const r: NvdRange = { cve_id: cveId, criteria: m.criteria, vulnerable: isTrue(m.vulnerable) && !neg };
      const si = str(m.versionStartIncluding); if (si) r.version_start_including = si;
      const se = str(m.versionStartExcluding); if (se) r.version_start_excluding = se;
      const ei = str(m.versionEndIncluding); if (ei) r.version_end_including = ei;
      const ee = str(m.versionEndExcluding); if (ee) r.version_end_excluding = ee;
      const key = JSON.stringify(r);
      if (!seen.has(key)) { seen.add(key); out.push(r); }
    }
    for (const child of asArray(node.children)) walkNode(child, neg); // pre-2.0 nesting, harmless if absent
  };
  for (const conf of asArray(configurations)) {
    if (!isObj(conf)) continue;
    const confNeg = isTrue(conf.negate);
    for (const node of asArray(conf.nodes)) walkNode(node, confNeg);
  }
  return out;
}

export interface ParsedNvdCve { cve_id: string; published: string; vuln_status: string; has_configurations: boolean; ranges: NvdRange[]; }

/**
 * Accepts the `vulnerabilities` array, a whole API response ({vulnerabilities: [...]}), a single
 * {cve: {...}} wrapper, or a JSON string of any of these (what `to_json(...)` returns through Zetaris).
 */
export function parseNvdVulnerabilities(input: unknown): ParsedNvdCve[] {
  let v: unknown = input;
  if (typeof v === "string") {
    const t = v.trim();
    if (t === "") return [];
    v = JSON.parse(t);
  }
  if (isObj(v) && "vulnerabilities" in v) v = v.vulnerabilities;
  const out: ParsedNvdCve[] = [];
  for (const item of asArray(v)) {
    const cve = isObj(item) && isObj(item.cve) ? item.cve : isObj(item) && typeof item.id === "string" ? item : null;
    if (!cve) continue;
    const id = normaliseCveId(String(cve.id ?? ""));
    if (!id) continue;
    const ranges = parseNvdConfigurations(id, cve.configurations);
    out.push({
      cve_id: id,
      published: typeof cve.published === "string" ? cve.published : "",
      vuln_status: typeof cve.vulnStatus === "string" ? cve.vulnStatus : "",
      has_configurations: asArray(cve.configurations).length > 0,
      ranges,
    });
  }
  return out;
}

/** Keep ranges whose CPE is exactly vendor:product (NVD names, lower case). */
export function rangesForCpe(ranges: NvdRange[], cpeVendor: string, cpeProduct: string): NvdRange[] {
  const v = cpeVendor.toLowerCase();
  const p = cpeProduct.toLowerCase();
  return ranges.filter((r) => {
    const c = parseCpe(r.criteria);
    return c !== null && c.vendor === v && c.product === p;
  });
}

// ---------- rate limiter (shared per process unless a test injects its own clock) ----------
export interface Limiter { schedule<T>(fn: () => Promise<T>): Promise<T>; }

export function createLimiter(minIntervalMs: number, now: () => number = Date.now,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms))): Limiter {
  let tail: Promise<void> = Promise.resolve();
  let last = -Infinity;
  return {
    schedule<T>(fn: () => Promise<T>): Promise<T> {
      const run = tail.then(async () => {
        const wait = last + minIntervalMs - now();
        if (wait > 0) await sleep(wait);
        last = now();
        return fn();
      });
      tail = run.then(() => undefined, () => undefined);
      return run;
    },
  };
}
const SHARED_LIMITERS = new Map<number, Limiter>();
function sharedLimiter(ms: number): Limiter {
  let l = SHARED_LIMITERS.get(ms);
  if (!l) { l = createLimiter(ms); SHARED_LIMITERS.set(ms, l); }
  return l;
}

// ---------- the Queries implementation ----------
const SELECT_CVE = (db: string, table: string): string => `SELECT to_json(vulnerabilities) AS v FROM ${db.toLowerCase()}.${table} LIMIT 5`;
const SELECT_WHOLE = (db: string, table: string): string => `SELECT to_json(struct(*)) AS v FROM ${db.toLowerCase()}.${table} LIMIT 5`;
const SELECT_PRODUCT = (db: string, table: string): string => `SELECT totalResults AS total, to_json(vulnerabilities) AS v FROM ${db.toLowerCase()}.${table} LIMIT 5`;

function errText(err: unknown): string {
  const m = err instanceof Error ? err.message : String(err);
  return m.replace(/\s+/g, " ").slice(0, 300);
}
function isAlreadyExists(err: unknown): boolean {
  return /already exists/i.test(errText(err));
}

export function createNvdQueries(cfg: NvdConfig): NvdQueries {
  const prefix = cfg.prefix ?? "EL_";
  checkPrefix(prefix);
  const db = nvdDatabase(prefix);
  const client = cfg.client;
  const tracer = cfg.tracer ?? null;
  const clock: Clock = cfg.clock ?? { now: () => new Date() };
  const timeoutMs = cfg.timeoutMs ?? 60_000;
  const minInterval = cfg.minIntervalMs ?? 6_000;
  const limiter = cfg.now || cfg.sleep ? createLimiter(minInterval, cfg.now, cfg.sleep) : sharedLimiter(minInterval);
  const cacheDir = cfg.cacheDir === undefined ? DEFAULT_NVD_CACHE_DIR : cfg.cacheDir;
  const windowDays = cfg.productWindowDays ?? 120;
  const pageSize = cfg.productPageSize ?? 50;

  const memory = new Map<string, unknown>();
  const statuses: NvdLookupStatus[] = [];
  let dbReady: Promise<void> | null = null;
  let existing: Set<string> | null = null;

  const emit = (action: string, status: "ok" | "error" | "fallback", input: string, output: string, details?: Record<string, unknown>): void => {
    if (!tracer) return;
    try { tracer.emit({ agent: "nvd", action, status, input_summary: input, output_summary: output, details }); } catch { /* tracing never breaks a lookup */ }
  };
  const record = (s: NvdLookupStatus): void => { statuses.push(s); };
  const day = (): string => clock.now().toISOString().slice(0, 10);
  /** The as-of day of a read: today, or the client cache's save day on a fallback (unknown when it gave none). */
  const readDay = (res: { fromCache: boolean; cachedAt?: string }): string | undefined =>
    !res.fromCache ? day() : /^\d{4}-\d{2}-\d{2}/.test(res.cachedAt ?? "") ? (res.cachedAt as string).slice(0, 10) : undefined;

  // per-day cache: memory first, then disk
  const cacheGet = <T>(key: string): T | undefined => {
    const k = `${day()}|${key}`;
    if (memory.has(k)) return memory.get(k) as T;
    if (!cacheDir) return undefined;
    try {
      const file = join(cacheDir, day(), `${key.replace(/[^A-Za-z0-9_.-]/g, "_")}.json`);
      const data = JSON.parse(readFileSync(file, "utf8")) as { value: T };
      memory.set(k, data.value);
      return data.value;
    } catch { return undefined; }
  };
  const cachePut = (key: string, value: unknown, meta: Record<string, unknown>): void => {
    memory.set(`${day()}|${key}`, value);
    if (!cacheDir) return;
    try {
      const dir = join(cacheDir, day());
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, `${key.replace(/[^A-Za-z0-9_.-]/g, "_")}.json`), JSON.stringify({ ...meta, as_of_day: day(), value }));
    } catch { /* a cache write failure never breaks a lookup */ }
  };

  const ddl = async (sql: string, label: string): Promise<"created" | "exists"> => {
    if (client.ddl) return (await client.ddl(sql, { label, timeoutMs })).outcome;
    try {
      await client.query(sql, { cache: "bypass", label, timeoutMs, limit: 1 });
      return "created";
    } catch (err) {
      if (isAlreadyExists(err)) return "exists";
      throw err;
    }
  };

  const ensureDb = (): Promise<void> => {
    if (!dbReady) {
      dbReady = (async () => {
        await ddl(createDatabaseSql(prefix), "nvd_db");
        try {
          const r = await client.query(`SHOW LIGHTNING TABLES ${db}`, { cache: "bypass", label: "nvd_tables", timeoutMs, limit: 10_000 });
          existing = new Set(r.rows.map((row) => String(row.name ?? "").toLowerCase()).filter(Boolean));
        } catch {
          existing = new Set(); // unknown: CREATE and accept "already exists"
        }
      })();
      dbReady.catch(() => { dbReady = null; }); // let a later lookup retry
    }
    return dbReady;
  };

  /** Register (if missing) and read one REST table; returns the raw `v` cell(s) and whether they came from the client's cache. */
  const fetchTable = async (table: string, endpoint: string, selects: string[]): Promise<{ rows: Record<string, string>[]; fromCache: boolean; cachedAt?: string; sql: string }> => {
    await ensureDb();
    if (!existing?.has(table)) {
      await limiter.schedule(() => ddl(createRestTableSql(table, endpoint, prefix), "nvd_register"));
      existing?.add(table);
    }
    let lastErr: unknown = null;
    for (const sql of selects) {
      try {
        const r = await limiter.schedule(() => client.query(sql, { cache: "use", label: "nvd_read", timeoutMs, limit: 5 }));
        return { rows: r.rows, fromCache: r.fromCache, ...(r.cachedAt ? { cachedAt: r.cachedAt } : {}), sql };
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr ?? new Error("nvd: no query ran");
  };

  const lookupCve = async (id: string): Promise<NvdRange[]> => {
    const cached = cacheGet<NvdRange[]>(id);
    if (cached) {
      record({ key: id, state: "cached", table: nvdCveTable(id, prefix), ranges: cached.length, as_of: day() });
      emit("nvd_cve", "ok", id, `${cached.length} range(s) from today's cache`, { cve_id: id, cache: "day" });
      return cached;
    }
    const table = nvdCveTable(id, prefix);
    const endpoint = nvdCveEndpoint(id);
    const t0 = Date.now();
    try {
      const res = await fetchTable(table, endpoint, [SELECT_CVE(db, table), SELECT_WHOLE(db, table)]);
      const parsed = res.rows.flatMap((row) => parseNvdVulnerabilities(row.v ?? ""));
      const mine = parsed.filter((p) => p.cve_id === id);
      const others = parsed.filter((p) => p.cve_id !== id);
      if (mine.length === 0 && others.length > 0) {
        throw new Error(`table ${table} returned ${others.map((o) => o.cve_id).join(", ")}, not ${id}`);
      }
      const ranges = mine.flatMap((p) => p.ranges);
      const state: NvdLookupState = res.fromCache ? "fallback" : mine.length === 0 ? "not_found" : ranges.length === 0 ? "no_configurations" : "ok";
      const detail = res.fromCache ? "live read failed; the client served its cached copy" :
        state === "no_configurations" ? `NVD has no CPE configurations yet (${mine[0]?.vuln_status || "status unknown"})` :
        state === "not_found" ? "NVD returned no record" : undefined;
      if (!res.fromCache && mine.length > 0) cachePut(id, ranges, { cve_id: id, table, endpoint });
      const asOf = readDay(res);
      record({ key: id, state, table, ranges: ranges.length, detail, ...(asOf ? { as_of: asOf } : {}) });
      emit("nvd_cve", res.fromCache ? "fallback" : "ok", id, `${ranges.length} range(s) [${state}]`,
        { cve_id: id, table, endpoint, sql: res.sql, ms: Date.now() - t0, state, detail });
      return ranges;
    } catch (err) {
      record({ key: id, state: "error", table, ranges: 0, detail: errText(err) });
      emit("nvd_cve", "error", id, `failed: ${errText(err)}`, { cve_id: id, table, endpoint, ms: Date.now() - t0 });
      return [];
    }
  };

  return {
    async nvdCves(cveIds: string[]): Promise<NvdRange[]> {
      const ids: string[] = [];
      for (const raw of cveIds ?? []) {
        const id = normaliseCveId(raw);
        if (!id) {
          record({ key: String(raw), state: "invalid", table: null, ranges: 0, detail: "not a CVE id; skipped" });
          emit("nvd_cve", "error", String(raw).slice(0, 40), "invalid CVE id; skipped");
          continue;
        }
        if (!ids.includes(id)) ids.push(id);
      }
      const out: NvdRange[] = [];
      for (const id of ids) out.push(...(await lookupCve(id))); // sequential: one Zetaris query at a time anyway
      return out;
    },

    async nvdProduct(cpeVendor: string, cpeProduct: string): Promise<NvdProductHit[]> {
      const v = String(cpeVendor ?? "").toLowerCase();
      const p = String(cpeProduct ?? "").toLowerCase();
      const key = `cpe:${v}:${p}`;
      let endpoint: string;
      try {
        endpoint = nvdProductEndpoint(v, p, clock.now(), windowDays, pageSize);
      } catch (err) {
        record({ key, state: "invalid", table: null, ranges: 0, detail: errText(err) });
        emit("nvd_product", "error", key.slice(0, 80), "invalid CPE vendor/product; skipped");
        return [];
      }
      const cacheKey = `product_${v}_${p}`;
      const cached = cacheGet<NvdProductHit[]>(cacheKey);
      if (cached) {
        record({ key, state: "cached", table: nvdProductTable(endpoint, prefix), ranges: cached.reduce((n, h) => n + h.ranges.length, 0), as_of: day() });
        emit("nvd_product", "ok", key, `${cached.length} CVE(s) from today's cache`, { cache: "day" });
        return cached;
      }
      const table = nvdProductTable(endpoint, prefix);
      const t0 = Date.now();
      try {
        const res = await fetchTable(table, endpoint, [SELECT_PRODUCT(db, table), SELECT_WHOLE(db, table)]);
        const parsed = res.rows.flatMap((row) => parseNvdVulnerabilities(row.v ?? ""));
        const hits: NvdProductHit[] = [];
        const seen = new Set<string>();
        for (const c of parsed) {
          if (seen.has(c.cve_id)) continue;
          seen.add(c.cve_id);
          hits.push({ cve_id: c.cve_id, published: c.published, ranges: rangesForCpe(c.ranges, v, p) });
        }
        const totals = res.rows.map((row) => Number(row.total)).filter((n) => Number.isFinite(n));
        const total = totals.length ? Math.max(...totals) : null;
        const truncated = total !== null && total > hits.length;
        const detail = [res.fromCache ? "live read failed; the client served its cached copy" : "", truncated ? `truncated: NVD reports ${total}, page holds ${hits.length}` : ""].filter(Boolean).join("; ") || undefined;
        if (!res.fromCache) cachePut(cacheKey, hits, { cpe: key, table, endpoint });
        const nRanges = hits.reduce((n, h) => n + h.ranges.length, 0);
        const asOf = readDay(res);
        record({ key, state: res.fromCache ? "fallback" : "ok", table, ranges: nRanges, detail, ...(asOf ? { as_of: asOf } : {}) });
        emit("nvd_product", res.fromCache ? "fallback" : "ok", key, `${hits.length} CVE(s), ${nRanges} range(s)${truncated ? " (truncated)" : ""}`,
          { table, endpoint, sql: res.sql, ms: Date.now() - t0, total, truncated });
        return hits;
      } catch (err) {
        record({ key, state: "error", table, ranges: 0, detail: errText(err) });
        emit("nvd_product", "error", key, `failed: ${errText(err)}`, { table, endpoint, ms: Date.now() - t0 });
        return [];
      }
    },

    status(): NvdLookupStatus[] {
      return statuses.map((s) => ({ ...s }));
    },

    cachedCve(cveId: string): boolean {
      const id = normaliseCveId(cveId);
      return id !== null && cacheGet<NvdRange[]>(id) !== undefined;
    },
  };
}
