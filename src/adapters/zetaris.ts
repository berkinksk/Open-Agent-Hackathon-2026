// Zetaris REST SQL client.
// - One query at a time per Zetaris URL (a process-wide serial queue), because one slow
//   server-side query blocks every later one.
// - 60 s timeout per HTTP attempt, a hard 120 s watchdog over the whole call, and one retry
//   on a network error (never on a timeout or an HTTP error).
// - Values stay strings, exactly as Zetaris returns them; callers parse them.
// - A disk cache keyed by sha256(sql) in output/cache/zetaris/:
//     "use"    live; save on success; on failure serve the cached copy (labelled fallback)
//     "write"  live; save on success; no fallback (refresh / snapshot capture)
//     "bypass" live only; never reads or writes the cache (the verifier uses this)
//   Only SELECT/WITH statements touch the cache; DDL and SHOW/DESCRIBE are always live.
// - Every call emits a trace event with the label, SQL, sql_hash, rows, ms, fromCache, status.
// - Guards: DROP/DELETE/TRUNCATE/ALTER/INSERT/UPDATE/MERGE are refused, CREATE is allowed only
//   for EL_ databases and el_ tables/containers, and the large taxi tables are never queried.
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { Tracer } from "../contracts.ts";
import { REPO_ROOT } from "../config.ts";

export type CacheMode = "use" | "bypass" | "write";

export interface QueryOptions {
  cache?: CacheMode;
  timeoutMs?: number;
  label?: string;
  /** Row limit sent to Zetaris (the REST API truncates to it). Default 10000. */
  limit?: number;
}

export interface QueryResult {
  rows: Record<string, string>[];
  ms: number;
  fromCache: boolean;
  /** Zetaris "total" (live only). When it exceeds rows.length the result was truncated. */
  total?: number;
  /** When fromCache: when the cached copy was saved. */
  cachedAt?: string;
}

export interface DdlResult { outcome: "created" | "exists"; ms: number; }

export type ZetarisErrorKind = "http" | "timeout" | "watchdog" | "network" | "bad_response" | "refused";

export class ZetarisError extends Error {
  readonly kind: ZetarisErrorKind;
  readonly status: number | null;
  attempts: number;
  constructor(kind: ZetarisErrorKind, message: string, status: number | null = null, attempts = 1) {
    super(message);
    this.name = "ZetarisError";
    this.kind = kind;
    this.status = status;
    this.attempts = attempts;
  }
}

/** Zetaris answers a duplicate CREATE with HTTP 400 + "... already exists ...": that is success. */
export function isAlreadyExists(err: unknown): boolean {
  return err instanceof ZetarisError && err.kind === "http" && err.status === 400 && /already exists/i.test(err.message);
}

export interface ZetarisClientConfig {
  restUrl: string;   // e.g. http://localhost:8888/api/v1.0
  orgId: string;
  apiKey: string;
  tracer?: Tracer | null;
  cacheDir?: string;
  timeoutMs?: number;      // per HTTP attempt, default 60000
  watchdogMs?: number;     // whole call incl. retry, default 120000
  defaultLimit?: number;   // default 10000
  retryDelayMs?: number;   // pause before the network-error retry, default 1000
  fetchImpl?: typeof fetch;
  queue?: SerialQueue;     // default: the shared queue for this restUrl
}

export const DEFAULT_CACHE_DIR = join(REPO_ROOT, "output", "cache", "zetaris");

// ---------- the serial queue (one query at a time) ----------
export class SerialQueue {
  #tail: Promise<void> = Promise.resolve();
  #pending = 0;
  get pending(): number { return this.#pending; }
  run<T>(fn: () => Promise<T>): Promise<T> {
    this.#pending++;
    const result = this.#tail.then(() => fn());
    this.#tail = result.then(() => undefined, () => undefined).finally(() => { this.#pending--; });
    return result;
  }
}

const SHARED_QUEUES = new Map<string, SerialQueue>();
export function sharedQueue(key: string): SerialQueue {
  let q = SHARED_QUEUES.get(key);
  if (!q) { q = new SerialQueue(); SHARED_QUEUES.set(key, q); }
  return q;
}

// ---------- SQL helpers ----------
export function cleanSql(sql: string): string {
  return sql.trim().replace(/;+\s*$/, "").trim();
}

export function sqlHash(sql: string): string {
  return createHash("sha256").update(cleanSql(sql)).digest("hex");
}

/** A Spark/Zetaris string literal. Backslash escaping is the one that works ('' concatenates). */
export function sqlString(v: string): string {
  return "'" + v.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'";
}

const CACHEABLE = /^(select|with)\b/i;
const DESTRUCTIVE = /^(drop|delete|truncate|alter|insert|update|merge|grant|revoke)\b/i;
const FORBIDDEN_TABLES = /\b(yellow_taxi|green_taxi|hvv|for_hire_vehicles)\b/i;

/** Throws ZetarisError("refused") for statements this app must never send. */
export function guardSql(sql: string): void {
  if (!sql) throw new ZetarisError("refused", "empty SQL statement");
  if (DESTRUCTIVE.test(sql)) throw new ZetarisError("refused", `refused: destructive statement (${sql.split(/\s+/)[0].toUpperCase()}) is never sent`);
  if (FORBIDDEN_TABLES.test(sql)) throw new ZetarisError("refused", "refused: the NY taxi / hvv tables are never queried (they stall the engine)");
  if (/^create\b/i.test(sql)) {
    let m: RegExpMatchArray | null;
    if ((m = sql.match(/^create\s+lightning\s+database\s+([A-Za-z0-9_]+)/i))) {
      if (!/^EL_/.test(m[1])) throw new ZetarisError("refused", `refused: databases must start with EL_ (got ${m[1]})`);
    } else if ((m = sql.match(/^create\s+lightning\s+(?:\w+\s+)?table\s+([A-Za-z0-9_]+)/i))) {
      if (!/^el_/.test(m[1])) throw new ZetarisError("refused", `refused: tables must start with el_ (got ${m[1]})`);
    } else if ((m = sql.match(/^create\s+schemastore\s+container\s+([A-Za-z0-9_]+)/i))) {
      if (!/^el(_|$)/.test(m[1])) throw new ZetarisError("refused", `refused: containers must be el or start with el_ (got ${m[1]})`);
    } else if ((m = sql.match(/^create\s+schemastore\s+view\s+([A-Za-z0-9_]+)\s+with\s+container\s+([A-Za-z0-9_]+)/i))) {
      if (!/^el(_|$)/.test(m[2])) throw new ZetarisError("refused", `refused: views must live in container el or el_* (got ${m[2]})`);
    } else {
      throw new ZetarisError("refused", "refused: only CREATE LIGHTNING DATABASE/TABLE and SCHEMASTORE CONTAINER/VIEW are allowed");
    }
  }
}

function clip(s: string, n: number): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > n ? one.slice(0, n - 1) + "…" : one;
}

function cell(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

interface RawResult { headers: string[]; data: unknown[][]; total: number | null; serverMs: number | null; attempts: number; }

interface CacheFile { sql: string; sql_hash: string; label: string; saved_at: string; total: number | null; rows: Record<string, string>[]; }

// ---------- the client ----------
export class ZetarisClient {
  readonly restUrl: string;
  readonly tracer: Tracer | null;
  readonly cacheDir: string;
  readonly timeoutMs: number;
  readonly watchdogMs: number;
  readonly defaultLimit: number;
  readonly retryDelayMs: number;
  readonly queue: SerialQueue;
  #orgId: string;
  #apiKey: string;
  #fetch: typeof fetch;

  constructor(cfg: ZetarisClientConfig) {
    if (!cfg.restUrl) throw new Error("ZetarisClient: restUrl is required (ZETARIS_REST_URL)");
    if (!cfg.apiKey) throw new Error("ZetarisClient: apiKey is required (ZETARIS_API_KEY)");
    if (!cfg.orgId) throw new Error("ZetarisClient: orgId is required (ZETARIS_ORG_ID)");
    this.restUrl = cfg.restUrl.replace(/\/+$/, "");
    this.#orgId = cfg.orgId;
    this.#apiKey = cfg.apiKey;
    this.tracer = cfg.tracer ?? null;
    this.cacheDir = cfg.cacheDir ?? DEFAULT_CACHE_DIR;
    this.timeoutMs = cfg.timeoutMs ?? 60_000;
    this.watchdogMs = cfg.watchdogMs ?? 120_000;
    this.defaultLimit = cfg.defaultLimit ?? 10_000;
    this.retryDelayMs = cfg.retryDelayMs ?? 1_000;
    this.#fetch = cfg.fetchImpl ?? fetch;
    this.queue = cfg.queue ?? sharedQueue(this.restUrl);
  }

  /** The same connection (and queue) with another run's tracer. */
  withTracer(tracer: Tracer | null): ZetarisClient {
    return new ZetarisClient({
      restUrl: this.restUrl, orgId: this.#orgId, apiKey: this.#apiKey, tracer,
      cacheDir: this.cacheDir, timeoutMs: this.timeoutMs, watchdogMs: this.watchdogMs,
      defaultLimit: this.defaultLimit, retryDelayMs: this.retryDelayMs, fetchImpl: this.#fetch, queue: this.queue,
    });
  }

  toJSON(): Record<string, unknown> {
    return { restUrl: this.restUrl, timeoutMs: this.timeoutMs, watchdogMs: this.watchdogMs, cacheDir: this.cacheDir };
  }

  async query(sql: string, opts: QueryOptions = {}): Promise<QueryResult> {
    const stmt = cleanSql(sql);
    guardSql(stmt);
    const label = opts.label ?? "query";
    const mode: CacheMode = CACHEABLE.test(stmt) ? (opts.cache ?? "use") : "bypass";
    const hash = sqlHash(stmt);
    const limit = opts.limit ?? this.defaultLimit;
    const timeoutMs = opts.timeoutMs ?? this.timeoutMs;
    const queuedAt = performance.now();

    return this.queue.run(async () => {
      const queueMs = Math.round(performance.now() - queuedAt);
      const t0 = performance.now();
      const base = { label, sql_hash: hash, sql: clip(stmt, 2000), cache_mode: mode, queue_ms: queueMs, limit };
      try {
        const raw = await this.#execute(stmt, limit, timeoutMs);
        const ms = Math.round(performance.now() - t0);
        const rows = raw.data.map((r) => Object.fromEntries(raw.headers.map((h, i) => [h, cell(r[i])])));
        const truncated = raw.total !== null && raw.total > rows.length;
        if (mode !== "bypass") this.#writeCache({ sql: stmt, sql_hash: hash, label, saved_at: new Date().toISOString(), total: raw.total, rows });
        this.#emit({
          action: "sql_query", status: "ok", latency_ms: ms, retry_count: raw.attempts - 1,
          input_summary: `${label}: ${clip(stmt, 200)}`,
          output_summary: `${rows.length} row(s) in ${ms} ms${truncated ? ` (TRUNCATED: total ${raw.total})` : ""}`,
          details: { ...base, rows: rows.length, total: raw.total, truncated, ms, server_ms: raw.serverMs, fromCache: false },
        });
        return { rows, ms, fromCache: false, total: raw.total ?? rows.length };
      } catch (err) {
        const ms = Math.round(performance.now() - t0);
        const e = err instanceof ZetarisError ? err : new ZetarisError("network", (err as Error).message);
        if (mode === "use") {
          const cached = this.#readCache(hash);
          if (cached) {
            this.#emit({
              action: "sql_query", status: "fallback", latency_ms: ms, retry_count: e.attempts - 1,
              input_summary: `${label}: ${clip(stmt, 200)}`,
              output_summary: `live query failed (${e.kind}); served ${cached.rows.length} cached row(s) saved ${cached.saved_at}`,
              details: { ...base, rows: cached.rows.length, ms, fromCache: true, cached_at: cached.saved_at, error_kind: e.kind, http_status: e.status, error: clip(e.message, 300) },
            });
            return { rows: cached.rows, ms, fromCache: true, cachedAt: cached.saved_at };
          }
        }
        this.#emit({
          action: "sql_query", status: "error", latency_ms: ms, retry_count: e.attempts - 1,
          input_summary: `${label}: ${clip(stmt, 200)}`,
          output_summary: `failed (${e.kind}${e.status ? ` ${e.status}` : ""}): ${clip(e.message, 200)}`,
          details: { ...base, rows: 0, ms, fromCache: false, error_kind: e.kind, http_status: e.status, error: clip(e.message, 500), cache_hit_available: false },
        });
        throw e;
      }
    });
  }

  /** Run a CREATE statement. HTTP 400 + "already exists" counts as success (outcome "exists"). */
  async ddl(sql: string, opts: { label?: string; timeoutMs?: number } = {}): Promise<DdlResult> {
    const stmt = cleanSql(sql);
    guardSql(stmt);
    const label = opts.label ?? "ddl";
    const timeoutMs = opts.timeoutMs ?? this.timeoutMs;
    const queuedAt = performance.now();
    return this.queue.run(async () => {
      const queueMs = Math.round(performance.now() - queuedAt);
      const t0 = performance.now();
      const base = { label, sql_hash: sqlHash(stmt), sql: clip(stmt, 2000), queue_ms: queueMs, fromCache: false };
      try {
        const raw = await this.#execute(stmt, 1, timeoutMs);
        const ms = Math.round(performance.now() - t0);
        this.#emit({ action: "sql_ddl", status: "ok", latency_ms: ms, retry_count: raw.attempts - 1,
          input_summary: `${label}: ${clip(stmt, 200)}`, output_summary: `created in ${ms} ms`,
          details: { ...base, outcome: "created", ms, server_ms: raw.serverMs } });
        return { outcome: "created", ms };
      } catch (err) {
        const ms = Math.round(performance.now() - t0);
        if (isAlreadyExists(err)) {
          this.#emit({ action: "sql_ddl", status: "ok", latency_ms: ms,
            input_summary: `${label}: ${clip(stmt, 200)}`, output_summary: `already exists (ok) in ${ms} ms`,
            details: { ...base, outcome: "exists", ms } });
          return { outcome: "exists", ms };
        }
        const e = err instanceof ZetarisError ? err : new ZetarisError("network", (err as Error).message);
        this.#emit({ action: "sql_ddl", status: "error", latency_ms: ms, retry_count: e.attempts - 1,
          input_summary: `${label}: ${clip(stmt, 200)}`, output_summary: `failed (${e.kind}${e.status ? ` ${e.status}` : ""}): ${clip(e.message, 200)}`,
          details: { ...base, ms, error_kind: e.kind, http_status: e.status, error: clip(e.message, 500) } });
        throw e;
      }
    });
  }

  /** SELECT 1, live, short timeout. Never throws. */
  async health(timeoutMs = 10_000): Promise<{ ok: boolean; ms: number; error?: string }> {
    try {
      const r = await this.query("SELECT 1 AS ok", { cache: "bypass", label: "health", timeoutMs, limit: 1 });
      return { ok: r.rows.length === 1, ms: r.ms };
    } catch (err) {
      return { ok: false, ms: 0, error: (err as Error).message };
    }
  }

  // ---------- internals ----------
  async #execute(sql: string, limit: number, timeoutMs: number): Promise<RawResult> {
    const watchdog = new AbortController();
    const timer = setTimeout(() => watchdog.abort(), this.watchdogMs);
    let attempts = 0;
    try {
      for (;;) {
        attempts++;
        try {
          const r = await this.#attempt(sql, limit, timeoutMs, watchdog.signal);
          return { ...r, attempts };
        } catch (err) {
          let e = err as ZetarisError;
          if (watchdog.signal.aborted) e = new ZetarisError("watchdog", `watchdog fired after ${this.watchdogMs} ms`);
          e.attempts = attempts;
          if (e.kind === "network" && attempts < 2) {
            try { await delay(this.retryDelayMs, undefined, { signal: watchdog.signal }); }
            catch { throw new ZetarisError("watchdog", `watchdog fired after ${this.watchdogMs} ms`, null, attempts); }
            continue;
          }
          throw e;
        }
      }
    } finally {
      clearTimeout(timer);
    }
  }

  async #attempt(sql: string, limit: number, timeoutMs: number, watchdog: AbortSignal): Promise<Omit<RawResult, "attempts">> {
    const signal = AbortSignal.any([watchdog, AbortSignal.timeout(timeoutMs)]);
    const classify = (err: unknown): ZetarisError => {
      if (watchdog.aborted) return new ZetarisError("watchdog", `watchdog fired after ${this.watchdogMs} ms`);
      const name = (err as { name?: string })?.name;
      if (name === "TimeoutError" || name === "AbortError") return new ZetarisError("timeout", `no response within ${timeoutMs} ms`);
      const cause = (err as { cause?: { code?: string } })?.cause?.code;
      return new ZetarisError("network", `network error${cause ? ` (${cause})` : ""}: ${(err as Error)?.message ?? String(err)}`);
    };
    let res: Response;
    let text: string;
    try {
      res = await this.#fetch(`${this.restUrl}/sql-editor/sqls/run`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.#apiKey}`,
          "X-Org-ID": this.#orgId,
          "X-Request-ID": randomUUID(),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ queryId: randomUUID(), sql, source: "SqlEditor", limit }),
        signal,
      });
      text = await res.text();
    } catch (err) {
      throw classify(err);
    }
    let body: unknown = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = null; }
    if (res.status !== 200) {
      const msg = (body && typeof body === "object" && typeof (body as { msg?: unknown }).msg === "string")
        ? (body as { msg: string }).msg : text;
      throw new ZetarisError("http", `HTTP ${res.status}: ${clip(msg || res.statusText, 800)}`, res.status);
    }
    const b = body as { headers?: unknown; data?: unknown; total?: unknown; timeUsed?: unknown } | null;
    if (!b || !Array.isArray(b.headers) || !Array.isArray(b.data)) {
      throw new ZetarisError("bad_response", `unexpected response shape: ${clip(text, 200)}`, res.status);
    }
    const num = (v: unknown) => (v === null || v === undefined || v === "" || Number.isNaN(Number(v)) ? null : Number(v));
    return { headers: b.headers.map(cell), data: b.data as unknown[][], total: num(b.total), serverMs: num(b.timeUsed) };
  }

  #cachePath(hash: string): string { return join(this.cacheDir, `${hash}.json`); }

  #writeCache(c: CacheFile): void {
    try {
      mkdirSync(this.cacheDir, { recursive: true });
      const p = this.#cachePath(c.sql_hash);
      const tmp = `${p}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify(c));
      renameSync(tmp, p);
    } catch { /* a cache write failure never fails a query */ }
  }

  #readCache(hash: string): CacheFile | null {
    try {
      const c = JSON.parse(readFileSync(this.#cachePath(hash), "utf8")) as CacheFile;
      return Array.isArray(c.rows) ? c : null;
    } catch {
      return null;
    }
  }

  #emit(e: { action: string; status: "ok" | "error" | "fallback"; latency_ms: number; retry_count?: number;
    input_summary: string; output_summary: string; details: Record<string, unknown> }): void {
    this.tracer?.emit({ agent: "Zetaris", ...e });
  }
}
