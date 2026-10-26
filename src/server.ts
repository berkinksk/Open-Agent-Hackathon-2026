// HTTP entry point (node:http), bound to 0.0.0.0:$PORT (default 8000).
//   POST /run          body RunRequest -> RunResponse JSON, or a structured error JSON
//   GET  /health       liveness + which settings are missing (names only)
//   GET  /report/:id   output/report-<id>.html if it exists, else 404
// Runs are processed one at a time (Zetaris takes one query at a time anyway).
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Deps, InventoryRow, Mode, Policy, RunRequest, RunResponse } from "./contracts.ts";
import { ConfigError, REPO_ROOT, checkConfig, isSafeId, loadConfig, parseBool } from "./config.ts";

export type RunFn = (req: RunRequest, deps: Deps) => Promise<RunResponse>;
export type MakeDepsFn = (opts: { mode: Mode; runId?: string; policy?: Partial<Policy> }) => Deps;

export const DEFAULT_OUTPUT_DIR = join(REPO_ROOT, "output");
export const MAX_ROWS = 500;
export const MAX_BODY_BYTES = 2 * 1024 * 1024;
export const RUN_TIMEOUT_MS = 10 * 60 * 1000;

// ---------- request validation (shared with the CLI) ----------
export class RequestError extends Error {
  constructor(message: string) { super(message); this.name = "RequestError"; }
}

function asString(v: unknown, field: string, max = 500): string {
  if (v === undefined || v === null) return "";
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (typeof v !== "string") throw new RequestError(`${field} must be a string`);
  if (v.length > max) throw new RequestError(`${field} is longer than ${max} characters`);
  return v;
}

/** Validate and normalise a run request. A bare array is taken as the inventory.
 *  Inventory rows need only `software`; other fields get neutral defaults. */
export function normaliseRunRequest(body: unknown): RunRequest {
  if (Array.isArray(body)) body = { inventory: body };
  if (!body || typeof body !== "object") throw new RequestError("the body must be a JSON object (a RunRequest)");
  const b = body as Record<string, unknown>;
  const out: RunRequest = {};

  if (b.run_id !== undefined && b.run_id !== null && b.run_id !== "") {
    if (typeof b.run_id !== "string" || !isSafeId(b.run_id)) throw new RequestError("run_id must use only letters, digits, '-' and '_' (max 80 characters)");
    out.run_id = b.run_id;
  }
  if (b.sample_mode !== undefined && b.sample_mode !== null) {
    if (typeof b.sample_mode === "boolean") out.sample_mode = b.sample_mode;
    else if (typeof b.sample_mode === "string") out.sample_mode = parseBool(b.sample_mode);
    else throw new RequestError("sample_mode must be a boolean");
  }
  if (b.inventory !== undefined && b.inventory !== null) {
    if (!Array.isArray(b.inventory)) throw new RequestError("inventory must be an array of rows");
    if (b.inventory.length === 0) throw new RequestError("inventory is empty");
    if (b.inventory.length > MAX_ROWS) throw new RequestError(`inventory has ${b.inventory.length} rows; the limit is ${MAX_ROWS}`);
    const seen = new Set<string>();
    out.inventory = b.inventory.map((raw, i): InventoryRow => {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new RequestError(`inventory[${i}] must be an object`);
      const r = raw as Record<string, unknown>;
      const software = asString(r.software, `inventory[${i}].software`).trim();
      if (!software) throw new RequestError(`inventory[${i}].software is required`);
      const row_id = asString(r.row_id, `inventory[${i}].row_id`, 80).trim() || `R${String(i + 1).padStart(3, "0")}`;
      if (seen.has(row_id)) throw new RequestError(`duplicate row_id ${row_id}`);
      seen.add(row_id);
      const asset_id = asString(r.asset_id, `inventory[${i}].asset_id`, 120).trim() || `asset-${row_id}`;
      const net = r.internet_facing;
      if (net !== undefined && net !== null && typeof net !== "boolean" && typeof net !== "string" && typeof net !== "number") {
        throw new RequestError(`inventory[${i}].internet_facing must be a boolean`);
      }
      return {
        row_id,
        asset_id,
        asset_name: asString(r.asset_name, `inventory[${i}].asset_name`, 200).trim() || asset_id,
        asset_type: asString(r.asset_type, `inventory[${i}].asset_type`, 120).trim() || "unknown",
        internet_facing: typeof net === "boolean" ? net : typeof net === "number" ? net === 1 : parseBool(net as string | undefined),
        owner_team: asString(r.owner_team, `inventory[${i}].owner_team`, 200).trim(),
        software,
      };
    });
  }
  if (b.row_ids !== undefined && b.row_ids !== null) {
    if (!Array.isArray(b.row_ids) || b.row_ids.some((x) => typeof x !== "string")) throw new RequestError("row_ids must be an array of strings");
    if (b.row_ids.length > 2000) throw new RequestError("row_ids is too long");
    out.row_ids = (b.row_ids as string[]).map((s) => s.trim()).filter(Boolean);
  }
  if (b.policy !== undefined && b.policy !== null) {
    if (typeof b.policy !== "object" || Array.isArray(b.policy)) throw new RequestError("policy must be an object");
    out.policy = b.policy as Partial<Policy>;
  }
  return out;
}

// ---------- output ----------
/** Write output/run-<id>.json atomically; returns the path. */
export function saveRunFile(resp: RunResponse, outputDir = DEFAULT_OUTPUT_DIR): string | null {
  if (!resp || typeof resp.run_id !== "string" || !isSafeId(resp.run_id)) return null;
  mkdirSync(outputDir, { recursive: true });
  const p = join(outputDir, `run-${resp.run_id}.json`);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(resp, null, 2) + "\n");
  renameSync(tmp, p);
  return p;
}

export interface ErrorBody {
  run_id: string | null; status: "error"; mode: Mode | null;
  error: { type: string; message: string; recoverable: boolean };
  trace_file: string | null;
}

/** Map a thrown error to an HTTP status and a structured body. */
export function errorResponse(err: unknown, ctx: { runId?: string | null; mode?: Mode | null; traceFile?: string | null } = {}): { code: number; body: ErrorBody } {
  const e = err as Error & { code?: string; missing?: string[] };
  let code = 500;
  let type = e?.name && e.name !== "Error" ? e.name : "InternalError";
  let recoverable = false;
  if (err instanceof RequestError) { code = 400; type = "BadRequest"; }
  else if (err instanceof ConfigError) {
    const unavailable = (e.missing?.length ?? 0) > 0 || /not present yet/.test(e.message);
    code = unavailable ? 503 : 400;
    type = "ConfigError";
    recoverable = unavailable;
  } else if (e?.name === "RunTimeout") { code = 504; recoverable = true; }
  else if (e?.name === "PipelineUnavailable") { code = 503; recoverable = true; }
  const message = String(e?.message ?? err).slice(0, 1000);
  return {
    code,
    body: { run_id: ctx.runId ?? null, status: "error", mode: ctx.mode ?? null, error: { type, message, recoverable }, trace_file: ctx.traceFile ?? null },
  };
}

// ---------- the app ----------
export interface AppOptions {
  run: RunFn;
  makeDeps: MakeDepsFn;
  outputDir?: string;
  forceSample?: boolean;           // SAMPLE_MODE=true: every run is a sample run
  runTimeoutMs?: number;
  maxBodyBytes?: number;
  env?: Record<string, string | undefined>;
  log?: (line: string) => void;
}

function sendJson(res: ServerResponse, code: number, body: unknown, extra: Record<string, string> = {}): void {
  const s = JSON.stringify(body, null, 2) + "\n";
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(s), ...extra });
  res.end(s);
}

function readBody(req: IncomingMessage, max: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) { reject(Object.assign(new RequestError(`request body larger than ${max} bytes`), { tooLarge: true })); req.resume(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export function createApp(opts: AppOptions): Server & { busy(): number } {
  const outputDir = opts.outputDir ?? DEFAULT_OUTPUT_DIR;
  const runTimeoutMs = opts.runTimeoutMs ?? RUN_TIMEOUT_MS;
  const maxBody = opts.maxBodyBytes ?? MAX_BODY_BYTES;
  const log = opts.log ?? ((l: string) => console.log(l));
  const startedAt = Date.now();
  let lock: Promise<void> = Promise.resolve();
  let inFlight = 0;

  /** One run at a time. Resolves once the run STARTS, with its promise wrapped in an object (a bare
   *  promise would be adopted, i.e. awaited). The lock is held until the run really ends, even if
   *  the HTTP reply has already timed out. */
  function startSerialised<T>(fn: () => Promise<T>): Promise<{ work: Promise<T> }> {
    return new Promise<{ work: Promise<T> }>((started, failed) => {
      lock = lock.then(async () => {
        let work: Promise<T>;
        try { work = fn(); } catch (e) { failed(e); return; }
        started({ work });
        await work.then(() => undefined, () => undefined);
      });
    });
  }

  async function handleRun(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let runReq: RunRequest;
    try {
      const text = await readBody(req, maxBody);
      let parsed: unknown;
      try { parsed = text.trim() ? JSON.parse(text) : {}; } catch { throw new RequestError("the body is not valid JSON"); }
      runReq = normaliseRunRequest(parsed);
    } catch (err) {
      const tooLarge = (err as { tooLarge?: boolean }).tooLarge;
      const { code, body } = errorResponse(err);
      sendJson(res, tooLarge ? 413 : code, body);
      return;
    }
    const mode: Mode = opts.forceSample || runReq.sample_mode === true ? "sample" : "live";
    inFlight++;
    let deps: Deps | null = null;
    try {
      const { work } = await startSerialised(() => {
        const dd = opts.makeDeps({ mode, runId: runReq.run_id, policy: runReq.policy });
        deps = dd;
        return opts.run({ ...runReq, run_id: dd.tracer.run_id, sample_mode: mode === "sample" }, dd);
      });
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error(`run exceeded ${Math.round(runTimeoutMs / 1000)} s`), { name: "RunTimeout" })), runTimeoutMs);
      });
      let resp: RunResponse;
      try { resp = await Promise.race([work, timeout]); } finally { clearTimeout(timer); }
      try { saveRunFile(resp, outputDir); } catch (e) { log(`[WARN] could not save run file: ${(e as Error).message}`); }
      sendJson(res, resp.status === "error" ? 500 : 200, resp);
    } catch (err) {
      const d = deps as Deps | null;
      const { code, body } = errorResponse(err, { runId: d?.tracer.run_id ?? runReq.run_id ?? null, mode, traceFile: d?.tracer.file || null });
      d?.tracer.emit({ agent: "Server", action: "run_failed", status: "error", output_summary: `${body.error.type}: ${body.error.message.slice(0, 200)}` });
      sendJson(res, code, body);
    } finally {
      inFlight--;
    }
  }

  function handleReport(id: string, res: ServerResponse): void {
    if (!isSafeId(id)) { sendJson(res, 400, { status: "error", error: { type: "BadRequest", message: "invalid run id", recoverable: false } }); return; }
    const p = join(outputDir, `report-${id}.html`);
    if (!existsSync(p)) { sendJson(res, 404, { status: "error", error: { type: "NotFound", message: `no report for run ${id}`, recoverable: false } }); return; }
    const html = readFileSync(p);
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": html.length });
    res.end(html);
  }

  function handleHealth(res: ServerResponse): void {
    const cfg = loadConfig(opts.env ?? process.env);
    const mode: Mode = opts.forceSample ? "sample" : "live";
    const c = checkConfig(cfg, mode);
    sendJson(res, 200, {
      status: "ok",
      mode,
      busy: inFlight,
      uptime_s: Math.round((Date.now() - startedAt) / 1000),
      config: { ok: c.ok, missing: c.missing, invalid: c.invalid },
    });
  }

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = req.method ?? "GET";
    const done = (p: Promise<void> | void) => Promise.resolve(p).catch((err) => {
      const { code, body } = errorResponse(err);
      if (!res.headersSent) sendJson(res, code, body); else res.end();
    });
    if (path === "/run") {
      if (method !== "POST") return sendJson(res, 405, { status: "error", error: { type: "MethodNotAllowed", message: "use POST /run", recoverable: false } }, { Allow: "POST" });
      return void done(handleRun(req, res));
    }
    if (path === "/health") {
      if (method !== "GET" && method !== "HEAD") return sendJson(res, 405, { status: "error", error: { type: "MethodNotAllowed", message: "use GET /health", recoverable: false } }, { Allow: "GET" });
      return void done(handleHealth(res));
    }
    const m = path.match(/^\/report\/([^/]+)$/);
    if (m) {
      if (method !== "GET") return sendJson(res, 405, { status: "error", error: { type: "MethodNotAllowed", message: "use GET /report/:id", recoverable: false } }, { Allow: "GET" });
      let id = m[1];
      try { id = decodeURIComponent(id); } catch { /* keep raw; it will fail validation */ }
      return void done(handleReport(id.replace(/\.html$/, ""), res));
    }
    if (path === "/" && method === "GET") {
      return sendJson(res, 200, {
        name: "exposureledger",
        endpoints: { "POST /run": "RunRequest -> RunResponse", "GET /health": "liveness", "GET /report/:run_id": "HTML report" },
      });
    }
    sendJson(res, 404, { status: "error", error: { type: "NotFound", message: `no route ${method} ${path}`, recoverable: false } });
  });

  return Object.assign(server, { busy: () => inFlight });
}

/** The real pipeline, loaded on first use so the server can start (and answer /health) before it exists. */
export const lazyRun: RunFn = async (req, deps) => {
  let mod: { run: RunFn };
  try {
    mod = (await import("./run.ts")) as { run: RunFn };
  } catch (e) {
    const err = e as { code?: string; message?: string };
    if (err?.code === "ERR_MODULE_NOT_FOUND" && String(err.message ?? "").includes("run.ts")) {
      throw Object.assign(new Error("the pipeline (src/run.ts) is not present yet"), { name: "PipelineUnavailable" });
    }
    throw e;
  }
  return mod.run(req, deps);
};

async function main(): Promise<void> {
  const cfg = loadConfig();
  const mode: Mode = cfg.sampleMode ? "sample" : "live";
  const c = checkConfig(cfg, mode);
  if (c.invalid.some((s) => s.startsWith("PORT"))) {
    console.error("[ERROR] PORT must be an integer 1-65535");
    process.exitCode = 2;
    return;
  }
  if (!c.ok) console.log(`[WARN] configuration incomplete for ${mode} mode: ${[...c.missing.map((m) => `missing ${m}`), ...c.invalid].join("; ")}`);
  const { makeDeps } = await import("./deps.ts");
  const server = createApp({ run: lazyRun, makeDeps: (o) => makeDeps(o), forceSample: cfg.sampleMode });
  server.listen(cfg.port, "0.0.0.0", () => {
    console.log(`[INFO] exposureledger listening on http://0.0.0.0:${cfg.port} (mode=${mode}); POST /run, GET /health, GET /report/:id`);
  });
  const stop = () => { console.log("[INFO] shutting down"); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 5000).unref(); };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (import.meta.main) await main();
