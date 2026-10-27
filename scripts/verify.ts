// npm run verify: one command that checks the whole system, in order.
//   env         the required variables are set (names only; values are never printed)
//   zetaris     Zetaris REST answers SELECT 1
//   nightshift  Nightshift GET /v1/models answers 200 and lists the three pinned Nemotron models
//   views       SHOW LIGHTNING DATABASES finds the app's databases; LIMIT 1 on each <prefix>.* view
//   engine      npm run verify:engine (World Model conformance + idempotency checks)
//   tests       npm test (unit tests, run with the credentials removed from their environment)
//   receipts    every model call in the newest run trace that has model calls (logs/trace-*.jsonl, setup
//               traces ignored) has a receipt_id and a pinned routed_model. The trace is chosen and read
//               before the other checks run, so traces they write can't change it. In live mode, a chosen
//               trace with no completed model call FAILs. With no live trace in logs/ (a fresh clone), the
//               committed example traces (output_examples/*.trace.jsonl) are audited instead, labelled so.
// Each check prints PASS, FAIL or SKIP with a reason. In SAMPLE_MODE the live checks are skipped.
// The exit code is 1 if any check fails, 2 on a usage error.
//
// Options: --only <ids>  --skip <ids>  (comma-separated check ids, e.g. --skip tests)
//          --prefix <P>  (default: EL_PREFIX or EL_)   --trace <file>   --json   --help

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { MODELS } from "../src/contracts.ts";

export const CHECK_IDS = ["env", "zetaris", "nightshift", "views", "engine", "tests", "receipts"] as const;
export type CheckId = (typeof CHECK_IDS)[number];
export type CheckStatus = "PASS" | "FAIL" | "SKIP";
export interface CheckResult { id: CheckId; status: CheckStatus; detail: string; ms: number; tail?: string[]; }
export type Env = Record<string, string | undefined>;

export const ZETARIS_VARS = ["ZETARIS_REST_URL", "ZETARIS_ORG_ID", "ZETARIS_API_KEY"] as const;
export const NIGHTSHIFT_VARS = ["METERLESS_BASE_URL", "METERLESS_RUNTIME_TOKEN"] as const;
export const REQUIRED_VARS: readonly string[] = [...ZETARIS_VARS, ...NIGHTSHIFT_VARS];
export const SECRET_VARS = ["ZETARIS_API_KEY", "METERLESS_RUNTIME_TOKEN"] as const;
const URL_VARS = new Set(["ZETARIS_REST_URL", "METERLESS_BASE_URL"]);
const PINNED_IDS: readonly string[] = Object.values(MODELS);

export const DEFAULT_TIMEOUTS = { zetarisMs: 60_000, nightshiftMs: 30_000, engineMs: 120_000, testsMs: 600_000 };
export type Timeouts = typeof DEFAULT_TIMEOUTS;

// ---------------------------------------------------------------- small helpers

/** Same truthy values as the app's config (src/config.ts parseBool), so verify and the app agree on the mode. */
export function isSampleMode(env: Env): boolean {
  return /^(1|true|yes|y|on)$/i.test((env.SAMPLE_MODE ?? "").trim());
}

function clip(s: string, n = 200): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > n ? one.slice(0, n - 1) + "…" : one;
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

function msSince(t0: number): number {
  return Math.round(performance.now() - t0);
}

function fmtMs(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`;
}

/** Replaces every secret value (4+ characters) in a string with a fixed marker. */
export function redact(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const s of secrets) if (s.length >= 4) out = out.split(s).join("…redacted");
  return out;
}

export function secretValues(env: Env): string[] {
  return SECRET_VARS.map((n) => (env[n] ?? "").trim()).filter((v) => v.length >= 4);
}

function isPlaceholder(v: string): boolean {
  return /^(your[-_]|<|changeme|change[-_]me|replace[-_]?me|placeholder|xxx)/i.test(v);
}

function isHttpUrl(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function describeFetchError(err: unknown, timeoutMs: number): string {
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string } };
  if (e?.name === "TimeoutError" || e?.name === "AbortError") return `timed out after ${fmtMs(timeoutMs)}`;
  if (e?.cause?.code) return `cannot connect (${e.cause.code})`;
  return clip(e?.message ?? String(err), 160);
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- env

export interface EnvProblems { missing: string[]; placeholder: string[]; badUrl: string[]; }

/** Classifies the required variables by name. Never returns or prints a value. */
export function envProblems(env: Env): EnvProblems {
  const p: EnvProblems = { missing: [], placeholder: [], badUrl: [] };
  for (const name of REQUIRED_VARS) {
    const v = (env[name] ?? "").trim();
    if (!v) p.missing.push(name);
    else if (isPlaceholder(v)) p.placeholder.push(name);
    else if (URL_VARS.has(name) && !isHttpUrl(v)) p.badUrl.push(name);
  }
  return p;
}

function groupReady(p: EnvProblems, names: readonly string[]): boolean {
  return names.every((n) => !p.missing.includes(n) && !p.placeholder.includes(n) && !p.badUrl.includes(n));
}

export function checkEnv(env: Env): CheckResult {
  const sample = isSampleMode(env);
  const p = envProblems(env);
  const set = REQUIRED_VARS.length - p.missing.length;
  if (sample) {
    return { id: "env", status: "SKIP", ms: 0,
      detail: `sample mode: live credentials not needed (${set}/${REQUIRED_VARS.length} required variables set)` };
  }
  const parts: string[] = [];
  if (p.missing.length) parts.push(`missing: ${p.missing.join(", ")}`);
  if (p.placeholder.length) parts.push(`still a placeholder: ${p.placeholder.join(", ")}`);
  if (p.badUrl.length) parts.push(`not an http(s) URL: ${p.badUrl.join(", ")}`);
  if (parts.length) {
    return { id: "env", status: "FAIL", ms: 0,
      detail: `${parts.join("; ")} (copy .env.example to .env and fill it in, or set SAMPLE_MODE=true)` };
  }
  return { id: "env", status: "PASS", ms: 0, detail: `all ${REQUIRED_VARS.length} required variables set (values not shown)` };
}

// ---------------------------------------------------------------- Zetaris

export interface ZetarisCfg { url: string; apiKey: string; orgId: string; timeoutMs: number; fetchImpl: typeof fetch; }
export type SqlResult =
  | { ok: true; headers: string[]; data: unknown[][]; ms: number }
  | { ok: false; error: string; ms: number };

/** One Zetaris REST SQL call (callers run them one at a time). */
export async function zetarisSql(cfg: ZetarisCfg, sql: string, limit: number): Promise<SqlResult> {
  const t0 = performance.now();
  try {
    const res = await cfg.fetchImpl(`${trimSlash(cfg.url)}/sql-editor/sqls/run`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${cfg.apiKey}`,
        "X-Org-ID": cfg.orgId,
        "X-Request-ID": randomUUID(),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ queryId: randomUUID(), sql, source: "SqlEditor", limit }),
      signal: AbortSignal.timeout(cfg.timeoutMs),
    });
    const text = await res.text();
    const body = safeJson(text) as { headers?: unknown; data?: unknown; msg?: unknown } | null;
    if (res.status !== 200) {
      const msg = typeof body?.msg === "string" ? body.msg : text;
      return { ok: false, error: `HTTP ${res.status}${msg ? `: ${clip(msg, 160)}` : ""}`, ms: msSince(t0) };
    }
    if (!body || !Array.isArray(body.data)) return { ok: false, error: "HTTP 200 without a data array", ms: msSince(t0) };
    const headers = Array.isArray(body.headers) ? body.headers.map(String) : [];
    const data = body.data.filter((r): r is unknown[] => Array.isArray(r));
    return { ok: true, headers, data, ms: msSince(t0) };
  } catch (err) {
    return { ok: false, error: describeFetchError(err, cfg.timeoutMs), ms: msSince(t0) };
  }
}

export async function checkZetaris(cfg: ZetarisCfg): Promise<CheckResult> {
  const r = await zetarisSql(cfg, "SELECT 1 AS ok", 1);
  if (!r.ok) return { id: "zetaris", status: "FAIL", ms: r.ms, detail: `SELECT 1 failed: ${r.error}` };
  const v = r.data[0]?.[0];
  if (String(v) !== "1") return { id: "zetaris", status: "FAIL", ms: r.ms, detail: `SELECT 1 returned ${clip(JSON.stringify(v ?? null), 40)}` };
  return { id: "zetaris", status: "PASS", ms: r.ms, detail: `SELECT 1 → 1 in ${fmtMs(r.ms)}` };
}

/**
 * The objects npm run setup creates for a prefix (same rules as elNames in src/adapters/queries.ts):
 * EL_ → databases EL_INVENTORY, EL_KEV, EL_EPSS, EL_NVD and views el.inventory, el.kev;
 * EL_T1_ → EL_T1_* and el_t1.*. Prefixes outside the EL_ namespace are rejected (they also go into SQL).
 */
export function namesForPrefix(prefix: string): { databases: string[]; views: string[] } | null {
  if (!/^EL_([A-Z0-9]+_)*$/.test(prefix)) return null;
  const container = prefix.toLowerCase().replace(/_$/, "");
  return {
    databases: ["INVENTORY", "KEV", "EPSS", "NVD"].map((s) => prefix + s),
    views: [`${container}.inventory`, `${container}.kev`],
  };
}

/** Discovery, then LIMIT 1 on each registered view; strictly sequential. */
export async function checkViews(cfg: ZetarisCfg, prefix: string): Promise<CheckResult> {
  const t0 = performance.now();
  const names = namesForPrefix(prefix);
  if (!names) return { id: "views", status: "FAIL", ms: 0, detail: `invalid prefix "${clip(prefix, 30)}" (must look like EL_ or EL_T1_)` };
  const ok: string[] = [];
  const bad: string[] = [];

  const dbs = await zetarisSql(cfg, "SHOW LIGHTNING DATABASES", 1000);
  if (!dbs.ok) {
    bad.push(`SHOW LIGHTNING DATABASES: ${dbs.error}`);
  } else {
    const seen = new Set(dbs.data.flat().map((c) => String(c).trim().toUpperCase()));
    const missing = names.databases.filter((d) => !seen.has(d));
    if (missing.length) bad.push(`databases missing: ${missing.join(", ")} (run npm run setup)`);
    else ok.push(`databases ${names.databases.join(", ")} present`);
  }

  for (const view of names.views) {
    if (!dbs.ok && dbs.error.startsWith("timed out")) { bad.push(`${view}: not queried (Zetaris timed out)`); continue; }
    const r = await zetarisSql(cfg, `SELECT * FROM ${view} LIMIT 1`, 1);
    if (!r.ok) bad.push(`${view}: ${r.error}`);
    else if (r.data.length === 0) bad.push(`${view}: 0 rows (run npm run setup)`);
    else ok.push(`${view} 1 row in ${fmtMs(r.ms)}`);
  }
  if (bad.length) return { id: "views", status: "FAIL", ms: msSince(t0), detail: [...bad, ...ok].join("; ") };
  return { id: "views", status: "PASS", ms: msSince(t0), detail: ok.join("; ") };
}

// ---------------------------------------------------------------- Nightshift

export interface NightshiftCfg { baseUrl: string; token: string; timeoutMs: number; fetchImpl: typeof fetch; }

export async function checkNightshift(cfg: NightshiftCfg): Promise<CheckResult> {
  const t0 = performance.now();
  try {
    const res = await cfg.fetchImpl(`${trimSlash(cfg.baseUrl)}/models`, {
      method: "GET",
      headers: { Authorization: `Bearer ${cfg.token}`, "meterless-app": "exposureledger", "meterless-scope": "user" },
      signal: AbortSignal.timeout(cfg.timeoutMs),
    });
    const text = await res.text();
    const ms = msSince(t0);
    if (res.status === 401 || res.status === 403) {
      return { id: "nightshift", status: "FAIL", ms, detail: `GET /models → HTTP ${res.status}: token rejected (check METERLESS_RUNTIME_TOKEN)` };
    }
    if (res.status !== 200) return { id: "nightshift", status: "FAIL", ms, detail: `GET /models → HTTP ${res.status}` };
    const body = safeJson(text) as { data?: unknown } | null;
    const ids = Array.isArray(body?.data)
      ? body.data.map((m) => (m && typeof m === "object" ? String((m as { id?: unknown }).id ?? "") : "")).filter(Boolean)
      : [];
    const missing = PINNED_IDS.filter((id) => !ids.includes(id));
    if (missing.length) {
      return { id: "nightshift", status: "FAIL", ms, detail: `GET /models → 200, but pinned model(s) not listed: ${missing.join(", ")}` };
    }
    return { id: "nightshift", status: "PASS", ms,
      detail: `GET /models → 200 in ${fmtMs(ms)}; ${ids.length} models, all ${PINNED_IDS.length} pinned Nemotron IDs listed` };
  } catch (err) {
    return { id: "nightshift", status: "FAIL", ms: msSince(t0),
      detail: `cannot reach Nightshift: ${describeFetchError(err, cfg.timeoutMs)} (is the Nightshift app open?)` };
  }
}

// ---------------------------------------------------------------- sub-commands (engine checks, unit tests)

export interface CmdResult { code: number | null; output: string; ms: number; timedOut: boolean; }
export type Runner = (cmd: string, args: string[], opts: { cwd: string; env: Env; timeoutMs: number }) => Promise<CmdResult>;

export const spawnRunner: Runner = (cmd, args, opts) =>
  new Promise((resolve) => {
    const t0 = performance.now();
    let output = "";
    let timedOut = false;
    let done = false;
    const keep = (chunk: Buffer) => { output = (output + chunk.toString("utf8")).slice(-200_000); };
    const finish = (code: number | null, extra = "") => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(killer);
      resolve({ code, output: output + extra, ms: msSince(t0), timedOut });
    };
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env as Record<string, string>,
      shell: process.platform === "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    let killer: ReturnType<typeof setTimeout> | undefined;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      killer = setTimeout(() => child.kill("SIGKILL"), 5000);
    }, opts.timeoutMs);
    child.stdout?.on("data", keep);
    child.stderr?.on("data", keep);
    child.on("error", (err) => finish(null, `\n${err.message}`));
    child.on("close", (code) => finish(code));
  });

/** npm, invoked the way the current npm was (so `npm run verify` reuses the same npm), else from PATH. */
export function npmCommand(args: string[], env: Env): [string, string[]] {
  const execPath = env.npm_execpath ?? "";
  if (/npm-cli\.c?js$/.test(execPath)) return [process.execPath, [execPath, ...args]];
  return [process.platform === "win32" ? "npm.cmd" : "npm", args];
}

/** The environment for sub-commands: unit tests and engine checks never need live credentials. */
export function childEnv(env: Env): Env {
  const out: Env = { ...env };
  for (const n of SECRET_VARS) delete out[n];
  return out;
}

function lastLines(text: string, n: number): string[] {
  return text.split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim()).slice(-n);
}

/** Reads the summary counts of node --test (spec "ℹ pass N" or TAP "# pass N"). */
export function parseTestCounts(output: string): { pass: number; fail: number } | null {
  const last = (re: RegExp) => {
    const all = [...output.matchAll(re)];
    return all.length ? Number(all[all.length - 1][1]) : null;
  };
  const pass = last(/^\s*(?:#|ℹ)\s*pass\s+(\d+)\s*$/gm);
  const fail = last(/^\s*(?:#|ℹ)\s*fail\s+(\d+)\s*$/gm);
  return pass === null || fail === null ? null : { pass, fail };
}

export async function checkEngine(runner: Runner, root: string, env: Env, timeoutMs: number): Promise<CheckResult> {
  const [cmd, args] = npmCommand(["run", "--silent", "verify:engine"], env);
  const r = await runner(cmd, args, { cwd: root, env: childEnv(env), timeoutMs });
  const tail = lastLines(r.output, 15);
  if (r.timedOut) return { id: "engine", status: "FAIL", ms: r.ms, detail: `npm run verify:engine timed out after ${fmtMs(timeoutMs)}`, tail };
  if (r.code !== 0) return { id: "engine", status: "FAIL", ms: r.ms, detail: `npm run verify:engine exited ${r.code}`, tail };
  return { id: "engine", status: "PASS", ms: r.ms, detail: `${clip(tail[tail.length - 1] ?? "exit 0", 140)} (${fmtMs(r.ms)})` };
}

export async function checkTests(runner: Runner, root: string, env: Env, timeoutMs: number): Promise<CheckResult> {
  const [cmd, args] = npmCommand(["run", "--silent", "test"], env);
  const r = await runner(cmd, args, { cwd: root, env: childEnv(env), timeoutMs });
  const counts = parseTestCounts(r.output);
  const tail = lastLines(r.output, 20);
  if (r.timedOut) return { id: "tests", status: "FAIL", ms: r.ms, detail: `npm test timed out after ${fmtMs(timeoutMs)}`, tail };
  if (r.code !== 0 || (counts && counts.fail > 0)) {
    const c = counts ? `: ${counts.fail} failed, ${counts.pass} passed` : "";
    return { id: "tests", status: "FAIL", ms: r.ms, detail: `npm test exited ${r.code}${c}`, tail };
  }
  const c = counts ? `${counts.pass} passed, 0 failed` : "exit 0";
  return { id: "tests", status: "PASS", ms: r.ms, detail: `${c} (${fmtMs(r.ms)}; run without live credentials)` };
}

// ---------------------------------------------------------------- receipts

export interface ReceiptFailure { line: number; agent: string; action: string; problems: string[]; }
export interface ReceiptAudit {
  events: number; modelCalls: number; checked: number; exempt: number;
  byModel: Record<string, number>; failures: ReceiptFailure[]; badLines: number[];
}

/**
 * Which trace events are model calls: the ones whose `model` names a model, i.e. a MODELS key
 * ("bolt"), a pinned ID, or any provider/model ID containing "/" (e.g. "meterless/auto").
 * Values such as "normaliser" or "rules" are deterministic steps, not model calls.
 */
export function requestedModel(model: unknown): { isCall: boolean; pinnedId: string | null; raw: string } {
  if (typeof model !== "string" || !model.trim()) return { isCall: false, pinnedId: null, raw: "" };
  const m = model.trim();
  if (Object.hasOwn(MODELS, m)) return { isCall: true, pinnedId: MODELS[m as keyof typeof MODELS], raw: m };
  if (PINNED_IDS.includes(m)) return { isCall: true, pinnedId: m, raw: m };
  if (m.includes("/")) return { isCall: true, pinnedId: null, raw: m };
  return { isCall: false, pinnedId: null, raw: m };
}

/** Audits a trace (JSONL text). Calls whose status is error or fallback produced no receipt and are counted as exempt. */
export function auditReceipts(text: string): ReceiptAudit {
  const a: ReceiptAudit = { events: 0, modelCalls: 0, checked: 0, exempt: 0, byModel: {}, failures: [], badLines: [] };
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (!raw) continue;
    const e = safeJson(raw) as Record<string, unknown> | null;
    if (!e || typeof e !== "object" || Array.isArray(e)) { a.badLines.push(i + 1); continue; }
    a.events++;
    const req = requestedModel(e.model);
    if (!req.isCall) continue;
    a.modelCalls++;
    if (e.status === "error" || e.status === "fallback") { a.exempt++; continue; }
    a.checked++;
    const problems: string[] = [];
    if (!req.pinnedId) problems.push(`requested model "${clip(req.raw, 60)}" is not a pinned ID`);
    const rid = e.receipt_id;
    if (typeof rid !== "string" || !rid.trim()) problems.push("no receipt_id");
    const routed = e.routed_model;
    if (typeof routed !== "string" || !routed.trim()) problems.push("no routed_model");
    else if (!PINNED_IDS.includes(routed)) problems.push(`routed_model "${clip(routed, 60)}" is not a pinned model`);
    else if (req.pinnedId && routed !== req.pinnedId) problems.push(`requested ${req.pinnedId} but routed to ${routed}`);
    if (problems.length) {
      a.failures.push({ line: i + 1, agent: clip(String(e.agent ?? "?"), 40), action: clip(String(e.action ?? "?"), 40), problems });
    } else {
      a.byModel[routed as string] = (a.byModel[routed as string] ?? 0) + 1;
    }
  }
  return a;
}

export interface ReceiptsOptions {
  /** Live mode: a trace with no completed model call FAILs (nothing was proven); sample mode SKIPs it. */
  live?: boolean;
  /** How the trace was chosen; appended to the detail. */
  note?: string;
}

export function receiptsResult(file: string, a: ReceiptAudit, opts: ReceiptsOptions = {}): CheckResult {
  const name = path.basename(file);
  const note = opts.note ? ` [${opts.note}]` : "";
  const empty: CheckStatus = opts.live ? "FAIL" : "SKIP";
  if (a.badLines.length) {
    return { id: "receipts", status: "FAIL", ms: 0,
      detail: `${name}: ${a.badLines.length} line(s) are not JSON objects (lines ${a.badLines.slice(0, 5).join(", ")})${note}` };
  }
  if (a.failures.length) {
    return { id: "receipts", status: "FAIL", ms: 0,
      detail: `${name}: ${a.failures.length} of ${a.checked} model calls lack a valid receipt${note}`,
      tail: a.failures.slice(0, 8).map((f) => `line ${f.line} ${f.agent}/${f.action}: ${f.problems.join("; ")}`) };
  }
  if (a.modelCalls === 0) {
    const need = opts.live ? "; live mode needs the trace of a live run" : "";
    return { id: "receipts", status: empty, ms: 0,
      detail: `${name}: no model-call events, so no receipt was checked (setup and sample-mode traces make no model calls)${need}${note}` };
  }
  if (a.checked === 0) {
    const need = opts.live ? " (was Nightshift reachable? see the trace)" : "";
    return { id: "receipts", status: empty, ms: 0,
      detail: `${name}: all ${a.exempt} model call(s) failed, so there is no receipt to check${need}${note}` };
  }
  const keyOf = (id: string) => Object.entries(MODELS).find(([, v]) => v === id)?.[0] ?? id;
  const per = Object.entries(a.byModel).map(([id, n]) => `${keyOf(id)} ${n}`).join(", ");
  const ex = a.exempt ? `; ${a.exempt} failed call(s) had no receipt and were not counted` : "";
  return { id: "receipts", status: "PASS", ms: 0,
    detail: `${name}: ${a.checked}/${a.checked} model calls carry a receipt_id and a pinned routed_model (${per})${ex}${note}` };
}

/** Traces written by npm run setup: Zetaris DDL only, never a pipeline run, never a model call. */
export function isSetupTrace(name: string): boolean {
  return /^trace-setup-/.test(name);
}

/** The run traces in logsDir (trace-*.jsonl minus the setup traces), newest first by mtime. */
export function listRunTraces(logsDir: string): { files: string[]; setupIgnored: number } {
  let names: string[];
  try {
    names = readdirSync(logsDir);
  } catch {
    return { files: [], setupIgnored: 0 };
  }
  const traces = names.filter((n) => /^trace-.+\.jsonl$/.test(n));
  const files = traces
    .filter((n) => !isSetupTrace(n))
    .map((n) => {
      const p = path.join(logsDir, n);
      try { return { p, n, t: statSync(p).mtimeMs }; } catch { return null; }
    })
    .filter((x): x is { p: string; n: string; t: number } => x !== null)
    .sort((x, y) => y.t - x.t || y.n.localeCompare(x.n))
    .map((x) => x.p);
  return { files, setupIgnored: traces.filter(isSetupTrace).length };
}

export interface TracePick {
  /** The trace to audit, or null when no run trace has a model-call event. */
  file: string | null;
  /** Its audit, made once from the text read while picking. */
  audit: ReceiptAudit | null;
  /** Newer run traces without any model-call event (basenames), e.g. sample-mode runs. */
  passedOver: string[];
  setupIgnored: number;
  unreadable: string[];
  /** True when more run traces exist than were read. */
  capped: boolean;
}

/**
 * The trace whose receipts verify audits: the newest run trace that contains at least one
 * model-call event (failed calls count, so a run whose calls all failed is not hidden behind
 * an older good one). Setup traces are ignored; newer traces without model calls are passed over.
 */
export function pickTrace(logsDir: string, maxRead = 200): TracePick {
  const { files, setupIgnored } = listRunTraces(logsDir);
  const pick: TracePick = { file: null, audit: null, passedOver: [], setupIgnored, unreadable: [], capped: files.length > maxRead };
  for (const f of files.slice(0, maxRead)) {
    let text: string;
    try {
      text = readFileSync(f, "utf8");
    } catch {
      pick.unreadable.push(path.basename(f));
      continue;
    }
    const a = auditReceipts(text);
    if (a.modelCalls > 0) return { ...pick, file: f, audit: a, capped: false };
    pick.passedOver.push(path.basename(f));
  }
  return pick;
}

function pickNote(p: TracePick): string {
  const parts: string[] = [];
  if (p.passedOver.length) {
    const names = p.passedOver.slice(0, 3).join(", ") + (p.passedOver.length > 3 ? ", …" : "");
    parts.push(`${p.passedOver.length} ${p.file ? "newer " : ""}trace(s) without model calls skipped (${names})`);
  }
  if (p.setupIgnored) parts.push(`${p.setupIgnored} setup trace(s) ignored`);
  if (p.unreadable.length) parts.push(`${p.unreadable.length} unreadable: ${p.unreadable.slice(0, 3).join(", ")}`);
  if (p.capped) parts.push("only the newest 200 run traces were read");
  return parts.join("; ");
}

/** The committed example traces (output_examples/*.trace.jsonl), sorted by name. */
export function exampleTraces(root: string): string[] {
  const dir = path.join(root, "output_examples");
  try {
    return readdirSync(dir).filter((n) => /\.trace\.jsonl$/.test(n)).sort().map((n) => path.join(dir, n));
  } catch {
    return [];
  }
}

/**
 * The receipts check. With --trace it audits that file; otherwise the trace chosen by pickTrace; with no live trace
 * in logs/ (a fresh clone), the committed example traces, labelled as such.
 * The detail always names the audited file and says how it was chosen.
 */
export function checkReceipts(root: string, traceFile?: string, opts: { live?: boolean } = {}): CheckResult {
  const t0 = performance.now();
  const timed = (r: CheckResult): CheckResult => ({ ...r, ms: msSince(t0) });
  if (traceFile) {
    const file = path.resolve(root, traceFile);
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch (err) {
      return timed({ id: "receipts", status: "FAIL", ms: 0, detail: `cannot read ${path.basename(file)}: ${clip((err as Error).message, 120)}` });
    }
    return timed(receiptsResult(file, auditReceipts(text), { live: opts.live, note: "chosen with --trace" }));
  }
  const pick = pickTrace(path.join(root, "logs"));
  const how = pickNote(pick);
  if (!pick.file || !pick.audit) {
    // a fresh clone has no live trace yet: audit the committed example traces instead, and say so
    const examples = exampleTraces(root);
    if (examples.length) {
      const results = examples.map((f) => {
        let text = "";
        try { text = readFileSync(f, "utf8"); } catch { /* audited as empty, so it cannot pass */ }
        return receiptsResult(f, auditReceipts(text), { live: true });
      });
      const failed = results.filter((r) => r.status !== "PASS");
      const label = `no live trace in logs/ yet${how ? ` (${how})` : ""}, so the committed example traces in output_examples/ were audited instead`;
      return timed({
        id: "receipts", status: failed.length ? "FAIL" : "PASS", ms: 0,
        detail: `${label}: ${results.map((r) => r.detail.replace(/ carry a receipt_id and a pinned routed_model/, "")).join("; ")}; a live run writes its own trace (npm run cli, without --sample)`,
        ...(failed.length ? { tail: failed.flatMap((r) => r.tail ?? [r.detail]).slice(0, 8) } : {}),
      });
    }
    const hint = "a live run writes one (npm run cli, without --sample), then verify again";
    const detail = how
      ? `no run trace in logs/ has a model call, so no receipt was checked (${how}); ${hint}`
      : `no run trace in logs/ yet, so no receipt was checked; ${hint}`;
    return timed({ id: "receipts", status: "SKIP", ms: 0, detail });
  }
  const note = `the newest trace with model calls${how ? `; ${how}` : ""}`;
  return timed(receiptsResult(pick.file, pick.audit, { live: opts.live, note }));
}

// ---------------------------------------------------------------- orchestration

export interface VerifyOptions {
  env: Env; root: string; prefix?: string; only?: string[]; skip?: string[]; trace?: string;
  fetchImpl?: typeof fetch; runner?: Runner; print?: (line: string) => void; timeouts?: Partial<Timeouts>;
}

export function formatResult(r: CheckResult): string {
  const head = `${r.status.padEnd(4)}  ${r.id.padEnd(10)}  ${r.detail}`;
  return r.tail?.length ? [head, ...r.tail.map((l) => `        │ ${l}`)].join("\n") : head;
}

export async function runVerify(opts: VerifyOptions): Promise<CheckResult[]> {
  const env = opts.env;
  const sample = isSampleMode(env);
  const t: Timeouts = { ...DEFAULT_TIMEOUTS, ...opts.timeouts };
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  const runner = opts.runner ?? spawnRunner;
  const print = opts.print ?? ((l: string) => console.log(l));
  const secrets = secretValues(env);
  const prefix = opts.prefix ?? (env.EL_PREFIX?.trim() || "EL_");
  const results: CheckResult[] = [];

  const add = (r: CheckResult) => {
    const clean: CheckResult = { ...r, detail: redact(r.detail, secrets), tail: r.tail?.map((l) => redact(l, secrets)) };
    results.push(clean);
    print(formatResult(clean));
  };
  const selected = (id: CheckId) => (!opts.only?.length || opts.only.includes(id)) && !opts.skip?.includes(id);
  const skip = (id: CheckId, detail: string) => add({ id, status: "SKIP", ms: 0, detail });
  const statusOf = (id: CheckId) => results.find((r) => r.id === id)?.status;

  const p = envProblems(env);
  const zetarisReady = groupReady(p, ZETARIS_VARS);
  const nightshiftReady = groupReady(p, NIGHTSHIFT_VARS);
  const zcfg: ZetarisCfg = {
    url: (env.ZETARIS_REST_URL ?? "").trim(), apiKey: (env.ZETARIS_API_KEY ?? "").trim(),
    orgId: (env.ZETARIS_ORG_ID ?? "").trim(), timeoutMs: t.zetarisMs, fetchImpl,
  };

  // The receipts audit is taken first, on logs/ as it is now: the engine and test steps below
  // (and any setup or run in between) may write new trace files, which must not change what is audited.
  // Its result is printed in its place, as check 7.
  const receipts = selected("receipts") ? checkReceipts(opts.root, opts.trace, { live: !sample }) : null;

  // 1. env
  if (!selected("env")) skip("env", "not selected");
  else add(checkEnv(env));

  // 2. Zetaris SELECT 1
  if (!selected("zetaris")) skip("zetaris", "not selected");
  else if (sample) skip("zetaris", "sample mode: live check skipped");
  else if (!zetarisReady) skip("zetaris", "ZETARIS_* variables missing or invalid (see env)");
  else add(await checkZetaris(zcfg));

  // 3. Nightshift /v1/models
  if (!selected("nightshift")) skip("nightshift", "not selected");
  else if (sample) skip("nightshift", "sample mode: live check skipped");
  else if (!nightshiftReady) skip("nightshift", "METERLESS_* variables missing or invalid (see env)");
  else {
    add(await checkNightshift({ baseUrl: (env.METERLESS_BASE_URL ?? "").trim(),
      token: (env.METERLESS_RUNTIME_TOKEN ?? "").trim(), timeoutMs: t.nightshiftMs, fetchImpl }));
  }

  // 4. registered databases and LIMIT 1 per view
  if (!selected("views")) skip("views", "not selected");
  else if (sample) skip("views", "sample mode: live check skipped");
  else if (!zetarisReady) skip("views", "ZETARIS_* variables missing or invalid (see env)");
  else if (statusOf("zetaris") === "FAIL") skip("views", "Zetaris is not answering (see zetaris)");
  else add(await checkViews(zcfg, prefix));

  // 5. engine checks
  if (!selected("engine")) skip("engine", "not selected");
  else add(await checkEngine(runner, opts.root, env, t.engineMs));

  // 6. unit tests
  if (!selected("tests")) skip("tests", "not selected");
  else add(await checkTests(runner, opts.root, env, t.testsMs));

  // 7. receipts in the newest run trace with model calls (audited before step 1, see above)
  if (!receipts) skip("receipts", "not selected");
  else add(receipts);

  return results;
}

export function exitCode(results: CheckResult[]): number {
  return results.some((r) => r.status === "FAIL") ? 1 : 0;
}

export function summaryLine(results: CheckResult[]): string {
  const n = (s: CheckStatus) => results.filter((r) => r.status === s).length;
  return `verify: ${n("PASS")} passed, ${n("FAIL")} failed, ${n("SKIP")} skipped → ${exitCode(results) ? "FAILED" : "OK"}`;
}

const USAGE = `usage: npm run verify [-- [--only <ids>] [--skip <ids>] [--prefix EL_] [--trace <file>] [--json]]
check ids: ${CHECK_IDS.join(", ")}`;

function parseIds(v: string | undefined): string[] | undefined | Error {
  if (v === undefined) return undefined;
  const ids = v.split(",").map((s) => s.trim()).filter(Boolean);
  const unknown = ids.filter((id) => !(CHECK_IDS as readonly string[]).includes(id));
  return unknown.length ? new Error(`unknown check id(s): ${unknown.join(", ")}`) : ids;
}

async function main(): Promise<number> {
  let values: { only?: string; skip?: string; prefix?: string; trace?: string; json?: boolean; help?: boolean };
  try {
    ({ values } = parseArgs({
      options: {
        only: { type: "string" }, skip: { type: "string" }, prefix: { type: "string" },
        trace: { type: "string" }, json: { type: "boolean" }, help: { type: "boolean", short: "h" },
      },
      allowPositionals: false,
    }));
  } catch (err) {
    console.error(`${(err as Error).message}\n${USAGE}`);
    return 2;
  }
  if (values.help) { console.log(USAGE); return 0; }
  const only = parseIds(values.only);
  const skip = parseIds(values.skip);
  for (const v of [only, skip]) if (v instanceof Error) { console.error(`${v.message}\n${USAGE}`); return 2; }

  const env = process.env as Env;
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const json = Boolean(values.json);
  const prefix = values.prefix ?? (env.EL_PREFIX?.trim() || "EL_");
  if (!json) console.log(`verify (mode: ${isSampleMode(env) ? "sample" : "live"}, prefix: ${prefix})`);
  const results = await runVerify({
    env, root, prefix, trace: values.trace,
    only: only as string[] | undefined, skip: skip as string[] | undefined,
    print: json ? () => {} : undefined,
  });
  if (json) {
    console.log(JSON.stringify({ ok: exitCode(results) === 0, mode: isSampleMode(env) ? "sample" : "live", prefix, results }, null, 2));
  } else {
    console.log(summaryLine(results));
  }
  return exitCode(results);
}

if (import.meta.main) {
  main().then(
    (code) => { process.exitCode = code; },
    (err) => {
      console.error(`verify: internal error: ${redact(String((err as Error)?.stack ?? err), secretValues(process.env as Env))}`);
      process.exitCode = 2;
    },
  );
}
