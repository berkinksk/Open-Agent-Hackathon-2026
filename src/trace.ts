// JSONL trace: one line per event in logs/trace-<run_id>.jsonl, plus a readable stdout line.
// Each line carries the contract fields (ts, agent, ...) and the judges' recommended aliases
// (timestamp, agent_name). Known secret values and bearer tokens are scrubbed before writing.
import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { TraceEvent, TraceStatus, Tracer } from "./contracts.ts";
import { REPO_ROOT, isSafeId, secretValues } from "./config.ts";

export const DEFAULT_LOG_DIR = join(REPO_ROOT, "logs");

export interface TracerOptions {
  dir?: string;
  stdout?: boolean;
  /** Extra literal values to scrub (tests); env secrets are always scrubbed. */
  redact?: string[];
  /** Where readable lines go (tests). Defaults to console.log. */
  print?: (line: string) => void;
}

const BEARER = /(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi;

export function makeRedactor(values: string[]): (s: string) => string {
  const vals = [...new Set(values.filter((v) => v && v.length >= 6))].sort((a, b) => b.length - a.length);
  return (s: string) => {
    let out = s.replace(BEARER, "$1***redacted");
    for (const v of vals) out = out.split(v).join("***redacted");
    return out;
  };
}

function level(status: TraceStatus): string {
  if (status === "error") return "ERROR";
  if (status === "ok") return "INFO";
  return "WARN"; // fallback, blocked, sent_back
}

function clip(s: string | undefined, n: number): string {
  if (!s) return "";
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > n ? one.slice(0, n - 1) + "…" : one;
}

/** The readable stdout form of one event. */
export function formatLine(e: TraceEvent): string {
  const parts = [`[${level(e.status)}]`, `run_id=${e.run_id}`, e.agent, e.action, e.status];
  if (e.target_agent) parts.push(`-> ${e.target_agent}`);
  if (e.model) parts.push(`model=${e.model}`);
  if (e.routed_model && e.routed_model !== e.model) parts.push(`routed=${e.routed_model}`);
  if (e.receipt_id) parts.push(`receipt=${e.receipt_id}`);
  if (typeof e.latency_ms === "number") parts.push(`${Math.round(e.latency_ms)}ms`);
  if (e.retry_count) parts.push(`retry=${e.retry_count}`);
  const out = clip(e.output_summary, 160);
  if (out) parts.push(`| ${out}`);
  return parts.join(" ");
}

export function createTracer(runId: string, opts: TracerOptions = {}): Tracer {
  if (!isSafeId(runId)) throw new Error(`unsafe run id for a file name: ${JSON.stringify(runId).slice(0, 40)}`);
  const dir = opts.dir ?? DEFAULT_LOG_DIR;
  const file = join(dir, `trace-${runId}.jsonl`);
  const toStdout = opts.stdout ?? true;
  const print = opts.print ?? ((l: string) => console.log(l));
  const redact = makeRedactor([...secretValues(), ...(opts.redact ?? [])]);
  let dirReady = false;
  let warned = false;

  return {
    run_id: runId,
    file,
    emit(e: Omit<TraceEvent, "ts" | "run_id">): void {
      // Logging must never break a run: every failure here is swallowed after one warning.
      try {
        const ts = new Date().toISOString();
        const event = { ts, run_id: runId, ...e } as TraceEvent;
        const line = { ts, timestamp: ts, run_id: runId, agent: e.agent, agent_name: e.agent, ...e };
        const json = redact(JSON.stringify(line));
        if (!dirReady) { mkdirSync(dir, { recursive: true }); dirReady = true; }
        appendFileSync(file, json + "\n", "utf8");
        if (toStdout) print(redact(formatLine(event)));
      } catch (err) {
        if (!warned) {
          warned = true;
          console.error(`[WARN] trace write failed for run ${runId}: ${(err as Error).message}`);
        }
      }
    },
  };
}

/** A tracer that drops everything (tests, or tools that must stay silent). */
export function nullTracer(runId = "null"): Tracer {
  return { run_id: runId, file: "", emit() {} };
}

/** A tracer that keeps events in memory (tests). */
export function memoryTracer(runId = "mem"): Tracer & { events: TraceEvent[] } {
  const events: TraceEvent[] = [];
  return {
    run_id: runId,
    file: "",
    events,
    emit(e) { events.push({ ts: new Date().toISOString(), run_id: runId, ...e } as TraceEvent); },
  };
}
