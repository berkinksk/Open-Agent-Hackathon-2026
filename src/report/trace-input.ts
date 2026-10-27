// Reads trace events for the report. Pure (no IO): takes the JSONL text of logs/trace-<run_id>.jsonl.
// Tolerant: accepts both the TraceEvent field names (ts, agent) and the log-format names
// (timestamp, agent_name), and skips blank or malformed lines instead of failing the report.

import type { TraceEvent, TraceStatus } from "../contracts.ts";

function optStr(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function optNum(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/** Maps one parsed JSON object to a TraceEvent, or null when it has neither an agent nor an action. */
export function normaliseTraceEvent(o: unknown): TraceEvent | null {
  if (!o || typeof o !== "object" || Array.isArray(o)) return null;
  const x = o as Record<string, unknown>;
  const agent = optStr(x.agent) ?? optStr(x.agent_name) ?? "";
  const action = optStr(x.action) ?? "";
  if (!agent && !action) return null;
  const e: TraceEvent = {
    ts: optStr(x.ts) ?? optStr(x.timestamp) ?? "",
    run_id: optStr(x.run_id) ?? "",
    agent,
    action,
    status: (optStr(x.status) ?? "ok") as TraceStatus,
  };
  const s = (k: keyof TraceEvent, v: unknown) => { const t = optStr(v); if (t !== undefined) (e as unknown as Record<string, unknown>)[k] = t; };
  const n = (k: keyof TraceEvent, v: unknown) => { const t = optNum(v); if (t !== undefined) (e as unknown as Record<string, unknown>)[k] = t; };
  s("input_summary", x.input_summary);
  s("output_summary", x.output_summary);
  s("target_agent", x.target_agent);
  s("model", x.model);
  if (x.routed_model === null) e.routed_model = null; else s("routed_model", x.routed_model);
  if (x.receipt_id === null) e.receipt_id = null; else s("receipt_id", x.receipt_id);
  n("latency_ms", x.latency_ms);
  n("confidence", x.confidence);
  n("retry_count", x.retry_count);
  if (x.details && typeof x.details === "object" && !Array.isArray(x.details)) e.details = x.details as Record<string, unknown>;
  return e;
}

/** Parses JSONL text into trace events, skipping lines that are blank or not valid JSON. */
export function parseTraceJsonl(text: string): TraceEvent[] {
  const out: TraceEvent[] = [];
  for (const line of String(text ?? "").split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const e = normaliseTraceEvent(JSON.parse(t));
      if (e) out.push(e);
    } catch {
      // A torn or partial line (e.g. a run still writing) must not break the report.
    }
  }
  return out;
}
