// Report entry points with file IO. The rendering itself is pure (render.ts).
// - writeReport(resp): renders output/report-<run_id>.html (with the run's trace when it exists).
// - loadReportHtml(runId): what GET /report/<run_id> serves; it rejects unsafe run IDs (no path traversal).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { RunResponse, TraceEvent } from "../contracts.ts";
import { renderReport } from "./render.ts";
import { parseTraceJsonl } from "./trace-input.ts";

export { renderReport, esc, maskCredentials } from "./render.ts";
export type { RenderOptions } from "./render.ts";
export { parseTraceJsonl, normaliseTraceEvent } from "./trace-input.ts";

const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** True for run IDs that are safe to use in a file name (letters, digits, '.', '_', '-'; no leading dot; no '..'). */
export function isSafeRunId(id: unknown): id is string {
  return typeof id === "string" && RUN_ID_RE.test(id) && !id.includes("..");
}

/** Reads a trace JSONL file; a missing or unreadable file gives []. */
export function loadTrace(file: string): TraceEvent[] {
  try {
    return existsSync(file) ? parseTraceJsonl(readFileSync(file, "utf8")) : [];
  } catch {
    return [];
  }
}

export function reportFileName(runId: string): string {
  if (!isSafeRunId(runId)) throw new Error(`unsafe run_id for a file name: ${JSON.stringify(String(runId).slice(0, 80))}`);
  return `report-${runId}.html`;
}

/**
 * Renders the report and writes it to <dir>/report-<run_id>.html. Returns the path written.
 * trace: events to include; when omitted, resp.trace_file is read if it exists (no trace if it does not).
 */
export function writeReport(resp: RunResponse, opts: { dir?: string; trace?: TraceEvent[] } = {}): string {
  const dir = opts.dir ?? "output";
  const file = join(dir, reportFileName(resp.run_id));
  const trace = opts.trace ?? (resp.trace_file && existsSync(resp.trace_file) ? loadTrace(resp.trace_file) : undefined);
  mkdirSync(dir, { recursive: true });
  writeFileSync(file, renderReport(resp, { trace }), "utf8");
  return file;
}

/**
 * The HTML for GET /report/<run_id>, or null when the ID is unsafe or the run is unknown.
 * Prefers the saved report file; otherwise renders from <outputDir>/run-<run_id>.json, with
 * <logsDir>/trace-<run_id>.jsonl when present. Paths come from the validated ID, never from the run JSON.
 */
export function loadReportHtml(runId: unknown, opts: { outputDir?: string; logsDir?: string } = {}): string | null {
  if (!isSafeRunId(runId)) return null;
  const outputDir = resolve(opts.outputDir ?? "output");
  const logsDir = resolve(opts.logsDir ?? "logs");
  const html = join(outputDir, `report-${runId}.html`);
  try {
    if (existsSync(html)) return readFileSync(html, "utf8");
    const json = join(outputDir, `run-${runId}.json`);
    if (!existsSync(json)) return null;
    const resp = JSON.parse(readFileSync(json, "utf8")) as RunResponse;
    const tracePath = join(logsDir, `trace-${runId}.jsonl`);
    return renderReport(resp, { trace: existsSync(tracePath) ? loadTrace(tracePath) : undefined });
  } catch {
    return null;
  }
}
