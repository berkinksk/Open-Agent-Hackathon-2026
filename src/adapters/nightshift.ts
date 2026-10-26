// Nightshift client: the Meterless local runtime's OpenAI-compatible chat endpoint.
// Pinned Nemotron models only, thinking switched off for Lightning and Ultra, JSON mode on request,
// a 90 s timeout per attempt, at most 2 retries (backoff 2 s, 4 s, 8 s) on 429 / 5xx / network errors,
// a concurrency cap shared by every client of the same runtime, and a receipt for every call.
//
// chat() does not throw for transport or model failures: it returns { text: "", json: null } with
// receipt.status "error", so a caller can degrade (abstain, fall back) and still log the failed call.
// It throws only for programming errors (an unknown model key).
import { randomUUID } from "node:crypto";
import { MODELS } from "../contracts.ts";
import type { ChatRequest, ChatResult, Llm, ModelKey, Receipt, Tracer } from "../contracts.ts";

export interface NightshiftConfig {
  baseUrl: string;            // e.g. http://127.0.0.1:8088/v1
  token: string;              // METERLESS_RUNTIME_TOKEN; never logged
  app: string;                // stable lowercase id sent as `meterless-app`
  concurrency: number;        // shared cap per runtime URL, clamped to 1..4
  tracer: Tracer;
  timeoutMs?: number;         // per attempt; default 90 000
  maxRetries?: number;        // default 2
  backoffMs?: number[];       // default [2000, 4000, 8000]
  fetchImpl?: typeof fetch;   // tests and call counters
}

export const DEFAULT_TIMEOUT_MS = 90_000;
export const DEFAULT_MAX_RETRIES = 2;
export const DEFAULT_BACKOFF_MS = [2000, 4000, 8000];
export const MAX_CONCURRENCY = 4;
export const DEFAULT_MAX_TOKENS: Record<ModelKey, number> = { bolt: 1500, lightning: 1500, ultra: 2000 };

/** Models that need `chat_template_kwargs: {enable_thinking: false}` (Lightning returns 502 without it). */
const THINKING_SWITCH: ReadonlySet<ModelKey> = new Set<ModelKey>(["lightning", "ultra"]);

// ---------------------------------------------------------------- request body

/**
 * The JSON body for one chat completion. A unique request id is appended to the user message
 * (it ties the prompt to the receipt and defeats any response cache). `reasoning_budget` is
 * never sent: Nightshift rejects it.
 */
export function buildChatBody(req: ChatRequest, requestId: string): Record<string, unknown> {
  if (!Object.hasOwn(MODELS, req.model)) throw new Error(`unknown model key: ${String(req.model)}`);
  const messages: { role: "system" | "user"; content: string }[] = [];
  if (req.system) messages.push({ role: "system", content: req.system });
  messages.push({ role: "user", content: `${req.user}\n\nRequest id: ${requestId}` });
  const body: Record<string, unknown> = {
    model: MODELS[req.model],
    messages,
    max_tokens: req.max_tokens ?? DEFAULT_MAX_TOKENS[req.model],
    temperature: 0,
  };
  if (THINKING_SWITCH.has(req.model)) {
    body.chat_template_kwargs = { enable_thinking: false };
    if (req.json) body.response_format = { type: "json_object" };
  }
  return body;
}

// ---------------------------------------------------------------- reply parsing

/** Remove reasoning: closed <think>…</think> blocks, anything before a stray </think>, an unclosed <think> tail. */
export function stripThink(text: string): string {
  let t = text.replace(/<think>[\s\S]*?<\/think>/gi, "");
  const close = t.toLowerCase().lastIndexOf("</think>");
  if (close >= 0) t = t.slice(close + "</think>".length);
  const open = t.toLowerCase().indexOf("<think>");
  if (open >= 0) t = t.slice(0, open);
  return t.trim();
}

/** Index of the bracket that closes the one at `start`, honouring JSON strings; -1 if none. */
function matchBracket(s: string, start: number): number {
  const stack: string[] = [];
  let inStr = false;
  let esc = false;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "{") stack.push("}");
    else if (c === "[") stack.push("]");
    else if (c === "}" || c === "]") {
      if (stack.pop() !== c) return -1;
      if (stack.length === 0) return i;
    }
  }
  return -1;
}

function isContainer(v: unknown): boolean {
  return typeof v === "object" && v !== null;
}

/**
 * The last JSON object or array in a model reply, after removing reasoning. Handles code fences
 * and prose around the JSON. Returns null when there is none.
 */
export function extractJson(text: string): unknown | null {
  const t = stripThink(text ?? "");
  if (!t) return null;
  try {
    const whole = JSON.parse(t);
    if (isContainer(whole)) return whole;
  } catch { /* fall through to scanning */ }
  let last: unknown = null;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c !== "{" && c !== "[") continue;
    const end = matchBracket(t, i);
    if (end < 0) continue;
    try {
      const v = JSON.parse(t.slice(i, end + 1));
      if (isContainer(v)) { last = v; i = end; }
    } catch { /* not JSON; keep scanning inside it */ }
  }
  return last;
}

// ---------------------------------------------------------------- concurrency

interface Semaphore { acquire(): Promise<void>; release(): void; }

function makeSemaphore(max: number): Semaphore {
  let active = 0;
  const waiting: (() => void)[] = [];
  return {
    acquire(): Promise<void> {
      if (active < max) { active++; return Promise.resolve(); }
      return new Promise<void>((resolve) => waiting.push(resolve)); // the releaser hands its slot over
    },
    release(): void {
      const next = waiting.shift();
      if (next) next();
      else active--;
    },
  };
}

/** One semaphore per runtime URL, so concurrent runs share the 4-call cap. */
const SEMAPHORES = new Map<string, Semaphore>();
function sharedSemaphore(key: string, requested: number): Semaphore {
  let s = SEMAPHORES.get(key);
  if (!s) {
    const n = Number.isFinite(requested) ? Math.floor(requested) : MAX_CONCURRENCY;
    s = makeSemaphore(Math.min(MAX_CONCURRENCY, Math.max(1, n)));
    SEMAPHORES.set(key, s);
  }
  return s;
}

// ---------------------------------------------------------------- client

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isTimeout(e: unknown): boolean {
  const name = (e as { name?: string } | null)?.name;
  return name === "TimeoutError" || name === "AbortError";
}

function safeJson(raw: string): unknown {
  try { return JSON.parse(raw); } catch { return null; }
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v : null;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

type Obj = Record<string, unknown>;
function obj(v: unknown): Obj | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : null;
}

/** A short error text from a Nightshift error body, or from the raw text. */
function errorText(status: number, js: unknown, raw: string): string {
  const err = obj(obj(js)?.error);
  const msg = str(err?.message) ?? str(err?.meterless_detail) ?? raw.replace(/\s+/g, " ").slice(0, 200);
  const code = str(err?.code);
  return `HTTP ${status}${code ? ` ${code}` : ""}: ${msg || "(empty body)"}`;
}

export function createNightshiftLlm(cfg: NightshiftConfig): Llm {
  const base = (cfg.baseUrl ?? "").trim().replace(/\/+$/, "");
  const url = `${base}/chat/completions`;
  const sem = sharedSemaphore(base, cfg.concurrency);
  const timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRetries = Math.max(0, cfg.maxRetries ?? DEFAULT_MAX_RETRIES);
  const backoff = cfg.backoffMs && cfg.backoffMs.length ? cfg.backoffMs : DEFAULT_BACKOFF_MS;
  const doFetch = cfg.fetchImpl ?? fetch;
  const token = cfg.token ?? "";
  const mask = (s: string): string => (token.length >= 6 ? s.split(token).join("***") : s);

  return {
    async chat(req: ChatRequest): Promise<ChatResult> {
      const callId = `ns-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
      const body = JSON.stringify(buildChatBody(req, callId)); // throws on an unknown model key
      const requested = MODELS[req.model];
      const headers = {
        Authorization: `Bearer ${token}`,
        "meterless-app": cfg.app,
        "meterless-scope": "user",
        "Content-Type": "application/json",
      };
      const started = performance.now();
      let attempt = 0;
      let lastError = "";
      let httpStatus: number | null = null;
      let errMeta: Obj | null = null;

      for (;;) {
        let retryable = false;
        await sem.acquire();
        const t0 = performance.now();
        try {
          const res = await doFetch(url, { method: "POST", headers, body, signal: AbortSignal.timeout(timeoutMs) });
          httpStatus = res.status;
          const raw = await res.text();
          const js = safeJson(raw);
          const top = obj(js);
          if (res.ok && top && Array.isArray(top.choices)) {
            const latency = Math.round(performance.now() - t0);
            const meter = obj(top.meterless);
            const choice = obj(top.choices[0]);
            const message = obj(choice?.message);
            const content = typeof message?.content === "string" ? message.content : "";
            const text = stripThink(content);
            const json = extractJson(text);
            const usage = obj(top.usage);
            const receipt: Receipt = {
              call_id: callId,
              agent: req.agent,
              requested_model: requested,
              response_model: str(top.model),
              routed_model: str(meter?.routed_model),
              receipt_id: str(meter?.receipt_id),
              latency_ms: latency,
              prompt_tokens: num(usage?.prompt_tokens),
              completion_tokens: num(usage?.completion_tokens),
              status: "ok",
            };
            const route = obj(meter?.winning_route);
            cfg.tracer.emit({
              agent: req.agent,
              action: "llm_call",
              model: requested,
              routed_model: receipt.routed_model,
              receipt_id: receipt.receipt_id,
              latency_ms: latency,
              retry_count: attempt,
              status: "ok",
              input_summary: `${req.model}: ${req.user.length} chars${req.json ? ", json" : ""}, max_tokens ${req.max_tokens ?? DEFAULT_MAX_TOKENS[req.model]}`,
              output_summary: `${text.length} chars; json ${json === null ? "none" : Array.isArray(json) ? "array" : "object"}; ${receipt.completion_tokens ?? "?"} completion tokens`,
              details: {
                call_id: callId,
                response_model: receipt.response_model,
                prompt_tokens: receipt.prompt_tokens,
                completion_tokens: receipt.completion_tokens,
                finish_reason: str(choice?.finish_reason),
                provider: str(route?.provider),
                route_kind: str(route?.kind),
                total_ms: Math.round(performance.now() - started),
              },
            });
            return { text, json, receipt };
          }
          lastError = res.ok ? `HTTP ${res.status}: response is not a chat completion` : errorText(res.status, js, raw);
          errMeta = obj(top?.meterless);
          retryable = res.status === 429 || res.status >= 500;
        } catch (e) {
          if (isTimeout(e)) {
            lastError = `timeout after ${timeoutMs} ms`;
            retryable = false; // a stuck model: fail fast, the caller degrades (3-minute run budget)
          } else {
            const cause = (e as { cause?: { code?: string } })?.cause?.code;
            lastError = `network error: ${(e as Error)?.message ?? String(e)}${cause ? ` (${cause})` : ""}`;
            retryable = true;
          }
        } finally {
          sem.release();
        }
        if (!retryable || attempt >= maxRetries) break;
        const wait = backoff[Math.min(attempt, backoff.length - 1)];
        attempt++;
        cfg.tracer.emit({
          agent: req.agent,
          action: "llm_retry",
          model: requested,
          status: "error",
          retry_count: attempt,
          output_summary: mask(`${lastError}; retry ${attempt}/${maxRetries} in ${wait} ms`),
          details: { call_id: callId, http_status: httpStatus },
        });
        await sleep(wait);
      }

      const total = Math.round(performance.now() - started);
      const receipt: Receipt = {
        call_id: callId,
        agent: req.agent,
        requested_model: requested,
        response_model: null,
        routed_model: str(errMeta?.routed_model),
        receipt_id: str(errMeta?.receipt_id),
        latency_ms: total,
        status: "error",
        error: mask(lastError).slice(0, 300),
      };
      cfg.tracer.emit({
        agent: req.agent,
        action: "llm_call",
        model: requested,
        routed_model: receipt.routed_model,
        receipt_id: receipt.receipt_id,
        latency_ms: total,
        retry_count: attempt,
        status: "error",
        input_summary: `${req.model}: ${req.user.length} chars${req.json ? ", json" : ""}`,
        output_summary: receipt.error,
        details: { call_id: callId, http_status: httpStatus, request_id: str(errMeta?.request_id) },
      });
      return { text: "", json: null, receipt };
    },
  };
}
