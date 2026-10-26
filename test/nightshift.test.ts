// Nightshift client tests against a local mock server (node:http on port 0). No real network.
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { IncomingHttpHeaders, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { MODELS } from "../src/contracts.ts";
import type { TraceEvent, Tracer } from "../src/contracts.ts";
import { buildChatBody, createNightshiftLlm, extractJson, stripThink } from "../src/adapters/nightshift.ts";

const TOKEN = "fake-bearer-value-0001"; // a placeholder, not a credential

function memTracer(): Tracer & { events: TraceEvent[] } {
  const events: TraceEvent[] = [];
  return { run_id: "t", file: "", events, emit(e) { events.push({ ts: "", run_id: "t", ...e }); } };
}

interface Seen { method: string; url: string; headers: IncomingHttpHeaders; body: Record<string, unknown>; }
type Handler = (req: Seen, res: ServerResponse, n: number) => void;

const servers: { close(): Promise<void> }[] = [];
after(async () => { for (const s of servers) await s.close(); });

async function mockServer(handler: Handler) {
  const seen: Seen[] = [];
  let inflight = 0;
  let maxInflight = 0;
  const server = createServer((req, res) => {
    inflight++;
    maxInflight = Math.max(maxInflight, inflight);
    res.on("finish", () => { inflight--; });
    res.on("close", () => { if (!res.writableFinished) inflight--; });
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const entry: Seen = { method: req.method ?? "", url: req.url ?? "", headers: req.headers, body: raw ? JSON.parse(raw) : {} };
      seen.push(entry);
      handler(entry, res, seen.length);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const s = {
    url: `http://127.0.0.1:${port}/v1`, seen, maxInflight: () => maxInflight,
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
  servers.push(s);
  return s;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  if (res.destroyed) return;
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function completion(model: unknown, content: string, receiptId = "rcpt_req_test0001") {
  return {
    id: "chatcmpl-test", object: "chat.completion", model,
    choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
    usage: { prompt_tokens: 120, completion_tokens: 30, total_tokens: 150 },
    meterless: {
      schema: "meterless.compute_receipt.v1", receipt_id: receiptId, requested_model: model, routed_model: model,
      winning_route: { provider: "nvidia", kind: "cloud" }, phases: [],
    },
  };
}

const okJson = (req: Seen, res: ServerResponse) => send(res, 200, completion(req.body.model, '{"results":[]}'));

function llmFor(url: string, tracer: Tracer, extra: Record<string, unknown> = {}) {
  return createNightshiftLlm({ baseUrl: url, token: TOKEN, app: "exposureledger", concurrency: 4, tracer, backoffMs: [5, 5, 5], ...extra });
}

describe("request shape", () => {
  test("Lightning: pinned id, thinking off, JSON mode, temperature 0, never reasoning_budget", async () => {
    const srv = await mockServer(okJson);
    const tr = memTracer();
    await llmFor(srv.url, tr).chat({ model: "lightning", agent: "jury.lightning", system: "sys", user: "hello", json: true });
    const { body, url, method } = srv.seen[0];
    assert.equal(method, "POST");
    assert.equal(url, "/v1/chat/completions");
    assert.equal(body.model, MODELS.lightning);
    assert.deepEqual(body.chat_template_kwargs, { enable_thinking: false });
    assert.deepEqual(body.response_format, { type: "json_object" });
    assert.equal(body.max_tokens, 1500);
    assert.equal(body.temperature, 0);
    assert.equal("reasoning_budget" in body, false);
    const msgs = body.messages as { role: string; content: string }[];
    assert.equal(msgs[0].role, "system");
    assert.equal(msgs[0].content, "sys");
    assert.match(msgs[1].content, /^hello\n\nRequest id: ns-[0-9a-f]{12}$/);
  });

  test("Bolt: no thinking switch, no response_format; Ultra: both, max_tokens 2000", async () => {
    const srv = await mockServer(okJson);
    const llm = llmFor(srv.url, memTracer());
    await llm.chat({ model: "bolt", agent: "jury.bolt", user: "a", json: true });
    await llm.chat({ model: "ultra", agent: "jury.adjudicate", user: "b", json: true });
    const [bolt, ultra] = srv.seen.map((s) => s.body);
    assert.equal(bolt.model, MODELS.bolt);
    assert.equal("chat_template_kwargs" in bolt, false);
    assert.equal("response_format" in bolt, false);
    assert.equal(bolt.max_tokens, 1500);
    assert.equal(ultra.model, MODELS.ultra);
    assert.deepEqual(ultra.chat_template_kwargs, { enable_thinking: false });
    assert.deepEqual(ultra.response_format, { type: "json_object" });
    assert.equal(ultra.max_tokens, 2000);
    for (const b of [bolt, ultra]) assert.equal("reasoning_budget" in b, false);
  });

  test("no response_format without json:true; an explicit max_tokens wins", () => {
    const b = buildChatBody({ model: "lightning", agent: "x", user: "u", max_tokens: 600 }, "id1");
    assert.equal("response_format" in b, false);
    assert.equal(b.max_tokens, 600);
    assert.deepEqual(b.chat_template_kwargs, { enable_thinking: false });
  });

  test("headers: bearer token, meterless-app, meterless-scope, JSON content type", async () => {
    const srv = await mockServer(okJson);
    await llmFor(srv.url + "/", memTracer()).chat({ model: "bolt", agent: "a", user: "u" });
    const h = srv.seen[0].headers;
    assert.equal(h.authorization, `Bearer ${TOKEN}`);
    assert.equal(h["meterless-app"], "exposureledger");
    assert.equal(h["meterless-scope"], "user");
    assert.match(String(h["content-type"]), /application\/json/);
    assert.equal(srv.seen[0].url, "/v1/chat/completions"); // trailing slash in baseUrl is trimmed
  });

  test("an unknown model key is a programming error and throws", async () => {
    const llm = llmFor("http://127.0.0.1:9/v1", memTracer());
    await assert.rejects(() => llm.chat({ model: "auto" as never, agent: "a", user: "u" }), /unknown model key/);
  });
});

describe("receipt and parsing", () => {
  test("maps response.model, meterless.routed_model, receipt_id, usage and latency; traces the call", async () => {
    const srv = await mockServer((req, res) => send(res, 200, completion(req.body.model, '{"ok":1}', "rcpt_req_abc123")));
    const tr = memTracer();
    const r = await llmFor(srv.url, tr).chat({ model: "ultra", agent: "jury.adjudicate", user: "u", json: true });
    assert.equal(r.receipt.status, "ok");
    assert.equal(r.receipt.agent, "jury.adjudicate");
    assert.equal(r.receipt.requested_model, MODELS.ultra);
    assert.equal(r.receipt.response_model, MODELS.ultra);
    assert.equal(r.receipt.routed_model, MODELS.ultra);
    assert.equal(r.receipt.receipt_id, "rcpt_req_abc123");
    assert.equal(r.receipt.prompt_tokens, 120);
    assert.equal(r.receipt.completion_tokens, 30);
    assert.equal(typeof r.receipt.latency_ms, "number");
    assert.ok(r.receipt.latency_ms >= 0);
    assert.match(r.receipt.call_id, /^ns-[0-9a-f]{12}$/);
    assert.deepEqual(r.json, { ok: 1 });
    const ev = tr.events.filter((e) => e.action === "llm_call");
    assert.equal(ev.length, 1);
    assert.equal(ev[0].model, MODELS.ultra);
    assert.equal(ev[0].routed_model, MODELS.ultra);
    assert.equal(ev[0].receipt_id, "rcpt_req_abc123");
    assert.equal(ev[0].status, "ok");
    assert.equal(ev[0].retry_count, 0);
    assert.equal((ev[0].details as Record<string, unknown>).provider, "nvidia");
  });

  test("extracts the JSON after a <think> block (Ultra with reasoning in content)", async () => {
    const content = '<think>Candidates: {"maybe": true} ... I pick Log4j2.</think>\n{"results":[{"id":"I1","vendor":"Apache","product":"Log4j2"}]}';
    const srv = await mockServer((req, res) => send(res, 200, completion(req.body.model, content)));
    const r = await llmFor(srv.url, memTracer()).chat({ model: "ultra", agent: "a", user: "u", json: true });
    assert.deepEqual(r.json, { results: [{ id: "I1", vendor: "Apache", product: "Log4j2" }] });
    assert.equal(r.text.startsWith("{"), true);
  });

  test("a 200 without receipt fields is still ok, with null receipt ids (the verify check flags it)", async () => {
    const srv = await mockServer((req, res) => send(res, 200, { model: req.body.model, choices: [{ message: { content: "[1,2]" } }] }));
    const r = await llmFor(srv.url, memTracer()).chat({ model: "bolt", agent: "a", user: "u" });
    assert.equal(r.receipt.status, "ok");
    assert.equal(r.receipt.receipt_id, null);
    assert.equal(r.receipt.routed_model, null);
    assert.deepEqual(r.json, [1, 2]);
  });
});

describe("retries, timeouts, concurrency", () => {
  test("retries a 429, then succeeds (retry_count 1 and one llm_retry event)", async () => {
    const srv = await mockServer((req, res, n) => {
      if (n === 1) return send(res, 429, { error: { message: "rate limited", code: "rate_limit" } });
      send(res, 200, completion(req.body.model, '{"results":[]}', "rcpt_req_after429"));
    });
    const tr = memTracer();
    const r = await llmFor(srv.url, tr).chat({ model: "lightning", agent: "jury.lightning", user: "u", json: true });
    assert.equal(srv.seen.length, 2);
    assert.equal(r.receipt.status, "ok");
    assert.equal(r.receipt.receipt_id, "rcpt_req_after429");
    const retries = tr.events.filter((e) => e.action === "llm_retry");
    assert.equal(retries.length, 1);
    assert.equal(retries[0].status, "error");
    assert.match(String(retries[0].output_summary), /HTTP 429/);
    const call = tr.events.find((e) => e.action === "llm_call");
    assert.equal(call?.retry_count, 1);
    assert.equal(call?.status, "ok");
  });

  test("gives up after 2 retries on 5xx and returns an error receipt (no throw)", async () => {
    const srv = await mockServer((_req, res) => send(res, 502, {
      error: { message: "/nemotron-3.5-lightning-30b-a3b_empty_response", code: "provider_error" },
      meterless: { request_id: "chatcmpl-x1", requested_model: MODELS.lightning },
    }));
    const tr = memTracer();
    const r = await llmFor(srv.url, tr).chat({ model: "lightning", agent: "a", user: "u", json: true });
    assert.equal(srv.seen.length, 3);
    assert.equal(r.receipt.status, "error");
    assert.equal(r.json, null);
    assert.equal(r.text, "");
    assert.equal(r.receipt.receipt_id, null);
    assert.match(String(r.receipt.error), /HTTP 502 provider_error/);
    const call = tr.events.find((e) => e.action === "llm_call");
    assert.equal(call?.status, "error");
    assert.equal(call?.retry_count, 2);
    assert.equal((call?.details as Record<string, unknown>).request_id, "chatcmpl-x1");
  });

  test("does not retry a 400", async () => {
    const srv = await mockServer((_req, res) => send(res, 400, { error: { message: "bad request" } }));
    const r = await llmFor(srv.url, memTracer()).chat({ model: "bolt", agent: "a", user: "u" });
    assert.equal(srv.seen.length, 1);
    assert.equal(r.receipt.status, "error");
    assert.match(String(r.receipt.error), /HTTP 400/);
  });

  test("a timeout returns an error receipt and is not retried", async () => {
    const srv = await mockServer((req, res) => {
      const t = setTimeout(() => send(res, 200, completion(req.body.model, "{}")), 1500);
      t.unref();
    });
    const r = await llmFor(srv.url, memTracer(), { timeoutMs: 100 }).chat({ model: "bolt", agent: "a", user: "u" });
    assert.equal(srv.seen.length, 1);
    assert.equal(r.receipt.status, "error");
    assert.match(String(r.receipt.error), /timeout after 100 ms/);
  });

  test("a network error is retried twice, then reported", async () => {
    const dead = await mockServer(okJson);
    const url = dead.url;
    await dead.close();
    const tr = memTracer();
    const r = await llmFor(url, tr).chat({ model: "bolt", agent: "a", user: "u" });
    assert.equal(r.receipt.status, "error");
    assert.match(String(r.receipt.error), /network error/);
    assert.equal(tr.events.filter((e) => e.action === "llm_retry").length, 2);
  });

  test("caps concurrent calls at the configured limit", async () => {
    const srv = await mockServer((req, res) => {
      setTimeout(() => send(res, 200, completion(req.body.model, "{}")), 40);
    });
    const llm = llmFor(srv.url, memTracer(), { concurrency: 2 });
    const rs = await Promise.all(Array.from({ length: 6 }, (_, i) => llm.chat({ model: "bolt", agent: "a", user: `u${i}` })));
    assert.equal(rs.every((r) => r.receipt.status === "ok"), true);
    assert.equal(srv.seen.length, 6);
    assert.equal(srv.maxInflight(), 2);
  });

  test("the token never appears in receipts or trace events, even if the server echoes it", async () => {
    const srv = await mockServer((req, res) => send(res, 401, { error: { message: `bad token ${String(req.headers.authorization)}` } }));
    const tr = memTracer();
    const r = await llmFor(srv.url, tr).chat({ model: "bolt", agent: "a", user: "u" });
    assert.equal(r.receipt.status, "error");
    assert.equal(JSON.stringify(r).includes(TOKEN), false);
    assert.equal(JSON.stringify(tr.events).includes(TOKEN), false);
  });
});

describe("stripThink and extractJson", () => {
  test("strips closed blocks, text before a stray </think>, and an unclosed <think> tail", () => {
    assert.equal(stripThink("<think>a</think>B"), "B");
    assert.equal(stripThink("reasoning without an opening tag</think>\nanswer"), "answer");
    assert.equal(stripThink('{"a":1}<think>truncated reasoning'), '{"a":1}');
  });

  test("handles code fences, prose, nested braces in strings, and picks the last JSON value", () => {
    assert.deepEqual(extractJson('```json\n{"results":[{"id":"I1"}]}\n```'), { results: [{ id: "I1" }] });
    assert.deepEqual(extractJson('Here you go: {"a":"x}y{"} done'), { a: "x}y{" });
    assert.deepEqual(extractJson('first {"a":1} then {"b":2}'), { b: 2 });
    assert.deepEqual(extractJson("[{\"id\":\"I1\"}]"), [{ id: "I1" }]);
    assert.deepEqual(extractJson('<think>{"draft":1}</think>{"final":2}'), { final: 2 });
  });

  test("returns null when there is no JSON object or array", () => {
    assert.equal(extractJson(""), null);
    assert.equal(extractJson("no json here"), null);
    assert.equal(extractJson("42"), null);
    assert.equal(extractJson('"just a string"'), null);
    assert.equal(extractJson("{broken: json"), null);
  });
});
