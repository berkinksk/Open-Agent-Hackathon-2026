// The sample-mode network guard: while it is on, fetch rejects and net.Socket.connect throws, so no outbound socket
// opens. The proof uses a real local TCP server on port 0 and counts the connections it accepts: zero under the guard,
// one after the guard is released (so the test can fail).
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import tls from "node:tls";
import { setTimeout as delay } from "node:timers/promises";
import { NetworkBlockedError, installNetworkGuard, networkGuardActive, withNetworkGuard } from "../src/sample/guard.ts";
import { memoryTracer } from "../src/trace.ts";

async function countingServer(): Promise<{ port: number; count: () => number; close: () => Promise<void> }> {
  let n = 0;
  const open = new Set<net.Socket>();
  const server = net.createServer((s) => {
    n++;
    open.add(s);
    s.on("close", () => open.delete(s));
    s.on("error", () => {});
    s.end("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as net.AddressInfo).port;
  return {
    port, count: () => n,
    close: () => new Promise<void>((r) => { for (const s of open) s.destroy(); server.close(() => r()); }),
  };
}

test("under the guard no outbound socket opens: fetch, a fetch captured before the guard, net, http and tls all fail and the server sees 0 connections", async () => {
  const srv = await countingServer();
  const earlyFetch = globalThis.fetch; // a client that kept a reference before the guard (e.g. ZetarisClient)
  const g = installNetworkGuard();
  try {
    assert.equal(networkGuardActive(), true);
    await assert.rejects(fetch(`http://127.0.0.1:${srv.port}/`), NetworkBlockedError);
    await assert.rejects(earlyFetch(`http://127.0.0.1:${srv.port}/`)); // blocked inside undici at net.Socket.connect
    assert.throws(() => net.connect(srv.port, "127.0.0.1"), NetworkBlockedError);
    assert.throws(() => new net.Socket().connect({ port: srv.port, host: "127.0.0.1" }), NetworkBlockedError);
    assert.throws(() => http.get(`http://127.0.0.1:${srv.port}/`), NetworkBlockedError);
    assert.throws(() => tls.connect({ port: srv.port, host: "127.0.0.1", rejectUnauthorized: false }), NetworkBlockedError);
    await delay(100);
    assert.equal(srv.count(), 0, "no connection may reach the server while the guard is on");
    const kinds = new Set(g.attempts.map((a) => a.kind));
    assert.ok(kinds.has("fetch") && kinds.has("net.Socket.connect"), JSON.stringify(g.attempts));
    assert.ok(g.attempts.some((a) => a.target.includes(String(srv.port))), "the attempt names its target");
  } finally {
    g.release();
  }
  // released: the same calls connect again, so the zero above is a real measurement
  assert.equal(networkGuardActive(), false);
  const s = net.connect(srv.port, "127.0.0.1");
  await new Promise<void>((resolve, reject) => { s.once("connect", () => resolve()); s.once("error", reject); });
  s.destroy();
  const r = await fetch(`http://127.0.0.1:${srv.port}/`).catch((e: unknown) => e);
  assert.ok(!(r instanceof NetworkBlockedError), "fetch is restored");
  await delay(50);
  assert.ok(srv.count() >= 1, `the server must see connections once the guard is off (saw ${srv.count()})`);
  await srv.close();
});

test("the guard is reference-counted and restores the original functions exactly", () => {
  const origFetch = globalThis.fetch;
  const origConnect = net.Socket.prototype.connect;
  const a = installNetworkGuard();
  const b = installNetworkGuard();
  assert.notEqual(globalThis.fetch, origFetch);
  a.release();
  a.release(); // idempotent
  assert.equal(networkGuardActive(), true, "still on while one handle is held");
  assert.notEqual(net.Socket.prototype.connect, origConnect);
  b.release();
  assert.equal(networkGuardActive(), false);
  assert.equal(globalThis.fetch, origFetch);
  assert.equal(net.Socket.prototype.connect, origConnect);
});

test("withNetworkGuard traces the guard and a clean run, and releases even when the work throws", async () => {
  const t = memoryTracer("g1");
  const out = await withNetworkGuard(async () => { assert.equal(networkGuardActive(), true); return 42; }, { tracer: t });
  assert.equal(out, 42);
  assert.equal(networkGuardActive(), false);
  assert.deepEqual(t.events.map((e) => [e.agent, e.action, e.status]), [
    ["network_guard", "installed", "ok"], ["network_guard", "sample_run_checked", "ok"],
  ]);
  assert.match(t.events[1].output_summary ?? "", /no network access was attempted/);

  const t2 = memoryTracer("g2");
  await assert.rejects(withNetworkGuard(async () => { await fetch("https://example.invalid/x"); }, { tracer: t2 }), NetworkBlockedError);
  assert.equal(networkGuardActive(), false, "released after a throw");
  const last = t2.events[t2.events.length - 1];
  assert.equal(last.status, "blocked");
  assert.match(last.output_summary ?? "", /1 network attempt\(s\) blocked.*fetch https:\/\/example\.invalid/);
});
