// The sample-mode network guard (design §10): while a sample run is in progress, `fetch` rejects and
// `net.Socket.prototype.connect` throws, so no outbound socket can open (http, https, tls and fetch all connect
// through net.Socket). Listening sockets (the HTTP server) are untouched. The guard is reference-counted, records
// every blocked attempt, and is removed when the last sample run ends, so a live run in the same process (the server
// serialises runs) is never affected.
import net from "node:net";
import type { Tracer } from "../contracts.ts";

export class NetworkBlockedError extends Error {
  readonly code = "ERR_SAMPLE_NETWORK_BLOCKED";
  constructor(what: string) {
    super(`sample mode: network access is blocked (${what})`);
    this.name = "NetworkBlockedError";
  }
}

export interface NetworkAttempt { kind: "fetch" | "net.Socket.connect"; target: string; at: string; }

export interface NetworkGuard {
  /** Attempts blocked since this handle was taken. */
  readonly attempts: NetworkAttempt[];
  /** Remove this handle; the guard comes off when the last handle is released. Idempotent. */
  release(): void;
}

type ConnectFn = typeof net.Socket.prototype.connect;
interface Saved { fetch: typeof globalThis.fetch; connect: ConnectFn; }

let depth = 0;
let saved: Saved | null = null;
const listeners = new Set<NetworkAttempt[]>();

function describeFetch(input: unknown): string {
  try {
    if (typeof input === "string") return new URL(input).origin;
    if (input instanceof URL) return input.origin;
    if (input && typeof input === "object" && "url" in input) return new URL(String((input as { url: unknown }).url)).origin;
  } catch { /* not a URL */ }
  return "fetch";
}

function describeConnect(args: unknown[]): string {
  const a = args[0];
  if (Array.isArray(a)) return describeConnect(a); // net.connect passes the normalised [options, cb]
  if (typeof a === "number") return `${typeof args[1] === "string" ? args[1] : "localhost"}:${a}`;
  if (typeof a === "string") return a; // a pipe path
  if (a && typeof a === "object") {
    const o = a as { host?: unknown; port?: unknown; path?: unknown };
    if (o.path) return String(o.path);
    return `${o.host ?? "localhost"}:${o.port ?? "?"}`;
  }
  return "socket";
}

function record(kind: NetworkAttempt["kind"], target: string): void {
  const a: NetworkAttempt = { kind, target: target.slice(0, 120), at: new Date().toISOString() };
  for (const l of listeners) l.push(a);
}

/** Install (or join) the guard. Every handle must be released. */
export function installNetworkGuard(): NetworkGuard {
  if (depth === 0) {
    saved = { fetch: globalThis.fetch, connect: net.Socket.prototype.connect };
    const blockedFetch = async function fetch(input: unknown): Promise<Response> {
      const target = describeFetch(input);
      record("fetch", target);
      throw new NetworkBlockedError(`fetch ${target}`);
    };
    globalThis.fetch = blockedFetch as typeof globalThis.fetch;
    net.Socket.prototype.connect = function connect(this: net.Socket, ...args: unknown[]): net.Socket {
      const target = describeConnect(args);
      record("net.Socket.connect", target);
      // a refused socket is destroyed, so a handle it already holds (a TLS socket makes one) cannot keep the process alive
      try { this.destroy(); } catch { /* already gone */ }
      throw new NetworkBlockedError(`net.Socket.connect ${target}`);
    } as ConnectFn;
  }
  depth++;
  const attempts: NetworkAttempt[] = [];
  listeners.add(attempts);
  let released = false;
  return {
    attempts,
    release(): void {
      if (released) return;
      released = true;
      listeners.delete(attempts);
      depth--;
      if (depth === 0 && saved) {
        globalThis.fetch = saved.fetch;
        net.Socket.prototype.connect = saved.connect;
        saved = null;
      }
    },
  };
}

export function networkGuardActive(): boolean {
  return depth > 0;
}

/**
 * Run `fn` with the guard on, and trace what it saw: the guard's installation, then either "no network access
 * attempted" or every blocked attempt.
 */
export async function withNetworkGuard<T>(fn: () => Promise<T>, opts: { tracer?: Tracer | null } = {}): Promise<T> {
  const guard = installNetworkGuard();
  const emit = (e: Parameters<Tracer["emit"]>[0]): void => { try { opts.tracer?.emit(e); } catch { /* tracing never breaks a run */ } };
  emit({
    agent: "network_guard", action: "installed", status: "ok",
    output_summary: "sample mode: fetch and net.Socket.connect throw for the whole run; data comes from the snapshot only",
  });
  try {
    return await fn();
  } finally {
    const n = guard.attempts.length;
    emit({
      agent: "network_guard", action: "sample_run_checked", status: n ? "blocked" : "ok",
      output_summary: n
        ? `${n} network attempt(s) blocked during the sample run: ${[...new Set(guard.attempts.map((a) => `${a.kind} ${a.target}`))].slice(0, 5).join("; ")}`
        : "no network access was attempted during the sample run",
      details: { attempts: guard.attempts.slice(0, 20) },
    });
    guard.release();
  }
}
