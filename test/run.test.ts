// Pipeline tests: run() end to end with a mock Queries (real KEV rows) and a scripted mock Llm.
// No network. The output file goes to a temporary folder under the repo's output/ (git-ignored).
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_POLICY, MODELS } from "../src/contracts.ts";
import type {
  ChatRequest, ChatResult, Deps, EpssScore, InventoryRow, KevEntry, KevPair, Llm, Queries, TraceEvent, Tracer,
} from "../src/contracts.ts";
import { run, runWith } from "../src/run.ts";
import type { Pipeline } from "../src/run.ts";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TMP = join(REPO, "output", `test-run-${process.pid}`);
after(() => rmSync(TMP, { recursive: true, force: true }));

function memTracer(id = "test-run-1"): Tracer & { events: TraceEvent[] } {
  const events: TraceEvent[] = [];
  return { run_id: id, file: `logs/trace-${id}.jsonl`, events, emit(e) { events.push({ ts: "", run_id: id, ...e }); } };
}

const kev = (cve_id: string, vendor: string, product: string, date_added: string, due_date: string): KevEntry => ({
  cve_id, vendor, product, vulnerability_name: `${vendor} ${product.trim()} vulnerability`, date_added, due_date,
  ransomware_use: "Unknown", required_action: "Apply mitigations per vendor instructions.", short_description: "", notes: "",
  catalog_version: "2026.10.23",
});

// Real KEV pairs and rows (CVE-2099-0002 is a stand-in for the trailing-space "Windows " spelling).
const PAIRS: KevPair[] = [
  { vendor: "Apache", product: "Log4j2" }, { vendor: "Apache", product: "HTTP Server" }, { vendor: "Apache", product: "Tomcat" },
  { vendor: "Palo Alto Networks", product: "PAN-OS" }, { vendor: "Palo Alto Networks", product: "Expedition" },
  { vendor: "Microsoft", product: "Exchange" }, { vendor: "Microsoft", product: "Exchange Server" },
  { vendor: "Microsoft", product: "Windows" }, { vendor: "Microsoft", product: "Windows " },
  { vendor: "Citrix", product: "NetScaler" }, { vendor: "Citrix", product: "NetScaler ADC and Gateway" },
  { vendor: "Fortinet", product: "FortiClient EMS" }, { vendor: "Fortinet", product: "FortiOS" },
];
const ENTRIES: KevEntry[] = [
  kev("CVE-2021-44228", "Apache", "Log4j2", "2021-12-10", "2021-12-24"),
  kev("CVE-2026-0322", "Palo Alto Networks", "PAN-OS", "2026-10-14", "2026-10-17"),
  kev("CVE-2026-88779", "Citrix", "NetScaler", "2026-10-04", "2026-10-07"),
  kev("CVE-2026-96951", "Microsoft", "Windows", "2026-10-13", "2026-10-16"),
  kev("CVE-2099-0002", "Microsoft", "Windows ", "2026-01-05", "2026-01-26"),
];
const EPSS: EpssScore[] = [
  { cve_id: "CVE-2021-44228", epss: 0.99999, percentile: 1, score_date: "2026-10-25" },
  { cve_id: "CVE-2026-0322", epss: 0.2, percentile: 0.95, score_date: "2026-10-25" },
];

const inv = (row_id: string, asset_name: string, asset_type: string, internet_facing: boolean, software: string): InventoryRow =>
  ({ row_id, asset_id: `A-${row_id}`, asset_name, asset_type, internet_facing, owner_team: "IT", software });
const INVENTORY: InventoryRow[] = [
  inv("R01", "erp-portal-01", "server", true, "log4j-core 2.14.1 (bundled in ERP-Portal WAR)"),
  inv("R02", "branch-fw-01", "firewall", true, "PAN-OS 10.2.7 (GlobalProtect gw)"),
  inv("R03", "fin-laptop-07", "laptop", false, "Notepad++ v8.6"),
  inv("R04", "m365", "cloud", true, "Exchange Online (M365 tenant)"),
  inv("R05", "remote-01", "vpn", true, "Citrix NetScaler ADC 13.1-48.47"),
  inv("R06", "ops-laptop-02", "laptop", false, "Windows 11 Pro"),
];

function mockQueries(over: Partial<Queries> = {}): Queries & { calls: { name: string; arg?: unknown }[] } {
  const calls: { name: string; arg?: unknown }[] = [];
  return {
    calls,
    async inventory() { calls.push({ name: "inventory" }); return INVENTORY; },
    async kevPairs() { calls.push({ name: "kevPairs" }); return PAIRS; },
    async kevByProducts(pairs) {
      calls.push({ name: "kevByProducts", arg: pairs });
      const want = new Set(pairs.map((p) => `${p.vendor}|${p.product}`));
      return ENTRIES.filter((e) => want.has(`${e.vendor}|${e.product}`));
    },
    async kevVerify() { throw new Error("not used"); },
    async epss(ids) { calls.push({ name: "epss", arg: ids }); return EPSS.filter((s) => ids.includes(s.cve_id)); },
    async epssVerify() { throw new Error("not used"); },
    async nvdCves() { calls.push({ name: "nvdCves" }); throw new Error("dormant: implemented by A3"); },
    async nvdProduct() { throw new Error("dormant: implemented by A3"); },
    ...over,
  };
}

type Ans = [string | null, string | null];
const BOLT: Record<string, Ans> = {
  "log4j-core 2.14.1 (bundled in ERP-Portal WAR)": ["Apache", "Log4j2"],
  "PAN-OS 10.2.7 (GlobalProtect gw)": ["Palo Alto Networks", "PAN-OS"],
  "Exchange Online (M365 tenant)": ["Microsoft", "Exchange"],
  "Citrix NetScaler ADC 13.1-48.47": ["Citrix", "NetScaler ADC and Gateway"],
  "Windows 11 Pro": ["Microsoft", "Windows"],
};
const LIGHTNING: Record<string, Ans> = { ...BOLT, "Exchange Online (M365 tenant)": [null, null], "Citrix NetScaler ADC 13.1-48.47": ["Citrix", "NetScaler"] };
const ULTRA: Record<string, Ans> = { "Exchange Online (M365 tenant)": [null, null], "Citrix NetScaler ADC 13.1-48.47": ["Citrix", "NetScaler"] };

function mockLlm(fail: string[] = []): Llm & { calls: ChatRequest[] } {
  const calls: ChatRequest[] = [];
  return {
    calls,
    async chat(req): Promise<ChatResult> {
      calls.push(req);
      const n = calls.length;
      const receipt = {
        call_id: `c${n}`, agent: req.agent, requested_model: MODELS[req.model], response_model: MODELS[req.model],
        routed_model: MODELS[req.model], receipt_id: `rcpt_${req.model}_${n}`, latency_ms: 3, status: "ok" as const,
      };
      if (fail.includes(req.model)) return { text: "", json: null, receipt: { ...receipt, receipt_id: null, routed_model: null, status: "error", error: "HTTP 502" } };
      const table = req.model === "bolt" ? BOLT : req.model === "lightning" ? LIGHTNING : ULTRA;
      const results = [...req.user.matchAll(/^(I\d+) (".*") \(asset type: [^)]*\)$/gm)].map((m) => {
        const [vendor, product] = table[JSON.parse(m[2]) as string] ?? [null, null];
        return { id: m[1], vendor, product, product_type: "unknown", version: null, confidence: 0.9 };
      });
      return { text: "", json: { results }, receipt };
    },
  };
}

const CLOCK = { now: () => new Date("2026-10-26T12:00:00Z") };
function deps(over: Partial<Deps> = {}): Deps & { tracer: Tracer & { events: TraceEvent[] } } {
  return { mode: "live", clock: CLOCK, llm: mockLlm(), queries: mockQueries(), tracer: memTracer(), policy: DEFAULT_POLICY, ...over } as Deps & { tracer: Tracer & { events: TraceEvent[] } };
}

describe("end to end", () => {
  test("live run: decisions, dates, receipts, manifest, trace and the output file", async () => {
    const d = deps();
    const q = d.queries as ReturnType<typeof mockQueries>;
    const r = await runWith({}, d, { outputDir: TMP });
    assert.equal(r.status, "success");
    assert.equal(r.mode, "live");
    assert.equal(r.run_id, "test-run-1");
    assert.equal(r.as_of, "2026-10-26");
    assert.equal(r.started_at, "2026-10-26T12:00:00.000Z");
    assert.equal(r.trace_file, "logs/trace-test-run-1.jsonl");
    assert.equal(r.report_file, null);
    assert.deepEqual(r.summary, { patch_now: 4, this_cycle: 0, monitor: 2, ask_owner: 0 });

    const by = Object.fromEntries(r.lines.map((l) => [l.row_id, l]));
    assert.equal(by.R01.decision, "patch_now");
    assert.equal(by.R01.target_date, "2026-11-02");
    assert.equal(by.R01.kev?.overdue_days, 1767);
    assert.equal(by.R01.epss?.max, 0.99999);
    assert.equal(by.R02.kev?.overdue_days, 9);
    assert.equal(by.R03.decision, "monitor");
    assert.equal(by.R03.resolution.adjudicated_by, "rules"); // no candidate: no model call
    assert.equal(by.R04.decision, "monitor");
    assert.equal(by.R04.resolution.adjudicated_by, "ultra");
    assert.equal(by.R05.resolution.product, "NetScaler");
    assert.equal(by.R05.resolution.adjudicated_by, "ultra");
    assert.equal(by.R05.kev?.cves[0].cve_id, "CVE-2026-88779");
    // both KEV spellings of the Windows family are queried and cited
    assert.deepEqual(by.R06.kev?.cves.map((c) => c.cve_id), ["CVE-2026-96951", "CVE-2099-0002"]);
    const kevArg = q.calls.find((c) => c.name === "kevByProducts")?.arg as KevPair[];
    assert.ok(kevArg.some((p) => p.product === "Windows ") && kevArg.some((p) => p.product === "Windows"));
    assert.equal(kevArg.some((p) => p.vendor === "Fortinet"), false);
    const epssArg = q.calls.find((c) => c.name === "epss")?.arg as string[];
    assert.deepEqual(epssArg, ["CVE-2021-44228", "CVE-2026-0322", "CVE-2026-88779", "CVE-2026-96951", "CVE-2099-0002"]);

    // order: patch_now (internet-facing first, most overdue first), then monitor (internet-facing first)
    assert.deepEqual(r.lines.map((l) => l.row_id), ["R01", "R05", "R02", "R06", "R04", "R03"]);
    assert.ok(r.lines.every((l) => l.why.length > 0 && l.verified === false));

    assert.equal(r.receipts.length, 3);
    assert.deepEqual(r.receipts.map((x) => x.agent).sort(), ["jury.adjudicate", "jury.bolt", "jury.lightning"]);
    assert.deepEqual(r.manifest.models, MODELS);
    assert.deepEqual(r.manifest.helpers_dormant, ["nvdCves", "nvdProduct", "critic", "verifier", "world_model"]);
    assert.equal(r.manifest.engine, "world-model");
    assert.deepEqual(r.manifest.sources.map((s) => s.name), ["Inventory (synthetic)", "CISA KEV", "FIRST EPSS", "NIST NVD"]);
    assert.equal(r.manifest.sources[1].as_of, "2026.10.23");
    assert.ok(["inventory", "kev_pairs", "normalise", "jury", "facts", "analyst", "total"].every((k) => typeof r.timing_ms[k] === "number"));

    const actions = d.tracer.events.map((e) => e.action);
    for (const a of ["run_start", "inventory_loaded", "kev_pairs", "candidates_built", "jury_vote", "split_detected", "ultra_adjudication", "kev_lookup", "epss_lookup", "helper_dormant", "decisions", "why_written", "run_complete", "output_written"]) {
      assert.ok(actions.includes(a), `trace is missing ${a}`);
    }
    const file = join(TMP, "run-test-run-1.json");
    assert.ok(existsSync(file));
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), JSON.parse(JSON.stringify(r)));
  });

  test("run() is the default entry point (writes to output/ unless told not to); runWith can skip writing", async () => {
    assert.equal(typeof run, "function");
    const r = await runWith({ inventory: [{ software: "PAN-OS 10.2.7 (GlobalProtect gw)" }] }, deps(), { outputDir: null });
    assert.equal(r.status, "success");
    assert.equal(r.lines[0].decision, "patch_now");
  });
});

describe("requests", () => {
  test("inline rows get safe defaults, and row_ids filter them", async () => {
    const d = deps();
    const r = await runWith({
      inventory: [{ software: "Notepad++ v8.6" }, { row_id: "X2", software: "PAN-OS 10.2.7", internet_facing: "yes", asset_name: "fw" }],
      row_ids: ["X2"],
    }, d, { outputDir: null });
    assert.equal(r.status, "success");
    assert.equal(r.lines.length, 1);
    assert.equal(r.lines[0].row_id, "X2");
    assert.equal(r.lines[0].internet_facing, true);
    assert.equal(r.manifest.sources[0].name, "Inventory (request rows)");
    assert.ok(r.lines[0].evidence.some((e) => e.query === "run_request.inventory" && e.source === "agent"));
    assert.equal((d.queries as ReturnType<typeof mockQueries>).calls.some((c) => c.name === "inventory"), false);
  });

  test("bad requests become structured errors (no throw)", async () => {
    const cases: [Record<string, unknown>, RegExp][] = [
      [{ inventory: "R01" }, /must be an array/],
      [{ inventory: [{ asset_name: "x" }] }, /software is missing/],
      [{ inventory: [] }, /no usable rows/],
      [{ policy: { sla_days: { patch_now: -3 } } }, /patch_now/],
      [{ row_ids: ["NOPE"] }, /none of the requested row_ids/],
    ];
    for (const [req, re] of cases) {
      const r = await runWith(req as never, deps(), { outputDir: null });
      assert.equal(r.status, "error");
      assert.equal(r.error?.type, "invalid_request");
      assert.equal(r.error?.recoverable, true);
      assert.match(r.error?.message ?? "", re);
      assert.deepEqual(r.lines, []);
    }
  });

  test("a per-run policy override changes the dates", async () => {
    const r = await runWith({ policy: { sla_days: { patch_now: 2 } }, row_ids: ["R02"] }, deps(), { outputDir: null });
    assert.equal(r.lines[0].target_date, "2026-10-28");
    assert.equal(r.manifest.policy.sla_days.patch_now, 2);
  });
});

describe("failures degrade, never crash", () => {
  test("inventory unreadable -> error response", async () => {
    const r = await runWith({}, deps({ queries: mockQueries({ inventory: async () => { throw new Error("Zetaris 400: table not found"); } }) }), { outputDir: null });
    assert.equal(r.status, "error");
    assert.equal(r.error?.type, "inventory_unavailable");
  });

  test("KEV names unreadable -> partial, every row ask_owner, no model call", async () => {
    const llm = mockLlm();
    const r = await runWith({}, deps({ llm, queries: mockQueries({ kevPairs: async () => { throw new Error("watchdog fired"); } }) }), { outputDir: null });
    assert.equal(r.status, "partial");
    assert.equal(r.summary.ask_owner, INVENTORY.length);
    assert.equal(r.owner_questions.length, INVENTORY.length);
    assert.equal(llm.calls.length, 0);
  });

  test("an empty KEV name list is a failed read, not 'nothing exploited': every row ask_owner", async () => {
    const r = await runWith({}, deps({ queries: mockQueries({ kevPairs: async () => [] }) }), { outputDir: null });
    assert.equal(r.status, "partial");
    assert.equal(r.summary.monitor, 0);
    assert.equal(r.summary.ask_owner, INVENTORY.length);
    assert.match(r.owner_questions[0].reason, /no \(vendor, product\) pairs/);
  });

  test("KEV entries missing for a matched family -> that row asks the owner (fail-closed)", async () => {
    const q = mockQueries({ kevByProducts: async (pairs) => ENTRIES.filter((e) => e.product !== "PAN-OS" && pairs.some((p) => p.vendor === e.vendor && p.product === e.product)) });
    const r = await runWith({ row_ids: ["R01", "R02"] }, deps({ queries: q }), { outputDir: null });
    const by = Object.fromEntries(r.lines.map((l) => [l.row_id, l.decision]));
    assert.deepEqual(by, { R01: "patch_now", R02: "ask_owner" });
  });

  test("KEV entries unreadable -> matched rows fail closed to ask_owner", async () => {
    const r = await runWith({}, deps({ queries: mockQueries({ kevByProducts: async () => { throw new Error("timeout"); } }) }), { outputDir: null });
    assert.equal(r.status, "partial");
    assert.equal(r.summary.patch_now, 0);
    assert.equal(r.summary.monitor, 2); // the two no_match rows
    assert.equal(r.summary.ask_owner, 4);
  });

  test("EPSS unreadable -> patch_now stays, nothing relaxed to monitor", async () => {
    const r = await runWith({}, deps({ queries: mockQueries({ epss: async () => { throw new Error("FIRST API 503"); } }) }), { outputDir: null });
    assert.equal(r.status, "partial");
    assert.equal(r.summary.patch_now, 4);
    assert.equal(r.summary.monitor, 0);
    assert.equal(r.summary.ask_owner, 2);
  });

  test("models failing -> deterministic fallback, failed receipts kept, partial", async () => {
    const r = await runWith({}, deps({ llm: mockLlm(["bolt", "lightning"]) }), { outputDir: null });
    assert.equal(r.status, "partial");
    assert.equal(r.receipts.length, 2);
    assert.ok(r.receipts.every((x) => x.status === "error"));
    assert.equal(r.lines.find((l) => l.row_id === "R02")?.resolution.adjudicated_by, "rules");
  });

  test("a model client that throws is recorded as an error receipt", async () => {
    const throwing: Llm = { async chat() { throw new Error("socket hang up"); } };
    const r = await runWith({ row_ids: ["R02"] }, deps({ llm: throwing }), { outputDir: null });
    assert.equal(r.receipts.length, 2);
    assert.ok(r.receipts.every((x) => x.status === "error" && /socket hang up/.test(x.error ?? "")));
  });

  test("a live NVD helper is listed as live and its ranges become evidence", async () => {
    const q = mockQueries({
      nvdCves: async (ids) => ids.map((cve_id) => ({ cve_id, criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", vulnerable: true, version_start_including: "2.0.1", version_end_excluding: "2.15.0" })),
    });
    const r = await runWith({ row_ids: ["R01"] }, deps({ queries: q }), { outputDir: null });
    assert.ok(r.manifest.helpers_live.includes("nvdCves"));
    assert.equal(r.manifest.helpers_dormant.includes("nvdCves"), false);
    assert.ok(r.lines[0].evidence.some((e) => e.source === "zetaris:nvd" && /< 2\.15\.0/.test(e.value)));
  });

  test("an unexpected exception becomes an internal_error response", async () => {
    const broken: Pipeline = { name: "broken", prepare: () => { throw new Error("boom"); }, family: (p) => p.product, vote: () => { throw new Error("x"); } };
    const r = await runWith({}, deps(), { outputDir: null, pipeline: broken });
    assert.equal(r.status, "error");
    assert.equal(r.error?.type, "internal_error");
    assert.equal(r.error?.recoverable, false);
  });
});

describe("modes", () => {
  test("sample mode: no model, deterministic votes, stamped sample, no receipts", async () => {
    const d = deps({ mode: "sample", llm: null });
    const r = await runWith({}, d, { outputDir: null });
    assert.equal(r.mode, "sample");
    assert.equal(r.status, "success");
    assert.equal(r.receipts.length, 0);
    assert.ok(r.lines.every((l) => l.resolution.votes.every((v) => v.juror === "normaliser")));
    assert.equal(r.manifest.sources[1].live, false);
    assert.equal(d.tracer.events.find((e) => e.action === "deterministic_vote")?.status, "ok");
  });

  test("live mode without a model client: deterministic fallback, labelled partial", async () => {
    const r = await runWith({}, deps({ llm: null }), { outputDir: null });
    assert.equal(r.status, "partial");
    assert.equal(r.receipts.length, 0);
  });
});
