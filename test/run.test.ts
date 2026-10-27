// Pipeline tests: run() end to end with a mock Queries (KEV-shaped rows) and a scripted mock Llm. No network.
// The run file, report, saved world and audit go to a temporary folder under the repo's output/ (git-ignored).
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_POLICY, MODELS } from "../src/contracts.ts";
import type {
  ChatRequest, ChatResult, Deps, EpssScore, InventoryRow, KevEntry, KevPair, Llm, NvdRange, Queries, TraceEvent, Tracer,
} from "../src/contracts.ts";
import { notAffectedBlock, run, runOptionsFromEnv, runWith } from "../src/run.ts";
import type { Pipeline, RunOptions } from "../src/run.ts";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TMP = join(REPO, "output", `test-run-${process.pid}`);
after(() => rmSync(TMP, { recursive: true, force: true }));

function memTracer(id = "test-run-1", file = ""): Tracer & { events: TraceEvent[] } {
  const events: TraceEvent[] = [];
  return { run_id: id, file, events, emit(e) { events.push({ ts: "", run_id: id, ...e }); } };
}

const kev = (cve_id: string, vendor: string, product: string, date_added: string, due_date: string): KevEntry => ({
  cve_id, vendor, product, vulnerability_name: `${vendor} ${product.trim()} vulnerability`, date_added, due_date,
  ransomware_use: "Unknown", required_action: "Apply mitigations per vendor instructions.", short_description: "", notes: "",
  catalog_version: "2026.10.23",
});

// KEV-shaped test rows (CVE-2099-* are stand-ins; CVE-2099-0002 uses the trailing-space "Windows " spelling).
const PAIRS: KevPair[] = [
  { vendor: "Apache", product: "Log4j2" }, { vendor: "Apache", product: "HTTP Server" }, { vendor: "Apache", product: "Tomcat" },
  { vendor: "Palo Alto Networks", product: "PAN-OS" }, { vendor: "Palo Alto Networks", product: "Expedition" },
  { vendor: "Microsoft", product: "Exchange" }, { vendor: "Microsoft", product: "Exchange Server" },
  { vendor: "Microsoft", product: "Windows" }, { vendor: "Microsoft", product: "Windows " },
  { vendor: "Citrix", product: "NetScaler" }, { vendor: "Citrix", product: "NetScaler ADC and Gateway" },
  { vendor: "Fortinet", product: "FortiClient EMS" }, { vendor: "Fortinet", product: "FortiOS" },
  { vendor: "Docker", product: "Desktop Community Edition" },
];
const ENTRIES: KevEntry[] = [
  kev("CVE-2021-44228", "Apache", "Log4j2", "2021-12-10", "2021-12-24"),
  kev("CVE-2026-0322", "Palo Alto Networks", "PAN-OS", "2026-10-14", "2026-10-17"),
  kev("CVE-2026-88779", "Citrix", "NetScaler", "2026-10-04", "2026-10-07"),
  kev("CVE-2026-96951", "Microsoft", "Windows", "2026-10-13", "2026-10-16"),
  kev("CVE-2099-0002", "Microsoft", "Windows ", "2026-01-05", "2026-01-26"),
  kev("CVE-2099-0003", "Microsoft", "Exchange Server", "2025-03-01", "2025-03-22"),
  kev("CVE-2099-0004", "Docker", "Desktop Community Edition", "2022-01-01", "2022-01-22"),
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
    async kevVerify(ids) { calls.push({ name: "kevVerify", arg: ids }); return ENTRIES.filter((e) => ids.includes(e.cve_id)); },
    async epss(ids) { calls.push({ name: "epss", arg: ids }); return EPSS.filter((s) => ids.includes(s.cve_id)); },
    async epssVerify(ids) { calls.push({ name: "epssVerify", arg: ids }); return EPSS.filter((s) => ids.includes(s.cve_id)); },
    async nvdCves() { calls.push({ name: "nvdCves" }); throw new Error("dormant: no NVD adapter in this test"); },
    async nvdProduct() { throw new Error("dormant: no NVD adapter in this test"); },
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

interface Script {
  bolt?: Record<string, Ans>; lightning?: Record<string, Ans>; ultra?: Record<string, Ans>;
  retryLightning?: Record<string, Ans>; retryUltra?: Record<string, Ans>;
  /** Ultra's critique verdict from the prompt text (default: approve 3/3/3). */
  critique?: (user: string) => "approve" | "send_back" | "ask_owner";
  /** Ultra's same-product answer per software text (default: true). */
  same?: Record<string, boolean>;
}

function mockLlm(fail: string[] = [], script: Script = {}): Llm & { calls: ChatRequest[] } {
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
      const sw = (req.user.match(/software: "(.*)"/) ?? [])[1] ?? "";
      if (req.agent === "critic") {
        const verdict = script.critique?.(req.user) ?? "approve";
        return { text: "", json: { verdict, rubric: { accuracy: 3, appropriateness: 3, actionability: 3 }, reasons: [`mock ultra says ${verdict}`], question: null }, receipt };
      }
      if (req.agent === "critic.match_check") {
        return { text: "", json: { same_product: script.same?.[sw] ?? true, reason: "mock reason" }, receipt };
      }
      const table = req.agent === "resolver.retry.lightning" ? (script.retryLightning ?? {})
        : req.agent === "resolver.retry.ultra" ? (script.retryUltra ?? {})
        : req.model === "bolt" ? (script.bolt ?? BOLT) : req.model === "lightning" ? (script.lightning ?? LIGHTNING) : (script.ultra ?? ULTRA);
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
const NO_FILES: RunOptions = { outputDir: null, logsDir: null };
const by = (r: { lines: { row_id: string }[] }) => Object.fromEntries(r.lines.map((l) => [l.row_id, l])) as Record<string, Awaited<ReturnType<typeof run>>["lines"][number]>;
const actions = (d: { tracer: { events: TraceEvent[] } }) => d.tracer.events.map((e) => e.action);

describe("end to end", () => {
  test("live run: jury, critic, verifier, World Model, report and files", async () => {
    const d = deps({ tracer: memTracer("test-run-1", join(TMP, "trace-test-run-1.jsonl")) });
    const q = d.queries as ReturnType<typeof mockQueries>;
    const r = await runWith({}, d, { outputDir: TMP, logsDir: TMP });
    assert.equal(r.status, "success");
    assert.equal(r.mode, "live");
    assert.equal(r.as_of, "2026-10-26");
    assert.deepEqual(r.summary, { patch_now: 4, this_cycle: 0, monitor: 2, ask_owner: 0 });

    const L = by(r);
    assert.equal(L.R01.decision, "patch_now");
    assert.equal(L.R01.target_date, "2026-11-02");
    assert.equal(L.R01.kev?.overdue_days, 1767);
    assert.equal(L.R01.epss?.max, 0.99999);
    // NVD is dormant here: KEV-listed, version unconfirmed -> patch_now (fail-closed) with the owner question attached
    assert.ok(L.R01.evidence.some((e) => e.field === "version_unconfirmed"));
    assert.equal(L.R01.critic?.verdict, "ask_owner");
    assert.match(r.owner_questions.find((q) => q.row_id === "R01")?.question ?? "", /Log4j2 2\.14\.1 on erp-portal-01 .*NVD was not looked up/);
    assert.equal(L.R03.decision, "monitor");
    assert.equal(L.R03.resolution.adjudicated_by, "rules"); // no candidate: no model call
    assert.equal(L.R04.decision, "monitor");
    assert.equal(L.R04.resolution.adjudicated_by, "ultra");
    assert.equal(L.R05.resolution.product, "NetScaler");
    assert.equal(L.R05.kev?.cves[0].cve_id, "CVE-2026-88779");
    // both KEV spellings of the Windows family are fetched and cited; the row has no build: one question per edition
    assert.deepEqual(L.R06.kev?.cves.map((c) => c.cve_id), ["CVE-2026-96951", "CVE-2099-0002"]);
    assert.ok(((q.calls.find((c) => c.name === "kevByProducts")?.arg as KevPair[]) ?? []).length > 0);
    assert.ok(q.calls.filter((c) => c.name === "kevByProducts").flatMap((c) => c.arg as KevPair[]).some((p) => p.product === "Windows "));
    const winQ = r.owner_questions.find((x) => x.row_id === "R06") as { question: string; row_ids?: string[] };
    assert.match(winQ.question, /^Which Windows 11 build runs on ops-laptop-02\?/);
    assert.deepEqual(winQ.row_ids, ["R06"]);
    assert.match(L.R06.why, /install the latest cumulative update/);

    // verifier: every line re-checked (KEV/EPSS cited) or explicitly "nothing to re-check"
    assert.ok(r.lines.every((l) => l.verified === true));
    assert.ok(L.R01.verifier_notes[0].startsWith("re-checked"));
    assert.equal(L.R03.verifier_notes[0], "no KEV or EPSS values cited; nothing to re-check");
    assert.ok(q.calls.some((c) => c.name === "kevVerify") && q.calls.some((c) => c.name === "epssVerify"));

    // World Model provenance on each line, audit and saved world on disk
    assert.ok(r.lines.every((l) => l.evidence.some((e) => e.source === "world_model" && e.field === "provenance")));
    assert.ok(existsSync(join(TMP, "audit-test-run-1.jsonl")));
    assert.ok(existsSync(join(TMP, "world", ".world", "test-run-1.json")));

    // receipts: every model call, each with a receipt id and the pinned model
    assert.ok(r.receipts.length >= 3);
    assert.ok(r.receipts.every((x) => x.status === "ok" && x.receipt_id && x.routed_model === x.requested_model));
    assert.ok(["jury.adjudicate", "jury.bolt", "jury.lightning"].every((a) => r.receipts.some((x) => x.agent === a)));

    // manifest: what ran and what did not
    assert.deepEqual(r.manifest.models, MODELS);
    for (const h of ["normaliser", "resolver_jury", "critic", "verifier", "world_model", "report"]) assert.ok(r.manifest.helpers_live.includes(h), h);
    assert.ok(r.manifest.helpers_dormant.includes("nvdCves"));
    assert.ok(r.manifest.helpers_dormant.some((h) => h.startsWith("nvdProduct")));
    assert.deepEqual(r.manifest.sources.map((s) => s.name), ["Inventory (synthetic)", "CISA KEV", "FIRST EPSS", "NIST NVD"]);
    assert.ok(["inventory", "kev_pairs", "normalise", "jury", "facts", "critic", "analyst", "verifier", "world_model", "total"].every((k) => typeof r.timing_ms[k] === "number"));

    const acts = actions(d);
    for (const a of ["run_start", "inventory_loaded", "kev_pairs", "candidates_built", "jury_vote", "split_detected", "ultra_adjudication",
      "kev_lookup", "epss_lookup", "nvd_lookup", "critic_round", "windows_grouped", "decisions", "recheck", "ingest_run", "explain_audit",
      "agents_summary", "run_complete", "report_written", "output_written"]) {
      assert.ok(acts.includes(a), `trace is missing ${a}`);
    }
    assert.ok(d.tracer.events.some((e) => e.agent === "critic" && e.details?.row_id === "R04"));

    // the report and the run file
    assert.equal(r.report_file, join(TMP, "report-test-run-1.html"));
    assert.match(readFileSync(r.report_file as string, "utf8"), /<!doctype html>/i);
    const file = join(TMP, "run-test-run-1.json");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), JSON.parse(JSON.stringify(r)));
  });

  test("run() is the default entry point; runWith can skip every file", async () => {
    assert.equal(typeof run, "function");
    const r = await runWith({ inventory: [{ software: "PAN-OS 10.2.7 (GlobalProtect gw)" }] }, deps(), NO_FILES);
    assert.equal(r.status, "success");
    assert.equal(r.lines[0].decision, "patch_now");
    assert.equal(r.report_file, null);
  });

  test("runOptionsFromEnv reads the NVD budget knob", () => {
    assert.deepEqual(runOptionsFromEnv({}), {});
    assert.deepEqual(runOptionsFromEnv({ EL_NVD_BUDGET_S: "" }), {});
    assert.deepEqual(runOptionsFromEnv({ EL_NVD_BUDGET_S: "nope" }), {});
    assert.equal(runOptionsFromEnv({ EL_NVD_BUDGET_S: "120" }).nvdBudgetMs, 120_000);
    assert.equal(runOptionsFromEnv({ EL_NVD_BUDGET_S: "0" }).nvdBudgetMs, 0);
  });
});

describe("the critic loop", () => {
  const ONLINE: InventoryRow[] = [inv("C1", "m365", "cloud", true, "Exchange Online (M365 tenant)")];
  const both: Record<string, Ans> = { "Exchange Online (M365 tenant)": ["Microsoft", "Exchange Server"] };

  test("a cloud look-alike is sent back; Lightning re-decides with the critic's reason", async () => {
    const llm = mockLlm([], { bolt: both, lightning: both, retryLightning: { "Exchange Online (M365 tenant)": [null, null] } });
    const d = deps({ llm });
    const r = await runWith({ inventory: ONLINE }, d, NO_FILES);
    assert.equal(r.lines[0].decision, "monitor");
    assert.equal(r.lines[0].resolution.status, "no_match");
    assert.equal(r.lines[0].resolution.adjudicated_by, "lightning");
    const sent = d.tracer.events.find((e) => e.agent === "critic" && e.status === "sent_back");
    assert.match(sent?.output_summary ?? "", /type conflict: cloud service vs on-prem server/);
    assert.equal(sent?.target_agent, "resolver");
    assert.ok(d.tracer.events.some((e) => e.agent === "resolver.retry.lightning" && e.action === "redecide"));
    assert.ok(r.receipts.some((x) => x.agent === "resolver.retry.lightning"));
  });

  test("a match still wrong after Lightning and Ultra re-decide goes to the owner (L1)", async () => {
    const llm = mockLlm([], { bolt: both, lightning: both, retryLightning: both, retryUltra: both });
    const d = deps({ llm });
    const r = await runWith({ inventory: ONLINE }, d, NO_FILES);
    const l = r.lines[0];
    assert.equal(l.decision, "ask_owner");
    assert.equal(l.resolution.status, "unresolved");
    assert.equal(l.resolution.adjudicated_by, "critic");
    assert.equal(l.critic?.verdict, "ask_owner");
    assert.equal(l.critic?.round, DEFAULT_POLICY.max_critic_rounds);
    assert.match(r.owner_questions[0].question, /looks like a cloud service, but the KEV listing "Microsoft \/ Exchange Server" is an on-prem server/);
    assert.ok(r.receipts.some((x) => x.agent === "resolver.retry.lightning") && r.receipts.some((x) => x.agent === "resolver.retry.ultra"));
    assert.equal(l.kev, null);
  });

  test("Ultra's objection to an approved match is a blocker: the resolver must answer it", async () => {
    const sw = "DeskTools 0.84 desktop utilities";
    const docker: Record<string, Ans> = { [sw]: ["Docker", "Desktop Community Edition"] };
    const ranges = async (ids: string[]): Promise<NvdRange[]> => ids.map((cve_id) => ({ cve_id, criteria: "cpe:2.3:a:docker:desktop:*:*:*:*:community:*:*:*", vulnerable: true, version_end_excluding: "2.1.0.1" }));
    // Ultra objects while the row is matched to Docker; the re-decided "no KEV product" it accepts
    const critique = (user: string) => (user.includes(sw) && user.includes('"Docker"') ? "send_back" as const : "approve" as const);
    const llm = mockLlm([], { bolt: docker, lightning: docker, critique, retryLightning: { [sw]: [null, null] } });
    const d = deps({ llm, queries: mockQueries({ nvdCves: ranges }) });
    const r = await runWith({ inventory: [inv("U1", "it-pc-01", "desktop", false, sw)] }, d, NO_FILES);
    const l = r.lines[0];
    assert.equal(l.decision, "monitor");
    assert.equal(l.resolution.status, "no_match");
    assert.ok(d.tracer.events.some((e) => e.agent === "critic" && e.status === "sent_back" && /identity: Ultra judged/.test(e.output_summary ?? "")));
    // the row's first re-decide goes to Lightning (its earlier send-back was for NVD ranges, not a re-vote)
    assert.ok(d.tracer.events.some((e) => e.agent === "resolver.retry.lightning" && e.action === "redecide"));
  });
});

describe("one family per row (combo KEV spellings)", () => {
  const comboQueries = (pairs: KevPair[], entries: KevEntry[], ranges: Record<string, NvdRange[]>) => mockQueries({
    kevPairs: async () => pairs,
    kevByProducts: async (p) => entries.filter((e) => p.some((x) => x.vendor === e.vendor && x.product === e.product)),
    kevVerify: async (ids) => entries.filter((e) => ids.includes(e.cve_id)),
    nvdCves: async (ids) => ids.flatMap((c) => ranges[c] ?? []),
  });
  const TRIO = "Gladinet Triofox 16.4.10317";
  const trioPairs: KevPair[] = [{ vendor: "Gladinet", product: "Triofox" }, { vendor: "Gladinet", product: "CentreStack and Triofox" }];
  const trioEntries = [kev("CVE-2099-1001", "Gladinet", "Triofox", "2026-10-01", "2026-10-22"), kev("CVE-2099-1002", "Gladinet", "CentreStack and Triofox", "2025-04-08", "2025-04-29")];
  const TRIO_CPE = "cpe:2.3:a:gladinet:triofox:*:*:*:*:*:*:*:*";
  const trioNvd: Record<string, NvdRange[]> = {
    "CVE-2099-1001": [{ cve_id: "CVE-2099-1001", criteria: TRIO_CPE, vulnerable: true, version_end_excluding: "16.0" }], // 16.4 outside
    "CVE-2099-1002": [{ cve_id: "CVE-2099-1002", criteria: TRIO_CPE, vulnerable: true, version_end_excluding: "17.0" }], // 16.4 inside
  };

  test("the standalone and the combo spelling of one family give the same decision, checked on every cited CVE", async () => {
    const seen: Record<string, unknown>[] = [];
    for (const product of ["Triofox", "CentreStack and Triofox"]) {
      const ans: Record<string, Ans> = { [TRIO]: ["Gladinet", product] };
      const d = deps({ llm: mockLlm([], { bolt: ans, lightning: ans }), queries: comboQueries(trioPairs, trioEntries, trioNvd) });
      const r = await runWith({ inventory: [inv("G1", "files-01", "server", true, TRIO)] }, d, NO_FILES);
      const l = r.lines[0];
      const last = d.tracer.events.filter((e) => e.agent === "critic" && e.details?.row_id === "G1").pop();
      seen.push({
        decision: l.decision, family: l.resolution.family, cited: (l.kev?.cves ?? []).map((c) => c.cve_id).sort(),
        checked: [...((last?.details?.family_cves as string[]) ?? [])].sort(), version: last?.details?.version_status,
      });
    }
    assert.deepEqual(seen[0], seen[1]);
    // 16.4 is inside CVE-2099-1002's range: never "not affected" on the standalone spelling's CVE alone
    assert.deepEqual(seen[0], { decision: "patch_now", family: "gladinet:triofox", cited: ["CVE-2099-1001", "CVE-2099-1002"], checked: ["CVE-2099-1001", "CVE-2099-1002"], version: "affected" });
  });

  test("Ultra's objection to a match on a combo's second product stays while the resolver repeats it", async () => {
    const sw = "VMware Workstation Pro 17.5.1";
    const combo: Record<string, Ans> = { [sw]: ["VMware", "ESXi and Workstation"] };
    const pairs: KevPair[] = [{ vendor: "VMware", product: "ESXi and Workstation" }, { vendor: "VMware", product: "ESXi" }];
    const entries = [kev("CVE-2099-2001", "VMware", "ESXi and Workstation", "2026-03-01", "2026-03-22"), kev("CVE-2099-2002", "VMware", "ESXi", "2026-05-01", "2026-05-22")];
    const ranges: Record<string, NvdRange[]> = { "CVE-2099-2001": [{ cve_id: "CVE-2099-2001", criteria: "cpe:2.3:a:vmware:workstation:*:*:*:*:*:*:*:*", vulnerable: true, version_end_excluding: "18.0" }] };
    const llm = mockLlm([], { bolt: combo, lightning: { [sw]: [null, null] }, ultra: combo, critique: () => "send_back", retryLightning: combo, retryUltra: combo });
    const d = deps({ llm, queries: comboQueries(pairs, entries, ranges) });
    // a single Ultra critique: once it is spent, only the kept dispute stops the match from shipping as patch_now
    const r = await runWith({ inventory: [inv("V1", "dev-pc-01", "desktop", false, sw)] }, d, { ...NO_FILES, maxUltraCritiques: 1 });
    const l = r.lines[0];
    assert.equal(l.decision, "ask_owner");
    assert.equal(l.resolution.status, "unresolved");
    assert.equal(l.resolution.adjudicated_by, "critic");
    const redecides = d.tracer.events.filter((e) => e.action === "redecide");
    assert.ok(redecides.length >= 1);
    assert.ok(redecides.every((e) => /^0 of 1 changed/.test(e.output_summary ?? "")), redecides.map((e) => e.output_summary).join(" | "));
    assert.match(r.owner_questions.find((q) => q.row_id === "V1")?.question ?? "", /really VMware \/ ESXi and Workstation\?/);
  });
});

describe("version evidence (NVD)", () => {
  const LOG4J = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*";
  const nvd = (end: string) => async (ids: string[]): Promise<NvdRange[]> =>
    ids.filter((c) => c === "CVE-2021-44228").map((cve_id) => ({ cve_id, criteria: LOG4J, vulnerable: true, version_start_including: "2.0.1", version_end_excluding: end }));

  test("a range that settles the version: affected -> patch_now, approved, with the NVD range as evidence", async () => {
    const r = await runWith({ row_ids: ["R01"] }, deps({ queries: mockQueries({ nvdCves: nvd("2.15.0") }) }), NO_FILES);
    const l = r.lines[0];
    assert.equal(l.decision, "patch_now");
    assert.equal(l.critic?.verdict, "approve");
    assert.ok(l.evidence.some((e) => e.source === "zetaris:nvd" && /< 2\.15\.0/.test(e.value)));
    assert.ok(l.evidence.some((e) => e.field === "version_check" && /inside an NVD affected range/.test(e.value)));
    assert.ok(r.manifest.helpers_live.includes("nvdCves"));
  });

  test("NVD data from today's cache is labelled not live with its day; a read through Zetaris in this run is live", async () => {
    const reads = (state: string) => {
      const status: { key: string; state: string; ranges: number; as_of: string }[] = [];
      const inner = nvd("2.15.0");
      return {
        nvdCves: async (ids: string[]) => { const r = await inner(ids); for (const key of ids) status.push({ key, state, ranges: r.length, as_of: "2026-10-26" }); return r; },
        nvdStatus: () => status,
        nvdCached: () => state === "cached",
      } as Partial<Queries>;
    };
    const cached = await runWith({ row_ids: ["R01"] }, deps({ queries: mockQueries(reads("cached")) }), NO_FILES);
    const ev = cached.lines[0].evidence.filter((e) => e.source === "zetaris:nvd");
    assert.ok(ev.some((e) => e.field === "version_check") && ev.some((e) => e.field === "version_range"));
    assert.ok(ev.every((e) => e.live === false && e.as_of === "2026-10-26"), JSON.stringify(ev));
    const src = cached.manifest.sources.find((s) => s.name === "NIST NVD");
    assert.equal(src?.live, false);
    assert.equal(src?.as_of, "2026-10-26");
    assert.match(src?.object ?? "", /\(1 cached 2026-10-26\)/);

    const fresh = await runWith({ row_ids: ["R01"] }, deps({ queries: mockQueries(reads("ok")) }), NO_FILES);
    const ev2 = fresh.lines[0].evidence.filter((e) => e.source === "zetaris:nvd");
    assert.ok(ev2.length >= 2 && ev2.every((e) => e.live === true));
    assert.equal(fresh.manifest.sources.find((s) => s.name === "NIST NVD")?.live, true);
  });

  test("outside every NVD range of the family -> monitor, saying so", async () => {
    const r = await runWith({ row_ids: ["R01"] }, deps({ queries: mockQueries({ nvdCves: nvd("2.14.0") }) }), NO_FILES);
    const l = r.lines[0];
    assert.equal(l.decision, "monitor");
    assert.equal(l.target_date, "2027-01-24");
    assert.match(l.why, /NVD's version ranges place version 2\.14\.1 outside all of them/);
    assert.ok(!l.evidence.some((e) => e.query === "policy" && /^patch_now/.test(e.value)));
  });
});

describe("Windows rows", () => {
  test("rows that name the edition but no build share one owner question per edition", async () => {
    const rows = [
      inv("W1", "pc-01", "laptop", false, "Windows 11 Pro 23H2"), inv("W2", "pc-02", "laptop", false, "Win 11 Enterprise 23H2"),
      inv("W3", "pc-03", "desktop", false, "Windows 10 Pro 22H2"),
    ];
    const win: Record<string, Ans> = Object.fromEntries(rows.map((x) => [x.software, ["Microsoft", "Windows"]]));
    const d = deps({ llm: mockLlm([], { bolt: win, lightning: win }) });
    const r = await runWith({ inventory: rows }, d, NO_FILES);
    assert.deepEqual(r.summary, { patch_now: 3, this_cycle: 0, monitor: 0, ask_owner: 0 });
    assert.equal(r.owner_questions.length, 2);
    const w11 = r.owner_questions.find((x) => /Windows 11 23H2/.test(x.question)) as { question: string; row_ids?: string[] };
    assert.deepEqual(w11.row_ids, ["W1", "W2"]);
    assert.match(w11.question, /these 2 machines \(pc-01, pc-02\)/);
    assert.ok(d.tracer.events.some((e) => e.action === "windows_grouped"));
  });
});

describe("requests", () => {
  test("inline rows get safe defaults, and row_ids filter them", async () => {
    const d = deps();
    const r = await runWith({
      inventory: [{ software: "Notepad++ v8.6" }, { row_id: "X2", software: "PAN-OS 10.2.7", internet_facing: "yes", asset_name: "fw" }],
      row_ids: ["X2"],
    } as never, d, NO_FILES);
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
      const r = await runWith(req as never, deps(), NO_FILES);
      assert.equal(r.status, "error");
      assert.equal(r.error?.type, "invalid_request");
      assert.equal(r.error?.recoverable, true);
      assert.match(r.error?.message ?? "", re);
      assert.deepEqual(r.lines, []);
    }
  });

  test("a per-run policy override changes the dates", async () => {
    const r = await runWith({ policy: { sla_days: { patch_now: 2 } }, row_ids: ["R02"] }, deps(), NO_FILES);
    assert.equal(r.lines[0].target_date, "2026-10-28");
    assert.equal(r.manifest.policy.sla_days.patch_now, 2);
  });
});

describe("failures degrade, never crash", () => {
  test("inventory unreadable -> error response", async () => {
    const r = await runWith({}, deps({ queries: mockQueries({ inventory: async () => { throw new Error("Zetaris 400: table not found"); } }) }), NO_FILES);
    assert.equal(r.status, "error");
    assert.equal(r.error?.type, "inventory_unavailable");
  });

  test("KEV names unreadable -> partial, every row ask_owner, no model call, the critic skipped", async () => {
    const llm = mockLlm();
    const d = deps({ llm, queries: mockQueries({ kevPairs: async () => { throw new Error("watchdog fired"); } }) });
    const r = await runWith({}, d, NO_FILES);
    assert.equal(r.status, "partial");
    assert.equal(r.summary.ask_owner, INVENTORY.length);
    assert.equal(r.owner_questions.length, INVENTORY.length);
    assert.equal(llm.calls.length, 0);
    assert.ok(r.manifest.helpers_dormant.some((h) => h.startsWith("critic")));
  });

  test("an empty KEV name list is a failed read, not 'nothing exploited': every row ask_owner", async () => {
    const r = await runWith({}, deps({ queries: mockQueries({ kevPairs: async () => [] }) }), NO_FILES);
    assert.equal(r.status, "partial");
    assert.equal(r.summary.monitor, 0);
    assert.equal(r.summary.ask_owner, INVENTORY.length);
    assert.match(r.owner_questions[0].reason, /no \(vendor, product\) pairs/);
  });

  test("KEV entries missing for a matched family -> the critic's counterfactual check: never relaxed to monitor", async () => {
    const q = mockQueries({ kevByProducts: async (pairs) => ENTRIES.filter((e) => e.product !== "PAN-OS" && pairs.some((p) => p.vendor === e.vendor && p.product === e.product)) });
    const d2 = deps({ queries: q });
    const r = await runWith({ row_ids: ["R01", "R02"] }, d2, NO_FILES);
    const L = by(r);
    assert.equal(L.R01.decision, "patch_now");
    assert.equal(L.R02.decision, "ask_owner");
    // the counterfactual blocker sends the row back; the re-decide finds nothing better, so the owner is asked
    assert.ok(d2.tracer.events.some((e) => e.agent === "critic" && e.details?.row_id === "R02" && e.status === "sent_back" && /counterfactual failed/.test(e.output_summary ?? "")));
  });

  test("KEV entries unreadable -> matched rows fail closed to ask_owner", async () => {
    const r = await runWith({}, deps({ queries: mockQueries({ kevByProducts: async () => { throw new Error("timeout"); } }) }), NO_FILES);
    assert.equal(r.status, "partial");
    assert.equal(r.summary.patch_now, 0);
    assert.equal(r.summary.monitor, 2); // the two no_match rows
    assert.equal(r.summary.ask_owner, 4);
  });

  test("EPSS unreadable -> patch_now stays, nothing relaxed to monitor", async () => {
    const r = await runWith({}, deps({ queries: mockQueries({ epss: async () => { throw new Error("FIRST API 503"); } }) }), NO_FILES);
    assert.equal(r.status, "partial");
    assert.equal(r.summary.patch_now, 4);
    assert.equal(r.summary.monitor, 0);
    assert.equal(r.summary.ask_owner, 2);
  });

  test("EPSS unreadable + NVD 'not affected' -> ask_owner with the NVD finding, never monitor", async () => {
    const outside = async (ids: string[]): Promise<NvdRange[]> => ids.filter((c) => c === "CVE-2021-44228")
      .map((cve_id) => ({ cve_id, criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", vulnerable: true, version_start_including: "2.0.1", version_end_excluding: "2.14.0" }));
    const down = async (): Promise<EpssScore[]> => { throw new Error("FIRST API 503"); };
    const r = await runWith({ row_ids: ["R01"] }, deps({ queries: mockQueries({ nvdCves: outside, epss: down, epssVerify: down }) }), NO_FILES);
    const l = r.lines[0];
    assert.equal(r.status, "partial");
    assert.equal(l.decision, "ask_owner");
    assert.equal(r.summary.monitor, 0);
    assert.ok(l.evidence.some((e) => e.field === "version_check" && /outside every NVD affected range/.test(e.value)));
    assert.ok(l.evidence.some((e) => e.field === "rule" && /FIRST EPSS could not be read \(FIRST API 503\)/.test(e.value) && /fail-closed/.test(e.value)));
    const q = r.owner_questions.find((x) => x.row_id === "R01");
    assert.match(q?.question ?? "", /Log4j2 2\.14\.1, outside NVD's affected ranges for CVE-2021-44228\? Otherwise re-run when FIRST EPSS can be read/);
  });

  test("notAffectedBlock: relax only with KEV and EPSS read, and every cited CVE checked", () => {
    const cited = [{ cve_id: "CVE-2099-0001" }, { cve_id: " cve-2099-0002 " }];
    assert.equal(notAffectedBlock(["CVE-2099-0001", "CVE-2099-0002"], cited, { kevError: null, epssError: null }), null);
    assert.equal(notAffectedBlock(["CVE-2099-0001", "CVE-2099-0002"], cited, { epssError: "503" })?.kind, "source_unavailable");
    const both = notAffectedBlock(["CVE-2099-0001", "CVE-2099-0002"], cited, { kevError: "timeout", epssError: "503" });
    assert.equal(both?.kind === "source_unavailable" ? both.what : null, "the KEV entries and FIRST EPSS could not be read");
    const part = notAffectedBlock(["CVE-2099-0001"], cited, {});
    assert.deepEqual(part?.kind === "uncovered" ? part.cves : null, ["CVE-2099-0002"]);
  });

  test("the verifier blocks a line whose cited KEV value no longer matches the live catalogue", async () => {
    const changed = (ids: string[]) => ENTRIES.filter((e) => ids.includes(e.cve_id)).map((e) => (e.cve_id === "CVE-2021-44228" ? { ...e, due_date: "2030-01-01" } : e));
    const r = await runWith({ row_ids: ["R01", "R02"] }, deps({ queries: mockQueries({ kevVerify: async (ids) => changed(ids) }) }), NO_FILES);
    const L = by(r);
    assert.equal(L.R01.verified, false);
    assert.match(L.R01.verifier_notes.join(" "), /CVE-2021-44228 due_date: cited "2021-12-24", live "2030-01-01"/);
    assert.equal(L.R02.verified, true);
  });

  test("models failing -> deterministic fallback, failed receipts kept, partial", async () => {
    const r = await runWith({}, deps({ llm: mockLlm(["bolt", "lightning"]) }), NO_FILES);
    assert.equal(r.status, "partial");
    assert.ok(r.receipts.filter((x) => x.agent.startsWith("jury.")).every((x) => x.status === "error"));
    assert.equal(r.lines.find((l) => l.row_id === "R02")?.resolution.adjudicated_by, "rules");
  });

  test("a model client that throws is recorded as an error receipt", async () => {
    const throwing: Llm = { async chat() { throw new Error("socket hang up"); } };
    const r = await runWith({ row_ids: ["R02"] }, deps({ llm: throwing }), NO_FILES);
    assert.ok(r.receipts.length >= 2);
    assert.ok(r.receipts.every((x) => x.status === "error" && /socket hang up/.test(x.error ?? "")));
  });

  test("an unexpected exception becomes an internal_error response", async () => {
    const broken: Pipeline = { name: "broken", prepare: () => { throw new Error("boom"); }, family: (p) => p.product, vote: () => { throw new Error("x"); } };
    const r = await runWith({}, deps(), { ...NO_FILES, pipeline: broken });
    assert.equal(r.status, "error");
    assert.equal(r.error?.type, "internal_error");
    assert.equal(r.error?.recoverable, false);
  });
});

describe("modes", () => {
  test("sample mode: no model, deterministic votes, stamped sample, no receipts, still reviewed and verified", async () => {
    const d = deps({ mode: "sample", llm: null });
    const r = await runWith({}, d, NO_FILES);
    assert.equal(r.mode, "sample");
    assert.equal(r.status, "success");
    assert.equal(r.receipts.length, 0);
    assert.ok(r.lines.every((l) => l.resolution.votes.every((v) => v.juror === "normaliser")));
    assert.equal(r.manifest.sources[1].live, false);
    assert.equal(d.tracer.events.find((e) => e.action === "deterministic_vote")?.status, "ok");
    assert.ok(r.manifest.helpers_live.includes("critic") && r.manifest.helpers_live.includes("verifier"));
    assert.ok(r.lines.filter((l) => l.critic).length > 0);
  });

  test("live mode without a model client: deterministic fallback, labelled partial", async () => {
    const r = await runWith({}, deps({ llm: null }), NO_FILES);
    assert.equal(r.status, "partial");
    assert.equal(r.receipts.length, 0);
  });
});
