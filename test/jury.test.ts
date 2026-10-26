// Resolver jury tests with a scripted mock Llm (no network). KEV pairs are real spellings.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { MODELS } from "../src/contracts.ts";
import type { Candidate, ChatRequest, ChatResult, InventoryRow, JurorVote, Llm, ModelKey, TraceEvent, Tracer } from "../src/contracts.ts";
import { buildAdjudicatorPrompt, buildJurorPrompt, parseVotes, runJury, runSingleJuror } from "../src/agents/jury.ts";
import type { JuryItem } from "../src/agents/jury.ts";
import { deterministicVoteV0, familyV0 } from "../src/resolve/candidates.ts";

function memTracer(): Tracer & { events: TraceEvent[] } {
  const events: TraceEvent[] = [];
  return { run_id: "t", file: "", events, emit(e) { events.push({ ts: "", run_id: "t", ...e }); } };
}

function cand(vendor: string, product: string, family = familyV0({ vendor, product })): Candidate {
  return { vendor, product, family, score: 0.8, reason: "test" };
}

const C = {
  log4j: [cand("Apache", "Log4j2"), cand("Apache", "Tomcat")],
  exch: [cand("Microsoft", "Exchange Server"), cand("Microsoft", "Exchange")],
  citrix: [cand("Citrix", "NetScaler"), cand("Citrix", "NetScaler ADC and Gateway")],
  forti: [cand("Fortinet", "FortiClient EMS"), cand("Fortinet", "FortiOS")],
};

function item(rowId: string, software: string, candidates: Candidate[], version: string | null = null): JuryItem {
  const row: InventoryRow = { row_id: rowId, asset_id: `A-${rowId}`, asset_name: `host-${rowId}`, asset_type: "server", internet_facing: false, owner_team: "IT", software };
  return { row, candidates, version };
}

type Answer = Record<string, unknown> | "omit";
interface Script { bolt?: Record<string, Answer>; lightning?: Record<string, Answer>; ultra?: Record<string, Answer>; fail?: ModelKey[]; }
const A = (vendor: string | null, product: string | null, extra: Record<string, unknown> = {}): Answer =>
  ({ vendor, product, product_type: "server", version: null, confidence: 0.9, ...extra });

/** A mock model: reads the item lines from the prompt and answers from the script, keyed by software. */
function mockLlm(script: Script): Llm & { calls: ChatRequest[] } {
  const calls: ChatRequest[] = [];
  let n = 0;
  return {
    calls,
    async chat(req: ChatRequest): Promise<ChatResult> {
      calls.push(req);
      n++;
      const receipt = {
        call_id: `c${n}`, agent: req.agent, requested_model: MODELS[req.model], response_model: MODELS[req.model],
        routed_model: MODELS[req.model], receipt_id: `rcpt_${req.model}_${n}`, latency_ms: 5, status: "ok" as const,
      };
      if (script.fail?.includes(req.model)) return { text: "", json: null, receipt: { ...receipt, receipt_id: null, status: "error", error: "HTTP 502" } };
      const items = [...req.user.matchAll(/^(I\d+) (".*") \(asset type: [^)]*\)$/gm)].map((m) => ({ id: m[1], software: JSON.parse(m[2]) as string }));
      const table = script[req.model as "bolt" | "lightning" | "ultra"] ?? {};
      const results = items.flatMap(({ id, software }) => {
        const a = table[software];
        if (a === "omit" || a === undefined) return [];
        return [{ id, ...a }];
      });
      const json = { results };
      return { text: JSON.stringify(json), json, receipt };
    },
  };
}

const fallbackVote = (it: JuryItem): JurorVote => deterministicVoteV0(it.row, it.candidates);
const opts = (llm: Llm | null, tracer: Tracer, mode: "live" | "sample" = "live") => ({ llm, tracer, mode, fallbackVote });

describe("agreement", () => {
  test("Bolt and Lightning agree: matched, no Ultra call, votes keep their receipts, confidence 1", async () => {
    const llm = mockLlm({
      bolt: { "log4j-core 2.14.1": A("Apache", "Log4j2", { product_type: "library", version: "2.14.1" }) },
      lightning: { "log4j-core 2.14.1": A("apache ", " log4j2", { product_type: "library", version: "2.14.1" }) },
    });
    const tr = memTracer();
    const out = await runJury([item("R1", "log4j-core 2.14.1", C.log4j)], opts(llm, tr));
    const r = out.resolutions[0];
    assert.equal(r.status, "matched");
    assert.equal(r.vendor, "Apache");
    assert.equal(r.product, "Log4j2");
    assert.equal(r.family, "Apache Log4j2");
    assert.equal(r.adjudicated_by, null);
    assert.equal(r.confidence, 1);
    assert.equal(r.product_type, "library");
    assert.equal(r.version, "2.14.1");
    assert.deepEqual(r.votes.map((v) => [v.juror, v.receipt_id]), [["bolt", "rcpt_bolt_1"], ["lightning", "rcpt_lightning_2"]]);
    assert.equal(llm.calls.filter((c) => c.model === "ultra").length, 0);
    assert.deepEqual(out.stats.calls, { bolt: 1, lightning: 1, ultra: 0 });
    assert.equal(tr.events.filter((e) => e.action === "jury_vote").length, 2);
    assert.equal(tr.events.some((e) => e.action === "split_detected"), false);
    // jury events never carry a top-level model field (the receipts audit counts only real calls)
    assert.equal(tr.events.some((e) => e.model !== undefined), false);
  });

  test("both null: no_match without Ultra", async () => {
    const llm = mockLlm({ bolt: { "Notepad++ 8.6": A(null, null) }, lightning: { "Notepad++ 8.6": A("null", "none") } });
    const out = await runJury([item("R1", "Notepad++ 8.6", C.log4j)], opts(llm, memTracer()));
    assert.equal(out.resolutions[0].status, "no_match");
    assert.equal(out.resolutions[0].vendor, null);
    assert.equal(out.stats.calls.ultra, 0);
  });

  test("agreement is by product family: two KEV spellings of one family agree (Lightning's spelling kept)", async () => {
    const fam = "Citrix NetScaler ADC family";
    const cands = [cand("Citrix", "NetScaler", fam), cand("Citrix", "NetScaler ADC and Gateway", fam), cand("Citrix", "ShareFile")];
    const llm = mockLlm({
      bolt: { "Citrix NetScaler ADC 13.1": A("Citrix", "NetScaler") },
      lightning: { "Citrix NetScaler ADC 13.1": A("Citrix", "NetScaler ADC and Gateway") },
    });
    const out = await runJury([item("R1", "Citrix NetScaler ADC 13.1", cands)], opts(llm, memTracer()));
    assert.equal(out.resolutions[0].status, "matched");
    assert.equal(out.resolutions[0].product, "NetScaler ADC and Gateway");
    assert.equal(out.resolutions[0].family, fam);
    assert.equal(out.stats.calls.ultra, 0);
  });

  test("a look-alike both jurors agree on is accepted here: catching it is the critic's job", async () => {
    const llm = mockLlm({
      bolt: { "Exchange Online (M365 tenant)": A("Microsoft", "Exchange", { product_type: "cloud_service" }) },
      lightning: { "Exchange Online (M365 tenant)": A("Microsoft", "Exchange", { product_type: "cloud_service" }) },
    });
    const out = await runJury([item("R1", "Exchange Online (M365 tenant)", C.exch)], opts(llm, memTracer()));
    assert.equal(out.resolutions[0].status, "matched");
    assert.equal(out.resolutions[0].product_type, "cloud_service");
  });
});

describe("splits and Ultra", () => {
  test("a split goes to ONE batched Ultra call holding only the split rows; Ultra decides", async () => {
    const llm = mockLlm({
      bolt: {
        "log4j-core 2.14.1": A("Apache", "Log4j2"), "Citrix NetScaler ADC 13.1": A("Citrix", "NetScaler"),
        "MS Exchange Svr 2019": A("Microsoft", "Exchange Server"), "FortiClient VPN 7.0.9": A("Fortinet", "FortiClient EMS"),
      },
      lightning: {
        "log4j-core 2.14.1": A("Apache", "Log4j2"), "Citrix NetScaler ADC 13.1": A("Citrix", "NetScaler ADC and Gateway"),
        "MS Exchange Svr 2019": A("Microsoft", "Exchange Server"), "FortiClient VPN 7.0.9": A(null, null),
      },
      ultra: {
        "Citrix NetScaler ADC 13.1": A("Citrix", "NetScaler ADC and Gateway", { reason: "ADC is the appliance" }),
        "FortiClient VPN 7.0.9": A(null, null, { product_type: "client", reason: "EMS is the server, not the client" }),
      },
    });
    const tr = memTracer();
    const items = [
      item("R1", "log4j-core 2.14.1", C.log4j), item("R2", "Citrix NetScaler ADC 13.1", C.citrix),
      item("R3", "MS Exchange Svr 2019", C.exch), item("R4", "FortiClient VPN 7.0.9", C.forti),
    ];
    const out = await runJury(items, opts(llm, tr));
    const ultraCalls = llm.calls.filter((c) => c.model === "ultra");
    assert.equal(ultraCalls.length, 1);
    assert.equal(ultraCalls[0].agent, "jury.adjudicate");
    assert.match(ultraCalls[0].user, /^I1 "Citrix NetScaler ADC 13\.1"/m);
    assert.match(ultraCalls[0].user, /juror A: \(Citrix, NetScaler\)/);
    assert.match(ultraCalls[0].user, /juror B: \(Citrix, NetScaler ADC and Gateway\)/);
    assert.match(ultraCalls[0].user, /^I2 "FortiClient VPN 7\.0\.9"/m);
    assert.match(ultraCalls[0].user, /juror B: null \(no candidate fits\)/);
    assert.doesNotMatch(ultraCalls[0].user, /log4j|Exchange/);

    const [r1, r2, r3, r4] = out.resolutions;
    assert.equal(r1.adjudicated_by, null);
    assert.equal(r3.adjudicated_by, null);
    assert.equal(r2.status, "matched");
    assert.equal(r2.product, "NetScaler ADC and Gateway");
    assert.equal(r2.adjudicated_by, "ultra");
    assert.equal(r2.confidence, 0.67); // Lightning and Ultra agree; Bolt did not
    assert.deepEqual(r2.votes.map((v) => v.juror), ["bolt", "lightning", "ultra"]);
    assert.equal(r2.votes[2].receipt_id?.startsWith("rcpt_ultra_"), true);
    assert.equal(r4.status, "no_match");
    assert.equal(r4.adjudicated_by, "ultra");
    assert.equal(r4.product_type, "client");
    assert.equal(out.stats.splits, 2);
    assert.equal(out.stats.adjudicated, 2);

    const split = tr.events.find((e) => e.action === "split_detected");
    assert.equal(split?.target_agent, "jury.adjudicate");
    const adj = tr.events.find((e) => e.action === "ultra_adjudication");
    assert.equal(adj?.status, "ok");
    const decisions = (adj?.details as { decisions: Record<string, string>[] }).decisions;
    assert.deepEqual(decisions.map((d) => d.sided_with), ["lightning", "lightning"]);
  });

  test("a half answer (\"Apache\", \"null\") counts as a null vote, so it is a split", async () => {
    const llm = mockLlm({
      bolt: { "log4j-core 2.14.1": A("Apache", "null") },
      lightning: { "log4j-core 2.14.1": A("Apache", "Log4j2") },
      ultra: { "log4j-core 2.14.1": A("Apache", "Log4j2") },
    });
    const tr = memTracer();
    const out = await runJury([item("R1", "log4j-core 2.14.1", C.log4j)], opts(llm, tr));
    assert.equal(out.stats.calls.ultra, 1);
    assert.equal(out.resolutions[0].product, "Log4j2");
    assert.equal(out.resolutions[0].votes[0].product, null);
    const bolt = tr.events.find((e) => e.action === "jury_vote" && e.agent === "jury.bolt");
    assert.match(JSON.stringify(bolt?.details), /half an answer/);
  });

  test("an answer outside the row's candidate list is discarded (no vote), so it is a split", async () => {
    const llm = mockLlm({
      bolt: { "log4j-core 2.14.1": A("Apache", "Log4j") },
      lightning: { "log4j-core 2.14.1": A("Apache", "Log4j2") },
      ultra: { "log4j-core 2.14.1": A("Apache", "Log4j2") },
    });
    const out = await runJury([item("R1", "log4j-core 2.14.1", C.log4j)], opts(llm, memTracer()));
    const r = out.resolutions[0];
    assert.deepEqual(r.votes.map((v) => v.juror), ["lightning", "ultra"]);
    assert.equal(r.adjudicated_by, "ultra");
    assert.equal(r.confidence, 1);
  });

  test("Ultra failing leaves the split rows unresolved (never guessed)", async () => {
    const llm = mockLlm({
      bolt: { "Citrix NetScaler ADC 13.1": A("Citrix", "NetScaler") },
      lightning: { "Citrix NetScaler ADC 13.1": A("Citrix", "NetScaler ADC and Gateway") },
      fail: ["ultra"],
    });
    const tr = memTracer();
    const out = await runJury([item("R1", "Citrix NetScaler ADC 13.1", C.citrix)], opts(llm, tr));
    assert.equal(out.resolutions[0].status, "unresolved");
    assert.equal(out.resolutions[0].votes.length, 2);
    assert.equal(out.stats.failed_calls, 1);
    assert.equal(tr.events.find((e) => e.action === "ultra_adjudication")?.status, "error");
  });

  test("Ultra omitting a row leaves that row unresolved", async () => {
    const llm = mockLlm({
      bolt: { "Citrix NetScaler ADC 13.1": A("Citrix", "NetScaler") },
      lightning: { "Citrix NetScaler ADC 13.1": A(null, null) },
      ultra: { "Citrix NetScaler ADC 13.1": "omit" },
    });
    const out = await runJury([item("R1", "Citrix NetScaler ADC 13.1", C.citrix)], opts(llm, memTracer()));
    assert.equal(out.resolutions[0].status, "unresolved");
    assert.equal(out.stats.unresolved, 1);
  });
});

describe("fallbacks and batching", () => {
  test("both juror calls failing: the deterministic vote decides, labelled as a fallback, no Ultra call", async () => {
    const llm = mockLlm({ fail: ["bolt", "lightning"] });
    const tr = memTracer();
    const pan = [cand("Palo Alto Networks", "PAN-OS"), cand("Palo Alto Networks", "Expedition")];
    pan[0].score = 0.9; pan[1].score = 0.2;
    const out = await runJury([item("R1", "PAN-OS 10.2.7", pan)], opts(llm, tr));
    assert.equal(out.stats.calls.ultra, 0);
    assert.equal(out.resolutions[0].status, "matched");
    assert.equal(out.resolutions[0].adjudicated_by, "rules");
    assert.deepEqual(out.resolutions[0].votes.map((v) => v.juror), ["normaliser"]);
    assert.equal(tr.events.find((e) => e.action === "deterministic_vote")?.status, "fallback");
    assert.equal(out.stats.failed_calls, 2);
  });

  test("no model client (sample mode): deterministic votes only, status ok", async () => {
    const tr = memTracer();
    const pan = [cand("Palo Alto Networks", "PAN-OS")];
    pan[0].score = 0.9;
    const out = await runJury([item("R1", "PAN-OS 10.2.7", pan), item("R2", "MS Exchange Svr", C.exch)], opts(null, tr, "sample"));
    assert.equal(out.resolutions[0].status, "matched");
    assert.equal(out.resolutions[0].adjudicated_by, "rules");
    assert.equal(out.resolutions[1].status, "unresolved"); // two families score alike: ask the owner, never guess
    assert.equal(tr.events.find((e) => e.action === "deterministic_vote")?.status, "ok");
    assert.equal(out.stats.deterministic, 2);
  });

  test("rows without candidates are no_match by rule and never reach a model", async () => {
    const llm = mockLlm({});
    const out = await runJury([item("R1", "Notepad++ 8.6", [])], opts(llm, memTracer()));
    assert.equal(llm.calls.length, 0);
    assert.equal(out.resolutions[0].status, "no_match");
    assert.equal(out.resolutions[0].adjudicated_by, "rules");
    assert.equal(out.stats.no_candidates, 1);
  });

  test("batches of 10: 25 rows make 3 batches and 6 juror calls; output order matches input", async () => {
    const names = Array.from({ length: 25 }, (_, i) => `log4j-core 2.${i}.0`);
    const ans = Object.fromEntries(names.map((s) => [s, A("Apache", "Log4j2")]));
    const llm = mockLlm({ bolt: ans, lightning: ans });
    const items = names.map((s, i) => item(`R${i + 1}`, s, C.log4j));
    const out = await runJury(items, opts(llm, memTracer()));
    assert.equal(out.stats.batches, 3);
    assert.equal(llm.calls.length, 6);
    assert.deepEqual(out.resolutions.map((r) => r.row_id), items.map((i) => i.row.row_id));
    assert.ok(out.resolutions.every((r) => r.status === "matched"));
    const sizes = llm.calls.filter((c) => c.model === "bolt").map((c) => (c.user.match(/^I\d+ /gm) ?? []).length).sort((a, b) => a - b);
    assert.deepEqual(sizes, [5, 10, 10]);
  });
});

describe("prompts and validation", () => {
  test("the juror prompt lists each item with its asset type and its own candidates", () => {
    const p = buildJurorPrompt([{ localId: "I1", item: item("R1", 'log4j "core" 2.14.1', C.log4j) }]);
    assert.match(p.system, /AT MOST ONE/);
    assert.match(p.system, /cloud or online service is not the on-premises server/);
    assert.match(p.user, /^I1 "log4j \\"core\\" 2\.14\.1" \(asset type: server\)$/m);
    assert.match(p.user, /candidates: \(Apache, Log4j2\) \| \(Apache, Tomcat\)/);
  });

  test("the adjudicator prompt shows a missing vote as 'no valid answer'", () => {
    const p = buildAdjudicatorPrompt([{ localId: "I1", item: item("R1", "x", C.log4j), bolt: null, lightning: null }]);
    assert.match(p.user, /juror A: no valid answer/);
  });

  test("parseVotes: bare arrays, numeric ids, unknown ids, duplicates, bad types, string confidence", () => {
    const entries = [{ localId: "I1", item: item("R1", "a", C.log4j) }, { localId: "I2", item: item("R2", "b", C.exch) }];
    const p = parseVotes([
      { id: 1, vendor: "Apache", product: "Log4j2", product_type: "LIBRARY", confidence: "0.7", version: 2.14 },
      { id: "I1", vendor: "Apache", product: "Tomcat" },
      { id: "I9", vendor: "x", product: "y" },
      { id: "I2", vendor: "Microsoft", product: "Exchange", product_type: "saas", confidence: 95 },
    ], entries);
    const v1 = p.votes.get("I1");
    assert.equal(v1?.candidate?.product, "Log4j2");
    assert.equal(v1?.product_type, "library");
    assert.equal(v1?.confidence, 0.7);
    assert.equal(v1?.version, "2.14");
    const v2 = p.votes.get("I2");
    assert.equal(v2?.product_type, "unknown");
    assert.equal(v2?.confidence, 0.95);
    assert.ok(p.problems.some((x) => /duplicate/.test(x)));
    assert.ok(p.problems.some((x) => /unknown id/.test(x)));
    assert.ok(p.problems.some((x) => /invalid product_type/.test(x)));
    assert.equal(parseVotes(null, entries).votes.size, 0);
    assert.deepEqual(parseVotes({ answer: [] }, entries).problems, ["reply has no results array"]);
  });

  test("a vendor typed differently still maps when the product names one candidate", () => {
    const p = parseVotes({ results: [{ id: "I1", vendor: "Microsoft Corporation", product: "Exchange Server" }] }, [{ localId: "I1", item: item("R1", "x", C.exch) }]);
    assert.equal(p.votes.get("I1")?.candidate?.vendor, "Microsoft");
  });
});

test("runSingleJuror: one model, same prompt, no Ultra; a missing vote is unresolved", async () => {
  const llm = mockLlm({ lightning: { "log4j-core 2.14.1": A("Apache", "Log4j2"), "Citrix NetScaler ADC 13.1": "omit" } });
  const rs = await runSingleJuror([item("R1", "log4j-core 2.14.1", C.log4j), item("R2", "Citrix NetScaler ADC 13.1", C.citrix)], "lightning", { llm, tracer: memTracer() });
  assert.equal(rs[0].status, "matched");
  assert.equal(rs[1].status, "unresolved");
  assert.equal(llm.calls.length, 1);
  assert.equal(llm.calls[0].agent, "single.lightning");
});
