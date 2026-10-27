// Tests for the World Model wrapper (src/engine/index.ts). No network: the engine is in-process.
// Fixtures are small synthetic rows written for these tests (not the sealed evaluation rows).

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  createLedgerWorld, ledgerIds, sourceDate, defaultSourceLabels, ENGINE_SOURCE,
} from "../src/engine/index.ts";
import type { IngestRunInput } from "../src/engine/index.ts";
import type { InventoryRow, KevEntry, KevPair, Resolution, TraceEvent } from "../src/contracts.ts";

const AS_OF = "2026-10-27";

function row(row_id: string, asset_id: string, software: string, internet_facing = false): InventoryRow {
  return {
    row_id, asset_id, asset_name: `${asset_id} host`, asset_type: "server",
    internet_facing, owner_team: "it", software,
  };
}

function kevEntry(cve_id: string, vendor: string, product: string, date_added: string, due_date: string): KevEntry {
  return {
    cve_id, vendor, product, vulnerability_name: `${vendor} ${product} flaw`, date_added, due_date,
    ransomware_use: "Unknown", required_action: "Apply updates per vendor instructions.",
    short_description: "test fixture", notes: "", catalog_version: "2026.10.23",
  };
}

function matched(row_id: string, vendor: string, product: string, family: string, receipts: string[], adjudicated_by: Resolution["adjudicated_by"] = null): Resolution {
  const jurors = ["bolt", "lightning", "ultra"] as const;
  return {
    row_id, status: "matched", vendor, product, family, version: "1.0", product_type: "server",
    votes: receipts.map((r, i) => ({ row_id, juror: jurors[i], vendor, product, confidence: 0.9, receipt_id: r })),
    adjudicated_by, confidence: 0.9,
  };
}

function familyOf(p: KevPair): string {
  const v = p.vendor.trim().toLowerCase();
  const pr = p.product.trim().toLowerCase();
  if (v === "citrix" && pr.startsWith("netscaler")) return "Citrix NetScaler ADC/Gateway";
  if (v === "apache" && pr.startsWith("log4j")) return "Apache Log4j";
  return `${p.vendor.trim()} ${p.product.trim()}`;
}

function baseInput(overrides: Partial<IngestRunInput> = {}): IngestRunInput {
  return {
    runId: "run-test-1",
    asOf: AS_OF,
    rows: [
      row("r01", "srv-web-01", "log4j-core 2.14.1 (bundled in ERP-Portal WAR)", true),
      row("r02", "srv-web-01", "Apache Tomcat 9.0.30", true),
      row("r03", "gw-01", "Citrix NetScaler ADC 13.1", true),
      row("r04", "ws-001", "Exchange Online (M365 tenant)"),
      row("r05", "ws-002", "Notepad++ 8.4"),
    ],
    resolutions: [
      matched("r01", "Apache", "Log4j2", "Apache Log4j", ["rcpt-b1", "rcpt-l1"]),
      matched("r02", "Apache", "Tomcat", "Apache Tomcat", ["rcpt-b2", "rcpt-l2", "rcpt-u2"], "ultra"),
      matched("r03", "Citrix", "NetScaler ADC and NetScaler Gateway", "Citrix NetScaler ADC/Gateway", ["rcpt-b3", "rcpt-l3"]),
      {
        row_id: "r04", status: "no_match", vendor: null, product: null, family: null, version: null,
        product_type: "cloud_service", adjudicated_by: "critic", confidence: 0.3,
        votes: [{ row_id: "r04", juror: "bolt", vendor: "Microsoft", product: "Exchange Server", confidence: 0.95, receipt_id: "rcpt-b4" }],
      },
      {
        row_id: "r05", status: "no_match", vendor: null, product: null, family: null, version: "8.4",
        product_type: "client", adjudicated_by: "rules", confidence: 0.8,
        votes: [{ row_id: "r05", juror: "normaliser", vendor: null, product: null, confidence: 0.8 }],
      },
    ],
    kev: [
      kevEntry("CVE-2021-44228", "Apache", "Log4j2", "2021-12-10", "2021-12-24"),
      kevEntry("CVE-2020-1938", "Apache", "Tomcat", "2022-03-03", "2022-03-17"),
      kevEntry("CVE-2023-4966", "Citrix", "NetScaler ADC and NetScaler Gateway", "2023-10-18", "2023-11-08"),
    ],
    epss: [
      { cve_id: "CVE-2021-44228", epss: 0.94358, percentile: 0.99957, score_date: "2026-10-26" },
      { cve_id: "CVE-2020-1938", epss: 0.9447, percentile: 0.9998, score_date: "2026-10-26" },
      { cve_id: "CVE-2023-4966", epss: 0.9425, percentile: 0.9993, score_date: "2026-10-26" },
    ],
    decisions: [
      {
        row_id: "r01", decision: "patch_now", target_date: "2026-11-03", verified: true,
        kev: { cves: [kevEntry("CVE-2021-44228", "Apache", "Log4j2", "2021-12-10", "2021-12-24")], earliest_due: "2021-12-24", overdue_days: 1768 },
        epss: { max: 0.94358, cve_id: "CVE-2021-44228", percentile: 0.99957 },
      },
      { row_id: "r02", decision: "patch_now", target_date: "2026-11-03", verified: true },
      { row_id: "r03", decision: "patch_now", target_date: "2026-11-03", verified: true },
      { row_id: "r04", decision: "ask_owner", target_date: null },
      { row_id: "r05", decision: "monitor", target_date: "2027-01-25" },
    ],
    kevPairs: [
      { vendor: "Citrix", product: "NetScaler ADC and Gateway" },
      { vendor: "Citrix", product: "NetScaler" },
      { vendor: "Apache", product: "Log4j" },
    ],
    familyOf,
    ...overrides,
  };
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "el-engine-test-"));
}

test("ingesting the same run twice adds 0 events (and a changed input does add events)", async () => {
  const w = createLedgerWorld({ namespace: "t-idem" });
  const r1 = await w.ingestRun(baseInput());
  assert.ok(r1.events_added > 0, "first ingest writes events");
  assert.equal(r1.changed, true);
  const eventsAfter1 = w.model.events().length;
  const shape1 = w.model.stateShapeCanonical();

  const r2 = await w.ingestRun(baseInput());
  assert.equal(r2.events_added, 0);
  assert.equal(r2.entity_upserts, 0);
  assert.equal(r2.review_proposals_added, 0);
  assert.equal(r2.changed, false);
  assert.equal(w.model.events().length, eventsAfter1);
  assert.equal(w.model.stateShapeCanonical(), shape1);

  // The check can fail: a new EPSS score is a new fact.
  const input3 = baseInput();
  input3.epss = input3.epss!.map((e) => (e.cve_id === "CVE-2023-4966" ? { ...e, epss: 0.95 } : e));
  const r3 = await w.ingestRun(input3);
  assert.ok(r3.events_added >= 1);
  assert.equal(r3.changed, true);
});

test("input order does not change the world", async () => {
  const a = createLedgerWorld({ namespace: "t-order-a" });
  const b = createLedgerWorld({ namespace: "t-order-b" });
  await a.ingestRun(baseInput());
  const shuffled = baseInput();
  shuffled.rows = [...shuffled.rows].reverse();
  shuffled.resolutions = [...shuffled.resolutions!].reverse();
  shuffled.kev = [...shuffled.kev!].reverse();
  shuffled.epss = [...shuffled.epss!].reverse();
  shuffled.kevPairs = [...shuffled.kevPairs!].reverse();
  await b.ingestRun(shuffled);
  assert.equal(a.model.stateShapeCanonical(), b.model.stateShapeCanonical());
});

test("a fact without provenance is rejected (engine and wrapper)", async () => {
  const w = createLedgerWorld({ namespace: "t-prov" });
  await assert.rejects(
    w.model.assertFact({ about: ledgerIds.cve("CVE-2021-44228"), predicate: "epss", value: 0.9, source: undefined as never }),
    /provenance/,
  );
  await assert.rejects(
    w.model.assertFact({ about: ledgerIds.cve("CVE-2021-44228"), predicate: "epss", value: 0.9, source: { kind: "zetaris:epss" } as never }),
    /provenance/,
  );
  await assert.rejects(w.ingestRun(baseInput({ asOf: "" })), /asOf/);
  await assert.rejects(w.ingestRun(baseInput({ asOf: "yesterday" })), /asOf/);
  await assert.rejects(w.ingestRun(baseInput({ asOf: "2026-02-30" })), /asOf/);
  assert.equal(w.model.events().length, 0, "nothing was written");
});

test("every fact and event is stamped with a source date, never the wall clock", async () => {
  const w = createLedgerWorld({ namespace: "t-dates" });
  await w.ingestRun(baseInput());
  const allowed = new Set([
    "2026-10-27T00:00:00.000Z", // run as-of date (inventory, agents)
    "2026-10-23T00:00:00.000Z", // KEV catalogue version 2026.10.23
    "2026-10-26T00:00:00.000Z", // EPSS score date
  ]);
  for (const e of w.model.events()) assert.ok(allowed.has(e.at), `event ${e.id} (${e.kind}) at ${e.at}`);
  for (const a of w.model.audit()) assert.ok(allowed.has(a.at), `audit ${a.seq} at ${a.at}`);
  const kevFact = w.factsAsOf(ledgerIds.cve("CVE-2021-44228"), AS_OF).kev_listing;
  assert.equal(kevFact.at, "2026-10-23T00:00:00.000Z");
  assert.equal(kevFact.source, "zetaris:el.kev");
  const epssFact = w.factsAsOf(ledgerIds.cve("CVE-2021-44228"), AS_OF).epss;
  assert.equal(epssFact.at, "2026-10-26T00:00:00.000Z");
  assert.equal(epssFact.source, "zetaris:epss");
});

test("explain returns the provenance trail for a patch line", async () => {
  const w = createLedgerWorld({ namespace: "t-explain" });
  await w.ingestRun(baseInput());
  const x = w.explain("r01");
  assert.ok(x);
  assert.equal(x.intent, "explain_patch_line");
  assert.ok(x.selectionReason.length > 20);
  assert.equal(x.software.id, ledgerIds.software("r01"));
  assert.equal(x.asset?.id, ledgerIds.asset("srv-web-01"));
  assert.equal(x.family?.id, ledgerIds.family("Apache Log4j"));
  assert.ok(x.family!.aliases.includes("Apache / Log4j2"), "KEV spelling is an engine alias of the family");
  assert.ok(x.family!.aliases.includes("Apache Log4j"));
  assert.deepEqual(x.cves.map((c) => [c.id, c.cited]), [[ledgerIds.cve("CVE-2021-44228"), true]]);
  for (const s of ["zetaris:el.inventory", "agent:jury", "zetaris:el.kev", "zetaris:epss", "agent:analyst"]) {
    assert.ok(x.sources.includes(s), `sources include ${s}: ${x.sources.join(", ")}`);
  }
  const res = x.items.find((i) => i.predicate === "resolves_to");
  assert.ok(res);
  assert.deepEqual((res.value as { receipt_ids: string[] }).receipt_ids, ["rcpt-b1", "rcpt-l1"]);
  assert.equal(res.run_id, "run-test-1");
  assert.ok(x.items.every((i) => i.current), "current values only by default");

  const ev = w.evidence("r01");
  assert.ok(ev.length === x.items.length && ev.every((e) => e.source === "world_model" && e.as_of && !e.live));

  // Agent provenance follows who decided.
  assert.equal(w.explain("r02")!.items.find((i) => i.predicate === "resolves_to")!.by, "ultra");
  assert.equal(w.explain("r04")!.items.find((i) => i.predicate === "resolves_to")!.source, "agent:critic");
  assert.equal(w.explain("r05")!.items.find((i) => i.predicate === "resolves_to")!.source, "agent:normaliser");
  assert.equal(w.explain("r04")!.family, null, "an unmatched row has no family");
  assert.equal(w.explain("nope"), null);
});

test("Log4j vs Log4j2 lands in the engine's merge-review queue (0.82-0.85 band)", async () => {
  const w = createLedgerWorld({ namespace: "t-review" });
  await w.ingestRun(baseInput());
  const q = w.reviewQueue();
  const hit = q.find((p) => [p.left.name, p.right.name].sort().join("|") === "Log4j|Log4j2");
  assert.ok(hit, `review queue: ${JSON.stringify(q)}`);
  assert.equal(hit.similarity, 0.833);
  assert.equal(hit.status, "pending");
  assert.equal(hit.vendor, "Apache");
  // Distinct Citrix spellings stay below the band: separate entities, no proposal.
  assert.ok(!q.some((p) => p.left.name.startsWith("NetScaler") || p.right.name.startsWith("NetScaler")));
  assert.equal(w.autoMerges().length, 0);
  assert.equal(w.stats().merge_proposals.pending, q.length);
});

test("merge bands: the engine default auto-merges at 0.85; a stricter band sends the pair to review", async () => {
  const struts = baseInput({
    kevPairs: [{ vendor: "Apache", product: "Struts 1" }, { vendor: "Apache", product: "Struts 2" }],
    familyOf: (p) => (p.product.startsWith("Struts") ? "Apache Struts" : familyOf(p)),
  });
  const loose = createLedgerWorld({ namespace: "t-band-default" });
  await loose.ingestRun(struts);
  assert.equal(loose.autoMerges().length, 1, "Struts 1 ~ Struts 2 = 0.875 auto-merges under the engine default");
  assert.match(loose.autoMerges()[0].reason, /0\.875/);
  const again = await loose.ingestRun(struts);
  assert.equal(again.events_added, 0, "an auto-merged spelling stays idempotent");

  const strict = createLedgerWorld({ namespace: "t-band-strict", resolver: { autoMergeAt: 1.01 } });
  await strict.ingestRun(struts);
  assert.equal(strict.autoMerges().length, 0);
  const names = strict.reviewQueue().map((p) => [p.left.name, p.right.name].sort().join("|"));
  assert.ok(names.includes("Struts 1|Struts 2"), names.join(", "));
});

test("similar asset ids never merge; an asset keeps every software row", async () => {
  const w = createLedgerWorld({ namespace: "t-assets" });
  const input = baseInput({
    rows: [
      row("a1", "ws-001", "Notepad++ 8.4"), row("a2", "ws-002", "Notepad++ 8.4"),
      row("a3", "laptop-12", "7-Zip 19.00"), row("a4", "laptop-13", "7-Zip 19.00"),
      row("a5", "laptop-13", "VLC 3.0.11"),
    ],
    resolutions: [], kev: [], epss: [], decisions: [], kevPairs: [],
  });
  await w.ingestRun(input);
  assert.equal(w.stats().entities_by_type.asset, 4);
  assert.equal(w.stats().entities_by_type.software, 5);
  assert.equal(w.reviewQueue({ status: "all" }).length, 0);
  assert.equal(w.autoMerges().length, 0);
  const onLaptop = w.model.view("graph").incoming(ledgerIds.asset("laptop-13"), { via: "installed_on" });
  assert.deepEqual(onLaptop.map((e) => e.id).sort(), [ledgerIds.software("a4"), ledgerIds.software("a5")]);
  assert.deepEqual(w.factsAsOf(ledgerIds.asset("laptop-13"), AS_OF).runs.value, [ledgerIds.software("a4"), ledgerIds.software("a5")]);
});

test("factsAsOf answers what we believed on a past date", async () => {
  const w = createLedgerWorld({ namespace: "t-asof" });
  const cve = ledgerIds.cve("CVE-2023-4966");
  const day1 = baseInput({ runId: "run-d1", asOf: "2026-10-26" });
  day1.epss = day1.epss!.map((e) => ({ ...e, score_date: "2026-10-25", epss: e.cve_id === "CVE-2023-4966" ? 0.5 : e.epss }));
  await w.ingestRun(day1);
  const day2 = baseInput({ runId: "run-d2", asOf: "2026-10-27" });
  day2.epss = day2.epss!.map((e) => ({ ...e, score_date: "2026-10-26", epss: e.cve_id === "CVE-2023-4966" ? 0.7 : e.epss }));
  await w.ingestRun(day2);

  assert.equal(w.factsAsOf(cve, "2026-10-24").epss, undefined, "no score known before the first score date");
  assert.equal((w.factsAsOf(cve, "2026-10-25").epss.value as { epss: number }).epss, 0.5);
  assert.equal((w.factsAsOf(cve, "2026-10-26").epss.value as { epss: number }).epss, 0.7);
  assert.equal(w.factsAsOf(cve, "2026-10-26T00:00:00.000Z").epss.at, "2026-10-26T00:00:00.000Z");
  const history = w.explain("r03", { history: true })!.items.filter((i) => i.entity_id === cve && i.predicate === "epss");
  assert.deepEqual(history.map((i) => [(i.value as { epss: number }).epss, i.current]), [[0.5, false], [0.7, true]]);
  assert.throws(() => w.factsAsOf(cve, "not a date"), /not a date/);
});

function withDecision(input: IngestRunInput, rowId: string, decision: "patch_now" | "ask_owner"): IngestRunInput {
  input.decisions = input.decisions!.map((d) =>
    d.row_id === rowId ? { row_id: rowId, decision, target_date: decision === "patch_now" ? "2026-11-03" : null } : d);
  return input;
}

function withR03Resolution(input: IngestRunInput, matchedNow: boolean): IngestRunInput {
  // Sample mode: the normaliser decides and there are no receipt ids to make the values unique.
  const vote = (vendor: string | null, product: string | null) =>
    [{ row_id: "r03", juror: "normaliser" as const, vendor, product, confidence: 0.8 }];
  input.resolutions = input.resolutions!.map((r) => (r.row_id !== "r03" ? r : matchedNow
    ? { ...r, status: "matched" as const, vendor: "Citrix", product: "NetScaler ADC and NetScaler Gateway", family: "Citrix NetScaler ADC/Gateway",
      adjudicated_by: "rules" as const, votes: vote("Citrix", "NetScaler ADC and NetScaler Gateway") }
    : { ...r, status: "no_match" as const, vendor: null, product: null, family: null, adjudicated_by: "rules" as const, votes: vote(null, null) }));
  return input;
}

test("same-day runs in one reused world: the latest run's beliefs win (patch_now, ask_owner, patch_now)", async () => {
  const dir = tmpDir();
  try {
    const sw1 = ledgerIds.software("r01");
    const sw3 = ledgerIds.software("r03");
    const run = (runId: string, decision: "patch_now" | "ask_owner", r03Matched: boolean) =>
      withR03Resolution(withDecision(baseInput({ runId, mode: "sample" }), "r01", decision), r03Matched);

    // Run 1, persisted; runs 2 and 3 resume the same world (the path the wrapper offers).
    const w1 = createLedgerWorld({ namespace: "t-sameday", persistDir: dir });
    await w1.ingestRun(run("run-1", "patch_now", true));
    w1.persist();
    const w2 = createLedgerWorld({ namespace: "t-sameday", persistDir: dir, resume: true });
    const r2 = await w2.ingestRun(run("run-2", "ask_owner", false));
    assert.ok(r2.events_added > 0);
    assert.equal((w2.factsAsOf(sw1, AS_OF).decision.value as { decision: string }).decision, "ask_owner");
    const w = createLedgerWorld({ namespace: "t-sameday", persistDir: dir, resume: true });
    const r3 = await w.ingestRun(run("run-3", "patch_now", true));
    assert.ok(r3.events_added > 0, "run 3 re-asserts patch_now on the same as-of date: a new fact, not a silent no-op");

    const belief = w.factsAsOf(sw1, AS_OF).decision;
    assert.equal((belief.value as { decision: string }).decision, "patch_now");
    const item = w.explain("r01")!.items.find((i) => i.entity_id === sw1 && i.predicate === "decision")!;
    assert.equal((item.value as { decision: string }).decision, "patch_now");
    assert.equal(item.run_id, "run-3");
    assert.ok(item.current);
    const history = w.explain("r01", { history: true })!.items
      .filter((i) => i.entity_id === sw1 && i.predicate === "decision")
      .map((i) => [(i.value as { decision: string }).decision, i.run_id, i.current]);
    assert.deepEqual(history, [["patch_now", "run-1", false], ["ask_owner", "run-2", false], ["patch_now", "run-3", true]]);

    // Resolution facts (sample mode, no receipt ids): matched, no_match, matched again.
    assert.equal((w.factsAsOf(sw3, AS_OF).resolves_to.value as { status: string }).status, "matched");
    const x3 = w.explain("r03")!;
    assert.equal(x3.family?.id, ledgerIds.family("Citrix NetScaler ADC/Gateway"));
    assert.equal(x3.items.find((i) => i.entity_id === sw3 && i.predicate === "resolves_to")!.run_id, "run-3");

    // Data facts carry the run that read them too.
    const kev = w.factsAsOf(ledgerIds.cve("CVE-2021-44228"), AS_OF).kev_listing;
    assert.equal(kev.at, "2026-10-23T00:00:00.000Z", "still stamped with the source's own date");

    // Same-run re-ingest still adds 0 events, also after a reload.
    assert.equal((await w.ingestRun(run("run-3", "patch_now", true))).events_added, 0);
    const again = createLedgerWorld({ namespace: "t-sameday", persistDir: dir, resume: true });
    assert.equal((await again.ingestRun(run("run-3", "patch_now", true))).events_added, 0);
    assert.equal((again.factsAsOf(sw1, AS_OF).decision.value as { decision: string }).decision, "patch_now");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("re-ingesting one run id with a changed input, then the original, makes the original current again", async () => {
  const w = createLedgerWorld({ namespace: "t-replay" });
  const sw = ledgerIds.software("r01");
  const current = () => (w.factsAsOf(sw, AS_OF).decision.value as { decision: string }).decision;
  await w.ingestRun(withDecision(baseInput(), "r01", "patch_now"));
  await w.ingestRun(withDecision(baseInput(), "r01", "ask_owner"));
  assert.equal(current(), "ask_owner");
  const back = await w.ingestRun(withDecision(baseInput(), "r01", "patch_now"));
  assert.ok(back.events_added > 0);
  assert.equal(current(), "patch_now");
  assert.equal(w.explain("r01")!.items.find((i) => i.entity_id === sw && i.predicate === "decision")!.run_id, "run-test-1");
  assert.equal((await w.ingestRun(withDecision(baseInput(), "r01", "patch_now"))).events_added, 0, "the replay is idempotent again");
  await w.ingestRun(withDecision(baseInput(), "r01", "ask_owner"));
  assert.equal(current(), "ask_owner");
  await w.ingestRun(withDecision(baseInput(), "r01", "patch_now"));
  assert.equal(current(), "patch_now");
  assert.equal((await w.ingestRun(withDecision(baseInput(), "r01", "patch_now"))).events_added, 0);
});

test("a later run with an earlier as-of date never overrides a newer belief", async () => {
  const w = createLedgerWorld({ namespace: "t-backdated" });
  const sw = ledgerIds.software("r01");
  await w.ingestRun(withDecision(baseInput({ runId: "run-new", asOf: "2026-10-28" }), "r01", "ask_owner"));
  const r = await w.ingestRun(withDecision(baseInput({ runId: "run-old", asOf: "2026-10-27" }), "r01", "patch_now"));
  assert.ok(r.events_added > 0, "the older-dated run is still recorded");
  assert.equal((w.factsAsOf(sw, "2026-10-28").decision.value as { decision: string }).decision, "ask_owner");
  assert.equal((w.factsAsOf(sw, "2026-10-27").decision.value as { decision: string }).decision, "patch_now");
  assert.equal((await w.ingestRun(withDecision(baseInput({ runId: "run-old", asOf: "2026-10-27" }), "r01", "patch_now"))).events_added, 0);
});

test("sample mode labels data facts as snapshot, not zetaris", async () => {
  assert.deepEqual(defaultSourceLabels("sample"), { inventory: "snapshot:el.inventory", kev: "snapshot:el.kev", epss: "snapshot:epss" });
  const w = createLedgerWorld({ namespace: "t-sample" });
  await w.ingestRun(baseInput({ mode: "sample" }));
  const srcs = w.explain("r01")!.sources;
  assert.ok(srcs.includes("snapshot:el.kev") && srcs.includes("snapshot:epss") && srcs.includes("snapshot:el.inventory"));
  assert.ok(!srcs.some((s) => s.startsWith("zetaris:")));
  const w2 = createLedgerWorld({ namespace: "t-inline" });
  await w2.ingestRun(baseInput({ sources: { inventory: "request:inventory" } }));
  assert.ok(w2.explain("r01")!.sources.includes("request:inventory"));
});

test("bad inputs become warnings, never silent facts (missing EPSS is not 0)", async () => {
  const w = createLedgerWorld({ namespace: "t-warn" });
  const input = baseInput();
  input.epss = [...input.epss!, { cve_id: "CVE-2099-0001", epss: Number.NaN, percentile: Number.NaN, score_date: "2026-10-26" }];
  input.decisions = [...input.decisions!, { row_id: "ghost", decision: "monitor", target_date: null }];
  input.rows = [...input.rows, row("r01", "srv-web-01", "duplicate row id"), { ...row("r99", "", "no asset") }];
  input.kev = [...input.kev!, { ...kevEntry("", "Apache", "Log4j2", "2021-12-10", "2021-12-24") }];
  input.kevPairs = [...input.kevPairs!, { vendor: "Apache", product: 42 as unknown as string }];
  const r = await w.ingestRun(input);
  assert.ok(r.warnings.includes("malformed inventory row skipped"));
  assert.ok(r.warnings.includes("malformed KEV entry skipped"));
  assert.equal(w.model.view("graph").entity(ledgerIds.software("r99")), undefined);
  assert.ok(r.warnings.some((m) => m.includes("CVE-2099-0001")));
  assert.ok(r.warnings.some((m) => m.includes("ghost")));
  assert.ok(r.warnings.some((m) => m.includes("duplicate row r01")));
  assert.equal(w.model.view("graph").entity(ledgerIds.cve("CVE-2099-0001")), undefined);
  assert.equal(w.model.view("graph").entity(ledgerIds.software("ghost")), undefined);
});

test("audit lines are JSONL and are written to logs/audit-<run_id>.jsonl", async () => {
  const w = createLedgerWorld({ namespace: "t-audit" });
  await w.ingestRun(baseInput());
  const lines = w.auditLines();
  assert.ok(lines.length >= w.model.events().length);
  const parsed = lines.map((l) => JSON.parse(l) as { seq: number; runId?: string; actor: string });
  for (let i = 1; i < parsed.length; i++) assert.ok(parsed[i].seq > parsed[i - 1].seq);
  assert.ok(parsed.some((a) => a.runId === "run-test-1"));
  assert.ok(parsed.some((a) => a.actor === "zetaris:el.kev"));
  assert.equal(w.auditLines({ sinceSeq: parsed[parsed.length - 1].seq }).length, 0);
  const dir = tmpDir();
  try {
    const file = w.writeAudit(path.join(dir, "logs"), "run/../test 1");
    assert.equal(path.dirname(file), path.join(dir, "logs"), "run id cannot escape the directory");
    assert.match(path.basename(file), /^audit-run_\.\._test_1\.jsonl$/);
    assert.equal(fs.readFileSync(file, "utf-8").trim().split("\n").length, lines.length);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("stats and manifest report what the engine holds and which helpers ran", async () => {
  const events: Omit<TraceEvent, "ts" | "run_id">[] = [];
  const tracer = { run_id: "run-test-1", file: "", emit: (e: Omit<TraceEvent, "ts" | "run_id">) => { events.push(e); } };
  const w = createLedgerWorld({ namespace: "t-stats", tracer });
  assert.equal(w.stats().last_ingest, null);
  await w.ingestRun(baseInput());
  const s = w.stats();
  assert.equal(s.entities_by_type.asset, 4);
  assert.equal(s.entities_by_type.software, 5);
  assert.equal(s.entities_by_type.cve, 3);
  assert.equal(s.entities_by_type.kev_family, 3);
  assert.equal(s.entities_by_type.kev_product, 6);
  assert.equal(s.events_total, w.model.events().length);
  assert.ok(s.facts_current > 0 && s.facts_current <= s.facts_total);
  assert.equal(s.last_ingest?.run_id, "run-test-1");

  assert.equal(events.length, 1);
  assert.equal(events[0].agent, "world_model");
  assert.equal(events[0].action, "ingest_run");
  assert.equal(events[0].status, "ok");
  assert.match(events[0].output_summary!, /engine events/);

  w.explain("r01");
  const m = w.manifest();
  assert.equal(m.engine, "world-model");
  assert.equal(m.engine_source, ENGINE_SOURCE);
  assert.match(m.engine_source, /1742dec/);
  assert.ok(m.helpers_live.includes("world-model.ingestRun") && m.helpers_live.includes("world-model.explain"));
  assert.ok(m.helpers_dormant.includes("world-model.persist"));
  assert.ok(m.helpers_dormant.some((h) => h.includes("approveMerge")));
});

test("persist writes the engine's own file layout; resume reloads it and re-ingest adds 0 events", async () => {
  const dir = tmpDir();
  try {
    const w1 = createLedgerWorld({ namespace: "t-persist", persistDir: dir });
    await w1.ingestRun(baseInput());
    const file = w1.persist();
    assert.equal(file, path.join(dir, ".world", "t-persist.json"));
    assert.ok(fs.existsSync(file!));

    const w2 = createLedgerWorld({ namespace: "t-persist", persistDir: dir, resume: true });
    assert.equal(w2.model.events().length, w1.model.events().length);
    assert.equal(w2.reviewQueue().length, w1.reviewQueue().length);
    const r = await w2.ingestRun(baseInput());
    assert.equal(r.events_added, 0);
    assert.deepEqual(w2.explain("r01")!.sources, w1.explain("r01")!.sources);
    assert.equal(w2.manifest().storage, "local");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("stable ids and source dates", () => {
  assert.equal(ledgerIds.asset(" srv-01 "), "asset:inventory:srv-01");
  assert.equal(ledgerIds.cve("cve-2021-44228"), "cve:id:CVE-2021-44228");
  assert.equal(ledgerIds.family("Apache  Log4j"), ledgerIds.family("apache log4j"));
  assert.equal(ledgerIds.kevProduct("Microsoft", "Windows "), ledgerIds.kevProduct("Microsoft", "Windows"), "KEV's trailing-space spelling is the same product");
  assert.notEqual(ledgerIds.kevProduct("Apple", "iOS"), ledgerIds.kevProduct("Cisco", "IOS"), "vendor scopes the spelling");
  assert.equal(sourceDate("2026.10.23"), "2026-10-23T00:00:00.000Z");
  assert.equal(sourceDate("2026-10-26"), "2026-10-26T00:00:00.000Z");
  assert.equal(sourceDate("2026-10-26T12:30:00+01:00"), "2026-10-26T11:30:00.000Z");
  assert.equal(sourceDate("2026-13-01"), null);
  assert.equal(sourceDate(""), null);
  assert.equal(sourceDate(undefined), null);
  assert.throws(() => createLedgerWorld({ namespace: "../escape" }), /namespace/);
});
