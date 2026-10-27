import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_POLICY } from "../src/contracts.ts";
import type { EpssScore, Evidence, KevEntry, PatchLine, Queries, Resolution, Tracer, TraceEvent } from "../src/contracts.ts";
import { citedCves, verifyLines, verifyLive } from "../src/agents/verifier.ts";

// Hand-written KEV/EPSS-shaped values for these tests.
const kev = (cve_id: string, due_date: string, over: Partial<KevEntry> = {}): KevEntry => ({
  cve_id, vendor: "Apache", product: "Log4j2", vulnerability_name: "test flaw", date_added: "2021-12-10", due_date,
  ransomware_use: "Known", required_action: "Apply updates.", short_description: "test", notes: "", catalog_version: "2026.10.23", ...over,
});
const epss = (cve_id: string, score: number, score_date = "2026-10-26", percentile = 0.99): EpssScore => ({ cve_id, epss: score, percentile, score_date });

const RES: Resolution = {
  row_id: "r1", status: "matched", vendor: "Apache", product: "Log4j2", family: "apache:log4j", version: "2.14.1",
  product_type: "library", votes: [], adjudicated_by: null, confidence: 0.9,
};

function line(over: Partial<PatchLine> = {}): PatchLine {
  const k = kev("CVE-2021-44228", "2021-12-24");
  return {
    row_id: "r1", asset_id: "a1", asset_name: "erp-01", internet_facing: true, software: "log4j-core 2.14.1", resolution: RES,
    decision: "patch_now", target_date: "2026-11-02",
    kev: { cves: [k], earliest_due: "2021-12-24", overdue_days: 1767 },
    epss: { max: 0.99999, cve_id: "CVE-2021-44228", percentile: 1.0 },
    evidence: [
      { source: "zetaris:kev", query: "kevByProducts", field: "CVE-2021-44228.due_date", value: "2021-12-24", as_of: "2026.10.23", live: true },
      { source: "zetaris:epss", query: "epss", field: "CVE-2021-44228.epss", value: "0.99999", as_of: "2026-10-26", live: true },
    ],
    critic: null, verified: false, verifier_notes: [], why: "",
    ...over,
  };
}

const LIVE_KEV = [kev("CVE-2021-44228", "2021-12-24")];
const LIVE_EPSS = [epss("CVE-2021-44228", 0.99999, "2026-10-26", 1.0)];

test("all cited values match: the line is verified", () => {
  const [out] = verifyLines([line()], LIVE_KEV, LIVE_EPSS, { asOf: "2026-10-26" });
  assert.equal(out.verified, true);
  assert.equal(out.verifier_notes.length, 1);
  assert.match(out.verifier_notes[0], /re-checked \d+ cited value\(s\) against live single-source Zetaris queries: all match/);
});

test("a KEV due date or date added that differs live blocks the line", () => {
  const [due] = verifyLines([line()], [kev("CVE-2021-44228", "2021-12-31")], LIVE_EPSS);
  assert.equal(due.verified, false);
  assert.ok(due.verifier_notes.some((n) => n.includes('CVE-2021-44228 due_date: cited "2021-12-24", live "2021-12-31"')));
  assert.ok(due.verifier_notes.some((n) => n.includes("earliest KEV due date")));

  const [added] = verifyLines([line()], [kev("CVE-2021-44228", "2021-12-24", { date_added: "2021-12-11" })], LIVE_EPSS);
  assert.equal(added.verified, false);
  assert.ok(added.verifier_notes.some((n) => n.includes("date_added")));

  const [ransom] = verifyLines([line()], [kev("CVE-2021-44228", "2021-12-24", { ransomware_use: "Unknown" })], LIVE_EPSS);
  assert.equal(ransom.verified, false);
});

test("trailing spaces and case in KEV names are not mismatches", () => {
  const cited = kev("CVE-2024-0001", "2024-02-01", { vendor: "Microsoft", product: "Windows " });
  const l = line({ kev: { cves: [cited], earliest_due: "2024-02-01", overdue_days: null }, epss: null, evidence: [] });
  const [out] = verifyLines([l], [kev("CVE-2024-0001", "2024-02-01T00:00:00Z", { vendor: "microsoft", product: "Windows" })], []);
  assert.equal(out.verified, true, out.verifier_notes.join(" | "));
});

test("a cited CVE missing from the live KEV catalogue blocks the line", () => {
  const [out] = verifyLines([line()], [], LIVE_EPSS);
  assert.equal(out.verified, false);
  assert.ok(out.verifier_notes.some((n) => n.includes("CVE-2021-44228 is not in the live KEV catalogue")));
});

test("overdue days are re-derived from the live due date when the run date is given", () => {
  const [ok] = verifyLines([line()], LIVE_KEV, LIVE_EPSS, { asOf: "2026-10-26" });
  assert.equal(ok.verified, true);
  const [bad] = verifyLines([line({ kev: { cves: [kev("CVE-2021-44228", "2021-12-24")], earliest_due: "2021-12-24", overdue_days: 10 } })], LIVE_KEV, LIVE_EPSS, { asOf: "2026-10-26" });
  assert.equal(bad.verified, false);
  assert.ok(bad.verifier_notes.some((n) => n.includes("gives 1767")));
});

test("EPSS: exact on the same score date, within 0.02 across dates", () => {
  const sameDayDrift = verifyLines([line()], LIVE_KEV, [epss("CVE-2021-44228", 0.99, "2026-10-26", 1.0)]);
  assert.equal(sameDayDrift[0].verified, false);
  assert.ok(sameDayDrift[0].verifier_notes.some((n) => n.includes("same score date")));

  const nextDaySmall = verifyLines([line()], LIVE_KEV, [epss("CVE-2021-44228", 0.985, "2026-10-27", 0.999)]);
  assert.equal(nextDaySmall[0].verified, true, nextDaySmall[0].verifier_notes.join(" | "));

  const nextDayLarge = verifyLines([line()], LIVE_KEV, [epss("CVE-2021-44228", 0.95, "2026-10-27", 0.99)]);
  assert.equal(nextDayLarge[0].verified, false);
  assert.ok(nextDayLarge[0].verifier_notes.some((n) => n.includes("beyond the 0.02 tolerance")));

  const custom = verifyLines([line()], LIVE_KEV, [epss("CVE-2021-44228", 0.95, "2026-10-27", 0.99)], { epssTolerance: 0.1 });
  assert.equal(custom[0].verified, true);
});

test("a missing live EPSS score is unknown, never 0, and blocks the line", () => {
  const [out] = verifyLines([line()], LIVE_KEV, []);
  assert.equal(out.verified, false);
  assert.ok(out.verifier_notes.some((n) => n.includes("no live EPSS score for CVE-2021-44228 (unknown, not 0)")));
});

test("fail closed: an unreachable source blocks every line that cites it", () => {
  const [noKev] = verifyLines([line()], null, LIVE_EPSS);
  assert.equal(noKev.verified, false);
  assert.equal(noKev.verifier_notes.filter((n) => n.includes("KEV could not be re-queried")).length, 1);
  const [noEpss] = verifyLines([line()], LIVE_KEV, null);
  assert.equal(noEpss.verified, false);
  // a monitor line that cites nothing is unaffected
  const [monitor] = verifyLines([line({ decision: "monitor", kev: null, epss: null, evidence: [] })], null, null);
  assert.equal(monitor.verified, true);
  assert.match(monitor.verifier_notes[0], /nothing to re-check/);
});

test("decisions must rest on what they cite; this_cycle is re-derived from the live EPSS with the policy", () => {
  const [pn] = verifyLines([line({ kev: null })], LIVE_KEV, LIVE_EPSS);
  assert.equal(pn.verified, false);
  assert.ok(pn.verifier_notes.some((n) => n.includes("patch_now without a cited KEV listing")));

  const tc = line({ decision: "this_cycle", kev: null, internet_facing: false, epss: { max: 0.11, cve_id: "CVE-2026-88779", percentile: 0.96 },
    evidence: [{ source: "zetaris:epss", query: "epss", field: "CVE-2026-88779.epss", value: "0.11", as_of: "2026-10-25", live: true }] });
  const [drop] = verifyLines([tc], [], [epss("CVE-2026-88779", 0.095, "2026-10-26", 0.95)], { policy: DEFAULT_POLICY });
  assert.equal(drop.verified, false);
  assert.ok(drop.verifier_notes.some((n) => n.includes("below the this_cycle threshold 0.1")));
  const [keep] = verifyLines([tc], [], [epss("CVE-2026-88779", 0.105, "2026-10-26", 0.96)], { policy: DEFAULT_POLICY });
  assert.equal(keep.verified, true, keep.verifier_notes.join(" | "));
});

test("evidence-only citations are checked too, and the source label follows the mode", () => {
  const extra: Evidence = { source: "zetaris:kev", query: "kevByProducts CVE-2021-45046", field: "dueDate", value: "2021-12-24", live: true };
  const l = line({ evidence: [...line().evidence, extra] });
  const [bad] = verifyLines([l], [...LIVE_KEV, kev("CVE-2021-45046", "2022-01-07")], LIVE_EPSS, { source: "snapshot" });
  assert.equal(bad.verified, false);
  assert.ok(bad.verifier_notes.some((n) => n.includes('CVE-2021-45046 due_date: cited "2021-12-24", snapshot "2022-01-07"')));
  assert.deepEqual(citedCves([l]), { kev: ["CVE-2021-44228", "CVE-2021-45046"], epss: ["CVE-2021-44228"] });
});

test("evidence that contradicts the line's own KEV or EPSS value for the same CVE is compared too, and blocks the line", () => {
  const base = line();
  // the probe: evidence states due date 2030-01-01 and EPSS 0.01; the line and the live rows say 2021-12-24 and 0.99999
  const both = line({ evidence: [...base.evidence,
    { source: "zetaris:kev", query: "kevByProducts", field: "CVE-2021-44228.due_date", value: "2030-01-01", as_of: "2026.10.23", live: true },
    { source: "zetaris:epss", query: "epss", field: "CVE-2021-44228.epss", value: "0.01", as_of: "2026-10-26", live: true },
  ] });
  const [out] = verifyLines([both], LIVE_KEV, LIVE_EPSS, { asOf: "2026-10-26" });
  assert.equal(out.verified, false);
  assert.ok(out.verifier_notes.some((n) => n.includes('CVE-2021-44228 due_date: cited "2030-01-01", live "2021-12-24"')), out.verifier_notes.join(" | "));
  assert.ok(out.verifier_notes.some((n) => n.includes("CVE-2021-44228 epss: cited 0.01 (2026-10-26), live 0.99999 (2026-10-26), same score date")), out.verifier_notes.join(" | "));
  assert.ok(!out.verifier_notes.some((n) => /all match/.test(n)));

  // each contradiction blocks on its own, whichever order the citations come in
  const kevOnly = line({ evidence: [{ source: "zetaris:kev", query: "kevByProducts", field: "CVE-2021-44228.date_added", value: "2021-12-01", live: true }, ...base.evidence] });
  const [k] = verifyLines([kevOnly], LIVE_KEV, LIVE_EPSS);
  assert.equal(k.verified, false);
  assert.ok(k.verifier_notes.some((n) => n.includes('CVE-2021-44228 date_added: cited "2021-12-01", live "2021-12-10"')));
  const epssOnly = line({ evidence: [...base.evidence, { source: "zetaris:epss", query: "epss", field: "CVE-2021-44228.percentile", value: "0.5", live: true }] });
  const [e] = verifyLines([epssOnly], LIVE_KEV, LIVE_EPSS);
  assert.equal(e.verified, false);
  assert.ok(e.verifier_notes.some((n) => n.includes("CVE-2021-44228 percentile: cited 0.5")));

  // the same value cited again in another format is one comparison, not two (and not a mismatch)
  const [plain] = verifyLines([base], LIVE_KEV, LIVE_EPSS);
  const restated = line({ evidence: [...base.evidence,
    { source: "zetaris:kev", query: "kevVerify", field: "CVE-2021-44228.dueDate", value: "2021-12-24T00:00:00Z", as_of: "2026.10.23", live: true },
    { source: "zetaris:epss", query: "epss", field: "CVE-2021-44228.epss", value: "0.999990", as_of: "2026-10-26", live: true },
  ] });
  const [same] = verifyLines([restated], LIVE_KEV, LIVE_EPSS);
  assert.equal(same.verified, true, same.verifier_notes.join(" | "));
  assert.equal(same.verifier_notes[0], plain.verifier_notes[0]);
  assert.match(same.verifier_notes[0], /re-checked 8 cited value\(s\)/);
});

test("verifyLive re-queries in batches of <= 100, traces the re-check, and fails closed on errors", async () => {
  const many = Array.from({ length: 150 }, (_, i) => `CVE-2026-${String(10000 + i)}`);
  const lines = many.map((id, i) => line({ row_id: `r${i}`, kev: { cves: [kev(id, "2026-10-29")], earliest_due: "2026-10-29", overdue_days: null }, epss: { max: 0.2, cve_id: id, percentile: 0.9 }, evidence: [] }));
  const calls: { kind: string; n: number }[] = [];
  const queries: Pick<Queries, "kevVerify" | "epssVerify"> = {
    async kevVerify(ids) { calls.push({ kind: "kev", n: ids.length }); return ids.map((id) => kev(id, "2026-10-29")); },
    async epssVerify(ids) { calls.push({ kind: "epss", n: ids.length }); return ids.map((id) => epss(id, 0.2, "2026-10-26", 0.9)); },
  };
  const events: Omit<TraceEvent, "ts" | "run_id">[] = [];
  const tracer: Tracer = { run_id: "t", file: "/dev/null", emit: (e) => { events.push(e); } };
  const res = await verifyLive(lines, queries, { tracer });
  assert.deepEqual(calls, [{ kind: "kev", n: 100 }, { kind: "kev", n: 50 }, { kind: "epss", n: 100 }, { kind: "epss", n: 50 }]);
  assert.equal(res.lines.every((l) => l.verified), true);
  assert.equal(events.length, 1);
  assert.equal(events[0].agent, "verifier");
  assert.equal(events[0].status, "ok");

  const failing: Pick<Queries, "kevVerify" | "epssVerify"> = {
    async kevVerify() { throw new Error("watchdog fired after 120000 ms"); },
    async epssVerify(ids) { return ids.map((id) => epss(id, 0.99999, "2026-10-26", 1.0)); },
  };
  const events2: Omit<TraceEvent, "ts" | "run_id">[] = [];
  const res2 = await verifyLive([line()], failing, { tracer: { run_id: "t", file: "/dev/null", emit: (e) => { events2.push(e); } }, mode: "sample" });
  assert.equal(res2.lines[0].verified, false);
  assert.deepEqual(res2.blocked_rows, ["r1"]);
  assert.match(res2.errors[0], /kevVerify failed: watchdog/);
  assert.ok(res2.lines[0].verifier_notes[0].includes("(snapshot)"));
  assert.equal(events2[0].status, "error");
  assert.equal(events2[1].action, "block_line");
  assert.equal(events2[1].status, "blocked");
});

test("verifyLive's summary counts a line with nothing cited apart: never as re-checked", async () => {
  const cited = line({ row_id: "a", kev: { cves: [kev("CVE-2026-10001", "2026-10-29")], earliest_due: "2026-10-29", overdue_days: null }, epss: null, evidence: [] });
  const none = line({ row_id: "b", decision: "monitor", kev: { cves: [], earliest_due: null, overdue_days: null }, epss: null, evidence: [] });
  const queries: Pick<Queries, "kevVerify" | "epssVerify"> = {
    async kevVerify(ids) { return ids.map((id) => kev(id, "2026-10-29")); },
    async epssVerify() { return []; },
  };
  const events: Omit<TraceEvent, "ts" | "run_id">[] = [];
  const res = await verifyLive([cited, none], queries, { tracer: { run_id: "t", file: "/dev/null", emit: (e) => { events.push(e); } } });
  assert.ok(res.lines.every((l) => l.verified));
  assert.equal(events[0].output_summary, "1 re-checked and matched, 1 with nothing to re-check, 0 blocked (of 2)");
  assert.equal(events[0].details?.rechecked, 1);
  assert.equal(events[0].details?.nothing_to_recheck, 1);
});
