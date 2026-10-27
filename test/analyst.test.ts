// Exposure Analyst tests: policy merge, dates, decisions, fail-closed rules, ordering.
// KEV and EPSS values are real catalogue rows (CVE-2021-44228, CVE-2025-61624, CVE-2026-0322).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_POLICY } from "../src/contracts.ts";
import type { EpssScore, InventoryRow, KevEntry, PatchLine, Resolution } from "../src/contracts.ts";
import {
  addDays, assessRow, citeKev, dayDiff, isIsoDate, MAX_CITED_KEV, maxEpss, mergePolicy, PolicyError, scopeKevToVersion, sortLines, summarise,
} from "../src/policy/analyst.ts";
import type { AnalystContext } from "../src/policy/analyst.ts";
import { familyKey } from "../src/resolve/candidates.ts";

const AS_OF = "2026-10-26";

function kev(cve_id: string, vendor: string, product: string, date_added: string, due_date: string, ransomware_use = "Unknown"): KevEntry {
  return {
    cve_id, vendor, product, vulnerability_name: `${vendor} ${product} vulnerability`, date_added, due_date, ransomware_use,
    required_action: "Apply mitigations per vendor instructions.", short_description: "", notes: "", catalog_version: "2026.10.23",
  };
}
const LOG4SHELL = kev("CVE-2021-44228", "Apache", "Log4j2", "2021-12-10", "2021-12-24", "Known");
const FORTI = kev("CVE-2025-61624", "Fortinet", "Multiple Products", "2026-10-16", "2026-10-19");
const PANOS = kev("CVE-2026-0322", "Palo Alto Networks", "PAN-OS", "2026-10-14", "2026-10-17");
const epss = (cve_id: string, e: number, percentile: number): EpssScore => ({ cve_id, epss: e, percentile, score_date: "2026-10-25" });

function row(row_id: string, software: string, internet_facing = false): InventoryRow {
  return { row_id, asset_id: `A-${row_id}`, asset_name: `host-${row_id}`, asset_type: "server", internet_facing, owner_team: "IT", software };
}

function res(row_id: string, status: Resolution["status"], vendor: string | null = null, product: string | null = null): Resolution {
  return {
    row_id, status, vendor, product, family: vendor && product ? `${vendor} ${product}` : null, version: null,
    product_type: "unknown", adjudicated_by: null, confidence: 1,
    votes: [
      { row_id, juror: "bolt", vendor, product, confidence: 0.9, receipt_id: "rcpt_req_b1" },
      { row_id, juror: "lightning", vendor, product, confidence: 0.9, receipt_id: "rcpt_req_l1" },
    ],
  };
}

function ctx(over: Partial<AnalystContext> = {}): AnalystContext {
  return {
    asOf: AS_OF, policy: DEFAULT_POLICY, live: true, inventoryFrom: "zetaris", kevPairsError: null,
    kevByFamily: new Map([
      [familyKey("Apache Log4j2"), [LOG4SHELL]],
      [familyKey("Fortinet Multiple Products"), [FORTI]],
      [familyKey("Palo Alto Networks PAN-OS"), [PANOS]],
    ]),
    kevError: null, catalogVersion: "2026.10.23",
    epssByCve: new Map([["CVE-2021-44228", epss("CVE-2021-44228", 0.99999, 1.0)], ["CVE-2025-61624", epss("CVE-2025-61624", 0.01343, 0.71155)]]),
    epssError: null,
    ...over,
  };
}

describe("policy", () => {
  test("deep merge keeps the fields an override does not set", () => {
    const p = mergePolicy(DEFAULT_POLICY, { sla_days: { patch_now: 3 }, epss_this_cycle: 0.2 });
    assert.deepEqual(p.sla_days, { patch_now: 3, this_cycle: 30, monitor_review: 90 });
    assert.equal(p.epss_this_cycle, 0.2);
    assert.equal(p.epss_this_cycle_internet, 0.05);
    assert.deepEqual(DEFAULT_POLICY.sla_days, { patch_now: 7, this_cycle: 30, monitor_review: 90 }); // not mutated
    assert.notEqual(mergePolicy(DEFAULT_POLICY, undefined), DEFAULT_POLICY);
  });

  test("invalid overrides are rejected with a clear PolicyError", () => {
    assert.throws(() => mergePolicy(DEFAULT_POLICY, { epss_this_cycle: 1.5 }), PolicyError);
    assert.throws(() => mergePolicy(DEFAULT_POLICY, { sla_days: { patch_now: -1 } }), /patch_now/);
    assert.throws(() => mergePolicy(DEFAULT_POLICY, { sla_days: { patch_now: 2.5 } }), /integer/);
    assert.throws(() => mergePolicy(DEFAULT_POLICY, { epss_thiscycle: 0.1 }), /unknown policy field/);
    assert.throws(() => mergePolicy(DEFAULT_POLICY, { sla_days: { soon: 1 } }), /sla_days\.soon/);
    assert.throws(() => mergePolicy(DEFAULT_POLICY, "strict"), /object/);
  });
});

describe("dates", () => {
  test("addDays and dayDiff work in UTC calendar days across months, years and leap days", () => {
    assert.equal(addDays(AS_OF, 7), "2026-11-02");
    assert.equal(addDays(AS_OF, 90), "2027-01-24");
    assert.equal(addDays("2028-02-28", 1), "2028-02-29");
    assert.equal(dayDiff("2021-12-24", AS_OF), 1767);
    assert.equal(dayDiff("2026-11-03", AS_OF), -8);
    assert.equal(dayDiff(AS_OF, AS_OF), 0);
  });

  test("isIsoDate accepts only real YYYY-MM-DD dates", () => {
    assert.equal(isIsoDate("2026-10-19"), true);
    assert.equal(isIsoDate("2026-02-30"), false);
    assert.equal(isIsoDate("19/10/2026"), false);
    assert.equal(isIsoDate(""), false);
  });
});

describe("decisions", () => {
  test("KEV-listed -> patch_now: target as_of + 7, earliest due, signed overdue days, EPSS attached", () => {
    const a = assessRow(row("R1", "log4j-core 2.14.1", true), res("R1", "matched", "Apache", "Log4j2"), ctx());
    const l = a.line;
    assert.equal(l.decision, "patch_now");
    assert.equal(l.target_date, "2026-11-02");
    assert.equal(l.kev?.earliest_due, "2021-12-24");
    assert.equal(l.kev?.overdue_days, 1767);
    assert.deepEqual(l.kev?.cves.map((c) => c.cve_id), ["CVE-2021-44228"]);
    assert.deepEqual(l.epss, { max: 0.99999, cve_id: "CVE-2021-44228", percentile: 1 });
    assert.equal(l.verified, false);
    assert.equal(a.owner, null);
    assert.ok(l.evidence.some((e) => e.source === "zetaris:kev" && e.field === "cve_id" && e.value === "CVE-2021-44228" && e.as_of === "2026.10.23"));
    assert.ok(l.evidence.some((e) => e.source === "zetaris:epss" && e.value === "0.99999" && e.as_of === "2026-10-25"));
    assert.ok(l.evidence.some((e) => e.source === "zetaris:inventory" && e.value === "log4j-core 2.14.1"));
    assert.ok(l.evidence.some((e) => e.query === "jury.bolt" && e.value === "rcpt_req_b1"));
    assert.equal(l.evidence.some((e) => e.field === "kev_epss_disagreement"), false);
  });

  test("KEV wins over a low EPSS, and the disagreement is recorded (CVE-2025-61624: EPSS 0.013)", () => {
    const l = assessRow(row("R2", "FortiOS 7.2"), res("R2", "matched", "Fortinet", "Multiple Products"), ctx()).line;
    assert.equal(l.decision, "patch_now");
    assert.equal(l.kev?.overdue_days, 7);
    assert.equal(l.epss?.max, 0.01343);
    assert.ok(l.evidence.some((e) => e.field === "kev_epss_disagreement"));
  });

  test("a missing EPSS score is null, never 0; a due date in the future gives negative overdue days", () => {
    const future = kev("CVE-2026-96655", "Plex", "Media Server", "2026-10-20", "2026-11-03");
    const l = assessRow(row("R3", "Plex Media Server"), res("R3", "matched", "Plex", "Media Server"),
      ctx({ kevByFamily: new Map([[familyKey("Plex Media Server"), [future]]]) })).line;
    assert.equal(l.decision, "patch_now");
    assert.equal(l.epss, null);
    assert.equal(l.kev?.overdue_days, -8);
    assert.ok(l.evidence.some((e) => e.source === "zetaris:epss" && /no score/.test(e.value)));
  });

  test("no_match -> monitor, next review as_of + 90, with the 'no KEV match' evidence", () => {
    const l = assessRow(row("R4", "Notepad++ 8.6"), res("R4", "no_match"), ctx()).line;
    assert.equal(l.decision, "monitor");
    assert.equal(l.target_date, "2027-01-24");
    assert.deepEqual(l.kev, { cves: [], earliest_due: null, overdue_days: null });
    assert.ok(l.evidence.some((e) => e.query === "kevPairs" && e.value === "none"));
  });

  test("matched, but KEV returned no entry for that KEV name -> ask_owner (an incomplete read is never relaxed)", () => {
    const a = assessRow(row("R5", "Tomcat 9"), res("R5", "matched", "Apache", "Tomcat"), ctx());
    assert.equal(a.line.decision, "ask_owner");
    assert.match(a.owner?.reason ?? "", /KEV returned no entry for Apache Tomcat/);
    assert.ok(a.line.evidence.some((e) => e.field === "kev_cve_count" && e.value === "0"));
  });

  test("unresolved -> ask_owner with a concrete question naming the options", () => {
    const r: Resolution = { ...res("R6", "unresolved"), votes: [
      { row_id: "R6", juror: "bolt", vendor: "Citrix", product: "NetScaler", confidence: 0.9 },
      { row_id: "R6", juror: "lightning", vendor: null, product: null, confidence: 0.9 },
    ] };
    const a = assessRow(row("R6", "Citrix NetScaler ADC 13.1"), r, ctx());
    assert.equal(a.line.decision, "ask_owner");
    assert.equal(a.line.target_date, null);
    assert.match(a.owner?.reason ?? "", /Bolt chose Citrix NetScaler; Lightning chose none/);
    assert.equal(a.owner?.question, 'Is "Citrix NetScaler ADC 13.1" on host-R6 Citrix NetScaler, or none of these?');
  });

  test("a missing resolution is treated as unresolved", () => {
    const a = assessRow(row("R7", "x"), undefined, ctx());
    assert.equal(a.line.decision, "ask_owner");
    assert.match(a.owner?.question ?? "", /Which product and version/);
  });

  test("this_cycle: not in KEV, non-KEV EPSS at or above the threshold (lower for internet-facing)", () => {
    const nonKev = new Map([[familyKey("Apache Tomcat"), [epss("CVE-2099-0001", 0.07, 0.9)]]]);
    const inside = assessRow(row("R8", "Tomcat 9"), res("R8", "matched", "Apache", "Tomcat"), ctx({ nonKevByFamily: nonKev })).line;
    assert.equal(inside.decision, "ask_owner"); // 0.07 < 0.10, and no KEV entry came back: not relaxed to monitor
    const facing = assessRow(row("R9", "Tomcat 9", true), res("R9", "matched", "Apache", "Tomcat"), ctx({ nonKevByFamily: nonKev })).line;
    assert.equal(facing.decision, "this_cycle"); // 0.07 >= 0.05
    assert.equal(facing.target_date, "2026-11-25");
  });
});

describe("fail-closed", () => {
  test("KEV names unreadable: every row is ask_owner, nothing is monitor", () => {
    const c = ctx({ kevPairsError: "Zetaris watchdog fired after 120 s. No cache." });
    for (const r of [res("R1", "no_match"), res("R2", "matched", "Apache", "Log4j2")]) {
      const a = assessRow(row(r.row_id, "x"), r, c);
      assert.equal(a.line.decision, "ask_owner");
      assert.match(a.owner?.reason ?? "", /KEV catalogue could not be read/);
      assert.doesNotMatch(a.owner?.reason ?? "", /120 s\. No/); // inner sentence breaks are flattened
    }
  });

  test("KEV entries unreadable: matched rows are ask_owner; no_match rows can still be monitor", () => {
    const c = ctx({ kevError: "HTTP 400" });
    assert.equal(assessRow(row("R1", "log4j"), res("R1", "matched", "Apache", "Log4j2"), c).line.decision, "ask_owner");
    assert.equal(assessRow(row("R2", "Notepad++"), res("R2", "no_match"), c).line.decision, "monitor");
  });

  test("EPSS unreadable: patch_now stays (KEV decides) but nothing is relaxed to monitor", () => {
    const c = ctx({ epssError: "timeout", epssByCve: new Map() });
    const p = assessRow(row("R1", "log4j"), res("R1", "matched", "Apache", "Log4j2"), c).line;
    assert.equal(p.decision, "patch_now");
    assert.ok(p.evidence.some((e) => e.source === "zetaris:epss" && /unavailable/.test(e.value)));
    const m = assessRow(row("R2", "Notepad++"), res("R2", "no_match"), c);
    assert.equal(m.line.decision, "ask_owner");
    assert.match(m.owner?.reason ?? "", /EPSS could not be read/);
  });
});

describe("helpers and ordering", () => {
  test("citeKev de-duplicates, puts the most recent first, and caps the list", () => {
    const many = Array.from({ length: 30 }, (_, i) => kev(`CVE-2020-${1000 + i}`, "Microsoft", "Windows", `2022-01-${String((i % 28) + 1).padStart(2, "0")}`, "2022-02-01"));
    const cited = citeKev([...many, many[0]]);
    assert.equal(cited.length, MAX_CITED_KEV);
    assert.equal(new Set(cited.map((c) => c.cve_id)).size, MAX_CITED_KEV);
    for (let i = 1; i < cited.length; i++) assert.ok(cited[i - 1].date_added >= cited[i].date_added);
    const l = assessRow(row("R1", "Windows 10"), res("R1", "matched", "Microsoft", "Windows"),
      ctx({ kevByFamily: new Map([[familyKey("Microsoft Windows"), many]]) })).line;
    assert.ok(l.evidence.some((e) => e.field === "kev_cve_count" && /^30 /.test(e.value)));
  });

  test("maxEpss picks the highest score and ignores missing ones", () => {
    assert.equal(maxEpss([undefined, epss("A", 0.2, 0.5), epss("B", 0.9, 0.99)])?.cve_id, "B");
    assert.equal(maxEpss([undefined]), null);
  });

  test("sort: bucket, internet-facing first, most overdue, highest EPSS, then row id", () => {
    const c = ctx();
    const lines: PatchLine[] = [
      assessRow(row("R10", "Notepad++"), res("R10", "no_match"), c).line,
      assessRow(row("R2", "?"), res("R2", "unresolved"), c).line,
      assessRow(row("R3", "PAN-OS", false), res("R3", "matched", "Palo Alto Networks", "PAN-OS"), c).line,
      assessRow(row("R4", "Forti", true), res("R4", "matched", "Fortinet", "Multiple Products"), c).line,
      assessRow(row("R5", "log4j", false), res("R5", "matched", "Apache", "Log4j2"), c).line,
      assessRow(row("R1", "Notepad++"), res("R1", "no_match"), c).line,
    ];
    assert.deepEqual(sortLines(lines).map((l) => l.row_id), ["R4", "R5", "R3", "R2", "R1", "R10"]);
    assert.deepEqual(summarise(lines), { patch_now: 3, this_cycle: 0, monitor: 2, ask_owner: 1 });
  });
});

describe("scopeKevToVersion: a line cites the KEV CVEs NVD does not rule out for the installed version", () => {
  const T = (id: string, added: string, due: string) => kev(id, "Apache", "Tomcat", added, due);
  const entries = [T("CVE-2099-3001", "2026-04-01", "2026-04-22"), T("CVE-2099-3002", "2025-04-01", "2025-04-22"), T("CVE-2099-3003", "2022-03-03", "2022-03-17"), T("CVE-2099-3004", "2021-11-03", "2022-05-03")];
  const scores = [epss("CVE-2099-3001", 0.5, 0.97), epss("CVE-2099-3002", 0.3, 0.96), epss("CVE-2099-3003", 0.97, 0.999), epss("CVE-2099-3004", 0.99, 1)];
  const actx = (): AnalystContext => ({
    asOf: AS_OF, policy: DEFAULT_POLICY, live: true, inventoryFrom: "zetaris", kevPairsError: null, kevError: null,
    kevByFamily: new Map([[familyKey("Apache Tomcat"), entries]]), catalogVersion: "2026.10.23",
    epssByCve: new Map(scores.map((s) => [s.cve_id, s])), epssError: null,
  });
  const base = () => assessRow(row("T1", "Apache Tomcat v9.0.54", true), res("T1", "matched", "Apache", "Tomcat"), actx()).line;

  test("one outside, one inside, two unchecked: drops only the outside one; dates and EPSS from the inside and unchecked ones (fail-closed)", () => {
    const line = base();
    assert.equal(line.kev?.earliest_due, "2022-03-17"); // the family's earliest, from a CVE NVD did not check
    const out = scopeKevToVersion(line, { "CVE-2099-3001": "outside", "CVE-2099-3002": "inside", "CVE-2099-3003": "unchecked", "CVE-2099-3004": "unchecked" },
      { ...actx(), version: "9.0.54" }, () => ({ live: true, as_of: AS_OF }));
    assert.equal(out.changed, true);
    assert.equal(out.basis, "inside");
    // the confirmed CVE first, then the ones counted fail-closed
    assert.deepEqual(out.line.kev?.cves.map((c) => c.cve_id), ["CVE-2099-3002", "CVE-2099-3003", "CVE-2099-3004"]);
    assert.equal(out.line.kev?.earliest_due, "2022-03-17", "an unchecked CVE's older due date still counts");
    assert.equal(out.line.kev?.overdue_days, dayDiff("2022-03-17", AS_OF));
    assert.deepEqual(out.line.epss, { max: 0.99, cve_id: "CVE-2099-3004", percentile: 1 });
    const f = (name: string) => out.line.evidence.filter((e) => e.field === name);
    assert.deepEqual(f("cve_id").map((e) => e.value).sort(), ["CVE-2099-3002", "CVE-2099-3003", "CVE-2099-3004"]);
    assert.deepEqual(f("epss").map((e) => e.value), ["0.99"]);
    assert.equal(f("kev_cves_version_not_affected")[0].live, true);
    assert.match(f("kev_cves_version_not_affected")[0].value, /version 9\.0\.54 outside .*CVE-2099-3001$/);
    assert.match(f("kev_cves_not_version_checked")[0].value, /^2 other cited KEV CVE\(s\) .*counted fail-closed, they stay cited .*: CVE-2099-3003, CVE-2099-3004$/);
    assert.match(f("kev_basis")[0].value, /^NVD places version 9\.0\.54 inside 1 cited KEV CVE\(s\): CVE-2099-3002; 2 more cited CVE\(s\) not version-checked count fail-closed; .* these 3 cited CVE\(s\), none from the 1 NVD places it outside$/);
    assert.equal(line.kev?.cves.length, 4, "the input line is not mutated");
  });

  test("more NVD evidence never makes a line less urgent: one CVE confirmed or none, the same dates and EPSS", () => {
    const line = base();
    const withInside = scopeKevToVersion(line, { "CVE-2099-3001": "outside", "CVE-2099-3002": "inside" }, { ...actx(), version: "9.0.54" });
    const withoutInside = scopeKevToVersion(line, { "CVE-2099-3001": "outside" }, { ...actx(), version: "9.0.54" });
    assert.equal(withInside.basis, "inside");
    assert.equal(withoutInside.basis, "unchecked");
    assert.deepEqual(withInside.line.kev?.cves.map((c) => c.cve_id).sort(), withoutInside.line.kev?.cves.map((c) => c.cve_id).sort());
    assert.equal(withInside.line.kev?.earliest_due, withoutInside.line.kev?.earliest_due);
    assert.equal(withInside.line.kev?.overdue_days, withoutInside.line.kev?.overdue_days);
    assert.deepEqual(withInside.line.epss, withoutInside.line.epss);
    // only a CVE NVD places outside moves the date: proof, not a missing lookup
    const proven = scopeKevToVersion(line, { "CVE-2099-3001": "outside", "CVE-2099-3002": "inside", "CVE-2099-3003": "outside", "CVE-2099-3004": "outside" }, actx());
    assert.deepEqual(proven.line.kev?.cves.map((c) => c.cve_id), ["CVE-2099-3002"]);
    assert.equal(proven.line.kev?.earliest_due, "2025-04-22");
    assert.ok(!proven.line.evidence.some((e) => e.field === "kev_cves_not_version_checked"));
  });

  test("inside and unchecked, nothing outside: nothing dropped, the confirmed CVE listed first, the others labelled", () => {
    const line = base();
    const out = scopeKevToVersion(line, { "CVE-2099-3002": "inside" }, { ...actx(), version: "9.0.54" });
    assert.equal(out.changed, true);
    assert.equal(out.basis, "inside");
    assert.deepEqual(out.line.kev?.cves.map((c) => c.cve_id), ["CVE-2099-3002", "CVE-2099-3001", "CVE-2099-3003", "CVE-2099-3004"]);
    assert.equal(out.line.kev?.earliest_due, line.kev?.earliest_due);
    assert.deepEqual(out.line.epss, line.epss);
    assert.ok(!out.line.evidence.some((e) => e.field === "kev_cves_version_not_affected"));
    assert.match(out.line.evidence.find((e) => e.field === "kev_cves_not_version_checked")?.value ?? "", /^3 other cited KEV CVE\(s\)/);
  });

  test("nothing to change: no status, all inside, all unchecked, or every cited CVE outside (the not-affected rule)", () => {
    const line = base();
    const all = (s: "inside" | "outside" | "unchecked") => Object.fromEntries(entries.map((e) => [e.cve_id, s]));
    assert.equal(scopeKevToVersion(line, undefined, actx()).changed, false);
    assert.equal(scopeKevToVersion(line, all("inside"), actx()).basis, "inside");
    assert.equal(scopeKevToVersion(line, all("inside"), actx()).changed, false);
    assert.equal(scopeKevToVersion(line, all("unchecked"), actx()).changed, false);
    const outside = scopeKevToVersion(line, all("outside"), actx());
    assert.equal(outside.changed, false);
    assert.equal(outside.line, line);
  });

  test("no CVE inside: the CVEs not version-checked carry the dates and EPSS; the disagreement note follows the new top", () => {
    const line = base();
    const out = scopeKevToVersion(line, { "CVE-2099-3001": "outside", "CVE-2099-3002": "outside" }, { ...actx(), version: "10.1.50" });
    assert.equal(out.basis, "unchecked");
    assert.deepEqual(out.line.kev?.cves.map((c) => c.cve_id), ["CVE-2099-3003", "CVE-2099-3004"]);
    assert.equal(out.line.kev?.earliest_due, "2022-03-17");
    assert.equal(out.line.epss?.cve_id, "CVE-2099-3004");
    assert.ok(!out.line.evidence.some((e) => e.field === "kev_cves_not_version_checked"));
    assert.match(out.line.evidence.find((e) => e.field === "kev_basis")?.value ?? "", /not version-checked/);
  });
});
