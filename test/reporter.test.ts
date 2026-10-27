// Reporter (template) tests: at most two sentences, built only from the line's own facts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_POLICY } from "../src/contracts.ts";
import type { InventoryRow, KevEntry, Resolution } from "../src/contracts.ts";
import { whyConfirmed, whyFor, whyVersionUnconfirmed } from "../src/agents/reporter.ts";
import { assessRow } from "../src/policy/analyst.ts";
import type { AnalystContext } from "../src/policy/analyst.ts";
import { familyKey } from "../src/resolve/candidates.ts";

const AS_OF = "2026-10-26";
const kev = (cve_id: string, vendor: string, product: string, date_added: string, due_date: string): KevEntry => ({
  cve_id, vendor, product, vulnerability_name: "", date_added, due_date, ransomware_use: "Unknown", required_action: "",
  short_description: "", notes: "", catalog_version: "2026.10.23",
});
const row = (row_id: string, software: string, internet_facing = false): InventoryRow =>
  ({ row_id, asset_id: "A1", asset_name: "web-01", asset_type: "server", internet_facing, owner_team: "IT", software });
const res = (status: Resolution["status"], vendor: string | null = null, product: string | null = null): Resolution => ({
  row_id: "R1", status, vendor, product, family: vendor ? `${vendor} ${product}` : null, version: null, product_type: "unknown",
  votes: [], adjudicated_by: null, confidence: 1,
});
const ctx = (over: Partial<AnalystContext> = {}): AnalystContext => ({
  asOf: AS_OF, policy: DEFAULT_POLICY, live: true, inventoryFrom: "zetaris", kevPairsError: null, kevError: null,
  catalogVersion: "2026.10.23", epssError: null,
  kevByFamily: new Map([
    [familyKey("Apache Log4j2"), [kev("CVE-2021-44228", "Apache", "Log4j2", "2021-12-10", "2021-12-24"), kev("CVE-2021-45046", "Apache", "Log4j2", "2023-05-01", "2023-05-22")]],
    [familyKey("Fortinet Multiple Products"), [kev("CVE-2025-61624", "Fortinet", "Multiple Products", "2026-10-16", "2026-10-26")]],
    [familyKey("Plex Media Server"), [kev("CVE-2026-96655", "Plex", "Media Server", "2026-10-20", "2026-11-03")]],
  ]),
  epssByCve: new Map([
    ["CVE-2021-44228", { cve_id: "CVE-2021-44228", epss: 0.99999, percentile: 1, score_date: "2026-10-25" }],
    ["CVE-2025-61624", { cve_id: "CVE-2025-61624", epss: 0.01343, percentile: 0.71155, score_date: "2026-10-25" }],
  ]),
  ...over,
});

function sentences(s: string): number {
  return s.split(/(?<=[.?!])\s+(?=[A-Z"])/).filter(Boolean).length;
}

function why(software: string, r: Resolution, c = ctx(), internet = false): { text: string; lineJson: string } {
  const a = assessRow(row("R1", software, internet), r, c);
  return { text: whyFor(a.line, a.owner, c.policy), lineJson: JSON.stringify(a) };
}

test("patch_now: names the most recent cited CVE, the target, the overdue federal date and EPSS", () => {
  const { text, lineJson } = why("log4j-core 2.14.1", res("matched", "Apache", "Log4j2"));
  assert.ok(sentences(text) <= 2, text);
  assert.match(text, /^Apache Log4j2 is listed in CISA KEV as exploited in the wild: 2 cited CVEs, most recently CVE-2021-45046 \(added 2023-05-01\)\./);
  assert.match(text, /Patch by 2026-11-02 under your 7-day rule; the US federal due date \(2021-12-24\) passed 1767 days ago, and EPSS for CVE-2021-44228 is 0\.99999\.$/);
  for (const token of text.match(/CVE-\d{4}-\d+|\d{4}-\d{2}-\d{2}/g) ?? []) assert.ok(lineJson.includes(token), `${token} is not in the line`);
});

test("patch_now with a low EPSS says the KEV listing decides; a due date today reads 'is today'", () => {
  const { text } = why("FortiOS 7.2", res("matched", "Fortinet", "Multiple Products"));
  assert.ok(sentences(text) <= 2, text);
  assert.match(text, /due date \(2026-10-26\) is today/);
  assert.match(text, /EPSS for CVE-2025-61624 is 0\.01343, low, but the KEV listing decides under your rules\.$/);
});

test("patch_now with a future due date and no EPSS score", () => {
  const { text } = why("Plex Media Server", res("matched", "Plex", "Media Server"));
  assert.match(text, /\(2026-11-03\) is in 8 days, and no EPSS score was found\.$/);
});

test("monitor: no KEV match, and matched without a KEV entry", () => {
  const none = why("Notepad++ 8.6", res("no_match")).text;
  assert.equal(none, 'No CISA KEV product matches "Notepad++ 8.6". Review it again by 2027-01-24 (every 90 days under your rules).');
  // a matched row can reach monitor once version checks exist; the wording is ready for it
  const base = assessRow(row("R1", "Tomcat 9"), res("no_match"), ctx());
  const quiet = whyFor({ ...base.line, resolution: res("matched", "Apache", "Tomcat") }, null, DEFAULT_POLICY);
  assert.match(quiet, /^Apache Tomcat matched this row, but KEV lists no exploited CVE for it\. Review it again by 2027-01-24/);
});

test("a KEV product name that already starts with its vendor names the vendor once (PHP / PHP is 'PHP', not 'PHP PHP')", () => {
  const base = assessRow(row("R1", "PHP 8.1.2"), res("no_match"), ctx()).line;
  const named = (vendor: string, product: string): string =>
    whyFor({ ...base, resolution: res("matched", vendor, product) }, null, DEFAULT_POLICY).replace(/ matched this row, .*$/, "");
  assert.equal(named("PHP", "PHP"), "PHP");
  assert.equal(named("Notepad++", " Notepad++ "), "Notepad++");
  assert.equal(named("Roundcube", "Roundcube Webmail"), "Roundcube Webmail");
  assert.equal(named("jenkins", "Jenkins"), "Jenkins");
  // a product that does not start with the whole vendor word keeps the vendor
  assert.equal(named("Apache", "Tomcat"), "Apache Tomcat");
  assert.equal(named("Fortinet", "FortiOS"), "Fortinet FortiOS");
  assert.equal(named("SAP", "SAPgui"), "SAP SAPgui");
  // the confirmed "why" reads "PHP 8.1.2"
  const c = ctx({ kevByFamily: new Map([[familyKey("PHP PHP"), [kev("CVE-2024-4577", "PHP", "PHP", "2024-06-12", "2024-07-03")]]]) });
  const line = assessRow(row("R1", "PHP 8.1.2"), res("matched", "PHP", "PHP"), c).line;
  assert.match(whyConfirmed(line, DEFAULT_POLICY, { version: "8.1.2" }), /^NVD places PHP 8\.1\.2 inside the affected range of CVE-2024-4577, /);
});

test("ask_owner after an incomplete KEV read says so, in two sentences", () => {
  const { text } = why("Tomcat 9", res("matched", "Apache", "Tomcat"));
  assert.ok(sentences(text) <= 2, text);
  assert.match(text, /^KEV returned no entry for Apache Tomcat, although the KEV catalogue lists that name, so this row was not relaxed to monitor\. Please re-run/);
});

test("ask_owner: the reason, then the question", () => {
  const { text } = why("Citrix NetScaler ADC 13.1", res("unresolved"));
  assert.ok(sentences(text) <= 2, text);
  assert.equal(text, 'No juror gave a valid answer for this row. Which product and version is "Citrix NetScaler ADC 13.1" on web-01?');
});

test("this_cycle: the CVE, its EPSS and the threshold that applied", () => {
  const c = ctx({ nonKevByFamily: new Map([[familyKey("Apache Tomcat"), [{ cve_id: "CVE-2099-0001", epss: 0.07, percentile: 0.9, score_date: "2026-10-25" }]]]) });
  const { text } = why("Tomcat 9", res("matched", "Apache", "Tomcat"), c, true);
  assert.equal(text, "Apache Tomcat is not in KEV, but CVE-2099-0001 has EPSS 0.07, at or above your 0.05 threshold for internet-facing assets. Patch by 2026-11-25 under your 30-day rule.");
});

test("whyConfirmed leads with the CVE NVD places the version inside; whyVersionUnconfirmed counts the outside ones", () => {
  const line = assessRow(row("R1", "Apache Log4j 2.14.1"), res("matched", "Apache", "Log4j2"), ctx()).line;
  const one = { ...line, kev: { cves: [line.kev!.cves[1]], earliest_due: "2021-12-24", overdue_days: 1767 } };
  const w = whyConfirmed(one, DEFAULT_POLICY, { version: "2.14.1", outside: 1 });
  assert.match(w, /^NVD places Apache Log4j2 2\.14\.1 inside the affected range of CVE-2021-44228, which CISA KEV lists as exploited in the wild \(added 2021-12-10\); it is outside the ranges of 1 other KEV CVE\./);
  assert.match(w, /the US federal due date \(2021-12-24\) passed 1767 days ago/);
  assert.ok((w.match(/\. /g) ?? []).length <= 1, "at most two sentences");
  assert.match(whyConfirmed(line, DEFAULT_POLICY, { version: null }), /^NVD places every version of Apache Log4j2 inside the affected ranges of 2 KEV-listed CVEs, most recently/);
  assert.match(whyVersionUnconfirmed(line, DEFAULT_POLICY, { outside: 2 }), /; NVD places the version outside the ranges of 2 other KEV CVEs\./);
  assert.doesNotMatch(whyVersionUnconfirmed(line, DEFAULT_POLICY), /outside/);
});

test("whyConfirmed with cited CVEs not version-checked: leads with the confirmed one and labels the others fail-closed", () => {
  const line = assessRow(row("R1", "Apache Log4j 2.14.1"), res("matched", "Apache", "Log4j2"), ctx()).line;
  // CVE-2021-45046 (newest) confirmed; CVE-2021-44228 not version-checked, with the earlier due date and the top EPSS
  const w = whyConfirmed(line, DEFAULT_POLICY, { version: "2.14.1", inside: ["CVE-2021-45046"], outside: 1 });
  assert.match(w, /^NVD places Apache Log4j2 2\.14\.1 inside the affected range of CVE-2021-45046, which CISA KEV lists as exploited in the wild \(added 2023-05-01\); 1 other cited KEV CVE is not version-checked, counted fail-closed; it is outside the ranges of 1 other KEV CVE\./);
  assert.match(w, /the US federal due date \(2021-12-24\) passed \d+ days ago \(CVE-2021-44228, not version-checked\), and EPSS for CVE-2021-44228 \(not version-checked\) is 0\.99999\.$/);
  assert.equal(sentences(w), 2);
  // every cited CVE confirmed: no label
  const all = whyConfirmed(line, DEFAULT_POLICY, { version: "2.14.1", inside: ["CVE-2021-45046", "CVE-2021-44228"] });
  assert.doesNotMatch(all, /not version-checked/);
});
