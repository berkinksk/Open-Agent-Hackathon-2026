// Tests for the deterministic normaliser (src/resolve/normalise.ts).
// Fixture: test/fixtures/kev_pairs.json, 229 real KEV (vendor, product) pairs from 10 vendors, captured with a
// SELECT DISTINCT through Zetaris on 26 Oct 2026 (spellings kept exactly, trailing spaces and U+202F included).
// The inventory strings are development examples (the design examples and the P4 probe strings), never test rows.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { InventoryRow, KevPair } from "../src/contracts.ts";
import {
  NORMALISER_THRESHOLDS, assetContext, canonicalTokens, cloudCueSource, extractVersion, familiesOf, familyOf, jaroWinkler, kevProductType,
  matchedKevPart, normaliserVote, pairsInFamily, pairsMentioning, parseSoftware, topCandidates, typeRelation, voteKind,
} from "../src/resolve/normalise.ts";

const PAIRS: KevPair[] = (JSON.parse(readFileSync(new URL("./fixtures/kev_pairs.json", import.meta.url), "utf8")) as {
  rows: [string, string][];
}).rows.map(([vendor, product]) => ({ vendor, product }));

function row(software: string, asset_type = "server", row_id = "D01"): InventoryRow {
  return { row_id, asset_id: "A01", asset_name: "dev-asset", asset_type, internet_facing: false, owner_team: "IT", software };
}

function resolve(software: string, asset_type = "server") {
  const parsed = parseSoftware(software);
  const cands = topCandidates(parsed, PAIRS);
  const vote = normaliserVote(row(software, asset_type), parsed, cands);
  return { parsed, cands, vote };
}

const fam = (vendor: string, product: string): string => familyOf({ vendor, product });
const voteFamily = (v: { vendor: string | null; product: string | null }): string | null =>
  v.vendor && v.product ? fam(v.vendor, v.product) : null;

test("fixture sanity: 229 real pairs, including the trailing-space and U+202F spellings", () => {
  assert.equal(PAIRS.length, 229);
  assert.ok(PAIRS.some((p) => p.vendor === "Microsoft" && p.product === "Windows "));
  assert.ok(PAIRS.some((p) => p.vendor === "Adobe" && p.product === "Commerce and Magento"));
});

// ---------- parseSoftware: versions ----------
const VERSION_CASES: [string, string | null][] = [
  ["log4j-core 2.14.1 (bundled in ERP-Portal WAR)", "2.14.1"],
  ["Citrix NetScaler ADC 13.1-48.47", "13.1-48.47"],
  ["MS Exchange Svr 2019 CU12", "2019 CU12"],
  ["Notepad++ v8.6", "8.6"],
  ["FortiGate 60F, FortiOS 7.2.4", "7.2.4"],
  ["Ivanti ICS 22.4R2 (VPN)", "22.4R2"],
  ["vCenter 7.0 U3", "7.0 U3"],
  ["Citrix NetScaler 13.1 Build 48.47", "13.1-48.47"],
  ["PAN-OS 10.2.7-h3 (GlobalProtect gw)", "10.2.7-h3"],
  ["Cisco ASA 9.16(4)", "9.16(4)"],
  ["Windows 10 22H2", "22H2"],
  ["Zoom Workplace 6.0.2 x64 build 2201", "6.0.2"],
  ["Apache Struts 2", null],
  ["Exchange Online (M365 tenant)", null],
];
for (const [raw, expected] of VERSION_CASES) {
  test(`version: ${JSON.stringify(raw)} -> ${JSON.stringify(expected)}`, () => {
    assert.equal(parseSoftware(raw).version, expected);
  });
}

test("extractVersion returns the text without the version", () => {
  const { version, rest } = extractVersion("FortiOS 7.2.4 on branch");
  assert.equal(version, "7.2.4");
  assert.equal(rest.replace(/\s+/g, " ").trim(), "FortiOS on branch");
});

// ---------- parseSoftware: vendor, hint, tokens, type ----------
test("parse: 'MS Exchange Svr 2019 CU12' -> Microsoft, 'Exchange Svr', tokens exchange+server, server", () => {
  const p = parseSoftware("MS Exchange Svr 2019 CU12");
  assert.equal(p.raw, "MS Exchange Svr 2019 CU12");
  assert.equal(p.vendor_hint, "Microsoft");
  assert.equal(p.product_hint, "Exchange Svr");
  assert.deepEqual(p.tokens, ["exchange", "server"]);
  assert.equal(p.product_type, "server");
});

test("parse: the 'bundled in' host and bracketed notes are noise, not product words", () => {
  const p = parseSoftware("log4j-core 2.14.1 (bundled in ERP-Portal WAR)");
  assert.equal(p.vendor_hint, "Apache");
  assert.equal(p.product_hint, "log4j-core");
  assert.deepEqual(p.tokens, ["log4j"]);
  assert.equal(p.product_type, "library");
  const q = parseSoftware("FortiClient VPN 7.0.9 (laptops)");
  assert.equal(q.product_hint, "FortiClient VPN");
  assert.ok(!q.tokens.includes("laptops"));
  const z = parseSoftware("Zoom Workplace 6.0.2 x64 build 2201");
  assert.deepEqual(z.tokens, ["zoom", "workplace"]);
});

test("parse: vendor aliases (MS, Forti*, httpd, NetScaler, PAN-OS, Ivanti/Pulse)", () => {
  const cases: [string, string][] = [
    ["MS SQL 2019", "Microsoft"],
    ["FortiGate 60F, FortiOS 7.2.4", "Fortinet"],
    ["FortiClient VPN 7.0.9", "Fortinet"],
    ["httpd 2.4.49", "Apache"],
    ["NetScaler ADC 13.1-48.47", "Citrix"],
    ["PAN-OS 10.2.7", "Palo Alto Networks"],
    ["Ivanti ICS 22.4R2 (VPN)", "Ivanti"],
    ["Pulse Secure Connect Secure 9.1R11", "Ivanti"],
    ["vCenter 7.0 U3", "VMware"],
  ];
  for (const [raw, vendor] of cases) assert.equal(parseSoftware(raw).vendor_hint, vendor, raw);
  assert.equal(parseSoftware("Notepad++ v8.6").vendor_hint, null);
});

test("parse: product-type lexicon on inventory strings", () => {
  const cases: [string, string][] = [
    ["Exchange Online (M365 tenant)", "cloud_service"],
    ["SharePoint Online", "cloud_service"],
    ["FortiClient VPN 7.0.9 (laptops)", "client"],
    ["Citrix Workspace app", "client"],
    ["Google Chrome 118.0.5993.88", "client"],
    ["FortiClient EMS 7.0.1", "server"],
    ["MS Exchange Svr 2019 CU12", "server"],
    ["Citrix NetScaler ADC 13.1-48.47", "server"],
    ["FortiGate 60F, FortiOS 7.2.4", "network_appliance"],
    ["PAN-OS 10.2.7 (GlobalProtect gw)", "network_appliance"],
    ["log4j-core 2.14.1 (bundled in ERP-Portal WAR)", "library"],
    ["Windows 10 22H2", "os"],
    ["Apache 2.4.49", "server"],
  ];
  for (const [raw, type] of cases) assert.equal(parseSoftware(raw).product_type, type, raw);
});

test("parse: odd whitespace and empty input never throw", () => {
  const p = parseSoftware(" Apache httpd  2.4.49​ ");
  assert.equal(p.version, "2.4.49");
  assert.equal(p.vendor_hint, "Apache");
  assert.deepEqual(p.tokens, ["http", "server"]);
  for (const raw of ["", "   ", "()", "---"]) {
    const e = parseSoftware(raw);
    assert.equal(e.product_type, "unknown");
    assert.deepEqual(e.tokens, []);
    assert.equal(e.version, null);
  }
});

// ---------- kevProductType ----------
test("kevProductType: Exchange Server -> server, FortiClient EMS -> server, Workspace Application... -> client", () => {
  assert.equal(kevProductType({ vendor: "Microsoft", product: "Exchange Server" }), "server");
  assert.equal(kevProductType({ vendor: "Fortinet", product: "FortiClient EMS" }), "server");
  assert.equal(kevProductType({ vendor: "Citrix", product: "Workspace Application and Receiver for Windows" }), "client");
});

test("kevProductType: more KEV names, vendor-aware (Cisco IOS) and combo-aware (FortiOS and FortiProxy)", () => {
  const cases: [string, string, string][] = [
    ["Microsoft", "Exchange", "server"],
    ["Fortinet", "FortiOS and FortiProxy SSL-VPN", "network_appliance"],
    ["Apache", "Log4j2", "library"],
    ["Apache", "HTTP Server", "server"],
    ["Microsoft", "Windows", "os"],
    ["Microsoft", "Windows ", "os"],
    ["Microsoft", "Win32k", "os"],
    ["Cisco", "IOS", "network_appliance"],
    ["Microsoft", "Edge", "client"],
    ["VMware", "SD-WAN Edge", "network_appliance"],
    ["Fortinet", "FortiOS and FortiProxy", "network_appliance"],
    ["VMware", "vCenter Server and Cloud Foundation", "server"],
    // a combo whose products' types conflict (a server and a client) has no single type: neutral
    ["VMware", "ESXi and Workstation", "unknown"],
    ["VMware", "ESXi, Workstation, and Fusion", "unknown"],
    ["Microsoft", ".NET Framework, SharePoint, Visual Studio", "unknown"],
    ["Fortinet", "Multiple Products", "unknown"],
  ];
  for (const [vendor, product, type] of cases) assert.equal(kevProductType({ vendor, product }), type, `${vendor} / ${product}`);
});

test("typeRelation: cloud vs on-prem and client vs server/console/appliance conflict; unknown is neutral", () => {
  assert.equal(typeRelation("cloud_service", "server"), "conflict");
  assert.equal(typeRelation("client", "server"), "conflict");
  assert.equal(typeRelation("server", "client"), "conflict");
  assert.equal(typeRelation("client", "network_appliance"), "conflict");
  assert.equal(typeRelation("server", "network_appliance"), "compatible");
  assert.equal(typeRelation("library", "server"), "compatible");
  assert.equal(typeRelation("os", "os"), "same");
  assert.equal(typeRelation("unknown", "server"), "neutral");
  // the P4 look-alikes come out with conflicting types; the real Citrix client does not
  const exo = parseSoftware("Exchange Online (M365 tenant)").product_type;
  assert.equal(typeRelation(exo, kevProductType({ vendor: "Microsoft", product: "Exchange Server" })), "conflict");
  const fcv = parseSoftware("FortiClient VPN 7.0.9 (laptops)").product_type;
  assert.equal(typeRelation(fcv, kevProductType({ vendor: "Fortinet", product: "FortiClient EMS" })), "conflict");
  const cwa = parseSoftware("Citrix Workspace app").product_type;
  assert.equal(typeRelation(cwa, kevProductType({ vendor: "Citrix", product: "Workspace Application and Receiver for Windows" })), "same");
});

test("assetContext: laptops are endpoints, firewalls infrastructure, an M365 tenant cloud; plain 'cloud' sets nothing", () => {
  assert.equal(assetContext("laptop"), "endpoint");
  assert.equal(assetContext("firewall"), "infrastructure");
  assert.equal(assetContext("M365 tenant"), "cloud");
  assert.equal(assetContext("cloud"), null);
  assert.equal(assetContext(undefined), null);
});

// ---------- familyOf ----------
test("familyOf: the Citrix ADC/NetScaler/Gateway spellings are one family (NetScaler SD-WAN is not)", () => {
  const spellings = [
    "Application Delivery Controller (ADC) and Gateway",
    "Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP Appliance",
    "NetScaler",
    "NetScaler ADC and Gateway",
    "NetScaler ADC and NetScaler Gateway",
    "SD-WAN and NetScaler",
  ];
  for (const s of spellings) assert.equal(fam("Citrix", s), "citrix:netscaler-adc-gateway", s);
  assert.notEqual(fam("Citrix", "NetScaler SD-WAN Enterprise, CloudBridge Virtual WAN, and XenMobile Server"), "citrix:netscaler-adc-gateway");
  assert.notEqual(fam("Citrix", "Workspace Application and Receiver for Windows"), "citrix:netscaler-adc-gateway");
});

test("familyOf: Exchange and Exchange Server are one family; Internet Key Exchange is not", () => {
  assert.equal(fam("Microsoft", "Exchange"), "microsoft:exchange-server");
  assert.equal(fam("Microsoft", "Exchange Server"), "microsoft:exchange-server");
  assert.notEqual(fam("Microsoft", "Internet Key Exchange (IKE) Service Extensions"), "microsoft:exchange-server");
});

test("familyOf: 'Windows ' with a trailing space -> microsoft:windows", () => {
  assert.equal(fam("Microsoft", "Windows"), "microsoft:windows");
  assert.equal(fam("Microsoft", "Windows "), "microsoft:windows");
  assert.equal(fam("Microsoft ", " Windows "), "microsoft:windows");
});

test("familyOf: the FortiOS variants -> fortinet:fortios; FortiClient EMS is its own family", () => {
  for (const s of ["FortiOS", "FortiOS and FortiADC", "FortiOS and FortiProxy", "FortiOS and FortiProxy SSL-VPN"]) {
    assert.equal(fam("Fortinet", s), "fortinet:fortios", s);
  }
  assert.equal(fam("Fortinet", "FortiClient EMS"), "fortinet:forticlient-ems");
});

test("familyOf: case, trailing-space and U+202F variants collapse", () => {
  const magento = ["Commerce and Magento", "Commerce and Magento ", "Commerce and Magento", "Commerce and Magento Open Source"];
  assert.equal(new Set(magento.map((p) => fam("Adobe", p))).size, 1);
  assert.equal(fam("Cisco", "IOS Software"), fam("Cisco", "IOS software"));
  assert.equal(fam("Ivanti", " Endpoint Manager (EPM)"), fam("Ivanti", "Endpoint Manager (EPM)"));
});

test("familyOf: F1 feasibility near-duplicates share a family", () => {
  assert.equal(fam("Apache", "Log4j"), fam("Apache", "Log4j2"));
  assert.equal(fam("Citrix", "NetScaler ADC and Gateway"), fam("Citrix", "NetScaler ADC and NetScaler Gateway"));
  assert.equal(fam("Fortinet", "FortiOS"), fam("Fortinet", "FortiOS and FortiProxy"));
});

test("familyOf: generic fallback, vague entries, and pairsInFamily over the fixture", () => {
  assert.equal(fam("Cisco", "Identity Services Engine"), "cisco:identity-services-engine");
  assert.equal(fam("Fortinet", "Multiple Products"), "fortinet:multiple-products");
  assert.equal(fam("Apache", "Apache"), "apache:multiple-products");
  assert.equal(fam("Palo Alto Networks", "PAN-OS"), "palo-alto-networks:pan-os");
  const netscaler = pairsInFamily("citrix:netscaler-adc-gateway", PAIRS);
  assert.equal(netscaler.length, 6);
  assert.ok(netscaler.every((p) => PAIRS.includes(p)), "returns the exact KEV pairs");
  assert.equal(pairsInFamily("microsoft:windows", PAIRS).filter((p) => p.product.trim() === "Windows").length, 2);
});

// ---------- topCandidates ----------
// F1 feasibility table (Idea_Selection/feasibility/F1.md §2): pairs that World Model's Levenshtein score put in "new".
const F1_TABLE: [string, KevPair][] = [
  ["log4j-core 2.14.1", { vendor: "Apache", product: "Log4j2" }],
  ["Log4j", { vendor: "Apache", product: "Log4j2" }],
  ["MS Exchange Svr 2019", { vendor: "Microsoft", product: "Exchange Server" }],
  ["Citrix NetScaler ADC", { vendor: "Citrix", product: "NetScaler ADC and Gateway" }],
  ["NetScaler ADC and Gateway", { vendor: "Citrix", product: "NetScaler ADC and NetScaler Gateway" }],
  ["Apache HTTPD", { vendor: "Apache", product: "HTTP Server" }],
  ["FortiOS", { vendor: "Fortinet", product: "FortiOS and FortiProxy" }],
];
for (const [raw, expected] of F1_TABLE) {
  test(`F1 table: ${JSON.stringify(raw)} -> ${expected.vendor} / ${expected.product} (family)`, () => {
    const { cands, vote } = resolve(raw);
    const want = familyOf(expected);
    assert.equal(cands[0]?.family, want, `top candidate: ${JSON.stringify(cands[0])}`);
    assert.ok(cands.some((c) => c.family === want && c.score >= NORMALISER_THRESHOLDS.match_min));
    assert.equal(voteFamily(vote), want);
  });
}

test("topCandidates: shape: at most 12 by default, sorted, scores in [0,1], family and reason, exact KEV strings", () => {
  const parsed = parseSoftware("Microsoft Windows Server 2019");
  const cands = topCandidates(parsed, PAIRS);
  assert.ok(cands.length > 0 && cands.length <= 12);
  for (let i = 0; i < cands.length; i++) {
    const c = cands[i];
    assert.ok(c.score >= 0 && c.score <= 1);
    if (i) assert.ok(cands[i - 1].score >= c.score, "sorted by score");
    assert.ok(c.reason.length > 0);
    assert.equal(c.family, familyOf(c));
    assert.ok(PAIRS.some((p) => p.vendor === c.vendor && p.product === c.product), "an exact KEV pair");
  }
});

test("topCandidates: 'Windows' and 'Windows ' appear once, as the clean spelling", () => {
  const cands = topCandidates(parseSoftware("Windows 10 22H2"), PAIRS);
  const win = cands.filter((c) => c.vendor === "Microsoft" && c.product.trim() === "Windows");
  assert.equal(win.length, 1);
  assert.equal(win[0].product, "Windows");
  assert.equal(cands[0].product, "Windows");
});

test("topCandidates: k, empty inputs, and the per-family cap", () => {
  const parsed = parseSoftware("Citrix NetScaler ADC 13.1-48.47");
  assert.ok(topCandidates(parsed, PAIRS, 3).length <= 3);
  assert.deepEqual(topCandidates(parsed, PAIRS, 0), []);
  assert.deepEqual(topCandidates(parsed, []), []);
  assert.deepEqual(topCandidates(parseSoftware(""), PAIRS), []);
  const counts = new Map<string, number>();
  for (const c of topCandidates(parsed, PAIRS, 50)) counts.set(c.family, (counts.get(c.family) ?? 0) + 1);
  for (const [, n] of counts) assert.ok(n <= NORMALISER_THRESHOLDS.family_cap);
});

test("topCandidates: the look-alike stays in front of the jury, flagged as a type conflict", () => {
  const cands = topCandidates(parseSoftware("Exchange Online (M365 tenant)"), PAIRS);
  const server = cands.find((c) => c.family === "microsoft:exchange-server");
  assert.ok(server, "Exchange (Server) is still a candidate");
  assert.match(server.reason, /type conflict: cloud_service vs server/);
  const fc = topCandidates(parseSoftware("FortiClient VPN 7.0.9 (laptops)"), PAIRS).find((c) => c.product === "FortiClient EMS");
  assert.ok(fc);
  assert.match(fc.reason, /type conflict: client vs server/);
});

test("topCandidates: deterministic, and independent of the input order of the pairs", () => {
  const parsed = parseSoftware("Cisco IOS XE 17.3");
  const a = topCandidates(parsed, PAIRS);
  const b = topCandidates(parsed, [...PAIRS].reverse());
  assert.deepEqual(a, topCandidates(parsed, PAIRS));
  assert.deepEqual(a, b);
});

// ---------- normaliserVote ----------
test("vote: 'Exchange Online' -> cloud_service, no server match chosen (confident no-match)", () => {
  const { parsed, vote } = resolve("Exchange Online (M365 tenant)", "M365 tenant");
  assert.equal(parsed.product_type, "cloud_service");
  assert.equal(vote.vendor, null);
  assert.equal(vote.product, null);
  assert.equal(vote.product_type, "cloud_service");
  assert.equal(voteKind(vote), "no_match");
  // the same holds whatever the asset column says
  assert.equal(resolve("Exchange Online (M365 tenant)", "server").vote.product, null);
});

test("vote: a perfect name match is still refused when the types conflict ('Exchange (M365 tenant)')", () => {
  const { parsed, cands, vote } = resolve("Exchange (M365 tenant)", "server");
  assert.equal(parsed.product_type, "cloud_service");
  assert.equal(cands[0].family, "microsoft:exchange-server", "the look-alike is the best name match");
  assert.match(cands[0].reason, /type conflict/);
  assert.equal(vote.product, null);
  // the cloud cue is only in the note: no server vote, but unsure rather than a confident "no KEV product"
  assert.equal(voteKind(vote), "abstain");
  // an on-prem server whose note mentions the tenant stays a server, and matches
  const hybrid = resolve("Exchange Server 2019 CU12 (hybrid, M365 tenant)", "server");
  assert.equal(hybrid.parsed.product_type, "server");
  assert.equal(voteFamily(hybrid.vote), "microsoft:exchange-server");
});

test("vote: 'FortiClient VPN' -> client, not the FortiClient EMS server", () => {
  const { parsed, vote } = resolve("FortiClient VPN 7.0.9 (laptops)", "laptop");
  assert.equal(parsed.product_type, "client");
  assert.notEqual(vote.product, "FortiClient EMS");
  assert.equal(vote.product, null);
  assert.equal(vote.product_type, "client");
  assert.equal(voteKind(vote), "no_match");
});

test("vote: 'Citrix Workspace app' -> the KEV client 'Workspace Application and Receiver for Windows'", () => {
  const { cands, vote } = resolve("Citrix Workspace app", "laptop");
  assert.equal(cands[0].product, "Workspace Application and Receiver for Windows");
  assert.equal(vote.vendor, "Citrix");
  assert.equal(vote.product, "Workspace Application and Receiver for Windows");
  assert.equal(vote.product_type, "client");
});

test("vote: 'MS Exchange Svr 2019 CU12' -> Exchange Server, confident but never certain", () => {
  const { vote } = resolve("MS Exchange Svr 2019 CU12", "server");
  assert.equal(voteFamily(vote), "microsoft:exchange-server");
  assert.equal(vote.juror, "normaliser");
  assert.equal(vote.row_id, "D01");
  assert.ok(vote.confidence >= 0.55 && vote.confidence <= 0.95);
});

// P4 probe strings (Build_Workspace/probes.md P4) with the probe's accepted answers.
const P4: [string, string, string, string][] = [
  ["I1", "log4j-core 2.14.1 (bundled in ERP-Portal WAR)", "server", "apache:log4j"],
  ["I2", "MS Exchange Svr 2019 CU12", "server", "microsoft:exchange-server"],
  ["I3", "Citrix NetScaler ADC 13.1-48.47", "vpn", "citrix:netscaler-adc-gateway"],
  ["I4", "FortiGate 60F, FortiOS 7.2.4", "firewall", "fortinet:fortios"],
  ["I5", "Apache httpd 2.4.49", "server", "apache:http-server"],
  ["I6", "Ivanti ICS 22.4R2 (VPN)", "vpn", "ivanti:connect-secure"],
  ["I7", "PAN-OS 10.2.7 (GlobalProtect gw)", "firewall", "palo-alto-networks:pan-os"],
  ["I8", "vCenter 7.0 U3", "server", "vmware:vcenter-server"],
];
for (const [id, raw, assetType, family] of P4) {
  test(`P4 ${id}: ${JSON.stringify(raw)} -> ${family}`, () => {
    const { vote } = resolve(raw, assetType);
    assert.equal(voteFamily(vote), family);
    assert.equal(voteKind(vote), "match");
    assert.ok(vote.confidence > 0 && vote.confidence < 1);
  });
}

test("vote: the asset column vetoes a server product on a laptop", () => {
  assert.equal(voteFamily(resolve("vCenter 7.0 U3", "server").vote), "vmware:vcenter-server");
  const onLaptop = resolve("vCenter 7.0 U3", "laptop").vote;
  assert.equal(onLaptop.product, null);
  assert.equal(voteKind(onLaptop), "abstain", "the data contradicts itself: ask, do not claim 'no match'");
});

test("vote: software KEV does not list -> confident no-match", () => {
  for (const raw of ["Notepad++ v8.6", "Zoom Workplace 6.0.2 x64 build 2201", "Microsoft Teams"]) {
    const { vote } = resolve(raw, "laptop");
    assert.equal(vote.product, null, raw);
    assert.equal(voteKind(vote), "no_match", raw);
  }
});

test("vote: a close call between families or a bare vendor -> abstain, not a guess", () => {
  const catalyst = resolve("Cisco Catalyst", "switch").vote; // SD-WAN vs 6800 vs 4500 switches
  assert.equal(catalyst.product, null);
  assert.equal(voteKind(catalyst), "abstain");
  const vendorOnly = resolve("Microsoft", "server").vote;
  assert.equal(vendorOnly.product, null);
  assert.equal(voteKind(vendorOnly), "abstain");
  const empty = normaliserVote(row(""), parseSoftware(""), []);
  assert.equal(voteKind(empty), "abstain");
});

test("vote: typos and Cisco-style variants still resolve to the right family", () => {
  assert.equal(voteFamily(resolve("Exchnage Server 2016").vote), "microsoft:exchange-server");
  assert.equal(voteFamily(resolve("Cisco IOS XE 17.3", "switch").vote), "cisco:ios");
  assert.equal(voteFamily(resolve("Cisco ASA 9.16(4)", "firewall").vote), "cisco:asa");
  assert.equal(voteFamily(resolve("struts2-core 2.5.10").vote), "apache:struts");
});

// ---------- cloud spellings of a server product (review fix, round 1) ----------
// The 365 suite names and a bracketed "(cloud)" are cloud cues, not just "online"/"tenant": every one of these is the
// hosted Exchange, so no on-prem Exchange Server vote, whatever the asset column says. A cue in the main text gives a
// confident no-match; a cue only in a bracketed note gives an abstention (review fix, round 2: a note may only say
// where an on-prem product is hosted, so it never earns a confident "no KEV product").
const CLOUD_EXCHANGE: [string, "main" | "note"][] = [
  ["Exchange (M365)", "note"], ["Exchange (O365)", "note"], ["Exchange (Office 365)", "note"], ["Exchange (cloud)", "note"],
  ["Exchange 365", "main"], ["Exchange - Microsoft 365", "main"], ["M365 Exchange", "main"], ["O365 Exchange", "main"],
  ["Exchange mailboxes (M365)", "note"],
];
for (const [raw, source] of CLOUD_EXCHANGE) {
  test(`cloud cue: ${JSON.stringify(raw)} -> cloud_service (${source} cue), no Exchange Server vote on any asset type`, () => {
    for (const assetType of ["cloud", "server", ""]) {
      const { parsed, cands, vote } = resolve(raw, assetType);
      assert.equal(parsed.product_type, "cloud_service", `${raw} on "${assetType}"`);
      assert.equal(cloudCueSource(parsed), source, raw);
      assert.equal(vote.vendor, null, `${raw} on "${assetType}"`);
      assert.equal(vote.product, null, `${raw} on "${assetType}"`);
      assert.equal(voteKind(vote), source === "main" ? "no_match" : "abstain", `${raw} on "${assetType}"`);
      const server = cands.find((c) => c.family === "microsoft:exchange-server");
      assert.ok(server, "the look-alike stays in front of the jury");
      assert.match(server.reason, /type conflict: cloud_service vs server/);
    }
  });
}

test("cloud cue: on-prem, hybrid, versioned and IaaS-hosted installs stay on-prem and still match", () => {
  const cases: [string, string, string, string][] = [
    ["Exchange Server 2019 (hybrid, M365 tenant)", "server", "server", "microsoft:exchange-server"],
    ["Exchange (hybrid, M365 tenant)", "server", "server", "microsoft:exchange-server"],
    ["Exchange 2019 CU12 (M365 tenant)", "server", "server", "microsoft:exchange-server"], // a version: self-managed
    // no versions below, so each case exercises its own guard
    ["Exchange (cloud VM)", "server", "server", "microsoft:exchange-server"],              // IaaS, not the service
    ["Apache httpd (cloud)", "server", "server", "apache:http-server"],                    // only ever self-hosted
    ["Ivanti Cloud Services Appliance", "server", "server", "ivanti:cloud-services-appliance"],
    ["FortiGate 60F (Azure cloud)", "firewall", "network_appliance", "fortinet:fortios"],  // an appliance stays one
    ["log4j-core (bundled in cloud portal WAR)", "server", "library", "apache:log4j"],
    ["Apache ActiveMQ (bundled in cloud ERP suite)", "server", "server", "apache:activemq"], // names the host
  ];
  for (const [raw, assetType, type, family] of cases) {
    const { parsed, vote } = resolve(raw, assetType);
    assert.equal(parsed.product_type, type, raw);
    assert.equal(voteFamily(vote), family, raw);
  }
});

test("cloud cue: the desktop suite and its apps stay clients ('365 Apps', 'ProPlus', 'Office 365', 'Outlook (M365)')", () => {
  for (const raw of ["Microsoft 365 Apps for enterprise", "Office 365 ProPlus", "Office 365", "Outlook (M365)", "Outlook 365"]) {
    assert.equal(parseSoftware(raw).product_type, "client", raw);
  }
  assert.equal(voteFamily(resolve("Outlook (M365)", "laptop").vote), "microsoft:outlook");
  assert.equal(parseSoftware("Microsoft 365").product_type, "cloud_service");
  assert.equal(parseSoftware("Office 365 Exchange").product_type, "cloud_service");
  assert.notEqual(parseSoftware("Veeam Backup for Microsoft 365").product_type, "cloud_service"); // made for the suite
});

// ---------- note-only cloud cues fail closed (review fix, round 2) ----------
// A cloud word in a bracketed note may only say where an on-prem product runs. It must never turn a KEV-listed server
// product into a confident "no KEV product": NetScaler ADC in Azure is still the CitrixBleed-family appliance.
const NOTE_CLOUD_SERVERS: [string, string][] = [
  ["NetScaler ADC (Azure cloud)", "citrix:netscaler-adc-gateway"],
  ["NetScaler ADC VPX (cloud)", "citrix:netscaler-adc-gateway"],
  ["Citrix NetScaler Gateway (cloud hosted)", "citrix:netscaler-adc-gateway"],
  ["FortiClient EMS (365 endpoints)", "fortinet:forticlient-ems"],
  ["vCenter (private cloud)", "vmware:vcenter-server"],
];
for (const [raw, family] of NOTE_CLOUD_SERVERS) {
  test(`note-only cloud: ${JSON.stringify(raw)} is never a confident no-match; it stays a server and matches`, () => {
    for (const assetType of ["vpn", "server", "", "cloud"]) {
      const { vote } = resolve(raw, assetType);
      assert.notEqual(voteKind(vote), "no_match", `${raw} on "${assetType}"`);
      assert.ok(["match", "abstain"].includes(voteKind(vote)), `${raw} on "${assetType}"`);
    }
    const { parsed, vote } = resolve(raw, "server");
    assert.equal(parsed.product_type, "server", raw);
    assert.equal(cloudCueSource(parsed), null, raw);
    assert.equal(voteFamily(vote), family, raw);
  });
}

test("note-only cloud: appliance-class servers, IaaS and private-cloud notes, and a version in the note stay on-prem", () => {
  const cases: [string, string, string][] = [
    ["Citrix Gateway (SaaS)", "vpn", "citrix:netscaler-adc-gateway"],          // appliance class: never a tenant service
    ["Ivanti Sentry (cloud)", "server", "ivanti:sentry"],
    ["Ivanti Virtual Traffic Manager (Azure cloud)", "server", "ivanti:virtual-traffic-manager"],
    ["Cisco Identity Services Engine (cloud)", "server", "cisco:identity-services-engine"],
    ["Exchange (cloud hosted)", "server", "microsoft:exchange-server"],         // "hosted": IaaS, not the service
    ["Exchange (private cloud)", "server", "microsoft:exchange-server"],        // a private cloud runs its own server
    ["Exchange (cloud, 2019 CU12)", "server", "microsoft:exchange-server"],     // a version in the note: self-managed
    ["Exchange (365 users)", "server", "microsoft:exchange-server"],            // a bare 365 in a note is a count
  ];
  for (const [raw, assetType, family] of cases) {
    const { parsed, vote } = resolve(raw, assetType);
    assert.equal(parsed.product_type, "server", raw);
    assert.equal(voteFamily(vote), family, raw);
  }
  const ns = parseSoftware("NetScaler ADC (cloud, 13.1-48.47)");
  assert.equal(ns.version, "13.1-48.47");
  assert.equal(ns.product_type, "server");
  // the named suite still counts in a note; the bare number does not
  assert.equal(parseSoftware("Exchange (M365)").product_type, "cloud_service");
  assert.equal(parseSoftware("FortiClient EMS (365 endpoints)").product_type, "server");
  // a VPX note is a virtual appliance (IaaS), not the hosted service
  assert.notEqual(parseSoftware("Citrix (Azure cloud VPX)").product_type, "cloud_service");
  // the bracketed context never types a row cloud on its own: the guarded note rule decides that
  assert.equal(parseSoftware("Acme Widget (cloud VM)").product_type, "unknown");
});

test("note-only cloud: cloudCueSource tells a main-text cue from a note-only one", () => {
  assert.equal(cloudCueSource(parseSoftware("Exchange Online (M365 tenant)")), "main");
  assert.equal(cloudCueSource(parseSoftware("M365 Exchange")), "main");
  assert.equal(cloudCueSource(parseSoftware("Exchange (M365 tenant)")), "note");
  assert.equal(cloudCueSource(parseSoftware("Apache ActiveMQ (cloud)")), "note");
  assert.equal(cloudCueSource(parseSoftware("MS Exchange Svr 2019 CU12")), null);
  // the P4 look-alike keeps its confident no-match: its main text says "Online"
  assert.equal(voteKind(resolve("Exchange Online (M365 tenant)", "server").vote), "no_match");
});

test("note-only cloud: a note never turns a weak resemblance into a confident no-match, nor invents one", () => {
  // nothing close enough to be a look-alike, but the main text alone is a close call: still a close call
  assert.equal(voteKind(resolve("Cisco Prime reporting dashboard", "server").vote), "abstain");
  const weak = resolve("Cisco Prime reporting dashboard (cloud)", "server");
  assert.equal(cloudCueSource(weak.parsed), "note");
  assert.equal(voteKind(weak.vote), "abstain");
  // nothing in KEV resembles the row with or without the note: the confident no-match stands
  assert.equal(voteKind(resolve("Microsoft Dynamics", "server").vote), "no_match");
  assert.equal(voteKind(resolve("Microsoft Dynamics (cloud)", "server").vote), "no_match");
  // a server product that is SaaS-capable abstains with a cloud note (ask the owner), never "no KEV product"
  const amq = resolve("Apache ActiveMQ (cloud)", "server");
  assert.equal(amq.vote.product, null);
  assert.equal(voteKind(amq.vote), "abstain");
  // a look-alike blocked only by a note-only cloud type always means "ask", even a weak one from another vendor
  // (here the cloud type is what makes Cisco's RV Series routers a type-conflicting look-alike)
  const rv = resolve("Veeam RV Series sync service (cloud)", "server");
  assert.match(rv.cands[0].reason, /type conflict: cloud_service vs network_appliance/);
  assert.equal(voteKind(rv.vote), "abstain");
});

test("note-only cloud: over every fixture name, a cloud note never turns a match into a confident no-match", () => {
  const names = [...new Set(PAIRS.map((p) => `${p.vendor.trim()} ${p.product.trim()}`))];
  const kind = (sw: string): string => voteKind(resolve(sw, "server").vote);
  const bad: string[] = [];
  let matched = 0;
  for (const name of names) {
    if (kind(name) !== "match") continue;
    matched++;
    for (const note of ["(cloud)", "(Azure cloud)", "(365 users)", "(cloud hosted)", "(private cloud)", "(M365)"]) {
      if (kind(`${name} ${note}`) === "no_match") bad.push(`${name} ${note}`);
    }
  }
  assert.ok(matched > 150, `most fixture names match as rows (${matched})`);
  assert.deepEqual(bad, []);
});

// ---------- KEV combos, typed and grouped by the product the row matched (review fix, round 1) ----------
test("matchedKevPart: the combo product a row matched, with its own family and type", () => {
  const esxiWs = { vendor: "VMware", product: "ESXi and Workstation" };
  assert.deepEqual(matchedKevPart(parseSoftware("VMware Workstation 17.5"), esxiWs),
    { part: "workstation", family: "vmware:workstation", product_type: "client" });
  assert.deepEqual(matchedKevPart(parseSoftware("VMware ESXi 7.0 U3"), esxiWs),
    { part: "esxi", family: "vmware:esxi", product_type: "server" });
  const netSp = { vendor: "Microsoft", product: ".NET Framework, SharePoint, Visual Studio" };
  assert.equal(matchedKevPart(parseSoftware("SharePoint 2016"), netSp).family, "microsoft:sharepoint-server");
  assert.equal(matchedKevPart(parseSoftware("SharePoint 2016"), netSp).product_type, "server");
});

test("vote: VMware Workstation and Fusion match their KEV combos as clients, not 'no_match'", () => {
  const cases: [string, string, string][] = [
    ["VMware Workstation 17.5", "laptop", "vmware:workstation"],
    ["VMware Workstation Pro 17.5.0", "server", "vmware:workstation"],
    ["VMware Fusion 13.5", "laptop", "vmware:fusion"],
  ];
  for (const [raw, assetType, family] of cases) {
    const { parsed, cands, vote } = resolve(raw, assetType);
    assert.equal(voteKind(vote), "match", raw);
    assert.equal(vote.vendor, "VMware", raw);
    assert.equal(vote.product_type, "client", raw);
    assert.ok(familiesOf(vote as KevPair).includes(family), `${raw}: ${vote.product}`);
    assert.deepEqual(matchedKevPart(parsed, vote as KevPair).family, family);
    assert.match(cands[0].reason, /type client\/client same; via combo part/);
  }
  // ESXi in the same combos is still a server: matched on a server, vetoed on a laptop
  assert.equal(voteFamily(resolve("VMware ESXi 7.0 U3", "server").vote), "vmware:esxi");
  assert.equal(resolve("VMware ESXi 7.0 U3", "laptop").vote.product, null);
});

test("vote: a combo that lists the same product is not a rival family (SharePoint 2016, Cisco IOS XR, Edge)", () => {
  assert.equal(voteFamily(resolve("SharePoint 2016", "server").vote), "microsoft:sharepoint-server");
  assert.equal(voteFamily(resolve("Cisco IOS XR 7.5", "router").vote), "cisco:ios-xr");
  assert.equal(voteFamily(resolve("Microsoft Edge 118", "laptop").vote), "microsoft:edge");
});

test("familiesOf and pairsMentioning: KEV fetches include the combos that list the product second", () => {
  assert.deepEqual(familiesOf({ vendor: "VMware", product: "ESXi, Workstation, and Fusion" }),
    ["vmware:esxi", "vmware:workstation", "vmware:fusion"]);
  assert.deepEqual(familiesOf({ vendor: "Microsoft", product: "Exchange" }), ["microsoft:exchange-server"]);
  for (const p of PAIRS) assert.equal(familiesOf(p)[0], familyOf(p), `${p.vendor} / ${p.product}`);

  const sp = pairsMentioning("microsoft:sharepoint-server", PAIRS).map((p) => p.product);
  assert.ok(sp.includes(".NET Framework, SharePoint, Visual Studio"));
  assert.ok(pairsInFamily("microsoft:sharepoint-server", PAIRS).every((p) => sp.includes(p.product)), "a superset of pairsInFamily");
  assert.ok(!pairsInFamily("microsoft:sharepoint-server", PAIRS).some((p) => p.product.startsWith(".NET")));
  assert.deepEqual(pairsMentioning("vmware:workstation", PAIRS).map((p) => p.product).sort(),
    ["ESXi and Workstation", "ESXi, Workstation, and Fusion"]);
  const xr = pairsMentioning("cisco:ios-xr", PAIRS).map((p) => p.product);
  for (const s of ["IOS XR", "IOS, IOS XR, and IOS XE", "IOS, XR, and XE Software"]) assert.ok(xr.includes(s), s);
  const proxy = pairsMentioning("fortinet:fortiproxy", PAIRS).map((p) => p.product).sort();
  assert.deepEqual(proxy, ["FortiOS and FortiProxy", "FortiOS and FortiProxy SSL-VPN"]);
  assert.equal(pairsMentioning("citrix:netscaler-adc-gateway", PAIRS).length, 6);
});

// ---------- helpers ----------
test("jaroWinkler: identical 1, empty 0, and the textbook MARTHA/MARHTA value", () => {
  assert.equal(jaroWinkler("exchange", "exchange"), 1);
  assert.equal(jaroWinkler("", "exchange"), 0);
  assert.ok(Math.abs(jaroWinkler("martha", "marhta") - 0.9611) < 0.001);
  assert.ok(jaroWinkler("netscaler", "netscalar") > jaroWinkler("netscaler", "fortios"));
});

test("one-word spellings of Ivanti's gateways read as the KEV names (integration, dev-run finding)", () => {
  assert.deepEqual(canonicalTokens("Ivanti ConnectSecure VPN gateway").slice(0, 3), ["ivanti", "connect", "secure"]);
  assert.ok(canonicalTokens("PolicySecure NAC").includes("policy"));
  assert.equal(parseSoftware("ConnectSecure 22.7R2 (remote access)").vendor_hint, "Ivanti");
});

test("vendor-named KEV entries: an eponymous product is specific; an umbrella company's own name stays vague (sample-mode finding)", () => {
  // real KEV spellings (catalog 2026.10.23), added to the fixture inline
  const extra: KevPair[] = [
    { vendor: "OpenSSL", product: "OpenSSL" }, { vendor: "Samba", product: "Samba" }, { vendor: "Notepad++", product: "Notepad++" },
    { vendor: "Jenkins", product: "Jenkins" }, { vendor: "Jenkins", product: "Jenkins Command Line Interface (CLI)" },
    { vendor: "Jenkins", product: "Jenkins Stapler Web Framework" }, { vendor: "Jenkins", product: "Jenkins User Interface (UI)" },
    { vendor: "Jenkins", product: "Script Security Plugin" },
    { vendor: "Exim", product: "Exim" }, { vendor: "Exim", product: "Exim Internet Mailer" }, { vendor: "Exim", product: "Mail Transfer Agent (MTA)" },
    { vendor: "GitLab", product: "GitLab" }, { vendor: "GitLab", product: "GitLab CE/EE" }, { vendor: "GitLab", product: "Community and Enterprise Editions" },
    { vendor: "PHP", product: "PHP" }, { vendor: "PHP Group", product: "PHP" }, { vendor: "Langflow", product: "Langflow" }, { vendor: "IBM", product: "Langflow" },
  ];
  const all = [...PAIRS, ...extra];
  assert.equal(fam("OpenSSL", "OpenSSL"), "openssl:openssl");
  assert.equal(fam("Notepad++", "Notepad++"), "notepad++:notepad++");
  assert.equal(fam("Microsoft", "Microsoft"), "microsoft:multiple-products");
  assert.equal(fam("Apache", "Apache"), "apache:multiple-products");
  for (const p of ["Jenkins Command Line Interface (CLI)", "Jenkins Stapler Web Framework", "Jenkins User Interface (UI)"]) assert.equal(fam("Jenkins", p), "jenkins:jenkins", p);
  assert.notEqual(fam("Jenkins", "Script Security Plugin"), "jenkins:jenkins", "a plugin is its own product");
  for (const p of ["Exim Internet Mailer", "Mail Transfer Agent (MTA)"]) assert.equal(fam("Exim", p), "exim:exim", p);
  for (const p of ["GitLab CE/EE", "Community and Enterprise Editions"]) assert.equal(fam("GitLab", p), "gitlab:gitlab", p);
  assert.equal(fam("PHP Group", "PHP"), fam("PHP", "PHP"));
  assert.equal(fam("IBM", "Langflow"), fam("Langflow", "Langflow"));

  const vote = (software: string, asset_type = "server") => {
    const parsed = parseSoftware(software);
    return normaliserVote(row(software, asset_type), parsed, topCandidates(parsed, all));
  };
  for (const [software, family, asset] of [
    ["OpenSSL 1.0.1f", "openssl:openssl", "server"], ["Samba 4.5.9", "samba:samba", "server"], ["Notepad++ 8.6.2", "notepad++:notepad++", "laptop"],
    ["Jenkins 2.440", "jenkins:jenkins", "server"], ["Exim 4.92", "exim:exim", "server"], ["GitLab 16.0", "gitlab:gitlab", "server"], ["PHP 8.1.2", "php:php", "server"],
  ] as const) {
    const v = vote(software, asset);
    assert.equal(voteKind(v), "match", software);
    assert.equal(voteFamily(v), family, software);
  }
  assert.equal(pairsMentioning("jenkins:jenkins", all).length, 4, "Jenkins core: the product and its CLI, UI and web framework");
  assert.equal(pairsMentioning("php:php", all).length, 2, "both vendor spellings of PHP");
  // a row that resembles a vague entry is unsure, never a confident "no KEV product"
  assert.equal(voteKind(vote("Fortinet Multiple Products 7.0")), "abstain");
  assert.equal(voteKind(vote("Microsoft Teams", "laptop")), "no_match", "software KEV does not list stays a confident no-match");
});

test("vendor-named KEV entries: an exact brand name only; a neighbouring product or another vendor's is never matched (sample-mode review, round 2)", () => {
  // real KEV spellings (catalog 2026.10.23), added to the fixture inline; KEV lists none of the look-alike products below
  const extra: KevPair[] = [
    { vendor: "OpenSSL", product: "OpenSSL" }, { vendor: "OpenBSD", product: "OpenSMTPD" }, { vendor: "Samba", product: "Samba" },
    { vendor: "GitLab", product: "GitLab" }, { vendor: "GitLab", product: "GitLab CE/EE" }, { vendor: "GitLab", product: "Community and Enterprise Editions" },
    { vendor: "PHP", product: "PHP" }, { vendor: "PHP Group", product: "PHP" }, { vendor: "PHP", product: "PHPMailer" },
    { vendor: "JQuery", product: "JQuery" }, { vendor: "Git", product: "Git" }, { vendor: "Sudo", product: "Sudo" },
    { vendor: "Jenkins", product: "Jenkins" }, { vendor: "Jenkins", product: "Jenkins Command Line Interface (CLI)" },
    { vendor: "Jenkins", product: "Jenkins User Interface (UI)" }, { vendor: "ownCloud", product: "ownCloud" },
    { vendor: "Exim", product: "Exim" }, { vendor: "Exim", product: "Mail Transfer Agent (MTA)" },
    { vendor: "BeyondTrust", product: "Remote Support (RS) and Privileged Remote Access (PRA)" },
  ];
  const all = [...PAIRS, ...extra];
  const vote = (software: string, asset_type = "server") => {
    const parsed = parseSoftware(software);
    return normaliserVote(row(software, asset_type), parsed, topCandidates(parsed, all));
  };
  // a one-letter neighbour of a brand is another product, not a typo: a confident "no KEV product", as before the
  // vendor-named entries became specific
  for (const raw of ["OpenSSH 9.6p1", "OpenSSH for Windows 9.5"]) {
    const v = vote(raw);
    assert.equal(voteKind(v), "no_match", raw);
    const ssl = topCandidates(parseSoftware(raw), all).find((c) => c.product === "OpenSSL");
    assert.ok(!ssl || ssl.score < NORMALISER_THRESHOLDS.no_match_max, `${raw}: OpenSSL gets no typo credit (${ssl?.score})`);
  }
  // another product built on the brand's name, or another vendor's product of that name: unsure (ask the owner)
  for (const [raw, asset] of [
    ["GitLab Runner 16.0", "server"], ["PHP Composer 2.6", "server"], ["jQuery UI 1.12.1", "server"], ["jQuery Migrate 3.4", "server"],
    ["Git LFS 3.4", "laptop"], ["Sudo for Windows", "laptop"], ["sudo-rs 0.2", "server"], ["Jenkins X", "server"], ["Jenkins X 3.10", "server"],
    ["ownCloud desktop client 4.0", "laptop"],
  ] as const) {
    const v = vote(raw, asset);
    assert.equal(voteKind(v), "abstain", `${raw}: never a confident match (got ${v.vendor}/${v.product} ${v.confidence})`);
  }
  // the brand's own product still matches: bare, versioned, with an edition, release-track or packaging word, with a word
  // of another KEV spelling of the same family ("CE", "CLI", "MTA"), the vendor's other KEV name, or a vendor in a note
  for (const [raw, family] of [
    ["OpenSSL 1.0.1f", "openssl:openssl"], ["OpenSSL 1.1.x", "openssl:openssl"], ["openssl 3.0.2-0ubuntu1.10", "openssl:openssl"],
    ["OpenSSL 1.1.1k (bundled in Apache 2.4)", "openssl:openssl"], ["Samba 4.5.9", "samba:samba"], ["Samba server 4.5.9", "samba:samba"],
    ["Jenkins 2.440", "jenkins:jenkins"], ["Jenkins LTS 2.440", "jenkins:jenkins"], ["Jenkins CLI 2.440", "jenkins:jenkins"],
    ["GitLab 16.0", "gitlab:gitlab"], ["GitLab CE 16.0", "gitlab:gitlab"], ["Exim MTA 4.92", "exim:exim"], ["PHP 8.1.2", "php:php"],
    ["PHP Group PHP 8.1", "php:php"], ["jQuery 3.4.1", "jquery:jquery"], ["Git 2.39.1", "git:git"], ["Sudo 1.9.5p2", "sudo:sudo"],
  ] as const) {
    const v = vote(raw);
    assert.equal(voteKind(v), "match", raw);
    assert.equal(voteFamily(v), family, raw);
  }
  // typo credit stays for every other KEV name
  assert.equal(voteFamily(vote("Exchnage Server 2016")), "microsoft:exchange-server");
});
