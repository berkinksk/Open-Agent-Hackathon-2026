// Candidate filter v0 tests. The KEV pairs are real spellings from the catalogue (including its
// trailing-space and narrow-no-break-space variants); the inventory strings are dev examples.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { InventoryRow, KevPair } from "../src/contracts.ts";
import {
  candidatesV0, cleanName, deterministicVoteV0, familyKey, familyV0, parseVersionV0, tokenize,
} from "../src/resolve/candidates.ts";

const PAIRS: KevPair[] = [
  { vendor: "Apache", product: "Log4j2" }, { vendor: "Apache", product: "HTTP Server" },
  { vendor: "Apache", product: "Apache" }, { vendor: "Apache", product: "Tomcat" }, { vendor: "Apache", product: "Struts 2" },
  { vendor: "Microsoft", product: "Exchange Server" }, { vendor: "Microsoft", product: "Exchange" },
  { vendor: "Microsoft", product: "Windows" }, { vendor: "Microsoft", product: "Windows " },
  { vendor: "Microsoft", product: "SharePoint Server" }, { vendor: "Microsoft", product: "Internet Key Exchange (IKE) Service Extensions" },
  { vendor: "Fortinet", product: "FortiOS" }, { vendor: "Fortinet", product: "FortiClient EMS" },
  { vendor: "Fortinet", product: "FortiOS and FortiProxy SSL-VPN" }, { vendor: "Fortinet", product: "Multiple Products" },
  { vendor: "Citrix", product: "NetScaler ADC and Gateway" }, { vendor: "Citrix", product: "NetScaler" },
  { vendor: "Citrix", product: "Workspace Application and Receiver for Windows" },
  { vendor: "Adobe", product: "Commerce and Magento" }, { vendor: "Adobe", product: "Commerce and Magento" },
  { vendor: "Ivanti", product: " Endpoint Manager (EPM)" }, { vendor: "Ivanti", product: "Endpoint Manager (EPM)" },
  { vendor: "Ivanti", product: "Connect Secure" }, { vendor: "Palo Alto Networks", product: "PAN-OS" },
  { vendor: "VMware", product: "vCenter Server" },
];

const row = (software: string): InventoryRow => ({
  row_id: "R1", asset_id: "A1", asset_name: "host-1", asset_type: "server", internet_facing: false, owner_team: "IT", software,
});

const fams = (raw: string, k?: number) => candidatesV0(raw, PAIRS, k).map((c) => c.family);

test("cleanName and families: KEV spacing variants collapse; keys ignore case", () => {
  assert.equal(cleanName("  Windows  "), "Windows");
  assert.equal(cleanName("Commerce and Magento"), "Commerce and Magento");
  assert.equal(familyV0({ vendor: "Microsoft", product: "Windows " }), "Microsoft Windows");
  assert.equal(familyKey(familyV0({ vendor: "Adobe", product: "Commerce and Magento" })),
    familyKey(familyV0({ vendor: "Adobe", product: "Commerce and Magento" })));
  assert.equal(familyKey("Cisco IOS Software"), familyKey("cisco ios  software"));
});

test("tokenize drops versions, build tags and filler words", () => {
  assert.deepEqual(tokenize("MS Exchange Svr 2019 CU12"), ["ms", "exchange", "svr"]);
  assert.deepEqual(tokenize("log4j-core 2.14.1 (bundled in ERP-Portal WAR)"), ["log4j", "core", "erp", "portal", "war"]);
  assert.deepEqual(tokenize("FortiGate 60F, FortiOS 7.2.4"), ["fortigate", "fortios"]);
});

test("parseVersionV0 reads the common version shapes", () => {
  assert.equal(parseVersionV0("log4j-core 2.14.1 (bundled in ERP-Portal WAR)"), "2.14.1");
  assert.equal(parseVersionV0("MS Exchange Svr 2019 CU12"), "2019 CU12");
  assert.equal(parseVersionV0("Citrix NetScaler ADC 13.1-48.47"), "13.1-48.47");
  assert.equal(parseVersionV0("Notepad++ v8.6"), "8.6");
  assert.equal(parseVersionV0("Ivanti ICS 22.4R2 (VPN)"), "22.4R2");
  assert.equal(parseVersionV0("Exchange Online (M365 tenant)"), null);
});

test("the right KEV family ranks first for clear rows", () => {
  assert.equal(fams("log4j-core 2.14.1 (bundled in ERP-Portal WAR)")[0], "Apache Log4j2");
  assert.equal(fams("MS Exchange Svr 2019 CU12")[0], "Microsoft Exchange Server");
  assert.equal(fams("Apache httpd 2.4.49")[0], "Apache HTTP Server"); // the vague "Apache / Apache" entry ranks lower
  assert.equal(fams("FortiGate 60F, FortiOS 7.2.4")[0], "Fortinet FortiOS");
  assert.equal(fams("PAN-OS 10.2.7 (GlobalProtect gw)")[0], "Palo Alto Networks PAN-OS");
  assert.equal(fams("vCenter 7.0 U3")[0], "VMware vCenter Server");
  assert.equal(fams("Ivanti ICS 22.4R2 (VPN)")[0], "Ivanti Connect Secure");
});

test("look-alikes stay in the candidate list on purpose (the critic needs to see them)", () => {
  const forti = fams("FortiClient VPN 7.0.9");
  assert.ok(forti.includes("Fortinet FortiClient EMS"));
  assert.ok(forti.every((f) => f.startsWith("Fortinet")), "only Fortinet families for a Fortinet client");
  const exo = fams("Exchange Online (M365 tenant)");
  assert.ok(exo.includes("Microsoft Exchange") && exo.includes("Microsoft Exchange Server"));
});

test("one candidate per family, with the clean KEV spelling as its representative", () => {
  const c = candidatesV0("Windows 10 22H2 workstation", PAIRS);
  const win = c.filter((x) => familyKey(x.family) === "microsoft windows");
  assert.equal(win.length, 1);
  assert.equal(win[0].product, "Windows");
  const epm = candidatesV0("Ivanti Endpoint Manager 2022", PAIRS).filter((x) => familyKey(x.family) === "ivanti endpoint manager (epm)");
  assert.equal(epm.length, 1);
  assert.equal(epm[0].product, "Endpoint Manager (EPM)");
});

test("k caps the list; scores are positive, sorted, and the output is deterministic", () => {
  const a = candidatesV0("Microsoft Exchange Server 2016", PAIRS, 3);
  assert.equal(a.length, 3);
  for (let i = 1; i < a.length; i++) assert.ok(a[i - 1].score >= a[i].score);
  assert.ok(a.every((c) => c.score > 0 && c.reason.length > 0));
  assert.deepEqual(candidatesV0("Microsoft Exchange Server 2016", PAIRS, 3), a);
  assert.deepEqual(candidatesV0("Notepad++ v8.6", PAIRS), []);
  assert.deepEqual(candidatesV0("anything", PAIRS, 0), []);
});

test("deterministic vote: clear winner, ambiguous (unsure null), nothing plausible (confident null)", () => {
  const clear = deterministicVoteV0(row("PAN-OS 10.2.7"), candidatesV0("PAN-OS 10.2.7", PAIRS));
  assert.equal(clear.juror, "normaliser");
  assert.equal(clear.vendor, "Palo Alto Networks");
  assert.equal(clear.product, "PAN-OS");
  const ambiguous = deterministicVoteV0(row("MS Exchange Svr 2019 CU12"), candidatesV0("MS Exchange Svr 2019 CU12", PAIRS));
  assert.equal(ambiguous.vendor, null);
  assert.ok(ambiguous.confidence < 0.6);
  const none = deterministicVoteV0(row("Notepad++ v8.6"), []);
  assert.equal(none.vendor, null);
  assert.ok(none.confidence >= 0.6);
});
