// Windows OS rows: edition parsing, the first fixed build per edition, and one owner question per edition.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { InventoryRow, KevEntry, NvdRange } from "../src/contracts.ts";
import { fixedBuildFor, groupWindowsQuestions, rangesForEdition, windowsEdition } from "../src/policy/windows.ts";

const row = (row_id: string, asset_name: string, software: string): InventoryRow =>
  ({ row_id, asset_id: `A-${row_id}`, asset_name, asset_type: "laptop", internet_facing: false, owner_team: "IT", software });

test("windowsEdition reads client editions, server years and builds from messy text", () => {
  assert.deepEqual(windowsEdition("Microsoft Windows 11 Enterprise 24H2"), { key: "windows_11_24h2", label: "Windows 11 24H2", cpe_product: "windows_11_24h2", build: null });
  assert.equal(windowsEdition("Win10 Education 21H2")?.key, "windows_10_21h2");
  assert.equal(windowsEdition("win 11 home, 22h2")?.label, "Windows 11 22H2");
  assert.equal(windowsEdition("Windows Svr 2022 Datacenter")?.key, "windows_server_2022");
  assert.equal(windowsEdition("MS Windows Server 2016 (file share)")?.label, "Windows Server 2016");
  assert.equal(windowsEdition("Windows 11 Pro 23H2 build 22631.4317")?.build, "10.0.22631.4317");
  assert.equal(windowsEdition("Windows 10 Pro")?.cpe_product, null); // no feature version: the edition is incomplete
  assert.equal(windowsEdition("Veeam Agent for Microsoft Windows 6.1"), null);
  assert.equal(windowsEdition("Adobe Reader for Windows 2024"), null);
  assert.equal(windowsEdition("Ubuntu 22.04 LTS"), null);
});

const RANGES: NvdRange[] = [
  { cve_id: "CVE-2099-1000", criteria: "cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*", vulnerable: true, version_end_excluding: "10.0.26100.2033" },
  { cve_id: "CVE-2099-1000", criteria: "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", vulnerable: true, version_end_excluding: "10.0.20348.2762" },
];
const NEWEST: KevEntry = {
  cve_id: "CVE-2099-1000", vendor: "Microsoft", product: "Windows", vulnerability_name: "Microsoft Windows test flaw", date_added: "2099-01-02",
  due_date: "2099-01-23", ransomware_use: "Unknown", required_action: "Apply updates.", short_description: "", notes: "", catalog_version: "2099.01.02",
};

test("fixedBuildFor and rangesForEdition keep to the edition's own CPE", () => {
  const ed = windowsEdition("Windows 11 Pro 24H2");
  assert.ok(ed);
  assert.equal(fixedBuildFor(ed, RANGES), "10.0.26100.2033");
  assert.equal(rangesForEdition(ed, RANGES).length, 1);
  assert.equal(fixedBuildFor(windowsEdition("Windows 10 Pro 22H2")!, RANGES), null);
  assert.deepEqual(rangesForEdition(windowsEdition("Windows 10 Pro")!, RANGES), []);
});

test("groupWindowsQuestions: one question per edition, naming the machines and the first fixed build", () => {
  const members = [
    row("X3", "pc-03", "Windows 11 Pro 24H2"), row("X1", "pc-01", "Win 11 Enterprise 24H2"), row("X2", "srv-02", "Windows Server 2022 Std"),
    row("X4", "pc-04", "Windows 10 Pro 22H2"),
  ].map((r) => ({ row: r, edition: windowsEdition(r.software) }));
  const groups = groupWindowsQuestions(members, NEWEST, RANGES, 240);
  assert.deepEqual(groups.map((g) => g.label), ["Windows 10 22H2", "Windows 11 24H2", "Windows Server 2022"]);
  const w11 = groups.find((g) => g.label === "Windows 11 24H2")!;
  assert.deepEqual(w11.row_ids, ["X1", "X3"]);
  assert.equal(w11.fixed_build, "10.0.26100.2033");
  assert.equal(w11.question.row_id, "X1");
  assert.deepEqual(w11.question.row_ids, ["X1", "X3"]);
  assert.match(w11.question.question, /^Which Windows 11 24H2 build runs on these 2 machines \(pc-01, pc-03\)\? KEV lists 240 Windows CVEs; the newest, CVE-2099-1000, was added 2099-01-02 with a US federal due date of 2099-01-23, and NVD lists Windows 11 24H2 builds below 10\.0\.26100\.2033 as affected by it\./);
  assert.match(w11.question.reason, /name the edition but no build number/);
  const w10 = groups.find((g) => g.label === "Windows 10 22H2")!;
  assert.match(w10.question.question, /NVD gives no Windows 10 22H2 build range for it yet/);
  assert.equal(w10.question.asset_name, "pc-04");
});
