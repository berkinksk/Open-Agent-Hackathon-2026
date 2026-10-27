import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { parseSoftwareList, renderInventoryJson } from "../scripts/convert-inventory.ts";
import { buildTestRows, csvCell } from "../scripts/pick-test-rows.ts";

const HEADER = "row_id,asset_id,asset_name,asset_type,internet_facing,owner_team,software";
const GOOD = [
  HEADER,
  "R01,A01,erp-portal-01,server,yes,Finance,log4j-core 2.14.1 (bundled in ERP portal WAR)",
  'r02,A02,mail-01,server,YES,IT,"MS Win 10 Pro, 22H2"',
  "R03,A01,erp-portal-01,server,yes,Finance,Apache Tomcat v9.0.54",
  ",,,,,,",
].join("\n");

function list(n: number): string {
  const rows = Array.from({ length: n }, (_, i) => {
    const id = `R${String(i + 1).padStart(2, "0")}`;
    return `${id},A${i % 7},host-${i % 7},laptop,no,IT,"App ${i}, v1.${i}"`;
  });
  return [HEADER, ...rows].join("\n") + "\n";
}

test("parseSoftwareList reads the 7 columns, quoted commas, and skips blank export rows", () => {
  const rows = parseSoftwareList(GOOD);
  assert.equal(rows.length, 3);
  assert.equal(rows[1].row_id, "R02");
  assert.equal(rows[1].internet_facing, "yes");
  assert.equal(rows[1].software, "MS Win 10 Pro, 22H2");
});

test("parseSoftwareList refuses an extra column, so answers never reach the public file", () => {
  const csv = `${HEADER},kev_product\nR01,A01,a,server,yes,IT,log4j-core 2.14.1,Log4j2\n`;
  assert.throws(() => parseSoftwareList(csv), /unexpected column\(s\): kev_product/);
});

test("parseSoftwareList refuses a missing column", () => {
  const csv = "row_id,asset_id,asset_name,asset_type,internet_facing,software\nR01,A01,a,server,yes,x\n";
  assert.throws(() => parseSoftwareList(csv), /missing column\(s\): owner_team/);
});

test("parseSoftwareList refuses duplicate row ids, bad yes/no values and inconsistent assets", () => {
  assert.throws(() => parseSoftwareList(`${HEADER}\nR01,A01,a,server,yes,IT,x\nr01,A02,b,server,yes,IT,y\n`), /duplicate row_id R01/);
  assert.throws(() => parseSoftwareList(`${HEADER}\nR01,A01,a,server,maybe,IT,x\n`), /internet_facing must be yes or no/);
  assert.throws(() => parseSoftwareList(`${HEADER}\nR01,A01,a,server,yes,IT,x\nR02,A01,a,laptop,yes,IT,y\n`), /asset A01 has different details/);
  assert.throws(() => parseSoftwareList(`${HEADER}\nR01,A01,a,server,yes,IT,\n`), /empty software/);
});

test("parseSoftwareList refuses emails, IP addresses and links", () => {
  assert.throws(() => parseSoftwareList(`${HEADER}\nR01,A01,a,server,yes,IT,owner jo@example.org\n`), /email address/);
  assert.throws(() => parseSoftwareList(`${HEADER}\nR01,A01,a,server,yes,IT,host 10.0.0.12\n`), /IP address/);
  assert.throws(() => parseSoftwareList(`${HEADER}\nR01,A01,a,server,yes,IT,see https://x.test\n`), /a link/);
});

test("renderInventoryJson keeps the starter file's shape: description, created, items with the 7 columns", () => {
  const doc = JSON.parse(renderInventoryJson(parseSoftwareList(GOOD), "2026-10-26"));
  assert.deepEqual(Object.keys(doc), ["description", "created", "items"]);
  assert.match(doc.description, /^Synthetic/);
  assert.equal(doc.items.length, 3);
  assert.deepEqual(Object.keys(doc.items[0]), ["row_id", "asset_id", "asset_name", "asset_type", "internet_facing", "owner_team", "software"]);
  assert.equal(doc.items[1].internet_facing, "yes");
});

test("buildTestRows is reproducible, seeded by the file's sha256 by default, and sorted", () => {
  const bytes = Buffer.from(list(80));
  const a = buildTestRows(bytes, 30);
  const b = buildTestRows(Buffer.from(list(80)), 30);
  assert.deepEqual(a.file.row_ids, b.file.row_ids);
  assert.equal(a.file.seed, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(a.file.row_ids.length, 30);
  assert.equal(new Set(a.file.row_ids).size, 30);
  assert.deepEqual(a.file.row_ids, [...a.file.row_ids].sort((x, y) => x.localeCompare(y, "en", { numeric: true })));
  assert.equal(a.file.source_rows, 80);
  assert.notDeepEqual(buildTestRows(bytes, 30, "another seed").file.row_ids, a.file.row_ids);
  assert.throws(() => buildTestRows(Buffer.from(list(10)), 30), /cannot pick 30 rows from 10/);
});

test("the answer template has the answer-sheet columns, the picked rows and empty answers", () => {
  const pick = buildTestRows(Buffer.from(list(40)), 5);
  const lines = pick.template.trimEnd().split("\n");
  assert.equal(lines[0], "row_id,software,kev_vendor,kev_products,notes");
  assert.equal(lines.length, 6);
  assert.deepEqual(lines.slice(1).map((l) => l.split(",")[0]), pick.file.row_ids);
  assert.match(lines[1], /^R\d+,"App \d+, v1\.\d+",,,$/);
  assert.equal(csvCell('say "hi", ok'), '"say ""hi"", ok"');
});
