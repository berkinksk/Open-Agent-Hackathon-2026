// Converts the team's software list (CSV) into the inventory JSON that Zetaris reads from the public data repo
// (EL_INVENTORY.el_inventory_raw -> view el.inventory; see scripts/setup.ts).
//   npm run convert-inventory -- --in <software_list.csv> --out <inventory.json> [--created YYYY-MM-DD]
// The CSV must have exactly the seven inventory columns. Any other column (answers, notes) is refused, so labels
// can never reach the public file. Emails, IP addresses and links are refused too: the list is synthetic.
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { INVENTORY_COLUMNS } from "../src/adapters/queries.ts";
import { canonRowId } from "../src/eval/answers.ts";
import { normaliseHeader, parseCsv } from "../src/eval/csv.ts";

export type InventoryCsvRow = Record<(typeof INVENTORY_COLUMNS)[number], string>;

export const INVENTORY_DESCRIPTION = "Synthetic software inventory of a fictional 200-person charity (made-up data)";

const FORBIDDEN: [string, RegExp][] = [
  ["an email address", /[\w.+-]+@[\w-]+\.[\w.]+/],
  ["an IP address", /\b\d{1,3}(?:\.\d{1,3}){3}\b/],
  ["a link", /https?:\/\//i],
];

/** Parses and checks the software list. Throws with every problem found, one per line. */
export function parseSoftwareList(text: string): InventoryCsvRow[] {
  const records = parseCsv(text).filter((r) => r.fields.some((f) => f.trim() !== ""));
  if (records.length < 2) throw new Error("software list: no data rows");
  const header = records[0].fields.map(normaliseHeader);
  const problems: string[] = [];
  const missing = INVENTORY_COLUMNS.filter((c) => !header.includes(c));
  const extra = header.filter((h) => !(INVENTORY_COLUMNS as readonly string[]).includes(h));
  if (missing.length) problems.push(`missing column(s): ${missing.join(", ")}`);
  if (extra.length) problems.push(`unexpected column(s): ${extra.join(", ")} (only the 7 inventory columns may be published)`);
  if (new Set(header).size !== header.length) problems.push("duplicate column names");
  if (problems.length) throw new Error(`software list: ${problems.join("; ")}`);

  const rows: InventoryCsvRow[] = [];
  const seen = new Set<string>();
  const assets = new Map<string, string>();
  for (const rec of records.slice(1)) {
    const at = `line ${rec.line}`;
    if (rec.fields.length !== header.length) {
      problems.push(`${at}: ${rec.fields.length} fields, expected ${header.length}`);
      continue;
    }
    const row = Object.fromEntries(header.map((h, i) => [h, rec.fields[i].trim()])) as InventoryCsvRow;
    row.row_id = canonRowId(row.row_id);
    row.internet_facing = row.internet_facing.toLowerCase();
    for (const c of INVENTORY_COLUMNS) if (row[c] === "") problems.push(`${at}: empty ${c}`);
    if (seen.has(row.row_id)) problems.push(`${at}: duplicate row_id ${row.row_id}`);
    seen.add(row.row_id);
    if (row.internet_facing !== "yes" && row.internet_facing !== "no") {
      problems.push(`${at}: internet_facing must be yes or no, got "${row.internet_facing}"`);
    }
    const asset = [row.asset_name, row.asset_type, row.internet_facing, row.owner_team].join("|");
    const before = assets.get(row.asset_id);
    if (before !== undefined && before !== asset) problems.push(`${at}: asset ${row.asset_id} has different details than on an earlier row`);
    assets.set(row.asset_id, asset);
    for (const c of INVENTORY_COLUMNS) {
      for (const [what, re] of FORBIDDEN) if (re.test(row[c])) problems.push(`${at}: ${c} contains ${what}`);
    }
    rows.push(row);
  }
  if (problems.length) throw new Error(`software list:\n- ${problems.join("\n- ")}`);
  return rows;
}

/** The public file, in the starter file's shape: one item per line, so diffs stay readable. */
export function renderInventoryJson(rows: InventoryCsvRow[], created: string): string {
  const items = rows.map((r) => "    {" + INVENTORY_COLUMNS.map((c) => `${JSON.stringify(c)}: ${JSON.stringify(r[c])}`).join(", ") + "}");
  return `{\n  "description": ${JSON.stringify(INVENTORY_DESCRIPTION)},\n  "created": ${JSON.stringify(created)},\n` +
    `  "items": [\n${items.join(",\n")}\n  ]\n}\n`;
}

/** Runs the CLI. Returns the exit code: 0 written, 1 the list failed its checks, 2 usage error. */
export function main(argv: string[], out = (s: string) => console.log(s), err = (s: string) => console.error(s)): number {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) args.set(argv[i], argv[i + 1] ?? "");
  const input = args.get("--in");
  const output = args.get("--out");
  const created = args.get("--created") ?? new Date().toISOString().slice(0, 10);
  if (!input || !output || !/^\d{4}-\d{2}-\d{2}$/.test(created)) {
    err("usage: convert-inventory --in <software_list.csv> --out <inventory.json> [--created YYYY-MM-DD]");
    return 2;
  }
  try {
    const rows = parseSoftwareList(readFileSync(input, "utf8"));
    const json = renderInventoryJson(rows, created);
    const parsed = JSON.parse(json) as { items: unknown[] };
    if (parsed.items.length !== rows.length) throw new Error("internal: the rendered JSON lost rows");
    writeFileSync(output, json);
    const assets = new Set(rows.map((r) => r.asset_id)).size;
    const facing = rows.filter((r) => r.internet_facing === "yes").length;
    out(`Wrote ${output}: ${rows.length} rows, ${assets} assets, ${facing} internet-facing rows`);
    return 0;
  } catch (e) {
    err(`convert-inventory: ${(e as Error).message}`);
    return 1;
  }
}

const invokedDirectly = process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) process.exitCode = main(process.argv.slice(2));
