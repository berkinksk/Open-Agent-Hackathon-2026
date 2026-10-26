// npm run setup [-- --prefix EL_T1_] [--dry-run] [--no-preflight]
// Registers every Zetaris object the app reads, idempotently, starting from an empty Zetaris:
//   EL_INVENTORY + el_inventory_raw (REST over INVENTORY_URL) + view el.inventory (explode items)
//   EL_KEV + el_kev_raw (REST over the CISA KEV JSON)           + view el.kev       (explode vulnerabilities)
//   EL_EPSS, EL_NVD (tables are created per CVE batch at run time)
// Existing objects are detected with SHOW LIGHTNING DATABASES / TABLES; a duplicate CREATE
// answering 400 "already exists" also counts as success. Nothing is ever dropped.
// Ends with one LIMIT 1 query per object and prints a table.
import type { SqlClient } from "../src/adapters/queries.ts";
import { EPSS_API, INVENTORY_COLUMNS, KEV_COLUMNS, KEV_URL, createZetarisQueries, elNames } from "../src/adapters/queries.ts";
import { ZetarisClient } from "../src/adapters/zetaris.ts";
import { describeConfig, isValidPrefix, loadConfig, requireConfig } from "../src/config.ts";
import { createTracer, nullTracer } from "../src/trace.ts";
import type { Tracer } from "../src/contracts.ts";

export type StepKind = "database" | "rest_table" | "container" | "view" | "check";
export type StepState = "planned" | "created" | "exists" | "ok" | "skipped" | "error";

export interface SetupStep {
  object: string;        // as people write it: EL_KEV, EL_KEV.el_kev_raw, el.kev
  kind: StepKind;
  db?: string;           // database the table lives in (for SHOW LIGHTNING TABLES)
  name: string;          // bare object name
  url?: string;          // REST endpoint (tables)
  sql: string;           // the CREATE statement
  needs?: string[];      // objects that must exist first
  check?: string;        // LIMIT 1 query proving the object works
}

export interface SetupRow { object: string; kind: StepKind; state: StepState; note: string; check: string; ms: number; }

export interface SetupOptions {
  prefix: string;
  inventoryUrl: string;
  preflight?: boolean;             // GET the inventory file and check its shape before registering it
  fetchImpl?: typeof fetch;        // for the preflight
  timeoutMs?: number;              // per statement (setup may wait longer than the hot path)
  log?: (line: string) => void;
}

/** The DESCRIBE BY text may contain only letters, digits, spaces and _ . - , */
const DESCRIPTIONS = {
  inventory: "Synthetic software inventory JSON read over GitHub raw",
  kev: "CISA KEV catalogue JSON read over GitHub raw",
  epss: "FIRST EPSS score batches, one REST table per CVE batch",
  nvd: "NIST NVD CVE records, one REST table per CVE",
};

export const EPSS_SMOKE_CVE = "CVE-2021-44228";

function restTableSql(name: string, db: string, url: string): string {
  if (url.includes('"')) throw new Error("endpoint URL must not contain a double quote");
  return `CREATE LIGHTNING REST TABLE ${name} FROM ${db} REQUEST(endpoint "${url}", method "get", response_type "json", http_encoding "URLENCODED") HEADER () BODY ()`;
}

export function planSetup(prefix: string, inventoryUrl: string): SetupStep[] {
  const n = elNames(prefix);
  const lc = (db: string) => db.toLowerCase();
  const invCols = INVENTORY_COLUMNS.map((c) => `i.${c} AS ${c}`).join(", ");
  const kevMap: Record<string, string> = {
    cve_id: "v.cveID", vendor: "v.vendorProject", product: "v.product", vulnerability_name: "v.vulnerabilityName",
    date_added: "v.dateAdded", due_date: "v.dueDate", ransomware_use: "v.knownRansomwareCampaignUse",
    required_action: "v.requiredAction", short_description: "v.shortDescription", notes: "v.notes",
    catalog_version: "catalogVersion",
  };
  const kevCols = KEV_COLUMNS.map((c) => `${kevMap[c]} AS ${c}`).join(", ");
  return [
    { object: n.invDb, kind: "database", name: n.invDb, sql: `CREATE LIGHTNING DATABASE ${n.invDb} DESCRIBE BY "${DESCRIPTIONS.inventory}"` },
    { object: `${n.invDb}.${n.invRaw}`, kind: "rest_table", db: n.invDb, name: n.invRaw, url: inventoryUrl, needs: [n.invDb],
      sql: restTableSql(n.invRaw, n.invDb, inventoryUrl) },
    { object: n.kevDb, kind: "database", name: n.kevDb, sql: `CREATE LIGHTNING DATABASE ${n.kevDb} DESCRIBE BY "${DESCRIPTIONS.kev}"` },
    { object: `${n.kevDb}.${n.kevRaw}`, kind: "rest_table", db: n.kevDb, name: n.kevRaw, url: KEV_URL, needs: [n.kevDb],
      sql: restTableSql(n.kevRaw, n.kevDb, KEV_URL) },
    { object: n.epssDb, kind: "database", name: n.epssDb, sql: `CREATE LIGHTNING DATABASE ${n.epssDb} DESCRIBE BY "${DESCRIPTIONS.epss}"` },
    { object: n.nvdDb, kind: "database", name: n.nvdDb, sql: `CREATE LIGHTNING DATABASE ${n.nvdDb} DESCRIBE BY "${DESCRIPTIONS.nvd}"`,
      check: `SHOW LIGHTNING TABLES ${n.nvdDb}` },
    { object: n.container, kind: "container", name: n.container, sql: `CREATE SCHEMASTORE CONTAINER ${n.container}` },
    { object: n.kevRef, kind: "view", name: n.kevView, needs: [`${n.kevDb}.${n.kevRaw}`, n.container],
      sql: `CREATE SCHEMASTORE VIEW ${n.kevView} WITH CONTAINER ${n.container} AS SELECT ${kevCols} FROM ${lc(n.kevDb)}.${n.kevRaw} LATERAL VIEW explode(vulnerabilities) AS v`,
      check: `SELECT cve_id, vendor, product, date_added, due_date, catalog_version FROM ${n.kevRef} LIMIT 1` },
    { object: n.inventoryRef, kind: "view", name: n.inventoryView, needs: [`${n.invDb}.${n.invRaw}`, n.container],
      sql: `CREATE SCHEMASTORE VIEW ${n.inventoryView} WITH CONTAINER ${n.container} AS SELECT ${invCols} FROM ${lc(n.invDb)}.${n.invRaw} LATERAL VIEW explode(items) AS i`,
      check: `SELECT ${INVENTORY_COLUMNS.join(", ")} FROM ${n.inventoryRef} LIMIT 1` },
  ];
}

/** Check the inventory file before registering it: a REST table over a missing or half-built file
 *  would fix a wrong schema in Zetaris, and setup never drops objects. */
export async function preflightInventory(url: string, fetchImpl: typeof fetch = fetch): Promise<{ ok: boolean; reason: string; items?: number }> {
  try {
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(15_000) });
    if (res.status !== 200) return { ok: false, reason: `inventory file not published (HTTP ${res.status})` };
    const body = (await res.json()) as { items?: unknown };
    if (!body || !Array.isArray(body.items) || body.items.length === 0) return { ok: false, reason: "inventory JSON has no non-empty items[] array" };
    const first = body.items[0] as Record<string, unknown>;
    const missing = INVENTORY_COLUMNS.filter((c) => !(c in first));
    if (missing.length) return { ok: false, reason: `items[0] lacks field(s): ${missing.join(", ")}` };
    return { ok: true, reason: "ok", items: body.items.length };
  } catch (err) {
    return { ok: false, reason: `inventory file unreachable: ${(err as Error).message}` };
  }
}

function firstRowSummary(row: Record<string, string> | undefined, max = 90): string {
  if (!row) return "0 rows";
  const s = Object.values(row).join(" | ");
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

export async function runSetup(client: SqlClient, opts: SetupOptions): Promise<{ rows: SetupRow[]; ok: boolean }> {
  const log = opts.log ?? (() => {});
  const timeoutMs = opts.timeoutMs ?? 110_000;
  const steps = planSetup(opts.prefix, opts.inventoryUrl);
  const n = elNames(opts.prefix);
  const rows: SetupRow[] = [];
  const ready = new Set<string>();
  const row = (s: SetupStep, state: StepState, note = "", ms = 0): SetupRow => {
    const r = { object: s.object, kind: s.kind, state, note, check: "", ms };
    rows.push(r);
    log(`  ${state.padEnd(8)} ${s.kind.padEnd(10)} ${s.object}${note ? `  (${note})` : ""}`);
    if (state === "created" || state === "exists") ready.add(s.object);
    return r;
  };

  // 1. What exists already?
  const dbs = new Set((await client.query("SHOW LIGHTNING DATABASES", { label: "setup_show_databases", timeoutMs, limit: 10000 })).rows.map((r) => r.name));
  const tablesOf = new Map<string, Map<string, string>>(); // db -> table name -> source_table (endpoint URL)
  const showTables = async (db: string) => {
    if (!tablesOf.has(db)) {
      const r = await client.query(`SHOW LIGHTNING TABLES ${db}`, { label: "setup_show_tables", timeoutMs, limit: 10000 });
      tablesOf.set(db, new Map(r.rows.map((x) => [x.name, x.source_table ?? ""])));
    }
    return tablesOf.get(db)!;
  };

  // 2. Create what is missing, in dependency order.
  for (const s of steps) {
    const blocked = (s.needs ?? []).filter((d) => !ready.has(d));
    if (blocked.length) { row(s, "skipped", `needs ${blocked.join(", ")}`); continue; }
    try {
      if (s.kind === "database" && dbs.has(s.name)) { row(s, "exists", "found by SHOW LIGHTNING DATABASES"); continue; }
      if (s.kind === "rest_table" && s.db) {
        const existing = dbs.has(s.db) ? await showTables(s.db) : new Map<string, string>();
        if (existing.has(s.name)) {
          const src = existing.get(s.name) ?? "";
          if (s.url && src && src !== s.url) {
            row(s, "exists", `WARNING endpoint differs from the configured URL (registered: ${src}); setup never drops, use a new --prefix`);
          } else {
            row(s, "exists", "found by SHOW LIGHTNING TABLES");
          }
          continue;
        }
        if (s.name === n.invRaw && opts.preflight !== false) {
          const pf = await preflightInventory(s.url ?? "", opts.fetchImpl);
          if (!pf.ok) { row(s, "skipped", `${pf.reason}; re-run setup once data/inventory.json is published`); continue; }
          log(`  preflight ok: ${pf.items} inventory item(s) with all fields`);
        }
      }
      const r = await client.ddl(s.sql, { label: `setup_${s.kind}`, timeoutMs });
      row(s, r.outcome, r.outcome === "exists" ? "CREATE answered already exists" : "", r.ms);
    } catch (err) {
      row(s, "error", (err as Error).message.slice(0, 300));
    }
  }

  // 3. One LIMIT 1 query per object that can be queried.
  for (const s of steps) {
    const r = rows.find((x) => x.object === s.object)!;
    if (!s.check || !(r.state === "created" || r.state === "exists")) continue;
    try {
      const q = await client.query(s.check, { cache: "bypass", label: `setup_check ${s.object}`, timeoutMs, limit: 1 });
      r.check = s.check.startsWith("SHOW")
        ? `${q.rows.length} table(s) (${(q.ms / 1000).toFixed(1)} s)`
        : `LIMIT 1 -> ${firstRowSummary(q.rows[0])} (${(q.ms / 1000).toFixed(1)} s)`;
      if (!s.check.startsWith("SHOW") && q.rows.length === 0) r.state = "error";
    } catch (err) {
      r.state = "error";
      r.check = `check failed: ${(err as Error).message.slice(0, 200)}`;
    }
  }
  for (const r of rows) {
    if (r.kind === "rest_table" && (r.state === "created" || r.state === "exists") && !r.check) r.check = "checked through its view";
  }

  // 4. EPSS end-to-end: register a one-CVE batch table and read it.
  const epssRow: SetupRow = { object: `${n.epssDb} (smoke batch ${EPSS_SMOKE_CVE})`, kind: "check", state: "skipped", note: "", check: "", ms: 0 };
  if (ready.has(n.epssDb)) {
    try {
      const t0 = performance.now();
      const q = createZetarisQueries({ client, tracer: nullTracer(), prefix: opts.prefix });
      const scores = await q.epss([EPSS_SMOKE_CVE]);
      epssRow.ms = Math.round(performance.now() - t0);
      epssRow.state = scores.length ? "ok" : "error";
      epssRow.check = scores.length
        ? `LIMIT 1 -> ${scores[0].cve_id} epss=${scores[0].epss} pct=${scores[0].percentile} date=${scores[0].score_date} (${(epssRow.ms / 1000).toFixed(1)} s)`
        : "no EPSS row returned";
    } catch (err) {
      epssRow.state = "error";
      epssRow.check = `check failed: ${(err as Error).message.slice(0, 200)}`;
    }
  } else {
    epssRow.note = `needs ${n.epssDb}`;
  }
  rows.push(epssRow);

  const ok = rows.every((r) => r.state === "created" || r.state === "exists" || r.state === "ok");
  return { rows, ok };
}

export function formatTable(rows: SetupRow[]): string {
  const head = ["object", "kind", "state", "check / note"];
  const body = rows.map((r) => [r.object, r.kind, r.state, r.check || r.note || "-"]);
  const w = head.map((h, i) => Math.max(h.length, ...body.map((b) => Math.min(b[i].length, i === 3 ? 200 : 60))));
  const fmt = (cols: string[]) => cols.map((c, i) => (i === 3 ? c : c.padEnd(w[i]))).join("  ");
  return [fmt(head), w.map((x) => "-".repeat(x)).join("  "), ...body.map(fmt)].join("\n");
}

export function parseSetupArgs(argv: string[]): { prefix?: string; dryRun: boolean; preflight: boolean; help: boolean } {
  const out = { prefix: undefined as string | undefined, dryRun: false, preflight: true, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--prefix") out.prefix = argv[++i];
    else if (a.startsWith("--prefix=")) out.prefix = a.slice("--prefix=".length);
    else if (a === "--dry-run") out.dryRun = true;
    else if (a === "--no-preflight") out.preflight = false;
    else if (a === "--help" || a === "-h") out.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

async function main(): Promise<number> {
  let args;
  try { args = parseSetupArgs(process.argv.slice(2)); } catch (err) { console.error((err as Error).message); return 2; }
  if (args.help) {
    console.log("usage: npm run setup [-- --prefix EL_T1_] [--dry-run] [--no-preflight]");
    return 0;
  }
  const cfg = loadConfig();
  const prefix = args.prefix ?? cfg.prefix;
  if (!isValidPrefix(prefix)) { console.error(`invalid prefix ${JSON.stringify(prefix)}: must look like EL_ or EL_T1_`); return 2; }

  if (args.dryRun) {
    console.log(`# setup plan for prefix ${prefix} (dry run, nothing sent)`);
    for (const s of planSetup(prefix, cfg.inventoryUrl)) {
      console.log(`${s.sql};`);
      if (s.check) console.log(`-- check: ${s.check};`);
    }
    console.log(`-- EPSS smoke batch: ${EPSS_API}?cve=${EPSS_SMOKE_CVE}`);
    return 0;
  }

  try { requireConfig(cfg, "zetaris"); } catch (err) { console.error(`[ERROR] ${(err as Error).message}`); return 2; }
  const d = describeConfig(cfg);
  console.log(`[INFO] setup prefix=${prefix} zetaris=${d.ZETARIS_REST_URL} inventory=${d.INVENTORY_URL}`);
  const runId = `setup-${new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")}`;
  let tracer: Tracer;
  try { tracer = createTracer(runId, { stdout: false }); } catch { tracer = nullTracer(runId); }
  const client = new ZetarisClient({ restUrl: cfg.zetaris.restUrl, orgId: cfg.zetaris.orgId, apiKey: cfg.zetaris.apiKey, tracer });
  const t0 = performance.now();
  let result;
  try {
    result = await runSetup(client, { prefix, inventoryUrl: cfg.inventoryUrl, preflight: args.preflight, log: (l) => console.log(l) });
  } catch (err) {
    console.error(`[ERROR] setup aborted: ${(err as Error).message}`);
    return 1;
  }
  console.log("");
  console.log(formatTable(result.rows));
  console.log("");
  console.log(`[${result.ok ? "INFO" : "WARN"}] setup ${result.ok ? "complete" : "incomplete"} in ${((performance.now() - t0) / 1000).toFixed(1)} s; trace ${tracer.file || "(none)"}`);
  return result.ok ? 0 : 1;
}

if (import.meta.main) {
  process.exitCode = await main();
}
