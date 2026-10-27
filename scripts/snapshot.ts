// npm run snapshot [-- --out <file>] [--kev-scope all|vendors] [--nvd-budget-s 1200] [--nvd-max 120] [--products 3]
//                   [--plan]
// Captures the sample-mode snapshot (design §10) through live Zetaris, one query at a time:
//   1. the inventory (el.inventory), 2. the KEV names (distinct vendor, product) and the KEV entries (el.kev; the
//   whole catalogue by default, or only the vendors the inventory's KEV candidates name), 3. FIRST EPSS for every
//   captured KEV CVE (batches of <= 100, one EL_EPSS REST table each), 4. NVD ranges for the KEV CVEs the pipeline's
//   version check would look up for the families the normaliser matches in the inventory (one EL_NVD table per CVE,
//   >= 6 s apart), 5. a few NVD product lookups (recent CVEs per CPE product) for the internet-facing rows' families.
// Every value is stored as read, with its capture date; nothing is computed into it. Data reads bypass the app's query
// cache, so the snapshot is never filled from a stale copy. --plan reads steps 1-2 and prints the NVD plan only.
// The output is checked for the configured secret values before it is written; nothing secret is ever printed.
import { renameSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import type { EpssScore, InventoryRow, KevEntry, KevPair, NvdProductHit, NvdRange, Tracer } from "../src/contracts.ts";
import { REPO_ROOT, describeConfig, isValidPrefix, loadConfig, requireConfig, secretValues } from "../src/config.ts";
import { createTracer, nullTracer } from "../src/trace.ts";
import { ZetarisClient, sqlHash, sqlString } from "../src/adapters/zetaris.ts";
import type { DdlResult, QueryOptions, QueryResult } from "../src/adapters/zetaris.ts";
import {
  EPSS_BATCH_MAX, INVENTORY_COLUMNS, KEV_COLUMNS, chunk, cleanCveIds, elNames, epssCreateSql, epssSelectSql, epssTableName,
  toEpssScore, toInventoryRow, toKevEntry,
} from "../src/adapters/queries.ts";
import { createNvdQueries } from "../src/adapters/nvd.ts";
import type { NvdLookupStatus } from "../src/adapters/nvd.ts";
import { familiesOf, matchedKevPart, normaliserVote, parseSoftware, topCandidates } from "../src/resolve/normalise.ts";
import { familyKey } from "../src/resolve/candidates.ts";
import { parseCpe } from "../src/resolve/versions.ts";
import { WINDOWS_FAMILY } from "../src/policy/windows.ts";
import { CANDIDATES_K, NVD_SMALL_FAMILY } from "../src/run.ts";
import { DEFAULT_SNAPSHOT_FILE, SNAPSHOT_SCHEMA, formatSnapshot, parseSnapshot } from "../src/sample/snapshot.ts";
import type { CaptureQuery, NvdProductSnapshot, NvdSnapshotRecord, SampleSnapshot } from "../src/sample/snapshot.ts";

export const NVD_PRODUCT_PAGE = 20;
export const NVD_PRODUCT_WINDOW_DAYS = 120;

/** What the capture needs from Zetaris (ZetarisClient satisfies it; tests pass a fake). */
export interface CaptureClient {
  query(sql: string, opts?: QueryOptions): Promise<QueryResult>;
  ddl(sql: string, opts?: { label?: string; timeoutMs?: number }): Promise<DdlResult>;
}
/** What the capture needs from the NVD adapter (src/adapters/nvd.ts createNvdQueries). */
export interface CaptureNvd {
  nvdCves(ids: string[]): Promise<NvdRange[]>;
  nvdProduct(vendor: string, product: string): Promise<NvdProductHit[]>;
  status(): NvdLookupStatus[];
}

export interface CaptureOptions {
  client: CaptureClient;
  nvd: CaptureNvd;
  prefix?: string;
  kevScope?: "all" | "vendors";
  nvdBudgetMs?: number;
  nvdMax?: number;
  products?: number;
  /** Stop after the KEV entries and return the NVD plan only. */
  planOnly?: boolean;
  now?: () => Date;
  log?: (line: string) => void;
}

export interface NvdPlanFamily { family: string; rows: number; internet_facing: number; cves: string[]; }
export interface CaptureResult { snapshot: SampleSnapshot | null; plan: NvdPlanFamily[]; inventoryVendors: string[]; }

const byDateDesc = (a: KevEntry, b: KevEntry): number =>
  (b.date_added ?? "").localeCompare(a.date_added ?? "") || b.cve_id.localeCompare(a.cve_id);
const kevSort = (a: KevEntry, b: KevEntry): number =>
  a.vendor.localeCompare(b.vendor) || a.product.localeCompare(b.product) || a.cve_id.localeCompare(b.cve_id);
const rowSort = (a: InventoryRow, b: InventoryRow): number => a.row_id.localeCompare(b.row_id, "en", { numeric: true });
const cveKey = (s: string): string => String(s ?? "").trim().toUpperCase();
const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** The vendors named by the inventory's top-K KEV candidates (and the normaliser's votes): the minimum KEV slice. */
export function inventoryVendors(rows: InventoryRow[], pairs: KevPair[], k = CANDIDATES_K): string[] {
  const out = new Set<string>();
  for (const row of rows) {
    const parsed = parseSoftware(row.software);
    const cands = topCandidates(parsed, pairs, k);
    for (const c of cands) out.add(c.vendor.trim());
    const v = normaliserVote(row, parsed, cands);
    if (v.vendor) out.add(v.vendor.trim());
  }
  return [...out].filter(Boolean).sort((a, b) => a.localeCompare(b));
}

/**
 * The NVD CVEs to capture: for every family the normaliser matches in the inventory, the CVEs the pipeline's version
 * check looks up (src/run.ts nvdPlanFor): Windows the newest KEV CVE (it names the first fixed build per edition),
 * a family with at most NVD_SMALL_FAMILY KEV CVEs all of them, a larger family its 2 newest. Taken for every matched
 * family whether or not the row records a version, so a judge's row with a version also finds its ranges offline.
 * Internet-facing families first.
 */
export function nvdPlan(rows: InventoryRow[], pairs: KevPair[], entries: KevEntry[], k = CANDIDATES_K): NvdPlanFamily[] {
  const fams = new Map<string, { rows: number; internet_facing: number }>();
  for (const row of rows) {
    const parsed = parseSoftware(row.software);
    const vote = normaliserVote(row, parsed, topCandidates(parsed, pairs, k));
    if (!vote.vendor || !vote.product) continue;
    const fam = familyKey(matchedKevPart(parsed, { vendor: vote.vendor, product: vote.product }).family);
    const f = fams.get(fam) ?? { rows: 0, internet_facing: 0 };
    f.rows++;
    if (row.internet_facing) f.internet_facing++;
    fams.set(fam, f);
  }
  const byFamily = new Map<string, KevEntry[]>();
  for (const e of entries) {
    for (const f of new Set(familiesOf(e).map(familyKey))) (byFamily.get(f) ?? byFamily.set(f, []).get(f)!).push(e);
  }
  const plan: NvdPlanFamily[] = [];
  for (const [family, f] of fams) {
    const cves = [...new Set([...(byFamily.get(family) ?? [])].sort(byDateDesc).map((e) => cveKey(e.cve_id)))];
    if (!cves.length) continue;
    const pick = family === WINDOWS_FAMILY ? cves.slice(0, 1) : cves.length <= NVD_SMALL_FAMILY ? cves : cves.slice(0, 2);
    plan.push({ family, rows: f.rows, internet_facing: f.internet_facing, cves: pick });
  }
  return plan.sort((a, b) => b.internet_facing - a.internet_facing || b.rows - a.rows || a.family.localeCompare(b.family));
}

/** The most common vulnerable CPE vendor:product among a family's captured NVD ranges. */
function cpeProductOf(ranges: NvdRange[]): { vendor: string; product: string } | null {
  const count = new Map<string, number>();
  for (const r of ranges) {
    if (!r.vulnerable) continue;
    const c = parseCpe(r.criteria);
    if (!c || c.part === "o" && c.vendor === "microsoft") continue; // Windows: per-edition builds, no product feed
    const key = `${c.vendor}:${c.product}`;
    count.set(key, (count.get(key) ?? 0) + 1);
  }
  const best = [...count.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0];
  if (!best) return null;
  const [vendor, product] = best[0].split(":");
  return { vendor, product };
}

export async function captureSnapshot(o: CaptureOptions): Promise<CaptureResult> {
  const prefix = o.prefix ?? "EL_";
  if (!isValidPrefix(prefix)) throw new Error(`invalid prefix ${JSON.stringify(prefix)}`);
  const n = elNames(prefix);
  const now = o.now ?? (() => new Date());
  const log = o.log ?? (() => {});
  const scope = o.kevScope ?? "all";
  const nvdBudgetMs = o.nvdBudgetMs ?? 20 * 60_000;
  const nvdMax = o.nvdMax ?? 120;
  const productsMax = o.products ?? 3;
  const started = now().toISOString();
  const queries: CaptureQuery[] = [];
  const notes: string[] = [];
  let zetarisMs = 0;

  /** One live SELECT, cache bypassed; a truncated answer is an error (the snapshot must be complete). */
  const q = async (label: string, sql: string, limit: number): Promise<Record<string, string>[]> => {
    const at = now().toISOString();
    const r = await o.client.query(sql, { cache: "bypass", label: `snapshot:${label}`, limit });
    if (r.fromCache) throw new Error(`${label}: answered from a cache, not live`);
    if (typeof r.total === "number" && r.total > r.rows.length) throw new Error(`${label}: truncated (${r.rows.length} of ${r.total} rows)`);
    zetarisMs += r.ms;
    queries.push({ label, sql: clip(sql.replace(/\s+/g, " ").trim(), 400), sql_hash: sqlHash(sql), rows: r.rows.length, ms: r.ms, at });
    return r.rows;
  };

  // 1. inventory
  const invAt = now().toISOString();
  const inventory = (await q("inventory", `SELECT ${INVENTORY_COLUMNS.join(", ")} FROM ${n.inventoryRef}`, 5000))
    .map(toInventoryRow).filter((x) => x.row_id !== "" || x.software.trim() !== "").sort(rowSort);
  if (!inventory.length) throw new Error("el.inventory returned no rows");
  const ids = new Set(inventory.map((r) => r.row_id));
  if (ids.size !== inventory.length) throw new Error("el.inventory has duplicate row_id values");
  log(`[1/5] inventory: ${inventory.length} rows from ${n.inventoryRef}`);

  // 2. KEV names and entries
  const kevAt = now().toISOString();
  const pairs = (await q("kevPairs", `SELECT DISTINCT vendor, product FROM ${n.kevRef} ORDER BY vendor, product`, 10_000))
    .map((x) => ({ vendor: x.vendor ?? "", product: x.product ?? "" }));
  if (!pairs.length) throw new Error("el.kev returned no (vendor, product) pairs");
  const vendors = inventoryVendors(inventory, pairs);
  const cols = KEV_COLUMNS.join(", ");
  let entries: KevEntry[];
  if (scope === "all") {
    entries = (await q("kevEntries(all)", `SELECT ${cols} FROM ${n.kevRef}`, 10_000)).map(toKevEntry);
  } else {
    entries = [];
    const vs = vendors.map((v) => v.toLowerCase());
    for (const part of chunk(vs, 200)) {
      const where = part.map(sqlString).join(", ");
      entries.push(...(await q(`kevEntries(vendors ${part.length})`, `SELECT ${cols} FROM ${n.kevRef} WHERE lower(trim(vendor)) IN (${where})`, 10_000)).map(toKevEntry));
    }
  }
  entries = [...new Map(entries.map((e) => [`${cveKey(e.cve_id)}|${e.vendor}|${e.product}`, e])).values()].sort(kevSort);
  if (!entries.length) throw new Error("el.kev returned no entries");
  const versions = [...new Set(entries.map((e) => e.catalog_version).filter(Boolean))].sort();
  if (versions.length > 1) notes.push(`KEV entries carry ${versions.length} catalog versions: ${versions.join(", ")}`);
  const pairKeys = new Set(pairs.map((p) => `${p.vendor.trim().toLowerCase()}\u0000${p.product.trim().toLowerCase()}`));
  const strays = entries.filter((e) => !pairKeys.has(`${e.vendor.trim().toLowerCase()}\u0000${e.product.trim().toLowerCase()}`));
  if (strays.length) notes.push(`${strays.length} KEV entries name a pair missing from kevPairs (the catalogue changed between the two reads?)`);
  log(`[2/5] KEV: ${pairs.length} pairs, ${entries.length} entries (scope ${scope}; the inventory's candidates name ${vendors.length} vendors), catalog ${versions.join(", ") || "?"}`);

  const plan = nvdPlan(inventory, pairs, entries);
  const planned = [...new Set(plan.flatMap((p) => p.cves))];
  log(`      NVD plan: ${planned.length} CVE(s) for ${plan.length} famil${plan.length === 1 ? "y" : "ies"} the normaliser matches`);
  if (o.planOnly) return { snapshot: null, plan, inventoryVendors: vendors };

  // 3. EPSS for every captured KEV CVE
  const epssAt = now().toISOString();
  const cves = cleanCveIds(entries.map((e) => e.cve_id)).valid;
  const epss: EpssScore[] = [];
  const batches = chunk(cves, EPSS_BATCH_MAX);
  for (const [i, batch] of batches.entries()) {
    const table = epssTableName(batch, prefix);
    await o.client.ddl(epssCreateSql(table, batch, prefix), { label: `snapshot:epss_register(${batch.length})` });
    const got = (await q(`epss(${batch.length})`, epssSelectSql(table, prefix), EPSS_BATCH_MAX * 2)).map(toEpssScore).filter((x): x is EpssScore => x !== null);
    const mine = new Set(batch);
    epss.push(...got.filter((s) => mine.has(s.cve_id)));
    if ((i + 1) % 5 === 0 || i === batches.length - 1) log(`[3/5] EPSS: batch ${i + 1}/${batches.length}, ${epss.length} score(s) so far`);
  }
  const epssBy = new Map<string, EpssScore>();
  for (const s of epss) { const p = epssBy.get(s.cve_id); if (!p || s.score_date > p.score_date) epssBy.set(s.cve_id, s); }
  const scoreDates = [...new Set([...epssBy.values()].map((s) => s.score_date).filter(Boolean))].sort();

  // 4. NVD ranges (through the NVD adapter: one REST table per CVE, >= 6 s apart, today's cache reused)
  const nvdAt = now().toISOString();
  const nvd: Record<string, NvdSnapshotRecord> = {};
  const nvdErrors: Record<string, string> = {};
  const t0 = Date.now();
  const lookup = async (cve: string): Promise<void> => {
    const ranges = await o.nvd.nvdCves([cve]);
    const st = o.nvd.status().filter((s) => cveKey(s.key) === cve).pop();
    const state = st?.state ?? "error";
    if (state === "ok" || state === "no_configurations" || state === "not_found" || state === "cached" || state === "fallback") {
      nvd[cve] = {
        state, as_of: st?.as_of ?? now().toISOString().slice(0, 10), table: st?.table ?? null,
        ranges: ranges.filter((r) => cveKey(r.cve_id) === cve), ...(st?.detail ? { detail: st.detail } : {}),
      };
      delete nvdErrors[cve];
    } else {
      nvdErrors[cve] = clip(st?.detail ?? state, 200);
    }
  };
  let tried = 0;
  for (const cve of planned) {
    if (tried >= nvdMax || Date.now() - t0 > nvdBudgetMs) { nvdErrors[cve] = "not captured: the snapshot's NVD budget was spent"; continue; }
    tried++;
    await lookup(cve);
    log(`[4/5] NVD ${tried}/${planned.length} ${cve}: ${nvd[cve] ? `${nvd[cve].state}, ${nvd[cve].ranges.length} range(s)` : `error (${nvdErrors[cve]})`}  ${Math.round((Date.now() - t0) / 1000)} s`);
  }
  for (const cve of Object.keys(nvdErrors).filter((c) => !/budget/.test(nvdErrors[c]))) {
    if (Date.now() - t0 > nvdBudgetMs) break;
    await lookup(cve); // one retry for a failed read
    log(`[4/5] NVD retry ${cve}: ${nvd[cve] ? `${nvd[cve].state}, ${nvd[cve].ranges.length} range(s)` : `error (${nvdErrors[cve]})`}`);
  }
  const states: Record<string, number> = {};
  for (const r of Object.values(nvd)) states[r.state] = (states[r.state] ?? 0) + 1;
  if (Object.keys(nvdErrors).length) states.not_captured = Object.keys(nvdErrors).length;

  // 5. NVD product lookups for the internet-facing rows' families (recent CVEs per CPE product; KB-sized pages)
  const prodAt = now().toISOString();
  const products: Record<string, NvdProductSnapshot> = {};
  const wanted: { vendor: string; product: string }[] = [];
  for (const f of plan.filter((p) => p.internet_facing > 0)) {
    const cpe = cpeProductOf(f.cves.flatMap((c) => nvd[c]?.ranges ?? []));
    if (cpe && !wanted.some((w) => w.vendor === cpe.vendor && w.product === cpe.product)) wanted.push(cpe);
    if (wanted.length >= productsMax) break;
  }
  for (const w of wanted) {
    const hits = await o.nvd.nvdProduct(w.vendor, w.product);
    const key = `cpe:${w.vendor}:${w.product}`;
    const st = o.nvd.status().filter((s) => s.key === key).pop();
    if (st && (st.state === "ok" || st.state === "cached" || st.state === "fallback")) {
      products[key] = { state: st.state, as_of: st.as_of ?? now().toISOString().slice(0, 10), table: st.table, hits, ...(st.detail ? { detail: st.detail } : {}) };
    } else {
      notes.push(`NVD product lookup ${key} not captured: ${clip(st?.detail ?? "error", 160)}`);
    }
    log(`[5/5] NVD product ${key}: ${products[key] ? `${hits.length} CVE(s)` : "not captured"}`);
  }

  const snapshot: SampleSnapshot = {
    schema: SNAPSHOT_SCHEMA,
    description: "Sample-mode input data, captured through Zetaris by scripts/snapshot.ts: the synthetic inventory, CISA KEV, FIRST EPSS and NIST NVD rows as read on the capture dates below. Input data only: no model replies, decisions or outputs. Served offline by src/sample/queries.ts when SAMPLE_MODE=true.",
    captured_at: started,
    finished_at: now().toISOString(),
    capture: {
      tool: "scripts/snapshot.ts", prefix, zetaris_queries: queries.length, zetaris_ms: zetarisMs, queries,
      notes: [
        "Read through the app's Zetaris objects (el.inventory, el.kev, EL_EPSS and EL_NVD REST tables), one query at a time; the app's query cache was bypassed.",
        `NVD plan: for each KEV family the deterministic normaliser matches in the inventory, the CVEs the pipeline's version check looks up (Windows: the newest; families with at most ${NVD_SMALL_FAMILY} KEV CVEs: all; larger families: the 2 newest).`,
        ...notes,
      ],
    },
    sources: {
      inventory: { object: n.inventoryRef, captured_at: invAt, rows: inventory.length, synthetic: true },
      kev: { object: n.kevRef, captured_at: kevAt, catalog_version: versions[versions.length - 1] ?? null, pairs: pairs.length, entries: entries.length, scope: scope === "all" ? "full_catalogue" : "inventory_vendors", inventory_vendors: vendors },
      epss: { object: `${n.epssDb}.${n.epssTablePrefix}<batch>`, captured_at: epssAt, requested: cves.length, scored: epssBy.size, score_dates: scoreDates },
      nvd: { object: `${n.prefix}NVD.${n.prefix.toLowerCase()}nvd_<cve>`, captured_at: nvdAt, cves: Object.keys(nvd).length, states, plan: `${planned.length} CVE(s) for ${plan.length} famil${plan.length === 1 ? "y" : "ies"}` },
      nvd_products: { object: `${n.prefix}NVD.${n.prefix.toLowerCase()}nvdp_<hash>`, captured_at: prodAt, lookups: Object.keys(products).length, window_days: NVD_PRODUCT_WINDOW_DAYS, page_size: NVD_PRODUCT_PAGE },
    },
    inventory,
    kev_pairs: pairs,
    kev_entries: entries,
    epss_requested: cves,
    epss: [...epssBy.values()].sort((a, b) => a.cve_id.localeCompare(b.cve_id)),
    nvd: Object.fromEntries(Object.keys(nvd).sort().map((k) => [k, nvd[k]])),
    nvd_errors: Object.fromEntries(Object.keys(nvdErrors).sort().map((k) => [k, nvdErrors[k]])),
    nvd_products: Object.fromEntries(Object.keys(products).sort().map((k) => [k, products[k]])),
  };
  return { snapshot, plan, inventoryVendors: vendors };
}

/** Serialise, validate the round trip, refuse if a configured secret value appears, then write atomically. */
export function writeSnapshot(file: string, snap: SampleSnapshot, secrets: string[] = secretValues()): { bytes: number } {
  const text = formatSnapshot(snap);
  const back = parseSnapshot(text);
  if (back.kev_entries.length !== snap.kev_entries.length || back.inventory.length !== snap.inventory.length) {
    throw new Error("the formatted snapshot does not parse back to the same data");
  }
  if (secrets.some((v) => v && text.includes(v))) throw new Error("refused: a configured secret value appears in the snapshot (nothing written)");
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, text, "utf8");
  renameSync(tmp, file);
  return { bytes: Buffer.byteLength(text) };
}

export interface SnapshotArgs { out: string; kevScope: "all" | "vendors"; nvdBudgetS: number; nvdMax: number; products: number; plan: boolean; help: boolean; }

export function parseSnapshotArgs(argv: string[]): SnapshotArgs {
  const a: SnapshotArgs = { out: DEFAULT_SNAPSHOT_FILE, kevScope: "all", nvdBudgetS: 1200, nvdMax: 120, products: 3, plan: false, help: false };
  const num = (v: string | undefined, flag: string, lo: number, hi: number): number => {
    const x = Number(v);
    if (v === undefined || !Number.isFinite(x) || x < lo || x > hi) throw new Error(`${flag} needs a number from ${lo} to ${hi}`);
    return x;
  };
  for (let i = 0; i < argv.length; i++) {
    const [flag, inline] = argv[i].includes("=") ? [argv[i].slice(0, argv[i].indexOf("=")), argv[i].slice(argv[i].indexOf("=") + 1)] : [argv[i], undefined];
    const val = () => inline ?? argv[++i];
    if (flag === "--out") a.out = resolve(process.cwd(), String(val()));
    else if (flag === "--kev-scope") { const v = val(); if (v !== "all" && v !== "vendors") throw new Error("--kev-scope must be all or vendors"); a.kevScope = v; }
    else if (flag === "--nvd-budget-s") a.nvdBudgetS = num(val(), flag, 0, 3600);
    else if (flag === "--nvd-max") a.nvdMax = Math.floor(num(val(), flag, 0, 500));
    else if (flag === "--products") a.products = Math.floor(num(val(), flag, 0, 20));
    else if (flag === "--plan") a.plan = true;
    else if (flag === "--help" || flag === "-h") a.help = true;
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return a;
}

const USAGE = "usage: npm run snapshot [-- --out <file>] [--kev-scope all|vendors] [--nvd-budget-s 1200] [--nvd-max 120] [--products 3] [--plan]";

async function main(): Promise<number> {
  let args: SnapshotArgs;
  try { args = parseSnapshotArgs(process.argv.slice(2)); } catch (e) { console.error(`[ERROR] ${(e as Error).message}\n${USAGE}`); return 2; }
  if (args.help) { console.log(USAGE); return 0; }
  const cfg = loadConfig();
  try { requireConfig(cfg, "zetaris"); } catch (e) { console.error(`[ERROR] ${(e as Error).message}`); return 2; }
  const d = describeConfig(cfg);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  let tracer: Tracer;
  try { tracer = createTracer(`snapshot-${stamp}`, { stdout: false }); } catch { tracer = nullTracer(`snapshot-${stamp}`); }
  console.log(`[INFO] snapshot capture: zetaris=${d.ZETARIS_REST_URL} prefix=${cfg.prefix} kev-scope=${args.kevScope}${args.plan ? " (plan only)" : ""}; trace ${tracer.file ? relative(REPO_ROOT, tracer.file) : "(none)"}`);
  const client = new ZetarisClient({ restUrl: cfg.zetaris.restUrl, orgId: cfg.zetaris.orgId, apiKey: cfg.zetaris.apiKey, tracer });
  const health = await client.health();
  if (!health.ok) { console.error(`[ERROR] Zetaris is not reachable: ${health.error ?? "SELECT 1 failed"}`); return 1; }
  const nvd = createNvdQueries({ client, tracer, prefix: cfg.prefix, productPageSize: NVD_PRODUCT_PAGE, productWindowDays: NVD_PRODUCT_WINDOW_DAYS });
  const t0 = performance.now();
  let res: CaptureResult;
  try {
    res = await captureSnapshot({
      client, nvd, prefix: cfg.prefix, kevScope: args.kevScope, nvdBudgetMs: args.nvdBudgetS * 1000, nvdMax: args.nvdMax,
      products: args.products, planOnly: args.plan, log: (l) => console.log(l),
    });
  } catch (e) {
    console.error(`[ERROR] capture failed, nothing written: ${(e as Error).message}`);
    return 1;
  }
  const secs = ((performance.now() - t0) / 1000).toFixed(1);
  if (args.plan || !res.snapshot) {
    // counts only: the plan is computed over every inventory row, and per-row or per-family matches are not printed
    const cvesPlanned = new Set(res.plan.flatMap((f) => f.cves)).size;
    console.log(`  NVD plan: ${res.plan.length} families, ${cvesPlanned} CVE(s), ${res.plan.filter((f) => f.internet_facing > 0).length} families on internet-facing rows; KEV slice for inventory vendors: ${res.inventoryVendors.length} vendors`);
    console.log(`[INFO] plan only, nothing written (${secs} s)`);
    return 0;
  }
  const s = res.snapshot;
  let bytes: number;
  try { ({ bytes } = writeSnapshot(args.out, s)); } catch (e) { console.error(`[ERROR] ${(e as Error).message}`); return 1; }
  console.log("");
  console.log(`[INFO] wrote ${relative(REPO_ROOT, args.out) || args.out} (${(bytes / 1024).toFixed(0)} KB) in ${secs} s; ${s.capture.zetaris_queries} Zetaris data queries (${(s.capture.zetaris_ms / 1000).toFixed(1)} s)`);
  console.log(`  inventory ${s.inventory.length} rows · KEV ${s.kev_pairs.length} pairs, ${s.kev_entries.length} entries (catalog ${s.sources.kev.catalog_version}) · EPSS ${s.epss.length}/${s.epss_requested.length} scored (${s.sources.epss.score_dates.join(", ")}) · NVD ${Object.keys(s.nvd).length} CVE(s) ${JSON.stringify(s.sources.nvd.states)} · NVD products ${Object.keys(s.nvd_products).length}`);
  for (const n of s.capture.notes.slice(2)) console.log(`  note: ${n}`);
  return 0;
}

if (import.meta.main) {
  process.exitCode = await main();
}
