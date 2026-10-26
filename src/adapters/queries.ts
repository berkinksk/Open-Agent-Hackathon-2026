// Live Queries over Zetaris (design §6). The agents call these named queries and never see SQL.
// Object names come from the prefix (default EL_): databases EL_*, tables el_*, container "el"
// (for EL_T1_ it is "el_t1"), views <container>.inventory and <container>.kev.
import { createHash } from "node:crypto";
import type {
  EpssScore, InventoryRow, KevEntry, KevPair, NvdProductHit, NvdRange, Queries, Tracer,
} from "../contracts.ts";
import type { CacheMode, DdlResult, QueryOptions, QueryResult } from "./zetaris.ts";
import { sqlString } from "./zetaris.ts";
import { isValidPrefix, parseBool } from "../config.ts";

export const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
export const EPSS_API = "https://api.first.org/data/v1/epss";
export const EPSS_BATCH_MAX = 100;     // the EPSS API page cap
const KEV_IN_CHUNK = 200;
const PAIR_CHUNK = 100;

/** What queries.ts needs from a client; ZetarisClient satisfies it, tests pass a fake. */
export interface SqlClient {
  query(sql: string, opts?: QueryOptions): Promise<QueryResult>;
  ddl(sql: string, opts?: { label?: string; timeoutMs?: number }): Promise<DdlResult>;
}

export interface ElNames {
  prefix: string;
  invDb: string; invRaw: string;
  kevDb: string; kevRaw: string;
  epssDb: string; epssTablePrefix: string;
  nvdDb: string;
  container: string;
  inventoryView: string; kevView: string;
  inventoryRef: string; kevRef: string;   // container.view, as written in FROM
}

export function elNames(prefix = "EL_"): ElNames {
  if (!isValidPrefix(prefix)) throw new Error(`invalid prefix ${JSON.stringify(prefix)}: must look like EL_ or EL_T1_`);
  const P = prefix;
  const p = prefix.toLowerCase();
  const container = p.replace(/_$/, "");
  return {
    prefix: P,
    invDb: `${P}INVENTORY`, invRaw: `${p}inventory_raw`,
    kevDb: `${P}KEV`, kevRaw: `${p}kev_raw`,
    epssDb: `${P}EPSS`, epssTablePrefix: `${p}epss_`,
    nvdDb: `${P}NVD`,
    container,
    inventoryView: "inventory", kevView: "kev",
    inventoryRef: `${container}.inventory`, kevRef: `${container}.kev`,
  };
}

export const INVENTORY_COLUMNS = ["row_id", "asset_id", "asset_name", "asset_type", "internet_facing", "owner_team", "software"] as const;
export const KEV_COLUMNS = [
  "cve_id", "vendor", "product", "vulnerability_name", "date_added", "due_date", "ransomware_use",
  "required_action", "short_description", "notes", "catalog_version",
] as const;

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

/** Uppercase, trim, validate, de-duplicate and sort CVE ids. */
export function cleanCveIds(ids: string[]): { valid: string[]; invalid: string[] } {
  const valid = new Set<string>();
  const invalid: string[] = [];
  for (const raw of ids) {
    const id = String(raw ?? "").trim().toUpperCase();
    if (CVE_RE.test(id)) valid.add(id); else invalid.push(String(raw));
  }
  return { valid: [...valid].sort(), invalid };
}

export function chunk<T>(xs: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}

/** One EPSS REST table per distinct sorted batch: <prefix>epss_<sha8(ids joined by ",")>. */
export function epssTableName(sortedIds: string[], prefix = "EL_"): string {
  const h = createHash("sha256").update(sortedIds.join(",")).digest("hex").slice(0, 8);
  return `${elNames(prefix).epssTablePrefix}${h}`;
}

export function epssCreateSql(table: string, sortedIds: string[], prefix = "EL_"): string {
  const n = elNames(prefix);
  return `CREATE LIGHTNING REST TABLE ${table} FROM ${n.epssDb} REQUEST(endpoint "${EPSS_API}?cve=${sortedIds.join(",")}", method "get", response_type "json", http_encoding "URLENCODED") HEADER () BODY ()`;
}

export function epssSelectSql(table: string, prefix = "EL_", onlyIds?: string[]): string {
  const n = elNames(prefix);
  const where = onlyIds && onlyIds.length ? ` WHERE d.cve IN (${onlyIds.map(sqlString).join(", ")})` : "";
  return `SELECT d.cve AS cve_id, d.epss AS epss, d.percentile AS percentile, d.\`date\` AS score_date FROM ${n.epssDb.toLowerCase()}.${table} LATERAL VIEW explode(data) AS d${where}`;
}

export function toInventoryRow(r: Record<string, string>): InventoryRow {
  return {
    row_id: (r.row_id ?? "").trim(),
    asset_id: (r.asset_id ?? "").trim(),
    asset_name: (r.asset_name ?? "").trim(),
    asset_type: (r.asset_type ?? "").trim(),
    internet_facing: parseBool(r.internet_facing),
    owner_team: (r.owner_team ?? "").trim(),
    software: r.software ?? "",
  };
}

export function toKevEntry(r: Record<string, string>): KevEntry {
  const e = {} as Record<string, string>;
  for (const c of KEV_COLUMNS) e[c] = r[c] ?? "";
  return e as unknown as KevEntry;
}

/** Parse one EPSS row; values arrive as strings. Returns null when the score is not a number. */
export function toEpssScore(r: Record<string, string>): EpssScore | null {
  const epss = r.epss === "" || r.epss === undefined ? NaN : Number(r.epss);
  const percentile = r.percentile === "" || r.percentile === undefined ? NaN : Number(r.percentile);
  if (!Number.isFinite(epss) || !r.cve_id) return null;
  return { cve_id: r.cve_id.trim().toUpperCase(), epss, percentile: Number.isFinite(percentile) ? percentile : NaN, score_date: r.score_date ?? "" };
}

const kevSelect = (n: ElNames) => `SELECT ${KEV_COLUMNS.join(", ")} FROM ${n.kevRef}`;

function kevSort(a: KevEntry, b: KevEntry): number {
  return a.vendor.localeCompare(b.vendor) || a.product.localeCompare(b.product) || a.cve_id.localeCompare(b.cve_id);
}

export function createZetarisQueries(cfg: { client: SqlClient; tracer: Tracer; prefix: string }): Queries {
  const { client, tracer } = cfg;
  const n = elNames(cfg.prefix);
  const cveTable = new Map<string, string>(); // CVE -> EPSS table it was fetched through (this run)
  const registered = new Set<string>();       // EPSS tables created or confirmed by this instance

  const noteInvalid = (where: string, invalid: string[]) => {
    if (!invalid.length) return;
    tracer.emit({
      agent: "Queries", action: "invalid_cve_ids", status: "error",
      input_summary: `${where}: ${invalid.length} id(s) not shaped like CVE-YYYY-NNNN`,
      output_summary: "ignored; no score or listing can exist for them",
      details: { where, invalid: invalid.slice(0, 20) },
    });
  };

  async function ensureEpssTable(ids: string[]): Promise<string> {
    const table = epssTableName(ids, n.prefix);
    const key = `${n.epssDb}.${table}`;
    if (!registered.has(key)) {
      // A duplicate CREATE answers "already exists", which ddl() treats as success.
      await client.ddl(epssCreateSql(table, ids, n.prefix), { label: `epss_register(${ids.length})` });
      registered.add(key);
    }
    for (const id of ids) cveTable.set(id, table);
    return table;
  }

  async function readEpss(table: string, cache: CacheMode, label: string, onlyIds?: string[]): Promise<EpssScore[]> {
    const r = await client.query(epssSelectSql(table, n.prefix, onlyIds), { cache, label, limit: EPSS_BATCH_MAX * 2 });
    return r.rows.map(toEpssScore).filter((x): x is EpssScore => x !== null);
  }

  return {
    async inventory(): Promise<InventoryRow[]> {
      const r = await client.query(`SELECT ${INVENTORY_COLUMNS.join(", ")} FROM ${n.inventoryRef}`, { cache: "use", label: "inventory", limit: 5000 });
      return r.rows.map(toInventoryRow).filter((x) => x.row_id !== "" || x.software.trim() !== "");
    },

    async kevPairs(): Promise<KevPair[]> {
      const r = await client.query(`SELECT DISTINCT vendor, product FROM ${n.kevRef} ORDER BY vendor, product`, { cache: "use", label: "kevPairs", limit: 10000 });
      return r.rows.map((x) => ({ vendor: x.vendor ?? "", product: x.product ?? "" }));
    },

    async kevByProducts(pairs: KevPair[]): Promise<KevEntry[]> {
      // Match on lower(trim()) so "Windows" also finds KEV's "Windows " (trailing space).
      const keys = new Map<string, { v: string; p: string }>();
      for (const pr of pairs) {
        const v = (pr.vendor ?? "").trim().toLowerCase();
        const p = (pr.product ?? "").trim().toLowerCase();
        if (v && p) keys.set(`${v}\u0000${p}`, { v, p });
      }
      if (!keys.size) return [];
      const out: KevEntry[] = [];
      const parts = chunk([...keys.values()], PAIR_CHUNK);
      for (let i = 0; i < parts.length; i++) {
        const where = parts[i].map(({ v, p }) => `(lower(trim(vendor)) = ${sqlString(v)} AND lower(trim(product)) = ${sqlString(p)})`).join(" OR ");
        const r = await client.query(`${kevSelect(n)} WHERE ${where}`, { cache: "use", label: `kevByProducts(${parts[i].length})`, limit: 10000 });
        out.push(...r.rows.map(toKevEntry));
      }
      return out.sort(kevSort);
    },

    async kevVerify(cveIds: string[]): Promise<KevEntry[]> {
      const { valid, invalid } = cleanCveIds(cveIds);
      noteInvalid("kevVerify", invalid);
      const out: KevEntry[] = [];
      for (const part of chunk(valid, KEV_IN_CHUNK)) {
        const r = await client.query(`${kevSelect(n)} WHERE cve_id IN (${part.map(sqlString).join(", ")})`, { cache: "bypass", label: `kevVerify(${part.length})`, limit: 10000 });
        out.push(...r.rows.map(toKevEntry));
      }
      return out.sort(kevSort);
    },

    async epss(cveIds: string[]): Promise<EpssScore[]> {
      const { valid, invalid } = cleanCveIds(cveIds);
      noteInvalid("epss", invalid);
      const out: EpssScore[] = [];
      for (const batch of chunk(valid, EPSS_BATCH_MAX)) {
        const table = await ensureEpssTable(batch);
        out.push(...(await readEpss(table, "use", `epss(${batch.length})`)));
      }
      return out;
    },

    async epssVerify(cveIds: string[]): Promise<EpssScore[]> {
      // Same REST tables as epss() (a REST table re-fetches its source on every query), cache bypassed.
      const { valid, invalid } = cleanCveIds(cveIds);
      noteInvalid("epssVerify", invalid);
      const byTable = new Map<string, string[]>();
      const unknown: string[] = [];
      for (const id of valid) {
        const t = cveTable.get(id);
        if (t) byTable.set(t, [...(byTable.get(t) ?? []), id]); else unknown.push(id);
      }
      for (const batch of chunk(unknown, EPSS_BATCH_MAX)) {
        const t = await ensureEpssTable(batch);
        byTable.set(t, [...(byTable.get(t) ?? []), ...batch]);
      }
      const out: EpssScore[] = [];
      for (const [table, ids] of byTable) out.push(...(await readEpss(table, "bypass", `epssVerify(${ids.length})`, ids)));
      return out;
    },

    async nvdCves(_cveIds: string[]): Promise<NvdRange[]> {
      throw new Error("dormant: implemented by A3");
    },

    async nvdProduct(_cpeVendor: string, _cpeProduct: string): Promise<NvdProductHit[]> {
      throw new Error("dormant: implemented by A3");
    },
  };
}
