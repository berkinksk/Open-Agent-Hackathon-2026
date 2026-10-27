// Windows OS rows. KEV lists Windows as one product ("Microsoft / Windows", plus its components), and Microsoft ships
// every Windows fix in the monthly cumulative update. An inventory row that names the edition but not the build
// ("Windows 11 Pro 23H2", "Win 10 Pro 22H2", "Windows Server 2019") cannot be placed in NVD's ranges, which are per
// edition and per build (cpe ...:windows_11_23h2 with versionEndExcluding 10.0.22631.NNNN). So:
//   - the version stays unconfirmed, and the KEV listing keeps the row at patch_now (fail-closed ruling);
//   - the owner gets ONE question per edition ("which build runs on these N machines?"), not one per machine;
//   - when NVD has the newest KEV-listed Windows CVE, the question names the first fixed build for that edition.
// The edition and build parsing is general string handling, not a per-row table.
import type { InventoryRow, KevEntry, NvdRange, OwnerQuestion } from "../contracts.ts";
import { parseCpe } from "../resolve/versions.ts";

export const WINDOWS_FAMILY = "microsoft:windows";

export interface WindowsEdition {
  /** Stable group key, e.g. "windows_11_23h2" (the NVD CPE product when the edition is complete). */
  key: string;
  /** Display label, e.g. "Windows 11 23H2". */
  label: string;
  /** The NVD CPE product for this edition, or null when the edition is incomplete ("Windows 11" without 23H2). */
  cpe_product: string | null;
  /** A build number written in the row (10.0.22631.4317 or 22631.4317), or null. */
  build: string | null;
}

const FEATURE_RE = /\b(1[5-9]|2[0-9])h([12])\b/;
const SERVER_RE = /\b(?:server|svr|srv)\s*(2008(?:\s*r2)?|2012(?:\s*r2)?|2016|2019|2022|2025)\b/;
const CLIENT_RE = /\bwin(?:dows|dwos|odws|dows?)?\s*(7|8\.1|8|10|11)(?![\d.])/;
const BUILD_RE = /\b(?:10\.0\.)?(1\d{4}|2\d{4})\.(\d{1,5})\b/;

/** The Windows edition a row names, or null when the text is not a Windows OS row. */
export function windowsEdition(software: string): WindowsEdition | null {
  const s = ` ${String(software ?? "").toLowerCase().replace(/[_,;/()]+/g, " ").replace(/\s+/g, " ")} `;
  if (!/\bwin(?:dows|dwos|odws)?\s*(?:\d|server|svr|srv)|\bwindows\b/.test(s)) return null;
  const b = s.match(BUILD_RE);
  const build = b ? `10.0.${b[1]}.${b[2]}` : null;
  const server = s.match(SERVER_RE);
  if (server) {
    const year = server[1].replace(/\s+/g, "");
    const key = `windows_server_${year}`;
    return { key, label: `Windows Server ${year.replace(/r2$/, " R2")}`, cpe_product: key, build };
  }
  const client = s.match(CLIENT_RE);
  if (!client) return null;
  const major = client[1];
  const fv = s.match(FEATURE_RE);
  if (!fv) {
    const key = `windows_${major.replace(".", "_")}`;
    return { key, label: `Windows ${major}`, cpe_product: null, build };
  }
  const feature = `${fv[1]}h${fv[2]}`;
  const key = `windows_${major.replace(".", "_")}_${feature}`;
  return { key, label: `Windows ${major} ${feature.toUpperCase()}`, cpe_product: key, build };
}

/** The first fixed build NVD gives for this edition in these ranges (versionEndExcluding), or null. */
export function fixedBuildFor(edition: WindowsEdition, ranges: NvdRange[]): string | null {
  if (!edition.cpe_product) return null;
  const ends = ranges
    .filter((r) => r.vulnerable && r.version_end_excluding)
    .filter((r) => parseCpe(r.criteria)?.product === edition.cpe_product)
    .map((r) => r.version_end_excluding as string);
  return ends.length ? ends.sort()[0] : null;
}

/** NVD ranges that belong to this edition only (its own CPE product), for an edition-aware version check. */
export function rangesForEdition(edition: WindowsEdition, ranges: NvdRange[]): NvdRange[] {
  if (!edition.cpe_product) return [];
  return ranges.filter((r) => parseCpe(r.criteria)?.product === edition.cpe_product);
}

export interface WindowsGroupMember { row: InventoryRow; edition: WindowsEdition | null; }

export interface WindowsGroup {
  key: string;
  label: string;
  row_ids: string[];
  assets: string[];
  fixed_build: string | null;
  question: OwnerQuestion & { row_ids: string[] };
}

function list(xs: string[], n = 6): string {
  return xs.slice(0, n).join(", ") + (xs.length > n ? ` and ${xs.length - n} more` : "");
}

/**
 * One owner question per Windows edition for the rows whose build is unconfirmed. `newest` is the most recently added
 * KEV-listed Windows CVE (its NVD ranges, when looked up, give the first fixed build per edition).
 */
export function groupWindowsQuestions(
  members: WindowsGroupMember[], newest: KevEntry | null, newestRanges: NvdRange[], kevCount: number,
): WindowsGroup[] {
  const groups = new Map<string, { label: string; edition: WindowsEdition | null; rows: InventoryRow[] }>();
  for (const m of members) {
    const key = m.edition?.key ?? "windows_unknown";
    const label = m.edition?.label ?? "Windows (edition not given)";
    const g = groups.get(key);
    if (g) g.rows.push(m.row); else groups.set(key, { label, edition: m.edition, rows: [m.row] });
  }
  const out: WindowsGroup[] = [];
  for (const [key, g] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const rows = [...g.rows].sort((a, b) => a.row_id.localeCompare(b.row_id, "en", { numeric: true }));
    const assets = [...new Set(rows.map((r) => r.asset_name))];
    const fixed = g.edition && newest ? fixedBuildFor(g.edition, newestRanges) : null;
    const where = `${assets.length === 1 ? assets[0] : `these ${assets.length} machines (${list(assets)})`}`;
    const kevPart = newest
      ? `KEV lists ${kevCount} Windows CVE${kevCount === 1 ? "" : "s"}; the newest, ${newest.cve_id}, was added ${newest.date_added} with a US federal due date of ${newest.due_date}`
      : `KEV lists ${kevCount} Windows CVE${kevCount === 1 ? "" : "s"}`;
    const nvdPart = fixed
      ? `NVD lists ${g.label} builds below ${fixed} as affected by it`
      : newest ? `NVD gives no ${g.label} build range for it yet` : "";
    const question = `Which ${g.label} build runs on ${where}? ${kevPart}${nvdPart ? `, and ${nvdPart}` : ""}. Install the latest cumulative update on any machine below that build, then tell us the build.`;
    const reason = `${rows.length} ${g.label} row${rows.length === 1 ? "" : "s"} name the edition but no build number, so the NVD build ranges cannot place ${rows.length === 1 ? "it" : "them"}; listed as patch_now (fail-closed) until the build is confirmed.`;
    out.push({
      key, label: g.label, row_ids: rows.map((r) => r.row_id), assets, fixed_build: fixed,
      question: { row_id: rows[0].row_id, asset_name: assets.length === 1 ? assets[0] : `${assets.length} machines`, question, reason, row_ids: rows.map((r) => r.row_id) },
    });
  }
  return out;
}
