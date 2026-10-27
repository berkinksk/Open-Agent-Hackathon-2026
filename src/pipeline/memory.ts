// Memory across runs, through the World Model engine. Every live run saves its world (output/world/.world/<run>.json,
// the engine's own file). Memory is kept per inventory ROW, not per list: the run index (output/world/last-runs.json)
// maps each row (where it came from, its row id, its asset and its software text) to the last live run that included
// it. The next live run groups its rows by those runs, reopens each one's world read-only (the engine replays its saved
// events; nothing is written to it) and asks it, through factsAsOf, what it believed about each of those rows: the
// decision, its target date and the KEV CVEs it cited. From that:
// - "since the last run": decisions that changed, KEV CVEs cited now that were not cited then (and which of them KEV
//   added after that run), owner questions still open;
// - one decision input: the patch_now clock. A line that was already patch_now for the same KEV product family keeps
//   the earlier target date (the user's N days count from the first run that listed it), so re-running the list every
//   day never pushes the deadline back. The target only ever moves earlier.
// A run on another subset of the rows (CLI --rows, POST {row_ids}) moves only its own rows' pointers, so it never hides
// the history of the rows it left out. A row whose software text changes is a new row (a new clock).
// The index is a pointer file only; the beliefs come from the engine.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import type { Evidence, InventoryRow, PatchLine } from "../contracts.ts";
import { createLedgerWorld, ledgerIds } from "../engine/index.ts";
import type { LedgerWorld } from "../engine/index.ts";
import { familyKey } from "../resolve/candidates.ts";

export const RUN_INDEX_FILE = "last-runs.json";
export const RUN_INDEX_VERSION = 2;

export interface RunPointer { run_id: string; namespace: string; as_of: string; rows: number; }

/** The run index: each row's memory key -> the last live run that included that row, and those runs. */
export interface RunIndex { version: typeof RUN_INDEX_VERSION; runs: Record<string, RunPointer>; rows: Record<string, string>; }

/**
 * One inventory row's memory key: where the rows came from (the registered inventory, or a request), the row id, and a
 * hash of its asset and software text. The registered inventory and request rows never share memory.
 */
export function rowMemoryKey(inventoryFrom: "zetaris" | "request", row: Pick<InventoryRow, "row_id" | "asset_id" | "software">): string {
  const h = createHash("sha256").update(`${row.asset_id}\u0000${row.software}`).digest("hex").slice(0, 12);
  return `${inventoryFrom === "zetaris" ? "inventory" : "request"}:${row.row_id}:${h}`;
}

function emptyIndex(): RunIndex {
  return { version: RUN_INDEX_VERSION, runs: {}, rows: {} };
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** The run index; empty when absent, unreadable, or written by an older build (one pointer per list: not used). */
export function readRunIndex(worldDir: string): RunIndex {
  try {
    const j = JSON.parse(readFileSync(join(worldDir, RUN_INDEX_FILE), "utf8")) as unknown;
    if (!isObj(j) || j.version !== RUN_INDEX_VERSION || !isObj(j.runs) || !isObj(j.rows)) return emptyIndex();
    const out = emptyIndex();
    for (const [id, p] of Object.entries(j.runs)) {
      if (isObj(p) && typeof p.run_id === "string" && typeof p.namespace === "string" && typeof p.as_of === "string") {
        out.runs[id] = { run_id: p.run_id, namespace: p.namespace, as_of: p.as_of, rows: Number(p.rows) || 0 };
      }
    }
    for (const [k, id] of Object.entries(j.rows)) if (typeof id === "string" && out.runs[id]) out.rows[k] = id;
    return out;
  } catch {
    return emptyIndex();
  }
}

/** Points each of these rows at this run, and drops the runs no row points at any more. Atomic (write, then rename). */
export function writeRunIndex(worldDir: string, keys: string[], p: RunPointer): RunIndex {
  const idx = readRunIndex(worldDir);
  idx.runs[p.run_id] = p;
  for (const k of keys) idx.rows[k] = p.run_id;
  const used = new Set(Object.values(idx.rows));
  for (const id of Object.keys(idx.runs)) if (!used.has(id)) delete idx.runs[id];
  mkdirSync(worldDir, { recursive: true });
  const file = join(worldDir, RUN_INDEX_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(idx, null, 2)}\n`, "utf8");
  renameSync(tmp, file);
  return idx;
}

export interface EarlierRun { pointer: RunPointer; row_ids: string[]; }

/**
 * This run's rows grouped by the earlier run that last included each of them (most recent first). Rows no earlier run
 * included, or whose last run is this run's own id (a re-run under the same id), are `fresh`.
 */
export function earlierRunsFor(index: RunIndex, rows: { row_id: string; key: string }[], selfRunId: string): { runs: EarlierRun[]; fresh: string[] } {
  const groups = new Map<string, EarlierRun>();
  const fresh: string[] = [];
  for (const r of rows) {
    const id = index.rows[r.key];
    const p = id ? index.runs[id] : undefined;
    if (!p || p.run_id === selfRunId) { fresh.push(r.row_id); continue; }
    const g = groups.get(p.run_id);
    if (g) g.row_ids.push(r.row_id); else groups.set(p.run_id, { pointer: p, row_ids: [r.row_id] });
  }
  const runs = [...groups.values()].sort((a, b) => b.pointer.as_of.localeCompare(a.pointer.as_of) || a.pointer.run_id.localeCompare(b.pointer.run_id));
  return { runs, fresh };
}

/** Reopens a saved world read-only (the engine replays the file; this code never writes to it). Null when absent. */
export function openPreviousWorld(worldDir: string, p: RunPointer | undefined): LedgerWorld | null {
  if (!p || !p.namespace || !existsSync(join(worldDir, ".world", `${p.namespace}.json`))) return null;
  return createLedgerWorld({ namespace: p.namespace, persistDir: worldDir, resume: true });
}

interface PrevDecision { decision?: string; target_date?: string | null; kev_cves?: string[] }
interface PrevResolution { status?: string; family?: string | null }

export interface SinceLastRun {
  /** The earlier runs the rows were compared with (each row with the last run that included it), most recent first. */
  previous: { run_id: string; as_of: string; rows: string[] }[];
  rows_compared: number;
  rows_new: string[];
  changed: { row_id: string; from: string; to: string; since_run: string }[];
  newly_cited: { row_id: string; cves: { cve_id: string; date_added: string; added_since_last_run: boolean }[] }[];
  still_open: { row_id: string; since: string }[];
  anchored: { row_id: string; target_date: string; was: string; since: string; run_id: string }[];
  summary: string;
}

/**
 * Compares this run's lines with what each row's last earlier run believed about it, read from that run's saved world,
 * and anchors the patch_now clock (see the file header). Rows with no earlier run (`fresh`), or whose run's world is
 * missing, count as new. Mutates the anchored lines (target date, why, one evidence item). Pure otherwise.
 */
export function sinceLastRun(lines: PatchLine[], earlier: (EarlierRun & { world: LedgerWorld | null })[], fresh: string[] = []): SinceLastRun {
  const out: SinceLastRun = {
    previous: [], rows_compared: 0, rows_new: [], changed: [], newly_cited: [], still_open: [], anchored: [], summary: "",
  };
  const byId = new Map(lines.map((l) => [l.row_id, l]));
  const newIds = new Set(fresh.filter((id) => byId.has(id)));
  for (const g of earlier) {
    const compared: string[] = [];
    for (const id of g.row_ids) {
      const l = byId.get(id);
      if (!l) continue;
      let b: ReturnType<LedgerWorld["factsAsOf"]> = {};
      if (g.world) {
        try { b = g.world.factsAsOf(ledgerIds.software(l.row_id), g.pointer.as_of); } catch { b = {}; }
      }
      const d = b.decision?.value as PrevDecision | undefined;
      if (!d || typeof d.decision !== "string") { newIds.add(l.row_id); continue; }
      compared.push(l.row_id);
      out.rows_compared++;
      const since = String(b.decision?.at ?? g.pointer.as_of).slice(0, 10);
      if (d.decision !== l.decision) out.changed.push({ row_id: l.row_id, from: d.decision, to: l.decision, since_run: g.pointer.run_id });
      const before = new Set((d.kev_cves ?? []).map((c) => String(c).trim().toUpperCase()));
      const recent = (l.kev?.cves ?? []).filter((c) => !before.has(c.cve_id.trim().toUpperCase()));
      if (recent.length && before.size > 0) {
        out.newly_cited.push({ row_id: l.row_id, cves: recent.map((c) => ({ cve_id: c.cve_id, date_added: c.date_added, added_since_last_run: c.date_added > g.pointer.as_of })) });
      }
      if (d.decision === "ask_owner" && l.decision === "ask_owner") out.still_open.push({ row_id: l.row_id, since });
      // the patch_now clock: same decision, same KEV product family, an earlier target -> keep the earlier one
      const r = b.resolves_to?.value as PrevResolution | undefined;
      const sameFamily = !!r?.family && !!l.resolution.family && familyKey(r.family) === familyKey(l.resolution.family);
      if (d.decision === "patch_now" && l.decision === "patch_now" && sameFamily && d.target_date && l.target_date && d.target_date < l.target_date) {
        const was = l.target_date;
        l.target_date = d.target_date;
        l.why = l.why.replace(/Patch by \d{4}-\d{2}-\d{2} under your (\d+)-day rule/, `Patch by ${d.target_date} under your $1-day rule (the date run ${g.pointer.run_id} of ${since} already set)`);
        const ev: Evidence = {
          source: "world_model", query: `factsAsOf(${l.row_id}, ${g.pointer.as_of})`, field: "patch_now_since",
          value: `already patch_now in run ${g.pointer.run_id} of ${since}: the target stays ${d.target_date}, not ${was} (re-running never pushes the deadline back); recalled from that run's world`,
          as_of: since, live: false,
        };
        l.evidence.push(ev);
        out.anchored.push({ row_id: l.row_id, target_date: d.target_date, was, since, run_id: g.pointer.run_id });
      }
    }
    if (compared.length) out.previous.push({ run_id: g.pointer.run_id, as_of: g.pointer.as_of, rows: compared });
  }
  out.rows_new = lines.map((l) => l.row_id).filter((id) => newIds.has(id));
  const addedNow = out.newly_cited.flatMap((x) => x.cves).filter((c) => c.added_since_last_run).length;
  const head = out.previous.length === 1
    ? `since run ${out.previous[0].run_id} (${out.previous[0].as_of})`
    : `since each row's last run (${out.previous.map((p) => `${p.run_id} of ${p.as_of}: ${p.rows.length} row(s)`).join("; ")})`;
  out.summary = `${head}: ${out.rows_compared} row(s) compared, ${out.rows_new.length} new; `
    + `${out.changed.length} decision(s) changed; ${out.newly_cited.length} line(s) cite new KEV CVEs (${addedNow} added to KEV after that run); `
    + `${out.still_open.length} owner question(s) still open; ${out.anchored.length} patch_now target(s) kept from an earlier run`;
  return out;
}
