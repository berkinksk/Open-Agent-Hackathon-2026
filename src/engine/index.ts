// Wrapper around the vendored Meterless World Model engine (./world-model, unmodified).
//
// The engine is an event-sourced store: entities, bitemporal relationships and facts,
// each write carrying provenance. This file maps one pipeline run (inventory rows,
// resolutions, KEV and EPSS rows, decisions) onto engine writes, and exposes the read
// helpers the report and the trace need: explain, factsAsOf, reviewQueue, audit, stats.
//
// Rules this wrapper keeps:
// - every write carries provenance; `at` is the source's own date (the run's as-of date,
//   the KEV catalogue version, the EPSS score date), never the wall clock;
// - re-ingesting the same run adds no events (facts and edges are content-addressed in
//   the engine; unchanged entity upserts are skipped here);
// - every fact names its run (provenance `url` = `run:<runId>`, which the engine's fact id
//   includes), so in a world reused across runs the latest run's value is the current belief,
//   even when it repeats a value an earlier run wrote on the same source date;
// - assets, software rows and CVEs are externally keyed, so the engine's name-similarity
//   merge never touches them; only KEV product spellings are name-keyed, scoped per vendor,
//   so near-duplicate spellings land in the engine's merge-review band (0.82 to 0.85);
// - the engine never calls a model, and neither does this wrapper.

import fs from "node:fs";
import path from "node:path";
import {
  WorldModel, canonicalJson, entityIdFromName, externalId, normalizeName,
} from "./world-model/reference/src/index.ts";
// The engine's own content-addressed fact id (the key its assertFact dedupes on); read-only use.
import { factId } from "./world-model/reference/src/stableIds.ts";
import type {
  AuditEntry, Entity, Fact, MergeProposal, ObservationRecord, Provenance, Relationship, StoryAggregate,
} from "./world-model/reference/src/index.ts";
import type {
  Decision, EpssScore, Evidence, InventoryRow, KevEntry, KevPair, Mode, PatchLine, Resolution, Tracer,
} from "../contracts.ts";

export const ENGINE_NAME = "world-model" as const;
export const ENGINE_SOURCE =
  "Meterless/Meterless@1742dec engines/world-model/reference (Apache-2.0, vendored unmodified)";
/** The engine's default merge bands (conformance check band-001). */
export const MERGE_BANDS = { autoMergeAt: 0.85, reviewLower: 0.82 } as const;

// ---------------------------------------------------------------- ids and labels

function slug(s: string): string {
  return normalizeName(s).replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "unknown";
}

/** Stable entity ids. Same input, same id, on every machine and every run. */
export const ledgerIds = {
  asset: (assetId: string): string => externalId("asset", "inventory", assetId.trim()),
  software: (rowId: string): string => externalId("software", "inventory", rowId.trim()),
  cve: (cveId: string): string => externalId("cve", "id", cveId.trim().toUpperCase()),
  family: (label: string): string => externalId("kev_family", "normaliser", normalizeName(label)),
  kevProductType: (vendor: string): string => `kev_product/${slug(vendor)}`,
  kevProduct: (vendor: string, product: string): string =>
    entityIdFromName(`kev_product/${slug(vendor)}`, product),
};

export interface SourceLabels { inventory: string; kev: string; epss: string; }

/** Provenance labels for data sources. Sample mode reads the saved snapshot, and says so. */
export function defaultSourceLabels(mode: Mode = "live"): SourceLabels {
  return mode === "sample"
    ? { inventory: "snapshot:el.inventory", kev: "snapshot:el.kev", epss: "snapshot:epss" }
    : { inventory: "zetaris:el.inventory", kev: "zetaris:el.kev", epss: "zetaris:epss" };
}

export const AGENT_SOURCES = {
  jury: "agent:jury",
  critic: "agent:critic",
  normaliser: "agent:normaliser",
  analyst: "agent:analyst",
} as const;

/**
 * Turns a source date into the ISO timestamp the engine stores.
 * Accepts YYYY-MM-DD, the KEV catalogue form YYYY.MM.DD, or a full ISO timestamp.
 * Returns null for anything else (the caller then falls back or refuses the write).
 */
export function sourceDate(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  const m = /^(\d{4})[-.](\d{2})[-.](\d{2})$/.exec(s);
  if (m) {
    const day = `${m[1]}-${m[2]}-${m[3]}`;
    const t = Date.parse(`${day}T00:00:00.000Z`);
    if (Number.isNaN(t) || new Date(t).toISOString().slice(0, 10) !== day) return null;
    return `${day}T00:00:00.000Z`;
  }
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s)) {
    const t = Date.parse(s);
    return Number.isNaN(t) ? null : new Date(t).toISOString();
  }
  return null;
}

// ---------------------------------------------------------------- public types

export interface LedgerDecisionInput {
  row_id: string;
  decision: Decision;
  target_date: string | null;
  verified?: boolean;
  kev?: PatchLine["kev"];
  epss?: PatchLine["epss"];
}

export interface IngestRunInput {
  runId: string;
  /** The run's as-of date (YYYY-MM-DD or ISO). Inventory and agent facts are stamped with it. */
  asOf: string;
  rows: InventoryRow[];
  resolutions?: Resolution[];
  kev?: KevEntry[];
  epss?: EpssScore[];
  decisions?: LedgerDecisionInput[];
  /** Extra KEV spellings to register under their family (e.g. every spelling of a matched family). */
  kevPairs?: KevPair[];
  /** Family of a KEV pair that no resolution names (pass the normaliser's familyOf). */
  familyOf?: (pair: KevPair) => string;
  /** "sample" stamps data facts with snapshot labels instead of zetaris labels. */
  mode?: Mode;
  /** Override data-source labels, e.g. { inventory: "request:inventory" } for inline rows. */
  sources?: Partial<SourceLabels>;
}

export interface IngestRunReport {
  run_id: string;
  as_of: string;
  events_added: number;
  events_by_kind: Record<string, number>;
  entity_upserts: number;
  entity_upserts_skipped: number;
  review_proposals_added: number;
  auto_merges_added: number;
  changed: boolean;
  counts: {
    assets: number; software: number; families: number; kev_products: number; cves: number;
    resolutions: number; kev_entries: number; epss_scores: number; decisions: number;
  };
  warnings: string[];
}

export interface EntityBrief { id: string; type: string; name: string | null; }

export interface ExplainItem {
  entity_id: string;
  predicate: string;
  value: unknown;
  source: string;
  by: string | null;
  at: string;
  run_id: string | null;
  current: boolean;
  fact_id: string;
}

/** Structured context payload for one patch line (AGENTS.md section 8.2: not a pre-rendered string). */
export interface Explanation {
  intent: "explain_patch_line";
  strategy: string;
  selectionReason: string;
  row_id: string;
  software: EntityBrief;
  asset: EntityBrief | null;
  family: (EntityBrief & { aliases: string[] }) | null;
  cves: (EntityBrief & { cited: boolean })[];
  cves_omitted: number;
  items: ExplainItem[];
  sources: string[];
}

export interface BeliefAsOf { value: unknown; source: string; by: string | null; at: string; fact_id: string; }

export interface ReviewItem {
  id: string;
  type: string;
  vendor: string | null;
  left: { id: string; name: string };
  right: { id: string; name: string };
  similarity: number;
  status: MergeProposal["status"];
  reason: string;
  proposed_at: string;
}

export interface AutoMerge { alias_id: string; primary_id: string; reason: string; at: string; }

export interface LedgerStats {
  namespace: string;
  events_total: number;
  entities_total: number;
  entities_by_type: Record<string, number>;
  relationships_total: number;
  relationships_open: number;
  facts_total: number;
  facts_current: number;
  merge_proposals: { pending: number; approved: number; rejected: number };
  auto_merges: number;
  audit_entries: number;
  last_ingest: Pick<IngestRunReport, "run_id" | "as_of" | "events_added" | "entity_upserts_skipped" | "changed"> | null;
}

export interface EngineManifest {
  engine: typeof ENGINE_NAME;
  engine_source: string;
  namespace: string;
  storage: "memory" | "local";
  persist_file: string | null;
  helpers_live: string[];
  helpers_dormant: string[];
}

export interface LedgerWorld {
  readonly namespace: string;
  /** The engine instance itself (for checks and operator tools). Writes should go through ingestRun. */
  readonly model: WorldModel;
  readonly persistFile: string | null;
  ingestRun(input: IngestRunInput): Promise<IngestRunReport>;
  explain(rowId: string, opts?: { history?: boolean; maxCves?: number }): Explanation | null;
  evidence(rowId: string): Evidence[];
  factsAsOf(entityId: string, at: string): Record<string, BeliefAsOf>;
  reviewQueue(opts?: { status?: MergeProposal["status"] | "all" }): ReviewItem[];
  autoMerges(): AutoMerge[];
  auditLines(opts?: { sinceSeq?: number }): string[];
  writeAudit(dir: string, runId: string): string;
  stats(): LedgerStats;
  manifest(): EngineManifest;
  persist(): string | null;
}

export interface CreateLedgerWorldOptions {
  namespace: string;
  /** Directory for the saved world; the file is <persistDir>/.world/<namespace>.json (the engine's own layout). */
  persistDir?: string;
  /**
   * Load the saved world and keep writing through it (engine storage "local").
   * The engine rewrites its whole file on every write, so this is slower; off by default.
   * Each new run records its own facts (one per subject and predicate), so a resumed run costs
   * about 5 s at 80 rows and 150 CVEs, growing with history; re-ingesting the same run costs ~0.
   * For one world per run, use a per-run namespace without resume.
   */
  resume?: boolean;
  /** Optional trace sink: one summary event per ingestRun. */
  tracer?: Tracer;
  /** Clock for the engine's operator actions only (merge approvals). Never used for facts. */
  clock?: () => Date;
  /**
   * Merge bands for name-keyed KEV spellings. Default: the engine's own (auto-merge at 0.85,
   * review from 0.82). On real KEV names the default auto-merges a few distinct products
   * (e.g. "Struts 1" and "Struts 2", 0.875); pass { autoMergeAt: 1.01 } to send every pair
   * at or above 0.82 to the review queue instead. Only spelling entities are affected.
   */
  resolver?: { autoMergeAt?: number; reviewBand?: [number, number] };
}

const WRAPPER_HELPERS = [
  "ingestRun", "explain", "evidence", "factsAsOf", "reviewQueue", "autoMerges",
  "auditLines", "writeAudit", "stats", "persist",
] as const;
type WrapperHelper = (typeof WRAPPER_HELPERS)[number];

/** Engine features we deliberately do not wire (the wired-vs-helper map, AGENTS.md section 8.3). */
const ENGINE_DORMANT = [
  "world-model.engine.ingest (10-step stream pipeline; runs only in verify:engine)",
  "world-model.engine.approveMerge (operator approval; the review queue is shown, not auto-approved)",
  "world-model.engine.view(snapshot).entityAt (returns empty attrs; factsAsOf is used instead)",
];

const NAMESPACE_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const FILE_PART_RE = /[^A-Za-z0-9_.-]+/g;

// ---------------------------------------------------------------- helpers

function sameAttrs(existing: Record<string, unknown>, next: Record<string, unknown>): boolean {
  for (const [k, v] of Object.entries(next)) {
    if (canonicalJson(existing[k]) !== canonicalJson(v)) return false;
  }
  return true;
}

function pairKey(vendor: string, product: string): string {
  return `${normalizeName(vendor)}|${normalizeName(product)}`;
}

function spellingLabel(vendor: string, product: string): string {
  return `${vendor} / ${product}`;
}

function uniqSorted(xs: Iterable<string>): string[] {
  return [...new Set(xs)].sort();
}

function endOfDayIfDate(at: string): string | null {
  const s = at.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    const iso = sourceDate(s);
    return iso ? `${s}T23:59:59.999Z` : null;
  }
  return sourceDate(s);
}

/** Latest fact per predicate, in the engine's most-recent-wins order (ties: later assertion wins). */
function latestPerPredicate(facts: Fact[]): Map<string, Fact> {
  const out = new Map<string, Fact>();
  for (const f of facts) out.set(f.predicate, f); // facts are sorted by assertedAt (stable)
  return out;
}

function resolutionSource(res: Resolution): { kind: string; by: string } {
  const modelJurors = uniqSorted((res.votes ?? []).map((v) => v.juror).filter((j) => j !== "normaliser"));
  if (res.adjudicated_by === "critic") return { kind: AGENT_SOURCES.critic, by: "critic" };
  if (modelJurors.length === 0 || res.adjudicated_by === "rules") {
    return { kind: AGENT_SOURCES.normaliser, by: res.adjudicated_by ?? "normaliser" };
  }
  return { kind: AGENT_SOURCES.jury, by: res.adjudicated_by ?? modelJurors.join("+") };
}

// ---------------------------------------------------------------- factory

export function createLedgerWorld(opts: CreateLedgerWorldOptions): LedgerWorld {
  if (!opts || typeof opts.namespace !== "string" || !NAMESPACE_RE.test(opts.namespace)) {
    throw new Error("createLedgerWorld: namespace must match [A-Za-z0-9][A-Za-z0-9_.-]{0,99}");
  }
  const namespace = opts.namespace;
  const persistDir = opts.persistDir ? path.resolve(opts.persistDir) : null;
  const persistFile = persistDir ? path.join(persistDir, ".world", `${namespace}.json`) : null;
  const storage: "memory" | "local" = persistDir && opts.resume ? "local" : "memory";
  const model = new WorldModel({
    namespace,
    storage,
    ...(storage === "local" && persistDir ? { directory: persistDir } : {}),
    ...(opts.clock ? { clock: opts.clock } : {}),
    ...(opts.resolver ? { resolver: { ...opts.resolver } } : {}),
  });
  const tracer = opts.tracer;
  const emit: Tracer["emit"] = (e) => {
    try {
      tracer?.emit(e);
    } catch {
      // A failing trace sink must never break the engine write path.
    }
  };
  const used = new Set<WrapperHelper>();
  let lastIngest: IngestRunReport | null = null;
  let lock: Promise<unknown> = Promise.resolve();

  const graph = () => model.view("graph");
  const factsAbout = (id: string): Fact[] => model.view("facts").about(id);

  // -------------------------------------------------------------- ingest

  async function ingestRunInner(input: IngestRunInput): Promise<IngestRunReport> {
    if (!input || typeof input.runId !== "string" || input.runId.trim() === "") {
      throw new Error("ingestRun: runId is required");
    }
    const asOf = sourceDate(input.asOf);
    if (!asOf) {
      throw new Error(`ingestRun: asOf must be a source date (YYYY-MM-DD or ISO); got ${JSON.stringify(input.asOf)}. No provenance date, no write.`);
    }
    const runId = input.runId.trim();
    const labels: SourceLabels = { ...defaultSourceLabels(input.mode ?? "live"), ...(input.sources ?? {}) };
    const warnings: string[] = [];
    const eventsBefore = model.events().length;
    const proposalsBefore = model.mergeQueue().length;
    let upserts = 0;
    let skipped = 0;

    // The engine's fact id hashes (about, predicate, value, at, kind, url) but not runId, so the run
    // tag also goes in `url`. Without it, a later run re-asserting a value an earlier run wrote on the
    // same source date would be a silent no-op, and the in-between run's value would stay current.
    const runUrl = `run:${runId}`;
    const prov = (kind: string, at: string, by?: string): Provenance => ({ kind, at, runId, by: by ?? kind, url: runUrl });

    /**
     * Records a fact so that it is the current belief for (about, predicate), unless a fact with a
     * later source date exists (that one rightly stays current; this one joins the history).
     * - A new run's value is a new fact (its own `run:<id>` url), so it wins over same-date facts.
     * - Re-ingesting the same run finds its fact already current: no event.
     * - If this run's fact exists but a same-date write has replaced it since (one run id re-ingested
     *   with a changed input, then the original again), a numbered copy (`run:<id>#2`, ...) is
     *   written so the value is current again; re-ingesting once more is a no-op.
     */
    async function assertBelief(f: { about: string; predicate: string; value: unknown; confidence: number; source: Provenance }): Promise<void> {
      const at = f.source.at instanceof Date ? f.source.at.toISOString() : f.source.at;
      const facts = factsAbout(f.about).filter((x) => x.predicate === f.predicate); // sorted by assertedAt (stable)
      const current = facts.length > 0 ? facts[facts.length - 1] : null;
      const about = current?.about ?? f.about; // the engine resolves aliases; its facts carry the resolved id
      const ids = new Set(facts.map((x) => x.id));
      for (let k = 1; k <= facts.length + 1; k++) {
        const url = k === 1 ? runUrl : `${runUrl}#${k}`;
        const id = factId(about, f.predicate, f.value, at, f.source.kind, url);
        if (!ids.has(id)) {
          await model.assertFact({ ...f, source: { ...f.source, url } });
          return;
        }
        if (current!.id === id || current!.assertedAt > at) return; // already current, or a later-dated belief wins
      }
    }

    async function upsertIfChanged(
      id: string,
      write: { type: string; externalKey?: { system: string; id: string }; name?: string; attrs: Record<string, unknown>; source: Provenance },
      requireName: "alias" | "current" = "alias",
    ): Promise<string> {
      const existing = graph().entity(id);
      if (existing && sameAttrs(existing.attrs, write.attrs)) {
        const nameOk = !write.name
          || (requireName === "current" ? existing.name === write.name : existing.aliases.includes(write.name));
        if (nameOk) {
          skipped++;
          return existing.id;
        }
      }
      const e = await model.upsertEntity(write);
      upserts++;
      return e.id;
    }

    // Malformed records become warnings, never partial writes.
    const hasText = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";
    const valid = <T>(xs: T[] | undefined, ok: (x: T) => boolean, what: string): T[] => {
      const out: T[] = [];
      for (const x of xs ?? []) {
        if (x && ok(x)) out.push(x);
        else warnings.push(`malformed ${what} skipped`);
      }
      return out;
    };
    // Deterministic order, so the same inputs give the same world whatever order they arrive in.
    const rows = dedupeBy(valid(input.rows, (r) => hasText(r.row_id) && hasText(r.asset_id) && typeof r.software === "string", "inventory row"),
      (r) => r.row_id, "row", warnings)
      .sort((a, b) => a.row_id.localeCompare(b.row_id));
    const rowIds = new Set(rows.map((r) => r.row_id));
    const resolutions = dedupeBy(valid(input.resolutions, (r) => hasText(r.row_id) && typeof r.status === "string", "resolution"),
      (r) => r.row_id, "resolution", warnings)
      .sort((a, b) => a.row_id.localeCompare(b.row_id));
    const kev = dedupeBy(valid(input.kev, (k) => hasText(k.cve_id) && hasText(k.vendor) && hasText(k.product), "KEV entry"),
      (k) => k.cve_id.trim().toUpperCase(), "KEV entry", warnings)
      .sort((a, b) => a.cve_id.localeCompare(b.cve_id));
    const epss = dedupeBy(valid(input.epss, (e) => hasText(e.cve_id), "EPSS score"),
      (e) => `${e.cve_id.trim().toUpperCase()}|${e.score_date}`, "EPSS score", warnings)
      .sort((a, b) => a.cve_id.localeCompare(b.cve_id) || String(a.score_date).localeCompare(String(b.score_date)));
    const decisions = dedupeBy(valid(input.decisions, (d) => hasText(d.row_id) && typeof d.decision === "string", "decision"),
      (d) => d.row_id, "decision", warnings)
      .sort((a, b) => a.row_id.localeCompare(b.row_id));

    // 1. Assets and software rows (zetaris:el.inventory, at = as-of date).
    const inv = prov(labels.inventory, asOf);
    const assets = new Map<string, InventoryRow>();
    for (const r of rows) {
      const aid = r.asset_id.trim();
      if (!assets.has(aid)) assets.set(aid, r);
      else if (assets.get(aid)!.internet_facing !== r.internet_facing) {
        warnings.push(`asset ${aid}: rows disagree on internet_facing; the first row's value is kept`);
      }
    }
    for (const [assetId, r] of [...assets.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      await upsertIfChanged(ledgerIds.asset(assetId), {
        type: "asset",
        externalKey: { system: "inventory", id: assetId },
        name: r.asset_name,
        attrs: {
          asset_id: assetId, asset_name: r.asset_name, asset_type: r.asset_type,
          internet_facing: r.internet_facing === true, owner_team: r.owner_team,
        },
        source: inv,
      }, "current");
    }
    for (const r of rows) {
      const swId = await upsertIfChanged(ledgerIds.software(r.row_id), {
        type: "software",
        externalKey: { system: "inventory", id: r.row_id.trim() },
        name: r.software,
        attrs: { row_id: r.row_id, asset_id: r.asset_id, software: r.software },
        source: inv,
      }, "current");
      await model.relate({ from: swId, type: "installed_on", to: ledgerIds.asset(r.asset_id), source: inv });
    }
    for (const assetId of [...assets.keys()].sort()) {
      const onAsset = rows.filter((r) => r.asset_id.trim() === assetId).map((r) => ledgerIds.software(r.row_id)).sort();
      await assertBelief({ about: ledgerIds.asset(assetId), predicate: "runs", value: onAsset, confidence: 1, source: inv });
      await assertBelief({
        about: ledgerIds.asset(assetId), predicate: "internet_facing",
        value: assets.get(assetId)!.internet_facing === true, confidence: 1, source: inv,
      });
    }

    // 2. KEV families and their spellings (grouping by the normaliser, at = as-of date).
    const familyByPair = new Map<string, string>();
    for (const res of resolutions) {
      if (res.status === "matched" && res.vendor && res.product && res.family) {
        familyByPair.set(pairKey(res.vendor, res.product), res.family);
      }
    }
    const familyFor = (p: KevPair): string => {
      const known = familyByPair.get(pairKey(p.vendor, p.product));
      if (known) return known;
      if (input.familyOf) {
        const f = input.familyOf(p);
        if (typeof f === "string" && f.trim()) return f;
      }
      return `${p.vendor.trim()} ${p.product.trim()}`;
    };
    const pairs = new Map<string, KevPair>();
    const addPair = (vendor: string | null, product: string | null) => {
      if (typeof vendor !== "string" || typeof product !== "string" || !vendor.trim() || !product.trim()) return;
      const k = `${vendor}\u0000${product}`; // raw spelling: KEV's own variants are the point
      if (!pairs.has(k)) pairs.set(k, { vendor, product });
    };
    for (const res of resolutions) if (res.status === "matched") addPair(res.vendor, res.product);
    for (const k of kev) addPair(k.vendor, k.product);
    for (const p of input.kevPairs ?? []) addPair(p.vendor, p.product);
    const families = new Map<string, { label: string; spellings: Map<string, KevPair> }>();
    for (const p of pairs.values()) {
      const label = familyFor(p);
      const key = normalizeName(label);
      if (!families.has(key)) families.set(key, { label, spellings: new Map() });
      families.get(key)!.spellings.set(spellingLabel(p.vendor, p.product), p);
    }
    const normaliserProv = prov(AGENT_SOURCES.normaliser, asOf, "normaliser");
    for (const fam of [...families.values()].sort((a, b) => normalizeName(a.label).localeCompare(normalizeName(b.label)))) {
      const familyId = ledgerIds.family(fam.label);
      const spellings = [...fam.spellings.keys()].sort();
      const attrs = {
        family: fam.label,
        vendors: uniqSorted([...fam.spellings.values()].map((p) => p.vendor.trim())),
        kev_spellings: spellings,
      };
      const write = (name: string) => ({
        type: "kev_family", externalKey: { system: "normaliser", id: normalizeName(fam.label) }, name, attrs, source: normaliserProv,
      });
      // Every KEV spelling becomes an engine alias of the family; the family label stays the display name.
      for (const s of spellings) await upsertIfChanged(familyId, write(s), "alias");
      await upsertIfChanged(familyId, write(fam.label), "current");
      // Each spelling is also a name-keyed entity scoped to its vendor, so the engine's resolver
      // compares near-duplicate spellings and queues the 0.82-0.85 band for operator review.
      for (const s of spellings) {
        const p = fam.spellings.get(s)!;
        const type = ledgerIds.kevProductType(p.vendor);
        const spellingId = await upsertIfChanged(entityIdFromName(type, p.product), {
          type, name: p.product, attrs: { vendor: p.vendor.trim() }, source: normaliserProv,
        }, "alias");
        await model.relate({ from: spellingId, type: "spelling_of", to: familyId, source: normaliserProv });
      }
    }

    // 3. Resolutions (agent:jury / agent:critic / agent:normaliser, at = as-of date, with receipt ids).
    for (const res of resolutions) {
      if (!rowIds.has(res.row_id)) {
        warnings.push(`resolution for unknown row ${res.row_id} skipped`);
        continue;
      }
      const { kind, by } = resolutionSource(res);
      const src = prov(kind, asOf, by);
      const matched = res.status === "matched" && !!res.vendor && !!res.product;
      const family = matched ? familyFor({ vendor: res.vendor!, product: res.product! }) : null;
      const swId = ledgerIds.software(res.row_id);
      await assertBelief({
        about: swId,
        predicate: "resolves_to",
        value: {
          status: res.status,
          vendor: res.vendor, product: res.product, family,
          version: res.version, product_type: res.product_type,
          adjudicated_by: res.adjudicated_by,
          votes: (res.votes ?? []).map((v) => ({ juror: v.juror, vendor: v.vendor, product: v.product })),
          receipt_ids: uniqSorted((res.votes ?? []).map((v) => v.receipt_id).filter((x): x is string => typeof x === "string" && x !== "")),
        },
        confidence: Number.isFinite(res.confidence) ? res.confidence : 0.5,
        source: src,
      });
      if (matched && family) {
        await model.relate({ from: swId, type: "resolves_to", to: ledgerIds.family(family), source: src });
      }
    }

    // 4. KEV rows (zetaris:el.kev, at = the catalogue version date).
    for (const k of kev) {
      let at = sourceDate(k.catalog_version) ?? sourceDate(k.date_added);
      if (!at) {
        warnings.push(`KEV ${k.cve_id}: no catalogue or added date; stamped with the run's as-of date`);
        at = asOf;
      }
      const src = prov(labels.kev, at);
      const cveId = await upsertIfChanged(ledgerIds.cve(k.cve_id), {
        type: "cve", externalKey: { system: "id", id: k.cve_id.trim().toUpperCase() }, name: k.cve_id.trim().toUpperCase(),
        attrs: { cve_id: k.cve_id.trim().toUpperCase() }, source: src,
      }, "current");
      const family = familyFor({ vendor: k.vendor, product: k.product });
      await assertBelief({
        about: cveId, predicate: "affects",
        value: { vendor: k.vendor, product: k.product, family }, confidence: 1, source: src,
      });
      await assertBelief({
        about: cveId, predicate: "kev_listing",
        value: {
          date_added: k.date_added, due_date: k.due_date, ransomware_use: k.ransomware_use,
          catalog_version: k.catalog_version,
        },
        confidence: 1, source: src,
      });
      await model.relate({ from: cveId, type: "affects", to: ledgerIds.family(family), source: src });
    }

    // 5. EPSS scores (zetaris:epss, at = score date). A missing score is never written as 0.
    let epssWritten = 0;
    for (const e of epss) {
      if (typeof e.epss !== "number" || !Number.isFinite(e.epss)) {
        warnings.push(`EPSS ${e.cve_id}: no numeric score; not recorded`);
        continue;
      }
      let at = sourceDate(e.score_date);
      if (!at) {
        warnings.push(`EPSS ${e.cve_id}: no score date; stamped with the run's as-of date`);
        at = asOf;
      }
      const src = prov(labels.epss, at);
      const cveId = await upsertIfChanged(ledgerIds.cve(e.cve_id), {
        type: "cve", externalKey: { system: "id", id: e.cve_id.trim().toUpperCase() }, name: e.cve_id.trim().toUpperCase(),
        attrs: { cve_id: e.cve_id.trim().toUpperCase() }, source: src,
      }, "current");
      await assertBelief({
        about: cveId, predicate: "epss",
        value: { epss: e.epss, percentile: Number.isFinite(e.percentile) ? e.percentile : null, score_date: e.score_date },
        confidence: 1, source: src,
      });
      epssWritten++;
    }

    // 6. Decisions (agent:analyst, at = as-of date).
    let decisionsWritten = 0;
    for (const d of decisions) {
      if (!rowIds.has(d.row_id)) {
        warnings.push(`decision for unknown row ${d.row_id} skipped`);
        continue;
      }
      await assertBelief({
        about: ledgerIds.software(d.row_id),
        predicate: "decision",
        value: {
          decision: d.decision,
          target_date: d.target_date,
          verified: typeof d.verified === "boolean" ? d.verified : null,
          kev_cves: uniqSorted((d.kev?.cves ?? []).map((c) => c.cve_id.trim().toUpperCase())),
          kev_earliest_due: d.kev?.earliest_due ?? null,
          epss_max: d.epss ? { cve_id: d.epss.cve_id, epss: d.epss.max } : null,
        },
        confidence: 1,
        source: prov(AGENT_SOURCES.analyst, asOf, "analyst"),
      });
      decisionsWritten++;
    }

    const added = model.events().slice(eventsBefore);
    const byKind: Record<string, number> = {};
    for (const e of added) byKind[e.kind] = (byKind[e.kind] ?? 0) + 1;
    const proposalsAdded = model.mergeQueue().length - proposalsBefore;
    const report: IngestRunReport = {
      run_id: runId,
      as_of: asOf,
      events_added: added.length,
      events_by_kind: byKind,
      entity_upserts: upserts,
      entity_upserts_skipped: skipped,
      review_proposals_added: proposalsAdded,
      auto_merges_added: byKind.alias ?? 0,
      changed: added.length > 0 || proposalsAdded > 0,
      counts: {
        assets: assets.size,
        software: rows.length,
        families: families.size,
        kev_products: pairs.size,
        cves: new Set([...kev.map((k) => k.cve_id.trim().toUpperCase()), ...epss.map((e) => e.cve_id.trim().toUpperCase())]).size,
        resolutions: resolutions.filter((r) => rowIds.has(r.row_id)).length,
        kev_entries: kev.length,
        epss_scores: epssWritten,
        decisions: decisionsWritten,
      },
      warnings,
    };
    lastIngest = report;
    return report;
  }

  function ingestRun(input: IngestRunInput): Promise<IngestRunReport> {
    used.add("ingestRun");
    // One ingest at a time, so the unchanged-entity checks never interleave.
    const next = lock.then(async () => {
      try {
        const report = await ingestRunInner(input);
        emit({
          agent: "world_model",
          action: "ingest_run",
          input_summary: `${report.counts.software} rows, ${report.counts.resolutions} resolutions, `
            + `${report.counts.kev_entries} KEV rows, ${report.counts.epss_scores} EPSS scores, `
            + `${report.counts.decisions} decisions (as of ${report.as_of.slice(0, 10)})`,
          output_summary: `+${report.events_added} engine events; ${report.entity_upserts_skipped} unchanged entities skipped; `
            + `${report.review_proposals_added} merge reviews queued; ${report.auto_merges_added} auto-merges; `
            + `${report.warnings.length} warnings`,
          status: "ok",
          details: {
            engine_source: ENGINE_SOURCE,
            namespace,
            events_by_kind: report.events_by_kind,
            counts: report.counts,
            changed: report.changed,
            warnings: report.warnings.slice(0, 20),
            review_queue: reviewQueueInner("pending").slice(0, 10).map((r) => `${r.left.name} ~ ${r.right.name} (${r.similarity})`),
          },
        });
        return report;
      } catch (err) {
        emit({
          agent: "world_model",
          action: "ingest_run",
          status: "error",
          output_summary: (err as Error).message.slice(0, 300),
        });
        throw err;
      }
    });
    lock = next.catch(() => undefined);
    return next;
  }

  // -------------------------------------------------------------- reads

  function toItems(entityId: string, history: boolean): ExplainItem[] {
    const facts = factsAbout(entityId);
    const current = latestPerPredicate(facts);
    const out: ExplainItem[] = [];
    for (const f of facts) {
      const isCurrent = current.get(f.predicate)?.id === f.id;
      if (!history && !isCurrent) continue;
      out.push({
        entity_id: f.about,
        predicate: f.predicate,
        value: f.value,
        source: f.source.kind,
        by: f.source.by ?? null,
        at: f.assertedAt,
        run_id: f.source.runId ?? null,
        current: isCurrent,
        fact_id: f.id,
      });
    }
    return out;
  }

  function brief(e: Entity): EntityBrief {
    return { id: e.id, type: e.type, name: e.name ?? null };
  }

  function explain(rowId: string, o?: { history?: boolean; maxCves?: number }): Explanation | null {
    used.add("explain");
    const g = graph();
    const sw = g.entity(ledgerIds.software(rowId));
    if (!sw) return null;
    const history = o?.history === true;
    const maxCves = Math.max(0, Math.floor(o?.maxCves ?? 8));
    const swFacts = latestPerPredicate(factsAbout(sw.id));

    const asset = g.neighborsOf(sw.id, { via: "installed_on" }).find((e) => e.type === "asset") ?? null;

    // The current resolves_to fact decides the family (an older open edge never overrides it).
    const res = swFacts.get("resolves_to")?.value as { status?: string; family?: string | null } | undefined;
    const family = res && res.status === "matched" && res.family ? g.entity(ledgerIds.family(res.family)) ?? null : null;

    const decision = swFacts.get("decision")?.value as { kev_cves?: string[] } | undefined;
    const cited = new Set((decision?.kev_cves ?? []).map((c) => ledgerIds.cve(c)));
    const epssOf = (id: string): number => {
      const v = latestPerPredicate(factsAbout(id)).get("epss")?.value as { epss?: number } | undefined;
      return typeof v?.epss === "number" ? v.epss : -1;
    };
    const allCves = family ? g.incoming(family.id, { via: "affects" }).filter((e) => e.type === "cve") : [];
    for (const id of cited) {
      const e = g.entity(id);
      if (e && !allCves.some((c) => c.id === e.id)) allCves.push(e);
    }
    const ranked = allCves
      .map((e) => ({ e, cited: cited.has(e.id), epss: epssOf(e.id) }))
      .sort((a, b) => Number(b.cited) - Number(a.cited) || b.epss - a.epss || b.e.id.localeCompare(a.e.id));
    const chosen = ranked.slice(0, maxCves);

    const items = [
      ...toItems(sw.id, history),
      ...(asset ? toItems(asset.id, history) : []),
      ...chosen.flatMap((c) => toItems(c.e.id, history)),
    ];
    return {
      intent: "explain_patch_line",
      strategy: "graph walk: software -installed_on-> asset; software -resolves_to-> family <-affects- cve",
      selectionReason:
        "facts about this inventory row, its asset, its current KEV family match and the CVEs that KEV lists for "
        + "that family (CVEs cited by the decision first, then by EPSS), current values only unless history is asked",
      row_id: rowId,
      software: brief(sw),
      asset: asset ? brief(asset) : null,
      family: family ? { ...brief(family), aliases: [...family.aliases].sort() } : null,
      cves: chosen.map((c) => ({ ...brief(c.e), cited: c.cited })),
      cves_omitted: Math.max(0, ranked.length - chosen.length),
      items,
      sources: uniqSorted(items.map((i) => i.source)),
    };
  }

  function evidence(rowId: string): Evidence[] {
    used.add("evidence");
    const x = explain(rowId);
    if (!x) return [];
    return x.items.map((i) => {
      const value = canonicalJson(i.value);
      return {
        source: "world_model",
        query: `world_model facts.about(${i.entity_id})`,
        field: `${i.predicate} <- ${i.source}`,
        value: value.length > 300 ? `${value.slice(0, 297)}...` : value,
        as_of: i.at,
        live: false,
      };
    });
  }

  function factsAsOf(entityId: string, at: string): Record<string, BeliefAsOf> {
    used.add("factsAsOf");
    const cutoff = endOfDayIfDate(at);
    if (!cutoff) throw new Error(`factsAsOf: not a date: ${JSON.stringify(at)}`);
    const known = factsAbout(entityId).filter((f) => f.assertedAt <= cutoff);
    const out: Record<string, BeliefAsOf> = {};
    for (const [pred, f] of latestPerPredicate(known)) {
      out[pred] = { value: f.value, source: f.source.kind, by: f.source.by ?? null, at: f.assertedAt, fact_id: f.id };
    }
    return out;
  }

  function reviewQueueInner(status: MergeProposal["status"] | "all"): ReviewItem[] {
    const g = graph();
    return model.mergeQueue()
      .filter((p) => status === "all" || p.status === status)
      .map((p) => {
        const left = g.entity(p.leftId);
        const type = left?.type ?? g.entity(p.rightId)?.type ?? "unknown";
        const vendor = left?.attrs.vendor ?? g.entity(p.rightId)?.attrs.vendor;
        return {
          id: p.id,
          type,
          vendor: typeof vendor === "string" ? vendor : null,
          left: { id: p.leftId, name: p.leftName },
          right: { id: p.rightId, name: p.rightName },
          similarity: Math.round(p.similarity * 1000) / 1000,
          status: p.status,
          reason: p.reason,
          proposed_at: p.proposedAt,
        };
      });
  }

  function reviewQueue(o?: { status?: MergeProposal["status"] | "all" }): ReviewItem[] {
    used.add("reviewQueue");
    return reviewQueueInner(o?.status ?? "pending");
  }

  function autoMerges(): AutoMerge[] {
    used.add("autoMerges");
    return model.events()
      .filter((e) => e.kind === "alias")
      .map((e) => {
        const a = e.payload as { aliasId: string; primaryId: string; reason: string; mergedAt: string };
        return { alias_id: a.aliasId, primary_id: a.primaryId, reason: a.reason, at: a.mergedAt };
      });
  }

  function auditLines(o?: { sinceSeq?: number }): string[] {
    used.add("auditLines");
    const since = o?.sinceSeq ?? 0;
    return model.audit().filter((a: AuditEntry) => a.seq > since).map((a) => canonicalJson(a));
  }

  function writeAudit(dir: string, runId: string): string {
    used.add("writeAudit");
    const safe = String(runId).replace(FILE_PART_RE, "_").slice(0, 120);
    if (!safe || /^\.+$/.test(safe)) throw new Error("writeAudit: runId is required");
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `audit-${safe}.jsonl`);
    const lines = model.audit().map((a) => canonicalJson(a));
    fs.writeFileSync(file, lines.length ? lines.join("\n") + "\n" : "", "utf-8");
    return file;
  }

  function stats(): LedgerStats {
    used.add("stats");
    const shape = model.stateShape() as { entities: Entity[]; relationships: Relationship[]; facts: Fact[] };
    const byType: Record<string, number> = {};
    for (const e of shape.entities) {
      const t = e.type.split("/")[0];
      byType[t] = (byType[t] ?? 0) + 1;
    }
    const currentFacts = new Set<string>();
    const latest = new Map<string, Fact>();
    for (const f of [...shape.facts].sort((a, b) => a.assertedAt.localeCompare(b.assertedAt))) latest.set(`${f.about}|${f.predicate}`, f);
    for (const f of latest.values()) currentFacts.add(f.id);
    const q = model.mergeQueue();
    return {
      namespace,
      events_total: model.events().length,
      entities_total: shape.entities.length,
      entities_by_type: byType,
      relationships_total: shape.relationships.length,
      relationships_open: shape.relationships.filter((r) => !r.validTo).length,
      facts_total: shape.facts.length,
      facts_current: currentFacts.size,
      merge_proposals: {
        pending: q.filter((p) => p.status === "pending").length,
        approved: q.filter((p) => p.status === "approved").length,
        rejected: q.filter((p) => p.status === "rejected").length,
      },
      auto_merges: model.events().filter((e) => e.kind === "alias").length,
      audit_entries: model.audit().length,
      last_ingest: lastIngest
        ? {
          run_id: lastIngest.run_id, as_of: lastIngest.as_of, events_added: lastIngest.events_added,
          entity_upserts_skipped: lastIngest.entity_upserts_skipped, changed: lastIngest.changed,
        }
        : null,
    };
  }

  function persist(): string | null {
    used.add("persist");
    if (!persistFile) return null;
    // In resume mode the engine already writes through on every change.
    if (storage === "local") return fs.existsSync(persistFile) ? persistFile : null;
    const shape = model.stateShape() as { observations: ObservationRecord[]; stories: StoryAggregate[] };
    // Same layout the engine's own "local" storage reads back (reference/src/store.ts).
    const data = {
      events: model.events(),
      audit: model.audit(),
      observations: shape.observations.map((o) => [o.externalId, o]),
      stories: shape.stories.map((s) => [s.id, s]),
      scores: [],
      mergeQueue: model.mergeQueue(),
    };
    fs.mkdirSync(path.dirname(persistFile), { recursive: true });
    const tmp = `${persistFile}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", "utf-8");
    fs.renameSync(tmp, persistFile);
    return persistFile;
  }

  function manifest(): EngineManifest {
    const live = WRAPPER_HELPERS.filter((h) => used.has(h)).map((h) => `world-model.${h}`);
    const dormant = [
      ...WRAPPER_HELPERS.filter((h) => !used.has(h)).map((h) => `world-model.${h}`),
      ...ENGINE_DORMANT,
    ];
    return {
      engine: ENGINE_NAME,
      engine_source: ENGINE_SOURCE,
      namespace,
      storage,
      persist_file: persistFile,
      helpers_live: live,
      helpers_dormant: dormant,
    };
  }

  return {
    namespace,
    model,
    persistFile,
    ingestRun,
    explain,
    evidence,
    factsAsOf,
    reviewQueue,
    autoMerges,
    auditLines,
    writeAudit,
    stats,
    manifest,
    persist,
  };
}

function dedupeBy<T>(xs: T[], key: (x: T) => string, what: string, warnings: string[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const x of xs) {
    const k = key(x);
    if (seen.has(k)) {
      warnings.push(`duplicate ${what} ${k} ignored (first one kept)`);
      continue;
    }
    seen.add(k);
    out.push(x);
  }
  return out;
}
