// Fact store for one run: the KEV, EPSS and NVD facts the agents need, fetched once through the named Queries and
// kept in memory. It is the run's single planner of source reads:
// - KEV entries are fetched per product FAMILY (every KEV spelling that names the family, combos included), and indexed
//   under every family an entry names, so "Windows" and "Windows " (trailing space) both land in microsoft:windows.
// - EPSS scores are fetched for the cited CVEs only, in batches of at most 100; a missing score stays missing (never 0).
// - NVD ranges are fetched per CVE, sequentially, inside a per-run time budget (NVD's keyless rate limit makes a cold
//   CVE cost ~12 s); CVEs left over are recorded as skipped, so the critic never loops on them.
// Every failure is recorded (kevError / epssError / nvd states) for the fail-closed rules downstream; nothing throws.
import type { EpssScore, KevEntry, KevPair, NvdRange, Queries, Tracer } from "../contracts.ts";
import { familyKey } from "../resolve/candidates.ts";

export const EPSS_BATCH = 100;

/** What the NVD adapter reports per lookup (src/adapters/nvd.ts NvdLookupStatus), when deps.ts attaches it. */
export interface NvdStatusLike { key: string; state: string; ranges: number; detail?: string; as_of?: string; }
export type QueriesWithNvdStatus = Queries & { nvdStatus?: () => NvdStatusLike[]; nvdCached?: (cveId: string) => boolean };

export type NvdOutcome = "ok" | "cached" | "fallback" | "no_configurations" | "not_found" | "error" | "skipped_budget" | "dormant";
/** The outcomes of a read that went through Zetaris to NVD in this run (not today's cache, not the client's fallback copy). */
const NVD_READ_LIVE: ReadonlySet<NvdOutcome> = new Set<NvdOutcome>(["ok", "no_configurations", "not_found"]);

export interface FactStoreOptions {
  queries: QueriesWithNvdStatus;
  tracer: Tracer;
  pairs: KevPair[];
  /** Every family a KEV pair names (the normaliser's familiesOf); the first one is its own family. */
  familiesOf: (p: KevPair) => string[];
  /** Wraps a source read for the run's timing panel. */
  timed?: <T>(key: string, fn: () => Promise<T>) => Promise<T>;
  /** Wall-time budget for NVD reads in this run (ms). */
  nvdBudgetMs: number;
  /** Hard cap on NVD CVE lookups in this run. */
  nvdMaxCves: number;
  now?: () => number;
}

function msg(e: unknown): string {
  return String((e as Error)?.message ?? e).replace(/\s+/g, " ").trim().slice(0, 300);
}

function chunk<T>(xs: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}

const cveKey = (s: string): string => String(s ?? "").trim().toUpperCase();

export class FactStore {
  kevError: string | null = null;
  epssError: string | null = null;
  /** Set when the NVD helper is not available in this run (sample store without NVD, or no adapter). */
  nvdDormant: string | null = null;
  readonly nvdRanges = new Map<string, NvdRange[]>();
  readonly nvdState = new Map<string, NvdOutcome>();
  /** The day each looked-up CVE's NVD data was read (the adapter's status as_of): today, or the cache day. */
  readonly nvdAsOf = new Map<string, string>();
  /**
   * The per-run budget counter: NVD lookups attempted outside today's cache (failed attempts and the client's fallback
   * copies included), counted against nvdMaxCves. It is not a count of live reads: see nvdCounts().
   */
  nvdAttempts = 0;
  nvdCachedHits = 0;
  nvdMs = 0;

  readonly #o: FactStoreOptions;
  readonly #now: () => number;
  readonly #byFamily = new Map<string, KevEntry[]>();
  readonly #familiesDone = new Set<string>();
  readonly #entries = new Map<string, KevEntry>();
  readonly #epss = new Map<string, EpssScore>();
  readonly #epssAsked = new Set<string>();
  #nvdFirstStart: number | null = null;
  #kevChain: Promise<unknown> = Promise.resolve();
  #nvdChain: Promise<unknown> = Promise.resolve();

  constructor(o: FactStoreOptions) {
    this.#o = o;
    this.#now = o.now ?? (() => performance.now());
  }

  #timed<T>(key: string, fn: () => Promise<T>): Promise<T> {
    return this.#o.timed ? this.#o.timed(key, fn) : fn();
  }

  /** Serialise KEV/EPSS reads (the Zetaris queue is serial anyway; this keeps the bookkeeping simple). */
  #onKevChain<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#kevChain.then(fn, fn);
    this.#kevChain = run.then(() => undefined, () => undefined);
    return run;
  }

  #onNvdChain<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#nvdChain.then(fn, fn);
    this.#nvdChain = run.then(() => undefined, () => undefined);
    return run;
  }

  /** The KEV spellings that name a family (as its own family or a later product of a combo). */
  pairsFor(family: string): KevPair[] {
    const k = familyKey(family);
    return this.#o.pairs.filter((p) => this.#o.familiesOf(p).some((f) => familyKey(f) === k));
  }

  /** Fetch the KEV entries of these families (once each). A failed read sets kevError (fail closed downstream). */
  ensureFamilies(families: string[], why = "matched families"): Promise<void> {
    return this.#onKevChain(async () => {
      const todo = [...new Set(families.map(familyKey))].filter((f) => f && !this.#familiesDone.has(f));
      if (!todo.length || this.kevError) return;
      const wanted = new Map<string, KevPair>();
      for (const f of todo) for (const p of this.pairsFor(f)) wanted.set(`${p.vendor}\u0000${p.product}`, p);
      let got: KevEntry[] = [];
      if (wanted.size) {
        try {
          got = await this.#timed("facts", () => this.#o.queries.kevByProducts([...wanted.values()]));
        } catch (e) {
          this.kevError = msg(e);
        }
      }
      if (!this.kevError) {
        for (const f of todo) this.#familiesDone.add(f);
        for (const e of got) this.#addEntry(e);
      }
      this.#o.tracer.emit({
        agent: "exposure_analyst", action: "kev_lookup", status: this.kevError ? "error" : "ok",
        input_summary: `${wanted.size} KEV spelling(s) for ${todo.length} famil${todo.length === 1 ? "y" : "ies"} (${why})`,
        output_summary: this.kevError ? `KEV entries unavailable (${this.kevError}); matched rows fail closed` : `${got.length} KEV entries`,
        details: { families: todo },
      });
    });
  }

  #addEntry(e: KevEntry): void {
    const id = `${cveKey(e.cve_id)}|${e.vendor}|${e.product}`;
    if (this.#entries.has(id)) return;
    this.#entries.set(id, e);
    for (const f of new Set(this.#o.familiesOf(e).map(familyKey))) {
      const list = this.#byFamily.get(f);
      if (list) list.push(e); else this.#byFamily.set(f, [e]);
    }
  }

  /** Every KEV entry of a family (all spellings). */
  entries(family: string | null | undefined): KevEntry[] {
    return family ? this.#byFamily.get(familyKey(family)) ?? [] : [];
  }

  /** familyKey -> entries, for the analyst. */
  kevByFamily(): Map<string, KevEntry[]> {
    return this.#byFamily;
  }

  allEntries(): KevEntry[] {
    return [...this.#entries.values()];
  }

  catalogVersion(): string | null {
    for (const e of this.#entries.values()) if (e.catalog_version) return e.catalog_version;
    return null;
  }

  /** Fetch EPSS for these CVEs (once each, <= 100 per batch). A failed read sets epssError. */
  ensureEpss(cves: string[]): Promise<void> {
    return this.#onKevChain(async () => {
      const todo = [...new Set(cves.map(cveKey))].filter((c) => c && !this.#epssAsked.has(c)).sort();
      if (!todo.length || this.epssError) return;
      let n = 0;
      try {
        for (const batch of chunk(todo, EPSS_BATCH)) {
          const got = await this.#timed("facts", () => this.#o.queries.epss(batch));
          for (const s of got) {
            const score: EpssScore = { cve_id: cveKey(s?.cve_id ?? ""), epss: Number(s?.epss), percentile: Number(s?.percentile), score_date: String(s?.score_date ?? "") };
            if (!score.cve_id || !Number.isFinite(score.epss)) continue;
            const prev = this.#epss.get(score.cve_id);
            if (!prev || score.score_date > prev.score_date) this.#epss.set(score.cve_id, score);
            n++;
          }
          for (const c of batch) this.#epssAsked.add(c);
        }
      } catch (e) {
        this.epssError = msg(e);
      }
      this.#o.tracer.emit({
        agent: "exposure_analyst", action: "epss_lookup", status: this.epssError ? "error" : "ok",
        input_summary: `${todo.length} cited CVE(s) in ${Math.ceil(todo.length / EPSS_BATCH)} batch(es)`,
        output_summary: this.epssError ? `EPSS unavailable (${this.epssError}); nothing is relaxed to monitor` : `${n} EPSS score(s)`,
      });
    });
  }

  epssIndex(): Map<string, EpssScore> {
    return this.#epss;
  }

  epssScores(): EpssScore[] {
    return [...this.#epss.values()];
  }

  /** Was this CVE looked up in NVD (whatever the result)? */
  nvdLooked(cve: string): boolean {
    const s = this.nvdState.get(cveKey(cve));
    return s === "ok" || s === "cached" || s === "fallback" || s === "no_configurations" || s === "not_found";
  }

  /**
   * Was this CVE's NVD record read live through Zetaris in this run? False for today's cache, the client's fallback
   * copy and every CVE not looked up: such evidence is never labelled live.
   */
  nvdLive(cve: string): boolean {
    const s = this.nvdState.get(cveKey(cve));
    return s !== undefined && NVD_READ_LIVE.has(s);
  }

  /**
   * The run's NVD counts for the trace. live_reads = CVEs read through Zetaris to NVD in this run (states ok,
   * no_configurations, not_found), and only in live mode: a sample run reads the snapshot, so it is always 0.
   * attempts is the budget counter; errors, fallback (the client's saved copy), cached (today's cache), skipped (budget)
   * and dormant are counted apart.
   */
  nvdCounts(live: boolean): { live_reads: number; attempts: number; errors: number; fallback: number; cached: number; skipped: number; dormant: number } {
    const states = [...this.nvdState.values()];
    const n = (s: NvdOutcome): number => states.filter((x) => x === s).length;
    return {
      live_reads: live ? states.filter((x) => NVD_READ_LIVE.has(x)).length : 0,
      attempts: this.nvdAttempts, errors: n("error"), fallback: n("fallback"), cached: n("cached"), skipped: n("skipped_budget"), dormant: n("dormant"),
    };
  }

  /** Was this CVE given up on (budget spent, helper dormant or a failed lookup)? Never asked for again. */
  nvdGivenUp(cve: string): boolean {
    const s = this.nvdState.get(cveKey(cve));
    return s === "error" || s === "skipped_budget" || s === "dormant";
  }

  /** The ranges of the looked-up CVEs among these. */
  rangesFor(cves: string[]): NvdRange[] {
    return cves.flatMap((c) => this.nvdRanges.get(cveKey(c)) ?? []);
  }

  budgetLeftMs(): number {
    if (this.#nvdFirstStart === null) return this.#o.nvdBudgetMs;
    return this.#o.nvdBudgetMs - (this.#now() - this.#nvdFirstStart);
  }

  /**
   * Look these CVEs up in NVD, in the given order, one at a time, while the run's NVD budget lasts. CVEs that do not
   * fit are marked skipped_budget. Returns the CVEs looked up now.
   */
  ensureNvd(cves: string[], why: string): Promise<string[]> {
    return this.#onNvdChain(async () => {
      const todo = [...new Set(cves.map(cveKey))].filter((c) => c && !this.nvdState.has(c));
      if (!todo.length) return [];
      const done: string[] = [];
      const skipped: string[] = [];
      for (const cve of todo) {
        if (this.nvdDormant) { this.nvdState.set(cve, "dormant"); skipped.push(cve); continue; }
        // today's cache costs no NVD request, so it never counts against the budget or the cap
        const cached = this.#o.queries.nvdCached?.(cve) === true;
        if (!cached && (this.nvdAttempts >= this.#o.nvdMaxCves || this.budgetLeftMs() <= 0)) { this.nvdState.set(cve, "skipped_budget"); skipped.push(cve); continue; }
        if (!cached && this.#nvdFirstStart === null) this.#nvdFirstStart = this.#now();
        const t0 = this.#now();
        try {
          const ranges = await this.#timed("nvd", () => this.#o.queries.nvdCves([cve]));
          const st = this.#o.queries.nvdStatus?.().filter((s) => cveKey(s.key) === cve).pop();
          const state = (st?.state ?? "ok") as NvdOutcome;
          const known: NvdOutcome[] = ["ok", "cached", "fallback", "no_configurations", "not_found", "error"];
          this.nvdState.set(cve, known.includes(state) ? state : "error");
          if (st?.as_of) this.nvdAsOf.set(cve, st.as_of);
          if (state === "cached") this.nvdCachedHits++; else this.nvdAttempts++;
          if (state !== "error") {
            this.nvdRanges.set(cve, ranges.filter((r) => cveKey(r.cve_id) === cve));
            done.push(cve);
          }
        } catch (e) {
          if (/^dormant\b/i.test(msg(e))) {
            this.nvdDormant = msg(e);
            this.nvdState.set(cve, "dormant");
          } else {
            this.nvdAttempts++;
            this.nvdState.set(cve, "error");
          }
          skipped.push(cve);
        } finally {
          this.nvdMs += Math.round(this.#now() - t0);
        }
      }
      this.#o.tracer.emit({
        agent: "exposure_analyst", action: "nvd_lookup",
        status: this.nvdDormant ? "fallback" : skipped.length && !done.length ? "fallback" : "ok",
        input_summary: `${todo.length} CVE(s): ${why}`,
        output_summary: this.nvdDormant
          ? `NVD helper dormant (${this.nvdDormant}); version ranges not checked`
          : `${done.length} looked up (${this.rangesFor(done).length} version range(s)); ${skipped.length} not looked up${skipped.length ? " (budget or error)" : ""}; NVD time so far ${Math.round(this.nvdMs / 100) / 10} s`,
        details: {
          looked_up: done.map((c) => ({ cve_id: c, state: this.nvdState.get(c), ranges: (this.nvdRanges.get(c) ?? []).length, as_of: this.nvdAsOf.get(c) ?? null })),
          not_looked_up: skipped.map((c) => ({ cve_id: c, state: this.nvdState.get(c) })),
          budget_left_ms: Math.max(0, Math.round(this.budgetLeftMs())),
        },
      });
      return done;
    });
  }

  /** Wait for every pending read. */
  async settle(): Promise<void> {
    await Promise.all([this.#kevChain, this.#nvdChain]);
  }
}
