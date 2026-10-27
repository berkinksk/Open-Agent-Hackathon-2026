// Default wiring of resolveArm onto the pipeline's fixed cross-module names. The integration step may
// replace any arm through the options. Modules are imported lazily, so a missing module only disables
// the arms that need it.
import type {
  Candidate, Deps, InventoryRow, JurorVote, KevPair, ModelKey, ParsedSoftware, Receipt, RunRequest, RunResponse,
} from "../contracts.ts";
import { runBaseline } from "./baseline.ts";
import { predictionFromResolution } from "./score.ts";
import { ArmUnavailableError } from "./types.ts";
import type { ArmName, ArmOutput, ArmPrediction, ResolveArm } from "./types.ts";

export interface NormaliserModule {
  parseSoftware(raw: string): ParsedSoftware;
  topCandidates(parsed: ParsedSoftware, pairs: KevPair[], k?: number): Candidate[];
  normaliserVote(row: InventoryRow, parsed: ParsedSoftware, cands: Candidate[]): JurorVote;
}
export interface RunModule { run(req: RunRequest, deps: Deps): Promise<RunResponse>; }
export interface JuryItem { row: InventoryRow; parsed: ParsedSoftware; candidates: Candidate[]; }
/** Requested from the jury module: one model's votes with the jury's own prompt and batching. */
export interface JuryModule {
  voteWithModel?(model: ModelKey, items: JuryItem[], deps: Deps): Promise<{ votes: JurorVote[]; receipts: Receipt[] }>;
}

export interface WiringOptions {
  /** A fresh Deps per arm (its own run id and trace file). */
  depsFor: (arm: ArmName) => Deps;
  baselineModel?: ModelKey;
  candidatesPerRow?: number;
  /** Overrides: the integration step can supply any arm directly. */
  singleModel?: (model: ModelKey, rows: InventoryRow[], deps: Deps) => Promise<ArmOutput>;
  full?: (rows: InventoryRow[], deps: Deps) => Promise<ArmOutput>;
  load?: {
    normaliser?: () => Promise<NormaliserModule>;
    run?: () => Promise<RunModule>;
    jury?: () => Promise<JuryModule>;
  };
}

function isModuleNotFound(e: unknown): boolean {
  return Boolean(e && typeof e === "object" && (e as { code?: string }).code === "ERR_MODULE_NOT_FOUND");
}

async function loadOrUnavailable<T>(arm: string, file: string, loader: () => Promise<T>): Promise<T> {
  try {
    return await loader();
  } catch (e) {
    if (isModuleNotFound(e)) throw new ArmUnavailableError(arm, `not wired yet: ${file} is missing`);
    throw e;
  }
}

async function candidatesFor(norm: NormaliserModule, rows: InventoryRow[], deps: Deps, k?: number): Promise<JuryItem[]> {
  const pairs = await deps.queries.kevPairs();
  return rows.map((row) => {
    const parsed = norm.parseSoftware(row.software);
    return { row, parsed, candidates: norm.topCandidates(parsed, pairs, k) };
  });
}

function votesToPredictions(votes: JurorVote[], usedUltra: boolean): ArmPrediction[] {
  return votes.map((v) => ({ row_id: v.row_id, vendor: v.vendor, product: v.product, used_ultra: usedUltra }));
}

export function createResolveArm(opts: WiringOptions): ResolveArm {
  const load = {
    normaliser: opts.load?.normaliser ?? (() => import("../resolve/normalise.ts") as Promise<NormaliserModule>),
    run: opts.load?.run ?? (() => import("../run.ts") as Promise<RunModule>),
    jury: opts.load?.jury ?? (() => import("../agents/jury.ts") as Promise<JuryModule>),
  };
  const k = opts.candidatesPerRow;

  return async (arm: ArmName, rows: InventoryRow[]): Promise<ArmOutput> => {
    const deps = opts.depsFor(arm);
    switch (arm) {
      case "normaliser": {
        const norm = await loadOrUnavailable(arm, "src/resolve/normalise.ts", load.normaliser);
        const items = await candidatesFor(norm, rows, deps, k);
        const votes = items.map((it) => norm.normaliserVote(it.row, it.parsed, it.candidates));
        return { predictions: votesToPredictions(votes, false), receipts: [], notes: ["deterministic; no model calls"] };
      }
      case "baseline": {
        if (!deps.llm) throw new ArmUnavailableError(arm, "no model client (sample mode)");
        const norm = await loadOrUnavailable(arm, "src/resolve/normalise.ts", load.normaliser);
        const items = await candidatesFor(norm, rows, deps, k);
        const all: KevPair[] = items.flatMap((it) => it.candidates.map((c) => ({ vendor: c.vendor, product: c.product })));
        return runBaseline(deps.llm, rows, all, opts.baselineModel ?? "ultra");
      }
      case "bolt":
      case "lightning":
      case "ultra": {
        if (!deps.llm) throw new ArmUnavailableError(arm, "no model client (sample mode)");
        if (opts.singleModel) return opts.singleModel(arm, rows, deps);
        const jury = await loadOrUnavailable(arm, "src/agents/jury.ts", load.jury);
        if (typeof jury.voteWithModel !== "function") {
          throw new ArmUnavailableError(arm, "not wired yet: src/agents/jury.ts exports no voteWithModel(model, items, deps)");
        }
        const norm = await loadOrUnavailable(arm, "src/resolve/normalise.ts", load.normaliser);
        const items = await candidatesFor(norm, rows, deps, k);
        const { votes, receipts } = await jury.voteWithModel(arm, items, deps);
        return {
          predictions: votesToPredictions(votes, arm === "ultra"),
          receipts,
          notes: [`${arm} alone: the jury prompt, no second vote, no critic`],
        };
      }
      case "full": {
        if (opts.full) return opts.full(rows, deps);
        const mod = await loadOrUnavailable(arm, "src/run.ts", load.run);
        const req: RunRequest = { run_id: deps.tracer.run_id, inventory: rows, sample_mode: deps.mode === "sample" };
        const res = await mod.run(req, deps);
        if (res.status === "error") throw new Error(`pipeline error: ${res.error?.message ?? "unknown"}`);
        return {
          // an ask_owner line is an abstention (the match is left to the owner); a KEV-listed line kept at patch_now
          // with only its version unconfirmed is a prediction (the critic's L1 question there is about the version)
          predictions: res.lines.map((l) => {
            const p = predictionFromResolution(l.resolution, null);
            return l.decision === "ask_owner" ? { ...p, vendor: null, product: null, abstained: true } : p;
          }),
          receipts: res.receipts,
          notes: [
            `mode ${res.mode}; its time covers the whole pipeline (Zetaris queries, critic, policy, verifier), not only matching`,
            "an ask_owner line counts as an abstention; a patch_now line whose version is unconfirmed counts as its match",
          ],
        };
      }
      default:
        throw new ArmUnavailableError(String(arm), `unknown arm ${String(arm)}`);
    }
  };
}
