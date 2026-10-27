// Builds the injected dependencies for one run (contracts.ts `Deps`).
// live:   Zetaris queries (src/adapters/queries.ts) + the Nightshift LLM (src/adapters/nightshift.ts)
// sample: no LLM, no network; queries come from the sample store (src/sample/queries.ts)
// The sample store is loaded only if present, so this file works while it is being built;
// if it is missing, only sample mode fails, with a clear error.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Clock, Deps, Llm, Mode, Policy, Queries, Tracer } from "./contracts.ts";
import { DEFAULT_POLICY } from "./contracts.ts";
import { ConfigError, REPO_ROOT, checkConfig, describeConfig, isSafeId, loadConfig, newRunId } from "./config.ts";
import { createTracer } from "./trace.ts";
import { ZetarisClient } from "./adapters/zetaris.ts";
import { createZetarisQueries } from "./adapters/queries.ts";
import { createNightshiftLlm } from "./adapters/nightshift.ts";
import { createNvdQueries } from "./adapters/nvd.ts";

export const NIGHTSHIFT_APP_ID = "exposureledger";
export const NIGHTSHIFT_CONCURRENCY = 4;
export const POLICY_FILE = join(REPO_ROOT, "config", "policy.json");

interface SampleModule {
  createSampleQueries(cfg: { tracer: Tracer }): Queries;
}

async function optionalModule<T>(spec: string, file: string): Promise<T | null> {
  try {
    return (await import(spec)) as T;
  } catch (e) {
    const err = e as { code?: string; message?: string };
    if (err?.code === "ERR_MODULE_NOT_FOUND" && String(err.message ?? "").includes(file)) return null;
    throw e;
  }
}

const sampleModule = await optionalModule<SampleModule>("./sample/queries.ts", "sample/queries.ts");

// ---------- policy ----------
type PolicyPatch = Partial<Omit<Policy, "sla_days">> & { sla_days?: Partial<Policy["sla_days"]> };

export function mergePolicy(base: Policy, patch?: PolicyPatch | null): Policy {
  const p = patch ?? {};
  const pick = <K extends keyof Policy>(k: K): Policy[K] => (p[k] === undefined ? base[k] : (p[k] as Policy[K]));
  return {
    epss_this_cycle: pick("epss_this_cycle"),
    epss_this_cycle_internet: pick("epss_this_cycle_internet"),
    sla_days: { ...base.sla_days, ...(p.sla_days ?? {}) },
    rubric_auto_min: pick("rubric_auto_min"),
    max_critic_rounds: pick("max_critic_rounds"),
  };
}

/** Returns a list of problems (empty when the policy is usable). */
export function validatePolicy(p: Policy): string[] {
  const bad: string[] = [];
  const frac = (k: string, v: unknown) => { if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1) bad.push(`${k} must be a number in [0, 1]`); };
  const int = (k: string, v: unknown, lo: number, hi: number) => {
    if (typeof v !== "number" || !Number.isInteger(v) || v < lo || v > hi) bad.push(`${k} must be an integer in [${lo}, ${hi}]`);
  };
  frac("epss_this_cycle", p.epss_this_cycle);
  frac("epss_this_cycle_internet", p.epss_this_cycle_internet);
  int("sla_days.patch_now", p.sla_days?.patch_now, 0, 3650);
  int("sla_days.this_cycle", p.sla_days?.this_cycle, 0, 3650);
  int("sla_days.monitor_review", p.sla_days?.monitor_review, 0, 3650);
  int("rubric_auto_min", p.rubric_auto_min, 0, 9);
  int("max_critic_rounds", p.max_critic_rounds, 0, 5);
  return bad;
}

/** DEFAULT_POLICY <- config/policy.json (if present) <- the per-run patch. Throws ConfigError if invalid. */
export function resolvePolicy(patch?: Partial<Policy> | null, file: string | null = POLICY_FILE): Policy {
  let p = DEFAULT_POLICY;
  if (file && existsSync(file)) {
    let fromFile: PolicyPatch;
    try { fromFile = JSON.parse(readFileSync(file, "utf8")) as PolicyPatch; }
    catch (e) { throw new ConfigError(`policy file ${file} is not valid JSON: ${(e as Error).message}`); }
    p = mergePolicy(p, fromFile);
  }
  p = mergePolicy(p, patch as PolicyPatch | undefined);
  const bad = validatePolicy(p);
  if (bad.length) throw new ConfigError(`invalid policy: ${bad.join("; ")}`, [], bad);
  return p;
}

// ---------- deps ----------
export const systemClock: Clock = { now: () => new Date() };

export interface DepsOverrides {
  env?: Record<string, string | undefined>;
  clock?: Clock;
  llm?: Llm | null;
  queries?: Queries;
  tracer?: Tracer;
  client?: ZetarisClient;       // reuse a connection (its queue is shared per URL anyway)
  logDir?: string;
  stdout?: boolean;
  policyFile?: string | null;   // null = ignore config/policy.json
}

export function makeDeps(opts: { mode: Mode; runId?: string; policy?: Partial<Policy> }, o: DepsOverrides = {}): Deps {
  const env = o.env ?? process.env;
  const cfg = loadConfig(env);
  const mode: Mode = opts.mode === "sample" ? "sample" : "live";
  const runId = opts.runId ?? newRunId();
  if (!isSafeId(runId)) throw new ConfigError("run_id must use only letters, digits, '-' and '_' (max 80 characters)");
  const policy = resolvePolicy(opts.policy, o.policyFile === undefined ? POLICY_FILE : o.policyFile);

  let queries: Queries | undefined = o.queries;
  let llm: Llm | null = o.llm === undefined ? null : o.llm;
  const needZetaris = mode === "live" && !o.queries;
  const needNightshift = mode === "live" && o.llm === undefined;

  if (mode === "live") {
    const c = checkConfig(cfg, "live");
    const relevant = (name: string) =>
      name.startsWith("ZETARIS") ? needZetaris : name.startsWith("METERLESS") ? needNightshift : true;
    const missing = c.missing.filter(relevant);
    const invalid = c.invalid.filter((s) => relevant(s.split(":")[0]));
    if (missing.length || invalid.length) {
      const parts = [missing.length ? `missing: ${missing.join(", ")}` : "", invalid.length ? `invalid: ${invalid.join("; ")}` : ""].filter(Boolean);
      throw new ConfigError(`live mode needs Zetaris and Nightshift settings (${parts.join(" | ")}); set them in .env or use sample mode`, missing, invalid);
    }
  } else if (!queries && !sampleModule) {
    throw new ConfigError("sample mode needs the sample store (src/sample/queries.ts), which is not present yet");
  }

  const tracer = o.tracer ?? createTracer(runId, { dir: o.logDir, stdout: o.stdout });

  if (mode === "live") {
    if (!queries) {
      const client = o.client
        ? o.client.withTracer(tracer)
        : new ZetarisClient({ restUrl: cfg.zetaris.restUrl, orgId: cfg.zetaris.orgId, apiKey: cfg.zetaris.apiKey, tracer });
      // NVD per CVE through Zetaris (rate-limited, cached per day; A3); the rest of the named queries from S1
      const nvd = createNvdQueries({ client, tracer, prefix: cfg.prefix, clock: o.clock ?? systemClock });
      queries = Object.assign(createZetarisQueries({ client, tracer, prefix: cfg.prefix }), {
        nvdCves: nvd.nvdCves, nvdProduct: nvd.nvdProduct, nvdStatus: () => nvd.status(), nvdCached: (id: string) => nvd.cachedCve(id),
      });
    }
    if (needNightshift) {
      llm = createNightshiftLlm({
        baseUrl: cfg.meterless.baseUrl, token: cfg.meterless.token,
        app: NIGHTSHIFT_APP_ID, concurrency: NIGHTSHIFT_CONCURRENCY, tracer,
      });
    }
  } else {
    llm = null; // sample mode never calls a model
    if (!queries) queries = sampleModule!.createSampleQueries({ tracer });
  }

  const d = describeConfig(cfg);
  tracer.emit({
    agent: "Config", action: "deps_ready", status: "ok",
    input_summary: `mode=${mode}`,
    output_summary: `${mode === "live" ? `Zetaris ${d.ZETARIS_REST_URL} (prefix ${cfg.prefix}), Nightshift ${d.METERLESS_BASE_URL}` : "sample store, no LLM, no network"}`,
    details: {
      mode, prefix: cfg.prefix,
      queries: o.queries ? "injected" : mode === "live" ? "zetaris" : "sample",
      llm: o.llm !== undefined ? (o.llm ? "injected" : "none") : mode === "live" ? "nightshift" : "none",
      zetaris_url: mode === "live" ? d.ZETARIS_REST_URL : null,
      meterless_url: mode === "live" ? d.METERLESS_BASE_URL : null,
      policy,
    },
  });

  return { mode, clock: o.clock ?? systemClock, llm, queries: queries!, tracer, policy };
}

/** Whether the optional sample store is present (diagnostics and tests). */
export function sampleStorePresent(): boolean {
  return sampleModule !== null;
}
