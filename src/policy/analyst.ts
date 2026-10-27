// Exposure Analyst v0: policy as code. Turns one resolved inventory row plus KEV and EPSS facts into a
// decision, a target date and the evidence behind it. The policy is the user's own (config/policy.json,
// overridable per run). The KEV due date is shown only as the US federal benchmark.
//   patch_now  : the row's product family is listed in KEV (whatever the EPSS); target = as_of + sla.patch_now
//   this_cycle : not in KEV, a non-KEV CVE with EPSS >= threshold (needs the NVD product lookup; empty in v0)
//   monitor    : resolved to "no KEV product", nothing above; next review = as_of + sla.monitor_review
//   ask_owner  : unresolved, or a source failed or came back incomplete (fail-closed: nothing is relaxed to monitor)
// v0 does not check version ranges yet (the NVD helper is dormant): a KEV-listed family means patch_now.
import { DEFAULT_POLICY } from "../contracts.ts";
import type {
  Decision, EpssScore, Evidence, InventoryRow, JurorVote, KevEntry, OwnerQuestion, PatchLine, Policy, Resolution,
} from "../contracts.ts";
import { cleanName, familyKey } from "../resolve/candidates.ts";

export const MAX_CITED_KEV = 20;
/** Bucket order of the patch list: an open question may hide a patch_now, so it comes before monitor. */
export const DECISION_ORDER: readonly Decision[] = ["patch_now", "this_cycle", "ask_owner", "monitor"];

// ---------------------------------------------------------------- policy

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

const TOP_KEYS = ["epss_this_cycle", "epss_this_cycle_internet", "rubric_auto_min", "max_critic_rounds", "sla_days"];
const SLA_KEYS = ["patch_now", "this_cycle", "monitor_review"] as const;

function numberField(name: string, v: unknown, min: number, max: number, integer: boolean): number {
  const n = typeof v === "number" ? v : Number.NaN;
  if (!Number.isFinite(n) || n < min || n > max || (integer && !Number.isInteger(n))) {
    throw new PolicyError(`${name} must be ${integer ? "an integer" : "a number"} from ${min} to ${max}`);
  }
  return n;
}

/** Deep-merge a per-run override into a base policy, validating every field. Unknown fields are errors. */
export function mergePolicy(base: Policy = DEFAULT_POLICY, override?: unknown): Policy {
  const out: Policy = { ...base, sla_days: { ...base.sla_days } };
  if (override !== undefined && override !== null) {
    if (typeof override !== "object" || Array.isArray(override)) throw new PolicyError("policy must be an object");
    const o = override as Record<string, unknown>;
    for (const k of Object.keys(o)) if (!TOP_KEYS.includes(k)) throw new PolicyError(`unknown policy field: ${k}`);
    if (o.epss_this_cycle !== undefined) out.epss_this_cycle = numberField("policy.epss_this_cycle", o.epss_this_cycle, 0, 1, false);
    if (o.epss_this_cycle_internet !== undefined) out.epss_this_cycle_internet = numberField("policy.epss_this_cycle_internet", o.epss_this_cycle_internet, 0, 1, false);
    if (o.rubric_auto_min !== undefined) out.rubric_auto_min = numberField("policy.rubric_auto_min", o.rubric_auto_min, 0, 9, false);
    if (o.max_critic_rounds !== undefined) out.max_critic_rounds = numberField("policy.max_critic_rounds", o.max_critic_rounds, 0, 5, true);
    if (o.sla_days !== undefined) {
      if (!o.sla_days || typeof o.sla_days !== "object" || Array.isArray(o.sla_days)) throw new PolicyError("policy.sla_days must be an object");
      const s = o.sla_days as Record<string, unknown>;
      for (const k of Object.keys(s)) if (!(SLA_KEYS as readonly string[]).includes(k)) throw new PolicyError(`unknown policy field: sla_days.${k}`);
      for (const k of SLA_KEYS) if (s[k] !== undefined) out.sla_days[k] = numberField(`policy.sla_days.${k}`, s[k], 0, 3650, true);
    }
  }
  return out;
}

export function epssThreshold(row: Pick<InventoryRow, "internet_facing">, policy: Policy): number {
  return row.internet_facing ? policy.epss_this_cycle_internet : policy.epss_this_cycle;
}

// ---------------------------------------------------------------- dates (UTC calendar days)

const DAY_MS = 86_400_000;

export function isIsoDate(s: unknown): s is string {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const t = Date.parse(`${s}T00:00:00Z`);
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === s;
}

export function addDays(date: string, days: number): string {
  return new Date(Date.parse(`${date}T00:00:00Z`) + days * DAY_MS).toISOString().slice(0, 10);
}

/** Whole days from `from` to `to` (positive when `to` is later). */
export function dayDiff(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY_MS);
}

// ---------------------------------------------------------------- facts helpers

/** The KEV entries a line cites: de-duplicated, most recently added first, at most MAX_CITED_KEV. */
export function citeKev(entries: KevEntry[]): KevEntry[] {
  const seen = new Set<string>();
  const uniq = entries.filter((e) => e && e.cve_id && !seen.has(e.cve_id) && (seen.add(e.cve_id), true));
  return uniq
    .sort((a, b) => (b.date_added ?? "").localeCompare(a.date_added ?? "") || a.cve_id.localeCompare(b.cve_id))
    .slice(0, MAX_CITED_KEV);
}

/** The highest EPSS score (ties: higher percentile, then CVE id). */
export function maxEpss(scores: (EpssScore | undefined)[]): EpssScore | null {
  let best: EpssScore | null = null;
  for (const s of scores) {
    if (!s || !Number.isFinite(s.epss)) continue;
    if (!best || s.epss > best.epss || (s.epss === best.epss && (s.percentile > best.percentile
      || (s.percentile === best.percentile && s.cve_id < best.cve_id)))) best = s;
  }
  return best;
}

// ---------------------------------------------------------------- assessment

export interface AnalystContext {
  asOf: string;                            // YYYY-MM-DD
  policy: Policy;
  live: boolean;                           // facts came from Zetaris (live mode), not the sample snapshot
  inventoryFrom: "zetaris" | "request";
  kevPairsError: string | null;            // KEV names unreadable: nothing could be matched
  kevByFamily: Map<string, KevEntry[]>;    // familyKey(family) -> KEV entries of every spelling
  kevError: string | null;                 // KEV entries unreadable
  catalogVersion: string | null;
  epssByCve: Map<string, EpssScore>;
  epssError: string | null;
  /** Non-KEV CVEs with EPSS per family (NVD product lookup). Absent while that helper is dormant. */
  nonKevByFamily?: Map<string, EpssScore[]>;
}

export interface Assessment { line: PatchLine; owner: OwnerQuestion | null; }

const JUROR_NAMES: Record<JurorVote["juror"], string> = { bolt: "Bolt", lightning: "Lightning", ultra: "Ultra", normaliser: "the normaliser" };

function productLabel(vendor: string | null, product: string | null): string {
  return `${cleanName(vendor ?? "")} ${cleanName(product ?? "")}`.trim();
}

/** One clause of error text: single line, inner sentence breaks turned into semicolons, at most 120 chars. */
function short(s: string): string {
  const one = s.replace(/\s+/g, " ").replace(/[.!?]+\s+/g, "; ").replace(/[.!?]+$/, "").trim();
  return one.length > 120 ? `${one.slice(0, 119)}…` : one;
}

function inventoryEvidence(row: InventoryRow, ctx: AnalystContext): Evidence {
  const fromZetaris = ctx.inventoryFrom === "zetaris";
  return {
    source: fromZetaris ? "zetaris:inventory" : "agent",
    query: fromZetaris ? "inventory" : "run_request.inventory",
    field: "software", value: row.software, as_of: ctx.asOf, live: fromZetaris && ctx.live,
  };
}

function voteEvidence(res: Resolution, ctx: AnalystContext): Evidence[] {
  const ev: Evidence[] = [];
  for (const v of res.votes) {
    if (v.juror === "normaliser") {
      ev.push({ source: "agent", query: "normaliser", field: "vote", value: v.vendor ? productLabel(v.vendor, v.product) : "none", live: false });
    } else if (v.receipt_id) {
      ev.push({ source: "agent", query: v.juror === "ultra" ? "jury.adjudicate" : `jury.${v.juror}`, field: "receipt_id", value: v.receipt_id, live: ctx.live });
    }
  }
  if (res.status !== "unresolved") {
    ev.push({ source: "agent", query: "resolver_jury", field: "resolves_to", value: res.status === "matched" ? productLabel(res.vendor, res.product) : "none", live: ctx.live });
  }
  return ev;
}

function policyEvidence(rule: string): Evidence {
  return { source: "agent", query: "policy", field: "rule", value: rule, live: false };
}

function unresolvedReason(res: Resolution): string {
  if (!res.votes.length) return "No juror gave a valid answer for this row.";
  const said = res.votes.map((v) => `${JUROR_NAMES[v.juror]} chose ${v.vendor ? productLabel(v.vendor, v.product) : "none"}`);
  return `The jury could not settle this row (${said.join("; ")}).`;
}

function unresolvedQuestion(row: InventoryRow, res: Resolution): string {
  const options = [...new Set(res.votes.filter((v) => v.vendor && v.product).map((v) => productLabel(v.vendor, v.product)))];
  return options.length
    ? `Is "${row.software}" on ${row.asset_name} ${options.join(" or ")}, or none of these?`
    : `Which product and version is "${row.software}" on ${row.asset_name}?`;
}

function emptyResolution(row: InventoryRow): Resolution {
  return {
    row_id: row.row_id, status: "unresolved", vendor: null, product: null, family: null, version: null,
    product_type: "unknown", votes: [], adjudicated_by: null, confidence: 0,
  };
}

/** Decide one row. `line.why` is left empty for the reporter. */
export function assessRow(row: InventoryRow, resolution: Resolution | undefined, ctx: AnalystContext): Assessment {
  const res = resolution ?? emptyResolution(row);
  const { policy, asOf } = ctx;
  const ev: Evidence[] = [inventoryEvidence(row, ctx), ...voteEvidence(res, ctx)];
  const base = {
    row_id: row.row_id, asset_id: row.asset_id, asset_name: row.asset_name, internet_facing: row.internet_facing,
    software: row.software, resolution: res, critic: null, verified: false,
    verifier_notes: ["not re-checked live yet: the verifier is not wired into this build"], why: "",
  };
  const ask = (reason: string, question: string): Assessment => ({
    line: { ...base, decision: "ask_owner", target_date: null, kev: null, epss: null, evidence: [...ev, policyEvidence(`ask_owner: ${reason}`)] },
    owner: { row_id: row.row_id, asset_name: row.asset_name, question, reason },
  });

  if (ctx.kevPairsError) {
    return ask(`The KEV catalogue could not be read (${short(ctx.kevPairsError)}), so nothing was relaxed to monitor.`,
      `Please re-run when KEV is reachable, or confirm that "${row.software}" on ${row.asset_name} is fully patched.`);
  }
  if (res.status === "unresolved") return ask(unresolvedReason(res), unresolvedQuestion(row, res));

  const name = productLabel(res.vendor, res.product);
  const fam = familyKey(res.family ?? "");
  if (res.status === "matched") {
    if (ctx.kevError) {
      return ask(`KEV entries for ${name} could not be read (${short(ctx.kevError)}), so nothing was relaxed to monitor.`,
        `Please re-run when KEV is reachable, or check "${row.software}" on ${row.asset_name} against the current KEV list.`);
    }
    const entries = ctx.kevByFamily.get(fam) ?? [];
    if (entries.length) {
      const cited = citeKev(entries);
      const dues = cited.map((e) => e.due_date).filter(isIsoDate).sort();
      const earliest = dues[0] ?? null;
      const top = maxEpss(cited.map((e) => ctx.epssByCve.get(e.cve_id)));
      const threshold = epssThreshold(row, policy);
      for (const e of cited) {
        ev.push({ source: "zetaris:kev", query: "kevByProducts", field: "cve_id", value: e.cve_id, as_of: e.catalog_version || ctx.catalogVersion || undefined, live: ctx.live });
      }
      if (entries.length > cited.length) {
        ev.push({ source: "zetaris:kev", query: "kevByProducts", field: "kev_cve_count", value: `${entries.length} (the ${cited.length} most recent are cited)`, as_of: ctx.catalogVersion ?? undefined, live: ctx.live });
      }
      if (top) ev.push({ source: "zetaris:epss", query: "epss", field: "epss", value: String(top.epss), as_of: top.score_date, live: ctx.live });
      else ev.push({ source: "zetaris:epss", query: "epss", field: "epss", value: ctx.epssError ? `unavailable (${short(ctx.epssError)})` : "no score for the cited CVEs", live: ctx.live });
      ev.push(policyEvidence(`patch_now: listed in KEV, so patch within ${policy.sla_days.patch_now} days whatever the EPSS`));
      if (top && top.epss < threshold) {
        ev.push({ source: "agent", query: "policy", field: "kev_epss_disagreement", value: `KEV lists exploitation; EPSS ${top.epss} is below ${threshold}`, live: false });
      }
      return {
        line: {
          ...base, decision: "patch_now", target_date: addDays(asOf, policy.sla_days.patch_now),
          kev: { cves: cited, earliest_due: earliest, overdue_days: earliest ? dayDiff(earliest, asOf) : null },
          epss: top ? { max: top.epss, cve_id: top.cve_id, percentile: top.percentile } : null,
          evidence: ev,
        },
        owner: null,
      };
    }
    const top = maxEpss(ctx.nonKevByFamily?.get(fam) ?? []);
    const threshold = epssThreshold(row, policy);
    if (top && top.epss >= threshold) {
      ev.push({ source: "zetaris:epss", query: "epss", field: "epss", value: String(top.epss), as_of: top.score_date, live: ctx.live });
      ev.push(policyEvidence(`this_cycle: not in KEV, EPSS ${top.epss} >= ${threshold}${row.internet_facing ? " (internet-facing)" : ""}`));
      return {
        line: {
          ...base, decision: "this_cycle", target_date: addDays(asOf, policy.sla_days.this_cycle), kev: null,
          epss: { max: top.epss, cve_id: top.cve_id, percentile: top.percentile }, evidence: ev,
        },
        owner: null,
      };
    }
    // Every candidate is a KEV name, so a matched family with no KEV entry means the KEV read came back
    // incomplete. Fail closed: never relax such a row to monitor.
    ev.push({ source: "zetaris:kev", query: "kevByProducts", field: "kev_cve_count", value: "0", as_of: ctx.catalogVersion ?? undefined, live: ctx.live });
    return ask(`KEV returned no entry for ${name}, although the KEV catalogue lists that name, so this row was not relaxed to monitor.`,
      `Please re-run, or check "${row.software}" on ${row.asset_name} against the current KEV list for ${name}.`);
  }

  if (ctx.epssError) {
    return ask(`EPSS could not be read (${short(ctx.epssError)}), so this row was not relaxed to monitor.`,
      `Can you confirm that "${row.software}" on ${row.asset_name} runs a supported, fully patched version?`);
  }
  ev.push({ source: "zetaris:kev", query: "kevPairs", field: "match", value: "none", as_of: ctx.catalogVersion ?? undefined, live: ctx.live });
  ev.push(policyEvidence(`monitor: nothing above, so review every ${policy.sla_days.monitor_review} days`));
  return {
    line: {
      ...base, decision: "monitor", target_date: addDays(asOf, policy.sla_days.monitor_review),
      kev: { cves: [], earliest_due: null, overdue_days: null }, epss: null, evidence: ev,
    },
    owner: null,
  };
}

// ---------------------------------------------------------------- version scope (NVD per CVE)

/** One KEV CVE's version check, as the critic reports it (CriticOutcome.cve_status). */
export type CveScopeStatus = "inside" | "outside" | "unchecked";

export interface VersionScopeResult {
  line: PatchLine;
  /** True when the line was rewritten: CVEs NVD places outside dropped, or the not-version-checked ones labelled. */
  changed: boolean;
  /**
   * What the line rests on: "inside" when NVD places the version inside at least one cited CVE (the cited CVEs not
   * version-checked stay cited and count, fail-closed); "unchecked" when none is inside (version unconfirmed).
   */
  basis: "inside" | "unchecked" | null;
  inside: KevEntry[];
  outside: KevEntry[];
  unchecked: KevEntry[];
}

function cveListText(ids: string[], n = 4): string {
  return ids.slice(0, n).join(", ") + (ids.length > n ? ` and ${ids.length - n} more` : "");
}

/**
 * Restricts a KEV-listed line to the KEV CVEs NVD does not rule out for the installed version. The analyst cites every
 * KEV CVE of the family; the critic's NVD check says, per CVE, whether the version is inside its affected range,
 * outside it, or unchecked. Only a CVE NVD places outside is dropped (it stays as evidence, "version not affected").
 * The CVEs NVD places inside and the ones not version-checked stay cited, and the earliest due date, the overdue days
 * and the EPSS come from both (fail-closed, the same rule as the version-unconfirmed ruling): more NVD evidence can
 * only drop a CVE on proof, never make a line less urgent by leaving an unchecked CVE out. The confirmed CVEs are
 * listed first, so the "why" leads with them. When every cited CVE is outside, nothing changes here: that is the
 * "not affected" rule's case. The verifier re-derives the due date from the cited list, so the two stay consistent.
 */
export function scopeKevToVersion(
  line: PatchLine,
  status: Record<string, CveScopeStatus> | undefined,
  ctx: Pick<AnalystContext, "asOf" | "policy" | "epssByCve" | "live" | "catalogVersion"> & { version?: string | null },
  nvdLabel: (cves: string[]) => Pick<Evidence, "live" | "as_of"> = () => ({ live: false }),
): VersionScopeResult {
  const cited = line.kev?.cves ?? [];
  const st = (e: KevEntry): CveScopeStatus => status?.[String(e.cve_id ?? "").trim().toUpperCase()] ?? "unchecked";
  const inside = cited.filter((e) => st(e) === "inside");
  const outside = cited.filter((e) => st(e) === "outside");
  const unchecked = cited.filter((e) => st(e) === "unchecked");
  const same = (basis: VersionScopeResult["basis"]): VersionScopeResult => ({ line, changed: false, basis, inside, outside, unchecked });
  if (!line.kev || !cited.length || !status) return same(null);
  if (!inside.length && !unchecked.length) return same(null);          // every cited CVE outside: the "not affected" rule
  const basisKind: "inside" | "unchecked" = inside.length ? "inside" : "unchecked";
  // nothing to drop and nothing to label: every cited CVE inside, or every one unchecked
  if (!outside.length && (!inside.length || !unchecked.length)) return same(basisKind);

  // the confirmed CVEs first, then the ones counted fail-closed (each group newest first, as cited)
  const basis = [...inside, ...unchecked];
  const droppedIds = new Set(outside.map((e) => e.cve_id));
  const dues = basis.map((e) => e.due_date).filter(isIsoDate).sort();
  const earliest = dues[0] ?? null;
  const top = maxEpss(basis.map((e) => ctx.epssByCve.get(e.cve_id)));
  const threshold = epssThreshold(line, ctx.policy);
  const versionText = ctx.version ? `version ${ctx.version}` : "the installed version";

  let evidence = line.evidence.filter((e) => !(e.source === "zetaris:kev" && e.field === "cve_id" && droppedIds.has(e.value)));
  const epssWasDropped = !!line.epss && droppedIds.has(line.epss.cve_id);
  if (epssWasDropped) {
    evidence = evidence.filter((e) => !(e.source === "zetaris:epss" && e.query === "epss" && e.field === "epss"));
    evidence.push(top
      ? { source: "zetaris:epss", query: "epss", field: "epss", value: String(top.epss), as_of: top.score_date, live: ctx.live }
      : { source: "zetaris:epss", query: "epss", field: "epss", value: "no score for the cited CVEs", live: ctx.live });
  }
  if (line.decision === "patch_now") {
    evidence = evidence.filter((e) => !(e.source === "agent" && e.query === "policy" && e.field === "kev_epss_disagreement"));
    if (top && top.epss < threshold) {
      evidence.push({ source: "agent", query: "policy", field: "kev_epss_disagreement", value: `KEV lists exploitation; EPSS ${top.epss} is below ${threshold}`, live: false });
    }
  }
  if (outside.length) {
    const ids = outside.map((e) => e.cve_id);
    evidence.push({
      source: "zetaris:nvd", query: "nvdCves", field: "kev_cves_version_not_affected",
      value: `NVD places ${versionText} outside the affected ranges of ${outside.length} KEV CVE(s) of the family, so they are not cited: ${cveListText(ids)}`,
      ...nvdLabel(ids),
    });
  }
  if (basisKind === "inside" && unchecked.length) {
    evidence.push({
      source: "zetaris:kev", query: "kevByProducts", field: "kev_cves_not_version_checked",
      value: `${unchecked.length} other cited KEV CVE(s) of the family were not version-checked in this run (not looked up in NVD, or no NVD range places the version); counted fail-closed, they stay cited and count toward the due date, overdue days and EPSS: ${cveListText(unchecked.map((e) => e.cve_id))}`,
      ...(ctx.catalogVersion ? { as_of: ctx.catalogVersion } : {}), live: ctx.live,
    });
  }
  evidence.push({
    source: "agent", query: "exposure_analyst", field: "kev_basis",
    value: basisKind === "inside"
      ? `NVD places ${versionText} inside ${inside.length} cited KEV CVE(s): ${cveListText(inside.map((e) => e.cve_id))}`
        + `${unchecked.length ? `; ${unchecked.length} more cited CVE(s) not version-checked count fail-closed` : ""}`
        + `; the due date, overdue days and EPSS come from these ${basis.length} cited CVE(s)${outside.length ? `, none from the ${outside.length} NVD places it outside` : ""}`
      : `the due date, overdue days and EPSS come from the ${basis.length} KEV CVE(s) not version-checked in this run (NVD places ${versionText} outside the others)`,
    live: false,
  });

  const out: PatchLine = {
    ...line,
    kev: { cves: basis, earliest_due: earliest, overdue_days: earliest ? dayDiff(earliest, ctx.asOf) : null },
    epss: epssWasDropped ? (top ? { max: top.epss, cve_id: top.cve_id, percentile: top.percentile } : null) : line.epss,
    evidence,
  };
  return { line: out, changed: true, basis: basisKind, inside, outside, unchecked };
}

// ---------------------------------------------------------------- ordering

function desc(a: number | null | undefined, b: number | null | undefined): number {
  const x = a ?? null;
  const y = b ?? null;
  if (x === y) return 0;
  if (x === null) return 1;
  if (y === null) return -1;
  return y - x;
}

/** Bucket, then internet-facing first, then most overdue KEV due date, then highest EPSS, then row id. */
export function sortLines(lines: PatchLine[]): PatchLine[] {
  const rank = (d: Decision): number => DECISION_ORDER.indexOf(d);
  return [...lines].sort((a, b) =>
    rank(a.decision) - rank(b.decision)
    || Number(b.internet_facing) - Number(a.internet_facing)
    || desc(a.kev?.overdue_days, b.kev?.overdue_days)
    || desc(a.epss?.max, b.epss?.max)
    || a.row_id.localeCompare(b.row_id, "en", { numeric: true }));
}

export function summarise(lines: PatchLine[]): Record<Decision, number> {
  const s: Record<Decision, number> = { patch_now: 0, this_cycle: 0, monitor: 0, ask_owner: 0 };
  for (const l of lines) s[l.decision]++;
  return s;
}
