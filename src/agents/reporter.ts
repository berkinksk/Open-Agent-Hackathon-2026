// Reporter (template only): a "why" of at most two sentences per patch line, written from the line's
// structured facts, the policy and the owner question. It adds no facts of its own. (An optional
// Lightning rephrasing may come later; it must not add facts either.)
import type { OwnerQuestion, PatchLine, Policy } from "../contracts.ts";
import { cleanName } from "../resolve/candidates.ts";
import { epssThreshold } from "../policy/analyst.ts";

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function sentence(s: string): string {
  const t = s.trim();
  return /[.?!]$/.test(t) ? t : `${t}.`;
}

function productName(line: PatchLine): string {
  const r = line.resolution;
  return `${cleanName(r.vendor ?? "")} ${cleanName(r.product ?? "")}`.trim() || "This product";
}

function dueClause(due: string, overdue: number | null): string {
  if (overdue === null) return `is ${due}`;
  if (overdue > 0) return `(${due}) passed ${plural(overdue, "day")} ago`;
  if (overdue === 0) return `(${due}) is today`;
  return `(${due}) is in ${plural(-overdue, "day")}`;
}

function kevSentence(line: PatchLine, outside = 0): string {
  const name = productName(line);
  const cves = line.kev?.cves ?? [];
  const latest = cves[0];
  const out = outside > 0 ? `; NVD places the version outside the ranges of ${plural(outside, "other KEV CVE")}` : "";
  return latest
    ? `${name} is listed in CISA KEV as exploited in the wild: ${plural(cves.length, "cited CVE")}, most recently ${latest.cve_id} (added ${latest.date_added})${out}.`
    : `${name} is listed in CISA KEV as exploited in the wild.`;
}

function dueText(line: PatchLine): string {
  return line.kev?.earliest_due ? `the US federal due date ${dueClause(line.kev.earliest_due, line.kev.overdue_days)}` : "KEV gives no due date";
}

/**
 * A KEV-listed line whose installed version could not be confirmed (no version, or no NVD range settles it): it stays
 * patch_now (fail-closed), and the owner question says what to confirm. `group` names a grouped question (Windows).
 */
export function whyVersionUnconfirmed(line: PatchLine, policy: Policy, opts: { group?: string | null; action?: string | null; outside?: number } = {}): string {
  const action = opts.action ? `${opts.action}; ` : "";
  const ask = opts.group
    ? `the build is unconfirmed, so it stays patch_now and one question covers every ${opts.group} machine`
    : "the version is unconfirmed, so it stays patch_now until you answer the owner question";
  return `${kevSentence(line, opts.outside ?? 0)} Patch by ${line.target_date} under your ${policy.sla_days.patch_now}-day rule (${dueText(line)}): ${action}${ask}.`;
}

const cveKey = (s: string | null | undefined): string => String(s ?? "").trim().toUpperCase();

/**
 * A KEV-listed line whose version NVD places inside the affected range of at least one cited CVE: the "why" leads with
 * that confirmed CVE. The other cited CVEs were not version-checked and are counted fail-closed (see
 * scopeKevToVersion): the "why" says so, and names the CVE the due date or the EPSS comes from when it is one of them.
 * `inside` lists the confirmed CVEs; without it, every cited CVE counts as confirmed.
 */
export function whyConfirmed(
  line: PatchLine, policy: Policy, detail: { version: string | null; outside?: number; inside?: string[] },
): string {
  const name = productName(line);
  const cves = line.kev?.cves ?? [];
  const confirmedIds = new Set((detail.inside ?? cves.map((c) => c.cve_id)).map(cveKey));
  const confirmed = cves.filter((c) => confirmedIds.has(cveKey(c.cve_id)));
  const first = confirmed[0];
  if (!first) return whyFor(line, null, policy);
  const notChecked = cves.length - confirmed.length;
  const what = detail.version ? `${name} ${detail.version}` : `every version of ${name}`;
  const range = confirmed.length === 1
    ? `the affected range of ${first.cve_id}`
    : `the affected ranges of ${plural(confirmed.length, "KEV-listed CVE")}, most recently ${first.cve_id}`;
  const others = [
    notChecked > 0 ? `${plural(notChecked, "other cited KEV CVE")} ${notChecked === 1 ? "is" : "are"} not version-checked, counted fail-closed` : "",
    detail.outside ? `it is outside the ranges of ${plural(detail.outside, "other KEV CVE")}` : "",
  ].filter(Boolean);
  const s1 = `NVD places ${what} inside ${range}, which CISA KEV lists as exploited in the wild (added ${first.date_added})${others.length ? `; ${others.join("; ")}` : ""}.`;
  // which CVE the benchmark date comes from, when it is one counted fail-closed
  const due = line.kev?.earliest_due ?? null;
  const dueCve = due ? confirmed.find((c) => c.due_date === due) ?? cves.find((c) => c.due_date === due) : undefined;
  const dueNote = dueCve && !confirmedIds.has(cveKey(dueCve.cve_id)) ? ` (${dueCve.cve_id}, not version-checked)` : "";
  const e = line.epss;
  const epss = e
    ? `EPSS for ${e.cve_id}${confirmedIds.has(cveKey(e.cve_id)) ? "" : " (not version-checked)"} is ${e.max}${e.max < epssThreshold(line, policy) ? ", low, but the KEV listing decides under your rules" : ""}`
    : "no EPSS score was found";
  return `${s1} Patch by ${line.target_date} under your ${policy.sla_days.patch_now}-day rule; ${dueText(line)}${dueNote}, and ${epss}.`;
}

/** A matched row whose version NVD places outside every KEV-listed CVE of its family. */
export function whyNotAffected(line: PatchLine, policy: Policy, detail: { cves: number; version: string | null }): string {
  const name = productName(line);
  return `KEV lists ${plural(detail.cves, "exploited CVE")} for ${name}, but NVD's version ranges place ${detail.version ? `version ${detail.version}` : "this version"} outside all of them. Review it again by ${line.target_date} (every ${plural(policy.sla_days.monitor_review, "day")} under your rules).`;
}

/** The "why" for one line (at most two sentences). */
export function whyFor(line: PatchLine, owner: OwnerQuestion | null, policy: Policy): string {
  const name = productName(line);
  switch (line.decision) {
    case "patch_now": {
      const cves = line.kev?.cves ?? [];
      const latest = cves[0];
      const s1 = latest
        ? `${name} is listed in CISA KEV as exploited in the wild: ${plural(cves.length, "cited CVE")}, most recently ${latest.cve_id} (added ${latest.date_added}).`
        : `${name} is listed in CISA KEV as exploited in the wild.`;
      const due = line.kev?.earliest_due ? `the US federal due date ${dueClause(line.kev.earliest_due, line.kev.overdue_days)}` : "KEV gives no due date";
      const e = line.epss;
      const epss = e
        ? `EPSS for ${e.cve_id} is ${e.max}${e.max < epssThreshold(line, policy) ? ", low, but the KEV listing decides under your rules" : ""}`
        : "no EPSS score was found";
      return `${s1} Patch by ${line.target_date} under your ${policy.sla_days.patch_now}-day rule; ${due}, and ${epss}.`;
    }
    case "this_cycle": {
      const e = line.epss;
      const thr = epssThreshold(line, policy);
      const s1 = e
        ? `${name} is not in KEV, but ${e.cve_id} has EPSS ${e.max}, at or above your ${thr} threshold${line.internet_facing ? " for internet-facing assets" : ""}.`
        : `${name} is not in KEV, but a CVE for it is above your EPSS threshold.`;
      return `${s1} Patch by ${line.target_date} under your ${policy.sla_days.this_cycle}-day rule.`;
    }
    case "monitor": {
      const s2 = `Review it again by ${line.target_date} (every ${plural(policy.sla_days.monitor_review, "day")} under your rules).`;
      return line.resolution.status === "matched"
        ? `${name} matched this row, but KEV lists no exploited CVE for it. ${s2}`
        : `No CISA KEV product matches "${cleanName(line.software)}". ${s2}`;
    }
    case "ask_owner":
    default:
      return owner ? `${sentence(owner.reason)} ${sentence(owner.question)}` : "This row needs your answer before it can be decided.";
  }
}
