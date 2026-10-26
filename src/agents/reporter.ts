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
