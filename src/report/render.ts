// Static HTML report for one run.
// Pure: the same RunResponse (and optional trace) always gives the same HTML. No clock, no IO.
// Self-contained: inline CSS only, no scripts, no external assets, so it works offline.
// Every value taken from the run goes through esc(); the page also carries a CSP that forbids scripts.
// It renders only what the run JSON (and trace) contains. Derived values (counts, sums, the
// KEV-vs-EPSS disagreement flag, the autonomy level from the critic's verdict, the rubric-vs-threshold
// note) are computed from those fields only.

import { MODELS } from "../contracts.ts";
import type {
  CriticVerdict, Decision, Evidence, JurorVote, KevEntry, PatchLine, Policy, Receipt,
  RunResponse, TraceEvent,
} from "../contracts.ts";

export interface RenderOptions {
  /** Events of logs/trace-<run_id>.jsonl. Adds the critic timeline, Zetaris query times and the full timeline. */
  trace?: TraceEvent[];
  /** Cap for the full timeline table (default 400). */
  maxTimelineEvents?: number;
}

const DECISIONS: Decision[] = ["patch_now", "this_cycle", "monitor", "ask_owner"];
const DECISION_LABEL: Record<Decision, string> = {
  patch_now: "Patch now", this_cycle: "This cycle", monitor: "Monitor", ask_owner: "Ask owner",
};
const DASH = "—";

// ---------- text safety ----------

// Defence in depth: credential-shaped strings are masked even if a caller passes one in.
const CREDENTIAL_PATTERNS: RegExp[] = [
  /\b(?:nvapi|sk)-[A-Za-z0-9_-]{12,}/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi,
];
export function maskCredentials(s: string): string {
  let out = s;
  for (const re of CREDENTIAL_PATTERNS) out = out.replace(re, "[masked]");
  return out;
}

const ENTITIES: Record<string, string> = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;",
};
/** Escapes any value for use in HTML text or a quoted attribute. null/undefined become "". */
export function esc(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = typeof v === "object" ? safeJson(v) : String(v);
  return maskCredentials(s).replace(/[&<>"'`]/g, (ch) => ENTITIES[ch] ?? ch);
}

function safeJson(v: unknown): string {
  try { return JSON.stringify(v) ?? ""; } catch { return "[unserialisable]"; }
}

/** An id/fragment built only from [A-Za-z0-9_-]. */
function aid(prefix: string, raw: unknown): string {
  return `${prefix}-${String(raw ?? "").replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 120)}`;
}

// ---------- number and value formatting (formatting only; never invents a value) ----------

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
function fmtMs(v: unknown): string {
  const n = num(v);
  if (n === null) return DASH;
  if (n < 1000) return `${Math.round(n)} ms`;
  return `${(n / 1000).toFixed(n < 10000 ? 2 : 1)} s`;
}
function fmtProb(v: unknown): string {
  const n = num(v);
  if (n === null) return DASH;
  if (n === 0) return "0";
  // never round a probability below 1 up to "1" (EPSS 0.99999 is not certainty)
  if (n < 1 && Number(n.toFixed(3)) >= 1) return String(Number(n.toFixed(5)));
  if (Math.abs(n) >= 0.001) return String(Number(n.toFixed(3))); // 0.1 -> "0.1", 0.0131 -> "0.013"
  return String(Number(n.toPrecision(2)));
}
function fmtPercentile(v: unknown): string {
  const n = num(v);
  if (n === null) return DASH;
  return (Math.floor(n * 1000) / 10).toFixed(1); // floor, so 0.99999 never shows as 100.0
}
function fmtConf(v: unknown): string {
  const n = num(v);
  return n === null ? DASH : n.toFixed(2);
}
function txt(v: unknown): string {
  return v === null || v === undefined || v === "" ? DASH : esc(v);
}
function plural(n: number, one: string, many: string = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
function arr<T>(v: T[] | null | undefined): T[] {
  return Array.isArray(v) ? v.filter((x) => x !== null && x !== undefined) : [];
}
/** Array elements that are objects (drops null, primitives and nested arrays from a malformed run JSON). */
function objs<T>(v: T[] | null | undefined): T[] {
  return Array.isArray(v) ? v.filter((x) => x !== null && typeof x === "object" && !Array.isArray(x)) : [];
}

// ---------- small building blocks ----------

function badge(text: string, cls: string, title?: string): string {
  return `<span class="badge ${cls}"${title ? ` title="${esc(title)}"` : ""}>${esc(text)}</span>`;
}
function decisionPill(d: unknown): string {
  const known = DECISIONS.includes(d as Decision);
  const label = known ? DECISION_LABEL[d as Decision] : String(d ?? "unknown");
  return `<span class="pill ${known ? `d-${d}` : "d-other"}">${esc(label)}</span>`;
}
function modelName(id: unknown): string {
  const s = String(id ?? "");
  if (s === MODELS.bolt || s === "bolt" || /bolt/i.test(s)) return "Bolt";
  if (s === MODELS.lightning || s === "lightning" || /lightning/i.test(s)) return "Lightning";
  if (s === MODELS.ultra || s === "ultra" || /ultra/i.test(s)) return "Ultra";
  if (s === "normaliser") return "Normaliser";
  return s || DASH;
}
function isUltraReceipt(r: Receipt): boolean {
  return modelName(r.requested_model) === "Ultra" || modelName(r.routed_model) === "Ultra";
}
function section(id: string, title: string, body: string, lead?: string): string {
  return `<section id="${id}" class="card"><h2>${esc(title)}</h2>${lead ? `<p class="lead">${lead}</p>` : ""}${body}</section>`;
}
function table(head: string[], rows: string[], cls = ""): string {
  return `<div class="scroll"><table class="${cls}"><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

// ---------- derived flags ----------

function kevCves(l: PatchLine): KevEntry[] {
  return objs(l.kev?.cves);
}
function epssThreshold(l: PatchLine, policy: Policy | null): number | null {
  if (!policy) return null;
  return num(l.internet_facing ? policy.epss_this_cycle_internet : policy.epss_this_cycle);
}
/** KEV says "exploited in the wild" while EPSS is below the user's own threshold. */
function kevEpssDisagree(l: PatchLine, policy: Policy | null): { epss: number; threshold: number } | null {
  const epss = num(l.epss?.max);
  const threshold = epssThreshold(l, policy);
  if (kevCves(l).length === 0 || epss === null || threshold === null) return null;
  return epss < threshold ? { epss, threshold } : null;
}
/**
 * The autonomy level as the critic defines it (src/agents/critic.ts): ask_owner is L1 (a human confirms);
 * approve and send_back are L2 (the loop runs on, with stops). It follows the verdict, never the rubric:
 * an ask_owner can carry a high rubric (Ultra's verdict, or a blocker after max_critic_rounds), and a
 * send_back a low one. An unknown verdict gets no level.
 */
function autonomy(verdict: unknown): string {
  if (verdict === "ask_owner") return "L1 · ask owner";
  if (verdict === "approve" || verdict === "send_back") return "L2 · auto";
  return "";
}
/** The rubric against the user's threshold, kept as separate text: one input to the verdict, not the autonomy level. */
function belowThreshold(total: unknown, policy: Policy | null): string {
  const t = num(total);
  const min = num(policy?.rubric_auto_min);
  return t !== null && min !== null && t < min ? `below your ${min}/9 threshold` : "";
}
function rubricText(c: CriticVerdict | null | undefined): string {
  const t = num(c?.rubric?.total);
  return t === null ? DASH : `${t}/9`;
}
function juryVotes(l: PatchLine): JurorVote[] {
  return objs(l.resolution?.votes);
}
function jurySplit(l: PatchLine): boolean {
  const key = (v: JurorVote) => `${v.vendor ?? ""}|${v.product ?? ""}`.toLowerCase().trim();
  const models = juryVotes(l).filter((v) => v.juror === "bolt" || v.juror === "lightning");
  return models.length >= 2 && new Set(models.map(key)).size > 1;
}

// ---------- header ----------

function snapshotDates(resp: RunResponse): string[] {
  const dates = objs(resp.manifest?.sources).map((s) => s?.as_of).filter((d): d is string => typeof d === "string" && d !== "");
  return [...new Set(dates)].sort();
}

function header(resp: RunResponse): string {
  const sample = resp.mode === "sample";
  const started = Date.parse(String(resp.started_at ?? ""));
  const finished = Date.parse(String(resp.finished_at ?? ""));
  const wall = Number.isFinite(started) && Number.isFinite(finished) && finished >= started ? finished - started : null;
  const meta: [string, string][] = [
    ["Run ID", `<span class="mono">${txt(resp.run_id)}</span>`],
    ["As of", txt(resp.as_of)],
    ["Started", `<span class="mono">${txt(resp.started_at)}</span>`],
    ["Finished", `<span class="mono">${txt(resp.finished_at)}</span>`],
    ["Run time", fmtMs(wall)],
    ["Status", badge(String(resp.status ?? "unknown"), `st-${["success", "partial", "error"].includes(String(resp.status)) ? resp.status : "other"}`)],
  ];
  const dates = snapshotDates(resp);
  const modeBanner = sample
    ? `<div class="banner sample" id="mode-banner"><strong>SAMPLE MODE</strong> · deterministic offline run on a data snapshot${
        dates.length ? ` · snapshot captured <strong>${dates.map(esc).join(", ")}</strong>` : ` · snapshot date not recorded in this run`
      } · model calls in this run: ${objs(resp.receipts).length}</div>`
    : `<div class="banner live" id="mode-banner"><strong>LIVE MODE</strong> · sources flagged live below were read at run time</div>`;
  const err = resp.error
    ? `<div class="banner error" role="alert"><strong>Run error:</strong> ${esc(resp.error.type)} · ${esc(resp.error.message)} · ${resp.error.recoverable ? "recoverable" : "not recoverable"}</div>`
    : resp.status === "partial"
      ? `<div class="banner warn" role="status"><strong>Partial run:</strong> some steps did not complete. Lines below show what was decided; check the notes on each line.</div>`
      : "";
  return `<header class="top">
<div class="brand"><h1>ExposureLedger <span class="thin">patch list</span></h1><p class="tag">What do I patch first, and by when?</p></div>
<dl class="meta">${meta.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join("")}</dl>
</header>${modeBanner}${err}`;
}

function nav(): string {
  const items: [string, string][] = [
    ["summary", "Summary"], ["patch-list", "Patch list"], ["owner-questions", "Owner questions"], ["sources", "Sources and rules"],
    ["models", "Models at work"], ["critic", "Critic"], ["timing", "Timing"], ["run-details", "Run details"],
  ];
  return `<nav class="nav">${items.map(([id, t]) => `<a href="#${id}">${esc(t)}</a>`).join("")}</nav>`;
}

// ---------- summary, sources and rules ----------

function summarySection(resp: RunResponse, lines: PatchLine[], policy: Policy | null): string {
  const chips = DECISIONS.map((d) => {
    const given = num((resp.summary as Record<string, unknown> | undefined)?.[d]);
    const n = given ?? lines.filter((l) => l.decision === d).length;
    const inner = `<span class="chip-n">${n}</span><span class="chip-l">${esc(DECISION_LABEL[d])}</span>`;
    return n > 0 ? `<a class="chip d-${d}" href="#bucket-${d}">${inner}</a>` : `<span class="chip d-${d} zero">${inner}</span>`;
  }).join("");
  const inet = lines.filter((l) => l.decision === "patch_now" && l.internet_facing).length;
  const overdue = lines.filter((l) => (num(l.kev?.overdue_days) ?? 0) > 0).length;
  const verified = lines.filter((l) => l.verified === true && !nothingToRecheck(l)).length;
  const nothing = lines.filter((l) => nothingToRecheck(l)).length;
  const disagree = lines.filter((l) => kevEpssDisagree(l, policy) !== null).length;
  const stats = [
    `${plural(lines.length, "line")} · ${verified} verified${nothing ? ` · ${nothing} with nothing to re-check` : ""}`,
    `${inet} patch-now ${inet === 1 ? "line is" : "lines are"} internet-facing`,
    `${plural(overdue, "line")} past the US federal KEV benchmark`,
    disagree ? `${plural(disagree, "line")} where KEV and EPSS disagree (KEV wins under your rules)` : "",
  ].filter(Boolean);
  return `<section id="summary" class="card"><div class="chips">${chips}</div><ul class="stats">${stats.map((s) => `<li>${esc(s)}</li>`).join("")}</ul></section>`;
}

function sourcesAndRules(resp: RunResponse, policy: Policy | null): string {
  const sample = resp.mode === "sample";
  const sources = objs(resp.manifest?.sources);
  const srcRows = sources.map((s) => `<tr><td>${txt(s?.name)}</td><td class="mono">${txt(s?.object)}</td><td class="nw">${
    s?.live ? badge("live", "live") : badge(sample ? "snapshot" : "not live (cache)", "notlive")
  }</td><td class="nw">${txt(s?.as_of)}</td></tr>`);
  const srcTable = sources.length
    ? table(["Source", "Object", "Read", "As of"], srcRows, "compact")
    : `<p class="empty">No sources recorded in the run manifest.</p>`;
  let rules = `<p class="empty">No policy recorded in the run manifest.</p>`;
  if (policy) {
    const sla = policy.sla_days ?? ({} as Policy["sla_days"]);
    rules = `<ul class="rules">
<li>${decisionPill("patch_now")} the installed version is affected by a CVE listed in CISA KEV, whatever the EPSS score. Target: run date + ${txt(sla.patch_now)} days. The KEV due date is shown as the US federal benchmark.</li>
<li>${decisionPill("this_cycle")} affected by a CVE not in KEV with EPSS ≥ ${esc(fmtProb(policy.epss_this_cycle))} (≥ ${esc(fmtProb(policy.epss_this_cycle_internet))} if internet-facing). Target: run date + ${txt(sla.this_cycle)} days.</li>
<li>${decisionPill("monitor")} matched, with nothing above. Next review: run date + ${txt(sla.monitor_review)} days.</li>
<li>${decisionPill("ask_owner")} unresolved, a type conflict, a missing version, or a critic score below ${txt(policy.rubric_auto_min)}/9 (autonomy L1). The critic sends a match back at most ${txt(policy.max_critic_rounds)} times first.</li>
</ul>`;
  }
  return `<section id="sources" class="card split">
<div><h2>Sources</h2>${srcTable}</div>
<div><h2>Your rules</h2><p class="lead">The policy is yours and configurable; these are the values this run used.</p>${rules}</div>
</section>`;
}

// ---------- patch list ----------

function resolvedCell(l: PatchLine): string {
  const r = l.resolution;
  if (!r) return DASH;
  const name = r.vendor || r.product ? `<div class="strong">${esc(r.vendor ?? "")}${r.vendor && r.product ? " / " : ""}${esc(r.product ?? "")}</div>` : `<div class="muted">no KEV product</div>`;
  const fam = r.family && r.family !== r.product ? `<div class="sub">family: ${esc(r.family)}</div>` : "";
  const ver = `<div class="sub">version: ${r.version ? `<span class="mono">${esc(r.version)}</span>` : "not given"} · type: ${txt(r.product_type)}</div>`;
  const tags: string[] = [];
  if (r.status && r.status !== "matched") tags.push(badge(String(r.status).replace("_", " "), "neutral"));
  if (jurySplit(l)) tags.push(badge("jury split", "split"));
  if (r.adjudicated_by === "ultra") tags.push(badge("Ultra adjudicated", "ultra"));
  else if (r.adjudicated_by) tags.push(badge(`decided by ${r.adjudicated_by}`, "neutral"));
  return `${name}${fam}${ver}${tags.length ? `<div class="tags">${tags.join("")}</div>` : ""}`;
}

function kevCell(l: PatchLine): string {
  const cves = kevCves(l);
  if (!l.kev || cves.length === 0) return `<span class="muted">not in KEV</span>`;
  const due = l.kev.earliest_due;
  const od = num(l.kev.overdue_days);
  let dueNote = "";
  if (od !== null && od > 0) dueNote = `<div class="overdue">overdue by ${plural(od, "day")}</div>`;
  else if (od === 0) dueNote = `<div class="overdue">due today</div>`;
  else if (od !== null && od < 0) dueNote = `<div class="sub">due in ${plural(-od, "day")}</div>`;
  return `<div class="strong nw">${txt(due)}</div>${dueNote}<div class="sub">US federal benchmark · ${plural(cves.length, "KEV CVE")}</div>`;
}

function targetCell(l: PatchLine): string {
  const label = l.decision === "monitor" ? "review by" : l.decision === "ask_owner" ? "after your answer" : "patch by";
  if (!l.target_date) return `<span class="muted">${l.decision === "ask_owner" ? "needs your answer" : DASH}</span>`;
  return `<div class="strong nw">${esc(l.target_date)}</div><div class="sub">${esc(label)} (house target)</div>`;
}

function epssCell(l: PatchLine): string {
  if (!l.epss) return `<span class="muted">no EPSS score</span>`;
  return `<div class="strong">${esc(fmtProb(l.epss.max))}</div><div class="sub mono nw">${txt(l.epss.cve_id)}</div><div class="sub">percentile ${esc(fmtPercentile(l.epss.percentile))}</div>`;
}

/** A verified line that cites no KEV or EPSS value was not re-checked against anything: it gets its own badge. */
function nothingToRecheck(l: PatchLine): boolean {
  return l.verified === true && arr(l.verifier_notes).some((n) => typeof n === "string" && /nothing to re-check/i.test(n));
}

function verifierBadge(l: PatchLine, sample: boolean, withTitle = true): string {
  if (nothingToRecheck(l)) return badge("nothing to re-check", "notlive", withTitle ? "No KEV or EPSS value is cited on this line, so the Verifier had nothing to compare" : undefined);
  return l.verified
    ? badge(sample ? "verified (snapshot)" : "verified", "ok", withTitle ? "Cited KEV and EPSS values re-checked by the Verifier" : undefined)
    : badge("not verified", "bad", withTitle ? "The Verifier could not confirm the cited values; see the notes" : undefined);
}

function verifiedCell(l: PatchLine, sample: boolean): string {
  const notes = arr(l.verifier_notes);
  return `${verifierBadge(l, sample)}${notes.length ? `<div class="sub">${plural(notes.length, "note")}</div>` : ""}`;
}

function votesTable(l: PatchLine, receiptIds: Set<string>): string {
  const votes = juryVotes(l);
  if (!votes.length) return `<p class="empty">No votes recorded.</p>`;
  const rows = votes.map((v) => {
    const rid = v.receipt_id ?? null;
    const ridCell = rid ? (receiptIds.has(rid) ? `<a class="mono nw" href="#${aid("rcpt", rid)}">${esc(rid)}</a>` : `<span class="mono nw">${esc(rid)}</span>`) : DASH;
    const pick = v.vendor || v.product ? `${esc(v.vendor ?? "")}${v.vendor && v.product ? " / " : ""}${esc(v.product ?? "")}` : `<span class="muted">no match</span>`;
    return `<tr><td>${esc(modelName(v.juror))}</td><td>${pick}</td><td>${txt(v.product_type)}</td><td>${fmtConf(v.confidence)}</td><td>${ridCell}</td></tr>`;
  });
  return table(["Juror", "Vote", "Type", "Confidence", "Receipt"], rows, "compact");
}

function criticBlock(c: CriticVerdict | null | undefined, policy: Policy | null): string {
  if (!c) return `<p class="empty">No critic verdict recorded.</p>`;
  const r = c.rubric;
  const parts = r ? `accuracy ${txt(r.accuracy)} · appropriateness ${txt(r.appropriateness)} · actionability ${txt(r.actionability)}` : "";
  const auto = autonomy(c.verdict);
  const gate = belowThreshold(r?.total, policy);
  const reasons = arr(c.reasons);
  return `<p>${badge(String(c.verdict ?? "unknown").replace("_", " "), `v-${c.verdict === "approve" ? "approve" : c.verdict === "send_back" ? "send_back" : "ask_owner"}`)} round ${txt(c.round)} · rubric <strong>${esc(rubricText(c))}</strong>${parts ? ` (${parts})` : ""}${gate ? ` · ${esc(gate)}` : ""}${auto ? ` · ${esc(auto)}` : ""}</p>${
    reasons.length ? `<ul class="reasons">${reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}`;
}

function kevTable(cves: KevEntry[]): string {
  if (!cves.length) return `<p class="empty">No KEV entries on this line.</p>`;
  const rows = cves.map((k) => `<tr><td class="mono nw">${txt(k.cve_id)}</td><td>${txt(k.vendor)} / ${txt(k.product)}</td><td>${txt(k.vulnerability_name)}</td><td class="nw">${txt(k.date_added)}</td><td class="nw">${txt(k.due_date)}</td><td>${txt(k.ransomware_use)}</td><td>${txt(k.required_action)}</td><td>${txt(k.catalog_version)}</td></tr>`);
  return table(["CVE", "KEV vendor / product", "Name", "Added", "Due (US federal)", "Ransomware use", "Required action", "Catalogue"], rows, "compact");
}

function evidenceTable(ev: Evidence[], sample: boolean): string {
  if (!ev.length) return `<p class="empty">No evidence recorded.</p>`;
  const rows = ev.map((e) => `<tr><td class="mono">${txt(e.source)}</td><td>${txt(e.field)}</td><td class="mono">${txt(e.value)}</td><td class="mono">${txt(e.query)}${e.sql_hash ? `<div class="sub">sql ${esc(e.sql_hash)}</div>` : ""}</td><td class="nw">${txt(e.as_of)}</td><td>${
    e.live ? badge("live", "live") : badge(sample ? "snapshot" : "not live", "notlive")}</td></tr>`);
  return table(["Source", "Field", "Value", "Query", "As of", "Read"], rows, "compact");
}

function detailBody(l: PatchLine, policy: Policy | null, sample: boolean, receiptIds: Set<string>): string {
  const notes = arr(l.verifier_notes);
  const dis = kevEpssDisagree(l, policy);
  return `<div class="detail-grid">
<div><h4>Resolution and jury votes</h4>${votesTable(l, receiptIds)}<p class="sub">confidence ${fmtConf(l.resolution?.confidence)}${l.resolution?.adjudicated_by ? ` · adjudicated by ${esc(l.resolution.adjudicated_by)}` : ""}</p></div>
<div><h4>Critic</h4>${criticBlock(l.critic, policy)}<h4>Verifier</h4><p>${verifierBadge(l, sample, false)}</p>${
    notes.length ? `<ul class="reasons">${notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}</div>
</div>
<h4>KEV entries</h4>${kevTable(kevCves(l))}
<h4>EPSS</h4>${l.epss ? `<p>max ${esc(fmtProb(l.epss.max))} on <span class="mono">${txt(l.epss.cve_id)}</span>, percentile ${esc(fmtPercentile(l.epss.percentile))}${
    dis ? ` · ${badge("KEV and EPSS disagree", "warn")}` : ""}</p>` : `<p class="empty">No EPSS score for this line (not treated as 0).</p>`}
<h4>Evidence and provenance</h4>${evidenceTable(objs(l.evidence), sample)}`;
}

function lineRows(l: PatchLine, policy: Policy | null, sample: boolean, receiptIds: Set<string>): string {
  const dis = kevEpssDisagree(l, policy);
  const disNote = dis
    ? `<div class="note warn-note">Sources disagree: listed in KEV (exploited in the wild), but EPSS is ${esc(fmtProb(dis.epss))}, below your ${esc(fmtProb(dis.threshold))} threshold. Your rules put KEV first.</div>`
    : "";
  const ev = objs(l.evidence);
  return `<tr class="line" id="${aid("line", l.row_id)}">
<td>${decisionPill(l.decision)}</td>
<td class="asset"><div class="strong">${txt(l.asset_name)}</div><div class="sub mono">${txt(l.asset_id)}</div>${l.internet_facing ? badge("internet-facing", "inet") : ""}</td>
<td class="sw"><div class="mono">${txt(l.software)}</div><div class="sub">row ${txt(l.row_id)}</div></td>
<td>${resolvedCell(l)}</td>
<td>${kevCell(l)}</td>
<td>${targetCell(l)}</td>
<td>${epssCell(l)}</td>
<td>${verifiedCell(l, sample)}</td>
<td class="why">${txt(l.why)}${disNote}</td>
</tr>
<tr class="detail"><td colspan="9"><details><summary>Evidence and provenance · ${plural(ev.length, "item")} · critic ${esc(rubricText(l.critic))}</summary>${detailBody(l, policy, sample, receiptIds)}</details></td></tr>`;
}

function groupNote(d: Decision, policy: Policy | null): string {
  const sla = policy?.sla_days;
  if (d === "patch_now") return sla ? `house target: within ${esc(sla.patch_now)} days` : "";
  if (d === "this_cycle") return sla ? `house target: within ${esc(sla.this_cycle)} days` : "";
  if (d === "monitor") return sla ? `review every ${esc(sla.monitor_review)} days` : "";
  return "needs your answer before a decision";
}

function patchList(lines: PatchLine[], policy: Policy | null, sample: boolean, receiptIds: Set<string>): string {
  if (!lines.length) return section("patch-list", "Patch list", `<p class="empty">No patch lines in this run.</p>`);
  const head = ["Decision", "Asset", "Software (as written)", "Resolved KEV product", "KEV due", "Target", "Max EPSS", "Verified", "Why"];
  const groups: [string, string, PatchLine[]][] = DECISIONS.map((d) => [d, DECISION_LABEL[d], lines.filter((l) => l.decision === d)]);
  const other = lines.filter((l) => !DECISIONS.includes(l.decision));
  if (other.length) groups.push(["other", "Other", other]);
  const bodies = groups.filter(([, , ls]) => ls.length > 0).map(([d, label, ls]) => {
    const note = d === "other" ? "" : groupNote(d as Decision, policy);
    return `<tbody id="bucket-${d}" class="grp"><tr class="grp-head"><th colspan="9">${decisionPill(d === "other" ? label : d)} ${plural(ls.length, "line")}${note ? ` · <span class="muted">${note}</span>` : ""}</th></tr>${
      ls.map((l) => lineRows(l, policy, sample, receiptIds)).join("")}</tbody>`;
  }).join("");
  return section("patch-list", "Patch list",
    `<div class="scroll"><table class="patch"><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>${bodies}</table></div>`,
    "Grouped by decision, in the order the Exposure Analyst ranked them. Open a line for its evidence, votes, critic score and provenance.");
}

// ---------- owner questions ----------

function ownerQuestions(resp: RunResponse, lineIds: Set<string>): string {
  const qs = objs(resp.owner_questions);
  if (!qs.length) return section("owner-questions", "Owner questions", `<p class="empty">No questions for you in this run.</p>`);
  const rows = qs.map((q) => {
    const link = lineIds.has(String(q.row_id)) ? `<a href="#${aid("line", q.row_id)}">row ${esc(q.row_id)}</a>` : `row ${txt(q.row_id)}`;
    return `<tr><td>${txt(q.asset_name)}<div class="sub">${link}</div></td><td class="strong">${txt(q.question)}</td><td>${txt(q.reason)}</td></tr>`;
  });
  return section("owner-questions", "Owner questions", table(["Asset", "Question", "Why we ask"], rows),
    "These lines were not decided automatically. Your answer lets the next run decide them.");
}

// ---------- models at work ----------

function modelsSection(receipts: Receipt[]): string {
  if (!receipts.length) {
    return section("models", "Models at work", `<p class="empty">No model calls in this run.</p>`);
  }
  type Agg = { calls: number; errors: number; latency: number; pin: number; pout: number; mismatched: number; missing: number };
  const agg = new Map<string, Agg>();
  for (const r of receipts) {
    const k = String(r.requested_model ?? "unknown");
    const a = agg.get(k) ?? { calls: 0, errors: 0, latency: 0, pin: 0, pout: 0, mismatched: 0, missing: 0 };
    a.calls += 1;
    if (r.status !== "ok") a.errors += 1;
    a.latency += num(r.latency_ms) ?? 0;
    a.pin += num(r.prompt_tokens) ?? 0;
    a.pout += num(r.completion_tokens) ?? 0;
    if (r.routed_model && r.routed_model !== r.requested_model) a.mismatched += 1;
    if (!r.receipt_id) a.missing += 1;
    agg.set(k, a);
  }
  const cards = [...agg.entries()].map(([model, a]) => `<div class="mcard${modelName(model) === "Ultra" ? " ultra" : ""}">
<div class="mname">${esc(modelName(model))}</div><div class="mono sub">${esc(model)}</div>
<div class="mstats"><span><b>${a.calls}</b> ${a.calls === 1 ? "call" : "calls"}</span><span><b>${a.errors}</b> ${a.errors === 1 ? "error" : "errors"}</span><span><b>${esc(fmtMs(a.calls ? a.latency / a.calls : null))}</b> avg</span><span><b>${a.pin}</b>/<b>${a.pout}</b> tokens in/out</span></div>${
    a.mismatched ? `<div>${badge(`${a.mismatched} routed to a different model`, "bad")}</div>` : ""}${a.missing ? `<div>${badge(`${a.missing} without receipt ID`, "bad")}</div>` : ""}</div>`).join("");
  const rows = receipts.map((r, i) => {
    const ultra = isUltraReceipt(r);
    const mismatch = r.routed_model && r.routed_model !== r.requested_model;
    const anchor = r.receipt_id ? ` id="${aid("rcpt", r.receipt_id)}"` : "";
    const tok = num(r.prompt_tokens) !== null || num(r.completion_tokens) !== null ? `${txt(r.prompt_tokens)} / ${txt(r.completion_tokens)}` : DASH;
    return `<tr class="${ultra ? "ultra-row" : ""}"${anchor}><td>${i + 1}</td><td>${txt(r.agent)}</td><td>${ultra ? badge("Ultra", "ultra") + " " : ""}<span class="mono">${txt(r.requested_model)}</span></td><td class="mono">${txt(r.routed_model)}${
      mismatch ? ` ${badge("differs", "bad")}` : ""}</td><td class="mono">${txt(r.response_model)}</td><td class="mono nw">${r.receipt_id ? esc(r.receipt_id) : badge("missing", "bad")}</td><td>${esc(fmtMs(r.latency_ms))}</td><td>${tok}</td><td>${
      r.status === "ok" ? badge("ok", "ok") : `${badge(String(r.status ?? "error"), "bad")}${r.error ? `<div class="sub">${esc(r.error)}</div>` : ""}`}</td></tr>`;
  });
  return section("models", "Models at work",
    `<div class="mcards">${cards}</div>${table(["#", "Agent", "Requested model", "Routed model", "Response model", "Receipt ID", "Latency", "Tokens in / out", "Status"], rows, "receipts")}`,
    `Every model call in this run, with the receipt returned by Nightshift. Ultra adjudications are highlighted.`);
}

// ---------- critic ----------

function str(v: unknown): string {
  return typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);
}
function detailsObj(e: TraceEvent): Record<string, unknown> {
  return e.details && typeof e.details === "object" ? (e.details as Record<string, unknown>) : {};
}
const KNOWN_STATUS = ["ok", "error", "fallback", "blocked", "sent_back", "success"];
function statusPill(s: unknown): string {
  const v = str(s) || "unknown";
  return `<span class="st st-${KNOWN_STATUS.includes(v) ? v : "other"}">${esc(v.replace("_", " "))}</span>`;
}
function timeOf(ts: unknown): string {
  const s = str(ts);
  const m = /T(\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)/.exec(s);
  return m ? m[1] : s;
}

function isCriticEvent(e: TraceEvent): boolean {
  return /critic/i.test(str(e.agent)) || e.status === "sent_back" || e.status === "blocked";
}

function criticSection(lines: PatchLine[], policy: Policy | null, trace: TraceEvent[] | null, traceFile: string): string {
  const flagged = lines.filter((l) => l.critic && l.critic.verdict !== "approve");
  const approved = lines.filter((l) => l.critic && l.critic.verdict === "approve");
  const noVerdict = lines.filter((l) => !l.critic).length;
  const verdictRows = flagged.map((l) => {
    const c = l.critic as CriticVerdict;
    const gate = belowThreshold(c.rubric?.total, policy);
    return `<tr><td><a href="#${aid("line", l.row_id)}">${txt(l.asset_name)}</a><div class="sub mono">${txt(l.software)}</div></td><td>${badge(String(c.verdict).replace("_", " "), c.verdict === "send_back" ? "v-send_back" : "v-ask_owner")}</td><td>${txt(c.round)}</td><td class="strong">${esc(rubricText(c))}${gate ? `<div class="sub thin">${esc(gate)}</div>` : ""}</td><td>${esc(autonomy(c.verdict)) || DASH}</td><td>${
      arr(c.reasons).length ? `<ul class="reasons">${arr(c.reasons).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : DASH}</td></tr>`;
  });
  const verdicts = flagged.length
    ? table(["Line", "Final verdict", "Round", "Rubric", "Autonomy", "Reasons"], verdictRows)
    : `<p class="empty">No line ended blocked or sent to the owner by the critic.</p>`;
  const counts = `<p class="lead">${esc(plural(approved.length, "line"))} approved · ${esc(plural(flagged.length, "line"))} blocked or sent to the owner${
    noVerdict ? ` · ${esc(plural(noVerdict, "line"))} without a critic verdict` : ""}.</p>`;
  let timeline: string;
  if (trace) {
    const evs = trace.filter(isCriticEvent);
    timeline = evs.length
      ? table(["Time", "Agent", "Action", "Status", "To", "Rubric", "Detail"], evs.map((e) => {
          const d = detailsObj(e);
          const rub = d.rubric && typeof d.rubric === "object" ? num((d.rubric as Record<string, unknown>).total) : num(d.rubric_total);
          const reasons = Array.isArray(d.reasons) ? (d.reasons as unknown[]).map(str).filter(Boolean) : [];
          const detail = [str(e.input_summary), str(e.output_summary), ...reasons].filter(Boolean);
          return `<tr><td class="mono">${esc(timeOf(e.ts))}</td><td>${txt(e.agent)}</td><td>${txt(e.action)}</td><td>${statusPill(e.status)}</td><td>${txt(e.target_agent)}</td><td>${rub === null ? DASH : `${rub}/9`}</td><td>${
            detail.length ? detail.map((x) => `<div>${esc(x)}</div>`).join("") : DASH}${num(e.retry_count) ? `<div class="sub">retry ${esc(e.retry_count)}</div>` : ""}</td></tr>`;
        }))
      : `<p class="empty">The trace has no critic events.</p>`;
  } else {
    timeline = `<p class="empty">Trace not attached to this report. The full trace is in <span class="mono">${txt(traceFile)}</span>.</p>`;
  }
  return section("critic", "Critic: blocks, send-backs and questions",
    `${counts}<h3>Lines the critic did not approve</h3>${verdicts}<h3>Critic events in the trace (send-backs and blocks, in order)</h3>${timeline}`);
}

// ---------- timing ----------

function isZetarisEvent(e: TraceEvent): boolean {
  const d = detailsObj(e);
  return /zetaris/i.test(str(e.agent)) || /zetaris/i.test(str(e.action)) || typeof d.sql_hash === "string" || typeof d.sql === "string";
}

function timingSection(resp: RunResponse, receipts: Receipt[], trace: TraceEvent[] | null): string {
  const phases = Object.entries(resp.timing_ms ?? {}).filter(([, v]) => num(v) !== null) as [string, number][];
  const max = phases.reduce((m, [, v]) => Math.max(m, v), 0);
  const bars = phases.length
    ? `<div class="bars">${phases.map(([k, v]) => `<div class="bar-row"><span class="bar-k">${esc(k)}</span><span class="bar"><span class="bar-fill" style="width:${max > 0 ? ((v / max) * 100).toFixed(1) : "0"}%"></span></span><span class="bar-v">${esc(fmtMs(v))}</span></div>`).join("")}</div>`
    : `<p class="empty">No phase timings recorded.</p>`;
  const modelMs = receipts.reduce((s, r) => s + (num(r.latency_ms) ?? 0), 0);
  let zq = "";
  if (trace) {
    const evs = trace.filter((e) => isZetarisEvent(e) && (num(e.latency_ms) !== null || num(detailsObj(e).ms) !== null));
    if (evs.length) {
      const total = evs.reduce((s, e) => s + (num(e.latency_ms) ?? num(detailsObj(e).ms) ?? 0), 0);
      const rows = evs.map((e) => {
        const d = detailsObj(e);
        const label = str(d.label) || str(d.query) || str(d.name) || str(e.action);
        const rowsN = num(d.rows) ?? num(d.row_count) ?? num(d.rowCount);
        const cache = d.from_cache ?? d.fromCache ?? d.cache;
        const sql = str(d.sql);
        return `<tr><td class="mono">${esc(timeOf(e.ts))}</td><td>${esc(label)}${sql ? `<details class="sql"><summary>SQL${typeof d.sql_hash === "string" ? ` · ${esc(d.sql_hash)}` : ""}</summary><pre>${esc(sql)}</pre></details>` : ""}</td><td>${esc(fmtMs(num(e.latency_ms) ?? num(d.ms)))}</td><td>${rowsN === null ? DASH : rowsN}</td><td>${
          cache === undefined || cache === null ? DASH : esc(str(cache))}</td><td>${statusPill(e.status)}</td></tr>`;
      });
      zq = `<h3>Zetaris queries (${evs.length}, ${esc(fmtMs(total))} in total)</h3>${table(["Time", "Query", "Time taken", "Rows", "From cache", "Status"], rows, "compact")}`;
    } else {
      zq = `<h3>Zetaris queries</h3><p class="empty">The trace has no timed Zetaris queries.</p>`;
    }
  } else {
    zq = `<h3>Zetaris queries</h3><p class="empty">Trace not attached; per-query times are in <span class="mono">${txt(resp.trace_file)}</span>.</p>`;
  }
  return section("timing", "Timing",
    `${bars}<p class="sub">Model time, summed over ${plural(receipts.length, "call")}: ${esc(fmtMs(receipts.length ? modelMs : null))} (calls run in parallel, so this can exceed the run time).</p>${zq}`,
    "Where the run spent its time, as measured by the run itself.");
}

// ---------- full timeline and run details ----------

function timelineSection(trace: TraceEvent[] | null, cap: number): string {
  if (!trace) return "";
  const shown = trace.slice(0, cap);
  const rows = shown.map((e) => `<tr><td class="mono">${esc(timeOf(e.ts))}</td><td>${txt(e.agent)}</td><td>${txt(e.action)}</td><td>${txt(e.target_agent)}</td><td>${statusPill(e.status)}</td><td class="mono">${e.model ? esc(modelName(e.model)) : DASH}${
    e.receipt_id ? `<div class="sub">${esc(e.receipt_id)}</div>` : ""}</td><td>${esc(fmtMs(e.latency_ms))}</td><td>${txt(e.output_summary ?? e.input_summary)}</td></tr>`);
  const note = trace.length > cap ? `<p class="sub">Showing the first ${cap} of ${trace.length} events.</p>` : "";
  return section("timeline", "Agent timeline",
    `<details><summary>${esc(plural(trace.length, "trace event"))}: agents, handoffs, queries and model calls</summary>${note}${
      table(["Time", "Agent", "Action", "To", "Status", "Model", "Latency", "Summary"], rows, "compact")}</details>`);
}

function runDetails(resp: RunResponse): string {
  const m = resp.manifest;
  const models = m?.models ? Object.entries(m.models).map(([k, v]) => `<li>${esc(modelName(k))}: <span class="mono">${esc(v)}</span></li>`).join("") : "";
  const helpers = (xs: string[] | undefined) => (arr(xs).length ? arr(xs).map((h) => `<span class="badge neutral">${esc(h)}</span>`).join(" ") : DASH);
  return section("run-details", "Run details", `<dl class="kv">
<dt>Engine</dt><dd>${txt(m?.engine)} <span class="sub mono">${txt(m?.engine_source)}</span></dd>
<dt>Pinned models</dt><dd>${models ? `<ul class="plain">${models}</ul>` : DASH}</dd>
<dt>Helpers live</dt><dd>${helpers(m?.helpers_live)}</dd>
<dt>Helpers dormant</dt><dd>${helpers(m?.helpers_dormant)}</dd>
<dt>Trace file</dt><dd class="mono">${txt(resp.trace_file)}</dd>
<dt>Report file</dt><dd class="mono">${txt(resp.report_file)}</dd>
</dl>`);
}

function footer(): string {
  return `<footer class="caveats" id="caveats"><h2>Caveats</h2><ul>
<li><strong>Decision support only.</strong> You decide what to patch; this list does not act on any system.</li>
<li><strong>The policy is yours.</strong> Thresholds and target dates are configurable rules, shown above as used in this run.</li>
<li><strong>No exploitability claims.</strong> KEV means exploitation was reported in the wild; EPSS is a probability estimate. Neither says your system is exploitable.</li>
<li><strong>Synthetic inventory.</strong> The bundled sample inventory is synthetic; rows you send in are your own.</li>
<li><strong>KEV due dates are US federal benchmarks</strong> (for US federal agencies), not deadlines that apply to you.</li>
</ul></footer>`;
}

// ---------- page ----------

const CSS = `
:root{--bg:#f4f6f8;--card:#fff;--ink:#16191d;--muted:#5a636e;--line:#d9dee4;--soft:#eef1f4;--accent:#1d5bb8;
--now:#a5281b;--now-bg:#fde9e6;--cyc:#8a5300;--cyc-bg:#fff1d6;--mon:#25613a;--mon-bg:#e3f3e8;--own:#5536a8;--own-bg:#eee8fc;
--ok:#1f6b3b;--ok-bg:#e1f2e6;--bad:#a5281b;--bad-bg:#fde9e6;--warn:#7a4d00;--warn-bg:#fff4d6;--ultra:#0b5a6e;--ultra-bg:#dff3f7}
*{box-sizing:border-box}html{color-scheme:light}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1840px;margin:0 auto;padding:20px 32px 40px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:.92em}
.strong{font-weight:600}.muted{color:var(--muted)}.sub{color:var(--muted);font-size:13px;line-height:1.4}.thin{font-weight:400;color:var(--muted)}
h1{margin:0;font-size:30px;letter-spacing:-.01em}h2{margin:0 0 12px;font-size:21px}h3{margin:20px 0 8px;font-size:17px}h4{margin:14px 0 6px;font-size:15px}
.top{display:flex;flex-wrap:wrap;gap:16px 40px;align-items:flex-end;justify-content:space-between;margin-bottom:12px}
.tag{margin:2px 0 0;color:var(--muted);font-size:17px}
.meta{display:flex;flex-wrap:wrap;gap:8px 28px;margin:0}.meta div{min-width:110px}.meta dt{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}.meta dd{margin:0;font-weight:600}
.banner{border-radius:8px;padding:12px 16px;margin:0 0 12px;font-size:17px;border:1px solid}
.banner.sample{background:#fff3cd;border-color:#e0b100;color:#5c4200}.banner.live{background:var(--ok-bg);border-color:#9fd1ae;color:var(--ok)}
.banner.error{background:var(--bad-bg);border-color:#f0a99f;color:var(--bad)}.banner.warn{background:var(--warn-bg);border-color:#e9c46a;color:var(--warn)}
.nav{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 14px}.nav a{padding:5px 12px;border-radius:999px;background:var(--card);border:1px solid var(--line);color:var(--accent);text-decoration:none;font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:0 0 16px}
.card.split{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:28px}
.lead{margin:0 0 12px;color:var(--muted)}.empty{color:var(--muted);font-style:italic;margin:6px 0}
.chips{display:flex;flex-wrap:wrap;gap:12px}
.chip{display:flex;align-items:baseline;gap:10px;padding:10px 18px;border-radius:10px;text-decoration:none;border:1px solid transparent;min-width:170px}
.chip-n{font-size:34px;font-weight:700;line-height:1}.chip-l{font-size:17px;font-weight:600}.chip.zero{opacity:.55}
.stats{display:flex;flex-wrap:wrap;gap:4px 24px;margin:12px 0 0;padding:0;list-style:none;color:var(--muted)}
.d-patch_now{background:var(--now-bg);color:var(--now)}.d-this_cycle{background:var(--cyc-bg);color:var(--cyc)}
.d-monitor{background:var(--mon-bg);color:var(--mon)}.d-ask_owner{background:var(--own-bg);color:var(--own)}.d-other{background:var(--soft);color:var(--ink)}
.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:700;font-size:13.5px;white-space:nowrap}
.badge{display:inline-block;padding:1px 8px;border-radius:5px;font-size:12.5px;font-weight:600;margin:2px 4px 2px 0;border:1px solid transparent;white-space:nowrap}
.badge.ok,.badge.live,.badge.v-approve,.badge.st-success{background:var(--ok-bg);color:var(--ok)}
.badge.bad,.badge.st-error{background:var(--bad-bg);color:var(--bad)}
.badge.notlive,.badge.neutral,.badge.st-other{background:var(--soft);color:var(--muted);border-color:var(--line)}
.badge.inet{background:#e7eefc;color:#1d4fa3;border-color:#b8cbf0}.badge.warn,.badge.st-partial{background:var(--warn-bg);color:var(--warn)}
.badge.ultra{background:var(--ultra-bg);color:var(--ultra);border-color:#9fd3df}.badge.split{background:#fbe8f3;color:#8b1f5c}
.badge.v-send_back{background:var(--warn-bg);color:var(--warn)}.badge.v-ask_owner{background:var(--own-bg);color:var(--own)}
.tags{margin-top:4px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid var(--line)}
thead th{background:var(--soft);font-size:12.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);position:sticky;top:0}
table.compact{font-size:13.5px}table.compact th,table.compact td{padding:5px 8px}
table.patch td.why{min-width:240px;max-width:460px}table.patch td.sw{min-width:170px;max-width:280px;overflow-wrap:break-word}table.patch td.asset{min-width:150px}
.nw{white-space:nowrap}
tr.grp-head th{background:#fafbfc;font-size:15px;padding:12px 10px;border-top:2px solid var(--line)}
tr.line td{border-bottom:none}tr.detail td{padding:0 10px 10px}
tr.detail summary{cursor:pointer;color:var(--accent);font-size:13.5px;padding:2px 0}
tr.detail details[open]{background:#fafbfc;border:1px solid var(--line);border-radius:8px;padding:6px 14px 12px}
.detail-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px}
.overdue{color:var(--now);font-weight:700}
.note{margin-top:6px;padding:6px 9px;border-radius:6px;font-size:13.5px}.warn-note{background:var(--warn-bg);color:var(--warn)}
.reasons{margin:4px 0;padding-left:20px}.rules{margin:0;padding-left:0;list-style:none}.rules li{margin:0 0 10px}
.mcards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:14px}
.mcard{border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:300px}.mcard.ultra{border-color:#9fd3df;background:var(--ultra-bg)}
.mname{font-size:18px;font-weight:700}.mstats{display:flex;flex-wrap:wrap;gap:4px 16px;margin-top:6px;font-size:14px}
tr.ultra-row td{background:var(--ultra-bg)}
.st{display:inline-block;padding:1px 8px;border-radius:5px;font-size:12.5px;font-weight:600;background:var(--soft);color:var(--muted)}
.st-ok,.st-success{background:var(--ok-bg);color:var(--ok)}.st-error{background:var(--bad-bg);color:var(--bad)}
.st-fallback{background:var(--warn-bg);color:var(--warn)}.st-blocked{background:var(--bad-bg);color:var(--bad)}.st-sent_back{background:var(--own-bg);color:var(--own)}
.bars{display:grid;gap:6px;max-width:1100px}.bar-row{display:grid;grid-template-columns:220px 1fr 90px;gap:12px;align-items:center}
.bar{height:16px;background:var(--soft);border-radius:4px;overflow:hidden}.bar-fill{display:block;height:100%;background:var(--accent)}.bar-v{text-align:right;font-variant-numeric:tabular-nums}
details.sql summary{cursor:pointer;color:var(--accent);font-size:13px}pre{white-space:pre-wrap;word-break:break-word;background:var(--soft);padding:8px;border-radius:6px;font-size:12.5px;margin:6px 0}
.kv{display:grid;grid-template-columns:180px 1fr;gap:6px 16px;margin:0}.kv dt{color:var(--muted)}.kv dd{margin:0}.plain{margin:0;padding-left:18px}
.caveats{border-top:3px solid var(--line);padding:16px 4px 0;color:#2b3138}.caveats h2{font-size:18px}.caveats ul{margin:0;padding-left:20px}.caveats li{margin:4px 0}
@media (max-width:900px){main{padding:14px 16px}.card.split,.detail-grid{grid-template-columns:1fr}.bar-row{grid-template-columns:120px 1fr 70px}}
@media print{.nav{display:none}body{background:#fff}.card{break-inside:avoid}}
`;

/** Renders the self-contained HTML report for one run. */
export function renderReport(resp: RunResponse, opts: RenderOptions = {}): string {
  const r = (resp ?? {}) as RunResponse;
  const lines = objs(r.lines);
  const receipts = objs(r.receipts);
  const policy = r.manifest?.policy ?? null;
  const sample = r.mode === "sample";
  const trace = Array.isArray(opts.trace) ? objs(opts.trace) : null;
  const cap = Math.max(1, Math.floor(num(opts.maxTimelineEvents) ?? 400));
  const receiptIds = new Set(receipts.map((x) => x.receipt_id).filter((x): x is string => typeof x === "string" && x !== ""));
  const lineIds = new Set(lines.map((l) => String(l.row_id)));
  const title = `ExposureLedger report · ${str(r.run_id) || "run"}${sample ? " · SAMPLE MODE" : ""}`;
  return `<!doctype html>
<html lang="en" data-mode="${sample ? "sample" : "live"}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body>
<main>
${header(r)}
${nav()}
${summarySection(r, lines, policy)}
${patchList(lines, policy, sample, receiptIds)}
${ownerQuestions(r, lineIds)}
${sourcesAndRules(r, policy)}
${modelsSection(receipts)}
${criticSection(lines, policy, trace, str(r.trace_file))}
${timingSection(r, receipts, trace)}
${timelineSection(trace, cap)}
${runDetails(r)}
${footer()}
</main>
</body>
</html>
`;
}
