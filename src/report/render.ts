// Static HTML report for one run.
// Pure: the same RunResponse (and optional trace) always gives the same HTML. No clock, no IO.
// Self-contained: inline CSS only, no scripts, no external assets, so it works offline.
// Every value taken from the run goes through esc(); the page also carries a CSP that forbids scripts.
// It renders only what the run JSON (and trace) contains. Derived values (counts, sums, the
// KEV-vs-EPSS disagreement flag, the autonomy level from the critic's verdict, the rubric-vs-threshold
// note) are computed from those fields only. Long text may be clamped on screen (CSS), never cut in the page.
// Laid out for a 1920x1080 screen (and still readable at 1440 px): a sticky bar keeps the mode stamp and
// the section links in view, and the patch list keeps its column headings while it scrolls.

import { MODELS } from "../contracts.ts";
import type {
  CriticVerdict, Decision, Evidence, JurorVote, KevEntry, PatchLine, Policy, Receipt,
  RunResponse, TraceEvent,
} from "../contracts.ts";
import { indexTrace, pickText } from "./trace-facts.ts";
import type { CatchStep, NvdFacts, TraceFacts } from "./trace-facts.ts";

export interface RenderOptions {
  /** Events of logs/trace-<run_id>.jsonl. Adds the pipeline, Ultra's decisions, the critic loop, Zetaris query times and the full timeline. */
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

/**
 * Local absolute paths shown repo-relative: ".../logs/x" -> "logs/x", ".../output/x" -> "output/x"; any other
 * home directory -> "~". The run writes absolute paths (trace_file, audit file); on a shared screen they would
 * show the machine's user and folder names.
 */
export function maskLocalPaths(s: string): string {
  return s
    .replace(/(?:[A-Za-z]:)?[\\/](?:Users|home)[\\/][^\n"'<>]{0,240}?[\\/]((?:logs|output)[\\/])/g, "$1")
    .replace(/(?:[A-Za-z]:)?[\\/](?:Users|home)[\\/][^\\/\s"'<>]+/g, "~");
}

const ENTITIES: Record<string, string> = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;",
};
function escRaw(s: string): string {
  return s.replace(/[&<>"'`]/g, (ch) => ENTITIES[ch] ?? ch);
}
/** Escapes any value for use in HTML text or a quoted attribute. null/undefined become "". */
export function esc(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = typeof v === "object" ? safeJson(v) : String(v);
  return escRaw(maskLocalPaths(maskCredentials(s)));
}

function safeJson(v: unknown): string {
  try { return JSON.stringify(v) ?? ""; } catch { return "[unserialisable]"; }
}

/** An id/fragment built only from [A-Za-z0-9_-]. */
function aid(prefix: string, raw: unknown): string {
  return `${prefix}-${String(raw ?? "").replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 120)}`;
}

/** Escaped text in which every receipt ID of this run becomes a link to its row in "Models at work". */
function linkReceipts(v: unknown, receiptIds: Set<string>): string {
  if (v === null || v === undefined) return "";
  const s = maskLocalPaths(maskCredentials(typeof v === "object" ? safeJson(v) : String(v)));
  let out = "";
  let last = 0;
  for (const m of s.matchAll(/[A-Za-z0-9_-]{4,}/g)) {
    if (!receiptIds.has(m[0])) continue;
    out += escRaw(s.slice(last, m.index)) + `<a class="mono" href="#${aid("rcpt", m[0])}">${escRaw(m[0])}</a>`;
    last = (m.index ?? 0) + m[0].length;
  }
  return out + escRaw(s.slice(last));
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
/** "2026-10-26T23:25:48.677Z" -> "2026-10-26 23:25:48 UTC"; anything else is shown as given. */
function fmtTs(v: unknown): string {
  const s = str(v);
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$/.exec(s);
  return m ? `${m[1]} ${m[2]} UTC` : s;
}
/** A midnight UTC timestamp is a day (the run's as-of date): "2026-10-26T00:00:00.000Z" -> "2026-10-26". */
function fmtDay(v: unknown): string {
  const s = str(v);
  const m = /^(\d{4}-\d{2}-\d{2})T00:00:00(?:\.0+)?Z$/.exec(s);
  return m ? m[1] : fmtTs(s);
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
function str(v: unknown): string {
  return typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);
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
const MODEL_ORDER = ["Bolt", "Lightning", "Ultra"];
function modelRank(id: string): number {
  const i = MODEL_ORDER.indexOf(modelName(id));
  return i < 0 ? MODEL_ORDER.length : i;
}
function modelChip(name: string): string {
  const cls = name === "Ultra" ? "ultra" : name === "Lightning" ? "lightning" : name === "Bolt" ? "bolt" : "neutral";
  return badge(name, `m-${cls}`);
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
/**
 * Text shown on at most `lines` lines on screen (CSS clamp, lifted for print); the full text stays in the page.
 * No title tooltip: attributes carry only fixed text, never run data.
 */
function clamp(text: string, lines: 1 | 2 | 3 = 2): string {
  return `<span class="clamp c${lines}">${esc(text)}</span>`;
}
function lineLink(rowId: string, lineIds: Set<string>, label?: string): string {
  return lineIds.has(rowId) ? `<a href="#${aid("line", rowId)}">${esc(label ?? `row ${rowId}`)}</a>` : esc(label ?? `row ${rowId}`);
}
function receiptLink(rid: string | null | undefined, receiptIds: Set<string>): string {
  if (!rid) return DASH;
  return receiptIds.has(rid) ? `<a class="mono nw" href="#${aid("rcpt", rid)}">${esc(rid)}</a>` : `<span class="mono nw">${esc(rid)}</span>`;
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
/** The World Model's own summary of a line (the provenance item of explain()), if the run recorded one. */
function worldModelProvenance(l: PatchLine): Evidence | null {
  return objs(l.evidence).find((e) => e.source === "world_model" && e.field === "provenance") ?? null;
}
/** A line the version check could not settle (the run marks it with a "version_unconfirmed" evidence item). */
function versionUnconfirmed(l: PatchLine): boolean {
  return objs(l.evidence).some((e) => e.field === "version_unconfirmed");
}

/** Everything a section needs about the run, computed once. */
interface Ctx {
  resp: RunResponse;
  lines: PatchLine[];
  receipts: Receipt[];
  policy: Policy | null;
  sample: boolean;
  trace: TraceEvent[] | null;
  facts: TraceFacts | null;
  receiptIds: Set<string>;
  lineIds: Set<string>;
  lineById: Map<string, PatchLine>;
}

// ---------- header and sticky bar ----------

/**
 * When the sample snapshot was captured: manifest.snapshot_date if the run records one; else the as-of of the
 * source that is the snapshot itself (sample mode lists it as a source named "... snapshot"); else every
 * distinct source date.
 */
function snapshotDates(resp: RunResponse): string[] {
  const own = str((resp.manifest as unknown as Record<string, unknown> | undefined)?.snapshot_date);
  if (own) return [own];
  const sources = objs(resp.manifest?.sources);
  const snap = sources.find((s) => /snapshot/i.test(str(s?.name)) && str(s?.as_of));
  if (snap) return [str(snap.as_of)];
  const dates = sources.map((s) => s?.as_of).filter((d): d is string => typeof d === "string" && d !== "");
  return [...new Set(dates)].sort();
}

function header(c: Ctx): string {
  const resp = c.resp;
  const started = Date.parse(String(resp.started_at ?? ""));
  const finished = Date.parse(String(resp.finished_at ?? ""));
  const wall = Number.isFinite(started) && Number.isFinite(finished) && finished >= started ? finished - started : null;
  const meta: [string, string][] = [
    ["Run ID", `<span class="mono">${txt(resp.run_id)}</span>`],
    ["As of", txt(resp.as_of)],
    ["Started", `<span class="mono">${txt(fmtTs(resp.started_at))}</span>`],
    ["Finished", `<span class="mono">${txt(fmtTs(resp.finished_at))}</span>`],
    ["Run time", fmtMs(wall)],
    ["Status", badge(String(resp.status ?? "unknown"), `st-${["success", "partial", "error"].includes(String(resp.status)) ? resp.status : "other"}`)],
  ];
  const dates = snapshotDates(resp);
  const sources = objs(resp.manifest?.sources);
  const liveSources = sources.filter((s) => s?.live === true).length;
  const modeBanner = c.sample
    ? `<div class="banner sample" id="mode-banner"><strong>SAMPLE MODE</strong> · deterministic offline run on a data snapshot${
        dates.length ? ` · snapshot captured <strong>${dates.map(esc).join(", ")}</strong>` : ` · snapshot date not recorded in this run`
      } · model calls in this run: ${c.receipts.length}<span class="b2">${
        sources.length && liveSources === 0 ? `No source was read live (0 of ${sources.length}): the values come from the saved snapshot and are labelled "snapshot" wherever they are shown.`
          : sources.length ? `Sources read live in this run: ${liveSources} of ${sources.length}; the others come from the saved snapshot.` : `Values come from the saved snapshot and are labelled "snapshot".`}</span></div>`
    : `<div class="banner live" id="mode-banner"><strong>LIVE MODE</strong> · sources flagged live below were read at run time${
        c.receipts.length ? ` · ${plural(c.receipts.length, "model call")}, ${c.receipts.filter((r) => r.receipt_id).length} with a Nightshift receipt` : ""}</div>`;
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

function nav(c: Ctx): string {
  const items: [string, string][] = [["summary", "Summary"]];
  if (c.facts?.pipeline.length) items.push(["pipeline", "How it was made"]);
  items.push(["patch-list", "Patch list"], ["owner-questions", "Owner questions"], ["sources", "Sources and rules"],
    ["models", "Models at work"], ["critic", "Critic"], ["timing", "Timing"]);
  if (c.trace) items.push(["timeline", "Trace"]);
  items.push(["run-details", "Run details"]);
  const dates = snapshotDates(c.resp);
  const mode = c.sample
    ? `<span class="nav-mode m-sample">SAMPLE MODE${dates.length ? ` · snapshot ${dates.map(esc).join(", ")}` : ""}</span>`
    : `<span class="nav-mode m-live">LIVE</span>`;
  return `<nav class="nav" id="top">${mode}<span class="nav-run mono">${txt(c.resp.run_id)}</span>${
    items.map(([id, t]) => `<a href="#${id}">${esc(t)}</a>`).join("")}</nav>`;
}

// ---------- summary, pipeline, sources and rules ----------

function summarySection(c: Ctx): string {
  const { resp, lines, policy } = c;
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
  const unconfirmed = lines.filter((l) => l.decision === "patch_now" && versionUnconfirmed(l)).length;
  const stats = [
    `${plural(lines.length, "line")} · ${verified} verified${nothing ? ` · ${nothing} with nothing to re-check` : ""}`,
    `${inet} patch-now ${inet === 1 ? "line is" : "lines are"} internet-facing`,
    `${plural(overdue, "line")} past the US federal KEV benchmark`,
    unconfirmed ? `${unconfirmed} patch-now ${unconfirmed === 1 ? "line has its" : "lines have their"} version unconfirmed (owner question attached)` : "",
    disagree ? `${plural(disagree, "line")} where KEV and EPSS disagree (KEV wins under your rules)` : "",
  ].filter(Boolean);
  return `<section id="summary" class="card"><div class="chips">${chips}</div><ul class="stats">${stats.map((s) => `<li>${esc(s)}</li>`).join("")}</ul></section>`;
}

function pipelineSection(c: Ctx): string {
  const steps = c.facts?.pipeline ?? [];
  if (!steps.length) return "";
  const boxes = steps.map((s) => `<div class="step"><div class="step-h">${esc(s.agent)}${s.models.length ? ` ${[...s.models].sort((a, b) => modelRank(a) - modelRank(b)).map(modelChip).join("")}` : ""}</div>${
    s.text.map((t) => `<div class="step-t">${esc(t)}</div>`).join("")}</div>`).join(`<span class="arrow" aria-hidden="true">→</span>`);
  const receipted = c.receipts.filter((r) => r.receipt_id).length;
  return section("pipeline", "How this list was made", `<div class="steps-row">${boxes}</div>`,
    `Each agent's own summary from this run's trace, in pipeline order.${c.receipts.length ? ` ${receipted} of ${plural(c.receipts.length, "model call")} carry a Nightshift receipt (see <a href="#models">Models at work</a>).` : ""}`);
}

function sourcesAndRules(c: Ctx): string {
  const { resp, policy, sample } = c;
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

function resolvedCell(l: PatchLine, c: Ctx): string {
  const r = l.resolution;
  if (!r) return DASH;
  const name = r.vendor || r.product ? `<div class="strong">${esc(r.vendor ?? "")}${r.vendor && r.product ? " / " : ""}${esc(r.product ?? "")}</div>` : `<div class="muted">no KEV product</div>`;
  const fam = r.family && r.family !== r.product ? `<div class="sub">family: ${esc(r.family)}</div>` : "";
  const ver = `<div class="sub">version: ${r.version ? `<span class="mono">${esc(r.version)}</span>` : "not given"} · type: ${txt(r.product_type)}</div>`;
  const tags: string[] = [];
  if (r.status && r.status !== "matched") tags.push(badge(String(r.status).replace("_", " "), "neutral"));
  if (jurySplit(l)) tags.push(badge("jury split", "split"));
  const adj = c.facts?.adjudications.find((a) => a.row_id === l.row_id);
  if (r.adjudicated_by === "ultra") {
    tags.push(badge("Ultra adjudicated", "ultra"));
    if (adj?.sided_with) tags.push(`<div class="sub">Ultra sided with ${esc(adj.sided_with)}</div>`);
  } else if (r.adjudicated_by) tags.push(badge(`decided by ${r.adjudicated_by}`, "neutral"));
  const caught = c.facts?.catches.get(l.row_id);
  if (caught) {
    const backs = caught.filter((s) => s.kind === "critic" && s.status === "sent_back").length;
    tags.push(`<a class="badge caught" href="#${aid("catch", l.row_id)}">critic sent back${backs > 1 ? ` ×${backs}` : ""}</a>`);
  }
  return `${name}${fam}${ver}${tags.length ? `<div class="tags">${tags.join("")}</div>` : ""}`;
}

function kevCell(l: PatchLine): string {
  const cves = kevCves(l);
  if (!l.kev || cves.length === 0) return `<span class="muted">not in KEV</span>`;
  const od = num(l.kev.overdue_days);
  let dueNote = "";
  if (od !== null && od > 0) dueNote = `<div class="overdue">overdue by ${plural(od, "day")}</div>`;
  else if (od === 0) dueNote = `<div class="overdue">due today</div>`;
  else if (od !== null && od < 0) dueNote = `<div class="sub">due in ${plural(-od, "day")}</div>`;
  return `<div class="strong nw">${txt(l.kev.earliest_due)}</div>${dueNote}<div class="sub">${plural(cves.length, "KEV CVE")}</div>`;
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
  if (nothingToRecheck(l)) return badge("nothing to re-check", "notlive wrap", withTitle ? "No KEV or EPSS value is cited on this line, so the Verifier had nothing to compare" : undefined);
  return l.verified
    ? badge(sample ? "verified (snapshot)" : "verified", "ok", withTitle ? "Cited KEV and EPSS values re-checked by the Verifier" : undefined)
    : badge("not verified", "bad", withTitle ? "The Verifier could not confirm the cited values; see the notes" : undefined);
}

function verifiedCell(l: PatchLine, sample: boolean): string {
  const notes = arr(l.verifier_notes);
  return `${verifierBadge(l, sample)}${notes.length ? `<div class="sub">${plural(notes.length, "note")}</div>` : ""}`;
}

function votesTable(l: PatchLine, c: Ctx): string {
  const votes = juryVotes(l);
  if (!votes.length) return `<p class="empty">No votes recorded.</p>`;
  const rows = votes.map((v) => {
    const pick = v.vendor || v.product ? `${esc(v.vendor ?? "")}${v.vendor && v.product ? " / " : ""}${esc(v.product ?? "")}` : `<span class="muted">no match</span>`;
    return `<tr><td>${esc(modelName(v.juror))}</td><td>${pick}</td><td>${txt(v.product_type)}</td><td>${fmtConf(v.confidence)}</td><td>${receiptLink(v.receipt_id ?? null, c.receiptIds)}</td></tr>`;
  });
  return table(["Juror", "Vote", "Type", "Confidence", "Receipt"], rows, "compact");
}

function criticBlock(cv: CriticVerdict | null | undefined, policy: Policy | null): string {
  if (!cv) return `<p class="empty">No critic verdict recorded.</p>`;
  const r = cv.rubric;
  const parts = r ? `accuracy ${txt(r.accuracy)} · appropriateness ${txt(r.appropriateness)} · actionability ${txt(r.actionability)}` : "";
  const auto = autonomy(cv.verdict);
  const gate = belowThreshold(r?.total, policy);
  const reasons = arr(cv.reasons);
  return `<p>${badge(String(cv.verdict ?? "unknown").replace("_", " "), `v-${cv.verdict === "approve" ? "approve" : cv.verdict === "send_back" ? "send_back" : "ask_owner"}`)} round ${txt(cv.round)} · rubric <strong>${esc(rubricText(cv))}</strong>${parts ? ` (${parts})` : ""}${gate ? ` · ${esc(gate)}` : ""}${auto ? ` · ${esc(auto)}` : ""}</p>${
    reasons.length ? `<ul class="reasons">${reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}`;
}

function kevTable(cves: KevEntry[]): string {
  if (!cves.length) return `<p class="empty">No KEV entries on this line.</p>`;
  const rows = cves.map((k) => `<tr><td class="mono nw">${txt(k.cve_id)}</td><td>${txt(k.vendor)} / ${txt(k.product)}</td><td>${txt(k.vulnerability_name)}</td><td class="nw">${txt(k.date_added)}</td><td class="nw">${txt(k.due_date)}</td><td>${txt(k.ransomware_use)}</td><td>${txt(k.required_action)}</td><td class="nw">${txt(k.catalog_version)}</td></tr>`);
  return table(["CVE", "KEV vendor / product", "Name", "Added", "Due (US federal)", "Ransomware use", "Required action", "Catalogue"], rows, "compact");
}

/** The World Model's explain() items for this line: what the engine holds about it, and from which sources. */
function provenanceBlock(l: PatchLine, c: Ctx): string {
  const items = objs(l.evidence).filter((e) => e.source === "world_model");
  if (!items.length) return "";
  const rows = items.map((e) => `<div class="prov-row"><dt>${txt(e.field)}</dt><dd>${linkReceipts(e.value, c.receiptIds)}${
    e.as_of ? ` <span class="sub nw">as of ${esc(fmtDay(e.as_of))}</span>` : ""} <span class="sub mono nw">${esc(e.source)}${e.query ? ` · ${esc(e.query)}` : ""}</span></dd></div>`).join("");
  return `<div class="prov"><h4>Provenance (World Model engine)</h4><dl class="prov-list">${rows}</dl></div>`;
}

/** Evidence items sharing source, query, field, as-of and read mode are one row, with every value listed. */
function evidenceTable(ev: Evidence[], c: Ctx): string {
  const items = ev.filter((e) => e.source !== "world_model");
  if (!items.length) return `<p class="empty">No evidence recorded.</p>`;
  const groups = new Map<string, Evidence[]>();
  for (const e of items) {
    const k = JSON.stringify([str(e.source), str(e.query), str(e.field), str(e.as_of), e.live === true, str(e.sql_hash)]);
    groups.set(k, [...(groups.get(k) ?? []), e]);
  }
  const SHOW = 8;
  const rows = [...groups.values()].map((g) => {
    const e = g[0];
    const vals = g.map((x) => `<div class="mono">${linkReceipts(x.value, c.receiptIds) || DASH}</div>`);
    const valueCell = vals.length <= SHOW + 1
      ? vals.join("")
      : `${vals.slice(0, SHOW).join("")}<details class="more"><summary>${vals.length - SHOW} more</summary>${vals.slice(SHOW).join("")}</details>`;
    return `<tr><td class="mono">${txt(e.source)}</td><td>${txt(e.field)}${g.length > 1 ? ` <span class="sub">×${g.length}</span>` : ""}</td><td>${valueCell}</td><td class="mono">${txt(e.query)}${
      e.sql_hash ? `<div class="sub">sql ${esc(e.sql_hash)}</div>` : ""}</td><td class="nw">${txt(e.as_of)}</td><td>${
      e.live ? badge("live", "live") : badge(c.sample ? "snapshot" : "not live", "notlive")}</td></tr>`;
  });
  return table(["Source", "Field", "Value", "Query", "As of", "Read"], rows, "compact evidence");
}

function ultraNote(l: PatchLine, c: Ctx): string {
  const a = c.facts?.adjudications.find((x) => x.row_id === l.row_id);
  if (!a) return "";
  return `<p class="ultra-note">${badge("Ultra", "m-ultra")} decided this jury split: Bolt ${esc(pickText(a.bolt))}, Lightning ${esc(pickText(a.lightning))} → <strong>${esc(pickText(a.ultra))}</strong>${
    a.sided_with ? ` (sided with ${esc(a.sided_with)})` : ""}${a.reason ? `: ${esc(a.reason)}` : ""} · ${receiptLink(a.receipt_id, c.receiptIds)}</p>`;
}

function detailBody(l: PatchLine, c: Ctx): string {
  const notes = arr(l.verifier_notes);
  const dis = kevEpssDisagree(l, c.policy);
  return `${provenanceBlock(l, c)}<div class="detail-grid">
<div><h4>Resolution and jury votes</h4>${votesTable(l, c)}<p class="sub">confidence ${fmtConf(l.resolution?.confidence)}${l.resolution?.adjudicated_by ? ` · adjudicated by ${esc(l.resolution.adjudicated_by)}` : ""}</p>${ultraNote(l, c)}</div>
<div><h4>Critic</h4>${criticBlock(l.critic, c.policy)}<h4>Verifier</h4><p>${verifierBadge(l, c.sample, false)}</p>${
    notes.length ? `<ul class="reasons">${notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}</div>
</div>
<h4>KEV entries</h4>${kevTable(kevCves(l))}
<h4>EPSS</h4>${l.epss ? `<p>max ${esc(fmtProb(l.epss.max))} on <span class="mono">${txt(l.epss.cve_id)}</span>, percentile ${esc(fmtPercentile(l.epss.percentile))}${
    dis ? ` · ${badge("KEV and EPSS disagree", "warn")}` : ""}</p>` : `<p class="empty">No EPSS score for this line (not treated as 0).</p>`}
<h4>Evidence (source rows read through Zetaris, agent outputs and receipts)</h4>${evidenceTable(objs(l.evidence), c)}`;
}

const PATCH_COLS = 8;

function lineRows(l: PatchLine, c: Ctx): string {
  const dis = kevEpssDisagree(l, c.policy);
  const disNote = dis
    ? `<div class="note warn-note">Sources disagree: listed in KEV (exploited in the wild), but EPSS is ${esc(fmtProb(dis.epss))}, below your ${esc(fmtProb(dis.threshold))} threshold. Your rules put KEV first.</div>`
    : "";
  const unconfirmed = l.decision === "patch_now" && versionUnconfirmed(l) ? `<div class="tags">${badge("version unconfirmed · owner question", "warn")}</div>` : "";
  const ev = objs(l.evidence);
  const wm = worldModelProvenance(l);
  return `<tr class="line" id="${aid("line", l.row_id)}">
<td class="asset"><div class="dec">${decisionPill(l.decision)}</div><div class="strong">${txt(l.asset_name)}</div><div class="sub mono">${txt(l.asset_id)}</div>${l.internet_facing ? badge("internet-facing", "inet") : ""}</td>
<td class="sw"><div class="mono">${txt(l.software)}</div><div class="sub">row ${txt(l.row_id)}</div></td>
<td class="res">${resolvedCell(l, c)}</td>
<td class="kev">${kevCell(l)}</td>
<td class="tgt">${targetCell(l)}</td>
<td>${epssCell(l)}</td>
<td class="ver">${verifiedCell(l, c.sample)}</td>
<td class="why">${txt(l.why)}${unconfirmed}${disNote}</td>
</tr>
<tr class="detail"><td colspan="${PATCH_COLS}"><details><summary>Evidence and provenance · ${plural(ev.length, "item")} · critic ${esc(rubricText(l.critic))}${
    wm ? ` · <span class="wm">World Model: ${esc(wm.value)}</span>` : ""}</summary>${detailBody(l, c)}</details></td></tr>`;
}

function groupNote(d: Decision, policy: Policy | null): string {
  const sla = policy?.sla_days;
  if (d === "patch_now") return sla ? `house target: within ${esc(sla.patch_now)} days` : "";
  if (d === "this_cycle") return sla ? `house target: within ${esc(sla.this_cycle)} days` : "";
  if (d === "monitor") return sla ? `review every ${esc(sla.monitor_review)} days` : "";
  return "needs your answer before a decision";
}

function patchList(c: Ctx): string {
  const lines = c.lines;
  if (!lines.length) return section("patch-list", "Patch list", `<p class="empty">No patch lines in this run.</p>`);
  const head: [string, string][] = [
    ["Decision · asset", "c-asset"], ["Software (as written)", "c-sw"], ["Resolved KEV product", "c-res"],
    ["KEV due (US federal benchmark)", "c-kev"], ["Target (your rule)", "c-tgt"], ["Max EPSS", "c-epss"], ["Verified", "c-ver"], ["Why", "c-why"],
  ];
  const groups: [string, string, PatchLine[]][] = DECISIONS.map((d) => [d, DECISION_LABEL[d], lines.filter((l) => l.decision === d)]);
  const other = lines.filter((l) => !DECISIONS.includes(l.decision));
  if (other.length) groups.push(["other", "Other", other]);
  const bodies = groups.filter(([, , ls]) => ls.length > 0).map(([d, label, ls]) => {
    const note = d === "other" ? "" : groupNote(d as Decision, c.policy);
    return `<tbody id="bucket-${d}" class="grp"><tr class="grp-head"><th colspan="${PATCH_COLS}">${decisionPill(d === "other" ? label : d)} ${plural(ls.length, "line")}${note ? ` · <span class="muted">${note}</span>` : ""}</th></tr>${
      ls.map((l) => lineRows(l, c)).join("")}</tbody>`;
  }).join("");
  return section("patch-list", "Patch list",
    `<div class="scroll patch-wrap"><table class="patch"><thead><tr>${head.map(([h, cls]) => `<th class="${cls}">${esc(h)}</th>`).join("")}</tr></thead>${bodies}</table></div>`,
    "Grouped by decision, in the order the Exposure Analyst ranked them. Open a line for its provenance, evidence, votes, critic score and receipts.");
}

// ---------- owner questions ----------

function ownerQuestions(c: Ctx): string {
  const qs = objs(c.resp.owner_questions);
  if (!qs.length) return section("owner-questions", "Owner questions", `<p class="empty">No questions for you in this run.</p>`);
  const rows = qs.map((q) => {
    // a grouped question (one per Windows edition) carries the rows it covers in row_ids
    const ids = arr((q as unknown as { row_ids?: unknown[] }).row_ids).map(str).filter(Boolean);
    const covered = ids.length > 1 ? `<div class="sub">covers ${ids.map((id) => lineLink(id, c.lineIds, id)).join(", ")}</div>` : "";
    const link = c.lineIds.has(String(q.row_id)) ? `<a href="#${aid("line", q.row_id)}">row ${esc(q.row_id)}</a>` : `row ${txt(q.row_id)}`;
    return `<tr><td>${txt(q.asset_name)}<div class="sub">${link}</div>${covered}</td><td class="strong">${txt(q.question)}</td><td>${txt(q.reason)}</td></tr>`;
  });
  return section("owner-questions", "Owner questions", table(["Asset", "Question", "Why we ask"], rows, "questions"),
    "These lines were not decided automatically, or need one fact from you. Your answer lets the next run decide them.");
}

// ---------- models at work ----------

/** What a receipted call was used for, in the trace's own words. */
function usedFor(rid: string | null | undefined, c: Ctx): string {
  if (!rid || !c.facts) return "";
  const evs = c.facts.byReceipt.get(rid) ?? [];
  const parts = evs.map((e) => {
    const out = /^critic$/i.test(str(e.agent)) ? str(e.output_summary) || str(e.action) : str(e.output_summary);
    return [str(e.input_summary), out].filter(Boolean).join(" → ");
  }).filter(Boolean);
  return [...new Set(parts)].join(" · ");
}

function ultraAdjudications(c: Ctx): string {
  const adj = c.facts?.adjudications ?? [];
  if (!adj.length) return "";
  const rows = adj.map((a) => {
    const l = c.lineById.get(a.row_id);
    const line = `${lineLink(a.row_id, c.lineIds, l ? str(l.asset_name) : `row ${a.row_id}`)}<div class="sub mono">${esc(l ? l.software : a.row_id)}</div>`;
    const side = (who: string) => (a.sided_with === who ? " sided" : "");
    return `<tr class="adj"><td>${line}</td><td class="vote${side("bolt")}">${esc(pickText(a.bolt))}</td><td class="vote${side("lightning")}">${esc(pickText(a.lightning))}</td><td class="strong">${esc(pickText(a.ultra))}</td><td>${txt(a.sided_with)}</td><td>${clamp(a.reason, 2)}</td><td>${receiptLink(a.receipt_id, c.receiptIds)}</td></tr>`;
  });
  return `<h3 id="ultra">Jury splits decided by Ultra (${adj.length})</h3>${table(["Line", "Bolt said", "Lightning said", "Ultra decided", "Sided with", "Ultra's reason", "Receipt"], rows, "compact adjudications")}`;
}

function modelsSection(c: Ctx): string {
  const receipts = c.receipts;
  if (!receipts.length) {
    return section("models", "Models at work", `<p class="empty">No model calls in this run.${c.sample ? " Sample mode runs offline and calls no model." : ""}</p>`);
  }
  type Agg = { calls: number; errors: number; latency: number; pin: number; pout: number; mismatched: number; missing: number; agents: Map<string, number> };
  const agg = new Map<string, Agg>();
  for (const r of receipts) {
    const k = String(r.requested_model ?? "unknown");
    const a = agg.get(k) ?? { calls: 0, errors: 0, latency: 0, pin: 0, pout: 0, mismatched: 0, missing: 0, agents: new Map() };
    a.calls += 1;
    if (r.status !== "ok") a.errors += 1;
    a.latency += num(r.latency_ms) ?? 0;
    a.pin += num(r.prompt_tokens) ?? 0;
    a.pout += num(r.completion_tokens) ?? 0;
    if (r.routed_model && r.routed_model !== r.requested_model) a.mismatched += 1;
    if (!r.receipt_id) a.missing += 1;
    const ag = str(r.agent) || "unknown";
    a.agents.set(ag, (a.agents.get(ag) ?? 0) + 1);
    agg.set(k, a);
  }
  const ordered = [...agg.entries()].sort((x, y) => modelRank(x[0]) - modelRank(y[0]));
  const cards = ordered.map(([model, a]) => `<div class="mcard${modelName(model) === "Ultra" ? " ultra" : ""}">
<div class="mname">${esc(modelName(model))}</div><div class="mono sub">${esc(model)}</div>
<div class="mstats"><span><b>${a.calls}</b> ${a.calls === 1 ? "call" : "calls"}</span><span><b>${a.errors}</b> ${a.errors === 1 ? "error" : "errors"}</span><span><b>${esc(fmtMs(a.calls ? a.latency / a.calls : null))}</b> avg</span><span><b>${a.pin}</b>/<b>${a.pout}</b> tokens in/out</span></div>
<div class="magents">${[...a.agents.entries()].map(([ag, n]) => `<span class="mono">${esc(ag)}</span> ×${n}`).join(" · ")}</div>${
    a.mismatched ? `<div>${badge(`${a.mismatched} routed to a different model`, "bad")}</div>` : ""}${a.missing ? `<div>${badge(`${a.missing} without receipt ID`, "bad")}</div>` : ""}</div>`).join("");
  const withUse = !!c.facts;
  const rows = receipts.map((r, i) => {
    const ultra = isUltraReceipt(r);
    const mismatch = r.routed_model && r.routed_model !== r.requested_model;
    const anchor = r.receipt_id ? ` id="${aid("rcpt", r.receipt_id)}"` : "";
    const tok = num(r.prompt_tokens) !== null || num(r.completion_tokens) !== null ? `${txt(r.prompt_tokens)} / ${txt(r.completion_tokens)}` : DASH;
    const resp = r.response_model && r.response_model !== r.routed_model ? `<div class="sub">response: ${esc(r.response_model)}</div>` : "";
    const use = withUse ? `<td class="use">${(() => { const u = usedFor(r.receipt_id, c); return u ? clamp(u, 2) : DASH; })()}</td>` : "";
    return `<tr class="${ultra ? "ultra-row" : ""}"${anchor}><td>${i + 1}</td><td class="mono">${txt(r.agent)}</td><td class="nw">${ultra ? badge("Ultra", "ultra") + " " : ""}<span class="mono">${txt(r.requested_model)}</span></td><td class="mono nw">${txt(r.routed_model)}${
      mismatch ? ` ${badge("differs", "bad")}` : ""}${resp}</td><td class="mono nw">${r.receipt_id ? esc(r.receipt_id) : badge("missing", "bad")}</td><td class="nw">${esc(fmtMs(r.latency_ms))}</td><td class="nw">${tok}</td>${use}<td>${
      r.status === "ok" ? badge("ok", "ok") : `${badge(String(r.status ?? "error"), "bad")}${r.error ? `<div class="sub">${esc(r.error)}</div>` : ""}`}</td></tr>`;
  });
  const head = ["#", "Agent", "Requested model", "Routed model (receipt)", "Receipt ID", "Latency", "Tokens in / out", ...(withUse ? ["Used for (from the trace)"] : []), "Status"];
  return section("models", "Models at work",
    `<div class="mcards">${cards}</div>${ultraAdjudications(c)}<h3>Every call, with its receipt</h3>${table(head, rows, "receipts")}`,
    `Every model call in this run, with the receipt returned by Nightshift (requested model, the model it was routed to, receipt ID, latency). Ultra's calls are highlighted.`);
}

// ---------- critic ----------

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

const STEP_CLASS: Record<string, string> = {
  sent_back: "st-sent_back", blocked: "st-blocked", ok: "st-ok", changed: "st-fallback", unchanged: "st-other",
  "same product": "st-ok", "different product": "st-blocked", unclear: "st-other",
};
function stepLabel(s: CatchStep): string {
  if (s.kind === "critic") return s.status === "sent_back" ? "sent back" : s.status === "blocked" ? "to the owner" : s.status === "ok" ? "approved" : s.status;
  if (s.kind === "redecide") return s.status === "changed" ? "re-decided" : "kept its answer";
  return s.status;
}

function catchesTable(c: Ctx): string {
  const catches = c.facts?.catches;
  if (!catches || !catches.size) return "";
  const rows = [...catches.entries()].map(([rowId, steps]) => {
    const l = c.lineById.get(rowId);
    const line = `${lineLink(rowId, c.lineIds, l ? str(l.asset_name) : `row ${rowId}`)}<div class="sub mono">${esc(l ? l.software : rowId)}</div>`;
    const lis = steps.map((s) => {
      const who = s.actor.split(" + ").map((a) => (["Bolt", "Lightning", "Ultra"].includes(a) ? modelChip(a) : `<span class="who">${esc(a)}</span>`)).join(" + ");
      const what = s.proposal ? `<span class="prop">${esc(s.proposal)}</span> ` : "";
      const rub = s.rubric !== null ? `<span class="rub">${s.rubric}/9</span> ` : "";
      const rid = s.receipt_id && c.receiptIds.has(s.receipt_id) ? ` <a class="mono sub" href="#${aid("rcpt", s.receipt_id)}">receipt</a>` : "";
      return `<li>${who} <span class="st ${STEP_CLASS[s.status] ?? "st-other"}">${esc(stepLabel(s))}</span> ${what}${rub}${s.text ? clamp(s.text, 2) : ""}${rid}</li>`;
    }).join("");
    const outcome = l
      ? `${decisionPill(l.decision)}<div class="sub">${l.resolution?.vendor || l.resolution?.product ? esc(`${l.resolution?.vendor ?? ""} / ${l.resolution?.product ?? ""}`) : "no KEV product"}</div>`
      : DASH;
    return `<tr class="catch" id="${aid("catch", rowId)}"><td>${line}</td><td><ul class="steps">${lis}</ul></td><td>${outcome}</td></tr>`;
  });
  return `<h3>Catches: matches the critic sent back, and what happened next (${catches.size})</h3>${
    table(["Line", "The loop, in order (critic, re-decides, Ultra checks)", "Final"], rows, "catches")}`;
}

function criticSection(c: Ctx): string {
  const { lines, policy, trace } = c;
  const flagged = lines.filter((l) => l.critic && l.critic.verdict !== "approve");
  const approved = lines.filter((l) => l.critic && l.critic.verdict === "approve");
  const noVerdict = lines.filter((l) => !l.critic).length;
  const verdictRows = flagged.map((l) => {
    const cv = l.critic as CriticVerdict;
    const gate = belowThreshold(cv.rubric?.total, policy);
    return `<tr><td><a href="#${aid("line", l.row_id)}">${txt(l.asset_name)}</a><div class="sub mono">${txt(l.software)}</div></td><td>${decisionPill(l.decision)}</td><td>${badge(String(cv.verdict).replace("_", " "), cv.verdict === "send_back" ? "v-send_back" : "v-ask_owner")}</td><td>${txt(cv.round)}</td><td class="strong">${esc(rubricText(cv))}${gate ? `<div class="sub thin">${esc(gate)}</div>` : ""}</td><td>${esc(autonomy(cv.verdict)) || DASH}</td><td>${
      arr(cv.reasons).length ? `<ul class="reasons">${arr(cv.reasons).map((x) => `<li>${clamp(str(x), 2)}</li>`).join("")}</ul>` : DASH}</td></tr>`;
  });
  const verdicts = flagged.length
    ? table(["Line", "Decision", "Final verdict", "Round", "Rubric", "Autonomy", "Reasons"], verdictRows, "verdicts")
    : `<p class="empty">No line ended blocked or sent to the owner by the critic.</p>`;
  const counts = `<p class="lead">${esc(plural(approved.length, "line"))} approved · ${esc(plural(flagged.length, "line"))} blocked or sent to the owner${
    noVerdict ? ` · ${esc(plural(noVerdict, "line"))} without a critic verdict` : ""}.</p>`;
  const rounds = c.facts?.rounds.length
    ? `<div class="rounds">${c.facts.rounds.map((e) => `<div class="round"><div class="round-h">${esc(str(e.input_summary) || str(e.action))}</div><div>${esc(str(e.output_summary))}</div></div>`).join("")}</div>`
    : "";
  let timeline: string;
  if (trace) {
    const evs = trace.filter((e) => isCriticEvent(e) && (e.status === "sent_back" || e.status === "blocked"));
    timeline = evs.length
      ? `<details class="events"><summary>${esc(plural(evs.length, "critic event"))} in the trace (send-backs and blocks, in order)</summary>${
        table(["Time", "Agent", "Action", "Status", "To", "Rubric", "Detail"], evs.map((e) => {
          const d = detailsObj(e);
          const rub = d.rubric && typeof d.rubric === "object" ? num((d.rubric as Record<string, unknown>).total) : num(d.rubric_total);
          const reasons = Array.isArray(d.reasons) ? (d.reasons as unknown[]).map(str).filter(Boolean) : [];
          const detail = [str(e.input_summary), str(e.output_summary), ...reasons].filter(Boolean);
          return `<tr><td class="mono">${esc(timeOf(e.ts))}</td><td>${txt(e.agent)}</td><td>${txt(e.action)}</td><td>${statusPill(e.status)}</td><td>${txt(e.target_agent)}</td><td>${rub === null ? DASH : `${rub}/9`}</td><td>${
            detail.length ? detail.map((x) => `<div>${esc(x)}</div>`).join("") : DASH}${num(e.retry_count) ? `<div class="sub">retry ${esc(e.retry_count)}</div>` : ""}</td></tr>`;
        }), "compact")}</details>`
      : `<p class="empty">The trace has no critic send-backs or blocks.</p>`;
  } else {
    timeline = `<p class="empty">Trace not attached to this report. The full trace is in <span class="mono">${txt(c.resp.trace_file)}</span>.</p>`;
  }
  return section("critic", "Critic: blocks, send-backs and questions",
    `${counts}${rounds}${catchesTable(c)}<h3>Lines the critic did not approve (final verdict)</h3>${verdicts}<h3>Critic events in the trace</h3>${timeline}`);
}

// ---------- timing ----------

/**
 * The NVD tile, from the run's per-CVE outcomes: records read now, cached, failed and not looked up are counted apart
 * (a failed lookup is not a record). Sample mode reads the snapshot, so it never says "live". Without outcomes, the
 * NVD lookups in the trace; with neither, no tile.
 */
function nvdTile(nvd: NvdFacts, sample: boolean): [string, string] | null {
  const time = nvd.ms !== null ? `, ${fmtMs(nvd.ms)}` : "";
  const s = nvd.states;
  if (!s) return nvd.lookups ? [String(nvd.lookups), `NVD ${nvd.lookups === 1 ? "lookup" : "lookups"} in the trace${time}`] : null;
  const more = [
    s.fallback && !sample ? `${s.fallback} from the fallback copy` : "",
    s.error ? `${s.error} ${sample ? "missing from the snapshot" : "failed"}` : "",
    s.skipped_budget ? `${s.skipped_budget} not looked up in this run (NVD budget)` : "",
    s.dormant ? `${s.dormant} not looked up (NVD helper dormant)` : "",
  ].filter(Boolean);
  const head = sample ? `${s.read + s.cached + s.fallback} from the snapshot` : `${s.read} live · ${s.cached} cached`;
  return [head, `NVD CVE records${time}${more.length ? `; ${more.join("; ")}` : ""}`];
}

function timingSection(c: Ctx): string {
  const { resp, receipts, trace } = c;
  const all = Object.entries(resp.timing_ms ?? {}).filter(([, v]) => num(v) !== null) as [string, number][];
  const total = all.find(([k]) => k === "total")?.[1] ?? null;
  const phases = all.filter(([k]) => k !== "total");
  const max = Math.max(total ?? 0, phases.reduce((m, [, v]) => Math.max(m, v), 0));
  const bars = phases.length
    ? `<div class="bars">${phases.map(([k, v]) => `<div class="bar-row"><span class="bar-k">${esc(k)}</span><span class="bar"><span class="bar-fill" style="width:${max > 0 ? ((v / max) * 100).toFixed(1) : "0"}%"></span></span><span class="bar-v">${esc(fmtMs(v))}</span></div>`).join("")}</div>`
    : total === null ? `<p class="empty">No phase timings recorded.</p>` : "";
  const phaseSum = phases.reduce((s, [, v]) => s + v, 0);
  const overlap = total !== null && phases.length && phaseSum > total
    ? `<p class="sub">The phases add up to ${esc(fmtMs(phaseSum))} against ${esc(fmtMs(total))} end to end: some of them ran at the same time.</p>` : "";
  const modelMs = receipts.reduce((s, r) => s + (num(r.latency_ms) ?? 0), 0);
  const zq = c.facts?.zetaris ?? [];
  const zTotal = zq.reduce((s, q) => s + (q.ms ?? 0), 0);
  const tiles: [string, string][] = [];
  if (total !== null) tiles.push([fmtMs(total), "end to end, the whole run"]);
  if (zq.length) tiles.push([fmtMs(zTotal), `in Zetaris: ${plural(zq.filter((q) => q.kind === "query").length, "query", "queries")}, ${plural(zq.filter((q) => q.kind === "ddl").length, "table registration")}`]);
  tiles.push(receipts.length ? [fmtMs(modelMs), `in ${plural(receipts.length, "model call")}, summed (they run in parallel)`] : ["0", "model calls"]);
  const nvd = c.facts?.nvd ? nvdTile(c.facts.nvd, c.sample) : null;
  if (nvd) tiles.push(nvd);
  const tileHtml = `<div class="tiles">${tiles.map(([n, l]) => `<div class="tile"><div class="tile-n">${esc(n)}</div><div class="tile-l">${esc(l)}</div></div>`).join("")}</div>`;
  let zhtml = "";
  if (trace) {
    if (zq.length) {
      const rows = zq.map((q) => {
        const cache = q.fromCache === true ? "from cache" : q.fromCache === false ? "read now" : DASH;
        const mode = q.cacheMode === "bypass" ? `<div class="sub">cache bypassed</div>` : "";
        return `<tr><td class="mono">${esc(timeOf(q.ts))}</td><td class="q">${esc(q.label)}${q.sql ? `<div class="sqlprev mono">${esc(q.sql)}</div><details class="sql"><summary>SQL${q.sqlHash ? ` · ${esc(q.sqlHash)}` : ""}</summary><pre>${esc(q.sql)}</pre></details>` : ""}</td><td>${
          q.kind === "ddl" ? "register" : "query"}</td><td class="nw">${esc(fmtMs(q.ms))}</td><td>${q.rows === null ? DASH : q.rows}</td><td class="nw">${esc(cache)}${mode}</td><td>${statusPill(q.status)}</td></tr>`;
      });
      zhtml = `<h3>Zetaris queries (${zq.length}, ${esc(fmtMs(zTotal))} in total)</h3>${table(["Time", "Query (SQL as sent)", "Kind", "Time taken", "Rows", "Cache", "Status"], rows, "compact zq")}`;
    } else {
      zhtml = `<h3>Zetaris queries</h3><p class="empty">The trace has no timed Zetaris queries${c.sample ? " (sample mode reads the saved snapshot instead)" : ""}.</p>`;
    }
  } else {
    zhtml = `<h3>Zetaris queries</h3><p class="empty">Trace not attached; per-query times are in <span class="mono">${txt(resp.trace_file)}</span>.</p>`;
  }
  return section("timing", "Timing",
    `${tileHtml}${bars}${overlap}${receipts.length ? `<p class="sub">Model time, summed over ${plural(receipts.length, "call")}: ${esc(fmtMs(modelMs))} (calls run in parallel, so this can exceed the run time).</p>` : ""}${zhtml}`,
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

function runDetails(c: Ctx): string {
  const resp = c.resp;
  const m = resp.manifest;
  const models = m?.models ? Object.entries(m.models).map(([k, v]) => `<li>${esc(modelName(k))}: <span class="mono">${esc(v)}</span></li>`).join("") : "";
  const helpers = (xs: string[] | undefined) => (arr(xs).length ? arr(xs).map((h) => `<span class="badge neutral">${esc(h)}</span>`).join(" ") : DASH);
  const queue = c.facts?.reviewQueue ?? [];
  return section("run-details", "Run details", `<dl class="kv">
<dt>Engine</dt><dd>${txt(m?.engine)} <span class="sub mono">${txt(m?.engine_source)}</span></dd>
${queue.length ? `<dt>World Model review queue</dt><dd>${queue.map((q) => `<span class="badge neutral">${esc(q)}</span>`).join(" ")} <span class="sub">near-duplicate KEV spellings the engine queued for a human merge review</span></dd>` : ""}
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
--ok:#1f6b3b;--ok-bg:#e1f2e6;--bad:#a5281b;--bad-bg:#fde9e6;--warn:#7a4d00;--warn-bg:#fff4d6;--ultra:#0b5a6e;--ultra-bg:#dff3f7;
--navh:46px}
*{box-sizing:border-box}html{color-scheme:light;scroll-padding-top:calc(var(--navh) + 10px)}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1860px;margin:0 auto;padding:16px 28px 40px}
a{color:var(--accent)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:.92em}
.strong{font-weight:600}.muted{color:var(--muted)}.sub{color:var(--muted);font-size:13px;line-height:1.4}.thin{font-weight:400;color:var(--muted)}
h1{margin:0;font-size:30px;letter-spacing:-.01em}h2{margin:0 0 12px;font-size:22px}h3{margin:22px 0 8px;font-size:18px}h4{margin:14px 0 6px;font-size:15px}
.top{display:flex;flex-wrap:wrap;gap:12px 40px;align-items:flex-end;justify-content:space-between;margin-bottom:12px}
.tag{margin:2px 0 0;color:var(--muted);font-size:17px}
.meta{display:flex;flex-wrap:wrap;gap:8px 28px;margin:0}.meta div{min-width:100px}.meta dt{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}.meta dd{margin:0;font-weight:600}
.banner{border-radius:8px;padding:12px 16px;margin:0 0 12px;font-size:17px;border:1px solid}
.banner .b2{display:block;font-size:14.5px;margin-top:4px}
.banner.sample{background:repeating-linear-gradient(135deg,#fff3cd 0 18px,#ffecb0 18px 36px);border:2px solid #d9a400;color:#4d3700;font-size:19px;padding:14px 18px}
.banner.sample strong:first-child{font-size:21px;letter-spacing:.04em}
.banner.live{background:var(--ok-bg);border-color:#9fd1ae;color:var(--ok)}
.banner.error{background:var(--bad-bg);border-color:#f0a99f;color:var(--bad)}.banner.warn{background:var(--warn-bg);border-color:#e9c46a;color:var(--warn)}
.nav{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:0 -28px 14px;padding:7px 28px;min-height:var(--navh);background:rgba(244,246,248,.96);border-bottom:1px solid var(--line)}
.nav a{padding:4px 12px;border-radius:999px;background:var(--card);border:1px solid var(--line);color:var(--accent);text-decoration:none;font-size:14px}
.nav-mode{font-weight:700;font-size:13.5px;padding:4px 10px;border-radius:6px;letter-spacing:.03em}
.nav-mode.m-live{background:var(--ok-bg);color:var(--ok);border:1px solid #9fd1ae}.nav-mode.m-sample{background:#ffe08a;color:#4d3700;border:1px solid #d9a400}
.nav-run{font-size:13.5px;color:var(--muted);margin:0 8px 0 2px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:0 0 16px}
.card.split{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:28px}
.lead{margin:0 0 12px;color:var(--muted)}.empty{color:var(--muted);font-style:italic;margin:6px 0}
.chips{display:flex;flex-wrap:wrap;gap:12px}
.chip{display:flex;align-items:baseline;gap:10px;padding:10px 18px;border-radius:10px;text-decoration:none;border:1px solid transparent;min-width:170px}
.chip-n{font-size:34px;font-weight:700;line-height:1}.chip-l{font-size:17px;font-weight:600}.chip.zero{opacity:.55}
.stats{display:flex;flex-wrap:wrap;gap:4px 24px;margin:12px 0 0;padding:0;list-style:none;color:var(--muted)}
.steps-row{display:flex;align-items:stretch;gap:6px}
.step{flex:1 1 0;min-width:0;border:1px solid var(--line);border-radius:8px;padding:9px 11px;background:#fafbfc}
.step-h{font-weight:700;font-size:15px;margin-bottom:4px}.step-h .badge{margin:0 0 0 2px;font-size:11.5px;padding:0 6px}
.step-t{font-size:13px;line-height:1.4;color:#2b3138;margin-top:3px;overflow-wrap:anywhere}
.arrow{align-self:center;color:var(--muted);font-size:18px}
.d-patch_now{background:var(--now-bg);color:var(--now)}.d-this_cycle{background:var(--cyc-bg);color:var(--cyc)}
.d-monitor{background:var(--mon-bg);color:var(--mon)}.d-ask_owner{background:var(--own-bg);color:var(--own)}.d-other{background:var(--soft);color:var(--ink)}
.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:700;font-size:13.5px;white-space:nowrap}
.badge{display:inline-block;padding:1px 8px;border-radius:5px;font-size:12.5px;font-weight:600;margin:2px 4px 2px 0;border:1px solid transparent;white-space:nowrap;text-decoration:none}
.badge.wrap{white-space:normal}
.badge.ok,.badge.live,.badge.v-approve,.badge.st-success{background:var(--ok-bg);color:var(--ok)}
.badge.bad,.badge.st-error{background:var(--bad-bg);color:var(--bad)}
.badge.notlive,.badge.neutral,.badge.st-other{background:var(--soft);color:var(--muted);border-color:var(--line)}
.badge.inet{background:#e7eefc;color:#1d4fa3;border-color:#b8cbf0}.badge.warn,.badge.st-partial{background:var(--warn-bg);color:var(--warn)}
.badge.ultra,.badge.m-ultra{background:var(--ultra-bg);color:var(--ultra);border-color:#9fd3df}.badge.split{background:#fbe8f3;color:#8b1f5c}
.badge.m-lightning{background:#eef0ff;color:#3a3fa0;border-color:#c9ccf5}.badge.m-bolt{background:#f1f5e6;color:#4a5d12;border-color:#d3dfb0}.badge.m-neutral{background:var(--soft);color:var(--muted)}
.badge.caught{background:var(--own-bg);color:var(--own);border-color:#d3c7f5}
.badge.v-send_back{background:var(--warn-bg);color:var(--warn)}.badge.v-ask_owner{background:var(--own-bg);color:var(--own)}
.tags{margin-top:4px}.tags .sub{margin-right:6px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid var(--line)}
thead th{background:var(--soft);font-size:12.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
table.compact{font-size:13.5px}table.compact th,table.compact td{padding:5px 8px}
table.patch>tbody>tr>td{padding:8px 9px;overflow-wrap:anywhere}
table.patch>tbody>tr>td.why{font-size:14px;line-height:1.45;overflow-wrap:normal}
@media (min-width:1200px){table.patch{table-layout:fixed}
table.patch th.c-asset{width:11%}table.patch th.c-sw{width:13%}table.patch th.c-res{width:15%}table.patch th.c-kev{width:10.5%}
table.patch th.c-tgt{width:9%}table.patch th.c-epss{width:8%}table.patch th.c-ver{width:7%}table.patch th.c-why{width:26.5%}}
@media (min-width:1200px) and (max-width:1600px){table.patch th.c-asset{width:12%}table.patch th.c-kev{width:11%}table.patch th.c-tgt{width:10%}table.patch th.c-epss{width:9%}table.patch th.c-ver{width:8%}table.patch th.c-why{width:22%}}
td.asset .dec{margin-bottom:3px}
@media (max-width:1199px){table.patch>tbody>tr>td.why{min-width:320px}table.patch>tbody>tr>td.sw,table.patch>tbody>tr>td.res{min-width:170px}}
.nw{white-space:nowrap}
tr.grp-head th{background:#fafbfc;font-size:15px;padding:12px 10px;border-top:2px solid var(--line);text-transform:none;letter-spacing:0;color:var(--ink)}
tr.line td{border-bottom:none}tr.detail td{padding:0 10px 8px}
tr.line,tbody.grp,tr.catch{scroll-margin-top:calc(var(--navh) + 72px)}
table.patch>tbody>tr.detail>td{padding:0 9px 8px}
table.patch>tbody>tr>td.ver .badge{white-space:normal}
tr.detail summary{cursor:pointer;color:var(--accent);font-size:13.5px;padding:1px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
tr.detail summary .wm{color:var(--muted)}
tr.detail details[open]{background:#fafbfc;border:1px solid var(--line);border-radius:8px;padding:6px 14px 12px}
tr.detail details[open] summary{white-space:normal}
.detail-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px}
.prov{margin:6px 0 4px;padding:8px 12px;border-left:4px solid var(--ultra);background:var(--ultra-bg);border-radius:6px}
.prov h4{margin:0 0 4px}.prov-list{margin:0}.prov-row{display:grid;grid-template-columns:220px 1fr;gap:10px;padding:2px 0}
.prov-row dt{color:var(--muted);font-size:13.5px}.prov-row dd{margin:0;font-size:14px}
.ultra-note{font-size:13.5px;margin:6px 0}
table.evidence td:nth-child(3){max-width:640px;overflow-wrap:anywhere}
details.more summary{cursor:pointer;color:var(--accent);font-size:12.5px}
.overdue{color:var(--now);font-weight:700}
.note{margin-top:6px;padding:6px 9px;border-radius:6px;font-size:13.5px}.warn-note{background:var(--warn-bg);color:var(--warn)}
.reasons{margin:4px 0;padding-left:20px}.rules{margin:0;padding-left:0;list-style:none}.rules li{margin:0 0 10px}
.clamp{display:-webkit-box;-webkit-box-orient:vertical;overflow:hidden}.clamp.c1{-webkit-line-clamp:1}.clamp.c2{-webkit-line-clamp:2}.clamp.c3{-webkit-line-clamp:3}
li .clamp,.steps .clamp{display:-webkit-inline-box;vertical-align:top}
.mcards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:6px}
.mcard{flex:1 1 300px;max-width:560px;border:1px solid var(--line);border-radius:8px;padding:10px 14px}.mcard.ultra{border-color:#9fd3df;background:var(--ultra-bg)}
.mname{font-size:19px;font-weight:700}.mstats{display:flex;flex-wrap:wrap;gap:4px 16px;margin-top:6px;font-size:14.5px}
.magents{margin-top:4px;font-size:13px;color:var(--muted)}
tr.ultra-row td{background:var(--ultra-bg)}
table.receipts td.use{min-width:300px;font-size:13px;color:#2b3138}
@media (max-width:1600px){table.receipts td.nw.mono,table.receipts td.nw{white-space:normal;overflow-wrap:anywhere}table.receipts td.use{min-width:220px}}
table.adjudications td.vote{color:var(--muted)}table.adjudications td.vote.sided{color:var(--ink);font-weight:600}
table.adjudications td:nth-child(6){min-width:320px}
.st{display:inline-block;padding:1px 8px;border-radius:5px;font-size:12.5px;font-weight:600;background:var(--soft);color:var(--muted);white-space:nowrap}
.st-ok,.st-success{background:var(--ok-bg);color:var(--ok)}.st-error{background:var(--bad-bg);color:var(--bad)}
.st-fallback{background:var(--warn-bg);color:var(--warn)}.st-blocked{background:var(--bad-bg);color:var(--bad)}.st-sent_back{background:var(--own-bg);color:var(--own)}
.rounds{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 6px}.round{flex:1 1 260px;border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-size:14px;background:#fafbfc}.round-h{font-weight:700}
.steps{margin:0;padding-left:0;list-style:none}.steps li{margin:0 0 5px;font-size:13.5px;line-height:1.45}
.steps .badge{margin:0}.who{font-weight:700}.prop{font-weight:600}.rub{font-weight:700;color:var(--own)}
table.catches td:first-child{min-width:200px;max-width:280px}table.catches td:nth-child(3){min-width:140px}
table.verdicts td:last-child{min-width:420px}
table.questions td:first-child{min-width:170px;max-width:240px}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin:0 0 14px}
.tile{border:1px solid var(--line);border-radius:8px;padding:8px 16px;min-width:200px;background:#fafbfc}.tile-n{font-size:24px;font-weight:700;font-variant-numeric:tabular-nums}.tile-l{font-size:13.5px;color:var(--muted)}
.bars{display:grid;gap:6px;max-width:1200px}.bar-row{display:grid;grid-template-columns:200px 1fr 90px;gap:12px;align-items:center}
.bar{height:16px;background:var(--soft);border-radius:4px;overflow:hidden}.bar-fill{display:block;height:100%;background:var(--accent)}.bar-v{text-align:right;font-variant-numeric:tabular-nums}
.sqlprev{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:min(900px,50vw);color:#2b3138;font-size:12.5px;margin-top:2px}
details.sql summary{cursor:pointer;color:var(--accent);font-size:12.5px}pre{white-space:pre-wrap;word-break:break-word;background:var(--soft);padding:8px;border-radius:6px;font-size:12.5px;margin:6px 0}
details.events summary{cursor:pointer;color:var(--accent);font-size:14px;margin:4px 0}
.kv{display:grid;grid-template-columns:220px 1fr;gap:6px 16px;margin:0}.kv dt{color:var(--muted)}.kv dd{margin:0}.plain{margin:0;padding-left:18px}
.caveats{border-top:3px solid var(--line);padding:16px 4px 0;color:#2b3138}.caveats h2{font-size:18px}.caveats ul{margin:0;padding-left:20px}.caveats li{margin:4px 0}
@media (min-width:1200px){.patch-wrap{overflow:visible}table.patch>thead>tr>th{position:sticky;top:var(--navh);z-index:5;box-shadow:0 1px 0 var(--line)}}
@media (max-width:1300px){.steps-row{flex-wrap:wrap}.step{flex:1 1 220px}.arrow{display:none}}
@media (max-width:900px){main{padding:14px 16px}.nav{margin:0 -16px 14px;padding:7px 16px}.card.split,.detail-grid{grid-template-columns:1fr}.bar-row{grid-template-columns:120px 1fr 70px}.prov-row{grid-template-columns:1fr}}
@media print{.nav{position:static}body{background:#fff}.card{break-inside:avoid}.clamp{display:inline;-webkit-line-clamp:unset}}
`;

/** Renders the self-contained HTML report for one run. */
export function renderReport(resp: RunResponse, opts: RenderOptions = {}): string {
  const r = (resp ?? {}) as RunResponse;
  const lines = objs(r.lines);
  const receipts = objs(r.receipts);
  const trace = Array.isArray(opts.trace) ? objs(opts.trace) : null;
  const c: Ctx = {
    resp: r,
    lines,
    receipts,
    policy: r.manifest?.policy ?? null,
    sample: r.mode === "sample",
    trace,
    facts: trace ? indexTrace(trace, receipts) : null,
    receiptIds: new Set(receipts.map((x) => x.receipt_id).filter((x): x is string => typeof x === "string" && x !== "")),
    lineIds: new Set(lines.map((l) => String(l.row_id))),
    lineById: new Map(lines.map((l) => [String(l.row_id), l])),
  };
  const cap = Math.max(1, Math.floor(num(opts.maxTimelineEvents) ?? 400));
  const title = `ExposureLedger report · ${str(r.run_id) || "run"}${c.sample ? " · SAMPLE MODE" : ""}`;
  return `<!doctype html>
<html lang="en" data-mode="${c.sample ? "sample" : "live"}">
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
${header(c)}
${nav(c)}
${summarySection(c)}
${pipelineSection(c)}
${patchList(c)}
${ownerQuestions(c)}
${sourcesAndRules(c)}
${modelsSection(c)}
${criticSection(c)}
${timingSection(c)}
${timelineSection(trace, cap)}
${runDetails(c)}
${footer()}
</main>
</body>
</html>
`;
}
