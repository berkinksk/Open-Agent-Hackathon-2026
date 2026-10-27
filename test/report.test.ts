import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MODELS } from "../src/contracts.ts";
import type { RunResponse, TraceEvent } from "../src/contracts.ts";
import { esc, maskCredentials, maskLocalPaths, renderReport } from "../src/report/render.ts";
import { indexTrace, pickText } from "../src/report/trace-facts.ts";
import { normaliseTraceEvent, parseTraceJsonl } from "../src/report/trace-input.ts";
import { isSafeRunId, loadReportHtml, loadTrace, writeReport } from "../src/report/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(here, "fixtures", "run-sample.json");
const fixture = (): RunResponse => JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as RunResponse;

function sectionOf(html: string, id: string): string {
  const m = new RegExp(`<section id="${id}"[\\s\\S]*?</section>`).exec(html);
  assert.ok(m, `section #${id} missing`);
  return m[0];
}
function lineRow(html: string, rowId: string): string {
  const m = new RegExp(`<tr class="line" id="line-${rowId}">[\\s\\S]*?</tr>`).exec(html);
  assert.ok(m, `line row ${rowId} missing`);
  return m[0];
}
/** The expandable detail row that follows a line's row in the patch list. */
function detailRow(html: string, rowId: string): string {
  const m = new RegExp(`<tr class="line" id="line-${rowId}">[\\s\\S]*?</tr>\\s*(<tr class="detail">[\\s\\S]*?</details></td></tr>)`).exec(html);
  assert.ok(m, `detail row ${rowId} missing`);
  return m[1];
}
/** A line's row in the critic section's final-verdict table. */
function criticRow(criticSection: string, rowId: string): string {
  const m = new RegExp(`<tr><td><a href="#line-${rowId}">[\\s\\S]*?</tr>`).exec(criticSection);
  assert.ok(m, `critic row ${rowId} missing`);
  return m[0];
}
function count(hay: string, needle: string | RegExp): number {
  if (typeof needle === "string") return hay.split(needle).length - 1;
  return (hay.match(new RegExp(needle.source, needle.flags.includes("g") ? needle.flags : needle.flags + "g")) ?? []).length;
}

function sampleTrace(): TraceEvent[] {
  return [
    { ts: "2026-10-26T20:00:01.100Z", run_id: "fixture-run-001", agent: "Zetaris", action: "sql_query", latency_ms: 2310, status: "ok",
      details: { label: "kevPairs", sql_hash: "abc123", rows: 1756, from_cache: false, sql: "SELECT vendor, product FROM el_core.el_kev_table WHERE n < 1" } },
    { ts: "2026-10-26T20:00:30.000Z", run_id: "fixture-run-001", agent: "jury", action: "vote", model: "nvidia/nemotron-3.5-bolt-e4b",
      routed_model: "nvidia/nemotron-3.5-bolt-e4b", receipt_id: "rcpt-fx-bolt-1", latency_ms: 6400, status: "ok", output_summary: "10 rows voted" },
    { ts: "2026-10-26T20:00:45.000Z", run_id: "fixture-run-001", agent: "critic", action: "review", target_agent: "resolver", status: "sent_back",
      retry_count: 1, input_summary: "r-005 Exchange Online", details: { row_id: "r-005", rubric: { total: 5 }, reasons: ["type conflict: cloud_service vs server"] } },
    { ts: "2026-10-26T20:00:58.000Z", run_id: "fixture-run-001", agent: "critic", action: "review", target_agent: "owner", status: "blocked",
      details: { row_id: "r-005", rubric_total: 4 } },
  ];
}

describe("renderReport: page shell", () => {
  test("is a self-contained HTML page with no scripts or external assets", () => {
    const html = renderReport(fixture());
    assert.ok(html.startsWith("<!doctype html>"));
    assert.match(html, /<meta charset="utf-8">/);
    assert.match(html, /Content-Security-Policy" content="default-src 'none'/);
    assert.match(html, /<title>ExposureLedger report · fixture-run-001<\/title>/);
    assert.match(html, /<style>[\s\S]+<\/style>/);
    for (const bad of [/<script/i, /<link/i, /<img/i, /<iframe/i, /@import/i, /url\(/i, /<[^>]+\ssrc=/i, /https?:\/\//i]) {
      assert.doesNotMatch(html, bad, `found ${bad}`);
    }
    const hrefs = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
    assert.ok(hrefs.length > 10);
    for (const h of hrefs) assert.ok(h.startsWith("#"), `external href ${h}`);
  });

  test("every in-page link points at an element that exists", () => {
    const html = renderReport(fixture(), { trace: sampleTrace() });
    const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
    for (const m of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.has(m[1]), `dangling link #${m[1]}`);
  });

  test("is deterministic", () => {
    assert.equal(renderReport(fixture()), renderReport(fixture()));
    assert.equal(renderReport(fixture(), { trace: sampleTrace() }), renderReport(fixture(), { trace: sampleTrace() }));
  });

  test("ends with the caveats footer", () => {
    const html = renderReport(fixture());
    const foot = /<footer class="caveats"[\s\S]*<\/footer>/.exec(html)?.[0] ?? "";
    for (const s of ["Decision support only", "The policy is yours", "No exploitability claims", "Synthetic inventory", "KEV due dates are US federal benchmarks"]) {
      assert.ok(foot.includes(s), `caveat missing: ${s}`);
    }
  });
});

describe("renderReport: header and mode stamp", () => {
  test("live run: run ID, as-of date, run time and a LIVE stamp; no sample banner", () => {
    const html = renderReport(fixture());
    assert.match(html, /<span class="mono">fixture-run-001<\/span>/);
    assert.match(html, /<dt>As of<\/dt><dd>2026-10-26<\/dd>/);
    assert.match(html, /<dt>Run time<\/dt><dd>72\.4 s<\/dd>/);
    assert.match(html, /<strong>LIVE MODE<\/strong>/);
    assert.ok(!html.includes("SAMPLE MODE"));
    assert.match(html, /data-mode="live"/);
  });

  test("sample run: SAMPLE MODE banner with the snapshot date, and snapshot labels", () => {
    const r = fixture();
    r.mode = "sample";
    r.receipts = [];
    r.manifest.sources = r.manifest.sources.map((s) => ({ ...s, live: false, as_of: "2026-10-25" }));
    const html = renderReport(r);
    const banner = /<div class="banner sample" id="mode-banner">[\s\S]*?<\/div>/.exec(html)?.[0] ?? "";
    assert.ok(banner.includes("SAMPLE MODE"));
    assert.ok(banner.includes("snapshot captured <strong>2026-10-25</strong>"));
    assert.ok(banner.includes("model calls in this run: 0"));
    assert.match(html, /<title>[^<]*SAMPLE MODE<\/title>/);
    assert.match(html, /data-mode="sample"/);
    assert.ok(!html.includes("LIVE MODE"));
    assert.ok(sectionOf(html, "sources").includes(">snapshot<"));
    assert.ok(lineRow(html, "r-001").includes("verified (snapshot)"));
  });

  test("sample run without source dates says the snapshot date was not recorded", () => {
    const r = fixture();
    r.mode = "sample";
    r.manifest.sources = r.manifest.sources.map((s) => ({ name: s.name, object: s.object, live: false }));
    assert.ok(renderReport(r).includes("snapshot date not recorded in this run"));
  });

  test("error and partial runs show a banner", () => {
    const r = fixture();
    r.status = "error";
    r.error = { type: "zetaris_unreachable", message: "watchdog fired after 120 s", recoverable: true };
    const html = renderReport(r);
    assert.match(html, /role="alert"><strong>Run error:<\/strong> zetaris_unreachable · watchdog fired after 120 s · recoverable/);
    const p = fixture();
    p.status = "partial";
    assert.ok(renderReport(p).includes("<strong>Partial run:</strong>"));
  });
});

describe("renderReport: summary, sources and rules", () => {
  test("summary chips show the four decision counts and link to their groups", () => {
    const sum = sectionOf(renderReport(fixture()), "summary");
    for (const [d, n] of [["patch_now", 2], ["this_cycle", 1], ["monitor", 1], ["ask_owner", 2]] as const) {
      assert.match(sum, new RegExp(`<a class="chip d-${d}" href="#bucket-${d}"><span class="chip-n">${n}</span>`));
    }
    assert.ok(sum.includes("6 lines · 4 verified"));
    assert.ok(sum.includes("1 patch-now line is internet-facing"));
    assert.ok(sum.includes("1 line past the US federal KEV benchmark"));
    assert.ok(sum.includes("1 line where KEV and EPSS disagree"));
  });

  test("chips fall back to counting lines when the summary is missing, and zero groups are not links", () => {
    const r = fixture();
    (r as { summary?: unknown }).summary = undefined;
    r.lines = r.lines.filter((l) => l.decision !== "monitor");
    const sum = sectionOf(renderReport(r), "summary");
    assert.match(sum, /<a class="chip d-patch_now" href="#bucket-patch_now"><span class="chip-n">2<\/span>/);
    assert.match(sum, /<span class="chip d-monitor zero"><span class="chip-n">0<\/span>/);
  });

  test("sources list live flags and dates; your rules show this run's policy values", () => {
    const src = sectionOf(renderReport(fixture()), "sources");
    for (const s of ["CISA KEV", "el.kev", "FIRST EPSS", "NIST NVD", "2026-10-23", "Inventory (synthetic)"]) assert.ok(src.includes(s), s);
    assert.equal(count(src, 'class="badge live"'), 4);
    for (const s of ["run date + 7 days", "EPSS ≥ 0.1 (≥ 0.05 if internet-facing)", "run date + 30 days", "run date + 90 days", "below 7/9", "at most 2 times"]) {
      assert.ok(src.includes(s), `rule text missing: ${s}`);
    }
  });

  test("no policy in the manifest: says so instead of inventing defaults", () => {
    const r = fixture();
    (r.manifest as { policy?: unknown }).policy = undefined;
    const html = renderReport(r);
    assert.ok(sectionOf(html, "sources").includes("No policy recorded in the run manifest."));
    assert.ok(!lineRow(html, "r-002").includes("Sources disagree"));
  });
});

describe("renderReport: patch list", () => {
  test("lines are grouped by decision in bucket order", () => {
    const list = sectionOf(renderReport(fixture()), "patch-list");
    const order = ["bucket-patch_now", "bucket-this_cycle", "bucket-monitor", "bucket-ask_owner"].map((id) => list.indexOf(`id="${id}"`));
    assert.ok(order.every((i) => i > 0));
    assert.deepEqual([...order].sort((a, b) => a - b), order);
    assert.ok(list.indexOf('id="line-r-001"') < list.indexOf('id="line-r-002"'));
    assert.ok(list.indexOf('id="line-r-002"') < list.indexOf('id="line-r-003"'));
    assert.match(list, /<span class="pill d-patch_now">Patch now<\/span> 2 lines · <span class="muted">house target: within 7 days/);
    const html = renderReport(fixture());
    assert.ok(html.indexOf('id="patch-list"') < html.indexOf('id="sources"'), "the patch list comes before sources and rules");
  });

  test("a patch-now line shows asset, badge, software, product, KEV benchmark, target, EPSS, verified and why", () => {
    const html = renderReport(fixture());
    const row = lineRow(html, "r-001");
    for (const s of [
      "ERP Portal", "a-erp-01", 'class="badge inet"', "log4j-core 2.14.1 (bundled in ERP-Portal WAR)", "Apache / Log4j2", "family: Apache Log4j",
      "2.14.1", "2021-12-24", "overdue by 1767 days", "1 KEV CVE", "2026-11-02", "patch by (house target)",
      "0.944", "CVE-2021-44228", "percentile 99.9", ">verified<", "Listed in CISA KEV (CVE-2021-44228)",
    ]) assert.ok(row.includes(s), `r-001 missing: ${s}`);
    assert.ok(row.includes('class="pill d-patch_now">Patch now<'));
    // the KEV column says once, in its heading, that the due date is the US federal benchmark
    const head = /<table class="patch"><thead>[\s\S]*?<\/thead>/.exec(html)?.[0] ?? "";
    assert.equal(count(head, "<th "), 8);
    for (const h of ["Decision · asset", "KEV due (US federal benchmark)", "Target (your rule)", "Why"]) assert.ok(head.includes(`>${h}</th>`), h);
  });

  test("KEV due date in the future, and the KEV-vs-EPSS disagreement, are flagged", () => {
    const html = renderReport(fixture());
    const row = lineRow(html, "r-002");
    assert.ok(row.includes("due in 2 days"));
    assert.ok(row.includes("Sources disagree: listed in KEV (exploited in the wild), but EPSS is 0.013, below your 0.1 threshold."));
    assert.ok(!lineRow(html, "r-001").includes("Sources disagree"));
  });

  test("the jury split and the Ultra adjudication are visible on the line", () => {
    const row = lineRow(renderReport(fixture()), "r-002");
    assert.ok(row.includes(">jury split<"));
    assert.ok(row.includes(">Ultra adjudicated<"));
  });

  test("missing values render as missing, never as zero", () => {
    const html = renderReport(fixture());
    const mon = lineRow(html, "r-004");
    assert.ok(mon.includes("no EPSS score"));
    assert.ok(mon.includes("not in KEV"));
    assert.ok(mon.includes("review by (house target)"));
    assert.ok(mon.includes("no KEV product"));
    const ask = lineRow(html, "r-006");
    assert.ok(ask.includes("needs your answer"));
    assert.ok(ask.includes("version: not given"));
    assert.ok(ask.includes(">not verified<"));
  });

  test("internet-facing and verified badges match the data", () => {
    const list = sectionOf(renderReport(fixture()), "patch-list");
    const rows = [...list.matchAll(/<tr class="line"[\s\S]*?<\/tr>/g)].map((m) => m[0]);
    assert.equal(rows.length, 6);
    assert.equal(rows.filter((r) => r.includes('class="badge inet"')).length, 4);
    assert.equal(rows.filter((r) => r.includes('class="badge ok"')).length, 4);
    assert.equal(rows.filter((r) => r.includes(">not verified<")).length, 2);
  });

  test("each line has an expandable evidence and provenance block with votes linked to receipts", () => {
    const html = renderReport(fixture());
    const list = sectionOf(html, "patch-list");
    assert.equal(count(list, '<tr class="detail"><td colspan="8"><details>'), 6);
    assert.match(list, /<summary>Evidence and provenance · 5 items · critic 9\/9<\/summary>/);
    for (const s of ["zetaris:kev", "kevByProducts", "sql sha-kev-02", "world_model", "facts.about", "Apache Log4j2 Remote Code Execution Vulnerability", "Known", "2026.10.23"]) {
      assert.ok(list.includes(s), `evidence missing: ${s}`);
    }
    assert.ok(list.includes('<a class="mono nw" href="#rcpt-rcpt-fx-ultra-1">rcpt-fx-ultra-1</a>'));
    assert.ok(list.includes("No EPSS score for this line (not treated as 0)."));
  });

  test("lines with an unknown decision are still listed", () => {
    const r = fixture();
    (r.lines[3] as { decision: string }).decision = "something_new";
    const list = sectionOf(renderReport(r), "patch-list");
    assert.ok(list.includes('id="bucket-other"'));
    assert.ok(list.includes('id="line-r-004"'));
  });
});

describe("renderReport: owner questions, models, critic, timing", () => {
  test("owner questions show the question, reason and a link to the line", () => {
    const q = sectionOf(renderReport(fixture()), "owner-questions");
    assert.ok(q.includes("Is &quot;Exchange Online (M365 tenant)&quot; the Microsoft cloud service"));
    assert.ok(q.includes("Which FortiOS version runs on branch-fw-01?"));
    assert.ok(q.includes("Product-type conflict that survived two send-backs."));
    assert.ok(q.includes('<a href="#line-r-005">row r-005</a>'));
  });

  test("models at work: every receipt, model IDs readable, Ultra highlighted, errors visible", () => {
    const r = fixture();
    const m = sectionOf(renderReport(r), "models");
    for (const rc of r.receipts) {
      if (rc.receipt_id) assert.ok(m.includes(`id="rcpt-${rc.receipt_id}"`), rc.receipt_id);
    }
    for (const id of ["nvidia/nemotron-3.5-bolt-e4b", "nvidia/nemotron-3.5-lightning-30b-a3b", "nvidia/nemotron-3-ultra-550b-a55b"]) assert.ok(m.includes(id));
    assert.equal(count(m, 'class="ultra-row"'), 2);
    assert.match(m, /<div class="mcard ultra">\s*<div class="mname">Ultra<\/div>/);
    assert.match(m, /<div class="mname">Lightning<\/div>[\s\S]*?<b>3<\/b> calls<\/span><span><b>1<\/b> error<\/span>/);
    assert.match(m, /<div class="mname">Bolt<\/div>[\s\S]*?<b>1<\/b> call<\/span><span><b>0<\/b> errors<\/span>/);
    assert.ok(m.includes("502 empty_response (retried)"));
    assert.ok(m.includes('class="badge bad">missing<'));
    assert.ok(m.includes("6.40 s"));
    assert.ok(m.includes("1210 / 340"));
  });

  test("models at work: a routed model that differs from the requested one is flagged", () => {
    const r = fixture();
    r.receipts[0].routed_model = "some-other/model";
    const m = sectionOf(renderReport(r), "models");
    assert.ok(m.includes('class="badge bad">differs<'));
    assert.ok(m.includes("1 routed to a different model"));
  });

  test("no model calls: says so", () => {
    const r = fixture();
    r.receipts = [];
    assert.ok(sectionOf(renderReport(r), "models").includes("No model calls in this run."));
  });

  test("critic section lists blocked lines with rubric, autonomy level and reasons", () => {
    const c = sectionOf(renderReport(fixture()), "critic");
    assert.ok(c.includes("4 lines approved · 2 lines blocked or sent to the owner"));
    assert.ok(c.includes("4/9"));
    assert.ok(c.includes("6/9"));
    assert.equal(count(c, "L1 · ask owner"), 2);
    assert.equal(count(c, "below your 7/9 threshold"), 2);
    assert.ok(c.includes("Product-type conflict: the inventory row is a cloud service; the KEV product is an on-prem server."));
    assert.ok(c.includes("Trace not attached to this report"));
    assert.ok(c.includes("logs/trace-fixture-run-001.jsonl"));
  });

  test("autonomy follows the critic's verdict: ask_owner is L1 even with a rubric at or above the threshold", () => {
    // e.g. the rules approved 9/9, then Ultra said ask_owner (combineWithUltra), or a blocker outlived max_critic_rounds
    const r = fixture();
    const l = r.lines.find((x) => x.row_id === "r-005");
    assert.ok(l?.critic);
    l.critic.rubric = { accuracy: 3, appropriateness: 3, actionability: 3, total: 9 };
    const html = renderReport(r);
    const row = criticRow(sectionOf(html, "critic"), "r-005");
    assert.ok(row.includes("9/9"));
    assert.ok(row.includes("L1 · ask owner"));
    assert.ok(!row.includes("L2"), "an ask_owner line must never read L2 · auto");
    assert.ok(!row.includes("below your"), "9/9 is not below the threshold");
    const detail = detailRow(html, "r-005");
    assert.ok(detail.includes("L1 · ask owner"));
    assert.ok(!detail.includes("L2"));
    // without a recorded policy the level is still known (it comes from the verdict); only the threshold note goes
    delete (r.manifest as Partial<RunResponse["manifest"]>).policy;
    const noPolicy = criticRow(sectionOf(renderReport(r), "critic"), "r-005");
    assert.ok(noPolicy.includes("L1 · ask owner"));
  });

  test("autonomy follows the critic's verdict: send_back and approve are L2, with the threshold note kept separate", () => {
    const r = fixture();
    const l = r.lines.find((x) => x.row_id === "r-006");
    assert.ok(l?.critic);
    l.critic.verdict = "send_back"; // rubric 6/9, below the 7/9 threshold
    const html = renderReport(r);
    const row = criticRow(sectionOf(html, "critic"), "r-006");
    assert.ok(row.includes("L2 · auto"));
    assert.ok(!row.includes("L1"), "a send-back loops automatically; it is not L1");
    assert.ok(row.includes("6/9"));
    assert.ok(row.includes("below your 7/9 threshold"));
    const sentBack = detailRow(html, "r-006");
    assert.ok(sentBack.includes("below your 7/9 threshold · L2 · auto"));
    const approved = detailRow(html, "r-001"); // approve, 9/9
    assert.ok(approved.includes("L2 · auto"));
    assert.ok(!approved.includes("L1"));
    assert.ok(!approved.includes("below your"));
  });

  test("an unknown critic verdict gets no autonomy level", () => {
    const r = fixture();
    const l = r.lines.find((x) => x.row_id === "r-005");
    assert.ok(l?.critic);
    (l.critic as { verdict: string }).verdict = "something_new";
    const html = renderReport(r);
    const row = criticRow(sectionOf(html, "critic"), "r-005");
    assert.ok(!/L[12] · /.test(row));
    assert.ok(!/L[12] · /.test(detailRow(html, "r-005")));
  });

  test("timing panel shows every phase from timing_ms, scaled bars and summed model time", () => {
    const t = sectionOf(renderReport(fixture()), "timing");
    for (const [k, v] of [["inventory", "640 ms"], ["kev_pairs", "2.31 s"], ["normalise", "35 ms"], ["jury", "41.2 s"], ["critic", "12.8 s"], ["facts", "9.10 s"], ["verifier", "3.90 s"], ["world_model", "210 ms"]]) {
      assert.match(t, new RegExp(`<span class="bar-k">${k}</span>[\\s\\S]*?<span class="bar-v">${v.replace(".", "\\.")}</span>`), k);
    }
    assert.match(t, /<span class="bar-k">jury<\/span><span class="bar"><span class="bar-fill" style="width:100\.0%">/);
    assert.ok(t.includes("summed over 6 calls: 103.7 s"));
    assert.ok(t.includes("per-query times are in"));
  });

  test("with a trace: Zetaris query times, the critic timeline and the full agent timeline", () => {
    const html = renderReport(fixture(), { trace: sampleTrace() });
    const t = sectionOf(html, "timing");
    assert.ok(t.includes("Zetaris queries (1, 2.31 s in total)"));
    assert.ok(t.includes("kevPairs"));
    assert.ok(t.includes("<td>1756</td>"));
    assert.ok(t.includes("SELECT vendor, product FROM el_core.el_kev_table WHERE n &lt; 1"));
    assert.ok(t.includes("SQL · abc123"));
    const c = sectionOf(html, "critic");
    assert.ok(c.includes('class="st st-sent_back">sent back<'));
    assert.ok(c.includes('class="st st-blocked">blocked<'));
    assert.ok(c.includes("<td>5/9</td>"));
    assert.ok(c.includes("<td>4/9</td>"));
    assert.ok(c.includes("type conflict: cloud_service vs server"));
    assert.ok(c.includes("retry 1"));
    assert.ok(c.includes("20:00:45.000"));
    const tl = sectionOf(html, "timeline");
    assert.ok(tl.includes("4 trace events"));
    assert.ok(tl.includes("10 rows voted"));
    assert.ok(tl.includes(">Bolt<"));
  });

  test("full timeline is capped", () => {
    const trace: TraceEvent[] = Array.from({ length: 30 }, (_, i) => ({ ts: `2026-10-26T20:00:${String(i).padStart(2, "0")}.000Z`, run_id: "x", agent: "a", action: `step${i}`, status: "ok" }));
    const tl = sectionOf(renderReport(fixture(), { trace, maxTimelineEvents: 10 }), "timeline");
    assert.ok(tl.includes("Showing the first 10 of 30 events."));
    assert.ok(tl.includes("step9"));
    assert.ok(!tl.includes("step10<"));
  });
});

describe("renderReport: escaping and safety", () => {
  const PAYLOAD = `<script>alert(1)</script><img src=x onerror=alert(2)>" onmouseover="alert(3)' \`&amp;`;
  const ALLOWED_TAGS = new Set(["html", "head", "meta", "title", "style", "body", "main", "header", "nav", "section", "footer", "div", "span", "p",
    "h1", "h2", "h3", "h4", "dl", "dt", "dd", "ul", "li", "table", "thead", "tbody", "tr", "th", "td", "details", "summary", "pre", "a", "b", "strong"]);

  function poison<T>(v: T): T {
    if (typeof v === "string") return (PAYLOAD + v) as T;
    if (Array.isArray(v)) return v.map(poison) as T;
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) out[k] = poison(x);
      return out as T;
    }
    return v;
  }

  test("every string from the run and the trace is escaped; only known tags and no event handlers are emitted", () => {
    const r = poison(fixture());
    (r as { timing_ms: Record<string, number> }).timing_ms = { [PAYLOAD]: 1200, ok: 300 };
    const html = renderReport(r, { trace: poison(sampleTrace()) });
    assert.ok(!html.includes("<script"));
    assert.ok(!html.includes("<img"));
    assert.ok(!html.includes('" onmouseover="'));
    assert.doesNotMatch(html, /<[^>]*\son[a-z]+\s*=/i);
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(2)&gt;&quot; onmouseover=&quot;alert(3)&#39; &#96;&amp;amp;"));
    const tags = new Set([...html.matchAll(/<\/?([a-zA-Z][a-zA-Z0-9]*)/g)].map((m) => m[1].toLowerCase()));
    for (const t of tags) assert.ok(ALLOWED_TAGS.has(t), `unexpected tag <${t}>`);
    const hrefs = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
    for (const h of hrefs) assert.match(h, /^#[A-Za-z0-9_-]+$/);
    const ids = [...html.matchAll(/\sid="([^"]*)"/g)].map((m) => m[1]);
    for (const id of ids) assert.match(id, /^[A-Za-z0-9_-]+$/);
  });

  test("esc covers the five HTML specials plus backtick, and non-strings", () => {
    assert.equal(esc(`<a href="x">'&\``), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#96;");
    assert.equal(esc(null), "");
    assert.equal(esc(undefined), "");
    assert.equal(esc(42), "42");
    assert.equal(esc({ a: "<b>" }), "{&quot;a&quot;:&quot;&lt;b&gt;&quot;}");
  });

  test("credential-shaped strings are masked before rendering", () => {
    const key = ["nv" + "api", "Ab12".repeat(8)].join("-");
    const other = ["s" + "k", "Zz90".repeat(6)].join("-");
    const bearer = `Bear${"er"} ${"q1w2e3r4".repeat(3)}`;
    assert.equal(maskCredentials(`x ${key} y`), "x [masked] y");
    const wordy = ["risk", "assessment", "tool", "2026"].join("-"); // a word ending in the prefix is not a credential
    assert.equal(maskCredentials(wordy), wordy);
    const r = fixture();
    r.lines[0].why = `leaked ${key} and ${other}`;
    r.receipts[0].error = `header ${bearer}`;
    const html = renderReport(r);
    assert.ok(!html.includes(key));
    assert.ok(!html.includes(other));
    assert.ok(!html.includes(bearer));
    assert.ok(html.includes("leaked [masked] and [masked]"));
  });

  test("a malformed or minimal response renders without throwing", () => {
    const minimal = { run_id: "err-1", mode: "live", status: "error", error: { type: "bad_input", message: "no rows", recoverable: false } } as unknown as RunResponse;
    const html = renderReport(minimal);
    for (const s of ["Run error:", "bad_input", "No patch lines in this run.", "No questions for you in this run.", "No model calls in this run.",
      "No policy recorded in the run manifest.", "No sources recorded in the run manifest.", "No phase timings recorded."]) {
      assert.ok(html.includes(s), s);
    }
    const r = fixture();
    (r as { lines: unknown[] }).lines = [null, 7, ...r.lines.slice(0, 1)];
    (r as { receipts: unknown[] }).receipts = [null];
    (r.lines[2] as unknown as { evidence: unknown[] }).evidence = [null, "x"];
    assert.doesNotThrow(() => renderReport(r, { trace: [null as unknown as TraceEvent] }));
    assert.doesNotThrow(() => renderReport(undefined as unknown as RunResponse));
  });
});

describe("trace input", () => {
  test("parses JSONL, accepts log-format field names and skips bad lines", () => {
    const text = [
      JSON.stringify({ ts: "2026-10-26T20:00:01Z", run_id: "r", agent: "zetaris", action: "query", status: "ok", latency_ms: 812, details: { label: "epss" } }),
      "",
      "{not json",
      "[1,2]",
      JSON.stringify({ foo: 1 }),
      JSON.stringify({ timestamp: "2026-10-26T20:00:02Z", run_id: "r", agent_name: "critic", action: "review", status: "sent_back", receipt_id: null, retry_count: 1 }),
    ].join("\n");
    const evs = parseTraceJsonl(text);
    assert.equal(evs.length, 2);
    assert.equal(evs[0].latency_ms, 812);
    assert.deepEqual(evs[0].details, { label: "epss" });
    assert.equal(evs[1].agent, "critic");
    assert.equal(evs[1].ts, "2026-10-26T20:00:02Z");
    assert.equal(evs[1].receipt_id, null);
    assert.equal(evs[1].retry_count, 1);
    assert.equal(normaliseTraceEvent(null), null);
    assert.equal(normaliseTraceEvent({ agent: 5 }), null);
  });
});

describe("report files (index.ts)", () => {
  test("isSafeRunId accepts plain IDs and rejects path tricks", () => {
    for (const ok of ["fixture-run-001", "run_2026-10-26.1", "A1"]) assert.ok(isSafeRunId(ok), ok);
    for (const bad of ["", "../etc/passwd", "a/b", "a\\b", ".hidden", "a..b", "x".repeat(129), 7, null]) assert.ok(!isSafeRunId(bad), String(bad));
  });

  test("writeReport writes report-<run_id>.html and includes the run's trace when the file exists", () => {
    const dir = mkdtempSync(join(tmpdir(), "el-report-"));
    try {
      const traceFile = join(dir, "trace.jsonl");
      writeFileSync(traceFile, sampleTrace().map((e) => JSON.stringify(e)).join("\n") + "\n");
      const r = fixture();
      r.trace_file = traceFile;
      const out = writeReport(r, { dir: join(dir, "output") });
      assert.equal(out, join(dir, "output", "report-fixture-run-001.html"));
      const html = readFileSync(out, "utf8");
      assert.ok(html.includes("Zetaris queries (1, 2.31 s in total)"));
      assert.equal(loadTrace(traceFile).length, 4);
      assert.deepEqual(loadTrace(join(dir, "missing.jsonl")), []);
      r.trace_file = join(dir, "missing.jsonl");
      assert.ok(readFileSync(writeReport(r, { dir }), "utf8").includes("Trace not attached"));
      const bad = fixture();
      bad.run_id = "../escape";
      assert.throws(() => writeReport(bad, { dir }), /unsafe run_id/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("loadReportHtml serves the saved report, renders from run JSON otherwise, and rejects unknown or unsafe IDs", () => {
    const dir = mkdtempSync(join(tmpdir(), "el-report-"));
    try {
      const outputDir = join(dir, "output");
      const logsDir = join(dir, "logs");
      mkdirSync(outputDir);
      mkdirSync(logsDir);
      writeFileSync(join(outputDir, "run-fixture-run-001.json"), JSON.stringify(fixture()));
      writeFileSync(join(logsDir, "trace-fixture-run-001.jsonl"), sampleTrace().map((e) => JSON.stringify(e)).join("\n"));
      const rendered = loadReportHtml("fixture-run-001", { outputDir, logsDir });
      assert.ok(rendered?.includes("ExposureLedger report · fixture-run-001"));
      assert.ok(rendered?.includes("Zetaris queries (1, 2.31 s in total)"));
      writeFileSync(join(outputDir, "report-fixture-run-001.html"), "<!doctype html><p>saved</p>");
      assert.equal(loadReportHtml("fixture-run-001", { outputDir, logsDir }), "<!doctype html><p>saved</p>");
      assert.equal(loadReportHtml("no-such-run", { outputDir, logsDir }), null);
      assert.equal(loadReportHtml("../output/run-fixture-run-001", { outputDir, logsDir }), null);
      writeFileSync(join(outputDir, "run-broken.json"), "{not json");
      assert.equal(loadReportHtml("broken", { outputDir, logsDir }), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("integration additions", () => {
  test("a line with nothing cited to re-check gets its own badge, not 'verified'; the summary counts it apart", () => {
    const resp = fixture();
    const target = resp.lines[resp.lines.length - 1];
    target.verified = true;
    target.verifier_notes = ["no KEV or EPSS values cited; nothing to re-check"];
    const html = renderReport(resp);
    assert.match(lineRow(html, target.row_id), /nothing to re-check/);
    assert.doesNotMatch(lineRow(html, target.row_id), />verified</);
    assert.match(sectionOf(html, "summary"), /with nothing to re-check/);
  });

  test("an EPSS of 0.99999 is never shown as 1", () => {
    const resp = fixture();
    const l = resp.lines.find((x) => x.epss) as RunResponse["lines"][number];
    (l.epss as { max: number }).max = 0.99999;
    assert.match(lineRow(renderReport(resp), l.row_id), /0\.99999/);
  });
});

// ---------- the 1080p polish: panels read from the run's own trace (D3) ----------

/** sampleTrace() plus the event shapes the pipeline writes (src/run.ts and the agents), with fixture values. */
function richTrace(): TraceEvent[] {
  const ev = (t: string, e: Partial<TraceEvent> & { agent: string; action: string }): TraceEvent =>
    ({ ts: `2026-10-26T20:${t}Z`, run_id: "fixture-run-001", status: "ok", ...e }) as TraceEvent;
  return [
    ...sampleTrace(),
    ev("00:02.000", { agent: "pipeline", action: "inventory_loaded", output_summary: "6 row(s) from Zetaris el.inventory" }),
    ev("00:02.100", { agent: "pipeline", action: "kev_pairs", output_summary: "1756 distinct KEV (vendor, product) pairs" }),
    ev("00:02.200", { agent: "normaliser", action: "candidates_built", output_summary: "6 row(s): 5 with KEV candidates, 1 without" }),
    ev("00:03.000", { agent: "Zetaris", action: "sql_ddl", latency_ms: 40, output_summary: "already exists (ok) in 40 ms",
      details: { label: "epss_register(2)", sql: "CREATE LIGHTNING REST TABLE el_epss_x FROM EL_EPSS REQUEST(endpoint \"x\")", sql_hash: "ddl1" } }),
    ev("00:31.000", { agent: "resolver_jury", action: "split_detected", target_agent: "jury.adjudicate",
      details: { batch: 1, splits: [{ row_id: "r-002", bolt: "Examplesoft / Example File Transfer", lightning: "null" }] } }),
    ev("00:33.000", { agent: "jury.adjudicate", action: "llm_call", model: MODELS.ultra, routed_model: MODELS.ultra, receipt_id: "rcpt-fx-ultra-1", latency_ms: 10700 }),
    ev("00:33.001", { agent: "jury.adjudicate", action: "ultra_adjudication", target_agent: "resolver_jury", receipt_id: "rcpt-fx-ultra-1",
      input_summary: "group 1: 1 split row(s)", output_summary: "1 of 1 decided; 0 unresolved",
      details: { decisions: [{ row_id: "r-002", ultra: "Examplesoft / Example File Transfer", sided_with: "bolt", reason: "EFT is the Example File Transfer server." }] } }),
    ev("00:33.100", { agent: "resolver_jury", action: "jury_summary", output_summary: "6 rows: 4 agreed, 1 split (1 decided by Ultra)" }),
    ev("00:50.000", { agent: "resolver.retry.lightning", action: "redecide", target_agent: "critic", receipt_id: "rcpt-fx-lightning-2", retry_count: 1,
      input_summary: "round 1, group 1: 1 row(s) sent back by the critic", output_summary: "0 of 1 changed their answer",
      details: { decisions: [{ row_id: "r-005", rejected: "(Microsoft, Exchange Server)", answer: "Microsoft / Exchange Server", changed: false, reason: "Exchange Online is Exchange." }] } }),
    ev("00:55.000", { agent: "critic", action: "send_back", status: "sent_back", target_agent: "resolver",
      input_summary: "r-005 \"Exchange Online (M365 tenant)\" -> Microsoft / Exchange Server", output_summary: "send_back (rubric 4/9, L2): identity",
      details: { row_id: "r-005", rubric: { total: 4 }, reasons: ["identity: Ultra judged it a different product (cloud service vs on-prem server)"], ultra_critique: { receipt_id: "rcpt-fx-ultra-2", status: "ok" } } }),
    ev("00:56.000", { agent: "critic.match_check", action: "same_product_check", target_agent: "critic", receipt_id: "rcpt-fx-ultra-2",
      input_summary: "r-006 \"FortiOS (branch firewall)\" -> Fortinet / FortiOS (version unconfirmed; headed for patch_now)", output_summary: "same product: true",
      details: { row_id: "r-006", answer: { same: true, reason: "FortiOS is the firewall OS." } } }),
    ev("00:57.000", { agent: "critic", action: "critic_round", status: "sent_back", retry_count: 1, input_summary: "round 1: 2 row(s) reviewed",
      output_summary: "1 approved, 1 sent back, 0 to the owner; 1 Ultra critique(s)" }),
    ev("00:59.000", { agent: "nvd", action: "nvd_cve", input_summary: "CVE-2021-44228", output_summary: "4 range(s) from today's cache", details: { cve_id: "CVE-2021-44228", cache: "day" } }),
    ev("01:05.000", { agent: "Zetaris", action: "sql_query", latency_ms: 300, output_summary: "1 row(s) in 300 ms",
      details: { label: "kevVerify(1)", sql: "SELECT cve_id FROM el.kev WHERE cve_id IN ('CVE-2021-44228')", sql_hash: "ver1", rows: 1, fromCache: false, cache_mode: "bypass" } }),
    ev("01:06.000", { agent: "exposure_analyst", action: "decisions", output_summary: "2 patch_now, 1 this_cycle, 2 ask_owner, 1 monitor (as of 2026-10-26)" }),
    ev("01:08.000", { agent: "verifier", action: "recheck", input_summary: "6 line(s); 2 KEV + 2 EPSS CVE(s), re-queried live", output_summary: "4/6 verified; 0 blocked" }),
    ev("01:10.000", { agent: "world_model", action: "ingest_run", output_summary: "+120 engine events; 1 merge reviews queued", details: { review_queue: ["Example CMS ~ Example CMS Pro (0.84)"] } }),
    ev("01:12.000", { agent: "pipeline", action: "agents_summary", output_summary: "jury 4 agreed, 1 split",
      details: { critic: { reviews: 8, rounds: 2, sent_back: 2, redecided: { lightning: 1, ultra: 0 }, nvd_sendbacks: 0, ultra_critiques: 1, match_checks: 1 }, nvd: { live_calls: 0, cached: 1, ms: 2, states: { "CVE-2021-44228": "cached" } } } }),
    ev("01:12.400", { agent: "reporter", action: "report_written", output_summary: "/Users/someone/Desktop/My Projects/REPO/output/report-fixture-run-001.html" }),
  ];
}

describe("trace facts (indexTrace)", () => {
  test("joins Ultra's adjudications with the jurors' split votes and their receipt", () => {
    const f = indexTrace(richTrace(), fixture().receipts);
    assert.deepEqual(f.adjudications, [{
      row_id: "r-002", ultra: "Examplesoft / Example File Transfer", sided_with: "bolt", reason: "EFT is the Example File Transfer server.",
      receipt_id: "rcpt-fx-ultra-1", bolt: "Examplesoft / Example File Transfer", lightning: "null",
    }]);
    assert.equal(pickText("null"), "no KEV product");
    assert.equal(pickText("no vote"), "no valid vote");
    assert.equal(pickText("Apache / HTTP Server"), "Apache / HTTP Server");
  });

  test("a catch is a row the critic sent back, with every step about it in time order and the model that acted", () => {
    const f = indexTrace(richTrace(), fixture().receipts);
    assert.deepEqual([...f.catches.keys()], ["r-005"]); // r-006 had a same-product check but was never sent back
    const steps = f.catches.get("r-005") ?? [];
    assert.deepEqual(steps.map((s) => [s.actor, s.kind, s.status, s.rubric]), [
      ["Critic", "critic", "sent_back", 5],
      ["Lightning", "redecide", "unchanged", null],
      ["Critic + Ultra", "critic", "sent_back", 4],
      ["Critic", "critic", "blocked", 4],
    ]);
    assert.equal(steps[1].proposal, "Microsoft / Exchange Server");
    assert.equal(steps[1].receipt_id, "rcpt-fx-lightning-2");
    assert.equal(steps[2].proposal, "Microsoft / Exchange Server");
    assert.equal(steps[2].receipt_id, "rcpt-fx-ultra-2");
    assert.match(steps[2].text, /^identity: Ultra judged/);
  });

  test("indexes what each receipt was used for, the Zetaris calls, NVD counts, critic rounds, the pipeline and the review queue", () => {
    const f = indexTrace(richTrace(), fixture().receipts);
    assert.deepEqual((f.byReceipt.get("rcpt-fx-ultra-2") ?? []).map((e) => e.action), ["send_back", "same_product_check"]);
    assert.deepEqual((f.byReceipt.get("rcpt-fx-ultra-1") ?? []).map((e) => e.action), ["ultra_adjudication"]); // llm_call is the call itself
    assert.deepEqual(f.zetaris.map((q) => [q.label, q.kind, q.ms, q.cacheMode]), [
      ["kevPairs", "query", 2310, ""], ["epss_register(2)", "ddl", 40, ""], ["kevVerify(1)", "query", 300, "bypass"],
    ]);
    assert.deepEqual(f.nvd, { states: { read: 0, cached: 1, fallback: 0, error: 0, skipped_budget: 0, dormant: 0 }, ms: 2, lookups: 1 });
    assert.equal(f.rounds.length, 1);
    assert.deepEqual(f.reviewQueue, ["Example CMS ~ Example CMS Pro (0.84)"]);
    assert.deepEqual(f.pipeline.map((s) => s.agent), ["Zetaris", "Normaliser", "Resolver jury", "Conflict critic", "Exposure analyst", "Verifier", "World Model"]);
    assert.deepEqual(f.pipeline[2].models.sort(), ["Bolt", "Lightning", "Ultra"]);
    assert.deepEqual(f.pipeline[2].text, ["6 rows: 4 agreed, 1 split (1 decided by Ultra)", "Ultra: 1 of 1 decided; 0 unresolved"]);
    assert.deepEqual(f.pipeline[3].text, ["8 reviews in 2 round(s); 2 send-back(s) (1 re-decided by Lightning, 0 by Ultra, 0 for NVD ranges); 1 Ultra critique(s); 1 same-product check(s)"]);
    assert.deepEqual(f.pipeline[5].text, ["6 line(s); 2 KEV + 2 EPSS CVE(s), re-queried live", "4/6 verified; 0 blocked"]);
  });

  test("an empty or foreign trace gives empty facts", () => {
    const f = indexTrace([{ ts: "", run_id: "", agent: "x", action: "y", status: "ok" }], []);
    assert.equal(f.adjudications.length + f.catches.size + f.zetaris.length + f.pipeline.length + f.rounds.length, 0);
    assert.equal(f.nvd, null);
  });
});

describe("renderReport: 1080p panels from the trace", () => {
  test("a sticky bar keeps the mode and the section links in view; every link has a target", () => {
    const html = renderReport(fixture(), { trace: richTrace() });
    const bar = /<nav class="nav" id="top">[\s\S]*?<\/nav>/.exec(html)?.[0] ?? "";
    assert.ok(bar.includes('<span class="nav-mode m-live">LIVE</span>'));
    assert.ok(bar.includes("fixture-run-001"));
    for (const id of ["summary", "pipeline", "patch-list", "models", "critic", "timing", "timeline"]) assert.ok(bar.includes(`href="#${id}"`), id);
    const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
    for (const m of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.has(m[1]), `dangling link #${m[1]}`);
    assert.match(html, /\.nav\{position:sticky;top:0/);
    // without a trace there is no pipeline panel and no link to it
    const plain = renderReport(fixture());
    assert.ok(!plain.includes('href="#pipeline"'));
    assert.ok(!plain.includes('id="pipeline"'));
  });

  test("how this list was made: each agent's own summary, in pipeline order, with the models it called", () => {
    const p = sectionOf(renderReport(fixture(), { trace: richTrace() }), "pipeline");
    const order = ["Zetaris", "Normaliser", "Resolver jury", "Conflict critic", "Exposure analyst", "Verifier", "World Model"].map((a) => p.indexOf(`<div class="step-h">${a}`));
    assert.ok(order.every((i) => i > 0));
    assert.deepEqual([...order].sort((a, b) => a - b), order);
    for (const s of ["6 row(s) from Zetaris el.inventory", "1756 distinct KEV (vendor, product) pairs", "Ultra: 1 of 1 decided; 0 unresolved", "4/6 verified; 0 blocked", "+120 engine events"]) {
      assert.ok(p.includes(s), s);
    }
    assert.match(p, /Resolver jury <span class="badge m-bolt">Bolt<\/span><span class="badge m-lightning">Lightning<\/span><span class="badge m-ultra">Ultra<\/span>/);
    assert.ok(p.includes("5 of 6 model calls carry a Nightshift receipt")); // the fixture's 502 has no receipt
  });

  test("models at work: cards in size order with the agents that called them, Ultra's split decisions, and what each call was used for", () => {
    const m = sectionOf(renderReport(fixture(), { trace: richTrace() }), "models");
    assert.ok(m.indexOf('<div class="mname">Bolt</div>') < m.indexOf('<div class="mname">Lightning</div>'));
    assert.ok(m.indexOf('<div class="mname">Lightning</div>') < m.indexOf('<div class="mname">Ultra</div>'));
    assert.match(m, /<div class="magents"><span class="mono">jury\.lightning<\/span> ×1 · <span class="mono">resolver\.retry<\/span> ×2<\/div>/);
    const adj = /<h3 id="ultra">Jury splits decided by Ultra \(1\)<\/h3>[\s\S]*?<\/table>/.exec(m)?.[0] ?? "";
    for (const s of ['<a href="#line-r-002">File Transfer Server</a>', '<td class="vote sided">Examplesoft / Example File Transfer</td>', '<td class="vote">no KEV product</td>',
      '<td class="strong">Examplesoft / Example File Transfer</td>', "<td>bolt</td>", "EFT is the Example File Transfer server.", 'href="#rcpt-rcpt-fx-ultra-1"']) {
      assert.ok(adj.includes(s), s);
    }
    const ultraRow = /<tr class="ultra-row" id="rcpt-rcpt-fx-ultra-2">[\s\S]*?<\/tr>/.exec(m)?.[0] ?? "";
    assert.ok(ultraRow.includes("r-005 &quot;Exchange Online (M365 tenant)&quot; -&gt; Microsoft / Exchange Server → send_back (rubric 4/9, L2): identity"));
    assert.ok(ultraRow.includes(" · r-006 &quot;FortiOS (branch firewall)&quot;"));
    const boltRow = /<tr class="" id="rcpt-rcpt-fx-bolt-1">[\s\S]*?<\/tr>/.exec(m)?.[0] ?? "";
    assert.ok(boltRow.includes("10 rows voted"));
    assert.ok(m.includes("Used for (from the trace)"));
    // no trace: no "used for" column and no split table (nothing to read them from)
    const plain = sectionOf(renderReport(fixture()), "models");
    assert.ok(!plain.includes("Used for"));
    assert.ok(!plain.includes('id="ultra"'));
  });

  test("the patch line shows which juror Ultra sided with, links to its catch, and the detail explains the split", () => {
    const html = renderReport(fixture(), { trace: richTrace() });
    assert.ok(lineRow(html, "r-002").includes("Ultra sided with bolt"));
    assert.ok(lineRow(html, "r-005").includes('<a class="badge caught" href="#catch-r-005">critic sent back ×2</a>'));
    const d = detailRow(html, "r-002");
    assert.ok(d.includes("decided this jury split: Bolt Examplesoft / Example File Transfer, Lightning no KEV product → <strong>Examplesoft / Example File Transfer</strong> (sided with bolt): EFT is the Example File Transfer server."));
  });

  test("critic: the rounds, then each catch as a loop (critic, re-decide, Ultra) ending in the line's decision", () => {
    const c = sectionOf(renderReport(fixture(), { trace: richTrace() }), "critic");
    assert.ok(c.includes('<div class="round-h">round 1: 2 row(s) reviewed</div><div>1 approved, 1 sent back, 0 to the owner; 1 Ultra critique(s)</div>'));
    const row = /<tr class="catch" id="catch-r-005">[\s\S]*?<\/tr>/.exec(c)?.[0] ?? "";
    const steps = [...row.matchAll(/<li>([\s\S]*?)<\/li>/g)].map((m) => m[1]);
    assert.equal(steps.length, 4);
    // sampleTrace's first review names no proposal ("r-005 Exchange Online"); the rich trace's does ("... -> Microsoft / Exchange Server")
    assert.match(steps[0], /^<span class="who">Critic<\/span> <span class="st st-sent_back">sent back<\/span> <span class="rub">5\/9<\/span>/);
    assert.ok(steps[0].includes("type conflict: cloud_service vs server"));
    assert.match(steps[1], /^<span class="badge m-lightning">Lightning<\/span> <span class="st st-other">kept its answer<\/span>/);
    assert.ok(steps[1].includes('href="#rcpt-rcpt-fx-lightning-2"'));
    assert.match(steps[2], /^<span class="who">Critic<\/span> \+ <span class="badge m-ultra">Ultra<\/span> <span class="st st-sent_back">sent back<\/span> <span class="prop">Microsoft \/ Exchange Server<\/span> <span class="rub">4\/9<\/span>/);
    assert.match(steps[3], /<span class="st st-blocked">to the owner<\/span>/);
    assert.ok(row.includes('<span class="pill d-ask_owner">Ask owner</span>'));
    // the full event list stays in the page, folded
    assert.match(c, /<details class="events"><summary>4 critic events in the trace/); // 3 reviews + the round summary
    // the final-verdict table now names the line's decision too
    assert.ok(criticRow(c, "r-005").includes('<span class="pill d-ask_owner">Ask owner</span>'));
  });

  test("timing: headline tiles, phases without the total, the overlap note, Zetaris kinds and cache bypass, NVD counts", () => {
    const r = fixture();
    r.timing_ms = { inventory: 600, jury: 30000, facts: 20000, total: 45000 };
    const t = sectionOf(renderReport(r, { trace: richTrace() }), "timing");
    assert.ok(t.includes('<div class="tile-n">45.0 s</div><div class="tile-l">end to end, the whole run</div>'));
    assert.ok(t.includes('<div class="tile-n">2.65 s</div><div class="tile-l">in Zetaris: 2 queries, 1 table registration</div>'));
    assert.ok(t.includes('<div class="tile-n">103.7 s</div><div class="tile-l">in 6 model calls, summed (they run in parallel)</div>'));
    assert.ok(t.includes('<div class="tile-n">0 live · 1 cached</div><div class="tile-l">NVD CVE records, 2 ms</div>'));
    assert.ok(!t.includes('<span class="bar-k">total</span>'));
    assert.match(t, /<span class="bar-k">jury<\/span><span class="bar"><span class="bar-fill" style="width:66\.7%">/); // scaled to the 45 s total
    assert.ok(t.includes("The phases add up to 50.6 s against 45.0 s end to end: some of them ran at the same time."));
    assert.ok(t.includes("Zetaris queries (3, 2.65 s in total)"));
    assert.ok(t.includes("<td>register</td>"));
    assert.ok(t.includes('read now<div class="sub">cache bypassed</div>'));
    assert.ok(t.includes('<div class="sqlprev mono">SELECT cve_id FROM el.kev WHERE cve_id IN (&#39;CVE-2021-44228&#39;)</div>'));
  });

  test("provenance: the World Model's explain() items lead the line's detail, with receipts linked, and summarise it when folded", () => {
    const html = renderReport(fixture(), { trace: richTrace() });
    const d = detailRow(html, "r-002");
    assert.ok(d.includes("<summary>Evidence and provenance · 5 items · critic 8/9 · <span class=\"wm\">World Model: 6 current fact(s) about this row, its asset and 1 CVE(s), from agent:analyst, agent:jury, zetaris:el.kev, zetaris:epss</span></summary>"));
    const prov = /<div class="prov">[\s\S]*?<\/dl><\/div>/.exec(d)?.[0] ?? "";
    assert.ok(prov.includes("<h4>Provenance (World Model engine)</h4>"));
    assert.ok(prov.includes('<dt>resolves_to &lt;- agent:jury</dt><dd>matched by ultra; receipts <a class="mono" href="#rcpt-rcpt-fx-lightning-1">rcpt-fx-lightning-1</a>, <a class="mono" href="#rcpt-rcpt-fx-ultra-1">rcpt-fx-ultra-1</a>'));
    assert.ok(prov.includes('as of 2026-10-26</span>'));
    assert.ok(prov.includes("world_model · explain(r-002)"));
    assert.ok(d.indexOf('<div class="prov">') < d.indexOf("<h4>Resolution and jury votes</h4>"));
    // provenance text is escaped around the links
    const r = fixture();
    const wm = r.lines[1].evidence.find((e) => e.field === "resolves_to <- agent:jury");
    assert.ok(wm);
    wm.value = "receipts rcpt-fx-ultra-1 <b>x</b>";
    assert.ok(detailRow(renderReport(r), "r-002").includes('receipts <a class="mono" href="#rcpt-rcpt-fx-ultra-1">rcpt-fx-ultra-1</a> &lt;b&gt;x&lt;/b&gt;'));
  });

  test("evidence items that share source, query and field are one row listing every value", () => {
    const r = fixture();
    const kev = r.lines[0].evidence[1];
    for (let i = 0; i < 10; i++) r.lines[0].evidence.push({ ...kev, value: `CVE-2099-90${String(i).padStart(2, "0")}` });
    const d = detailRow(renderReport(r), "r-001");
    assert.ok(d.includes('cve_id <span class="sub">×11</span>'));
    assert.ok(d.includes("<summary>3 more</summary>"));
    for (const v of ["CVE-2021-44228", "CVE-2099-9000", "CVE-2099-9009"]) assert.ok(d.includes(`>${v}</div>`), v);
  });

  test("owner questions that cover several machines link every row they cover", () => {
    const r = fixture();
    (r.owner_questions[1] as unknown as { row_ids: string[] }).row_ids = ["r-006", "r-004"];
    const q = sectionOf(renderReport(r), "owner-questions");
    assert.ok(q.includes('covers <a href="#line-r-006">r-006</a>, <a href="#line-r-004">r-004</a>'));
  });

  test("a patch-now line whose version is unconfirmed says so, and the summary counts it", () => {
    const r = fixture();
    r.lines[0].evidence.push({ source: "agent", query: "critic", field: "version_unconfirmed", value: "which Log4j version?", live: false });
    const html = renderReport(r);
    assert.ok(lineRow(html, "r-001").includes(">version unconfirmed · owner question<"));
    assert.ok(sectionOf(html, "summary").includes("1 patch-now line has its version unconfirmed (owner question attached)"));
  });

  test("local absolute paths are shown repo-relative, never with the machine's user name", () => {
    assert.equal(maskLocalPaths("/Users/someone/Desktop/My Projects/REPO/logs/trace-1.jsonl"), "logs/trace-1.jsonl");
    assert.equal(maskLocalPaths("audit /home/u/app/output/world/x.json done"), "audit output/world/x.json done");
    assert.equal(maskLocalPaths("C:\\Users\\bob\\proj\\logs\\a.jsonl"), "logs\\a.jsonl");
    assert.equal(maskLocalPaths("config in /Users/bob/.config"), "config in ~/.config");
    assert.equal(maskLocalPaths("/usr/local/bin and Users/x"), "/usr/local/bin and Users/x");
    const r = fixture();
    r.trace_file = "/Users/someone/Desktop/My Projects/REPO/logs/trace-fixture-run-001.jsonl";
    r.report_file = "/Users/someone/Desktop/My Projects/REPO/output/report-fixture-run-001.html";
    const html = renderReport(r, { trace: richTrace() });
    assert.ok(!html.includes("/Users/"));
    assert.ok(!html.includes("someone"));
    assert.ok(sectionOf(html, "run-details").includes('<dd class="mono">logs/trace-fixture-run-001.jsonl</dd>'));
    assert.ok(sectionOf(html, "timeline").includes("output/report-fixture-run-001.html"));
  });

  test("sample mode: the stamp stays in the sticky bar, the banner counts live sources, and models say why there are none", () => {
    const r = fixture();
    r.mode = "sample";
    r.receipts = [];
    r.manifest.sources = r.manifest.sources.map((s) => ({ ...s, live: false, as_of: "2026-10-25" }));
    const html = renderReport(r);
    assert.ok(html.includes('<span class="nav-mode m-sample">SAMPLE MODE · snapshot 2026-10-25</span>'));
    const banner = /<div class="banner sample" id="mode-banner">[\s\S]*?<\/div>/.exec(html)?.[0] ?? "";
    assert.ok(banner.includes("No source was read live (0 of 4)"));
    assert.ok(sectionOf(html, "models").includes("No model calls in this run. Sample mode runs offline and calls no model."));
    // timing: no Zetaris tile and no summed model time when there were none
    const t = sectionOf(renderReport(r, { trace: sampleTrace().filter((e) => e.agent !== "Zetaris") }), "timing");
    assert.ok(t.includes('<div class="tile-n">0</div><div class="tile-l">model calls</div>'));
    assert.ok(!t.includes("in Zetaris:"));
    assert.ok(!t.includes("Model time, summed"));
    assert.ok(t.includes("The trace has no timed Zetaris queries (sample mode reads the saved snapshot instead)."));
    // the snapshot's own source (sample mode lists it, e.g. "Sample snapshot") dates the capture, not the data dates
    r.manifest.sources = [{ name: "Sample snapshot", object: "data/sample/snapshot.json", live: false, as_of: "2026-10-27" },
      { name: "CISA KEV", object: "sample snapshot (el.kev)", live: false, as_of: "2026.10.23" }];
    assert.ok(renderReport(r).includes("snapshot captured <strong>2026-10-27</strong> · model calls"));
    // a dedicated snapshot date, when the manifest carries one, is preferred over the sources' dates
    (r.manifest as unknown as { snapshot_date: string }).snapshot_date = "2026-10-24";
    assert.ok(renderReport(r).includes("snapshot captured <strong>2026-10-24</strong>"));
    // a live run counts its receipted calls in the banner
    assert.ok(renderReport(fixture()).includes("<strong>LIVE MODE</strong> · sources flagged live below were read at run time · 6 model calls, 5 with a Nightshift receipt"));
  });

  test("every string from the run and the rich trace is escaped in the new panels too", () => {
    const PAYLOAD = `<script>alert(1)</script><img src=x onerror=alert(2)>" onmouseover="alert(3)' \`&amp;`;
    const poison = <T>(v: T): T => {
      if (typeof v === "string") return (PAYLOAD + v) as T;
      if (Array.isArray(v)) return v.map(poison) as T;
      if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, poison(x)])) as T;
      return v;
    };
    const html = renderReport(poison(fixture()), { trace: poison(richTrace()) });
    assert.ok(!html.includes("<script"));
    assert.ok(!html.includes("<img"));
    assert.doesNotMatch(html, /<[^>]*\son[a-z]+\s*=/i);
    const allowed = new Set(["html", "head", "meta", "title", "style", "body", "main", "header", "nav", "section", "footer", "div", "span", "p",
      "h1", "h2", "h3", "h4", "dl", "dt", "dd", "ul", "li", "table", "thead", "tbody", "tr", "th", "td", "details", "summary", "pre", "a", "b", "strong"]);
    for (const t of new Set([...html.matchAll(/<\/?([a-zA-Z][a-zA-Z0-9]*)/g)].map((m) => m[1].toLowerCase()))) assert.ok(allowed.has(t), `unexpected tag <${t}>`);
    for (const m of html.matchAll(/href="([^"]*)"/g)) assert.match(m[1], /^#[A-Za-z0-9_-]+$/);
    for (const m of html.matchAll(/\sid="([^"]*)"/g)) assert.match(m[1], /^[A-Za-z0-9_-]+$/);
    for (const m of html.matchAll(/\stitle="([^"]*)"/g)) assert.ok(!m[1].includes("alert"), "a title attribute carries run data");
    // the same, with the events' agent, action and status kept, so the trace-only panels (the Zetaris table among them) render too
    const keep = new Set(["agent", "action", "status"]);
    const poisonData = <T>(v: T, key = ""): T => {
      if (typeof v === "string") return (keep.has(key) ? v : PAYLOAD + v) as T;
      if (Array.isArray(v)) return v.map((x) => poisonData(x, key)) as T;
      if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, poisonData(x, k)])) as T;
      return v;
    };
    const html2 = renderReport(poison(fixture()), { trace: poisonData(richTrace()) });
    assert.ok(sectionOf(html2, "timing").includes("Zetaris queries (3, 2.65 s in total)"));
    assert.ok(!html2.includes("<script"));
    assert.ok(!html2.includes("<img"));
    assert.doesNotMatch(html2, /<[^>]*\son[a-z]+\s*=/i);
  });
});

/** The NVD tile of a timing section: [big number, label]. */
function nvdTile(timing: string): [string, string] {
  const m = /<div class="tile"><div class="tile-n">([^<]*)<\/div><div class="tile-l">([^<]*NVD[^<]*)<\/div><\/div>/.exec(timing);
  assert.ok(m, "NVD tile missing");
  return [m[1], m[2]];
}
function summaryEvent(nvd: Record<string, unknown>): TraceEvent {
  return { ts: "2026-10-26T22:58:24.394Z", run_id: "fixture-run-001", agent: "pipeline", action: "agents_summary", status: "ok", details: { nvd } };
}

describe("timing panel: counts from the run's own events (review round 1)", () => {
  test("an NVD lookup that copies its SQL is not a second Zetaris query: the tile and the table count it once", () => {
    const sql = "SELECT to_json(vulnerabilities) AS v FROM el_nvd.el_nvd_cve_2026_96951";
    const trace: TraceEvent[] = [
      { ts: "2026-10-26T22:57:14.758Z", run_id: "fixture-run-001", agent: "Zetaris", action: "sql_query", status: "ok", latency_ms: 896,
        output_summary: "1 row(s) in 896 ms", details: { label: "nvd_read", sql, sql_hash: "1ecb", rows: 1, fromCache: false, cache_mode: "use", ms: 896 } },
      // the NVD adapter's own event for the same lookup (the real shape): it copies the SQL and times the whole lookup, rate-limit pacing included
      { ts: "2026-10-26T22:57:14.758Z", run_id: "fixture-run-001", agent: "nvd", action: "nvd_cve", status: "ok", input_summary: "CVE-2026-96951",
        output_summary: "3 range(s) [ok]", details: { cve_id: "CVE-2026-96951", table: "el_nvd_cve_2026_96951", sql, ms: 7014, state: "ok" } },
      // any other agent's event that carries SQL or a SQL hash is not a Zetaris query either
      { ts: "2026-10-26T22:58:00.000Z", run_id: "fixture-run-001", agent: "verifier", action: "recheck", status: "ok", latency_ms: 1200,
        details: { sql: "SELECT 1", sql_hash: "v1", ms: 1200 } },
      summaryEvent({ live_calls: 1, cached: 0, ms: 7014, states: { "CVE-2026-96951": "ok" } }),
    ];
    const f = indexTrace(trace, []);
    assert.deepEqual(f.zetaris.map((q) => [q.label, q.kind, q.ms]), [["nvd_read", "query", 896]]);
    const r = fixture();
    r.timing_ms = { total: 81400 };
    const t = sectionOf(renderReport(r, { trace }), "timing");
    assert.ok(t.includes('<div class="tile-n">896 ms</div><div class="tile-l">in Zetaris: 1 query, 0 table registrations</div>'));
    assert.ok(t.includes("Zetaris queries (1, 896 ms in total)"));
    assert.equal(count(t, '<td class="q">'), 1);
    // the NVD lookup's own time belongs to the NVD tile
    assert.deepEqual(nvdTile(t), ["1 live · 0 cached", "NVD CVE records, 7.01 s"]);
  });

  test("live mode: the NVD tile counts records read now, cached, failed and not looked up separately (failed lookups are not records)", () => {
    const trace = [summaryEvent({
      live_calls: 7, cached: 1, ms: 67359, // FactStore's live_calls counts failed attempts too
      states: { "CVE-1": "ok", "CVE-2": "ok", "CVE-3": "no_configurations", "CVE-4": "not_found", "CVE-5": "cached", "CVE-6": "fallback",
        "CVE-7": "error", "CVE-8": "error", "CVE-9": "skipped_budget", "CVE-10": "skipped_budget", "CVE-11": "skipped_budget" },
    })];
    const t = sectionOf(renderReport(fixture(), { trace }), "timing");
    assert.deepEqual(nvdTile(t), ["4 live · 1 cached", "NVD CVE records, 67.4 s; 1 from the fallback copy; 2 failed; 3 not looked up in this run (NVD budget)"]);
    assert.deepEqual(indexTrace(trace, []).nvd, {
      states: { read: 4, cached: 1, fallback: 1, error: 2, skipped_budget: 3, dormant: 0 }, ms: 67359, lookups: 0,
    });
  });

  test("sample mode: the NVD tile says 'from the snapshot' and never 'live', even when the run's live_calls counter is above 0", () => {
    const r = fixture();
    r.mode = "sample";
    r.receipts = [];
    r.manifest.sources = r.manifest.sources.map((s) => ({ ...s, live: false, as_of: "2026-10-27" }));
    // the shape of a real offline sample run: 4 CVEs missing from the snapshot (state error), 2 read from it (state cached)
    const trace = [summaryEvent({
      live_calls: 4, cached: 2, ms: 0,
      states: { "CVE-2025-68686": "error", "CVE-2026-73570": "error", "CVE-2026-34486": "cached", "CVE-2019-6693": "error", "CVE-2025-48700": "error", "CVE-2025-24813": "cached" },
    })];
    const html = renderReport(r, { trace });
    const [n, label] = nvdTile(sectionOf(html, "timing"));
    assert.equal(n, "2 from the snapshot");
    assert.equal(label, "NVD CVE records, 0 ms; 4 missing from the snapshot");
    assert.doesNotMatch(`${n} ${label}`, /live/i);
    assert.ok(html.includes("No source was read live (0 of 4)")); // the banner on the same page agrees
  });

  test("a run that recorded no per-CVE outcomes falls back to the NVD lookups in its trace", () => {
    const nvdEv = (ts: string, cve: string): TraceEvent => ({ ts, run_id: "fixture-run-001", agent: "nvd", action: "nvd_cve", status: "ok", input_summary: cve, details: { cve_id: cve } });
    const trace = [nvdEv("2026-10-26T22:57:14.000Z", "CVE-1"), nvdEv("2026-10-26T22:57:20.000Z", "CVE-2"), summaryEvent({ calls: 2, ms: 13000 })];
    assert.deepEqual(nvdTile(sectionOf(renderReport(fixture(), { trace }), "timing")), ["2", "NVD lookups in the trace, 13.0 s"]);
    // no outcomes and no lookup events: no NVD tile at all
    assert.ok(!sectionOf(renderReport(fixture(), { trace: [summaryEvent({ calls: 0 })] }), "timing").includes("NVD"));
  });
});
