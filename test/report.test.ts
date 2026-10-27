import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { RunResponse, TraceEvent } from "../src/contracts.ts";
import { esc, maskCredentials, renderReport } from "../src/report/render.ts";
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
    { ts: "2026-10-26T20:00:01.100Z", run_id: "fixture-run-001", agent: "zetaris", action: "query", latency_ms: 2310, status: "ok",
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
    const row = lineRow(renderReport(fixture()), "r-001");
    for (const s of [
      "ERP Portal", "a-erp-01", 'class="badge inet"', "log4j-core 2.14.1 (bundled in ERP-Portal WAR)", "Apache / Log4j2", "family: Apache Log4j",
      "2.14.1", "2021-12-24", "overdue by 1767 days", "US federal benchmark · 1 KEV CVE", "2026-11-02", "patch by (house target)",
      "0.944", "CVE-2021-44228", "percentile 99.9", ">verified<", "Listed in CISA KEV (CVE-2021-44228)",
    ]) assert.ok(row.includes(s), `r-001 missing: ${s}`);
    assert.ok(row.includes('class="pill d-patch_now">Patch now<'));
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
    assert.equal(count(list, '<tr class="detail"><td colspan="9"><details>'), 6);
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
