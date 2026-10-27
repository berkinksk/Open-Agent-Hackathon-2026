// Tests for the accuracy evaluation (src/eval/**, scripts/eval.ts, scripts/compare-answers.ts).
// No network: the arms are fakes, and every file lives in a temporary directory.
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { MODELS } from "../src/contracts.ts";
import type { ChatRequest, Deps, InventoryRow, KevPair, Llm, Receipt, Resolution, RunResponse } from "../src/contracts.ts";
import { CsvError, detectDelimiter, mdCell, parseCsv, parseCsvObjects } from "../src/eval/csv.ts";
import { answerKey, checkAnswersAgainstKev, isNoneWithExtraText, isNoneWord, normName, parseAnswerSheet } from "../src/eval/answers.ts";
import { callStats, isNullPrediction, matchesAnswer, predictionFromResolution, scoreArm, scoreRow } from "../src/eval/score.ts";
import { assertSetAllowed, parseTestRows, pickTestRows, selectRows } from "../src/eval/split.ts";
import { buildEvalRows, runEvaluation, withholdSealedIssues } from "../src/eval/evaluate.ts";
import { evalFileStem, evalJson, renderEvalMarkdown, renderSummaryTable, renderUnlabelledMarkdown, renderUnlabelledSummaryTable } from "../src/eval/report.ts";
import { classifyPair, compareAnswerSheets, renderComparisonMarkdown } from "../src/eval/compare.ts";
import { buildBaselinePrompt, extractJson, parseBaselineReply, runBaseline, uniqueCandidates } from "../src/eval/baseline.ts";
import { createResolveArm, ultraRowsFromTrace } from "../src/eval/wiring.ts";
import { devRowsOf, runUnlabelledEvaluation, sameAnswer, summariseUnlabelledArm } from "../src/eval/unlabelled.ts";
import { ArmUnavailableError } from "../src/eval/types.ts";
import { familiesOf } from "../src/resolve/normalise.ts";
import type { AnswerRow, ArmName, ArmOutput, ArmPrediction, UnlabelledRow } from "../src/eval/types.ts";
import { isUnlabelled, main as evalMain, parseEvalArgs, parseInventoryJson, UsageError } from "../scripts/eval.ts";
import { main as compareMain, parseCompareArgs } from "../scripts/compare-answers.ts";

// ---------- fixtures (synthetic) ----------
const HEADER = "row_id,software (copy it from the row),kev_vendor,kev_products,notes";
const SHEET = [
  HEADER,
  'R01,log4j-core 2.14.1 (bundled in ERP-Portal WAR),Apache,Log4j2,',
  'R02,"Citrix NetScaler ADC 13.1-48.47, DMZ",Citrix,"NetScaler; NetScaler ADC and Gateway; NetScaler ADC and NetScaler Gateway; Application Delivery Controller (ADC) and Gateway",several spellings',
  "R03,Notepad++ v8.6,–,none,",
  "R04,Exchange Online (M365 tenant),Microsoft,none,look-alike of Exchange Server",
  "R05,Windows Server 2019 DC,Microsoft,Windows ,unsure",
  "R06,FortiClient VPN 7.0.9 (laptops),Fortinet,None,lookalike",
].join("\r\n");

// The KEV (vendor, product) pairs the fixture sheet's names come from (synthetic subset; real KEV spellings).
const KEV_PAIRS: KevPair[] = [
  { vendor: "Apache", product: "Log4j2" },
  { vendor: "Citrix", product: "NetScaler" },
  { vendor: "Citrix", product: "NetScaler ADC and Gateway" },
  { vendor: "Citrix", product: "NetScaler ADC and NetScaler Gateway" },
  { vendor: "Citrix", product: "Application Delivery Controller (ADC) and Gateway" },
  { vendor: "Microsoft", product: "Windows " },
  { vendor: "Microsoft", product: "Exchange Server" },
  { vendor: "Fortinet", product: "FortiClient EMS" },
];

function sheet(text = SHEET, source = "answers.csv") {
  return parseAnswerSheet(text, source);
}
function ans(id: string): AnswerRow {
  const a = sheet().rows.find((r) => r.row_id === id);
  assert.ok(a, `fixture row ${id}`);
  return a;
}
function receipt(model: string, pt = 100, ct = 20, status: "ok" | "error" = "ok"): Receipt {
  return {
    call_id: `c-${Math.random()}`, agent: "jury", requested_model: model, response_model: model, routed_model: model,
    receipt_id: "rcpt_test", latency_ms: 10, prompt_tokens: pt, completion_tokens: ct, status,
  };
}
function inv(id: string, software: string): InventoryRow {
  return { row_id: id, asset_id: `A-${id}`, asset_name: `host-${id}`, asset_type: "server", internet_facing: false, owner_team: "IT", software };
}

const tmpRoots: string[] = [];
function tmp(): string {
  const d = mkdtempSync(path.join(tmpdir(), "eval-test-"));
  tmpRoots.push(d);
  return d;
}
after(() => { for (const d of tmpRoots) rmSync(d, { recursive: true, force: true }); });

// ---------- CSV ----------
describe("csv", () => {
  test("quoted fields: commas, doubled quotes, newlines, CRLF and BOM", () => {
    const text = '﻿a,b,c\r\n"x, y","say ""hi""","line1\nline2"\r\n\r\nplain,,end\n';
    const recs = parseCsv(text);
    assert.equal(recs.length, 3);
    assert.deepEqual(recs[0].fields, ["a", "b", "c"]);
    assert.deepEqual(recs[1].fields, ["x, y", 'say "hi"', "line1\nline2"]);
    assert.deepEqual(recs[2].fields, ["plain", "", "end"]);
    assert.equal(recs[2].line, 5); // the embedded newline and the blank line both count
  });
  test("a final record without a newline, and an empty quoted last field", () => {
    assert.deepEqual(parseCsv('a,""').map((r) => r.fields), [["a", ""]]);
  });
  test("an unterminated quote throws with its line", () => {
    assert.throws(() => parseCsv('a,b\n"open,c\n'), (e: unknown) => e instanceof CsvError && e.line === 2);
  });
  test("delimiter detection: comma, tab, semicolon (quotes ignored)", () => {
    assert.equal(detectDelimiter('a,"b;c;d",e'), ",");
    assert.equal(detectDelimiter("a\tb\tc"), "\t");
    assert.equal(detectDelimiter("a;b;c"), ";");
    assert.deepEqual(parseCsv("a\tb\n1\t2").map((r) => r.fields), [["a", "b"], ["1", "2"]]);
  });
  test("headers are normalised and aliased", () => {
    const { header, rows } = parseCsvObjects("Row ID,Software (copy it),vendorProject\nr1,x,Acme", {
      row_id: ["rowid"], kev_vendor: ["vendorproject"],
    });
    assert.deepEqual(header, ["row_id", "software", "kev_vendor"]);
    assert.deepEqual(rows[0].values, { row_id: "r1", software: "x", kev_vendor: "Acme" });
  });
  test("mdCell escapes pipes and newlines", () => {
    assert.equal(mdCell("a|b\nc"), "a\\|b c");
    assert.equal(mdCell(null), "");
  });
});

// ---------- answer sheets ----------
describe("answer sheets", () => {
  test("parses the answer-sheet format, including several spellings and none", () => {
    const s = sheet();
    assert.equal(s.rows.length, 6);
    assert.deepEqual(s.issues, []);
    assert.deepEqual(ans("R02").kev_products.length, 4);
    assert.equal(ans("R02").software, "Citrix NetScaler ADC 13.1-48.47, DMZ");
    assert.equal(ans("R03").is_none, true);
    assert.equal(ans("R03").kev_vendor, null);
    assert.equal(ans("R04").is_none, true);
    assert.equal(ans("R04").lookalike, true);
    assert.equal(ans("R06").is_none, true); // "None", any case
    assert.equal(ans("R06").lookalike, true);
    assert.equal(ans("R05").unsure, true);
    assert.deepEqual(ans("R05").kev_products, ["Windows"]);
  });
  test("row ids are trimmed and upper-cased", () => {
    const s = sheet(`${HEADER}\n r07 ,x,Apache,Log4j2,`);
    assert.equal(s.rows[0].row_id, "R07");
  });
  test("blank answers, products without a vendor and mixed none are left out as issues", () => {
    const s = sheet([HEADER, "R10,x,,,", "R11,x,,Log4j2,", "R12,x,Apache,none; Log4j2,", "R13,x,none,,", ",x,Apache,Log4j2,", ",,,,"].join("\n"));
    assert.deepEqual(s.rows.map((r) => r.row_id), ["R13"]); // "none" written in the vendor column
    assert.equal(s.rows[0].is_none, true);
    assert.deepEqual(s.issues.map((i) => i.row_id), ["R10", "R11", "R12", null]);
    assert.match(s.issues[0].problem, /blank answer/);
    assert.match(s.issues[1].problem, /without a KEV vendor/);
  });
  test("duplicates: identical answers keep one; conflicting answers drop the row", () => {
    const s = sheet([HEADER, "R20,x,Apache,Log4j2,", "r20,x,apache, log4j2 ,", "R21,x,Apache,Log4j2,", "R21,x,Apache,Tomcat,"].join("\n"));
    assert.deepEqual(s.rows.map((r) => r.row_id), ["R20"]);
    assert.equal(s.issues.length, 2);
    assert.match(s.issues[1].problem, /conflicts/);
  });
  test("a missing required column throws", () => {
    assert.throws(() => sheet("row_id,software,notes\nR1,x,"), /missing column\(s\) kev_vendor, kev_products/);
  });
  test("'none' with extra text is an issue, never a KEV product (fail closed)", () => {
    const s = sheet([
      HEADER,
      "R04,Exchange Online,Microsoft,none (cloud service),",
      "R30,x,Microsoft,None - SaaS,",
      "R31,x,Microsoft,not in KEV list,",
      "R32,x,Microsoft,Not on KEV,",
      "R33,x,Microsoft,N/A (SaaS),",
      "R34,x,Microsoft,– cloud only,",
      "R35,x,Microsoft,Exchange Server; none (cloud),",
      "R36,x,none (SaaS),Exchange Server,",
      "R37,x,none (SaaS),,",
      "R38,x,N/A (cloud),none,",   // a clean none in kev_products wins; the vendor cell is ignored
      "R39,x,Microsoft,Exchange Server (not Online),", // a comment inside a name: caught by the KEV check
    ].join("\n"));
    assert.deepEqual(s.rows.map((r) => r.row_id), ["R38", "R39"]);
    assert.equal(s.rows[0].is_none, true);
    assert.deepEqual(s.issues.map((i) => i.row_id), ["R04", "R30", "R31", "R32", "R33", "R34", "R35", "R36", "R37"]);
    for (const i of s.issues.slice(0, 7)) assert.equal(i.problem, "kev_products: 'none' with extra text; put comments in the notes column");
    assert.match(s.issues[7].problem, /^kev_vendor: 'none' with extra text/);
    assert.match(s.issues[8].problem, /^kev_vendor: 'none' with extra text/);
    assert.equal(s.issues[0].line, 2);
  });
  test("isNoneWithExtraText: flags none words with text, never clean none words or real names", () => {
    for (const w of ["none (cloud service)", "None - SaaS", "not in KEV list", "Not on KEV", "NONE: SaaS", "n/a - cloud", "null (n/a)", "no match found", "- SaaS", "none(cloud)"]) {
      assert.ok(isNoneWithExtraText(w), w);
    }
    for (const w of ["none", "None.", "n/a", "-", "no match", "not in KEV", "Log4j2", "NAS", "Node.js", "NoneCMS", "Nullsoft", "Notepad++", "Exchange Server (not Online)", "Nostromo nhttpd"]) {
      assert.equal(isNoneWithExtraText(w), false, w);
    }
  });
  test("checkAnswersAgainstKev: names compare as in scoring; a name not in KEV leaves the row unlabelled", () => {
    const base = sheet();
    const ok = checkAnswersAgainstKev(base, KEV_PAIRS);
    assert.equal(ok.rows.length, 6); // trailing-space "Windows " and every Citrix spelling are KEV names
    assert.deepEqual(ok.issues, []);
    const s = sheet([
      HEADER,
      "R40,x,microsoft, exchange server ,",                        // case and spaces: fine
      "R41,Exchange Online,Microsoft,Exchange Server (not Online),", // a comment typed into the products cell
      "R42,x,Apache Software Foundation,Log4j2,",                  // not the KEV vendor name
      "R43,x,Citrix,NetScaler; NetScaler ADC & Gateway,",           // one stray spelling among valid ones
      "R44,x,Microsoft,Log4j2,",                                   // a KEV product, but of another vendor
      "R45,x,–,none,",                                             // none rows pass
    ].join("\n"));
    const c = checkAnswersAgainstKev(s, KEV_PAIRS);
    assert.deepEqual(c.rows.map((r) => r.row_id), ["R40", "R45"]);
    assert.deepEqual(c.issues.map((i) => i.row_id), ["R41", "R42", "R43", "R44"]);
    assert.match(c.issues[0].problem, /^kev_products 'Exchange Server \(not Online\)' is not a KEV product of 'Microsoft'; copy the names exactly from KEV \(row left unlabelled\)$/);
    assert.match(c.issues[1].problem, /kev_vendor 'Apache Software Foundation' is not a KEV vendor/);
    assert.match(c.issues[2].problem, /'NetScaler ADC & Gateway' is not a KEV product of 'Citrix'/);
    assert.match(c.issues[3].problem, /'Log4j2' is not a KEV product of 'Microsoft'/);
    assert.equal(s.rows.length, 6, "the input sheet is not mutated");
    assert.throws(() => checkAnswersAgainstKev(s, []), /KEV list is empty/);
  });
  test("none words and the name normaliser", () => {
    for (const w of ["none", "None", " NONE ", "n/a", "-", "–", "none?", "no match"]) assert.ok(isNoneWord(w), w);
    assert.equal(isNoneWord("Log4j2"), false);
    assert.equal(normName("  NetScaler ADC and  Gateway "), "netscaleradcandgateway");
    assert.equal(answerKey(ans("R03")), "none");
  });
});

// ---------- scoring ----------
describe("scoring", () => {
  test("any listed spelling counts, case- and space-insensitively", () => {
    const a = ans("R02");
    for (const p of ["NetScaler", "NetScaler ADC and Gateway", "  netscaler adc AND netscaler gateway", "Application Delivery Controller (ADC) and Gateway"]) {
      assert.equal(scoreRow(a, { row_id: "R02", vendor: "citrix ", product: p }).outcome, "match_ok", p);
    }
    assert.equal(scoreRow(a, { row_id: "R02", vendor: "Citrix", product: "NetScaler Gateway Plus" }).outcome, "wrong_match");
    assert.equal(scoreRow(ans("R05"), { row_id: "R05", vendor: "Microsoft", product: "Windows " }).outcome, "match_ok");
    assert.equal(scoreRow(ans("R05"), { row_id: "R05", vendor: "Microsoft", product: "Win dows" }).outcome, "match_ok");
  });
  test("by KEV family: another KEV spelling of the answer's product is correct; a different product is still wrong", () => {
    // the answer lists one spelling only; the prediction uses another KEV spelling of the same family
    const a: AnswerRow = { ...ans("R02"), kev_vendors: ["Citrix"], kev_vendor: "Citrix", kev_products: ["NetScaler ADC and Gateway"] };
    const other = { row_id: "R02", vendor: "Citrix", product: "NetScaler" };
    assert.equal(scoreRow(a, other).outcome, "wrong_match", "listed spellings only: the unlisted spelling is not matched");
    assert.equal(scoreRow(a, other, familiesOf).outcome, "match_ok", "by family: NetScaler and NetScaler ADC and Gateway are one family");
    assert.equal(matchesAnswer({ vendor: "Citrix", product: "Workspace Application and Receiver for Windows" }, a, familiesOf), false);
    const ff: AnswerRow = { ...ans("R02"), kev_vendors: ["Mozilla"], kev_vendor: "Mozilla", kev_products: ["Firefox"] };
    assert.equal(matchesAnswer({ vendor: "Mozilla", product: "Firefox and Thunderbird" }, ff, familiesOf), true, "a combo spelling names the family");
    assert.equal(matchesAnswer({ vendor: "Mozilla", product: "Firefox and Thunderbird" }, ff), false);
    assert.equal(scoreRow(ans("R04"), { row_id: "R04", vendor: "Microsoft", product: "Exchange Server" }, familiesOf).outcome, "false_match", "none stays none");
  });
  test("the vendor must match too", () => {
    assert.equal(scoreRow(ans("R01"), { row_id: "R01", vendor: "Apache Foundation", product: "Log4j2" }).outcome, "wrong_match");
    assert.equal(matchesAnswer({ vendor: null, product: "Log4j2" }, ans("R01")), false);
  });
  test("none: null is correct, a product is a false match, a vendor alone counts as null", () => {
    const a = ans("R04");
    assert.equal(scoreRow(a, { row_id: "R04", vendor: null, product: null }).outcome, "none_ok");
    assert.equal(scoreRow(a, { row_id: "R04", vendor: "Microsoft", product: "" }).outcome, "none_ok");
    assert.equal(scoreRow(a, { row_id: "R04", vendor: "Microsoft", product: "Exchange Server" }).outcome, "false_match");
    assert.equal(isNullPrediction({ product: "   " }), true);
  });
  test("a KEV answer with a null prediction is missed; no prediction is missing", () => {
    assert.equal(scoreRow(ans("R01"), { row_id: "R01", vendor: "Apache", product: null }).outcome, "missed");
    const s = scoreRow(ans("R01"), undefined);
    assert.equal(s.outcome, "missing");
    assert.equal(s.correct, false);
  });
  test("abstentions: correct for none under the rule, never under strict; wrong for a KEV answer", () => {
    const n = scoreRow(ans("R04"), { row_id: "R04", vendor: "Microsoft", product: "Exchange Server", abstained: true });
    assert.equal(n.outcome, "none_abstained");
    assert.equal(n.correct, true);
    assert.deepEqual(n.predicted, { vendor: null, product: null });
    assert.equal(scoreRow(ans("R01"), { row_id: "R01", vendor: null, product: null, abstained: true }).outcome, "abstained");
  });
  test("scoreArm: accuracy, strict accuracy, Ultra share, calls, tokens and extras", () => {
    const answers = sheet().rows;
    const preds: ArmPrediction[] = [
      { row_id: "r01", vendor: "Apache", product: "Log4j2" },                                  // match_ok (id case)
      { row_id: "R02", vendor: "Citrix", product: "NetScaler ADC and Gateway", used_ultra: true }, // match_ok
      { row_id: "R03", vendor: null, product: null },                                         // none_ok
      { row_id: "R04", vendor: null, product: null, abstained: true, used_ultra: true },      // none_abstained
      { row_id: "R05", vendor: "Microsoft", product: "Windows Server" },                      // wrong_match
      // R06 missing
      { row_id: "R99", vendor: "X", product: "Y" },                                           // extra
      { row_id: "R01", vendor: "Wrong", product: "Wrong" },                                   // duplicate ignored
    ];
    const receipts = [receipt(MODELS.bolt, 100, 10), receipt(MODELS.lightning, 200, 20), receipt(MODELS.ultra, 300, 30, "error")];
    const { metrics: m, rows, extra_predictions } = scoreArm(answers, preds, receipts, 1234);
    assert.equal(m.rows, 6);
    assert.equal(m.correct, 4);
    assert.equal(m.accuracy, 4 / 6);
    assert.equal(m.correct_strict, 3);
    assert.equal(m.kev_rows, 3);
    assert.equal(m.kev_matched, 2);
    assert.equal(m.none_rows, 3);
    assert.equal(m.none_rejected, 2);
    assert.equal(m.lookalike_rows, 2);
    assert.equal(m.lookalike_rejected, 1);
    assert.equal(m.abstained, 1);
    assert.equal(m.missing, 1);
    assert.equal(m.wrong_match, 1);
    assert.equal(m.ultra_rows, 2);
    assert.equal(m.ultra_share, 2 / 6);
    assert.equal(m.calls, 3);
    assert.equal(m.ultra_calls, 1);
    assert.equal(m.call_errors, 1);
    assert.deepEqual(m.calls_by_model, { [MODELS.bolt]: 1, [MODELS.lightning]: 1, [MODELS.ultra]: 1 });
    assert.equal(m.tokens, 660);
    assert.equal(m.time_ms, 1234);
    assert.deepEqual(extra_predictions, ["R99"]);
    assert.equal(rows.find((r) => r.row_id === "R06")?.outcome, "missing");
  });
  test("scoreArm with no rows gives null ratios", () => {
    const { metrics } = scoreArm([], [], [], 0);
    assert.equal(metrics.accuracy, null);
    assert.equal(metrics.ultra_share, null);
  });
  test("predictionFromResolution: matched, no_match, unresolved, critic ask_owner, Ultra use", () => {
    const base: Resolution = {
      row_id: "R01", status: "matched", vendor: "Apache", product: "Log4j2", family: "apache/log4j", version: "2.14.1",
      product_type: "library", votes: [], adjudicated_by: null, confidence: 0.9,
    };
    assert.deepEqual(predictionFromResolution(base), { row_id: "R01", vendor: "Apache", product: "Log4j2", used_ultra: false });
    assert.equal(predictionFromResolution({ ...base, status: "no_match" }).product, null);
    assert.equal(predictionFromResolution({ ...base, status: "unresolved" }).abstained, true);
    const critic = { row_id: "R01", verdict: "ask_owner" as const, reasons: [], rubric: { accuracy: 1, appropriateness: 1, actionability: 1, total: 3 }, round: 2 };
    assert.equal(predictionFromResolution(base, critic).abstained, true);
    assert.equal(predictionFromResolution({ ...base, adjudicated_by: "ultra" }).used_ultra, true);
    assert.equal(predictionFromResolution({ ...base, votes: [{ row_id: "R01", juror: "ultra", vendor: null, product: null, confidence: 1 }] }).used_ultra, true);
  });
});

// ---------- split ----------
describe("dev/test split", () => {
  test("test-row file formats", () => {
    assert.deepEqual(parseTestRows(["r1", "R2"]).row_ids, ["R1", "R2"]);
    const f = parseTestRows({ seed: "s", method: "m", row_ids: ["R3"] });
    assert.deepEqual(f.row_ids, ["R3"]);
    assert.deepEqual(f.meta, { seed: "s", method: "m" });
    assert.deepEqual(parseTestRows([{ row_id: "R4", software: "x" }]).row_ids, ["R4"]);
    assert.throws(() => parseTestRows([]), /empty/);
    assert.throws(() => parseTestRows(["R1", "r1"]), /duplicate/);
    assert.throws(() => parseTestRows({ x: 1 }), /expected/);
    assert.throws(() => parseTestRows([{}]), /no row id/);
  });
  test("the test set is sealed without --final", () => {
    assert.throws(() => assertSetAllowed("test", false), /sealed/);
    assert.doesNotThrow(() => assertSetAllowed("test", true));
    assert.doesNotThrow(() => assertSetAllowed("dev", false));
  });
  test("dev excludes every test row; test takes exactly the test rows and reports missing labels", () => {
    const answers = sheet().rows;
    const dev = selectRows("dev", answers, ["r02", "R04"]);
    assert.deepEqual(dev.answers.map((a) => a.row_id), ["R01", "R03", "R05", "R06"]);
    assert.equal(dev.sealed_excluded, 2);
    const t = selectRows("test", answers, ["R04", "R02", "R77"]);
    assert.deepEqual(t.answers.map((a) => a.row_id), ["R04", "R02"]);
    assert.deepEqual(t.missing_labels, ["R77"]);
  });
  test("pickTestRows is reproducible from the seed", () => {
    const ids = Array.from({ length: 80 }, (_, i) => `R${String(i + 1).padStart(2, "0")}`);
    const a = pickTestRows(ids, 30, "seed-1");
    const b = pickTestRows([...ids].reverse(), 30, "seed-1");
    assert.deepEqual(a.row_ids, b.row_ids);
    assert.equal(new Set(a.row_ids).size, 30);
    assert.notDeepEqual(pickTestRows(ids, 30, "seed-2").row_ids, a.row_ids);
    assert.throws(() => pickTestRows(ids, 81, "s"), /cannot pick/);
  });
});

// ---------- runner ----------
function fakeArms(script: Partial<Record<ArmName, (rows: InventoryRow[]) => ArmOutput | Promise<ArmOutput>>>) {
  const seen: { arm: ArmName; ids: string[] }[] = [];
  let active = 0;
  let maxActive = 0;
  const resolveArm = async (arm: ArmName, rows: InventoryRow[]): Promise<ArmOutput> => {
    active++;
    maxActive = Math.max(maxActive, active);
    seen.push({ arm, ids: rows.map((r) => r.row_id) });
    try {
      await new Promise((r) => setTimeout(r, 2));
      const f = script[arm];
      if (!f) throw new ArmUnavailableError(arm, "not wired yet");
      return await f(rows);
    } finally { active--; }
  };
  return { resolveArm, seen, maxActive: () => maxActive };
}
const perfect = (rows: InventoryRow[]): ArmOutput => ({
  predictions: rows.map((r) => {
    const a = sheet().rows.find((x) => x.row_id === r.row_id)!;
    return { row_id: r.row_id, vendor: a.kev_vendor, product: a.kev_products[0] ?? null };
  }),
  receipts: [receipt(MODELS.bolt), receipt(MODELS.lightning)],
});
const allNull = (rows: InventoryRow[]): ArmOutput => ({ predictions: rows.map((r) => ({ row_id: r.row_id, vendor: null, product: null })), receipts: [] });
const INVENTORY = sheet().rows.map((a) => inv(a.row_id, a.software));

describe("runEvaluation", () => {
  test("dev: test rows never reach an arm; arms run one at a time; failures are recorded", async () => {
    const f = fakeArms({ full: perfect, normaliser: allNull, bolt: () => { throw new Error("boom"); } });
    let t = 0;
    const r = await runEvaluation({
      set: "dev", final: false, arms: ["full", "normaliser", "bolt", "lightning"], labels: sheet(),
      testIds: ["R02", "R05"], inventory: [...INVENTORY, inv("R50", "unlabelled thing")], resolveArm: f.resolveArm,
      now: () => (t += 500), clock: () => new Date("2026-10-27T10:00:00Z"),
    });
    for (const s of f.seen) assert.deepEqual(s.ids, ["R01", "R03", "R04", "R06"]);
    assert.equal(f.maxActive(), 1);
    assert.equal(r.rows_evaluated, 4);
    assert.equal(r.sealed_rows_excluded, 2);
    assert.deepEqual(r.unlabelled_rows, ["R50"]);
    const [full, norm, bolt, light] = r.arms;
    assert.equal(full.metrics?.accuracy, 1);
    assert.equal(full.metrics?.time_ms, 500);
    assert.equal(norm.metrics?.correct, 3); // the 3 none rows
    assert.equal(bolt.status, "error");
    assert.equal(bolt.message, "boom");
    assert.equal(light.status, "unavailable");
    assert.equal(r.generated_at, "2026-10-27T10:00:00.000Z");
  });
  test("test: refused without --final; with --final every test row needs an agreed answer", async () => {
    const f = fakeArms({ full: perfect });
    const base = { arms: ["full"] as ArmName[], labels: sheet(), inventory: INVENTORY, resolveArm: f.resolveArm };
    await assert.rejects(runEvaluation({ ...base, set: "test", final: false, testIds: ["R01"] }), /sealed/);
    await assert.rejects(runEvaluation({ ...base, set: "test", final: true, testIds: ["R01", "R88"] }), /no usable agreed answer: R88/);
    assert.equal(f.seen.length, 0);
    const r = await runEvaluation({ ...base, set: "test", final: true, testIds: ["R04", "R01"] });
    assert.deepEqual(f.seen[0].ids, ["R04", "R01"]);
    assert.equal(r.arms[0].metrics?.correct, 2);
  });
  test("a final run refuses a test row whose answer was 'none' with extra text, and says why", async () => {
    // The probe from review: a correct null prediction must never be scored against a bogus "KEV product".
    const labels = checkAnswersAgainstKev(sheet([...SHEET.split("\r\n"), "R07,Exchange Online,Microsoft,none (cloud service),"].join("\n")), KEV_PAIRS);
    assert.equal(labels.rows.some((r) => r.row_id === "R07"), false);
    const f = fakeArms({ full: allNull });
    await assert.rejects(
      runEvaluation({ set: "test", final: true, arms: ["full"], labels, testIds: ["R01", "R07"], inventory: null, resolveArm: f.resolveArm }),
      /1 test row\(s\) have no usable agreed answer: R07 \(line 8: kev_products: 'none' with extra text; put comments in the notes column\)\. Fix the answer sheet/,
    );
    assert.equal(f.seen.length, 0, "no arm runs before the sheet is fixed");
  });
  test("dev runs withhold the details of a sealed row's sheet issue; final runs show them", async () => {
    const labels = checkAnswersAgainstKev(sheet([...SHEET.split("\r\n"), "R08,x,Microsoft,Exchange Server (not Online),", "R09,x,Microsoft,Exchange Online,"].join("\n")), KEV_PAIRS);
    const f = fakeArms({ normaliser: allNull });
    const dev = await runEvaluation({ set: "dev", final: false, arms: ["normaliser"], labels, testIds: ["R02", "R08"], inventory: null, resolveArm: f.resolveArm });
    assert.deepEqual(dev.label_issues.map((i) => i.row_id), ["R08", "R09"]);
    assert.equal(dev.label_issues[0].problem, "an issue on a sealed test row (details withheld outside the final run)");
    assert.match(dev.label_issues[1].problem, /'Exchange Online' is not a KEV product/); // a dev row: shown
    assert.doesNotMatch(renderEvalMarkdown(dev), /not Online/);
    assert.deepEqual(withholdSealedIssues([{ row_id: null, line: 3, problem: "missing row_id" }], ["R01"])[0].problem, "missing row_id");
  });
  test("test rows missing from the inventory stop a test run", async () => {
    const f = fakeArms({ full: perfect });
    await assert.rejects(
      runEvaluation({ set: "test", final: true, arms: ["full"], labels: sheet(), testIds: ["R01"], inventory: [inv("R02", "x")], resolveArm: f.resolveArm }),
      /missing from the inventory: R01/,
    );
  });
  test("a bad arm result is an error, not a crash", async () => {
    const f = fakeArms({ full: () => ({ nope: true }) as unknown as ArmOutput });
    const r = await runEvaluation({ set: "dev", final: false, arms: ["full"], labels: sheet(), testIds: ["R99"], inventory: null, resolveArm: f.resolveArm });
    assert.equal(r.arms[0].status, "error");
    assert.match(r.arms[0].message ?? "", /predictions, receipts/);
  });
  test("buildEvalRows: inventory rows win, label software is the fallback, mismatches are flagged", () => {
    const answers = sheet().rows.slice(0, 3);
    const b = buildEvalRows(answers, [inv("R01", "log4j-core 2.14.1 (bundled in ERP-Portal WAR)"), inv("R02", "something else")]);
    assert.deepEqual(b.rows.map((r) => r.row_id), ["R01", "R02"]);
    assert.deepEqual(b.no_row, ["R03"]);
    assert.deepEqual(b.software_mismatches, ["R02"]);
    const fromLabels = buildEvalRows(answers, null);
    assert.equal(fromLabels.rows.length, 3);
    assert.equal(fromLabels.rows[2].software, "Notepad++ v8.6");
  });
});

// ---------- report ----------
describe("report", () => {
  test("Markdown table and JSON; the test-set Markdown carries no per-row results", async () => {
    const f = fakeArms({ full: perfect, normaliser: allNull });
    const dev = await runEvaluation({ set: "dev", final: false, arms: ["full", "normaliser", "bolt"], labels: sheet(), testIds: ["R02"], inventory: INVENTORY, resolveArm: f.resolveArm, baselineModel: "ultra" });
    const table = renderSummaryTable(dev);
    assert.match(table, /\| Full system \(jury \+ Ultra \+ critic\) \| 5\/5 \(100\.0%\)/);
    assert.match(table, /Bolt alone \| not run: not wired yet/);
    const md = renderEvalMarkdown(dev);
    assert.match(md, /## Misses on development rows/);
    assert.match(md, /\| R01 \| Normaliser alone \(no model\) \| missed \| null \| Apache \/ Log4j2 \|/);
    assert.match(md, /1 sealed test row withheld/);
    const partial = fakeArms({ full: () => ({ predictions: [{ row_id: "R04", vendor: null, product: null, abstained: true }], receipts: [] }) });
    const pr = await runEvaluation({ set: "dev", final: false, arms: ["full"], labels: sheet(), testIds: ["R02"], inventory: INVENTORY, resolveArm: partial.resolveArm });
    const pmd = renderEvalMarkdown(pr);
    assert.match(pmd, /\| R01 \| Full system \(jury \+ Ultra \+ critic\) \| missing \| \(no prediction\) \| Apache \/ Log4j2 \|/);
    assert.match(pmd, /\| R04 \| Full system \(jury \+ Ultra \+ critic\) \| none_abstained \| \(left to the owner\) \| none \|/);
    assert.equal((evalJson(dev).arms as { rows: unknown[] }[])[0].rows.length, 5);

    const test = await runEvaluation({ set: "test", final: true, arms: ["normaliser"], labels: sheet(), testIds: ["R01", "R04"], inventory: INVENTORY, resolveArm: f.resolveArm });
    const tmd = renderEvalMarkdown(test);
    assert.doesNotMatch(tmd, /R01|R04|Log4j2/);
    assert.equal((evalJson(test).arms as { rows: unknown[] }[])[0].rows.length, 2); // final run keeps evidence
    assert.equal((evalJson({ ...test, final: false }).arms as { rows: unknown[] }[])[0].rows.length, 0);
  });
  test("file stem", () => {
    assert.equal(evalFileStem("dev", new Date("2026-10-27T09:05:07Z")), "eval-2026-10-27-090507-dev");
  });
});

// ---------- comparison ----------
describe("answer comparison", () => {
  const A = [HEADER,
    "R01,log4j,Apache,Log4j2,",
    "R02,netscaler,Citrix,NetScaler,",
    "R03,notepad,–,none,",
    "R04,exchange online,Microsoft,Exchange Server,unsure",
    "R05,winsrv,Microsoft,Windows,",
    "R06,forticlient,Fortinet,FortiClient EMS,",
    "R07,only in a,Apache,Tomcat,",
    "R09,both none,,none,",
  ].join("\n");
  const B = [HEADER,
    "R01,log4j,apache, log4j2 ,",
    "R02,netscaler,Citrix,NetScaler ADC and Gateway; netscaler,",
    "R03,notepad,Notepad++,Notepad++,",
    "R04,exchange online,Microsoft,none,cloud service",
    "R05,winsrv,Microsoft Corp,Windows,",
    "R06,forticlient,Fortinet,FortiOS,unsure",
    "R08,only in b,Apache,HTTP Server,",
    "R09,both none,–,None,",
  ].join("\n");
  const cmp = () => compareAnswerSheets(sheet(A, "a.csv"), sheet(B, "b.csv"), { names: ["First", "Second"] });

  test("classifies every row", () => {
    const c = cmp();
    const kind = (id: string) => c.rows.find((r) => r.row_id === id)?.kind;
    assert.equal(kind("R01"), "agree");             // case and spaces
    assert.equal(kind("R02"), "spellings_differ");
    assert.equal(kind("R03"), "disagree");          // none vs product
    assert.equal(kind("R04"), "disagree");
    assert.equal(kind("R05"), "disagree");          // vendor differs
    assert.equal(kind("R06"), "disagree");          // product differs
    assert.equal(kind("R07"), "only_a");
    assert.equal(kind("R08"), "only_b");
    assert.equal(kind("R09"), "agree");
    assert.deepEqual(c.counts, { agree: 2, spellings_differ: 1, disagree: 4, only_a: 1, only_b: 1 });
    assert.deepEqual(c.rows.find((r) => r.row_id === "R02")?.union_products, ["NetScaler", "NetScaler ADC and Gateway"]);
    assert.deepEqual(c.rows.find((r) => r.row_id === "R04")?.flags, ["unsure (First)"]);
    assert.equal(classifyPair(ans("R03"), ans("R04")).kind, "agree");
  });
  test("restrictTo limits the comparison to the given rows", () => {
    const c = compareAnswerSheets(sheet(A), sheet(B), { restrictTo: ["r01", "R03"] });
    assert.deepEqual(c.rows.map((r) => r.row_id), ["R01", "R03"]);
  });
  test("Markdown lists disagreements, spelling differences and flags", () => {
    const md = renderComparisonMarkdown(cmp());
    assert.match(md, /# Answer comparison: First vs Second/);
    assert.match(md, /\*\*disagree: 4\*\*/);
    assert.match(md, /\| R03 \| notepad \| none \| Notepad\+\+ \/ Notepad\+\+ \| one says none, the other names a KEV product \|/);
    assert.match(md, /\| R06 \| forticlient \| Fortinet \/ FortiClient EMS \| Fortinet \/ FortiOS \| different KEV product \| Second: unsure; unsure \(Second\) \|/);
    assert.match(md, /Suggested kev_products/);
    assert.match(md, /NetScaler; NetScaler ADC and Gateway/);
    assert.match(md, /Only in First:\*\* 1 \(R07\)/);
    assert.doesNotMatch(md, /\| R01 \|/); // agreements are not listed
  });
});

// ---------- baseline ----------
function mockLlm(reply: { text?: string; json?: unknown }) {
  const calls: ChatRequest[] = [];
  const llm: Llm = {
    async chat(req) {
      calls.push(req);
      return { text: reply.text ?? "", json: reply.json ?? null, receipt: receipt(MODELS[req.model], 1000, 200) };
    },
  };
  return { llm, calls };
}

describe("one-call baseline", () => {
  const rows = [inv("R01", "log4j-core 2.14.1"), inv("R04", "Exchange Online (M365 tenant)")];
  const cands = [
    { vendor: "Apache", product: "Log4j2" }, { vendor: "apache", product: " log4j2" },
    { vendor: "Microsoft", product: "Exchange Server" }, { vendor: "Microsoft", product: "Windows " },
  ];
  test("the prompt lists unique candidates and every row", () => {
    assert.equal(uniqueCandidates(cands).length, 3);
    const p = buildBaselinePrompt(rows, cands);
    assert.match(p.user, /3 in total/);
    assert.match(p.user, /- R04: "Exchange Online \(M365 tenant\)" \[asset type: server\]/);
    assert.match(p.system, /cloud or online service is not the on-premises server/);
  });
  test("exactly one call; the reply becomes predictions with its receipt", async () => {
    const { llm, calls } = mockLlm({ json: { results: [
      { row_id: "r01", vendor: "Apache", product: "Log4j2" },
      { row_id: "R04", vendor: "Microsoft", product: null },
      { row_id: "R99", vendor: "X", product: "Y" },
    ] } });
    const out = await runBaseline(llm, rows, cands, "lightning");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].model, "lightning");
    assert.equal(calls[0].json, true);
    assert.deepEqual(out.predictions, [
      { row_id: "R01", vendor: "Apache", product: "Log4j2" },
      { row_id: "R04", vendor: null, product: null },
    ]);
    assert.equal(out.receipts.length, 1);
    assert.equal(out.receipts[0].requested_model, MODELS.lightning);
  });
  test("JSON after </think> is extracted; an unparseable reply leaves every row missing", async () => {
    assert.deepEqual(extractJson(null, '<think>{"x":1}</think>\n{"results":[]}'), { results: [] });
    assert.equal(extractJson(null, "no json here"), null);
    assert.equal(parseBaselineReply({ other: 1 }, rows), null);
    const { llm } = mockLlm({ text: "sorry" });
    const out = await runBaseline(llm, rows, cands);
    assert.deepEqual(out.predictions, []);
    assert.equal(out.receipts.length, 1);
    assert.match(out.notes?.join(" ") ?? "", /could not be parsed/);
  });
});

// ---------- wiring ----------
function fakeDeps(opts: { llm?: Llm | null; mode?: "live" | "sample" } = {}): Deps {
  return {
    mode: opts.mode ?? "live",
    clock: { now: () => new Date("2026-10-27T10:00:00Z") },
    llm: opts.llm === undefined ? mockLlm({ json: { results: [] } }).llm : opts.llm,
    queries: {
      inventory: async () => [], kevPairs: async () => [{ vendor: "Apache", product: "Log4j2" }, { vendor: "Microsoft", product: "Exchange Server" }],
      kevByProducts: async () => [], kevVerify: async () => [], epss: async () => [], epssVerify: async () => [],
      nvdCves: async () => [], nvdProduct: async () => [],
    },
    tracer: { run_id: "eval-run", file: "logs/trace-eval-run.jsonl", emit: () => {} },
    policy: { epss_this_cycle: 0.1, epss_this_cycle_internet: 0.05, sla_days: { patch_now: 7, this_cycle: 30, monitor_review: 90 }, rubric_auto_min: 7, max_critic_rounds: 2 },
  };
}
const fakeNormaliser = async () => ({
  parseSoftware: (raw: string) => ({ raw, vendor_hint: null, product_hint: raw, version: null, product_type: "unknown" as const, tokens: [] }),
  topCandidates: (_p: unknown, pairs: { vendor: string; product: string }[]) => pairs.map((p) => ({ ...p, family: p.product, score: 0.5, reason: "test" })),
  normaliserVote: (row: InventoryRow, _p: unknown, c: { vendor: string; product: string }[]) =>
    ({ row_id: row.row_id, juror: "normaliser" as const, vendor: /log4j/i.test(row.software) ? c[0].vendor : null, product: /log4j/i.test(row.software) ? c[0].product : null, confidence: 0.6 }),
});
const notFound = async (): Promise<never> => { throw Object.assign(new Error("Cannot find module"), { code: "ERR_MODULE_NOT_FOUND" }); };

describe("wiring", () => {
  const rows = [inv("R01", "log4j-core 2.14.1"), inv("R04", "Exchange Online")];
  test("normaliser arm: deterministic, no receipts", async () => {
    const ra = createResolveArm({ depsFor: () => fakeDeps(), load: { normaliser: fakeNormaliser } });
    const out = await ra("normaliser", rows);
    assert.deepEqual(out.predictions.map((p) => p.product), ["Log4j2", null]);
    assert.deepEqual(out.receipts, []);
  });
  test("baseline arm gets the union of candidates in one call", async () => {
    const m = mockLlm({ json: { results: [{ row_id: "R01", vendor: "Apache", product: "Log4j2" }] } });
    const ra = createResolveArm({ depsFor: () => fakeDeps({ llm: m.llm }), load: { normaliser: fakeNormaliser } });
    const out = await ra("baseline", rows);
    assert.equal(m.calls.length, 1);
    assert.equal(m.calls[0].model, "ultra");
    assert.match(m.calls[0].user, /2 in total/);
    assert.equal(out.predictions[0].product, "Log4j2");
  });
  test("model arms are unavailable in sample mode, or until the jury exposes voteWithModel", async () => {
    const sample = createResolveArm({ depsFor: () => fakeDeps({ llm: null, mode: "sample" }), load: { normaliser: fakeNormaliser } });
    await assert.rejects(sample("bolt", rows), (e: unknown) => e instanceof ArmUnavailableError && /sample mode/.test(e.message));
    const noJury = createResolveArm({ depsFor: () => fakeDeps(), load: { normaliser: fakeNormaliser, jury: notFound } });
    await assert.rejects(noJury("lightning", rows), /src\/agents\/jury\.ts is missing/);
    const noExport = createResolveArm({ depsFor: () => fakeDeps(), load: { normaliser: fakeNormaliser, jury: async () => ({}) } });
    await assert.rejects(noExport("bolt", rows), /exports no voteWithModel/);
  });
  test("single-model arm through the jury's voteWithModel", async () => {
    const seen: string[] = [];
    const jury = async () => ({
      voteWithModel: async (model: string, items: { row: InventoryRow }[]) => {
        seen.push(model);
        return { votes: items.map((i) => ({ row_id: i.row.row_id, juror: "bolt" as const, vendor: null, product: null, confidence: 1 })), receipts: [receipt(MODELS.bolt)] };
      },
    });
    const ra = createResolveArm({ depsFor: () => fakeDeps(), load: { normaliser: fakeNormaliser, jury } });
    const out = await ra("ultra", rows);
    assert.deepEqual(seen, ["ultra"]);
    assert.equal(out.predictions.every((p) => p.used_ultra), true);
    assert.equal(out.receipts.length, 1);
  });
  test("full arm maps the pipeline's lines; a missing pipeline is unavailable", async () => {
    const resolution = (row_id: string, status: Resolution["status"], product: string | null): Resolution => ({
      row_id, status, vendor: product ? "Apache" : null, product, family: null, version: null, product_type: "library", votes: [], adjudicated_by: "ultra", confidence: 1,
    });
    let req: unknown = null;
    const run = async () => ({
      run: async (r: unknown) => {
        req = r;
        return {
          run_id: "eval-run", mode: "live", status: "success", lines: [
            { row_id: "R01", resolution: resolution("R01", "matched", "Log4j2"), critic: null },
            { row_id: "R04", resolution: resolution("R04", "unresolved", null), critic: null },
          ], receipts: [receipt(MODELS.ultra)],
        } as unknown as RunResponse;
      },
    });
    const ra = createResolveArm({ depsFor: () => fakeDeps(), load: { run } });
    const out = await ra("full", rows);
    assert.deepEqual((req as { inventory: InventoryRow[] }).inventory.map((r) => r.row_id), ["R01", "R04"]);
    assert.equal(out.predictions[0].product, "Log4j2");
    assert.equal(out.predictions[1].abstained, true);
    assert.equal(out.predictions[0].used_ultra, true);
    const missing = createResolveArm({ depsFor: () => fakeDeps(), load: { run: notFound } });
    await assert.rejects(missing("full", rows), (e: unknown) => e instanceof ArmUnavailableError);
  });
  test("full arm: an ask_owner line abstains; a patch_now line whose version is unconfirmed is a prediction", async () => {
    const resolution = (row_id: string): Resolution => ({
      row_id, status: "matched", vendor: "Apache", product: "Log4j2", family: null, version: null, product_type: "library", votes: [], adjudicated_by: null, confidence: 1,
    });
    const versionQuestion = { row_id: "R01", verdict: "ask_owner" as const, reasons: ["name-only match"], rubric: { accuracy: 3, appropriateness: 2, actionability: 2, total: 7 }, round: 0 };
    const run = async () => ({
      run: async () => ({
        run_id: "eval-run", mode: "live", status: "success", receipts: [], lines: [
          { row_id: "R01", decision: "patch_now", resolution: resolution("R01"), critic: versionQuestion },
          { row_id: "R04", decision: "ask_owner", resolution: resolution("R04"), critic: { ...versionQuestion, row_id: "R04" } },
        ],
      }) as unknown as RunResponse,
    });
    const out = await createResolveArm({ depsFor: () => fakeDeps(), load: { run } })("full", rows);
    assert.equal(out.predictions[0].product, "Log4j2");
    assert.equal(out.predictions[0].abstained, undefined);
    assert.equal(out.predictions[1].abstained, true);
    assert.equal(out.predictions[1].product, null);
  });
});

// ---------- scripts ----------
function workspace() {
  const root = tmp();
  mkdirSync(path.join(root, "data", "eval"), { recursive: true });
  writeFileSync(path.join(root, "data", "eval", "test_rows.json"), JSON.stringify({ seed: "t", row_ids: ["R02", "R05"] }));
  const inbox = tmp();
  writeFileSync(path.join(inbox, "labels.csv"), SHEET);
  writeFileSync(path.join(inbox, "inventory.json"), JSON.stringify({ items: INVENTORY }));
  return { root, inbox };
}
function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, stdout: (s: string) => out.push(s), stderr: (s: string) => err.push(s) };
}

describe("scripts/eval.ts", () => {
  test("argument parsing", () => {
    const a = parseEvalArgs(["--labels", "x.csv"], {});
    assert.equal(a.set, "dev");
    assert.deepEqual(a.arms, ["full", "bolt", "lightning", "baseline", "normaliser"]);
    assert.equal(a.mode, "live");
    assert.equal(parseEvalArgs(["--labels", "x.csv"], { SAMPLE_MODE: "true" }).mode, "sample");
    assert.deepEqual(parseEvalArgs(["--labels", "x", "--arms", "full,bolt,full"], {}).arms, ["full", "bolt"]);
    assert.throws(() => parseEvalArgs(["--labels", "x", "--arms", "full,gpt"], {}), UsageError);
    assert.throws(() => parseEvalArgs(["--set", "all", "--labels", "x"], {}), /dev or test/);
    assert.throws(() => parseEvalArgs([], {}), /--labels/);
    assert.throws(() => parseEvalArgs(["--labels"], {}), /needs a value/);
  });
  test("inventory JSON shapes", () => {
    const rows = parseInventoryJson({ items: [{ row_id: "R1", software: "x", internet_facing: "Yes" }] });
    assert.equal(rows[0].internet_facing, true);
    assert.equal(rows[0].asset_name, "");
    assert.equal(parseInventoryJson([{ row_id: "R1", software: "x" }]).length, 1);
    assert.throws(() => parseInventoryJson([{ row_id: "R1" }]), /row_id and software/);
  });
  test("--set test without --final is refused before any file is read", async () => {
    const c = capture();
    let wired = false;
    const code = await evalMain(["--set", "test", "--labels", "/nonexistent/labels.csv"], {
      repoRoot: "/nonexistent", stdout: c.stdout, stderr: c.stderr, env: {}, wiring: async () => { wired = true; throw new Error("no"); },
    });
    assert.equal(code, 2);
    assert.equal(wired, false);
    assert.match(c.err.join("\n"), /sealed/);
  });
  test("a missing test-row list stops even a dev run", async () => {
    const { inbox } = workspace();
    const c = capture();
    const code = await evalMain(["--labels", path.join(inbox, "labels.csv")], { repoRoot: tmp(), stdout: c.stdout, stderr: c.stderr, env: {} });
    assert.equal(code, 2);
    assert.match(c.err.join("\n"), /sealed test-row list/);
  });
  test("dev run end to end: files written, stdout has only the summary", async () => {
    const { root, inbox } = workspace();
    const f = fakeArms({ full: perfect, normaliser: allNull });
    const c = capture();
    const code = await evalMain(
      ["--labels", path.join(inbox, "labels.csv"), "--inventory", path.join(inbox, "inventory.json"), "--arms", "full,normaliser,bolt"],
      { repoRoot: root, cwd: root, stdout: c.stdout, stderr: c.stderr, env: {}, now: () => new Date("2026-10-27T10:30:00Z"), wiring: async () => ({ resolveArm: f.resolveArm }) },
    );
    assert.equal(code, 0, c.err.join("\n"));
    for (const s of f.seen) assert.deepEqual(s.ids, ["R01", "R03", "R04", "R06"]);
    const files = readdirSync(path.join(root, "output")).sort();
    assert.deepEqual(files, ["eval-2026-10-27-103000-dev.json", "eval-2026-10-27-103000-dev.md"]);
    const stdout = c.out.join("\n");
    assert.match(stdout, /4 rows \(2 sealed test rows withheld\)/);
    assert.match(stdout, /Full system/);
    assert.doesNotMatch(stdout, /R0\d|Log4j2/); // no per-row output on stdout
    const json = JSON.parse(readFileSync(path.join(root, "output", files[0]), "utf8"));
    assert.equal(json.set, "dev");
    assert.equal(json.labels_source, "labels.csv");
    assert.equal(json.arms[2].status, "unavailable");
  });
  test("final test run: only the test rows, nothing per-row on stdout", async () => {
    const { root, inbox } = workspace();
    const f = fakeArms({ full: perfect });
    const c = capture();
    const code = await evalMain(
      ["--set", "test", "--final", "--labels", path.join(inbox, "labels.csv"), "--inventory", "labels", "--arms", "full"],
      { repoRoot: root, cwd: root, stdout: c.stdout, stderr: c.stderr, env: {}, now: () => new Date("2026-10-27T11:00:00Z"), wiring: async () => ({ resolveArm: f.resolveArm, loadKevPairs: async () => KEV_PAIRS }) },
    );
    assert.equal(code, 0, c.err.join("\n"));
    assert.deepEqual(f.seen[0].ids, ["R02", "R05"]);
    assert.doesNotMatch(c.out.join("\n"), /R02|R05|NetScaler|Windows/);
    assert.ok(existsSync(path.join(root, "output", "eval-2026-10-27-110000-test.md")));
  });
  test("final run: refused when the answer names cannot be checked against KEV, or a test answer is not a KEV name", async () => {
    const run = async (inbox: string, root: string, wiring: Partial<{ loadKevPairs: () => Promise<KevPair[]> }>) => {
      const f = fakeArms({ full: perfect });
      const c = capture();
      const code = await evalMain(
        ["--set", "test", "--final", "--labels", path.join(inbox, "labels.csv"), "--inventory", "labels", "--arms", "full"],
        { repoRoot: root, cwd: root, stdout: c.stdout, stderr: c.stderr, env: {}, wiring: async () => ({ resolveArm: f.resolveArm, ...wiring }) },
      );
      return { code, err: c.err.join("\n"), seen: f.seen, root };
    };
    const w = workspace();
    const noLoader = await run(w.inbox, w.root, {});
    assert.equal(noLoader.code, 2);
    assert.match(noLoader.err, /refusing the final run: the answer names cannot be checked against KEV \(no KEV loader is wired\)/);
    const down = await run(w.inbox, w.root, { loadKevPairs: async () => { throw new Error("Zetaris timeout"); } });
    assert.equal(down.code, 2);
    assert.match(down.err, /Zetaris timeout/);
    const empty = await run(w.inbox, w.root, { loadKevPairs: async () => [] });
    assert.equal(empty.code, 2);
    for (const r of [noLoader, down, empty]) assert.equal(r.seen.length, 0);
    assert.equal(existsSync(path.join(w.root, "output")), false);

    // R05's answer is not a KEV name: the final run stops before any arm, and names the row and the reason.
    const bad = workspace();
    writeFileSync(path.join(bad.inbox, "labels.csv"), SHEET.replace("Microsoft,Windows ,unsure", "Microsoft,Windows Server (on-prem),unsure"));
    const r = await run(bad.inbox, bad.root, { loadKevPairs: async () => KEV_PAIRS });
    assert.equal(r.code, 1);
    assert.match(r.err, /no usable agreed answer: R05 \(line 6: kev_products 'Windows Server \(on-prem\)' is not a KEV product of 'Microsoft'/);
    assert.equal(r.seen.length, 0);
  });
  test("dev run: answer names are checked against KEV; a name not in KEV is not scored and is listed", async () => {
    const { root, inbox } = workspace();
    writeFileSync(path.join(inbox, "labels.csv"), SHEET.replace("Apache,Log4j2,", "Apache,Log4j2 (bundled),"));
    const f = fakeArms({ normaliser: allNull });
    const c = capture();
    const code = await evalMain(
      ["--labels", path.join(inbox, "labels.csv"), "--inventory", path.join(inbox, "inventory.json"), "--arms", "normaliser"],
      { repoRoot: root, cwd: root, stdout: c.stdout, stderr: c.stderr, env: {}, now: () => new Date("2026-10-27T10:30:00Z"), wiring: async () => ({ resolveArm: f.resolveArm, loadKevPairs: async () => KEV_PAIRS }) },
    );
    assert.equal(code, 0, c.err.join("\n"));
    assert.deepEqual(f.seen[0].ids, ["R03", "R04", "R06"]); // R01 left unlabelled
    assert.match(c.err.join("\n"), /1 answer-sheet issue; unusable rows are left unlabelled/);
    assert.doesNotMatch(c.out.join("\n"), /Log4j2/);
    const json = JSON.parse(readFileSync(path.join(root, "output", "eval-2026-10-27-103000-dev.json"), "utf8"));
    assert.deepEqual(json.unlabelled_rows, ["R01"]);
    assert.match(json.label_issues[0].problem, /'Log4j2 \(bundled\)' is not a KEV product of 'Apache'/);
    // Without a KEV loader a dev run still runs, with a warning.
    const c2 = capture();
    const code2 = await evalMain(["--labels", path.join(inbox, "labels.csv"), "--inventory", "labels", "--arms", "normaliser"], { repoRoot: root, cwd: root, stdout: c2.stdout, stderr: c2.stderr, env: {}, wiring: async () => ({ resolveArm: f.resolveArm }) });
    assert.equal(code2, 0);
    assert.match(c2.err.join("\n"), /warning: the answer names were not checked against KEV \(no KEV loader is wired\)/);
  });
  test("a labels file inside the repository triggers a warning", async () => {
    const { root, inbox } = workspace();
    writeFileSync(path.join(root, "labels.csv"), readFileSync(path.join(inbox, "labels.csv")));
    const f = fakeArms({ normaliser: allNull });
    const c = capture();
    await evalMain(["--labels", "labels.csv", "--inventory", "labels", "--arms", "normaliser"], { repoRoot: root, cwd: root, stdout: c.stdout, stderr: c.stderr, env: {}, wiring: async () => ({ resolveArm: f.resolveArm }) });
    assert.match(c.err.join("\n"), /inside the repository/);
  });
});

describe("scripts/compare-answers.ts", () => {
  test("argument parsing", () => {
    assert.deepEqual(parseCompareArgs(["a.csv", "b.csv", "--names", "X,Y"]).names, ["X", "Y"]);
    assert.throws(() => parseCompareArgs(["a.csv"]), /exactly two/);
    assert.throws(() => parseCompareArgs(["a.csv", "b.csv", "--names", "X"]), /two names/);
  });
  test("prints the comparison, restricted to the test rows when asked; --out writes a file", async () => {
    const { root, inbox } = workspace();
    writeFileSync(path.join(inbox, "b.csv"), SHEET.replace("Apache,Log4j2", "Apache,Log4j").replace("Fortinet,None", "Fortinet,FortiClient EMS"));
    const c = capture();
    assert.equal(await compareMain([path.join(inbox, "labels.csv"), path.join(inbox, "b.csv"), "--names", "P,Q"], { repoRoot: root, stdout: c.stdout, stderr: c.stderr }), 0);
    const md = c.out.join("\n");
    assert.match(md, /disagree: 2\*\*/);
    assert.match(md, /\| R01 \|/);
    assert.match(md, /\| R06 \|/);

    const c2 = capture();
    const outFile = path.join(inbox, "cmp.md");
    assert.equal(await compareMain([path.join(inbox, "labels.csv"), path.join(inbox, "b.csv"), "--test-rows", "data/eval/test_rows.json", "--out", outFile], { repoRoot: root, cwd: inbox, stdout: c2.stdout, stderr: c2.stderr }), 0);
    const written = readFileSync(outFile, "utf8");
    assert.match(written, /Rows in both sheets:\*\* 2/);
    assert.match(written, /disagree: 0/);
    assert.match(c2.out.join("\n"), /0 disagreement/);
  });
  test("a sheet without the required columns fails cleanly", async () => {
    const { inbox } = workspace();
    writeFileSync(path.join(inbox, "bad.csv"), "id,answer\nR01,Apache Log4j2\n");
    const c = capture();
    assert.equal(await compareMain([path.join(inbox, "labels.csv"), path.join(inbox, "bad.csv")], { stdout: c.stdout, stderr: c.stderr }), 1);
    assert.match(c.err.join("\n"), /missing column/);
  });
});

// ---------- unlabelled development runs (no answer sheet yet) ----------
describe("unlabelled development runs", () => {
  const families = (p: KevPair): string[] => {
    const v = p.vendor.trim().toLowerCase();
    const pr = p.product.trim().toLowerCase();
    if (v === "citrix" && /netscaler|application delivery controller/.test(pr)) return ["citrix:netscaler-adc-gateway"];
    if (v === "microsoft" && /^exchange/.test(pr)) return ["microsoft:exchange-server"];
    return [`${v}:${pr.replace(/\s+/g, "-")}`];
  };
  const row = (id: string, vendor: string | null, product: string | null, extra: Partial<UnlabelledRow> = {}): UnlabelledRow =>
    ({ row_id: id, vendor, product, abstained: false, missing: false, used_ultra: false, ...extra });

  test("dev rows: the inventory minus the sealed test rows, first row per id", () => {
    const r = devRowsOf([inv("R01", "a"), inv("r02", "b"), inv("R03", "c"), inv("R01", "dup")], ["R02"]);
    assert.deepEqual(r.rows.map((x) => x.software), ["a", "c"]);
    assert.equal(r.sealed_excluded, 1);
  });
  test("sameAnswer: both none agree; any spelling of one family agrees; abstentions are not compared", () => {
    assert.equal(sameAnswer(row("R1", null, null), row("R1", null, null)), true);
    assert.equal(sameAnswer(row("R1", "Citrix", "NetScaler"), row("R1", "citrix", "netscaler ")), true);
    assert.equal(sameAnswer(row("R1", "Citrix", "NetScaler"), row("R1", "Citrix", "NetScaler ADC and Gateway")), false);
    assert.equal(sameAnswer(row("R1", "Citrix", "NetScaler"), row("R1", "Citrix", "NetScaler ADC and Gateway"), families), true);
    assert.equal(sameAnswer(row("R1", "Microsoft", "Exchange Server"), row("R1", null, null), families), false);
    assert.equal(sameAnswer(row("R1", "Microsoft", "Exchange Server"), row("R1", null, null, { abstained: true })), null);
    assert.equal(sameAnswer(row("R1", null, null, { missing: true }), row("R1", null, null)), null);
  });
  test("summary counts what each arm named, Ultra rows and calls; a vendor without a product is no KEV product", () => {
    const out: ArmOutput = {
      predictions: [
        { row_id: "R01", vendor: "Apache", product: "Log4j2", used_ultra: true },
        { row_id: "R03", vendor: "Microsoft", product: null },
        { row_id: "R04", vendor: null, product: null, abstained: true },
        { row_id: "R99", vendor: null, product: null },
      ],
      receipts: [receipt(MODELS.bolt), receipt(MODELS.ultra, 50, 10, "error")],
      run: { run_id: "x", status: "success", decisions: {}, owner_questions: 0, timing_ms: {}, trace_file: "", ultra_reviewed_rows: ["R01", "R03", "R50"] },
    };
    const s = summariseUnlabelledArm(["R01", "R03", "R04", "R06"], out, 1234);
    assert.deepEqual([s.metrics.named_kev, s.metrics.no_kev, s.metrics.abstained, s.metrics.missing], [1, 1, 1, 1]);
    assert.equal(s.metrics.ultra_rows, 1);
    assert.equal(s.metrics.ultra_share, 0.25);
    assert.equal(s.metrics.ultra_reviewed, 2); // R50 was not asked
    assert.equal(s.metrics.calls, 2);
    assert.equal(s.metrics.ultra_calls, 1);
    assert.equal(s.metrics.call_errors, 1);
    assert.equal(s.metrics.tokens, 180);
    assert.deepEqual(s.extra_predictions, ["R99"]);
    assert.deepEqual(callStats([]), { calls: 0, calls_by_model: {}, ultra_calls: 0, call_errors: 0, prompt_tokens: 0, completion_tokens: 0, tokens: 0 });
  });
  test("run: test rows never reach an arm, arms run one at a time, agreement with the full system, failures recorded", async () => {
    const answers: Record<string, [string | null, string | null]> = {
      R01: ["Apache", "Log4j2"], R03: [null, null], R04: ["Microsoft", "Exchange Server"], R06: ["Fortinet", "FortiClient EMS"],
    };
    const f = fakeArms({
      full: (rows) => ({
        predictions: rows.map((r) => r.row_id === "R06"
          ? { row_id: r.row_id, vendor: null, product: null, abstained: true, decision: "ask_owner" }
          : { row_id: r.row_id, vendor: answers[r.row_id][0], product: answers[r.row_id][1], decision: answers[r.row_id][1] ? "patch_now" : "monitor", used_ultra: r.row_id === "R04" }),
        receipts: [receipt(MODELS.bolt), receipt(MODELS.ultra)],
        run: { run_id: "eval-full", status: "success", decisions: { patch_now: 2, this_cycle: 0, monitor: 1, ask_owner: 1 }, owner_questions: 1, timing_ms: { jury: 1000 }, trace_file: "t", ultra_reviewed_rows: ["R04", "R06"] },
      }),
      bolt: (rows) => ({ predictions: rows.map((r) => ({ row_id: r.row_id, vendor: answers[r.row_id][0], product: answers[r.row_id][1] })), receipts: [receipt(MODELS.bolt)] }),
      normaliser: allNull,
      lightning: () => { throw new Error("boom"); },
    });
    let t = 0;
    const r = await runUnlabelledEvaluation({
      arms: ["full", "bolt", "normaliser", "lightning", "ultra"], inventory: INVENTORY, testIds: ["R02", "R05"], resolveArm: f.resolveArm, families,
      now: () => (t += 100), clock: () => new Date("2026-10-27T02:00:00Z"),
    });
    for (const s of f.seen) assert.deepEqual(s.ids, ["R01", "R03", "R04", "R06"]);
    assert.equal(f.maxActive(), 1);
    assert.equal(r.kind, "unlabelled");
    assert.equal(r.rows_evaluated, 4);
    assert.equal(r.sealed_rows_excluded, 2);
    const [full, bolt, norm, light, ultra] = r.arms;
    assert.equal(full.metrics?.agree_with_full, null);
    assert.equal(full.metrics?.ultra_reviewed, 2);
    assert.equal(full.run?.decisions.patch_now, 2);
    assert.equal(full.rows.find((x) => x.row_id === "R06")?.decision, "ask_owner");
    assert.deepEqual(bolt.metrics?.agree_with_full, { compared: 3, agree: 3 }); // R06 left to the owner by full: not compared
    assert.deepEqual(norm.metrics?.agree_with_full, { compared: 3, agree: 1 });
    assert.deepEqual(norm.disagree_with_full, ["R01", "R04"]);
    assert.equal(light.status, "error");
    assert.equal(ultra.status, "unavailable");
    assert.equal(r.generated_at, "2026-10-27T02:00:00.000Z");

    const md = renderUnlabelledMarkdown(r);
    assert.match(md, /no accuracy/i);
    assert.match(md, /\| 2 \| 0 \| 1 \| 1 \| 1 \| success \| eval-full \|/);
    assert.match(md, /\| R01 \| Normaliser alone \(no model\) \| no KEV product \| Apache \/ Log4j2 \|/);
    const table = renderUnlabelledSummaryTable(r);
    assert.match(table, /Bolt alone \| 3 \| 1 \| 0 \| 3\/3 \(100\.0%\)/);
    assert.match(table, /Lightning alone \| not run: boom/);
    assert.doesNotMatch(table, /R0\d|Log4j2/);
  });
  test("without a full arm, no agreement is reported; with no dev rows the run stops", async () => {
    const r = await runUnlabelledEvaluation({ arms: ["normaliser"], inventory: INVENTORY, testIds: [], resolveArm: fakeArms({ normaliser: allNull }).resolveArm });
    assert.equal(r.arms[0].metrics?.agree_with_full, null);
    assert.equal(r.rows_evaluated, 6);
    await assert.rejects(runUnlabelledEvaluation({ arms: ["normaliser"], inventory: [inv("R01", "x")], testIds: ["R01"], resolveArm: fakeArms({}).resolveArm }), /no dev rows/);
  });
  test("ultraRowsFromTrace: adjudications, Ultra re-decides, critiques and same-product checks; Lightning re-decides and bad lines ignored", () => {
    const lines = [
      { agent: "jury.adjudicate", action: "ultra_adjudication", details: { decisions: [{ row_id: "R01" }, { row_id: "R43" }] } },
      { agent: "resolver.retry.lightning", action: "redecide", details: { decisions: [{ row_id: "R20" }] } },
      { agent: "resolver.retry.ultra", action: "redecide", details: { decisions: [{ row_id: "R71" }] } },
      { agent: "critic", action: "critic_round", details: { sent_back: ["R07"], ultra_critiques: ["R12", "R01"] } },
      { agent: "critic.match_check", action: "same_product_check", details: { row_id: "R31" } },
    ].map((e) => JSON.stringify(e));
    assert.deepEqual(ultraRowsFromTrace([...lines, "not json", ""].join("\n")), ["R01", "R12", "R31", "R43", "R71"]);
  });
  test("full arm wiring: decisions, owner questions and the Ultra rows from the run's trace", async () => {
    const res = (row_id: string): Resolution => ({ row_id, status: "matched", vendor: "Apache", product: "Log4j2", family: null, version: null, product_type: "library", votes: [], adjudicated_by: null, confidence: 1 });
    const run = async () => ({
      run: async () => ({
        run_id: "eval-run", mode: "live", status: "success", receipts: [], trace_file: "logs/trace-eval-run.jsonl",
        summary: { patch_now: 1, this_cycle: 0, monitor: 0, ask_owner: 1 }, timing_ms: { jury: 5 }, owner_questions: [{}, {}],
        lines: [{ row_id: "R01", decision: "patch_now", resolution: res("R01"), critic: null }, { row_id: "R04", decision: "ask_owner", resolution: res("R04"), critic: null }],
      }) as unknown as RunResponse,
    });
    let asked = "";
    const out = await createResolveArm({ depsFor: () => fakeDeps(), load: { run }, readTrace: (f) => { asked = f ?? ""; return ["R04"]; } })("full", [inv("R01", "x"), inv("R04", "y")]);
    assert.equal(asked, "logs/trace-eval-run.jsonl");
    assert.deepEqual(out.run?.decisions, { patch_now: 1, this_cycle: 0, monitor: 0, ask_owner: 1 });
    assert.equal(out.run?.owner_questions, 2);
    assert.deepEqual(out.run?.ultra_reviewed_rows, ["R04"]);
    assert.deepEqual(out.predictions.map((p) => p.decision), ["patch_now", "ask_owner"]);
    // An unreadable trace leaves the count unknown, never zero.
    const out2 = await createResolveArm({ depsFor: () => fakeDeps(), load: { run } })("full", [inv("R01", "x")]);
    assert.equal(out2.run?.ultra_reviewed_rows, null);
  });
  test("CLI --labels none: dev rows only, files written, stdout has only the summary", async () => {
    assert.equal(isUnlabelled(parseEvalArgs(["--labels", "none"], {})), true);
    assert.equal(isUnlabelled(parseEvalArgs(["--labels", "x.csv"], {})), false);
    const { root, inbox } = workspace();
    const f = fakeArms({ full: (rows) => ({ predictions: rows.map((r) => ({ row_id: r.row_id, vendor: null, product: null })), receipts: [] }), normaliser: allNull });
    const c = capture();
    const code = await evalMain(
      ["--labels", "none", "--inventory", path.join(inbox, "inventory.json"), "--arms", "full,normaliser"],
      { repoRoot: root, cwd: root, stdout: c.stdout, stderr: c.stderr, env: {}, now: () => new Date("2026-10-27T02:00:00Z"), wiring: async () => ({ resolveArm: f.resolveArm }) },
    );
    assert.equal(code, 0, c.err.join("\n"));
    for (const s of f.seen) assert.deepEqual(s.ids, ["R01", "R03", "R04", "R06"]);
    assert.deepEqual(readdirSync(path.join(root, "output")).sort(), ["eval-2026-10-27-020000-dev-unlabelled.json", "eval-2026-10-27-020000-dev-unlabelled.md"]);
    assert.match(c.out.join("\n"), /4 rows \(2 sealed test rows withheld\); no accuracy/);
    assert.doesNotMatch(c.out.join("\n"), /R0\d/);
    assert.match(c.err.join("\n"), /nothing is scored/);
    const json = JSON.parse(readFileSync(path.join(root, "output", "eval-2026-10-27-020000-dev-unlabelled.json"), "utf8"));
    assert.equal(json.kind, "unlabelled");
    assert.deepEqual(json.arms[1].metrics.agree_with_full, { compared: 4, agree: 4 });
  });
  test("CLI --labels none is refused for the test set and with the answer sheet as inventory", async () => {
    const { root } = workspace();
    const f = fakeArms({ full: allNull });
    for (const argv of [["--set", "test", "--final", "--labels", "none"], ["--labels", "none", "--inventory", "labels"]]) {
      const c = capture();
      const code = await evalMain(argv, { repoRoot: root, cwd: root, stdout: c.stdout, stderr: c.stderr, env: {}, wiring: async () => ({ resolveArm: f.resolveArm }) });
      assert.equal(code, 2, argv.join(" "));
    }
    assert.equal(f.seen.length, 0);
    assert.equal(existsSync(path.join(root, "output")), false);
  });
});
