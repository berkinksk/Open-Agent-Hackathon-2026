// Sample mode end to end on the shipped snapshot (data/sample/snapshot.json): a judge's own rows run offline through
// the real pipeline (normaliser, critic, policy, verifier, World Model, report) with no model and no socket.
// Independent observers (diagnostics_channel) watch for any client socket or HTTP request during the run.
// The sealed test rows are never run here: inline rows and rows outside data/eval/test_rows.json only.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import dc from "node:diagnostics_channel";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Deps, InventoryRow, Queries, RunResponse } from "../src/contracts.ts";
import { REPO_ROOT } from "../src/config.ts";
import { makeDeps } from "../src/deps.ts";
import { run, runWith } from "../src/run.ts";
import { familyOf, normaliserVote, parseSoftware, topCandidates, voteKind } from "../src/resolve/normalise.ts";
import { networkGuardActive, withNetworkGuard } from "../src/sample/guard.ts";
import { loadSnapshot } from "../src/sample/snapshot.ts";

const TMP = join(REPO_ROOT, "output", ".test-tmp", "sample-run");
const OUT = join(REPO_ROOT, "output");
const LOGS = join(REPO_ROOT, "logs");
const SNAP = loadSnapshot();
const SEALED = new Set<string>((JSON.parse(readFileSync(join(REPO_ROOT, "data", "eval", "test_rows.json"), "utf8")) as { row_ids: string[] }).row_ids);

/** Rows a judge might type: none of them is in the bundled inventory; Zimbra's vendor is not among its vendors. */
const JUDGE_ROWS: Partial<InventoryRow>[] = [
  { row_id: "J1", asset_id: "edge-fw-01", asset_name: "edge-fw-01", asset_type: "firewall", internet_facing: true, software: "Fortinet FortiOS 7.2.4 (edge firewall)" },
  { row_id: "J2", asset_id: "mail-01", asset_name: "mail-01", asset_type: "server", internet_facing: true, software: "Zimbra Collaboration Suite 8.8.15" },
  { row_id: "J3", asset_id: "web-02", asset_name: "web-02", asset_type: "server", internet_facing: true, software: "Apache Tomcat 9.0.80" },
  { row_id: "J4", asset_id: "laptop-07", asset_name: "laptop-07", asset_type: "laptop", internet_facing: false, software: "Exchange Online (M365 tenant) mailbox" },
];

const CHANNELS = ["net.client.socket", "http.client.request.start", "undici:request:create", "undici:client:beforeConnect"];

/** Count every client socket / HTTP request any code starts while `fn` runs (independent of the guard). */
async function observed<T>(fn: () => Promise<T>): Promise<{ value: T; seen: string[] }> {
  const seen: string[] = [];
  const subs = CHANNELS.map((name) => { const f = () => { seen.push(name); }; dc.subscribe(name, f); return [name, f] as const; });
  try {
    return { value: await fn(), seen };
  } finally {
    for (const [name, f] of subs) dc.unsubscribe(name, f);
  }
}

function sampleDeps(runId: string): Deps {
  mkdirSync(TMP, { recursive: true });
  return makeDeps({ mode: "sample", runId }, { env: {}, logDir: TMP, stdout: false });
}

function cleanRun(id: string): void {
  for (const f of [join(OUT, `run-${id}.json`), join(OUT, `report-${id}.html`), join(OUT, "world", ".world", `${id}.json`), join(LOGS, `trace-${id}.jsonl`), join(LOGS, `audit-${id}.jsonl`)]) {
    rmSync(f, { force: true });
  }
}

const strip = (r: RunResponse) => r.lines.map((l) => ({
  row: l.row_id, decision: l.decision, target: l.target_date, res: [l.resolution.status, l.resolution.vendor, l.resolution.product],
  kev: l.kev?.cves.map((c) => c.cve_id) ?? null, epss: l.epss?.max ?? null, verified: l.verified,
  evidence: l.evidence.filter((e) => e.source !== "world_model").map((e) => `${e.source}|${e.field}|${e.value}|${e.live}`),
  why: l.why,
}));

test("a judge's own rows run offline through run(): no model, no socket, real KEV and EPSS facts from the snapshot, stamped sample", async () => {
  const id = `test-sample-judge-${process.pid}`;
  const deps = sampleDeps(id);
  assert.equal(deps.mode, "sample");
  assert.equal(deps.llm, null);
  try {
    const { value: res, seen } = await observed(() => run({ run_id: id, inventory: JUDGE_ROWS as InventoryRow[] }, deps));
    assert.deepEqual(seen, [], `no client socket or HTTP request may start in a sample run (saw ${seen.join(", ")})`);
    assert.equal(res.mode, "sample");
    assert.equal(res.status, "success");
    assert.equal(res.receipts.length, 0, "no model call");
    assert.equal(res.lines.length, JUDGE_ROWS.length);
    assert.equal(networkGuardActive(), false, "the guard comes off after the run");

    const snapSrc = res.manifest.sources.find((s) => s.name === "Sample snapshot");
    assert.equal(snapSrc?.as_of, SNAP.captured_at.slice(0, 10), "stamped with the snapshot date");
    assert.equal(snapSrc?.live, false);
    assert.ok(res.manifest.sources.every((s) => s.live === false), "nothing in a sample run is labelled live");
    assert.equal(res.manifest.sources.find((s) => s.name === "CISA KEV")?.as_of, SNAP.sources.kev.catalog_version);

    const by = new Map(res.lines.map((l) => [l.row_id, l]));
    for (const rid of ["J1", "J2", "J3"]) {
      const l = by.get(rid)!;
      assert.equal(l.resolution.status, "matched", `${rid} resolves deterministically`);
      assert.ok((l.kev?.cves.length ?? 0) > 0, `${rid} cites KEV CVEs from the snapshot`);
      assert.notEqual(l.decision, "monitor", `${rid} is KEV-listed: never relaxed to monitor without proof`);
      const kevEv = l.evidence.filter((e) => e.source === "zetaris:kev");
      assert.ok(kevEv.length > 0 && kevEv.every((e) => e.live === false), `${rid} KEV evidence is labelled not live`);
      for (const c of l.kev!.cves) assert.ok(SNAP.kev_entries.some((e) => e.cve_id === c.cve_id && e.due_date === c.due_date), `${c.cve_id} comes from the snapshot as captured`);
    }
    assert.equal(by.get("J2")!.resolution.vendor, "Synacor", "a vendor outside the bundled inventory still resolves offline (full KEV catalogue)");
    assert.notEqual(by.get("J4")!.resolution.product?.trim(), "Exchange Server", "the cloud look-alike is never matched to the on-prem server");
    for (const l of res.lines) if (l.decision === "ask_owner") assert.ok(res.owner_questions.some((q) => q.row_id === l.row_id || (q as { row_ids?: string[] }).row_ids?.includes(l.row_id)), `${l.row_id} has an owner question`);

    const trace = readFileSync(deps.tracer.file, "utf8").trim().split("\n").map((x) => JSON.parse(x) as { agent: string; action: string; status: string; model?: string });
    assert.ok(trace.some((e) => e.agent === "network_guard" && e.action === "installed"));
    assert.ok(trace.some((e) => e.agent === "network_guard" && e.action === "sample_run_checked" && e.status === "ok"));
    assert.ok(trace.some((e) => e.agent === "sample_store" && e.action === "snapshot_loaded"));
    assert.ok(trace.some((e) => e.agent === "verifier" && e.action === "recheck"), "the verifier still runs, against the snapshot");
    assert.ok(trace.some((e) => e.agent === "world_model" && e.action === "explain_audit"), "the World Model still runs");
    assert.ok(trace.some((e) => e.agent === "resolver_jury" && e.action === "deterministic_vote"), "the jury is the deterministic normaliser vote");
    assert.equal(trace.filter((e) => e.model).length, 0, "no event names a model");
    // the NVD counts never claim a live read in a run with no network (snapshot misses are errors, not live calls)
    const summary = trace.find((e) => e.action === "agents_summary") as unknown as { details: { nvd: Record<string, unknown> } };
    assert.equal(summary.details.nvd.live_reads, 0);
    assert.ok(!("live_calls" in summary.details.nvd));
    assert.ok(Object.keys(summary.details.nvd.states as object).length > 0, "NVD was consulted (from the snapshot)");
    assert.ok(existsSync(join(OUT, `report-${id}.html`)));
    assert.match(readFileSync(join(OUT, `report-${id}.html`), "utf8"), /SAMPLE MODE/);
  } finally {
    cleanRun(id);
  }
});

/**
 * Rows for products KEV lists under the vendor's own name ("OpenSSL / OpenSSL", "Samba / Samba") or under several
 * spellings of one product (Jenkins core and its CLI; Exim and its "Mail Transfer Agent (MTA)"; GitLab and
 * "GitLab CE/EE"; "PHP" and "PHP Group"). Each expected CVE is one the snapshot's KEV lists for that product.
 */
const EPONYMOUS_ROWS: { row: Partial<InventoryRow>; cves: string[] }[] = [
  { row: { row_id: "K1", asset_id: "web-01", asset_name: "web-01", asset_type: "server", internet_facing: true, software: "OpenSSL 1.0.1f" }, cves: ["CVE-2014-0160"] },
  { row: { row_id: "K2", asset_id: "nas-01", asset_name: "nas-01", asset_type: "server", internet_facing: false, software: "Samba 4.5.9" }, cves: ["CVE-2017-7494"] },
  { row: { row_id: "K3", asset_id: "lnx-01", asset_name: "lnx-01", asset_type: "server", internet_facing: false, software: "Sudo 1.8.31" }, cves: ["CVE-2021-3156"] },
  { row: { row_id: "K4", asset_id: "ci-01", asset_name: "ci-01", asset_type: "server", internet_facing: true, software: "Jenkins 2.440" }, cves: ["CVE-2017-1000353", "CVE-2024-23897"] },
  { row: { row_id: "K5", asset_id: "mx-01", asset_name: "mx-01", asset_type: "server", internet_facing: true, software: "Exim 4.92" }, cves: ["CVE-2018-6789", "CVE-2019-10149"] },
  { row: { row_id: "K6", asset_id: "laptop-03", asset_name: "laptop-03", asset_type: "laptop", internet_facing: false, software: "Notepad++ 8.6.2" }, cves: ["CVE-2025-15556"] },
  { row: { row_id: "K7", asset_id: "git-01", asset_name: "git-01", asset_type: "server", internet_facing: true, software: "GitLab 16.0" }, cves: ["CVE-2021-22175", "CVE-2023-7028"] },
  { row: { row_id: "K8", asset_id: "laptop-04", asset_name: "laptop-04", asset_type: "laptop", internet_facing: false, software: "7-Zip 23.01" }, cves: ["CVE-2025-0411"] },
  { row: { row_id: "K9", asset_id: "web-03", asset_name: "web-03", asset_type: "server", internet_facing: true, software: "PHP 8.1.2" }, cves: ["CVE-2012-1823", "CVE-2024-4577"] },
];

test("vendor-named KEV products resolve offline: never monitor or 'no KEV product' (fail-closed), with every spelling's CVEs", async () => {
  for (const { cves } of EPONYMOUS_ROWS) for (const c of cves) assert.ok(SNAP.kev_entries.some((e) => e.cve_id === c), `${c} is in the snapshot's KEV`);
  const control: Partial<InventoryRow> = { row_id: "K0", asset_id: "laptop-05", asset_name: "laptop-05", asset_type: "laptop", internet_facing: false, software: "Microsoft Teams" };
  const id = `test-sample-eponymous-${process.pid}`;
  const rows = [...EPONYMOUS_ROWS.map((x) => x.row), control] as InventoryRow[];
  const res = await withNetworkGuard(() => runWith({ run_id: id, inventory: rows }, sampleDeps(id), { outputDir: null, logsDir: null }));
  assert.equal(res.mode, "sample");
  assert.equal(res.status, "success");
  assert.equal(res.receipts.length, 0, "no model call");
  const by = new Map(res.lines.map((l) => [l.row_id, l]));
  for (const { row, cves } of EPONYMOUS_ROWS) {
    const l = by.get(row.row_id!)!;
    const tag = `${row.row_id} "${row.software}"`;
    assert.equal(l.resolution.status, "matched", `${tag} resolves deterministically`);
    assert.notEqual(l.decision, "monitor", `${tag} is KEV-listed: never relaxed to monitor without proof`);
    assert.ok(["patch_now", "ask_owner"].includes(l.decision), `${tag}: ${l.decision}`);
    const cited = l.kev?.cves.map((c) => c.cve_id) ?? [];
    // every spelling's CVEs reach the line: cited (the confirmed ones and the ones not version-checked), or named in the
    // evidence as not affected (NVD places the version outside its range)
    const outside = l.evidence.find((e) => e.field === "kev_cves_version_not_affected")?.value ?? "";
    const unchecked = l.evidence.find((e) => e.field === "kev_cves_not_version_checked")?.value ?? "";
    for (const c of cves) assert.ok(cited.includes(c) || outside.includes(c), `${tag} cites ${c}, or names it as not affected (cited: ${cited.join(", ")}; ${outside})`);
    if (row.row_id === "K9") {
      // PHP 8.1.2: NVD places it inside CVE-2024-4577's range, so the line leads with that CVE; the 2012 CGI flaw has no
      // NVD record in the snapshot (not version-checked), so it stays cited and counts toward the due date (fail-closed)
      assert.deepEqual(cited, ["CVE-2024-4577", "CVE-2012-1823"]);
      assert.match(unchecked, /counted fail-closed.*CVE-2012-1823/);
      assert.equal(l.kev?.earliest_due, SNAP.kev_entries.find((e) => e.cve_id === "CVE-2012-1823")?.due_date);
      assert.match(l.why, /^NVD places (PHP )?PHP 8\.1\.2 inside the affected range of CVE-2024-4577, .*1 other cited KEV CVE is not version-checked, counted fail-closed/);
    }
    assert.doesNotMatch(l.why, /no CISA KEV product/i, `${tag} never claims KEV lists nothing`);
    const vote = l.resolution.votes.find((v) => v.juror === "normaliser");
    assert.ok(vote?.vendor && vote.product, `${tag}: the normaliser names the KEV product`);
    if (l.decision === "ask_owner") assert.ok(res.owner_questions.some((q) => q.row_id === l.row_id), `${tag} has an owner question`);
  }
  const k0 = by.get("K0")!;
  assert.equal(k0.resolution.status, "no_match", "control: software KEV does not list stays a confident no-match");
  assert.equal(k0.decision, "monitor");
});

/**
 * Look-alikes of vendor-named KEV products, none of which KEV lists: a one-letter neighbour (OpenSSH vs OpenSSL), other
 * products built on the brand's name, and another vendor's product of the same name. None may be shown as the KEV
 * product, in a resolution, a cited CVE, the "why" or an owner question.
 */
const LOOKALIKE_ROWS: { row: Partial<InventoryRow>; kevName: RegExp; cves: string[] }[] = [
  { row: { row_id: "N1", software: "OpenSSH 9.6p1", asset_type: "server", internet_facing: true }, kevName: /\bOpenSSL\b/, cves: ["CVE-2014-0160"] },
  { row: { row_id: "N2", software: "OpenSSH for Windows 9.5", asset_type: "server" }, kevName: /\bOpenSSL\b/, cves: ["CVE-2014-0160"] },
  { row: { row_id: "N3", software: "GitLab Runner 16.0", asset_type: "server" }, kevName: /\bIs GitLab\b/, cves: ["CVE-2021-22205"] },
  { row: { row_id: "N4", software: "PHP Composer 2.6", asset_type: "server" }, kevName: /\bIs PHP\b/, cves: ["CVE-2024-4577"] },
  { row: { row_id: "N5", software: "jQuery UI 1.12.1", asset_type: "server" }, kevName: /\bIs JQuery\b/i, cves: ["CVE-2020-11023"] },
  { row: { row_id: "N6", software: "jQuery Migrate 3.4", asset_type: "server" }, kevName: /\bIs JQuery\b/i, cves: ["CVE-2020-11023"] },
  { row: { row_id: "N7", software: "Git LFS 3.4", asset_type: "laptop" }, kevName: /\bIs Git\b/, cves: [] },
  { row: { row_id: "N8", software: "Sudo for Windows", asset_type: "laptop" }, kevName: /\bIs Sudo\b/, cves: ["CVE-2021-3156"] },
  { row: { row_id: "N9", software: "sudo-rs 0.2", asset_type: "server" }, kevName: /\bIs Sudo\b/i, cves: ["CVE-2021-3156"] },
  { row: { row_id: "N10", software: "Jenkins X 3.10", asset_type: "server" }, kevName: /\bIs Jenkins\b/, cves: ["CVE-2024-23897"] },
  { row: { row_id: "N11", software: "ownCloud desktop client 4.0", asset_type: "laptop" }, kevName: /\bIs ownCloud\b/, cves: [] },
  // the same look-alikes with the extra words in a bracketed note (review round 3); before the fix each was matched to the
  // brand, cited its CVEs and asked "Is GitLab 16.0 ... affected by ...?" or "Which Sudo version runs on ...?"
  { row: { row_id: "N12", software: "GitLab 16.0 (Runner)", asset_type: "server" }, kevName: /\b(?:Is|Which) GitLab\b/, cves: ["CVE-2021-22205", "CVE-2023-7028"] },
  { row: { row_id: "N13", software: "jQuery 1.12.1 (UI)", asset_type: "server" }, kevName: /\b(?:Is|Which) JQuery\b/i, cves: ["CVE-2020-11023"] },
  { row: { row_id: "N14", software: "Git 3.4 (LFS)", asset_type: "laptop" }, kevName: /\b(?:Is|Which) Git\b/, cves: ["CVE-2025-48384"] },
  { row: { row_id: "N15", software: "Sudo (for Windows)", asset_type: "laptop" }, kevName: /\b(?:Is|Which) Sudo\b/i, cves: ["CVE-2021-3156", "CVE-2025-32463"] },
  { row: { row_id: "N16", software: "ownCloud 4.0 (desktop client)", asset_type: "laptop" }, kevName: /\b(?:Is|Which) ownCloud\b/, cves: ["CVE-2023-49103", "CVE-2023-49105"] },
  { row: { row_id: "N17", software: "MinIO 2024 (client)", asset_type: "server" }, kevName: /\b(?:Is|Which) MinIO\b/, cves: ["CVE-2023-28432", "CVE-2023-28434"] },
  { row: { row_id: "N18", software: "OpenSSL 3.2 (Ruby gem)", asset_type: "server" }, kevName: /\b(?:Is|Which) OpenSSL\b/, cves: ["CVE-2014-0160"] },
  { row: { row_id: "N19", software: "Strapi (Cloud)", asset_type: "server" }, kevName: /\b(?:Is|Which) Strapi\b/, cves: ["CVE-2023-22894"] },
  { row: { row_id: "N20", software: "Metabase (Cloud)", asset_type: "server" }, kevName: /\b(?:Is|Which) Metabase\b/, cves: ["CVE-2021-41277"] },
  { row: { row_id: "N21", software: "dotCMS (Cloud)", asset_type: "server" }, kevName: /\b(?:Is|Which) dotCMS\b/, cves: ["CVE-2022-26352"] },
];

test("vendor-named look-alikes offline: OpenSSH is no KEV product, and a brand's other products are never shown as the KEV product", async () => {
  for (const { cves } of LOOKALIKE_ROWS) for (const c of cves) assert.ok(SNAP.kev_entries.some((e) => e.cve_id === c), `${c} is in the snapshot's KEV`);
  const id = `test-sample-lookalike-${process.pid}`;
  const rows = LOOKALIKE_ROWS.map(({ row }, i) => ({ asset_id: `n${i}`, asset_name: `n${i}`, internet_facing: false, owner_team: "IT", ...row })) as InventoryRow[];
  const res = await withNetworkGuard(() => runWith({ run_id: id, inventory: rows }, sampleDeps(id), { outputDir: null, logsDir: null }));
  assert.equal(res.status, "success");
  assert.equal(res.receipts.length, 0, "no model call");
  const by = new Map(res.lines.map((l) => [l.row_id, l]));
  for (const { row, kevName, cves } of LOOKALIKE_ROWS) {
    const l = by.get(row.row_id!)!;
    const tag = `${row.row_id} "${row.software}"`;
    assert.notEqual(l.resolution.status, "matched", `${tag} is not matched to a KEV product (got ${l.resolution.vendor}/${l.resolution.product})`);
    const vote = l.resolution.votes.find((v) => v.juror === "normaliser");
    assert.ok(vote && !vote.vendor && !vote.product, `${tag}: the normaliser names no KEV product`);
    const cited = l.kev?.cves.map((c) => c.cve_id) ?? [];
    for (const c of cves) assert.ok(!cited.includes(c), `${tag} never cites ${c}`);
    for (const q of res.owner_questions.filter((q) => q.row_id === l.row_id)) assert.doesNotMatch(q.question, kevName, `${tag}: ${q.question}`);
  }
  // the one-letter neighbour is a confident "no KEV product" (KEV has no OpenSSH entry); the others ask the owner
  for (const rid of ["N1", "N2"]) {
    assert.equal(by.get(rid)!.resolution.status, "no_match", rid);
    assert.equal(by.get(rid)!.decision, "monitor", rid);
  }
  for (const { row } of LOOKALIKE_ROWS.slice(2)) {
    const l = by.get(row.row_id!)!;
    assert.equal(l.decision, "ask_owner", `${row.row_id} "${row.software}": unsure -> ask the owner`);
    assert.ok(res.owner_questions.some((q) => q.row_id === l.row_id), `${row.row_id} has an owner question`);
  }
});

/**
 * KEV-listed products with a bracketed note that names no other product. The note may cost the normaliser's match (a
 * short note's role or host words count like the same words in the name: the owner is asked), but it never turns the row
 * into another product or a confident "no KEV product". A "bundled in" clause and a note with no product word keep it.
 */
const NOTED_ROWS: { row: Partial<InventoryRow>; family: string; mayAbstain: boolean }[] = [
  { row: { row_id: "M1", software: "OpenSSL 1.1.1k (bundled in Apache 2.4)", asset_type: "server" }, family: "openssl:openssl", mayAbstain: false },
  { row: { row_id: "M2", software: "Samba 4.15 (file shares)", asset_type: "server" }, family: "samba:samba", mayAbstain: true },
  { row: { row_id: "M3", software: "Jenkins 2.440 (controller)", asset_type: "server" }, family: "jenkins:jenkins", mayAbstain: true },
  { row: { row_id: "M4", software: "PHP 8.1.2 (Apache module)", asset_type: "server" }, family: "php:php", mayAbstain: true },
  { row: { row_id: "M5", software: "Notepad++ 8.6.2 (64-bit)", asset_type: "laptop" }, family: "notepad++:notepad++", mayAbstain: false },
  { row: { row_id: "M6", software: "log4j-core 2.14.1 (bundled in ERP WAR)", asset_type: "server" }, family: "apache:log4j", mayAbstain: false },
];

test("KEV-listed products with a bracketed note offline: their own product or the owner is asked; never another product, never 'no KEV product'", async () => {
  const id = `test-sample-noted-${process.pid}`;
  const rows = NOTED_ROWS.map(({ row }, i) => ({ asset_id: `m${i}`, asset_name: `m${i}`, internet_facing: false, owner_team: "IT", ...row })) as InventoryRow[];
  const res = await withNetworkGuard(() => runWith({ run_id: id, inventory: rows }, sampleDeps(id), { outputDir: null, logsDir: null }));
  assert.equal(res.status, "success");
  assert.equal(res.receipts.length, 0, "no model call");
  const by = new Map(res.lines.map((l) => [l.row_id, l]));
  for (const { row, family, mayAbstain } of NOTED_ROWS) {
    const l = by.get(row.row_id!)!;
    const tag = `${row.row_id} "${row.software}"`;
    assert.notEqual(l.resolution.status, "no_match", `${tag} is KEV-listed: never a confident "no KEV product"`);
    assert.doesNotMatch(l.why, /no CISA KEV product/i, tag);
    if (l.resolution.status === "matched") assert.equal(l.resolution.family, family, `${tag} resolves to its own product`);
    else {
      assert.ok(mayAbstain, `${tag} keeps its match (got ${l.resolution.status})`);
      assert.equal(l.decision, "ask_owner", tag);
      assert.ok(res.owner_questions.some((q) => q.row_id === l.row_id), `${tag} has an owner question`);
    }
    const vote = l.resolution.votes.find((v) => v.juror === "normaliser");
    if (vote?.vendor && vote.product) assert.equal(familyOf({ vendor: vote.vendor, product: vote.product }), family, `${tag}: the normaliser names no other product`);
  }
});

test("every vendor-named product in the snapshot's KEV gets the normaliser's vote for its own family; umbrella names stay vague", () => {
  const norm = (s: string) => s.trim().toLowerCase();
  const named = SNAP.kev_pairs.filter((p) => norm(p.vendor) === norm(p.product));
  assert.ok(named.length >= 50, `the snapshot lists ${named.length} vendor-named KEV pairs`);
  const misses: string[] = [];
  for (const p of named) {
    const sw = `${p.product.trim()} 1.0`;
    const parsed = parseSoftware(sw);
    const vote = normaliserVote({ row_id: "x", asset_id: "x", asset_name: "x", asset_type: "server", internet_facing: false, owner_team: "IT", software: sw }, parsed, topCandidates(parsed, SNAP.kev_pairs));
    const umbrella = ["microsoft", "apache"].includes(norm(p.vendor));
    if (umbrella) {
      assert.match(familyOf(p), /:multiple-products$/, `${p.vendor} / ${p.product} names no product`);
      assert.ok(!(vote.vendor === p.vendor && vote.product === p.product), `"${sw}" is never matched to the vague ${p.vendor} entry`);
      continue;
    }
    assert.doesNotMatch(familyOf(p), /:multiple-products$/, `${p.vendor} / ${p.product} is a product`);
    if (voteKind(vote) !== "match" || familyOf({ vendor: vote.vendor!, product: vote.product! }) !== familyOf(p)) misses.push(`${sw} -> ${voteKind(vote)} ${vote.vendor ?? ""}/${vote.product ?? ""}`);
  }
  assert.deepEqual(misses, []);
});

test("the observers are real: outside the guard, one local fetch is seen (so the zero above is a measurement)", async () => {
  const http = await import("node:http");
  const server = http.createServer((_q, s) => { s.writeHead(204, { Connection: "close" }); s.end(); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  try {
    const { seen } = await observed(async () => { await (await fetch(`http://127.0.0.1:${port}/`)).arrayBuffer(); });
    assert.ok(seen.length > 0, "diagnostics_channel saw the request");
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("sample mode is deterministic: the same rows twice give the same decisions, evidence and wording", async () => {
  const dev = SNAP.inventory.filter((r) => !SEALED.has(r.row_id)).slice(0, 12).map((r) => r.row_id);
  assert.equal(dev.length, 12);
  const once = async (id: string) => withNetworkGuard(() => runWith({ run_id: id, row_ids: dev }, sampleDeps(id), { outputDir: null, logsDir: null }));
  const a = await once(`test-sample-det-a-${process.pid}`);
  const b = await once(`test-sample-det-b-${process.pid}`);
  assert.equal(a.status, "success");
  assert.deepEqual(a.lines.map((l) => l.row_id).sort(), [...dev].sort(), "only the requested dev rows ran");
  assert.deepEqual(strip(a), strip(b));
});

test("run() puts the guard on for sample runs only", async () => {
  const seen: Record<string, boolean> = {};
  const spy = (deps: Deps, tag: string): Deps => {
    const q: Queries = deps.queries;
    return { ...deps, queries: { ...q, kevPairs: async () => { seen[tag] = networkGuardActive(); return q.kevPairs(); } } as Queries };
  };
  const ids = [`test-sample-g1-${process.pid}`, `test-sample-g2-${process.pid}`];
  try {
    const sample = spy(sampleDeps(ids[0]), "sample");
    await run({ run_id: ids[0], inventory: JUDGE_ROWS.slice(2, 3) as InventoryRow[] }, sample);
    const live: Deps = spy({ ...sampleDeps(ids[1]), mode: "live" }, "live"); // live mode with the snapshot data, no model
    await run({ run_id: ids[1], inventory: JUDGE_ROWS.slice(2, 3) as InventoryRow[] }, live);
    assert.deepEqual(seen, { sample: true, live: false });
  } finally {
    for (const id of ids) cleanRun(id);
  }
});

test("the CLI runs sample mode with an empty environment (no .env, no Zetaris, no Nightshift) and says so", () => {
  const id = `test-sample-cli-${process.pid}`;
  mkdirSync(TMP, { recursive: true });
  const input = join(TMP, "judge.json");
  writeFileSync(input, JSON.stringify({ inventory: JUDGE_ROWS }));
  try {
    const r = spawnSync(process.execPath, ["--experimental-transform-types", "--no-warnings", "src/cli.ts", "--sample", "--input", input, "--run-id", id], {
      cwd: REPO_ROOT, env: { PATH: process.env.PATH ?? "" }, encoding: "utf8", timeout: 60_000,
    });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(`run ${id}  mode=sample  status=success`));
    assert.match(r.stdout, /model calls: 0/);
    assert.match(r.stdout, /network_guard sample_run_checked ok \| no network access was attempted/);
    const saved = JSON.parse(readFileSync(join(OUT, `run-${id}.json`), "utf8")) as RunResponse;
    assert.equal(saved.mode, "sample");
    assert.equal(saved.lines.length, JUDGE_ROWS.length);
  } finally {
    cleanRun(id);
    rmSync(TMP, { recursive: true, force: true });
  }
});

test("glued 'Windows11' and 'Win Server/Svr' rows offline: Microsoft / Windows like their spaced form, never monitor or 'no KEV product'", async () => {
  const id = `test-sample-winspell-${process.pid}`;
  const pairs: [string, string, string][] = [
    ["Windows11 Home", "Windows 11 Home", "laptop"],
    ["Windows10 Enterprise 21H2", "Windows 10 Enterprise 21H2", "desktop"],
    ["Win Server 2016 Std (file share)", "Windows Server 2016 Std (file share)", "server"],
    ["MS Win Svr 2012 R2", "MS Windows Svr 2012 R2", "server"],
    ["Windows11Pro", "Windows 11 Pro", "laptop"],
    ["WinServer 2022 Std", "Windows Server 2022 Std", "server"],
  ];
  const rows = pairs.flatMap(([glued, spaced, asset_type], i) => [glued, spaced].map((software, j) => ({
    row_id: `WS${i}${j ? "s" : "g"}`, asset_id: `ws${i}`, asset_name: `ws${i}`, asset_type, internet_facing: false, owner_team: "IT", software,
  }))) as InventoryRow[];
  const res = await withNetworkGuard(() => runWith({ run_id: id, inventory: rows }, sampleDeps(id), { outputDir: null, logsDir: null }));
  assert.equal(res.status, "success");
  assert.equal(res.receipts.length, 0, "no model call");
  const by = new Map(res.lines.map((l) => [l.row_id, l]));
  pairs.forEach(([glued, spaced], i) => {
    const g = by.get(`WS${i}g`)!;
    const s = by.get(`WS${i}s`)!;
    assert.equal(g.resolution.status, "matched", glued);
    assert.equal(g.resolution.family, "microsoft:windows", glued);
    assert.equal(g.resolution.product_type, "os", glued);
    assert.notEqual(g.decision, "monitor", `${glued}: KEV lists Windows, never monitor`);
    assert.doesNotMatch(g.why, /no CISA KEV product/i, glued);
    assert.equal(g.decision, s.decision, `${glued} is decided like ${spaced}`);
    assert.equal(g.critic?.rubric.total, s.critic?.rubric.total, `${glued}: the same rubric as ${spaced}`);
  });
});
