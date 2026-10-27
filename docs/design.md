# ExposureLedger: design

**Version 1** (26 Oct 2026). This is the source of truth for builders. The shared types live in `src/contracts.ts`.

## 1. What it does, and for whom
- **The user:** the only IT administrator at a charity of about 200 people.
- **Their question:** *"What do I patch first, and by when?"*
- **Input:** their software list, written the messy way people really write it (for example `MS Exchange Svr 2019 CU12`, `log4j-core 2.14.1 (bundled in ERP-Portal WAR)`).
- **Output:** a **dated patch list**. Every line has a decision (`patch_now`, `this_cycle`, `monitor` or `ask_owner`), a target date, the evidence (source rows read through Zetaris), and the receipt of every model call involved.
- **Why it is hard (fragmented intelligence):** four sources name the same flaw differently.
  1. **The inventory:** free text.
  2. **CISA KEV:** flaws exploited in the wild, keyed by `vendorProject`/`product` plus a CVE. KEV alone names Citrix's ADC 7 ways.
  3. **FIRST EPSS:** the probability of exploitation in the next 30 days, keyed by CVE.
  4. **NIST NVD:** which product versions are affected, keyed by CVE and CPE.
- **Safety framing:** this is decision support. **The policy is the user's own** (configurable). We make no claims about exploitability. The inventory is synthetic. KEV due dates are US federal benchmarks.

## 2. Architecture
```
        ┌──────────── Zetaris (data layer, local Docker, REST SQL) ────────────┐
        │  el.inventory (our JSON on GitHub raw) · el.kev (CISA KEV, live)      │
        │  el_epss_<hash> (FIRST EPSS, per-run, ≤100 CVEs) · el_nvd_<cve> (NVD) │
        └───────────────▲──────────────────────────▲───────────────────────────┘
                        │ named queries (Queries)  │ live re-query (no cache)
 inventory rows ─► Normaliser ─► Resolver jury ─► Conflict Critic ─► Exposure Analyst ─► Verifier ─► Patch list
                  (code: parse,   (Bolt + Lightning  (code rules + Ultra  (policy as code:   (re-checks every   + report.html
                   type, top-K     vote; Ultra on    on contested; send    KEV/EPSS/NVD →     cited KEV/EPSS     + trace.jsonl
                   candidates)     splits)           back ≤2 → ask owner)  decision + dates)  value live)        + manifest
                        │                 │                 │                    │
                        └──────── World Model engine (shared state + provenance + audit) ─────┘
        all model calls → Meterless Nightshift (127.0.0.1:8088/v1, pinned Nemotron, receipt per call)
```

## 3. Agents and how they interact
| # | Agent | Kind | Job | Talks to |
|---|---|---|---|---|
| 1 | **Normaliser** | deterministic code | Parse each row: product hint, version, **product type** (server / network_appliance / client / cloud_service / library / os). Build the top-K (≈12) KEV candidate pairs. Cast the deterministic "third vote". | → Jury |
| 2 | **Resolver jury** | Bolt + Lightning, Ultra | Bolt and Lightning each map every row to one KEV (vendor, product) or `null` (batches of 10 rows; run in parallel). **They agree → accept. They split → Ultra adjudicates** (with the receipt shown). | → Critic; ← Critic (send back) |
| 3 | **Conflict Critic** | code rules + Ultra on contested | Rejects: **a product-type conflict** (e.g. "Exchange Online" = cloud vs KEV "Exchange Server" = on-prem; "FortiClient VPN" = client vs "FortiClient EMS" = server); a name-only match with no version evidence; a KEV family with no CVE (counterfactual check); missing provenance. Scores a **0–3 × 3 rubric** (accuracy, appropriateness, actionability). **Below 7/9 → `ask_owner` (autonomy L1); otherwise auto (L2).** Sends work back to the Resolver with the reason, **at most 2 rounds**. | → Resolver / Analyst |
| 4 | **Exposure Analyst** | policy as code | Turns resolved rows plus KEV/EPSS/NVD facts into decisions and dates (see §5). | → Verifier |
| 5 | **Verifier** | code, live | Re-queries every cited KEV listing and EPSS score **live through Zetaris (never from cache)** before a line is shown. A mismatch blocks the line (`verified: false`, with a note). | → Report |
| 6 | **Reporter** | template (+ Lightning, optional) | Writes a ≤2-sentence "why" per line **from structured facts only**. The deterministic template is the default; Lightning only rephrases, and adds no facts. | → output |

**Collaboration that judges must see in the trace:**
- the jury split and the Ultra adjudication;
- the critic blocking a look-alike and sending it back;
- the retry with new evidence;
- an `ask_owner` with its reason;
- the verifier's live re-check;
- the World Model facts with their provenance.

## 4. Models (pinned through Nightshift; never `meterless/auto`)
| Model ID | Role | Settings |
|---|---|---|
| `nvidia/nemotron-3.5-bolt-e4b` | First juror (fast) | `max_tokens` 1500 |
| `nvidia/nemotron-3.5-lightning-30b-a3b` | Second juror; resolver retries; optional phrasing | **`chat_template_kwargs: {"enable_thinking": false}`**, `response_format: {"type":"json_object"}`, `max_tokens` 1500 |
| `nvidia/nemotron-3-ultra-550b-a55b` | Adjudicator on splits; critic on contested rows | **`enable_thinking: false`**, `json_object`, `max_tokens` 2000. **Never send `reasoning_budget`.** |

- **Measured on 26 Oct, at batch size** (10 strings × 12 candidates): Bolt 6.4 s, 7/10; Lightning 11.5 s, 8/10; Ultra 10.7 s, 8/10. Every reply was valid JSON. 4 concurrent calls are OK. No caching was seen.
- **Every call is logged with:** the requested model, `response.model`, `meterless.routed_model`, `meterless.receipt_id`, latency and tokens.
- **Headers:** `Authorization: Bearer $METERLESS_RUNTIME_TOKEN`, `meterless-app: exposureledger`, `meterless-scope: user`.
- **Limits:** timeout 90 s; at most 2 retries (backoff of 2, 4, 8 s on 429 or 5xx); at most 4 concurrent calls.

## 5. Policy (the user's rules, as code; in `config/policy.json`, overridable per run)
1. **`patch_now`:** the installed version is affected by a CVE **listed in KEV**. This holds **whatever the EPSS score**; the report flags where KEV and EPSS disagree.
   - Target date = run date + `sla_days.patch_now` (7).
   - The KEV `dueDate` is shown as the **US-federal benchmark**, with "overdue by N days" when it has passed.
2. **`this_cycle`:** affected by a CVE **not in KEV** with **EPSS ≥ 0.10**, or **≥ 0.05 if the asset is internet-facing**. Target = run date + 30 days.
   - The non-KEV CVEs come from the NVD product lookup (§6).
   - If that helper is unavailable, the bucket is empty, and the manifest lists the helper as *dormant*.
3. **`monitor`:** resolved, with nothing above. Next review = run date + 90 days.
4. **`ask_owner`:** unresolved, a type conflict that survives the retries, a rubric score under 7/9, or a version needed to decide that is missing. Each one comes with a concrete question (e.g. "Which FortiOS version runs on branch-fw-01?").
5. **Fail-closed:** if EPSS or KEV can't be read live and has no cache, nothing is relaxed to `monitor`. Those rows become `ask_owner`, with the reason.
- **Sort order:** decision bucket → internet-facing first → most overdue KEV due date → highest EPSS.

## 6. Data sources in Zetaris (all objects use the `EL_`/`el_` prefix; `npm run setup` creates them idempotently from an empty Zetaris)
| Object | What | Live? |
|---|---|---|
| `EL_INVENTORY.el_inventory_raw` + view `el.inventory` | Our synthetic inventory, `data/inventory.json` in the public data repo, read over GitHub raw | our file (labelled synthetic) |
| `EL_KEV.el_kev_raw` + view `el.kev` | The full CISA KEV catalogue (`cisagov/kev-data` raw JSON): `cve_id, vendor, product, vulnerability_name, date_added, short_description, required_action, due_date, ransomware_use, notes, catalog_version` | **live** |
| `EL_EPSS.el_epss_<sha8>` | One REST table per run per batch of ≤100 CVEs: `api.first.org/data/v1/epss?cve=…`. Query with `LATERAL VIEW explode(data)`; values arrive as strings, so `CAST` them | **live** |
| `EL_NVD.el_nvd_<cve>` | One REST table per deciding CVE: `services.nvd.nist.gov/rest/json/cves/2.0?cveId=…`. Read `to_json(vulnerabilities)` and parse the CPE ranges in code | **live** (⚠ keyless rate limit; cached per day) |
| `EL_NVD.el_nvdp_<hash>` | NVD product lookup (recent CVEs for a CPE vendor:product) | **live**, cached per day; cut-list item |

- **Setup rules (probe P3):**
  - A duplicate `CREATE` returns **HTTP 400 "already exists"**: treat it as success.
  - Check first with `SHOW LIGHTNING TABLES <DB>`, whose `source_table` is the endpoint URL.
  - **Never DROP.**
  - `npm run setup -- --prefix EL_T1_` proves that setup works on a fresh prefix.
- **Query rules:**
  - One Zetaris query at a time (a queue of 1).
  - A 120 s watchdog. When it fires: try a narrower query, then fall back to a cached snapshot, logged as `fallback`.
  - Values come back as strings, so parse them.
  - Cache results by SQL hash for sample mode. **The Verifier always bypasses the cache.**
- **Named queries (`Queries` in contracts):** `inventory`, `kevPairs`, `kevByProducts`, `kevVerify`, `epss`, `epssVerify`, `nvdCves`, `nvdProduct`.
  - Live mode implements them in Zetaris SQL; sample mode implements them over the snapshot. **The agents never see SQL.**

## 7. World Model engine (the Meterless engine; official test `npm run verify:engine` → 8/8)
- **Copied from `Meterless/Meterless@1742dec`** (Apache-2.0), keeping the reference layout: `src/engine/world-model/{reference/src,reference/scripts,conformance}`. It runs with no install, via `node --experimental-transform-types`.
- **What it does for us (visible in the report and the trace):**
  - **Entities:** asset, software row, KEV product **family** (with every KEV spelling as an alias), CVE.
  - **Facts with mandatory provenance**, each with `source = zetaris:<view>` or `agent:<name>` and `at` = the source's own date (KEV `catalogVersion`, EPSS `score_date`, the run's as-of date). **Never wall-clock time.**
    - `runs` (asset → software);
    - `resolves_to` (software → family), citing the receipt IDs;
    - `affects` (CVE → family);
    - `epss`;
    - `decision`.
  - **The review band** (0.82–0.85) queues near-duplicate KEV spellings, e.g. `Log4j` vs `Log4j2` = 0.833, for merge review. Its own name similarity is **not** used for matching raw inventory strings (it scored 0.00–0.55 on true matches).
  - **Idempotent re-ingest:** running the same run twice adds no events. `verify` proves it, and also proves with `--mutate` that the check can fail.
  - **`audit()`** → `logs/audit-<run_id>.jsonl`. A run manifest lists which helpers are live and which are dormant.
- **Gotcha:** `entityAt` returns empty `attrs`. For "what did we believe on date D", use `view("facts").about(id)`, filtered by `assertedAt`.
- **Fallback (engine gate ~02:00):** if the World Model is not green and used by then, switch to H-MEM (13/13 proven) with the same facts as memory records.

## 8. Run flow and budget (target: under 3 minutes live for ~80 rows)
1. Load the inventory (`el.inventory`, or inline `RunRequest.inventory`; judges may send their own rows).
2. `kevPairs()` once per run, then the Normaliser builds the top-K candidates per row.
3. Jury: Bolt and Lightning in parallel per batch of 10 → agreement → Ultra on the splits (batched).
4. Critic rules → send back (≤2 rounds; Lightning re-decides with the critic's note, Ultra if still contested) → `ask_owner` if still failing.
5. `kevByProducts()` → `nvdCves()` for the deciding CVEs (version ranges) → `epss()` for every candidate CVE (≤100 per table) → `nvdProduct()` (if live).
6. Analyst → decisions and dates. 7. Verifier → `kevVerify` + `epssVerify` (live).
8. World Model ingest + audit. 9. Write `output/run-<id>.json`, `output/report-<id>.html`, `logs/trace-<id>.jsonl`.

**Rough budget:**
- jury: 8 batches × 2 models, 4 at a time ≈ 40 s;
- Ultra and retries ≈ 40 s;
- Zetaris ≈ 30 s;
- NVD ≈ 15 s.

## 9. Interfaces (entry points)
- `npm start`: an HTTP server on `0.0.0.0:$PORT` (default 8000).
  - `POST /run`: body `RunRequest`, returns `RunResponse`.
  - `GET /report/:run_id`: the HTML report.
  - `GET /health`.
- `npm run cli -- --input input_examples/example_1.json [--sample]`: one run; prints a summary and writes the outputs.
- `npm run setup [-- --prefix EL_T1_]` · `npm test` · `npm run verify:engine` · `npm run verify` · `npm run eval -- --set dev`.
- **The node flags everywhere:** `node --experimental-transform-types --no-warnings --env-file-if-exists=.env`.
- **Zero runtime dependencies:** `fetch`, `node:http`, `node:crypto`, `node:fs`, `node:test`, `node:sqlite` only.

## 10. Sample mode (`SAMPLE_MODE=true`): deterministic, no network
- **Data:** `Queries` is served from `data/sample/snapshot.json`, which holds real rows captured by `scripts/snapshot.ts`: the inventory, KEV entries for the inventory's vendors, EPSS scores, NVD ranges and product lookups, each with its capture date.
- **No models:**
  - the LLM is `null`; the **jury is replaced by the Normaliser's deterministic decision**;
  - Ultra adjudication becomes the deterministic tie-break rules or `ask_owner`.
- **What still runs for real:** the critic rules, the policy, the verifier (against the snapshot, labelled as such), the World Model and the report.
- **Nothing recorded from a model is ever replayed.**
- **Network guard:** `fetch` and `net.Socket.connect` throw, and a test proves no socket opens.
- **Labelling:** every output is stamped `mode: "sample"`, with the snapshot date.
- **Judges' own rows work offline,** using the KEV and EPSS data in the snapshot.

## 11. Logs and evidence
- **`logs/trace-<run_id>.jsonl`, also printed to stdout.** One `TraceEvent` per step: the agent, action, input and output summaries, target agent, model, routed model, receipt, latency, confidence, retry count, status (`ok`/`error`/`fallback`/`blocked`/`sent_back`) and details (query names, SQL hash, rubric).
- **Secrets are never logged.**
- **`npm run verify` asserts** that every model call in the last trace has a `receipt_id` and the pinned `routed_model`.

## 12. Evaluation (accuracy test)
- **Arms:** the full system · Bolt alone · Lightning alone · the Normaliser alone · (optional) Ultra alone.
- **Metrics:** accuracy against human answers, scored by KEV family (any listed spelling counts; `none` is correct when the answer is null); look-alike rejection; the share of rows that needed Ultra; run time; tokens.
- **Rows:**
  - 30 random **test rows** (`data/eval/test_rows.json`, seeded and saved), **sealed until the agreed answers exist** (E5);
  - development uses only the other rows, with Zaw's labels.
- **Label files stay outside the repo** until E5. Then the agreed answers arrive as `data/test_answers.csv`, uploaded by a teammate.
- **Output:** `output/eval-<date>.{md,json}`; the final table goes into `docs/evaluation.md`.

## 13. Repository layout and ownership (build phase)
```
src/contracts.ts (controller) · src/config.ts · src/trace.ts · src/adapters/{zetaris,queries,nightshift,nvd}.ts
src/resolve/{normalise,candidates}.ts · src/agents/{jury,critic,verifier,reporter}.ts · src/policy/analyst.ts
src/engine/world-model/** (vendored) · src/engine/index.ts · src/report/render.ts · src/sample/** · src/eval/**
src/run.ts (pipeline) · src/server.ts · src/cli.ts · scripts/{setup,verify,verify-engine,eval,snapshot,convert-inventory,pick-test-rows}.ts
test/*.test.ts · config/policy.json · data/sample/ · data/eval/test_rows.json · input_examples/ · output_examples/ · docs/
Dockerfile · .dockerignore · .env.example · .env.docker.example · package.json (controller) · README.md
```
- **Reserved for teammates, never created by code:** `data/software_list.csv`, `data/test_answers.csv`, `docs/deck.pdf`.
- **Not committed:** `output/` and `logs/` (selected real runs are copied into `output_examples/`).

## 14. Cut list (in this order)
1. a governed `SCHEMASTORE VIEW` of the resolved mapping;
2. a discovery prelude (SHOW/DESCRIBE logged);
3. the NVD product lookup for `this_cycle`;
4. report-page polish;
5. the "reopen when a premise changes" stretch feature.

**Never cut:** messy list → matched list → dated patch list with sources and receipts; one critic loop; the engine test; sample mode; the four required submission parts.

## 15. Where to look (originals)
- **Product and judges:** `Idea_Selection/finalists.md` §F1, `feasibility/F1.md`, `evaluations/J1–J3.md` §4.
- **Engines:** `research/engine_menu.md`; the World Model `AGENTS.md`; `meterless-world-model-agent-engine.md`.
- **Data:** `research/data_menu.md` §5–6; `Build_Workspace/probes.md`.
- **Requirements:** `technical-execution-requirements.md`, `vibe-coding-starter-guide.md`, `disqualification-checklist.md` §7–10 and §14, `submission-requirements.md`, `ai-usage-policy.md`.

## 16. Changes after testing (integration, 26 Oct, dev rows only)
Measured on the 50 development rows (the 30 sealed test rows were never run), live, one variable at a time; each line of the build ledger records the metric before and after. Labels were not available yet, so the measures are per-row decisions with identical jury answers, the known look-alikes, the critic's send-backs, run time and the Ultra share.
- **Version-unconfirmed ruling.** A KEV-listed family whose installed version cannot be confirmed (no version, a name-only match, an edition label, a CVE outside this run's NVD lookups) stays `patch_now` (fail-closed), flagged "version unconfirmed", with the critic's concrete question attached. To make that possible, a match without version evidence now scores appropriateness 2 when its product type fits exactly (it was capped at 1), so a unanimous, type-fitting match reaches 7/9; anything weaker stays below 7/9 and goes to the owner.
- **The critic's row type** is the normaliser's type plus the strong cloud cues only (online, SaaS, tenant): one source of truth.
- **An operating system and an application are a type conflict** (experiment E3). It sent back exactly the three predicted rows: a Windows Server row both jurors had matched to Exchange Server, a file-sync client matched to the vendor's server product, a remote-desktop client matched to a Windows server component.
- **Ultra's objections are blockers.** When Ultra's critique says a match is wrong, the row is sent back to the resolver with Ultra's reason and stays disputed until the answer changes (a bug fix: before, the objection was lost in the next round, and one wrong match still shipped as `patch_now`).
- **One family per row** (a bug fix after review): a KEV spelling that lists several products ("CentreStack and Triofox", "ESXi and Workstation") belongs to the product the row matched. The fact store, the NVD plan, the analyst, the critic's family filter and vote support, Ultra's dispute key and the re-decide's "changed" all use that one row family. Before, the critic used the combo's first product: it checked only part of the cited KEV CVEs (so the jury's choice of spelling could flip patch_now to monitor), and a repeated combo answer counted as "changed", which dropped Ultra's dispute. A line is relaxed to monitor only when the version check covered every cited KEV CVE.
- **Fail-closed on "not affected"**: when EPSS or KEV entries cannot be read, NVD's "not affected" never relaxes a KEV-listed line to monitor; the line goes to the owner with the NVD finding in the question.
- **NVD read labels**: NVD evidence and the manifest's NVD source say "live" only for CVEs read through Zetaris in this run; today's cache (and the client's fallback copy) is labelled not live, with its day.
- **Ultra's final check** (experiment E2): every row headed for a version-unconfirmed `patch_now` that the normaliser does not back gets one small Ultra call, "is this the same product?" (version excluded); a "no" is a blocker. Patch-bound rows come first in Ultra's queue (at most 16 Ultra critiques per run).
- **An unsure normaliser is not dissent against a match** (experiment E1b): a null vote below 0.6 no longer lowers a match's accuracy score; for a "no KEV product" outcome it still counts as support. Two KEV-listed rows with no recorded version (a firewall OS, a typo'd Windows row) reached the ruling's `patch_now`, both confirmed by Ultra's check; a cross-vendor look-alike it would have let through was caught by that check.
- **Normaliser spelling** (experiment E5): one-word "ConnectSecure"/"PolicySecure" read as Ivanti Connect/Policy Secure.
- **Windows rows without a build number** (24 of 80): KEV lists Windows as one product with ~240 CVEs, NVD bounds Windows by build per edition, and Microsoft ships every fix in the monthly cumulative update. Such rows stay `patch_now` ("install the latest cumulative update"), and the owner gets **one question per edition** ("which Windows 11 23H2 build runs on these 6 machines?"), naming the first fixed build from NVD's ranges for the newest KEV-listed Windows CVE. An edition label ("23H2", "2019") is never compared with build bounds (`namesEdition`), which would otherwise read 23 > 10 and say "not affected".
- **NVD budget.** A cold NVD CVE costs ~10 s through Zetaris (keyless rate limit). Each run has a 60 s NVD budget (`EL_NVD_BUDGET_S`); CVEs left over are named "not looked up in this run" and keep their rows at the fail-closed outcome; today's cache is free and never counts. The prefetch of the normaliser's families runs while the jury votes.
- **Re-decides:** a row's first send-back goes to Lightning, its second to Ultra. A run is `partial` only when model calls fail or no model client exists, not when one row's jurors give no valid answer (that row uses the deterministic vote, traced).
- **Measured:** dev rows, NVD cache warm: 43-80 s per run (final run 49 s, 30 receipted calls, 18 of them Ultra); first run of the day 81 s with the 60 s NVD budget (part of NVD left for later runs); warming every NVD record once took 200 s.
- **New modules:** `src/pipeline/facts.ts` (the run's fact store: KEV per family, EPSS, NVD within the budget), `src/pipeline/critic-loop.ts` (the loop above), `src/policy/windows.ts` (edition parsing and the grouped question). `src/resolve/candidates.ts` (v0) is no longer the pipeline's default; its small name helpers are still shared.

## 17. Final fixes (27 Oct, after the final review)
- **A line cites the KEV CVEs NVD does not rule out for the version.** The critic records NVD's check per CVE (inside, outside, unchecked; `CriticOutcome.cve_status`). The analyst's `scopeKevToVersion` drops only the CVEs NVD places the version outside (kept as "version not affected" evidence). The CVEs it places inside come first and the ones not version-checked stay cited, labelled "not version-checked, counted fail-closed"; the due date, overdue days, EPSS and sort key come from both (the same fail-closed rule as the version-unconfirmed ruling), so more NVD evidence can only drop a CVE on proof and never makes a line less urgent. The "why" leads with the confirmed CVE and names the unchecked CVE the date or EPSS comes from. The verifier re-derives the due date from the cited list, so the two agree.
- **Completing the version check.** Once NVD places a match inside one KEV CVE, the critic loop looks up the line's other cited CVEs too (`completeVersionCheck`; most urgent first: earliest due date, then highest EPSS; round-robin over the rows, internet-facing first), inside the run's NVD budget (today's cache is free), and redoes only the per-CVE check. The verdict and rubric stand (more ranges cannot turn "affected" into anything else). Traced as `version_check_completed`.
- **Cached Zetaris copies are labelled.** `createZetarisQueries` records every cache-backed read (`sourceStatus()`). A read served from the client's saved copy makes the source `live: false` with the copy's day, its evidence not live, the run `partial`, and no line `monitor` (fail-closed: such lines go to the owner).
- **NVD counts:** `nvdAttempts` is the budget counter; the trace reports `live_reads` (0 in sample mode), attempts, errors, fallback, cached and skipped apart.
- **Verifier counts:** "N re-checked and matched, M with nothing to re-check, K blocked".
- **Normaliser:** a KEV vendor whose KEV product name is only generic words (`WordPress / Core`) gets an unsure vote, never a confident "no KEV product" (0 of 50 dev votes changed).
- **Discovery and one federated SQL:** each live run lists the registered sources (`SHOW LIGHTNING DATABASES` / `TABLES`) and runs one naive inventory × KEV join inside Zetaris, set against the agents' answers in the trace and the report (display only).
- **Memory across runs** (`src/pipeline/memory.ts`), kept per row: the index (`output/world/last-runs.json`) maps each row (source, id, asset and software text) to the last live run that included it. A run reopens those runs' saved worlds read-only, reports what changed, and a line already `patch_now` keeps the earlier target date. A run on a subset of the rows moves only its own rows' pointers, so it never resets the clock of the rows it left out; the registered inventory and request rows never share memory.
- **Eval:** scored by KEV family (`familiesOf`), the scoring mode stated in the report; the dev table gained the one-call baseline arm.
