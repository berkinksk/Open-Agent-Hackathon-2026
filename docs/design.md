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
